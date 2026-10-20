"""
Run a plan of cells, each as its own runner.py process, and keep an index.

    uv run --project ../helios-server python sweep.py --plan config/sweep.yaml
    uv run --project ../helios-server python sweep.py --plan config/equivalence.yaml --dry-run

Order: small N to large N; at each (N, rep), every arm, and every populate mode
when the plan has more than one. The order of arms and of modes flips on odd
reps, so neither always runs first. Cells are serial (§3.8), and pinning is
inherited: run the sweep itself under the runbook's taskset.

A cell already accepted in results/sweep_index.jsonl is skipped, so an
interrupted sweep resumes by being run again. Before each cell the free disk
must hold N x the face's bytes per ballot x 2.5 -- Helios stores each ballot
twice, plus indexes -- or the sweep stops. The first cell that fails, in the
runner or in acceptance, stops it too: the next cell would usually fail the
same way, and the index lets the rerun pick up from there.

Plan keys: face, arms (elgamal, paillier-off), levels, reps, ballots
(prepared | live), sample_size, populate (a list), strict, cleanup_after.
"""

import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys

import console
import helios_env

INDEX = helios_env.WORKLOAD_ROOT / 'results' / 'sweep_index.jsonl'
ARM_SCHEME = {'elgamal': 'elgamal', 'paillier-off': 'paillier'}
DISK_FACTOR = 2.5


def cells(plan):
  """The plan's cells, in run order."""
  arms = list(plan['arms'])
  modes = list(plan.get('populate') or ['insert'])
  prepared = plan.get('ballots', 'prepared') == 'prepared'
  if not prepared:
    modes = [None]
  out = []
  for N in sorted(plan['levels']):
    for rep in range(plan.get('reps', 1)):
      flip = rep % 2 == 1
      for arm in (arms[::-1] if flip else arms):
        for mode in (modes[::-1] if flip else modes):
          out.append({'face': plan['face'], 'arm': arm, 'N': N, 'rep': rep,
                      'ballots': 'prepared' if prepared else 'live',
                      'populate': mode,
                      'sample_size': plan.get('sample_size', 10) if prepared
                      else None})
  return out


def cell_key(c):
  return (f'{c["face"]}|{c["arm"]}|n={c["N"]}|r={c["rep"]}|{c["ballots"]}'
          f'|{c["populate"] or "-"}|s={c["sample_size"] or "-"}')


def read_index(path=INDEX):
  out = []
  if pathlib.Path(path).exists():
    for line in pathlib.Path(path).read_text().splitlines():
      if line.strip():
        out.append(json.loads(line))
  return out


def accepted_keys(path=INDEX):
  return {e['key'] for e in read_index(path) if e.get('accepted')}


def append_index(entry, path=INDEX):
  pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
  with open(path, 'a') as f:
    f.write(json.dumps(entry, sort_keys=True) + '\n')
    f.flush()
    os.fsync(f.fileno())


def bytes_per_ballot(face_key, scheme, cfg):
  """
  One ballot as Stage 2 casts it, from the prepared set's first line: the
  JSON body, with an election hash and uuid of the real lengths. None when
  there is no set to measure.
  """
  from drivers import prepared_set as ps
  d = ps.set_dir(face_key, scheme, cfg)
  chunks = ps.completed_chunks(d)
  if not chunks:
    return None
  rec = next(ps.read_chunk(chunks[0][2]))
  vote = {'answers': rec['encrypted_answers'], 'election_hash': 'x' * 43,
          'election_uuid': 'x' * 36}
  return len(json.dumps(vote, separators=(',', ':')).encode('utf-8'))


def free_bytes():
  """Free space where the board lands: the workload filesystem, and
  Postgres's data directory when the role may read it. The smaller wins."""
  free = [shutil.disk_usage(helios_env.WORKLOAD_ROOT).free]
  try:
    helios_env.setup_django()
    from django.db import connection
    with connection.cursor() as c:
      c.execute('SHOW data_directory')
      free.append(shutil.disk_usage(c.fetchone()[0]).free)
  except Exception:
    pass
  return min(free)


def run_one(c, plan, run_id):
  args = [sys.executable, 'runner.py', '--face', c['face'],
          '--scheme', ARM_SCHEME[c['arm']], '--n', str(c['N']),
          '--rep', str(c['rep']), '--run-id', run_id]
  if c['ballots'] == 'prepared':
    args += ['--prepared', '--sample', str(c['sample_size']),
             '--populate', c['populate']]
  else:
    args += ['--live']
  if plan.get('strict'):
    args += ['--strict']
  console.detail(' '.join(args[1:]))
  return subprocess.run(args, cwd=helios_env.WORKLOAD_ROOT).returncode


def main(argv=None):
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  p.add_argument('--plan', required=True)
  p.add_argument('--cleanup-after', action='store_true', default=None,
                 help='delete each accepted cell\'s election (cleanup.py)')
  p.add_argument('--dry-run', action='store_true',
                 help='print the order and what would be skipped')
  p.add_argument('--index', default=str(INDEX))
  args = p.parse_args(argv)

  import yaml
  plan = yaml.safe_load(pathlib.Path(args.plan).read_text())
  for arm in plan['arms']:
    if arm not in ARM_SCHEME:
      console.fail(f'unknown arm {arm!r}; expected {", ".join(ARM_SCHEME)}')
      return 2
  cleanup_after = (args.cleanup_after if args.cleanup_after is not None
                   else bool(plan.get('cleanup_after')))
  cfg = helios_env.load_config('levels.yaml')

  todo = cells(plan)
  done = accepted_keys(args.index)
  console.title(f'SWEEP · {args.plan}')
  console.field('cells', len(todo))
  console.field('already accepted', sum(cell_key(c) in done for c in todo))
  console.field('index', args.index)

  if args.dry_run:
    for c in todo:
      state = 'skip (accepted)' if cell_key(c) in done else 'run'
      console.detail(f'{state:16} {cell_key(c)}')
    return 0

  from emit import make_run_id
  import acceptance
  import cleanup

  for n, c in enumerate(todo, 1):
    key = cell_key(c)
    console.section(f'CELL {n}/{len(todo)} · {key}')
    if key in done:
      console.ok('already accepted — skipped')
      continue

    per = bytes_per_ballot(c['face'], ARM_SCHEME[c['arm']], cfg)
    if per is None:
      console.warn('no prepared set to size a ballot from; disk not checked')
    else:
      need, free = int(c['N'] * per * DISK_FACTOR), free_bytes()
      if need > free:
        console.fail(f'disk: needs ~{console.size(need)} (N x '
                     f'{console.size(per)} x {DISK_FACTOR}), '
                     f'{console.size(free)} free — sweep stopped')
        return 1
      console.ok(f'disk: ~{console.size(need)} needed, {console.size(free)} free')

    run_id = make_run_id()
    rc = run_one(c, plan, run_id)
    path = helios_env.WORKLOAD_ROOT / 'results' / f'{run_id}.jsonl'
    ok = rc == 0 and path.exists() and acceptance.check(str(path), c['N'])

    uuid = None
    if path.exists():
      for line in path.read_text().splitlines():
        r = json.loads(line)
        if r['metric'] == 'election_created':
          uuid = r['extra'].get('election_uuid')
          break
    append_index({'key': key, 'cell': c, 'run_id': run_id, 'jsonl': str(path),
                  'exit_code': rc, 'accepted': bool(ok),
                  'election_uuid': uuid, 'plan': str(args.plan),
                  'at': datetime.datetime.now(datetime.timezone.utc)
                        .strftime('%Y-%m-%dT%H:%M:%SZ')}, args.index)
    if not ok:
      console.fail(f'cell not accepted (runner exit {rc}) — sweep stopped; '
                   f'rerun to resume from here')
      return 1
    console.ok(f'accepted: {path.name}')
    if cleanup_after and uuid:
      console.detail(f'deleted {cleanup.delete_elections([uuid])} election(s)')

  console.section('SWEEP DONE')
  return 0


if __name__ == '__main__':
  sys.exit(main())
