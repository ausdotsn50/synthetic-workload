"""
Run a plan of cells, each as its own runner.py process, and keep an index.

    uv run --project ../helios-server python sweep.py --plan config/sweep_nle2025.yaml
    uv run --project ../helios-server python sweep.py --plan config/compare_smoke.yaml --dry-run

Plans (config/):
  sweep_nle2025.yaml, sweep_smoke.yaml    the main sweeps: bulk, 3 reps
  compare_nle2025.yaml, compare_smoke.yaml  live vs bulk at small N, for
                                          compare_modes.py
  sweep_live.yaml, anchors_live.yaml      fallbacks, live only

Each cell runs in one mode:
  live   runner.py --live: all N ballots encrypted in the browser, cast and
         verified
  bulk   runner.py --prepared --sample S: S live, N - S inserted prepared

Order: small N to large N; at each (N, rep), every arm, and within each arm
every mode the plan lists. The order of arms and of modes flips on odd reps,
so neither always runs first. Cells are serial (§3.8), and pinning is
inherited: run the sweep itself under the runbook's taskset.

A cell already accepted in results/sweep_index.jsonl is skipped, so an
interrupted sweep resumes by being run again. Before each cell the free disk
must hold N x the face's bytes per ballot x 2.5 -- Helios stores each ballot
twice, plus indexes -- or the sweep stops. With cleanup_after, an accepted
cell's election is deleted and the database VACUUM ANALYZEd before the next
cell, so every cell starts on an empty board. The first cell that fails, in
the runner or in acceptance, keeps its election and stops the sweep: the next
cell would usually fail the same way, and the index lets the rerun pick up
from there. Generation elections (wlprep-) are never touched.

Plan keys: face, arms (elgamal, paillier-off), modes (a list of live, bulk),
levels, reps, sample_size (bulk), strict, cleanup_after.
"""

import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import console
import helios_env

RESULTS_DIR = helios_env.WORKLOAD_ROOT / 'results'   # where runner.py writes
INDEX = RESULTS_DIR / 'sweep_index.jsonl'
ARM_SCHEME = {'elgamal': 'elgamal', 'paillier-off': 'paillier'}
MODES = ('live', 'bulk')
DISK_FACTOR = 2.5


def cells(plan):
  """The plan's cells, in run order."""
  arms = list(plan['arms'])
  modes = list(plan['modes'])
  out = []
  for N in sorted(plan['levels']):
    for rep in range(plan.get('reps', 1)):
      flip = rep % 2 == 1
      for arm in (arms[::-1] if flip else arms):
        for mode in (modes[::-1] if flip else modes):
          out.append({'face': plan['face'], 'arm': arm, 'N': N, 'rep': rep,
                      'mode': mode,
                      'sample_size': (plan.get('sample_size', 10)
                                      if mode == 'bulk' else None)})
  return out


def cell_key(c):
  key = f'{c["face"]}|{c["arm"]}|n={c["N"]}|r={c["rep"]}|{c["mode"]}'
  if c['mode'] == 'bulk':
    key += f'|s={c["sample_size"]}'
  return key


def check_plan(plan):
  """Problems with a plan, before anything runs."""
  problems = []
  for k in ('face', 'arms', 'modes', 'levels'):
    if not plan.get(k):
      problems.append(f'plan has no {k}')
  for arm in plan.get('arms') or []:
    if arm not in ARM_SCHEME:
      problems.append(f'unknown arm {arm!r}; expected {", ".join(ARM_SCHEME)}')
  for mode in plan.get('modes') or []:
    if mode not in MODES:
      problems.append(f'unknown mode {mode!r}; expected {", ".join(MODES)}')
  for stale in ('ballots', 'populate'):
    if stale in plan:
      problems.append(f'plan key {stale!r} is gone; use modes: [live, bulk]')
  return problems


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


def vacuum_analyze():
  """
  A plain VACUUM ANALYZE of the whole database, in autocommit (VACUUM cannot
  run inside a transaction block). Returns seconds.
  """
  helios_env.setup_django()
  from django.db import connection
  old = connection.get_autocommit()
  connection.set_autocommit(True)
  try:
    t0 = time.perf_counter()
    with connection.cursor() as c:
      c.execute('VACUUM ANALYZE')
    return time.perf_counter() - t0
  finally:
    connection.set_autocommit(old)


def empty_database(election_uuid):
  """
  After an accepted cell: delete its election (cleanup.delete_elections, which
  only ever matches wl- elections, so wlprep- generation elections stay), then
  VACUUM ANALYZE, so the next cell starts on an empty board.
  """
  import cleanup
  deleted = cleanup.delete_elections([election_uuid])
  return {'deleted': deleted, 'vacuum_s': vacuum_analyze()}


def run_one(c, plan, run_id):
  args = [sys.executable, 'runner.py', '--face', c['face'],
          '--scheme', ARM_SCHEME[c['arm']], '--n', str(c['N']),
          '--rep', str(c['rep']), '--run-id', run_id]
  if c['mode'] == 'bulk':
    args += ['--prepared', '--sample', str(c['sample_size'])]
  else:
    args += ['--live']
  if plan.get('strict'):
    args += ['--strict']
  console.detail(' '.join(args[1:]))
  return subprocess.run(args, cwd=helios_env.WORKLOAD_ROOT).returncode


def _election_uuid(path):
  if not path.exists():
    return None
  for line in path.read_text().splitlines():
    r = json.loads(line)
    if r['metric'] == 'election_created':
      return r['extra'].get('election_uuid')
  return None


def main(argv=None):
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  p.add_argument('--plan', required=True)
  p.add_argument('--cleanup-after', action='store_true', default=None,
                 help='after each accepted cell, delete its election and '
                      'VACUUM ANALYZE (default: the plan\'s cleanup_after)')
  p.add_argument('--dry-run', action='store_true',
                 help='print the order and what would be skipped')
  p.add_argument('--index', default=str(INDEX))
  args = p.parse_args(argv)

  import yaml
  plan = yaml.safe_load(pathlib.Path(args.plan).read_text())
  problems = check_plan(plan)
  if problems:
    for m in problems:
      console.fail(m)
    return 2
  cleanup_after = (args.cleanup_after if args.cleanup_after is not None
                   else bool(plan.get('cleanup_after')))
  cfg = helios_env.load_config('levels.yaml')

  todo = cells(plan)
  done = accepted_keys(args.index)
  console.title(f'SWEEP · {args.plan}')
  console.field('cells', len(todo))
  console.field('already accepted', sum(cell_key(c) in done for c in todo))
  console.field('cleanup after', 'delete + VACUUM ANALYZE' if cleanup_after
                else 'off — elections stay')
  console.field('index', args.index)

  if args.dry_run:
    for c in todo:
      state = 'skip (accepted)' if cell_key(c) in done else 'run'
      console.detail(f'{state:16} {cell_key(c)}')
    return 0

  from emit import make_run_id
  import acceptance

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
    path = RESULTS_DIR / f'{run_id}.jsonl'
    ok = rc == 0 and path.exists() and acceptance.check(str(path), c['N'])
    uuid = _election_uuid(path)

    entry = {'key': key, 'cell': c, 'run_id': run_id, 'jsonl': str(path),
             'exit_code': rc, 'accepted': bool(ok), 'election_uuid': uuid,
             'plan': str(args.plan),
             'at': datetime.datetime.now(datetime.timezone.utc)
                   .strftime('%Y-%m-%dT%H:%M:%SZ')}
    cleanup_error = None
    if ok and cleanup_after and uuid:
      try:
        entry['cleanup'] = empty_database(uuid)
      except Exception as e:
        cleanup_error = f'{type(e).__name__}: {e}'
        entry['cleanup'] = {'error': cleanup_error}
    append_index(entry, args.index)

    if not ok:
      console.fail(f'cell not accepted (runner exit {rc}) — its election is '
                   f'kept and the sweep stopped; rerun to resume from here')
      return 1
    console.ok(f'accepted: {path.name}')
    if cleanup_error:
      console.fail(f'cleanup failed: {cleanup_error} — sweep stopped, so the '
                   f'next cell does not start on a full board')
      return 1
    if 'cleanup' in entry:
      cl = entry['cleanup']
      console.ok(f'deleted {cl["deleted"]} election(s); VACUUM ANALYZE '
                 f'{console.dur(cl["vacuum_s"])}')

  console.section('SWEEP DONE')
  return 0


if __name__ == '__main__':
  sys.exit(main())
