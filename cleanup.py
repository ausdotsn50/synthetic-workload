"""
Remove artifacts left by workload runs.

    uv run --project ../helios-server python cleanup.py                  # dry run
    uv run --project ../helios-server python cleanup.py --yes            # drop failed runs
    uv run --project ../helios-server python cleanup.py --yes --results all --ballots --vacuum

DRY RUN BY DEFAULT. Nothing is deleted without --yes.

SCOPE: only elections whose short_name starts with 'wl-' (the prefix runner.py
assigns) and only files under results/. A hand-made election, or anything else in
the database, is never touched.

WHY THIS EXISTS
---------------
Leftover elections do not corrupt a later cell — every stage is scoped by
election_uuid and each cell mints its own keypair, so measurements cannot bleed
across. What accumulates is bulk:

  * Postgres rows. Spec §3.8 calls for a VACUUM between cells; an unbounded pile
    of dead elections is what makes that necessary.
  * Encrypted-ballot JSONL. At the nle2025 face this is ~926 KiB per ballot —
    roughly 9 GiB at N = 10,000, per cell. This is what fills a disk.
  * Half-finished measurement files. A cell that dies at Stage 2b leaves a
    perfectly valid JSONL containing real Stage 0-2a numbers and no tally.
    These are the common case during development, and they are the ones worth
    distinguishing rather than blanket-deleting.

RUN CLASSIFICATION
------------------
A run is COMPLETE if its JSONL contains a `result` record — the decrypted tally,
which only Stage 4 emits. That is the same signal acceptance.py treats as the
real correctness check, so "complete" here means the same thing it means there.

Anything else is INCOMPLETE (interrupted, or failed mid-pipeline) or EMPTY
(aborted before the first emit). The default --yes deletes EMPTY and INCOMPLETE
and keeps COMPLETE, because a completed run is data and a failed one is litter.
Pass --results all to wipe everything, or --results none to keep every file and
clean only the database.
"""

import argparse
import collections
import json
import pathlib
import sys

import helios_env

PREFIX = 'wl-'


# ---- inspection -------------------------------------------------------------

def find_elections(keep_suffix=None):
  helios_env.setup_django()
  from helios.models import Election
  from helios.datatypes.djangofield import LDObjectField

  # DEFER every LDObjectField on Election.
  #
  # Those columns run through LDObjectField.from_db_value on *fetch*, which
  # deserializes against a hard-coded ElGamal type hint — public_key is
  # `LDObjectField(type_hint='legacy/EGPublicKey')`, whose STRUCTURED_FIELDS are
  # g/p/q/y. The wl-paillier-* rows in this database hold a Paillier public key
  # ({g, n} or {g, g_prime, h, n}), so the converter raises KeyError: 'y' and
  # merely SELECTing the row explodes — before a single thing is deleted.
  #
  # That is precisely backwards for this script: a row the ORM can no longer
  # load is the litter cleanup exists to remove. Deferring keeps the converter
  # from ever running. Nothing here reads a key, a tally or a result — only
  # short_name, created_at, frozen_at and the pk that .delete() needs — and the
  # cascade to Voter/CastVote is a fast delete that does not materialize those
  # rows either.
  #
  # Derived from the model rather than hand-listed so a new LDObjectField cannot
  # silently reintroduce the crash.
  ld_fields = [f.name for f in Election._meta.get_fields()
               if isinstance(f, LDObjectField)]

  # objects_with_deleted, not objects: ElectionManager (the default manager)
  # filters out soft-deleted rows, and a soft-deleted wl- election is still a
  # full set of Voter/CastVote rows taking up space. Hiding it here would make
  # it permanently unreachable by the only thing that hard-deletes it.
  qs = (Election.objects_with_deleted
        .filter(short_name__startswith=PREFIX)
        .defer(*ld_fields)
        .order_by('created_at'))
  els = list(qs)
  if keep_suffix:
    els = [e for e in els if not e.short_name.endswith(keep_suffix)]
  return els


def describe_elections(elections):
  helios_env.setup_django()
  from helios.models import Voter, VoterFile, CastVote
  rows = []
  for e in elections:
    rows.append({
      'election': e,
      'voters': Voter.objects.filter(election=e).count(),
      'votes': CastVote.objects.filter(voter__election=e).count(),
      'files': VoterFile.objects.filter(election=e).count(),
      'frozen': bool(e.frozen_at),
    })
  return rows


def classify_runs():
  """
  Group results/ by run_id and label each run EMPTY / INCOMPLETE / COMPLETE.

  Ballot files are attached to their run so they are deleted or kept together —
  orphaning a 9 GiB ballot file from the measurements that describe it helps
  nobody.
  """
  d = helios_env.WORKLOAD_ROOT / 'results'
  if not d.exists():
    return {}

  runs = collections.defaultdict(
    lambda: {'measure': None, 'ballots': [], 'records': 0, 'state': 'EMPTY',
             'bytes': 0, 'last': None})

  for p in sorted(d.glob('*.jsonl')):
    name = p.name[:-len('.jsonl')]
    if '-ballots-' in name:
      run_id = name.split('-ballots-')[0]
      runs[run_id]['ballots'].append(p)
      runs[run_id]['bytes'] += p.stat().st_size
      continue

    run_id = name
    r = runs[run_id]
    r['measure'] = p
    r['bytes'] += p.stat().st_size

    if p.stat().st_size == 0:
      r['state'] = 'EMPTY'
      continue

    recs = []
    for line in p.open():
      line = line.strip()
      if not line:
        continue
      try:
        recs.append(json.loads(line))
      except json.JSONDecodeError:
        pass          # truncated final write; the rest of the file still counts
    r['records'] = len(recs)
    r['last'] = f"{recs[-1]['stage']}/{recs[-1]['metric']}" if recs else None
    # Stage 4 is the only emitter of `result`, so its presence means the cell ran
    # all the way through decryption.
    r['state'] = 'COMPLETE' if any(x['metric'] == 'result' for x in recs) \
        else 'INCOMPLETE'

  return dict(runs)


# ---- reporting --------------------------------------------------------------

def report(rows, runs):
  print(f'{"election":34} {"frozen":>7} {"voters":>7} {"votes":>7} {"files":>6}')
  print('-' * 66)
  for r in rows:
    print(f'{r["election"].short_name:34} {str(r["frozen"]):>7} '
          f'{r["voters"]:>7} {r["votes"]:>7} {r["files"]:>6}')
  if not rows:
    print('(no wl- elections)')

  print()
  print(f'{"run_id":30} {"state":11} {"recs":>6} {"size":>10}  last stage')
  print('-' * 78)
  for run_id in sorted(runs):
    r = runs[run_id]
    mib = r['bytes'] / (1 << 20)
    size = f'{mib:.1f} MiB' if mib >= 1 else f'{r["bytes"]:,} B'
    nb = f'  (+{len(r["ballots"])} ballot file)' if r['ballots'] else ''
    print(f'{run_id:30} {r["state"]:11} {r["records"]:>6} {size:>10}  '
          f'{r["last"] or "-"}{nb}')
  if not runs:
    print('(no result files)')


# ---- main -------------------------------------------------------------------

def main(argv=None):
  ap = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter)
  ap.add_argument('--yes', action='store_true', help='actually delete')
  ap.add_argument('--results', choices=('none', 'incomplete', 'all'),
                  default='incomplete',
                  help='which measurement files to remove (default: incomplete)')
  ap.add_argument('--ballots', action='store_true',
                  help='also remove encrypted-ballot files of deleted runs')
  ap.add_argument('--vacuum', action='store_true',
                  help='VACUUM ANALYZE afterwards (spec §3.8)')
  ap.add_argument('--keep', default=None, metavar='RUN_ID',
                  help='preserve this run and its election')
  args = ap.parse_args(argv)

  keep_suffix = args.keep[-4:] if args.keep else None
  elections = find_elections(keep_suffix=keep_suffix)
  rows = describe_elections(elections)
  runs = classify_runs()

  report(rows, runs)

  # which runs' files are in scope
  doomed = []
  for run_id, r in runs.items():
    if args.keep and run_id.endswith(keep_suffix):
      continue
    if args.results == 'all' or \
       (args.results == 'incomplete' and r['state'] in ('EMPTY', 'INCOMPLETE')):
      doomed.append(run_id)

  kept = [r for r in runs if r not in doomed]
  print()
  print(f'elections to delete : {len(rows)}')
  print(f'runs to delete      : {len(doomed)}'
        + (f'   (keeping {len(kept)})' if kept else ''))

  if not args.yes:
    print('\nDRY RUN — nothing deleted. Re-run with --yes to proceed.')
    if any(runs[r]['state'] == 'COMPLETE' for r in kept):
      print('Completed runs are kept by default; --results all removes them too.')
    return 0

  # ---- delete ---------------------------------------------------------------
  helios_env.setup_django()
  from django.db import transaction

  for r in rows:
    with transaction.atomic():
      # Cascades to Voter, CastVote, VoterFile, Trustee via FK on_delete.
      r['election'].delete()
  print(f'\ndeleted {len(rows)} elections')

  freed = 0
  nfiles = 0
  for run_id in doomed:
    r = runs[run_id]
    targets = [r['measure']] if r['measure'] else []
    if args.ballots:
      targets += r['ballots']
    for p in targets:
      if p and p.exists():
        freed += p.stat().st_size
        p.unlink()
        nfiles += 1
  print(f'deleted {nfiles} files ({freed / (1 << 20):.1f} MiB reclaimed)')

  orphan_ballots = [p for run_id in doomed for p in runs[run_id]['ballots']
                    if p.exists()]
  if orphan_ballots:
    mib = sum(p.stat().st_size for p in orphan_ballots) / (1 << 20)
    print(f'NOTE: {len(orphan_ballots)} ballot files left in place '
          f'({mib:.1f} MiB) — pass --ballots to remove them')

  if args.vacuum:
    from django.db import connection
    # Autocommit: VACUUM cannot run inside a transaction block.
    old = connection.get_autocommit()
    connection.set_autocommit(True)
    with connection.cursor() as c:
      c.execute('VACUUM ANALYZE')
    connection.set_autocommit(old)
    print('VACUUM ANALYZE done')

  return 0


if __name__ == '__main__':
  sys.exit(main())
