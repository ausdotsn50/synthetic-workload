"""
Bulk off (cast) vs bulk on (insert), from accepted prepared cells.

    uv run --project ../helios-server python compare_modes.py [--index results/sweep_index.jsonl] [--face nle2025]

For each (face, arm, N): median and IQR of each tally-side metric under each
mode, and the relative difference of the medians, (insert - cast) / cast. The
decrypted tallies must be identical across every arm, mode and rep at the
same (face, N): both modes put master[:N] on the board, and a mode that
changed the tally would not be a population method but a bug.

Read-only. No significance test: that choice is still open.
"""

import argparse
import collections
import json
import statistics
import sys

import sweep

# (label, function of a cell's records) -> one value per cell.
def _first(records, metric):
  return next((r for r in records if r['metric'] == metric), None)


def _value(metric):
  def f(records):
    r = _first(records, metric)
    return r['value'] if r else None
  return f


def _agg_per_ballot(records):
  r = _first(records, 'aggregation_time_ns')
  if not r or not (r.get('extra') or {}).get('n_votes'):
    return None
  return r['value'] / r['extra']['n_votes']


METRICS = [
  ('aggregation_time_ns', _value('aggregation_time_ns')),
  ('aggregation per ballot (ns)', _agg_per_ballot),
  ('decryption_factor_time_ns', _value('decryption_factor_time_ns')),
  ('decryption_factor_only_ns', _value('decryption_factor_only_ns')),
  ('dlog_precompute_time_ns', _value('dlog_precompute_time_ns')),
]
MODES = ('cast', 'insert')


def load_cells(index, face=None):
  out = []
  for e in sweep.read_index(index):
    if not e.get('accepted'):
      continue
    with open(e['jsonl']) as f:
      records = [json.loads(line) for line in f if line.strip()]
    created = (_first(records, 'election_created') or {}).get('extra') or {}
    if created.get('ballots') != 'prepared':
      continue
    if face and created.get('ballot_face') != face:
      continue
    res = _first(records, 'result')
    out.append({'face': created.get('ballot_face'), 'arm': created.get('arm'),
                'N': records[0]['N'], 'rep': records[0]['rep'],
                'populate': created.get('populate'), 'records': records,
                'tally': res['value'] if res else None,
                'jsonl': e['jsonl']})
  return out


def _summary(xs):
  xs = sorted(x for x in xs if x is not None)
  if not xs:
    return None
  med = statistics.median(xs)
  if len(xs) >= 2:
    q1, _q2, q3 = statistics.quantiles(xs, n=4, method='inclusive')
    iqr = q3 - q1
  else:
    iqr = 0.0
  return {'n': len(xs), 'median': med, 'iqr': iqr}


def _fmt(v):
  if v is None:
    return '—'
  if v >= 1e9:
    return f'{v / 1e9:.3f} s'
  if v >= 1e6:
    return f'{v / 1e6:.2f} ms'
  if v >= 1e3:
    return f'{v / 1e3:.1f} µs'
  return f'{v:.0f} ns'


def main(argv=None):
  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  p.add_argument('--index', default=str(sweep.INDEX))
  p.add_argument('--face', default=None)
  args = p.parse_args(argv)

  cells = load_cells(args.index, args.face)
  if not cells:
    print('no accepted prepared cells in', args.index)
    return 1

  # Tallies: one per (face, N), across every arm, mode and rep.
  tallies = collections.defaultdict(set)
  for c in cells:
    tallies[(c['face'], c['N'])].add(json.dumps(c['tally']))
  all_same = True
  print('TALLIES — identical across arms, modes and reps at each (face, N)')
  for (face, N), ts in sorted(tallies.items()):
    same = len(ts) == 1
    all_same &= same
    n = sum(1 for c in cells if (c['face'], c['N']) == (face, N))
    print(f'  {face} N={N}: {"identical" if same else "DIFFER"} '
          f'across {n} cell(s)')

  groups = collections.defaultdict(list)
  for c in cells:
    groups[(c['face'], c['arm'], c['N'])].append(c)

  for (face, arm, N), cs in sorted(groups.items()):
    by_mode = {m: [c for c in cs if c['populate'] == m] for m in MODES}
    print()
    print(f'{face} · {arm} · N={N}   '
          + ', '.join(f'{m}: {len(by_mode[m])} rep(s)' for m in MODES))
    print(f'  {"metric":30} {"cast median [IQR]":>24} '
          f'{"insert median [IQR]":>24} {"rel. diff":>10}')
    for label, fn in METRICS:
      s = {m: _summary([fn(c['records']) for c in by_mode[m]]) for m in MODES}
      if not any(s.values()):
        continue          # e.g. the dlog metric under Paillier
      cell = {m: (f'{_fmt(s[m]["median"])} [{_fmt(s[m]["iqr"])}]'
                  if s[m] else '—') for m in MODES}
      rel = ('—' if not (s['cast'] and s['insert']) else
             f'{100 * (s["insert"]["median"] - s["cast"]["median"]) / s["cast"]["median"]:+.1f}%')
      print(f'  {label:30} {cell["cast"]:>24} {cell["insert"]:>24} {rel:>10}')

  return 0 if all_same else 1


if __name__ == '__main__':
  sys.exit(main())
