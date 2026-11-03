"""
Live vs bulk, from accepted cells of the comparison plans.

    uv run --project ../helios-server python compare_modes.py [--index results/sweep_index.jsonl] [--face nle2025]

For each (face, arm, N), each mode's value of every tally-side metric -- the
median when a mode has more than one rep -- and the relative difference
(bulk - live) / live. A bulk cell's tally and decryption run over the same N
ballots as a live one, but the cell differs in three ways at once: N - S
ballots were inserted rather than cast, the worker verified S ballots before
the tally rather than N, and the election is frozen under the set's fixed key
rather than the one Helios generated. A difference reflects all three, not
insertion alone.

The decrypted tallies must be identical across modes at each (face, N): both
modes cast master_ballots[:N], so a mode that changed the tally would not be a
way to fill the board but a bug.

Reads only index entries written with a mode (config/compare_*.yaml and the
other current plans). Read-only. No significance test: that choice is open.
"""

import argparse
import collections
import json
import statistics
import sys

import sweep

MODES = ('live', 'bulk')


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


# (label, unit, function of a cell's records -> one value)
METRICS = [
  ('aggregation_time_ns', 'ns', _value('aggregation_time_ns')),
  ('aggregation per ballot', 'ns', _agg_per_ballot),
  ('decryption_factor_time_ns', 'ns', _value('decryption_factor_time_ns')),
  ('decryption_factor_only_ns', 'ns', _value('decryption_factor_only_ns')),
  ('dlog_precompute_time_ns', 'ns', _value('dlog_precompute_time_ns')),
  ('worker_rss_at_tally_start_bytes', 'bytes',
   _value('worker_rss_at_tally_start_bytes')),
]


def load_cells(index, face=None):
  out = []
  for e in sweep.read_index(index):
    cell = e.get('cell') or {}
    if not e.get('accepted') or cell.get('mode') not in MODES:
      continue
    if face and cell.get('face') != face:
      continue
    with open(e['jsonl']) as f:
      records = [json.loads(line) for line in f if line.strip()]
    res = _first(records, 'result')
    out.append({**cell, 'records': records,
                'tally': res['value'] if res else None, 'jsonl': e['jsonl']})
  return out


def _fmt(v, unit):
  if v is None:
    return '—'
  if unit == 'bytes':
    import console
    return console.size(v)
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
    print('no accepted live or bulk cells in', args.index)
    return 1

  # Tallies: one per (face, N), across every arm, mode and rep.
  tallies = collections.defaultdict(set)
  for c in cells:
    tallies[(c['face'], c['N'])].add(json.dumps(c['tally']))
  all_same = True
  print('TALLIES — identical across modes (and arms, and reps) at each (face, N)')
  for (face, N), ts in sorted(tallies.items()):
    same = len(ts) == 1
    all_same &= same
    modes = sorted({c['mode'] for c in cells if (c['face'], c['N']) == (face, N)})
    print(f'  {face} N={N}: {"identical" if same else "DIFFER"} '
          f'across {", ".join(modes)}')

  groups = collections.defaultdict(list)
  for c in cells:
    groups[(c['face'], c['arm'], c['N'])].append(c)

  for (face, arm, N), cs in sorted(groups.items()):
    by_mode = {m: [c for c in cs if c['mode'] == m] for m in MODES}
    print()
    print(f'{face} · {arm} · N={N}   '
          + ', '.join(f'{m}: {len(by_mode[m])} cell(s)' for m in MODES))
    print(f'  {"metric":32} {"live":>12} {"bulk":>12} {"(bulk-live)/live":>17}')
    for label, unit, fn in METRICS:
      v = {}
      for m in MODES:
        xs = [x for x in (fn(c['records']) for c in by_mode[m]) if x is not None]
        v[m] = statistics.median(xs) if xs else None
      if v['live'] is None and v['bulk'] is None:
        continue          # e.g. the dlog metric under Paillier
      rel = ('—' if v['live'] in (None, 0) or v['bulk'] is None else
             f'{100 * (v["bulk"] - v["live"]) / v["live"]:+.1f}%')
      print(f'  {label:32} {_fmt(v["live"], unit):>12} '
            f'{_fmt(v["bulk"], unit):>12} {rel:>17}')

  return 0 if all_same else 1


if __name__ == '__main__':
  sys.exit(main())
