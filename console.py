"""
Console output formatting file for workload iterations.

Re-print a run's summary from its JSONL:
    python console.py results/<run_id>.jsonl
"""

import json
import shutil
import statistics
import sys
import time

WIDTH = min(shutil.get_terminal_size((80, 24)).columns, 78)


def _p(s=''):
  print(s, flush=True)


# ---- formatting -------------------------------------------------------------

def dur(seconds):
  """Human duration from seconds."""
  if seconds is None:
    return '—'
  if seconds < 1:
    return f'{seconds * 1000:.0f} ms'
  if seconds < 60:
    return f'{seconds:.1f} s'
  if seconds < 3600:
    return f'{seconds / 60:.1f} min'
  if seconds < 86400:
    return f'{seconds / 3600:.1f} h'
  return f'{seconds / 86400:.1f} d'


def ns(v):
  return dur(v / 1e9) if v is not None else '—'


def size(nbytes):
  if nbytes is None:
    return '—'
  for unit, div in (('GiB', 1 << 30), ('MiB', 1 << 20), ('KiB', 1 << 10)):
    if nbytes >= div:
      return f'{nbytes / div:.1f} {unit}'
  return f'{nbytes:.0f} B'


# ---- structure --------------------------------------------------------------

def title(text):
  _p()
  _p('=' * WIDTH)
  _p(f'  {text}')
  _p('=' * WIDTH)


def section(text):
  _p()
  head = f'--- {text} '
  _p(head + '-' * max(0, WIDTH - len(head)))


def field(key, value, w=18):
  _p(f'  {key:<{w}} {value}')


def step(msg):
  _p(f'  -> {msg}')


def detail(msg):
  _p(f'     {msg}')


def ok(msg):
  _p(f'  [ok]   {msg}')


def warn(msg):
  _p(f'  [warn] {msg}')


def fail(msg):
  _p(f'  [FAIL] {msg}')


class Stage:
  """Wall-clock a pipeline stage and bracket it with a banner."""

  def __init__(self, name):
    self.name = name
    self.wall = None

  def __enter__(self):
    section(self.name)
    self._t0 = time.perf_counter()
    return self

  def __exit__(self, exc_type, *_):
    self.wall = time.perf_counter() - self._t0
    if exc_type is None:
      ok(f'complete in {dur(self.wall)}')
    else:
      fail(f'failed after {dur(self.wall)}')
    return False


class Progress:
  """
  Rate + ETA for a loop whose per-item cost is the thing we care about.

  Printed after each reported item, never between a Timer's t0 and t1.
  """

  def __init__(self, total, label, every=None):
    self.total = max(int(total), 1)
    self.label = label
    self.t0 = time.perf_counter()
    self.every = every or max(1, self.total // 10)

  def tick(self, done):
    if done % self.every and done != self.total:
      return
    el = time.perf_counter() - self.t0
    rate = done / el if el > 0 else 0
    eta = (self.total - done) / rate if rate > 0 else None
    detail(f'{self.label} {done}/{self.total}  '
           f'{rate:.2f}/s  elapsed {dur(el)}  eta {dur(eta)}')

  def done(self):
    el = time.perf_counter() - self.t0
    per = el / self.total
    detail(f'{self.label} finished — {dur(el)} total, {dur(per)}/item')
    return el


# ---- end-of-run summary -----------------------------------------------------

def _vals(records, metric_name, stage=None, source=None):
  out = []
  for r in records:
    if r['metric'] != metric_name:
      continue
    if stage and r['stage'] != stage:
      continue
    if source and r.get('extra', {}).get('source') != source:
      continue
    if isinstance(r['value'], (int, float)):
      out.append(r['value'])
  return out


def _where(records, metric_name):
  """
  'stage · where it ran' for one metric, e.g. 'decrypt · Helios web'.

  Under the instrumented design a metric's emission point is no longer where
  its work happened -- everything from Helios arrives in one lump at the
  sidecar join, after the last stage. So the stage and the process have to be
  stated on the line rather than implied by where it is printed.
  """
  hits = [r for r in records if r['metric'] == metric_name]
  if not hits:
    return ''
  # If a metric name carries records from more than one source, the in-Helios
  # measurement is the authoritative one. Picking arbitrarily would print a
  # provenance that contradicts the number beside it, which is worse than
  # printing none.
  hits.sort(key=lambda r:
            r.get('extra', {}).get('source') != 'helios_instrumentation')

  stage = proc = None
  for r in hits[:1]:
    stage = r.get('stage')
    src = r.get('extra', {}).get('source')
    if src == 'browser':
      proc = 'browser'
    elif src == 'helios_instrumentation':
      try:
        from drivers.measure_join import PROCESS_OF
        proc = PROCESS_OF.get(metric_name, 'Helios')
      except Exception:
        proc = 'Helios'
    elif src:
      proc = 'harness'
    break
  if not stage:
    return ''
  return f'{stage} · {proc}' if proc else stage


def _note(records, metric_name, *rest):
  """'<stage · process>, <extra notes>' — the label first, details after."""
  parts = [p for p in (_where(records, metric_name), *rest) if p]
  return ', '.join(parts)


def _mean(xs):
  return statistics.fmean(xs) if xs else None


def _median(xs):
  return statistics.median(xs) if xs else None


def _first(records, metric_name):
  return next((r for r in records if r['metric'] == metric_name), None)


def _paired(records, a, b, key):
  """Per-item a - b, matched on extra[key]. Items missing either are skipped."""
  def by(metric_name):
    return {r['extra'][key]: r['value'] for r in records
            if r['metric'] == metric_name
            and r.get('extra', {}).get(key) is not None}
  va, vb = by(a), by(b)
  return [va[k] - vb[k] for k in va if k in vb]


def _n_votes(records, N):
  """Ballots tallied, from the aggregation record; N if absent."""
  r = _first(records, 'aggregation_time_ns')
  return max((r or {}).get('extra', {}).get('n_votes') or N, 1)


def _dlog_entries(records, N):
  r = _first(records, 'dlog_precompute_time_ns')
  e = (r or {}).get('extra', {})
  return max(e.get('dlog_entries') or e.get('num_tallied') or N, 1)


def _ms(v):
  return f'{v:.2f} ms' if v < 10 else f'{v:.1f} ms'


def _row(label, value, note=''):
  _p(f'  {label:<26} {value:>10}   {note}'.rstrip())


def summary(records, N):
  """Print the measured result of one cell, then project it to larger N."""
  # Stage walls from their records, in file order.
  stage_walls = {r['extra']['stage_name']: r['value'] / 1e9 for r in records
                 if r['metric'] == 'stage_wall_time_ns'}

  # One section per class of metric, and each value is printed once. A timing
  # that spans several classes (encryption, verify_and_store, the aggregation
  # and factor loops) is shown as its parts, not as a total.
  _crypto_ops(records, N)
  _zkp(records)
  _payloads(records)
  _payload_timing(records, N)

  res = _first(records, 'result')
  if res:
    section('RESULT — decrypted tally')
    totals = [sum(q) for q in res['value']] if res['value'] else []
    _row('per-question totals', str(totals))

  # ---- operational wall clock ----------------------------------------------
  if stage_walls:
    section('WALL CLOCK — per stage')
    total = sum(stage_walls.values())
    for name, w in stage_walls.items():
      bar = '#' * int(28 * w / total) if total else ''
      _p(f'  {name:<22} {dur(w):>10}  {bar}')
    _p(f'  {"TOTAL":<22} {dur(total):>10}')

  # ---- projection -----------------------------------------------------------
  # Whole-phase rates: a projection asks how long each phase takes.
  enc = _vals(records, 'encryption_time_ms', source='browser')
  agg = _vals(records, 'aggregation_time_ns')
  agg_per = agg[0] / _n_votes(records, N) if agg else None
  pre = _vals(records, 'dlog_precompute_time_ns')
  per_entry = pre[0] / _dlog_entries(records, N) if pre else None
  ct, pf = _vals(records, 'ciphertext_bytes'), _vals(records, 'proof_bytes')
  ballot_bytes = _median(ct) + _median(pf) if ct and pf else None
  _projection(N, enc, agg_per, per_entry, ballot_bytes, stage_walls)


def _crypto_ops(records, N):
  """
  The cryptographic work alone. Proofs are in the ZKP section, and the
  parsing around the work is in payload-driven timing.
  """
  rows = []

  # Once per election, for the key this election actually used.
  kg = _vals(records, 'keygen_time_ns')
  if kg:
    rows.append(('keygen_time_ns', _ms(kg[0] / 1e6),
                 _note(records, 'keygen_time_ns')))

  # Encryption minus proof generation, paired per ballot.
  enc = _paired(records, 'encryption_time_ms', 'encryption_proof_ms', 'sample')
  if enc:
    rows.append(('encryption, excl. proof', _ms(_median(enc)),
                 _note(records, 'encryption_time_ms', 'derived',
                       f'median of {len(enc)}')))

  # Homomorphic addition alone, inside the aggregation loop.
  agg_only = _vals(records, 'aggregation_only_ns')
  if agg_only:
    per = agg_only[0] / _n_votes(records, N)
    rows.append(('aggregation_only_ns', _ms(agg_only[0] / 1e6),
                 _note(records, 'aggregation_only_ns',
                       f'{per / 1e6:.2f} ms/ballot')))

  # Factors alone, inside the factor-and-proof loop.
  fac_only = _vals(records, 'decryption_factor_only_ns')
  if fac_only:
    rows.append(('decryption_factor_only_ns', _ms(fac_only[0] / 1e6),
                 _note(records, 'decryption_factor_only_ns')))

  pre = _vals(records, 'dlog_precompute_time_ns')
  if pre:
    entries = _dlog_entries(records, N)
    rows.append(('dlog_precompute_time_ns', _ms(pre[0] / 1e6),
                 _note(records, 'dlog_precompute_time_ns',
                       f'{pre[0] / entries / 1e3:.1f} µs/entry',
                       f'{entries} entries')))

  look = _vals(records, 'dlog_lookup_time_ns')
  if look:
    rows.append(('dlog_lookup_time_ns', _ms(look[0] / 1e6),
                 _note(records, 'dlog_lookup_time_ns')))

  # Paillier's decryption, which has no dlog step.
  dec = _vals(records, 'decryption_time_ns')
  if dec:
    rows.append(('decryption_time_ns', _ms(dec[0] / 1e6),
                 _note(records, 'decryption_time_ns')))

  if not rows:
    return
  section('CRYPTOGRAPHIC OPERATIONS — crypto only, proofs excluded')
  for label, value, note in rows:
    _row(label, value, note)


def _zkp(records):
  """
  Proof generation and checking, separated from the operations they sit in.

  The share is proof time over the call that contains it. That total is not
  printed: its other part is in its own section.
  """
  def med(metric, **want):
    v = [r['value'] for r in records if r['metric'] == metric
         and all(r.get('extra', {}).get(k) == w for k, w in want.items())]
    return _median(v) if v else None

  def share(part, whole, what):
    return f'{100 * part / whole:.0f}% of {what}' if part and whole else ''

  rows = []

  # keygen and prove_sk are adjacent spans with no span around the pair, so
  # key setup is their sum.
  sk = med('prove_sk_time_ns')
  if sk is not None:
    kg = med('keygen_time_ns')
    rows.append(('prove_sk_time_ns', _ms(sk / 1e6),
                 _note(records, 'prove_sk_time_ns',
                       share(sk, kg and kg + sk, 'key setup'))))

  enc_proof = med('encryption_proof_ms', source='browser')
  if enc_proof is not None:
    n = len(_vals(records, 'encryption_proof_ms', source='browser'))
    rows.append(('encryption_proof_ms', _ms(enc_proof),
                 _note(records, 'encryption_proof_ms', f'median of {n}',
                       share(enc_proof,
                             med('encryption_time_ms', source='browser'),
                             'encryption'))))

  ver_only = med('verification_only_ns')
  if ver_only is not None:
    n = len(_vals(records, 'verification_only_ns'))
    rows.append(('verification_only_ns', _ms(ver_only / 1e6),
                 _note(records, 'verification_only_ns', f'median of {n}',
                       share(ver_only, med('verification_time_ns'),
                             'verify_and_store'))))

  # Not emitted: the factor loop minus the factors alone, one of each per cell.
  ft = _first(records, 'decryption_factor_time_ns')
  fo = _first(records, 'decryption_factor_only_ns')
  if ft and fo:
    dec_proof = ft['value'] - fo['value']
    rows.append(('decryption_proof_ns', _ms(dec_proof / 1e6),
                 _note(records, 'decryption_factor_time_ns', 'derived',
                       share(dec_proof, ft['value'], 'the factor loop'))))

  if not rows:
    return
  section('ZKP PROCESSING — proof generation and checking')
  for label, value, note in rows:
    _row(label, value, note)


def _payloads(records):
  """Payload sizes: what the scheme produces, on the wire and in storage."""
  WHAT = [
    ('ciphertext_bytes',         'per ballot, median'),
    ('proof_bytes',              'per ballot, median'),
    ('cast_payload_bytes',       'voter -> server, per ballot'),
    ('election_json_bytes',      'server -> voter, once per session'),
    ('decryption_factors_bytes', 'trustee -> board'),
    ('decryption_proofs_bytes',  'trustee -> board'),
  ]
  vals = {}
  for m, _ in WHAT:
    v = [r['value'] for r in records if r['metric'] == m]
    if v:
      vals[m] = _median(v)
  if not vals:
    return

  section('PAYLOAD SIZES — on the wire and in storage')
  for m, what in WHAT:
    if m in vals:
      _row(m, size(vals[m]), what)
    # The ballot's crypto content, right after its two parts.
    if m == 'proof_bytes' and {'ciphertext_bytes', 'proof_bytes'} <= set(vals):
      ballot = vals['ciphertext_bytes'] + vals['proof_bytes']
      pct = 100 * vals['proof_bytes'] / ballot
      _row('ballot total', size(ballot),
           f'ciphertext + proof, proofs {pct:.0f}%')

def _payload_timing(records, N):
  """
  Server time that grows with payload size, not with the crypto. Scales with
  the ballot total in PAYLOAD SIZES.

  Derived here from records already emitted; nothing new is recorded.
  """
  rows = []

  # Parse: the aggregation loop minus the homomorphic addition inside it.
  agg, agg_only = (_first(records, 'aggregation_time_ns'),
                   _first(records, 'aggregation_only_ns'))
  if agg and agg_only:
    per = (agg['value'] - agg_only['value']) / _n_votes(records, N)
    rows.append(('parse, per ballot', _ms(per / 1e6),
                 'reading a ballot from storage'))

  # Persistence: verify_and_store minus the proof checking inside it, paired
  # on the same ballot. What remains is the two row writes.
  diffs = _paired(records, 'verification_time_ns', 'verification_only_ns',
                  'cast_vote_id')
  if diffs:
    rows.append(('persistence, per ballot', _ms(_median(diffs) / 1e6),
                 f'writing a ballot to storage (x2), median of '
                 f'{len(diffs)} pairs'))

  if not rows:
    return
  section('PAYLOAD-DRIVEN TIMING — derived, not emitted')
  for label, value, note in rows:
    _row(label, value, note)


def _projection(N, enc_samples, agg_per_ns, dlog_per_entry_ns, ballot_bytes,
                stage_walls):
  """
  Extrapolate this cell's measured per-ballot rates to larger electorates.

  Linear extrapolation is defensible for exactly the quantities extrapolated
  here: encryption is per-ballot independent work, aggregation is N modular
  multiplications, dlog precompute is Theta(N) by construction (spec 0.1), and
  storage is N x ballot size. It is NOT defensible for anything involving memory
  pressure or database growth, which is why those are not projected.
  """
  if not (enc_samples or agg_per_ns):
    return

  section('CAPACITY PROJECTION — extrapolated from this cell')
  detail('Linear in N. Valid for per-ballot work only; ignores memory pressure,')
  detail('DB growth and thermal throttling. Treat as an order-of-magnitude gate.')
  _p()

  enc_ms = _mean(enc_samples) if enc_samples else None
  cast_per = None
  if stage_walls and N:
    # Cast (HTTP login+cast+cast_confirm) + Celery verification drain, per
    # ballot. Browser encryption is excluded because it is already projected
    # in its own column; adding it here would double-count.
    cast_wall = (stage_walls.get('stage 2 cast', 0)
                 + stage_walls.get('stage 2 verify', 0))
    cast_per = cast_wall / max(N, 1) if cast_wall else None

  hdr = f'  {"N":>9}  {"encrypt":>10}  {"cast+verify":>12}  {"aggregate":>10}  {"dlog":>9}  {"storage":>10}'
  _p(hdr)
  _p('  ' + '-' * (len(hdr) - 2))

  for target in (100, 1_000, 10_000, 100_000, 250_000):
    enc = dur(enc_ms * target / 1000) if enc_ms else '—'
    cast = dur(cast_per * target) if cast_per else '—'
    agg = dur(agg_per_ns * target / 1e9) if agg_per_ns else '—'
    dl = dur(dlog_per_entry_ns * target / 1e9) if dlog_per_entry_ns else '—'
    st = size(ballot_bytes * target) if ballot_bytes else '—'
    _p(f'  {target:>9,}  {enc:>10}  {cast:>12}  {agg:>10}  {dl:>9}  {st:>10}')

  _p()
  if enc_ms:
    # What fits in a working day of encryption?
    per_day = int(86400 / (enc_ms / 1000))
    per_8h = int(28800 / (enc_ms / 1000))
    detail(f'At {enc_ms:.0f} ms/ballot this machine encrypts ~{per_8h:,} ballots '
           f'in 8 h, ~{per_day:,} in 24 h.')
  if ballot_bytes:
    gb = (100 << 30) / ballot_bytes
    detail(f'At {size(ballot_bytes)}/ballot, 100 GiB of board holds '
           f'~{int(gb):,} ballots.')


if __name__ == '__main__':
  path = sys.argv[1]
  with open(path) as f:
    records = [json.loads(line) for line in f if line.strip()]
  r0 = records[0]
  N = r0['N']
  _p(f'{path} — scheme {r0["scheme"]}, N={N}, rep {r0["rep"]}')
  summary(records, N)
