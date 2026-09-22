"""
Console output formatting file for workload iterations.\
"""

import shutil
import statistics
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


def subsection(text):
  """A labelled group inside a section. Lighter than section()."""
  _p()
  _p(f'  {text}')
  _p('  ' + '.' * max(0, WIDTH - 4))


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


def metric(name, value, unit, note=''):
  """Echo one emitted measurement so the run is legible as it happens."""
  line = f'     · {name:<32} {value:>14}  {unit}' + (f'   {note}' if note else '')
  _p(line.rstrip())


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


def _mean(xs):
  return statistics.fmean(xs) if xs else None


def _median(xs):
  return statistics.median(xs) if xs else None


def summary(records, N, stage_walls):
  """Print the measured result of one cell, then project it to larger N."""
  section('MEASURED — this cell')

  # This is the tier the study compares. Everything here changes when the
  # scheme changes; the tiers below are the system around it.
  subsection('operation tier — the cryptographic work')

  # One measurement each, taken inside Helios at election creation for the key
  # this election actually used. A distribution comes from repeating cells.
  for name in ('keygen_time_ns', 'prove_sk_time_ns'):
    v = _vals(records, name)
    if v:
      metric(f'{name} (election)', f'{v[0] / 1e6:.2f}', 'ms',
             'measured in Helios, web process')

  # 'browser' per the source taxonomy: a performance.now() reading taken in the
  # booth page, as opposed to helios_instrumentation or harness_derived.
  enc_2a = _vals(records, 'encryption_time_ms', source='browser')
  enc_2b = _vals(records, 'encryption_time_ms', source='node')
  if enc_2a:
    metric('encryption_time_ms (browser)', f'{_median(enc_2a):.1f}', 'ms/ballot',
           f'n={len(enc_2a)}')
  if enc_2b:
    metric('encryption_time_ms (node)', f'{_median(enc_2b):.1f}', 'ms/ballot',
           f'n={len(enc_2b)}')

  ct = _vals(records, 'ciphertext_bytes', source='node') or \
      _vals(records, 'ciphertext_bytes')
  pf = _vals(records, 'proof_bytes', source='node') or \
      _vals(records, 'proof_bytes')
  if ct:
    metric('ciphertext_bytes (median)', size(_median(ct)), '')
  if pf:
    metric('proof_bytes (median)', size(_median(pf)), '')
  ballot_bytes = None
  if ct and pf:
    ballot_bytes = _median(ct) + _median(pf)
    share = 100 * _median(pf) / ballot_bytes
    metric('ballot total (median)', size(ballot_bytes), '',
           f'proofs {share:.0f}%')

  agg = _vals(records, 'aggregation_time_ns')
  agg_per = None
  n_votes = None
  for r in records:
    if r['metric'] == 'aggregation_time_ns':
      n_votes = r.get('extra', {}).get('n_votes')
  if agg:
    agg_per = agg[0] / max(n_votes or N, 1)
    metric('aggregation_time_ns', f'{agg[0] / 1e6:.1f}', 'ms',
           f'{agg_per / 1e6:.2f} ms/ballot')

  fac = _vals(records, 'decryption_factor_time_ns')
  if fac:
    metric('decryption_factor_time_ns', f'{fac[0] / 1e6:.1f}', 'ms')
  # The parent span of the two dlog metrics below. Printed before them so the
  # containment reads in order: combine total, then what it is made of.
  comb = _vals(records, 'decryption_combine_time_ns')
  if comb:
    metric('decryption_combine_time_ns', f'{comb[0] / 1e6:.2f}', 'ms',
           'contains precompute + lookup')
  pre = _vals(records, 'dlog_precompute_time_ns')
  per_entry = None
  if pre:
    entries = None
    for r in records:
      if r['metric'] == 'dlog_precompute_time_ns':
        entries = (r.get('extra', {}).get('dlog_entries')
                   or r.get('extra', {}).get('num_tallied'))
    per_entry = pre[0] / max(entries or N, 1)
    metric('dlog_precompute_time_ns', f'{pre[0] / 1e6:.2f}', 'ms',
           f'{per_entry / 1e3:.1f} µs/entry, {entries} entries')
  look = _vals(records, 'dlog_lookup_time_ns')
  if look:
    # Directly measured inside decrypt_from_factors, not derived by
    # subtracting precompute from combine as it was before Option C.
    metric('dlog_lookup_time_ns', f'{look[0] / 1e6:.2f}', 'ms', 'measured')

  v = _vals(records, 'verification_time_ns')
  if v:
    metric('verification_time_ns', f'{_median(v) / 1e6:.1f}', 'ms/ballot',
           f'n={len(v)}, Celery worker')

  for r in records:
    if r['metric'] == 'result':
      totals = [sum(q) for q in r['value']] if r['value'] else []
      metric('tally (per-question totals)', str(totals), '')

  # ---- task tier: Celery task entry to exit ---------------------------------
  task_rows = [('task_compute_tally_ns', 'aggregate'),
               ('task_helios_decrypt_ns', 'decrypt')]
  if any(_vals(records, m) for m, _ in task_rows):
    subsection('task tier — Celery task entry to exit')
    for m, phase in task_rows:
      v = _vals(records, m)
      if v:
        metric(m, f'{v[0] / 1e6:.1f}', 'ms', phase)
    v = _vals(records, 'celery_dispatch_ns')
    if v:
      metric('celery_dispatch_ns', f'{v[0] / 1e6:.1f}', 'ms',
             'POST to task start, wall clock')

  # ---- flow tier: what the administrator waits for --------------------------
  flow_rows = [('flow_aggregate_ns', 'aggregate'),
               ('flow_decrypt_factors_ns', 'decrypt'),
               ('flow_combine_ns', 'decrypt, synchronous')]
  if any(_vals(records, m) for m, _ in flow_rows):
    subsection('flow tier — POST to completion observed')
    for m, phase in flow_rows:
      v = _vals(records, m)
      if not v:
        continue
      poll = None
      for r in records:
        if r['metric'] == m:
          poll = r.get('extra', {}).get('poll_interval_ms')
      note = phase + (f', +/-{poll:.0f} ms poll' if poll else '')
      metric(m, f'{v[0] / 1e6:.1f}', 'ms', note)

  _decomposition(records)
  _zkp_split(records)
  _payloads(records, N)

  # ---- operational wall clock ----------------------------------------------
  if stage_walls:
    section('WALL CLOCK — per stage')
    total = sum(stage_walls.values())
    for name, w in stage_walls.items():
      bar = '#' * int(28 * w / total) if total else ''
      _p(f'  {name:<22} {dur(w):>10}  {bar}')
    _p(f'  {"TOTAL":<22} {dur(total):>10}')

  # ---- projection -----------------------------------------------------------
  _projection(N, enc_2a, agg_per, per_entry, ballot_bytes, stage_walls)


def _decomposition(records):
  """
  The aggregate phase split across all three tiers.

  This is the quantity that makes the study system-level rather than a
  benchmark: it shows how much of an administrator's wait is the cryptosystem
  and how much is the system around it.
  """
  def one(metric_name):
    v = [r['value'] for r in records if r['metric'] == metric_name]
    return v[0] if v else None

  flow = one('flow_aggregate_ns')
  task = one('task_compute_tally_ns')
  op = one('aggregation_time_ns')
  if not (flow and task and op):
    return

  section('DECOMPOSITION — aggregate phase')
  # A containing span cannot be shorter than what it contains. If that holds
  # here the run is mismeasured, and printing a negative remainder or a >100%
  # share would present the error as a result. Acceptance fails on this too.
  if not (flow >= task >= op):
    warn(f'ordering violated: flow {flow / 1e6:.1f} / task {task / 1e6:.1f} / '
         f'operation {op / 1e6:.1f} ms — a span is shorter than what it '
         f'contains, so this cell is mismeasured')
    return
  _p(f'  {"flow":<38} {flow / 1e6:>9.1f} ms   POST to observed completion')
  _p(f'  {"  task":<38} {task / 1e6:>9.1f} ms   Celery entry to exit')
  _p(f'  {"    operation":<38} {op / 1e6:>9.1f} ms   the cryptosystem')
  _p('  ' + '-' * (WIDTH - 4))
  _p(f'  {"flow - task  (HTTP, queue, poll)":<38} '
     f'{(flow - task) / 1e6:>9.1f} ms')
  _p(f'  {"task - operation  (ORM, persistence)":<38} '
     f'{(task - op) / 1e6:>9.1f} ms')
  _p(f'  {"cryptosystem share of the phase":<38} '
     f'{100 * op / flow:>9.1f} %')


def _zkp_split(records):
  """
  Where proof work happens, separated from the processing it accompanies.

  Zero-knowledge proofs are the dominant cost in a verifiable election, and
  they are paid in three different places by two different parties. Reporting
  one blended number per stage would hide that.
  """
  def med(metric, **want):
    v = [r['value'] for r in records if r['metric'] == metric
         and all(r.get('extra', {}).get(k) == w for k, w in want.items())]
    return _median(v) if v else None

  enc_only, enc_proof = med('encryption_only_ms'), med('encryption_proof_ms')
  verify = med('verification_time_ns')
  dec_only, dec_proof = med('decryption_factor_only_ns'), med('decryption_proof_ns')
  if not any((enc_proof, verify, dec_proof)):
    return

  section('ZKP vs PROCESSING — where proof work happens')
  _p(f'  {"where":<26} {"processing":>12} {"ZKP":>12} {"ZKP share":>11}')
  _p('  ' + '-' * (WIDTH - 4))

  def row(where, proc_ms, zkp_ms, note=''):
    total = (proc_ms or 0) + (zkp_ms or 0)
    share = f'{100 * zkp_ms / total:.0f}%' if (zkp_ms and total) else '—'
    _p(f'  {where:<26} {(f"{proc_ms:.1f} ms" if proc_ms else "—"):>12} '
       f'{(f"{zkp_ms:.1f} ms" if zkp_ms else "—"):>12} {share:>11}'
       + (f'   {note}' if note else ''))

  if enc_proof is not None:
    row("voter's browser", enc_only, enc_proof, 'per ballot')
  if verify is not None:
    # EncryptedVote.verify does little besides disjunctive-proof checking, so
    # it sits in the ZKP column whole rather than being split.
    row('server, at cast', None, verify / 1e6, 'per ballot, all ZKP')
  if dec_proof is not None:
    row('server, at decrypt', (dec_only or 0) / 1e6, dec_proof / 1e6, 'once')


def _payloads(records, N):
  """What crosses the wire and what ends up on the board."""
  WHAT = [
    ('cast_payload_bytes',       'voter -> server, per ballot'),
    ('election_json_bytes',      'server -> voter, once per session'),
    ('encrypted_tally_bytes',    'on the board, after tally'),
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

  section('PAYLOADS — bytes, not just time')
  for m, what in WHAT:
    if m in vals:
      _p(f'  {m:<26} {size(vals[m]):>10}   {what}')

  # Board total. Only the cast payload multiplies by N; the rest are per
  # election, which is the point of measuring them separately.
  cast = vals.get('cast_payload_bytes')
  if cast:
    fixed = sum(vals.get(m, 0) for m in
                ('encrypted_tally_bytes', 'decryption_factors_bytes',
                 'decryption_proofs_bytes'))
    total = cast * N + fixed
    _p('  ' + '-' * (WIDTH - 4))
    _p(f'  {"board total at N=" + str(N):<26} {size(total):>10}   '
       f'cast x {N} + tally + factors + proofs')
    if fixed:
      _p(f'  {"":<26} {"":>10}   the fixed part is '
         f'{100 * fixed / total:.1f}% here, and does not grow with N')


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
