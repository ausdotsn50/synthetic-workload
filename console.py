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
    elif src == 'harness_derived':
      proc = 'derived'
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
      metric(name, f'{v[0] / 1e6:.2f}', 'ms', _note(records, name))

  # 'browser' per the source taxonomy: a performance.now() reading taken in the
  # booth page, as opposed to helios_instrumentation or harness_derived.
  enc_2a = _vals(records, 'encryption_time_ms', source='browser')
  enc_2b = _vals(records, 'encryption_time_ms', source='node')
  if enc_2a:
    metric('encryption_time_ms', f'{_median(enc_2a):.1f}', 'ms/ballot',
           _note(records, 'encryption_time_ms', f'median of {len(enc_2a)}'))
  if enc_2b:
    metric('encryption_time_ms (node)', f'{_median(enc_2b):.1f}', 'ms/ballot',
           f'n={len(enc_2b)}')

  ct = _vals(records, 'ciphertext_bytes', source='node') or \
      _vals(records, 'ciphertext_bytes')
  pf = _vals(records, 'proof_bytes', source='node') or \
      _vals(records, 'proof_bytes')
  if ct:
    metric('ciphertext_bytes', size(_median(ct)), '',
           _note(records, 'ciphertext_bytes', 'median'))
  if pf:
    metric('proof_bytes', size(_median(pf)), '',
           _note(records, 'proof_bytes', 'median'))
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
           _note(records, 'aggregation_time_ns', f'{agg_per / 1e6:.2f} ms/ballot'))
  # The homomorphic addition on its own. Printed beside its parent because the
  # gap between the two is row loading and ballot parsing, not cryptography --
  # which is the distinction the whole comparison rests on.
  agg_only = _vals(records, 'aggregation_only_ns')
  if agg and agg_only:
    metric('aggregation_only_ns', f'{agg_only[0] / 1e6:.1f}', 'ms',
           _note(records, 'aggregation_only_ns',
                 f'{100 * agg_only[0] / agg[0]:.0f}% of the loop',
                 'homomorphic addition alone'))

  fac = _vals(records, 'decryption_factor_time_ns')
  if fac:
    metric('decryption_factor_time_ns', f'{fac[0] / 1e6:.1f}', 'ms',
           _note(records, 'decryption_factor_time_ns'))
  # Factors without the Chaum-Pedersen proofs, timed on the same pass by a
  # wrapper on sk.decryption_factor. The remainder is the ZKP table's row.
  fac_only = _vals(records, 'decryption_factor_only_ns')
  if fac and fac_only:
    metric('decryption_factor_only_ns', f'{fac_only[0] / 1e6:.1f}', 'ms',
           _note(records, 'decryption_factor_only_ns',
                 f'{100 * fac_only[0] / fac[0]:.0f}% of the loop',
                 'factors alone'))
  # The whole combine_decryptions body, run in the web process and synchronous
  # inside the request. Printed above its two children because it exists to
  # bound them: precompute + lookup should account for it, and a gap that opens
  # between them is work nobody is timing.
  comb = _vals(records, 'decryption_combine_time_ns')
  if comb:
    metric('decryption_combine_time_ns', f'{comb[0] / 1e6:.2f}', 'ms',
           _note(records, 'decryption_combine_time_ns',
                 'precompute + lookup below'))

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
           _note(records, 'dlog_precompute_time_ns',
                 f'{per_entry / 1e3:.1f} µs/entry', f'{entries} entries',
                 f'{100 * pre[0] / comb[0]:.0f}% of combine' if comb else ''))
  look = _vals(records, 'dlog_lookup_time_ns')
  if look:
    # Directly measured inside decrypt_from_factors, not derived by
    # subtracting precompute from combine as it was before Option C.
    metric('dlog_lookup_time_ns', f'{look[0] / 1e6:.2f}', 'ms',
           _note(records, 'dlog_lookup_time_ns', 'directly measured',
                 f'{100 * look[0] / comb[0]:.0f}% of combine' if comb else ''))

  v = _vals(records, 'verification_time_ns')
  if v:
    metric('verification_time_ns', f'{_median(v) / 1e6:.1f}', 'ms/ballot',
           _note(records, 'verification_time_ns', f'median of {len(v)}'))
  v = _vals(records, 'verification_only_ns')
  if v:
    metric('verification_only_ns', f'{_median(v) / 1e6:.1f}', 'ms/ballot',
           _note(records, 'verification_only_ns',
                 f'median of {len(v)}', 'proof checking alone'))

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
        metric(m, f'{v[0] / 1e6:.1f}', 'ms', _note(records, m))
    # Two records per run, one per task; distinguished by the task attribute.
    # Outside the task span, so it is not part of any nesting check.
    for r in records:
      if r['metric'] == 'election_load_time_ns':
        _task = (r.get('extra') or {}).get('task', '')
        metric('election_load_time_ns', f'{r["value"] / 1e6:.1f}', 'ms',
               f'{_task}, outside the task span')
    v = _vals(records, 'celery_dispatch_ns')
    if v:
      metric('celery_dispatch_ns', f'{v[0] / 1e6:.1f}', 'ms',
             'POST to task start, wall clock')

  # ---- flow tier: what the administrator waits for --------------------------
  flow_rows = [('flow_cast_ns', 'cast'),
               ('flow_aggregate_ns', 'aggregate'),
               ('flow_decrypt_factors_ns', 'decrypt'),
               ('flow_combine_ns', 'decrypt, synchronous')]
  if any(_vals(records, m) for m, _ in flow_rows):
    subsection('flow tier — POST to completion observed')
    for m, phase in flow_rows:
      v = _vals(records, m)
      if not v:
        continue
      poll = per_ballot = None
      for r in records:
        if r['metric'] == m:
          poll = r.get('extra', {}).get('poll_interval_ms')
          per_ballot = r.get('extra', {}).get('per_ballot_ns')
      note = phase
      if per_ballot:
        # flow_cast_ns is the only flow phase that scales with N, so the
        # per-ballot rate is what transfers to a larger electorate.
        note += f', {per_ballot / 1e6:.0f} ms/ballot'
      if poll:
        note += f', +/-{poll:.0f} ms poll'
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

  Every column is a metric that was timed directly -- the booth's decorator on
  generateDisjunctiveProof, and Helios's own spans. The operation column is the
  call that CONTAINS the proof work (encryption, verify_and_store, the
  factor-and-proof loop), so the share is proof time over the operation it is
  part of, which is the quantity the operation-tier reference quotes.

  The remainders are deliberately not shown. Reading them off the two columns
  is a subtraction; storing them was a metric with nothing in it.
  """
  def med(metric, **want):
    v = [r['value'] for r in records if r['metric'] == metric
         and all(r.get('extra', {}).get(k) == w for k, w in want.items())]
    return _median(v) if v else None

  enc_total = med('encryption_time_ms', source='browser')
  enc_proof = med('encryption_proof_ms', source='browser')
  ver_total, ver_only = med('verification_time_ns'), med('verification_only_ns')
  dec_total = med('decryption_factor_time_ns')
  dec_proof = med('decryption_proof_ns')
  if not any((enc_proof, ver_only, dec_proof)):
    return

  section('ZKP — proof work as a share of the operation containing it')
  _p(f'  {"where":<26} {"operation":>12} {"ZKP":>12} {"ZKP share":>11}')
  _p('  ' + '-' * (WIDTH - 4))

  def row(where, total_ms, zkp_ms, note=''):
    share = f'{100 * zkp_ms / total_ms:.0f}%' if (zkp_ms and total_ms) else '—'
    _p(f'  {where:<26} {(f"{total_ms:.1f} ms" if total_ms else "—"):>12} '
       f'{(f"{zkp_ms:.1f} ms" if zkp_ms else "—"):>12} {share:>11}'
       + (f'   {note}' if note else ''))

  def ms(ns_value):
    return ns_value / 1e6 if ns_value else None

  if enc_proof is not None:
    row("voter's browser", enc_total, enc_proof, 'per ballot')
  if ver_only is not None:
    # Measured, not asserted: verification_only_ns isolates proof checking
    # inside the verify_and_store that contains it.
    row('server, at cast', ms(ver_total), ms(ver_only), 'per ballot')
  if dec_proof is not None:
    row('server, at decrypt', ms(dec_total), ms(dec_proof), 'once')


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
