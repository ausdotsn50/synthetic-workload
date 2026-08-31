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


def summary(records, N, stage_walls):
  """Print the measured result of one cell, then project it to larger N."""
  section('MEASURED — this cell')

  keygen = _vals(records, 'keygen_time_ns')
  if keygen:
    metric('keygen_time_ns (median)', f'{statistics.median(keygen) / 1e6:.2f}',
           'ms', f'n={len(keygen)}')
  psk = _vals(records, 'prove_sk_time_ns')
  if psk:
    metric('prove_sk_time_ns (median)', f'{statistics.median(psk) / 1e6:.2f}',
           'ms', f'n={len(psk)}')

  enc_2a = _vals(records, 'encryption_time_ms', source='selenium')
  enc_2b = _vals(records, 'encryption_time_ms', source='node')
  if enc_2a:
    metric('encryption_time_ms (browser)', f'{_mean(enc_2a):.1f}', 'ms/ballot',
           f'n={len(enc_2a)}')
  if enc_2b:
    metric('encryption_time_ms (node)', f'{_mean(enc_2b):.1f}', 'ms/ballot',
           f'n={len(enc_2b)}')

  ct = _vals(records, 'ciphertext_bytes', source='node') or \
      _vals(records, 'ciphertext_bytes')
  pf = _vals(records, 'proof_bytes', source='node') or \
      _vals(records, 'proof_bytes')
  if ct:
    metric('ciphertext_bytes (mean)', size(_mean(ct)), '')
  if pf:
    metric('proof_bytes (mean)', size(_mean(pf)), '')
  ballot_bytes = None
  if ct and pf:
    ballot_bytes = _mean(ct) + _mean(pf)
    share = 100 * _mean(pf) / ballot_bytes
    metric('ballot total (mean)', size(ballot_bytes), '',
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

  ver = _vals(records, 'proof_verification_time_ns')
  if ver and agg:
    pure = ver[0] - agg[0]
    metric('proof_verification (pure)', ns(pure), '',
           f'{pure / max(n_votes or N, 1) / 1e9:.2f} s/ballot')

  fac = _vals(records, 'decryption_factor_time_ns')
  if fac:
    metric('decryption_factor_time_ns', f'{fac[0] / 1e6:.1f}', 'ms')
  pre = _vals(records, 'dlog_precompute_time_ns')
  per_entry = None
  if pre:
    entries = None
    for r in records:
      if r['metric'] == 'dlog_precompute_time_ns':
        entries = r.get('extra', {}).get('dlog_entries')
    per_entry = pre[0] / max(entries or N, 1)
    metric('dlog_precompute_time_ns', f'{pre[0] / 1e6:.2f}', 'ms',
           f'{per_entry / 1e3:.1f} µs/entry, {entries} entries')
  look = _vals(records, 'dlog_lookup_time_ns')
  if look:
    metric('dlog_lookup_time_ns', f'{look[0] / 1e6:.2f}', 'ms', 'DERIVED')

  rss = None
  for r in records:
    rss = r.get('extra', {}).get('peak_rss_bytes') or rss
  if rss:
    metric('peak_rss_bytes', size(rss), '')

  for r in records:
    if r['metric'] == 'result':
      totals = [sum(q) for q in r['value']] if r['value'] else []
      metric('tally (per-question totals)', str(totals), '')

  # ---- operational wall clock ----------------------------------------------
  if stage_walls:
    section('WALL CLOCK — per stage')
    total = sum(stage_walls.values())
    for name, w in stage_walls.items():
      bar = '#' * int(28 * w / total) if total else ''
      _p(f'  {name:<22} {dur(w):>10}  {bar}')
    _p(f'  {"TOTAL":<22} {dur(total):>10}')

  # ---- projection -----------------------------------------------------------
  _projection(N, enc_2b, agg_per, per_entry, ballot_bytes, stage_walls)


def _projection(N, enc_2b, agg_per_ns, dlog_per_entry_ns, ballot_bytes,
                stage_walls):
  """
  Extrapolate this cell's measured per-ballot rates to larger electorates.

  Linear extrapolation is defensible for exactly the quantities extrapolated
  here: encryption is per-ballot independent work, aggregation is N modular
  multiplications, dlog precompute is Theta(N) by construction (spec 0.1), and
  storage is N x ballot size. It is NOT defensible for anything involving memory
  pressure or database growth, which is why those are not projected.
  """
  if not (enc_2b or agg_per_ns):
    return

  section('CAPACITY PROJECTION — extrapolated from this cell')
  detail('Linear in N. Valid for per-ballot work only; ignores memory pressure,')
  detail('DB growth and thermal throttling. Treat as an order-of-magnitude gate.')
  _p()

  enc_ms = _mean(enc_2b) if enc_2b else None
  cast_per = None
  if stage_walls and N:
    # Cast + Celery verification only. Node encryption is excluded because it is
    # already projected in its own column; adding it here would double-count.
    cast_wall = (stage_walls.get('stage 2b cast', 0)
                 + stage_walls.get('stage 2b verify', 0))
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
