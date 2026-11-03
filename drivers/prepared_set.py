"""
On-disk layout of a prepared-ballot set, and the provenance it is checked
against.

    <prepared.dir>/<face>/<scheme>/
      key.json                          the fixed trustee key (drivers/fixed_key.py)
      manifest.json                     what the set was made from
      chunks/0000000-0000100.jsonl.gz   one ballot per line, [start, end)
      validation.json                   the last `prepare.py validate` result

<scheme> is the cryptosystem, elgamal or paillier. The CRT-proofs setting
touches neither keys nor ballots, so the paillier-off arm reads `paillier`.

A chunk line is {"ballot_index": i, "plaintext": [[...], ...],
"encrypted_answers": [...]}, encrypted_answers exactly as
stage1_encrypt.sample_encryptions streams them. There is no election uuid or
hash in it: Stage 2 adds both when it builds the vote (stage2_cast.py:52-54),
so one set serves every election frozen under the same key.

The chunk files are the source of truth for which indices exist. A chunk is
complete when its final name exists; it is written as a .part and committed by
os.link, so a half-written chunk never carries a final name.
"""

import datetime
import gzip
import hashlib
import html.parser
import json
import os
import pathlib
import re

import helios_env

SCHEMES = ('elgamal', 'paillier')
DEFAULT_DIR = 'prepared'
CHUNK_RE = re.compile(r'^(\d{7})-(\d{7})\.jsonl\.gz$')


def now_utc():
  return datetime.datetime.now(datetime.timezone.utc).strftime(
    '%Y-%m-%dT%H:%M:%SZ')


# ---- layout -----------------------------------------------------------------

def root(cfg=None):
  cfg = cfg if cfg is not None else helios_env.load_config('levels.yaml')
  d = (cfg.get('prepared') or {}).get('dir') or DEFAULT_DIR
  return (helios_env.WORKLOAD_ROOT / os.path.expanduser(d)).resolve()


def set_dir(face_key, scheme, cfg=None):
  if scheme not in SCHEMES:
    raise ValueError(f'scheme {scheme!r} has no prepared set; expected one of '
                     f'{", ".join(SCHEMES)} (paillier-off reads paillier)')
  return root(cfg) / face_key / scheme


def key_path(d):
  return pathlib.Path(d) / 'key.json'


def manifest_path(d):
  return pathlib.Path(d) / 'manifest.json'


def validation_path(d):
  return pathlib.Path(d) / 'validation.json'


def chunks_dir(d):
  return pathlib.Path(d) / 'chunks'


def chunk_name(start, end):
  return f'{start:07d}-{end:07d}.jsonl.gz'


# ---- chunks -----------------------------------------------------------------

def completed_chunks(d):
  """
  [(start, end, path)] of every committed chunk, in index order. Raises if two
  overlap: that set holds some index twice and must not be used.
  """
  cd = chunks_dir(d)
  out = []
  if cd.exists():
    for p in cd.iterdir():
      m = CHUNK_RE.match(p.name)
      if m:
        s, e = int(m.group(1)), int(m.group(2))
        if e <= s:
          raise ValueError(f'{p}: empty or reversed range')
        out.append((s, e, p))
  out.sort()
  for (s0, e0, p0), (s1, _e1, p1) in zip(out, out[1:]):
    if s1 < e0:
      raise ValueError(f'chunks overlap: {p0.name} and {p1.name}')
  return out


def contiguous_count(chunks):
  """How many indices from 0 are covered without a gap: the usable count."""
  n = 0
  for s, e, _p in chunks:
    if s != n:
      break
    n = e
  return n


def plan_chunks(chunks, count, chunk_size):
  """
  The [start, end) ranges still to generate for 0..count-1: gaps left by an
  interrupted run first, then new chunks after the last one. Deterministic in
  its inputs, so a rerun plans the same ranges an interrupted run did.
  """
  todo = []
  cursor = 0

  def fill(a, b):
    for s in range(a, b, chunk_size):
      todo.append((s, min(s + chunk_size, b)))

  for s, e, _p in chunks:
    if s > cursor:
      fill(cursor, min(s, count))
    cursor = max(cursor, e)
    if cursor >= count:
      break
  if cursor < count:
    fill(cursor, count)
  return [(s, e) for s, e in todo if s < e]


def read_chunk(path):
  """Yields each line of a chunk as a dict."""
  with gzip.open(path, 'rt', encoding='utf-8') as f:
    for line in f:
      if line.strip():
        yield json.loads(line)


def iter_ballots(d, start=0, stop=None):
  """
  Yields the prepared ballots with start <= ballot_index < stop, in index
  order, one at a time: a set too large to hold in memory still streams.
  """
  chunks = completed_chunks(d)
  have = contiguous_count(chunks)
  stop = have if stop is None else stop
  if stop > have:
    raise ValueError(f'{d} holds {have} contiguous ballots; {stop} requested')
  for s, e, p in chunks:
    if e <= start or s >= stop:
      continue
    for rec in read_chunk(p):
      if start <= rec['ballot_index'] < stop:
        yield rec


def sha256_file(path):
  h = hashlib.sha256()
  with open(path, 'rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
      h.update(block)
  return h.hexdigest()


# ---- provenance -------------------------------------------------------------

def questions_sha256(questions):
  """sha256 of the canonical questions JSON (sorted keys, no whitespace)."""
  canonical = json.dumps(questions, sort_keys=True, separators=(',', ':'))
  return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class _ScriptSrcs(html.parser.HTMLParser):
  """<script src=...> in document order. Commented-out tags never reach
  handle_starttag, which is the point: vote.html keeps its uncompressed
  script list inside <!-- -->."""

  def __init__(self):
    super().__init__()
    self.srcs = []

  def handle_starttag(self, tag, attrs):
    if tag == 'script':
      src = dict(attrs).get('src')
      if src:
        self.srcs.append(src)


def booth_js_hashes(helios_path=None):
  """
  {src: sha256} for every script booth/vote.html loads. /booth/ is served
  straight from heliosbooth/ (urls.py, `serve`), so the checkout's files are
  the bytes the browser runs.
  """
  hp = pathlib.Path(helios_path or helios_env.helios_path())
  booth = hp / 'heliosbooth'
  parser = _ScriptSrcs()
  parser.feed((booth / 'vote.html').read_text(encoding='utf-8'))
  if not parser.srcs:
    raise RuntimeError(f'no <script src> found in {booth / "vote.html"}')
  out = {}
  for src in parser.srcs:
    if '://' in src or src.startswith('//'):
      raise RuntimeError(f'booth loads {src} from off the checkout; its bytes '
                         f'cannot be pinned')
    out[src] = sha256_file(booth / src)
  return out


# ---- use in a cell -------------------------------------------------------------

class SetUnusable(RuntimeError):
  pass


# The manifest fields a prepared cell's provenance is defined by. Kept on the
# cell's records, so acceptance can check them after the set has moved on.
IDENTITY = ('face', 'questions_sha256', 'master_seed', 'booth_js', 'key_size',
            'key_fingerprint', 'scheme', 'helios_commit', 'generator_version',
            'count')


def identity_problems(m, *, face_key, questions, seed, booth, key_size):
  """
  How a manifest (or its snapshot on a cell's records) disagrees with the
  current face, master seed, booth JS and Helios key size. Each one is fatal:
  the cell would cast ballots that are not the ones it claims. A different
  Helios commit is not here -- that is a warning, see commit_warning.
  """
  problems = []
  for k, v in (('face', face_key),
               ('questions_sha256', questions_sha256(questions)),
               ('master_seed', seed), ('booth_js', booth),
               ('key_size', key_size)):
    if m.get(k) != v:
      problems.append(f'manifest {k} is {m.get(k)!r}, current {v!r}')
  return problems


def commit_warning(m, helios_commit):
  if m.get('helios_commit') != helios_commit:
    return (f'set prepared at Helios {m.get("helios_commit")}, running at '
            f'{helios_commit}')
  return None


def snapshot_for_cell(face_key, questions, scheme, N, cfg):
  """
  Check a prepared set can serve a cell of N ballots, before anything runs,
  and return the snapshot the cell records. Raises SetUnusable on a set made
  from another face, seed, booth or key size; on a manifest and key.json that
  disagree; on fewer than N contiguous ballots; or on a validation that did
  not pass or does not reach N.
  """
  from drivers import fixed_key

  d = set_dir(face_key, scheme, cfg)
  kp = key_path(d)
  try:
    key = fixed_key.load(kp)
  except (FileNotFoundError, ValueError) as e:
    raise SetUnusable(str(e))
  manifest = read_json(manifest_path(d))
  if manifest is None:
    raise SetUnusable(f'no manifest in {d}: nothing is prepared for '
                      f'{face_key}/{scheme}')
  validation = read_json(validation_path(d))

  booth = booth_js_hashes()
  problems = identity_problems(
    manifest, face_key=face_key, questions=questions, seed=cfg['seed'],
    booth=booth, key_size=fixed_key.key_size(scheme))
  for k, v in (('key_fingerprint', key.fingerprint), ('key_size', key.key_size),
               ('scheme', key.scheme)):
    if manifest.get(k) != v:
      problems.append(f'manifest {k} is {manifest.get(k)!r}, key.json {v!r}')

  have = contiguous_count(completed_chunks(d))
  if have < N:
    problems.append(f'the set holds {have} ballots; the cell needs {N}')
  if validation is None:
    problems.append(f'{validation_path(d)} missing: run prepare.py validate')
  else:
    if not validation.get('passed'):
      problems.append('the last validation FAILED; the set is unusable')
    if (validation.get('validated_count') or 0) < N:
      problems.append(f'validated_count is {validation.get("validated_count")}; '
                      f'the cell needs {N}: run prepare.py validate')
    if validation.get('key_fingerprint') != key.fingerprint:
      problems.append('validation.json was made under a different key')
  if problems:
    raise SetUnusable(f'prepared set {d} cannot serve this cell: '
                      + '; '.join(problems))

  helios_commit = helios_env.git_commit(helios_env.helios_path())
  z = validation.get('zero_failure_bound') or {}
  return {
    'dir': str(d),
    'key_path': str(kp),
    'key_fingerprint': key.fingerprint,
    'manifest_sha256': sha256_file(manifest_path(d)),
    'manifest': {k: manifest.get(k) for k in IDENTITY},
    'validation': {k: validation.get(k) for k in
                   ('passed', 'validated_count', 'validated_at',
                    'manifest_sha256', 'helios_commit')},
    'validation_bound': {k: z.get(k) for k in
                         ('n', 'n_effective', 'bound', 'confidence', 'census')},
    'warnings': [w for w in [commit_warning(manifest, helios_commit)] if w],
  }


def read_json(path):
  path = pathlib.Path(path)
  return json.loads(path.read_text()) if path.exists() else None


def write_json(path, doc):
  """Atomic replace, so a reader never sees a half-written manifest."""
  path = pathlib.Path(path)
  tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
  with open(tmp, 'w') as f:
    f.write(json.dumps(doc, sort_keys=True, indent=2) + '\n')
    f.flush()
    os.fsync(f.fileno())
  os.replace(tmp, path)
