"""
Prepared ballots: the fixed key, the encrypted set, and its validation.

    uv run --project ../helios-server python prepare.py keys     --face F --scheme S
    uv run --project ../helios-server python prepare.py ballots  --face F --scheme S --count M --workers K [--cpus 16-27]
    uv run --project ../helios-server python prepare.py validate --face F --scheme S [--sample 300] [--workers K]

A cell's tally and decryption must run at full N, but encrypting every one of
the N ballots in the booth costs ~95 s per ballot (Paillier, nle2025 face, lab
server). The ballots outside the live sample are therefore encrypted ONCE,
here, ahead of the runs, under one fixed key per arm, and the pipeline only
reads them. Layout: drivers/prepared_set.py. Key: drivers/fixed_key.py.

Nothing here is a measurement. Generation reuses the measured encryption path
-- stage1_encrypt.sample_encryptions, the booth's own HELIOS.EncryptedAnswer in
headless Chrome -- and throws its timings away. Validation calls Helios's own
verification, tally and decryption code, untimed.

Exit status: 0 done, 1 validation failed, 2 refused.
"""

import argparse
import bisect
import fcntl
import json
import math
import os
import pathlib
import platform
import queue
import random
import re
import secrets
import signal
import sys
import threading
import time
import traceback

# Generation and validation are not measurements. Helios's spans record
# whenever HELIOS_MEASURE_PATH is set, even without an election uuid
# (measure.record writes election_uuid "None"), so the variable is dropped
# before Django loads -- here and in every worker spawned from here. The web
# process and the Celery worker keep theirs: what the generation election makes
# there is keyed on its own uuid, and no cell ever joins it.
os.environ.pop('HELIOS_MEASURE_PATH', None)

import console
import helios_env
from drivers import fixed_key
from drivers import prepared_set as ps
from generator import votes as votes_gen

# Bumped when the chunk line format or how a ballot is produced changes. A set
# made by another version is refused rather than extended.
GENERATOR_VERSION = 1
DEFAULT_CHUNK = 100

# On the first validation every one of these is proof-checked, plus the sample.
FIRST_RUN_ALL = 100
# Randomly sampled ballots per validation, spread across every chunk.
DEFAULT_SAMPLE = 300
# For the zero-failure bound recorded in validation.json.
CONFIDENCE = 0.95
# Ballots tallied homomorphically and decrypted in the prefix check.
PREFIX_MAX = 200

# Generation elections are named so cleanup.py, which only ever touches
# short_names starting 'wl-', never deletes one from under a run. There is one
# per (face, scheme); it is reused by later extends and by validate, and made
# again if it is gone.
GEN_PREFIX = 'wlprep'


class Refused(RuntimeError):
  pass


# ---- guards -----------------------------------------------------------------

def require_clean_helios(path=None):
  """
  The Helios commit every prepared artifact is stamped with. Refuses a dirty
  or unreadable checkout: a commit hash does not describe a dirty tree, and a
  ballot set from an unknown commit cannot be traced to the code that made it.
  """
  path = path or helios_env.helios_path()
  commit, dirty = helios_env.git_commit(path), helios_env.git_is_dirty(path)
  if not commit or dirty is None:
    raise Refused(f'cannot read the git state of {path}; prepared ballots must '
                  f'come from a known Helios commit')
  if dirty:
    raise Refused(f'{path} has uncommitted changes. Prepared ballots must come '
                  f'from a known commit: commit or stash, then rerun.')
  return commit


def pin_cpus(cpus):
  """
  --cpus pins the whole process tree -- this process, its workers, their
  chromedrivers and Chromes -- by re-executing under taskset, so it is in place
  before anything is spawned and visible in ps. Linux only; ignored on macOS.
  """
  if not cpus:
    return
  if not sys.platform.startswith('linux'):
    console.warn(f'--cpus {cpus} ignored: taskset is Linux-only')
    return
  if not re.fullmatch(r'[0-9,\-]+', cpus):
    raise Refused(f'--cpus {cpus!r} is not a taskset CPU list')
  if os.environ.get('WL_PREPARE_PINNED') != cpus:
    os.environ['WL_PREPARE_PINNED'] = cpus
    os.execvp('taskset', ['taskset', '-c', cpus, sys.executable, *sys.argv])
  console.ok(f'pinned to CPUs {cpus} '
             f'({len(os.sched_getaffinity(0))} logical CPUs)')


class SetLock:
  """
  One prepare.py run per set at a time: ballots and validate both read the
  chunk directory and write the manifest. flock is released by the kernel when
  the holder dies, so a killed run never leaves the set locked.
  """

  def __init__(self, d):
    self.path = pathlib.Path(d) / '.lock'

  def __enter__(self):
    self.path.parent.mkdir(parents=True, exist_ok=True)
    self.fh = open(self.path, 'w')
    try:
      fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      self.fh.close()
      raise Refused(f'another prepare.py run holds {self.path}')
    return self

  def __exit__(self, *exc):
    fcntl.flock(self.fh, fcntl.LOCK_UN)
    self.fh.close()
    return False


# ---- worker pool --------------------------------------------------------------
#
# Each worker leads its own process group, so it, its chromedriver and its
# Chrome can be stopped together, and a watchdog thread stops that group the
# moment the parent is gone -- by Ctrl-C, SIGTERM or SIGKILL alike. A worker
# whose parent is gone never commits a chunk, so an interrupted run leaves only
# .part files, which the rerun deletes and redoes.

def _kill_group(pgid, grace_s=5.0):
  # PermissionError counts as gone: macOS answers EPERM, not ESRCH, for a
  # group whose only members are unreaped zombies.
  gone = (ProcessLookupError, PermissionError)
  try:
    os.killpg(pgid, signal.SIGTERM)
  except gone:
    return
  deadline = time.time() + grace_s
  while time.time() < deadline:
    try:
      os.killpg(pgid, 0)
    except gone:
      return
    time.sleep(0.1)
  try:
    os.killpg(pgid, signal.SIGKILL)
  except gone:
    pass


def _watchdog(parent_pid):
  while True:
    if os.getppid() != parent_pid:
      _kill_group(os.getpgrp())
      os._exit(1)
    time.sleep(1.0)


def _worker_main(kind, jobq, resq, parent_pid):
  os.setpgrp()
  threading.Thread(target=_watchdog, args=(parent_pid,), daemon=True).start()
  fn = {'encrypt': _encrypt_chunk, 'check': _check_sampled}[kind]
  while True:
    job = jobq.get()
    if job is None:
      return
    try:
      resq.put({'ok': True, 'job': job['id'], 'result': fn(job)})
    except BaseException as e:
      resq.put({'ok': False, 'job': job['id'],
                'error': f'{type(e).__name__}: {e}',
                'trace': traceback.format_exc()})
      if not isinstance(e, Exception):
        return


def run_pool(kind, jobs, workers, on_result):
  """
  Run `jobs` across `workers` spawned processes; on_result(job, result) is
  called in this process as each finishes. The first failure stops the pool
  and is raised.

  Checks with one worker run in-process. Encryption always gets a spawned
  worker, even alone: its Chrome then belongs to a group that is stopped with
  it, however this process dies.
  """
  if not jobs:
    return
  for i, j in enumerate(jobs):
    j['id'] = i
  if workers <= 1 and kind == 'check':
    fn = {'encrypt': _encrypt_chunk, 'check': _check_sampled}[kind]
    for j in jobs:
      on_result(j, fn(j))
    return

  import multiprocessing
  # spawn, not fork: each worker opens its own database connection and
  # chromedriver rather than inheriting this process's.
  ctx = multiprocessing.get_context('spawn')
  jobq, resq = ctx.Queue(), ctx.Queue()
  for j in jobs:
    jobq.put(j)
  n = min(workers, len(jobs))
  for _ in range(n):
    jobq.put(None)
  procs = [ctx.Process(target=_worker_main,
                       args=(kind, jobq, resq, os.getpid()))
           for _ in range(n)]

  def on_term(signum, frame):
    raise KeyboardInterrupt(f'signal {signum}')
  old_term = signal.signal(signal.SIGTERM, on_term)
  try:
    for p in procs:
      p.start()
    done = 0
    while done < len(jobs):
      try:
        msg = resq.get(timeout=1.0)
      except queue.Empty:
        dead = [p for p in procs if p.exitcode not in (None, 0)]
        if dead:
          raise RuntimeError(f'worker pid {dead[0].pid} exited with '
                             f'{dead[0].exitcode} before finishing its job')
        continue
      if not msg['ok']:
        raise RuntimeError(f'job {msg["job"]} failed: {msg["error"]}\n'
                           f'{msg["trace"]}')
      on_result(jobs[msg['job']], msg['result'])
      done += 1
    for p in procs:
      p.join()
  finally:
    signal.signal(signal.SIGTERM, old_term)
    for p in procs:
      if p.is_alive():
        _kill_group(p.pid)
        p.join(timeout=5)
      if p.is_alive():
        # Not yet its own group leader when the pool stopped.
        p.kill()
        p.join(timeout=5)


# ---- the generation election --------------------------------------------------

def _generation_election_problem(uuid, scheme, questions, key):
  """None if the recorded generation election can still be used, else why."""
  from helios.models import Election
  e = Election.objects.filter(uuid=uuid).first()
  if e is None:
    return 'it no longer exists'
  if not e.frozen_at:
    return 'it is not frozen'
  if e.crypto_scheme != scheme:
    return f'it is {e.crypto_scheme}'
  if e.public_key is None or fixed_key.fingerprint(e.public_key) != key.fingerprint:
    return 'it is not frozen under the saved key'
  if ps.questions_sha256(e.questions) != ps.questions_sha256(questions):
    return 'its questions are not this face'
  return None


def generation_election(d, manifest, face_key, scheme, questions, key, cfg):
  """
  The election generation encrypts against and validation verifies against:
  Stage 0 configure with 1 voter, install_fixed_key, freeze -- the same order a
  prepared cell uses. Reused when the manifest's one still fits.
  """
  helios_env.setup_django()
  from drivers import stage0_setup
  import runner

  log = console.detail
  gen = manifest.get('generation_election') or {}
  if gen.get('uuid'):
    why = _generation_election_problem(gen['uuid'], scheme, questions, key)
    if why is None:
      console.ok(f'reusing generation election {gen["short_name"]} '
                 f'({gen["uuid"]})')
      return gen['uuid']
    console.warn(f'generation election {gen.get("short_name")} unusable: '
                 f'{why}; making a new one')

  import preflight
  base_url = helios_env.helios_url()
  if not preflight._http_ok(base_url):
    raise Refused(f'no Helios server at {base_url}; the generation election is '
                  f'made through its HTTP API')

  short_name = f'{GEN_PREFIX}-{face_key}-{scheme}-{secrets.token_hex(2)}'
  ablation = runner.resolve_ablation(scheme)
  console.step(f'creating generation election {short_name}')
  uuid = stage0_setup.configure(
    base_url=base_url, short_name=short_name,
    name=f'Workload prepared-ballot generation, {face_key} {scheme}',
    questions=questions, n_voters=1, scheme=scheme, ablation=ablation,
    log=log)
  stage0_setup.install_fixed_key(uuid, ps.key_path(d), log=log)
  stage0_setup.freeze(base_url=base_url, election_uuid=uuid, log=log)
  stage0_setup.check_fixed_key(uuid, ps.key_path(d), log=log)

  manifest['generation_election'] = {'uuid': uuid, 'short_name': short_name,
                                     'created_at': ps.now_utc()}
  ps.write_json(ps.manifest_path(d), manifest)
  return uuid


# ---- keys ---------------------------------------------------------------------

def cmd_keys(args, cfg):
  d = ps.set_dir(args.face, args.scheme, cfg)
  path = ps.key_path(d)
  console.title(f'PREPARE · fixed key · {args.face} / {args.scheme}')
  console.field('key', path)
  if path.exists():
    raise Refused(f'{path} already exists; every prepared ballot in {d} '
                  f'depends on it. Refusing to overwrite.')
  commit = require_clean_helios()

  t0 = time.perf_counter()
  key = fixed_key.write_new(path, args.scheme, commit)
  console.ok(f'generated in {console.dur(time.perf_counter() - t0)} '
             f'(not a measurement)')

  # Round trip: what loads back must re-serialize to the same bytes, or a
  # cell would install a key that differs from the one the ballots were made
  # under.
  if not fixed_key.roundtrip_ok(path):
    bad = path.with_name(path.name + '.failed-roundtrip')
    path.rename(bad)
    raise RuntimeError(f'key.json does not round-trip byte for byte; moved to '
                       f'{bad}')
  console.ok('round trip: load and re-serialize is byte-identical')
  problems = fixed_key.check_consistent(fixed_key.load(path))
  if problems:
    raise RuntimeError('saved key is inconsistent: ' + '; '.join(problems))
  console.ok('secret key, public key and proof belong together')

  console.field('scheme', key.scheme)
  console.field('key_size', key.key_size)
  console.field('fingerprint', key.fingerprint)
  console.field('helios commit', commit)
  return 0


# ---- ballots ------------------------------------------------------------------

def _manifest_identity(face_key, questions, scheme, key, seed, chunk_size,
                       commit, booth):
  """The fields a set is defined by. An extend must match every one."""
  return {
    'face': face_key,
    'questions_sha256': ps.questions_sha256(questions),
    'n_questions': len(questions),
    'n_answers': sum(len(q['answers']) for q in questions),
    'scheme': scheme,
    'key_fingerprint': key.fingerprint,
    'key_size': key.key_size,
    'master_seed': seed,
    'chunk_size': chunk_size,
    'helios_commit': commit,
    'booth_js': booth,
    'generator_version': GENERATOR_VERSION,
  }


def _mismatches(manifest, want):
  return [f'{k}: set has {manifest.get(k)!r}, this run {v!r}'
          for k, v in want.items() if manifest.get(k) != v]


def _refresh_manifest(d, manifest, made=None):
  """
  Re-read the chunk directory into the manifest and write it. `made` maps a
  chunk this run committed to what is known about its making -- the host --
  which validate needs to show every machine's chunks were sampled. A chunk
  found on disk without that (committed by a run killed before it could
  record it) is listed with host null.
  """
  known = {c['file']: c for c in manifest.get('chunks', [])}
  chunks = []
  for s, e, p in ps.completed_chunks(d):
    rel = f'chunks/{p.name}'
    c = known.get(rel)
    if not c:
      c = {'file': rel, 'start': s, 'end': e, 'sha256': ps.sha256_file(p),
           'bytes': p.stat().st_size, 'host': None}
    # Also for a chunk another worker's refresh already listed: results
    # arrive one at a time, files land whenever.
    if made and rel in made:
      c.update(made[rel])
    chunks.append(c)
  manifest['chunks'] = chunks
  manifest['count'] = ps.contiguous_count(ps.completed_chunks(d))
  manifest['updated_at'] = ps.now_utc()
  ps.write_json(ps.manifest_path(d), manifest)


def _encrypt_chunk(job):
  """
  One chunk, in a worker: the booth encrypts the master plaintexts for
  [start, end) exactly as Stage 1 does, and the result is rewritten to the
  prepared line format and committed under its final name.
  """
  import gzip
  from drivers import stage1_encrypt

  start, end = job['start'], job['end']
  final = pathlib.Path(job['final'])
  part = final.with_name(f'{final.name}.{job["token"]}.part')
  raw = final.with_name(f'.{final.name}.{job["token"]}.raw.jsonl')
  tag = f'[{final.name[:-len(".jsonl.gz")]}]'
  t0 = time.perf_counter()
  committed = False
  try:
    # warmup=0 and the timings dropped: generation is not a measurement.
    stage1_encrypt.sample_encryptions(
      base_url=job['base_url'], election_uuid=job['election_uuid'],
      ballots=job['plaintexts'], scheme=job['scheme'], out_path=str(raw),
      headless=job['headless'], warmup=0,
      log=lambda m: console.detail(f'{tag} {m}'))

    n = 0
    with open(part, 'wb') as fh:
      # mtime=0 and no filename: the gzip bytes depend on the ballots alone.
      with gzip.GzipFile(filename='', fileobj=fh, mode='wb', mtime=0) as gz:
        for rec in stage1_encrypt.load_encrypted(raw):
          if rec['ballot_index'] != n:
            raise RuntimeError(f'{tag} ballot {n} came back as '
                               f'{rec["ballot_index"]}')
          if len(rec['encrypted_answers']) != job['n_questions']:
            raise RuntimeError(f'{tag} ballot {start + n} has '
                               f'{len(rec["encrypted_answers"])} answers')
          line = {'ballot_index': start + n, 'plaintext': job['plaintexts'][n],
                  'encrypted_answers': rec['encrypted_answers']}
          gz.write((json.dumps(line, separators=(',', ':')) + '\n')
                   .encode('utf-8'))
          n += 1
      fh.flush()
      os.fsync(fh.fileno())
    if n != end - start:
      raise RuntimeError(f'{tag} {n} ballots encrypted, {end - start} planned')

    # An orphaned worker never commits; the rerun redoes this chunk.
    if os.getppid() != job['parent_pid']:
      raise RuntimeError(f'{tag} parent gone; not committing')
    try:
      # link, not rename: the first writer of a range wins and a second one can
      # never replace it, so no index is ever held twice.
      os.link(part, final)
      committed = True
    except FileExistsError:
      committed = False
  finally:
    raw.unlink(missing_ok=True)
    part.unlink(missing_ok=True)
  return {'start': start, 'end': end, 'committed': committed,
          'seconds': time.perf_counter() - t0, 'host': platform.node()}


def cmd_ballots(args, cfg, faces):
  pin_cpus(args.cpus)
  face = faces[args.face]
  questions = votes_gen.build_questions(face)
  seed = cfg['seed']
  d = ps.set_dir(args.face, args.scheme, cfg)

  console.title(f'PREPARE · ballots · {args.face} / {args.scheme}')
  console.field('set', d)
  console.field('target count', args.count)
  console.field('workers', args.workers)

  commit = require_clean_helios()
  key = fixed_key.load(ps.key_path(d))
  if key.scheme != args.scheme:
    raise Refused(f'{ps.key_path(d)} holds a {key.scheme} key')
  booth = ps.booth_js_hashes()

  with SetLock(d):
    manifest = ps.read_json(ps.manifest_path(d))
    chunks = ps.completed_chunks(d)
    if manifest is None and chunks:
      raise Refused(f'{ps.chunks_dir(d)} holds chunks but there is no manifest; '
                    f'their provenance is unknown')

    chunk_size = (args.chunk_size or (manifest or {}).get('chunk_size')
                  or DEFAULT_CHUNK)
    want = _manifest_identity(args.face, questions, args.scheme, key, seed,
                              chunk_size, commit, booth)
    if manifest is None:
      manifest = {'format': 1, **want, 'count': 0, 'chunks': [],
                  'created_at': ps.now_utc()}
      ps.chunks_dir(d).mkdir(parents=True, exist_ok=True)
    else:
      bad = _mismatches(manifest, want)
      if bad:
        raise Refused('this run would not extend the set it found -- '
                      + '; '.join(bad))
    manifest['workload_commit'] = helios_env.git_commit(helios_env.WORKLOAD_ROOT)
    _refresh_manifest(d, manifest)

    # Anything uncommitted is from an interrupted run: redone, never resumed.
    stale = (list(ps.chunks_dir(d).glob('*.part'))
             + list(ps.chunks_dir(d).glob('.*.raw.jsonl')))
    for p in stale:
      p.unlink(missing_ok=True)
    if stale:
      console.warn(f'removed {len(stale)} uncommitted file(s) from an '
                   f'interrupted run; their chunks are redone')

    have = manifest['count']
    plan = ps.plan_chunks(ps.completed_chunks(d), args.count, chunk_size)
    console.field('already prepared', have)
    console.field('chunks to make', f'{len(plan)} '
                  f'({sum(e - s for s, e in plan)} ballots, chunk size '
                  f'{chunk_size})')
    if not plan:
      console.ok(f'nothing to do: the set holds {have} ballots')
      return 0

    uuid = generation_election(d, manifest, args.face, args.scheme, questions,
                               key, cfg)
    master = votes_gen.master_ballots(seed, questions, max(e for _s, e in plan))
    token = secrets.token_hex(3)
    jobs = [{'start': s, 'end': e, 'plaintexts': master[s:e],
             'final': str(ps.chunks_dir(d) / ps.chunk_name(s, e)),
             'token': token, 'parent_pid': os.getpid(),
             'base_url': helios_env.helios_url(), 'election_uuid': uuid,
             'scheme': args.scheme, 'headless': not args.headed,
             'n_questions': len(questions)} for s, e in plan]

    console.section('ENCRYPTING (booth, headless Chrome; timings discarded)')
    t0 = time.perf_counter()
    per_ballot = []

    def on_result(job, r):
      rel = f'chunks/{ps.chunk_name(r["start"], r["end"])}'
      _refresh_manifest(d, manifest,
                        made={rel: {'host': r['host']}} if r['committed']
                        else None)
      n = r['end'] - r['start']
      per_ballot.append(r['seconds'] / n)
      state = 'committed' if r['committed'] else 'already present, discarded'
      console.ok(f'chunk {r["start"]:07d}-{r["end"]:07d} {state} — '
                 f'{n} ballots in {console.dur(r["seconds"])} '
                 f'({r["seconds"] / n:.2f} s/ballot); contiguous from 0: '
                 f'{manifest["count"]}')

    run_pool('encrypt', jobs, args.workers, on_result)
    wall = time.perf_counter() - t0

  made = sum(e - s for s, e in plan)
  console.section('DONE')
  console.field('set holds', f'{manifest["count"]} ballots')
  console.field('wall clock', console.dur(wall))
  console.field('s/ballot', f'{sorted(per_ballot)[len(per_ballot) // 2]:.2f} '
                            f'per worker (median chunk), '
                            f'{wall / made:.2f} wall with {args.workers} '
                            f'worker(s)')
  console.detail('generation is not a measurement: these figures are for '
                 'planning only and are not recorded')
  console.field('next', f'python prepare.py validate --face {args.face} '
                        f'--scheme {args.scheme}')
  return 0


# ---- validate -----------------------------------------------------------------

def _parse_vote(encrypted_answers, election_uuid, election_hash):
  """
  The vote Stage 2 would cast (stage2_cast.py:52-64), parsed the way the
  cast-confirm view parses it (views.py:870).
  """
  from helios import datatypes, utils
  vote = {'answers': encrypted_answers, 'election_hash': election_hash,
          'election_uuid': election_uuid}
  body = json.dumps(vote, separators=(',', ':'))
  return datatypes.LDObject.fromDict(
    utils.from_json(body), type_hint='legacy/EncryptedVote').wrapped_obj


def _decrypt_choice(choice, key, decoder):
  """
  One ciphertext under the saved secret key, through the same calls
  Tally.decryption_factors_and_proofs and Tally.decrypt_from_factors make for
  one cell, minus the proof: decryption_factor, Ciphertext.decrypt, and the
  key's tally_decoder.
  """
  factor = key.secret_key.decryption_factor(choice)
  return decoder(choice.decrypt([factor], key.public_key))


def _check_sampled(job):
  """
  Proof and plaintext checks for the sampled indices of one chunk. The proof
  check is the call CastVote.verify_and_store makes (models.py ~1310),
  vote.verify(election), untimed.
  """
  helios_env.setup_django()
  from helios.models import Election

  key = fixed_key.load(job['key_path'])
  e = Election.objects.get(uuid=job['election_uuid'])
  election_hash = e.hash
  decoder = key.public_key.tally_decoder(1)
  want = set(job['indices'])
  out = []
  for rec in ps.read_chunk(job['chunk']):
    i = rec['ballot_index']
    if i not in want:
      continue
    try:
      vote = _parse_vote(rec['encrypted_answers'], e.uuid, election_hash)
      proof_ok = bool(vote.verify(e))

      plain_ok, why = True, ''
      for q_num, ea in enumerate(vote.encrypted_answers):
        picks = set(rec['plaintext'][q_num])
        for a_num, choice in enumerate(ea.choices):
          got = _decrypt_choice(choice, key, decoder)
          exp = 1 if a_num in picks else 0
          if got != exp:
            plain_ok, why = False, (f'question {q_num} answer {a_num} '
                                    f'decrypts to {got}, plaintext says {exp}')
            break
        if not plain_ok:
          break
    except Exception as exc:
      # A ballot Helios cannot even parse fails both checks; it does not stop
      # the others from being checked.
      proof_ok = plain_ok = False
      why = f'{type(exc).__name__}: {exc}'
    out.append({'index': i, 'proof_ok': proof_ok, 'plaintext_ok': plain_ok,
                'why': why})
  return out


def stratified_sample(ranges, n, rng):
  """
  About n random indices with every chunk represented, so every machine that
  made chunks is too. Chunk h, of N_h ballots out of N, gets
  k_h = max(1, ceil(n * N_h / N)) of its indices (at most all of them), drawn
  uniformly without replacement. n >= N checks every ballot.

  Returns (indices, n_effective): the sample size the zero-failure bound may
  claim. It is the largest m with k_h >= m * N_h / N in every chunk not
  checked in full, so n_effective >= n. For that design, with an invalid
  fraction p over the set, P(no failure) <= (1 - p)^n_effective, the same as
  a simple random sample of n_effective: each chunk contributes at most
  (1 - p_h)^k_h (sampling without replacement, and exactly 0 for a fully
  checked chunk holding a bad ballot), and the product over chunks is at most
  (1 - p)^n_effective by concavity of log.
  """
  total = sum(e - s for s, e in ranges)
  if n >= total:
    return [i for s, e in ranges for i in range(s, e)], float(total)
  picked, n_eff = [], math.inf
  for s, e in ranges:
    size = e - s
    k = min(size, max(1, -(-n * size // total)))
    picked.extend(rng.sample(range(s, e), k))
    if k < size:
      n_eff = min(n_eff, k * total / size)
  return sorted(picked), (float(total) if n_eff == math.inf else n_eff)


def zero_failure_bound(n_effective, confidence=CONFIDENCE):
  """
  With n random ballots checked and none failing, the invalid fraction is
  below 1 - (1 - confidence)^(1/n) at that confidence -- about 3/n at 95%,
  the rule of three: n = 300 gives under 1%.
  """
  return 1 - (1 - confidence) ** (1 / n_effective)


def cmd_validate(args, cfg, faces):
  import schemes

  face = faces[args.face]
  questions = votes_gen.build_questions(face)
  seed = cfg['seed']
  d = ps.set_dir(args.face, args.scheme, cfg)
  hp = helios_env.helios_path()

  console.title(f'PREPARE · validate · {args.face} / {args.scheme}')
  console.field('set', d)

  with SetLock(d):
    key = fixed_key.load(ps.key_path(d))
    manifest = ps.read_json(ps.manifest_path(d))
    if manifest is None:
      raise Refused(f'no manifest in {d}; nothing has been prepared')
    prev = ps.read_json(ps.validation_path(d))
    checks = {}

    # --- 1. structure --------------------------------------------------------
    console.section('1 · STRUCTURE')
    problems = []
    for k, v in (('key_fingerprint', key.fingerprint),
                 ('key_size', key.key_size), ('scheme', key.scheme)):
      if manifest.get(k) != v:
        problems.append(f'manifest {k} is {manifest.get(k)!r}, key.json {v!r}')
    for k, v in (('face', args.face),
                 ('questions_sha256', ps.questions_sha256(questions)),
                 ('master_seed', seed)):
      if manifest.get(k) != v:
        problems.append(f'manifest {k} is {manifest.get(k)!r}, config {v!r}')

    chunks = ps.completed_chunks(d)
    count = ps.contiguous_count(chunks)
    if any(s >= count for s, _e, _p in chunks):
      problems.append('chunks exist past a gap: the set is not contiguous')
    if manifest.get('count') != count:
      problems.append(f'manifest count {manifest.get("count")} but the chunks '
                      f'hold {count} contiguous ballots')
    listed = {c['file']: c for c in manifest.get('chunks', [])}
    for s, e, p in chunks:
      c = listed.get(f'chunks/{p.name}')
      if c is None:
        problems.append(f'{p.name} is not in the manifest')
      elif c['sha256'] != ps.sha256_file(p):
        problems.append(f'{p.name} does not match its manifest sha256')

    # What is checked is fixed before reading, so the stream below can pick
    # it out. The random sample is drawn from the whole set every run -- the
    # bound is a statement about the set -- and spread over every chunk.
    first_run = not (prev and prev.get('passed'))
    fixed = list(range(min(FIRST_RUN_ALL, count))) if first_run else []
    in_set = [(s, e, p) for s, e, p in chunks if s < count]
    sample_seed = secrets.randbits(32)
    sampled, n_eff = stratified_sample([(s, e) for s, e, _p in in_set],
                                       args.sample, random.Random(sample_seed))
    # A ballot that failed before is checked again, every run. The checks are
    # deterministic, so it fails again until its chunk is regenerated: a fresh
    # sample cannot turn a set that has failed into one that passes.
    prev_checks = (prev or {}).get('checks', {})
    recheck = sorted({i for k in ('proofs', 'plaintexts')
                      for i in prev_checks.get(k, {}).get('failed') or []
                      if i < count})
    to_check = sorted(set(fixed) | set(sampled) | set(recheck))

    helios_env.setup_django()
    master = votes_gen.master_ballots(seed, questions, count)
    uuid = generation_election(d, manifest, args.face, args.scheme, questions,
                               key, cfg)
    from helios.models import Election
    e = Election.objects.get(uuid=uuid)
    election_hash = e.hash
    prefix_n = min(count, PREFIX_MAX)
    tally = e.init_tally()

    seen = bytearray(count)
    jobs = []
    for s, end, p in chunks:
      if s >= count:
        continue          # past a gap: already a structure failure above
      in_chunk = to_check[bisect.bisect_left(to_check, s):
                          bisect.bisect_left(to_check, end)]
      if in_chunk:
        jobs.append({'chunk': str(p), 'indices': in_chunk,
                     'key_path': str(ps.key_path(d)), 'election_uuid': uuid})
      for rec in ps.read_chunk(p):
        i = rec.get('ballot_index')
        if not isinstance(i, int) or not s <= i < end:
          problems.append(f'{p.name}: ballot_index {i!r} outside the chunk')
          continue
        if seen[i] < 2:
          seen[i] += 1
        if rec.get('plaintext') != master[i]:
          problems.append(f'ballot {i}: plaintext is not master_ballots[{i}]')
        ea = rec.get('encrypted_answers') or []
        if len(ea) != len(questions):
          problems.append(f'ballot {i}: {len(ea)} answers for '
                          f'{len(questions)} questions')
          continue
        for q_num, (a, q) in enumerate(zip(ea, questions)):
          if len(a.get('choices', [])) != len(q['answers']):
            problems.append(f'ballot {i} question {q_num}: '
                            f'{len(a.get("choices", []))} choices for '
                            f'{len(q["answers"])} answers')
        got = schemes.observed_scheme((ea[0].get('choices') or [None])[0])
        if got != args.scheme:
          problems.append(f'ballot {i}: ciphertexts look {got!r}')
        # 4, streamed: Helios's own tally code, as compute_tally adds a vote
        # (models.py ~552), with verify_p=False.
        if i < prefix_n:
          tally.add_vote(_parse_vote(ea, e.uuid, election_hash),
                         verify_p=False)

    missing = [i for i in range(count) if seen[i] == 0]
    dup = [i for i in range(count) if seen[i] > 1]
    if missing:
      problems.append(f'{len(missing)} index(es) missing, first {missing[:5]}')
    if dup:
      problems.append(f'{len(dup)} index(es) held more than once, first '
                      f'{dup[:5]}')
    checks['structure'] = {'passed': not problems, 'count': count,
                           'problems': problems[:50]}
    _report('every index 0..count-1 once, plaintexts = master, shapes, '
            'manifest = key.json', checks['structure'],
            f'{count} ballots in {len(chunks)} chunk(s)')

    # --- 2 + 3. proofs and plaintexts, on the sample -------------------------
    console.section('2 · PROOFS (vote.verify)  3 · PLAINTEXTS (saved key)')
    console.detail(f'{len(sampled)} randomly sampled ballot(s) over '
                   f'{len(in_set)} chunk(s)'
                   + (f', plus all of the first {len(fixed)}' if fixed else '')
                   + (f', plus {len(recheck)} that failed before'
                      if recheck else '')
                   + f'; election {e.short_name}')

    # Every chunk, and so every machine that made chunks, is in the sample.
    hosts = {c['file']: c.get('host') for c in manifest.get('chunks', [])}
    by_host, unsampled = {}, []
    for s, end, p in in_set:
      k = (bisect.bisect_left(sampled, end) - bisect.bisect_left(sampled, s))
      h = by_host.setdefault(hosts.get(f'chunks/{p.name}') or 'unrecorded',
                             {'chunks': 0, 'ballots': 0, 'sampled': 0})
      h['chunks'] += 1
      h['ballots'] += end - s
      h['sampled'] += k
      if not k:
        unsampled.append(p.name)
    checks['coverage'] = {'passed': bool(in_set) and not unsampled,
                          'chunks': len(in_set), 'unsampled': unsampled[:50],
                          'by_host': by_host}
    _report('every chunk and every machine in the random sample',
            checks['coverage'],
            ', '.join(f'{h}: {v["sampled"]} of {v["ballots"]} ballots, '
                      f'{v["chunks"]} chunk(s)' for h, v in by_host.items()))
    if 'unrecorded' in by_host:
      console.detail(f'{by_host["unrecorded"]["chunks"]} chunk(s) have no '
                     f'recorded host (made before hosts were recorded, or by a '
                     f'run killed before recording); every chunk is sampled, '
                     f'so their machines are covered regardless')

    results = []
    t0 = time.perf_counter()
    run_pool('check', jobs, args.workers,
             lambda job, r: (results.extend(r),
                             console.detail(f'{len(results)}/{len(to_check)} '
                                            f'checked')))
    bad_proof = sorted(r['index'] for r in results if not r['proof_ok'])
    bad_plain = [(r['index'], r['why']) for r in results
                 if not r['plaintext_ok']]
    unchecked = sorted(set(to_check) - {r['index'] for r in results})
    checks['proofs'] = {'passed': not bad_proof and not unchecked,
                        'checked': len(results), 'failed': bad_proof,
                        'unchecked': unchecked}
    checks['plaintexts'] = {'passed': not bad_plain and not unchecked,
                            'checked': len(results),
                            'failed': [i for i, _w in bad_plain],
                            'detail': [w for _i, w in bad_plain][:10]}
    _report('vote.verify(election) is True', checks['proofs'],
            f'{len(results)} ballots in {console.dur(time.perf_counter() - t0)}')
    _report('each answer decrypts to its plaintext', checks['plaintexts'],
            f'{sum(sum(len(q["answers"]) for q in questions) for _ in results)}'
            f' ciphertexts')

    # The bound holds only with zero failures. With any, there is no bound to
    # state: the set fails, whatever fraction of it is bad.
    failed = set(bad_proof) | {i for i, _w in bad_plain} | set(unchecked)
    sample_failures = len(failed & set(sampled))
    census = len(sampled) == count
    bound = None if failed or not n_eff else zero_failure_bound(n_eff)
    zero_failure = {
      'n': len(sampled), 'n_effective': n_eff, 'confidence': CONFIDENCE,
      'bound': bound, 'failures': sample_failures, 'census': census,
      'formula': '1 - (1 - confidence)^(1 / n_effective)',
      'method': 'random sample stratified by chunk, at least one per chunk, '
                'at least the proportional share of n_effective in each; the '
                'first-run and recheck indices are not part of n'}
    if bound is not None:
      console.ok(f'zero-failure bound: invalid fraction < {100 * bound:.2f}% at '
                 f'{100 * CONFIDENCE:.0f}% confidence (n = {len(sampled)} '
                 f'random ballots, n_effective = {n_eff:.1f})'
                 + (' — every ballot was checked' if census else ''))
    elif failed:
      console.fail(f'no zero-failure bound: {len(failed)} checked ballot(s) '
                   f'failed ({sample_failures} of them in the random sample)')
    else:
      console.fail('no zero-failure bound: nothing was sampled')

    # --- 4. homomorphic prefix -----------------------------------------------
    console.section('4 · HOMOMORPHIC PREFIX (Tally.add_vote, decrypt_from_factors)')
    if prefix_n:
      factors = [[key.secret_key.decryption_factor(c) for c in q]
                 for q in tally.tally]
      # decrypt_from_factors is span-wrapped; measurement is off in this
      # process (top of file), so it runs Helios's combine and decode only.
      got = tally.decrypt_from_factors([factors], key.public_key)
      expected = votes_gen.expected_tally(questions, master[:prefix_n])

      # An ElGamal cell outside the dlog table decodes to None, not a count.
      def totals(t):
        return [sum(q) if all(isinstance(x, int) for x in q) else None
                for q in t]
      checks['homomorphic_prefix'] = {
        'passed': got == expected and tally.num_tallied == prefix_n,
        'ballots': prefix_n, 'num_tallied': tally.num_tallied,
        'expected_totals': totals(expected), 'got_totals': totals(got)}
      _report(f'first {prefix_n} tally to expected_tally(master[:{prefix_n}])',
              checks['homomorphic_prefix'],
              f'per-question totals {totals(got)}, expected '
              f'{totals(expected)}')
    else:
      checks['homomorphic_prefix'] = {'passed': False, 'ballots': 0}
      _report('prefix tally', checks['homomorphic_prefix'], 'set is empty')

    # Any failure fails the whole set. The generator is deterministic code, so
    # one bad ballot means a bug in how the set was made, not bad luck; nothing
    # in it is usable until that is found and the set regenerated.
    passed = all(c['passed'] for c in checks.values())
    out = {
      'format': 2,
      'passed': passed,
      'validated_count': count,
      'first_run': first_run,
      'checks': checks,
      'zero_failure_bound': zero_failure,
      'sample_indices': sampled,
      'sample_seed': sample_seed,
      'first_run_indices': [0, len(fixed)],
      'recheck_indices': recheck,
      'election_uuid': uuid,
      'key_fingerprint': key.fingerprint,
      'manifest_sha256': ps.sha256_file(ps.manifest_path(d)),
      'helios_commit': helios_env.git_commit(hp),
      'helios_dirty': helios_env.git_is_dirty(hp),
      'set_helios_commit': manifest.get('helios_commit'),
      'validated_at': ps.now_utc(),
    }
    ps.write_json(ps.validation_path(d), out)

  console.section('RESULT')
  if out['helios_commit'] != manifest.get('helios_commit'):
    console.warn(f'validated at Helios {out["helios_commit"]}; the set was '
                 f'made at {manifest.get("helios_commit")}')
  (console.ok if passed else console.fail)(
    f'{"PASSED" if passed else "FAILED"} — validated_count {count}, '
    f'written to {ps.validation_path(d)}')
  if not passed:
    console.detail('the whole set fails: a failure is a bug in generation, not '
                   'bad luck. Rerunning validate re-checks every failed ballot, '
                   'so it cannot pass until the cause is fixed and the set '
                   'regenerated.')
  return 0 if passed else 1


def _report(name, check, detail):
  if check['passed']:
    console.ok(f'{name} — {detail}')
  else:
    console.fail(f'{name} — {detail}')
    for p in (check.get('problems') or check.get('detail') or [])[:10]:
      console.detail(p)
    for k in ('failed', 'unchecked'):
      if check.get(k):
        console.detail(f'{k}: {check[k][:20]}')


# ---- main ---------------------------------------------------------------------

def main(argv=None):
  cfg = helios_env.load_config('levels.yaml')
  faces = helios_env.load_config('ballot_face.yaml')

  p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  sub = p.add_subparsers(dest='cmd', required=True)

  def common(sp):
    sp.add_argument('--face', default=cfg['ballot_face'], choices=sorted(faces))
    sp.add_argument('--scheme', required=True, choices=ps.SCHEMES,
                    help='the cryptosystem; paillier-off uses paillier')
    sp.add_argument('--root', default=None,
                    help='prepared root; default levels.yaml prepared.dir')

  sp = sub.add_parser('keys', help='make the fixed trustee key')
  common(sp)

  sp = sub.add_parser('ballots', help='encrypt the master plaintexts')
  common(sp)
  sp.add_argument('--count', type=int, required=True,
                  help='prepare indices 0..count-1 (extends an existing set)')
  sp.add_argument('--workers', type=int, default=1)
  sp.add_argument('--chunk-size', type=int, default=None,
                  help=f'ballots per chunk; default the set\'s, or '
                       f'{DEFAULT_CHUNK}')
  sp.add_argument('--cpus', default=None,
                  help='taskset CPU list for the whole run (Linux only)')
  sp.add_argument('--headed', action='store_true', help='show the browsers')

  sp = sub.add_parser('validate', help='check a prepared set with Helios code')
  common(sp)
  sp.add_argument('--sample', type=int, default=DEFAULT_SAMPLE,
                  help='random ballots to proof-check, spread over every chunk')
  sp.add_argument('--workers', type=int, default=1,
                  help='processes for the proof checks')

  args = p.parse_args(argv)
  if args.root:
    cfg = {**cfg, 'prepared': {**(cfg.get('prepared') or {}),
                               'dir': os.path.abspath(args.root)}}
  try:
    if args.cmd == 'keys':
      return cmd_keys(args, cfg)
    if args.cmd == 'ballots':
      if args.count < 1 or args.workers < 1 or (args.chunk_size or 1) < 1:
        raise Refused('--count, --workers and --chunk-size must be positive')
      return cmd_ballots(args, cfg, faces)
    return cmd_validate(args, cfg, faces)
  except (Refused, FileExistsError, FileNotFoundError) as e:
    console.section('REFUSED')
    console.fail(str(e))
    return 2
  except KeyboardInterrupt as e:
    # Ctrl-C, or SIGTERM via run_pool. Committed chunks stand; the rest are
    # redone by the next run.
    console.section('INTERRUPTED')
    console.warn(f'{e or "interrupted"} — committed chunks are kept; rerun the '
                 f'same command to finish')
    return 130


if __name__ == '__main__':
  sys.exit(main())
