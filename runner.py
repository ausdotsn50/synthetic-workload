"""
Sample commands, one per measured arm:
- uv run --project ../helios-server python runner.py --face smoke --n 10
- uv run --project ../helios-server python runner.py --face smoke --n 10 --scheme paillier

Prepared cells (ballots from prepare.py; S live, N - S prepared):
- uv run --project ../helios-server python runner.py --face smoke --n 10 --prepared --sample 3 --populate insert
- uv run --project ../helios-server python runner.py --face smoke --n 10 --prepared --sample 3 --populate cast --scheme paillier

The arm is the scheme: elgamal, paillier-off. Both cast the same ballots at
the same (N, rep) -- see generator/votes.py, cell_seed -- so arms compare
pairwise. --crt-proofs defaults to the `paillier:` block in
config/levels.yaml (CRT on, the server's own default).

Execution is SERIAL by design (§3.8). At ~6.5 s of pure computation per ballot,
concurrency on this machine would saturate CPU immediately and the numbers would
measure the OS scheduler rather than cryptography.

One cell == one election: fresh election, fresh voter list. A live cell also
has a fresh trustee keypair and fresh ballots. A prepared cell still has
Helios generate (and time) its keypair, then freezes under its set's fixed key,
because the prepared ballots only verify under the key they were made with.

Nothing here is run automatically. Every stage is invoked explicitly.
"""

import argparse
import os
import re
import sys
import time

import console
import helios_env
import preflight
import schemes
from emit import Emitter, make_run_id

# ElectionForm.short_name is a SlugField(max_length=40); a longer name is
# refused by the form, and the election is never created.
SHORT_NAME_MAX = 40


def resolve_ablation(scheme, cfg, crt_proofs=None):
  """
  The configuration a cell runs under, in Election.ablation_config's shape:
  {} under ElGamal, {'paillier_use_crt_proofs'} under
  Paillier. A flag given on the command line wins over the `paillier:` block
  in config/levels.yaml. Raises ValueError on a flag the scheme cannot take.
  """
  if scheme != 'paillier':
    if crt_proofs is not None:
      raise ValueError(f'--crt-proofs applies only to '
                       f'--scheme paillier, and this cell is {scheme!r}')
    return {}

  p = cfg.get('paillier') or {}
  crt = ((crt_proofs == 'on') if crt_proofs is not None
         else p.get('crt_proofs', True))
  if not isinstance(crt, bool):
    raise ValueError(f'paillier crt_proofs is {crt!r}, not true or false')
  return {'paillier_use_crt_proofs': crt}


def arm_label(scheme, ablation):
  """elgamal, or paillier-off: the two measured arms."""
  if scheme == 'paillier':
    return 'paillier-off'
  return scheme


def short_name_for(arm, N, rep, run_id, tag=''):
  """The election's short_name, refused before anything runs if the form would
  refuse it. `tag` marks a prepared cell: -pc (populate cast), -pi (insert)."""
  name = f'wl-{arm}-n{N}-r{rep}{tag}-{run_id[-4:]}'
  if len(name) > SHORT_NAME_MAX:
    raise ValueError(f'election short_name {name!r} is {len(name)} characters; '
                     f'Helios accepts at most {SHORT_NAME_MAX}')
  return name


def prepared_tag(populate):
  return {'cast': '-pc', 'insert': '-pi'}[populate]


def _trustee_fingerprint(election_uuid):
  """The fingerprint of the key Helios generated, computed as fixed_key does
  for a saved one, so live and prepared cells record the same quantity."""
  helios_env.setup_django()
  from helios.models import Election
  from drivers import fixed_key
  t = Election.objects.get(uuid=election_uuid).get_helios_trustee()
  return fixed_key.fingerprint(t.public_key)


def _checked_bulk(set_dir, start, stop, master):
  """
  The prepared ballots start..stop-1, streamed, each checked on the way past:
  the right index, in order, with the master plaintext the tally expects.
  validate already proved this for the set; this proves it for what this
  cell is actually about to put on its board.
  """
  from drivers import prepared_set
  want = start
  for rec in prepared_set.iter_ballots(set_dir, start, stop):
    i = rec['ballot_index']
    if i != want:
      raise RuntimeError(f'prepared ballot {want} expected, {i} read')
    if rec['plaintext'] != master[i]:
      raise RuntimeError(f'prepared ballot {i} is not master_ballots[{i}]')
    want += 1
    yield rec
  if want != stop:
    raise RuntimeError(f'prepared set ended at {want}, cell needs {stop}')


# Cell run equivalent to one election run
def run_cell(*, scheme, N, rep, cfg, face, emitter, ablation, face_key='?',
             headless=True, skip=(), prep=None):
  """
  One cell. `prep` is None for a live cell -- all N encrypted in the browser
  from cell_seed plaintexts, exactly as before -- or, for a prepared cell,
  {'snapshot': prepared_set.snapshot_for_cell(...), 'sample': S,
  'populate': 'cast'|'insert'}: S ballots live, N - S from the prepared set.
  """
  # Usage of seed for reproducibility purposes
  seed_base = cfg['seed']
  base_url = helios_env.helios_url()
  helios_path = helios_env.helios_path()

  # Import of votes and voters module from generator/
  from generator import votes as votes_gen
  from generator import voters as voters_gen

  arm = arm_label(scheme, ablation)
  # Not keyed on the arm: every arm at this (N, rep) casts the same ballots.
  # A prepared cell's plaintexts are master_ballots(seed_base, ...)[:N], the
  # same for every (N, rep), so its records carry the base seed itself.
  seed = seed_base if prep else votes_gen.cell_seed(seed_base, N, rep)
  questions = votes_gen.build_questions(face)
  short_name = short_name_for(arm, N, rep, emitter.run_id,
                              prepared_tag(prep['populate']) if prep else '')
  S = prep['sample'] if prep else N
  # Per-ballot records of a prepared cell say which population they are from.
  src = {'ballot_source': 'sample'} if prep else {}

  # HELIOS_MEASURE_PATH wins: it is the variable Helios itself reads, so taking
  # it from the same place removes any chance of the harness looking somewhere
  # the writer is not writing — a mismatch would look exactly like "no
  # instrumentation". config is the fallback for a shell that has not sourced
  # an env file.
  m_cfg = cfg.get('measurement', {})
  sidecar = os.path.expanduser(
    os.environ.get('HELIOS_MEASURE_PATH') or m_cfg.get('sidecar_path', ''))

  n_answers = sum(len(q['answers']) for q in questions) # Sum of possible choices

  # Store records
  records = []

  # Record produced by emit in .json file
  def em(stage, metric, value, unit, extra=None):
    # Every record, the harness's own and those joined from Helios, carries the
    # configuration the election ran under, in Election.ablation_config's
    # shape ({} under ElGamal). acceptance.py checks it against the election.
    extra = {**(extra or {}), 'ablation': ablation}
    r = emitter.emit(scheme=scheme, N=N, rep=rep, seed=seed, stage=stage,
                     metric=metric, value=value, unit=unit, extra=extra)
    records.append(r)
    return r

  # One stage wall clock. The console's WALL CLOCK table is built from these.
  def stage_wall(stage, name, seconds):
    em(stage, 'stage_wall_time_ns', int(seconds * 1e9), 'ns',
       {'stage_name': name, 'operational': True})

  # Header formatted
  console.title('HELIOS WORKLOAD — cell execution')
  console.field('run_id', emitter.run_id)
  console.field('arm', arm)
  console.field('scheme', scheme)
  if ablation:
    console.field('ablation', ', '.join(f'{k}={v}'
                                        for k, v in sorted(ablation.items())))
  console.field('N (voters)', N)
  console.field('rep', rep)
  console.field('ballot face', f'{face_key} — {len(questions)} questions, '
                               f'{n_answers} answers')
  console.field('ciphertexts/ballot', n_answers)
  console.field('cell seed', seed)
  if prep:
    console.field('ballots', f'prepared — {S} live sample, {N - S} '
                             f'{prep["populate"]}')
    console.field('prepared set', prep['snapshot']['dir'])
    console.field('key', prep['snapshot']['key_fingerprint'][:16])
    for w in prep['snapshot']['warnings']:
      console.warn(w)
  else:
    console.field('ballots', 'live — all N encrypted in the browser')
  console.field('election', short_name)
  console.field('output', emitter.path)
  console.field('skipped', ', '.join(skip) if skip else '(nothing)')

  log = console.detail

  # Stage 0 - see stage0_setup.py
  # See console.py (using a Stage object for pipeline wall-clock)
  # with... as syntax triggers __enter__
  with console.Stage('STAGE 0 · CONFIGURE') as stg_zero:
    from drivers import stage0_setup
    console.step(f'creating election, uploading {N} voters')
    # Election uuid found via short name function in stage0_setup
    election_uuid = stage0_setup.configure( # Note: uuid creation upon the following configure
      base_url=base_url, short_name=short_name,
      name=f'Workload {arm} N={N} rep={rep}',
      questions=questions, n_voters=N, scheme=scheme, ablation=ablation,
      log=log)

  # time_perf_counter_ns ends at with... as... statement
  stage_wall('configure', 'stage 0 configure', stg_zero.wall)
  # Cell level: which ballots, and under which key. A live cell freezes under
  # the key Helios generated; a prepared one under the set's saved key.
  em('configure', 'election_created', 1, 'count',
     {'election_uuid': election_uuid, 'short_name': short_name,
      'arm': arm, 'ballot_face': face_key,
      'n_questions': len(questions), 'n_answers': n_answers,
      'ballots': 'prepared' if prep else 'live',
      'populate': prep['populate'] if prep else None,
      'sample_size': S,
      'key_source': 'prepared' if prep else 'generated',
      'key_fingerprint': (prep['snapshot']['key_fingerprint'] if prep
                          else _trustee_fingerprint(election_uuid)),
      'manifest_sha256': prep['snapshot']['manifest_sha256'] if prep else None})

  from drivers import stage0_setup
  if prep:
    # The set's provenance as this cell saw it, for acceptance to check after
    # the set itself has moved on.
    em('configure', 'prepared_set', 1, 'count',
       {**prep['snapshot'], 'operational': True})
    # After configure (Helios's own keygen is already measured), before
    # freeze (which copies the trustee key into the election).
    console.step('installing the prepared set\'s fixed key on the trustee')
    stage0_setup.install_fixed_key(election_uuid, prep['snapshot']['key_path'],
                                   log=log)
    em('configure', 'fixed_key_installed', 1, 'count',
       {'key_fingerprint': prep['snapshot']['key_fingerprint'],
        'operational': True})

  # Stage 1 - freeze election
  with console.Stage('STAGE 1 · FREEZE') as st:
    # Key generation is NOT sampled here any more. keygen_time_ns and
    # prove_sk_time_ns are recorded by Helios inside Election.generate_trustee
    # (Stage 0, web process) for the key the election actually used. The
    # distribution comes from repeating cells, not from timing the primitive
    # outside the code path that runs it.
    console.detail('keygen and prove_sk are measured inside Helios at election '
                   'creation; repetitions supply the distribution')

    console.step('freezing election (locks ballot + roll, opens voting)')
    t0 = time.perf_counter()
    stage0_setup.freeze(base_url=base_url, election_uuid=election_uuid, log=log)
    stage_wall('freeze', 'stage 1 freeze', time.perf_counter() - t0)
    if prep:
      fp = stage0_setup.check_fixed_key(
        election_uuid, prep['snapshot']['key_path'], log=log)
      em('freeze', 'key_fingerprint_checked', 1, 'count',
         {'key_fingerprint': fp, 'operational': True})

    # What every voter's browser downloads before it can render a ballot. The
    # endpoint already exists (views.one_election), so this needs no Helios
    # change -- it is measured by asking for it exactly as a booth would.
    # Taken AFTER the freeze: before it, public_key is still null, so the
    # measured payload would be missing the key the booth needs.
    try:
      from drivers.http_client import HeliosSession
      _r = HeliosSession(base_url).get(f'/helios/elections/{election_uuid}')
      em('freeze', 'election_json_bytes', len(_r.content), 'bytes',
         {'tier': 'flow', 'source': 'harness',
          'note': 'GET /helios/elections/<uuid> — the booth download'})
    except Exception as e:
      console.warn(f'could not measure election JSON payload: '
                   f'{type(e).__name__}: {e}')
  em('freeze', 'frozen', 1, 'count', {'election_uuid': election_uuid})

  # Stage 2 - browser encryption, measured, then cast to the board
  out_path = emitter.path.with_name(
    f'{emitter.run_id}-ballots-n{N}-r{rep}.jsonl') # Separate jsonl for the ballots
  
  with console.Stage('STAGE 2 · ENCRYPTION (browser) + CAST') as st:
    from drivers import stage1_encrypt, stage2_cast
    from generator import voters as voters_gen

    if prep:
      # The tally's plaintexts are the master list's first N; ballots
      # 0..S-1 are encrypted live here, the rest come from the prepared set.
      ballots = votes_gen.master_ballots(seed, questions, N)
      live = ballots[:S]
      console.step(f'encrypting the live sample: {S} of {N} ballots in Chrome')
      console.detail('the sample supplies every per-ballot metric; ballots '
                     f'{S}..{N - 1} are prepared and populated below')
    else:
      ballots = votes_gen.generate_ballots(seed, questions, N)
      live = ballots
      console.step(f'encrypting {N} ballots in Chrome')
      console.detail('these ballots are cast — the measured population and the '
                      'aggregated population are the same ballots')

    enc_cfg = cfg.get('encryption', {})
    t0 = time.perf_counter()
    samples, warmup_timings = stage1_encrypt.sample_encryptions(
      base_url=base_url, election_uuid=election_uuid, ballots=live,
      scheme=scheme,
      out_path=out_path, headless=headless,
      warmup=enc_cfg.get('warmup_ballots', 1), log=log)
    stage_wall('encrypt', 'stage 2 encrypt', time.perf_counter() - t0)

    # Discarded warm-up ballots: kept in the record, excluded from analysis.
    for i, t in enumerate(warmup_timings):
      em('encrypt', 'encryption_warmup_ms', t, 'ms',
         {'operational': True, 'sample': i, 'source': 'browser',
          'note': 'discarded warm-up ballot, not cast, not part of N'})

    for i, s in enumerate(samples):
      em('encrypt', 'encryption_time_ms', s['timing_ms'], 'ms',
          {'tier': 'operation', 'source': 'browser', 'sample': i, **src})
      em('encrypt', 'ciphertext_bytes', s['ciphertext_bytes'], 'bytes',
          {'tier': 'operation', 'source': 'browser', 'sample': i, **src})
      em('encrypt', 'proof_bytes', s['proof_bytes'], 'bytes',
          {'tier': 'operation', 'source': 'browser', 'sample': i, **src})
      # Measured in flow, on the same single pass as encryption_time_ms: a
      # decorator on the booth's own generateDisjunctiveProof, so this is
      # Helios's proof generation, not a re-creation of it.
      em('encrypt', 'encryption_proof_ms', s['proof_ms'], 'ms',
          {'tier': 'operation', 'source': 'browser', 'sample': i, **src})
      # The remainder -- plaintext setup, the pk.encrypt per answer slot, the
      # homomorphic sum that feeds the overall proof -- is not recorded.
      # It was encryption_time_ms minus encryption_proof_ms on the same ballot,
      # both emitted just above under the same sample index, so the third
      # record held nothing the first two did not, once per ballot. The ZKP
      # table reports proof time against the encryption containing it instead.

    # One liveness line; the values themselves are in the summary.
    timings = [s['timing_ms'] for s in samples]
    mean_ms = sum(timings) / max(len(timings), 1)
    console.detail(f'{len(samples)} ballots encrypted, '
                   f'mean {mean_ms:.0f} ms — see summary below')

    console.step('retrieving voter credentials')
    credentials = voters_gen.fetch_credentials(election_uuid)

    console.step(f'casting {len(live)} ballots through the real HTTP flow')
    t0 = time.perf_counter()
    n_cast, payloads = stage2_cast.cast_ballots(
      base_url=base_url, election_uuid=election_uuid,
      encrypted=stage1_encrypt.load_encrypted(out_path),
      credentials=credentials, total=len(live), log=log)
    stage_wall('encrypt', 'stage 2 cast', time.perf_counter() - t0)

    # What crossed the wire, as opposed to ciphertext_bytes + proof_bytes which
    # count cryptographic content only.
    for i, p in enumerate(payloads):
      em('encrypt', 'cast_payload_bytes', p['payload_bytes'], 'bytes',
         {'tier': 'flow', 'sample': i, 'json_bytes': p['json_bytes'], **src})

    console.step('waiting for Celery ballot verification')
    console.detail('Helios refuses to tally while any vote is unverified, so '
                    'Stage 3 cannot start until this drains')
    t0 = time.perf_counter()
    stage2_cast.await_verification(election_uuid, n_cast, log=log)
    stage_wall('encrypt', 'stage 2 verify', time.perf_counter() - t0)

  from drivers import stage2_populate, worker
  if prep:
    mode = prep['populate']
    bulk = _checked_bulk(prep['snapshot']['dir'], S, N, ballots)
    with console.Stage(f'STAGE 2 · POPULATE {N - S} PREPARED BALLOTS '
                       f'({mode})') as stp:
      if mode == 'cast':
        # Bulk off: the real HTTP + Celery path, ballot by ballot.
        console.step(f'casting ballots {S}..{N - 1} through the real HTTP flow')
        _n, bulk_payloads = stage2_cast.cast_ballots(
          base_url=base_url, election_uuid=election_uuid, encrypted=bulk,
          credentials=credentials[S:N], total=N - S, log=log)
        for k, p in enumerate(bulk_payloads):
          em('encrypt', 'cast_payload_bytes', p['payload_bytes'], 'bytes',
             {'tier': 'flow', 'sample': S + k, 'json_bytes': p['json_bytes'],
              'ballot_source': 'bulk'})
        console.step('waiting for Celery ballot verification')
        stage2_cast.await_verification(election_uuid, N, log=log)
      else:
        # Bulk on: the rows a verified cast leaves behind, written directly.
        console.step(f'storing ballots {S}..{N - 1} as verified casts')
        stage2_populate.insert_ballots(
          election_uuid=election_uuid, encrypted=bulk,
          credentials=credentials[S:N], total=N - S, sidecar=sidecar, log=log)
      stage2_populate.check_board(election_uuid, N)
    stage_wall('encrypt', 'stage 2 populate', stp.wall)

    if mode == 'insert':
      # Untimed: what insert wrote must verify where Celery never looked.
      idx = stage2_populate.spot_indices(S, N, 5, f'{seed}|{N}|{rep}|spot')
      ok = stage2_populate.spot_verify(election_uuid, idx, credentials)
      if not all(ok.values()):
        raise RuntimeError(f'inserted ballots fail vote.verify: '
                           f'{[i for i, v in ok.items() if not v]}')
      em('encrypt', 'bulk_spot_verified', len(idx), 'count',
         {'operational': True, 'indices': idx,
          'note': 'vote.verify(election) on stored rows, untimed'})
      console.ok(f'{len(idx)} inserted ballots verify: {idx}')

    # Both modes: statistics for the tally's voter_set query, however the
    # tables were filled.
    t_an = stage2_populate.analyze()
    em('encrypt', 'analyze', int(t_an * 1e9), 'ns',
       {'operational': True, 'tables': ['helios_voter', 'helios_castvote']})

  em('encrypt', 'pg_database_size', stage2_populate.database_size(), 'bytes',
     {'operational': True, 'note': 'after population'})

  if prep:
    # Both modes: the tally starts on a worker process that has done nothing
    # since it started, whatever population ran through it.
    console.step('restarting the Celery worker (fresh process for the tally)')
    w = worker.restart(log=log)
    em('encrypt', 'worker_restarted', int(w['seconds'] * 1e9), 'ns',
       {'operational': True, 'old_pid': w['old_pid'], 'new_pid': w['new_pid'],
        'pool': w['pool'], 'node': w['node'],
        'cmdline': w['identity']['cmdline'],
        'affinity': w['identity']['affinity']})

  # ---- STAGES 3+4 · THE REAL FLOW, INSTRUMENTED -----------------------------
  # There is exactly ONE execution. Each stage drives its own phase through the
  # endpoint an administrator uses; Helios (helios/measure.py -- on master, and
  # merged into paillier-helios, which the server runs) times its own calls
  # from the inside and appends them to the sidecar. The harness joins on
  # election uuid. Nothing is re-executed to be measured.
  from drivers import stage3_aggregate, stage4_decrypt, measure_join

  poll_s = m_cfg.get('poll_s', 0.05)
  timeout_s = m_cfg.get('timeout_s', 3600)

  # Operational, every cell: the worker's peak RSS is what sets max N, since
  # compute_tally loads every voter row at once (models.py:552).
  _node, w_info = worker.the_worker()
  probe = worker.MemoryProbe(w_info['pid']).start()
  try:
    probe.stage('aggregate')
    with console.Stage('STAGE 3 · HOMOMORPHIC AGGREGATION (via endpoint)') as st3:
      console.step('POST /compute_tally, then wait for encrypted_tally')
      console.detail('aggregation runs in the Celery worker and is timed from '
                     'inside Helios')
      f3 = stage3_aggregate.compute_tally(
        base_url=base_url, election_uuid=election_uuid,
        poll_s=poll_s, timeout_s=timeout_s, log=log)
    stage_wall('aggregate', 'stage 3 aggregate', st3.wall)

    probe.stage('decrypt')
    with console.Stage('STAGE 4 · DECRYPTION (via endpoints)') as st4:
      console.step('waiting for decryption_factors')
      console.detail('the task was already chained off Stage 3\'s POST — no '
                     'second request is issued here')
      stage4_decrypt.await_factors(
        election_uuid=election_uuid, since_ns=f3['signal_ns'],
        poll_s=poll_s, timeout_s=timeout_s, log=log)

      console.step('POST /combine_decryptions — synchronous')
      result = stage4_decrypt.combine(
        base_url=base_url, election_uuid=election_uuid, log=log)
    stage_wall('decrypt', 'stage 4 decrypt', st4.wall)
  finally:
    peaks = probe.stop()
  for stage_label, pk in peaks.items():
    em(stage_label, 'worker_peak_rss_bytes', pk['peak_tree_rss'], 'bytes',
       {'operational': True, 'pid': w_info['pid'],
        'interval_s': probe.interval_s, **pk})

  # The tally these exact ballots must decrypt to, counted in the clear from the
  # plaintexts. acceptance.py fails the cell unless Helios's result equals it.
  em('decrypt', 'result', result, 'tally',
     {'election_uuid': election_uuid,
      'expected': votes_gen.expected_tally(questions, ballots)})

  # ---- join Helios's own timings --------------------------------------------
  console.section('INSTRUMENTATION · joined from Helios sidecar')
  rows = measure_join.read_sidecar(sidecar, election_uuid)
  if not rows:
    msg = (f'no instrumentation records for election {election_uuid} in '
           f'{sidecar or "(no sidecar_path configured)"}.\n'
           f'  HELIOS_MEASURE_PATH must be set for BOTH the Django process and '
           f'the Celery worker (source measure-env.sh before starting each), '
           f'and helios-server must carry helios/measure.py -- master, or '
           f'paillier-helios, which has it merged.')
    if m_cfg.get('require_instrumentation', True):
      raise RuntimeError(msg)
    console.warn(msg)
  else:
    # Prepared cells: each verification record is a sample or a bulk ballot,
    # through cast_vote_id -> voter -> index. Under insert only the sample has
    # any; under cast, all N do.
    index_of = (measure_join.ballot_index_by_cast_vote(election_uuid)
                if prep else {})
    for metric, metric_rows in sorted(rows.items()):
      if metric in measure_join.SKIP_EMIT:
        continue
      for r in metric_rows:
        extra = measure_join.extra_for(r)
        if prep and metric in measure_join.PER_BALLOT:
          i = index_of.get(r.get('cast_vote_id'))
          extra['ballot_index'] = i
          extra['ballot_source'] = (None if i is None
                                    else 'sample' if i < S else 'bulk')
        em(measure_join.STAGE_OF.get(metric, 'decrypt'), metric, r['value'],
           r.get('unit', 'ns'), extra)
      # No value echo here: the summary prints each metric in its section
      # (crypto, ZKP, payload sizes, payload-driven timing).

    # The one thing this section uniquely establishes: records arrived from
    # more than one process, so the work really ran where Helios runs it.
    # Values themselves are printed in the labelled sections below.
    _all = [x for v in rows.values() for x in v]
    _pids = sorted({x.get('pid') for x in _all if x.get('pid')})
    console.ok(f'{len(_all)} records joined from {len(_pids)} process(es): '
               + ', '.join(str(p) for p in _pids))
    if len(_pids) < 2:
      web_metrics = ('keygen, prove_sk and both dlog metrics'
                     if schemes.get(scheme).has_dlog
                     else 'keygen and decryption_time_ns')
      console.warn('all records from a single process — expected two (Django '
                   f'web + Celery worker). The web process records '
                   f'{web_metrics}; if those are '
                   'absent, Django was started without HELIOS_MEASURE_PATH '
                   'and must be restarted, not just re-exported.')

    # Decryption proof time is not emitted: console and acceptance compute it
    # as decryption_factor_time_ns minus decryption_factor_only_ns.

    # Verification split. verification_time_ns encloses verify_and_store, which
    # is proof checking PLUS two row writes; verification_only_ns isolates the
    # cryptography. Both are joined above, so the row-write remainder is not
    # emitted: the metric that used to sit here subtracted one median from
    # another, which is two different ballots and describes neither. The ZKP
    # table reports proof checking against verification_time_ns instead.

  # Summary of results
  console.summary(records, N)

  console.section('OUTPUT')
  console.field('measurements', emitter.path)
  console.field('records', len(records))
  console.field('ballots', out_path)
  console.field('verify with',
                f'python acceptance.py {emitter.path} {N}')

  return {'election_uuid': election_uuid, 'result': result,
          'jsonl': str(emitter.path), 'records': len(records)}


RUN_ID_RE = r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ-[0-9a-f]{4}'


def main(argv=None):
  # Parse CLI args
  p = argparse.ArgumentParser(description='Run one workload cell (spec PART 3)')
  p.add_argument('--scheme', default=None, help='default: first in levels.yaml')
  # Paillier only. Unset means the `paillier:` block in levels.yaml.
  p.add_argument('--crt-proofs', choices=('on', 'off'), default=None,
                 help='Paillier CRT decryption proofs; default from levels.yaml')
  p.add_argument('--n', type=int, default=None, help='default: first level')
  p.add_argument('--rep', type=int, default=0)
  p.add_argument('--face', default=None, help='ballot face key; default from config')
  p.add_argument('--headed', action='store_true', help='show the browser')
  # '2a' is accepted as an alias for '2' so older invocations keep working.
  # Skipping Stage 2 leaves the board empty, so Stage 3 will find nothing to
  # aggregate — useful only for exercising Stages 0/1 on their own.
  p.add_argument('--skip', default='', help='comma-separated: 2')
  p.add_argument('--strict', action='store_true',
                 help='treat provenance warnings as fatal (use for real runs)')
  p.add_argument('--no-preflight', action='store_true')
  # Prepared cells (prepare.py). Defaults from the `prepared:` block.
  g = p.add_mutually_exclusive_group()
  g.add_argument('--prepared', action='store_true', default=None,
                 help='S live ballots, N - S from the prepared set')
  g.add_argument('--live', action='store_true',
                 help='all N encrypted live, whatever prepared.use says')
  p.add_argument('--sample', type=int, default=None,
                 help='live sample size S; default prepared.sample_size')
  p.add_argument('--populate', choices=('cast', 'insert'), default=None,
                 help='how N - S reach the board; default prepared.populate')
  p.add_argument('--run-id', default=None,
                 help='use this run id (sweep.py picks it to find the output)')
  args = p.parse_args(argv)

  # Configuration settings
  cfg = helios_env.load_config('levels.yaml')
  faces = helios_env.load_config('ballot_face.yaml')
  pcfg = cfg.get('prepared') or {}
  use_prepared = (False if args.live
                  else bool(args.prepared or pcfg.get('use', False)))

  scheme = args.scheme or cfg['schemes'][0]
  N = args.n if args.n is not None else cfg['levels'][0] # N voters
  face_key = args.face or cfg['ballot_face'] # Curr choices: smoke or nle2025
  face = faces[face_key]
  skip = tuple(x.strip() for x in args.skip.split(',') if x.strip())
  base_url = helios_env.helios_url()

  # Gate BEFORE any stage runs. Not reachable by --skip: skipping a stage must
  # never be a route to emitting records that claim a scheme this checkout
  # cannot actually execute. See schemes.py.
  try:
    schemes.require(scheme)
  except (schemes.UnsupportedScheme, KeyError) as e:
    console.section('ABORTED')
    console.fail(str(e) if isinstance(e, schemes.UnsupportedScheme) else e.args[0])
    return 2

  # The arm, settled before anything runs: a flag the scheme cannot take, or a
  # short_name the form would refuse, stops the cell here rather than halfway.
  # The run id's suffix is always 4 characters, so a placeholder sizes the name.
  prep = None
  try:
    ablation = resolve_ablation(scheme, cfg,
                                crt_proofs=args.crt_proofs)
    if use_prepared:
      S = args.sample if args.sample is not None else pcfg.get('sample_size', 10)
      populate = args.populate or pcfg.get('populate', 'insert')
      if not 1 <= S <= N:
        raise ValueError(f'--sample {S} must be between 1 and N = {N}')
      prep = {'sample': S, 'populate': populate}
    short_name_for(arm_label(scheme, ablation), N, args.rep, 'xxxx',
                   prepared_tag(prep['populate']) if prep else '')
    if args.run_id and not re.fullmatch(RUN_ID_RE, args.run_id):
      raise ValueError(f'--run-id {args.run_id!r} is not a run id '
                       f'(e.g. 2026-08-17T04:22:31Z-a1b2)')
  except ValueError as e:
    console.section('ABORTED')
    console.fail(str(e))
    return 2

  # A prepared cell checks its set before anything runs: a set from another
  # face, seed, booth or key size, too short, or not validated to N, stops the
  # cell here. A different Helios commit is only a warning.
  if prep:
    from drivers import prepared_set
    from generator import votes as votes_gen
    try:
      prep['snapshot'] = prepared_set.snapshot_for_cell(
        face_key, votes_gen.build_questions(face), scheme, N, cfg)
    except prepared_set.SetUnusable as e:
      console.section('ABORTED')
      console.fail(str(e))
      return 2

  if not args.no_preflight:
    if not preflight.check(base_url, need_browser=('2a' not in skip),
                           strict=args.strict):
      return 2

  run_id = args.run_id or make_run_id()
  t0 = time.time() # time.time() usage as estimate; tbd for perf_counter_ns change
  with Emitter(run_id) as em:
    try:
      out = run_cell(scheme=scheme, N=N, rep=args.rep, cfg=cfg, face=face,
                     emitter=em, ablation=ablation, face_key=face_key,
                     headless=not args.headed, skip=skip, prep=prep)
    except Exception as e:
      console.section('ABORTED')
      console.fail(f'{type(e).__name__}: {e}')
      console.detail(f'partial output preserved at {em.path}')
      raise

  console.section('DONE')
  console.field('wall clock', console.dur(time.time() - t0)) # Note of time.time() usage; estimated elapse since Emitter object was activated
  console.field('records', out['records'])
  console.field('jsonl', out['jsonl'])
  return 0


if __name__ == '__main__':
  sys.exit(main())
