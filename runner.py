"""
Sample command:
- uv run --project ../helios-server python runner.py --face smoke --n 10

Execution is SERIAL by design (§3.8). At ~6.5 s of pure computation per ballot,
concurrency on this machine would saturate CPU immediately and the numbers would
measure the OS scheduler rather than cryptography.

One cell == one election. Nothing is shared between cells: fresh election, fresh
trustee keypair, fresh voter list, fresh ballots.

Nothing here is run automatically. Every stage is invoked explicitly.
"""

import argparse
import os
import sys
import time

import console
import helios_env
import preflight
import schemes
from emit import Emitter, make_run_id

# Cell run equivalent to one election run
def run_cell(*, scheme, N, rep, cfg, face, emitter, face_key='?',
             headless=True, skip=()):
  # Usage of seed for reproducibility purposes
  seed_base = cfg['seed']
  base_url = helios_env.helios_url()
  helios_path = helios_env.helios_path()

  # Import of votes and voters module from generator/
  from generator import votes as votes_gen
  from generator import voters as voters_gen

  seed = votes_gen.cell_seed(seed_base, scheme, N, rep)
  questions = votes_gen.build_questions(face)
  short_name = f'wl-{scheme}-n{N}-r{rep}-{emitter.run_id[-4:]}' # Format for election short name

  n_answers = sum(len(q['answers']) for q in questions) # Sum of possible choices

  # Store records/walls
  records = []
  walls = {}

  # Record produced by emit in .json file
  def em(stage, metric, value, unit, extra=None):
    r = emitter.emit(scheme=scheme, N=N, rep=rep, seed=seed, stage=stage,
                     metric=metric, value=value, unit=unit, extra=extra)
    records.append(r)
    return r

  # Header formatted
  console.title('HELIOS WORKLOAD — cell execution')
  console.field('run_id', emitter.run_id)
  console.field('scheme', scheme)
  console.field('N (voters)', N)
  console.field('rep', rep)
  console.field('ballot face', f'{face_key} — {len(questions)} questions, '
                               f'{n_answers} answers')
  console.field('ciphertexts/ballot', n_answers)
  console.field('cell seed', seed)
  console.field('election', short_name)
  console.field('output', emitter.path)
  console.field('skipped', ', '.join(skip) if skip else '(nothing)')

  log = console.detail

  # Stage 0 - see stage0_configure.py
  # See console.py (using a Stage object for pipeline wall-clock)
  # with... as syntax triggers __enter__
  with console.Stage('STAGE 0 · CONFIGURE') as stg_zero:
    from drivers import stage0_configure
    console.step(f'creating election, uploading {N} voters')
    # Election uuid found via short name function in stage0_configure
    election_uuid = stage0_configure.configure( # Note: uuid creation upon the following configure
      base_url=base_url, short_name=short_name,
      name=f'Workload {scheme} N={N} rep={rep}',
      questions=questions, n_voters=N, log=log)
  
  # time_perf_counter_ns ends at with... as... statement
  # stored in walls array
  walls['stage 0 configure'] = stg_zero.wall
  # first and second records in jsonl file
  em('configure', 'election_created', 1, 'count',
     {'election_uuid': election_uuid, 'short_name': short_name,
      'n_questions': len(questions), 'n_answers': n_answers})
  em('configure', 'stage_wall_time_ns', int(stg_zero.wall * 1e9), 'ns',
     {'stage_name': 'configure', 'operational': True})

  # What every voter's browser downloads before it can render a ballot. The
  # endpoint already exists (views.one_election), so this needs no Helios
  # change -- it is measured by asking for it exactly as a booth would.
  try:
    from drivers.http_client import HeliosSession
    _r = HeliosSession(base_url).get(f'/helios/elections/{election_uuid}')
    em('configure', 'election_json_bytes', len(_r.content), 'bytes',
       {'tier': 'flow', 'source': 'harness',
        'note': 'GET /helios/elections/<uuid> — the booth download'})
  except Exception as e:
    console.warn(f'could not measure election JSON payload: '
                 f'{type(e).__name__}: {e}')

  # Stage 1 - freeze election
  from drivers import stage1_freeze
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
    stage1_freeze.freeze(base_url=base_url, election_uuid=election_uuid, log=log)
    walls['stage 1 freeze'] = time.perf_counter() - t0
  em('freeze', 'frozen', 1, 'count', {'election_uuid': election_uuid})

  # Stage 2 - browser encryption, measured, then cast to the board
  out_path = emitter.path.with_name(
    f'{emitter.run_id}-ballots-n{N}-r{rep}.jsonl') # Separate jsonl for the ballots
  
  with console.Stage('STAGE 2 · ENCRYPTION (browser) + CAST') as st:
    from drivers import stage2_encryption
    from generator import voters as voters_gen

    ballots = votes_gen.generate_ballots(seed, questions, N)

    console.step(f'encrypting {N} ballots in Chrome')
    console.detail('these ballots are cast — the measured population and the '
                    'aggregated population are the same ballots')

    enc_cfg = cfg.get('encryption', {})
    t0 = time.perf_counter()
    samples, warmup_timings = stage2_encryption.sample_encryptions(
      base_url=base_url, election_uuid=election_uuid, ballots=ballots,
      out_path=out_path, headless=headless,
      split_samples=enc_cfg.get('encrypt_split_samples', 30),
      warmup=enc_cfg.get('warmup_ballots', 1), log=log)
    walls['stage 2 encrypt'] = time.perf_counter() - t0

    # Discarded warm-up ballots: kept in the record, excluded from analysis.
    for i, t in enumerate(warmup_timings):
      em('encrypt', 'encryption_warmup_ms', t, 'ms',
         {'operational': True, 'sample': i, 'source': 'browser',
          'note': 'discarded warm-up ballot, not cast, not part of N'})

    for i, s in enumerate(samples):
      em('encrypt', 'encryption_time_ms', s['timing_ms'], 'ms',
          {'tier': 'operation', 'source': 'browser', 'sample': i})
      em('encrypt', 'ciphertext_bytes', s['ciphertext_bytes'], 'bytes',
          {'tier': 'operation', 'source': 'browser', 'sample': i})
      em('encrypt', 'proof_bytes', s['proof_bytes'], 'bytes',
          {'tier': 'operation', 'source': 'browser', 'sample': i})
      # The proof-free pass runs on the first encrypt_split_samples ballots
      # only; beyond that there is no split to emit.
      if s['split_sampled']:
        em('encrypt', 'encryption_only_ms', s['timing_only_ms'], 'ms',
            {'tier': 'operation', 'source': 'browser', 'sample': i})
        em('encrypt', 'encryption_proof_ms',
            max(s['timing_ms'] - s['timing_only_ms'], 0.0), 'ms',
            {'tier': 'operation', 'source': 'harness_derived', 'sample': i,
             'derived': True,
             'note': 'encryption_time_ms minus encryption_only_ms'})

    # One liveness line; the values themselves are reported under MEASURED.
    timings = [s['timing_ms'] for s in samples]
    mean_ms = sum(timings) / max(len(timings), 1)
    console.detail(f'{len(samples)} ballots encrypted, '
                   f'mean {mean_ms:.0f} ms — see MEASURED below')

    console.step('retrieving voter credentials')
    credentials = voters_gen.fetch_credentials(election_uuid)

    console.step(f'casting {N} ballots through the real HTTP flow')
    # perf_counter_ns, matching the other flow metrics; walls is derived from
    # it so there is one clock read, not two.
    t0 = time.perf_counter_ns()
    n_cast, payloads = stage2_encryption.cast_ballots(
      base_url=base_url, election_uuid=election_uuid,
      encrypted=stage2_encryption.load_encrypted(out_path),
      credentials=credentials, total=N, log=log)
    cast_ns = time.perf_counter_ns() - t0
    walls['stage 2 cast'] = cast_ns / 1e9

    # The cast phase, voter -> server, N times: login, POST /cast, POST
    # /cast_confirm per voter. Previously this was measured into walls only,
    # which is operational bookkeeping and excluded from analysis -- so the one
    # phase the voter actually experiences was absent from the flow tier.
    em('encrypt', 'flow_cast_ns', cast_ns, 'ns',
       {'tier': 'flow', 'n_ballots': n_cast,
        'per_ballot_ns': int(cast_ns / max(n_cast, 1)),
        'note': 'login + POST /cast + POST /cast_confirm, per voter'})

    # What crossed the wire, as opposed to ciphertext_bytes + proof_bytes which
    # count cryptographic content only.
    for i, p in enumerate(payloads):
      em('encrypt', 'cast_payload_bytes', p['payload_bytes'], 'bytes',
         {'tier': 'flow', 'sample': i, 'json_bytes': p['json_bytes']})

    console.step('waiting for Celery ballot verification')
    console.detail('Helios refuses to tally while any vote is unverified, so '
                    'Stage 3 cannot start until this drains')
    t0 = time.perf_counter()
    stage2_encryption.await_verification(election_uuid, n_cast, log=log)
    walls['stage 2 verify'] = time.perf_counter() - t0

  em('encrypt', 'stage_wall_time_ns', int(st.wall * 1e9), 'ns',
      {'stage_name': 'encrypt_and_cast', 'operational': True, 'n_ballots': n_cast})

  # ---- STAGES 3+4 · THE REAL FLOW, INSTRUMENTED -----------------------------
  # There is exactly ONE execution. Each stage drives its own phase through the
  # endpoint an administrator uses; Helios (branch measure/instrumentation)
  # times its own calls from the inside and appends them to the sidecar. The
  # harness joins on election uuid. Nothing is re-executed to be measured.
  from drivers import stage3_aggregate, stage4_decrypt, measure_join

  m_cfg = cfg.get('measurement', {})
  # HELIOS_MEASURE_PATH wins: it is the variable Helios itself reads, so taking
  # it from the same place removes any chance of the harness looking somewhere
  # the writer is not writing — a mismatch would look exactly like "no
  # instrumentation". config is the fallback for a shell that has not sourced
  # an env file.
  sidecar = os.path.expanduser(
    os.environ.get('HELIOS_MEASURE_PATH') or m_cfg.get('sidecar_path', ''))
  poll_s = m_cfg.get('poll_s', 0.05)
  timeout_s = m_cfg.get('timeout_s', 3600)

  with console.Stage('STAGE 3 · HOMOMORPHIC AGGREGATION (via endpoint)') as st3:
    console.step('POST /compute_tally, then wait for encrypted_tally')
    console.detail('aggregation runs in the Celery worker and is timed from '
                   'inside Helios; this measures the phase around it')
    f3 = stage3_aggregate.compute_tally(
      base_url=base_url, election_uuid=election_uuid,
      poll_s=poll_s, timeout_s=timeout_s, log=log)
  walls['stage 3 aggregate'] = st3.wall

  with console.Stage('STAGE 4 · DECRYPTION (via endpoints)') as st4:
    console.step('waiting for decryption_factors')
    console.detail('the task was already chained off Stage 3\'s POST — no '
                   'second request is issued here')
    f4 = stage4_decrypt.await_factors(
      election_uuid=election_uuid, since_ns=f3['signal_ns'],
      poll_s=poll_s, timeout_s=timeout_s, log=log)

    console.step('POST /combine_decryptions — synchronous, exact')
    combine_ns, flow_result = stage4_decrypt.combine(
      base_url=base_url, election_uuid=election_uuid, log=log)
  walls['stage 4 decrypt'] = st4.wall

  em('aggregate', 'flow_aggregate_ns', f3['flow_aggregate_ns'], 'ns',
     {'tier': 'flow', 'poll_interval_ms': f3['poll_interval_ms'],
      'n_votes': n_cast})
  em('decrypt', 'flow_decrypt_factors_ns', f4['flow_decrypt_factors_ns'], 'ns',
     {'tier': 'flow', 'poll_interval_ms': f3['poll_interval_ms']})
  em('decrypt', 'flow_combine_ns', combine_ns, 'ns',
     {'tier': 'flow', 'synchronous': True})
  em('decrypt', 'result', flow_result, 'tally', {'election_uuid': election_uuid})

  # ---- join Helios's own timings --------------------------------------------
  console.section('INSTRUMENTATION · joined from Helios sidecar')
  rows = measure_join.read_sidecar(sidecar, election_uuid)
  if not rows:
    msg = (f'no instrumentation records for election {election_uuid} in '
           f'{sidecar or "(no sidecar_path configured)"}.\n'
           f'  HELIOS_MEASURE_PATH must be set for BOTH the Django process and '
           f'the Celery worker, and helios-server must be on the '
           f'measure/instrumentation branch.')
    if m_cfg.get('require_instrumentation', True):
      raise RuntimeError(msg)
    console.warn(msg)
  else:
    for metric, metric_rows in sorted(rows.items()):
      if metric in measure_join.SKIP_EMIT:
        continue
      for r in metric_rows:
        em(measure_join.STAGE_OF.get(metric, 'decrypt'), metric, r['value'],
           r.get('unit', 'ns'), measure_join.extra_for(r))
      # No value echo here: every metric in this block reappears in a labelled
      # section below (MEASURED, ZKP, PAYLOADS). Printing it twice made the
      # section redundant as a list of values.

    # The one thing this section uniquely establishes: records arrived from
    # more than one process, so the work really ran where Helios runs it.
    # Values themselves are printed in the labelled sections below.
    _all = [x for v in rows.values() for x in v]
    _pids = sorted({x.get('pid') for x in _all if x.get('pid')})
    console.ok(f'{len(_all)} records joined from {len(_pids)} process(es): '
               + ', '.join(str(p) for p in _pids))
    if len(_pids) < 2:
      console.warn('all records from a single process — expected two (Django '
                   'web + Celery worker). The web process records keygen, '
                   'prove_sk, combine and both dlog metrics; if those are '
                   'absent, Django was started without HELIOS_MEASURE_PATH '
                   'and must be restarted, not just re-exported.')

    # ZKP split, decryption side. The factor-only pass does the same modexp
    # work without the Chaum-Pedersen proofs, so the remainder is proof
    # generation — the mirror of encryption_proof_ms on the browser side.
    def _first(metric):
      v = rows.get(metric)
      return v[0]['value'] if v else None

    ft, fo = _first('decryption_factor_time_ns'), _first('decryption_factor_only_ns')
    if ft is not None and fo is not None:
      em('decrypt', 'decryption_proof_ns', max(ft - fo, 0), 'ns',
         {'tier': 'operation', 'source': 'harness_derived', 'derived': True,
          'note': 'decryption_factor_time_ns minus decryption_factor_only_ns'})

    # Celery dispatch latency: worker task entry minus the harness's POST.
    # Cross-process wall clock, so disclosed as such rather than as a
    # perf_counter quantity.
    for task, ns in measure_join.dispatch_latency_ns(rows, f3['posted_at']).items():
      em('aggregate', 'celery_dispatch_ns', ns, 'ns',
         {'tier': 'flow', 'task': task, 'source': 'harness_derived',
          'clock': 'wall', 'note': 'task_start_wall_ns.started_at minus POST'})

  # Summary of results
  console.summary(records, N, walls)

  console.section('OUTPUT')
  console.field('measurements', emitter.path)
  console.field('records', len(records))
  console.field('ballots', out_path)
  console.field('verify with',
                f'python acceptance.py {emitter.path} {N}')

  return {'election_uuid': election_uuid, 'result': flow_result,
          'jsonl': str(emitter.path), 'records': len(records)}

def main(argv=None):
  # Parse CLI args
  p = argparse.ArgumentParser(description='Run one workload cell (spec PART 3)')
  p.add_argument('--scheme', default=None, help='default: first in levels.yaml')
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
  args = p.parse_args(argv)

  # Configuration settings
  cfg = helios_env.load_config('levels.yaml')
  faces = helios_env.load_config('ballot_face.yaml')

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

  if not args.no_preflight:
    if not preflight.check(base_url, need_browser=('2a' not in skip),
                           strict=args.strict):
      return 2

  run_id = make_run_id()
  t0 = time.time() # time.time() usage as estimate; tbd for perf_counter_ns change
  with Emitter(run_id) as em:
    try:
      out = run_cell(scheme=scheme, N=N, rep=args.rep, cfg=cfg, face=face,
                     emitter=em, face_key=face_key,
                     headless=not args.headed, skip=skip)
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
