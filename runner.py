"""
Sample commands, one per measured arm:
- uv run --project ../helios-server python runner.py --face smoke --n 10
- uv run --project ../helios-server python runner.py --face smoke --n 10 --scheme paillier --djn41-mode off
- uv run --project ../helios-server python runner.py --face smoke --n 10 --scheme paillier --djn41-mode short
- uv run --project ../helios-server python runner.py --face smoke --n 10 --scheme paillier --djn41-mode long

The arm is the scheme plus, under Paillier, its DJN §4.1 mode: elgamal,
paillier-off, paillier-short, paillier-long. All four cast the same ballots at
the same (N, rep) -- see generator/votes.py, cell_seed -- so arms compare
pairwise. --djn41-mode and --crt-proofs default to the `paillier:` block in
config/levels.yaml ('off' and CRT on, the server's own defaults).

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

DJN41_MODES = ('off', 'short', 'long')

# ElectionForm.short_name is a SlugField(max_length=40); a longer name is
# refused by the form, and the election is never created.
SHORT_NAME_MAX = 40


def resolve_ablation(scheme, cfg, djn41_mode=None, crt_proofs=None):
  """
  The configuration a cell runs under, in Election.ablation_config's shape:
  {} under ElGamal, {'paillier_djn41_mode', 'paillier_use_crt_proofs'} under
  Paillier. A flag given on the command line wins over the `paillier:` block
  in config/levels.yaml. Raises ValueError on a flag the scheme cannot take.
  """
  if scheme != 'paillier':
    if djn41_mode is not None or crt_proofs is not None:
      raise ValueError(f'--djn41-mode and --crt-proofs apply only to '
                       f'--scheme paillier, and this cell is {scheme!r}')
    return {}

  p = cfg.get('paillier') or {}
  mode = djn41_mode if djn41_mode is not None else p.get('djn41_mode', 'off')
  if mode not in DJN41_MODES:
    raise ValueError(
      f'paillier djn41_mode is {mode!r}, not one of {DJN41_MODES}. In YAML a '
      f"bare off is the boolean false: write it quoted, 'off'.")
  crt = ((crt_proofs == 'on') if crt_proofs is not None
         else p.get('crt_proofs', True))
  if not isinstance(crt, bool):
    raise ValueError(f'paillier crt_proofs is {crt!r}, not true or false')
  return {'paillier_djn41_mode': mode, 'paillier_use_crt_proofs': crt}


def arm_label(scheme, ablation):
  """elgamal, or paillier-<djn41 mode>: the four measured arms."""
  if scheme == 'paillier':
    return f"paillier-{ablation['paillier_djn41_mode']}"
  return scheme


def short_name_for(arm, N, rep, run_id):
  """The election's short_name, refused before anything runs if the form would
  refuse it."""
  name = f'wl-{arm}-n{N}-r{rep}-{run_id[-4:]}'
  if len(name) > SHORT_NAME_MAX:
    raise ValueError(f'election short_name {name!r} is {len(name)} characters; '
                     f'Helios accepts at most {SHORT_NAME_MAX}')
  return name


# Cell run equivalent to one election run
def run_cell(*, scheme, N, rep, cfg, face, emitter, ablation, face_key='?',
             headless=True, skip=()):
  # Usage of seed for reproducibility purposes
  seed_base = cfg['seed']
  base_url = helios_env.helios_url()
  helios_path = helios_env.helios_path()

  # Import of votes and voters module from generator/
  from generator import votes as votes_gen
  from generator import voters as voters_gen

  arm = arm_label(scheme, ablation)
  # Not keyed on the arm: every arm at this (N, rep) casts the same ballots.
  seed = votes_gen.cell_seed(seed_base, N, rep)
  questions = votes_gen.build_questions(face)
  short_name = short_name_for(arm, N, rep, emitter.run_id) # Format for election short name

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
      name=f'Workload {arm} N={N} rep={rep}',
      questions=questions, n_voters=N, scheme=scheme, ablation=ablation,
      log=log)

  # time_perf_counter_ns ends at with... as... statement
  stage_wall('configure', 'stage 0 configure', stg_zero.wall)
  em('configure', 'election_created', 1, 'count',
     {'election_uuid': election_uuid, 'short_name': short_name,
      'arm': arm, 'ballot_face': face_key,
      'n_questions': len(questions), 'n_answers': n_answers})

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
    stage_wall('freeze', 'stage 1 freeze', time.perf_counter() - t0)

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
    from drivers import stage2_encryption
    from generator import voters as voters_gen

    ballots = votes_gen.generate_ballots(seed, questions, N)

    console.step(f'encrypting {N} ballots in Chrome')
    console.detail('these ballots are cast — the measured population and the '
                    'aggregated population are the same ballots')

    enc_cfg = cfg.get('encryption', {})
    t0 = time.perf_counter()
    samples, warmup_timings, table_build = stage2_encryption.sample_encryptions(
      base_url=base_url, election_uuid=election_uuid, ballots=ballots,
      scheme=scheme, djn41_mode=ablation.get('paillier_djn41_mode'),
      out_path=out_path, headless=headless,
      warmup=enc_cfg.get('warmup_ballots', 1), log=log)
    stage_wall('encrypt', 'stage 2 encrypt', time.perf_counter() - t0)

    # Paillier 'short' and 'long' only: the booth's one-time DJN §4.1
    # fixed-base table build, timed on its own before the warm-up. Once per
    # cell, because the booth builds the tables once per page load.
    if table_build is not None:
      em('encrypt', 'djn41_table_build_ms', table_build['build_ms'], 'ms',
         {'tier': 'operation', 'source': 'browser',
          'hn_table_len': table_build['hn_len'],
          'h_table_len': table_build['h_len'],
          'note': 'built once per booth page load, so in real use once per '
                  'voter, before their ballot; encryption_time_ms excludes it'})

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
      # Measured in flow, on the same single pass as encryption_time_ms: a
      # decorator on the booth's own generateDisjunctiveProof, so this is
      # Helios's proof generation, not a re-creation of it.
      em('encrypt', 'encryption_proof_ms', s['proof_ms'], 'ms',
          {'tier': 'operation', 'source': 'browser', 'sample': i})
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

    console.step(f'casting {N} ballots through the real HTTP flow')
    t0 = time.perf_counter()
    n_cast, payloads = stage2_encryption.cast_ballots(
      base_url=base_url, election_uuid=election_uuid,
      encrypted=stage2_encryption.load_encrypted(out_path),
      credentials=credentials, total=N, log=log)
    stage_wall('encrypt', 'stage 2 cast', time.perf_counter() - t0)

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
    stage_wall('encrypt', 'stage 2 verify', time.perf_counter() - t0)

  # ---- STAGES 3+4 · THE REAL FLOW, INSTRUMENTED -----------------------------
  # There is exactly ONE execution. Each stage drives its own phase through the
  # endpoint an administrator uses; Helios (helios/measure.py -- on master, and
  # merged into paillier-helios, which the server runs) times its own calls
  # from the inside and appends them to the sidecar. The harness joins on
  # election uuid. Nothing is re-executed to be measured.
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
                   'inside Helios')
    f3 = stage3_aggregate.compute_tally(
      base_url=base_url, election_uuid=election_uuid,
      poll_s=poll_s, timeout_s=timeout_s, log=log)
  stage_wall('aggregate', 'stage 3 aggregate', st3.wall)

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
    for metric, metric_rows in sorted(rows.items()):
      if metric in measure_join.SKIP_EMIT:
        continue
      for r in metric_rows:
        em(measure_join.STAGE_OF.get(metric, 'decrypt'), metric, r['value'],
           r.get('unit', 'ns'), measure_join.extra_for(r))
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

def main(argv=None):
  # Parse CLI args
  p = argparse.ArgumentParser(description='Run one workload cell (spec PART 3)')
  p.add_argument('--scheme', default=None, help='default: first in levels.yaml')
  # Paillier only. Unset means the `paillier:` block in levels.yaml.
  p.add_argument('--djn41-mode', choices=DJN41_MODES, default=None,
                 help="Paillier encryption function: 'off' (standard), or DJN "
                      "§4.1 'short' or 'long'; default from levels.yaml")
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

  # The arm, settled before anything runs: a flag the scheme cannot take, or a
  # short_name the form would refuse, stops the cell here rather than halfway.
  # The run id's suffix is always 4 characters, so a placeholder sizes the name.
  try:
    ablation = resolve_ablation(scheme, cfg, djn41_mode=args.djn41_mode,
                                crt_proofs=args.crt_proofs)
    short_name_for(arm_label(scheme, ablation), N, args.rep, 'xxxx')
  except ValueError as e:
    console.section('ABORTED')
    console.fail(str(e))
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
                     emitter=em, ablation=ablation, face_key=face_key,
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
