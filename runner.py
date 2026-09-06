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
import sys
import time

import console
import helios_env
import preflight
from emit import Emitter, make_run_id

# Cell run equivalent to one election run
def run_cell(*, scheme, N, rep, cfg, face, emitter, face_key='?',
             headless=True, skip=()):
  # Usage of seed for reproducibility purposes
  seed_base = cfg['seed']
  base_url = cfg['helios']['url'].rstrip('/')
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
  console.field('ciphertexts per ballot', n_answers)
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

  # Stage 1 - freeze election
  from drivers import stage1_freeze
  with console.Stage('STAGE 1 · FREEZE + KEY GENERATION') as st:
    if 'keygen' not in skip:
      console.step('sampling key generation (>= 30 independent keypairs)') # 30 is currently an arbitrary number
      console.detail('these are throwaway keypairs — the election\'s own key was '
                     'generated in Stage 0 by views.election_new')
      # Outer time for the whole measure_keygen operation
      t0 = time.perf_counter()
      
      # keygen_ns and prove_sk_ns as array of time measurements
      keygen_ns, prove_sk_ns = stage1_freeze.measure_keygen(
        scheme=scheme, n_samples=30, log=log)
      walls['stage 1 keygen'] = time.perf_counter() - t0

      # 
      for i, v in enumerate(keygen_ns):
        em('freeze', 'keygen_time_ns', v, 'ns', {'sample': i}) # enumerate func adds counter variable (i)
      for i, v in enumerate(prove_sk_ns):
        em('freeze', 'prove_sk_time_ns', v, 'ns', {'sample': i})
      console.metric('keygen_time_ns', f'{sum(keygen_ns) / len(keygen_ns) / 1e6:.2f}',
                     'ms (mean)', f'{len(keygen_ns)} samples emitted')
    else:
      console.warn('keygen sampling skipped')

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

    t0 = time.perf_counter()
    samples = stage2_encryption.sample_encryptions(
      base_url=base_url, election_uuid=election_uuid, ballots=ballots,
      out_path=out_path, headless=headless, log=log)
    walls['stage 2 encrypt'] = time.perf_counter() - t0

    for i, s in enumerate(samples):
      em('encrypt', 'encryption_time_ms', s['timing_ms'], 'ms',
          {'sample': i, 'source': 'selenium'})
      em('encrypt', 'ciphertext_bytes', s['ciphertext_bytes'], 'bytes',
          {'sample': i, 'source': 'selenium'})
      em('encrypt', 'proof_bytes', s['proof_bytes'], 'bytes',
          {'sample': i, 'source': 'selenium'})

    timings = [s['timing_ms'] for s in samples]
    mean_ms = sum(timings) / max(len(timings), 1)
    mean_ct = sum(s['ciphertext_bytes'] for s in samples) / max(len(samples), 1)
    mean_pf = sum(s['proof_bytes'] for s in samples) / max(len(samples), 1)
    console.metric('encryption_time_ms', f'{mean_ms:.1f}', 'ms/ballot',
                    f'{len(samples)} ballots')
    console.metric('ciphertext_bytes', console.size(mean_ct), '(mean)')
    console.metric('proof_bytes', console.size(mean_pf), '(mean)',
                    f'{100 * mean_pf / max(mean_ct + mean_pf, 1):.0f}% of ballot')

    console.step('retrieving voter credentials')
    credentials = voters_gen.fetch_credentials(election_uuid)

    console.step(f'casting {N} ballots through the real HTTP flow')
    t0 = time.perf_counter()
    n_cast = stage2_encryption.cast_ballots(
      base_url=base_url, election_uuid=election_uuid,
      encrypted=stage2_encryption.load_encrypted(out_path),
      credentials=credentials, total=N, log=log)
    walls['stage 2 cast'] = time.perf_counter() - t0

    console.step('waiting for Celery ballot verification')
    console.detail('Helios refuses to tally while any vote is unverified, so '
                    'Stage 3 cannot start until this drains')
    t0 = time.perf_counter()
    stage2_encryption.await_verification(election_uuid, n_cast, log=log)
    walls['stage 2 verify'] = time.perf_counter() - t0

  em('encrypt', 'stage_wall_time_ns', int(st.wall * 1e9), 'ns',
      {'stage_name': 'encrypt_and_cast', 'operational': True, 'n_ballots': n_cast})

  # Stage 3 - aggregate
  from drivers import stage3_aggregate
  with console.Stage('STAGE 3 · HOMOMORPHIC AGGREGATION') as st:
    election, votes = stage3_aggregate.load_votes(election_uuid, log=log)

    console.step('timing Tally.add_vote_batch(verify_p=False)')
    console.detail('verify_p defaults to True upstream; left alone it would fold'
                   '~11 s/ballot of proof checking into "aggregation time"')
    t0 = time.perf_counter() 
    tally, agg_ns, rss = stage3_aggregate.aggregate(election, votes, log=log)
    walls['stage 3 aggregate'] = time.perf_counter() - t0
    em('aggregate', 'aggregation_time_ns', agg_ns, 'ns',
       {'peak_rss_bytes': rss, 'verify_p': False, 'n_votes': len(votes)})
    console.metric('aggregation_time_ns', f'{agg_ns / 1e6:.1f}', 'ms',
                   f'{agg_ns / max(len(votes), 1) / 1e6:.2f} ms/ballot')
    console.metric('peak_rss_bytes', console.size(rss), '')

    # Only run at small N (verify_p=True)
    if N <= cfg.get('verification_metric_max_n', 0):
      console.step(f'measuring proof verification separately (N <= '
                   f'{cfg["verification_metric_max_n"]})')
      t0 = time.perf_counter()
      verify_ns = stage3_aggregate.measure_verification(election, votes, log=log)
      walls['stage 3 verify-pass'] = time.perf_counter() - t0
      em('aggregate', 'proof_verification_time_ns', verify_ns, 'ns',
         {'verify_p': True, 'n_votes': len(votes),
          'note': 'includes aggregation; subtract aggregation_time_ns for pure '
                  'verification cost'})
      pure = verify_ns - agg_ns
      console.metric('proof_verification (pure)', f'{pure / 1e9:.2f}', 's',
                     f'{pure / max(len(votes), 1) / 1e9:.2f} s/ballot')
    else:
      console.detail(f'proof-verification metric skipped — N={N} exceeds '
                     f'verification_metric_max_n='
                     f'{cfg.get("verification_metric_max_n", 0)}')

  # Stage 4: decrypt
  from drivers import stage4_decrypt
  with console.Stage('STAGE 4 · DECRYPTION') as st:
    console.step('decrypting the Tally object Stage 3 built')
    d = stage4_decrypt.decrypt(election, tally, log=log)
  walls['stage 4 decrypt'] = st.wall

  em('decrypt', 'decryption_factor_time_ns', d['decryption_factor_time_ns'], 'ns')
  em('decrypt', 'decryption_combine_time_ns', d['decryption_combine_time_ns'], 'ns')
  em('decrypt', 'dlog_precompute_time_ns', d['dlog_precompute_time_ns'], 'ns',
     {'dlog_entries': d['dlog_entries']})
  em('decrypt', 'dlog_lookup_time_ns', d['dlog_lookup_time_ns'], 'ns',
     {'derived': True,
      'note': 'decryption_combine_time_ns minus dlog_precompute_time_ns'})
  em('decrypt', 'result', d['result'], 'tally', {'election_uuid': election_uuid})

  console.metric('decryption_factor_time_ns',
                 f'{d["decryption_factor_time_ns"] / 1e6:.1f}', 'ms')
  console.metric('dlog_precompute_time_ns',
                 f'{d["dlog_precompute_time_ns"] / 1e6:.2f}', 'ms',
                 f'{d["dlog_entries"]} entries')
  console.metric('dlog_lookup_time_ns',
                 f'{d["dlog_lookup_time_ns"] / 1e6:.2f}', 'ms', 'DERIVED')

  # Summary of results
  console.summary(records, N, walls)

  console.section('OUTPUT')
  console.field('measurements', emitter.path)
  console.field('records', len(records))
  console.field('ballots', out_path)
  console.field('verify with',
                f'python acceptance.py {emitter.path} {N}')

  return {'election_uuid': election_uuid, 'result': d['result'],
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
  p.add_argument('--skip', default='', help='comma-separated: keygen,2')
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
  base_url = cfg['helios']['url'].rstrip('/')

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
