"""
Milestone 2 acceptance test.

    uv run --project ../helios-server python acceptance.py results/<run_id>.jsonl

Spec PART 5 defines Milestone 2 as done when "Stages 0-4 produce JSONL for N = 10".
That is a floor, not a definition of correct: a harness can emit well-formed JSONL
full of wrong numbers. These checks therefore test the properties that would be
silently violated by a plausible bug.

Read-only. Verifies an existing run; never produces one.
"""

import glob
import json
import os
import sys

import schemes

# 'encrypt' replaces the former 'encrypt_sample' + 'encrypt_bulk' pair: Stage 2
# now encrypts once in the browser and casts what it measured, so there is a
# single encryption population instead of a measured one and an aggregated one.
REQUIRED_STAGES = {'configure', 'freeze', 'encrypt',
                   'aggregate', 'decrypt'}

# Required metrics are SCHEME-DEPENDENT (build spec §8.3). The dlog metrics
# belong to ElGamal alone; requiring them of a Paillier run would fail a correct
# run, which is how a guard turns into an obstacle. See schemes.required_metrics.

ENV_KEYS = {'host', 'cpu', 'py', 'node', 'helios_commit', 'workload_commit'}


class Check:
  def __init__(self):
    self.passed, self.failed, self.warned = [], [], []

  def ok(self, name, detail=''):
    self.passed.append((name, detail))

  def fail(self, name, detail=''):
    self.failed.append((name, detail))

  def warn(self, name, detail=''):
    self.warned.append((name, detail))

  def report(self):
    for n, d in self.passed:
      print(f'  PASS  {n}' + (f' — {d}' if d else ''))
    for n, d in self.warned:
      print(f'  WARN  {n}' + (f' — {d}' if d else ''))
    for n, d in self.failed:
      print(f'  FAIL  {n}' + (f' — {d}' if d else ''))
    print(f'\n{len(self.passed)} passed, {len(self.warned)} warnings, '
          f'{len(self.failed)} failed')
    return not self.failed


def load(path):
  """Parse line by line so a truncated final record is reported, not fatal."""
  records, bad = [], 0
  with open(path) as f:
    for i, line in enumerate(f, 1):
      line = line.strip()
      if not line:
        continue
      try:
        records.append(json.loads(line))
      except json.JSONDecodeError:
        bad += 1
        print(f'  (line {i} is not valid JSON — truncated write?)')
  return records, bad


def _observed_from_ballots(path):
  """
  Identify the scheme from the ballots this run actually produced.

  The ballots file sits beside the measurements file and holds the serialized
  encrypted answers exactly as the browser emitted them. A ciphertext's field
  set is decided by the cryptosystem, so it cannot agree with a mislabeled
  record by accident.

  Returns (scheme_key, evidence_str) or (None, reason).
  """
  d = os.path.dirname(os.path.abspath(path))
  run_id = os.path.basename(path)[:-len('.jsonl')]
  matches = sorted(glob.glob(os.path.join(d, f'{run_id}-ballots-*.jsonl')))
  if not matches:
    return None, 'no ballots file beside the measurements file'

  try:
    with open(matches[0]) as f:
      for line in f:
        line = line.strip()
        if not line:
          continue
        rec = json.loads(line)
        for answer in rec.get('encrypted_answers', []):
          for choice in answer.get('choices', []):
            got = schemes.observed_scheme(choice)
            if got:
              return got, (f'{os.path.basename(matches[0])}: ciphertext fields '
                           f'{sorted(choice)}')
            return None, f'ciphertext fields {sorted(choice)} match no scheme'
  except Exception as e:
    return None, f'could not read ballots file: {type(e).__name__}: {e}'
  return None, 'ballots file held no ciphertext'


def _observed_from_db(records):
  """
  Read the scheme back off the election row, if Django is reachable.

  Best-effort and strictly secondary to the ballot evidence: acceptance is
  documented as read-only over a results file, and must still work when the
  database is gone.
  """
  uuid = None
  for r in records:
    if r['metric'] == 'election_created':
      uuid = r.get('extra', {}).get('election_uuid')
  if not uuid:
    return None, 'no election_uuid in the records'
  try:
    import helios_env
    helios_env.setup_django()
    from helios.models import Election
    e = Election.objects.get(uuid=uuid)
    return getattr(e, 'crypto_scheme', 'elgamal'), f'Election<{uuid}>.crypto_scheme'
  except Exception as e:
    return None, f'database unreachable: {type(e).__name__}: {e}'


def _observed_ablation(records):
  """
  Read the optimization configuration back off the election row.

  Same principle as the scheme cross-check, one level down. An ablation study
  whose results cannot be traced to what the election actually did is not an
  ablation study -- and the switches were previously process-wide settings,
  invisible to the results and settable on the wrong process entirely.
  """
  uuid = None
  for r in records:
    if r['metric'] == 'election_created':
      uuid = r.get('extra', {}).get('election_uuid')
  if not uuid:
    return None, 'no election_uuid in the records'
  try:
    import helios_env
    helios_env.setup_django()
    from helios.models import Election
    e = Election.objects.get(uuid=uuid)
    return e.ablation_config, f'Election<{uuid}>'
  except Exception as exc:
    return None, f'database unreachable: {type(exc).__name__}: {exc}'


def check(path, expected_n=10):
  c = Check()
  records, bad = load(path)

  if not records:
    c.fail('records present', 'file is empty')
    return c.report()

  c.ok('JSONL parses', f'{len(records)} records'
       + (f', {bad} malformed' if bad else ''))
  if bad:
    c.warn('malformed lines', f'{bad} — expected only on an interrupted run')

  # --- the scheme the records CLAIM --------------------------------------
  claimed = {r.get('scheme') for r in records}
  if len(claimed) != 1:
    c.fail('records agree on one scheme', f'found {sorted(claimed)}')
    return c.report()
  scheme = claimed.pop()
  try:
    spec = schemes.get(scheme)
  except KeyError as e:
    c.fail('scheme is registered', str(e))
    return c.report()
  c.ok('records agree on one scheme', scheme)

  # --- ...against the scheme the run PRODUCED (§8.1) ----------------------
  # This is the check whose absence let `--scheme paillier --skip keygen` run a
  # complete ElGamal election, stamp "paillier" on all ~71 records, and pass.
  # A stamp is a claim; a ballot is evidence.
  ballot_scheme, ballot_why = _observed_from_ballots(path)
  db_scheme, db_why = _observed_from_db(records)

  if ballot_scheme is None and db_scheme is None:
    c.fail('emitted scheme matches what the run produced (§8.1)',
           f'could not corroborate {scheme!r} from any artifact — '
           f'ballots: {ballot_why}; db: {db_why}')
  else:
    for got, why in ((ballot_scheme, ballot_why), (db_scheme, db_why)):
      if got is None:
        c.warn('scheme corroboration unavailable', why)
      elif got != scheme:
        c.fail('emitted scheme matches what the run produced (§8.1)',
               f'records claim {scheme!r} but {why} shows {got!r} — '
               f'this run is mislabeled')
      else:
        c.ok('emitted scheme matches what the run produced (§8.1)', why)

  # --- the ablation the records CLAIM, against what the election DID -------
  claimed_ablations = {json.dumps(r.get('extra', {}).get('ablation'), sort_keys=True)
                       for r in records}
  if len(claimed_ablations) > 1:
    c.fail('records agree on one ablation configuration',
           f'found {len(claimed_ablations)} distinct configurations in one run')
  else:
    claimed = json.loads(claimed_ablations.pop())

    if claimed is None:
      if spec.key == 'paillier':
        c.warn('ablation configuration recorded',
               'no ablation stamped on the records — this run predates the '
               'per-election ablation switches, so which optimizations were '
               'active cannot be recovered')
      else:
        c.ok('ablation configuration recorded',
             f'not applicable to {scheme}')
    else:
      c.ok('ablation configuration recorded',
           ', '.join(f'{k}={v}' for k, v in sorted(claimed.items())))

      observed, why = _observed_ablation(records)
      if observed is None:
        c.warn('ablation corroboration unavailable', why)
      elif observed != claimed:
        c.fail('emitted ablation matches what the election did',
               f'records claim {claimed} but {why} shows {observed} — this '
               f'run is mislabeled')
      else:
        c.ok('emitted ablation matches what the election did', why)

  # --- schema ------------------------------------------------------------
  stages = {r['stage'] for r in records}
  missing = REQUIRED_STAGES - stages
  (c.ok if not missing else c.fail)(
    'all stages emitted',
    'stages: ' + ', '.join(sorted(stages)) if not missing
    else 'missing: ' + ', '.join(sorted(missing)))

  metrics = {r['metric'] for r in records}
  required = schemes.required_metrics(scheme)
  missing_m = required - metrics
  (c.ok if not missing_m else c.fail)(
    f'all required metrics present (for {scheme})',
    '' if not missing_m else 'missing: ' + ', '.join(sorted(missing_m)))

  # Symmetric to the above, and just as load-bearing: a Paillier run emitting
  # dlog_lookup_time_ns is reporting a stage that does not exist.
  forbidden = schemes.forbidden_metrics(scheme) & metrics
  (c.ok if not forbidden else c.fail)(
    f'no metrics emitted that {scheme} cannot produce',
    '' if not forbidden
    else 'present but impossible under this scheme: '
         + ', '.join(sorted(forbidden)))

  bad_env = [r for r in records if not ENV_KEYS <= set(r.get('env', {}))]
  (c.ok if not bad_env else c.fail)(
    'env captured per record (§4.1)',
    '' if not bad_env else f'{len(bad_env)} records missing env keys')

  # Both commits, because the two repos version independently — one hash cannot
  # pin a measurement.
  sample_env = records[0]['env']
  if sample_env.get('helios_commit') and sample_env.get('workload_commit'):
    c.ok('both commit hashes recorded',
         f"helios={sample_env['helios_commit']} "
         f"workload={sample_env['workload_commit']}")
  else:
    c.fail('both commit hashes recorded', 'a run is not reproducible without both')

  if sample_env.get('helios_dirty') or sample_env.get('workload_dirty'):
    c.warn('working tree clean',
           'a commit hash does not describe a dirty tree — this run is not '
           'exactly reproducible')

  # --- the measurement decisions that are easy to get silently wrong -----
  agg = [r for r in records if r['metric'] == 'aggregation_time_ns']
  if agg and all(r['extra'].get('verify_p') is False for r in agg):
    c.ok('aggregation measured with verify_p=False (§0.4)',
         'proof verification is not hidden inside aggregation time')
  else:
    c.fail('aggregation measured with verify_p=False (§0.4)',
           'add_vote_batch defaults to verify_p=True — at ~11 s/ballot that '
           'silently inflates aggregation time')

  if {'ciphertext_bytes', 'proof_bytes'} <= metrics:
    c.ok('ballot size split (§0.5 / PART 6 item 4)')
  else:
    c.fail('ballot size split (§0.5 / PART 6 item 4)')

  if 'proof_verification_time_ns' in metrics:
    c.fail('no verify_p=True pass at tally time',
           'production never verifies during compute_tally — this record should '
           'not exist')
  else:
    c.ok('no tally-time verification, matching Election.compute_tally')

  keygen = [r for r in records if r['metric'] == 'keygen_time_ns']
  (c.ok if len(keygen) >= 30 else c.fail)(
    'keygen sampled >= 30 times (§3.3)', f'{len(keygen)} samples')

  # --- values are plausible, not merely present --------------------------
  nonpositive = [r for r in records
                 if r['unit'] in ('ns', 'ms')
                 and isinstance(r['value'], (int, float))
                 and r['value'] <= 0]
  (c.ok if not nonpositive else c.fail)(
    'all timings positive',
    '' if not nonpositive
    else f'{len(nonpositive)} non-positive, e.g. '
         f'{nonpositive[0]["metric"]}={nonpositive[0]["value"]}')

  # Θ(N) dlog precompute: with N entries at ~24-26 µs each, a precompute that
  # took no measurable time means it never ran.
  #
  # The ~13 µs in IMPLEMENTATION_SPEC.md §0.1 is superseded and must not be
  # cited: claude/run_analysis_n10.md §2.1 measured ~23.8 µs and the N=1000 run
  # 26.0 µs on this machine. The same stale figure appears in
  # notes/paillier_dlog_hypothesis_verification.md.
  #
  # ElGamal only. Under a scheme with no discrete-log stage the metric is
  # correctly absent, and demanding it here would fail a correct run — the
  # precise failure build spec §8.3 flags.
  if spec.has_dlog:
    pre = [r for r in records if r['metric'] == 'dlog_precompute_time_ns']
    if pre and all(r['value'] > 0 for r in pre):
      c.ok('dlog precompute ran', f'{pre[0]["value"] / 1e6:.1f} ms for '
                                  f'{pre[0]["extra"].get("dlog_entries")} entries')
    elif pre:
      c.fail('dlog precompute ran', 'zero time — the Θ(N) step did not execute')
    else:
      c.fail('dlog precompute ran',
             f'{scheme} decrypts through a dlog table but emitted no '
             f'dlog_precompute_time_ns')
  else:
    c.ok('dlog metrics correctly absent',
         f'{scheme} has no discrete-log stage — omitted rather than zeroed')

  # --- the real correctness signal ---------------------------------------
  res = [r for r in records if r['metric'] == 'result']
  if not res:
    c.fail('decrypted result present')
  else:
    tally = res[-1]['value']
    n_votes = None
    for r in records:
      if r['metric'] == 'aggregation_time_ns':
        n_votes = r['extra'].get('n_votes')
    totals = [sum(q) for q in tally] if tally else []
    c.ok('decrypted result present', f'per-question totals {totals}')

    # Each question's votes must sum to at most (max selections) x (voters). For a
    # max=1 question the total equals the number of voters who selected anything.
    # A tally that decrypts to garbage will not satisfy this, so it is a cheap,
    # high-signal check that the homomorphic path is actually correct — not merely
    # that it produced numbers.
    if n_votes and totals:
      if all(0 <= t <= n_votes * 12 for t in totals):
        c.ok('tally within achievable bounds',
             f'{totals} for {n_votes} voters')
      else:
        c.fail('tally within achievable bounds',
               f'{totals} impossible for {n_votes} voters — decryption is wrong')

  cast = [r for r in records if r['metric'] == 'aggregation_time_ns']
  if cast:
    got = cast[0]['extra'].get('n_votes')
    (c.ok if got == expected_n else c.fail)(
      f'N = {expected_n} ballots tallied', f'got {got}')

  return c.report()


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(2)
  expected = int(sys.argv[2]) if len(sys.argv) > 2 else 10
  print(f'Milestone 2 acceptance — {sys.argv[1]}\n')
  sys.exit(0 if check(sys.argv[1], expected) else 1)
