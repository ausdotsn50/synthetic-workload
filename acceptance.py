"""
Milestone 2 acceptance test.

    uv run --project ../helios-server python acceptance.py results/<run_id>.jsonl [N]

The same checks apply to both arms (elgamal, paillier-off); which metrics are required or forbidden follows from the
scheme and the ablation the records claim, both checked against the election.

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

# stage_name of each stage_wall_time_ns record runner.py emits.
STAGE_WALLS = {'stage 0 configure', 'stage 1 freeze', 'stage 2 encrypt',
               'stage 2 cast', 'stage 2 verify', 'stage 3 aggregate',
               'stage 4 decrypt'}
# A prepared cell also populates N - S ballots after the live sample.
PREPARED_STAGE_WALLS = STAGE_WALLS | {'stage 2 populate'}

# Per-ballot metrics of the live sample alone, in every prepared cell.
ENCRYPTION_METRICS = ('encryption_time_ms', 'encryption_proof_ms',
                      'ciphertext_bytes', 'proof_bytes')
# Per-ballot metrics of whatever went through the real cast path: the sample
# under insert, all N under cast.
CAST_METRICS = ('cast_payload_bytes', 'verification_time_ns',
                'verification_only_ns')

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
  # claimed_ablation also decides which metrics are required and forbidden
  # below. It stays
  # None when the records disagree or carry no stamp.
  claimed_ablation = None
  claimed_ablations = {json.dumps(r.get('extra', {}).get('ablation'), sort_keys=True)
                       for r in records}
  if len(claimed_ablations) > 1:
    c.fail('records agree on one ablation configuration',
           f'found {len(claimed_ablations)} distinct configurations in one run')
  else:
    claimed = json.loads(claimed_ablations.pop())
    claimed_ablation = claimed

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
           ', '.join(f'{k}={v}' for k, v in sorted(claimed.items()))
           or f'none — {scheme} has no ablation switches, stamped as {{}}')

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
  required = schemes.required_metrics(scheme, claimed_ablation)
  missing_m = required - metrics
  (c.ok if not missing_m else c.fail)(
    f'all required metrics present (for {scheme})',
    '' if not missing_m else 'missing: ' + ', '.join(sorted(missing_m)))

  # Symmetric to the above, and just as load-bearing: a Paillier run emitting
  # dlog_lookup_time_ns is reporting a stage that does not exist.
  forbidden = schemes.forbidden_metrics(scheme, claimed_ablation) & metrics
  (c.ok if not forbidden else c.fail)(
    f'no metrics emitted that {scheme} cannot produce',
    '' if not forbidden
    else 'present but impossible under this scheme: '
         + ', '.join(sorted(forbidden)))

  # === Option C: instrumented-in-place checks ==============================
  def _ex(r):
    return r.get('extra', {})

  def _by(metric, **want):
    return [r for r in records if r['metric'] == metric
            and all(_ex(r).get(k) == v for k, v in want.items())]

  instrumented = [r for r in records
                  if _ex(r).get('source') == 'helios_instrumentation']

  # --- 8.1 instrumentation present ---------------------------------------
  # Catches HELIOS_MEASURE_PATH unset on the worker, a helios-server checkout
  # without helios/measure.py (it is on master, and merged into
  # paillier-helios), or a span dropped in a merge.
  # Imported, not duplicated: a local copy drifted once already, leaving
  # acceptance checking a weaker set than the join required. measure_join is
  # the single source of truth for what Helios emits, and it imports only json
  # and os, so acceptance still runs without Django.
  from drivers.measure_join import REQUIRED_INSTRUMENTED
  if not instrumented:
    c.fail('Helios instrumentation present',
           'no records with source=helios_instrumentation — the sidecar was '
           'empty or unreadable. Check HELIOS_MEASURE_PATH on BOTH the Django '
           'process and the Celery worker.')
  else:
    required_i = (REQUIRED_INSTRUMENTED
                  - schemes.forbidden_metrics(scheme, claimed_ablation))
    missing_i = required_i - {r['metric'] for r in instrumented}
    (c.ok if not missing_i else c.fail)(
      f'all instrumented metrics present (for {scheme})',
      f'{len(instrumented)} records from Helios'
      if not missing_i else 'missing: ' + ', '.join(sorted(missing_i)))

    # --- 8.7 exactly one tally per election ------------------------------
    aggs = _by('aggregation_time_ns', source='helios_instrumentation')
    (c.ok if len(aggs) == 1 else c.fail)(
      'exactly one tally for this election',
      f'{len(aggs)} aggregation_time_ns record(s)'
      + ('' if len(aggs) == 1 else ' — the cell tallied more than once, so '
                                   'every number in it is suspect'))

    # --- 8.4 process separation ------------------------------------------
    # Aggregation runs in the Celery worker, the final decode in the web
    # process: the dlog lookup under ElGamal, decryption_time_ns (the same
    # loop) under Paillier. Equal pids mean the flow was not actually
    # exercised across processes.
    web_metric = ('dlog_lookup_time_ns' if spec.has_dlog
                  else 'decryption_time_ns')
    web = _by(web_metric, source='helios_instrumentation')
    if aggs and web:
      pa, pc = _ex(aggs[0]).get('pid'), _ex(web[0]).get('pid')
      if pa is None or pc is None:
        c.warn('worker and web process are distinct', 'pid missing on a record')
      elif pa != pc:
        c.ok('worker and web process are distinct',
             f'aggregation pid {pa}, {web_metric} pid {pc}')
      else:
        c.fail('worker and web process are distinct',
               f'both pid {pa} — either Celery ran eagerly in-process (a test '
               f'configuration, not a real run) or the flow was bypassed')

  # --- 8.8 tier and source completeness ----------------------------------
  untagged = sorted({
    r['metric'] for r in records
    if r['unit'] in ('ns', 'ms')
    and not _ex(r).get('tier') and not _ex(r).get('operational')})
  (c.ok if not untagged else c.fail)(
    'every timing carries tier or operational',
    '' if not untagged else 'untagged: ' + ', '.join(untagged))

  no_source = sorted({
    r['metric'] for r in records
    if _ex(r).get('tier') == 'operation' and not _ex(r).get('source')})
  (c.ok if not no_source else c.fail)(
    'every operation metric declares a source',
    '' if not no_source else 'no source: ' + ', '.join(no_source))

  # Measurements only: anything derivable is computed at print time.
  derived = sorted({
    r['metric'] for r in records
    if _ex(r).get('derived') is True
    or _ex(r).get('source') == 'harness_derived'})
  (c.ok if not derived else c.fail)(
    'no derived records emitted',
    '' if not derived else 'derived: ' + ', '.join(derived))

  # The console re-prints WALL CLOCK and the projection from these alone.
  created = next((r for r in records if r['metric'] == 'election_created'),
                 None)
  prepared = ((created or {}).get('extra') or {}).get('ballots') == 'prepared'
  want_walls = PREPARED_STAGE_WALLS if prepared else STAGE_WALLS
  walls = [_ex(r).get('stage_name') for r in records
           if r['metric'] == 'stage_wall_time_ns']
  missing_w = want_walls - set(walls)
  extra_w = sorted(set(walls) - want_walls, key=str)
  name_w = f'all {len(want_walls)} stage walls present'
  if not missing_w and not extra_w and len(walls) == len(want_walls):
    c.ok(name_w, f'{len(walls)} stage_wall_time_ns records')
  else:
    c.fail(name_w,
           f'{len(walls)} stage_wall_time_ns record(s)'
           + (f'; missing: {", ".join(sorted(missing_w))}' if missing_w else '')
           + (f'; unexpected: {", ".join(map(str, extra_w))}' if extra_w else ''))

  # --- 11.4 load stability across the cell -------------------------------
  loads = [r['load'][0] for r in records if isinstance(r.get('load'), list) and r['load']]
  if loads:
    first, peak = loads[0], max(loads)
    if peak > 1.5 * max(first, 0.1):
      c.warn('load stable across the cell',
             f'1-min load rose from {first:.2f} to {peak:.2f} '
             f'({peak / max(first, 0.01):.1f}x) — encryption timings are '
             f'sensitive to this even when operation metrics are not')
    else:
      c.ok('load stable across the cell', f'{first:.2f} -> {peak:.2f}')

  # --- ZKP splits: positive and bounded by their parent -------------------
  # This is the check that catches the regression class directly. The
  # decryption split vanished once before, when the Pass A module it lived in
  # stopped being called, and nothing noticed until an adviser asked.
  # Encryption is not here: its split is per-ballot and is checked ballot by
  # ballot below, not in aggregate.
  #
  # decryption_proof_ns is not emitted. It is computed here as the factor loop
  # minus the factors alone, so a missing part fails the check.
  pv = [r['value'] for r in records if r['metric'] == 'decryption_factor_time_ns']
  sv = [r['value'] for r in records if r['metric'] == 'decryption_factor_only_ns']
  if pv and not sv:
    c.fail('decryption_proof_ns computable',
           'decryption_factor_time_ns is measured but decryption_factor_only_ns '
           'is missing — processing and ZKP time cannot be separated')
  elif pv:
    dv = [p - s for p, s in zip(pv, sv)]
    bad = [x for x in dv if x <= 0]
    if bad:
      c.fail('decryption_proof_ns positive',
             f'{len(bad)} non-positive — factors alone were not faster than '
             f'factors plus proofs, so the split is noise, not signal')
    else:
      share = 100 * sum(dv) / sum(pv[:len(dv)])
      c.ok('decryption_proof_ns split valid',
           f'ZKP is {share:.0f}% of decryption_factor_time_ns')

  # --- encryption proof time is real, on every ballot ---------------------
  # encryption_proof_ms comes from a decorator on the booth's own
  # generateDisjunctiveProof. The failure mode that matters is not a wrong
  # number, it is a decorator that never fired: that reports 0.0, and every
  # share computed from it becomes a claim about work nobody timed. So this
  # fails, per ballot, rather than warning in aggregate.
  #
  # Bounded above by encryption_time_ms for the same reason the decryption
  # split is: proof generation happens inside the encryption it is part of, so
  # a proof time that equals or exceeds the whole is a measurement error.
  def _by_sample(metric_name, **want):
    out = {}
    for r in records:
      if r['metric'] != metric_name:
        continue
      e = r.get('extra', {}) or {}
      if any(e.get(k) != v for k, v in want.items()):
        continue
      out[e.get('sample')] = r['value']
    return out

  enc_total = _by_sample('encryption_time_ms', source='browser')
  enc_proof = _by_sample('encryption_proof_ms', source='browser')
  if enc_total and not enc_proof:
    c.fail('encryption_proof_ms present',
           'encryption is measured but its proof time is missing — the ZKP '
           'probe did not run, and the browser side of the ZKP split is gone')
  elif enc_proof:
    paired = [(i, enc_proof[i], enc_total[i]) for i in enc_proof
              if i in enc_total]
    orphan = [i for i in enc_proof if i not in enc_total]
    zero = [i for i, p, _t in paired if p <= 0]
    over = [i for i, p, t in paired if p >= t]
    if orphan:
      c.fail('every encryption_proof_ms pairs with a ballot',
             f'{len(orphan)} sample(s) have proof time but no '
             f'encryption_time_ms to bound it')
    elif zero:
      c.fail('encryption_proof_ms > 0 on every ballot',
             f'{len(zero)}/{len(paired)} ballot(s) report zero proof time — '
             f'the probe was installed but never fired, so this metric is '
             f'fabricated, not measured')
    elif over:
      c.fail('encryption_proof_ms < encryption_time_ms on every ballot',
             f'{len(over)}/{len(paired)} ballot(s) spent at least their whole '
             f'encryption inside proof generation, which is impossible — the '
             f'accumulator is not being zeroed per ballot')
    else:
      share = 100 * sum(p for _i, p, _t in paired) / sum(
        t for _i, _p, t in paired)
      c.ok('encryption proof split valid on every ballot',
           f'ZKP is {share:.0f}% of encryption_time_ms across '
           f'{len(paired)} ballot(s)')

  # --- verification split is sane -----------------------------------------
  # The ZKP table reports verification as essentially all proof checking. That
  # is now measured: if it drops below 90%, something other than verification
  # has become expensive and the table's framing needs revisiting.
  vt = [r['value'] for r in records if r['metric'] == 'verification_time_ns']
  vo = [r['value'] for r in records if r['metric'] == 'verification_only_ns']
  if vt and vo:
    import statistics as _st
    mt, mo = _st.median(vt), _st.median(vo)
    if not 0 < mo <= mt:
      c.fail('verification_only_ns within verification_time_ns',
             f'{mo / 1e6:.1f} ms vs {mt / 1e6:.1f} ms — the isolated span is '
             f'not inside the span containing it')
    elif mo / mt <= 0.90:
      c.warn('verification is essentially all proof checking',
             f'proof checking is {100 * mo / mt:.1f}% of verify_and_store — '
             f'below 90%, so the row writes are no longer negligible')
    else:
      c.ok('verification is essentially all proof checking',
           f'{100 * mo / mt:.1f}% is proof checking, '
           f'{100 * (mt - mo) / mt:.1f}% row writes')

  # --- aggregation split is sane ------------------------------------------
  # aggregation_only_ns accumulates around Tally.add_vote inside the
  # aggregation_time_ns span, so it must be strictly inside it. Zero means the
  # accumulator never fired and the crypto share would be a claim about work
  # nobody timed; at or above the parent means it is not measuring what it
  # says. One tally per cell, so these are single values, not medians.
  at = [r['value'] for r in records if r['metric'] == 'aggregation_time_ns']
  ao = [r['value'] for r in records if r['metric'] == 'aggregation_only_ns']
  if at and ao:
    pt, po = at[0], ao[0]
    if not 0 < po < pt:
      c.fail('aggregation_only_ns within aggregation_time_ns',
             f'{po / 1e6:.1f} ms vs {pt / 1e6:.1f} ms — the homomorphic '
             f'multiplication is not strictly inside the loop containing it')
    else:
      c.ok('aggregation_only_ns within aggregation_time_ns',
           f'{100 * po / pt:.1f}% is homomorphic multiplication, '
           f'{100 * (pt - po) / pt:.1f}% deserialization and row iteration')

  # --- payload sizes ------------------------------------------------------
  # Two from the harness, two from Helios.
  PAYLOADS = {'cast_payload_bytes', 'election_json_bytes',
              'decryption_factors_bytes', 'decryption_proofs_bytes'}
  present_payloads = PAYLOADS & {r['metric'] for r in records}
  if present_payloads:
    missing_p = PAYLOADS - present_payloads
    (c.ok if not missing_p else c.fail)(
      'all payload metrics present',
      f'{len(present_payloads)}/{len(PAYLOADS)}'
      if not missing_p else 'missing: ' + ', '.join(sorted(missing_p)))

    # The wire payload must exceed the cryptographic content it wraps: JSON
    # structure, wrapper fields and form-encoding all add bytes the
    # ciphertext+proof figure does not describe.
    cp = [r['value'] for r in records if r['metric'] == 'cast_payload_bytes']
    ct = [r['value'] for r in records if r['metric'] == 'ciphertext_bytes']
    pf = [r['value'] for r in records if r['metric'] == 'proof_bytes']
    if cp and ct and pf:
      n = min(len(ct), len(pf))
      worst = max(ct[i] + pf[i] for i in range(n))
      if min(cp) > worst:
        c.ok('cast payload exceeds ciphertext+proof',
             f'{min(cp) / 1024:.1f} KiB on the wire vs '
             f'{worst / 1024:.1f} KiB of crypto content '
             f'(+{100 * (min(cp) - worst) / worst:.1f}%)')
      else:
        c.fail('cast payload exceeds ciphertext+proof',
               f'smallest payload {min(cp)} <= largest content {worst}')

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

  # Key generation is measured inside Helios, once per election, for the key
  # the election actually used. There is no 30-sample harness population any
  # more: the distribution comes from repeated cells, and pooling a microbench
  # with a real-flow measurement would average across two processes.
  kg = [r for r in records if r['metric'] == 'keygen_time_ns']
  kg_election = [r for r in kg
                 if r.get('extra', {}).get('context') == 'election']
  if not kg:
    c.fail('keygen recorded', 'no keygen_time_ns record')
  elif len(kg_election) == 1 and len(kg) == 1:
    c.ok('keygen recorded once, in the real flow',
         f'{kg_election[0]["value"] / 1e6:.2f} ms, '
         f'source={kg_election[0].get("extra", {}).get("source")}')
  elif not kg_election:
    c.fail('keygen recorded in the real flow',
           f'{len(kg)} keygen record(s), none with context=election — the '
           f'election\'s own key generation was not measured')
  else:
    c.warn('keygen recorded once, in the real flow',
           f'{len(kg)} keygen records ({len(kg_election)} from the election) — '
           f'expected exactly one per cell')

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
      n_entries = (pre[0]['extra'].get('dlog_entries')
                   or pre[0]['extra'].get('num_tallied'))
      c.ok('dlog precompute ran', f'{pre[0]["value"] / 1e6:.1f} ms for '
                                  f'{n_entries} entries')
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

    # Exact, not merely plausible: the runner counts the cast plaintexts in the
    # clear, and every arm casts the same ballots, so both must match it.
    expected_tally = (res[-1].get('extra') or {}).get('expected')
    name = 'decrypted result equals the tally of the cast ballots'
    if expected_tally is None:
      c.warn(name, 'no expected tally recorded — this run predates it, so '
                   'only the bounds check below applies')
    elif tally == expected_tally:
      c.ok(name, f'{tally}')
    else:
      c.fail(name, f'Helios decrypted {tally}, but the cast plaintexts count '
                   f'{expected_tally} — the tally or its decryption is wrong')

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

  if prepared:
    _check_prepared(c, records, created, scheme)

  return c.report()


def _check_prepared(c, records, created, scheme):
  """
  The checks a prepared cell adds (§2.7). Live cells never reach here.

  The set's provenance is checked against the snapshot the runner recorded
  before Stage 0, not against whatever the set directory holds now: a set
  extended since this cell ran still describes this cell correctly.
  """
  import helios_env
  from drivers import prepared_set as ps
  from generator import votes as votes_gen

  ex = created.get('extra') or {}
  N = created['N']
  S = ex.get('sample_size')
  mode = ex.get('populate')
  c.ok('prepared cell', f'S = {S} live, {N - (S or 0)} by {mode}')

  def _ex(r):
    return r.get('extra') or {}

  def count(metric, **want):
    return sum(1 for r in records if r['metric'] == metric
               and all(_ex(r).get(k) == v for k, v in want.items()))

  snap_r = next((r for r in records if r['metric'] == 'prepared_set'), None)
  if snap_r is None:
    c.fail('prepared-set snapshot recorded', 'no prepared_set record')
    return
  snap = _ex(snap_r)
  m = snap.get('manifest') or {}

  # --- the tally: master[:N], counted again here, from config alone --------
  faces = helios_env.load_config('ballot_face.yaml')
  cfg = helios_env.load_config('levels.yaml')
  face_key = ex.get('ballot_face')
  questions = votes_gen.build_questions(faces[face_key])
  expected = votes_gen.expected_tally(
    questions, votes_gen.master_ballots(cfg['seed'], questions, N))
  res = next((r for r in reversed(records) if r['metric'] == 'result'), None)
  name = 'result equals expected_tally(master[:N])'
  if res is None:
    c.fail(name, 'no result record')
  elif res['value'] != expected:
    c.fail(name, f'Helios decrypted {res["value"]}, master[:{N}] counts '
                 f'{expected}')
  elif (_ex(res).get('expected')) != expected:
    c.fail(name, 'the runner recorded a different expected tally')
  else:
    c.ok(name, f'{expected}')

  # --- num_tallied == N ---------------------------------------------------
  tallied = {_ex(r).get('n_votes') for r in records
             if r['metric'] in ('aggregation_time_ns', 'aggregation_only_ns')}
  tallied |= {_ex(r).get('num_tallied') for r in records
              if r['metric'] == 'dlog_precompute_time_ns'}
  tallied.discard(None)
  (c.ok if tallied == {N} else c.fail)(
    'num_tallied == N', f'{sorted(tallied)} for N = {N}')

  # --- per-ballot counts ----------------------------------------------------
  bad = [f'{mtr} {count(mtr, source="browser")}' for mtr in ENCRYPTION_METRICS
         if count(mtr, source='browser') != S]
  (c.ok if not bad else c.fail)(
    f'encryption metrics count == S = {S}',
    'each of ' + ', '.join(ENCRYPTION_METRICS) if not bad else '; '.join(bad))

  want = S if mode == 'insert' else N
  bad = [f'{mtr} {count(mtr)}' for mtr in CAST_METRICS if count(mtr) != want]
  (c.ok if not bad else c.fail)(
    f'cast and verification metrics count == {"S" if mode == "insert" else "N"}'
    f' = {want}',
    'each of ' + ', '.join(CAST_METRICS) if not bad else '; '.join(bad))
  if mode == 'cast':
    tags = [_ex(r).get('ballot_source') for r in records
            if r['metric'] == 'verification_time_ns']
    ok = tags.count('sample') == S and tags.count('bulk') == N - S
    (c.ok if ok else c.fail)(
      'verification records tagged sample / bulk',
      f'{tags.count("sample")} sample, {tags.count("bulk")} bulk, '
      f'{len(tags) - tags.count("sample") - tags.count("bulk")} untagged')

  # --- the key ----------------------------------------------------------------
  fps = {ex.get('key_fingerprint'), m.get('key_fingerprint'),
         snap.get('key_fingerprint')}
  fps |= {_ex(r).get('key_fingerprint') for r in records
          if r['metric'] == 'key_fingerprint_checked'}
  ok = len(fps) == 1 and None not in fps and count('key_fingerprint_checked')
  (c.ok if ok else c.fail)(
    'election key fingerprint matches the manifest',
    next(iter(fps))[:16] if ok else f'fingerprints seen: {sorted(map(str, fps))}')

  # --- operational records ------------------------------------------------------
  for mtr in ('analyze', 'worker_restarted', 'pg_database_size'):
    (c.ok if count(mtr) == 1 else c.fail)(f'{mtr} record present',
                                          f'{count(mtr)} record(s)')
  wr = next((r for r in records if r['metric'] == 'worker_restarted'), None)
  if wr and _ex(wr).get('old_pid') == _ex(wr).get('new_pid'):
    c.fail('worker restarted into a new process',
           f'pid {_ex(wr).get("old_pid")} before and after')
  peaks = {r['stage'] for r in records if r['metric'] == 'worker_peak_rss_bytes'
           and r['value'] > 0}
  (c.ok if peaks >= {'aggregate', 'decrypt'} else c.fail)(
    'worker_peak_rss_bytes for Stage 3 and Stage 4',
    ', '.join(f'{r["stage"]} {r["value"] / (1 << 20):.0f} MiB' for r in records
              if r['metric'] == 'worker_peak_rss_bytes') or 'none')
  if mode == 'insert':
    (c.ok if count('bulk_spot_verified') == 1 else c.fail)(
      'bulk ballots spot-verified', f'{count("bulk_spot_verified")} record(s)')

  # --- the set's provenance against the current config and checkout ---------
  try:
    from drivers import fixed_key
    key_size = fixed_key.key_size(scheme)
  except Exception as e:
    key_size = m.get('key_size')
    c.warn('current Helios key size', f'unavailable ({type(e).__name__}); '
                                      f'not compared')
  problems = ps.identity_problems(
    m, face_key=face_key, questions=questions, seed=cfg['seed'],
    booth=ps.booth_js_hashes(), key_size=key_size)
  (c.ok if not problems else c.fail)(
    'manifest matches the current face, seed, booth JS and key size',
    'face, questions, seed, booth JS, key size' if not problems
    else '; '.join(problems))
  run_commit = records[0].get('env', {}).get('helios_commit')
  w = ps.commit_warning(m, run_commit)
  (c.warn if w else c.ok)('set made at the Helios commit the cell ran at',
                          w or run_commit)

  # --- validation -------------------------------------------------------------
  v = snap.get('validation') or {}
  ok = v.get('passed') and (v.get('validated_count') or 0) >= N
  (c.ok if ok else c.fail)(
    'validation.json passed with validated_count >= N',
    f'passed={v.get("passed")}, validated_count={v.get("validated_count")}, '
    f'N={N}')
  # A set found bad after this cell ran makes the cell's board suspect too.
  now = ps.read_json(ps.validation_path(snap.get('dir', ''))) if snap.get('dir') \
      else None
  if now is not None and not now.get('passed'):
    c.fail('the set still validates', f'{snap["dir"]}/validation.json now FAILS')


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(2)
  expected = int(sys.argv[2]) if len(sys.argv) > 2 else 10
  print(f'Milestone 2 acceptance — {sys.argv[1]}\n')
  sys.exit(0 if check(sys.argv[1], expected) else 1)
