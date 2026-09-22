"""
Stage 2 — encryption measurement AND board population, both in a real browser

This module loads the booth page and drives the SAME `HELIOS.EncryptedAnswer`
constructor via `driver.execute_script`, timing it with performance.now() in page
context.
"""

import json
import math
import statistics
import time
from urllib.parse import urlencode

import console

# Headless webdriver 
def _driver(headless=True):
  from selenium import webdriver
  from selenium.webdriver.chrome.options import Options

  opts = Options()
  
  # Running headless browser: https://www.virtuosoqa.com/post/headless-browser-testing-with-selenium
  if headless:
    opts.add_argument('--headless=new')
  opts.add_argument('--no-sandbox')
  opts.add_argument('--disable-dev-shm-usage')
  return webdriver.Chrome(options=opts)

# Usage of performance.now() as a lighweight function for benchmarking
# Other alternatives like performance.measure() are ok as well but has more overhead and more recommended for multi-step workflows
# Performance.mark() and Performance.measure() extra object storage
# performance.now() = https://developer.mozilla.org/en-US/docs/Web/API/Performance/now

# Parse the election ONCE per page load and keep it in page context
# Hashes the whole election
_LOAD_ELECTION_JS = r"""
const [electionJson] = arguments;
window.__workload_election = HELIOS.Election.fromJSONString(electionJson);
return window.__workload_election.questions.length;
"""

# See the ff. class in helios.js >> HELIOS.EncryptedAnswer = Class.extend({...})
_ENCRYPT_JS = r"""
const [qNum, answerIndexes] = arguments;
const election = window.__workload_election;
if (!election) {
  throw new Error('election missing from page context — the booth page reloaded '
                  + 'between calls, so encryption would not be measured against '
                  + 'the election under test');
}

// Triggerred after construction via new HELIOS.EncryptedAnswer
const t0 = performance.now();
const ea = new HELIOS.EncryptedAnswer(
    election.questions[qNum], answerIndexes, election.public_key);
const t1 = performance.now();

// Serialization is deliberately AFTER t1: the ballot now travels back to Python
// so it can be cast, but turning it into JSON is not part of encryption and must
// not enter encryption_time_ms.
const json = ea.toJSONObject(false);

// UTF-8 byte length. Table 5 specifies UTF-8 bytes; String.length counts UTF-16
// code units and the two differ for any non-ASCII content.
const enc = new TextEncoder();
return {
  timing_ms: t1 - t0,
  ciphertext_bytes: enc.encode(JSON.stringify(json.choices)).length,
  proof_bytes: enc.encode(
      JSON.stringify([json.individual_proofs, json.overall_proof])).length,
  encrypted_answer: json
};
"""

# Encryption WITHOUT proofs, mirroring HELIOS.EncryptedAnswer.doEncryption
# (helios.js:262-276) exactly: same zero/one plaintexts, same randomness source,
# same ElGamal.encrypt call, same answer-index selection. What it omits is
# generateDisjunctiveProof per choice and the overall proof's homomorphic sum.
#
# encryption_time_ms - encryption_only_ms = proof generation. The hom_sum and
# rand_sum loops fall on the proof side, which is correct -- they exist only to
# build the overall proof.
_ENCRYPT_ONLY_JS = r"""
const [qNum, answerIndexes] = arguments;
const election = window.__workload_election;
if (!election) {
  throw new Error('election missing from page context');
}
const q  = election.questions[qNum];
const pk = election.public_key;
const zero_one = UTILS.generate_plaintexts(pk, 0, 1);

const t0 = performance.now();
for (var i = 0; i < q.answers.length; i++) {
  const idx = _(answerIndexes).include(i) ? 1 : 0;
  const r = Random.getRandomInteger(pk.q);
  ElGamal.encrypt(pk, zero_one[idx], r);
}
const t1 = performance.now();
return { timing_ms: t1 - t0 };
"""


def sample_encryptions(*, base_url, election_uuid, ballots, out_path=None,
                       headless=True, split_samples=30, warmup=1, log=print):
  """
  Encrypt `ballots` in a real browser, one record per ballot.

  Returns (samples, warmup_timings).

  samples is [{timing_ms, ciphertext_bytes, proof_bytes, timing_only_ms}], summed
  across questions so each entry is a whole ballot. timing_only_ms is 0.0 for
  ballots beyond `split_samples` -- the proof-free pass costs ~69% extra wall
  clock, and the split it establishes is a ratio, so it is sampled rather than
  run on every ballot (spec 10 section 11.1).

  `warmup` ballots are encrypted and discarded before measurement begins: the
  first ballots of a cell read high against steady state (997/1100/843 ms vs
  ~675 in the 2026-09-20 calibration). Their timings are returned separately so
  the caller can emit them tagged operational.

  If `out_path` is given, each ballot's encrypted answers are streamed there as
  JSONL -- one object per line, {ballot_index, encrypted_answers} -- as it is
  produced.
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election

  # Fetches Django election model from the database
  # Note: every Election instance is a normal Django ORM model, persisted in your PostgreSQL database
  election_json = Election.objects.get(uuid=election_uuid).toJSON()

  log(f'launching Chrome ({"headless" if headless else "headed"})')
  driver = _driver(headless=headless) # headless chrome webdriver
  samples = []
  warmup_timings = []
  out = open(out_path, 'w') if out_path else None
  # Cap the reporting interval: len//10 gives 20-minute blackouts at N=1000 on
  # the nle2025 face, which is indistinguishable from a hang.
  prog = console.Progress(len(ballots), 'ballots encrypted',
                          every=max(1, min(len(ballots) // 10, 25)))
  try:
    # The booth page pulls in all of jscrypto. Loading it gives us HELIOS.* in
    # page context without reimplementing the dependency order.
    driver.get(f'{base_url}/booth/vote.html') # Load this url
    # Script loads HELIOS from helios.js <script language="javascript" src="js/20160507-helios-booth-compressed.js"></script>
    if not driver.execute_script('return typeof HELIOS !== "undefined";'):
      raise RuntimeError(
        f'HELIOS is undefined after loading {base_url}/booth/vote.html — '
        f'jscrypto did not load. Check the server is serving /booth/.')
    log('booth jscrypto loaded — HELIOS.EncryptedAnswer available')


    # One parse for the whole run, mirroring a real booth page load.
    n_q = driver.execute_script(_LOAD_ELECTION_JS, election_json)
    log(f'election parsed once into page context — {n_q} questions')

    """
    Visualization for ballots/ballot
    ballots = [
            ballot 0                ballot 1                ballot 2
        [ [1, 3],   [0] ],   [ [0, 2, 4], [2] ],   [ [1],      [1] ],
           Q0 picks Q1 pick    Q0 picks   Q1 pick    Q0 picks  Q1 pick
    ]
    """
    # Warm-up: encrypt and discard. The booth's first encryptions in a fresh
    # page context read high (JIT warm-up in V8, plus CPU frequency ramp under
    # the powersave governor). Output is thrown away — these ballots are not
    # cast and not part of N.
    if warmup and ballots:
      log(f'warm-up: encrypting {warmup} ballot(s), discarded')
      for w in range(warmup):
        t = 0.0
        for q_num, answer_indexes in enumerate(ballots[0]):
          t += driver.execute_script(_ENCRYPT_JS, q_num,
                                     answer_indexes)['timing_ms']
        warmup_timings.append(t)
      log(f'warm-up timings: '
          f'{", ".join(f"{t:.0f} ms" for t in warmup_timings)}')

    """
    Visualization for ballots/ballot
    ballots = [
            ballot 0                ballot 1                ballot 2
        [ [1, 3],   [0] ],   [ [0, 2, 4], [2] ],   [ [1],      [1] ],
           Q0 picks Q1 pick    Q0 picks   Q1 pick    Q0 picks  Q1 pick
    ]
    """
    for i, ballot in enumerate(ballots): # Looping over the ballots
      total = {'timing_ms': 0.0, 'ciphertext_bytes': 0, 'proof_bytes': 0,
               'timing_only_ms': 0.0, 'split_sampled': i < split_samples}
      answers = []

      """
      Sample:
        - q_num=0, answer_indexes=[1,3]   --> encrypt Q0's answer
        - q_num=1, answer_indexes=[0]     --> encrypt Q1's answer
      """
      for q_num, answer_indexes in enumerate(ballot):
        # The election is already in page context; only the two small arguments
        # cross the WebDriver connection now, instead of the whole election JSON.
        r = driver.execute_script(_ENCRYPT_JS, q_num, answer_indexes)
        total['timing_ms'] += r['timing_ms']
        total['ciphertext_bytes'] += r['ciphertext_bytes']
        total['proof_bytes'] += r['proof_bytes']
        answers.append(r['encrypted_answer'])

        # Proof-free second pass, on the first `split_samples` ballots only.
        # Its output is discarded; the ballot that gets cast is the one above.
        if total['split_sampled']:
          ro = driver.execute_script(_ENCRYPT_ONLY_JS, q_num, answer_indexes)
          total['timing_only_ms'] += ro['timing_ms']

      if out: # Once write on jsonl file
        out.write(json.dumps({'ballot_index': i,
                              'encrypted_answers': answers}) + '\n')

      samples.append(total)
      prog.tick(i + 1)
  finally:
    driver.quit()
    if out:
      out.close() # Closing the open file from out_path

  prog.done()
  if out_path:
    log(f'wrote {out_path}')
  return samples, warmup_timings


def load_encrypted(path):
  """Yields {ballot_index, encrypted_answers} one line at a time.

  A generator, not a list: the caller casts each ballot as it is read, so the
  board can be populated at any N without the whole board being resident.
  """
  # Just like the idea of lazy-loading
  with open(path) as f:
    for line in f:
      if line.strip():
        yield json.loads(line) # Usage of yield generator -- one line at a time


def cast_ballots(*, base_url, election_uuid, encrypted, credentials, total=None,
                 log=print):
  """
  Cast each encrypted ballot through Helios's real flow:

      password_voter_login -> POST /cast -> POST /cast_confirm

  One fresh session per voter, because Helios keys the pending ballot to the
  session (views.one_election_cast stores it via save_in_session_across_logouts,
  and cast_confirm reads it back).

  `encrypted` may be a list or the generator from load_encrypted; `total` is the
  expected count, needed for the progress bar when a generator hides len().

  Returns (number successfully cast, per-ballot payload sizes).
  """
  from drivers.http_client import HeliosSession

  election_hash = _election_hash(election_uuid)

  n = total if total is not None else len(encrypted)
  if len(credentials) < n:
    raise RuntimeError(
      f'{n} ballots but only {len(credentials)} voter credentials — '
      f'Stage 0 registered fewer voters than N')

  cast = 0
  payloads = []
  prog = console.Progress(n, 'ballots cast', every=max(1, min(n // 10, 25)))
  for i, item in enumerate(encrypted):
    login_id, password, _voter_uuid = credentials[i] # From fetched credentials

    vote = {'answers': item['encrypted_answers'],
            'election_hash': election_hash,
            'election_uuid': election_uuid}

    # What actually crosses the wire, which ciphertext_bytes + proof_bytes does
    # not describe: those count cryptographic content only, omitting the JSON
    # structure, the election_hash/uuid wrapper fields, and form-encoding
    # expansion. The storage projection based on them understates the board.
    body = json.dumps(vote)
    payloads.append({
      'json_bytes': len(body.encode('utf-8')),
      'payload_bytes': len(urlencode({'encrypted_vote': body}).encode('utf-8')),
    })

    s = HeliosSession(base_url)
    s.login_voter(election_uuid, login_id, password) # Voter login

    # POST /cast does not check_csrf — one_election_cast only stashes the ballot
    # via save_in_session_across_logouts and redirects. requests follows that
    # redirect, so `r` is already the cast_confirm page, which renders the
    # csrf_token field. Reading it from there is exactly what a browser does.
    r = s.post(f'/helios/elections/{election_uuid}/cast',
               data={'encrypted_vote': body}, csrf=False)
    if not s.learn_csrf(r): # /cast_confirm contains csrf check for that (currently r)
      raise RuntimeError(
        f'no csrf_token on the cast_confirm page for voter {login_id}. '
        f'Landed on {r.url} — if that is not .../cast_confirm the ballot was '
        f'rejected before confirmation.')

    # cast_confirm DOES check_csrf (views.py:902): this is the one POST in the
    # cast flow that needs the token.
    s.post(f'/helios/elections/{election_uuid}/cast_confirm',
           data={'status_update': ''})
    cast += 1
    prog.tick(cast)

  prog.done()
  return cast, payloads


def _election_hash(election_uuid):
  import helios_env
  helios_env.setup_django()
  from helios.models import Election
  return Election.objects.get(uuid=election_uuid).hash

# Await verification formatted derived from Election object
def await_verification(election_uuid, expected, stall_s=120, poll_s=2.0,
                       log=print):
  """
  Cast ballots are verified by a Celery task (tasks.cast_vote_verify_and_store), so
  a ballot is not tallyable the instant the POST returns. Helios itself refuses to
  compute a tally while any vote is unverified — so Stage 3 cannot start until this
  drains.

  Waits on *lack of progress*, not on total elapsed time. The drain is linear in N
  (measured: ~0.52 s/ballot at --concurrency 1), so any fixed deadline is really a
  guess about throughput, and the previous flat 1800s went under-budget somewhere
  around N=4000 — aborting runs that were draining normally and blaming the worker.
  A healthy queue moves every poll; only a genuinely stuck one goes quiet.
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election

  t0 = time.time()
  last_progress = t0
  last = None
  while True:
    e = Election.objects.get(uuid=election_uuid)
    pending = e.num_pending_votes
    cast = e.voter_set.exclude(vote=None).count()
    if pending == 0 and cast >= expected:
      log(f'{cast}/{expected} verified in {time.time() - t0:.1f}s')
      return cast

    state = (pending, cast)
    if state != last: # Different from last printed
      log(f'celery: {cast}/{expected} verified, {pending} pending '
          f'({time.time() - t0:.0f}s elapsed)')
      last = state
      last_progress = time.time()
    elif time.time() - last_progress >= stall_s:
      raise TimeoutError(_stall_diagnosis(e, expected, cast, pending, stall_s))

    time.sleep(poll_s)


def _stall_diagnosis(election, expected, cast, pending, stall_s):
  """
  A stalled drain has two very different causes and they need different fixes.

  `cast` counts voters whose vote was stored, and store_vote only runs when
  verification SUCCEEDS. A ballot that fails verification gets invalidated_at set,
  which drops it out of num_pending_votes without ever reaching voter.vote — so
  `pending == 0 and cast >= expected` becomes unsatisfiable and the wait can never
  exit on its own. Quarantined ballots are excluded from the pending count for the
  same reason. Reporting either as "is a worker running?" sends you after the wrong
  thing entirely.
  """
  from helios.models import CastVote

  votes = CastVote.objects.filter(voter__election=election)
  invalidated = votes.exclude(invalidated_at=None).count()
  quarantined = votes.filter(quarantined_p=True).count()

  head = (f'ballot verification stalled: {cast}/{expected} verified, '
          f'{pending} pending, no change for {stall_s}s.')

  if invalidated or quarantined:
    return (f'{head} {invalidated} ballot(s) failed verification and '
            f'{quarantined} are quarantined; neither ever reaches voter.vote, so '
            f'this run cannot reach {expected} verified. The board is incomplete '
            f'— this cell should be discarded, not resumed.')

  return (f'{head} No ballot has failed verification, so the queue simply is not '
          f'draining: check that a Celery worker is running and consuming the '
          f'"celery" queue.')