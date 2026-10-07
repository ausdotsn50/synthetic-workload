"""
Stage 1 — ballot encryption in headless Chrome, with Helios's own booth code

Loads the booth page so HELIOS.* and jscrypto are in page context, parses the
election there once, and drives the booth's own `HELIOS.EncryptedAnswer`
constructor via `driver.execute_script`. Each encryption is timed with
performance.now() inside the page; proof generation is timed on the same pass
by a probe wrapped around the scheme's own generateDisjunctiveProof.

The same code drives every arm: the booth dispatches on the election's key, and
the harness only tells the probe which scheme's prototype to wrap. Under
Paillier 'short' and 'long', the booth's one-time DJN §4.1 fixed-base table
build is timed on its own before the warm-up, so no encryption timing holds it.

Encrypted ballots are streamed to a JSONL file as they are produced;
load_encrypted reads them back for Stage 2 to cast.
"""

import json

import console
import schemes

# Longest one execute_script may run. Each call encrypts one whole question in
# the booth, and Selenium's default (30 s) is less than Paillier needs on the
# nle2025 face: 66 and 156 answers at ~1.2 s each on a 2026-10-07 laptop run.
# Timing is taken in the page with performance.now(), so this only decides when
# the harness gives up -- it never enters a measurement.
SCRIPT_TIMEOUT_S = 1800

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
  driver = webdriver.Chrome(options=opts)
  driver.set_script_timeout(SCRIPT_TIMEOUT_S)
  return driver

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

# ZKP timing probe.
#
# Every proof in a ballot is produced by one function per scheme:
# ElGamal.Ciphertext.prototype.generateDisjunctiveProof (elgamal.js:245) or
# Paillier.Ciphertext.prototype.generateDisjunctiveProof (paillier.js:375).
# doEncryption calls it once per answer slot for the individual proofs
# (helios.js:270) and once more per question for the overall proof
# (helios.js:298), so wrapping the scheme's own one captures all ballot proof
# generation and nothing else. The scheme is passed in rather than guessed: the
# booth loads both libraries, and wrapping the other one would record nothing.
#
# The wrapper calls the original through .apply and returns its value untouched.
# Helios's own loop still drives the work, the proof that goes into the cast
# ballot is the real one, and there is no second encryption pass: this is the
# same shape as the server-side split, where tasks.py times verify_and_store and
# models.py times self.vote.verify inside it.
#
# What falls on the non-proof side is everything doEncryption does around these
# calls: generate_plaintexts, pk.encrypt per slot, the hom_sum/rand_sum loops,
# array construction. The hom_sum loop exists only to feed the overall proof,
# but it is not proof generation, and moving it across the line would mean
# judging Helios's code instead of timing it.
#
# Under Paillier DJN §4.1 ('short' and 'long') the Pi_root witness h^a mod n is
# derived from the stored exponent inside the proof itself
# (Paillier.Ciphertext.generateProof -> pk.proofWitness), so it counts as proof
# time. The ciphertext's own hn^a stays on the encryption side, where 'off''s
# v^n and ElGamal's encryption are.
_INSTALL_ZKP_PROBE_JS = r"""
const [scheme] = arguments;
const libName = scheme === 'paillier' ? 'Paillier' : 'ElGamal';
const lib = scheme === 'paillier'
    ? (typeof Paillier !== 'undefined' ? Paillier : null)
    : (typeof ElGamal !== 'undefined' ? ElGamal : null);
const target = libName + '.Ciphertext.prototype';
const proto = (lib && lib.Ciphertext) ? lib.Ciphertext.prototype : null;
if (!proto) {
  throw new Error(target + ' is not reachable on the booth page, so there is '
                  + 'nothing to wrap and encryption proof time cannot be '
                  + 'measured');
}

// The key the booth parsed must belong to the same scheme: its ciphertexts are
// the ones whose prototype is wrapped. A key of the other scheme would encrypt
// through the other prototype and never reach the wrapper.
const election = window.__workload_election;
const pk = election ? election.public_key : null;
if (!(lib.PublicKey && pk instanceof lib.PublicKey)) {
  throw new Error('the election key parsed on the booth page is not '
                  + (libName === 'ElGamal' ? 'an ' : 'a ') + libName
                  + '.PublicKey, so its encryptions would never reach '
                  + target + '.generateDisjunctiveProof');
}

const current = proto.generateDisjunctiveProof;
if (typeof current !== 'function') {
  throw new Error(target + '.generateDisjunctiveProof is '
                  + (typeof current) + ', not a function — this booth build has '
                  + 'moved the proof entry point, and installing the probe '
                  + 'anyway would silently measure nothing');
}

// Idempotent. A second install would nest one wrapper inside the other and
// bill every proof twice.
if (window.__workload_zkp) {
  if (window.__workload_zkp.target !== target) {
    throw new Error('the ZKP probe is already installed on '
                    + window.__workload_zkp.target + ', not ' + target);
  }
  return {installed: true, already_installed: true, target: target};
}

const acc = {ms: 0.0, calls: 0, target: target};
window.__workload_zkp = acc;
proto.generateDisjunctiveProof = function() {
  const s = performance.now();
  const out = current.apply(this, arguments);
  acc.ms += performance.now() - s;
  acc.calls += 1;
  return out;
};
return {installed: true, already_installed: false, target: target};
"""

# DJN §4.1 fixed-base tables, built and timed on their own (W7).
#
# Under 'short' and 'long' the key caches [hn^(2^i) mod n^2] and [h^(2^i) mod n]
# (paillier.js, PublicKey.fixedBaseTables), built on the first encryption and
# reused by every later one. Left alone, the build would land inside the
# discarded warm-up ballot and be recorded nowhere. Building it here, before the
# probe and the warm-up, times it exactly once per page load -- which in real
# use is once per voter, before their ballot -- and keeps it out of every
# encryption_time_ms.
_BUILD_DJN41_TABLES_JS = r"""
const [mode] = arguments;
const election = window.__workload_election;
const pk = election ? election.public_key : null;
if (!(typeof Paillier !== 'undefined' && pk instanceof Paillier.PublicKey)) {
  throw new Error('the election key on the booth page is not a '
                  + 'Paillier.PublicKey, so there are no DJN tables to build');
}
if (pk.djn41_mode !== mode) {
  throw new Error('the booth parsed the key in djn41_mode ' + pk.djn41_mode
                  + ', but the election was created in ' + mode);
}
if (typeof pk.fixedBaseTables !== 'function') {
  throw new Error('Paillier.PublicKey.fixedBaseTables is '
                  + (typeof pk.fixedBaseTables) + ', not a function — this '
                  + 'booth build has no fixed-base tables to time');
}
// Nothing may have built them yet, or part of the cost would already be paid
// and this would time a cache hit.
if (pk.tables !== null) {
  throw new Error('the fixed-base tables already exist before the measured '
                  + 'build, so their cost would be hidden');
}

const t0 = performance.now();
const tables = pk.fixedBaseTables();
const t1 = performance.now();
return {build_ms: t1 - t0, hn_len: tables.hn.length, h_len: tables.h.length};
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

// Zeroed here, not inside the probe, so what is read back below belongs to
// exactly this EncryptedAnswer and nothing that ran before it.
const zkp = window.__workload_zkp;
if (!zkp) {
  throw new Error('ZKP probe missing from page context — encryption proof time '
                  + 'would come back as zero, which is a lie rather than a '
                  + 'measurement');
}
zkp.ms = 0.0;
zkp.calls = 0;

// Triggerred after construction via new HELIOS.EncryptedAnswer
const t0 = performance.now();
const ea = new HELIOS.EncryptedAnswer(
    election.questions[qNum], answerIndexes, election.public_key);
const t1 = performance.now();

// Read immediately, before anything else on this page can call into the
// cryptosystem.
const proof_ms = zkp.ms;
const proof_calls = zkp.calls;

// Serialization is deliberately AFTER t1: the ballot now travels back to Python
// so it can be cast, but turning it into JSON is not part of encryption and must
// not enter encryption_time_ms.
const json = ea.toJSONObject(false);

// UTF-8 byte length. Table 5 specifies UTF-8 bytes; String.length counts UTF-16
// code units and the two differ for any non-ASCII content.
const enc = new TextEncoder();
return {
  timing_ms: t1 - t0,
  proof_ms: proof_ms,
  proof_calls: proof_calls,
  ciphertext_bytes: enc.encode(JSON.stringify(json.choices)).length,
  proof_bytes: enc.encode(
      JSON.stringify([json.individual_proofs, json.overall_proof])).length,
  encrypted_answer: json
};
"""

def sample_encryptions(*, base_url, election_uuid, ballots, scheme,
                       djn41_mode=None, out_path=None, headless=True, warmup=1,
                       log=print):
  """
  Encrypt `ballots` in a real browser, one record per ballot.

  Returns (samples, warmup_timings, table_build).

  samples is [{timing_ms, proof_ms, ciphertext_bytes, proof_bytes}], summed
  across questions so each entry is a whole ballot. timing_ms covers the booth's
  own `new HELIOS.EncryptedAnswer` and nothing else -- the operation the voter
  actually runs, not a harness-side re-creation of its parts.

  proof_ms is the part of timing_ms spent inside Helios's own
  generateDisjunctiveProof -- `scheme`'s own, ElGamal's or Paillier's --
  measured on the same single pass by the probe installed below. Every ballot
  carries it; there is no second pass to sample.

  table_build is {build_ms, hn_len, h_len} under Paillier with `djn41_mode`
  'short' or 'long': the one-time DJN §4.1 fixed-base table build, timed on its
  own before the warm-up so that no encryption timing contains it. None under
  ElGamal and under 'off', which have no tables.

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
  table_build = None
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

    # DJN §4.1 only: build the fixed-base tables now, timed, so that neither
    # the warm-up nor any measured ballot pays for them.
    if scheme == 'paillier' and djn41_mode in schemes.DJN41_TABLE_MODES:
      table_build = driver.execute_script(_BUILD_DJN41_TABLES_JS, djn41_mode)
      log(f'DJN §4.1 fixed-base tables built in '
          f'{table_build["build_ms"]:.0f} ms (hn: {table_build["hn_len"]} '
          f'entries, h: {table_build["h_len"]})')

    # Before any encryption, warm-up included: the probe throws rather than
    # no-opping if the proof entry point is not where it should be.
    probe = driver.execute_script(_INSTALL_ZKP_PROBE_JS, scheme)
    target = probe['target']
    log(f'ZKP probe installed on {target}.generateDisjunctiveProof')

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
      total = {'timing_ms': 0.0, 'proof_ms': 0.0,
               'ciphertext_bytes': 0, 'proof_bytes': 0}
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

        # doEncryption generates a disjunctive proof per answer slot, so any
        # question that encrypted at all made at least one call. Zero means the
        # wrapper is not on the path being exercised, and proof_ms would be a
        # fabricated 0.0 -- fail the run here rather than emit it.
        if not r['proof_calls']:
          raise RuntimeError(
            f'ZKP probe recorded no calls while encrypting question {q_num} of '
            f'ballot {i}. {target}.generateDisjunctiveProof was wrapped but '
            f'never ran, so encryption_proof_ms cannot be measured for this '
            f'run.')

        total['timing_ms'] += r['timing_ms']
        total['proof_ms'] += r['proof_ms']
        total['ciphertext_bytes'] += r['ciphertext_bytes']
        total['proof_bytes'] += r['proof_bytes']
        answers.append(r['encrypted_answer'])

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
  return samples, warmup_timings, table_build


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
