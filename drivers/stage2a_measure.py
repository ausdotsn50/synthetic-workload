"""
Stage 2a — sampled encryption measurement in a real browser 

This module loads the booth page and drives the SAME
`HELIOS.EncryptedAnswer` constructor via `driver.execute_script`, timing it with
performance.now() in page context.
"""

import json
import math
import statistics

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

# See the ff. class in helios.js >> HELIOS.EncryptedAnswer = Class.extend({...})
_ENCRYPT_JS = r"""
const [electionJson, qNum, answerIndexes] = arguments;
const election = HELIOS.Election.fromJSONString(electionJson);

// Triggerred after construction via new HELIOS.EncryptedAnswer
const t0 = performance.now();
const ea = new HELIOS.EncryptedAnswer(
    election.questions[qNum], answerIndexes, election.public_key);
const t1 = performance.now();

const json = ea.toJSONObject(false);

// UTF-8 byte length. Table 5 specifies UTF-8 bytes; String.length counts UTF-16
// code units and the two differ for any non-ASCII content.
const enc = new TextEncoder();
return {
  timing_ms: t1 - t0,
  ciphertext_bytes: enc.encode(JSON.stringify(json.choices)).length,
  proof_bytes: enc.encode(
      JSON.stringify([json.individual_proofs, json.overall_proof])).length
};
"""


def sample_encryptions(*, base_url, election_uuid, ballots, headless=True,
                       log=print):
  """
  Encrypt `ballots` in a real browser, one record per ballot.

  Returns [{timing_ms, ciphertext_bytes, proof_bytes}], summed across questions so
  each entry is a whole ballot.
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
  prog = console.Progress(len(ballots), 'ballots encrypted',
                          every=max(1, len(ballots) // 10))
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
    
    """
    Visualization for ballots/ballot
    ballots = [
            ballot 0                ballot 1                ballot 2
        [ [1, 3],   [0] ],   [ [0, 2, 4], [2] ],   [ [1],      [1] ],
           Q0 picks Q1 pick    Q0 picks   Q1 pick    Q0 picks  Q1 pick
    ]
    """
    for i, ballot in enumerate(ballots): # Looping over the pilot ballots
      total = {'timing_ms': 0.0, 'ciphertext_bytes': 0, 'proof_bytes': 0}
      
      """
      Sample:
        - q_num=0, answer_indexes=[1,3]   --> encrypt Q0's answer
        - q_num=1, answer_indexes=[0]     --> encrypt Q1's answer
      """
      for q_num, answer_indexes in enumerate(ballot):
        r = driver.execute_script(_ENCRYPT_JS, election_json, q_num,
                                  answer_indexes) # election_json, q_num, answer_indexes as arguments for ENCRYPT_JS
        total['timing_ms'] += r['timing_ms']
        total['ciphertext_bytes'] += r['ciphertext_bytes']
        total['proof_bytes'] += r['proof_bytes']
      samples.append(total)
      prog.tick(i + 1)
  finally:
    driver.quit()

  prog.done()
  return samples