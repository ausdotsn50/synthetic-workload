"""
Stage 0 — election configuration

Creates the election in the requested arm, saves the ballot face, uploads the
voter list, opens eligibility. Driven through Helios's own HTTP API.

Measures nothing. Setup only -- apart from confirming, from the database, that
the election is the arm that was asked for.
"""

import json
import time

from drivers.http_client import HeliosSession
from generator import voters as voters_gen
from generator import votes as votes_gen


def configure(*, base_url, short_name, name, questions, n_voters, scheme,
              ablation, celery_timeout_s=600, poll_s=2.0, log=print):
  """
  Returns the election uuid. Raises if Helios rejects any step, or if the
  election it created is not the arm that was asked for.

  `scheme` is the cryptosystem, 'elgamal' or 'paillier'. `ablation` is the
  Paillier configuration in Election.ablation_config's shape: {} for ElGamal,
  {'paillier_djn41_mode': ..., 'paillier_use_crt_proofs': ...} for Paillier.
  """
  s = HeliosSession(base_url).login_devlogin()

  # See helios/forms.py for ElectionForm schema
  # Generates trustee keypair
  # election.generate_trustee(crypto_params_for(election)) in election_new in views.py
  data = {
    'short_name': short_name,
    'name': name,
    'description': 'Synthetic workload election. Not a real vote.',
    'election_type': 'election',
    'use_voter_aliases': '',
    'randomize_answer_order': '',
    'private_p': '',
    'help_email': '',
    'voting_starts_at': '',
    'voting_ends_at': '',
    'crypto_scheme': scheme,
  }
  if scheme == 'paillier':
    # The mode is a three-way choice. The CRT flag is read from the raw post
    # (helios/forms.py, _raw_flag), so it goes as '1' or '0'. The retired
    # boolean paillier_use_djn41 is never posted: the form refuses it.
    data['paillier_djn41_mode'] = ablation['paillier_djn41_mode']
    data['paillier_use_crt_proofs'] = (
      '1' if ablation['paillier_use_crt_proofs'] else '0')

  log(f'POST /helios/elections/new  short_name={short_name}  '
      f'crypto_scheme={scheme}  ablation={ablation}')
  s.post('/helios/elections/new', data=data) # Note: Helios has its own tests.py file

  uuid = _find_election_uuid(s, short_name)
  if not uuid:
    raise RuntimeError(
      f'election {short_name!r} was not created. A soft-deleted election may still '
      f'hold the short_name — short_name is UNIQUE at the DB level and soft delete '
      f'does not release it.')
  log(f'election uuid = {uuid}')

  # Before anything else: is this the arm that was asked for?
  _check_arm(uuid, scheme, ablation, log)

  # Add questions
  # POST json formatted questions func in helios/views.py 
  # Admin op: def one_election_save_questions(request, election):
  log(f'POST save_questions  {len(questions)} questions, '
      f'{sum(len(q["answers"]) for q in questions)} answers '
      f'({sum(len(q["answers"]) for q in questions)} ciphertexts per ballot)')
  r = s.post(f'/helios/elections/{uuid}/save_questions',
             data={'questions_json': json.dumps(questions)}) # json.dumps; converts Python obj to json string
  if 'SUCCESS' not in r.text.upper():
    raise RuntimeError(f'save_questions rejected the ballot face: {r.text[:200]}')

  # Upload voters
  # voters_upload function in views.py // elections_url.py
  log(f'POST voters/upload  {n_voters} voters (preview, then confirm)')
  csv_text = voters_gen.build_voter_csv(n_voters)
  s.post(f'/helios/elections/{uuid}/voters/upload',
         data={}, # False bool
         files={'voters_file': ('voters.csv', csv_text, 'text/csv')})
  # Two-step: the first POST parses and previews, the second confirms and queues
  # the Celery job (views.voters_upload -> tasks.voter_file_process.delay).
  s.post(f'/helios/elections/{uuid}/voters/upload', data={'confirm_p': '1'})

  _await_voters(uuid, n_voters, celery_timeout_s, poll_s, log)
  return uuid


def _check_arm(uuid, scheme, ablation, log):
  """
  Read the new election back and fail fast unless it is the arm that was posted.

  A form that dropped or misread a field would otherwise run a whole cell under
  the wrong configuration -- the failure the retired paillier_use_djn41 flag
  once produced, when '0' parsed as True. Checked on the election row AND on
  the key the trustee actually generated: a Paillier key carries its own mode,
  and a standard ('off') key carries no h or hn.
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election

  e = Election.objects.get(uuid=uuid)
  problems = []
  if e.crypto_scheme != scheme:
    problems.append(f'crypto_scheme is {e.crypto_scheme!r}, posted {scheme!r}')
  if e.ablation_config != ablation:
    problems.append(f'ablation_config is {e.ablation_config}, posted {ablation}')

  trustee = e.get_helios_trustee()
  pk = trustee.public_key if trustee else None
  if pk is None:
    problems.append('no Helios trustee key was generated')
  elif scheme == 'paillier':
    want = ablation['paillier_djn41_mode']
    got = getattr(pk, 'djn41_mode', None)
    if got != want:
      problems.append(f'the trustee key is in djn41_mode {got!r}, requested '
                      f'{want!r}')
    if got == 'off' and (getattr(pk, 'h', None) is not None
                         or getattr(pk, 'hn', None) is not None):
      problems.append("the trustee key is 'off' but carries h/hn")
  elif getattr(pk, 'y', None) is None:
    problems.append(f'the trustee key is not an ElGamal key: '
                    f'{type(pk).__name__}')

  if problems:
    raise RuntimeError(f'election {uuid} is not the arm that was requested: '
                       + '; '.join(problems))
  log(f'arm confirmed on the election row and the trustee key: {scheme} '
      f'{ablation}')


def _find_election_uuid(session, short_name):
  """Resolve short_name -> uuid via the public shortcut route."""
  # Verified with urls.py
  r = session.s.get(session.url(f'/helios/e/{short_name}'), allow_redirects=True)
  if r.status_code != 200:
    return None
  # Final URL looks like /helios/elections/<uuid>/view
  for part in r.url.split('/'):
    if len(part) == 36 and part.count('-') == 4:
      return part
  return None


def _await_voters(uuid, expected, timeout_s, poll_s, log):
  """
  Voter-file processing is a Celery task, so the upload POST returns before any
  Voter row exists. Poll until they appear.

  If this times out, the usual cause is no Celery worker running — the job sits
  queued in RabbitMQ indefinitely and nothing is lost, but nothing progresses
  either.
  """
  deadline = time.time() + timeout_s
  t0 = time.time()
  seen = -1
  last = None
  while time.time() < deadline: # Rmv for later, unnecessary time unit measure
    seen = voters_gen.count_registered(uuid)
    if seen >= expected:
      log(f'{seen}/{expected} voters registered')
      return
    if seen != last:
      log(f'celery voter_file_process: {seen}/{expected} '
          f'({time.time() - t0:.0f}s elapsed)')
      last = seen
    time.sleep(poll_s)
  raise TimeoutError(
    f'only {seen}/{expected} voters registered after {timeout_s}s. '
    f'Is a Celery worker running? '
    f'(uv run celery --app helios worker --events --beat --concurrency 1)')


def build_face(face_cfg):
  """ballot_face.yaml entry -> Helios question dicts."""
  return votes_gen.build_questions(face_cfg)
