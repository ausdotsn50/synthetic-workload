"""
Stage 2 — cast the encrypted ballots, then wait for Celery verification

Casts each ballot through Helios's voter pages over HTTP, one fresh session per
voter: password login -> POST /cast -> POST /cast_confirm. No browser is
involved; the ballots were encrypted in Stage 1.

Helios verifies every cast ballot in a Celery task and refuses to tally while
any vote is unverified, so await_verification polls the database until the
board is fully verified. Stage 3 cannot start before that.
"""

import json
import time
from urllib.parse import urlencode

import console


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
    # Compact separators, matching the booth's JSON.stringify: without them
    # json.dumps adds a space after every ',' and ':'.
    body = json.dumps(vote, separators=(',', ':'))
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
