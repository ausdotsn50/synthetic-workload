"""
Stage 2, bulk population of a prepared cell: ballots S..N-1 of the prepared
set go onto the board without passing through the browser.

Two modes, chosen per cell (runner.py --populate):

  cast    stage2_cast.cast_ballots with the prepared items, then
          await_verification: the real HTTP + Celery path, ballot by ballot.
  insert  insert_ballots below: the rows a verified cast leaves behind, written
          directly. No Helios span runs, so nothing here is measured.

insert_ballots builds each row with the calls the real path makes, in order:

  body       json.dumps(vote, separators=(',', ':'))      stage2_cast.py:52-64
  vote_hash  cryptoutils.hash_b64(body)                     views.py:866
  vote       LDObject.fromDict(..., 'legacy/EncryptedVote') views.py:870
  CastVote(...).save()   save() sets the tinyhash           models.py ~1288
  voter.store_vote(cast_vote)                               models.py ~1209

verified_at is set at creation, which is what verify_and_store leaves on a
ballot that passes (models.py ~1313). The ballots it is allowed to skip
verifying were all verified once already, by prepare.py validate's sample and
by the spot check below.
"""

import datetime
import json
import random

import console


def _sidecar_rows(sidecar, election_uuid):
  from drivers import measure_join
  return sum(len(v) for v in
             measure_join.read_sidecar(sidecar, election_uuid).values())


def insert_ballots(*, election_uuid, encrypted, credentials, total, sidecar,
                   batch=200, log=print):
  """
  Store `encrypted` as verified casts for `credentials`, in order. Both start
  at the same ballot: credentials[k] receives the k-th item.

  Returns the number inserted. Raises unless the election then holds every
  voter's vote with none pending, and the sidecar gained no record for the
  election while inserting.
  """
  import helios_env
  helios_env.setup_django()
  from django.db import transaction
  from helios import datatypes, utils
  from helios.crypto import utils as cryptoutils
  from helios.models import CastVote, Election, Voter

  if len(credentials) < total:
    raise RuntimeError(f'{total} ballots to insert but {len(credentials)} voter '
                       f'credentials')

  e = Election.objects.get(uuid=election_uuid)
  election_hash = e.hash
  voters = {v.uuid: v for v in Voter.objects.filter(election=e)}
  sidecar_before = _sidecar_rows(sidecar, election_uuid)

  done = 0
  pending = []
  prog = console.Progress(total, 'ballots inserted',
                          every=max(1, min(total // 10, 500)))

  def flush():
    nonlocal done
    with transaction.atomic():
      for item, cred in pending:
        _login_id, _password, voter_uuid = cred
        vote = {'answers': item['encrypted_answers'],
                'election_hash': election_hash,
                'election_uuid': election_uuid}
        body = json.dumps(vote, separators=(',', ':'))
        now = datetime.datetime.utcnow()
        cast_vote = CastVote(
          vote=datatypes.LDObject.fromDict(
            utils.from_json(body), type_hint='legacy/EncryptedVote').wrapped_obj,
          voter=voters[voter_uuid],
          vote_hash=cryptoutils.hash_b64(body),
          cast_at=now, cast_ip=None, verified_at=now)
        cast_vote.save()
        voters[voter_uuid].store_vote(cast_vote)
        done += 1
    pending.clear()
    prog.tick(done)

  for k, item in enumerate(encrypted):
    if k >= total:
      break
    pending.append((item, credentials[k]))
    if len(pending) >= batch:
      flush()
  if pending:
    flush()
  prog.done()

  if done != total:
    raise RuntimeError(f'{done} ballots inserted, {total} expected — the '
                       f'prepared set ran out')
  after = _sidecar_rows(sidecar, election_uuid)
  if after != sidecar_before:
    raise RuntimeError(
      f'the sidecar gained {after - sidecar_before} record(s) for this election '
      f'during insert. No Helios span may run on this path; something did.')
  log(f'{done} ballots stored as verified casts; sidecar unchanged '
      f'({after} records for this election)')
  return done


def check_board(election_uuid, expected):
  """num_cast_votes == expected and nothing pending: the board a full cast
  and verification would leave."""
  import helios_env
  helios_env.setup_django()
  from helios.models import Election
  e = Election.objects.get(uuid=election_uuid)
  cast, pending = e.num_cast_votes, e.num_pending_votes
  if cast != expected or pending:
    raise RuntimeError(f'board holds {cast} cast votes and {pending} pending; '
                       f'expected {expected} and 0')
  return cast


def spot_verify(election_uuid, indices, credentials):
  """
  vote.verify(election) on the stored rows of the given ballot indices,
  untimed: the call CastVote.verify_and_store makes (models.py ~1310), on what
  insert actually wrote. Returns {index: bool}.
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import CastVote, Election
  e = Election.objects.get(uuid=election_uuid)
  out = {}
  for i in indices:
    voter_uuid = credentials[i][2]
    cv = CastVote.objects.get(voter__election=e, voter__uuid=voter_uuid)
    out[i] = bool(cv.vote.verify(e))
  return out


def spot_indices(start, stop, k, seed):
  """k reproducible random indices from [start, stop)."""
  pool = range(start, stop)
  return sorted(random.Random(seed).sample(pool, min(k, len(pool))))


def analyze():
  """ANALYZE helios_voter; ANALYZE helios_castvote; -- so the tally's
  voter_set query plans against the populated tables, whichever way they were
  filled. Returns seconds."""
  import time
  import helios_env
  helios_env.setup_django()
  from django.db import connection
  t0 = time.perf_counter()
  with connection.cursor() as c:
    c.execute('ANALYZE helios_voter')
    c.execute('ANALYZE helios_castvote')
  return time.perf_counter() - t0


def database_size():
  import helios_env
  helios_env.setup_django()
  from django.db import connection
  with connection.cursor() as c:
    c.execute('SELECT pg_database_size(current_database())')
    return int(c.fetchone()[0])
