"""
Stage 3 — homomorphic aggregation (spec §3.6).

WHICH Tally CLASS — helios.workflows.homomorphic, NOT helios.crypto.electionalgs
--------------------------------------------------------------------------------
Helios carries two parallel Tally implementations, and only one of them is live:

  helios/workflows/homomorphic.py   PRODUCTION. Election.encrypted_tally is
                                    LDObjectField(type_hint='legacy/Tally'), and
                                    datatypes/legacy.py binds that name via
                                    WRAPPED_OBJ_CLASS = homomorphic.Tally. This
                                    is what tasks.py and helios_trustee_decrypt
                                    actually operate on.

  helios/crypto/electionalgs.py     LEGACY. Nothing in the running system
                                    constructs it. Its
                                    decryption_factors_and_proofs is in fact
                                    BROKEN — it calls proof.toJSONDict(), which
                                    exists on neither elgamal.ZKProof nor
                                    algs.EGZKProof.

The harness must measure the code Helios runs, or the "system-level" framing in
the thesis does not hold. add_vote and decrypt_from_factors happen to be
byte-identical between the two apart from whitespace, so the aggregation figure
would have come out the same either way — but that is luck, not a guarantee, and
Stage 4 crashes outright on the legacy class.

verify_p=False MATCHES PRODUCTION — it is not a deviation
---------------------------------------------------------
`verify_p=True` is the DEFAULT in the function signature, but nothing in Helios
uses it. `Election.compute_tally` passes verify_p=False explicitly, with the
docstring "tally the election, assuming votes already verified"
(helios/models.py:485-491). This stage does the same thing for the same reason.

The assumption holds structurally, not by convention. `CastVote.verify_and_store`
calls `vote.verify(election)` and only calls `voter.store_vote(self)` when it
passes (models.py:1221-1234) — a ballot that fails verification never reaches
`voter.vote`, so `voter_set.exclude(vote=None)` cannot return one. On top of that,
`views.one_election_compute_tally` refuses to tally while `num_pending_votes > 0`.
By the time anything is aggregated, every ballot has been verified exactly once.

So verification is real production cost, but it is CAST-time cost, paid per ballot
in Celery as votes arrive and amortised across the voting period. It is not tally
cost. A verify_p=True pass here would price work Helios never performs — ~11 s per
ballot on the NLE face, or 30 hours at N = 10,000, inside a number labelled
"aggregation time".

Stage 2's `await_verification` is where that cast-time work is visible, since it
waits for exactly those Celery tasks to drain.
"""

from emit import Timer


def load_votes(election_uuid, log=print):
  """
  Pull the cast ballots off the bulletin board, exactly as Helios's own tally path
  does (see Election.compute_tally, which iterates voter_set).
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election

  election = Election.objects.get(uuid=election_uuid)
  # Rule to exclude voters with no-vote
  # cast_vote.save() in cast-confirm saves vote data to Voter (encrypted already)
  votes = [v.vote for v in election.voter_set.exclude(vote=None).order_by('uuid')]
  log(f'loaded {len(votes)} cast ballots from the bulletin board')
  return election, votes


def aggregate(election, votes, log=print):
  """
  Time the homomorphic tally.

  Returns (tally, aggregation_ns). The Tally object is returned so Stage 4 can
  decrypt the very object this stage built — re-deriving it would measure a
  different computation.
  """
  import helios_env
  helios_env.setup_django()
  from helios.workflows.homomorphic import Tally

  tally = Tally(election=election)

  # add_vote_batch in helios/workflows/homomorphic — "Add a batch of votes."
  with Timer() as t:
    tally.add_vote_batch(votes, verify_p=False) # verify_p=True checks if EACH ballot is well-formed

  log(f'{len(votes)} ballots in {t.ns / 1e6:.1f} ms '
      f'({t.ns / max(len(votes), 1) / 1e6:.2f} ms/ballot)')
  return tally, t.ns

