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

THE verify_p TRAP
-----------------
`Tally.add_vote_batch(encrypted_votes, verify_p=True)` is the DEFAULT signature in
helios/crypto/electionalgs.py. With it left at the default, every ballot's proofs
are re-verified before being folded in — measured at ~11 s/ballot (§0.3). At
N = 10,000 that is 30 hours of proof verification hiding inside a number the
manuscript labels "aggregation time".

Table 5 defines aggregation as Helios's homomorphic tally routine — the
multiplication, not the verification. So this stage passes verify_p=False
explicitly (§0.4).

Proof verification is not discarded, though: it is a first-class metric in its own
right (PART 6 item 3, adopted), and arguably the most interesting one for a
Paillier-vs-ElGamal comparison because the two proof systems differ structurally.
It is measured in a separate pass, and only at small N, because it is expensive.
"""

from emit import Timer, peak_rss_bytes


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

  Returns (tally, aggregation_ns, peak_rss). The Tally object is returned so
  Stage 4 can decrypt the very object this stage built — re-deriving it would
  measure a different computation.
  """
  import helios_env
  helios_env.setup_django()
  from helios.workflows.homomorphic import Tally

  tally = Tally(election=election)

  # add_vote_batch func in helios/workflows/homomorphic
   """
    Add a batch of votes.
    """
  with Timer() as t:
    tally.add_vote_batch(votes, verify_p=False) # verify_p=True checks if EACH ballot is well-formed

  # Capture how much memory the process was using at its high-water mark 
  # How much RAM was spent aggregating
  rss = peak_rss_bytes() 
  log(f'{len(votes)} ballots in {t.ns / 1e6:.1f} ms '
      f'({t.ns / max(len(votes), 1) / 1e6:.2f} ms/ballot)')
  return tally, t.ns, rss


def measure_verification(election, votes, log=print):
  """
  Proof verification cost, isolated

  Runs the same aggregation with verify_p=True into a throwaway Tally. The
  difference against the verify_p=False figure is verification cost, cleanly
  separated

  Expensive: ~11 s/ballot on the NLE face. Callers gate this on
  levels.yaml:verification_metric_max_n.
  """
  import helios_env
  helios_env.setup_django()
  from helios.workflows.homomorphic import Tally

  tally = Tally(election=election)
  with Timer() as t:
    tally.add_vote_batch(votes, verify_p=True)

  log(f'verify_p=True pass took {t.ns / 1e9:.1f} s '
      f'({t.ns / max(len(votes), 1) / 1e9:.2f} s/ballot, aggregation included)')
  return t.ns
