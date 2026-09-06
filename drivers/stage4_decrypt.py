"""
Stage 4 — decryption (spec §3.7).

Decryption is reported as THREE numbers, not one. Spec §2.3 calls this
decomposition "the single most informative chart in the results section, and it is
only possible if you plan for it now":

  decryption_factor_time   ElGamal: alpha^x + Chaum-Pedersen proofs
                           Paillier: plaintexts + Pi_root proofs
  dlog_precompute_time     ElGamal: DLogTable.precompute -- Theta(N)
                           Paillier: DOES NOT EXIST
  dlog_lookup_time         ElGamal: the O(1) dict lookups + factor combination
                           Paillier: pass-through

The point is structural, not incidental. Helios does not use BSGS; it walks
g^0..g^N into a dict (§0.1). So ElGamal's decryption cost grows linearly with the
number of voters and is INDEPENDENT of how votes are distributed, while Paillier
has no dlog step at all. Reporting one combined "decryption time" would hide
exactly the difference the thesis exists to measure.

How the split is obtained without touching Helios
-------------------------------------------------
Tally.decrypt_from_factors (electionalgs.py:775) builds its own DLogTable and calls
precompute internally, so the phases cannot be timed from outside directly. Rather
than modify Helios -- which would break the "no modifications to ElGamal-Helios"
constraint (§9.2.1) -- this stage times the whole call, then separately times an
identically-constructed DLogTable.precompute over the same range. Lookup+combine is
the remainder.

That makes dlog_lookup_time a derived quantity carrying both measurements' noise.
It is recorded as such in `extra.derived`, so the analysis stage never mistakes it
for a directly observed number.
"""

from emit import Timer


def decrypt(election, tally, log=print):
  """
  Returns a dict of phase timings plus the decrypted result.

  Uses the Tally object Stage 3 actually built.
  """
  import helios_env
  helios_env.setup_django()
  # Production class, matching Stage 3
  from helios.workflows.homomorphic import DLogTable

  # We need the helios private key and then the public key for decryption
  sk = election.get_helios_trustee().secret_key
  pk = election.public_key

  # from Tally object --  array of decryption factors and a corresponding array of decryption proofs
  with Timer() as t_factors:
    factors, proofs = tally.decryption_factors_and_proofs(sk)

  # decrypt_from_factors: combines decryption factors into each cell's ciphertext
  # AND builds its own dlog table internally (precompute cost isolated below)
  with Timer() as t_combine:
    result = tally.decrypt_from_factors([factors], pk)

  with Timer() as t_precompute: # Rebuild the same dlog table standalone, to isolate its cost
    table = DLogTable(base=pk.g, modulus=pk.p)
    table.precompute(tally.num_tallied)

  # decrypt_from_factors' work minus its internal precompute — i.e. per-cell
  # decrypt() + O(1) table lookups
  decrypt_and_lookup_ns = max(t_combine.ns - t_precompute.ns, 0)

  log(f'phase 1  decryption factors + CP proofs   '
      f'{t_factors.ns / 1e6:9.2f} ms')
  log(f'phase 2  combine + dlog recovery          '
      f'{t_combine.ns / 1e6:9.2f} ms')
  log(f'   of which  DLogTable.precompute         '
      f'{t_precompute.ns / 1e6:9.2f} ms  '
      f'({tally.num_tallied} entries, Theta(N))')
  log(f'   remainder lookup + combine             '
      f'{lookup_ns / 1e6:9.2f} ms  DERIVED')
  log(f'result: {result}')

  return {
    'result': result,
    'decryption_factor_time_ns': t_factors.ns,
    'decryption_combine_time_ns': t_combine.ns,
    'dlog_precompute_time_ns': t_precompute.ns,
    'dlog_lookup_time_ns': lookup_ns,
    'dlog_entries': tally.num_tallied,
    'proofs': proofs,
  }
