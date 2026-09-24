"""
Stage 4 — decryption, driven through Helios's own endpoints.

Two phases, and they are reached differently:

  decryption factors   tally_helios_decrypt, a Celery task CHAINED off the
                       /compute_tally POST Stage 3 already made. This stage
                       does not request it -- it waits for its signal.
  combine              /combine_decryptions, SYNCHRONOUS: Helios runs
                       combine_decryptions() inside the request, so the round
                       trip IS the measurement. No polling, no quantization.

The cryptographic timings come from inside Helios (helios/measure.py, branch
measure/instrumentation) and reach the harness through the sidecar, joined on
election uuid. Decryption arrives there already decomposed, and the dlog split
is now DIRECTLY MEASURED rather than derived:

  decryption_factor_time_ns    alpha^x + Chaum-Pedersen proofs, in the worker
  dlog_precompute_time_ns      DLogTable.precompute -- Theta(N)
  dlog_lookup_time_ns          per-cell decrypt() + the O(1) lookups

That structure is the point of the thesis: Helios walks g^0..g^N into a dict
rather than using BSGS, so ElGamal's decryption grows linearly with the number
of voters, while Paillier has no dlog step at all. Reporting one combined
"decryption time" would hide exactly the difference being measured.

Why the poll is an EXISTS query
-------------------------------
trustee.decryption_factors is an LDObjectField, and
Election.get_helios_trustee() does len() on a queryset -- loading every
trustee's secret key and factors. Polling either would put that cost inside the
measured window. The predicate below asks the database whether the column is
non-NULL and never transfers the value.
"""

import time

from drivers.http_client import HeliosSession, await_signal, close_stale_connection


def _factors_present(uuid):
  from helios.models import Trustee
  return Trustee.objects.filter(election__uuid=uuid,
                                secret_key__isnull=False,
                                decryption_factors__isnull=False).exists()


def await_factors(*, election_uuid, since_ns, poll_s=0.05, timeout_s=3600,
                  log=print):
  """
  Wait for the chained tally_helios_decrypt task to publish its factors.

  `since_ns` is Stage 3's signal instant: this phase runs from the moment the
  tally appeared to the moment the factors do. No POST is issued here -- the
  task was already triggered by Stage 3's /compute_tally.

  Returns {'signal_ns'}. The wait itself is the point: combine must not run
  before the factors exist.
  """
  import helios_env
  helios_env.setup_django()

  close_stale_connection()
  t2 = await_signal(lambda: _factors_present(election_uuid),
                    poll_s, timeout_s, 'decryption_factors', since_ns, log)
  return {'signal_ns': t2}


def combine(*, base_url, election_uuid, log=print):
  """
  POST /combine_decryptions and time the round trip.

  Returns (flow_combine_ns, result).
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election

  if not _factors_present(election_uuid):
    raise RuntimeError(
      'decryption factors not present; combine_decryptions would produce a '
      'wrong result. await_factors() must reach its signal first.')

  s = HeliosSession(base_url).login_devlogin()
  close_stale_connection()

  # Unbounded by design: combine_decryptions runs DLogTable.precompute(N)
  # inside the request, so at large N this blocks. requests sets no default
  # timeout, so it waits rather than failing spuriously.
  log('POST /combine_decryptions (synchronous — runs inside the request)')
  t0 = time.perf_counter_ns()
  s.post(f'/helios/elections/{election_uuid}/combine_decryptions',
         data={}, expect_redirect=False)
  t1 = time.perf_counter_ns()
  log(f'combined in {(t1 - t0) / 1e6:.1f} ms')

  result = Election.objects.get(uuid=election_uuid).result
  if result is None:
    raise RuntimeError('combine_decryptions returned but election.result is null')

  return t1 - t0, result
