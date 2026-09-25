"""
Stage 3 — homomorphic aggregation, driven through Helios's own endpoint.

This stage drives the phase and waits for its signal: it POSTs /compute_tally
and polls until encrypted_tally appears. It times nothing. The aggregation is
timed inside Helios (helios/measure.py, branch measure/instrumentation) and
reaches the harness through the sidecar, joined on election uuid -- see
drivers/measure_join.py.

Why the poll is an EXISTS query
-------------------------------
election.encrypted_tally is an LDObjectField: touching it deserializes the
whole tally (222 ciphertexts at the nle2025 face). Polling the attribute would
repeat that work every 50 ms on the same machine as the worker being timed. The
predicate below asks the database whether the column is non-NULL and never
transfers the value.

NOTE ON SCOPE: the single POST this stage makes also triggers the chained
tally_helios_decrypt task, so it starts the phase Stage 4 waits on. Stage 4
waits for that second signal; it must NOT issue a second POST.
"""

import time

from drivers.http_client import HeliosSession, await_signal, close_stale_connection


def _tally_present(uuid):
  from helios.models import Election
  return Election.objects.filter(uuid=uuid, encrypted_tally__isnull=False).exists()


def compute_tally(*, base_url, election_uuid, poll_s=0.05, timeout_s=3600,
                  log=print):
  """
  POST /compute_tally, then wait for encrypted_tally to appear.

  Returns {'signal_ns'}: when the tally appeared. Stage 4 uses it only for its
  progress log.
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election

  e = Election.objects.get(uuid=election_uuid)
  if e.num_pending_votes > 0:
    raise RuntimeError(
      f'{e.num_pending_votes} votes still pending verification; '
      f'/compute_tally will refuse. Stage 2 await_verification must finish first.')
  # There is exactly ONE execution under this design, so a cell that tallies
  # twice has no clean measurement at all.
  if _tally_present(election_uuid):
    raise RuntimeError(
      'encrypted_tally is already set — this election has been tallied. '
      'The flow must run on a fresh election, exactly once.')

  s = HeliosSession(base_url).login_devlogin()
  close_stale_connection()

  # t0 feeds only the "waiting on ..." progress log.
  t0 = time.perf_counter_ns()
  # expect_redirect=False: the view redirects to the election page on success,
  # and rendering it is not needed.
  s.post(f'/helios/elections/{election_uuid}/compute_tally',
         data={}, expect_redirect=False)

  t1 = await_signal(lambda: _tally_present(election_uuid),
                    poll_s, timeout_s, 'encrypted_tally', t0, log)
  return {'signal_ns': t1}
