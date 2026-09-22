"""
Stage 3 — homomorphic aggregation, driven through Helios's own endpoint.

The harness POSTs /compute_tally and waits for the encrypted_tally signal. The
aggregation itself is timed from INSIDE Helios (helios/measure.py, branch
measure/instrumentation) and reaches the harness through the sidecar, joined on
election uuid -- see drivers/measure_join.py. Nothing is re-executed here to be
measured.

What this stage contributes is the OUTER layer: the phase duration, bounded by
the poll interval. Against the exact in-process spans it decomposes as

    flow - task       = HTTP + Celery queue latency + poll quantization
    task - operation  = deserialization, ORM, persistence
    operation         = the cryptosystem

Why the poll is an EXISTS query
-------------------------------
election.encrypted_tally is an LDObjectField: touching it deserializes the
whole tally (222 ciphertexts at the nle2025 face). Polling the attribute would
put that cost inside the measured window, and the poll that finally succeeds
would pay a full deserialization before the clock is read. The predicate below
asks the database whether the column is non-NULL and never transfers the value.

NOTE ON SCOPE: the single POST this stage makes also triggers the chained
tally_helios_decrypt task, so it starts the phase Stage 4 measures. Stage 4
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

  Returns {'flow_aggregate_ns', 'poll_interval_ms', 'posted_at', 'signal_ns'}.
  posted_at is wall clock, for joining against the worker's task_start_wall_ns
  to get Celery dispatch latency. signal_ns is handed to Stage 4, which times
  its phase from this point.
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

  posted_at = time.time()
  t0 = time.perf_counter_ns()
  # expect_redirect=False: the view redirects to the election page on success.
  # Following it would add a page render to the measured phase.
  s.post(f'/helios/elections/{election_uuid}/compute_tally',
         data={}, expect_redirect=False)

  t1 = await_signal(lambda: _tally_present(election_uuid),
                    poll_s, timeout_s, 'encrypted_tally', t0, log)

  return {
    'flow_aggregate_ns': t1 - t0,
    'poll_interval_ms': poll_s * 1000,
    'posted_at': posted_at,
    'signal_ns': t1,
  }
