"""
Join Helios's instrumentation sidecar onto a measurement cell.

Helios (branch measure/instrumentation) appends one JSON object per line to
HELIOS_MEASURE_PATH as it executes. The file is shared across runs and across
processes -- the web process and the Celery worker are long-lived and read the
path once at startup, so it cannot be run-scoped. Records are keyed by election
uuid instead, and one cell is one election, so the join is exact.

The harness re-emits every row through its own em(), so the JSONL output format
is unchanged downstream: nothing in the analysis needs to know where a number
came from beyond the `source` field.
"""

import json
import os

# Keys the sidecar writer always sets; everything else on a row is metadata
# specific to that metric and is carried through into `extra`.
_RESERVED = {'election_uuid', 'metric', 'value', 'unit'}

# Which harness stage each instrumented metric belongs under, so the existing
# REQUIRED_STAGES grouping in acceptance.py keeps working.
STAGE_OF = {
  'keygen_time_ns': 'configure',
  'prove_sk_time_ns': 'configure',
  'verification_time_ns': 'encrypt',
  'verification_only_ns': 'encrypt',
  'aggregation_time_ns': 'aggregate',
  'aggregation_only_ns': 'aggregate',
  'decryption_factor_time_ns': 'decrypt',
  'decryption_factor_only_ns': 'decrypt',
  'decryption_factors_bytes': 'decrypt',
  'decryption_proofs_bytes': 'decrypt',
  'dlog_precompute_time_ns': 'decrypt',
  'dlog_lookup_time_ns': 'decrypt',
}

# Which Helios process records each metric. Not inferred from pid -- this is a
# static fact about where Helios does the work, and naming the process is far
# more legible in a summary than a bare pid.
#
#   Celery worker  -- compute_tally and tally_helios_decrypt are async tasks,
#                     and cast verification is a task per ballot
#   Django web     -- combine_decryptions is synchronous inside the request,
#                     and generate_trustee runs during the election-creation POST
PROCESS_OF = {
  'keygen_time_ns': 'Helios web',
  'prove_sk_time_ns': 'Helios web',
  'dlog_precompute_time_ns': 'Helios web',
  'dlog_lookup_time_ns': 'Helios web',
  'aggregation_time_ns': 'Celery worker',
  'aggregation_only_ns': 'Celery worker',
  'decryption_factor_time_ns': 'Celery worker',
  'decryption_factor_only_ns': 'Celery worker',
  'verification_time_ns': 'Celery worker',
  'verification_only_ns': 'Celery worker',
  'decryption_factors_bytes': 'Celery worker',
  'decryption_proofs_bytes': 'Celery worker',
}

# Payload sizes: what crosses the wire or sits on the board, not a duration.
# Tagged 'flow', like the harness's own payload metrics.
PAYLOAD_METRICS = {'decryption_factors_bytes', 'decryption_proofs_bytes'}

# Sidecar metrics the harness reads but does not emit. Empty for now.
SKIP_EMIT = set()

# What a correctly instrumented ElGamal cell must contain. Missing any of these
# means the branch is not checked out, HELIOS_MEASURE_PATH is unset on one of
# the two processes, or a span was dropped in a merge.
REQUIRED_INSTRUMENTED = {
  'keygen_time_ns', 'prove_sk_time_ns', 'aggregation_time_ns',
  'aggregation_only_ns',
  'decryption_factor_time_ns', 'dlog_precompute_time_ns',
  'dlog_lookup_time_ns',
  'decryption_factor_only_ns', 'verification_only_ns',
  'decryption_factors_bytes', 'decryption_proofs_bytes',
}


def read_sidecar(path, election_uuid):
  """
  Return {metric: [row, ...]} for one election.

  Tolerates a torn final line: the writer fsyncs each record, but a reader can
  still arrive mid-append. A malformed line is skipped rather than fatal --
  acceptance checks the metric set, which is the property that matters.
  """
  out = {}
  if not path or not os.path.exists(path):
    return out
  with open(path) as f:
    for line in f:
      line = line.strip()
      if not line:
        continue
      try:
        row = json.loads(line)
      except json.JSONDecodeError:
        continue
      if row.get('election_uuid') != str(election_uuid):
        continue
      out.setdefault(row['metric'], []).append(row)
  return out


def tier_of(metric):
  return 'flow' if metric in PAYLOAD_METRICS else 'operation'


def extra_for(row):
  """Carry the sidecar row's own metadata into the emitted record."""
  extra = {k: v for k, v in row.items() if k not in _RESERVED}
  extra['tier'] = tier_of(row['metric'])
  extra['source'] = 'helios_instrumentation'
  return extra
