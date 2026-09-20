"""
Scheme registry — which cryptosystems this harness can actually drive.

Why this exists (build spec §8.1)
---------------------------------
Before this module, `runner.py --scheme paillier --n 10 --skip keygen` ran a
complete ElGamal election, stamped "scheme":"paillier" on every emitted record,
and passed acceptance. Only stage1_freeze branched on scheme, and --skip routed
around it. A run could claim a scheme it had not executed.

Two independent guards close that, and they are deliberately different in kind:

  require(scheme)      BEFORE the run. Refuses to start when the scheme has no
                       working driver set. Not reachable by --skip.
  observed_scheme(...)  AFTER the run. Reads the scheme back out of the artifacts
                       the election actually produced, and acceptance compares it
                       against what the records claim.

The first is a promise; the second is evidence. A bug that defeats both has to
forge a ballot.

Support is PROBED, not declared
-------------------------------
`supported` is not a hand-maintained boolean. A boolean flipped by hand is a
claim that drifts from the code the moment someone forgets to flip it back, and
this whole module exists because a claim drifted from the code. Instead each
scheme lists the capabilities it needs from helios-server, and the probe imports
them. The gate opens exactly when the implementation lands.
"""

import dataclasses


@dataclasses.dataclass(frozen=True)
class Capability:
  """One importable thing a scheme needs, and how to check for it."""
  label: str
  probe: object  # callable() -> None; raises on absence

  def check(self):
    """Returns None when present, else a short reason string."""
    try:
      self.probe()
    except Exception as e:
      return f'{self.label}: {type(e).__name__}: {e}'
    return None


# --- capability probes -------------------------------------------------------
# Each imports inside the function: this module must be importable without
# Django configured, so acceptance.py can use it on a results file alone.

def _probe_elgamal_params():
  import helios_env
  helios_env.setup_django()
  from helios.views import ELGAMAL_PARAMS
  assert ELGAMAL_PARAMS.p and ELGAMAL_PARAMS.q and ELGAMAL_PARAMS.g


def _probe_paillier_crypto():
  import helios_env
  helios_env.setup_django()
  from helios.crypto import paillier
  # Not merely importable — the surface stage1/stage4 will call must exist.
  for attr in ('Paillier', 'PaillierPublicKey', 'PaillierSecretKey',
               'PaillierCiphertext'):
    assert hasattr(paillier, attr), f'paillier.{attr} missing'


def _probe_paillier_params():
  import helios_env
  helios_env.setup_django()
  from helios.views import PAILLIER_PARAMS
  assert PAILLIER_PARAMS.key_size


def _probe_election_scheme_column():
  """Stage 0 cannot create a Paillier election without somewhere to say so."""
  import helios_env
  helios_env.setup_django()
  from helios.models import Election
  Election._meta.get_field('crypto_scheme')


@dataclasses.dataclass(frozen=True)
class Scheme:
  key: str
  # The ciphertext field set this scheme -- and only this scheme -- produces.
  # Used by observed_scheme() to identify a scheme from a ballot alone.
  ciphertext_fields: frozenset
  # Does decryption pass through a discrete-log table? Decides which decrypt
  # metrics are legitimate (build spec §8.2/§8.3).
  has_dlog: bool
  capabilities: tuple

  def missing(self):
    """Capabilities this checkout does not provide. Empty tuple == supported."""
    return tuple(r for r in (c.check() for c in self.capabilities) if r)

  @property
  def supported(self):
    return not self.missing()


REGISTRY = {
  'elgamal': Scheme(
    key='elgamal',
    ciphertext_fields=frozenset({'alpha', 'beta'}),
    has_dlog=True,
    capabilities=(
      Capability('helios.views.ELGAMAL_PARAMS', _probe_elgamal_params),
    ),
  ),
  'paillier': Scheme(
    key='paillier',
    ciphertext_fields=frozenset({'c'}),
    has_dlog=False,
    capabilities=(
      Capability('helios.crypto.paillier', _probe_paillier_crypto),
      Capability('helios.views.PAILLIER_PARAMS', _probe_paillier_params),
      Capability('Election.crypto_scheme', _probe_election_scheme_column),
    ),
  ),
}


def get(scheme):
  """Registry lookup. Raises on a scheme this harness has never heard of."""
  try:
    return REGISTRY[scheme]
  except KeyError:
    raise KeyError(
      f'unknown scheme {scheme!r} — registered: '
      f'{", ".join(sorted(REGISTRY))}') from None


class UnsupportedScheme(RuntimeError):
  pass


def require(scheme):
  """
  Gate a run. Raises UnsupportedScheme unless every capability is present.

  Called before any stage runs and NOT gated by --skip: skipping a stage must
  never be a route to claiming a scheme the harness cannot execute.
  """
  s = get(scheme)
  missing = s.missing()
  if missing:
    detail = '\n'.join(f'    - {m}' for m in missing)
    raise UnsupportedScheme(
      f'scheme {scheme!r} is registered but this helios-server checkout does '
      f'not implement it.\n'
      f'  missing capabilities:\n{detail}\n'
      f'  Refusing to run: a run that cannot execute {scheme!r} must not emit '
      f'records claiming it.')
  return s


def observed_scheme(ciphertext_dict):
  """
  Identify the scheme from one serialized ciphertext.

  This is the evidence half of the guard. The field set is decided by the
  cryptosystem -- ElGamal serializes {alpha, beta}, Paillier {c} -- so it cannot
  agree with a mislabeled record by accident.

  Returns the scheme key, or None if the shape matches nothing registered.
  """
  if not isinstance(ciphertext_dict, dict):
    return None
  keys = set(ciphertext_dict)
  for s in REGISTRY.values():
    if s.ciphertext_fields <= keys:
      return s.key
  return None


def required_metrics(scheme):
  """
  Metrics a correct run of this scheme must emit (build spec §8.3).

  The dlog metrics are ElGamal-only. Under Paillier there is no discrete-log
  stage, so requiring them would fail a correct run, and emitting them as zero
  would be a claim about a step that never happened.
  """
  s = get(scheme)
  metrics = {
    'keygen_time_ns',
    'encryption_time_ms',
    'ciphertext_bytes',
    'proof_bytes',
    'aggregation_time_ns',
    'decryption_factor_time_ns',
    'result',
  }
  if s.has_dlog:
    metrics |= {'dlog_precompute_time_ns', 'dlog_lookup_time_ns'}
  else:
    metrics |= {'decryption_time_ns'}
  return metrics


def forbidden_metrics(scheme):
  """
  Metrics this scheme must NOT emit.

  Symmetric to required_metrics and just as load-bearing: a Paillier run that
  emits dlog_lookup_time_ns is reporting a stage that does not exist, which is
  exactly the failure §8.2 describes.
  """
  s = get(scheme)
  if s.has_dlog:
    return {'decryption_time_ns'}
  return {'dlog_precompute_time_ns', 'dlog_lookup_time_ns'}
