"""
Stage 1 — freeze and key generation
"""

import statistics

import console
from drivers.http_client import HeliosSession
from emit import Timer


def freeze(*, base_url, election_uuid, log=print):
  """Freeze the election over HTTP. Opens voting."""
  s = HeliosSession(base_url).login_devlogin()
  s.post(f'/helios/elections/{election_uuid}/freeze', data={})

  import helios_env
  helios_env.setup_django()
  from helios.models import Election
  e = Election.objects.get(uuid=election_uuid)
  if not e.frozen_at:
    raise RuntimeError(
      'freeze did not take. Helios refuses to freeze while issues_before_freeze is '
      'non-empty — typically no questions, no trustee, or no voters.')
  log(f'frozen at {e.frozen_at} — voting is open')
  return e.frozen_at


# log as console.detail formatter
def measure_keygen(*, scheme, n_samples=30, log=print):
  """
  Time key generation `n_samples` times.

  Returns (keygen_ns[], prove_sk_ns[]). The caller emits one record per sample for
  distribution to be reported, not just mean +/- sd, so the raw samples
  must survive into the JSONL rather than being averaged here.
  """
  import helios_env
  helios_env.setup_django()

  if scheme != 'elgamal':
    raise NotImplementedError(
      f'scheme {scheme!r} has no keypair generator yet')

  # standard usage for trustee keypair gen (ELGAMAL_PARAMS)
  from helios.views import ELGAMAL_PARAMS 
  from helios.crypto import algs

  keygen_ns, prove_sk_ns = [], []
  prog = console.Progress(n_samples, 'keypairs', every=max(1, n_samples // 6))

  # See views.py for ELGAMAL_PARAMS.{p,q,g} values
  # See algs.py for verification of keypair
  for i in range(n_samples):
    with Timer() as t:
      # See in views.py inside election_new = election.generate_trustee(ELGAMAL_PARAMS)
      # See models.py = def generate_trustee(self, params)
      kp = ELGAMAL_PARAMS.generate_keypair()
    keygen_ns.append(t.ns) # Per iteration recorded in array

    with Timer() as t:
      kp.sk.prove_sk(algs.DLog_challenge_generator)
    prove_sk_ns.append(t.ns)

    prog.tick(i + 1)

  # Statistical computation logged
  if log:
    kg, ps = sorted(keygen_ns), sorted(prove_sk_ns)
    log(f'keygen   median {statistics.median(kg) / 1e6:.2f} ms  '
        f'min {kg[0] / 1e6:.2f}  max {kg[-1] / 1e6:.2f}')
    log(f'prove_sk median {statistics.median(ps) / 1e6:.2f} ms  '
        f'min {ps[0] / 1e6:.2f}  max {ps[-1] / 1e6:.2f}')
    # Spread matters: ElGamal expected to be tight and Paillier (a random
    # prime search) to be heavy-tailed. Printing min/max makes that visible now
    # rather than only in analysis.
    
  return keygen_ns, prove_sk_ns
