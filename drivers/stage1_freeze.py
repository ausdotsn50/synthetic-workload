"""
Stage 1 — freeze and key generation
"""


import console
from drivers.http_client import HeliosSession


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
