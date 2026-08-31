"""
Synthetic voter list generation and credential retrieval.

Retrieving voter credentials directly from the database instead of by
email; real election mails passwords to humans, and the harness cannot.
"""

import csv
import io


def voter_id(i):
  return f'wlvoter{i:06d}'


def build_voter_csv(count, voter_type='password'):
  """
  Helios voter-file format see helios/models.py
  def itervoters():
    ...
    yield {
      'voter_type': voter_type,
      'voter_id': voter_id,
      'email': voter_email,
      'name': voter_name,
    }

  helios/fixtures/voter_file.csv
  col 0,      col 1,    col 2, col3
  voter_type, voter_id, email, name
  """
  buf = io.StringIO() # use io.StringIO() instead of writing on disk (only needed once)
  w = csv.writer(buf)
  for i in range(count):
    vid = voter_id(i)
    # Use reserved TLD .invalid https://www.rfc-editor.org/info/rfc2606/
    w.writerow([voter_type, vid, f'{vid}@workload.invalid',
                f'Workload Voter {i}'])
  return buf.getvalue() # csv formatted string 


def fetch_credentials(election_uuid):
  """
  Read voter login IDs + passwords straight from the database.

  Read-only. A real voter receives these by email; the harness cannot, so it reads
  what Helios generated. Returns [(voter_login_id, voter_password, voter_uuid)].
  """
  import helios_env
  helios_env.setup_django()
  from helios.models import Election, Voter

  election = Election.objects.get(uuid=election_uuid)
  rows = (Voter.objects
          .filter(election=election)
          .order_by('voter_login_id')
          .values_list('voter_login_id', 'voter_password', 'uuid'))
  return [tuple(r) for r in rows]


def count_registered(election_uuid):
  """How many voters Helios actually created — used to wait out the Celery upload."""
  import helios_env
  helios_env.setup_django()
  from helios.models import Election, Voter

  election = Election.objects.get(uuid=election_uuid)
  return Voter.objects.filter(election=election).count()
