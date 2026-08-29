"""
Pre-run environment checks

Checks on postgresql, rabbitmq -- django server + celery workers
"""

import shutil
import socket
import urllib.error
import urllib.request

import console
import helios_env

# Checking server status
def _http_ok(url, timeout=5):
  try:
    with urllib.request.urlopen(url, timeout=timeout) as r:
      return r.status < 500
  except urllib.error.HTTPError as e:
    return e.code < 500          # 4xx means Django answered — server is up
  except Exception:
    return False


def _port_open(host, port, timeout=2):
  try:
    with socket.create_connection((host, port), timeout=timeout):
      return True
  except Exception:
    return False


def check(base_url, *, need_browser=True, strict=False):
  """
  Returns True if the run may proceed.

  need_browser=False when Stage 2a is skipped — Chrome is then irrelevant and a
  missing browser should not block an otherwise valid run.
  """
  console.section('PREFLIGHT')
  hard_fail = False
  soft_fail = False

  # Checking at port 8000 (Django server)
  if _http_ok(base_url):
    console.ok(f'helios server responding at {base_url}')
  else:
    console.fail(f'no response from {base_url}')
    console.detail('start it:  cd ../helios-server && '
                   'uv run python manage.py runserver')
    hard_fail = True

  # Checking at 5672 (default for RabbitMQ)
  if _port_open('127.0.0.1', 5672):
    console.ok('AMQP broker listening on 5672')
    console.detail('note: broker up != worker running. Stages 0 and 2b will '
                   'time out if no worker is consuming.')
  else:
    console.warn('nothing listening on 5672 (RabbitMQ)')
    console.detail('Stage 0 will hang at voter registration if Celery is not up:')
    console.detail('  uv run celery --app helios worker --events --beat '
                   '--concurrency 1')
    soft_fail = True
  
  """
    RabbitMQ mechanism
      > RabbitMQ holds messages in a queue until a connected, listening worker is 
      available to receive one — then it delivers the message to that worker.
  """

  # Check for Node js; uses absolute path via shutil
  node = shutil.which('node')
  if node:
    console.ok(f'node found at {node}')
  else: # 2b as browser encryption
    console.fail('node not on PATH — Stage 2b cannot encrypt ballots')
    hard_fail = True

  # Check for Chrome/Chrome v.  
  if need_browser:
    import emit
    chrome = emit._chrome_version()
    if chrome:
      console.ok(f'chrome: {chrome}')
    else:
      console.fail('Chrome not found — Stage 2a needs it (or pass --skip 2a)')
      hard_fail = True
  else:
    console.detail('chrome not checked (Stage 2a skipped)')

  hp = helios_env.helios_path() # Loads levels.yaml
  wp = helios_env.WORKLOAD_ROOT # Workload root

  # c for commits, d for dirty | recording the commit hashes as per workload and Helios repository separation
  hc, hd = helios_env.git_commit(hp), helios_env.git_is_dirty(hp)
  wc, wd = helios_env.git_commit(wp), helios_env.git_is_dirty(wp)

  if hc:
    console.ok(f'helios commit {hc}' + ('  DIRTY' if hd else ''))
  else:
    console.warn('helios commit unavailable')
    soft_fail = True

  if wc:
    console.ok(f'workload commit {wc}' + ('  DIRTY' if wd else ''))
  else:
    console.warn('workload has no commits — workload_commit will be null')
    console.detail('every record from this run will be unreproducible by the '
                   "harness's own definition (README, acceptance.py)")
    soft_fail = True

  if hd or wd:
    console.warn('a working tree is dirty — the commit hash does not describe '
                 'what ran')
    soft_fail = True

  # Finalized conditions (hard/soft fail) for preflight
  if hard_fail:
    console.fail('preflight failed — cannot run')
    return False
  if soft_fail and strict:
    console.fail('preflight warnings are fatal under --strict')
    return False
  if soft_fail:
    console.warn('proceeding with warnings (development run)')
  else:
    console.ok('preflight clean')
  return True
