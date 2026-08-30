"""
Append-only JSONL measurement writer

Environment is captured PER RECORD, not per run. Redundancy on purpose.
"""

import json
import pathlib
import platform
import shutil
import subprocess
import sys
import time

import helios_env

# WORKLAOD_ROOT importable from helios_env
# write
RESULTS_DIR = helios_env.WORKLOAD_ROOT / 'results'

_env_cache = None

# Check for _tool_version
def _tool_version(cmd, args=('--version',)):
  exe = shutil.which(cmd)
  if not exe:
    return None
  try:
    out = subprocess.run([exe, *args], capture_output=True, text=True, timeout=10)
    return (out.stdout or out.stderr).strip().splitlines()[0]
  except Exception:
    return None

# Check for chrome version
def _chrome_version():
  mac = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  if pathlib.Path(mac).exists():
    try:
      out = subprocess.run([mac, '--version'], capture_output=True, text=True, timeout=10)
      return out.stdout.strip() or None
    except Exception:
      return None
  return _tool_version('google-chrome')


def env():
  global _env_cache # Cache env here
  if _env_cache is not None:
    return _env_cache

  hp = helios_env.helios_path()
  wp = helios_env.WORKLOAD_ROOT

  # Add anything else necessary for env
  _env_cache = {
    'host': platform.node(),
    'cpu': platform.processor() or platform.machine(),
    'machine': platform.machine(),
    'os': platform.platform(),
    'py': platform.python_version(),
    'node': _tool_version('node'),
    'chrome': _chrome_version(),
    'helios_commit': helios_env.git_commit(hp),
    'helios_dirty': helios_env.git_is_dirty(hp),
    'workload_commit': helios_env.git_commit(wp),
    'workload_dirty': helios_env.git_is_dirty(wp),
  }
  return _env_cache


class Emitter:
  """
  Writes one JSONL file per run. Opened in append mode and flushed after every record.
  """

  # Initialized emitter
  def __init__(self, run_id, results_dir=None):
    self.run_id = run_id
    d = pathlib.Path(results_dir) if results_dir else RESULTS_DIR # pathlib.Path wraps string to Path
    d.mkdir(parents=True, exist_ok=True) # Checks if exist or true (results_dir)
    self.path = d / f'{run_id}.jsonl'
    self._fh = open(self.path, 'a', encoding='utf-8')

  def emit(self, *, scheme, N, rep, seed, stage, metric, value, unit, extra=None):
    record = {
      'run_id': self.run_id,
      'scheme': scheme,
      'N': N,
      'rep': rep,
      'seed': seed,
      'stage': stage,
      'metric': metric,
      'value': value,
      'unit': unit,
      'env': env(),
      'extra': extra or {},
    }
    self._fh.write(json.dumps(record, separators=(',', ':')) + '\n')
    self._fh.flush()
    return record

  def close(self):
    if not self._fh.closed:
      self._fh.close()

  def __enter__(self):
    return self

  def __exit__(self, *exc):
    self.close()


# Helios uses UTC; gmtime() func insteaf of localtime()
def make_run_id(stamp=None):
  """
  e.g. 2026-08-17T04:22:31Z-a1b2

  Timestamp is generated here rather than passed in, so a run is always
  self-identifying. The suffix disambiguates two runs starting in the same second.
  """
  import secrets
  t = time.gmtime(stamp) if stamp else time.gmtime()
  return time.strftime('%Y-%m-%dT%H:%M:%SZ', t) + '-' + secrets.token_hex(2)
  # Added secrets suffix for anti-collission purposes

# Src: GFG - https://www.geeksforgeeks.org/python/python-time-perf_counter_ns-function/
# Nanoseconds precision compared to normal time_perf_counter()
# Real-user facing latency uses wall clock time instead of merely CPU time
# Monotonic
class Timer:
  """
  perf_counter_ns stopwatch (§3.6/§3.7 use perf_counter_ns explicitly — it is
  monotonic and does not skip when the system clock is adjusted mid-run).

      with Timer() as t:
          ...
      t.ns
  """

  def __enter__(self):
    self._t0 = time.perf_counter_ns() # Func for benchmarking code - methodology based
    return self

  def __exit__(self, *exc):
    self.ns = time.perf_counter_ns() - self._t0
    return False