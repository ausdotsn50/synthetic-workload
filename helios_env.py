"""
status: checked
Bootstrap Helios so the in-process stages (1, 3, 4) can import its code.

This module must be imported BEFORE any `helios.*` or `django.*` import.
"""

import os
import pathlib
import subprocess
import sys

import yaml

# Relative to helios_env.py
WORKLOAD_ROOT = pathlib.Path(__file__).resolve().parent

"""
- reads a YAML file from config/
"""
def load_config(name):
  with open(WORKLOAD_ROOT / 'config' / name) as f:
    return yaml.safe_load(f)

def helios_path():
  cfg = load_config('levels.yaml')
  return (WORKLOAD_ROOT / cfg['helios']['path']).resolve() # converted to abs url

def helios_url():
  return load_config('levels.yaml')['helios']['url'].rstrip('/')


_django_ready = False


def setup_django():
  """
  Put helios-server on sys.path and initialise Django.

  Idempotent — safe to call from every stage.
  """
  global _django_ready
  if _django_ready:
    return

  hp = str(helios_path())

  # APPEND, never insert at position 0. helios-server contains a `selenium/`
  # directory (one file, no __init__.py) which Python 3 will happily treat as a
  # namespace package and import in preference to the real selenium wheel if the
  # helios path is searched first. Appending keeps site-packages ahead of it.
  if hp not in sys.path:
    sys.path.append(hp)

  # sys.path - list of directories Python searches, in order, whenever you write an import statement
  # Since hp already in sys.path -- settings.py is importable
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

  import django
  django.setup() # Needs settings

  _django_ready = True


"""
git related tasks
"""
def git_commit(path):
  """Short HEAD hash of a checkout, or None. Never raises."""
  try:
    out = subprocess.run(
      ['git', '-C', str(path), 'rev-parse', '--short', 'HEAD'],
      capture_output=True, text=True, timeout=10)
    return out.stdout.strip() or None
  except Exception:
    return None


def git_is_dirty(path):
  """True if the checkout has uncommitted changes — a measurement provenance risk."""
  try:
    out = subprocess.run(
      ['git', '-C', str(path), 'status', '--porcelain'],
      capture_output=True, text=True, timeout=10)
    return bool(out.stdout.strip())
  except Exception:
    return None
