"""
Sample command:
- uv run --project ../helios-server python runner.py --face smoke --n 10
"""

import argparse
import sys
import time

import console
import helios_env
import preflight

def main(argv=None):
  # Parse CLI args
  p = argparse.ArgumentParser(description='Run one workload cell (spec PART 3)')
  p.add_argument('--scheme', default=None, help='default: first in levels.yaml')
  p.add_argument('--n', type=int, default=None, help='default: first level')
  p.add_argument('--rep', type=int, default=0)
  p.add_argument('--face', default=None, help='ballot face key; default from config')
  p.add_argument('--headed', action='store_true', help='show the browser')
  p.add_argument('--skip', default='', help='comma-separated: keygen,2a')
  p.add_argument('--strict', action='store_true',
                 help='treat provenance warnings as fatal (use for real runs)')
  p.add_argument('--no-preflight', action='store_true')
  args = p.parse_args(argv)

  # Configuration settings
  cfg = helios_env.load_config('levels.yaml')
  faces = helios_env.load_config('ballot_face.yaml')

  # Python or uses truthy left
  scheme = args.scheme or cfg['schemes'][0]
  N = args.n if args.n is not None else cfg['levels'][0] # N voters
  face_key = args.face or cfg['ballot_face'] # Curr choices: smoke or nle2025
  face = faces[face_key]
  skip = tuple(x.strip() for x in args.skip.split(',') if x.strip())
  base_url = cfg['helios']['url'].rstrip('/')

  if not args.no_preflight:
    if not preflight.check(base_url, need_browser=('2a' not in skip),
                           strict=args.strict):
      return 2


if __name__ == '__main__':
  sys.exit(main())
