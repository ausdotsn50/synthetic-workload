"""
Prepared ballots, Phase 2: insert is what a verified cast leaves behind, a
wrong set is refused, the sweep orders and skips cells, the probe samples.

    uv run --project ../helios-server python -m unittest discover -s tests -t . -v

The equivalence test drives a real Helios (server, Celery, Postgres) and the
prepared smoke ElGamal set; it is skipped without them. Its elections are named
wl-test-*, so cleanup.py removes them.
"""

import json
import pathlib
import secrets
import shutil
import tempfile
import unittest

import helios_env
import preflight
import runner
import sweep
from drivers import prepared_set as ps
from generator import votes as votes_gen

FACES = helios_env.load_config('ballot_face.yaml')
CFG = helios_env.load_config('levels.yaml')
helios_env.setup_django()

SMOKE = ps.set_dir('smoke', 'elgamal')


def _server_up():
  return preflight._http_ok(helios_env.helios_url(), timeout=2)


def _have_set():
  return (SMOKE / 'validation.json').exists()


@unittest.skipUnless(_server_up() and _have_set(),
                     'needs the server, Celery and prepared/smoke/elgamal')
class InsertEqualsCastTests(unittest.TestCase):
  """
  §2.3: cast prepared ballots 0..2 through the real path in one election and
  insert the same ballots in another. Row by row, field by field, they must be
  the same, apart from what is per-election (the vote's election uuid and
  hash, hence vote_hash and the tinyhash), per-moment (cast_at, verified_at)
  and the cast_ip only a real request has.
  """

  N = 3
  PER_ELECTION = {'id', 'voter', 'vote', 'vote_hash', 'vote_tinyhash',
                  'cast_at', 'verified_at', 'cast_ip'}

  @classmethod
  def setUpClass(cls):
    from drivers import stage0_setup, stage2_cast, stage2_populate
    from generator import voters as voters_gen

    base_url = helios_env.helios_url()
    questions = votes_gen.build_questions(FACES['smoke'])
    key_path = ps.key_path(SMOKE)
    ballots = list(ps.iter_ballots(SMOKE, 0, cls.N))

    def election(tag):
      uuid = stage0_setup.configure(
        base_url=base_url,
        short_name=f'wl-test-{tag}-{secrets.token_hex(2)}',
        name=f'workload test: {tag}', questions=questions, n_voters=cls.N,
        scheme='elgamal', ablation={}, log=lambda m: None)
      stage0_setup.install_fixed_key(uuid, key_path, log=lambda m: None)
      stage0_setup.freeze(base_url=base_url, election_uuid=uuid,
                          log=lambda m: None)
      return uuid

    cls.ballots = ballots
    cls.cast_uuid = election('cast')
    creds = voters_gen.fetch_credentials(cls.cast_uuid)
    stage2_cast.cast_ballots(base_url=base_url, election_uuid=cls.cast_uuid,
                             encrypted=ballots, credentials=creds,
                             total=cls.N, log=lambda m: None)
    stage2_cast.await_verification(cls.cast_uuid, cls.N, log=lambda m: None)

    cls.insert_uuid = election('insert')
    creds = voters_gen.fetch_credentials(cls.insert_uuid)
    stage2_populate.insert_ballots(
      election_uuid=cls.insert_uuid, encrypted=iter(ballots),
      credentials=creds, total=cls.N, sidecar=None, log=lambda m: None)

  def _rows(self, uuid):
    from helios.models import CastVote, Election, Voter
    e = Election.objects.get(uuid=uuid)
    voters = list(Voter.objects.filter(election=e).order_by('voter_login_id'))
    return e, [(v, CastVote.objects.get(voter=v)) for v in voters]

  def test_board(self):
    from helios.models import Election
    for uuid in (self.cast_uuid, self.insert_uuid):
      e = Election.objects.get(uuid=uuid)
      self.assertEqual(e.num_cast_votes, self.N)
      self.assertEqual(e.num_pending_votes, 0)

  def test_rows_match(self):
    from helios.crypto import utils as cryptoutils
    from helios.models import CastVote
    ec, cast_rows = self._rows(self.cast_uuid)
    ei, insert_rows = self._rows(self.insert_uuid)
    fields = [f.name for f in CastVote._meta.concrete_fields]
    for i, ((vc, cc), (vi, ci)) in enumerate(zip(cast_rows, insert_rows)):
      with self.subTest(ballot=i):
        # Every field that is not per-election is equal.
        for f in fields:
          if f not in self.PER_ELECTION:
            self.assertEqual(getattr(cc, f), getattr(ci, f), f)

        # The vote, apart from its election uuid and hash.
        dc, di = cc.vote.toJSONDict(), ci.vote.toJSONDict()
        for d in (dc, di):
          d.pop('election_uuid')
          d.pop('election_hash')
        self.assertEqual(dc, di)

        # vote_hash derived the same way: hash_b64 of the compact body Stage 2
        # posts, built from the prepared ballot (stage2_cast.py:52-64) -- not
        # from the stored object, whose re-serialization need not match it
        # byte for byte.
        for e, cv in ((ec, cc), (ei, ci)):
          body = json.dumps({'answers': self.ballots[i]['encrypted_answers'],
                             'election_hash': e.hash, 'election_uuid': e.uuid},
                            separators=(',', ':'))
          self.assertEqual(cv.vote_hash, cryptoutils.hash_b64(body))
          safe = cv.vote_hash.replace('/', '').replace('+', '').replace('#', '')
          self.assertTrue(safe.startswith(cv.vote_tinyhash))
          self.assertGreaterEqual(len(cv.vote_tinyhash), 8)

        for cv in (cc, ci):
          self.assertIsNotNone(cv.verified_at)
          self.assertIsNone(cv.invalidated_at)
          self.assertFalse(cv.quarantined_p)
          self.assertFalse(cv.is_quarantined)

        # The only expected difference: a real request has an address.
        self.assertIsNotNone(cc.cast_ip)
        self.assertIsNone(ci.cast_ip)

        # The voter row holds the cast vote, as store_vote leaves it.
        for v, cv in ((vc, cc), (vi, ci)):
          self.assertEqual(v.vote_hash, cv.vote_hash)
          self.assertEqual(v.cast_at, cv.cast_at)
          self.assertEqual(v.vote.toJSONDict(), cv.vote.toJSONDict())

  def test_inserted_votes_verify(self):
    e, rows = self._rows(self.insert_uuid)
    for _v, cv in rows:
      self.assertTrue(cv.vote.verify(e))


@unittest.skipUnless(_have_set(), 'needs prepared/smoke/elgamal')
class WrongSetRefusedTests(unittest.TestCase):
  """A prepared cell refuses a set that is not the one it claims, before
  Stage 0."""

  def setUp(self):
    self.root = pathlib.Path(tempfile.mkdtemp())
    self.d = self.root / 'smoke' / 'elgamal'
    shutil.copytree(SMOKE, self.d, ignore=shutil.ignore_patterns('.lock'))
    self.cfg = {**CFG, 'prepared': {**CFG['prepared'], 'dir': str(self.root)}}
    self.q = votes_gen.build_questions(FACES['smoke'])

  def tearDown(self):
    shutil.rmtree(self.root)

  def _snapshot(self, N=10):
    return ps.snapshot_for_cell('smoke', self.q, 'elgamal', N, self.cfg)

  def _edit(self, name, **changes):
    doc = ps.read_json(self.d / name)
    doc.update(changes)
    ps.write_json(self.d / name, doc)

  def test_good_copy_accepted(self):
    snap = self._snapshot()
    self.assertEqual(snap['manifest']['face'], 'smoke')

  def test_booth_changed(self):
    self._edit('manifest.json', booth_js={'js/other.js': '0' * 64})
    with self.assertRaisesRegex(ps.SetUnusable, 'booth_js'):
      self._snapshot()

  def test_other_seed(self):
    self._edit('manifest.json', master_seed=1)
    with self.assertRaisesRegex(ps.SetUnusable, 'master_seed'):
      self._snapshot()

  def test_wrong_key(self):
    # The Paillier smoke key in the ElGamal set's place.
    shutil.copy(ps.key_path(ps.set_dir('smoke', 'paillier')),
                ps.key_path(self.d))
    with self.assertRaisesRegex(ps.SetUnusable, 'key'):
      self._snapshot()

  def test_too_short(self):
    with self.assertRaisesRegex(ps.SetUnusable, 'needs 100000'):
      self._snapshot(N=100000)

  def test_failed_validation(self):
    self._edit('validation.json', passed=False)
    with self.assertRaisesRegex(ps.SetUnusable, 'FAILED'):
      self._snapshot()

  def test_runner_refuses_before_stage0(self):
    # Real config: the smoke set holds fewer than this N.
    rc = runner.main(['--face', 'smoke', '--n', '100000', '--prepared',
                      '--sample', '3', '--populate', 'insert',
                      '--no-preflight'])
    self.assertEqual(rc, 2)


class SweepTests(unittest.TestCase):

  PLAN = {'face': 'smoke', 'arms': ['elgamal', 'paillier-off'],
          'levels': [500, 100], 'reps': 2, 'ballots': 'prepared',
          'sample_size': 10, 'populate': ['cast', 'insert']}

  def test_order(self):
    got = [(c['N'], c['rep'], c['arm'], c['populate'])
           for c in sweep.cells(self.PLAN)]
    self.assertEqual(len(got), 2 * 2 * 2 * 2)
    self.assertEqual([n for n, *_ in got], sorted(n for n, *_ in got))
    self.assertEqual(got[:4], [(100, 0, 'elgamal', 'cast'),
                               (100, 0, 'elgamal', 'insert'),
                               (100, 0, 'paillier-off', 'cast'),
                               (100, 0, 'paillier-off', 'insert')])
    # Odd reps flip both orders.
    self.assertEqual(got[4:8], [(100, 1, 'paillier-off', 'insert'),
                                (100, 1, 'paillier-off', 'cast'),
                                (100, 1, 'elgamal', 'insert'),
                                (100, 1, 'elgamal', 'cast')])
    self.assertEqual(len({sweep.cell_key(c) for c in sweep.cells(self.PLAN)}),
                     len(got))

  def test_accepted_cells_skipped(self):
    d = pathlib.Path(tempfile.mkdtemp())
    try:
      index = d / 'sweep_index.jsonl'
      c0, c1, c2 = sweep.cells(self.PLAN)[:3]
      sweep.append_index({'key': sweep.cell_key(c0), 'accepted': True}, index)
      sweep.append_index({'key': sweep.cell_key(c1), 'accepted': False}, index)
      done = sweep.accepted_keys(index)
      self.assertIn(sweep.cell_key(c0), done)
      self.assertNotIn(sweep.cell_key(c1), done)    # failed: run again
      self.assertNotIn(sweep.cell_key(c2), done)
    finally:
      shutil.rmtree(d)


class MemoryProbeTests(unittest.TestCase):

  def test_short_stage_still_sampled(self):
    import os
    from drivers import worker
    probe = worker.MemoryProbe(os.getpid(), interval_s=10).start()
    probe.stage('a')
    probe.stage('b')
    peaks = probe.stop()
    for label in ('a', 'b'):
      self.assertGreaterEqual(peaks[label]['samples'], 2)
      self.assertGreater(peaks[label]['peak_tree_rss'], 0)


if __name__ == '__main__':
  unittest.main()
