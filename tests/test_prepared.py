"""
Prepared ballots, Phase 1: the master prefix property, the fixed key's round
trip, swap-then-freeze, and the refusals.

    uv run --project ../helios-server python -m unittest discover -s tests -t . -v

The swap test and the validator tests drive a real Helios (server, Celery,
Postgres) and are skipped when the server is not answering. Elections they
make are named wl-test-*, so cleanup.py removes them.
"""

import gzip
import json
import pathlib
import secrets
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import helios_env
import prepare
import preflight
from drivers import fixed_key
from drivers import prepared_set as ps
from generator import votes as votes_gen

FACES = helios_env.load_config('ballot_face.yaml')
CFG = helios_env.load_config('levels.yaml')

# Puts helios-server on sys.path, so helios.* imports below resolve.
helios_env.setup_django()


def _server_up():
  return preflight._http_ok(helios_env.helios_url(), timeout=2)


class MasterPrefixTests(unittest.TestCase):

  def test_prefix_property(self):
    # master_ballots(s, q, M)[:N] == master_ballots(s, q, N), for every N <= M.
    for face_key in ('smoke', 'nle2025'):
      q = votes_gen.build_questions(FACES[face_key])
      M = 120
      big = votes_gen.master_ballots(CFG['seed'], q, M)
      self.assertEqual(len(big), M)
      for N in (0, 1, 2, 10, 40, 60, 100, 119, 120):
        with self.subTest(face=face_key, N=N):
          self.assertEqual(big[:N], votes_gen.master_ballots(CFG['seed'], q, N))

  def test_same_list_for_every_cell(self):
    # No scheme, mode or rep input: every cell reads the levels.yaml seed's
    # list, and another seed gives another list.
    q = votes_gen.build_questions(FACES['smoke'])
    self.assertEqual(votes_gen.master_ballots(CFG['seed'], q, 30),
                     votes_gen.generate_ballots(CFG['seed'], q, 30))
    self.assertNotEqual(votes_gen.master_ballots(CFG['seed'], q, 30),
                        votes_gen.master_ballots(CFG['seed'] + 1, q, 30))


class ChunkPlanTests(unittest.TestCase):

  def setUp(self):
    self.d = pathlib.Path(tempfile.mkdtemp())
    ps.chunks_dir(self.d).mkdir()

  def tearDown(self):
    shutil.rmtree(self.d)

  def _touch(self, s, e):
    (ps.chunks_dir(self.d) / ps.chunk_name(s, e)).write_bytes(b'')

  def test_fresh(self):
    self.assertEqual(ps.plan_chunks([], 250, 100),
                     [(0, 100), (100, 200), (200, 250)])

  def test_resume_fills_gaps_then_extends(self):
    # An interrupted run committed 10-20 and 30-40 only.
    self._touch(10, 20)
    self._touch(30, 40)
    done = ps.completed_chunks(self.d)
    self.assertEqual(ps.contiguous_count(done), 0)
    self.assertEqual(ps.plan_chunks(done, 40, 10), [(0, 10), (20, 30)])
    self.assertEqual(ps.plan_chunks(done, 60, 10),
                     [(0, 10), (20, 30), (40, 50), (50, 60)])

  def test_extend_after_short_last_chunk(self):
    self._touch(0, 40)
    done = ps.completed_chunks(self.d)
    self.assertEqual(ps.plan_chunks(done, 60, 100), [(40, 60)])
    self.assertEqual(ps.plan_chunks(done, 40, 100), [])
    self.assertEqual(ps.plan_chunks(done, 30, 100), [])

  def test_parts_are_not_chunks(self):
    self._touch(0, 10)
    (ps.chunks_dir(self.d) / (ps.chunk_name(10, 20) + '.abc123.part')).write_bytes(b'')
    done = ps.completed_chunks(self.d)
    self.assertEqual([(s, e) for s, e, _p in done], [(0, 10)])
    self.assertEqual(ps.plan_chunks(done, 20, 10), [(10, 20)])

  def test_overlap_refused(self):
    self._touch(0, 20)
    self._touch(10, 30)
    with self.assertRaises(ValueError):
      ps.completed_chunks(self.d)


class SampleDesignTests(unittest.TestCase):
  """§1.6: a random sample spread over every chunk, and its zero-failure bound."""

  def _ranges(self, sizes):
    out, s = [], 0
    for n in sizes:
      out.append((s, s + n))
      s += n
    return out

  def _check(self, ranges, n, seed=1):
    import random
    got, n_eff = prepare.stratified_sample(ranges, n, random.Random(seed))
    total = sum(e - s for s, e in ranges)
    self.assertEqual(got, sorted(set(got)))              # no index twice
    for s, e in ranges:
      k = sum(1 for i in got if s <= i < e)
      self.assertGreaterEqual(k, 1, f'chunk {s}-{e} unsampled')
      if k < e - s:
        # The share the bound relies on: k_h >= n_eff * N_h / N.
        self.assertGreaterEqual(k, n_eff * (e - s) / total - 1e-9)
    if n < total:
      self.assertGreaterEqual(n_eff, n)
    return got, n_eff

  def test_every_chunk_represented_even_beyond_n(self):
    # 1000 chunks of 100 and n = 300: every chunk still gets one.
    got, n_eff = self._check(self._ranges([100] * 1000), 300)
    self.assertEqual(len(got), 1000)
    self.assertGreaterEqual(n_eff, 300)

  def test_uneven_chunks(self):
    # Sets extended in odd steps end with short chunks.
    self._check(self._ranges([100] * 37 + [40, 20, 3]), 300)
    self._check(self._ranges([10] * 6), 12)

  def test_census_when_n_covers_the_set(self):
    ranges = self._ranges([10] * 6)
    got, n_eff = self._check(ranges, 300)
    self.assertEqual(got, list(range(60)))
    self.assertEqual(n_eff, 60.0)

  def test_reproducible_from_seed(self):
    ranges = self._ranges([100] * 20)
    self.assertEqual(self._check(ranges, 300, seed=7),
                     self._check(ranges, 300, seed=7))

  def test_bound(self):
    # 1 - 0.05^(1/n); n = 300 gives under 1%, close to the rule of three.
    b = prepare.zero_failure_bound(300)
    self.assertAlmostEqual(b, 1 - 0.05 ** (1 / 300))
    self.assertLess(b, 0.01)
    self.assertAlmostEqual(b * 300, 3, delta=0.02)


class BoothScriptTests(unittest.TestCase):

  def test_commented_scripts_are_not_loaded(self):
    hp = pathlib.Path(tempfile.mkdtemp())
    try:
      booth = hp / 'heliosbooth' / 'js'
      booth.mkdir(parents=True)
      (booth / 'a.js').write_text('a')
      (booth / 'b.js').write_text('b')
      (hp / 'heliosbooth' / 'vote.html').write_text(
        '<html><head><!--\n<script src="js/b.js"></script>-->\n'
        '<script language="javascript" src="js/a.js"></script>'
        '<script>inline()</script></head></html>')
      self.assertEqual(list(ps.booth_js_hashes(hp)), ['js/a.js'])
    finally:
      shutil.rmtree(hp)

  def test_real_booth(self):
    got = ps.booth_js_hashes()
    self.assertTrue(got)
    self.assertNotIn('js/jscrypto/helios.js', got)   # inside <!-- --> today
    for src, h in got.items():
      self.assertRegex(h, r'^[0-9a-f]{64}$', src)


class KeyRoundTripTests(unittest.TestCase):

  def setUp(self):
    self.d = pathlib.Path(tempfile.mkdtemp())

  def tearDown(self):
    shutil.rmtree(self.d)

  def _roundtrip(self, scheme, pk_class):
    path = self.d / scheme / 'key.json'
    key = fixed_key.write_new(path, scheme, 'testcommit')
    self.assertTrue(fixed_key.roundtrip_ok(path))
    self.assertEqual(fixed_key.check_consistent(key), [])
    self.assertIsInstance(key.public_key, pk_class)

    # What loads from key.json is what a Trustee row with these values loads.
    from helios.models import Trustee
    for name in fixed_key.LD_FIELDS:
      f = Trustee._meta.get_field(name)
      obj = getattr(key, name)
      row_text = f.get_prep_value(obj)
      if obj is None:
        self.assertIsNone(row_text)
        continue
      self.assertEqual(f.get_prep_value(f.from_db_value(row_text)), row_text)
      self.assertEqual(type(f.from_db_value(row_text)), type(obj))
    self.assertEqual(key.public_key_hash, fixed_key.public_key_hash(
      key.public_key, fixed_key.params_for(scheme)))
    self.assertEqual(key.key_size, 1024 if scheme == 'paillier' else 2048)
    # generate_trustee's pok branch: none for Paillier, a Schnorr proof else.
    if scheme == 'paillier':
      self.assertIsNone(key.pok)
    else:
      self.assertIsNotNone(key.pok)

    # A changed key no longer matches its fingerprint.
    doc = json.loads(path.read_text())
    field = 'n' if scheme == 'paillier' else 'y'
    v = doc['public_key'][field]
    doc['public_key'][field] = v[:-1] + ('1' if v[-1] != '1' else '2')
    path.write_text(json.dumps(doc, sort_keys=True, indent=2) + '\n')
    with self.assertRaises(ValueError):
      fixed_key.load(path)

  def test_elgamal(self):
    from helios.crypto import elgamal
    self._roundtrip('elgamal', elgamal.PublicKey)

  def test_paillier(self):
    from helios.crypto import paillier
    self._roundtrip('paillier', paillier.PaillierPublicKey)


class RefusalTests(unittest.TestCase):

  def setUp(self):
    self.d = pathlib.Path(tempfile.mkdtemp())

  def tearDown(self):
    shutil.rmtree(self.d)

  def test_existing_key_not_overwritten(self):
    path = self.d / 'key.json'
    fixed_key.write_new(path, 'elgamal', 'testcommit')
    before = path.read_bytes()
    with self.assertRaises(FileExistsError):
      fixed_key.write_new(path, 'elgamal', 'testcommit')
    self.assertEqual(path.read_bytes(), before)

  def test_existing_key_refused_by_cli(self):
    args = ['keys', '--face', 'smoke', '--scheme', 'elgamal',
            '--root', str(self.d)]
    with mock.patch.object(prepare, 'require_clean_helios',
                           return_value='testcommit'):
      self.assertEqual(prepare.main(args), 0)
      path = ps.key_path(self.d / 'smoke' / 'elgamal')
      before = path.read_bytes()
      self.assertEqual(prepare.main(args), 2)
    self.assertEqual(path.read_bytes(), before)

  def _git(self, repo, *a):
    subprocess.run(['git', '-C', str(repo), *a], check=True,
                   capture_output=True)

  def test_dirty_tree(self):
    repo = self.d / 'repo'
    repo.mkdir()
    self._git(repo, 'init', '-q')
    (repo / 'f').write_text('1')
    self._git(repo, 'add', 'f')
    self._git(repo, '-c', 'user.email=t@t', '-c', 'user.name=t',
              'commit', '-qm', 'x')
    self.assertTrue(prepare.require_clean_helios(repo))
    (repo / 'f').write_text('2')
    with self.assertRaises(prepare.Refused):
      prepare.require_clean_helios(repo)
    with self.assertRaises(prepare.Refused):
      prepare.require_clean_helios(self.d / 'not-a-repo')

  def test_dirty_tree_refused_by_cli(self):
    for cmd in (['keys'], ['ballots', '--count', '1']):
      with self.subTest(cmd=cmd[0]), \
           mock.patch.object(helios_env, 'git_is_dirty', return_value=True):
        args = [*cmd, '--face', 'smoke', '--scheme', 'elgamal',
                '--root', str(self.d)]
        self.assertEqual(prepare.main(args), 2)
    # Nothing was written: no key, no manifest.
    self.assertFalse((self.d / 'smoke' / 'elgamal' / 'key.json').exists())
    self.assertFalse((self.d / 'smoke' / 'elgamal' / 'manifest.json').exists())


@unittest.skipUnless(_server_up(), 'Helios server not answering')
class SwapThenFreezeTests(unittest.TestCase):
  """
  Through the real stack: Stage 0 configure, install_fixed_key, freeze over
  HTTP. The frozen election's public key must be the saved key.
  """

  def setUp(self):
    self.d = pathlib.Path(tempfile.mkdtemp())

  def tearDown(self):
    shutil.rmtree(self.d)

  def _swap_then_freeze(self, scheme):
    import runner
    from drivers import stage0_setup
    from helios.models import Election

    path = self.d / 'key.json'
    key = fixed_key.write_new(path, scheme, 'testcommit')
    base_url = helios_env.helios_url()
    uuid = stage0_setup.configure(
      base_url=base_url, short_name=f'wl-test-swap-{scheme}-{secrets.token_hex(2)}',
      name='workload test: swap then freeze',
      questions=votes_gen.build_questions(FACES['smoke']), n_voters=1,
      scheme=scheme, ablation=runner.resolve_ablation(scheme),
      log=lambda m: None)

    generated = Election.objects.get(uuid=uuid).get_helios_trustee()
    self.assertNotEqual(fixed_key.fingerprint(generated.public_key),
                        key.fingerprint)

    stage0_setup.install_fixed_key(uuid, path, log=lambda m: None)
    stage0_setup.freeze(base_url=base_url, election_uuid=uuid,
                        log=lambda m: None)
    self.assertEqual(stage0_setup.check_fixed_key(uuid, path, log=lambda m: None),
                     key.fingerprint)

    e = Election.objects.get(uuid=uuid)
    self.assertEqual(fixed_key.fingerprint(e.public_key), key.fingerprint)
    t = e.get_helios_trustee()
    self.assertEqual(t.public_key_hash, key.public_key_hash)
    self.assertEqual(fixed_key._dump('secret_key', t.secret_key),
                     key.doc['secret_key'])
    self.assertEqual(fixed_key._dump('pok', t.pok), key.doc['pok'])

    # After freeze the swap is refused: the election key is already set.
    with self.assertRaises(RuntimeError):
      stage0_setup.install_fixed_key(uuid, path, log=lambda m: None)

  def test_elgamal(self):
    self._swap_then_freeze('elgamal')

  def test_paillier(self):
    self._swap_then_freeze('paillier')

  def test_wrong_key_fails_check(self):
    from drivers import stage0_setup
    import runner
    base_url = helios_env.helios_url()
    uuid = stage0_setup.configure(
      base_url=base_url, short_name=f'wl-test-nokey-{secrets.token_hex(2)}',
      name='workload test: generated key kept',
      questions=votes_gen.build_questions(FACES['smoke']), n_voters=1,
      scheme='elgamal', ablation=runner.resolve_ablation('elgamal'),
      log=lambda m: None)
    stage0_setup.freeze(base_url=base_url, election_uuid=uuid,
                        log=lambda m: None)
    path = self.d / 'key.json'
    fixed_key.write_new(path, 'elgamal', 'testcommit')
    with self.assertRaises(RuntimeError):
      stage0_setup.check_fixed_key(uuid, path, log=lambda m: None)


SMOKE_ELGAMAL = ps.set_dir('smoke', 'elgamal')


@unittest.skipUnless(_server_up() and (SMOKE_ELGAMAL / 'manifest.json').exists(),
                     'needs the server and prepared/smoke/elgamal')
class ValidatorCatchesTampering(unittest.TestCase):
  """
  validate must fail a set that is wrong, not only pass one that is right.
  Works on a copy of prepared/smoke/elgamal; the original is never touched.
  """

  def setUp(self):
    self.root = pathlib.Path(tempfile.mkdtemp())
    self.d = self.root / 'smoke' / 'elgamal'
    shutil.copytree(SMOKE_ELGAMAL, self.d,
                    ignore=shutil.ignore_patterns('validation.json', '.lock'))
    self.chunk = ps.completed_chunks(self.d)[0][2]
    self.lines = list(ps.read_chunk(self.chunk))

  def tearDown(self):
    shutil.rmtree(self.root)

  def _rewrite(self, lines):
    with open(self.chunk, 'wb') as fh:
      with gzip.GzipFile(filename='', fileobj=fh, mode='wb', mtime=0) as gz:
        for line in lines:
          gz.write((json.dumps(line, separators=(',', ':')) + '\n').encode())
    # Re-stamp the manifest so structure passes and the deeper check must
    # catch it.
    m = ps.read_json(ps.manifest_path(self.d))
    for c in m['chunks']:
      if c['file'] == f'chunks/{self.chunk.name}':
        c['sha256'] = ps.sha256_file(self.chunk)
    ps.write_json(ps.manifest_path(self.d), m)

  def _validate(self, *extra):
    rc = prepare.main(['validate', '--face', 'smoke', '--scheme', 'elgamal',
                       '--root', str(self.root), *extra])
    return rc, ps.read_json(ps.validation_path(self.d))

  def test_untouched_copy_passes(self):
    rc, v = self._validate()
    self.assertEqual(rc, 0)
    self.assertTrue(v['passed'])
    # Default sample (300) covers this whole set: a census, bound recorded.
    z = v['zero_failure_bound']
    self.assertTrue(z['census'])
    self.assertEqual(z['n'], v['validated_count'])
    self.assertEqual(z['confidence'], 0.95)
    self.assertAlmostEqual(z['bound'], prepare.zero_failure_bound(z['n_effective']))

  def test_small_sample_spans_every_chunk(self):
    self.assertEqual(self._validate()[0], 0)        # first run checks all
    n_chunks = len(ps.completed_chunks(self.d))
    rc, v = self._validate('--sample', str(n_chunks))
    self.assertEqual(rc, 0)
    self.assertFalse(v['first_run'])
    self.assertTrue(v['checks']['coverage']['passed'])
    self.assertEqual(v['checks']['coverage']['chunks'], n_chunks)
    for s, e, _p in ps.completed_chunks(self.d):
      self.assertTrue(any(s <= i < e for i in v['sample_indices']))
    z = v['zero_failure_bound']
    self.assertFalse(z['census'])
    self.assertEqual(z['failures'], 0)
    self.assertGreaterEqual(z['n_effective'], n_chunks)
    self.assertAlmostEqual(z['bound'], prepare.zero_failure_bound(z['n_effective']))

  def test_a_failure_stays_failed(self):
    # Past the first-run census, a fresh small sample would usually miss the
    # bad ballot. It is re-checked every run instead, so the set keeps
    # failing until it is regenerated.
    c = self.lines[3]['encrypted_answers'][0]['choices'][0]
    c['beta'] = str(int(c['beta']) + 1)
    self._rewrite(self.lines)
    with mock.patch.object(prepare, 'FIRST_RUN_ALL', 0):
      rc, v = self._validate('--sample', '1000')
      self.assertEqual(rc, 1)
      self.assertIn(3, v['checks']['proofs']['failed'])
      self.assertIsNone(v['zero_failure_bound']['bound'])
      for _ in range(2):
        rc, v = self._validate('--sample', '1')
        self.assertEqual(rc, 1)
        self.assertEqual(v['recheck_indices'], [3])
        self.assertFalse(v['passed'])

  def test_altered_ciphertext_fails_proofs(self):
    c = self.lines[3]['encrypted_answers'][0]['choices'][0]
    c['beta'] = str(int(c['beta']) + 1)
    self._rewrite(self.lines)
    rc, v = self._validate()
    self.assertEqual(rc, 1)
    self.assertTrue(v['checks']['structure']['passed'])
    self.assertIn(3, v['checks']['proofs']['failed'])

  def test_swapped_ciphertexts_fail_plaintexts(self):
    # Both ballots stay valid encryptions, so only decryption shows the swap.
    a, b = next((i, j) for i in range(len(self.lines))
                for j in range(i + 1, len(self.lines))
                if self.lines[i]['plaintext'] != self.lines[j]['plaintext'])
    ea, eb = self.lines[a]['encrypted_answers'], self.lines[b]['encrypted_answers']
    self.lines[a]['encrypted_answers'], self.lines[b]['encrypted_answers'] = eb, ea
    self._rewrite(self.lines)
    rc, v = self._validate()
    self.assertEqual(rc, 1)
    self.assertTrue(v['checks']['proofs']['passed'])
    self.assertEqual(sorted(v['checks']['plaintexts']['failed']), [a, b])

  def test_duplicate_index_fails_structure(self):
    self.lines[1]['ballot_index'] = self.lines[0]['ballot_index']
    self._rewrite(self.lines)
    rc, v = self._validate()
    self.assertEqual(rc, 1)
    self.assertFalse(v['checks']['structure']['passed'])

  def test_edited_chunk_fails_manifest_hash(self):
    with open(self.chunk, 'ab') as f:
      f.write(gzip.compress(b''))
    rc, v = self._validate()
    self.assertEqual(rc, 1)
    self.assertFalse(v['checks']['structure']['passed'])


if __name__ == '__main__':
  unittest.main()
