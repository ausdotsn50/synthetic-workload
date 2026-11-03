"""
The fixed trustee key a prepared-ballot set is encrypted under.

A ciphertext only decrypts and verifies under the key it was encrypted with, so
every prepared-ballot cell of an arm must run under one saved key. Helios still
generates its own key at election creation -- that keygen is still measured,
inside Election.generate_trustee (models.py ~716, span keygen_time_ns) -- and
the harness then swaps the trustee's key for this one before freeze
(stage0_setup.install_fixed_key). Freeze copies the trustee key into the
election (Election.freeze, models.py ~692) and never checks that it is new.

key.json holds the four values a Trustee row holds for its key, each written
and read through that Trustee field's own LDObjectField (models.py ~1366-1390),
so what loads back is exactly the object Helios would load from the row:

    public_key       LDObjectField(type_hint='legacy/EGPublicKey')
    secret_key       LDObjectField(type_hint='legacy/EGSecretKey')
    pok              LDObjectField(type_hint='legacy/DLogProof'), null under Paillier
    public_key_hash  CharField

The type hints name ElGamal, but LDObject dispatches a Paillier key on its own
shape and datatype (helios/datatypes/__init__.py, _resolve_by_shape), exactly as
it does for the row.

This is a synthetic test key. It never protects a real vote, and it stays out
of git with the rest of prepared/.
"""

import dataclasses
import datetime
import hashlib
import json
import os
import pathlib

import helios_env

FORMAT = 1

# Trustee fields carried by key.json, in Trustee's own declaration order.
LD_FIELDS = ('public_key', 'secret_key', 'pok')


class _SchemeOnly:
  """
  Stand-in for an Election, for helios.views.crypto_params_for (views.py:63).
  It reads crypto_scheme, plus uuid in its unknown-scheme error message.
  """

  def __init__(self, scheme):
    self.crypto_scheme = scheme
    self.uuid = f'(fixed {scheme} key)'


def params_for(scheme):
  """The cryptosystem Helios would generate this scheme's trustee key in."""
  helios_env.setup_django()
  from helios.views import crypto_params_for
  return crypto_params_for(_SchemeOnly(scheme))


def key_size(scheme, params=None):
  """
  Paillier: bits per prime, PAILLIER_PARAMS.key_size (views.py:55), which is
  what crypto_params_for builds from. ElGamal: the bit length of the fixed
  group modulus p (views.py ELGAMAL_PARAMS), the same width by construction.
  """
  params = params or params_for(scheme)
  if scheme == 'paillier':
    return int(params.key_size)
  return int(params.p).bit_length()


def _field(name):
  helios_env.setup_django()
  from helios.models import Trustee
  return Trustee._meta.get_field(name)


def _dump(name, obj):
  """The JSON a Trustee row stores for this field, parsed back to a value."""
  text = _field(name).get_prep_value(obj)
  return None if text is None else json.loads(text)


def _load(name, value):
  """The object Helios loads from a Trustee row holding this value."""
  if value is None:
    return None
  return _field(name).from_db_value(json.dumps(value))


def fingerprint(public_key):
  """
  sha256 of the canonical public-key JSON: the Trustee/Election public_key
  field's own serialization, re-dumped with sorted keys and no whitespace.

  Takes the key object, so the same function reads key.json, a trustee row and
  the frozen election's public_key -- all three hold the same field type.
  """
  d = _dump('public_key', public_key)
  canonical = json.dumps(d, sort_keys=True, separators=(',', ':'))
  return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def public_key_hash(public_key, params):
  """Computed exactly as Election.generate_trustee does (models.py ~735)."""
  from helios import datatypes
  return datatypes.LDObject.instantiate(
    public_key, datatype=params.public_key_datatype).hash


def _render(doc):
  """The bytes of key.json. The round-trip check compares these."""
  return json.dumps(doc, sort_keys=True, indent=2) + '\n'


@dataclasses.dataclass
class FixedKey:
  path: pathlib.Path
  doc: dict
  public_key: object
  secret_key: object
  pok: object
  public_key_hash: str

  @property
  def scheme(self):
    return self.doc['scheme']

  @property
  def fingerprint(self):
    return self.doc['fingerprint']

  @property
  def key_size(self):
    return self.doc['key_size']


def generate(scheme):
  """
  The body of Election.generate_trustee (models.py ~716-745), minus the
  measure spans and the Trustee row: this key is made once, ahead of the runs,
  and its generation is not a measurement.

  Returns (values, params): values holds the four Trustee field values.
  """
  params = params_for(scheme)
  keypair = params.generate_keypair()
  pk, sk = keypair.pk, keypair.sk

  if params.dlog_challenge_generator is None:
    # Paillier: no trustee proof of knowledge (PaillierSecretKey.prove_sk
    # returns None), the same branch generate_trustee takes.
    pok = sk.prove_sk(None)
  else:
    pok = sk.prove_sk(params.dlog_challenge_generator)

  values = {'public_key': pk, 'secret_key': sk, 'pok': pok,
            'public_key_hash': public_key_hash(pk, params)}
  return values, params


def _doc(scheme, values, meta):
  doc = dict(meta)
  doc.update({name: _dump(name, values[name]) for name in LD_FIELDS})
  doc['public_key_hash'] = values['public_key_hash']
  doc['scheme'] = scheme
  return doc


def write_new(path, scheme, helios_commit):
  """
  Generate a key and write it to `path`. Refuses an existing file: every
  prepared ballot in the directory depends on the key already there.

  Committed with os.link, which fails if the target exists, so two concurrent
  runs cannot both believe they wrote the key.
  """
  path = pathlib.Path(path)
  if path.exists():
    raise FileExistsError(
      f'{path} already exists. Every prepared ballot in {path.parent} is '
      f'encrypted under it; a new key would orphan them all. Delete the whole '
      f'directory deliberately if a new key is really wanted.')

  values, params = generate(scheme)
  pk = values['public_key']
  meta = {
    'format': FORMAT,
    'key_size': key_size(scheme, params),
    'fingerprint': fingerprint(pk),
    'helios_commit': helios_commit,
    'created_at': datetime.datetime.now(datetime.timezone.utc)
                  .strftime('%Y-%m-%dT%H:%M:%SZ'),
    'note': 'synthetic workload test key; never used for a real election',
  }
  text = _render(_doc(scheme, values, meta))

  path.parent.mkdir(parents=True, exist_ok=True)
  tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
  # 0600: it holds a secret key, synthetic or not.
  fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
  try:
    with os.fdopen(fd, 'w') as f:
      f.write(text)
      f.flush()
      os.fsync(f.fileno())
    os.link(tmp, path)
  finally:
    tmp.unlink(missing_ok=True)
  return load(path)


def load(path):
  """
  Read key.json into the objects a Trustee row holds. Raises if the stored
  fingerprint or public_key_hash no longer describes the stored key.
  """
  path = pathlib.Path(path)
  if not path.exists():
    raise FileNotFoundError(
      f'{path} not found. Make it first: python prepare.py keys --face F '
      f'--scheme S')
  doc = json.loads(path.read_text())
  if doc.get('format') != FORMAT:
    raise ValueError(f'{path}: format {doc.get("format")!r}, expected {FORMAT}')

  objs = {name: _load(name, doc[name]) for name in LD_FIELDS}
  key = FixedKey(path=path, doc=doc, public_key=objs['public_key'],
                 secret_key=objs['secret_key'], pok=objs['pok'],
                 public_key_hash=doc['public_key_hash'])

  got = fingerprint(key.public_key)
  if got != doc['fingerprint']:
    raise ValueError(f'{path}: stored fingerprint {doc["fingerprint"]} but the '
                     f'stored public key hashes to {got}')
  params = params_for(doc['scheme'])
  pkh = public_key_hash(key.public_key, params)
  if pkh != key.public_key_hash:
    raise ValueError(f'{path}: stored public_key_hash {key.public_key_hash} '
                     f'but Helios computes {pkh} for the stored key')
  return key


def reserialize(key):
  """key.json's bytes rebuilt from the loaded objects, for the round trip."""
  meta = {k: v for k, v in key.doc.items()
          if k not in LD_FIELDS and k not in ('public_key_hash', 'scheme')}
  values = {'public_key': key.public_key, 'secret_key': key.secret_key,
            'pok': key.pok, 'public_key_hash': key.public_key_hash}
  return _render(_doc(key.scheme, values, meta))


def roundtrip_ok(path):
  """True if load-then-reserialize reproduces key.json byte for byte."""
  path = pathlib.Path(path)
  return reserialize(load(path)).encode('utf-8') == path.read_bytes()


def check_consistent(key):
  """
  The secret key, public key and proof belong together. Returns a list of
  problems, empty when consistent. Untimed sanity checks on Helios's objects.
  """
  pk, sk = key.public_key, key.secret_key
  problems = []
  if key.scheme == 'paillier':
    if sk.p * sk.q != pk.n:
      problems.append('p*q != n')
    if key.pok is not None:
      problems.append('Paillier key carries a pok; generate_trustee stores None')
  else:
    if pow(pk.g, sk.x, pk.p) != pk.y:
      problems.append('g^x != y')
    params = params_for(key.scheme)
    if key.pok is None:
      problems.append('ElGamal key has no pok')
    elif not pk.verify_sk_proof(key.pok, params.dlog_challenge_generator):
      problems.append('the pok does not verify against the public key')
  if fingerprint(sk.public_key) != key.fingerprint:
    problems.append('the secret key embeds a different public key')
  return problems
