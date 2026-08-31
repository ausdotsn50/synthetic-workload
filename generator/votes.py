"""
Seeded plaintext vote generation.

Every cell is reproducible from (base_seed, scheme, N, rep) alone — no shared RNG
state between cells, so a single cell can be re-run in isolation and produce
identical plaintext votes.

Note what is NOT modelled: a skewed / worst-case vote distribution. Spec §0.1 shows
Helios recovers discrete logs from a precomputed table walked to `num_tallied`, not
via BSGS, so decryption cost is Θ(N) and *independent of how votes are spread*.
A skewed condition would therefore measure nothing. Uniform selection is used and
the distribution-independence is itself the finding.
"""

import hashlib
import random

# Same inputs, same plaintext ballots
# Purpose: repoducibility
# Ot: election seed; marked in .jsonl column
def cell_seed(base_seed, scheme, N, rep):
  """
  Derive a per-cell seed deterministically. Hashing rather than arithmetic mixing
  so neighbouring cells do not get correlated streams.
  """
  key = f'{base_seed}|{scheme}|{N}|{rep}'.encode()
  return int.from_bytes(hashlib.sha256(key).digest()[:8], 'big')

# Expand a ballot_face.yaml entry into Helios question dicts.
def build_questions(face):
  """
  See helios/fixtures/election.json -- questions for the SCHEMA
  """
  questions = []
  for q in face['questions']:
    answers = [f"{q['answer_prefix']} {i + 1}" for i in range(q['answer_count'])]
    questions.append({
      'answer_urls': [None] * len(answers),
      'answers': answers,
      'choice_type': 'approval',
      'max': q['max'],
      'min': q['min'],
      'question': q['question'],
      'result_type': 'absolute',
      'short_name': q['short_name'],
      'tally_type': 'homomorphic',
    })
  return questions

# Produces one ballot
# For modification - simulating front-runner style in real NLE
def generate_ballot(rng, questions):
  """
  Initial generate ballot mechanism:
    - Loop over the questions
    - Get min and max values
    - Random value of how many candidates the voter picks accdg. to max min
    - Pick k items
  """
  ballot = []
  for q in questions:
    lo, hi = q.get('min', 0), q['max']
    k = rng.randint(lo, hi)
    ballot.append(sorted(rng.sample(range(len(q['answers'])), k))) # Randomly selected k items from full answers length
  return ballot


def generate_ballots(seed, questions, count):
  # To do: modify generate ballots mechanism
  rng = random.Random(seed) # Note: 424242 base seed only for randomization no crypto val
  return [generate_ballot(rng, questions) for _ in range(count)]

