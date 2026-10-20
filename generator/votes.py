"""
Seeded plaintext vote generation.

Every cell casts master_ballots(seed, questions, N): ballot i is the same in
every cell that has one, whatever its arm, mode or repetition. Neither the
scheme nor the rep is an input, so both arms at the same N cast identical
ballots and must produce identical tallies (a paired comparison), and a live
and a bulk cell at the same N tally the same votes. The seed is levels.yaml
`seed`, recorded on every record, so any cell's ballots can be regenerated
exactly.

Note what is NOT modelled: a skewed / worst-case vote distribution. Spec §0.1 shows
Helios recovers discrete logs from a precomputed table walked to `num_tallied`, not
via BSGS, so decryption cost is Θ(N) and *independent of how votes are spread*.
A skewed condition would therefore measure nothing. Uniform selection is used and
the distribution-independence is itself the finding.
"""

import random

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


def master_ballots(seed, questions, count):
  """
  The one plaintext list every cell casts from, and every prepared-ballot set
  is cut from: ballot i of any cell is master_ballots(seed, questions, M)[i].

  generate_ballots draws every ballot from one sequential RNG, so a longer list
  only appends: master_ballots(s, q, M)[:N] == master_ballots(s, q, N). That
  prefix property is what lets one prepared set of M ballots serve every N <= M
  and be extended later without re-encrypting what is already there. The seed
  is levels.yaml `seed`, and the list depends on neither the arm nor the mode,
  so every cell at the same N casts identical ballots.
  """
  return generate_ballots(seed, questions, count)


def expected_tally(questions, ballots):
  """
  The tally the cast ballots must decrypt to, in the layout of Helios's
  Election.result: per question, per answer, the number of ballots selecting
  it. acceptance.py compares it with the decrypted result.

  Checked against a real run before being relied on: regenerating the ballots of
  results/2026-09-26T08:55:37Z-405d.jsonl (ElGamal, N=5, smoke face) from its
  recorded seed gives [[0, 1, 1], [1, 0, 3]], the result Helios decrypted.
  """
  counts = [[0] * len(q['answers']) for q in questions]
  for ballot in ballots:
    for q_num, picks in enumerate(ballot):
      for a in picks:
        counts[q_num][a] += 1
  return counts

