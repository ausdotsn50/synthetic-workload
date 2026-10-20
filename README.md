# Synthetic Helios election workload

Measurement harness for *System-Level Performance Comparison of Paillier and
Exponential ElGamal using the Helios Voting System*.

## Relationship to helios-server

This is a **separate git repo** from `helios-server/` — the instrument is not the
subject. But it deliberately runs on **helios-server's interpreter**:

```bash
uv run --project ../helios-server python runner.py ...
```

Because the two repos version independently, every JSONL record carries **both**
`helios_commit` and `workload_commit`. Reproducing a measurement requires the pair.

## Setup

```bash
# harness deps live in helios-server's non-default 'workload' group
cd ../helios-server && uv sync --group workload
```

## Layout

```
config/          levels.yaml, ballot_face.yaml; sweep plans (sweep_*, compare_*, *_live)
generator/       the seeded master ballot list; synthetic voters + credential retrieval
drivers/
  stage0_setup.py      create the election in the requested arm (trustee key made here), upload voters, freeze
  stage1_encrypt.py    encrypt ballots with Helios's booth code in headless Chrome
  stage2_cast.py       cast ballots over HTTP, wait for Celery verification
  stage3_aggregate.py  POST /compute_tally, wait for the encrypted tally
  stage4_decrypt.py    wait for decryption factors, POST /combine_decryptions
  http_client.py       Helios HTTP session; polling helper for Celery-completed phases
  measure_join.py      joins Helios's sidecar timings onto the cell by election uuid
  fixed_key.py         the fixed trustee key of a prepared-ballot set (key.json)
  prepared_set.py      prepared-ballot layout, chunks, manifest provenance
  stage2_populate.py   bulk cells: insert N - S ballots as verified casts; ANALYZE (every cell)
  worker.py            fresh Celery worker at every cell's start; worker RSS probe
emit.py          append-only JSONL writer, env captured per record
runner.py        orchestrates one (scheme, N, rep, mode) cell, live or bulk
prepare.py       prepared ballots: `keys`, `ballots`, `validate` (not measurements)
sweep.py         runs a plan of cells, resumable, emptying the database between cells
compare_modes.py live vs bulk: each metric per mode, relative difference, tallies identical
acceptance.py    Milestone 2 acceptance checks
tests/           unittest suite: python -m unittest discover -s tests -t .
```

## Cells and modes

One cell is one election: one scheme, one N, one repetition, one mode. Every
cell starts on a fresh Celery worker, and nothing interrupts the election's own
pipeline (encrypt → cast → verify → aggregate → decrypt). Every cell casts
`master_ballots(seed, questions, N)`, so cells at the same N tally the same
votes whatever their arm or mode.

| Mode | Command | Ballots |
|---|---|---|
| `live` | `runner.py --face smoke --n 10` (or `--live`) | all N encrypted in the browser, cast and verified |
| `bulk` | `runner.py --face smoke --n 10 --prepared --sample 3` | S live as above, plus N − S prepared ballots inserted as verified casts |

Each prefixed with `uv run --project ../helios-server python`; add
`--scheme paillier` for the `paillier-off` arm (CRT decryption proofs on, the
server's default). Window 1 of the runbook must run the Celery worker inside its
restart loop (SERVER_RUNBOOK.md §4): the runner shuts the worker down at the
start of every cell and waits for the fresh one. Needs `psutil` from
helios-server's `workload` group, for the worker's RSS probe.

Plans of many cells run with `sweep.py`, which skips accepted cells on a rerun
and, after each accepted cell, deletes its election and runs `VACUUM ANALYZE`:

| Plan | Face | Modes | Levels | Reps |
|---|---|---|---|---|
| `config/sweep_nle2025.yaml` | nle2025 | bulk | 100 … 10000 | 3 |
| `config/sweep_smoke.yaml` | smoke | bulk | 1000 … 200000 | 3 |
| `config/compare_nle2025.yaml` | nle2025 | live, bulk | 50, 100, 200 | 1 |
| `config/compare_smoke.yaml` | smoke | live, bulk | 1000, 2000, 5000 | 1 |
| `config/sweep_live.yaml` (fallback) | nle2025 | live | 10 … 500 | 1 |
| `config/anchors_live.yaml` (fallback) | nle2025 | live | 100 | 3 |

```bash
uv run --project ../helios-server python sweep.py --plan config/compare_smoke.yaml
uv run --project ../helios-server python compare_modes.py --face smoke
```

## Prepared ballots

Ballots outside a bulk cell's live sample are encrypted once, ahead of the runs,
under one fixed key per (face, scheme), into `prepared/<face>/<scheme>/`
(gitignored; root is `levels.yaml prepared.dir`):

```bash
uv run --project ../helios-server python prepare.py keys     --face smoke --scheme elgamal
uv run --project ../helios-server python prepare.py ballots  --face smoke --scheme elgamal --count 40 --workers 4
uv run --project ../helios-server python prepare.py validate --face smoke --scheme elgamal
```

`ballots` needs the Helios server, Celery and Chrome, refuses a dirty
helios-server, resumes an interrupted run and extends a set when `--count`
grows. `validate` checks every index against the master plaintext list, then
proof-checks and decrypts a random sample (default 300, spread over every
chunk) and tallies a prefix with Helios's own code. It records the 95%
zero-failure bound on the invalid fraction; any failure fails the whole set.

A bulk cell freezes under its set's fixed key (Helios's own keygen still runs
and is measured), refuses a set that does not match the current face, seed,
booth or key size, and spot-verifies five inserted ballots with
`vote.verify(election)`.

## Stages

Every stage drives Helios through the endpoints a real election uses, and the
same drivers run both arms (`elgamal`, `paillier-off`). Helios times its own operations from the inside
(`helios/measure.py` in helios-server), appends them to the sidecar file at
`HELIOS_MEASURE_PATH`, and `measure_join.py` joins them onto the cell by
election uuid. The harness itself records stage wall clocks, in-browser
encryption timings and payload sizes.

| Module | What it does | Runs in | Recorded there |
|---|---|---|---|
| `stage0_setup.py` | `configure`: create the election in the requested arm and confirm the election row and trustee key match it, save the ballot face, upload the voter list and wait for Celery to register it. `freeze`: lock the ballot and roll, open voting | Helios web process, over HTTP; voter-file processing in the Celery worker | Helios, at election creation: `keygen_time_ns`; `prove_sk_time_ns` (ElGamal only). Harness: walls `stage 0 configure` and `stage 1 freeze`; `election_json_bytes` (the booth's download, fetched after freeze) |
| `stage1_encrypt.py` | encrypt each ballot with the booth's own `HELIOS.EncryptedAnswer`, after discarded warm-up ballot(s); stream the ciphertexts to `<run_id>-ballots-n<N>-r<rep>.jsonl` | headless Chrome (Selenium) | Harness, timed in the page with `performance.now()`: `encryption_time_ms`, `encryption_proof_ms`, `ciphertext_bytes`, `proof_bytes`, `encryption_warmup_ms`; wall `stage 2 encrypt` |
| `stage2_cast.py` | cast each ballot as its voter (login → `/cast` → `/cast_confirm`), then wait until Celery has verified every ballot | web process + Celery worker | Harness: `cast_payload_bytes`; walls `stage 2 cast` and `stage 2 verify`. Helios, per ballot: `verification_time_ns`, `verification_only_ns` |
| `stage3_aggregate.py` | `POST /compute_tally`, wait for `encrypted_tally` | Celery worker | Helios: `aggregation_time_ns`, `aggregation_only_ns`. Harness: wall `stage 3 aggregate` |
| `stage4_decrypt.py` | wait for the decryption factors (a task chained off Stage 3's POST), then `POST /combine_decryptions` | Celery worker + web process | Helios: `decryption_factor_time_ns`, `decryption_factor_only_ns`, `decryption_factors_bytes`, `decryption_proofs_bytes`; then `dlog_precompute_time_ns` and `dlog_lookup_time_ns` (ElGamal) or `decryption_time_ns` (Paillier). Harness: `result` with the expected tally; wall `stage 4 decrypt` |

> The driver modules are grouped by concern (setup, encrypt, cast + verify, aggregate, decrypt). The console banners, `stage_wall_time_ns` names and record `stage` labels deliberately keep the original names (`configure`, `freeze`, `encrypt`, `aggregate`, `decrypt`), so output is comparable with earlier runs.