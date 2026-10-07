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
config/          levels.yaml, ballot_face.yaml
generator/       seeded plaintext votes; synthetic voters + credential retrieval
drivers/
  stage0_setup.py      create the election in the requested arm (trustee key made here), upload voters, freeze
  stage1_encrypt.py    encrypt ballots with Helios's booth code in headless Chrome
  stage2_cast.py       cast ballots over HTTP, wait for Celery verification
  stage3_aggregate.py  POST /compute_tally, wait for the encrypted tally
  stage4_decrypt.py    wait for decryption factors, POST /combine_decryptions
  http_client.py       Helios HTTP session; polling helper for Celery-completed phases
  measure_join.py      joins Helios's sidecar timings onto the cell by election uuid
emit.py          append-only JSONL writer, env captured per record
runner.py        orchestrates one (scheme, N, rep) cell
acceptance.py    Milestone 2 acceptance checks
```

## Stages

Every stage drives Helios through the endpoints a real election uses, and the
same drivers run all four arms (`elgamal`, `paillier-off`, `paillier-short`,
`paillier-long`). Helios times its own operations from the inside
(`helios/measure.py` in helios-server), appends them to the sidecar file at
`HELIOS_MEASURE_PATH`, and `measure_join.py` joins them onto the cell by
election uuid. The harness itself records stage wall clocks, in-browser
encryption timings and payload sizes.

| Module | What it does | Runs in | Recorded there |
|---|---|---|---|
| `stage0_setup.py` | `configure`: create the election in the requested arm and confirm the election row and trustee key match it, save the ballot face, upload the voter list and wait for Celery to register it. `freeze`: lock the ballot and roll, open voting | Helios web process, over HTTP; voter-file processing in the Celery worker | Helios, at election creation: `keygen_time_ns`; `prove_sk_time_ns` (ElGamal only). Harness: walls `stage 0 configure` and `stage 1 freeze`; `election_json_bytes` (the booth's download, fetched after freeze) |
| `stage1_encrypt.py` | encrypt each ballot with the booth's own `HELIOS.EncryptedAnswer`, after discarded warm-up ballot(s); stream the ciphertexts to `<run_id>-ballots-n<N>-r<rep>.jsonl` | headless Chrome (Selenium) | Harness, timed in the page with `performance.now()`: `encryption_time_ms`, `encryption_proof_ms`, `ciphertext_bytes`, `proof_bytes`, `encryption_warmup_ms`; `djn41_table_build_ms` (Paillier `short` and `long` only); wall `stage 2 encrypt` |
| `stage2_cast.py` | cast each ballot as its voter (login → `/cast` → `/cast_confirm`), then wait until Celery has verified every ballot | web process + Celery worker | Harness: `cast_payload_bytes`; walls `stage 2 cast` and `stage 2 verify`. Helios, per ballot: `verification_time_ns`, `verification_only_ns` |
| `stage3_aggregate.py` | `POST /compute_tally`, wait for `encrypted_tally` | Celery worker | Helios: `aggregation_time_ns`, `aggregation_only_ns`. Harness: wall `stage 3 aggregate` |
| `stage4_decrypt.py` | wait for the decryption factors (a task chained off Stage 3's POST), then `POST /combine_decryptions` | Celery worker + web process | Helios: `decryption_factor_time_ns`, `decryption_factor_only_ns`, `decryption_factors_bytes`, `decryption_proofs_bytes`; then `dlog_precompute_time_ns` and `dlog_lookup_time_ns` (ElGamal) or `decryption_time_ns` (Paillier). Harness: `result` with the expected tally; wall `stage 4 decrypt` |

> The driver modules are grouped by concern (setup, encrypt, cast + verify, aggregate, decrypt). The console banners, `stage_wall_time_ns` names and record `stage` labels deliberately keep the original names (`configure`, `freeze`, `encrypt`, `aggregate`, `decrypt`), so output is comparable with earlier runs.