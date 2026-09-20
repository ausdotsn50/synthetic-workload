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
drivers/         stage0..stage4 — one file per pipeline stage
node_encryptor/  encrypt.js — loads Helios's own jscrypto under Node
emit.py          append-only JSONL writer, env captured per record
runner.py        orchestrates one (scheme, N, rep) cell
acceptance.py    Milestone 2 acceptance checks
```

## Stages

| Stage | Measures | Path |
|---|---|---|
| 0 configure | — | HTTP API (§3.2) |
| 1 freeze | key generation (≥30 samples, §3.3) | in-process |
| 2 sample encryption | encryption time, ciphertext/proof bytes | Selenium + booth worker |
| 3 aggregate | aggregation time, proof-verification time | in-process |
| 4 decrypt | decryption factors, dlog precompute, dlog lookup | in-process |