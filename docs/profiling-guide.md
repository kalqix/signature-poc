# Profiling Guide

## Quick Start

```bash
# Build the SP1 guest ELF (required after any shared/ or program/ change)
cd program && cargo prove build --elf-name signature-poc --output-directory elf && cd ..

# Run the recommended production-shaped benchmark
cargo run --release --bin profile -- batch-dedup-flat-200-6000
```

## CLI Modes

### Single-Signature

| Mode | Description |
|------|-------------|
| `register-key` | EIP-191 + JMT insert |
| `verify-order` | Septic Schnorr + JMT membership (production single-order path) |
| `verify-order-eth` | secp256k1 EIP-191 ecrecover (baseline comparison) |
| `verify-order-septic` | Per-bit scalar_mul Schnorr + Merkle (precompile cost isolation) |

### Batch — No Merkle

| Mode | Schnorr Strategy |
|------|-----------------|
| `batch-septic-{N}` | Per-bit `scalar_mul` (naive) |
| `batch-septic-opt-{N}` | Shamir's trick (combined-equation) |
| `batch-septic-single-{N}` | Single-syscall `scalar_mul_single` |
| `batch-septic-opt-single-{N}` | Shamir + single-syscall |
| `batch-septic-verify-{N}` | `SEPTIC_VERIFY` precompile |
| `batch-eth-{N}` | secp256k1 ecrecover |

N = 1, 10, 2000, 4000, 6000

### Batch — With Merkle

| Mode | Description |
|------|-------------|
| `batch-septic-verify-merkle-{N}` | Per-order Merkle + SEPTIC_VERIFY |

N = 1, 10, 2000, 6000

### Dedup Batch — Shortcut Forms (Recommended)

```
batch-dedup-flat-<unique>-<orders>    # FlatBatch + rkyv (best)
batch-dedup-rkyv-<unique>-<orders>    # BatchExistence + rkyv
batch-dedup-batch-<unique>-<orders>   # BatchExistence + borsh
```

Tree size equals order count. Examples:

```bash
# 200 unique keys, 6000 orders, 6000-key JMT
cargo run --release --bin profile -- batch-dedup-flat-200-6000

# 50 unique keys, 6000 orders (more key reuse)
cargo run --release --bin profile -- batch-dedup-flat-50-6000

# Compare all three serialization strategies
cargo run --release --bin profile -- batch-dedup-flat-200-6000
cargo run --release --bin profile -- batch-dedup-rkyv-200-6000
cargo run --release --bin profile -- batch-dedup-batch-200-6000
```

### Dedup Batch — Long Forms (Configurable)

```
batch-septic-dedup-<count> [ratio] [tree_size]
batch-septic-dedup-batch-<count> [ratio] [tree_size]
batch-septic-dedup-rkyv-<count> [ratio] [tree_size]
```

- `ratio`: fraction of orders that are repeats (default 0.2)
- `tree_size`: total keys in JMT (default = unique_count)
- `unique_count = ceil(count * (1 - ratio))`

Examples:

```bash
# 6000 orders, 96.67% repeat → 200 unique, 6000 in JMT
cargo run --release --bin profile -- batch-septic-dedup-batch-6000 0.9667 6000
```

### Host Benchmark

```bash
# Septic Schnorr vs secp256k1 signing speed (2000 sigs)
cargo run --release --bin profile -- bench-sign
```

## Reading Output

Each run prints:

```
============================================================
  Profiling: BatchSepticDedupFlat (6000 orders, 200 unique in batch, 6000 in JMT)
============================================================
  input_size:         1090177 bytes (1 B borsh tag + 1090176 B rkyv flat witness)
  proof_type:         BATCH_DEDUP_FLAT_200u_6000o
  total_instructions: 13649675
  total_syscalls:     15679
  total_cycles:       13665354
  gas (normalized):   81304175  (5.950 gas/cycle)
  touched_memory:     0

  Cycle tracker breakdown:
    section                              cycles     gas (est.)       %
    flat_merkle_total                   8440647       50218958   61.8%
    flat_schnorr_total                  4668299       27774779   34.2%
    flat_bind_leaves                     532909        3170625    3.9%
    flat_read                               342           2034    0.0%
    flat_access                             298           1772    0.0%
```

Key fields:
- **total_cycles** = total_instructions + total_syscalls (the number that matters)
- **gas (normalized)** = SP1's gas metric (accounts for syscall cost weights)
- **cycle tracker breakdown** = per-section costs from `cycle-tracker-report` annotations

## Trace Files (Flamegraphs)

```bash
# Generate trace
TRACE_FILE=output.json TRACE_SAMPLE_RATE=100 \
  cargo run --release --bin profile -- batch-dedup-flat-200-6000

# View in samply
samply load output.json
```

## Cycle Tracker Labels

### Flat + rkyv path

| Label | What it measures |
|-------|-----------------|
| `flat_read` | `sp1_zkvm::io::read_vec()` buffer copy |
| `flat_access` | `rkyv::access_unchecked()` pointer cast |
| `flat_merkle_total` | `FlatBatchExistenceProof::verify()` |
| `flat_bind_leaves` | Leaf deserialization + field assertions |
| `flat_schnorr_total` | All `schnorr_compute()` calls |

### rkyv path (non-flat)

| Label | What it measures |
|-------|-----------------|
| `rkyv_read` | Buffer copy |
| `rkyv_access` | Pointer cast |
| `rkyv_merkle_total` | `BatchExistenceProof::verify()` |
| `rkyv_bind_leaves` | Leaf binding |
| `rkyv_schnorr_total` | Schnorr verification |

### Borsh BatchExistence path

| Label | What it measures |
|-------|-----------------|
| `dedup_batch_merkle_total` | `BatchExistenceProof::verify()` |
| `dedup_batch_bind_leaves` | Leaf binding |
| `dedup_batch_schnorr_total` | Schnorr verification |

Note: borsh deserialization is NOT tracked by a cycle label — it happens
inside `borsh::from_slice()` before any handler runs. The difference between
`total_cycles` and the sum of tracked sections is the deserialization cost.

### Single-order paths

| Label | Handler |
|-------|---------|
| `jmt_verify_old`, `eip191_recover` | RegisterKey |
| `jmt_verify`, `schnorr_verify` | VerifyOrder |
| `eip191_hash`, `secp256k1_recover` | VerifyOrderEth |

## ELF Rebuild Warning

The `--elf-name` and `--output-directory` flags are load-bearing:

```bash
cargo prove build --elf-name signature-poc --output-directory elf
```

The backend `include_bytes!`s `program/elf/signature-poc`. Running plain
`cargo prove build` (without these flags) writes to a different path and
silently leaves a stale ELF.
