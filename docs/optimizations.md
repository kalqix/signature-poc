# Optimization Journey

This document traces the progression of batch verification strategies, from
naive per-order Merkle to the final FlatBatch+rkyv path. Each step targets a
specific bottleneck identified via SP1 cycle profiling.

## Baseline: Per-Order Merkle + Per-Order Schnorr

**Mode:** `BatchSepticVerifyMerkle`

Every order carries its own `SparseMerkleProof`. The guest verifies N Merkle
proofs and N Schnorr signatures independently.

```
Per order:
  1 SparseMerkleProof::verify_existence   (~60k cycles at depth 13)
  1 schnorr_compute (SEPTIC_VERIFY)       (~780 cycles)
```

**Problem:** Merkle dominates. At 6000 orders with the same 200 unique keys,
5800 Merkle proofs are redundant — the same key is re-verified many times.

## Step 1: Dedup — One Merkle Per Unique Key

**Mode:** `BatchSepticDedup`

Group orders by `(account_address, key_index)`. Verify each unique key's
Merkle proof once, then Schnorr-verify every order using the already-validated
pubkey via `unique_keys[key_idx]`.

```
Unique keys:  N_u SparseMerkleProof::verify_existence
Orders:       N_o schnorr_compute
```

**Win:** Eliminates `(N_o - N_u)` redundant Merkle proofs. At 200 unique /
6000 orders, that's 5800 fewer Merkle verifications.

## Step 2: BatchExistenceProof — Shared Hash Caching

**Mode:** `BatchSepticDedupBatch`

Replace N_u individual `SparseMerkleProof` verifications with a single
`BatchExistenceProof::verify()` call. The batch proof caches Poseidon2
hashes at internal nodes shared by multiple key paths, avoiding
recomputation.

Requires a "bind leaves" step after verification to cross-check each
authenticated leaf against the claimed `unique_keys[i]`.

```
1 BatchExistenceProof::verify             (caches shared Poseidon2 nodes)
N_u bind-leaf assertions                  (bincode deserialize + field compare)
N_o schnorr_compute
```

**Benchmark (200 unique, 6000 orders, borsh wire format):**

| Section | Cycles |
|---------|-------:|
| borsh deserialize (implicit) | ~18M |
| dedup_batch_merkle_total | 12.0M |
| dedup_batch_schnorr_total | 4.5M |
| dedup_batch_bind_leaves | 0.5M |
| **Total** | **35.3M** |

**Bottleneck:** borsh deserialization of the ~1.2 MB witness vector dominates
at ~18M cycles (51% of total).

## Step 3: rkyv Zero-Copy Deserialization

**Mode:** `BatchSepticDedupRkyv`

Replace borsh serialization with rkyv. The host serializes the witness with
`rkyv::to_bytes()`. The guest reads the raw bytes into a buffer and calls
`rkyv::access_unchecked()` — a pointer cast that reinterprets the buffer as
an `ArchivedBatchSepticDedupBatchWitness` with zero deserialization.

The `ProgramInput` tag is still borsh-encoded (1 byte) in a first stdin chunk.
The rkyv witness bytes go in a second chunk via `write_slice()`.

```
1 read_vec()                              (buffer copy, ~342 cycles)
1 access_unchecked()                      (pointer cast, ~298 cycles)
1 ArchivedBatchExistenceProof::verify     (operates on archived data)
N_u bind-leaf (bincode deserialize leaf from archived entry.value)
N_o schnorr_compute (convert archived [u32;7] → native via to_native())
```

**Benchmark (200 unique, 6000 orders):**

| Section | Cycles |
|---------|-------:|
| rkyv_read | 342 |
| rkyv_access | 298 |
| rkyv_merkle_total | 12.0M |
| rkyv_schnorr_total | 4.7M |
| rkyv_bind_leaves | 0.5M |
| **Total** | **17.2M** |

**Win:** 2x reduction (35.3M → 17.2M). Deserialization collapses from ~18M
to ~640 cycles. Merkle is now the bottleneck (70% of total).

## Step 4: FlatBatchExistenceProof — Pre-Hashed Siblings

**Mode:** `BatchSepticDedupFlat`

The host converts `BatchExistenceProof → FlatBatchExistenceProof` via
`from_batch::<Poseidon2Hasher>()`. This pre-hashes all sibling nodes, so
each tree level costs one Poseidon2 call (combine node hash with pre-hashed
sibling) instead of two (hash sibling children, then combine).

Still uses rkyv zero-copy for the wire format.

```
1 read_vec()                              (buffer copy)
1 access_unchecked()                      (pointer cast)
1 ArchivedFlatBatchExistenceProof::verify (one Poseidon2 per level)
N_u bind-leaf
N_o schnorr_compute
```

**Benchmark (200 unique, 6000 orders):**

| Section | Cycles |
|---------|-------:|
| flat_read | 342 |
| flat_access | 298 |
| flat_merkle_total | 8.4M |
| flat_schnorr_total | 4.7M |
| flat_bind_leaves | 0.5M |
| **Total** | **13.7M** |

**Win:** 20% reduction over rkyv-only (17.2M → 13.7M). Merkle cost drops 30%
(12.0M → 8.4M). Total 2.6x reduction from the borsh baseline.

## Summary Table

| Step | Mode | Deserialize | Merkle | Schnorr | Bind | Total | vs Borsh |
|------|------|----------:|-------:|--------:|-----:|------:|---------:|
| 2 | BatchExistence + borsh | ~18M | 12.0M | 4.5M | 0.5M | 35.3M | 1.0x |
| 3 | BatchExistence + rkyv | 342 | 12.0M | 4.7M | 0.5M | 17.2M | 2.1x |
| 4 | **FlatBatch + rkyv** | **342** | **8.4M** | **4.7M** | **0.5M** | **13.7M** | **2.6x** |

## Cycle Budget Breakdown (Recommended Path)

At 200 unique keys / 6000 orders:

```
Merkle (flat):  8.4M  (61.5%)  ← JMT depth ~13, 200 paths, pre-hashed siblings
Schnorr:        4.7M  (34.2%)  ← 6000 SEPTIC_VERIFY syscalls
Bind leaves:    0.5M  ( 3.9%)  ← 200 bincode deserializes + field asserts
Deserialize:    ~640  ( 0.0%)  ← rkyv zero-copy (read_vec + pointer cast)
Overhead:       ~0.1M ( 0.4%)  ← dispatch, commit, etc.
```

Schnorr is fixed at ~780 cycles/order regardless of batch strategy. Further
Merkle wins require either shallower trees or cheaper hash functions.

## Per-Order Cost

| Component | Cycles/order (amortized) |
|-----------|-------------------------:|
| Merkle | 1,400 (8.4M / 6000) |
| Schnorr | 778 (4.7M / 6000) |
| Bind | 83 (0.5M / 6000) |
| **Total** | **~2,261** |

These amortized costs assume 200 unique keys across 6000 orders. More key
reuse (fewer unique keys) reduces the Merkle amortization further.
