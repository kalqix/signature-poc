# Architecture

## Overview

One SP1 guest program (`program/src/main.rs`) handles all transaction types.
The host (backend) builds a witness, serializes it to SP1 stdin, and the guest
verifies cryptographic proofs inside the zkVM. A single ELF binary and proving
key covers every code path.

```
                  ┌──────────────────────────────────────┐
                  │           SP1 Guest Program           │
                  │                                       │
  SP1 stdin ────► │  borsh tag → dispatch → handler       │
  (borsh or       │  [optional] rkyv witness → zero-copy  │
   rkyv bytes)    │  verify Merkle + Schnorr              │
                  │  commit_slice(ProofOutput)             │
                  └──────────────────────────────────────┘
```

## ProgramInput Dispatch

The guest reads a borsh-encoded `ProgramInput` enum from the first stdin chunk.
Most variants carry their witness inline. Two unit variants (`BatchSepticDedupRkyv`,
`BatchSepticDedupFlat`) read an additional rkyv-encoded witness from a second
stdin chunk and access it zero-copy.

```rust
pub enum ProgramInput {
    // ── Production paths ────────────────────────────────
    RegisterKey(RegisterKeyWitness),
    VerifyOrder(OrderWitness),

    // ── Benchmark-only ──────────────────────────────────
    VerifyOrderEth(EthOrderWitness),
    VerifyOrderSeptic(VerifyOrderSepticWitness),

    // ── Batch (no Merkle) ───────────────────────────────
    BatchSeptic(BatchSepticWitness),
    BatchSepticOpt(BatchSepticOptWitness),
    BatchSepticSingle(BatchSepticSingleWitness),
    BatchSepticOptSingle(BatchSepticOptWitness),
    BatchSepticVerify(BatchSepticVerifyWitness),
    BatchSepticVerifyMerkle(BatchSepticVerifyMerkleWitness),

    // ── Dedup batch (one Merkle per unique key) ─────────
    BatchSepticDedup(BatchSepticDedupWitness),
    BatchSepticDedupBatch(BatchSepticDedupBatchWitness),
    BatchSepticDedupRkyv,   // unit — rkyv witness in next read_vec()
    BatchSepticDedupFlat,   // unit — rkyv flat witness in next read_vec()

    BatchEth(BatchEthWitness),
}
```

## Guest Handlers

Each handler follows the same pattern:
1. Read/deserialize witness
2. Verify Merkle proof(s) against the session key root
3. Verify cryptographic signature(s)
4. Commit a `ProofOutput` to public values

### RegisterKey

```
jmt_verify_old   → SparseMerkleProof::verify (non-existence or existence)
eip191_recover   → secp256k1 ecrecover of EIP-191 signature
```

Verifies that the caller's ETH wallet authorized the session key registration.
The old proof is non-existence for fresh slots, existence for key rotation.
The new root is host-computed and trusted (POC limitation — production should
verify an `UpdateMerkleProof`).

### VerifyOrder (production path)

```
jmt_verify       → SparseMerkleProof::verify_existence
schnorr_verify   → sp1_lib::septic::schnorr_compute (SEPTIC_VERIFY precompile)
```

Reconstructs the session key leaf, verifies JMT inclusion, then verifies the
Schnorr signature via SP1's SEPTIC_VERIFY precompile (Shamir's trick in one
syscall). This is the single-order production path.

### Batch Dedup — Flat + rkyv (recommended production batch path)

```
flat_read         → sp1_zkvm::io::read_vec()
flat_access       → rkyv::access_unchecked (pointer cast, zero-copy)
flat_merkle_total → ArchivedFlatBatchExistenceProof::verify::<Poseidon2Hasher>
flat_bind_leaves  → cross-check leaf bytes against unique_keys[i]
flat_schnorr_total→ per-order schnorr_compute
```

The host converts `BatchExistenceProof → FlatBatchExistenceProof` via
`from_batch()`, pre-hashing all sibling nodes. The guest verifies with one
Poseidon2 call per tree level instead of two. Combined with rkyv zero-copy
deserialization, this is the lowest-cost batch path.

## Witness Types

### Session Key Types

| Type | Fields | Usage |
|------|--------|-------|
| `SessionKey` | pubkey_x/y `[u32;7]`, key_index `u8` | Public key + slot |
| `SessionKeyLeaf` | account_address `[u8;20]`, key_index, pubkey_x/y | JMT leaf value |

The leaf is serialized with `bincode` and stored as the JMT value. The key
hash is `Poseidon2(address ∥ key_index)`.

### Order Types

| Type | Fields | Serialization |
|------|--------|---------------|
| `SignedOrder` | address, key_index, market/side, price/quantity, r_x/y, s, e | borsh + serde |
| `DedupOrder` | key_idx `u32`, market/side, price/quantity, r_x/y, s, e | borsh + serde + **rkyv** |
| `UniqueKeyInfo` | address, key_index, pubkey_x/y | borsh + serde + **rkyv** |

`DedupOrder` and `UniqueKeyInfo` have rkyv derives because they appear inside
the rkyv-serialized batch witnesses.

### Batch Witness Hierarchy

```
Per-order Merkle:
  BatchSepticVerifyMerkleWitness
    └── Vec<SepticMerkleOrder>  (each has its own SparseMerkleProof)

Dedup (one Merkle per unique key):
  BatchSepticDedupWitness
    ├── Vec<DedupKey>           (each has its own SparseMerkleProof)
    └── Vec<DedupOrder>         (key_idx indexes into DedupKey)

  BatchSepticDedupBatchWitness
    ├── BatchExistenceProof     (single proof, all unique keys)
    ├── Vec<UniqueKeyInfo>      (pubkey only, no per-key proof)
    └── Vec<DedupOrder>

  BatchSepticDedupFlatWitness
    ├── FlatBatchExistenceProof (pre-hashed siblings)
    ├── Vec<UniqueKeyInfo>
    └── Vec<DedupOrder>
```

## Public Output

Every handler commits a `ProofOutput`:

```rust
pub struct ProofOutput {
    pub old_session_key_root: [u8; 32],
    pub new_session_key_root: [u8; 32],
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub proof_type: String,
}
```

For batch modes, `account_address` and `key_index` are zeroed. The
`proof_type` string encodes the mode and batch dimensions (e.g.,
`BATCH_DEDUP_FLAT_200u_6000o`).
