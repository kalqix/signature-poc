# Production Migration Guide

How to apply POC findings to kalqix-zk-service.

## File Mapping

| POC | kalqix-zk-service | Notes |
|-----|-------------------|-------|
| `program/src/main.rs` | `program/range/src/main.rs` | Guest program entry point |
| `shared/src/lib.rs` (session types) | `shared/src/models/session_key.rs` | `SessionKeyLeaf`, `UniqueKeyInfo`, `DedupOrder`, `BatchSepticDedupFlatWitness` |
| `shared/src/poseidon2_hasher.rs` | `shared/src/jmt_hasher.rs` | `Poseidon2Hasher` implementing `jmt::SimpleHasher` |
| `backend/src/state.rs` (JMT) | `host/src/state/session_key_store.rs` | Replace `MockTreeStore` with RocksDB `TreeReader`/`TreeWriter` |
| `backend/src/witness.rs` | `host/src/proposer.rs` | Witness builder |
| `backend/src/bin/profile.rs` | (not migrated) | Profiling-only |

## What to Migrate

### 1. Poseidon2Hasher

Copy `shared/src/poseidon2_hasher.rs` as-is. The host/guest dispatch via
`cfg(target_os = "zkvm")` works in any SP1 project. The critical constraint:

> Host and guest must produce byte-identical Poseidon2 output.
> Run `test_poseidon2_host_vs_guest_sponge` after any change.

Dependencies:
- Guest: `sp1-zkvm` (Poseidon2ByteHash precompile)
- Host: `sp1-primitives` + `p3-field` + `p3-symmetric`

### 2. Session Key Types

Migrate these types with their derives:

```rust
// Core types (borsh + serde)
SessionKey, SessionKeyLeaf, RegisterKeyWitness, RegisterKeyRequest

// Batch types (borsh + serde + rkyv)
UniqueKeyInfo, DedupOrder

// Flat batch witness (serde + rkyv only, no borsh)
BatchSepticDedupFlatWitness
```

Also migrate the helper functions:
- `session_key_hash()` — JMT key derivation
- `encode_session_key_leaf()` — JMT value encoding

### 3. Guest Handler — Batch Dedup Flat

Port `handle_batch_septic_dedup_flat()` from `program/src/main.rs`. Key
pattern:

```rust
fn handle_batch_dedup_flat() {
    // 1. Read rkyv bytes (second stdin chunk)
    let bytes = sp1_zkvm::io::read_vec();

    // 2. Zero-copy access
    let archived = unsafe {
        rkyv::access_unchecked::<ArchivedBatchSepticDedupFlatWitness>(&bytes)
    };

    // 3. Verify flat Merkle proof
    archived.flat_proof
        .verify::<Poseidon2Hasher>(&archived.session_key_root);

    // 4. Bind leaves (critical for soundness)
    for (i, entry) in archived.flat_proof.entries.iter().enumerate() {
        let leaf: SessionKeyLeaf = bincode::deserialize(entry.value.as_slice())?;
        // assert leaf fields match unique_keys[i]
        // assert entry.key_hash matches session_key_hash(address, key_index)
    }

    // 5. Per-order Schnorr verify
    for order in archived.orders.iter() {
        let key = &archived.unique_keys[order.key_idx.to_native() as usize];
        // schnorr_compute(pubkey, s, e) == (r_x, r_y)
    }
}
```

### 4. Host Witness Builder

Port the witness construction pattern from `build_batch_septic_dedup_flat_witness()`:

```rust
fn build_flat_witness(/* ... */) -> BatchSepticDedupFlatWitness {
    // 1. Build individual proofs for each unique key
    let proof_entries = unique_keys.iter().map(|key| {
        let key_hash = KeyHash(session_key_hash(&key.address, key.key_index));
        let (value, proof) = tree.get_with_proof(key_hash, version)?;
        (key_hash, value.unwrap(), proof)
    }).collect();

    // 2. Fold into BatchExistenceProof
    let batch_proof = build_batch_existence_proof(proof_entries);

    // 3. Convert to FlatBatchExistenceProof (pre-hash siblings on host)
    let flat_proof = FlatBatchExistenceProof::from_batch::<Poseidon2Hasher>(&batch_proof);

    BatchSepticDedupFlatWitness {
        session_key_root: root.0,
        flat_proof,
        unique_keys: key_infos,
        orders,
    }
}
```

### 5. Host Stdin Writing

Use the two-chunk pattern:

```rust
let tag_bytes = borsh::to_vec(&ProgramInput::BatchSepticDedupFlat)?;
let rkyv_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&witness)?;

let mut stdin = SP1Stdin::new();
stdin.write_vec(tag_bytes);
stdin.write_slice(rkyv_bytes.as_ref());
```

## What NOT to Migrate

| POC Component | Reason |
|---------------|--------|
| Frontend (`frontend/`) | kalqix-zk-service has no frontend |
| `/place-order-eth` route | Benchmark-only (secp256k1 comparison) |
| In-memory `AppState` | Production uses RocksDB |
| `MockTreeStore` | Replace with RocksDB `TreeReader`/`TreeWriter` |
| Mock prover | Production uses real SP1 GPU prover |
| All non-flat batch modes | Superseded by flat+rkyv path |
| `profile.rs` bench harness | POC-specific profiling |

## JMT Storage Swap

The POC uses `jmt::mock::MockTreeStore`. Production should implement:

```rust
// These traits are already defined in the jmt crate
impl TreeReader for RocksDbStore { /* ... */ }
impl TreeWriter for RocksDbStore { /* ... */ }
```

Everything else — `JellyfishMerkleTree::new(&store)`, `put_value_set()`,
`get_with_proof()`, `build_batch_existence_proof()` — works unchanged.
The witness types (`SparseMerkleProof<Poseidon2Hasher>`,
`FlatBatchExistenceProof`) are storage-agnostic.

## Dependency Versions

```toml
# Shared crate
jmt = { git = "https://github.com/kalqix/jmt", rev = "4bd0faa...", features = ["std", "sha2"] }
rkyv = { version = "0.8", default-features = false, features = ["alloc", "bytecheck"] }
borsh = { version = "1.3", features = ["derive"] }

# Host crate (needs mocks feature for tests only)
jmt = { ..., features = ["std", "sha2", "mocks"] }
rkyv = { version = "0.8", features = ["alloc", "bytecheck"] }

# Guest crate
jmt = { ..., features = ["std", "sha2"] }
rkyv = { version = "0.8", default-features = false, features = ["alloc", "bytecheck"] }
```

## Security Checklist

Before deploying the batch path:

- [ ] `test_poseidon2_host_vs_guest_sponge` passes (host/guest hash alignment)
- [ ] `test_poseidon2_parameters` passes (sponge parameters match SP1)
- [ ] Bind-leaves step is present and checks all four fields + key_hash
- [ ] `access_unchecked` is only used inside the guest (not on untrusted host input)
- [ ] `unique_keys.len() == flat_proof.entries.len()` assertion is present
- [ ] `order.key_idx < unique_keys.len()` bounds are checked
- [ ] ELF is rebuilt after any change to `shared/` or `program/`
- [ ] ProofOutput includes batch dimensions in `proof_type` for auditability

## Expected Cycle Costs in Production

At 200 unique keys / 6000 orders (depth ~13):

| Component | Cycles | % |
|-----------|-------:|--:|
| Merkle (flat) | 8.4M | 61% |
| Schnorr | 4.7M | 34% |
| Bind leaves | 0.5M | 4% |
| Overhead | 0.1M | 1% |
| **Total** | **13.7M** | |

Per-order amortized cost: ~2,261 cycles. Scaling is linear in order count
with sub-linear Merkle growth (shared paths in the JMT).
