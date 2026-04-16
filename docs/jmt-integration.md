# JMT Integration

## Jellyfish Merkle Tree Fork

The POC uses a Kalqix fork of the JMT crate:

```toml
jmt = { git = "https://github.com/kalqix/jmt",
        rev = "4bd0faa76480419b0eda86e13b0d61e27d495f40" }
```

The fork adds:
- **`BatchExistenceProof`** — single proof covering multiple leaves with
  shared-hash caching at common internal nodes.
- **`FlatBatchExistenceProof`** — pre-hashed siblings so each tree level
  costs one Poseidon2 call instead of two.
- **rkyv derives** on all proof types (`Archive`, `Serialize`, `Deserialize`),
  enabling zero-copy deserialization in the guest.

## Poseidon2Hasher

`shared/src/poseidon2_hasher.rs` implements `jmt::SimpleHasher` and is used
for all JMT hashing — both leaf value hashing and internal node hashing.

```rust
pub struct Poseidon2Hasher { buffer: Vec<u8> }

impl jmt::SimpleHasher for Poseidon2Hasher {
    fn new()                        -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self)               -> [u8; 32];
}
```

### Host vs Guest Dispatch

The hasher dispatches on `cfg(target_os = "zkvm")`:

| | Host | Guest |
|---|------|-------|
| Implementation | `sp1_primitives::poseidon2_init` + length-prefixed sponge | `sp1_zkvm::syscalls::Poseidon2ByteHash` precompile |
| Sponge rate | 8 field elements (24 bytes per block) | Handled by precompile |
| Length prefix | First block = `input.len()` as LE bytes | Handled by precompile |

**Both paths must produce byte-identical output.** The alignment test
`test_poseidon2_host_vs_guest_sponge` verifies this. If it fails, every JMT
proof will silently fail in the guest (UnexpectedEof or root mismatch).

### Host Sponge Detail

```
Block layout:  [rate=8 elements] [capacity=8 elements]  (width=16)
Byte block:    24 bytes (8 elements * 3 bytes each, masked to 2^24-1)

1. First block: input.len() as little-endian, padded to 24 bytes
2. Subsequent blocks: 24-byte chunks of input, zero-padded
3. Each block: absorb into state[0..8], then permute
4. Output: state[0..8] as 32 bytes (4 LE bytes per element)
```

## Proof Types

### SparseMerkleProof (per-key)

Standard JMT inclusion/non-inclusion proof. Used for:
- `RegisterKeyWitness.old_proof` — non-existence (fresh) or existence (rotation)
- `OrderWitness.merkle_proof` — single-order existence
- `DedupKey.merkle_proof` — per-unique-key in the non-batch dedup path

Guest verification:
```rust
proof.verify_existence(RootHash(root), key_hash, &leaf_value)
proof.verify(RootHash(root), key_hash, value_opt)  // non-existence if None
```

### BatchExistenceProof (batch)

Single proof covering N leaves. Verifies all in one pass, caching Poseidon2
hashes at shared internal nodes to avoid recomputation.

```rust
// Host: build from individual proofs
let batch_proof = build_batch_existence_proof(proof_entries);

// Guest: one verify call
batch_proof.verify(RootHash(root))?;
```

Each entry carries:
- `key_hash: KeyHash` — the JMT key
- `value: Vec<u8>` — the leaf value (bincode-encoded `SessionKeyLeaf`)
- Sibling hashes along the path

**Cycle cost at 200 keys, depth ~13:** 12.0M cycles.

### FlatBatchExistenceProof (flat batch)

Derived from `BatchExistenceProof` by pre-hashing all sibling nodes on the
host. The guest only computes one Poseidon2 per tree level (combining the
node's own hash with the pre-hashed sibling) instead of two (hashing the
sibling from raw children, then combining).

```rust
// Host: convert from batch proof
let flat = FlatBatchExistenceProof::from_batch::<Poseidon2Hasher>(&batch_proof);

// Guest: verify with hasher type parameter
flat.verify::<Poseidon2Hasher>(&root_bytes)
```

The flat proof type has no hasher generic at the type level — the hasher is
only needed at verification time. This simplifies rkyv serialization.

**Cycle cost at 200 keys, depth ~13:** 8.4M cycles (30% reduction).

## Key Hashing

Session key slots are addressed by `Poseidon2(address ∥ key_index)`:

```rust
pub fn session_key_hash(address: &[u8; 20], key_index: u8) -> [u8; 32] {
    let mut input = [0u8; 21];
    input[..20].copy_from_slice(address);
    input[20] = key_index;
    poseidon2_hash_bytes(&input)
}
```

This is identical on host and guest, producing the same `KeyHash` for JMT
lookups and proof verification.

## Leaf Encoding

Leaves are bincode-encoded `SessionKeyLeaf` structs:

```rust
pub fn encode_session_key_leaf(leaf: &SessionKeyLeaf) -> Vec<u8> {
    bincode::serialize(leaf).expect("bincode serialize")
}
```

The JMT stores these bytes as the value at each key hash. During batch
verification, the guest deserializes each entry's value back to
`SessionKeyLeaf` to cross-check against `unique_keys[i]` ("bind leaves").

## Bind-Leaves Security

After batch proof verification, the guest must bind each authenticated leaf
to the claimed `unique_keys[i]`. Without this step, a malicious host could
pair one key's Merkle proof with a different key's pubkey:

```rust
for (i, entry) in proof.entries.iter().enumerate() {
    let leaf: SessionKeyLeaf = bincode::deserialize(&entry.value)?;
    let key_info = &unique_keys[i];
    assert_eq!(leaf.account_address, key_info.account_address);
    assert_eq!(leaf.key_index,       key_info.key_index);
    assert_eq!(leaf.pubkey_x,        key_info.pubkey_x);
    assert_eq!(leaf.pubkey_y,        key_info.pubkey_y);

    let expected = session_key_hash(&key_info.account_address, key_info.key_index);
    assert_eq!(entry.key_hash.0, expected);
}
```

This is cheap (~0.5M cycles for 200 keys) and critical for soundness.

## Production Notes

- The POC uses `jmt::mock::MockTreeStore` (in-memory). Production should use
  the RocksDB-backed `TreeReader`/`TreeWriter`.
- Witness types (`SparseMerkleProof<Poseidon2Hasher>`, `BatchExistenceProof`,
  `FlatBatchExistenceProof`) and guest verify paths are unchanged between
  mock and production storage.
- The `build_batch_existence_proof()` helper takes individual per-key proofs
  and folds them into a single batch proof. Production's proposer should call
  this after fetching proofs from RocksDB.
