# Wire Format

## Overview

The SP1 guest reads witness data from stdin via `sp1_zkvm::io::read_vec()`.
The POC uses two serialization strategies:

| Strategy | Modes | Serialization cost | Wire size |
|----------|-------|-------------------|-----------|
| **Borsh** | All data-carrying `ProgramInput` variants | ~18M cycles (1.2 MB payload) | Compact |
| **rkyv zero-copy** | `BatchSepticDedupRkyv`, `BatchSepticDedupFlat` | ~640 cycles | ~10% larger |

## Borsh Path (Single Chunk)

Used by all modes except the two rkyv unit variants.

### Host

```rust
let input_bytes = borsh::to_vec(&ProgramInput::SomeVariant(witness))?;
let mut stdin = SP1Stdin::new();
stdin.write_vec(input_bytes);
```

### Guest

```rust
let raw = sp1_zkvm::io::read_vec();
let input: ProgramInput = borsh::from_slice(&raw)?;
match input {
    ProgramInput::SomeVariant(w) => handle(w),
    // ...
}
```

### Cost

Borsh deserialization is the dominant cost for large witnesses. At ~1.2 MB
(6000 orders), borsh consumes ~18M cycles — more than the Merkle and Schnorr
verification combined. This motivated the rkyv migration.

## rkyv Zero-Copy Path (Two Chunks)

Used by `BatchSepticDedupRkyv` and `BatchSepticDedupFlat`.

### Host

```rust
// Chunk 1: borsh-encoded unit variant tag (1 byte)
let tag_bytes = borsh::to_vec(&ProgramInput::BatchSepticDedupFlat)?;

// Chunk 2: rkyv-encoded witness (raw bytes)
let rkyv_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&witness)?;

let mut stdin = SP1Stdin::new();
stdin.write_vec(tag_bytes);        // first read_vec() in guest
stdin.write_slice(rkyv_bytes.as_ref());  // second read_vec() in guest
```

Note: `write_vec` for the tag (includes length prefix) and `write_slice` for
the rkyv bytes (also includes length prefix internally).

### Guest

```rust
// 1. Read borsh tag and dispatch
let raw = sp1_zkvm::io::read_vec();
let input: ProgramInput = borsh::from_slice(&raw)?;

match input {
    ProgramInput::BatchSepticDedupFlat => {
        // 2. Read rkyv witness bytes
        let bytes: Vec<u8> = sp1_zkvm::io::read_vec();

        // 3. Zero-copy access (pointer cast, no validation)
        let archived = unsafe {
            rkyv::access_unchecked::<ArchivedBatchSepticDedupFlatWitness>(&bytes)
        };

        // 4. Operate directly on archived data
        archived.flat_proof.verify::<Poseidon2Hasher>(&archived.session_key_root);
    }
    // ...
}
```

### Why `access_unchecked`

`rkyv::access_unchecked` is a pointer cast — it does NOT validate the
archive. This is safe in the ZK context because:

1. The guest trusts the host to encode correctly (same trust model as borsh).
2. Any data tampering produces a Merkle verification failure.
3. The proof is only valid if all assertions pass; invalid data cannot produce
   a valid proof.

Checked access (`rkyv::access`) adds validation cycles that provide no
security benefit inside the zkVM.

### Cost

| Operation | Cycles |
|-----------|-------:|
| `read_vec()` (buffer copy, ~1.1 MB) | 342 |
| `access_unchecked()` (pointer cast) | 298 |
| **Total deserialization** | **640** |

Compare: borsh deserialization of the same payload costs ~18M cycles.

## Archived Type Conversion

rkyv archives store integers in little-endian format via `rend` wrappers
(e.g., `rend::u32_le`). When passing archived fields to SP1 syscalls that
expect native `[u32; N]`, convert explicitly:

```rust
#[inline(always)]
fn archived_array7_to_native(arr: &rkyv::Archived<[u32; 7]>) -> [u32; 7] {
    [
        arr[0].to_native(), arr[1].to_native(), arr[2].to_native(),
        arr[3].to_native(), arr[4].to_native(), arr[5].to_native(),
        arr[6].to_native(),
    ]
}
```

On little-endian targets (including RISC-V), `to_native()` is a no-op. The
compiler optimizes it away entirely.

## rkyv Derive Requirements

Types that appear inside an rkyv-serialized witness need:

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
```

For types with complex generics (like `FlatBatchExistenceProof`), the JMT
fork already provides these derives. For custom types, explicit bounds may
be needed:

```rust
#[rkyv(
    serialize(bound(
        __S: rkyv::ser::Writer + rkyv::ser::Allocator,
        __S::Error: rkyv::rancor::Source,
    )),
    deserialize(bound(
        __D: rkyv::de::Pooling,
        __D::Error: rkyv::rancor::Source,
    )),
)]
```

## Witness Size Comparison

At 200 unique keys / 6000 orders:

| Format | Size |
|--------|-----:|
| Borsh (BatchExistence) | 1,174,262 bytes |
| rkyv (BatchExistence) | 1,195,688 bytes |
| rkyv (FlatBatch) | 1,090,176 bytes |

The flat proof is actually smaller than the non-flat rkyv witness because
pre-hashed siblings are 32-byte hashes instead of full subtree structures.

## Production Recommendation

Use the two-chunk rkyv pattern for all batch witnesses:

1. First chunk: borsh-encoded unit variant tag (tiny, used for dispatch only).
2. Second chunk: rkyv-encoded witness (zero-copy access in guest).

This eliminates deserialization as a bottleneck entirely. The only cost is
the buffer copy for `read_vec()`, which scales linearly with witness size
at negligible per-byte cost.
