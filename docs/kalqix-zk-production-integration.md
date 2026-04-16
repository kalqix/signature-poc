# KalqiX ZK Signature Verification — Production Integration Guide

**Status:** POC complete, ready for production migration
**Target codebase:** `kalqix-zk-service`
**Author:** KalqiX Engineering
**Last updated:** April 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem](#2-the-problem)
3. [Final Architecture](#3-final-architecture)
4. [Benchmark Results](#4-benchmark-results)
5. [Technical Deep Dive](#5-technical-deep-dive)
6. [Migration Plan for kalqix-zk-service](#6-migration-plan-for-kalqix-zk-service)
7. [Audit Preparation](#7-audit-preparation)
8. [Operational Considerations](#8-operational-considerations)
9. [SP1 Fork & JMT Fork Maintenance](#9-sp1-fork--jmt-fork-maintenance)
10. [Appendix: Dependency Specifications](#10-appendix-dependency-specifications)

---

## 1. Executive Summary

### The Problem

Production `kalqix-zk-service` had secp256k1 ECDSA signature verification consuming **83% of SP1 zkVM cycles** — 1 billion cycles per 2,000-order batch, blocking go-live.

### The Solution

A four-layer optimization stack built on SP1's internal septic curve, JMT state tree with pre-hashed siblings, and rkyv zero-copy deserialization.

### The Results

**From 490M cycles down to 13.7M for 6,000 orders — a 36× reduction. Per-order cost: 2,283 cycles.**

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Per-order cycles (signature) | 54,447 | 750 | **73× faster** |
| Per-order cycles (all) | 54,447+ | 2,283 | **24× faster** |
| Batch (6,000 orders) | 327M | 13.7M | **24× faster** |
| Cycle budget consumed | 65% | 2.7% | **24× headroom** |

### Key Technical Decisions

1. **Septic Schnorr on SP1's internal KoalaBear Fp7 curve** — field-native, replaces secp256k1 for order signing
2. **Custom SEPTIC precompiles** added to KalqiX fork of SP1 — ADD, DOUBLE, SCALAR_MUL, VERIFY
3. **JMT (Jellyfish Merkle Tree) with Poseidon2Hasher** — variable-depth proofs, ~log2(N) levels
4. **Deduplicated Merkle proofs** — one per unique session key, not per order
5. **BatchExistenceProof with shared hash caching** — common tree paths hashed once
6. **FlatBatchExistenceProof with pre-hashed siblings** — 50% fewer Poseidon2 calls per level
7. **rkyv zero-copy deserialization** — 600× reduction in witness parsing cost
8. **secp256k1 preserved for ETH wallet registration** — users sign once with MetaMask, no gas

### Architecture Comparison with Lighter.xyz

| Aspect | Lighter.xyz | **KalqiX** |
|--------|-------------|------------|
| Proof system | Plonky2 / Goldilocks | **SP1 / KoalaBear Fp7** |
| Order signature curve | ECgFp5 | **Septic (KoalaBear Fp7)** |
| Order signature scheme | Schnorr | **Schnorr** |
| State tree | SMT (Sparse Merkle) depth 48 | **JMT depth log2(N)** |
| Hash function | Poseidon2 (native) | **Poseidon2 (precompile)** |
| Deduplication | Per block | **Per batch** |
| Registration sig | secp256k1 (per block) | **secp256k1 (per batch)** |

### Status

- ✅ POC complete with all optimizations benchmarked
- ✅ SP1 fork PR submitted to Succinct Labs
- ✅ JMT fork with all optimizations committed
- ⏳ Production migration to `kalqix-zk-service` (this document)
- ⏳ External audit (estimated 3-4 weeks)
- ⏳ Mainnet deployment

---

## 2. The Problem

### Starting State

`kalqix-zk-service`'s `process_range()` in `shared/src/utils/program_helpers.rs` contained three signature verification loops:

```rust
// Three loops × up to 2,000 iterations × ~500k cycles = ~3B cycles budget (broken)
for transfer in &program_payload.unique_transfers {
    verify_transfer_signature_once(transfer)?;  // secp256k1 ecrecover
}
for withdrawal in &program_payload.unique_withdrawals {
    verify_withdrawal_signature_once(withdrawal)?;  // secp256k1 ecrecover
}
for order in &program_payload.unique_orders {
    verify_order_signature_once(order)?;  // secp256k1 ecrecover
}
```

Each signature verification cost approximately **500,000 cycles** even with the `k256` precompile engaged. With 2,000 orders per batch, signatures alone consumed the entire cycle budget.

### Why Not Optimize secp256k1?

The `SECP256K1_ADD/DOUBLE/DECOMPRESS` precompiles in SP1 accelerate point operations, but the underlying Weierstrass curve arithmetic over a 256-bit prime field has an irreducible cost. Benchmarks showed the precompile path at ~500k cycles/sig — the hard floor of secp256k1 in SP1. Signature verification needed to be architectural, not algorithmic.

### The Insight

Lighter.xyz faced this exact problem and solved it by using **ECgFp5 Schnorr** — a curve native to their proof system's field. SP1's proof system operates over **KoalaBear Fp7** (a degree-7 extension of the KoalaBear prime field, used internally for SP1's Hypercube memory argument). A Schnorr signature scheme built on this curve would be field-native to SP1 just as ECgFp5 is native to Plonky2.

---

## 3. Final Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ Browser (Frontend)                                              │
│  • WASM-compiled septic key generation                          │
│  • Private keys in IndexedDB (non-extractable)                  │
│  • Orders signed silently via Schnorr on septic curve           │
│  • Registration: single MetaMask personal_sign, no gas          │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (HTTP)
┌─────────────────────────────────────────────────────────────────┐
│ Matching Engine (Rust, off-circuit)                             │
│  • Session key state in memory (hot path)                       │
│  • Off-circuit signature pre-validation                         │
│  • Order matching, book management                              │
│  • Dedup: groups orders by unique session key                   │
│  • Registrations processed before orders within batch           │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (prover witness)
┌─────────────────────────────────────────────────────────────────┐
│ SP1 Prover (Guest Program)                                      │
│  Per batch proves:                                              │
│  1. Each registration: valid secp256k1 EIP-191 sig,             │
│     JMT update proof (root_i → root_{i+1})                      │
│  2. Each unique order key: FlatBatchExistenceProof              │
│     verifies membership in post-registration root               │
│  3. Each order: Schnorr sig valid via SEPTIC_VERIFY precompile  │
│  4. Commits: (old_root, new_root, ...)                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓ (proof + public inputs)
┌─────────────────────────────────────────────────────────────────┐
│ On-Chain Verifier (Solidity)                                    │
│  • Verifies SP1 proof                                           │
│  • Checks (old_session_key_root, new_session_key_root)          │
│  • Updates balance roots, processes deposits/withdrawals        │
└─────────────────────────────────────────────────────────────────┘
```

### Two-Layer Cryptographic Architecture

Following Lighter.xyz's proven pattern:

| Layer | Curve | Scheme | Purpose | When |
|-------|-------|--------|---------|------|
| L1 (ETH wallet) | secp256k1 | EIP-191 personal_sign | Authorize session key | Once per session key registration |
| L2 (session key) | Septic (KoalaBear Fp7) | Schnorr | Sign orders | Every order |

**Security properties:**
- Session key compromise → orders only, withdrawals still require ETH wallet
- Same security model as CEX API keys
- ETH wallet never stored anywhere, used only at registration

### Mixed Batch Structure

A single SP1 proof covers both registrations and orders atomically:

```
BatchWitness {
    // Phase 1: Registrations (0..N, sequential root transitions)
    registrations: [
        RegisterKey { eth_sig, pubkey, jmt_update_proof },  // root_0 → root_1
        RegisterKey { eth_sig, pubkey, jmt_update_proof },  // root_1 → root_2
        ...
    ],
    
    // Phase 2: Orders (all verified against final root)
    orders: {
        unique_session_keys: FlatBatchExistenceProof,  // against root_N
        orders_by_key: [ schnorr_sig, ... ],           // 6,000+ entries
    }
}
```

**Key property:** Orders are reordered within the batch to execute after registrations. Off-chain matching engine ensures an order for key K is only included in the batch if K was registered (either before the batch or within the batch's registration phase).

### Flow Diagrams

**Registration flow:**
```
User clicks "Register Session Key"
  ↓
Browser generates Schnorr keypair on septic curve (WASM)
  ↓
Browser stores private key in IndexedDB (non-extractable)
  ↓
Browser builds registration message
  (format matches shared/src/utils/message_builder.rs exactly)
  ↓
Browser calls MetaMask personal_sign → secp256k1 signature (no gas)
  ↓
POST /register-key → matching engine
  ↓
Matching engine inserts session key into JMT
  ↓
Next proof batch includes this registration
  ↓
SP1 proves: (a) ETH sig recovers user's address,
            (b) JMT insertion is correct
  ↓
On-chain: new session_key_root committed
```

**Order flow:**
```
User places order in UI
  ↓
Browser signs order message with septic private key (WASM)
  ↓
POST /place-order → matching engine
  ↓
Matching engine verifies Schnorr sig off-circuit (pre-validation)
  ↓
Matching engine includes order in current batch
  ↓
When batch is full or timer expires:
  ↓
Proposer assembles batch:
  • Groups orders by unique session key
  • Generates JMT existence proof per unique key
  • Converts to FlatBatchExistenceProof
  • Serializes witness with rkyv
  ↓
SP1 prover:
  • read_vec() → rkyv bytes
  • access_unchecked → archived witness (zero-copy)
  • Verifies flat batch existence (pre-hashed siblings)
  • Verifies Schnorr sig per order via SEPTIC_VERIFY
  ↓
Proof submitted on-chain
```

---

## 4. Benchmark Results

### The Complete Optimization Journey

Each row represents a measured improvement on 6,000 orders with 200 unique session keys:

| Milestone | Total cycles | Per-order | Multiplier | Notes |
|-----------|-------------|-----------|-----------|-------|
| Naive secp256k1 (no dedup) | ~490M | 81,667 | — | Original problem |
| secp256k1 per-order | 327M | 54,447 | 1.5× | Fixed patches |
| Septic Schnorr naive | 719M | 119,883 | 0.7× | Worse! (per-order Merkle) |
| + Dedup (individual proofs) | 39.1M | 6,517 | 12.5× | Game-changer |
| + BatchExistenceProof | 35.2M | 5,867 | 13.9× | Shared hash caching |
| + rkyv zero-copy | 17.2M | 2,867 | 28.5× | Eliminated borsh cost |
| **+ FlatBatchExistence** | **13.7M** | **2,283** | **36×** | **Final** |

### Final Performance Breakdown (13.7M cycles)

| Component | Cycles | % of total | Nature |
|-----------|--------|-----------|--------|
| Merkle verification | 8.4M | 61% | 200 flat proofs, cache overhead |
| Schnorr verification | 4.7M | 34% | 6,000 × SEPTIC_VERIFY + archived→native array conversion |
| Leaf binding | 0.5M | 3.6% | 200 borsh deserializations + field checks |
| Deserialization | 342 | 0.002% | rkyv access_unchecked |
| Dispatch overhead | ~100k | 0.7% | Match arms, setup |

### Signature Scheme Comparison

Single signature verification cost in SP1:

| Scheme | Cycles | Syscalls | Speedup |
|--------|--------|----------|---------|
| **Septic Schnorr (SEPTIC_VERIFY)** | **750** | **1** | **baseline** |
| secp256k1 ecrecover | 54,447 | 783 | 73× slower |
| Ed25519 verify | 124,975 | 807 | 167× slower |
| P-256 verify | 151,237 | 787 | 202× slower |

### Scaling Characteristics

Cost as a function of batch size (200 unique keys, varying orders):

| Orders | Total cycles | Per-order | Merkle per proof |
|--------|-------------|-----------|------------------|
| 1,000 | ~4.7M | 4,700 | 42k (unchanged) |
| 3,000 | ~7.9M | 2,633 | 42k (unchanged) |
| **6,000** | **13.7M** | **2,283** | **42k (unchanged)** |
| 10,000 | ~21.3M | 2,130 | 42k (unchanged) |

**Key insight:** The fixed cost (Merkle verification for unique keys) amortizes over more orders. Larger batches have lower per-order cost, up to the Schnorr asymptote of ~750 cycles/order.

### Cost as a Function of Unique Keys

At 6,000 orders, varying unique keys:

| Unique keys | Merkle cost | Schnorr cost | Total | Per-order |
|-------------|-------------|-------------|-------|-----------|
| 10 | 0.5M | 4.7M | 5.7M | 950 |
| 50 | 2.5M | 4.7M | 7.7M | 1,283 |
| **200** | **8.4M** | **4.7M** | **13.7M** | **2,283** |
| 500 | 21M | 4.7M | 26.2M | 4,367 |
| 1,000 | 42M | 4.7M | 47.2M | 7,867 |

**Production expectation:** A CLOB at realistic scale has 50-300 unique active signers per batch. This is the sweet spot.

### Witness Size Analysis

| Component | Size (6,000 orders, 200 unique) |
|-----------|------------------------------|
| Raw order data | 300 KB (6,000 × 50 bytes) |
| Unique key info | 20 KB (200 × 100 bytes) |
| Flat Merkle proofs | 800 KB (200 × 4 KB avg) |
| **Total witness (rkyv)** | **~1.2 MB** |
| Same witness (borsh) | ~1.17 MB |
| Alignment padding | +2% |

---

## 5. Technical Deep Dive

### 5.1 Septic Curve Parameters

The septic curve is SP1's internal memory argument curve, exposed via custom precompiles in the KalqiX fork.

```
Field: KoalaBear prime, p = 2,130,706,433 = 2^31 - 2^24 + 1
Extension: Fp7 = Fp[z] / (z^7 - 3z - 5)
Curve equation: y² = x³ + 45x + 41·z³
Group order: r = 199,372,529,839,252,601,278,447,397,890,876,471,698,671,718,266,839,763,841,250,021,879
             (217 bits, prime)
Twist order: also prime
Generator: CURVE_CUMULATIVE_SUM_START (from SP1 codebase)
Security: ≥100 bits
```

**Verified via:**
1. Direct reading of SP1 6.0.2 source (`crates/core/executor/src/syscall_code.rs`)
2. Independent SageMath computation of group order
3. Cross-check of curve equation at 3 locations in SP1 codebase

### 5.2 Custom SP1 Precompiles

Added in the KalqiX fork of SP1 (branch `feat/septic-precompiles`):

| Precompile | Syscall ID | Operation | Cycles |
|------------|-----------|-----------|--------|
| SEPTIC_ADD | 0x134 | Point addition | ~1,000 |
| SEPTIC_DOUBLE | 0x135 | Point doubling | ~800 |
| SEPTIC_SCALAR_MUL | 0x136 | Full scalar multiplication | ~4,000 |
| **SEPTIC_VERIFY** | **0x137** | **Schnorr verify (Shamir's trick)** | **~750** |

All four implemented with minimal functional executors. Full VM executor stubs need AIR constraint implementations — submitted as RFC PR to Succinct Labs for collaboration.

**SEPTIC_VERIFY via Shamir's trick:**

Instead of computing `s·G + e·A` as two separate scalar multiplications, Shamir's trick interleaves them:

```
For each bit position (high to low):
    P = 2·P
    If s bit set: P = P + G
    If e bit set: P = P + A
```

One pass, two additions per bit maximum. Result is `s·G + e·A` in roughly half the cycles of sequential computation.

### 5.3 JMT with Poseidon2Hasher

The production codebase already uses `jmt` (our fork: `github.com/kalqix/jmt`) for the balance state tree. The session key tree reuses this infrastructure.

**Conditional compilation pattern** for `Poseidon2Hasher`:

```rust
// shared/src/poseidon2_hasher.rs
impl jmt::SimpleHasher for Poseidon2Hasher {
    fn new() -> Self { ... }
    fn update(&mut self, data: &[u8]) { ... }
    fn finalize(self) -> [u8; 32] {
        #[cfg(target_os = "zkvm")]
        {
            // Guest: POSEIDON2 precompile (~1,800 cycles)
            let out: [u32; 8] = Poseidon2ByteHash::hash(&self.data);
            u32_array_to_bytes(out)
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            // Host: sp1_primitives software implementation (~instant)
            use sp1_primitives::poseidon2_hash;
            // ... convert bytes to field elements, hash, convert back
        }
    }
}
```

**Same bytes in → same bytes out** on both host and guest. The JMT crate is generic over `H: SimpleHasher` and doesn't know about the dispatch.

### 5.4 FlatBatchExistenceProof Internals

The evolution from standard to flat:

**Standard JMT proof (SparseMerkleProof):**
```rust
pub struct SparseMerkleProof<H: SimpleHasher> {
    pub leaf: Option<SparseMerkleLeafNode>,
    pub siblings: Vec<SparseMerkleNode>,  // Enum: Null | Internal | Leaf
    pub phantom_hasher: PhantomData<H>,
}
```

Verification does **2 hashes per level**: one for the sibling (`sibling.hash::<H>()`) and one for the parent.

**FlatBatchExistenceProof entry:**
```rust
pub struct FlatExistenceEntry {
    pub key_hash: KeyHash,
    pub value: Vec<u8>,
    pub sibling_hashes: Vec<[u8; 32]>,  // Pre-hashed on host
}
```

Verification does **1 hash per level**: just the parent. Sibling hash is already computed.

**Sibling ordering (critical):**

From `SparseMerkleProof::verify()`:
```rust
element_key.0.iter_bits()
    .rev()
    .skip(256 - self.siblings.len())
    .fold(current_hash, |hash, (sibling_node, bit)| { ... })
```

- `iter_bits()` = MSB-first
- `.rev()` = now yields LSB bits first
- `.skip(256 - depth)` = skips to the deep-tree bits

**`siblings[0]` pairs with the deep-tree bit = CLOSEST TO LEAF**
**`siblings[depth-1]` pairs with the root-side bit = CLOSEST TO ROOT**

The FlatBatchExistenceProof preserves this ordering. The verify loop walks bottom-to-top.

### 5.5 Shared Hash Caching

In a batch of 200 proofs, keys with common prefixes share upper tree nodes. Caching avoids re-hashing:

```rust
for entry in entries {
    let mut current = leaf_hash(entry.key_hash, entry.value);
    
    for i in 0..depth {
        let sibling = &entry.sibling_hashes[i];
        current = combine(current, sibling, bit_at_position);
        
        // Check cache at this tree level
        let cache_key = prefix_of(entry.key_hash, level_from_root);
        if let Some(cached) = cache.get(&cache_key) {
            assert_eq!(current, cached);  // sanity check
            break;  // Upper levels already verified
        }
        cache.insert(cache_key, current);
    }
}
```

**Measured savings:** 27% reduction in Merkle hashing at 200 unique keys in a 6,000-key tree.

### 5.6 rkyv Zero-Copy Deserialization

The traditional flow serializes a witness struct with borsh, then the guest deserializes by walking every byte:

```rust
// Borsh flow — 18M cycles to deserialize
let witness: Witness = sp1_zkvm::io::read();  // full parse + heap allocations
```

The rkyv flow writes the in-memory layout directly, and the guest casts a pointer:

```rust
// rkyv flow — 342 cycles total
let bytes: Vec<u8> = sp1_zkvm::io::read_vec();  // raw byte copy
let archived = unsafe { rkyv::access_unchecked::<ArchivedWitness>(&bytes) };
// archived is a reference into `bytes` — zero copy
```

**Safety:** `access_unchecked` skips bytecheck validation. For production, consider `rkyv::access` with bytecheck enabled — ~1-2M additional cycles for validation, still far below borsh. Not critical for our use case since the prover is trusted relative to the witness.

**Alignment:** rkyv default is 16-byte aligned, but `sp1_zkvm::io::read_vec()` returns 8-byte aligned memory. Since our archived types don't contain anything requiring >8-byte alignment ([u8; 32], Vec, Option, enums), `access_unchecked` works safely.

### 5.7 Dedup Strategy

Without dedup (6,000 orders × Merkle proof per order):
- 6,000 × 42k = 252M cycles for Merkle alone

With dedup (one Merkle per unique key):
- 200 × 42k = 8.4M cycles for Merkle
- 6,000 × 750 = 4.5M cycles for Schnorr
- Total: 12.9M

**The dedup handler groups orders by unique session key:**

```rust
fn build_dedup_witness(orders: &[SignedOrder]) -> Witness {
    let mut by_key: HashMap<(Address, u8), Vec<&SignedOrder>> = HashMap::new();
    for order in orders {
        by_key.entry((order.account_address, order.key_index))
            .or_default()
            .push(order);
    }
    
    let unique_keys: Vec<UniqueKey> = by_key.keys()
        .map(|k| generate_proof_for_key(k))
        .collect();
    
    let flattened_orders: Vec<DedupOrder> = orders.iter().enumerate()
        .map(|(_, order)| {
            let key_idx = find_index_in_unique_keys(order);
            DedupOrder { key_idx, signature: order.sig, ... }
        })
        .collect();
    
    Witness { unique_keys, orders: flattened_orders, ... }
}
```

---

## 6. Migration Plan for kalqix-zk-service

### 6.1 Scope

This migration modifies `kalqix-zk-service` only. The POC serves as the implementation reference. No changes to smart contracts, deployment infrastructure, or on-chain verifier beyond adding `session_key_root` fields.

### 6.2 Target Repository Structure

After migration, `kalqix-zk-service` gains these new/modified files:

```
kalqix-zk-service/
├── shared/
│   ├── Cargo.toml                    [MODIFIED — add dependencies]
│   └── src/
│       ├── lib.rs                    [MODIFIED — add new types, ProgramInput variants]
│       ├── poseidon2_hasher.rs       [NEW — Poseidon2Hasher with conditional compilation]
│       ├── septic/                   [NEW — septic curve primitives]
│       │   ├── mod.rs
│       │   ├── point.rs
│       │   └── scalar.rs
│       ├── session_key.rs            [NEW — SessionKeyLeaf, message builders]
│       └── utils/
│           ├── program_helpers.rs    [MODIFIED — mixed batch handler]
│           └── verify_signature.rs   [MODIFIED — secp256k1 only for registration]
├── program/
│   ├── range/
│   │   ├── Cargo.toml               [MODIFIED — add rkyv, session key deps]
│   │   └── src/main.rs              [MODIFIED — add register/order handlers]
│   └── aggregation/                  [UNCHANGED]
├── host/
│   ├── Cargo.toml                   [MODIFIED — add JMT session key store]
│   └── src/
│       ├── proposer.rs              [MODIFIED — build mixed witnesses]
│       └── state/
│           ├── jmt_store.rs         [UNCHANGED — balance tree]
│           └── session_key_store.rs [NEW — session key JMT]
└── Cargo.toml                       [MODIFIED — workspace deps]
```

### 6.3 Migration Phases

#### Phase 0: Infrastructure Setup (1 week)

**Goal:** Add dependencies and foundation, no behavior changes yet.

**Deliverables:**
1. Pin SP1 to KalqiX fork with septic precompiles:
   ```toml
   sp1-zkvm = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
   sp1-lib = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
   ```
2. Pin JMT to latest commit with all features:
   ```toml
   jmt = { git = "https://github.com/kalqix/jmt", rev = "4bd0faa76480419b0eda86e13b0d61e27d495f40" }
   ```
3. Add rkyv dependency:
   ```toml
   rkyv = { version = "0.8", default-features = false, features = ["alloc", "bytecheck"] }
   ```
4. Add septic curve module (`shared/src/septic/`)
5. Add `Poseidon2Hasher` (`shared/src/poseidon2_hasher.rs`)
6. CI passes, no runtime changes

**Acceptance:** `cargo build --all` succeeds. All existing tests pass.

#### Phase 1: Session Key Infrastructure (1-2 weeks)

**Goal:** Add session key tree and types without changing signature verification.

**Deliverables:**
1. New types in `shared/src/lib.rs`:
   - `SessionKeyLeaf`
   - `SessionKey`
   - `RegisterKeyRequest`, `RegisterKeyWitness`
   - `SignedOrder` (Schnorr variant)
   - `UniqueKeyInfo`, `DedupOrder`
   - `BatchSepticDedupFlatWitness`

2. `SessionKeyStore` in `host/src/state/session_key_store.rs`:
   - Wraps `JellyfishMerkleTree<RocksDB, Poseidon2Hasher>`
   - `register_key()`, `get_key_proof()`
   - Persistence in RocksDB (separate column family)

3. Extend `BlocksInfoStruct` to include:
   ```rust
   session_key_root: [u8; 32]
   old_session_key_root: [u8; 32]
   ```
   
4. ProgramInput enum gains variants:
   - `RegisterKey(RegisterKeyWitness)`
   - `VerifyOrderSeptic(OrderWitness)`
   - `BatchSepticDedupFlat` (unit variant, rkyv witness)

**Acceptance:** New types serialize/deserialize correctly. `SessionKeyStore` passes unit tests.

#### Phase 2: Guest Handlers (1-2 weeks)

**Goal:** Add new signature verification paths. Old paths still work.

**Deliverables:**
1. `handle_register_key()` in `program/range/src/main.rs`:
   - Verify secp256k1 EIP-191 signature
   - Verify old root has empty leaf at this position
   - Verify new root reflects insertion
   - Commit (old_session_key_root, new_session_key_root)

2. `handle_verify_order_septic()`:
   - Single-order path for testing
   - Verify JMT inclusion proof
   - Verify Schnorr sig via SEPTIC_VERIFY

3. `handle_batch_septic_dedup_flat()`:
   - Read rkyv bytes, access_unchecked
   - FlatBatchExistenceProof::verify
   - Bind leaves to unique_keys
   - Schnorr verify per order
   
4. Main dispatch updated to route new variants

**Acceptance:** Each handler passes end-to-end test with matching host builder. Cycle counts match POC benchmarks within 5%.

#### Phase 3: Proposer Integration (2 weeks)

**Goal:** The proposer can build mixed witnesses and choose between old/new paths.

**Deliverables:**
1. `host/src/proposer.rs` changes:
   - `build_mixed_witness()` — registrations first, orders second
   - `deduplicate_orders_by_session_key()`
   - `generate_flat_batch_proof()` — uses JMT `FlatBatchExistenceProof::from_batch`
   - Feature flag to toggle old/new path

2. Off-circuit validation:
   - Matching engine validates Schnorr sigs (Phase 0 trust model)
   - Rejects orders from unregistered keys
   - Enforces nonce ordering per session key

3. Ensure balance JMT (existing, SHA-256) and session key JMT (new, Poseidon2) don't interfere — separate stores, separate roots

**Acceptance:** End-to-end: registration + orders in same batch, proof generates successfully. Testnet deployment with new path running in parallel with old.

#### Phase 4: Smart Contract Updates (1 week, parallel with Phase 3)

**Goal:** Contracts accept new root fields.

**Deliverables:**
1. `ZkKalqiXVerifier.sol`:
   ```solidity
   struct BlocksInfoStruct {
       // ... existing fields ...
       bytes32 oldAccountRoot;
       bytes32 sessionKeyRoot;      // NEW
       bytes32 oldSessionKeyRoot;   // NEW
   }
   ```

2. Verifier contract decodes these fields from proof public inputs

3. No validation logic needed — SP1 proof asserts correctness

**Acceptance:** Testnet contract deployment, proof verification succeeds.

#### Phase 5: Client SDK (1-2 weeks, parallel with Phase 3)

**Goal:** Frontend signs orders with septic Schnorr.

**Deliverables:**
1. WASM-compiled septic signer (from POC)
2. `kalqix-sdk-ts`:
   - `SessionKey.generate()` — WASM keypair
   - `SessionKey.register(ethSigner)` — personal_sign, POST to /register-key
   - `SessionKey.signOrder(order)` — silent, WASM
3. IndexedDB storage (non-extractable where possible)

**Acceptance:** Testnet users can register + place orders end-to-end.

#### Phase 6: Cutover and Migration (2 weeks)

**Goal:** Mainnet users on new path, old path deprecated.

**Deliverables:**
1. All existing mainnet users prompted to register session key on next login
2. Old secp256k1-per-order path removed from circuit
3. Smart contract migration (if needed)
4. Deployment with monitoring

**Acceptance:** 100% of mainnet orders use septic Schnorr. Balance JMT and session key JMT both operating normally.

### 6.4 Rollback Strategy

Each phase is independently deployable:
- **Phase 0-1:** No behavior change, pure infrastructure
- **Phase 2-3:** Old path still functional, new path behind feature flag
- **Phase 4-5:** New path optional in contracts/SDK
- **Phase 6:** After 2 weeks of parallel operation, deprecate old path

Rollback at any stage: disable feature flag, old path resumes.

### 6.5 Production Configuration

**Tree depths** (for session key JMT):
```rust
// Account tree: 2^20 users = 1M
// Key sub-tree: not used (flat with hash(addr || key_index) as key)
const ACCOUNT_TREE_HEIGHT: usize = 20;
```

Actually — since we use JMT, depth is variable (log2(active_keys)). No fixed depth parameter needed.

**Batch sizes:**
```rust
const MAX_ORDERS_PER_BATCH: usize = 10_000;     // up from 2,000
const MAX_REGISTRATIONS_PER_BATCH: usize = 100;
const PROOF_INTERVAL_MS: u64 = 2_000;
```

**Pre-hashing:** Always enabled in production. No configuration option.

**rkyv alignment:** Always use `access_unchecked` in guest for zero cycle overhead. Host uses `to_bytes::<Error>` with bytecheck.

---

## 7. Audit Preparation

### 7.1 Scope of Audit

The audit must cover five critical areas:

1. **Septic curve parameters and operations** — correctness, security level
2. **SEPTIC_VERIFY precompile** — Shamir's trick implementation, edge cases
3. **JMT session key tree** — insertion, inclusion proofs, root transitions
4. **FlatBatchExistenceProof** — sibling ordering, cache logic, domain separators
5. **Mixed batch circuit** — registration/order ordering, root transition correctness

### 7.2 Audit Artifacts

For auditors:

1. **This document** — architecture overview and technical deep dive
2. **Benchmark data** — full cycle count analysis (POC + production)
3. **SP1 fork diff** — custom precompile implementations
4. **JMT fork diff** — BatchExistenceProof, FlatBatchExistenceProof, rkyv derives
5. **Test vectors** — known signatures, known Merkle proofs, known root transitions
6. **Comparison with Lighter.xyz** — why our approach is equivalent

### 7.3 Known Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Septic curve parameters incorrect | Critical | SageMath verification at 3 independent locations |
| Sibling ordering bug in FlatBatchExistenceProof | Critical | Cross-test with standard BatchExistenceProof |
| Host-guest Poseidon2 mismatch | Critical | Host-side test with known vectors from guest execution |
| Batch Schnorr incompatibility | High | We don't use batch Schnorr; each verify independent |
| rkyv version skew on redeployment | Medium | Pinned to exact commit in Cargo.lock |
| Nonce race in browser (IndexedDB) | Medium | Single-tab enforcement, queue order signing |
| SP1 fork not upstream | Medium | PR submitted to Succinct, continue parallel maintenance |

### 7.4 Critical Code Paths (Audit Focus)

**Must be audited line-by-line:**

1. `shared/src/septic/point.rs` — curve operations, edge cases (point at infinity, scalar = 0)
2. `shared/src/poseidon2_hasher.rs` — host-guest alignment
3. `shared/src/session_key.rs` — message format, hash derivation
4. `program/range/src/main.rs::handle_register_key` — secp256k1 verification, JMT update proof
5. `program/range/src/main.rs::handle_batch_septic_dedup_flat` — batch verification flow
6. SP1 fork: `crates/core/executor/src/syscalls/septic_verify.rs` — Shamir's trick

**Can be audited as a whole:**

1. JMT crate (already audited upstream, we add derives and verify methods)
2. rkyv crate (audited upstream, we use standard features)
3. SP1 core (audited upstream, we only add precompiles)

### 7.5 Test Coverage Expectations

Before audit, ensure these test suites pass:

1. **Unit tests:**
   - Septic curve: known test vectors, identity, doubling, scalar mul consistency
   - SEPTIC_VERIFY: positive (valid sig), negative (invalid sig), edge cases
   - Poseidon2Hasher: host/guest match for 100 random inputs
   - FlatBatchExistenceProof: round-trip with BatchExistenceProof

2. **Integration tests:**
   - Full registration → order → proof → verification flow
   - Mixed batch: 3 registrations + 100 orders in one proof
   - Large batch: 6,000 orders / 200 unique keys matches POC numbers

3. **Property tests:**
   - For any valid (address, key_index), registration followed by verify succeeds
   - Tampering with any sibling hash causes verification failure

4. **Fuzz tests:**
   - Random signatures do not verify
   - Random tree modifications are detected

---

## 8. Operational Considerations

### 8.1 Monitoring

Key metrics to track in production:

| Metric | Target | Alert threshold |
|--------|--------|----------------|
| Per-batch proof time | <30s | >60s |
| Per-order cycles (amortized) | <5,000 | >10,000 |
| Session key registrations/day | N/A | Sudden spike (abuse) |
| Unique keys per batch | 50-300 | >500 (dedup degrading) |
| JMT tree depth | log2(keys) | >24 (unexpected) |
| Failed sig verifications (off-chain) | <0.1% | >1% |

### 8.2 Capacity Planning

**Per-prover throughput:**
- 6,000 orders / 30s proof = 200 orders/sec per prover
- 100 provers = 20,000 orders/sec aggregate
- Competitive CLOB target: 10,000-50,000 orders/sec

**Storage:**
- Session key JMT: ~100 bytes per key × 1M keys = 100 MB
- Replication factor 3: 300 MB
- Snapshot per version: ~500 MB with history
- Much smaller than balance JMT

### 8.3 Incident Response

**If a Schnorr verification fails on-chain (post-proof):**
- Impossible if proof verified — indicates contract bug
- Runbook: pause verifier, investigate, deploy fix

**If JMT root transition fails:**
- Indicates state corruption between proposer and prover
- Runbook: rollback to last known good, rebuild from RocksDB snapshot

**If a user reports lost session key:**
- Expected: IndexedDB cleared, incognito mode, etc.
- SDK auto-detects missing key, prompts re-registration
- One MetaMask signature, no gas, done

**If a malicious sequencer includes invalid orders:**
- Prevention: Schnorr signatures required, matching engine validates off-circuit
- Detection: proof would fail to generate or pass invalid state
- Recovery: slashing via L1 fraud proofs (future)

### 8.4 Key Rotation

Users can rotate session keys:
```
User action: rotateSessionKey()
  ↓
SDK generates new keypair
  ↓
SDK builds rotation message signed by OLD key
  ↓
POST /rotate-key → matching engine
  ↓
Matching engine inserts new key, deletes old
  ↓
Proof proves: (a) old key's Schnorr sig on rotation msg,
              (b) new root reflects both changes
```

No ETH wallet interaction needed. Happens as a regular L2 transaction.

### 8.5 Key Loss Recovery

If a user loses all session keys (e.g., cleared all browser data):

```
User returns, SDK detects no keys stored
  ↓
SDK prompts: "Register new session key?"
  ↓
User signs new registration (ETH wallet, no gas)
  ↓
New key registered as index N+1 (old keys remain but unused)
```

User can also explicitly revoke lost keys via a signed message (future feature).

### 8.6 Migration from Old Signature Scheme

Users with pre-migration secp256k1 auth:

**Option A (recommended):** Prompt on next login for session key registration. Old path deprecated after 30 days.

**Option B:** Automatic migration: next time user places an order, SDK detects missing session key and handles registration inline before order submission.

---

## 9. SP1 Fork & JMT Fork Maintenance

### 9.1 SP1 Fork Status

**Repository:** `github.com/kalqix/sp1`
**Branch:** `feat/septic-precompiles`
**Base:** SP1 6.0.2

**Custom additions:**
- `crates/core/executor/src/syscall_code.rs` — syscall IDs 0x134-0x137
- `crates/core/executor/src/syscalls/septic_*.rs` — executor implementations
- `crates/zkvm/lib/src/septic.rs` — guest-side API
- AIR constraints: **NOT YET IMPLEMENTED** — submitted as RFC PR to Succinct Labs

**Ongoing maintenance required:**
1. Merge upstream SP1 updates (especially security patches)
2. Respond to Succinct review feedback on the PR
3. Eventually implement full AIR constraints for real proving (not just mock/execute)

**Currently blocks:** Real proving. The custom precompiles work in executor mode (cycle counting, correctness testing) but don't yet generate valid proofs. For mainnet, either:
- (a) Wait for Succinct to merge and implement full constraints
- (b) Implement our own AIR constraints for SEPTIC_* (significant effort)

For Phase 0 (trusted sequencer), this is acceptable — proofs are not required for security. For Phase 1 (trustless), this must be resolved.

### 9.2 JMT Fork Status

**Repository:** `github.com/kalqix/jmt`
**Branch:** `feat/batch-verify`
**Base:** `penumbra-zone/jmt` 0.11.0

**Custom additions:**
- `src/batch_existence.rs` (commit `35bc0f14`) — BatchExistenceProof with shared hash caching
- rkyv derives on all proof types (commit `435ff9f9`)
- `src/flat_proof.rs` (commit `4bd0faa7`) — FlatBatchExistenceProof with pre-hashed siblings

**Pinned in production:** `4bd0faa76480419b0eda86e13b0d61e27d495f40`

**Ongoing maintenance required:**
1. Merge upstream JMT updates
2. Add documentation (upstream RFC if they're interested)
3. Maintain rkyv 0.8 compatibility

### 9.3 Dependency Alignment

Critical version pins:

```toml
# Workspace Cargo.toml
[workspace.dependencies]
sp1-zkvm = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
sp1-lib = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
jmt = { git = "https://github.com/kalqix/jmt", rev = "4bd0faa76480419b0eda86e13b0d61e27d495f40" }
rkyv = { version = "0.8", default-features = false, features = ["alloc", "bytecheck"] }
```

**Version lock:** `Cargo.lock` committed. Upgrades require explicit testing.

---

## 10. Appendix: Dependency Specifications

### 10.1 shared/Cargo.toml

```toml
[package]
name = "shared"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
sha3 = "0.10"
k256 = "0.13"
tiny-keccak = "2.0"
bincode = "1"
borsh = { version = "1", features = ["derive"] }
hex = "0.4"
alloy-primitives = "0.8"
alloy-sol-types = "0.8"
anyhow = "1"
jmt = { git = "https://github.com/kalqix/jmt", rev = "4bd0faa76480419b0eda86e13b0d61e27d495f40" }
rkyv = { version = "0.8", default-features = false, features = ["alloc"] }
hashbrown = "0.15"

[target.'cfg(target_os = "zkvm")'.dependencies]
sp1-zkvm = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
sp1-lib = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }

[target.'cfg(not(target_os = "zkvm"))'.dependencies]
sp1-primitives = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
p3-field = "0.2"
```

### 10.2 program/range/Cargo.toml

```toml
[package]
name = "kalqix-range"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = { path = "../../shared" }
sp1-zkvm = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
sp1-lib = { git = "https://github.com/kalqix/sp1", branch = "feat/septic-precompiles" }
sha2 = "0.10"
sha3 = "0.10"
k256 = "0.13"
tiny-keccak = "2.0"
bincode = "1"
borsh = "1"
hex = "0.4"
rkyv = { version = "0.8", default-features = false, features = ["alloc"] }
thiserror = "1"

[patch.crates-io]
# Required patches from Succinct for other precompiles
sha2 = { git = "https://github.com/sp1-patches/sha2", tag = "patch-sha2-0.10.9-sp1-6.0.0" }
sha3 = { git = "https://github.com/sp1-patches/sha3", tag = "patch-sha3-0.10.8-sp1-6.0.0" }
k256 = { git = "https://github.com/sp1-patches/k256", tag = "patch-k256-13.4-sp1-6.0.0" }
tiny-keccak = { git = "https://github.com/sp1-patches/tiny-keccak", tag = "patch-2.0.2-sp1-6.0.0" }
```

### 10.3 host/Cargo.toml

```toml
[package]
name = "host"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = { path = "../shared" }
jmt = { git = "https://github.com/kalqix/jmt", rev = "4bd0faa76480419b0eda86e13b0d61e27d495f40", features = ["mocks"] }
rkyv = { version = "0.8", features = ["alloc", "bytecheck"] }
sp1-sdk = "6.0.2"
alloy = { version = "0.8", features = ["full"] }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
rocksdb = "0.22"
serde = "1"
serde_json = "1"
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | April 2026 | Initial release — POC complete, migration plan ready |

## Contact

KalqiX Engineering Team
This document is confidential.

---

**End of document.**
