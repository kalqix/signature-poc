# kalqix-poc

Proof-of-concept for KalqiX ZK signature verification migration.
Used to profile cycle counts before modifying kalqix-zk-service.

## Purpose

Validate that Ed25519 + SHA-256 + Poseidon2 is viable for production
before touching the production codebase (kalqix-zk-service).
The POC is throwaway — do not copy code from here into kalqix-zk-service.

## Architecture

One SP1 6.0.2 guest program handles three transaction types:

  RegisterKey    — secp256k1 EIP-191 sig + Poseidon2 Merkle insertion
  VerifyOrder    — Ed25519 sig + SHA-256 hash + Poseidon2 Merkle read
  VerifyOrderEth — secp256k1 EIP-191 sig + keccak256 hash (benchmark only)

## Workspace layout

  shared/    — types and message format helpers shared by backend and program
  program/   — SP1 guest program (cargo prove build)
  backend/   — Axum HTTP server, in-memory state, SP1 mock prover
  frontend/  — React + wagmi + Web Crypto API

## Key decisions (do not change without understanding why)

1. Session key leaf has NO nonce
   The leaf is immutable after registration. Replay protection is the
   matching engine's responsibility (expiry/timestamp), not the circuit's.
   Adding a nonce would require a Merkle write per order — incompatible
   with batch proving.

2. Poseidon2 for everything in the session key tree
   Both leaf hashing and node hashing use Poseidon2.
   The session key tree is a Jellyfish Merkle Tree (jmt crate, kalqix
   fork) — variable depth ~log2(N), supports insert/rotate/delete.
   `shared::Poseidon2Hasher` implements `jmt::SimpleHasher` and dispatches
   on cfg(target_os = "zkvm"):
     guest: sp1_zkvm::syscalls::Poseidon2ByteHash precompile
     host:  sp1_primitives::poseidon2_init + length-prefixed sponge
   Both paths must produce byte-identical output — verified by
   `shared/src/poseidon2_hasher.rs::test_poseidon2_host_vs_guest_sponge`.

3. Web Crypto non-extractable keys
   Ed25519 private keys are stored in IndexedDB as CryptoKey objects
   with extractable: false. Raw private key bytes never exist in JS.
   Requires Chrome 113+ or Firefox 113+.

4. Single ELF, single proving key
   All three transaction types go through one SP1 program.
   Backend uses one ELF constant and one run_proof() function.

5. Key rotation supported
   register_key() accepts both empty slots (fresh) and occupied slots
   (rotation). Circuit verifies old_leaf_hash against old_root in both
   cases. ETH wallet signature required for rotation — session key
   cannot rotate itself.

6. VerifyOrderEth is benchmark-only
   The /place-order-eth route exists only to compare cycle counts.
   It has no session key Merkle proof. Do not extend it.

## Running

  # Build SP1 program first
  cd program && cargo prove build

  # Backend (port 3001)
  cd backend && cargo run --release

  # Frontend (port 5173)
  cd frontend && npm install && npm run dev

## Profiling

Use the dedicated profile binary for cycle counting:

  # All three proof types:
  cargo run --release --bin profile

  # Single proof type:
  cargo run --release --bin profile -- verify-order

  # Samply flamegraph:
  TRACE_FILE=output.json TRACE_SAMPLE_RATE=100 cargo run --release --bin profile -- verify-order
  samply load output.json

The guest program has cycle-tracker-report annotations. Access
per-section cycle counts via report.cycle_tracker["label"]:

  RegisterKey:    jmt_verify_old, eip191_recover
  VerifyOrder:    jmt_verify, schnorr_verify
  VerifyOrderEth: eip191_hash, secp256k1_recover

The comparison between VerifyOrder and VerifyOrderEth cycle counts
is the primary output of this POC. It determines whether the Ed25519
migration is viable for kalqix-zk-service Phase 2.

sp1-sdk profiling feature is enabled in backend/Cargo.toml.
Set TRACE_FILE and TRACE_SAMPLE_RATE env vars to generate trace files.

## What maps to kalqix-zk-service

  POC                              → kalqix-zk-service
  -------------------------------------------------------
  program/src/main.rs              → program/range/src/main.rs
  shared/src/lib.rs (session types)→ shared/src/models/session_key.rs
  shared/src/poseidon2_hasher.rs   → shared/src/jmt_hasher.rs
  backend/src/state.rs (JMT)       → host/src/state/session_key_store.rs
  backend/src/witness.rs           → host/src/proposer.rs
  BlocksInfoStruct (2 new fields)  → shared/src/types.rs

The POC uses `jmt::mock::MockTreeStore`; production should swap in the
RocksDB-backed `TreeReader`/`TreeWriter`. Witness types
(`SparseMerkleProof<Poseidon2Hasher>`) and the guest verify path
(`proof.verify_existence` / `verify_nonexistence`) are unchanged
between mock and production storage.

## What does NOT map to kalqix-zk-service

  frontend/           — kalqix-zk-service has no frontend
  /place-order-eth    — benchmark only, not a production route
  in-memory state     — production uses RocksDB + JMT
  mock prover         — production uses real SP1 GPU prover

## Critical tests (run before any code change)

  cargo test test_poseidon2_host_vs_guest_sponge   # in shared/
  cargo test test_poseidon2_parameters             # in shared/
  cargo test --package backend                     # state.rs JMT round-trips
  cargo prove build --elf-name signature-poc \     # in program/
                   --output-directory elf

If test_poseidon2_host_vs_guest_sponge fails, all JMT proofs will fail
silently in the guest (UnexpectedEof or root mismatch). Fix it before
anything else.

The `--elf-name`/`--output-directory` flags on `cargo prove build` are
load-bearing: the backend `include_bytes!`s `program/elf/signature-poc`,
not the default target dir. Plain `cargo prove build` will silently
leave a stale ELF at `program/elf/`.

## Known limitations (intentional, not bugs)

  - In-memory state resets on server restart
  - Single account supported in frontend (connected wallet only)
  - No on-chain verification
  - Mock proofs only (no real SP1 proving)
  - key_index 0-4 in frontend (circuit supports 0-254)
