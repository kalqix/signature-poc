# KalqiX Signature POC

Zero-knowledge proof-of-concept for session key registration and order signing using SP1, Ed25519, and EIP-191. Compares Ed25519 vs secp256k1 cycle counts inside SP1 to validate the signature migration.

## Prerequisites

- **Rust** (installed via rustup)
- **SP1 toolchain** — install with `sp1up`:
  ```
  curl -L https://sp1up.succinct.xyz | bash
  sp1up
  ```
- **Node.js 18+**
- **MetaMask** browser extension (Chrome 113+ or Firefox 113+ for Ed25519 Web Crypto)
- **samply** (optional, for flamegraph profiling): `cargo install --locked samply`

## Build & Run

### 1. Build the SP1 guest program

```
cd program
cargo prove build
```

Compiles the guest program to a RISC-V ELF. Must be run before the backend.

### 2. Run the backend

```
cd backend
cargo run --release
```

Axum server starts on `http://localhost:3001`.

### 3. Run the frontend

```
cd frontend
npm install
npm run dev
```

Vite dev server starts on `http://localhost:5173`.

## Testing the flow

1. Open **http://localhost:5173** in Chrome 113+ or Firefox 113+
2. Click **Connect** and approve in MetaMask
3. You'll see 5 key slots (indices 0–4). Click **Register** on any slot
4. MetaMask prompts you to sign a message (no gas, no transaction)
5. The backend runs a mock SP1 proof verifying the ETH signature and Merkle insertion
6. Once a key is registered, the order form appears
7. Toggle between **Ed25519 (session key)** and **Ethereum personal_sign** signing schemes
8. Fill in market/side/price/quantity and click **Place Order**
9. Each order triggers a mock SP1 proof — instruction counts appear in the UI
10. After submitting at least one order with each scheme, a **Benchmark** panel shows the comparison

### Key rotation

Click **Rotate** on any active key slot. This generates a new Ed25519 keypair, signs with your ETH wallet, and the backend handles the Merkle leaf replacement.

## What each proof verifies

**REGISTER_KEY** (secp256k1 + Poseidon2)
- Verifies old leaf against old Merkle root (empty for fresh, previous hash for rotation)
- Recovers Ethereum address from EIP-191 secp256k1 signature
- Hashes new `SessionKeyLeaf` with Poseidon2 and verifies new root

**VERIFY_ORDER** (Ed25519 + SHA-256 + Poseidon2)
- Proves session key exists in Merkle tree via Poseidon2 membership proof
- Verifies Ed25519 signature over SHA-256(order_message)

**VERIFY_ORDER_ETH** (secp256k1 + keccak256 — benchmark only)
- Recovers Ethereum address from EIP-191 secp256k1 signature over order message
- No Merkle proof — exists only for cycle count comparison

## Profiling

### Quick cycle comparison

```
cargo run --release --bin profile
```

Runs all three proof types with real cryptographic signatures and prints cycle breakdowns:

```
  Profiling: VerifyOrder (Ed25519)
    total_cycles:       1,564,894
    merkle_verify          1,447,371 (92.5%)
    ed25519_verify            78,865 (5.0%)
    sha256_hash                7,506 (0.5%)

  Profiling: VerifyOrderEth (secp256k1)
    total_cycles:       2,782,003
    secp256k1_recover      2,746,387 (98.7%)
    eip191_hash               15,649 (0.6%)
```

### Single proof type

```
cargo run --release --bin profile -- register-key
cargo run --release --bin profile -- verify-order
cargo run --release --bin profile -- verify-order-eth
```

### Samply flamegraph

```
TRACE_FILE=output.json TRACE_SAMPLE_RATE=100 cargo run --release --bin profile -- verify-order
samply load output.json
```

Opens the Firefox Profiler with a flamegraph of SP1 program execution.

### Cycle tracker labels

The guest program uses `cycle-tracker-report-*` annotations:

| Handler | Labels |
|---|---|
| RegisterKey | `merkle_verify_old`, `eip191_recover`, `hash_new_leaf`, `merkle_verify_new` |
| VerifyOrder | `merkle_verify`, `sha256_hash`, `ed25519_verify` |
| VerifyOrderEth | `eip191_hash`, `secp256k1_recover` |

Access via `report.cycle_tracker["label"]` on the host side.

## Architecture

```
frontend/          React + wagmi + Web Crypto API (Ed25519 non-extractable keys)
    |
    | POST /register-key     (EIP-191 sig + pubkey)
    | POST /place-order      (Ed25519 sig + order)
    | POST /place-order-eth  (EIP-191 sig + order, benchmark only)
    v
backend/           Axum server + Poseidon2 Merkle tree + SP1 mock prover
    |
    | SP1Stdin with ProgramInput (RegisterKey | VerifyOrder | VerifyOrderEth)
    v
program/           SP1 guest (single ELF, all three proof types)
    |
    | commits ProofOutput (roots, address, proof_type)
    v
shared/            Types + message format helpers (used by backend + program)
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/register-key` | Register or rotate a session key |
| POST | `/place-order` | Verify order with Ed25519 session key |
| POST | `/place-order-eth` | Verify order with ETH wallet (benchmark) |
| GET | `/state` | Current Merkle root and registered key count |

## Known POC limitations

This is a proof-of-concept, not production software:

- **Mock proofs only** — uses `ProverClient::builder().mock()`, no real SP1 proving
- **In-memory state** — Merkle tree and registered keys reset on server restart
- **No on-chain verification** — proofs are generated but not submitted to any chain
- **No replay protection** — order replay protection is the matching engine's responsibility
- **Fixed tree depth** — 256 leaf slots total (8-level Poseidon2 Merkle tree)
- **key_index 0–4 in frontend** — circuit supports 0–254
