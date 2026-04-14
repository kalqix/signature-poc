# KalqiX Signature POC

Zero-knowledge proof-of-concept for session key registration and order signing. Measures SP1 cycle counts and gas across several signature schemes — Ed25519, P-256, secp256k1 (ecrecover), and Schnorr over SP1's septic curve — to decide the production path for `kalqix-zk-service`.

**If you only want to run the benchmarks, skip to [Profiling](#profiling).**

## Prerequisites

- **Rust** (via rustup)
- **SP1 toolchain** (for building the guest ELF):
  ```
  curl -L https://sp1up.succinct.xyz | bash
  sp1up
  ```
  This repo pins SP1 to a private fork (`github.com/kalqix/sp1`, branch `feat/septic-precompiles`) that adds septic-curve precompiles. The fork is fetched by `cargo` automatically the first time you build — no extra setup.
- **Node.js 18+** (only if you want to run the frontend)
- **MetaMask** browser extension (Chrome 113+ / Firefox 113+) for the frontend
- **samply** (optional, for flamegraphs): `cargo install --locked samply`

## Build & Run

### 1. Build the SP1 guest program

```
cd program
cargo prove build --elf-name signature-poc --output-directory elf
```

Compiles the guest program to a RISC-V ELF. Must be run before the backend.

### 2. Run the backend

```
cd backend
cargo run --release --bin backend
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

**RegisterKey** (secp256k1 EIP-191 + Poseidon2 Merkle)
- Verifies old leaf against old Merkle root (empty for fresh slot, previous hash for rotation)
- Recovers Ethereum address from EIP-191 signature over the register-key message
- Hashes the new `SessionKeyLeaf` with Poseidon2 and verifies the new root

**VerifyOrder** (Ed25519 + SHA-256 + Poseidon2 Merkle)
- Proves the session key exists in the Merkle tree
- Verifies Ed25519 signature over SHA-256(order_message)

**VerifyOrderEth** (secp256k1 EIP-191 — benchmark only)
- Recovers the signer from an EIP-191 signature over the order message — no Merkle proof

**VerifyOrderP256** (P-256 ECDSA — benchmark only)
- Verifies a P-256 ECDSA signature over SHA-256(order_message)

**VerifyOrderSeptic** (Schnorr over SP1's septic curve — benchmark only)
- Verifies `s·G + e·A == R` using SP1's septic-curve precompiles

**BatchSeptic / BatchSepticOpt / BatchSepticSingle / BatchSepticOptSingle / BatchSepticVerify** (benchmark only)
- Verify `N` septic-Schnorr signatures using progressively better primitives; see [Profiling → Batch modes](#batch-modes-septic-schnorr-vs-ecrecover) below.

**BatchEth** (benchmark only)
- Verifies `N` EIP-191 secp256k1 signatures via ecrecover (baseline for batch comparisons).

## Profiling

This is the primary output of the POC — cycle counts that inform the `kalqix-zk-service` signature migration.

### Setup (one-time)

The profile binary `include_bytes!`es the guest ELF, so you must build the ELF before running any benchmark. From the repo root:

```sh
cd program
cargo prove build --elf-name signature-poc --output-directory elf
cd ..
```

The `--elf-name` + `--output-directory` flags put the ELF at `program/elf/signature-poc` where the host expects it. Rebuild whenever you change anything under `program/` or `shared/`.

### Running a benchmark

Every mode runs end-to-end: it generates real signatures on the host, executes the SP1 guest on the CPU, and prints cycle counts, gas, and a per-section cycle-tracker breakdown.

```sh
# From repo root:
cargo run --release --bin profile -- <MODE>
```

Omit `<MODE>` to run the default sweep (register-key, verify-order, verify-order-eth, verify-order-p256, verify-order-septic).

Expect the first run to take several minutes while SP1 and dependencies compile in release mode. Subsequent runs are fast.

### Single-signature modes

| Mode | Measures |
|---|---|
| `register-key` | secp256k1 EIP-191 + Poseidon2 Merkle insert |
| `verify-order` | Ed25519 + SHA-256 + Poseidon2 Merkle membership |
| `verify-order-eth` | secp256k1 EIP-191 ecrecover (order-only, no Merkle) |
| `verify-order-p256` | P-256 ECDSA (order-only, no Merkle) |
| `verify-order-septic` | Single septic-curve Schnorr verify |

### Batch modes (septic Schnorr vs. ecrecover)

Batch modes verify `N` independent signatures in one proof. Use the `-10` suffix for a fast sanity check; use `-2000` (or `-4000` where available) for realistic numbers.

| Mode | What it measures |
|---|---|
| `batch-septic-{10,2000,4000}` | Naive Schnorr verify via per-bit add/double syscalls (~325 syscalls per scalar mul) |
| `batch-septic-opt-{10,2000,4000}` | Batched Fiat-Shamir Schnorr over the same per-bit syscalls |
| `batch-septic-single-{10,2000}` | Naive Schnorr verify using `SEPTIC_SCALAR_MUL` precompile (1 syscall per scalar mul) |
| `batch-septic-opt-single-{10,2000}` | Batched Fiat-Shamir Schnorr using `SEPTIC_SCALAR_MUL` precompile |
| `batch-septic-verify-{10,2000}` | Schnorr verify using `SEPTIC_VERIFY` precompile (Shamir's trick, 1 syscall/sig) |
| `batch-eth-{10,2000,4000}` | EIP-191 secp256k1 ecrecover baseline |

**Latest results at N = 2000** (SP1 fork `c9dc63f8`, executor on CPU):

| Mode | Total cycles | Cycles / sig | Gas |
|---|---:|---:|---:|
| `batch-septic-verify-2000` | 10,325,357 | 5,163 | 32.6M |
| `batch-septic-single-2000` | 10,525,458 | 5,263 | 48.9M |
| `batch-septic-opt-single-2000` | 15,778,780 | 7,889 | 57.1M |
| `batch-septic-opt-2000` | 61,070,587 | 30,535 | 90.4M |
| `batch-septic-2000` | 69,928,702 | 34,964 | 104.7M |
| `batch-eth-2000` | 108,891,917 | 54,446 | 146.5M |

**Shamir's-trick verify (`batch-septic-verify`) is the fastest path:** ~10.5× fewer cycles and ~4.5× less gas than ecrecover at 2000 sigs.

### Host signing benchmark

```sh
cargo run --release --bin profile -- bench-sign
```

Times host-side signing throughput for septic Schnorr vs. secp256k1 ECDSA (key generation excluded). Useful for frontend / client-side latency estimation.

### Reading the output

```
============================================================
  Profiling: BatchSepticVerify (2000 Shamir)
============================================================
  proof_type:         BATCH_SEPTIC_VERIFY_2000
  total_instructions: 10323353
  total_syscalls:     2004
  total_cycles:       10325357
  gas (normalized):   32555605  (3.153 gas/cycle)
  touched_memory:     0

  Cycle tracker breakdown:
    section                              cycles     gas (est.)       %
    batch_verify_total                  1468296        4629502   14.2%
```

- `total_cycles = total_instructions + total_syscalls` — the primary proving-cost metric.
- `gas` — SP1's normalized proving cost. Use this (not cycles alone) to compare precompile-heavy modes, since one syscall can represent many internal EC operations.
- `cycle tracker breakdown` — per-section cycles from `println!("cycle-tracker-report-{start,end}: <label>")` annotations in `program/src/main.rs`. Gas is a pro-rata estimate — SP1 doesn't track gas per section.

### Cycle-tracker labels

| Handler | Labels |
|---|---|
| `handle_register_key` | `merkle_verify_old`, `eip191_recover`, `hash_new_leaf`, `merkle_verify_new` |
| `handle_verify_order` | `merkle_verify`, `sha256_hash`, `ed25519_verify` |
| `handle_verify_order_eth` | `eip191_hash`, `secp256k1_recover` |
| `handle_verify_order_p256` | `p256_sha256_hash`, `p256_verify` |
| `handle_verify_order_septic` | `septic_s_times_G`, `septic_e_times_A`, `septic_final_check` |
| `handle_batch_septic` | `batch_septic_total` |
| `handle_batch_septic_opt` | `batch_opt_commitment`, `batch_opt_scalar_combine`, `batch_opt_s_times_G`, `batch_opt_ae_times_A`, `batch_opt_alpha_times_R`, `batch_opt_final_check`, `batch_opt_lhs_combine` |
| `handle_batch_septic_single` | `batch_single_total` |
| `handle_batch_septic_opt_single` | `batch_opt_single_*` (same phases as non-single variant) |
| `handle_batch_septic_verify` | `batch_verify_total` |
| `handle_batch_eth` | `batch_eth_total` |

Access these via `report.cycle_tracker["label"]` on the host (`backend/src/bin/profile.rs::run_and_report`).

### Samply flamegraph

```sh
TRACE_FILE=output.json TRACE_SAMPLE_RATE=100 cargo run --release --bin profile -- verify-order
samply load output.json
```

Opens the Firefox Profiler with a flamegraph of guest execution. `sp1-sdk`'s `profiling` feature is enabled in `backend/Cargo.toml` — it hooks into the executor when those env vars are set.

### Troubleshooting

- **"old leaf does not match old root" on first run** — the ELF at `program/elf/signature-poc` is stale. Rebuild with `cd program && cargo prove build --elf-name signature-poc --output-directory elf`.
- **`sp1up: command not found`** — re-run the `curl | bash` installer or add `$HOME/.sp1/bin` to your `$PATH`.
- **Cargo refetches the SP1 fork on every build** — make sure your network can reach `github.com/kalqix/sp1`. To force a refresh after a fork push: `cargo update -p sp1-zkvm -p sp1-lib -p sp1-sdk -p sp1-primitives`.
- **Benchmarks look identical to a previous run** — you probably forgot to rebuild the ELF after editing `program/` or `shared/`.

## Architecture

```
frontend/          React + wagmi + Web Crypto API (Ed25519 non-extractable keys)
    |
    | POST /register-key     (EIP-191 sig + pubkey)
    | POST /place-order      (Ed25519 sig + order)
    | POST /place-order-eth  (EIP-191 sig + order, benchmark only)
    v
backend/           Axum server + Poseidon2 Merkle tree + SP1 mock prover
    |               Also hosts bin/profile.rs — the benchmarking entry point.
    | SP1Stdin with ProgramInput (RegisterKey | VerifyOrder | VerifyOrderEth |
    |                             VerifyOrderP256 | VerifyOrderSeptic |
    |                             BatchSeptic[Opt|Single|OptSingle|Verify] |
    |                             BatchEth)
    v
program/           SP1 guest (single ELF dispatches on ProgramInput variant)
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
