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
- **wasm-pack + wasm32 target** (only if you want browser-side septic Schnorr signing):
  ```
  brew install wasm-pack       # or: cargo install wasm-pack
  rustup target add wasm32-unknown-unknown
  ```
- **samply** (optional, for flamegraphs): `cargo install --locked samply`

## Build & Run

### 1. Build the SP1 guest program

```
cd program
cargo prove build --elf-name signature-poc --output-directory elf
```

Compiles the guest program to a RISC-V ELF. Must be run before the backend.

### 2. Build the WASM signer (only if you want septic Schnorr in the browser)

```
cd frontend/wasm-signer
wasm-pack build --target web --out-dir ../src/wasm-pkg --release
```

Compiles `frontend/wasm-signer` (a thin wrapper over `shared::septic`) to WebAssembly. Re-run after any change to `shared/src/septic.rs` or `wasm-signer/src/lib.rs`. The output is checked-in-by-build, not committed; Vite picks it up via standard ESM imports (no plugin needed).

### 3. Run the backend

```
cd backend
cargo run --release --bin backend
```

Axum server starts on `http://localhost:3001`.

### 4. Run the frontend

```
cd frontend
npm install
npm run dev
```

Vite dev server starts on `http://localhost:5173`.

## Testing the flow

1. Open **http://localhost:5173** in Chrome 113+ or Firefox 113+
2. Click **Connect** and approve in MetaMask
3. You'll see 5 Ed25519 key slots (indices 0–4) plus a single **Septic Schnorr** slot
   - Click **Register** on an Ed25519 slot — MetaMask prompts for a signature; the backend runs a mock SP1 proof and inserts the leaf into the Poseidon2 Merkle tree
   - Or click **Generate** on the Septic slot — produces a fresh KoalaBear-Fp7 Schnorr keypair locally via WASM (~50ms), no wallet prompt and no backend roundtrip
4. Once any key is active, the order form appears
5. Pick a signing scheme: **Ed25519 (session key)**, **Ethereum personal_sign**, **P-256 ECDSA**, or **Septic Schnorr (session key)**
6. Fill in market/side/price/quantity and click **Place Order**
7. Each order triggers a mock SP1 proof — instruction counts appear in the UI; septic shows host-side sign latency too
8. After submitting at least one order with each scheme, a **Benchmark** panel compares them side-by-side

### Key rotation

Click **Rotate** on any active Ed25519 slot. This generates a new keypair, signs with your ETH wallet, and the backend handles the Merkle leaf replacement. The septic key has a **Regenerate** button that overwrites the existing keypair locally — no wallet prompt, no backend call.

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
| `batch-septic-{1,10,2000,4000,6000}` | Naive Schnorr verify via per-bit add/double syscalls (~325 syscalls per scalar mul) |
| `batch-septic-opt-{1,10,2000,4000,6000}` | Batched Fiat-Shamir Schnorr over the same per-bit syscalls |
| `batch-septic-single-{1,10,2000,6000}` | Naive Schnorr verify using `SEPTIC_SCALAR_MUL` precompile (1 syscall per scalar mul) |
| `batch-septic-opt-single-{1,10,2000,6000}` | Batched Fiat-Shamir Schnorr using `SEPTIC_SCALAR_MUL` precompile |
| `batch-septic-verify-{1,10,2000,6000}` | Schnorr verify using `SEPTIC_VERIFY` precompile (Shamir's trick, 1 syscall/sig) |
| `batch-eth-{1,10,2000,4000,6000}` | EIP-191 secp256k1 ecrecover baseline |

**Latest results at N = 6000** (SP1 fork `c9dc63f8`, executor on CPU):

| Mode | Total cycles | Cycles / sig | Gas |
|---|---:|---:|---:|
| `batch-septic-verify-6000` | 31,335,089 | 5,223 | 99.1M |
| `batch-septic-single-6000` | 31,935,190 | 5,323 | 147.9M |
| `batch-septic-opt-single-6000` | 47,683,075 | 7,947 | 172.2M |
| `batch-septic-opt-6000` | 183,589,305 | 30,598 | 273.2M |
| `batch-septic-6000` | 210,082,714 | 35,014 | 316.3M |
| `batch-eth-6000` | 326,735,623 | 54,456 | 440.5M |

**Shamir's-trick verify (`batch-septic-verify`) is the fastest path:** ~10.4× fewer cycles and ~4.4× less gas than ecrecover at 6000 sigs. Per-sig cost stays essentially flat from 2000 → 6000 — proving cost scales linearly with batch size, no per-batch fixed overhead worth worrying about.

**Per-batch overhead at N = 1** — same six modes, one signature each. Useful for sizing the fixed cost of Fiat-Shamir batching and for spotting when the `_opt` modes start to pay off:

| Mode | N=1 cycles | N=1 gas | Asymptotic per-sig (from N=6000) |
|---|---:|---:|---:|
| `batch-septic-verify-1` | 22,446 | 36.6K | 5,223 |
| `batch-septic-single-1` | 22,647 | 45.0K | 5,323 |
| `batch-septic-opt-single-1` | 31,119 | 64.2K | 7,947 |
| `batch-septic-1` | 51,598 | 71.8K | 35,014 |
| `batch-septic-opt-1` | 68,464 | 94.5K | 30,598 |
| `batch-eth-1` | 70,586 | 92.6K | 54,456 |

Two crossovers worth noting:

- **`batch-septic-opt` vs `batch-septic` (per-bit syscalls)**: Fiat-Shamir batching is a *net loss* below ~5 signatures (68k vs 52k cycles at N=1) but saves ~13% at N=6000. Use the naive variant for small batches.
- **`batch-septic-opt-single` vs `batch-septic-single` (single-syscall mul)**: opt-single is *always* worse — 47.7M vs 31.9M cycles even at N=6000. When `SEPTIC_SCALAR_MUL` already collapses each scalar mul to one syscall, the Fiat-Shamir hashing overhead never amortizes. Stick with `batch-septic-single` if you want naive batching on top of the precompile.

### Host signing benchmark

```sh
cargo run --release --bin profile -- bench-sign
```

Times host-side signing throughput for septic Schnorr vs. secp256k1 ECDSA (key generation excluded). Useful for frontend / client-side latency estimation.

### Reading the output

```
============================================================
  Profiling: BatchSepticVerify (6000 Shamir)
============================================================
  proof_type:         BATCH_SEPTIC_VERIFY_6000
  total_instructions: 31329085
  total_syscalls:     6004
  total_cycles:       31335089
  gas (normalized):   99063441  (3.161 gas/cycle)
  touched_memory:     0

  Cycle tracker breakdown:
    section                              cycles     gas (est.)       %
    batch_verify_total                  4404296       13923838   14.1%
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
frontend/             React + wagmi + Web Crypto API (Ed25519/P-256 non-extractable keys)
  └─ wasm-signer/     Rust crate compiled to WASM via wasm-pack — re-exports
                      shared::septic for browser-side Schnorr signing (~50ms/sig)
    |
    | POST /register-key        (EIP-191 sig + pubkey)
    | POST /place-order         (Ed25519 sig + order)
    | POST /place-order-eth     (EIP-191 sig + order, benchmark only)
    | POST /place-order-p256    (P-256 sig + order, benchmark only)
    | POST /place-order-septic  (Septic Schnorr sig + order, benchmark only)
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
shared/            Types, message format helpers, AND septic Fp7/EC/scalar math.
                   Imported by program/, backend/, and frontend/wasm-signer/ —
                   single source of truth, no duplicated math.
```

`frontend/wasm-signer` is its own Cargo workspace (note `[workspace]` at the top of its `Cargo.toml`). This isolates it from the root workspace's SP1 patches so its `shared` dependency tree resolves to vanilla crates.io versions that compile to `wasm32-unknown-unknown`.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/register-key` | Register or rotate an Ed25519 session key |
| POST | `/place-order` | Verify order with Ed25519 session key |
| POST | `/place-order-eth` | Verify order with ETH wallet (benchmark) |
| POST | `/place-order-p256` | Verify order with P-256 ECDSA (benchmark) |
| POST | `/place-order-septic` | Verify order with septic Schnorr (benchmark) |
| GET | `/state` | Current Merkle root and registered key count |

## Known POC limitations

This is a proof-of-concept, not production software:

- **Mock proofs only** — uses `ProverClient::builder().mock()`, no real SP1 proving
- **In-memory state** — Merkle tree and registered keys reset on server restart
- **No on-chain verification** — proofs are generated but not submitted to any chain
- **No replay protection** — order replay protection is the matching engine's responsibility
- **Fixed tree depth** — 256 leaf slots total (8-level Poseidon2 Merkle tree)
- **key_index 0–4 in frontend** — circuit supports 0–254
- **Septic key material is extractable** — there's no Web Crypto primitive for KoalaBear, so the private scalar lives in IndexedDB as raw `Uint32Array` limbs. Ed25519/P-256 keys remain non-extractable `CryptoKey` objects.
- **Septic flow has no Merkle proof** — `/place-order-septic` is benchmark-only; the order payload carries the public key directly. Production session-key registration would still go through the Ed25519 path.
