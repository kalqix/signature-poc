//! Profiling binary for SP1 cycle counting.
//!
//! Usage:
//!   # All three proof types:
//!   TRACE_FILE=all.json cargo run --release --bin profile
//!
//!   # Single proof type:
//!   TRACE_FILE=register.json cargo run --release --bin profile -- register-key
//!   TRACE_FILE=order_ed.json cargo run --release --bin profile -- verify-order
//!   TRACE_FILE=order_eth.json cargo run --release --bin profile -- verify-order-eth
//!
//!   # View in samply:
//!   samply load all.json

use std::env;

use anyhow::Result;
use ed25519_dalek::Signer;
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use num_bigint::BigUint;
use num_traits::Zero;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use sp1_sdk::{Elf, ProverClient, Prover, SP1Stdin};

use shared::septic::{
    SepticBenchWitness, SepticPoint, SepticSchnorrOrder, SepticSchnorrSignature,
};
use shared::*;

// Re-use the backend's state module for building witnesses.
#[path = "../state.rs"]
mod state;
use state::AppState;

const ELF: &[u8] = include_bytes!("../../../program/elf/signature-poc");

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn eip191_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = Vec::with_capacity(prefix.len() + message.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(message.as_bytes());
    keccak256(&data)
}

fn eth_address_from_key(sk: &Secp256k1SigningKey) -> [u8; 20] {
    let pk = sk.verifying_key().to_encoded_point(false);
    let hash = keccak256(&pk.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

fn eth_sign(sk: &Secp256k1SigningKey, digest: &[u8; 32]) -> String {
    let (sig, recid) = sk.sign_prehash(digest).expect("sign failed");
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = recid.to_byte() + 27;
    hex::encode(sig_bytes)
}

struct TestFixtures {
    eth_sk: Secp256k1SigningKey,
    address: [u8; 20],
    ed_sk: ed25519_dalek::SigningKey,
    ed_pk: ed25519_dalek::VerifyingKey,
    p256_sk: P256SigningKey,
    p256_pk_hex: String,
}

impl TestFixtures {
    fn new() -> Self {
        let eth_sk = Secp256k1SigningKey::random(&mut OsRng);
        let address = eth_address_from_key(&eth_sk);
        let ed_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let ed_pk = ed_sk.verifying_key();
        let p256_sk = P256SigningKey::random(&mut OsRng);
        let p256_pk_hex = hex::encode(p256_sk.verifying_key().to_sec1_bytes());
        Self { eth_sk, address, ed_sk, ed_pk, p256_sk, p256_pk_hex }
    }
}

fn build_register_key_input(fix: &TestFixtures, app: &mut AppState) -> ProgramInput {
    let pubkey_hex = hex::encode(fix.ed_pk.as_bytes());
    let key = SessionKey {
        pubkey: *fix.ed_pk.as_bytes(),
        key_index: 0,
    };

    let (old_leaf_hash, old_root, new_root, siblings, leaf_index) =
        app.register_key(fix.address, key);

    let message = register_key_message(&fix.address, fix.ed_pk.as_bytes(), 0);
    let digest = eip191_hash(&message);
    let eth_sig_hex = eth_sign(&fix.eth_sk, &digest);

    ProgramInput::RegisterKey(RegisterKeyWitness {
        request: RegisterKeyRequest {
            account_address: fix.address,
            key_index: 0,
            pubkey_hex,
            eth_signature_hex: eth_sig_hex,
        },
        old_leaf_hash,
        old_session_key_root: old_root,
        new_session_key_root: new_root,
        merkle_siblings: siblings,
        leaf_index,
    })
}

fn build_verify_order_input(fix: &TestFixtures, app: &AppState) -> ProgramInput {
    let (session_key, siblings, leaf_index) = app
        .get_key_proof(fix.address, 0)
        .expect("key not registered");
    let root = app.current_root;

    let order_msg_str = format!(
        "ETH/USDC:BUY:2000000:100:{}",
        hex::encode(fix.address)
    );
    let msg_bytes = order_msg_str.as_bytes();
    let hash = Sha256::digest(msg_bytes);

    let sig = fix.ed_sk.sign(&hash);
    let sig_hex = hex::encode(sig.to_bytes());

    let order = SignedOrder {
        account_address: fix.address,
        key_index: 0,
        market: "ETH/USDC".to_string(),
        side: "BUY".to_string(),
        price: 2000000,
        quantity: 100,
        ed25519_signature_hex: sig_hex,
    };

    ProgramInput::VerifyOrder(OrderWitness {
        order,
        session_key,
        session_key_root: root,
        merkle_siblings: siblings,
        leaf_index,
    })
}

fn build_verify_order_eth_input(fix: &TestFixtures) -> ProgramInput {
    let order_msg = format!(
        "ETH/USDC:BUY:2000000:100:{}",
        hex::encode(fix.address)
    );
    let digest = eip191_hash(&order_msg);
    let eth_sig_hex = eth_sign(&fix.eth_sk, &digest);

    let order = EthSignedOrder {
        account_address: fix.address,
        key_index: 0,
        market: "ETH/USDC".to_string(),
        side: "BUY".to_string(),
        price: 2000000,
        quantity: 100,
        eth_signature_hex: eth_sig_hex,
    };

    ProgramInput::VerifyOrderEth(EthOrderWitness { order })
}

fn build_verify_order_p256_input(fix: &TestFixtures) -> ProgramInput {
    let order_msg = format!(
        "ETH/USDC:BUY:2000000:100:{}",
        hex::encode(fix.address)
    );
    let hash = Sha256::digest(order_msg.as_bytes());
    let (sig, _): (p256::ecdsa::Signature, _) = fix.p256_sk.sign_prehash(&hash).expect("p256 sign failed");
    let sig_hex = hex::encode(sig.to_bytes());

    let order = P256SignedOrder {
        account_address: fix.address,
        key_index: 0,
        market: "ETH/USDC".to_string(),
        side: "BUY".to_string(),
        price: 2000000,
        quantity: 100,
        p256_signature_hex: sig_hex,
        p256_pubkey_hex: fix.p256_pk_hex.clone(),
    };

    ProgramInput::VerifyOrderP256(P256OrderWitness { order })
}

// ── Septic Schnorr helpers (host-side scalar arithmetic via num-bigint) ────

fn group_order_biguint() -> BigUint {
    BigUint::parse_bytes(
        b"199372529839252601278447397890876471698671718266839763841250021879",
        10,
    )
    .unwrap()
}

fn biguint_to_limbs(n: &BigUint) -> [u32; 8] {
    let digits = n.to_u32_digits();
    let mut limbs = [0u32; 8];
    for (i, &d) in digits.iter().enumerate().take(8) {
        limbs[i] = d;
    }
    limbs
}

fn random_scalar(r: &BigUint) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let k = BigUint::from_bytes_le(&bytes) % r;
        if !k.is_zero() {
            return k;
        }
    }
}

fn build_verify_order_septic_input(fix: &TestFixtures) -> ProgramInput {
    let r = group_order_biguint();
    let g = SepticPoint::generator();

    // Key pair: private scalar a, public point A = a*G
    let a_scalar = random_scalar(&r);
    let a_limbs = biguint_to_limbs(&a_scalar);
    let pubkey = g.scalar_mul(&a_limbs);
    assert!(pubkey.on_curve(), "host-generated pubkey must be on curve");

    // Message hash
    let order_msg = format!("ETH/USDC:BUY:2000000:100:{}", hex::encode(fix.address));
    let msg_hash = Sha256::digest(order_msg.as_bytes());

    // Nonce and commitment: k random, R = k*G
    let k = random_scalar(&r);
    let k_limbs = biguint_to_limbs(&k);
    let r_point = g.scalar_mul(&k_limbs);
    assert!(r_point.on_curve(), "host-generated R must be on curve");

    // Challenge e = SHA256(R_x || A_x || msg_hash) mod r
    let mut challenge_input = Vec::with_capacity(28 + 28 + 32);
    challenge_input.extend_from_slice(&r_point.x.to_bytes());
    challenge_input.extend_from_slice(&pubkey.x.to_bytes());
    challenge_input.extend_from_slice(&msg_hash);
    let e_hash = Sha256::digest(&challenge_input);
    let e_biguint = BigUint::from_bytes_be(&e_hash) % &r;
    let e_limbs = biguint_to_limbs(&e_biguint);

    // s = (k - e*a) mod r
    let ea = (&e_biguint * &a_scalar) % &r;
    let s_biguint = if k >= ea {
        (&k - &ea) % &r
    } else {
        (&k + &r - &ea) % &r
    };
    let s_limbs = biguint_to_limbs(&s_biguint);

    // Host-side sanity: s*G + e*A == R
    let s_g = g.scalar_mul(&s_limbs);
    let e_a = pubkey.scalar_mul(&e_limbs);
    let sum = s_g.add(&e_a);
    assert!(
        !sum.is_infinity && sum.x == r_point.x && sum.y == r_point.y,
        "host-side Schnorr self-check failed"
    );

    let order = SepticSchnorrOrder {
        account_address: fix.address,
        key_index: 0,
        market: "ETH/USDC".to_string(),
        side: "BUY".to_string(),
        price: 2000000,
        quantity: 100,
        signature: SepticSchnorrSignature {
            r_x: r_point.x,
            r_y: r_point.y,
            s: s_limbs,
        },
        pubkey_x: pubkey.x,
        pubkey_y: pubkey.y,
    };

    ProgramInput::VerifyOrderSeptic(SepticBenchWitness {
        order,
        challenge_e: e_limbs,
    })
}

fn build_batch_septic_input(fix: &TestFixtures, count: usize) -> ProgramInput {
    let r = group_order_biguint();
    let g = SepticPoint::generator();

    let mut orders = Vec::with_capacity(count);
    for i in 0..count {
        let a_scalar = random_scalar(&r);
        let a_limbs = biguint_to_limbs(&a_scalar);
        let pubkey = g.scalar_mul(&a_limbs);

        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(fix.address)
        );
        let msg_hash = Sha256::digest(order_msg.as_bytes());

        let k = random_scalar(&r);
        let k_limbs = biguint_to_limbs(&k);
        let r_point = g.scalar_mul(&k_limbs);

        let mut challenge_input = Vec::with_capacity(28 + 28 + 32);
        challenge_input.extend_from_slice(&r_point.x.to_bytes());
        challenge_input.extend_from_slice(&pubkey.x.to_bytes());
        challenge_input.extend_from_slice(&msg_hash);
        let e_hash = Sha256::digest(&challenge_input);
        let e_biguint = BigUint::from_bytes_be(&e_hash) % &r;
        let e_limbs = biguint_to_limbs(&e_biguint);

        let ea = (&e_biguint * &a_scalar) % &r;
        let s_biguint = if k >= ea {
            (&k - &ea) % &r
        } else {
            (&k + &r - &ea) % &r
        };
        let s_limbs = biguint_to_limbs(&s_biguint);

        let order = SepticSchnorrOrder {
            account_address: fix.address,
            key_index: 0,
            market: "ETH/USDC".to_string(),
            side: "BUY".to_string(),
            price: 2000000 + i as u64,
            quantity: 100 + (i % 50) as u64,
            signature: SepticSchnorrSignature {
                r_x: r_point.x,
                r_y: r_point.y,
                s: s_limbs,
            },
            pubkey_x: pubkey.x,
            pubkey_y: pubkey.y,
        };

        orders.push(SepticBenchWitness {
            order,
            challenge_e: e_limbs,
        });

        if count >= 500 && (i + 1) % 500 == 0 {
            println!("  generated {}/{}", i + 1, count);
        }
    }

    ProgramInput::BatchSeptic(BatchSepticWitness { orders })
}

fn build_batch_septic_opt_input(fix: &TestFixtures, count: usize) -> ProgramInput {
    // Witness data is identical to the naive batch — only the verification
    // algorithm inside the guest differs.
    match build_batch_septic_input(fix, count) {
        ProgramInput::BatchSeptic(w) => {
            ProgramInput::BatchSepticOpt(BatchSepticOptWitness { orders: w.orders })
        }
        _ => unreachable!("build_batch_septic_input returned non-BatchSeptic variant"),
    }
}

fn build_batch_septic_single_input(fix: &TestFixtures, count: usize) -> ProgramInput {
    match build_batch_septic_input(fix, count) {
        ProgramInput::BatchSeptic(w) => {
            ProgramInput::BatchSepticSingle(BatchSepticSingleWitness { orders: w.orders })
        }
        _ => unreachable!("build_batch_septic_input returned non-BatchSeptic variant"),
    }
}

fn build_batch_septic_opt_single_input(fix: &TestFixtures, count: usize) -> ProgramInput {
    match build_batch_septic_input(fix, count) {
        ProgramInput::BatchSeptic(w) => {
            ProgramInput::BatchSepticOptSingle(BatchSepticOptWitness { orders: w.orders })
        }
        _ => unreachable!("build_batch_septic_input returned non-BatchSeptic variant"),
    }
}

fn build_batch_septic_verify_input(fix: &TestFixtures, count: usize) -> ProgramInput {
    match build_batch_septic_input(fix, count) {
        ProgramInput::BatchSeptic(w) => {
            ProgramInput::BatchSepticVerify(BatchSepticVerifyWitness { orders: w.orders })
        }
        _ => unreachable!("build_batch_septic_input returned non-BatchSeptic variant"),
    }
}

fn build_batch_eth_input(fix: &TestFixtures, count: usize) -> ProgramInput {
    let mut orders = Vec::with_capacity(count);
    for i in 0..count {
        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(fix.address)
        );
        let digest = eip191_hash(&order_msg);
        let eth_sig_hex = eth_sign(&fix.eth_sk, &digest);

        let order = EthSignedOrder {
            account_address: fix.address,
            key_index: 0,
            market: "ETH/USDC".to_string(),
            side: "BUY".to_string(),
            price: 2000000 + i as u64,
            quantity: 100 + (i % 50) as u64,
            eth_signature_hex: eth_sig_hex,
        };

        orders.push(EthOrderWitness { order });
    }

    ProgramInput::BatchEth(BatchEthWitness { orders })
}

/// Bench host-side signature generation (excluding key generation).
///
/// For each scheme, a keypair is generated once up front, then `count`
/// fresh signatures are produced over distinct messages. Only the signing
/// loop is timed.
fn bench_signing(fix: &TestFixtures, count: usize) {
    use std::time::Instant;

    println!("\n============================================================");
    println!("  Host signing benchmark (count = {count}, key generation excluded)");
    println!("============================================================");

    // ── Septic Schnorr: generate key pair once, outside the timed section. ──
    let r = group_order_biguint();
    let g = SepticPoint::generator();
    let a_scalar = random_scalar(&r);
    let a_limbs = biguint_to_limbs(&a_scalar);
    let septic_pubkey = g.scalar_mul(&a_limbs);

    let start = Instant::now();
    for i in 0..count {
        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(fix.address)
        );
        let msg_hash = Sha256::digest(order_msg.as_bytes());

        // Nonce + commitment.
        let k = random_scalar(&r);
        let k_limbs = biguint_to_limbs(&k);
        let r_point = g.scalar_mul(&k_limbs);

        // Challenge.
        let mut challenge_input = Vec::with_capacity(28 + 28 + 32);
        challenge_input.extend_from_slice(&r_point.x.to_bytes());
        challenge_input.extend_from_slice(&septic_pubkey.x.to_bytes());
        challenge_input.extend_from_slice(&msg_hash);
        let e_hash = Sha256::digest(&challenge_input);
        let e_biguint = BigUint::from_bytes_be(&e_hash) % &r;

        // Response s = (k - e·a) mod r.
        let ea = (&e_biguint * &a_scalar) % &r;
        let _s = if k >= ea {
            (&k - &ea) % &r
        } else {
            (&k + &r - &ea) % &r
        };

        // Silence the optimizer.
        std::hint::black_box(&r_point);
        std::hint::black_box(&_s);
    }
    let septic_total = start.elapsed();
    let septic_per_sig = septic_total / count as u32;

    // ── secp256k1 ECDSA: fix.eth_sk already generated in TestFixtures. ──
    let start = Instant::now();
    for i in 0..count {
        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(fix.address)
        );
        let digest = eip191_hash(&order_msg);
        let sig = eth_sign(&fix.eth_sk, &digest);
        std::hint::black_box(sig);
    }
    let eth_total = start.elapsed();
    let eth_per_sig = eth_total / count as u32;

    println!(
        "  Septic Schnorr (Fp7, software):   total = {:>10.3?}   per-sig = {:>10.3?}",
        septic_total, septic_per_sig
    );
    println!(
        "  secp256k1 ECDSA (RustCrypto k256): total = {:>10.3?}   per-sig = {:>10.3?}",
        eth_total, eth_per_sig
    );
    let ratio = septic_per_sig.as_nanos() as f64 / eth_per_sig.as_nanos() as f64;
    println!("  Ratio (Schnorr / ECDSA):          {ratio:.2}×");
}

async fn run_and_report(label: &str, input: ProgramInput, elf: &[u8]) -> Result<()> {
    let client = ProverClient::builder().cpu().build().await;

    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    println!("\n============================================================");
    println!("  Profiling: {label}");
    println!("============================================================");

    let (mut public_values, report) = client
        .execute(Elf::from(elf), stdin)
        .await
        .map_err(|e| anyhow::anyhow!("execution failed: {e}"))?;

    let output: ProofOutput = public_values.read();

    let total = report.total_instruction_count() + report.total_syscall_count();
    let gas_opt = report.gas();
    println!("  proof_type:         {}", output.proof_type);
    println!("  total_instructions: {}", report.total_instruction_count());
    println!("  total_syscalls:     {}", report.total_syscall_count());
    println!("  total_cycles:       {total}");
    if let Some(gas) = gas_opt {
        let gas_per_cycle = gas as f64 / total as f64;
        println!("  gas (normalized):   {gas}  ({gas_per_cycle:.3} gas/cycle)");
    }
    println!("  touched_memory:     {}", report.touched_memory_addresses);

    if !report.cycle_tracker.is_empty() {
        println!("\n  Cycle tracker breakdown:");
        let header_gas = if gas_opt.is_some() { "gas (est.)" } else { "" };
        println!(
            "    {:<30} {:>12} {:>14} {:>7}",
            "section", "cycles", header_gas, "%"
        );
        let mut entries: Vec<_> = report.cycle_tracker.iter().collect();
        entries.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
        for (name, cycles) in entries {
            let pct = (*cycles as f64 / total as f64) * 100.0;
            let gas_est_str = match gas_opt {
                // Pro-rata by cycle share — SP1 doesn't track gas per section,
                // so this is a proportional estimate, not a measured value.
                Some(total_gas) => {
                    let est = (*cycles as u128 * total_gas as u128 / total as u128) as u64;
                    format!("{est}")
                }
                None => String::new(),
            };
            println!(
                "    {name:<30} {cycles:>12} {gas_est_str:>14} {pct:>6.1}%"
            );
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str());

    let fix = TestFixtures::new();
    let mut app = AppState::new();

    match mode {
        Some("register-key") => {
            let input = build_register_key_input(&fix, &mut app);
            run_and_report("RegisterKey", input, ELF).await?;
        }
        Some("verify-order") => {
            // Must register first to have a Merkle proof
            let _ = build_register_key_input(&fix, &mut app);
            let input = build_verify_order_input(&fix, &app);
            run_and_report("VerifyOrder (Ed25519)", input, ELF).await?;
        }
        Some("verify-order-eth") => {
            let input = build_verify_order_eth_input(&fix);
            run_and_report("VerifyOrderEth (secp256k1)", input, ELF).await?;
        }
        Some("verify-order-p256") => {
            let input = build_verify_order_p256_input(&fix);
            run_and_report("VerifyOrderP256 (P-256)", input, ELF).await?;
        }
        Some("verify-order-septic") => {
            let input = build_verify_order_septic_input(&fix);
            run_and_report("VerifyOrderSeptic (Schnorr/Fp7)", input, ELF).await?;
        }
        Some("batch-septic-10") => {
            let input = build_batch_septic_input(&fix, 10);
            run_and_report("BatchSeptic (10 Schnorr)", input, ELF).await?;
        }
        Some("batch-eth-10") => {
            let input = build_batch_eth_input(&fix, 10);
            run_and_report("BatchEth (10 ecrecover)", input, ELF).await?;
        }
        Some("batch-septic-2000") => {
            println!("\nGenerating 2000 septic Schnorr signatures (host-side, may take a minute)...");
            let input = build_batch_septic_input(&fix, 2000);
            run_and_report("BatchSeptic (2000 Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-opt-10") => {
            let input = build_batch_septic_opt_input(&fix, 10);
            run_and_report("BatchSepticOpt (10 batch Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-opt-2000") => {
            println!("\nGenerating 2000 septic signatures for batch Schnorr (host-side)...");
            let input = build_batch_septic_opt_input(&fix, 2000);
            run_and_report("BatchSepticOpt (2000 batch Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-single-10") => {
            let input = build_batch_septic_single_input(&fix, 10);
            run_and_report("BatchSepticSingle (10 naive/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-single-2000") => {
            println!("\nGenerating 2000 septic signatures for naive single-syscall (host-side)...");
            let input = build_batch_septic_single_input(&fix, 2000);
            run_and_report("BatchSepticSingle (2000 naive/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-opt-single-10") => {
            let input = build_batch_septic_opt_single_input(&fix, 10);
            run_and_report("BatchSepticOptSingle (10 batch-Schnorr/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-opt-single-2000") => {
            println!("\nGenerating 2000 septic signatures for batch Schnorr single-syscall (host-side)...");
            let input = build_batch_septic_opt_single_input(&fix, 2000);
            run_and_report("BatchSepticOptSingle (2000 batch-Schnorr/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-verify-10") => {
            let input = build_batch_septic_verify_input(&fix, 10);
            run_and_report("BatchSepticVerify (10 Shamir)", input, ELF).await?;
        }
        Some("batch-septic-verify-2000") => {
            println!("\nGenerating 2000 septic signatures for Shamir verify (host-side)...");
            let input = build_batch_septic_verify_input(&fix, 2000);
            run_and_report("BatchSepticVerify (2000 Shamir)", input, ELF).await?;
        }
        Some("batch-eth-2000") => {
            println!("\nGenerating 2000 secp256k1 signatures (host-side)...");
            let input = build_batch_eth_input(&fix, 2000);
            run_and_report("BatchEth (2000 ecrecover)", input, ELF).await?;
        }
        Some("batch-septic-opt-4000") => {
            println!("\nGenerating 4000 septic signatures for batch Schnorr (host-side)...");
            let input = build_batch_septic_opt_input(&fix, 4000);
            run_and_report("BatchSepticOpt (4000 batch Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-4000") => {
            println!("\nGenerating 4000 septic Schnorr signatures (host-side, may take a minute)...");
            let input = build_batch_septic_input(&fix, 4000);
            run_and_report("BatchSeptic (4000 Schnorr)", input, ELF).await?;
        }
        Some("batch-eth-4000") => {
            println!("\nGenerating 4000 secp256k1 signatures (host-side)...");
            let input = build_batch_eth_input(&fix, 4000);
            run_and_report("BatchEth (4000 ecrecover)", input, ELF).await?;
        }
        Some("bench-sign") => {
            bench_signing(&fix, 2000);
        }
        _ => {
            // Run all benchmarks
            let reg_input = build_register_key_input(&fix, &mut app);
            run_and_report("RegisterKey", reg_input, ELF).await?;

            let order_input = build_verify_order_input(&fix, &app);
            run_and_report("VerifyOrder (Ed25519)", order_input, ELF).await?;

            let eth_input = build_verify_order_eth_input(&fix);
            run_and_report("VerifyOrderEth (secp256k1)", eth_input, ELF).await?;

            let p256_input = build_verify_order_p256_input(&fix);
            run_and_report("VerifyOrderP256 (P-256)", p256_input, ELF).await?;

            let septic_input = build_verify_order_septic_input(&fix);
            run_and_report("VerifyOrderSeptic (Schnorr/Fp7)", septic_input, ELF).await?;

            println!("\n============================================================");
            println!("  Done. Compare VerifyOrder vs VerifyOrderEth vs VerifyOrderP256 vs VerifyOrderSeptic totals above.");
            println!("============================================================");
        }
    }

    Ok(())
}
