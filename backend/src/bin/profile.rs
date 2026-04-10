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
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use sp1_sdk::{Elf, ProverClient, Prover, SP1Stdin};

use shared::*;

// Re-use the backend's state module for building witnesses.
#[path = "../state.rs"]
mod state;
use state::AppState;

const ELF: &[u8] = include_bytes!("../../../program/elf/riscv64im-succinct-zkvm-elf");

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
}

impl TestFixtures {
    fn new() -> Self {
        let eth_sk = Secp256k1SigningKey::random(&mut OsRng);
        let address = eth_address_from_key(&eth_sk);
        let ed_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let ed_pk = ed_sk.verifying_key();
        Self { eth_sk, address, ed_sk, ed_pk }
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
    println!("  proof_type:         {}", output.proof_type);
    println!("  total_instructions: {}", report.total_instruction_count());
    println!("  total_syscalls:     {}", report.total_syscall_count());
    println!("  total_cycles:       {total}");
    if let Some(gas) = report.gas() {
        println!("  gas (normalized):   {gas}");
    }
    println!("  touched_memory:     {}", report.touched_memory_addresses);

    if !report.cycle_tracker.is_empty() {
        println!("\n  Cycle tracker breakdown:");
        let mut entries: Vec<_> = report.cycle_tracker.iter().collect();
        entries.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
        for (name, cycles) in entries {
            let pct = (*cycles as f64 / total as f64) * 100.0;
            println!("    {name:<30} {cycles:>12} ({pct:.1}%)");
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
        _ => {
            // Run all three
            let reg_input = build_register_key_input(&fix, &mut app);
            run_and_report("RegisterKey", reg_input, ELF).await?;

            let order_input = build_verify_order_input(&fix, &app);
            run_and_report("VerifyOrder (Ed25519)", order_input, ELF).await?;

            let eth_input = build_verify_order_eth_input(&fix);
            run_and_report("VerifyOrderEth (secp256k1)", eth_input, ELF).await?;

            println!("\n============================================================");
            println!("  Done. Compare VerifyOrder vs VerifyOrderEth totals above.");
            println!("============================================================");
        }
    }

    Ok(())
}
