//! Profiling binary for SP1 cycle counting.
//!
//! Usage:
//!   # All proof types:
//!   TRACE_FILE=all.json cargo run --release --bin profile
//!
//!   # Single proof type:
//!   TRACE_FILE=register.json cargo run --release --bin profile -- register-key
//!   TRACE_FILE=order.json cargo run --release --bin profile -- verify-order
//!   TRACE_FILE=order_eth.json cargo run --release --bin profile -- verify-order-eth
//!
//!   # View in samply:
//!   samply load all.json

use std::env;

use anyhow::Result;
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use num_bigint::BigUint;
use num_traits::Zero;
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

/// Session-key pair: (private scalar, public point) on the septic curve.
#[derive(Clone)]
struct SessionPair {
    priv_scalar: BigUint,
    pubkey: SepticPoint,
}

fn make_session_pair() -> SessionPair {
    let r = group_order_biguint();
    let g = SepticPoint::generator();
    let priv_scalar = random_scalar(&r);
    let priv_limbs = biguint_to_limbs(&priv_scalar);
    let pubkey = g.scalar_mul(&priv_limbs);
    assert!(pubkey.on_curve(), "host-generated pubkey must be on curve");
    SessionPair { priv_scalar, pubkey }
}

/// Schnorr-sign `msg_hash` with `session` and return (r_point, s_limbs, e_limbs).
fn schnorr_sign(session: &SessionPair, msg_hash: &[u8; 32]) -> ([u32; 7], [u32; 7], [u32; 8], [u32; 8]) {
    let r = group_order_biguint();
    let g = SepticPoint::generator();

    let k = random_scalar(&r);
    let k_limbs = biguint_to_limbs(&k);
    let r_point = g.scalar_mul(&k_limbs);

    let mut challenge_input = Vec::with_capacity(28 + 28 + 32);
    challenge_input.extend_from_slice(&r_point.x.to_bytes());
    challenge_input.extend_from_slice(&session.pubkey.x.to_bytes());
    challenge_input.extend_from_slice(msg_hash);
    let e_hash = Sha256::digest(&challenge_input);
    let e_biguint = BigUint::from_bytes_be(&e_hash) % &r;
    let e_limbs = biguint_to_limbs(&e_biguint);

    let ea = (&e_biguint * &session.priv_scalar) % &r;
    let s_biguint = if k >= ea {
        (&k - &ea) % &r
    } else {
        (&k + &r - &ea) % &r
    };
    let s_limbs = biguint_to_limbs(&s_biguint);

    // Host-side sanity: s*G + e*A == R
    let s_g = g.scalar_mul(&s_limbs);
    let e_a = session.pubkey.scalar_mul(&e_limbs);
    let sum = s_g.add(&e_a);
    assert!(
        !sum.is_infinity && sum.x == r_point.x && sum.y == r_point.y,
        "host-side Schnorr self-check failed"
    );

    (r_point.x.0, r_point.y.0, s_limbs, e_limbs)
}

struct TestFixtures {
    eth_sk: Secp256k1SigningKey,
    address: [u8; 20],
    session: SessionPair,
}

impl TestFixtures {
    fn new() -> Self {
        let eth_sk = Secp256k1SigningKey::random(&mut OsRng);
        let address = eth_address_from_key(&eth_sk);
        let session = make_session_pair();
        Self { eth_sk, address, session }
    }
}

fn build_register_key_input(fix: &TestFixtures, app: &mut AppState) -> ProgramInput {
    let pubkey_x = fix.session.pubkey.x.0;
    let pubkey_y = fix.session.pubkey.y.0;
    let key = SessionKey {
        pubkey_x,
        pubkey_y,
        key_index: 0,
    };

    let result = app
        .register_key(fix.address, key)
        .expect("register_key failed");

    let message = register_key_message(&fix.address, &pubkey_x, &pubkey_y, 0);
    let digest = eip191_hash(&message);
    let eth_sig_hex = eth_sign(&fix.eth_sk, &digest);

    ProgramInput::RegisterKey(RegisterKeyWitness {
        request: RegisterKeyRequest {
            account_address: fix.address,
            key_index: 0,
            pubkey_x,
            pubkey_y,
            eth_signature_hex: eth_sig_hex,
        },
        old_session_key_root: result.old_root,
        new_session_key_root: result.new_root,
        old_proof: result.old_proof,
        old_leaf: result.old_leaf,
    })
}

fn build_verify_order_input(fix: &TestFixtures, app: &AppState) -> ProgramInput {
    let proof = app
        .get_key_proof(fix.address, 0)
        .expect("key not registered");

    let order_msg_str = format!(
        "ETH/USDC:BUY:2000000:100:{}",
        hex::encode(fix.address)
    );
    let msg_hash: [u8; 32] = Sha256::digest(order_msg_str.as_bytes()).into();
    let (r_x, r_y, s_limbs, e_limbs) = schnorr_sign(&fix.session, &msg_hash);

    let order = SignedOrder {
        account_address: fix.address,
        key_index: 0,
        market: "ETH/USDC".to_string(),
        side: "BUY".to_string(),
        price: 2000000,
        quantity: 100,
        signature_r_x: r_x,
        signature_r_y: r_y,
        signature_s: s_limbs,
        challenge_e: e_limbs,
    };

    ProgramInput::VerifyOrder(OrderWitness {
        order,
        session_key: proof.key,
        session_key_root: proof.root,
        merkle_proof: proof.proof,
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

fn build_verify_order_septic_input(fix: &TestFixtures, app: &AppState) -> ProgramInput {
    // Reuse the registered key's JMT proof so this path is apples-to-apples
    // with `build_verify_order_input` (same tree, same session key, same
    // proof) — only the scalar-mul strategy in the guest differs.
    let proof = app
        .get_key_proof(fix.address, 0)
        .expect("key not registered — call build_register_key_input first");

    let order_msg = format!("ETH/USDC:BUY:2000000:100:{}", hex::encode(fix.address));
    let msg_hash: [u8; 32] = Sha256::digest(order_msg.as_bytes()).into();

    let (r_x, r_y, s_limbs, e_limbs) = schnorr_sign(&fix.session, &msg_hash);

    let order = SepticSchnorrOrder {
        account_address: fix.address,
        key_index: 0,
        market: "ETH/USDC".to_string(),
        side: "BUY".to_string(),
        price: 2000000,
        quantity: 100,
        signature: SepticSchnorrSignature {
            r_x: shared::septic::Fp7(r_x),
            r_y: shared::septic::Fp7(r_y),
            s: s_limbs,
        },
        pubkey_x: fix.session.pubkey.x,
        pubkey_y: fix.session.pubkey.y,
    };

    let bench = SepticBenchWitness {
        order,
        challenge_e: e_limbs,
    };

    ProgramInput::VerifyOrderSeptic(VerifyOrderSepticWitness {
        bench,
        session_key_root: proof.root,
        merkle_proof: proof.proof,
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

/// Build a deduped batch:
///   - `tree_size`   total keys inserted into a fresh JMT (drives proof depth).
///   - `unique_count` keys (the first slice) are referenced by the batch and
///                   carry inclusion proofs in the witness.
///   - `count`       total orders, randomly distributed across the
///                   `unique_count` referenced keys (first `unique_count`
///                   orders introduce a fresh key, then random reuse, then
///                   shuffle).
///
/// `tree_size == unique_count` is the original behavior (proof depth tracks
/// the batch's unique-key count). `tree_size > unique_count` lets the
/// benchmark hold the JMT depth fixed (e.g., 6000-key tree) while varying
/// how much per-batch dedup the workload exposes (e.g., 200 unique keys).
fn build_batch_septic_dedup_input(
    count: usize,
    unique_count: usize,
    tree_size: usize,
) -> ProgramInput {
    use jmt::mock::MockTreeStore;
    use jmt::{JellyfishMerkleTree, KeyHash};
    use rand::seq::SliceRandom;
    use rand::Rng;
    use shared::{encode_session_key_leaf, session_key_hash, Poseidon2Hasher};

    assert!(unique_count >= 1, "unique_count must be >= 1");
    assert!(
        unique_count <= tree_size,
        "unique_count ({}) must be <= tree_size ({})",
        unique_count,
        tree_size
    );

    println!(
        "  Dedup config: {} orders, {} unique keys in batch, {} keys in JMT (depth ~{})",
        count,
        unique_count,
        tree_size,
        ((tree_size as f64).log2().ceil() as usize).max(0),
    );

    // 1. Generate `tree_size` session pairs + synthetic addresses + JMT leaves.
    let mut session_pairs: Vec<(SessionPair, [u8; 20], u8)> = Vec::with_capacity(tree_size);
    let mut value_set: Vec<(KeyHash, Option<Vec<u8>>)> = Vec::with_capacity(tree_size);

    for i in 0..tree_size {
        let session = make_session_pair();
        let mut address = [0u8; 20];
        address[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let key_index = 0u8;

        let leaf = SessionKeyLeaf {
            account_address: address,
            key_index,
            pubkey_x: session.pubkey.x.0,
            pubkey_y: session.pubkey.y.0,
        };
        let leaf_value = encode_session_key_leaf(&leaf);
        let key_hash = KeyHash(session_key_hash(&address, key_index));
        value_set.push((key_hash, Some(leaf_value)));

        session_pairs.push((session, address, key_index));

        if tree_size >= 500 && (i + 1) % 500 == 0 {
            println!("  generated {}/{} keys for JMT", i + 1, tree_size);
        }
    }

    // 2. Batch-insert all `tree_size` keys into a fresh JMT at version 1.
    let store = MockTreeStore::default();
    let (root, batch) = {
        let tree: JellyfishMerkleTree<MockTreeStore, Poseidon2Hasher> =
            JellyfishMerkleTree::new(&store);
        tree.put_value_set(value_set, 1).expect("dedup put_value_set")
    };
    store
        .write_tree_update_batch(batch)
        .expect("dedup write_tree_update_batch");

    // 3. Pull JMT inclusion proofs for the FIRST `unique_count` keys — these
    //    are the only ones the batch references. Remaining (tree_size -
    //    unique_count) tree entries just contribute to depth.
    let unique_keys: Vec<DedupKey> = {
        let tree: JellyfishMerkleTree<MockTreeStore, Poseidon2Hasher> =
            JellyfishMerkleTree::new(&store);
        session_pairs
            .iter()
            .take(unique_count)
            .map(|(session, address, key_index)| {
                let key_hash = KeyHash(session_key_hash(address, *key_index));
                let (_value, proof) = tree
                    .get_with_proof(key_hash, 1)
                    .expect("dedup get_with_proof");
                DedupKey {
                    account_address: *address,
                    key_index: *key_index,
                    pubkey_x: session.pubkey.x.0,
                    pubkey_y: session.pubkey.y.0,
                    merkle_proof: proof,
                }
            })
            .collect()
    };

    // 4. Generate `count` orders against the first `unique_count` keys. First
    //    `unique_count` orders introduce a fresh key; remainder pick a
    //    previously-used unique-key index at random.
    let mut rng = rand::rngs::OsRng;
    let mut orders = Vec::with_capacity(count);
    for i in 0..count {
        let key_idx: usize = if i < unique_count {
            i
        } else {
            rng.gen_range(0..unique_count)
        };
        let (session, address, _key_index) = &session_pairs[key_idx];
        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(address)
        );
        let msg_hash: [u8; 32] = Sha256::digest(order_msg.as_bytes()).into();
        let (r_x, r_y, s_limbs, e_limbs) = schnorr_sign(session, &msg_hash);

        orders.push(DedupOrder {
            key_idx: key_idx as u32,
            market: "ETH/USDC".to_string(),
            side: "BUY".to_string(),
            price: 2000000 + i as u64,
            quantity: 100 + (i % 50) as u64,
            signature_r_x: r_x,
            signature_r_y: r_y,
            signature_s: s_limbs,
            challenge_e: e_limbs,
        });

        if count >= 500 && (i + 1) % 500 == 0 {
            println!("  generated {}/{} orders", i + 1, count);
        }
    }

    // Shuffle so reused keys aren't all clustered at the end.
    orders.shuffle(&mut rng);

    ProgramInput::BatchSepticDedup(BatchSepticDedupWitness {
        unique_keys,
        orders,
        session_key_root: root.0,
    })
}

/// Same shape as `build_batch_septic_dedup_input`, but emits a
/// `BatchSepticDedupBatchWitness` that wraps all unique-key proofs in
/// a single `BatchExistenceProof`. Tree construction and order
/// distribution are identical, so cycle-count deltas against the
/// non-batch builder isolate the `BatchExistenceProof::verify` win.
fn build_batch_septic_dedup_batch_input(
    count: usize,
    unique_count: usize,
    tree_size: usize,
) -> ProgramInput {
    use jmt::mock::MockTreeStore;
    use jmt::{build_batch_existence_proof, JellyfishMerkleTree, KeyHash};
    use rand::seq::SliceRandom;
    use rand::Rng;
    use shared::{
        encode_session_key_leaf, session_key_hash, BatchSepticDedupBatchWitness, Poseidon2Hasher,
        UniqueKeyInfo,
    };

    assert!(unique_count >= 1, "unique_count must be >= 1");
    assert!(
        unique_count <= tree_size,
        "unique_count ({}) must be <= tree_size ({})",
        unique_count,
        tree_size
    );

    println!(
        "  DedupBatch config: {} orders, {} unique in batch, {} keys in JMT (depth ~{})",
        count,
        unique_count,
        tree_size,
        ((tree_size as f64).log2().ceil() as usize).max(0),
    );

    // 1. Generate `tree_size` session pairs + addresses + JMT leaves.
    let mut session_pairs: Vec<(SessionPair, [u8; 20], u8)> = Vec::with_capacity(tree_size);
    let mut value_set: Vec<(KeyHash, Option<Vec<u8>>)> = Vec::with_capacity(tree_size);

    for i in 0..tree_size {
        let session = make_session_pair();
        let mut address = [0u8; 20];
        address[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let key_index = 0u8;

        let leaf = SessionKeyLeaf {
            account_address: address,
            key_index,
            pubkey_x: session.pubkey.x.0,
            pubkey_y: session.pubkey.y.0,
        };
        let leaf_value = encode_session_key_leaf(&leaf);
        let key_hash = KeyHash(session_key_hash(&address, key_index));
        value_set.push((key_hash, Some(leaf_value)));

        session_pairs.push((session, address, key_index));

        if tree_size >= 500 && (i + 1) % 500 == 0 {
            println!("  generated {}/{} keys for JMT", i + 1, tree_size);
        }
    }

    // 2. Insert all keys at version 1.
    let store = MockTreeStore::default();
    let (root, batch_update) = {
        let tree: JellyfishMerkleTree<MockTreeStore, Poseidon2Hasher> =
            JellyfishMerkleTree::new(&store);
        tree.put_value_set(value_set, 1)
            .expect("dedup-batch put_value_set")
    };
    store
        .write_tree_update_batch(batch_update)
        .expect("dedup-batch write_tree_update_batch");

    // 3. Pull individual inclusion proofs for the first `unique_count` keys,
    //    then fold them into a BatchExistenceProof.
    let tree: JellyfishMerkleTree<MockTreeStore, Poseidon2Hasher> =
        JellyfishMerkleTree::new(&store);
    let mut proof_entries: Vec<(
        KeyHash,
        Vec<u8>,
        jmt::proof::SparseMerkleProof<Poseidon2Hasher>,
    )> = Vec::with_capacity(unique_count);
    let mut key_infos: Vec<UniqueKeyInfo> = Vec::with_capacity(unique_count);

    for (session, address, key_index) in session_pairs.iter().take(unique_count) {
        let key_hash = KeyHash(session_key_hash(address, *key_index));
        let (value_opt, proof) = tree
            .get_with_proof(key_hash, 1)
            .expect("dedup-batch get_with_proof");
        let value = value_opt.expect("key was just inserted, should exist");
        proof_entries.push((key_hash, value, proof));
        key_infos.push(UniqueKeyInfo {
            account_address: *address,
            key_index: *key_index,
            pubkey_x: session.pubkey.x.0,
            pubkey_y: session.pubkey.y.0,
        });
    }

    let batch_proof = build_batch_existence_proof(proof_entries);

    // 4. Same order-distribution logic as the non-batch dedup builder.
    let mut rng = rand::rngs::OsRng;
    let mut orders = Vec::with_capacity(count);
    for i in 0..count {
        let key_idx: usize = if i < unique_count {
            i
        } else {
            rng.gen_range(0..unique_count)
        };
        let (session, address, _key_index) = &session_pairs[key_idx];
        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(address)
        );
        let msg_hash: [u8; 32] = Sha256::digest(order_msg.as_bytes()).into();
        let (r_x, r_y, s_limbs, e_limbs) = schnorr_sign(session, &msg_hash);

        orders.push(DedupOrder {
            key_idx: key_idx as u32,
            market: "ETH/USDC".to_string(),
            side: "BUY".to_string(),
            price: 2000000 + i as u64,
            quantity: 100 + (i % 50) as u64,
            signature_r_x: r_x,
            signature_r_y: r_y,
            signature_s: s_limbs,
            challenge_e: e_limbs,
        });

        if count >= 500 && (i + 1) % 500 == 0 {
            println!("  generated {}/{} orders", i + 1, count);
        }
    }
    orders.shuffle(&mut rng);

    ProgramInput::BatchSepticDedupBatch(BatchSepticDedupBatchWitness {
        session_key_root: root.0,
        batch_proof,
        unique_keys: key_infos,
        orders,
    })
}

/// Build a Merkle-checked batch using one already-registered session key.
/// All `count` orders share the same JMT proof — same key, same tree
/// snapshot, same root. Per-order JMT work in the guest is identical
/// regardless of whether proofs are unique or duplicated.
fn build_batch_septic_verify_merkle_input(
    fix: &TestFixtures,
    app: &AppState,
    count: usize,
) -> ProgramInput {
    let proof = app
        .get_key_proof(fix.address, 0)
        .expect("key not registered — call build_register_key_input first");

    let mut orders = Vec::with_capacity(count);
    for i in 0..count {
        let order_msg = format!(
            "ETH/USDC:BUY:{}:{}:{}",
            2000000 + i,
            100 + (i % 50),
            hex::encode(fix.address)
        );
        let msg_hash: [u8; 32] = Sha256::digest(order_msg.as_bytes()).into();
        let (r_x, r_y, s_limbs, e_limbs) = schnorr_sign(&fix.session, &msg_hash);

        let order = SepticSchnorrOrder {
            account_address: fix.address,
            key_index: 0,
            market: "ETH/USDC".to_string(),
            side: "BUY".to_string(),
            price: 2000000 + i as u64,
            quantity: 100 + (i % 50) as u64,
            signature: SepticSchnorrSignature {
                r_x: shared::septic::Fp7(r_x),
                r_y: shared::septic::Fp7(r_y),
                s: s_limbs,
            },
            pubkey_x: fix.session.pubkey.x,
            pubkey_y: fix.session.pubkey.y,
        };
        let bench = SepticBenchWitness {
            order,
            challenge_e: e_limbs,
        };
        orders.push(SepticMerkleOrder {
            bench,
            merkle_proof: proof.proof.clone(),
        });

        if count >= 500 && (i + 1) % 500 == 0 {
            println!("  generated {}/{}", i + 1, count);
        }
    }

    ProgramInput::BatchSepticVerifyMerkle(BatchSepticVerifyMerkleWitness {
        orders,
        session_key_root: proof.root,
    })
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
fn bench_signing(fix: &TestFixtures, count: usize) {
    use std::time::Instant;

    println!("\n============================================================");
    println!("  Host signing benchmark (count = {count}, key generation excluded)");
    println!("============================================================");

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

        let k = random_scalar(&r);
        let k_limbs = biguint_to_limbs(&k);
        let r_point = g.scalar_mul(&k_limbs);

        let mut challenge_input = Vec::with_capacity(28 + 28 + 32);
        challenge_input.extend_from_slice(&r_point.x.to_bytes());
        challenge_input.extend_from_slice(&septic_pubkey.x.to_bytes());
        challenge_input.extend_from_slice(&msg_hash);
        let e_hash = Sha256::digest(&challenge_input);
        let e_biguint = BigUint::from_bytes_be(&e_hash) % &r;

        let ea = (&e_biguint * &a_scalar) % &r;
        let _s = if k >= ea {
            (&k - &ea) % &r
        } else {
            (&k + &r - &ea) % &r
        };

        std::hint::black_box(&r_point);
        std::hint::black_box(&_s);
    }
    let septic_total = start.elapsed();
    let septic_per_sig = septic_total / count as u32;

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

    // borsh wire format (faster than bincode in the zkVM).
    let input_bytes = borsh::to_vec(&input).expect("borsh serialize input");
    let input_size = input_bytes.len();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes);

    println!("\n============================================================");
    println!("  Profiling: {label}");
    println!("============================================================");
    println!("  input_size:         {input_size} bytes (borsh)");

    let (public_values, report) = client
        .execute(Elf::from(elf), stdin)
        .await
        .map_err(|e| anyhow::anyhow!("execution failed: {e}"))?;

    let output: ProofOutput =
        borsh::from_slice(public_values.as_slice()).expect("borsh deserialize public output");

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
            run_and_report("VerifyOrder (Septic Schnorr + Merkle)", input, ELF).await?;
        }
        Some("verify-order-eth") => {
            let input = build_verify_order_eth_input(&fix);
            run_and_report("VerifyOrderEth (secp256k1)", input, ELF).await?;
        }
        Some("verify-order-septic") => {
            // Register the key first so the Merkle proof is well-formed.
            let _ = build_register_key_input(&fix, &mut app);
            let input = build_verify_order_septic_input(&fix, &app);
            run_and_report("VerifyOrderSeptic (Schnorr/Fp7 + Merkle, per-bit scalar_mul)", input, ELF).await?;
        }
        Some("batch-septic-1") => {
            let input = build_batch_septic_input(&fix, 1);
            run_and_report("BatchSeptic (1 Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-opt-1") => {
            let input = build_batch_septic_opt_input(&fix, 1);
            run_and_report("BatchSepticOpt (1 batch Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-single-1") => {
            let input = build_batch_septic_single_input(&fix, 1);
            run_and_report("BatchSepticSingle (1 naive/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-opt-single-1") => {
            let input = build_batch_septic_opt_single_input(&fix, 1);
            run_and_report("BatchSepticOptSingle (1 batch-Schnorr/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-verify-1") => {
            let input = build_batch_septic_verify_input(&fix, 1);
            run_and_report("BatchSepticVerify (1 Shamir)", input, ELF).await?;
        }
        Some("batch-eth-1") => {
            let input = build_batch_eth_input(&fix, 1);
            run_and_report("BatchEth (1 ecrecover)", input, ELF).await?;
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
        Some("batch-septic-6000") => {
            println!("\nGenerating 6000 septic Schnorr signatures (host-side, may take a few minutes)...");
            let input = build_batch_septic_input(&fix, 6000);
            run_and_report("BatchSeptic (6000 Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-opt-6000") => {
            println!("\nGenerating 6000 septic signatures for batch Schnorr (host-side)...");
            let input = build_batch_septic_opt_input(&fix, 6000);
            run_and_report("BatchSepticOpt (6000 batch Schnorr)", input, ELF).await?;
        }
        Some("batch-septic-single-6000") => {
            println!("\nGenerating 6000 septic signatures for naive single-syscall (host-side)...");
            let input = build_batch_septic_single_input(&fix, 6000);
            run_and_report("BatchSepticSingle (6000 naive/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-opt-single-6000") => {
            println!("\nGenerating 6000 septic signatures for batch Schnorr single-syscall (host-side)...");
            let input = build_batch_septic_opt_single_input(&fix, 6000);
            run_and_report("BatchSepticOptSingle (6000 batch-Schnorr/single-syscall)", input, ELF).await?;
        }
        Some("batch-septic-verify-6000") => {
            println!("\nGenerating 6000 septic signatures for Shamir verify (host-side)...");
            let input = build_batch_septic_verify_input(&fix, 6000);
            run_and_report("BatchSepticVerify (6000 Shamir)", input, ELF).await?;
        }
        Some("batch-eth-6000") => {
            println!("\nGenerating 6000 secp256k1 signatures (host-side)...");
            let input = build_batch_eth_input(&fix, 6000);
            run_and_report("BatchEth (6000 ecrecover)", input, ELF).await?;
        }
        Some("batch-septic-verify-merkle-1") => {
            let _ = build_register_key_input(&fix, &mut app);
            let input = build_batch_septic_verify_merkle_input(&fix, &app, 1);
            run_and_report("BatchSepticVerifyMerkle (1 Shamir + Merkle)", input, ELF).await?;
        }
        Some("batch-septic-verify-merkle-10") => {
            let _ = build_register_key_input(&fix, &mut app);
            let input = build_batch_septic_verify_merkle_input(&fix, &app, 10);
            run_and_report("BatchSepticVerifyMerkle (10 Shamir + Merkle)", input, ELF).await?;
        }
        Some("batch-septic-verify-merkle-2000") => {
            let _ = build_register_key_input(&fix, &mut app);
            println!("\nGenerating 2000 septic Schnorr + Merkle witnesses (host-side)...");
            let input = build_batch_septic_verify_merkle_input(&fix, &app, 2000);
            run_and_report("BatchSepticVerifyMerkle (2000 Shamir + Merkle)", input, ELF).await?;
        }
        Some("batch-septic-verify-merkle-6000") => {
            let _ = build_register_key_input(&fix, &mut app);
            println!("\nGenerating 6000 septic Schnorr + Merkle witnesses (host-side)...");
            let input = build_batch_septic_verify_merkle_input(&fix, &app, 6000);
            run_and_report("BatchSepticVerifyMerkle (6000 Shamir + Merkle)", input, ELF).await?;
        }
        Some(s) if s.starts_with("batch-septic-dedup-batch-") => {
            // Same args as `batch-septic-dedup-<count>` but uses
            // `BatchExistenceProof` (one JMT verify, cached hashes).
            //   batch-septic-dedup-batch-6000 0.9667 6000  → 6000 orders,
            //   ~200 unique keys, JMT holds 6000 keys.
            let count: usize = s
                .trim_start_matches("batch-septic-dedup-batch-")
                .parse()
                .expect("expected batch-septic-dedup-batch-<count>");
            let ratio: f64 = args
                .get(2)
                .map(|s| s.parse().expect("ratio must be a number in [0, 1]"))
                .unwrap_or(0.2);
            assert!((0.0..=1.0).contains(&ratio), "ratio must be in [0, 1]");
            let unique_count = (((count as f64) * (1.0 - ratio)).ceil() as usize).max(1);
            let tree_size: usize = args
                .get(3)
                .map(|s| s.parse().expect("tree_size must be a positive int"))
                .unwrap_or(unique_count);
            assert!(
                tree_size >= unique_count,
                "tree_size ({}) must be >= unique_count ({})",
                tree_size,
                unique_count
            );
            println!(
                "\nGenerating {} septic witnesses via BatchExistenceProof (unique={}, JMT size={})...",
                count, unique_count, tree_size
            );
            let input = build_batch_septic_dedup_batch_input(count, unique_count, tree_size);
            run_and_report(
                &format!(
                    "BatchSepticDedupBatch ({} orders, {} unique in batch, {} in JMT)",
                    count, unique_count, tree_size
                ),
                input,
                ELF,
            )
            .await?;
        }
        Some(s) if s.starts_with("batch-septic-dedup-") => {
            // Mode form: `batch-septic-dedup-<count> [ratio] [tree_size]`
            //   batch-septic-dedup-6000              → 6000 orders, 20% repeat,
            //                                          tree_size = unique_count
            //   batch-septic-dedup-6000 0.5          → 6000 orders, 50% repeat,
            //                                          tree_size = unique_count
            //   batch-septic-dedup-6000 0.9667 6000  → 6000 orders, ~200 unique
            //                                          keys in batch, JMT holds
            //                                          6000 keys (depth ~13)
            let count: usize = s
                .trim_start_matches("batch-septic-dedup-")
                .parse()
                .expect("expected batch-septic-dedup-<count>");
            let ratio: f64 = args
                .get(2)
                .map(|s| s.parse().expect("ratio must be a number in [0, 1]"))
                .unwrap_or(0.2);
            assert!((0.0..=1.0).contains(&ratio), "ratio must be in [0, 1]");
            let unique_count = (((count as f64) * (1.0 - ratio)).ceil() as usize).max(1);
            let tree_size: usize = args
                .get(3)
                .map(|s| s.parse().expect("tree_size must be a positive int"))
                .unwrap_or(unique_count);
            assert!(
                tree_size >= unique_count,
                "tree_size ({}) must be >= unique_count ({})",
                tree_size,
                unique_count
            );
            println!(
                "\nGenerating {} septic witnesses (batch unique={}, JMT size={})...",
                count, unique_count, tree_size
            );
            let input = build_batch_septic_dedup_input(count, unique_count, tree_size);
            run_and_report(
                &format!(
                    "BatchSepticDedup ({} orders, {} unique in batch, {} in JMT)",
                    count, unique_count, tree_size
                ),
                input,
                ELF,
            )
            .await?;
        }
        Some("bench-sign") => {
            bench_signing(&fix, 2000);
        }
        _ => {
            // Run all benchmarks
            let reg_input = build_register_key_input(&fix, &mut app);
            run_and_report("RegisterKey", reg_input, ELF).await?;

            let order_input = build_verify_order_input(&fix, &app);
            run_and_report("VerifyOrder (Septic Schnorr + Merkle)", order_input, ELF).await?;

            let eth_input = build_verify_order_eth_input(&fix);
            run_and_report("VerifyOrderEth (secp256k1)", eth_input, ELF).await?;

            let septic_input = build_verify_order_septic_input(&fix, &app);
            run_and_report(
                "VerifyOrderSeptic (Schnorr/Fp7 + Merkle, per-bit scalar_mul)",
                septic_input,
                ELF,
            )
            .await?;

            println!("\n============================================================");
            println!("  Done. Compare VerifyOrder vs VerifyOrderEth vs VerifyOrderSeptic totals above.");
            println!("============================================================");
        }
    }

    Ok(())
}
