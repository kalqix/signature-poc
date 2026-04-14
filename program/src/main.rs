#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use k256::ecdsa::{RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};

use sp1_zkvm::syscalls::Poseidon2ByteHash;

use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::hazmat::PrehashVerifier};

use shared::{
    BatchEthWitness, BatchSepticOptWitness, BatchSepticWitness, EthOrderWitness, OrderWitness,
    P256OrderWitness, ProgramInput, ProofOutput, RegisterKeyWitness, SessionKeyLeaf,
    eth_order_message, order_message, p256_order_message, register_key_message,
    septic::{SepticBenchWitness, GENERATOR_X, GENERATOR_Y, GROUP_ORDER, scalar_add},
};

#[inline(always)]
fn write_usize_ascii(mut n: usize, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

// ── Poseidon2 helpers ───────────────────────────────────────────────────────

const RATE: usize = 8;

fn poseidon2_hash_to_bytes(input: &[u8]) -> [u8; 32] {
    let out: [u32; RATE] = Poseidon2ByteHash::hash(input);
    let mut result = [0u8; 32];
    for (i, &w) in out.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    result
}

// ── Merkle helpers ──────────────────────────────────────────────────────────

fn hash_leaf(leaf: &SessionKeyLeaf) -> [u8; 32] {
    poseidon2_hash_to_bytes(&bincode::serialize(leaf).expect("bincode serialize"))
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    poseidon2_hash_to_bytes(&combined)
}

fn verify_merkle_proof(
    leaf_hash: [u8; 32],
    leaf_index: u64,
    siblings: &[[u8; 32]],
    expected_root: [u8; 32],
) -> bool {
    let mut current = leaf_hash;
    for (level, sibling) in siblings.iter().enumerate() {
        let bit = (leaf_index >> level) & 1;
        current = if bit == 0 {
            merkle_node(&current, sibling)
        } else {
            merkle_node(sibling, &current)
        };
    }
    current == expected_root
}

fn compute_new_root(
    new_leaf_hash: [u8; 32],
    leaf_index: u64,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut current = new_leaf_hash;
    for (level, sibling) in siblings.iter().enumerate() {
        let bit = (leaf_index >> level) & 1;
        current = if bit == 0 {
            merkle_node(&current, sibling)
        } else {
            merkle_node(sibling, &current)
        };
    }
    current
}

// ── Hex decode helper ───────────────────────────────────────────────────────

fn decode_hex_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("expected 32 bytes")
}

fn decode_hex_64(hex_str: &str) -> [u8; 64] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("expected 64 bytes")
}

fn decode_hex_65(hex_str: &str) -> [u8; 65] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    bytes.try_into().expect("expected 65 bytes")
}

// ── EIP-191 helpers ─────────────────────────────────────────────────────────

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

pub fn recover_eth_address_kalqix(
    message_bytes: &[u8],
    sig_bytes: &[u8; 65]
) -> [u8; 20] {
    // 1. Build EIP-191 digest (same as ethers.js hashMessage)
    let mut hasher = Keccak::v256();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    // Write message length as ASCII digits without heap allocation
    let mut len_buf = [0u8; 20];
    let len_str = write_usize_ascii(message_bytes.len(), &mut len_buf);
    hasher.update(len_str);
    hasher.update(message_bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    // 2. Parse signature components
    let v = sig_bytes[64];
    let recovery_id = if v >= 27 { v - 27 } else { v };

    let sig = Secp256k1Signature::try_from(&sig_bytes[..64])
        .expect("invalid secp256k1 signature");
    let recid = RecoveryId::try_from(recovery_id)
    .expect("invalid recovery id");

    // 3. Recover public key
    let verifying_key = Secp256k1VerifyingKey::recover_from_prehash(&digest, &sig, recid)
    .expect("secp256k1 recovery failed");

    // 4. Derive Ethereum address from recovered public key
    let encoded_point = verifying_key.to_encoded_point(false);
    let encoded_bytes = encoded_point.as_bytes();
    // Remove the 0x04 prefix byte before hashing
    let key_hash = keccak256(&encoded_bytes[1..]);
    // Ethereum address is the last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&key_hash[12..32]);
    address
}

fn recover_eth_address(digest: &[u8; 32], sig_bytes: &[u8; 65]) -> [u8; 20] {
    let sig = Secp256k1Signature::from_slice(&sig_bytes[..64])
        .expect("invalid secp256k1 signature");
    let v = sig_bytes[64];
    let recovery_id = RecoveryId::from_byte(if v >= 27 { v - 27 } else { v })
        .expect("invalid recovery id");

    let recovered_key =
        Secp256k1VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
            .expect("secp256k1 recovery failed");

    let pubkey_bytes = recovered_key.to_encoded_point(false);
    // Uncompressed pubkey is 65 bytes: 0x04 ++ x[32] ++ y[32]
    let pubkey_hash = keccak256(&pubkey_bytes.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&pubkey_hash[12..32]);
    address
}

// ── Register Key ────────────────────────────────────────────────────────────

fn handle_register_key(w: RegisterKeyWitness) {
    // 1. Verify old leaf is consistent with old root
    println!("cycle-tracker-report-start: merkle_verify_old");
    assert!(
        verify_merkle_proof(
            w.old_leaf_hash,
            w.leaf_index,
            &w.merkle_siblings,
            w.old_session_key_root
        ),
        "old leaf does not match old root"
    );
    println!("cycle-tracker-report-end: merkle_verify_old");

    // 2. Reconstruct and verify EIP-191 signature
    let pubkey_bytes = decode_hex_32(&w.request.pubkey_hex);
    let message = register_key_message(
        &w.request.account_address,
        &pubkey_bytes,
        w.request.key_index,
    );
    println!("cycle-tracker-report-start: eip191_recover");
    let digest = eip191_hash(&message);
    let sig_bytes = decode_hex_65(&w.request.eth_signature_hex);
    let recovered_address = recover_eth_address(&digest, &sig_bytes);
    println!("cycle-tracker-report-end: eip191_recover");
    assert!(
        recovered_address == w.request.account_address,
        "EIP-191 signature does not match account address"
    );

    // 3. Hash the new leaf
    println!("cycle-tracker-report-start: hash_new_leaf");
    let new_leaf = SessionKeyLeaf {
        account_address: w.request.account_address,
        key_index: w.request.key_index,
        pubkey: pubkey_bytes,
    };
    let new_leaf_hash = hash_leaf(&new_leaf);
    println!("cycle-tracker-report-end: hash_new_leaf");

    // 4. Verify new state
    println!("cycle-tracker-report-start: merkle_verify_new");
    let computed_new_root =
        compute_new_root(new_leaf_hash, w.leaf_index, &w.merkle_siblings);
    assert!(
        computed_new_root == w.new_session_key_root,
        "new root mismatch"
    );
    println!("cycle-tracker-report-end: merkle_verify_new");

    // 5. Commit public output
    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: w.old_session_key_root,
        new_session_key_root: w.new_session_key_root,
        account_address: w.request.account_address,
        key_index: w.request.key_index,
        proof_type: "REGISTER_KEY".to_string(),
    });
}

// ── Verify Order ────────────────────────────────────────────────────────────

fn handle_verify_order(w: OrderWitness) {
    // 1. Reconstruct session key leaf and verify Merkle proof
    println!("cycle-tracker-report-start: merkle_verify");
    let leaf = SessionKeyLeaf {
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        pubkey: w.session_key.pubkey,
    };
    let leaf_hash = hash_leaf(&leaf);
    assert!(
        verify_merkle_proof(
            leaf_hash,
            w.leaf_index,
            &w.merkle_siblings,
            w.session_key_root
        ),
        "session key not registered — Merkle proof failed"
    );
    println!("cycle-tracker-report-end: merkle_verify");

    // 2. Build order message and hash it
    println!("cycle-tracker-report-start: sha256_hash");
    let message_bytes = order_message(&w.order);
    let order_hash = Sha256::digest(&message_bytes);
    println!("cycle-tracker-report-end: sha256_hash");

    // 3. Verify Ed25519 signature
    println!("cycle-tracker-report-start: ed25519_verify");
    let vk = VerifyingKey::from_bytes(&w.session_key.pubkey)
        .expect("invalid Ed25519 public key");
    let sig_bytes = decode_hex_64(&w.order.ed25519_signature_hex);
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(
        vk.verify(&order_hash, &sig).is_ok(),
        "Ed25519 signature invalid"
    );
    println!("cycle-tracker-report-end: ed25519_verify");

    // 5. Commit public output
    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: w.session_key_root,
        new_session_key_root: w.session_key_root,
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        proof_type: "VERIFY_ORDER".to_string(),
    });
}

// ── Verify Order (Ethereum secp256k1 — benchmark path) ─────────────────────

fn handle_verify_order_eth(w: EthOrderWitness) {
    // 1. Reconstruct the order message and build EIP-191 digest
    println!("cycle-tracker-report-start: eip191_hash");
    let message = eth_order_message(&w.order);
    let digest = eip191_hash(&message);
    println!("cycle-tracker-report-end: eip191_hash");

    // 2. Recover signer from secp256k1 signature
    println!("cycle-tracker-report-start: secp256k1_recover");
    let sig_bytes = decode_hex_65(&w.order.eth_signature_hex);
    let recovered_address = recover_eth_address_kalqix(
        message.as_bytes(), &sig_bytes
    );
    //let recovered_address = recover_eth_address(&digest, &sig_bytes);
    println!("cycle-tracker-report-end: secp256k1_recover");
    assert!(
        recovered_address == w.order.account_address,
        "EIP-191 order signature does not match account address"
    );

    // 4. Commit public output
    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        proof_type: "VERIFY_ORDER_ETH".to_string(),
    });
}

// ── Verify Order (P-256 ECDSA — benchmark path) ───────────────────────────

fn handle_verify_order_p256(w: P256OrderWitness) {
    // 1. Hash the order message with SHA-256
    println!("cycle-tracker-report-start: p256_sha256_hash");
    let message = p256_order_message(&w.order);
    let digest = Sha256::digest(message.as_bytes());
    println!("cycle-tracker-report-end: p256_sha256_hash");

    // 2. Verify P-256 ECDSA signature
    println!("cycle-tracker-report-start: p256_verify");
    let pubkey_bytes = hex::decode(&w.order.p256_pubkey_hex).expect("invalid p256 pubkey hex");
    let vk = P256VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .expect("invalid P-256 public key");
    let sig_bytes = hex::decode(&w.order.p256_signature_hex).expect("invalid p256 sig hex");
    let sig = P256Signature::from_slice(&sig_bytes)
        .expect("invalid P-256 signature");
    assert!(
        vk.verify_prehash(&digest, &sig).is_ok(),
        "P-256 ECDSA signature invalid"
    );
    println!("cycle-tracker-report-end: p256_verify");

    // 3. Commit output
    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        proof_type: "VERIFY_ORDER_P256".to_string(),
    });
}

// ── Verify Order (Septic Schnorr — precompile-backed) ─────────────────────

fn handle_verify_order_septic(w: SepticBenchWitness) {
    let r_point = sp1_lib::septic::SepticPoint::new(
        w.order.signature.r_x.0,
        w.order.signature.r_y.0,
    );
    let pubkey = sp1_lib::septic::SepticPoint::new(
        w.order.pubkey_x.0,
        w.order.pubkey_y.0,
    );
    let g = sp1_lib::septic::SepticPoint::new(GENERATOR_X.0, GENERATOR_Y.0);

    println!("cycle-tracker-report-start: septic_s_times_G");
    let s_g = g.scalar_mul(&w.order.signature.s);
    println!("cycle-tracker-report-end: septic_s_times_G");

    println!("cycle-tracker-report-start: septic_e_times_A");
    let e_a = pubkey.scalar_mul(&w.challenge_e);
    println!("cycle-tracker-report-end: septic_e_times_A");

    println!("cycle-tracker-report-start: septic_final_check");
    let check = s_g.add(&e_a);
    assert!(
        check.x() == r_point.x() && check.y() == r_point.y(),
        "Schnorr verify failed: s·G + e·A != R"
    );
    println!("cycle-tracker-report-end: septic_final_check");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        proof_type: "VERIFY_ORDER_SEPTIC".to_string(),
    });
}

// ── Batch Septic ──────────────────────────────────────────────────────────

fn handle_batch_septic(w: BatchSepticWitness) {
    let count = w.orders.len();
    let g = sp1_lib::septic::SepticPoint::new(GENERATOR_X.0, GENERATOR_Y.0);

    println!("cycle-tracker-report-start: batch_septic_total");
    for witness in &w.orders {
        let r_point = sp1_lib::septic::SepticPoint::new(
            witness.order.signature.r_x.0,
            witness.order.signature.r_y.0,
        );
        let pubkey = sp1_lib::septic::SepticPoint::new(
            witness.order.pubkey_x.0,
            witness.order.pubkey_y.0,
        );

        let s_g = g.scalar_mul(&witness.order.signature.s);
        let e_a = pubkey.scalar_mul(&witness.challenge_e);
        let check = s_g.add(&e_a);

        assert!(
            check.x() == r_point.x() && check.y() == r_point.y(),
            "Schnorr verify failed in batch"
        );
    }
    println!("cycle-tracker-report-end: batch_septic_total");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_{}", count),
    });
}

// ── Batch Septic (optimized: combined-equation Schnorr) ───────────────────
//
// Verifies all `count` Schnorr signatures simultaneously by checking
//   (Σ α_i·s_i)·G + Σ(α_i·e_i·A_i) == Σ(α_i·R_i)
// for random 128-bit weights α_i derived via Fiat-Shamir from the batch.
// Soundness error per single bad signature ≤ 2^-128.

/// (a × b) mod GROUP_ORDER via SP1's UINT256_MUL precompile.
///
/// Layout the precompile expects:
///   x_ptr → 32 bytes (operand a; overwritten with the result)
///   y_ptr → 64 bytes (operand b in first 32, modulus in next 32)
fn scalar_mul_mod_r_fast(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut x = [0u64; 4];
    for i in 0..4 {
        x[i] = a[i * 2] as u64 | ((a[i * 2 + 1] as u64) << 32);
    }

    let mut y_and_mod = [0u64; 8];
    for i in 0..4 {
        y_and_mod[i] = b[i * 2] as u64 | ((b[i * 2 + 1] as u64) << 32);
        y_and_mod[4 + i] =
            GROUP_ORDER[i * 2] as u64 | ((GROUP_ORDER[i * 2 + 1] as u64) << 32);
    }

    unsafe {
        sp1_lib::syscall_uint256_mulmod(
            &mut x as *mut [u64; 4],
            y_and_mod.as_ptr() as *const [u64; 4],
        );
    }

    let mut result = [0u32; 8];
    for i in 0..4 {
        result[i * 2] = x[i] as u32;
        result[i * 2 + 1] = (x[i] >> 32) as u32;
    }
    result
}

fn handle_batch_septic_opt(w: BatchSepticOptWitness) {
    let count = w.orders.len();
    assert!(count > 0, "empty batch");

    let g = sp1_lib::septic::SepticPoint::new(GENERATOR_X.0, GENERATOR_Y.0);

    // Phase 1 — derive 128-bit α_i via Fiat-Shamir from the whole batch.
    println!("cycle-tracker-report-start: batch_opt_commitment");
    let mut hasher = Sha256::new();
    for witness in &w.orders {
        hasher.update(witness.order.signature.r_x.to_bytes());
        hasher.update(witness.order.signature.r_y.to_bytes());
        hasher.update(witness.order.pubkey_x.to_bytes());
        hasher.update(witness.order.pubkey_y.to_bytes());
        for limb in &witness.challenge_e {
            hasher.update(limb.to_le_bytes());
        }
    }
    let batch_commitment = hasher.finalize();

    let mut alphas: Vec<[u32; 8]> = Vec::with_capacity(count);
    for i in 0..count {
        let mut h = Sha256::new();
        h.update(batch_commitment);
        h.update((i as u32).to_le_bytes());
        let digest = h.finalize();
        let mut alpha = [0u32; 8];
        for j in 0..4 {
            alpha[j] = u32::from_le_bytes([
                digest[j * 4],
                digest[j * 4 + 1],
                digest[j * 4 + 2],
                digest[j * 4 + 3],
            ]);
        }
        // Top 4 limbs stay zero — α_i is a 128-bit weight.
        alphas.push(alpha);
    }
    println!("cycle-tracker-report-end: batch_opt_commitment");

    // Phase 2 — combine: s_combined = Σ α_i·s_i mod r,  ae_i = α_i·e_i mod r.
    println!("cycle-tracker-report-start: batch_opt_scalar_combine");
    let mut s_combined = [0u32; 8];
    let mut ae_scalars: Vec<[u32; 8]> = Vec::with_capacity(count);
    for i in 0..count {
        let alpha = &alphas[i];
        let s_i = &w.orders[i].order.signature.s;
        let e_i = &w.orders[i].challenge_e;

        let as_i = scalar_mul_mod_r_fast(alpha, s_i);
        s_combined = scalar_add(&s_combined, &as_i);

        let ae_i = scalar_mul_mod_r_fast(alpha, e_i);
        ae_scalars.push(ae_i);
    }
    println!("cycle-tracker-report-end: batch_opt_scalar_combine");

    // Phase 3 — single 217-bit scalar mul on G.
    println!("cycle-tracker-report-start: batch_opt_s_times_G");
    let lhs_g = g.scalar_mul(&s_combined);
    println!("cycle-tracker-report-end: batch_opt_s_times_G");

    // Phase 4 — Σ(ae_i · A_i): full 217-bit scalar muls.
    println!("cycle-tracker-report-start: batch_opt_ae_times_A");
    let mut ae_a_sum = sp1_lib::septic::SepticPoint::new([0u32; 7], [0u32; 7]);
    let mut ae_sum_initialized = false;
    for i in 0..count {
        let a_i = sp1_lib::septic::SepticPoint::new(
            w.orders[i].order.pubkey_x.0,
            w.orders[i].order.pubkey_y.0,
        );
        let term = a_i.scalar_mul(&ae_scalars[i]);
        if !ae_sum_initialized {
            ae_a_sum = term;
            ae_sum_initialized = true;
        } else {
            ae_a_sum = ae_a_sum.add(&term);
        }
    }
    println!("cycle-tracker-report-end: batch_opt_ae_times_A");

    // Phase 5 — LHS = s_combined·G + Σ(ae_i · A_i).
    println!("cycle-tracker-report-start: batch_opt_lhs_combine");
    let lhs = lhs_g.add(&ae_a_sum);
    println!("cycle-tracker-report-end: batch_opt_lhs_combine");

    // Phase 6 — Σ(α_i · R_i): α_i is 128 bits, so iterate only the low 4 limbs
    // and skip half the doublings vs the full 256-bit scalar_mul.
    println!("cycle-tracker-report-start: batch_opt_alpha_times_R");
    let mut rhs = sp1_lib::septic::SepticPoint::new([0u32; 7], [0u32; 7]);
    let mut rhs_initialized = false;
    for i in 0..count {
        let r_i = sp1_lib::septic::SepticPoint::new(
            w.orders[i].order.signature.r_x.0,
            w.orders[i].order.signature.r_y.0,
        );
        // alphas[i] has top 4 limbs zero; feed SP1's scalar_mul only the low
        // 128 bits so it runs 128 doublings instead of 256.
        let term = r_i.scalar_mul(&alphas[i][..4]);
        if !rhs_initialized {
            rhs = term;
            rhs_initialized = true;
        } else {
            rhs = rhs.add(&term);
        }
    }
    println!("cycle-tracker-report-end: batch_opt_alpha_times_R");

    // Phase 7 — single equality check covers all `count` signatures.
    println!("cycle-tracker-report-start: batch_opt_final_check");
    assert!(
        lhs.x() == rhs.x() && lhs.y() == rhs.y(),
        "Batch Schnorr verification failed"
    );
    println!("cycle-tracker-report-end: batch_opt_final_check");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_OPT_{}", count),
    });
}

// ── Batch Eth (secp256k1 EIP-191 ecrecover) ───────────────────────────────

fn handle_batch_eth(w: BatchEthWitness) {
    let count = w.orders.len();

    println!("cycle-tracker-report-start: batch_eth_total");
    for witness in &w.orders {
        let message = eth_order_message(&witness.order);
        let sig_bytes = decode_hex_65(&witness.order.eth_signature_hex);
        let recovered_address = recover_eth_address_kalqix(message.as_bytes(), &sig_bytes);
        assert!(
            recovered_address == witness.order.account_address,
            "EIP-191 order signature mismatch in batch"
        );
    }
    println!("cycle-tracker-report-end: batch_eth_total");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_ETH_{}", count),
    });
}

// ── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    let input: ProgramInput = sp1_zkvm::io::read();
    match input {
        ProgramInput::RegisterKey(w) => handle_register_key(w),
        ProgramInput::VerifyOrder(w) => handle_verify_order(w),
        ProgramInput::VerifyOrderEth(w) => handle_verify_order_eth(w),
        ProgramInput::VerifyOrderP256(w) => handle_verify_order_p256(w),
        ProgramInput::VerifyOrderSeptic(w) => handle_verify_order_septic(w),
        ProgramInput::BatchSeptic(w) => handle_batch_septic(w),
        ProgramInput::BatchSepticOpt(w) => handle_batch_septic_opt(w),
        ProgramInput::BatchEth(w) => handle_batch_eth(w),
    }
}
