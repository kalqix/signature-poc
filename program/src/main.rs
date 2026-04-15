#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use k256::ecdsa::{RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};

use sp1_zkvm::syscalls::Poseidon2ByteHash;

use shared::{
    BatchEthWitness, BatchSepticDedupWitness, BatchSepticOptWitness, BatchSepticSingleWitness,
    BatchSepticVerifyMerkleWitness, BatchSepticVerifyWitness, BatchSepticWitness,
    EthOrderWitness, OrderWitness, ProgramInput, ProofOutput, RegisterKeyWitness,
    SessionKeyLeaf, VerifyOrderSepticWitness, eth_order_message, register_key_message,
    septic_order_message,
    septic::{GENERATOR_X, GENERATOR_Y, GROUP_ORDER, scalar_add},
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
    let mut hasher = Keccak::v256();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    let mut len_buf = [0u8; 20];
    let len_str = write_usize_ascii(message_bytes.len(), &mut len_buf);
    hasher.update(len_str);
    hasher.update(message_bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    let v = sig_bytes[64];
    let recovery_id = if v >= 27 { v - 27 } else { v };

    let sig = Secp256k1Signature::try_from(&sig_bytes[..64])
        .expect("invalid secp256k1 signature");
    let recid = RecoveryId::try_from(recovery_id)
        .expect("invalid recovery id");

    let verifying_key = Secp256k1VerifyingKey::recover_from_prehash(&digest, &sig, recid)
        .expect("secp256k1 recovery failed");

    let encoded_point = verifying_key.to_encoded_point(false);
    let encoded_bytes = encoded_point.as_bytes();
    let key_hash = keccak256(&encoded_bytes[1..]);
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
    let message = register_key_message(
        &w.request.account_address,
        &w.request.pubkey_x,
        &w.request.pubkey_y,
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

    // 3. Hash the new leaf (septic pubkey)
    println!("cycle-tracker-report-start: hash_new_leaf");
    let new_leaf = SessionKeyLeaf {
        account_address: w.request.account_address,
        key_index: w.request.key_index,
        pubkey_x: w.request.pubkey_x,
        pubkey_y: w.request.pubkey_y,
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

// ── Verify Order (Septic Schnorr + Merkle membership) ──────────────────────

fn handle_verify_order(w: OrderWitness) {
    // 1. Reconstruct session key leaf and verify Merkle proof
    println!("cycle-tracker-report-start: merkle_verify");
    let leaf = SessionKeyLeaf {
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        pubkey_x: w.session_key.pubkey_x,
        pubkey_y: w.session_key.pubkey_y,
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

    // 2. Verify Schnorr signature via SEPTIC_VERIFY precompile (Shamir's trick)
    println!("cycle-tracker-report-start: schnorr_verify");
    let r_point = sp1_lib::septic::SepticPoint::new(
        w.order.signature_r_x,
        w.order.signature_r_y,
    );
    let pubkey = sp1_lib::septic::SepticPoint::new(
        w.session_key.pubkey_x,
        w.session_key.pubkey_y,
    );

    let result = sp1_lib::septic::schnorr_compute(
        &pubkey,
        &w.order.signature_s,
        &w.order.challenge_e,
    );

    assert!(
        result.x() == r_point.x() && result.y() == r_point.y(),
        "Schnorr signature verification failed"
    );
    println!("cycle-tracker-report-end: schnorr_verify");

    // Silence "unused" warning when only the message is needed off-host.
    let _ = septic_order_message(&w.order);

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
    println!("cycle-tracker-report-start: eip191_hash");
    let message = eth_order_message(&w.order);
    let _digest = eip191_hash(&message);
    println!("cycle-tracker-report-end: eip191_hash");

    println!("cycle-tracker-report-start: secp256k1_recover");
    let sig_bytes = decode_hex_65(&w.order.eth_signature_hex);
    let recovered_address = recover_eth_address_kalqix(
        message.as_bytes(), &sig_bytes
    );
    println!("cycle-tracker-report-end: secp256k1_recover");
    assert!(
        recovered_address == w.order.account_address,
        "EIP-191 order signature does not match account address"
    );

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        proof_type: "VERIFY_ORDER_ETH".to_string(),
    });
}

// ── Verify Order (Septic Schnorr + Merkle, per-bit scalar_mul) ────────────

/// Production-shaped Schnorr verify (Merkle membership + single-signature
/// Schnorr check `s·G + e·A == R`) using per-bit `scalar_mul` syscalls
/// instead of the `SEPTIC_VERIFY` precompile. Directly comparable to
/// `handle_verify_order` — same Merkle proof, different scalar-mul strategy —
/// so the cycle delta is the precompile's contribution.
fn handle_verify_order_septic(w: VerifyOrderSepticWitness) {
    let bench = w.bench;

    // 1. Verify session-key Merkle membership
    println!("cycle-tracker-report-start: merkle_verify");
    let leaf = SessionKeyLeaf {
        account_address: bench.order.account_address,
        key_index: bench.order.key_index,
        pubkey_x: bench.order.pubkey_x.0,
        pubkey_y: bench.order.pubkey_y.0,
    };
    let leaf_hash = hash_leaf(&leaf);
    assert!(
        verify_merkle_proof(
            leaf_hash,
            w.leaf_index,
            &w.merkle_siblings,
            w.session_key_root,
        ),
        "session key not registered — Merkle proof failed"
    );
    println!("cycle-tracker-report-end: merkle_verify");

    // 2. Per-bit scalar-mul Schnorr verify (s·G + e·A == R)
    let r_point = sp1_lib::septic::SepticPoint::new(
        bench.order.signature.r_x.0,
        bench.order.signature.r_y.0,
    );
    let pubkey = sp1_lib::septic::SepticPoint::new(
        bench.order.pubkey_x.0,
        bench.order.pubkey_y.0,
    );
    let g = sp1_lib::septic::SepticPoint::new(GENERATOR_X.0, GENERATOR_Y.0);

    println!("cycle-tracker-report-start: septic_s_times_G");
    let s_g = g.scalar_mul(&bench.order.signature.s);
    println!("cycle-tracker-report-end: septic_s_times_G");

    println!("cycle-tracker-report-start: septic_e_times_A");
    let e_a = pubkey.scalar_mul(&bench.challenge_e);
    println!("cycle-tracker-report-end: septic_e_times_A");

    println!("cycle-tracker-report-start: septic_final_check");
    let check = s_g.add(&e_a);
    assert!(
        check.x() == r_point.x() && check.y() == r_point.y(),
        "Schnorr verify failed: s·G + e·A != R"
    );
    println!("cycle-tracker-report-end: septic_final_check");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: w.session_key_root,
        new_session_key_root: w.session_key_root,
        account_address: bench.order.account_address,
        key_index: bench.order.key_index,
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

/// (a × b) mod GROUP_ORDER via SP1's UINT256_MUL precompile.
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
        alphas.push(alpha);
    }
    println!("cycle-tracker-report-end: batch_opt_commitment");

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

    println!("cycle-tracker-report-start: batch_opt_s_times_G");
    let lhs_g = g.scalar_mul(&s_combined);
    println!("cycle-tracker-report-end: batch_opt_s_times_G");

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

    println!("cycle-tracker-report-start: batch_opt_lhs_combine");
    let lhs = lhs_g.add(&ae_a_sum);
    println!("cycle-tracker-report-end: batch_opt_lhs_combine");

    println!("cycle-tracker-report-start: batch_opt_alpha_times_R");
    let mut rhs = sp1_lib::septic::SepticPoint::new([0u32; 7], [0u32; 7]);
    let mut rhs_initialized = false;
    for i in 0..count {
        let r_i = sp1_lib::septic::SepticPoint::new(
            w.orders[i].order.signature.r_x.0,
            w.orders[i].order.signature.r_y.0,
        );
        let term = r_i.scalar_mul(&alphas[i][..4]);
        if !rhs_initialized {
            rhs = term;
            rhs_initialized = true;
        } else {
            rhs = rhs.add(&term);
        }
    }
    println!("cycle-tracker-report-end: batch_opt_alpha_times_R");

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

// ── Batch Septic (single-syscall scalar mul, naive per-signature verify) ──

fn handle_batch_septic_single(w: BatchSepticSingleWitness) {
    let count = w.orders.len();
    let g = sp1_lib::septic::SepticPoint::new(GENERATOR_X.0, GENERATOR_Y.0);

    println!("cycle-tracker-report-start: batch_single_total");
    for witness in &w.orders {
        let r_point = sp1_lib::septic::SepticPoint::new(
            witness.order.signature.r_x.0,
            witness.order.signature.r_y.0,
        );
        let pubkey = sp1_lib::septic::SepticPoint::new(
            witness.order.pubkey_x.0,
            witness.order.pubkey_y.0,
        );

        let s_g = g.scalar_mul_single(&witness.order.signature.s);
        let e_a = pubkey.scalar_mul_single(&witness.challenge_e);
        let check = s_g.add(&e_a);

        assert!(
            check.x() == r_point.x() && check.y() == r_point.y(),
            "Schnorr verify failed in batch (single)"
        );
    }
    println!("cycle-tracker-report-end: batch_single_total");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_SINGLE_{}", count),
    });
}

// ── Batch Septic Opt (single-syscall scalar mul, combined-equation Schnorr) ──

fn handle_batch_septic_opt_single(w: BatchSepticOptWitness) {
    let count = w.orders.len();
    assert!(count > 0, "empty batch");

    let g = sp1_lib::septic::SepticPoint::new(GENERATOR_X.0, GENERATOR_Y.0);

    println!("cycle-tracker-report-start: batch_opt_single_commitment");
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
        alphas.push(alpha);
    }
    println!("cycle-tracker-report-end: batch_opt_single_commitment");

    println!("cycle-tracker-report-start: batch_opt_single_scalar_combine");
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
    println!("cycle-tracker-report-end: batch_opt_single_scalar_combine");

    println!("cycle-tracker-report-start: batch_opt_single_s_times_G");
    let lhs_g = g.scalar_mul_single(&s_combined);
    println!("cycle-tracker-report-end: batch_opt_single_s_times_G");

    println!("cycle-tracker-report-start: batch_opt_single_ae_times_A");
    let mut ae_a_sum = sp1_lib::septic::SepticPoint::new([0u32; 7], [0u32; 7]);
    let mut ae_sum_initialized = false;
    for i in 0..count {
        let a_i = sp1_lib::septic::SepticPoint::new(
            w.orders[i].order.pubkey_x.0,
            w.orders[i].order.pubkey_y.0,
        );
        let term = a_i.scalar_mul_single(&ae_scalars[i]);
        if !ae_sum_initialized {
            ae_a_sum = term;
            ae_sum_initialized = true;
        } else {
            ae_a_sum = ae_a_sum.add(&term);
        }
    }
    println!("cycle-tracker-report-end: batch_opt_single_ae_times_A");

    println!("cycle-tracker-report-start: batch_opt_single_lhs_combine");
    let lhs = lhs_g.add(&ae_a_sum);
    println!("cycle-tracker-report-end: batch_opt_single_lhs_combine");

    println!("cycle-tracker-report-start: batch_opt_single_alpha_times_R");
    let mut rhs = sp1_lib::septic::SepticPoint::new([0u32; 7], [0u32; 7]);
    let mut rhs_initialized = false;
    for i in 0..count {
        let r_i = sp1_lib::septic::SepticPoint::new(
            w.orders[i].order.signature.r_x.0,
            w.orders[i].order.signature.r_y.0,
        );
        let term = r_i.scalar_mul_single(&alphas[i]);
        if !rhs_initialized {
            rhs = term;
            rhs_initialized = true;
        } else {
            rhs = rhs.add(&term);
        }
    }
    println!("cycle-tracker-report-end: batch_opt_single_alpha_times_R");

    println!("cycle-tracker-report-start: batch_opt_single_final_check");
    assert!(
        lhs.x() == rhs.x() && lhs.y() == rhs.y(),
        "Batch Schnorr verification failed (single)"
    );
    println!("cycle-tracker-report-end: batch_opt_single_final_check");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_OPT_SINGLE_{}", count),
    });
}

// ── Batch Septic Verify (SEPTIC_VERIFY precompile, Shamir's trick) ────────

fn handle_batch_septic_verify(w: BatchSepticVerifyWitness) {
    let count = w.orders.len();

    println!("cycle-tracker-report-start: batch_verify_total");
    for witness in &w.orders {
        let r_point = sp1_lib::septic::SepticPoint::new(
            witness.order.signature.r_x.0,
            witness.order.signature.r_y.0,
        );
        let pubkey = sp1_lib::septic::SepticPoint::new(
            witness.order.pubkey_x.0,
            witness.order.pubkey_y.0,
        );

        let result = sp1_lib::septic::schnorr_compute(
            &pubkey,
            &witness.order.signature.s,
            &witness.challenge_e,
        );

        assert!(
            result.x() == r_point.x() && result.y() == r_point.y(),
            "Schnorr verify failed in batch (verify)"
        );
    }
    println!("cycle-tracker-report-end: batch_verify_total");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_VERIFY_{}", count),
    });
}

// ── Batch Septic Verify + Merkle (production-shaped) ─────────────────────

/// Per-order Merkle membership + `SEPTIC_VERIFY` precompile. Same per-order
/// Schnorr work as `handle_batch_septic_verify`, plus session-key Merkle
/// verification — the realistic per-order cost at scale.
fn handle_batch_septic_verify_merkle(w: BatchSepticVerifyMerkleWitness) {
    let count = w.orders.len();

    println!("cycle-tracker-report-start: batch_verify_merkle_total");
    for entry in &w.orders {
        // Merkle membership check
        let leaf = SessionKeyLeaf {
            account_address: entry.bench.order.account_address,
            key_index: entry.bench.order.key_index,
            pubkey_x: entry.bench.order.pubkey_x.0,
            pubkey_y: entry.bench.order.pubkey_y.0,
        };
        let leaf_hash = hash_leaf(&leaf);
        assert!(
            verify_merkle_proof(
                leaf_hash,
                entry.leaf_index,
                &entry.merkle_siblings,
                w.session_key_root,
            ),
            "session key not registered — Merkle proof failed"
        );

        // Schnorr verify via SEPTIC_VERIFY (single syscall, Shamir's trick)
        let r_point = sp1_lib::septic::SepticPoint::new(
            entry.bench.order.signature.r_x.0,
            entry.bench.order.signature.r_y.0,
        );
        let pubkey = sp1_lib::septic::SepticPoint::new(
            entry.bench.order.pubkey_x.0,
            entry.bench.order.pubkey_y.0,
        );
        let result = sp1_lib::septic::schnorr_compute(
            &pubkey,
            &entry.bench.order.signature.s,
            &entry.bench.challenge_e,
        );
        assert!(
            result.x() == r_point.x() && result.y() == r_point.y(),
            "Schnorr verify failed in batch (verify+merkle)"
        );
    }
    println!("cycle-tracker-report-end: batch_verify_merkle_total");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: w.session_key_root,
        new_session_key_root: w.session_key_root,
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_VERIFY_MERKLE_{}", count),
    });
}

// ── Batch Septic Dedup (one Merkle per unique key, Schnorr per order) ────

/// Realistic batch where many orders are signed by a small number of session
/// keys. Each unique (account_address, key_index) leaf is Merkle-verified
/// once; every order goes through SEPTIC_VERIFY independently. Saves
/// (orders - unique_keys) Merkle verifications per batch.
fn handle_batch_septic_dedup(w: BatchSepticDedupWitness) {
    let unique_count = w.unique_keys.len();
    let order_count = w.orders.len();

    // 1. One Merkle proof per unique session key.
    println!("cycle-tracker-report-start: dedup_merkle_total");
    for key in &w.unique_keys {
        let leaf = SessionKeyLeaf {
            account_address: key.account_address,
            key_index: key.key_index,
            pubkey_x: key.pubkey_x,
            pubkey_y: key.pubkey_y,
        };
        let leaf_hash = hash_leaf(&leaf);
        assert!(
            verify_merkle_proof(
                leaf_hash,
                key.leaf_index,
                &key.merkle_siblings,
                w.session_key_root,
            ),
            "session key not registered — Merkle proof failed"
        );
    }
    println!("cycle-tracker-report-end: dedup_merkle_total");

    // 2. Per-order Schnorr verify; pubkey is pulled from the (already
    //    Merkle-verified) unique_keys table by index.
    println!("cycle-tracker-report-start: dedup_schnorr_total");
    for order in &w.orders {
        let key = &w.unique_keys[order.key_idx as usize];
        let r_point = sp1_lib::septic::SepticPoint::new(
            order.signature_r_x,
            order.signature_r_y,
        );
        let pubkey = sp1_lib::septic::SepticPoint::new(
            key.pubkey_x,
            key.pubkey_y,
        );
        let result = sp1_lib::septic::schnorr_compute(
            &pubkey,
            &order.signature_s,
            &order.challenge_e,
        );
        assert!(
            result.x() == r_point.x() && result.y() == r_point.y(),
            "Schnorr verify failed in dedup batch"
        );
    }
    println!("cycle-tracker-report-end: dedup_schnorr_total");

    sp1_zkvm::io::commit(&ProofOutput {
        old_session_key_root: w.session_key_root,
        new_session_key_root: w.session_key_root,
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_DEDUP_{}u_{}o", unique_count, order_count),
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
        ProgramInput::VerifyOrderSeptic(w) => handle_verify_order_septic(w),
        ProgramInput::BatchSeptic(w) => handle_batch_septic(w),
        ProgramInput::BatchSepticOpt(w) => handle_batch_septic_opt(w),
        ProgramInput::BatchSepticSingle(w) => handle_batch_septic_single(w),
        ProgramInput::BatchSepticOptSingle(w) => handle_batch_septic_opt_single(w),
        ProgramInput::BatchSepticVerify(w) => handle_batch_septic_verify(w),
        ProgramInput::BatchSepticVerifyMerkle(w) => handle_batch_septic_verify_merkle(w),
        ProgramInput::BatchSepticDedup(w) => handle_batch_septic_dedup(w),
        ProgramInput::BatchEth(w) => handle_batch_eth(w),
    }
}
