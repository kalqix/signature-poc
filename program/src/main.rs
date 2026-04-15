#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use k256::ecdsa::{RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};

use jmt::{KeyHash, RootHash};

use shared::{
    encode_session_key_leaf, session_key_hash,
    ArchivedBatchSepticDedupBatchWitness, BatchEthWitness, BatchSepticDedupBatchWitness,
    BatchSepticDedupWitness, BatchSepticOptWitness, BatchSepticSingleWitness,
    BatchSepticVerifyMerkleWitness, BatchSepticVerifyWitness, BatchSepticWitness, EthOrderWitness,
    OrderWitness, ProgramInput, ProofOutput, RegisterKeyWitness, SessionKeyLeaf,
    VerifyOrderSepticWitness, eth_order_message, register_key_message, septic_order_message,
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

// ── borsh-backed public-output commit ──────────────────────────────────────

fn commit_borsh<T: borsh::BorshSerialize>(value: &T) {
    let bytes = borsh::to_vec(value).expect("borsh serialize public output");
    sp1_zkvm::io::commit_slice(&bytes);
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
    // 1. Verify the OLD JMT proof. `Some(old_leaf)` → inclusion proof for
    //    rotation; `None` → non-inclusion proof for a fresh slot.
    println!("cycle-tracker-report-start: jmt_verify_old");
    let key_hash = KeyHash(session_key_hash(
        &w.request.account_address,
        w.request.key_index,
    ));
    let old_value = w.old_leaf.as_ref().map(encode_session_key_leaf);
    w.old_proof
        .verify(
            RootHash(w.old_session_key_root),
            key_hash,
            old_value.as_deref(),
        )
        .expect("old JMT proof failed against old_session_key_root");
    println!("cycle-tracker-report-end: jmt_verify_old");

    // 2. Reconstruct and verify EIP-191 signature.
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

    // 3. The new root is committed to public output and validated on-chain;
    //    POC trusts the host to compute it correctly. Production would also
    //    verify a JMT `UpdateMerkleProof` here.
    commit_borsh(&ProofOutput {
        old_session_key_root: w.old_session_key_root,
        new_session_key_root: w.new_session_key_root,
        account_address: w.request.account_address,
        key_index: w.request.key_index,
        proof_type: "REGISTER_KEY".to_string(),
    });
}

// ── Verify Order (Septic Schnorr + Merkle membership) ──────────────────────

fn handle_verify_order(w: OrderWitness) {
    // 1. Reconstruct session key leaf and verify JMT inclusion proof.
    //    Inclusion verifies that this exact (address, key_index, pubkey)
    //    triple is registered — if the host substituted a different pubkey
    //    the value-hash check inside `verify_existence` will fail.
    println!("cycle-tracker-report-start: jmt_verify");
    let leaf = SessionKeyLeaf {
        account_address: w.order.account_address,
        key_index: w.order.key_index,
        pubkey_x: w.session_key.pubkey_x,
        pubkey_y: w.session_key.pubkey_y,
    };
    let leaf_value = encode_session_key_leaf(&leaf);
    let key_hash = KeyHash(session_key_hash(
        &w.order.account_address,
        w.order.key_index,
    ));
    w.merkle_proof
        .verify_existence(RootHash(w.session_key_root), key_hash, &leaf_value)
        .expect("session key not registered — JMT inclusion proof failed");
    println!("cycle-tracker-report-end: jmt_verify");

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

    commit_borsh(&ProofOutput {
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

    commit_borsh(&ProofOutput {
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

    // 1. Verify session-key JMT inclusion.
    println!("cycle-tracker-report-start: jmt_verify");
    let leaf = SessionKeyLeaf {
        account_address: bench.order.account_address,
        key_index: bench.order.key_index,
        pubkey_x: bench.order.pubkey_x.0,
        pubkey_y: bench.order.pubkey_y.0,
    };
    let leaf_value = encode_session_key_leaf(&leaf);
    let key_hash = KeyHash(session_key_hash(
        &bench.order.account_address,
        bench.order.key_index,
    ));
    w.merkle_proof
        .verify_existence(RootHash(w.session_key_root), key_hash, &leaf_value)
        .expect("session key not registered — JMT inclusion proof failed");
    println!("cycle-tracker-report-end: jmt_verify");

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

    commit_borsh(&ProofOutput {
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

    commit_borsh(&ProofOutput {
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

    commit_borsh(&ProofOutput {
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

    commit_borsh(&ProofOutput {
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

    commit_borsh(&ProofOutput {
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

    commit_borsh(&ProofOutput {
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
    let session_key_root = RootHash(w.session_key_root);

    println!("cycle-tracker-report-start: batch_verify_merkle_total");
    for entry in &w.orders {
        // JMT membership check
        let leaf = SessionKeyLeaf {
            account_address: entry.bench.order.account_address,
            key_index: entry.bench.order.key_index,
            pubkey_x: entry.bench.order.pubkey_x.0,
            pubkey_y: entry.bench.order.pubkey_y.0,
        };
        let leaf_value = encode_session_key_leaf(&leaf);
        let key_hash = KeyHash(session_key_hash(
            &entry.bench.order.account_address,
            entry.bench.order.key_index,
        ));
        entry
            .merkle_proof
            .verify_existence(session_key_root, key_hash, &leaf_value)
            .expect("session key not registered — JMT inclusion proof failed");

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

    commit_borsh(&ProofOutput {
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
    let session_key_root = RootHash(w.session_key_root);

    // 1. One JMT proof per unique session key.
    println!("cycle-tracker-report-start: dedup_merkle_total");
    for key in &w.unique_keys {
        let leaf = SessionKeyLeaf {
            account_address: key.account_address,
            key_index: key.key_index,
            pubkey_x: key.pubkey_x,
            pubkey_y: key.pubkey_y,
        };
        let leaf_value = encode_session_key_leaf(&leaf);
        let key_hash = KeyHash(session_key_hash(&key.account_address, key.key_index));
        key.merkle_proof
            .verify_existence(session_key_root, key_hash, &leaf_value)
            .expect("session key not registered — JMT inclusion proof failed");
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

    commit_borsh(&ProofOutput {
        old_session_key_root: w.session_key_root,
        new_session_key_root: w.session_key_root,
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_DEDUP_{}u_{}o", unique_count, order_count),
    });
}

// ── Batch Septic Dedup (BatchExistenceProof: single verify call, shared-hash caching) ──

/// Same shape as `handle_batch_septic_dedup`, but the unique-key Merkle
/// membership is proved with a single `BatchExistenceProof::verify` call
/// that caches intermediate Poseidon2 hashes at shared internal nodes.
/// Expected win: ~40% reduction in `dedup_merkle_total` when the batch
/// has overlapping key-prefix paths.
fn handle_batch_septic_dedup_batch(w: BatchSepticDedupBatchWitness) {
    let unique_count = w.unique_keys.len();
    let order_count = w.orders.len();
    let session_key_root = RootHash(w.session_key_root);

    // 1. Single batch JMT verification (all unique keys in one pass).
    println!("cycle-tracker-report-start: dedup_batch_merkle_total");
    w.batch_proof
        .verify(session_key_root)
        .expect("BatchExistenceProof verify failed");
    println!("cycle-tracker-report-end: dedup_batch_merkle_total");

    // 2. Bind each proven entry to the claimed `unique_keys[i]`. The batch
    //    proof authenticates the *value bytes* at each leaf but Schnorr
    //    below pulls the pubkey from `unique_keys[idx]`, so a malicious host
    //    could otherwise pair one key's proof with another key's pubkey.
    //    Cross-check address, key_index, pubkey, and derived key_hash.
    assert_eq!(
        w.batch_proof.entries.len(),
        unique_count,
        "batch proof entry count must equal unique_keys length"
    );
    println!("cycle-tracker-report-start: dedup_batch_bind_leaves");
    for (i, entry) in w.batch_proof.entries.iter().enumerate() {
        let leaf: SessionKeyLeaf =
            bincode::deserialize(&entry.value).expect("invalid session key leaf");
        let key_info = &w.unique_keys[i];
        assert!(
            leaf.account_address == key_info.account_address
                && leaf.key_index == key_info.key_index
                && leaf.pubkey_x == key_info.pubkey_x
                && leaf.pubkey_y == key_info.pubkey_y,
            "leaf/unique_keys mismatch at entry {}",
            i
        );
        let expected_key_hash = KeyHash(session_key_hash(
            &key_info.account_address,
            key_info.key_index,
        ));
        assert!(
            entry.key_hash == expected_key_hash,
            "entry key_hash does not match derived session_key_hash at entry {}",
            i
        );
    }
    println!("cycle-tracker-report-end: dedup_batch_bind_leaves");

    // 3. Per-order Schnorr verify; pubkey from unique_keys (now bound).
    println!("cycle-tracker-report-start: dedup_batch_schnorr_total");
    for order in &w.orders {
        let key = &w.unique_keys[order.key_idx as usize];
        let r_point = sp1_lib::septic::SepticPoint::new(order.signature_r_x, order.signature_r_y);
        let pubkey = sp1_lib::septic::SepticPoint::new(key.pubkey_x, key.pubkey_y);
        let result =
            sp1_lib::septic::schnorr_compute(&pubkey, &order.signature_s, &order.challenge_e);
        assert!(
            result.x() == r_point.x() && result.y() == r_point.y(),
            "Schnorr verify failed in dedup batch"
        );
    }
    println!("cycle-tracker-report-end: dedup_batch_schnorr_total");

    commit_borsh(&ProofOutput {
        old_session_key_root: w.session_key_root,
        new_session_key_root: w.session_key_root,
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_DEDUP_BATCH_{}u_{}o", unique_count, order_count),
    });
}

// ── Batch Septic Dedup (rkyv zero-copy) ────────────────────────────────────

/// Same verification semantics as `handle_batch_septic_dedup_batch`, but the
/// witness is accessed *zero-copy* from the rkyv archive written by the host
/// — no borsh deserialization of the ~1 MB order vector. The guest does:
///
///   1. `read_vec()` into an owned byte buffer.
///   2. `rkyv::access_unchecked` to reinterpret those bytes as a reference
///      to `ArchivedBatchSepticDedupBatchWitness` (just a pointer cast).
///   3. Call `ArchivedBatchExistenceProof::verify` which has identical logic
///      to the owned verify.
///   4. Per-order Schnorr on the archived orders (fields converted via
///      `to_native()` into `[u32; N]` arrays expected by the precompile).
///
/// The ~18M residual observed on the borsh path is dominated by deserialize
/// overhead; this handler should collapse it to essentially the read_vec
/// copy cost.
fn handle_batch_septic_dedup_rkyv() {
    // 1. Read the rkyv witness bytes (second stdin chunk).
    println!("cycle-tracker-report-start: rkyv_read");
    let bytes = sp1_zkvm::io::read_vec();
    println!("cycle-tracker-report-end: rkyv_read");

    // 2. Zero-copy access. `access_unchecked` is a pointer cast — it does
    //    NOT validate the archive. The guest trusts that the host encoded
    //    the witness correctly; any tampering produces a proof-verify
    //    failure below.
    println!("cycle-tracker-report-start: rkyv_access");
    let archived: &ArchivedBatchSepticDedupBatchWitness =
        unsafe { rkyv::access_unchecked::<ArchivedBatchSepticDedupBatchWitness>(&bytes) };
    println!("cycle-tracker-report-end: rkyv_access");

    let unique_count = archived.unique_keys.len();
    let order_count = archived.orders.len();
    let session_key_root_bytes: [u8; 32] = archived.session_key_root;
    let session_key_root = RootHash(session_key_root_bytes);

    // 3. Single batch JMT verify — directly on the archived representation.
    println!("cycle-tracker-report-start: rkyv_merkle_total");
    archived
        .batch_proof
        .verify(session_key_root)
        .expect("ArchivedBatchExistenceProof verify failed");
    println!("cycle-tracker-report-end: rkyv_merkle_total");

    // 4. Bind each authenticated leaf to the claimed `unique_keys[i]` so
    //    the host can't swap keys between Merkle and Schnorr verification.
    assert_eq!(
        archived.batch_proof.entries.len(),
        unique_count,
        "batch proof entry count must equal unique_keys length"
    );
    println!("cycle-tracker-report-start: rkyv_bind_leaves");
    for (i, entry) in archived.batch_proof.entries.iter().enumerate() {
        // `entry.value` is `ArchivedVec<u8>`; `as_slice()` gives `&[u8]`.
        let leaf: SessionKeyLeaf =
            bincode::deserialize(entry.value.as_slice()).expect("invalid session key leaf");
        let key_info = &archived.unique_keys[i];
        let info_address: [u8; 20] = key_info.account_address;
        let info_pubkey_x: [u32; 7] = archived_array7_to_native(&key_info.pubkey_x);
        let info_pubkey_y: [u32; 7] = archived_array7_to_native(&key_info.pubkey_y);
        assert!(
            leaf.account_address == info_address
                && leaf.key_index == key_info.key_index
                && leaf.pubkey_x == info_pubkey_x
                && leaf.pubkey_y == info_pubkey_y,
            "leaf/unique_keys mismatch at entry {}",
            i
        );
        let expected_key_hash = session_key_hash(&info_address, key_info.key_index);
        let proven_key_hash: [u8; 32] = entry.key_hash.0;
        assert!(
            proven_key_hash == expected_key_hash,
            "entry key_hash does not match derived session_key_hash at entry {}",
            i
        );
    }
    println!("cycle-tracker-report-end: rkyv_bind_leaves");

    // 5. Per-order Schnorr verify; pubkey from the now-bound unique_keys.
    println!("cycle-tracker-report-start: rkyv_schnorr_total");
    for order in archived.orders.iter() {
        let key = &archived.unique_keys[order.key_idx.to_native() as usize];
        let r_point = sp1_lib::septic::SepticPoint::new(
            archived_array7_to_native(&order.signature_r_x),
            archived_array7_to_native(&order.signature_r_y),
        );
        let pubkey = sp1_lib::septic::SepticPoint::new(
            archived_array7_to_native(&key.pubkey_x),
            archived_array7_to_native(&key.pubkey_y),
        );
        let s_limbs = archived_array8_to_native(&order.signature_s);
        let e_limbs = archived_array8_to_native(&order.challenge_e);
        let result = sp1_lib::septic::schnorr_compute(&pubkey, &s_limbs, &e_limbs);
        assert!(
            result.x() == r_point.x() && result.y() == r_point.y(),
            "Schnorr verify failed in rkyv dedup batch"
        );
    }
    println!("cycle-tracker-report-end: rkyv_schnorr_total");

    commit_borsh(&ProofOutput {
        old_session_key_root: session_key_root_bytes,
        new_session_key_root: session_key_root_bytes,
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_SEPTIC_DEDUP_RKYV_{}u_{}o", unique_count, order_count),
    });
}

/// Archived `[u32; 7]` stores each element as `rend::u32_le` (transparent
/// wrapper on LE targets); convert back to the native `[u32; 7]` shape
/// expected by the septic precompile.
#[inline(always)]
fn archived_array7_to_native(arr: &rkyv::Archived<[u32; 7]>) -> [u32; 7] {
    [
        arr[0].to_native(),
        arr[1].to_native(),
        arr[2].to_native(),
        arr[3].to_native(),
        arr[4].to_native(),
        arr[5].to_native(),
        arr[6].to_native(),
    ]
}

#[inline(always)]
fn archived_array8_to_native(arr: &rkyv::Archived<[u32; 8]>) -> [u32; 8] {
    [
        arr[0].to_native(),
        arr[1].to_native(),
        arr[2].to_native(),
        arr[3].to_native(),
        arr[4].to_native(),
        arr[5].to_native(),
        arr[6].to_native(),
        arr[7].to_native(),
    ]
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

    commit_borsh(&ProofOutput {
        old_session_key_root: [0u8; 32],
        new_session_key_root: [0u8; 32],
        account_address: [0u8; 20],
        key_index: 0,
        proof_type: format!("BATCH_ETH_{}", count),
    });
}

// ── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    // borsh-encoded ProgramInput (faster than bincode in the zkVM).
    let raw = sp1_zkvm::io::read_vec();
    let input: ProgramInput =
        borsh::from_slice(&raw).expect("borsh deserialize ProgramInput");
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
        ProgramInput::BatchSepticDedupBatch(w) => handle_batch_septic_dedup_batch(w),
        ProgramInput::BatchSepticDedupRkyv => handle_batch_septic_dedup_rkyv(),
        ProgramInput::BatchEth(w) => handle_batch_eth(w),
    }
}
