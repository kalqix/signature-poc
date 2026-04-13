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
    EthOrderWitness, OrderWitness, P256OrderWitness, ProgramInput, ProofOutput,
    RegisterKeyWitness, SessionKeyLeaf,
    eth_order_message, order_message, p256_order_message, register_key_message,
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

// ── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    let input: ProgramInput = sp1_zkvm::io::read();
    match input {
        ProgramInput::RegisterKey(w) => handle_register_key(w),
        ProgramInput::VerifyOrder(w) => handle_verify_order(w),
        ProgramInput::VerifyOrderEth(w) => handle_verify_order_eth(w),
        ProgramInput::VerifyOrderP256(w) => handle_verify_order_p256(w),
    }
}
