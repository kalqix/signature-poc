use serde::{Deserialize, Serialize};

use jmt::proof::SparseMerkleProof;

pub mod poseidon2_hasher;
pub mod septic;

pub use poseidon2_hasher::{poseidon2_hash_bytes, Poseidon2Hasher};

// ── Session Key (septic Schnorr) ────────────────────────────────────────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct SessionKey {
    pub pubkey_x: [u32; 7],
    pub pubkey_y: [u32; 7],
    pub key_index: u8,
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct SessionKeyLeaf {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub pubkey_x: [u32; 7],
    pub pubkey_y: [u32; 7],
}

/// Canonical bincoded leaf bytes — used as the JMT value at this key.
pub fn encode_session_key_leaf(leaf: &SessionKeyLeaf) -> Vec<u8> {
    bincode::serialize(leaf).expect("bincode serialize")
}

/// JMT key hash for a session key slot. Same Poseidon2 byte hash on
/// host and guest, so backend and circuit address the same tree slot.
pub fn session_key_hash(address: &[u8; 20], key_index: u8) -> [u8; 32] {
    let mut input = [0u8; 21];
    input[..20].copy_from_slice(address);
    input[20] = key_index;
    poseidon2_hash_bytes(&input)
}

// ── Key Registration (secp256k1 EIP-191 + JMT insert) ──────────────────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct RegisterKeyRequest {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub pubkey_x: [u32; 7],
    pub pubkey_y: [u32; 7],
    pub eth_signature_hex: String,
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct RegisterKeyWitness {
    pub request: RegisterKeyRequest,
    pub old_session_key_root: [u8; 32],
    pub new_session_key_root: [u8; 32],
    /// Proof of the (key_hash) state under `old_session_key_root` —
    /// non-existence for fresh registration, existence for rotation.
    pub old_proof: SparseMerkleProof<Poseidon2Hasher>,
    /// `Some(old_leaf)` for rotation, `None` for fresh registration.
    pub old_leaf: Option<SessionKeyLeaf>,
}

// ── Septic Schnorr Order (with JMT membership proof) ───────────────────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct SignedOrder {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub signature_r_x: [u32; 7],
    pub signature_r_y: [u32; 7],
    pub signature_s: [u32; 8],
    pub challenge_e: [u32; 8],
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct OrderWitness {
    pub order: SignedOrder,
    pub session_key: SessionKey,
    pub session_key_root: [u8; 32],
    pub merkle_proof: SparseMerkleProof<Poseidon2Hasher>,
}

// ── Ethereum secp256k1 Order (benchmark comparison path, no Merkle) ─────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct EthSignedOrder {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub eth_signature_hex: String,
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct EthOrderWitness {
    pub order: EthSignedOrder,
}

// ── Single-order Septic Schnorr benchmark (Merkle-checked) ─────────────────

/// Standalone Schnorr-verify benchmark that mirrors the production `VerifyOrder`
/// path (Merkle membership + per-order Schnorr) but uses per-bit `scalar_mul`
/// syscalls instead of the `SEPTIC_VERIFY` precompile. Lets us isolate the
/// precompile's win while holding the Merkle overhead constant.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct VerifyOrderSepticWitness {
    pub bench: septic::SepticBenchWitness,
    pub session_key_root: [u8; 32],
    pub merkle_proof: SparseMerkleProof<Poseidon2Hasher>,
}

// ── Batch witnesses (benchmark profiling) ──────────────────────────────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchSepticWitness {
    pub orders: Vec<septic::SepticBenchWitness>,
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchSepticOptWitness {
    pub orders: Vec<septic::SepticBenchWitness>,
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchSepticSingleWitness {
    pub orders: Vec<septic::SepticBenchWitness>,
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchSepticVerifyWitness {
    pub orders: Vec<septic::SepticBenchWitness>,
}

/// One order in a Merkle-checked batch: Schnorr witness + per-order JMT
/// membership proof. The tree root is shared across the batch and lives on
/// the outer `BatchSepticVerifyMerkleWitness`.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct SepticMerkleOrder {
    pub bench: septic::SepticBenchWitness,
    pub merkle_proof: SparseMerkleProof<Poseidon2Hasher>,
}

/// Production-shaped batch Schnorr verify: per-order Merkle membership +
/// `SEPTIC_VERIFY` precompile. Cycle cost is the realistic per-order cost
/// for batched Schnorr in kalqix-zk-service.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchSepticVerifyMerkleWitness {
    pub orders: Vec<SepticMerkleOrder>,
    pub session_key_root: [u8; 32],
}

/// One unique session key in a deduped batch — JMT proof verified once
/// no matter how many orders reference it.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct DedupKey {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub pubkey_x: [u32; 7],
    pub pubkey_y: [u32; 7],
    pub merkle_proof: SparseMerkleProof<Poseidon2Hasher>,
}

/// One signed order in a deduped batch. Schnorr verifies per-order; the
/// pubkey comes from `unique_keys[key_idx]` so the same Merkle-verified key
/// can authorize many orders.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct DedupOrder {
    pub key_idx: u32,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub signature_r_x: [u32; 7],
    pub signature_r_y: [u32; 7],
    pub signature_s: [u32; 8],
    pub challenge_e: [u32; 8],
}

/// Realistic batch where one trader posts many orders: each unique
/// (account_address, key_index) is JMT-verified once, but every order
/// goes through SEPTIC_VERIFY independently.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchSepticDedupWitness {
    pub unique_keys: Vec<DedupKey>,
    pub orders: Vec<DedupOrder>,
    pub session_key_root: [u8; 32],
}

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct BatchEthWitness {
    pub orders: Vec<EthOrderWitness>,
}

// ── Proof Output ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub struct ProofOutput {
    pub old_session_key_root: [u8; 32],
    pub new_session_key_root: [u8; 32],
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub proof_type: String,
}

// ── Program Input ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug)]
pub enum ProgramInput {
    RegisterKey(RegisterKeyWitness),
    VerifyOrder(OrderWitness),
    VerifyOrderEth(EthOrderWitness),
    VerifyOrderSeptic(VerifyOrderSepticWitness),
    BatchSeptic(BatchSepticWitness),
    BatchSepticOpt(BatchSepticOptWitness),
    BatchSepticSingle(BatchSepticSingleWitness),
    BatchSepticOptSingle(BatchSepticOptWitness),
    BatchSepticVerify(BatchSepticVerifyWitness),
    BatchSepticVerifyMerkle(BatchSepticVerifyMerkleWitness),
    BatchSepticDedup(BatchSepticDedupWitness),
    BatchEth(BatchEthWitness),
}

// ── Message builders ────────────────────────────────────────────────────────

pub fn septic_order_message(order: &SignedOrder) -> String {
    let account_hex = hex::encode(order.account_address);
    format!(
        "{}:{}:{}:{}:{}",
        order.market, order.side, order.price, order.quantity, account_hex
    )
}

pub fn eth_order_message(order: &EthSignedOrder) -> String {
    let account_hex = hex::encode(order.account_address);
    format!(
        "{}:{}:{}:{}:{}",
        order.market, order.side, order.price, order.quantity, account_hex
    )
}

/// Serialize a septic pubkey as 56 bytes: x[28 LE] || y[28 LE].
pub fn pubkey_bytes(pubkey_x: &[u32; 7], pubkey_y: &[u32; 7]) -> [u8; 56] {
    let mut out = [0u8; 56];
    for i in 0..7 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&pubkey_x[i].to_le_bytes());
        out[28 + i * 4..28 + (i + 1) * 4].copy_from_slice(&pubkey_y[i].to_le_bytes());
    }
    out
}

pub fn register_key_message(
    address: &[u8; 20],
    pubkey_x: &[u32; 7],
    pubkey_y: &[u32; 7],
    key_index: u8,
) -> String {
    let pubkey_hex = hex::encode(pubkey_bytes(pubkey_x, pubkey_y));
    let address_hex = hex::encode(address);
    format!(
        "Register KalqiX Session Key\n\npubkey: 0x{}\naccount: 0x{}\nkey index: {}\nOnly sign this message for a trusted client!",
        pubkey_hex, address_hex, key_index
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_septic_order_message() {
        let order = SignedOrder {
            account_address: [
                0xab, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xef,
            ],
            key_index: 0,
            market: "ETH/USDC".to_string(),
            side: "BUY".to_string(),
            price: 2000000,
            quantity: 100,
            signature_r_x: [0u32; 7],
            signature_r_y: [0u32; 7],
            signature_s: [0u32; 8],
            challenge_e: [0u32; 8],
        };
        let msg = septic_order_message(&order);
        let expected = "ETH/USDC:BUY:2000000:100:ab123456789abcdef0112233445566778899aaef";
        assert_eq!(msg, expected);
    }

    #[test]
    fn test_register_key_message() {
        let address: [u8; 20] = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ];
        let pubkey_x: [u32; 7] = [
            0x04030201, 0x08070605, 0x0c0b0a09, 0x100f0e0d,
            0x14131211, 0x18171615, 0x1c1b1a19,
        ];
        let pubkey_y: [u32; 7] = [
            0x04030201, 0x08070605, 0x0c0b0a09, 0x100f0e0d,
            0x14131211, 0x18171615, 0x1c1b1a19,
        ];
        let msg = register_key_message(&address, &pubkey_x, &pubkey_y, 3);
        let expected = "Register KalqiX Session Key\n\npubkey: 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c\naccount: 0xabcdef0123456789abcdef0123456789abcdef01\nkey index: 3\nOnly sign this message for a trusted client!";
        assert_eq!(msg, expected);
    }

    #[test]
    fn session_key_hash_is_deterministic() {
        let addr = [0xAB; 20];
        let h1 = session_key_hash(&addr, 0);
        let h2 = session_key_hash(&addr, 0);
        let h3 = session_key_hash(&addr, 1);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h1, [0u8; 32]);
    }
}
