use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionKey {
    pub pubkey: [u8; 32],
    pub key_index: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionKeyLeaf {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub pubkey: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterKeyRequest {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub pubkey_hex: String,
    pub eth_signature_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterKeyWitness {
    pub request: RegisterKeyRequest,
    pub old_leaf_hash: [u8; 32],
    pub old_session_key_root: [u8; 32],
    pub new_session_key_root: [u8; 32],
    pub merkle_siblings: Vec<[u8; 32]>,
    pub leaf_index: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedOrder {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub ed25519_signature_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OrderWitness {
    pub order: SignedOrder,
    pub session_key: SessionKey,
    pub session_key_root: [u8; 32],
    pub merkle_siblings: Vec<[u8; 32]>,
    pub leaf_index: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProofOutput {
    pub old_session_key_root: [u8; 32],
    pub new_session_key_root: [u8; 32],
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub proof_type: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EthSignedOrder {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub eth_signature_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EthOrderWitness {
    pub order: EthSignedOrder,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ProgramInput {
    RegisterKey(RegisterKeyWitness),
    VerifyOrder(OrderWitness),
    VerifyOrderEth(EthOrderWitness),
    VerifyOrderP256(P256OrderWitness),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P256SignedOrder {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub p256_signature_hex: String,
    pub p256_pubkey_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P256OrderWitness {
    pub order: P256SignedOrder,
}

pub fn order_message(order: &SignedOrder) -> Vec<u8> {
    let account_hex = hex::encode(order.account_address);
    format!(
        "{}:{}:{}:{}:{}",
        order.market, order.side, order.price, order.quantity, account_hex
    )
    .into_bytes()
}

pub fn eth_order_message(order: &EthSignedOrder) -> String {
    let account_hex = hex::encode(order.account_address);
    format!(
        "{}:{}:{}:{}:{}",
        order.market, order.side, order.price, order.quantity, account_hex
    )
}

pub fn p256_order_message(order: &P256SignedOrder) -> String {
    let account_hex = hex::encode(order.account_address);
    format!(
        "{}:{}:{}:{}:{}",
        order.market, order.side, order.price, order.quantity, account_hex
    )
}

pub fn register_key_message(
    address: &[u8; 20],
    pubkey: &[u8; 32],
    key_index: u8,
) -> String {
    let pubkey_hex = hex::encode(pubkey);
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
    fn test_order_message() {
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
            ed25519_signature_hex: String::new(),
        };
        let msg = order_message(&order);
        let expected = "ETH/USDC:BUY:2000000:100:ab123456789abcdef0112233445566778899aaef";
        assert_eq!(String::from_utf8(msg).unwrap(), expected);
    }

    #[test]
    fn test_register_key_message() {
        let address: [u8; 20] = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ];
        let pubkey: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let msg = register_key_message(&address, &pubkey, 3);
        let expected = "Register KalqiX Session Key\n\npubkey: 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\naccount: 0xabcdef0123456789abcdef0123456789abcdef01\nkey index: 3\nOnly sign this message for a trusted client!";
        assert_eq!(msg, expected);
    }
}
