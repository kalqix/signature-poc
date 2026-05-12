//! WASM-compiled septic Schnorr signer for the KalqiX frontend.
//!
//! All Schnorr math (sign, verify, scalar generation) lives in
//! `shared::septic`. This crate is a thin WASM-bindgen shim that converts
//! JS-friendly `Vec<u32>` payloads to/from the limb-array types `shared`
//! expects. It stays out of the main workspace so it does not inherit SP1
//! patches (which don't target wasm32); `shared`'s deps fall back to
//! vanilla crates.io here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use shared::septic::{random_scalar, schnorr_sign, Fp7, SepticPoint};

// ─── WASM types ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KeyPairJs {
    priv_limbs: Vec<u32>,
    pub_x: Vec<u32>,
    pub_y: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
struct SignatureJs {
    r_x: Vec<u32>,
    r_y: Vec<u32>,
    s: Vec<u32>,
    challenge_e: Vec<u32>,
    pubkey_x: Vec<u32>,
    pubkey_y: Vec<u32>,
}

// ─── WASM exports ───────────────────────────────────────────────────────────

/// Generate a fresh septic Schnorr key pair.
/// Returns `{ priv_limbs: [u32; 8], pub_x: [u32; 7], pub_y: [u32; 7] }`.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let priv_limbs = random_scalar();
    let pubkey = SepticPoint::generator().scalar_mul(&priv_limbs);

    let kp = KeyPairJs {
        priv_limbs: priv_limbs.to_vec(),
        pub_x: pubkey.x.0.to_vec(),
        pub_y: pubkey.y.0.to_vec(),
    };
    serde_wasm_bindgen::to_value(&kp).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sign `message` with a septic Schnorr key.
///
/// Hash convention matches `shared::septic_order_message` / backend verify:
/// 1. `msg_hash = SHA256(message)`
/// 2. `k = random scalar in [1, r-1]`, `R = k·G`
/// 3. `e = SHA256(R_x || A_x || msg_hash) mod r`
/// 4. `s = (k - e·a) mod r`
#[wasm_bindgen]
pub fn sign_order(
    priv_limbs: Vec<u32>,
    pub_x: Vec<u32>,
    pub_y: Vec<u32>,
    message: &str,
) -> Result<JsValue, JsValue> {
    if priv_limbs.len() != 8 {
        return Err(JsValue::from_str("priv_limbs must be length 8"));
    }
    if pub_x.len() != 7 || pub_y.len() != 7 {
        return Err(JsValue::from_str("pub_x/pub_y must be length 7"));
    }

    let mut a_limbs = [0u32; 8];
    a_limbs.copy_from_slice(&priv_limbs);
    let mut px = [0u32; 7];
    px.copy_from_slice(&pub_x);
    let mut py = [0u32; 7];
    py.copy_from_slice(&pub_y);

    let pubkey = SepticPoint::new(Fp7(px), Fp7(py));
    let msg_hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();
    let k_limbs = random_scalar();

    let (r_x, r_y, s_limbs, e_limbs) = schnorr_sign(&a_limbs, &pubkey, &k_limbs, &msg_hash);

    let sig = SignatureJs {
        r_x: r_x.to_vec(),
        r_y: r_y.to_vec(),
        s: s_limbs.to_vec(),
        challenge_e: e_limbs.to_vec(),
        pubkey_x: pubkey.x.0.to_vec(),
        pubkey_y: pubkey.y.0.to_vec(),
    };
    serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Tests (native target only) ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shared::septic::{schnorr_verify, GROUP_ORDER};

    #[test]
    fn test_generator_on_curve() {
        assert!(SepticPoint::generator().on_curve());
    }

    #[test]
    fn test_scalar_mul_group_order_is_infinity() {
        let g = SepticPoint::generator();
        let result = g.scalar_mul(&GROUP_ORDER);
        assert!(result.is_infinity, "r·G must be point at infinity");
    }

    /// End-to-end: shared::schnorr_sign output verifies via shared::schnorr_verify.
    #[test]
    fn test_sign_verify_roundtrip_via_shared() {
        let g = SepticPoint::generator();
        let a_limbs = random_scalar();
        let pubkey = g.scalar_mul(&a_limbs);

        let msg = "ETH/USDC:BUY:2000000:100:ab123456789abcdef0112233445566778899aaef";
        let msg_hash: [u8; 32] = Sha256::digest(msg.as_bytes()).into();
        let k_limbs = random_scalar();

        let (r_x, r_y, s, e) = schnorr_sign(&a_limbs, &pubkey, &k_limbs, &msg_hash);
        assert!(schnorr_verify(&pubkey, &msg_hash, &r_x, &r_y, &s, &e));
    }
}
