//! WASM-compiled septic Schnorr signer for the KalqiX frontend.
//!
//! Math is re-exported from `shared::septic` — the single source of truth
//! for Fp7, curve, and 256-bit scalar arithmetic. This crate stays out of
//! the workspace so it does not inherit SP1 patches (which don't target
//! wasm32); `shared`'s deps fall back to vanilla crates.io here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use shared::septic::{
    reduce_512_mod_r, scalar_mul_mod_r, scalar_sub, Fp7, SepticPoint,
};

// ─── Signing helpers (thin wrappers over shared) ────────────────────────────

fn random_scalar_limbs() -> [u32; 8] {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let mut limbs = [0u32; 8];
        for i in 0..8 {
            limbs[i] = u32::from_le_bytes([
                bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2], bytes[i * 4 + 3],
            ]);
        }
        let mut padded = [0u32; 16];
        padded[..8].copy_from_slice(&limbs);
        let reduced = reduce_512_mod_r(&padded);
        if reduced != [0u32; 8] {
            return reduced;
        }
    }
}

/// Reduce a 32-byte big-endian SHA-256 digest mod GROUP_ORDER.
fn be_hash_to_scalar_mod_r(hash: &[u8; 32]) -> [u32; 8] {
    let mut limbs = [0u32; 8];
    for i in 0..8 {
        let start = (7 - i) * 4;
        limbs[i] = u32::from_be_bytes([
            hash[start], hash[start + 1], hash[start + 2], hash[start + 3],
        ]);
    }
    let mut padded = [0u32; 16];
    padded[..8].copy_from_slice(&limbs);
    reduce_512_mod_r(&padded)
}

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
    let priv_limbs = random_scalar_limbs();
    let g = SepticPoint::generator();
    let pubkey = g.scalar_mul(&priv_limbs);

    let kp = KeyPairJs {
        priv_limbs: priv_limbs.to_vec(),
        pub_x: pubkey.x.0.to_vec(),
        pub_y: pubkey.y.0.to_vec(),
    };
    serde_wasm_bindgen::to_value(&kp).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sign `message` with a septic Schnorr key.
///
/// Matches `build_verify_order_septic_input` in `backend/src/bin/profile.rs`:
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
    let g = SepticPoint::generator();

    let mut h = Sha256::new();
    h.update(message.as_bytes());
    let msg_hash: [u8; 32] = h.finalize().into();

    let k_limbs = random_scalar_limbs();
    let r_point = g.scalar_mul(&k_limbs);

    let mut h = Sha256::new();
    h.update(r_point.x.to_bytes());
    h.update(pubkey.x.to_bytes());
    h.update(msg_hash);
    let e_hash: [u8; 32] = h.finalize().into();
    let e_limbs = be_hash_to_scalar_mod_r(&e_hash);

    let ea = scalar_mul_mod_r(&e_limbs, &a_limbs);
    let s_limbs = scalar_sub(&k_limbs, &ea);

    let sig = SignatureJs {
        r_x: r_point.x.0.to_vec(),
        r_y: r_point.y.0.to_vec(),
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
    use shared::septic::GROUP_ORDER;

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

    /// Schnorr self-check: s·G + e·A == R.
    #[test]
    fn test_schnorr_self_verify() {
        let g = SepticPoint::generator();
        let a_limbs = random_scalar_limbs();
        let pubkey = g.scalar_mul(&a_limbs);

        let msg = "ETH/USDC:BUY:2000000:100:ab123456789abcdef0112233445566778899aaef";
        let mut h = Sha256::new();
        h.update(msg.as_bytes());
        let msg_hash: [u8; 32] = h.finalize().into();

        let k_limbs = random_scalar_limbs();
        let r_point = g.scalar_mul(&k_limbs);

        let mut h = Sha256::new();
        h.update(r_point.x.to_bytes());
        h.update(pubkey.x.to_bytes());
        h.update(msg_hash);
        let e_hash: [u8; 32] = h.finalize().into();
        let e_limbs = be_hash_to_scalar_mod_r(&e_hash);

        let ea = scalar_mul_mod_r(&e_limbs, &a_limbs);
        let s_limbs = scalar_sub(&k_limbs, &ea);

        let s_g = g.scalar_mul(&s_limbs);
        let e_a = pubkey.scalar_mul(&e_limbs);
        let sum = s_g.add(&e_a);
        assert!(!sum.is_infinity && sum.x == r_point.x && sum.y == r_point.y);
    }
}
