//! Backend state — JMT-backed session-key store.
//!
//! Wraps a `MockTreeStore` keyed by `session_key_hash(address, key_index)`
//! and hashed with `Poseidon2Hasher`. Both `register_key` and
//! `get_key_proof` produce JMT proofs that the SP1 guest verifies via
//! `SparseMerkleProof::verify_existence` / `verify_nonexistence`.

use std::collections::HashMap;
use std::marker::PhantomData;

use jmt::mock::MockTreeStore;
use jmt::proof::SparseMerkleProof;
use jmt::{JellyfishMerkleTree, KeyHash};

use shared::{
    encode_session_key_leaf, session_key_hash, Poseidon2Hasher, SessionKey, SessionKeyLeaf,
};

type SessionKeyTree<'a> = JellyfishMerkleTree<'a, MockTreeStore, Poseidon2Hasher>;

const EMPTY_ROOT: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";

pub struct RegisterKeyResult {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_proof: SparseMerkleProof<Poseidon2Hasher>,
    /// `Some(leaf)` when rotating an existing key, `None` for a fresh slot.
    pub old_leaf: Option<SessionKeyLeaf>,
}

pub struct KeyProofResult {
    pub key: SessionKey,
    pub proof: SparseMerkleProof<Poseidon2Hasher>,
    pub root: [u8; 32],
}

pub struct AppState {
    pub store: MockTreeStore,
    /// JMT version. `0` means the tree is empty (no puts yet); `current_root`
    /// is the JMT placeholder hash and `get_with_proof` would fail with
    /// `MissingRootError`, so we hand back an empty proof in that case.
    pub version: u64,
    pub current_root: [u8; 32],
    pub session_keys: HashMap<(String, u8), SessionKey>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            store: MockTreeStore::default(),
            version: 0,
            current_root: EMPTY_ROOT,
            session_keys: HashMap::new(),
        }
    }

    /// Insert (or rotate) the given session key. Returns the JMT proof of
    /// the *pre-insertion* state, the old leaf (if any), and the new root.
    pub fn register_key(
        &mut self,
        address: [u8; 20],
        key: SessionKey,
    ) -> Result<RegisterKeyResult, String> {
        let key_hash_bytes = session_key_hash(&address, key.key_index);
        let key_hash = KeyHash(key_hash_bytes);

        let old_root = self.current_root;

        // 1. Capture proof of the OLD state (before insertion).
        //    Empty tree (version 0) has no stored root node — construct an
        //    empty non-inclusion proof against EMPTY_ROOT directly.
        let (old_value, old_proof) = if self.version == 0 {
            (None, empty_proof())
        } else {
            let tree: SessionKeyTree<'_> = JellyfishMerkleTree::new(&self.store);
            tree.get_with_proof(key_hash, self.version)
                .map_err(|e| format!("get_with_proof: {e}"))?
        };

        let old_leaf = match old_value {
            Some(bytes) => Some(
                bincode::deserialize::<SessionKeyLeaf>(&bytes)
                    .map_err(|e| format!("decode old leaf: {e}"))?,
            ),
            None => None,
        };

        // 2. Build and insert the new leaf at version+1.
        let new_leaf = SessionKeyLeaf {
            account_address: address,
            key_index: key.key_index,
            pubkey_x: key.pubkey_x,
            pubkey_y: key.pubkey_y,
        };
        let new_value = encode_session_key_leaf(&new_leaf);

        let new_version = self.version + 1;
        let (new_root, batch) = {
            let tree: SessionKeyTree<'_> = JellyfishMerkleTree::new(&self.store);
            tree.put_value_set(vec![(key_hash, Some(new_value))], new_version)
                .map_err(|e| format!("put_value_set: {e}"))?
        };

        self.store
            .write_tree_update_batch(batch)
            .map_err(|e| format!("write batch: {e}"))?;

        self.version = new_version;
        self.current_root = new_root.0;

        let address_hex = hex::encode(address);
        self.session_keys.insert((address_hex, key.key_index), key);

        Ok(RegisterKeyResult {
            old_root,
            new_root: new_root.0,
            old_proof,
            old_leaf,
        })
    }

    /// JMT inclusion proof for a previously registered key.
    pub fn get_key_proof(
        &self,
        address: [u8; 20],
        key_index: u8,
    ) -> Option<KeyProofResult> {
        let address_hex = hex::encode(address);
        let key = self.session_keys.get(&(address_hex, key_index))?.clone();

        let key_hash = KeyHash(session_key_hash(&address, key_index));
        let tree: SessionKeyTree<'_> = JellyfishMerkleTree::new(&self.store);
        let (_value, proof) = tree.get_with_proof(key_hash, self.version).ok()?;

        Some(KeyProofResult {
            key,
            proof,
            root: self.current_root,
        })
    }
}

/// JMT placeholder proof — empty siblings, no leaf. Verifies as
/// non-inclusion against `EMPTY_ROOT` for any key.
fn empty_proof() -> SparseMerkleProof<Poseidon2Hasher> {
    SparseMerkleProof {
        leaf: None,
        siblings: Vec::new(),
        phantom_hasher: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_key(idx: u8) -> SessionKey {
        SessionKey {
            pubkey_x: [idx as u32 + 1; 7],
            pubkey_y: [idx as u32 + 2; 7],
            key_index: idx,
        }
    }

    #[test]
    fn empty_tree_root_is_placeholder() {
        let state = AppState::new();
        assert_eq!(state.current_root, EMPTY_ROOT);
        assert_eq!(state.version, 0);
    }

    #[test]
    fn register_first_key_changes_root_and_verifies() {
        let mut state = AppState::new();
        let address = [0xAB; 20];
        let key = fresh_key(0);

        let result = state.register_key(address, key.clone()).expect("register");

        assert_eq!(result.old_root, EMPTY_ROOT, "old root should be EMPTY_ROOT");
        assert!(result.old_leaf.is_none(), "fresh slot has no old leaf");
        assert_ne!(result.new_root, EMPTY_ROOT, "new root must differ");
        assert_eq!(state.current_root, result.new_root);
        assert_eq!(state.version, 1);

        // The empty proof verifies non-existence against EMPTY_ROOT.
        let key_hash = jmt::KeyHash(shared::session_key_hash(&address, 0));
        result
            .old_proof
            .verify_nonexistence(jmt::RootHash(EMPTY_ROOT), key_hash)
            .expect("empty proof should verify non-existence against EMPTY_ROOT");

        // The current key proof verifies inclusion against the new root.
        let proof = state.get_key_proof(address, 0).expect("registered key");
        let leaf = SessionKeyLeaf {
            account_address: address,
            key_index: 0,
            pubkey_x: key.pubkey_x,
            pubkey_y: key.pubkey_y,
        };
        let leaf_value = encode_session_key_leaf(&leaf);
        proof
            .proof
            .verify_existence(jmt::RootHash(proof.root), key_hash, leaf_value)
            .expect("inclusion proof should verify");
    }

    #[test]
    fn rotate_key_returns_old_leaf() {
        let mut state = AppState::new();
        let address = [0xCD; 20];
        let first = fresh_key(0);
        state.register_key(address, first.clone()).expect("first register");

        let rotated = SessionKey {
            pubkey_x: [99u32; 7],
            pubkey_y: [88u32; 7],
            key_index: 0,
        };
        let result = state.register_key(address, rotated.clone()).expect("rotate");

        let old_leaf = result.old_leaf.expect("rotation must surface old leaf");
        assert_eq!(old_leaf.pubkey_x, first.pubkey_x);
        assert_eq!(old_leaf.pubkey_y, first.pubkey_y);

        // Old proof verifies inclusion of the OLD leaf against the OLD root.
        let key_hash = jmt::KeyHash(shared::session_key_hash(&address, 0));
        let old_value = encode_session_key_leaf(&old_leaf);
        result
            .old_proof
            .verify_existence(jmt::RootHash(result.old_root), key_hash, old_value)
            .expect("old leaf inclusion proof should verify against old root");
    }

    #[test]
    fn register_witness_bincodes_round_trip() {
        use shared::{ProgramInput, RegisterKeyRequest, RegisterKeyWitness};

        let mut state = AppState::new();
        let address = [0xEE; 20];
        let key = fresh_key(0);
        let result = state.register_key(address, key.clone()).expect("register");

        let witness = RegisterKeyWitness {
            request: RegisterKeyRequest {
                account_address: address,
                key_index: 0,
                pubkey_x: key.pubkey_x,
                pubkey_y: key.pubkey_y,
                eth_signature_hex: "00".repeat(65),
            },
            old_session_key_root: result.old_root,
            new_session_key_root: result.new_root,
            old_proof: result.old_proof,
            old_leaf: result.old_leaf,
        };
        let input = ProgramInput::RegisterKey(witness);

        let bytes = bincode::serialize(&input).expect("serialize");
        let _round: ProgramInput = bincode::deserialize(&bytes).expect("deserialize");
    }

    #[test]
    fn two_distinct_keys_independent_proofs() {
        let mut state = AppState::new();
        let addr_a = [0x11; 20];
        let addr_b = [0x22; 20];
        state.register_key(addr_a, fresh_key(0)).expect("a");
        state.register_key(addr_b, fresh_key(0)).expect("b");

        let proof_a = state.get_key_proof(addr_a, 0).expect("a registered");
        let proof_b = state.get_key_proof(addr_b, 0).expect("b registered");
        assert_eq!(proof_a.root, proof_b.root, "shared root after both inserts");

        let key_a_hash = jmt::KeyHash(shared::session_key_hash(&addr_a, 0));
        let leaf_a = encode_session_key_leaf(&SessionKeyLeaf {
            account_address: addr_a,
            key_index: 0,
            pubkey_x: proof_a.key.pubkey_x,
            pubkey_y: proof_a.key.pubkey_y,
        });
        proof_a
            .proof
            .verify_existence(jmt::RootHash(proof_a.root), key_a_hash, leaf_a)
            .expect("a inclusion");
    }
}
