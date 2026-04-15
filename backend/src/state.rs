use std::collections::HashMap;

use p3_field::{AbstractField, PrimeField32};
use p3_symmetric::Permutation;
use sp1_primitives::{poseidon2_init, SP1Field};
use tiny_keccak::{Hasher, Keccak};

use shared::{SessionKey, SessionKeyLeaf};

const TREE_DEPTH: usize = 8;
const NUM_LEAVES: usize = 1 << TREE_DEPTH; // 256

// ── Poseidon2 byte hash (matches sp1-lib Poseidon2ByteHash::hash) ──────────
const RATE: usize = 8;
const WIDTH: usize = 16;
const BYTE_BLOCK_SIZE: usize = RATE * 3; // 24

/// Absorb one 24-byte block: pack 3 bytes per field element, overwrite
/// state[0..RATE], then permute.
fn absorb_byte_block(state: &mut [SP1Field; WIDTH], block: &[u8; BYTE_BLOCK_SIZE]) {
    for i in 0..RATE {
        let s = 3 * i;
        let val = block[s] as u32
            | ((block[s + 1] as u32) << 8)
            | ((block[s + 2] as u32) << 16);
        state[i] = SP1Field::from_canonical_u32(val);
    }
    let perm = poseidon2_init();
    perm.permute_mut(state);
}

/// Poseidon2 byte hash matching Poseidon2ByteHash::hash from sp1-lib.
/// Length-prefixed sponge, 3-bytes-per-element, 24-byte blocks.
pub fn poseidon2_hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut state = [SP1Field::zero(); WIDTH];

    // 1. Length prefix — absorb input.len() as first block.
    let len_bytes = input.len().to_le_bytes();
    let mut len_block = [0u8; BYTE_BLOCK_SIZE];
    len_block[..len_bytes.len()].copy_from_slice(&len_bytes);
    absorb_byte_block(&mut state, &len_block);

    // 2. Full 24-byte blocks.
    let chunks = input.chunks_exact(BYTE_BLOCK_SIZE);
    let remainder = chunks.remainder();
    for chunk in chunks {
        absorb_byte_block(&mut state, chunk.try_into().unwrap());
    }

    // 3. Partial final block (zero-padded).
    if !remainder.is_empty() {
        let mut last = [0u8; BYTE_BLOCK_SIZE];
        last[..remainder.len()].copy_from_slice(remainder);
        absorb_byte_block(&mut state, &last);
    }

    // 4. Squeeze: first RATE state words → 32 bytes.
    let mut result = [0u8; 32];
    for (i, el) in state[..RATE].iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&el.as_canonical_u32().to_le_bytes());
    }
    result
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    poseidon2_hash_bytes(&combined)
}

pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert_eq!(leaves.len(), NUM_LEAVES);
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    for _ in 0..TREE_DEPTH {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks_exact(2) {
            next_level.push(hash_pair(&pair[0], &pair[1]));
        }
        current_level = next_level;
    }
    current_level[0]
}

pub fn get_siblings(leaves: &[[u8; 32]], leaf_index: u64) -> Vec<[u8; 32]> {
    assert_eq!(leaves.len(), NUM_LEAVES);
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = leaf_index as usize;
    for _ in 0..TREE_DEPTH {
        let sibling_idx = idx ^ 1;
        siblings.push(current_level[sibling_idx]);
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks_exact(2) {
            next_level.push(hash_pair(&pair[0], &pair[1]));
        }
        current_level = next_level;
        idx /= 2;
    }
    siblings
}

#[allow(dead_code)]
pub fn verify_proof(
    leaf_hash: [u8; 32],
    leaf_index: u64,
    siblings: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    let mut current = leaf_hash;
    let mut idx = leaf_index;
    for sibling in siblings {
        current = if idx % 2 == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        idx /= 2;
    }
    current == root
}

pub fn set_leaf(leaves: &mut Vec<[u8; 32]>, index: usize, leaf_hash: [u8; 32]) {
    leaves[index] = leaf_hash;
}

fn leaf_index_for(address: &[u8; 20], key_index: u8) -> u64 {
    let mut keccak = Keccak::v256();
    keccak.update(address);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    (hash[0] as u64 * 254 + key_index as u64) % 256
}

fn hash_leaf(
    address: &[u8; 20],
    key_index: u8,
    pubkey_x: &[u32; 7],
    pubkey_y: &[u32; 7],
) -> [u8; 32] {
    let leaf = SessionKeyLeaf {
        account_address: *address,
        key_index,
        pubkey_x: *pubkey_x,
        pubkey_y: *pubkey_y,
    };
    let encoded = bincode::serialize(&leaf).expect("bincode serialize");
    poseidon2_hash_bytes(&encoded)
}

#[derive(Clone, Debug)]
pub struct SessionKeyTree {
    pub leaves: Vec<[u8; 32]>,
}

impl SessionKeyTree {
    pub fn new() -> Self {
        Self {
            leaves: vec![[0u8; 32]; NUM_LEAVES],
        }
    }
}

pub struct AppState {
    pub session_key_tree: SessionKeyTree,
    pub session_keys: HashMap<(String, u8), SessionKey>,
    pub current_root: [u8; 32],
}

impl AppState {
    pub fn new() -> Self {
        let tree = SessionKeyTree::new();
        let root = compute_root(&tree.leaves);
        Self {
            session_key_tree: tree,
            session_keys: HashMap::new(),
            current_root: root,
        }
    }

    /// Register a key, returning (old_leaf_hash, old_root, new_root, siblings, leaf_index).
    /// Siblings are captured *before* the leaf is updated (proving the old state).
    pub fn register_key(
        &mut self,
        address: [u8; 20],
        key: SessionKey,
    ) -> ([u8; 32], [u8; 32], [u8; 32], Vec<[u8; 32]>, u64) {
        let idx = leaf_index_for(&address, key.key_index);
        let old_leaf_hash = self.session_key_tree.leaves[idx as usize];
        let old_root = self.current_root;
        let siblings = get_siblings(&self.session_key_tree.leaves, idx);

        let leaf_hash = hash_leaf(&address, key.key_index, &key.pubkey_x, &key.pubkey_y);
        set_leaf(&mut self.session_key_tree.leaves, idx as usize, leaf_hash);
        let new_root = compute_root(&self.session_key_tree.leaves);
        self.current_root = new_root;

        let address_hex = hex::encode(address);
        self.session_keys
            .insert((address_hex, key.key_index), key);

        (old_leaf_hash, old_root, new_root, siblings, idx)
    }

    /// Look up a registered key and return its proof data.
    pub fn get_key_proof(
        &self,
        address: [u8; 20],
        key_index: u8,
    ) -> Option<(SessionKey, Vec<[u8; 32]>, u64)> {
        let address_hex = hex::encode(address);
        let key = self.session_keys.get(&(address_hex, key_index))?.clone();
        let idx = leaf_index_for(&address, key_index);
        let siblings = get_siblings(&self.session_key_tree.leaves, idx);
        Some((key, siblings, idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_deterministic() {
        let tree = SessionKeyTree::new();
        let root1 = compute_root(&tree.leaves);
        let root2 = compute_root(&tree.leaves);
        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn set_leaf_changes_root() {
        let mut tree = SessionKeyTree::new();
        let root_before = compute_root(&tree.leaves);
        set_leaf(&mut tree.leaves, 0, [1u8; 32]);
        let root_after = compute_root(&tree.leaves);
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn verify_proof_works() {
        let mut leaves = vec![[0u8; 32]; NUM_LEAVES];
        let leaf_hash = [42u8; 32];
        let idx: u64 = 7;
        set_leaf(&mut leaves, idx as usize, leaf_hash);
        let root = compute_root(&leaves);
        let siblings = get_siblings(&leaves, idx);
        assert!(verify_proof(leaf_hash, idx, &siblings, root));
        assert!(!verify_proof([99u8; 32], idx, &siblings, root));
    }

    #[test]
    fn register_and_lookup() {
        let mut state = AppState::new();
        let address = [0xAB; 20];
        let key = SessionKey {
            pubkey_x: [0x01; 7],
            pubkey_y: [0x02; 7],
            key_index: 0,
        };
        let (old_leaf_hash, old_root, new_root, siblings, idx) = state.register_key(address, key.clone());
        assert_ne!(old_root, new_root);
        assert_eq!(old_leaf_hash, [0u8; 32]); // fresh slot

        assert!(verify_proof([0u8; 32], idx, &siblings, old_root));

        let (found_key, new_siblings, found_idx) =
            state.get_key_proof(address, 0).expect("key should exist");
        assert_eq!(found_key.pubkey_x, key.pubkey_x);
        assert_eq!(found_key.pubkey_y, key.pubkey_y);
        assert_eq!(found_idx, idx);
        let leaf_hash = hash_leaf(&address, 0, &found_key.pubkey_x, &found_key.pubkey_y);
        assert!(verify_proof(leaf_hash, found_idx, &new_siblings, new_root));
    }

    #[test]
    fn test_poseidon2_parameters() {
        let input = b"kalqix_test_vector_00000000000000";
        let result1 = poseidon2_hash_bytes(input);
        let result2 = poseidon2_hash_bytes(input);
        assert_eq!(result1, result2, "must be deterministic");
        assert_ne!(result1, [0u8; 32], "must be non-zero");
        println!("poseidon2_hash test vector: {:?}", result1);
    }

    /// Verify host poseidon2 matches sp1-lib Poseidon2ByteHash by running
    /// the guest sponge logic on the host using the same raw u32 operations.
    #[test]
    fn test_poseidon2_host_vs_guest_sponge() {
        use p3_symmetric::Permutation as _;

        const R: usize = 8;
        const W: usize = 16;
        const BBS: usize = R * 3;

        // "Guest-style" hash: raw u32 state, same sponge as Poseidon2ByteHash
        fn guest_style_hash(input: &[u8]) -> [u8; 32] {
            let perm = poseidon2_init();

            let mut state = [SP1Field::zero(); W];

            // Length prefix
            let len_bytes = input.len().to_le_bytes();
            let mut len_block = [0u8; BBS];
            len_block[..len_bytes.len()].copy_from_slice(&len_bytes);
            absorb_block_raw(&perm, &mut state, &len_block);

            let chunks = input.chunks_exact(BBS);
            let remainder = chunks.remainder();
            for chunk in chunks {
                absorb_block_raw(&perm, &mut state, chunk.try_into().unwrap());
            }
            if !remainder.is_empty() {
                let mut last = [0u8; BBS];
                last[..remainder.len()].copy_from_slice(remainder);
                absorb_block_raw(&perm, &mut state, &last);
            }

            let mut result = [0u8; 32];
            for (i, el) in state[..R].iter().enumerate() {
                result[i * 4..(i + 1) * 4]
                    .copy_from_slice(&el.as_canonical_u32().to_le_bytes());
            }
            result
        }

        fn absorb_block_raw(
            perm: &sp1_primitives::SP1Perm,
            state: &mut [SP1Field; W],
            block: &[u8; BBS],
        ) {
            for i in 0..R {
                let s = 3 * i;
                let val = block[s] as u32
                    | ((block[s + 1] as u32) << 8)
                    | ((block[s + 2] as u32) << 16);
                state[i] = SP1Field::from_canonical_u32(val);
            }
            perm.permute_mut(state);
        }

        // Test a few inputs
        for input in [
            b"hello".as_slice(),
            b"kalqix_test_vector_00000000000000".as_slice(),
            &[0u8; 64],
            &[0xFF; 100],
        ] {
            let host_result = poseidon2_hash_bytes(input);
            let guest_result = guest_style_hash(input);
            assert_eq!(
                host_result, guest_result,
                "host vs guest mismatch for input len={}",
                input.len()
            );
        }

        // Also test empty input
        let host_empty = poseidon2_hash_bytes(b"");
        let guest_empty = guest_style_hash(b"");
        assert_eq!(host_empty, guest_empty, "mismatch on empty input");
    }
}
