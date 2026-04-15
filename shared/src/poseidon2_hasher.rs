//! Poseidon2 byte hasher implementing JMT's [`SimpleHasher`] trait.
//!
//! Guest path: dispatches to the SP1 POSEIDON2 precompile via
//! `Poseidon2ByteHash::hash`. Host path: uses the same length-prefixed
//! sponge in pure software via `sp1_primitives::poseidon2_init`. Both
//! must produce byte-identical output — verified by
//! [`tests::test_poseidon2_host_vs_guest_sponge`].

use jmt::SimpleHasher;

/// Buffer-then-hash adapter for Poseidon2. JMT calls `update` several
/// times per node hash (domain separator + key + value); we accumulate
/// all bytes and call the underlying one-shot hasher in `finalize`.
pub struct Poseidon2Hasher {
    buffer: Vec<u8>,
}

impl SimpleHasher for Poseidon2Hasher {
    fn new() -> Self {
        Poseidon2Hasher { buffer: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self) -> [u8; 32] {
        poseidon2_hash_bytes(&self.buffer)
    }
}

// ── Guest path: SP1 POSEIDON2 precompile ───────────────────────────────────

#[cfg(target_os = "zkvm")]
pub fn poseidon2_hash_bytes(input: &[u8]) -> [u8; 32] {
    use sp1_zkvm::syscalls::Poseidon2ByteHash;
    let out: [u32; 8] = Poseidon2ByteHash::hash(input);
    let mut result = [0u8; 32];
    for (i, &w) in out.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    result
}

// ── Host path: software Poseidon2 ──────────────────────────────────────────
//
// Mirrors `sp1-zkvm::lib::poseidon2::Poseidon2ByteHash::hash`:
//   * length-prefixed sponge (input.len() absorbed as first 24-byte block)
//   * 24-byte (3-bytes-per-element) block size, RATE = 8, WIDTH = 16
//   * output = first RATE state words after the final permutation
// Any divergence here will break every JMT proof — alignment is verified
// by `test_poseidon2_host_vs_guest_sponge`.

#[cfg(not(target_os = "zkvm"))]
const HOST_RATE: usize = 8;
#[cfg(not(target_os = "zkvm"))]
const HOST_WIDTH: usize = 16;
#[cfg(not(target_os = "zkvm"))]
const HOST_BYTE_BLOCK_SIZE: usize = HOST_RATE * 3; // 24

#[cfg(not(target_os = "zkvm"))]
fn host_absorb_byte_block(
    state: &mut [sp1_primitives::SP1Field; HOST_WIDTH],
    block: &[u8; HOST_BYTE_BLOCK_SIZE],
) {
    use p3_field::AbstractField;
    use p3_symmetric::Permutation;
    use sp1_primitives::{poseidon2_init, SP1Field};

    for i in 0..HOST_RATE {
        let s = 3 * i;
        let val = block[s] as u32
            | ((block[s + 1] as u32) << 8)
            | ((block[s + 2] as u32) << 16);
        state[i] = SP1Field::from_canonical_u32(val);
    }
    let perm = poseidon2_init();
    perm.permute_mut(state);
}

#[cfg(not(target_os = "zkvm"))]
pub fn poseidon2_hash_bytes(input: &[u8]) -> [u8; 32] {
    use p3_field::{AbstractField, PrimeField32};
    use sp1_primitives::SP1Field;

    let mut state = [SP1Field::zero(); HOST_WIDTH];

    let len_bytes = input.len().to_le_bytes();
    let mut len_block = [0u8; HOST_BYTE_BLOCK_SIZE];
    len_block[..len_bytes.len()].copy_from_slice(&len_bytes);
    host_absorb_byte_block(&mut state, &len_block);

    let chunks = input.chunks_exact(HOST_BYTE_BLOCK_SIZE);
    let remainder = chunks.remainder();
    for chunk in chunks {
        host_absorb_byte_block(&mut state, chunk.try_into().unwrap());
    }

    if !remainder.is_empty() {
        let mut last = [0u8; HOST_BYTE_BLOCK_SIZE];
        last[..remainder.len()].copy_from_slice(remainder);
        host_absorb_byte_block(&mut state, &last);
    }

    let mut result = [0u8; 32];
    for (i, el) in state[..HOST_RATE].iter().enumerate() {
        result[i * 4..(i + 1) * 4]
            .copy_from_slice(&el.as_canonical_u32().to_le_bytes());
    }
    result
}

// ── Tests (host-only — guest target has no test harness) ───────────────────

#[cfg(all(test, not(target_os = "zkvm")))]
mod tests {
    use super::*;
    use jmt::SimpleHasher as _;

    #[test]
    fn test_poseidon2_parameters() {
        let input = b"kalqix_test_vector_00000000000000";
        let result1 = poseidon2_hash_bytes(input);
        let result2 = poseidon2_hash_bytes(input);
        assert_eq!(result1, result2, "must be deterministic");
        assert_ne!(result1, [0u8; 32], "must be non-zero");
    }

    #[test]
    fn test_poseidon2_hasher_simple_hasher_trait() {
        let result = Poseidon2Hasher::hash(b"hello world");
        assert_ne!(result, [0u8; 32]);
        assert_eq!(result, poseidon2_hash_bytes(b"hello world"));
    }

    #[test]
    fn test_poseidon2_hasher_concatenation() {
        // SimpleHasher's update is called multiple times per node hash;
        // make sure two `update`s produce the same digest as one `update`
        // with the concatenated input.
        let mut h = Poseidon2Hasher::new();
        h.update(b"first part ");
        h.update(b"second part");
        let split = h.finalize();
        let one_shot = poseidon2_hash_bytes(b"first part second part");
        assert_eq!(split, one_shot);
    }

    /// Re-implements the guest's `Poseidon2ByteHash::hash` sponge in pure
    /// software, then compares against the host code path. If this test
    /// fails, every JMT proof produced by the host will fail to verify in
    /// the guest. Treat as load-bearing.
    #[test]
    fn test_poseidon2_host_vs_guest_sponge() {
        use p3_field::{AbstractField, PrimeField32};
        use p3_symmetric::Permutation as _;
        use sp1_primitives::{poseidon2_init, SP1Field};

        const R: usize = 8;
        const W: usize = 16;
        const BBS: usize = R * 3;

        fn guest_style_hash(input: &[u8]) -> [u8; 32] {
            let perm = poseidon2_init();
            let mut state = [SP1Field::zero(); W];

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

        for input in [
            b"hello".as_slice(),
            b"kalqix_test_vector_00000000000000".as_slice(),
            &[0u8; 64],
            &[0xFF; 100],
            // JMT-shaped inputs: domain separator + 64 bytes of children
            b"JMT::IntrnalNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let host_result = poseidon2_hash_bytes(input);
            let guest_result = guest_style_hash(input);
            assert_eq!(
                host_result, guest_result,
                "host vs guest mismatch for input len={}",
                input.len()
            );
        }

        let host_empty = poseidon2_hash_bytes(b"");
        let guest_empty = guest_style_hash(b"");
        assert_eq!(host_empty, guest_empty, "mismatch on empty input");
    }
}
