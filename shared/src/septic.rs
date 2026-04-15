//! Septic extension field arithmetic, curve operations, and Schnorr types.
//!
//! Field: KoalaBear, p = 2^31 - 2^24 + 1.
//! Extension: Fp7 = Fp[z] / (z^7 - 3z - 5).
//! Curve:   y^2 = x^3 + 45x + 41·z^3 over Fp7 (prime subgroup order r, 217 bits).
//!
//! Frobenius constants and multiplication reduction rule mirror SP1's
//! production `septic_extension.rs`. Generator point is taken from SP1's
//! codebase (derived from digits of sqrt(2)) and r·G = O is asserted in tests.

use serde::{Deserialize, Serialize};

// ─── KoalaBear base field ───────────────────────────────────────────────────

pub const P: u64 = 2130706433;

#[inline]
pub fn kb_add(a: u32, b: u32) -> u32 {
    let s = a as u64 + b as u64;
    (if s >= P { s - P } else { s }) as u32
}

#[inline]
pub fn kb_sub(a: u32, b: u32) -> u32 {
    let s = a as u64 + P - b as u64;
    (if s >= P { s - P } else { s }) as u32
}

#[inline]
pub fn kb_mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P) as u32
}

#[inline]
pub fn kb_neg(a: u32) -> u32 {
    if a == 0 { 0 } else { (P - a as u64) as u32 }
}

pub fn kb_pow(mut base: u32, mut exp: u64) -> u32 {
    let mut result = 1u32;
    while exp > 0 {
        if exp & 1 == 1 {
            result = kb_mul(result, base);
        }
        base = kb_mul(base, base);
        exp >>= 1;
    }
    result
}

pub fn kb_inv(a: u32) -> u32 {
    assert!(a != 0, "division by zero");
    kb_pow(a, P - 2)
}

// ─── Fp7 extension ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Fp7(pub [u32; 7]);

impl Fp7 {
    pub const fn zero() -> Self {
        Fp7([0; 7])
    }

    pub const fn one() -> Self {
        Fp7([1, 0, 0, 0, 0, 0, 0])
    }

    pub fn from_u32(val: u32) -> Self {
        Fp7([val % P as u32, 0, 0, 0, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 7]
    }

    pub fn add(&self, rhs: &Fp7) -> Fp7 {
        Fp7([
            kb_add(self.0[0], rhs.0[0]),
            kb_add(self.0[1], rhs.0[1]),
            kb_add(self.0[2], rhs.0[2]),
            kb_add(self.0[3], rhs.0[3]),
            kb_add(self.0[4], rhs.0[4]),
            kb_add(self.0[5], rhs.0[5]),
            kb_add(self.0[6], rhs.0[6]),
        ])
    }

    pub fn sub(&self, rhs: &Fp7) -> Fp7 {
        Fp7([
            kb_sub(self.0[0], rhs.0[0]),
            kb_sub(self.0[1], rhs.0[1]),
            kb_sub(self.0[2], rhs.0[2]),
            kb_sub(self.0[3], rhs.0[3]),
            kb_sub(self.0[4], rhs.0[4]),
            kb_sub(self.0[5], rhs.0[5]),
            kb_sub(self.0[6], rhs.0[6]),
        ])
    }

    pub fn neg(&self) -> Fp7 {
        Fp7([
            kb_neg(self.0[0]),
            kb_neg(self.0[1]),
            kb_neg(self.0[2]),
            kb_neg(self.0[3]),
            kb_neg(self.0[4]),
            kb_neg(self.0[5]),
            kb_neg(self.0[6]),
        ])
    }

    /// Schoolbook multiplication with z^7 = 3z + 5 reduction.
    // Reduce mod P after each accumulation: 7 raw products (each < P^2 ≈ 2^62)
    // would overflow u64 otherwise.
    pub fn mul(&self, rhs: &Fp7) -> Fp7 {
        let mut res = [0u64; 13];
        for i in 0..7 {
            for j in 0..7 {
                res[i + j] = (res[i + j] + self.0[i] as u64 * rhs.0[j] as u64) % P;
            }
        }
        let mut ret = [
            res[0], res[1], res[2], res[3], res[4], res[5], res[6],
        ];
        for i in 7..13 {
            ret[i - 7] = (ret[i - 7] + res[i] * 5) % P;
            ret[i - 6] = (ret[i - 6] + res[i] * 3) % P;
        }
        Fp7([
            ret[0] as u32, ret[1] as u32, ret[2] as u32, ret[3] as u32,
            ret[4] as u32, ret[5] as u32, ret[6] as u32,
        ])
    }

    pub fn square(&self) -> Fp7 {
        self.mul(self)
    }

    pub fn cube(&self) -> Fp7 {
        self.square().mul(self)
    }

    pub fn scale(&self, s: u32) -> Fp7 {
        Fp7([
            kb_mul(self.0[0], s),
            kb_mul(self.0[1], s),
            kb_mul(self.0[2], s),
            kb_mul(self.0[3], s),
            kb_mul(self.0[4], s),
            kb_mul(self.0[5], s),
            kb_mul(self.0[6], s),
        ])
    }

    // z^(k*p) precomputed constants for KoalaBear, copied verbatim from SP1's
    // septic_extension.rs — Frobenius constants are field-specific.
    fn z_pow_p(index: usize) -> Fp7 {
        match index {
            0 => Fp7::one(),
            1 => Fp7([1272123317, 1950759909, 1879852731, 746569225, 180350946, 1600835585, 333893434]),
            2 => Fp7([129050189, 1749509219, 983995729, 711096547, 1505254548, 639452798, 68186395]),
            3 => Fp7([1911662442, 1095215454, 1794102427, 1173566779, 140526665, 110899104, 1387282150]),
            4 => Fp7([1366416596, 1212861, 2104391040, 1447859676, 308944373, 106444152, 1362577042]),
            5 => Fp7([1411781189, 1580508159, 1332301780, 1528790701, 380217034, 1752756730, 989817517]),
            6 => Fp7([37669840, 439102875, 410223214, 964813232, 1250258104, 877333757, 222095778]),
            _ => unreachable!(),
        }
    }

    fn z_pow_p2(index: usize) -> Fp7 {
        match index {
            0 => Fp7::one(),
            1 => Fp7([1330073564, 1724372201, 942213154, 258987814, 1836986639, 566030553, 2086945921]),
            2 => Fp7([473977877, 99096011, 1919717963, 733784355, 1167998744, 19619652, 1354518805]),
            3 => Fp7([1040563478, 1866766699, 1875293643, 846885082, 1921678452, 2127718474, 1489297699]),
            4 => Fp7([1350284585, 1583164394, 512913106, 1818487640, 2116891899, 318922921, 1013732863]),
            5 => Fp7([887772098, 1971095075, 843183752, 711838602, 1717807390, 521017530, 1548716569]),
            6 => Fp7([372606377, 357514301, 335089633, 330400379, 1545190367, 1813349020, 1393941056]),
            _ => unreachable!(),
        }
    }

    pub fn frobenius(&self) -> Fp7 {
        let mut result = Fp7::from_u32(self.0[0]);
        for i in 1..7 {
            result = result.add(&Self::z_pow_p(i).scale(self.0[i]));
        }
        result
    }

    pub fn double_frobenius(&self) -> Fp7 {
        let mut result = Fp7::from_u32(self.0[0]);
        for i in 1..7 {
            result = result.add(&Self::z_pow_p2(i).scale(self.0[i]));
        }
        result
    }

    // x^(p + p^2 + p^3 + p^4 + p^5 + p^6); used so that self * pow_r_1(self)
    // lands in the base field (Norm_{Fp7/Fp}(self)), enabling fast inversion.
    fn pow_r_1(&self) -> Fp7 {
        let base = self.frobenius().mul(&self.double_frobenius());
        let base_p2 = base.double_frobenius();
        let base_p4 = base_p2.double_frobenius();
        base.mul(&base_p2).mul(&base_p4)
    }

    pub fn inv(&self) -> Fp7 {
        assert!(!self.is_zero(), "Fp7 division by zero");
        let pow_r_1 = self.pow_r_1();
        let pow_r = pow_r_1.mul(self);
        let base_inv = kb_inv(pow_r.0[0]);
        pow_r_1.scale(base_inv)
    }

    pub fn div(&self, rhs: &Fp7) -> Fp7 {
        self.mul(&rhs.inv())
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut out = [0u8; 28];
        for (i, &val) in self.0.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
        out
    }
}

// ─── Elliptic curve: y^2 = x^3 + 45x + 41z^3 over Fp7 ───────────────────────

/// b = 41 * z^3 in Fp7 basis
pub const CURVE_B: Fp7 = Fp7([0, 0, 0, 41, 0, 0, 0]);

/// Generator — derived from sqrt(2) digits, taken from SP1 codebase.
/// r * G = O is verified by `test_scalar_mul_group_order`.
pub const GENERATOR_X: Fp7 = Fp7([
    0x1414213, 0x5623730, 0x9504880, 0x1688724, 0x2096980, 0x7856967, 0x1875376,
]);
pub const GENERATOR_Y: Fp7 = Fp7([
    2020310104, 1513506566, 1843922297, 2003644209, 805967281, 1882435203, 1623804682,
]);

/// Prime subgroup order (217 bits):
/// r = 199372529839252601278447397890876471698671718266839763841250021879
pub const GROUP_ORDER: [u32; 8] = [
    0x4e94d1f7, 0x8aeeafa3, 0xc62a61f1, 0x89b4547e,
    0xcc910bb6, 0x7579fd9a, 0x01e4a5d4, 0x00000000,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SepticPoint {
    pub x: Fp7,
    pub y: Fp7,
    pub is_infinity: bool,
}

impl Default for SepticPoint {
    fn default() -> Self {
        Self::infinity()
    }
}

impl SepticPoint {
    pub fn infinity() -> Self {
        SepticPoint { x: Fp7::zero(), y: Fp7::zero(), is_infinity: true }
    }

    pub fn new(x: Fp7, y: Fp7) -> Self {
        SepticPoint { x, y, is_infinity: false }
    }

    pub fn generator() -> Self {
        SepticPoint::new(GENERATOR_X, GENERATOR_Y)
    }

    pub fn curve_rhs(x: &Fp7) -> Fp7 {
        x.cube().add(&x.scale(45)).add(&CURVE_B)
    }

    pub fn on_curve(&self) -> bool {
        if self.is_infinity {
            return true;
        }
        self.y.square() == Self::curve_rhs(&self.x)
    }

    pub fn neg(&self) -> Self {
        if self.is_infinity {
            return *self;
        }
        SepticPoint::new(self.x, self.y.neg())
    }

    /// Complete Weierstrass addition.
    pub fn add(&self, other: &SepticPoint) -> SepticPoint {
        if self.is_infinity {
            return *other;
        }
        if other.is_infinity {
            return *self;
        }
        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            }
            return SepticPoint::infinity();
        }
        let slope = other.y.sub(&self.y).div(&other.x.sub(&self.x));
        let x3 = slope.square().sub(&self.x).sub(&other.x);
        let y3 = slope.mul(&self.x.sub(&x3)).sub(&self.y);
        SepticPoint::new(x3, y3)
    }

    pub fn double(&self) -> SepticPoint {
        if self.is_infinity {
            return *self;
        }
        if self.y.is_zero() {
            return SepticPoint::infinity();
        }
        let three_x_sq = self.x.square().scale(3);
        let numerator = three_x_sq.add(&Fp7::from_u32(45));
        let denominator = self.y.scale(2);
        let slope = numerator.div(&denominator);
        let x3 = slope.square().sub(&self.x.scale(2));
        let y3 = slope.mul(&self.x.sub(&x3)).sub(&self.y);
        SepticPoint::new(x3, y3)
    }

    /// Double-and-add over a 256-bit scalar (little-endian limbs).
    /// Top 39 bits are zero for scalars < r; extra doublings are harmless.
    pub fn scalar_mul(&self, scalar: &[u32; 8]) -> SepticPoint {
        let mut result = SepticPoint::infinity();
        let mut temp = *self;
        for i in 0..8 {
            for bit in 0..32 {
                if (scalar[i] >> bit) & 1 == 1 {
                    result = result.add(&temp);
                }
                temp = temp.double();
            }
        }
        result
    }
}

// ─── 256-bit scalar arithmetic (host-side only needs add/sub/reduce) ────────

pub fn u256_add(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut result = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let sum = a[i] as u64 + b[i] as u64 + carry;
        result[i] = sum as u32;
        carry = sum >> 32;
    }
    (result, carry != 0)
}

pub fn u256_sub(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut result = [0u32; 8];
    let mut borrow = 0i64;
    for i in 0..8 {
        let diff = a[i] as i64 - b[i] as i64 - borrow;
        if diff < 0 {
            result[i] = (diff + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            result[i] = diff as u32;
            borrow = 0;
        }
    }
    (result, borrow != 0)
}

pub fn u256_gte(a: &[u32; 8], b: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true
}

pub fn scalar_reduce(a: &[u32; 8]) -> [u32; 8] {
    if u256_gte(a, &GROUP_ORDER) {
        let (result, _) = u256_sub(a, &GROUP_ORDER);
        result
    } else {
        *a
    }
}

pub fn scalar_add(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let (sum, _) = u256_add(a, b);
    scalar_reduce(&sum)
}

pub fn scalar_sub(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let (diff, borrow) = u256_sub(a, b);
    if borrow {
        let (result, _) = u256_add(&diff, &GROUP_ORDER);
        result
    } else {
        diff
    }
}

// ─── 256-bit × 256-bit modular multiplication mod GROUP_ORDER ──────────────

/// Schoolbook 256-bit × 256-bit → 512-bit multiplication.
///
/// Carry-propagating accumulation keeps each intermediate ≤ 2^64 - 1, so a
/// `[u32; 16]` accumulator without overflow protection is sufficient.
pub fn u256_full_mul(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            // (2^32-1)^2 + 2*(2^32-1) = 2^64 - 1, so this never overflows.
            let p = a[i] as u64 * b[j] as u64 + out[i + j] as u64 + carry;
            out[i + j] = p as u32;
            carry = p >> 32;
        }
        out[i + 8] = carry as u32;
    }
    out
}

/// True iff 512-bit `a` is ≥ 512-bit `b`.
fn u512_gte_u512(a: &[u32; 16], b: &[u32; 16]) -> bool {
    for i in (0..16).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Reduce a 512-bit product modulo GROUP_ORDER (217 bits) by binary long
/// division. For inputs that are products of two values < r the input is
/// at most ~434 bits, so the loop runs ≤ 217 iterations.
pub fn reduce_512_mod_r(product: &[u32; 16]) -> [u32; 8] {
    let mut rem = *product;

    // Position one above the highest set bit (0 if rem is zero).
    let mut high_bit = 0usize;
    for i in (0..16).rev() {
        if rem[i] != 0 {
            high_bit = i * 32 + (32 - rem[i].leading_zeros() as usize);
            break;
        }
    }

    // GROUP_ORDER has bit 216 set as its top bit → 217 significant bits.
    const R_BITS: usize = 217;

    if high_bit <= R_BITS {
        let mut out = [0u32; 8];
        out.copy_from_slice(&rem[..8]);
        return scalar_reduce(&out);
    }

    for shift in (0..=(high_bit - R_BITS)).rev() {
        let word_shift = shift / 32;
        let bit_shift = shift % 32;

        let mut shifted_r = [0u32; 16];
        for i in 0..8 {
            let dest = i + word_shift;
            if dest < 16 {
                shifted_r[dest] |= GROUP_ORDER[i] << bit_shift;
            }
            if bit_shift > 0 && dest + 1 < 16 {
                shifted_r[dest + 1] |= GROUP_ORDER[i] >> (32 - bit_shift);
            }
        }

        if u512_gte_u512(&rem, &shifted_r) {
            let mut borrow = 0i64;
            for i in 0..16 {
                let diff = rem[i] as i64 - shifted_r[i] as i64 - borrow;
                if diff < 0 {
                    rem[i] = (diff + (1i64 << 32)) as u32;
                    borrow = 1;
                } else {
                    rem[i] = diff as u32;
                    borrow = 0;
                }
            }
        }
    }

    // After the shift=0 iteration, rem < GROUP_ORDER.
    let mut out = [0u32; 8];
    out.copy_from_slice(&rem[..8]);
    out
}

/// (a × b) mod GROUP_ORDER.
pub fn scalar_mul_mod_r(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let product = u256_full_mul(a, b);
    reduce_512_mod_r(&product)
}

// ─── Schnorr types ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SepticSchnorrSignature {
    pub r_x: Fp7,
    pub r_y: Fp7,
    pub s: [u32; 8],
}

#[derive(Clone, Debug, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SepticSchnorrOrder {
    pub account_address: [u8; 20],
    pub key_index: u8,
    pub market: String,
    pub side: String,
    pub price: u64,
    pub quantity: u64,
    pub signature: SepticSchnorrSignature,
    pub pubkey_x: Fp7,
    pub pubkey_y: Fp7,
}

#[derive(Clone, Debug, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SepticBenchWitness {
    pub order: SepticSchnorrOrder,
    pub challenge_e: [u32; 8],
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp7_basics() {
        let a = Fp7::from_u32(7);
        let b = Fp7::from_u32(11);
        assert_eq!(a.add(&b), Fp7::from_u32(18));
        assert_eq!(a.mul(&Fp7::one()), a);
        assert_eq!(a.mul(&Fp7::zero()), Fp7::zero());
    }

    #[test]
    fn test_fp7_inv() {
        let a = Fp7([3, 6, 17, 91, 37, 35, 33]);
        let a_inv = a.inv();
        assert_eq!(a.mul(&a_inv), Fp7::one());
    }

    #[test]
    fn test_fp7_inv_many() {
        for i in 0..16u32 {
            let a = Fp7([
                i + 3, 2 * i + 6, 5 * i + 17, 6 * i + 91,
                8 * i + 37, 11 * i + 35, 14 * i + 33,
            ]);
            let a_inv = a.inv();
            assert_eq!(a.mul(&a_inv), Fp7::one(), "inv failed for i={}", i);
        }
    }

    #[test]
    fn test_fp7_mul_associative() {
        let a = Fp7([1, 2, 3, 4, 5, 6, 7]);
        let b = Fp7([7, 6, 5, 4, 3, 2, 1]);
        let c = Fp7([11, 13, 17, 19, 23, 29, 31]);
        let ab_c = a.mul(&b).mul(&c);
        let a_bc = a.mul(&b.mul(&c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn test_generator_on_curve() {
        let g = SepticPoint::generator();
        assert!(g.on_curve(), "generator not on curve");
    }

    #[test]
    fn test_point_add_double() {
        let g = SepticPoint::generator();
        let g2_add = g.add(&g);
        let g2_dbl = g.double();
        assert_eq!(g2_add.x, g2_dbl.x);
        assert_eq!(g2_add.y, g2_dbl.y);
        assert!(g2_add.on_curve());
    }

    #[test]
    fn test_point_add_negation_is_infinity() {
        let g = SepticPoint::generator();
        let neg_g = g.neg();
        let result = g.add(&neg_g);
        assert!(result.is_infinity);
    }

    #[test]
    fn test_scalar_mul_identity() {
        let g = SepticPoint::generator();
        let one = [1, 0, 0, 0, 0, 0, 0, 0];
        let result = g.scalar_mul(&one);
        assert_eq!(result.x, g.x);
        assert_eq!(result.y, g.y);
        assert!(!result.is_infinity);
    }

    #[test]
    fn test_scalar_mul_two() {
        let g = SepticPoint::generator();
        let two = [2, 0, 0, 0, 0, 0, 0, 0];
        let result = g.scalar_mul(&two);
        let doubled = g.double();
        assert_eq!(result.x, doubled.x);
        assert_eq!(result.y, doubled.y);
    }

    /// Critical test: r * G must equal point-at-infinity.
    /// This validates the group order constant, generator, and all EC arithmetic.
    #[test]
    fn test_scalar_mul_group_order() {
        let g = SepticPoint::generator();
        let result = g.scalar_mul(&GROUP_ORDER);
        assert!(result.is_infinity, "r*G should be point at infinity, got {:?}", result);
    }

    #[test]
    fn test_scalar_add_sub_roundtrip() {
        let a: [u32; 8] = [100, 200, 300, 400, 500, 600, 700, 0];
        let b: [u32; 8] = [50, 60, 70, 80, 90, 100, 110, 0];
        let sum = scalar_add(&a, &b);
        let back = scalar_sub(&sum, &b);
        assert_eq!(back, a);
    }

    #[test]
    fn test_u256_full_mul_small() {
        // 7 × 11 = 77.
        let a = [7u32, 0, 0, 0, 0, 0, 0, 0];
        let b = [11u32, 0, 0, 0, 0, 0, 0, 0];
        let prod = u256_full_mul(&a, &b);
        assert_eq!(prod[0], 77);
        for i in 1..16 {
            assert_eq!(prod[i], 0, "limb {} should be zero", i);
        }
    }

    #[test]
    fn test_u256_full_mul_max() {
        // (2^256 - 1) × (2^256 - 1) = 2^512 - 2^257 + 1.
        // In limbs: low limb = 1, limbs 1..8 = 0, limb 8 = 0xFFFFFFFE,
        // limbs 9..16 = 0xFFFFFFFF.
        let max = [0xFFFFFFFFu32; 8];
        let prod = u256_full_mul(&max, &max);
        assert_eq!(prod[0], 1);
        for i in 1..8 {
            assert_eq!(prod[i], 0, "limb {} should be zero", i);
        }
        assert_eq!(prod[8], 0xFFFFFFFE);
        for i in 9..16 {
            assert_eq!(prod[i], 0xFFFFFFFF, "limb {} should be all ones", i);
        }
    }

    #[test]
    fn test_scalar_mul_mod_r_basic() {
        // 2 × 3 = 6, well below r.
        let a = [2u32, 0, 0, 0, 0, 0, 0, 0];
        let b = [3u32, 0, 0, 0, 0, 0, 0, 0];
        let result = scalar_mul_mod_r(&a, &b);
        assert_eq!(result, [6, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_scalar_mul_mod_r_one_is_identity() {
        let one = [1u32, 0, 0, 0, 0, 0, 0, 0];
        let x: [u32; 8] = [
            0x12345678, 0x9abcdef0, 0xfedcba98, 0x76543210,
            0x11223344, 0x55667788, 0x000aabbc, 0,
        ];
        // x has top limb zero and is < r (limb 6 < GROUP_ORDER[6]).
        assert!(!u256_gte(&x, &GROUP_ORDER));
        let result = scalar_mul_mod_r(&x, &one);
        assert_eq!(result, x);
    }

    #[test]
    fn test_scalar_mul_mod_r_zero() {
        let zero = [0u32; 8];
        let x: [u32; 8] = [
            0xdeadbeef, 0xcafebabe, 0xfeedface, 0xbaddcafe,
            0x12345678, 0x9abcdef0, 0x000abcde, 0,
        ];
        assert_eq!(scalar_mul_mod_r(&x, &zero), [0u32; 8]);
        assert_eq!(scalar_mul_mod_r(&zero, &x), [0u32; 8]);
    }

    #[test]
    fn test_scalar_mul_mod_r_overflow_r_times_two() {
        // r × 2 mod r = 0.
        let two = [2u32, 0, 0, 0, 0, 0, 0, 0];
        let result = scalar_mul_mod_r(&GROUP_ORDER, &two);
        assert_eq!(result, [0u32; 8]);
    }

    #[test]
    fn test_scalar_mul_mod_r_r_minus_one_squared_is_one() {
        // (r-1)^2 mod r = (r^2 - 2r + 1) mod r = 1.
        let (r_minus_one, _) = u256_sub(&GROUP_ORDER, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let result = scalar_mul_mod_r(&r_minus_one, &r_minus_one);
        assert_eq!(result, [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_scalar_mul_mod_r_commutative() {
        let a: [u32; 8] = [
            0x4e94d1f6, 0x8aeeafa2, 0xc62a61f0, 0x89b4547d,
            0xcc910bb5, 0x7579fd99, 0x01e4a5d3, 0,
        ];
        let b: [u32; 8] = [
            0x12345678, 0x9abcdef0, 0xfedcba98, 0x76543210,
            0x11223344, 0x55667788, 0x000abcde, 0,
        ];
        assert_eq!(scalar_mul_mod_r(&a, &b), scalar_mul_mod_r(&b, &a));
    }

    #[test]
    fn test_scalar_mul_mod_r_reduces_to_below_r() {
        let a: [u32; 8] = [
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0x01e4a5d3, 0,
        ];
        // Square of an almost-r-sized scalar definitely needs reduction.
        let result = scalar_mul_mod_r(&a, &a);
        assert!(!u256_gte(&result, &GROUP_ORDER), "result must be < r");
    }
}
