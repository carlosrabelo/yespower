//! Unit tests for private yespower primitives (`p2floor`, `wrap`, `salsa20`, …).
//!
//! These belong next to the implementation because they exercise non-`pub` helpers.
//! Public API / end-to-end behavior lives under the crate-level `tests/` directory.

use super::*;

#[test]
fn p2floor_powers_and_in_between() {
    assert_eq!(p2floor(1), 1);
    assert_eq!(p2floor(2), 2);
    assert_eq!(p2floor(3), 2);
    assert_eq!(p2floor(1024), 1024);
    assert_eq!(p2floor(1025), 1024);
    assert_eq!(p2floor(4095), 2048);
    assert_eq!(p2floor(4096), 4096);
}

#[test]
fn wrap_maps_into_half_open_range() {
    // wrap(x, i) ∈ [0, i)
    for i in 2u32..64 {
        for x in 0..256 {
            let w = wrap(x, i);
            assert!(w < i, "wrap({x}, {i}) = {w}");
        }
    }
}

#[test]
fn wrap_matches_scrypt_style_examples() {
    // When i is a power of two, wrap(x, i) == x % i
    assert_eq!(wrap(5, 8), 5);
    assert_eq!(wrap(13, 8), 5);
    // When i is not a power of two: n = p2floor(i), result = (x & (n-1)) + (i - n)
    // i = 6 → n = 4 → wrap(x,6) = (x & 3) + 2
    assert_eq!(wrap(0, 6), 2);
    assert_eq!(wrap(1, 6), 3);
    assert_eq!(wrap(3, 6), 5);
    assert_eq!(wrap(4, 6), 2);
}

#[test]
fn salsa20_is_deterministic_and_mixes() {
    let mut b = [0u32; 16];
    for (i, w) in b.iter_mut().enumerate() {
        *w = (i as u32).wrapping_mul(0x9e37_79b9);
    }
    let before = b;
    salsa20(&mut b, 8);
    assert_ne!(b, before, "salsa20 must modify the block");
    let mut again = before;
    salsa20(&mut again, 8);
    assert_eq!(b, again, "salsa20 must be deterministic");
}

#[test]
fn salsa20_zero_rounds_is_shuffle_add_only() {
    // With 0 rounds the column/row loop is skipped; only unshuffle+add remains.
    let mut b = [1u32; 16];
    salsa20(&mut b, 0);
    // After unshuffle into x and add: B[i] += x[i*5%16] where x[j*5%16]=B_orig[j]=1
    // so every B[i] becomes 2.
    assert_eq!(b, [2u32; 16]);
}

#[test]
fn integerify_reads_last_block_word0() {
    let mut b = vec![0u32; 32 * 2];
    let r = 2usize;
    b[(2 * r - 1) * 16] = 0xdead_beef;
    assert_eq!(integerify(&b, r), 0xdead_beef);
}
