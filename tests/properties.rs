//! Integration: behavioral properties via the public API
//! (determinism, avalanche, version / personalization semantics).

mod common;

use common::{fast_params, hamming_distance, hash, src_pattern, FAST_N, FAST_R};
use yespower::{yespower, Version};

#[test]
fn is_deterministic() {
    let src = src_pattern();
    for version in [Version::V0_5, Version::V1_0] {
        let a = hash(version, FAST_N, FAST_R, &src, None);
        let b = hash(version, FAST_N, FAST_R, &src, None);
        assert_eq!(a, b, "{version:?}");
    }
}

#[test]
fn single_bit_flip_avalanches() {
    // Cryptographic mixing: flipping one input bit should change ~half the output bits.
    // Sample representative positions (ends, middle, nonce-like trailer) instead of all 640 bits.
    let base = src_pattern();
    let h0 = hash(Version::V1_0, FAST_N, FAST_R, &base, None);
    let samples: &[(usize, u8)] = &[
        (0, 0),
        (0, 7),
        (1, 3),
        (17, 0),
        (39, 4),
        (40, 1),
        (64, 2),
        (75, 0),
        (76, 0),
        (76, 3),
        (79, 0),
        (79, 7),
        (10, 5),
        (32, 2),
        (55, 6),
        (70, 1),
    ];

    let mut distances = Vec::new();
    for &(byte, bit) in samples {
        let mut flipped = base;
        flipped[byte] ^= 1 << bit;
        let h1 = hash(Version::V1_0, FAST_N, FAST_R, &flipped, None);
        let d = hamming_distance(&h0, &h1);
        assert_ne!(h0, h1, "byte={byte} bit={bit}");
        assert!(
            d >= 80,
            "weak avalanche: Hamming={d} at byte={byte} bit={bit}"
        );
        distances.push(d);
    }

    let avg = distances.iter().sum::<u32>() as f64 / distances.len() as f64;
    // Ideal ~128; allow a wide but still meaningful band.
    assert!(
        (100.0..156.0).contains(&avg),
        "average Hamming distance out of band: {avg}"
    );
}

#[test]
fn versions_diverge_on_same_params() {
    let src = src_pattern();
    let h05 = hash(Version::V0_5, FAST_N, FAST_R, &src, None);
    let h10 = hash(Version::V1_0, FAST_N, FAST_R, &src, None);
    assert_ne!(h05, h10);
    assert!(hamming_distance(&h05, &h10) >= 80);
}

#[test]
fn changing_n_or_r_changes_digest() {
    let src = src_pattern();
    let base = hash(Version::V1_0, 1024, 8, &src, None);
    let other_n = hash(Version::V1_0, 2048, 8, &src, None);
    let other_r = hash(Version::V1_0, 1024, 16, &src, None);
    assert_ne!(base, other_n);
    assert_ne!(base, other_r);
    assert_ne!(other_n, other_r);
}

#[test]
fn v0_5_personalization_is_final_domain_separator() {
    let src = src_pattern();
    let none = hash(Version::V0_5, FAST_N, FAST_R, &src, None);
    let key = hash(Version::V0_5, FAST_N, FAST_R, &src, Some(b"Client Key"));
    let other = hash(Version::V0_5, FAST_N, FAST_R, &src, Some(b"Other Key"));
    assert_ne!(none, key);
    assert_ne!(key, other);

    // Empty personalization still takes the HMAC+SHA256 path (unlike None).
    let empty = hash(Version::V0_5, FAST_N, FAST_R, &src, Some(b""));
    assert_ne!(none, empty);
}

#[test]
fn v1_0_none_pers_equals_empty_pers_salt() {
    // In 1.0, missing pers and empty pers both feed an empty PBKDF2 salt.
    let src = src_pattern();
    let a = hash(Version::V1_0, FAST_N, FAST_R, &src, None);
    let b = hash(Version::V1_0, FAST_N, FAST_R, &src, Some(b""));
    assert_eq!(a, b);

    let c = hash(
        Version::V1_0,
        FAST_N,
        FAST_R,
        &src,
        Some(b"personality test"),
    );
    assert_ne!(a, c);
}

#[test]
fn input_length_affects_output() {
    let params = fast_params(Version::V1_0, None);
    let lengths = [0usize, 1, 16, 79, 80, 81, 256, 1024];
    let mut seen = Vec::new();
    for &len in &lengths {
        let src: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let h = yespower(&src, &params).unwrap();
        assert!(
            !seen.contains(&h),
            "collision across distinct lengths at len={len}"
        );
        seen.push(h);
    }
}

#[test]
fn distinct_inputs_do_not_collide_in_small_set() {
    let mut digests = std::collections::HashSet::new();
    for seed in 0u8..32 {
        let mut src = [0u8; 80];
        for (i, b) in src.iter_mut().enumerate() {
            *b = seed.wrapping_mul(3).wrapping_add(i as u8);
        }
        let h = hash(Version::V1_0, FAST_N, FAST_R, &src, None);
        assert!(digests.insert(h), "unexpected collision for seed={seed}");
    }
}

#[test]
fn all_r_values_produce_unique_digests_at_fixed_n() {
    let src = src_pattern();
    let mut digests = std::collections::HashSet::new();
    for r in 8u32..=32 {
        let h = hash(Version::V1_0, FAST_N, r, &src, None);
        assert!(digests.insert(h), "duplicate digest for r={r}");
    }
    assert_eq!(digests.len(), 25);
}
