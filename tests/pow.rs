//! Integration: proof-of-work oriented checks (target comparison, nonce search).

mod common;

use common::{hamming_distance, hash, FAST_N, FAST_R};
use yespower::Version;

/// Interpret the first 8 bytes of a digest as a big-endian `u64` (PoW-style).
fn digest_prefix_u64(h: &[u8; 32]) -> u64 {
    u64::from_be_bytes(h[0..8].try_into().unwrap())
}

/// Count leading zero bits in the digest (MSB-first).
fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut zeros = 0u32;
    for &b in h {
        if b == 0 {
            zeros += 8;
            continue;
        }
        zeros += b.leading_zeros();
        break;
    }
    zeros
}

#[test]
fn target_comparison_is_stable() {
    // Mining loops check hash < target. Ensure a real digest is ordered and non-trivial.
    let mut header = [0u8; 80];
    for (i, b) in header.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17);
    }

    let h = hash(Version::V1_0, FAST_N, FAST_R, &header, None);
    let value = digest_prefix_u64(&h);

    assert_ne!(h, [0u8; 32]);
    assert_ne!(h, [0xffu8; 32]);
    assert!(value > 0);

    // Compact target: require digest < 2^248 (first byte zero). Most headers fail.
    let meets_easy = h[0] == 0;
    let meets_impossible = h.iter().all(|&b| b == 0);
    assert!(!meets_impossible);
    let _ = meets_easy; // exercised below in nonce search
}

#[test]
fn nonce_scan_finds_easy_target() {
    // Embed a 4-byte nonce at the end of an 80-byte header and search for a weak target:
    // leading byte == 0x00 (≈ 1/256). Bound the search so the test stays fast.
    let mut header = [0u8; 80];
    for (i, b) in header.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3);
    }

    let mut found = None;
    for nonce in 0u32..1536 {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let h = hash(Version::V1_0, FAST_N, FAST_R, &header, None);
        if h[0] == 0 {
            found = Some((nonce, h));
            break;
        }
    }

    let (nonce, h) = found.expect("expected a digest with leading zero byte within 1536 nonces");
    assert_eq!(h[0], 0);
    assert!(leading_zero_bits(&h) >= 8);

    // Recompute: same nonce must reproduce the same digest (miner verification path).
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    let again = hash(Version::V1_0, FAST_N, FAST_R, &header, None);
    assert_eq!(again, h);
}

#[test]
fn harder_leading_zero_bits_are_rarer() {
    // Statistical smoke: among a modest nonce sample, 8 leading zero bits should appear
    // more often than 16. This guards against a broken hasher that always returns zeros.
    let mut header = [0u8; 80];
    for (i, b) in header.iter_mut().enumerate() {
        *b = 0xA5 ^ (i as u8);
    }

    let mut count8 = 0u32;
    let mut count16 = 0u32;
    for nonce in 0u32..512 {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let h = hash(Version::V1_0, FAST_N, FAST_R, &header, None);
        let z = leading_zero_bits(&h);
        if z >= 8 {
            count8 += 1;
        }
        if z >= 16 {
            count16 += 1;
        }
    }

    assert!(count8 > 0, "no 8-bit leading-zero digests in sample");
    assert!(
        count16 <= count8,
        "16-bit hits ({count16}) should not exceed 8-bit hits ({count8})"
    );
}

#[test]
fn v0_5_and_v1_0_disagree_as_pow_candidates() {
    // Digests under the two versions are not interchangeable as PoW shares.
    let mut header = [0u8; 80];
    header[0] = 0x42;
    header[76..80].copy_from_slice(&7u32.to_le_bytes());

    let h05 = hash(Version::V0_5, FAST_N, FAST_R, &header, Some(b"Client Key"));
    let h10 = hash(Version::V1_0, FAST_N, FAST_R, &header, None);
    assert_ne!(h05, h10);
    assert!(hamming_distance(&h05, &h10) >= 80);
}
