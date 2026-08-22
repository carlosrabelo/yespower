//! Shared helpers for **integration** tests (`tests/*.rs`).
//!
//! These helpers only use the public `yespower` API. They must not reach into
//! crate-private modules — that belongs in `src/*/tests.rs`.
#![allow(dead_code)]

use yespower::{yespower, Params, Version};

pub const FAST_N: u32 = 1024;
pub const FAST_R: u32 = 8;

pub fn parse_hex_bytes(s: &str) -> [u8; 32] {
    let parts: Vec<&str> = s.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        32,
        "expected 32 hex bytes, got {}",
        parts.len()
    );
    let mut out = [0u8; 32];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).unwrap();
    }
    out
}

pub fn fmt_hex(h: &[u8; 32]) -> String {
    h.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Classic Openwall test pattern: `src[i] = i * 3`.
pub fn src_pattern() -> [u8; 80] {
    let mut src = [0u8; 80];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i * 3) as u8;
    }
    src
}

pub fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

pub fn hash(version: Version, n: u32, r: u32, src: &[u8], pers: Option<&[u8]>) -> [u8; 32] {
    yespower(
        src,
        &Params {
            version,
            n,
            r,
            pers,
        },
    )
    .expect("yespower")
}

pub fn fast_params(version: Version, pers: Option<&[u8]>) -> Params<'_> {
    Params {
        version,
        n: FAST_N,
        r: FAST_R,
        pers,
    }
}
