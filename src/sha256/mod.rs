//! SHA-256, HMAC-SHA256, and PBKDF2-HMAC-SHA256 helpers.
//!
//! These wrap the `sha2` / `hmac` / `pbkdf2` crates so the yespower code can
//! call short, named functions that mirror the helpers in the C reference.
//!
//! Also included: little helpers that reproduce how the C code treats a
//! `uint8_t*` buffer as a `uint32_t*` array (native word layout + LE loads).
//!
//! Unit tests for these private helpers are in [`tests`].

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

/// HMAC instantiated over SHA-256 (32-byte tags).
type HmacSha256 = Hmac<Sha256>;

/// One-shot SHA-256 digest → 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    // `into()` converts the generic digest array into `[u8; 32]`.
    hasher.finalize().into()
}

/// HMAC-SHA256(key, data) → 32-byte authentication tag.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC theoretically accepts any key length; the expect should never fire.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA256 into `out` (length of `out` is the derived-key length).
///
/// yespower always uses `rounds == 1` in the reference path, but the helper
/// keeps the parameter so it matches the generic KDF API.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(password, salt, rounds, out);
}

/// Load a host-endian `u32` word as little-endian (C `le32dec`).
///
/// On a little-endian host this is effectively a no-op; on a big-endian host
/// it byte-swaps so the numeric value matches what the C reference reads.
pub fn le32dec_word(w: u32) -> u32 {
    u32::from_le_bytes(w.to_ne_bytes())
}

/// Store a value into a host-endian `u32` word as little-endian (C `le32enc`).
///
/// Inverse of [`le32dec_word`].
pub fn le32enc_word(x: u32) -> u32 {
    u32::from_ne_bytes(x.to_le_bytes())
}

/// Interpret a byte buffer as host `u32` words the way C casts
/// `uint8_t*` → `uint32_t*` (native endianness, 4-byte chunks).
///
/// Length must be a multiple of 4 (PBKDF2 / SMix buffers always are).
pub fn words_from_bytes(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
        .collect()
}

/// Flatten host `u32` words back to bytes (native memory layout).
pub fn bytes_from_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

// Compile this submodule's unit tests only when `cargo test` builds the lib.
#[cfg(test)]
mod tests;
