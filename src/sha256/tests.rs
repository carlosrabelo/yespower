//! Unit tests for private crypto helpers (SHA-256, PBKDF2, endian layout).
//!
//! Kept under `src/` so they can call crate-private functions without exporting them.
//! Crate-level `tests/` covers only the public `yespower` API.

use super::*;

#[test]
fn sha256_empty_nist() {
    // SHA256("")
    let h = sha256(b"");
    assert_eq!(
        h,
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );
}

#[test]
fn pbkdf2_sha256_rfc6070_c1() {
    // RFC 6070: password="password", salt="salt", c=1, dkLen=20
    let mut out = [0u8; 20];
    pbkdf2_sha256(b"password", b"salt", 1, &mut out);
    assert_eq!(
        out,
        [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9
        ]
    );
}

#[test]
fn words_bytes_roundtrip_native_layout() {
    let bytes: Vec<u8> = (0..32).collect();
    let words = words_from_bytes(&bytes);
    assert_eq!(bytes_from_words(&words), bytes);
}

#[test]
fn le32_codec_roundtrip() {
    for x in [0u32, 1, 0xff, 0x0102_0304, u32::MAX] {
        assert_eq!(le32dec_word(le32enc_word(x)), x);
    }
}
