//! Integration: public parameter validation (accept / reject surface).

mod common;

use yespower::{yespower, Error, Params, Version};

fn try_hash(version: Version, n: u32, r: u32, pers: Option<&[u8]>) -> Result<[u8; 32], Error> {
    yespower(
        &[0u8; 80],
        &Params {
            version,
            n,
            r,
            pers,
        },
    )
}

#[test]
fn accepts_boundary_valid_params() {
    // Minimum legal N and r
    try_hash(Version::V1_0, 1024, 8, None).unwrap();
    try_hash(Version::V0_5, 1024, 8, Some(b"x")).unwrap();

    // Maximum legal r
    try_hash(Version::V1_0, 1024, 32, None).unwrap();

    // Next power-of-two N steps used in production
    for n in [1024u32, 2048, 4096] {
        try_hash(Version::V1_0, n, 8, None).unwrap();
    }
}

#[test]
fn rejects_n_below_minimum() {
    for n in [0, 1, 2, 512, 1023] {
        assert_eq!(
            try_hash(Version::V1_0, n, 8, None),
            Err(Error::InvalidParams),
            "N={n}"
        );
    }
}

#[test]
fn rejects_n_above_maximum() {
    // Just above the documented cap (avoids allocating 512 MiB+)
    assert_eq!(
        try_hash(Version::V1_0, 512 * 1024 + 1, 8, None),
        Err(Error::InvalidParams)
    );
    assert_eq!(
        try_hash(Version::V1_0, u32::MAX, 8, None),
        Err(Error::InvalidParams)
    );
}

#[test]
fn rejects_n_not_power_of_two() {
    for n in [1025u32, 1536, 2047, 3000, 4095] {
        assert_eq!(
            try_hash(Version::V1_0, n, 8, None),
            Err(Error::InvalidParams),
            "N={n}"
        );
    }
}

#[test]
fn rejects_r_out_of_range() {
    for r in [0u32, 1, 7, 33, 64, 128] {
        assert_eq!(
            try_hash(Version::V1_0, 1024, r, None),
            Err(Error::InvalidParams),
            "r={r}"
        );
    }
}

#[test]
fn accepts_every_legal_r_at_min_n() {
    for r in 8u32..=32 {
        try_hash(Version::V1_0, 1024, r, None).unwrap_or_else(|e| {
            panic!("expected Ok for r={r}, got {e:?}");
        });
    }
}

#[test]
fn both_versions_share_param_surface() {
    for version in [Version::V0_5, Version::V1_0] {
        assert!(try_hash(version, 1024, 8, None).is_ok());
        assert_eq!(try_hash(version, 1023, 8, None), Err(Error::InvalidParams));
        assert_eq!(try_hash(version, 1024, 7, None), Err(Error::InvalidParams));
    }
}

#[test]
fn empty_src_is_allowed() {
    let h = yespower(
        b"",
        &Params {
            version: Version::V1_0,
            n: 1024,
            r: 8,
            pers: None,
        },
    )
    .unwrap();
    assert_ne!(h, [0u8; 32]);
}
