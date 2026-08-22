//! Integration: golden vectors driven by the upstream Openwall `TESTS-OK` file.
//!
//! Uses only the public API (`yespower`, `Params`, `Version`).

mod common;

use common::{fmt_hex, parse_hex_bytes, src_pattern};
use yespower::{yespower, Params, Version};

#[derive(Debug)]
enum PersKind {
    None,
    Literal(String),
    /// Openwall "BSTY": personality bytes equal the 80-byte `src` buffer.
    Bsty,
}

#[derive(Debug)]
struct VectorLine {
    version: Version,
    n: u32,
    r: u32,
    pers: PersKind,
    expected: [u8; 32],
}

#[derive(Debug)]
struct XorLine {
    version: Version,
    expected: [u8; 32],
}

fn parse_version(v: u32) -> Version {
    match v {
        5 => Version::V0_5,
        10 => Version::V1_0,
        other => panic!("unknown yespower version in TESTS-OK: {other}"),
    }
}

fn parse_tests_ok(contents: &str) -> (Vec<VectorLine>, Vec<XorLine>) {
    let mut vectors = Vec::new();
    let mut xors = Vec::new();

    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("XOR of yespower(") {
            // XOR of yespower(5, ...) = aa bb ...
            let (ver_s, after) = rest.split_once(',').expect("XOR version");
            let version = parse_version(ver_s.trim().parse().unwrap());
            assert!(after.contains("...)"));
            let hex = after
                .split_once('=')
                .unwrap_or_else(|| panic!("line {}: missing '='", lineno + 1))
                .1
                .trim();
            xors.push(XorLine {
                version,
                expected: parse_hex_bytes(hex),
            });
            continue;
        }

        // yespower(5, 2048, 8, "Client Key") = aa bb ...
        let rest = line
            .strip_prefix("yespower(")
            .unwrap_or_else(|| panic!("line {}: expected yespower(", lineno + 1));
        let (args, hex_part) = rest
            .split_once(") = ")
            .unwrap_or_else(|| panic!("line {}: malformed", lineno + 1));

        let mut parts = Vec::new();
        let mut buf = String::new();
        let mut in_quotes = false;
        for ch in args.chars() {
            match ch {
                '"' => {
                    in_quotes = !in_quotes;
                    buf.push(ch);
                }
                ',' if !in_quotes => {
                    parts.push(buf.trim().to_string());
                    buf.clear();
                }
                _ => buf.push(ch),
            }
        }
        parts.push(buf.trim().to_string());
        assert_eq!(parts.len(), 4, "line {}: args={parts:?}", lineno + 1);

        let version = parse_version(parts[0].parse().unwrap());
        let n: u32 = parts[1].parse().unwrap();
        let r: u32 = parts[2].parse().unwrap();
        let pers = match parts[3].as_str() {
            "NULL" => PersKind::None,
            "BSTY" => PersKind::Bsty,
            s if s.starts_with('"') && s.ends_with('"') => {
                PersKind::Literal(s[1..s.len() - 1].to_string())
            }
            other => panic!("line {}: bad pers {other}", lineno + 1),
        };

        vectors.push(VectorLine {
            version,
            n,
            r,
            pers,
            expected: parse_hex_bytes(hex_part.trim()),
        });
    }

    (vectors, xors)
}

fn xor_loop(version: Version, pers: Option<&[u8]>) -> [u8; 32] {
    let mut src = [0u8; 80];
    src[0] = 43;
    for (i, b) in src.iter_mut().enumerate().skip(1) {
        *b = (i * 3) as u8;
    }

    let mut xor = [0u8; 32];
    let mut n = 1024u32;
    while n <= 4096 {
        for r in 8..=32 {
            let dst = yespower(
                &src,
                &Params {
                    version,
                    n,
                    r,
                    pers,
                },
            )
            .unwrap();
            for i in 0..32 {
                xor[i] ^= dst[i];
            }
        }
        n <<= 1;
    }
    xor
}

#[test]
fn tests_ok_vectors() {
    let contents = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/TESTS-OK"));
    let (vectors, _) = parse_tests_ok(contents);
    assert!(
        vectors.len() >= 14,
        "expected the full Openwall vector set, got {}",
        vectors.len()
    );

    for (idx, v) in vectors.iter().enumerate() {
        let src = src_pattern();
        let pers_owned: Option<Vec<u8>> = match &v.pers {
            PersKind::None => None,
            PersKind::Literal(s) => Some(s.as_bytes().to_vec()),
            PersKind::Bsty => Some(src.to_vec()),
        };
        let pers = pers_owned.as_deref();
        let got = yespower(
            &src,
            &Params {
                version: v.version,
                n: v.n,
                r: v.r,
                pers,
            },
        )
        .unwrap_or_else(|e| panic!("vector[{idx}] failed: {e:?}"));

        assert_eq!(
            got,
            v.expected,
            "TESTS-OK vector[{idx}] {:?}/N={}/r={:?}\ngot: {}\nexp: {}",
            v.version,
            v.n,
            v.r,
            fmt_hex(&got),
            fmt_hex(&v.expected)
        );
    }
}

#[test]
fn tests_ok_xor_loops() {
    let contents = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/TESTS-OK"));
    let (_, xors) = parse_tests_ok(contents);
    assert_eq!(xors.len(), 2);

    for xor in xors {
        let pers: Option<&[u8]> = match xor.version {
            Version::V0_5 => Some(b"Client Key"),
            Version::V1_0 => None,
        };
        let got = xor_loop(xor.version, pers);
        assert_eq!(
            got,
            xor.expected,
            "XOR {:?}\ngot: {}\nexp: {}",
            xor.version,
            fmt_hex(&got),
            fmt_hex(&xor.expected)
        );
    }
}
