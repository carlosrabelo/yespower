//! yespower — proof-of-work hash (reference Rust port of Openwall yespower).
//!
//! This crate ports the reference C implementation (`yespower-ref.c`). It is
//! intentionally not optimized; use it for compatibility and testing.
//!
//! # How to read this crate
//!
//! 1. Start here: public types ([`Version`], [`Params`], [`Error`]) and the
//!    re-exported entry point [`yespower`].
//! 2. Then open [`yespower`](crate::yespower) for the algorithm itself
//!    (SMix / pwxform / finalization).
//! 3. [`sha256`](crate::sha256) holds small crypto helpers used by the port.
//!
//! # Testing layout
//!
//! - **Unit tests** live next to private code under `src/*/tests.rs`
//!   (`cargo test --lib`). They can call non-`pub` helpers.
//! - **Integration tests** live under `tests/` and exercise only this public API.

// Private modules: not part of the public crate surface.
mod sha256;
mod yespower;

// Re-export the main function so callers write `yespower::yespower(...)`
// instead of reaching into the submodule.
pub use yespower::yespower;

/// yespower algorithm version.
///
/// The numeric discriminants (`5` and `10`) match the upstream C API
/// (`YESPOWER_0_5`, `YESPOWER_1_0`) and the values written in `TESTS-OK`.
///
/// `#[repr(u32)]` fixes the in-memory integer size/layout so those numbers
/// stay stable if we ever interop with C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Version {
    /// yespower 0.5 / yescrypt 0.5 compatible.
    ///
    /// Uses the input (`src`) as the PBKDF2 salt and may apply a final
    /// HMAC+SHA-256 personalization step.
    V0_5 = 5,
    /// yespower 1.0 (current).
    ///
    /// Uses the personalization string (or empty) as the PBKDF2 salt and
    /// finishes with HMAC-SHA256 over the SMix state.
    V1_0 = 10,
}

/// Parameters for a single yespower invocation.
///
/// The lifetime `'a` ties any personalization slice (`pers`) to this struct:
/// `Params` may borrow those bytes without copying them.
///
/// # Fields
///
/// - `version` — algorithm flavour ([`Version::V0_5`] or [`Version::V1_0`])
/// - `n` — main memory cost parameter (must be a power of two)
/// - `r` — block-size factor (affects working-set width)
/// - `pers` — optional personalization / "Client Key" bytes
#[derive(Debug, Clone, Copy)]
pub struct Params<'a> {
    pub version: Version,
    pub n: u32,
    pub r: u32,
    pub pers: Option<&'a [u8]>,
}

/// Error returned when parameters are invalid.
///
/// Today this is only [`Error::InvalidParams`]. The dedicated type keeps the
/// API open if more failure modes are added later, and lets callers match on
/// a stable error instead of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `n` / `r` outside the ranges accepted by the reference implementation.
    InvalidParams,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidParams => write!(f, "invalid yespower parameters"),
        }
    }
}

// Marker trait so `Error` works with `?` and the broader Rust error ecosystem.
impl std::error::Error for Error {}
