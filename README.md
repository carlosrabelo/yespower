# yespower

Rust library that computes the yespower proof-of-work hash for blockchain and mining-related workloads.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

## Highlights

- Computes yespower 0.5 and 1.0 hashes from a byte input and parameter set
- Supports optional personalization strings for chain-specific variants
- Ports the Openwall reference algorithm (`yespower-ref.c`) for correctness over peak speed
- Exposes a small idiomatic API (`yespower`, `Params`, `Version`, `Error`)
- Validates parameters the same way as the upstream C reference
- Ships golden tests against the Openwall `TESTS-OK` vectors
- Keeps unit tests next to private code and integration tests on the public API
- Builds and checks through standard `make` targets

## Overview

yespower is a CPU-friendly, GPU-unfriendly proof-of-work function derived from yescrypt. Callers typically hash trial inputs such as block headers and compare the 256-bit result against a difficulty target.

This crate is a Rust reimplementation of the Openwall reference sources. It is suitable for compatibility testing and light use; it is not a SIMD-optimized miner backend.

scrypt was designed by Colin Percival. yescrypt and yespower were designed by Solar Designer (Alexander Peslyak). Upstream project: <https://www.openwall.com/yespower/>.

## Prerequisites

- **Rust 1.73+** (stable) with Cargo — [install via rustup](https://rustup.rs/)
- **rustfmt** and **clippy** — required for `make quality` (`rustup component add rustfmt clippy`)

## Installation

### Build from Source

```bash
git clone https://github.com/carlosrabelo/yespower.git
cd yespower
make build
```

### As a Cargo dependency

```toml
[dependencies]
yespower = { git = "https://github.com/carlosrabelo/yespower.git" }
```

## Usage

### Hash a block-sized input

```rust
use yespower::{yespower, Params, Version};

let src = [0u8; 80]; // e.g. block header
let params = Params {
    version: Version::V1_0,
    n: 2048,
    r: 32,
    pers: None,
};
let hash = yespower(&src, &params).expect("valid params");
assert_eq!(hash.len(), 32);
```

### Use yespower 0.5 with personalization

```rust
use yespower::{yespower, Params, Version};

let header = [0u8; 80];
let params = Params {
    version: Version::V0_5,
    n: 2048,
    r: 8,
    pers: Some(b"Client Key"),
};
let hash = yespower(&header, &params).expect("valid params");
```

### Parameter constraints

Invalid parameters return `Err(Error::InvalidParams)`:

| Field | Constraint |
|-------|------------|
| `n`   | Power of two in `1024..=512 * 1024` |
| `r`   | Integer in `8..=32` |

Memory cost is roughly `128 * N * r` bytes for the main buffer (plus S-box scratch space).

### Suggested parameter sets

| Memory | N    | r  |
|--------|------|----|
| 1 MiB  | 1024 | 8  |
| 2 MiB  | 2048 | 8  |
| 4 MiB  | 1024 | 32 |
| 8 MiB  | 2048 | 32 |
| 16 MiB | 4096 | 32 |

## Project Layout

```
src/lib.rs           # Public API (yespower, Params, Version, Error)
src/yespower/        # Reference algorithm + unit tests
src/sha256/          # Crypto helpers + unit tests
tests/               # Integration tests (public API only)
tests/common/        # Shared helpers for integration tests
tests/golden.rs      # Openwall TESTS-OK vectors
tests/params.rs      # Parameter validation
tests/properties.rs  # Determinism / avalanche / version semantics
tests/pow.rs         # PoW-style nonce / target checks
TESTS-OK             # Upstream golden vectors (read by tests/golden.rs)
.make/               # Build, test, and quality scripts
Makefile             # Developer entry point
Cargo.toml           # Crate manifest
```

## Development

```bash
make build      # Build release library
make test       # Unit tests (src) + integration tests (tests/)
make quality    # Format check and clippy
make clean      # Remove Cargo build artifacts
```

## License

This project is licensed under the GNU General Public License v3.0 only — see [LICENSE](LICENSE) for details.
