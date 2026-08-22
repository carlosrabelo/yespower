#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "Checking format..."
cargo fmt --all -- --check

echo "Running clippy..."
cargo clippy --all-targets -- -D warnings

echo "Quality checks passed."
