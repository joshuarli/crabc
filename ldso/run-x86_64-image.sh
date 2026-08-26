#!/usr/bin/env bash
# Native Linux/x86-64 evidence runner for the source-only ELF image parser.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_image.rs"

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    printf 'ERROR: x86-64 image evidence requires a native Linux/x86-64 host\n' >&2
    exit 2
fi

if [ "${1:-}" != "test" ] || [ "$#" -ne 1 ]; then
    printf 'Usage: ./ldso/run-x86_64-image.sh test\n' >&2
    exit 2
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

if [ -n "${RUSTC:-}" ]; then
    rustc_command=("$RUSTC")
elif command -v rustc >/dev/null 2>&1; then
    rustc_command=(rustc)
elif command -v rustup >/dev/null 2>&1; then
    rustc_command=(rustup run nightly-2026-07-24 rustc)
else
    printf 'ERROR: rustc or rustup is required for x86-64 image evidence\n' >&2
    exit 2
fi

"${rustc_command[@]}" --edition=2021 --test "$SOURCE" -o "$work_dir/x86_64_image_tests"
CRABC_EXECUTION_MODE=native "$work_dir/x86_64_image_tests"
