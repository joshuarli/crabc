#!/usr/bin/env bash
# Build one explicit x86 crabc-libc archive for the differential bootstrap.
#
# Archive construction stays outside the reusable comparator so a future
# selected artifact can supply its own immutable archive input instead.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    printf 'ERROR: x86 static C ABI differential bootstrap: %s\n' "$*" >&2
    exit 1
}

work_dir="$(mktemp -d /tmp/crabc-x86-64-static-c-abi-differential-build.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
archive="$work_dir/cargo-target/x86_64-unknown-linux-musl/debug/libc.a"

cd "$ROOT_DIR"
build_source_runtime_libc "$work_dir/cargo-target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the explicit x86 static libc archive"

bash "$ROOT_DIR/compat/x86_64/run_static_c_abi_differential.sh" --archive "$archive"
