#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw sync_file_range ABI/behavior reference.
#
# This proves only direct typed regular-file range-sync request behavior. It
# does not claim writeback durability, select a C filesystem API, or broaden
# x86-64 support beyond the separately admitted Rust operation.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sync_file_range reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

# Establish compiler/header/runtime provenance before using musl as the oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-sync-file-range.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-sync-file-range-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_sync_file_range_reference_probe.c" \
    -o "$probe"
expected='syscall=277 flags=WAIT_BEFORE:1,WRITE:2,WAIT_AFTER:4 regular-file=zero-length-to-eof-writeback-request:success-or-EOPNOTSUPP position=stable raw=matches-musl invalid-flags=EINVAL pipe=ESPIPE invalid-fd=EBADF'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 sync_file_range reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw sync_file_range ABI/behavior reference: PASS\n'
