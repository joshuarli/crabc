#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl ftruncate ABI/behavior reference.
#
# This proves only the direct typed descriptor-length boundary. It does not
# select a C filesystem API or claim broader x86-64 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 ftruncate reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-ftruncate.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-ftruncate-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_ftruncate_reference_probe.c" \
    -o "$probe"
expected='ftruncate=77 loff_t=signed64 lifecycle=extend8:zero-fill:shrink2:position-stable max=i64-max over-i64=EINVAL direct-errors=EINVAL,EBADF'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 ftruncate reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl ftruncate ABI/behavior reference: PASS\n'
