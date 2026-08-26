#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl fadvise64/readahead ABI/behavior reference.
#
# This proves only the direct typed filesystem-advice boundary. It does not
# select crabc-rs or claim public x86-64 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 filesystem-advice reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-fs-advice.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-fs-advice-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_fs_advice_reference_probe.c" \
    -o "$probe"
expected='fadvise64=221 policies=0,1,2,3,4,5 readahead=187 position=stable negative-length=EINVAL invalid-fd=EBADF'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 filesystem-advice reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl filesystem-advice ABI/behavior reference: PASS\n'
