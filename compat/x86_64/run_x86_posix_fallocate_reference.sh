#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw posix_fallocate(3)/fallocate(2) reference.
#
# This proves only the direct typed mode-zero allocation boundary. It does not
# select crabc-libc or claim public x86-64 C ABI support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 posix_fallocate reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-posix-fallocate.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-posix-fallocate-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_posix_fallocate_reference_probe.c" \
    -o "$probe"
expected='syscall=285 off_t=signed64 mode=zero fixture=unlinked-regular-file range=offset4096:length4096 extends8192 bytes=retained-prefix:zero-filled position=stable zero-length=c:EINVAL,raw:errno=EINVAL negative-offset=c:EINVAL:errno-unchanged,raw:errno=EINVAL closed=c:EBADF:errno-unchanged,raw:errno=EBADF c-api-selection=excluded path-surface=excluded'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 posix_fallocate reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw posix_fallocate reference: PASS\n'
