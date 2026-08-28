#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw general fallocate(2) reference.
#
# This proves only the selected direct descriptor modes on its regular-file fixture.
# It does not select crabc-libc or claim public x86-64 C ABI support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 fallocate reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-fallocate.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-fallocate-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_fallocate_reference_probe.c" \
    -o "$probe"
expected='syscall=285 off_t=signed64 modes=zero:keep-size:punch-hole|keep-size:zero-range:zero-range|keep-size fixture=unlinked-regular-file range=offset4096:length4096 zero=success:retained-edges:zeroed-range:size-extends-or-kept|EOPNOTSUPP punch=success:size-kept:range-zeroed|EOPNOTSUPP position=stable invalid=EINVAL:negative-offset|zero-length,EOPNOTSUPP:bad-combinations|unknown-bits closed=EBADF read-only=EBADF pipe=ESPIPE future-modes=excluded c-api-selection=excluded path-surface=excluded durability=excluded'
actual="$(
    cd "$work_dir"
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
        "$probe"
)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 fallocate reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw fallocate reference: PASS\n'
