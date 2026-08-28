#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw timestamp-mutation ABI/behavior reference.
#
# This proves only the timestamp-update family over disposable descriptors and
# paths. It does not select a project C API, general pathname surface, or
# public x86-64 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 timestamp reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-timestamp.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-timestamp-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_timestamp_reference_probe.c" \
    -o "$probe"
expected='syscall=280 abi=syscall4:rdi,rsi,rdx,r10 records=timespec2x16-align8:timeval2x16-align8:utimbuf16 descriptor=null-path=futimens:futimes legacy=futimes:futimesat:lutimes:utimes:utime direct-utimensat=normal:nofollow explicit=exact null=current sentinels=now-omit nofollow=link-not-target:AT_SYMLINK_NOFOLLOW=0x100 position=stable raw=matches-musl errors=EINVAL:timespec|timeval|unknown-flags,EBADF:closed|dirfd,ENOENT:missing c-api-selection=excluded cwd=unchanged:relative-utimes-AT_FDCWD'
actual="$(
    # This subshell alone selects the disposable cwd for relative-path tests;
    # the probe snapshots it and makes no cwd mutation of its own.
    cd "$work_dir"
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
        "$probe"
)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 timestamp reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw timestamp-mutation ABI/behavior reference: PASS\n'
