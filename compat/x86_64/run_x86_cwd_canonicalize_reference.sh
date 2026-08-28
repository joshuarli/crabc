#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw canonical-path and CWD-mutation reference.
#
# The C APIs compiled here are oracle-only for a private Rust facade boundary;
# this launcher does not select a C ABI or public x86 support profile.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 cwd/canonicalize reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-cwd-canonicalize.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-cwd-canonicalize-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_cwd_canonicalize_reference_probe.c" \
    -o "$probe"

expected='syscalls=getcwd:79,chdir:80,fchdir:81,openat:257,readlinkat:267 canonical=musl-realpath:relative-link:byte-path:absolute-link:empty:missing-ENOENT:trailing-file-ENOTDIR:cycle-ELOOP raw=openat:readlinkat:getcwd cwd=forked-child:chdir:fchdir:restore errors=missing-ENOENT:notdir-ENOTDIR:badfd-EBADF c-api-selection=excluded'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 cwd/canonicalize reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw canonical-path and CWD-mutation reference: PASS\n'
