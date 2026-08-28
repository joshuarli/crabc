#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw temporary-object reference.
#
# This fixture is private evidence for the typed Rust ownership boundary. Its
# C APIs are oracle-only and do not select a public C temporary-object API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 temporary-object reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-temporary-object.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-temporary-object-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_temporary_object_reference_probe.c" \
    -o "$probe"

available='syscalls=read:0,write:1,close:3,fstat:5,lseek:8,fcntl:72,openat:257,mkdirat:258,newfstatat:262,unlinkat:263 flags=creat:0x40,excl:0x80,cloexec:0x80000,tmpfile:0x410000,removedir:0x200 named=exclusive:cloexec:mode0600:stable-parent-unlink anonymous=cloexec:regular:nlink0:read-write tempdir=mkdirat:mode0700:name-flow c-api-selection=excluded'
unavailable='syscalls=read:0,write:1,close:3,fstat:5,lseek:8,fcntl:72,openat:257,mkdirat:258,newfstatat:262,unlinkat:263 flags=creat:0x40,excl:0x80,cloexec:0x80000,tmpfile:0x410000,removedir:0x200 named=exclusive:cloexec:mode0600:stable-parent-unlink anonymous=unavailable:EOPNOTSUPP tempdir=mkdirat:mode0700:name-flow c-api-selection=excluded'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
case "$actual" in
    "$available"|"$unavailable") ;;
    *)
        printf 'ERROR: x86 temporary-object reference output mismatch\navailable: %s\nunavailable: %s\nactual: %s\n' \
            "$available" "$unavailable" "$actual" >&2
        exit 1
        ;;
esac
printf 'x86 pinned-musl/raw temporary-object reference: PASS\n'
