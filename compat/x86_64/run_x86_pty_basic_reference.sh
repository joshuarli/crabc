#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw basic pseudoterminal reference.
#
# This runner proves only the private Rust PTY pair/name boundary. It neither
# selects a C PTY ABI nor claims controlling-terminal/session, termios, or
# public x86-64 runtime support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 PTY-basic reference: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-pty-basic.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-pty-basic-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_pty_basic_reference_probe.c" \
    -o "$probe"

expected='syscalls=openat:257,ioctl:16,read:0,write:1,close:3 ioctls=TIOCGPTN:0x80045430,TIOCSPTLCK:0x40045431,TIOCGPTPEER:0x5441 flags=RDWR|NOCTTY|CLOEXEC raw+musl=ptmx-lifecycle name=exact+ERANGE nonpty=raw-ENOTTY+musl-grant-noop peer=owned-noctty-cloexec io=slave-to-master-roundtrip c-api-selection=excluded'
actual="$(env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
    -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH \
    -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 PTY-basic reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw basic pseudoterminal reference: PASS\n'
