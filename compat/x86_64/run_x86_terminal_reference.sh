#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw terminal reference.
#
# This oracle compares x86 kernel tty records and observable terminal behavior
# through raw syscalls and pinned-musl wrappers. It is evidence for the native
# Rust facade only; it does not select a C terminal ABI or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 terminal reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-terminal.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-terminal-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_terminal_reference_probe.c" \
    -o "$probe"

expected='syscalls=ioctl:16,setsid:112,fork:57,wait4:61,openat:257,readlinkat:267 kernel-termios=36/4@0,4,8,12,16,17 musl-termios=60/4,nccs=32 winsize=8/2 ioctls=TCGETS-SETSF,TCSBRK,TCXONC,TCFLSH,TIOCEXCL,TIOCNXCL,TIOCSCTTY,TIOC{G,S}PGRP,TIOCGSID,TIOC{G,S}WINSZ raw+musl=pty-rawmode-termios-queue-exclusive-ttyname-session nonpty=ENOTTY c-api-selection=excluded'
actual="$(env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
    -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH \
    -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 terminal reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw terminal reference: PASS\n'
