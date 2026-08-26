#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <sys/reg.h> ABI slice.
#
# This checks only the staged x86 ptrace register-index declarations against
# pinned musl 1.2.6. It does not link or select crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/reg.h ABI: %s\n' "$*" >&2
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

# Keep the oracle compiler/header/runtime identity proof separate from this
# source-only declaration check. The project include tree is intentionally
# first in the include search path.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -fsyntax-only \
    "$ROOT_DIR/compat/x86_64/sys_reg_header_abi_probe.c"

printf 'x86 pinned-musl sys/reg.h header ABI: PASS\n'
