#!/usr/bin/env bash
# Native Linux/x86-64 compile-only crabc public-header ABI slice.
#
# This checks only the admitted fenv/float/fundamental-type declarations with
# the pinned musl oracle compiler. It does not link or select crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 project header ABI: %s\n' "$*" >&2
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

# Verify the compiler/header/runtime provenance before using it only for a
# declaration check. The project header is deliberately first in the include
# search order, while the underlying standard vocabulary remains pinned musl.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

probe="$ROOT_DIR/compat/x86_64/project_header_abi_probe.c"
for mode in sse x87; do
    case "$mode" in
        sse) arguments=() ;;
        x87) arguments=(-mfpmath=387) ;;
    esac
    "$ORACLE_CC" -std=c11 "${arguments[@]}" -I "$ROOT_DIR/include" \
        -fsyntax-only "$probe"
done

printf 'x86 pinned-musl project fenv/float header ABI: PASS\n'
