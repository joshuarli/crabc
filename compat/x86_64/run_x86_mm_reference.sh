#!/usr/bin/env bash
# Pinned-musl Linux/x86-64 mapping ABI reference check.
#
# This compile-only reference establishes the constants admitted by the narrow
# Rust mapping facade. It does not compile project headers, link code, or
# select crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 mapping ABI reference: %s\n' "$*" >&2
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

# Establish compiler/header provenance before using musl as the ABI oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
"$ORACLE_CC" -std=c11 -fsyntax-only "$ROOT_DIR/compat/x86_64/x86_mm_reference_probe.c"

printf 'x86 pinned-musl mapping ABI reference: PASS\n'
