#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl public type-header ABI check.
#
# Compile the C and C++ project-header-first probes with no link step, then
# compile those same assertions against the pinned musl headers. This proves
# only the explicitly checked source-level declarations and opaque-object
# layouts; it does not select crabc-libc or claim pthread behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 type header ABI: %s\n' "$*" >&2
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

# Prove the compiler/header provenance before using it for declarations.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/types_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/types_header_abi_probe.cpp"

# First accept the assertions against the pinned musl headers themselves.
"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"

# Then place the project public headers first. Every invocation is compile-only.
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

printf 'x86 pinned-musl C/C++ public type header ABI: PASS\n'
