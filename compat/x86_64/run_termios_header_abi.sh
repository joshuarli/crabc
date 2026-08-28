#!/usr/bin/env bash
# Native Linux/x86-64 compile-only GNU <termios.h> ABI slice.
#
# Pinned musl 1.2.6 supplies the declaration and record oracle. The project
# headers are then placed first for the candidate pass. This gate never links
# and therefore does not itself select a C runtime implementation.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROJECT_TERMIOS_HEADER="$ROOT_DIR/include/termios.h"
readonly PROJECT_ALLTYPES_HEADER="$ROOT_DIR/include/bits/alltypes.h"

fail() {
    printf 'ERROR: x86 termios header ABI: %s\n' "$*" >&2
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
[ -f "$PROJECT_TERMIOS_HEADER" ] || fail "missing project include/termios.h"
[ -f "$PROJECT_ALLTYPES_HEADER" ] || fail "missing project include/bits/alltypes.h"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/termios_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/termios_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-termios-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

# First prove the fixed GNU declarations/layout facts against musl itself.
"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"

# Then resolve the same assertions through the installed project headers.
"$ORACLE_CC" -std=c11 -DCRABC_PROJECT_HEADERS -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"
for header in "$PROJECT_TERMIOS_HEADER" "$ROOT_DIR/include/features.h" \
    "$PROJECT_ALLTYPES_HEADER"; do
    grep -Fq "$header" "$header_trace" ||
        fail "C probe did not use the project ${header#"$ROOT_DIR/include/"}"
done
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

printf 'x86 pinned-musl C/C++ GNU <termios.h> ABI: PASS\n'
