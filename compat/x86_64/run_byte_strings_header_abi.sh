#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <string.h> byte-string ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. The candidate pass places the
# project headers first; neither pass links or selects crabc-libc. GNU-only
# strverscmp and strchrnul are checked explicitly against both header trees.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 string.h byte-string ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/byte_strings_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/byte_strings_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-byte-strings-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

oracle_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_GNU -DCRABC_EXPECT_ALIASES)
candidate_definitions=("${oracle_definitions[@]}")

"$ORACLE_CC" -std=c11 "${oracle_definitions[@]}" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${oracle_definitions[@]}" -fsyntax-only "$cxx_probe"

# `-H` makes candidate-header provenance observable rather than merely
# compiling against whichever system string.h happens to be installed.
"$ORACLE_CC" -std=c11 "${candidate_definitions[@]}" -I "$ROOT_DIR/include" \
    -H -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/string.h" "$header_trace" || {
    fail "C probe did not use the project <string.h>"
}
grep -Fq "$ROOT_DIR/include/strings.h" "$header_trace" || {
    fail "C probe did not use the project <strings.h>"
}
"$ORACLE_CC" -std=c++17 -x c++ "${candidate_definitions[@]}" \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

# Under strict POSIX selectors, musl exposes the ordinary byte-string set but
# keeps the GNU strverscmp and strchrnul declarations hidden. A successful
# opt-in C reference is therefore a header-gating regression in either oracle
# or candidate headers.
strict_definitions=(-D_POSIX_C_SOURCE=200809L -DCRABC_REQUIRE_STRCHRNUL -DCRABC_REQUIRE_STRVERSCMP)
if "$ORACLE_CC" -std=c11 "${strict_definitions[@]}" -fsyntax-only "$c_probe" \
    >/dev/null 2>"$work_dir/oracle-strict-errors"; then
    fail "pinned musl exposes GNU byte-string declarations outside _GNU_SOURCE"
fi
if "$ORACLE_CC" -std=c11 "${strict_definitions[@]}" -I "$ROOT_DIR/include" \
    -fsyntax-only "$c_probe" >/dev/null 2>"$work_dir/project-strict-errors"; then
    fail "project string.h exposes GNU byte-string declarations outside _GNU_SOURCE"
fi
printf 'x86 pinned-musl C/C++ <string.h> byte-string ABI: PASS\n'
