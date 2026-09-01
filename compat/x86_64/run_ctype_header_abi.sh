#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <ctype.h> ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
# The ordinary byte ctype functions and C-only ctype fast-path macros are
# unconditional in C, while isascii/toascii and the exact bitwise
# _tolower/_toupper macros use musl's POSIX/XOPEN/GNU/BSD C feature selection.
# The compiler-native C++17 profile is checked directly because its driver
# supplies the corresponding GNU view; C++ must hide __isspace.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 ctype.h ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/ctype_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/ctype_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-ctype-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

strict_definitions=(-D__STRICT_ANSI__ -DCRABC_ASSERT_LEGACY_CASE_MACROS_HIDDEN -DCRABC_EXPECT_C_FAST_CTYPE)
posix_definitions=(-D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_EXTENDED_CTYPE -DCRABC_EXPECT_C_FAST_CTYPE)
xopen_definitions=(-D_XOPEN_SOURCE=700 -DCRABC_EXPECT_EXTENDED_CTYPE -DCRABC_EXPECT_C_FAST_CTYPE)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_EXTENDED_CTYPE -DCRABC_EXPECT_C_FAST_CTYPE)
bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_EXTENDED_CTYPE -DCRABC_EXPECT_C_FAST_CTYPE)
cxx_strict_definitions=(-DCRABC_REQUIRE_C_FAST_CTYPE_HIDDEN)
cxx_gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_EXTENDED_CTYPE -DCRABC_REQUIRE_C_FAST_CTYPE_HIDDEN)

for definitions_name in strict_definitions posix_definitions xopen_definitions gnu_definitions bsd_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
done
for definitions_name in cxx_strict_definitions cxx_gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" \
        -fsyntax-only "$cxx_probe"
done

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever system ctype.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project strict C ctype header contract drifted"
fi
grep -Fq "$ROOT_DIR/include/ctype.h" "$header_trace" || {
    fail "C probe did not use the project <ctype.h>"
}
for definitions_name in posix_definitions xopen_definitions gnu_definitions bsd_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
done
for definitions_name in cxx_strict_definitions cxx_gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

# Strict C must hide musl's extended isascii/toascii/_tolower/_toupper names.
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -DCRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN \
    -fsyntax-only "$c_probe" >"$work_dir/oracle-strict-hidden.out" 2>&1; then
    fail "pinned musl exposes isascii/toascii/_tolower/_toupper outside feature selectors"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -I "$ROOT_DIR/include" \
    -DCRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN -fsyntax-only "$c_probe" \
    >"$work_dir/project-strict-hidden.out" 2>&1; then
    fail "project ctype.h exposes isascii/toascii/_tolower/_toupper outside feature selectors"
fi

printf 'x86 pinned-musl/project C/C++ <ctype.h> ABI: PASS\n'
