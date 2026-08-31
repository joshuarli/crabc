#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <string.h> mempcpy ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
# mempcpy is GNU-selected and stays hidden in default/strict/POSIX/XOPEN/BSD C.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 string.h mempcpy ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/mempcpy_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/mempcpy_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-mempcpy-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

default_definitions=()
strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L)
xopen_definitions=(-D_XOPEN_SOURCE=700)
bsd_definitions=(-D_BSD_SOURCE)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_MEMPCPY)

for definitions_name in default_definitions strict_definitions posix_definitions xopen_definitions \
    bsd_definitions gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
done
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" -fsyntax-only "$cxx_probe"

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever host string.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${gnu_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project GNU mempcpy header contract drifted"
fi
for header in string.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project $header"
done
for definitions_name in default_definitions strict_definitions posix_definitions xopen_definitions \
    bsd_definitions gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
done
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

# These C selectors must reject the GNU-only declaration in both header trees.
# Do not repeat negative C++ checks: the C++ driver enables GNU names.
for definitions_name in default_definitions strict_definitions posix_definitions xopen_definitions \
    bsd_definitions; do
    declare -n definitions="$definitions_name"
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -DCRABC_REQUIRE_MEMPCPY_HIDDEN \
        -fsyntax-only "$c_probe" >"$work_dir/oracle-${definitions_name}.out" 2>&1; then
        fail "pinned musl exposes mempcpy outside the GNU selector"
    fi
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" \
        -DCRABC_REQUIRE_MEMPCPY_HIDDEN -fsyntax-only "$c_probe" \
        >"$work_dir/project-${definitions_name}.out" 2>&1; then
        fail "project string.h exposes mempcpy outside the GNU selector"
    fi
done

printf 'x86 pinned-musl/project C/C++ <string.h> mempcpy ABI: PASS\n'
