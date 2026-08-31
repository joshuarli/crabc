#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <unistd.h> getdtablesize ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
# getdtablesize is GNU/BSD-selected and stays hidden in default/strict/POSIX/
# XOPEN C profiles.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 unistd.h getdtablesize ABI: %s\n' "$*" >&2
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
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/getdtablesize_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/getdtablesize_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-getdtablesize-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-getdtablesize-cxx.o"
candidate_cxx_object="$work_dir/candidate-getdtablesize-cxx.o"

default_definitions=()
strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L)
xopen_definitions=(-D_XOPEN_SOURCE=700)
bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_GETDTABLESIZE)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_GETDTABLESIZE)

for definitions_name in default_definitions strict_definitions posix_definitions xopen_definitions \
    bsd_definitions gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
done
for definitions_name in bsd_definitions gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever host unistd.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${gnu_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project GNU getdtablesize header contract drifted"
fi
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]getdtablesize$' ||
        fail "C++ probe does not retain C linkage for getdtablesize"
    if printf '%s\n' "$undefined" | grep -Eq '_Z13getdtablesizev'; then
        fail "C++ probe retained a mangled getdtablesize reference"
    fi
done

# The exact GNU/BSD declaration stays unavailable to strict/POSIX/XOPEN C and
# C++ callers. -U_GNU_SOURCE prevents a toolchain environment from widening the
# C++ profile behind the header under test.
for definitions_name in default_definitions strict_definitions posix_definitions xopen_definitions; do
    declare -n definitions="$definitions_name"
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -DCRABC_REQUIRE_GETDTABLESIZE_HIDDEN \
        -fsyntax-only "$c_probe" >"$work_dir/oracle-c-${definitions_name}.out" 2>&1; then
        fail "pinned musl exposes getdtablesize outside GNU/BSD C selectors"
    fi
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -DCRABC_REQUIRE_GETDTABLESIZE_HIDDEN \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe" \
        >"$work_dir/project-c-${definitions_name}.out" 2>&1; then
        fail "project unistd.h exposes getdtablesize outside GNU/BSD C selectors"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
        -DCRABC_REQUIRE_GETDTABLESIZE_HIDDEN -fsyntax-only "$cxx_probe" \
        >"$work_dir/oracle-cxx-${definitions_name}.out" 2>&1; then
        fail "pinned musl exposes getdtablesize outside GNU/BSD C++ selectors"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
        -DCRABC_REQUIRE_GETDTABLESIZE_HIDDEN -I "$ROOT_DIR/include" \
        -fsyntax-only "$cxx_probe" >"$work_dir/project-cxx-${definitions_name}.out" 2>&1; then
        fail "project unistd.h exposes getdtablesize outside GNU/BSD C++ selectors"
    fi
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> getdtablesize ABI: PASS\n'
