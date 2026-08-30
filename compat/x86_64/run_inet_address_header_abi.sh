#!/usr/bin/env bash
# Native Linux/x86-64 <arpa/inet.h> numeric-address header ABI matrix.
#
# Pinned musl 1.2.6 makes inet_pton, inet_ntop, inet_aton, and inet_addr
# unconditional in its default, GNU, and strict feature selections. The
# candidate must retain that exact C/C++ declaration, type/layout, constant,
# and C-linkage surface through project headers alone. This compile-only gate
# does not select archive linkage or address-conversion runtime behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/inet_address_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/inet_address_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=6
readonly -a PROFILES=(c-default c11-gnu c11-strict cxx17-default cxx17-gnu cxx17-strict)

fail() {
    printf 'ERROR: x86 arpa/inet numeric-address header ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

run_compiler() {
    local compiler="$1"
    shift

    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$compiler" "$@"
}

profile_arguments() {
    local profile="$1"

    case "$profile" in
        c-default|cxx17-default) ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        # GCC's C++ driver predefines _GNU_SOURCE. Remove it so this row
        # measures musl's actual macro-free C++17 selection.
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        *) fail "unknown profile: $profile" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    local path

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    grep -Fq "$root/arpa/inet.h" "$trace" ||
        fail "$tree $profile trace did not use $root/arpa/inet.h"
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$COMPILER_BUILTIN_INCLUDE"/*) ;;
            *) fail "$tree $profile trace escaped declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local object="$4"
    local compiler
    local include_root
    local source
    local -a profile_args
    local -a arguments

    case "$tree" in
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$COMPILER_BUILTIN_INCLUDE"
        -H
        -fno-builtin
        "${profile_args[@]}"
    )
    case "$profile" in
        c-default)
            source="$C_PROBE"
            arguments=(-x c "${arguments[@]}" -fsyntax-only "$source")
            ;;
        c11-*)
            source="$C_PROBE"
            arguments=(-x c -std=c11 "${arguments[@]}" -fsyntax-only "$source")
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" \
                -c -o "$object" "$source")
            ;;
        *) fail "unknown profile: $profile" ;;
    esac

    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"
}

check_cxx_c_linkage() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol
    local -a expected=(inet_pton inet_ntop inet_aton inet_addr)

    undefined="$(nm --undefined-only "$object")"
    for symbol in "${expected[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe does not retain C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*inet_(pton|ntop|aton|addr)'; then
        fail "$tree $profile C++ probe retained a mangled inet-address reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in grep mapfile mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C inet-address header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ inet-address header ABI probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

COMPILER_BUILTIN_INCLUDE="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$COMPILER_BUILTIN_INCLUDE" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
COMPILER_BUILTIN_INCLUDE="$(realpath "$COMPILER_BUILTIN_INCLUDE")"
[ -d "$COMPILER_BUILTIN_INCLUDE" ] || fail "missing raw candidate compiler builtin include directory"
[ "$COMPILER_BUILTIN_INCLUDE" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases pinned musl headers"

work_dir="$(mktemp -d /tmp/crabc-x86-64-inet-address-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            diagnostic="$(sed -n '/fatal error:/p; /error:/p' "$trace" | sed -n '1p' || true)"
            fail "$tree $profile compile failed: ${diagnostic:-no compiler diagnostic}"
        fi
        check_trace "$tree" "$profile" "$trace"
        case "$profile" in
            cxx17-*) check_cxx_c_linkage "$tree" "$profile" "$object" ;;
        esac
    done
done

printf 'x86 pinned-musl/project C/C++ <arpa/inet.h> numeric-address ABI: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
