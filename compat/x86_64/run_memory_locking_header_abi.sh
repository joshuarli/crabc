#!/usr/bin/env bash
# Native Linux/x86-64 selected <sys/mman.h> per-range locking header matrix.
#
# Pinned musl 1.2.6 is the C/C++ declaration, GNU-visibility, and C-linkage
# oracle. The project candidate uses raw GCC with project headers only, so an
# ambient libc cannot satisfy the selected mlock/munlock/mlock2 surface. This
# compile-only gate selects neither archive linkage nor runtime behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/memory_locking_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/memory_locking_header_abi_probe.cpp"
readonly -a PROFILES=(
    c11-strict cxx17-strict c11-posix-2008 cxx17-posix-2008 c11-gnu cxx17-gnu
)

fail() {
    printf 'ERROR: x86 memory-locking header ABI: %s\n' "$*" >&2
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

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_is_gnu() {
    case "$1" in
        c11-gnu|cxx17-gnu) return 0 ;;
        *) return 1 ;;
    esac
}

profile_arguments() {
    case "$1" in
        c11-strict|cxx17-strict)
            printf '%s\n' -U_GNU_SOURCE -U_BSD_SOURCE -U_LARGEFILE64_SOURCE
            ;;
        c11-posix-2008|cxx17-posix-2008)
            printf '%s\n' -U_GNU_SOURCE -U_BSD_SOURCE -U_LARGEFILE64_SOURCE \
                -D_POSIX_C_SOURCE=200809L
            ;;
        c11-gnu|cxx17-gnu)
            printf '%s\n' -U_BSD_SOURCE -U_LARGEFILE64_SOURCE -D_GNU_SOURCE \
                -DCRABC_MEMORY_LOCKING_GNU
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local mode="$3"
    local diagnostic="$4"
    local object="$5"
    local compiler
    local include_root
    local -a profile_args
    local -a mode_args=()
    local -a arguments

    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    case "$mode" in
        normal) ;;
        gnu-hidden) mode_args=(-DCRABC_MEMORY_LOCKING_REQUIRE_GNU_HIDDEN) ;;
        *) fail "unknown header compile mode: $mode" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc -I "$include_root" -isystem "$compiler_builtin_include" -H
        -fno-builtin "${profile_args[@]}" "${mode_args[@]}"
    )
    if profile_is_cxx "$profile"; then
        arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" \
            -c -o "$object" "$CXX_PROBE")
    else
        arguments=(-x c -std=c11 -Werror=implicit-function-declaration \
            "${arguments[@]}" -fsyntax-only "$C_PROBE")
    fi
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

assert_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root

    case "$tree" in
        reference)
            root="$MUSL_ROOT/include"
            grep -Fq "$PROJECT_INCLUDE/" "$trace" &&
                fail "$profile reference trace reached project headers"
            ;;
        candidate)
            root="$PROJECT_INCLUDE"
            grep -Fq "$MUSL_ROOT/include/" "$trace" &&
                fail "$profile candidate trace reached pinned musl headers"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    for header in features.h sys/mman.h bits/mman.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
}

assert_cxx_c_linkage() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local -a expected=(mlock munlock)

    if profile_is_gnu "$profile"; then
        expected+=(mlock2)
    fi
    undefined="$(nm --undefined-only "$object")"
    for symbol in "${expected[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe lacks unmangled $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*mlock'; then
        fail "$tree $profile C++ probe retains a mangled memory-lock symbol"
    fi
}

require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C memory-locking header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ memory-locking header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
compiler_builtin_include="$(realpath "$compiler_builtin_include")"
[ -d "$compiler_builtin_include" ] || fail "missing raw compiler builtin headers"

work_dir="$(mktemp -d /tmp/crabc-x86-64-memory-locking-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if ! compile_profile "$tree" "$profile" normal "$trace" "$object"; then
            fail "$tree $profile header profile failed"
        fi
        assert_trace "$tree" "$profile" "$trace"
        if profile_is_cxx "$profile"; then
            assert_cxx_c_linkage "$tree" "$profile" "$object"
        fi
        if ! profile_is_gnu "$profile"; then
            hidden_trace="$work_dir/$tree-$profile-gnu-hidden.trace"
            hidden_object="$work_dir/$tree-$profile-gnu-hidden.o"
            if compile_profile "$tree" "$profile" gnu-hidden "$hidden_trace" \
                "$hidden_object"; then
                fail "$tree $profile unexpectedly exposes GNU mlock2"
            fi
            grep -Fq 'mlock2' "$hidden_trace" ||
                fail "$tree $profile hidden GNU diagnostic does not name mlock2"
        fi
    done
done

printf 'x86 pinned-musl/project per-range memory-locking C/C++ header ABI: PASS (6 profiles; compile-only)\n'
