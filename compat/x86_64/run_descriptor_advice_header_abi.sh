#!/usr/bin/env bash
# Native Linux/x86-64 <fcntl.h> descriptor-advice header ABI matrix.
#
# Pinned musl 1.2.6 is the declaration, feature-selection, constant, and C++
# C-linkage oracle. The candidate uses raw GCC with only project headers and
# compiler builtin headers, so ambient libc headers cannot conceal a profile
# mismatch. This is compile-only header evidence: it selects no runtime C API,
# Rust leaf, syscall behavior, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/descriptor_advice_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/descriptor_advice_header_abi_probe.cpp"
readonly -a PROFILES=(
    c11-strict
    cxx17-strict
    c11-gnu
    cxx17-gnu
    c11-largefile64
    cxx17-largefile64
)

fail() {
    printf 'ERROR: x86 descriptor-advice header ABI: %s\n' "$*" >&2
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

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

trace_has_header() {
    local trace="$1"
    local root="$2"
    local header="$3"

    grep -Fq "$root/$header" "$trace"
}

trace_has_unapproved_path() {
    local tree="$1"
    local trace="$2"
    local path

    while IFS= read -r path; do
        case "$tree" in
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            *) fail "unknown header tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

profile_arguments() {
    local profile="$1"

    case "$profile" in
        c11-strict|cxx17-strict)
            printf '%s\n' \
                '-U_GNU_SOURCE' \
                '-U_LARGEFILE64_SOURCE' \
                '-DCRABC_DESCRIPTOR_ADVICE_STRICT'
            ;;
        c11-gnu|cxx17-gnu)
            printf '%s\n' \
                '-U_LARGEFILE64_SOURCE' \
                '-D_GNU_SOURCE' \
                '-DCRABC_DESCRIPTOR_ADVICE_GNU'
            ;;
        c11-largefile64|cxx17-largefile64)
            printf '%s\n' \
                '-U_GNU_SOURCE' \
                '-D_LARGEFILE64_SOURCE' \
                '-DCRABC_DESCRIPTOR_ADVICE_LARGEFILE64'
            ;;
        *) fail "unknown profile: $profile" ;;
    esac
}

mode_arguments() {
    local mode="$1"

    case "$mode" in
        normal) ;;
        readahead-hidden)
            printf '%s\n' '-DCRABC_DESCRIPTOR_ADVICE_REQUIRE_READAHEAD_HIDDEN'
            ;;
        *) fail "unknown compile mode: $mode" ;;
    esac
}

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_requires_gnu() {
    case "$1" in
        c11-gnu|cxx17-gnu) return 0 ;;
        *) return 1 ;;
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
    local -a mode_args
    local -a arguments

    case "$tree" in
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    mapfile -t profile_args < <(profile_arguments "$profile")
    mapfile -t mode_args < <(mode_arguments "$mode")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -H
        -fno-builtin
        "${profile_args[@]}"
        "${mode_args[@]}"
    )
    if profile_is_cxx "$profile"; then
        arguments=(
            -x c++
            -std=c++17
            -nostdinc++
            "${arguments[@]}"
            -c
            -o "$object"
            "$CXX_PROBE"
        )
    else
        arguments=(
            -x c
            -std=c11
            "${arguments[@]}"
            -fsyntax-only
            "$C_PROBE"
        )
    fi
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    local header

    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree trace escaped its declared header roots"
    fi
    for header in fcntl.h features.h bits/fcntl.h; do
        trace_has_header "$trace" "$root" "$header" ||
            fail "$profile $tree trace omitted ${root}/$header"
    done
}

check_cxx_symbols() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol
    local -a expected=(posix_fadvise)

    if profile_requires_gnu "$profile"; then
        expected+=(readahead)
    fi
    undefined="$(nm --undefined-only "$object")"
    for symbol in "${expected[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe does not retain C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(posix_fadvise|readahead)'; then
        fail "$tree $profile C++ probe retained a mangled descriptor-advice reference"
    fi
    case "$profile" in
        c11-largefile64|cxx17-largefile64)
            if printf '%s\n' "$undefined" | grep -Eq '[[:space:]]posix_fadvise64$'; then
                fail "$tree $profile did not macro-alias posix_fadvise64"
            fi
            ;;
    esac
}

expect_readahead_hidden() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local object="$4"

    if compile_profile "$tree" "$profile" readahead-hidden "$diagnostic" "$object"; then
        fail "$tree $profile unexpectedly exposes GNU readahead"
    fi
    grep -Fq 'readahead' "$diagnostic" ||
        fail "$tree $profile hidden readahead diagnostic does not name readahead"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C descriptor-advice header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ descriptor-advice header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-descriptor-advice-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if ! compile_profile "$tree" "$profile" normal "$trace" "$object"; then
            fail "$tree $profile descriptor-advice header profile did not compile"
        fi
        check_trace "$tree" "$profile" "$trace"
        if profile_is_cxx "$profile"; then
            check_cxx_symbols "$tree" "$profile" "$object"
        fi
        if ! profile_requires_gnu "$profile"; then
            hidden_trace="$work_dir/$tree-$profile-readahead-hidden.trace"
            hidden_object="$work_dir/$tree-$profile-readahead-hidden.o"
            expect_readahead_hidden "$tree" "$profile" "$hidden_trace" \
                "$hidden_object"
        fi
    done
done

printf 'x86 pinned-musl/project descriptor-advice C/C++ header ABI: PASS\n'
