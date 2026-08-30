#!/usr/bin/env bash
# Native Linux/x86-64 deferred pthread-cancellation header ABI matrix.
#
# Pinned musl 1.2.6 supplies the selected declaration and constant oracle.
# Raw GCC sees only project headers and its builtin include root, so an ambient
# libc cannot satisfy this surface.  The gate is compile-only: it neither
# requests a crabc artifact nor proves cancellation behavior, cleanup-handler
# ordering, pthread runtime ownership, family completion, or public x86
# support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/pthread_cancellation_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/pthread_cancellation_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=8
readonly -a PROFILES=(c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 pthread-cancellation header ABI: %s\n' "$*" >&2
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
    case "$1" in
        c-default|c11-strict) ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        # GCC predefines _GNU_SOURCE for C++; remove it to keep this an
        # independently checked macro-free C++17 context.
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
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
        candidate)
            root="$PROJECT_INCLUDE"
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$profile $tree trace escaped its declared header roots" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$root/pthread.h" "$trace" ||
        fail "$profile $tree trace omitted ${root}/pthread.h"
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local object="$4"
    local compiler
    local include_root
    local source
    local -a profile_args
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
        *) fail "unknown compiler tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
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
            arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" -c -o "$object" "$source")
            ;;
        *) fail "unknown profile language: $profile" ;;
    esac
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_cxx_c_linkage() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol

    undefined="$(nm --undefined-only "$object")"
    for symbol in pthread_cancel pthread_setcancelstate pthread_setcanceltype pthread_testcancel \
        _pthread_cleanup_push _pthread_cleanup_pop; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe does not retain C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(_pthread_cleanup_(push|pop)|pthread_(cancel|setcancelstate|setcanceltype|testcancel))'; then
        fail "$tree $profile C++ probe retained a mangled pthread-cancellation reference"
    fi
}

first_diagnostic() {
    local diagnostic="$1"
    local line

    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    if [ -z "$line" ]; then
        printf '%s\n' 'no compiler diagnostic'
    else
        printf '%s\n' "$line" | tr '\t\r\n' ' '
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C pthread-cancellation header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ pthread-cancellation header probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

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
    fail "candidate compiler builtin include aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-cancellation-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            fail "$tree $profile deferred-cancellation profile failed: $(first_diagnostic "$trace")"
        fi
        check_trace "$tree" "$profile" "$trace"
        case "$profile" in
            cxx17-*) check_cxx_c_linkage "$tree" "$profile" "$object" ;;
        esac
    done
done

printf 'x86 pinned-musl/project C/C++ deferred pthread-cancellation ABI matrix: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
