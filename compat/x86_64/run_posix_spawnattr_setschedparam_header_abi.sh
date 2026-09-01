#!/usr/bin/env bash
# Native Linux/x86-64 POSIX spawn-attribute setschedparam C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. The candidate
# uses raw GCC with project headers plus only compiler builtin headers, so an
# ambient libc cannot mask the unconditional declaration or its C++ linkage.
# This proves one fixed-error compatibility spelling, not spawn execution,
# child lifecycle, file actions, attribute state, signals, or scheduler policy.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/posix_spawnattr_setschedparam_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/posix_spawnattr_setschedparam_header_abi_probe.cpp"
readonly -a PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 c11-gnu cxx17-strict cxx17-gnu)

fail() {
    printf 'ERROR: x86 spawn.h posix_spawnattr_setschedparam headers: %s\n' "$*" >&2
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

profile_arguments() {
    case "$1" in
        c11-strict|cxx17-strict) printf '%s\n' '-D__STRICT_ANSI__' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

compile_profile() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local compiler include_root source
    local -a profile_args arguments

    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE
        -H -fno-builtin
        "${profile_args[@]}"
    )
    case "$profile" in
        c11-*)
            source="$C_PROBE"
            arguments=(-x c -std=c11 "${arguments[@]}" \
                -Werror=implicit-function-declaration -fsyntax-only "$source")
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" \
                -c -o "$object" "$source")
            ;;
        *) fail "unknown profile language: $profile" ;;
    esac
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"
}

check_trace() {
    local tree="$1" profile="$2" trace="$3" root path

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$profile $tree trace escaped its declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    for header in sched.h spawn.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
}

check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]posix_spawnattr_setschedparam$' ||
        fail "$profile $tree C++ probe does not retain C linkage for posix_spawnattr_setschedparam"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*posix_spawnattr_setschedparam'; then
        fail "$profile $tree C++ probe retained a mangled posix_spawnattr_setschedparam reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-posix-spawnattr-setschedparam-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        compile_profile "$tree" "$profile" "$trace" "$object" ||
            fail "$profile $tree unconditional posix_spawnattr_setschedparam declaration failed"
        check_trace "$tree" "$profile" "$trace"
        case "$profile" in
            cxx17-*) check_cxx_linkage "$tree" "$profile" "$object" ;;
        esac
    done
done

printf 'x86 pinned-musl/project C/C++ <spawn.h> posix_spawnattr_setschedparam ABI: PASS (%s unconditional profiles)\n' \
    "${#PROFILES[@]}"
