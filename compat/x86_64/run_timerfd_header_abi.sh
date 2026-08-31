#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/project <sys/timerfd.h> ABI matrix.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/timerfd_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/timerfd_header_abi_probe.cpp"
readonly -a PROFILES=(c-default c11-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-gnu cxx17-strict)

fail() {
    printf 'ERROR: x86 timerfd header ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

run_compiler() {
    local compiler="$1"
    shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

profile_arguments() {
    case "$1" in
        c-default|c11-strict) ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile $1" ;;
    esac
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local object="$4"
    local compiler include_root source
    local -a profile_args arguments

    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown tree $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(-nostdinc -I "$include_root" -isystem "$compiler_builtin_include" \
        -H -fno-builtin "${profile_args[@]}")
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
        *) fail "unknown language profile $profile" ;;
    esac
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"
}

check_trace() {
    local tree="$1"
    local trace="$2"
    local root
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
    esac
    for header in sys/timerfd.h time.h fcntl.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" || fail "$tree trace omitted $header"
    done
    if grep -Eq '^[. ]+ (/usr/include/|/usr/local/include/)' "$trace"; then
        fail "$tree trace reached an ambient libc header"
    fi
}

check_cxx_linkage() {
    local object="$1"
    local undefined
    undefined="$(nm --undefined-only "$object")"
    for symbol in timerfd_create timerfd_settime timerfd_gettime; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ probe did not retain unmangled ${symbol}"
        if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
            fail "C++ probe retained a mangled ${symbol}"
        fi
    done
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in grep mapfile mktemp nm realpath uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] && [ -f "$CXX_PROBE" ] || fail "missing timerfd header probe"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin_include="$(realpath "$($CANDIDATE_CC -print-file-name=include)")"
[ -d "$compiler_builtin_include" ] || fail "missing compiler builtin include root"
work_dir="$(mktemp -d /tmp/crabc-x86-64-timerfd-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
rows=0
for tree in reference candidate; do
    for profile in "${PROFILES[@]}"; do
        trace="$work_dir/${tree}-${profile}.trace"
        object="$work_dir/${tree}-${profile}.o"
        compile_profile "$tree" "$profile" "$trace" "$object"
        check_trace "$tree" "$trace"
        case "$profile" in cxx17-*) check_cxx_linkage "$object" ;; esac
        rows=$((rows + 1))
    done
done
[ "$rows" -eq 16 ] || fail "expected 16 profile/tree rows, observed $rows"
printf 'x86 pinned-musl/project timerfd header ABI: PASS (16 rows)\n'
