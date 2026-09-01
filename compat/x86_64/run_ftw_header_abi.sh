#!/usr/bin/env bash
# Native Linux/x86-64 <ftw.h> ABI profile matrix.
#
# Pinned musl 1.2.6 is the declaration/layout oracle. Its ftw declaration is
# unconditional, while the frozen project header deliberately retains the
# older GNU/BSD/XOPEN<800 visibility gate. This runner records that inherited
# divergence explicitly while proving nftw's every-profile declaration and
# C++ C linkage; it does not link a crabc archive or claim runtime support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/ftw_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/ftw_header_abi_probe.cpp"
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-gnu-largefile cxx17-gnu-largefile c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a PROJECT_FTW_VISIBLE=(c11-gnu cxx17-gnu c11-gnu-largefile cxx17-gnu-largefile c11-xopen-700 c11-bsd)

fail() {
    printf 'ERROR: x86 ftw header ABI: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

run_compiler() {
    local compiler="$1"
    shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

profile_is_cxx() {
    case "$1" in cxx17-*) return 0 ;; *) return 1 ;; esac
}

profile_requires_largefile_aliases() {
    case "$1" in *-largefile) return 0 ;; *) return 1 ;; esac
}

project_ftw_visible() {
    local profile="$1" visible
    for visible in "${PROJECT_FTW_VISIBLE[@]}"; do
        [ "$profile" = "$visible" ] && return 0
    done
    return 1
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-gnu-largefile|cxx17-gnu-largefile) printf '%s\n' '-D_GNU_SOURCE' '-D_LARGEFILE64_SOURCE' ;;
        c11-strict|cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-U_GNU_SOURCE' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-U_GNU_SOURCE' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-U_GNU_SOURCE' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

compile_profile() {
    local tree="$1" profile="$2" expected="$3" diagnostic="$4" object="$5"
    local compiler include_root source
    local -a arguments profile_args

    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(-nostdinc -I "$include_root" -isystem "$builtin_include" -H -fno-builtin "${profile_args[@]}")
    if [ "$expected" = visible ]; then
        arguments+=(-DCRABC_FTW_EXPECT_FTW_VISIBLE)
    else
        arguments+=(-DCRABC_FTW_REQUIRE_FTW_HIDDEN)
    fi
    if profile_requires_largefile_aliases "$profile"; then
        arguments+=(-DCRABC_FTW_REQUIRE_LARGEFILE_ALIASES)
    fi
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"
        arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" -c -o "$object" "$source")
    else
        source="$C_PROBE"
        arguments=(-x c -std=c11 "${arguments[@]}" -c -o "$object" "$source")
    fi
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

check_trace() {
    local tree="$1" trace="$2" root path
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    grep -Fq "$root/ftw.h" "$trace" || fail "$tree trace omitted ftw.h"
    grep -Fq "$root/sys/stat.h" "$trace" || fail "$tree trace omitted sys/stat.h"
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$builtin_include"/*) ;;
            *) fail "$tree trace escaped declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    if [ "$tree" = candidate ] && grep -Fq "$MUSL_ROOT/include/" "$trace"; then
        fail "candidate trace reached pinned musl"
    fi
}

check_cxx_linkage() {
    local object="$1" expected="$2" undefined
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]nftw$' ||
        fail "C++ probe does not retain nftw's C spelling"
    if [ "$expected" = visible ]; then
        printf '%s\n' "$undefined" | grep -Eq '[[:space:]]ftw$' ||
            fail "C++ probe does not retain ftw's C spelling"
    fi
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(ftw|nftw)'; then
        fail "C++ probe retained a mangled ftw/nftw spelling"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in env grep mapfile mktemp nm realpath sed uname; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$C_PROBE" ] && [ -f "$CXX_PROBE" ] || fail "missing ftw header probe"

builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$builtin_include" in /*) ;; *) fail "raw compiler did not report an absolute builtin include directory" ;; esac
builtin_include="$(realpath "$builtin_include")"
[ -d "$builtin_include" ] || fail "missing compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-ftw-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        expected=visible
        if [ "$tree" = candidate ] && ! project_ftw_visible "$profile"; then
            expected=hidden
        fi
        diagnostic="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if compile_profile "$tree" "$profile" "$expected" "$diagnostic" "$object"; then
            if [ "$expected" = hidden ]; then
                fail "$tree $profile unexpectedly exposed frozen-hidden ftw"
            fi
        else
            if [ "$expected" = visible ]; then
                fail "$tree $profile ftw/nftw header profile failed"
            fi
            grep -Eq 'ftw' "$diagnostic" ||
                fail "$tree $profile hidden ftw diagnostic named no ftw declaration"
            continue
        fi
        check_trace "$tree" "$diagnostic"
        if profile_is_cxx "$profile"; then
            check_cxx_linkage "$object" "$expected"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ ftw header ABI: PASS (9 profiles; frozen ftw visibility divergence recorded)\n'
