#!/usr/bin/env bash
# Native Linux/x86-64 GNU <unistd.h> syncfs header matrix.
#
# Pinned musl 1.2.6 is the C/C++ declaration, feature-visibility, and C-linkage
# oracle.  The candidate uses raw GCC with project headers only, so ambient
# libc cannot conceal a mismatch.  This compile-only gate selects neither a
# crabc archive nor filesystem synchronization or durability behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/syncfs_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/syncfs_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=8
readonly EXPECTED_GNU_PROFILE_COUNT=2
readonly EXPECTED_GNU_HIDDEN_PROFILE_COUNT=6
readonly -a PROFILES=(c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a GNU_PROFILES=(c11-gnu cxx17-gnu)
readonly -a GNU_HIDDEN_PROFILES=(c-default c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 GNU syncfs header ABI: %s\n' "$*" >&2
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

first_diagnostic() {
    local diagnostic="$1"
    local line

    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    [ -n "$line" ] || line='no compiler diagnostic'
    printf '%s\n' "$line" | tr '\t\r\n' ' '
}

profile_arguments() {
    case "$1" in
        c-default) printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE' ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-U_BSD_SOURCE' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-U_GNU_SOURCE' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

mode_arguments() {
    local profile="$1"
    local mode="$2"

    case "$mode" in
        normal)
            case "$profile" in
                c11-gnu|cxx17-gnu) printf '%s\n' '-DCRABC_SYNCFS_REQUIRE_GNU' ;;
            esac
            ;;
        gnu-hidden) printf '%s\n' '-DCRABC_SYNCFS_REQUIRE_GNU_HIDDEN' ;;
        *) fail "unknown compile mode: $mode" ;;
    esac
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local mode="$3"
    local diagnostic="$4"
    local object="$5"
    local compiler include_root source
    local -a profile_args mode_args arguments

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
    mapfile -t mode_args < <(mode_arguments "$profile" "$mode")
    arguments=(
        -nostdinc -I "$include_root" -isystem "$candidate_compiler_builtin_include"
        -H -fno-builtin "${profile_args[@]}" "${mode_args[@]}"
    )
    case "$profile" in
        c-default)
            source="$C_PROBE"
            arguments=(-x c "${arguments[@]}" -fsyntax-only "$source")
            ;;
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
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root

    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            grep -Fq "$MUSL_ROOT/include/" "$trace" &&
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    trace_has_unapproved_path "$tree" "$trace" &&
        fail "$profile $tree trace escaped its declared header roots"
    for header in unistd.h features.h sys/syscall.h bits/syscall.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted ${root}/$header"
    done
}

profile_requires_gnu() {
    case "$1" in
        c11-gnu|cxx17-gnu) return 0 ;;
        *) return 1 ;;
    esac
}

check_cxx_c_linkage() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined

    profile_requires_gnu "$profile" || return 0
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]syncfs$' ||
        fail "$tree $profile C++ probe lacks C-linkage syncfs"
    if printf '%s\n' "$undefined" | grep -Eq '_Z6syncfsi'; then
        fail "$tree $profile C++ probe retained a mangled syncfs reference"
    fi
}

expect_hidden_failure() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local object="$4"

    if compile_profile "$tree" "$profile" gnu-hidden "$diagnostic" "$object"; then
        fail "$tree $profile unexpectedly exposes GNU syncfs"
    fi
    grep -Fq 'syncfs' "$diagnostic" ||
        fail "$tree $profile hidden GNU diagnostic does not name syncfs"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C GNU syncfs header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ GNU syncfs header probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"
[ "${#GNU_PROFILES[@]}" = "$EXPECTED_GNU_PROFILE_COUNT" ] || fail "GNU profile roster drifted"
[ "${#GNU_HIDDEN_PROFILES[@]}" = "$EXPECTED_GNU_HIDDEN_PROFILE_COUNT" ] ||
    fail "GNU hidden profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin headers"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-syncfs-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    reference_trace="$work_dir/$profile.reference.trace"
    candidate_trace="$work_dir/$profile.candidate.trace"
    reference_object="$work_dir/$profile.reference.o"
    candidate_object="$work_dir/$profile.candidate.o"
    if ! compile_profile reference "$profile" normal "$reference_trace" "$reference_object"; then
        fail "$profile pinned-musl reference failed: $(first_diagnostic "$reference_trace")"
    fi
    check_trace reference "$profile" "$reference_trace"
    if ! compile_profile candidate "$profile" normal "$candidate_trace" "$candidate_object"; then
        fail "$profile project-header candidate failed: $(first_diagnostic "$candidate_trace")"
    fi
    check_trace candidate "$profile" "$candidate_trace"
    case "$profile" in
        cxx17-*)
            check_cxx_c_linkage reference "$profile" "$reference_object"
            check_cxx_c_linkage candidate "$profile" "$candidate_object"
            ;;
    esac
done

for profile in "${GNU_HIDDEN_PROFILES[@]}"; do
    expect_hidden_failure reference "$profile" \
        "$work_dir/$profile.reference.gnu-hidden.trace" \
        "$work_dir/$profile.reference.gnu-hidden.o"
    expect_hidden_failure candidate "$profile" \
        "$work_dir/$profile.candidate.gnu-hidden.trace" \
        "$work_dir/$profile.candidate.gnu-hidden.o"
done

printf 'x86 pinned-musl/project GNU syncfs C/C++ header ABI matrix: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
