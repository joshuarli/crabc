#!/usr/bin/env bash
# Native Linux/x86-64 selected unlinkat C/C++ header ABI matrix.
#
# Pinned musl 1.2.6 is the declaration, constant, and unmangled C++ C-linkage
# oracle. The candidate uses raw GCC with only project headers and compiler
# builtin headers, so an ambient libc cannot hide a mismatch. This proves one
# caller-directed directory-entry removal leaf, not a pathname-policy family
# or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/unlinkat_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/unlinkat_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=8
readonly EXPECTED_VISIBLE_PROFILE_COUNT=8
readonly EXPECTED_HIDDEN_PROFILE_COUNT=0
readonly -a PROFILES=(c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 unlinkat headers: %s\n' "$*" >&2
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
            *) fail "unknown trace tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
    return 1
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

profile_arguments() {
    local profile="$1"

    case "$profile" in
        c-default|c11-strict) ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $profile" ;;
    esac
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
            arguments=(-x c "${arguments[@]}" -Werror=implicit-function-declaration \
                -fsyntax-only "$source")
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
    local header

    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown trace tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree trace escaped its declared header roots"
    fi
    for header in fcntl.h sys/syscall.h unistd.h features.h bits/alltypes.h bits/syscall.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
}

check_cxx_symbol() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]unlinkat$' ||
        fail "$tree $profile C++ probe does not retain C linkage for unlinkat"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*unlinkat'; then
        fail "$tree $profile C++ probe retained a mangled unlinkat reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in grep mapfile mktemp nm realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C unlinkat ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ unlinkat ABI probe"
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
    fail "compiler builtin include directory aliases the pinned musl tree"

work_dir="$(mktemp -d /tmp/crabc-x86-64-unlinkat-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
visible_count=0
hidden_count=0

for profile in "${PROFILES[@]}"; do
    reference_trace="$work_dir/$profile.reference.trace"
    candidate_trace="$work_dir/$profile.candidate.trace"
    reference_object="$work_dir/$profile.reference.o"
    candidate_object="$work_dir/$profile.candidate.o"
    visible_count=$((visible_count + 1))
    if ! compile_profile reference "$profile" "$reference_trace" "$reference_object"; then
        fail "$profile pinned-musl visible reference failed: $(first_diagnostic "$reference_trace")"
    fi
    check_trace reference "$profile" "$reference_trace"
    if ! compile_profile candidate "$profile" "$candidate_trace" "$candidate_object"; then
        fail "$profile project-header visible candidate failed: $(first_diagnostic "$candidate_trace")"
    fi
    check_trace candidate "$profile" "$candidate_trace"
    if [[ "$profile" == cxx17-* ]]; then
        check_cxx_symbol reference "$profile" "$reference_object"
        check_cxx_symbol candidate "$profile" "$candidate_object"
    fi
done

[ "$visible_count" = "$EXPECTED_VISIBLE_PROFILE_COUNT" ] ||
    fail "visible profile count drifted: $visible_count"
[ "$hidden_count" = "$EXPECTED_HIDDEN_PROFILE_COUNT" ] ||
    fail "hidden profile count drifted: $hidden_count"

printf 'x86 pinned-musl/project C/C++ unlinkat ABI matrix: PASS (%s profiles; visible=%s hidden=%s; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT" "$visible_count" "$hidden_count"
