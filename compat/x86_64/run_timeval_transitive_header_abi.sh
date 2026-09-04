#!/usr/bin/env bash
# Native Linux/x86-64 timeval transitive-header ABI profile matrix.
#
# Pinned musl is the declaration/layout oracle. The candidate uses raw GCC
# with only project headers and raw-GCC builtin headers, so an ambient libc
# cannot conceal a missing public type dependency. This is compile-only
# evidence: it proves no sys/time callable linkage, runtime, or family
# completion.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/timeval_transitive_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/timeval_transitive_header_abi_probe.cpp"
readonly EXPECTED_HEADER_COUNT=5
readonly EXPECTED_PROFILE_COUNT=7
readonly EXPECTED_ROW_COUNT=35
readonly -a TARGET_IDS=(sys-time utmpx utmp lastlog sys-timex)
readonly -a TARGET_HEADERS=(sys/time.h utmpx.h utmp.h lastlog.h sys/timex.h)
readonly -a TARGET_SELECTORS=(CRABC_TIMEVAL_TARGET_SYS_TIME CRABC_TIMEVAL_TARGET_UTMPX CRABC_TIMEVAL_TARGET_UTMP CRABC_TIMEVAL_TARGET_LASTLOG CRABC_TIMEVAL_TARGET_SYS_TIMEX)
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 timeval transitive-header ABI: %s\n' "$*" >&2
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
            *) fail "unknown trace tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

assert_no_time_record_overincludes() {
    local tree="$1"
    local target_id="$2"
    local profile="$3"
    local trace="$4"
    local root

    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown trace tree: $tree" ;;
    esac
    for forbidden_header in sys/types.h sys/time.h time.h; do
        if trace_has_header "$trace" "$root" "$forbidden_header"; then
            fail "$target_id $profile $tree trace over-included $forbidden_header"
        fi
    done
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
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict) ;;
        # GCC predefines _GNU_SOURCE for C++; remove that ambient selection
        # so this row exercises the declared macro-free C++17 profile.
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $profile" ;;
    esac
}

compile_profile() {
    local tree="$1"
    local selector="$2"
    local profile="$3"
    local diagnostic="$4"
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
        -D "$selector"
        -H
        -fsyntax-only
    )
    case "$profile" in
        c11-*)
            source="$C_PROBE"
            arguments=(-x c -std=c11 "${profile_args[@]}" "${arguments[@]}" "$source")
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            arguments=(-x c++ -std=c++17 -nostdinc++ "${profile_args[@]}" "${arguments[@]}" "$source")
            ;;
        *) fail "unknown profile language: $profile" ;;
    esac

    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_trace() {
    local tree="$1"
    local target_id="$2"
    local target_header="$3"
    local profile="$4"
    local trace="$5"
    local root
    local required_header

    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$target_id $profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        reference)
            root="$MUSL_ROOT/include"
            ;;
        *) fail "unknown trace tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$target_id $profile $tree trace escaped its declared header roots"
    fi
    trace_has_header "$trace" "$root" "$target_header" ||
        fail "$target_id $profile $tree trace omitted ${root}/$target_header"
    # Musl's utmpx route provides struct timeval directly through alltypes.
    # Keep the candidate include graph equally narrow: these accounting
    # records must not import the unrelated sys/types, sys/time, or time
    # declaration surfaces merely to obtain their fixed-width record types.
    case "$target_id" in
        sys-time|sys-timex)
            for required_header in sys/time.h sys/select.h; do
                trace_has_header "$trace" "$root" "$required_header" ||
                    fail "$target_id $profile $tree trace omitted required timeval dependency ${root}/$required_header"
            done
            ;;
        utmpx)
            trace_has_header "$trace" "$root" utmpx.h ||
                fail "$target_id $profile $tree trace omitted required public chain ${root}/utmpx.h"
            assert_no_time_record_overincludes "$tree" "$target_id" "$profile" "$trace"
            ;;
        utmp)
            for required_header in utmp.h utmpx.h; do
                trace_has_header "$trace" "$root" "$required_header" ||
                    fail "$target_id $profile $tree trace omitted required public chain ${root}/$required_header"
            done
            assert_no_time_record_overincludes "$tree" "$target_id" "$profile" "$trace"
            ;;
        lastlog)
            for required_header in lastlog.h utmp.h utmpx.h; do
                trace_has_header "$trace" "$root" "$required_header" ||
                    fail "$target_id $profile $tree trace omitted required public chain ${root}/$required_header"
            done
            assert_no_time_record_overincludes "$tree" "$target_id" "$profile" "$trace"
            ;;
        *) fail "unknown timeval transitive-header target: $target_id" ;;
    esac
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in grep mapfile mktemp realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C timeval transitive-header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ timeval transitive-header ABI probe"
[ "${#TARGET_IDS[@]}" = "$EXPECTED_HEADER_COUNT" ] || fail "target id roster drifted"
[ "${#TARGET_HEADERS[@]}" = "$EXPECTED_HEADER_COUNT" ] || fail "target header roster drifted"
[ "${#TARGET_SELECTORS[@]}" = "$EXPECTED_HEADER_COUNT" ] || fail "target selector roster drifted"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"
[ "$EXPECTED_ROW_COUNT" = "$((EXPECTED_HEADER_COUNT * EXPECTED_PROFILE_COUNT))" ] ||
    fail "row count no longer matches the target/profile cross-product"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] || fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases the pinned musl tree"

work_dir="$(mktemp -d /tmp/crabc-x86-64-timeval-transitive-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for index in "${!TARGET_IDS[@]}"; do
    target_id="${TARGET_IDS[$index]}"
    target_header="${TARGET_HEADERS[$index]}"
    target_selector="${TARGET_SELECTORS[$index]}"
    for profile in "${PROFILES[@]}"; do
        reference_trace="$work_dir/$target_id.$profile.reference.trace"
        candidate_trace="$work_dir/$target_id.$profile.candidate.trace"
        if ! compile_profile reference "$target_selector" "$profile" "$reference_trace"; then
            fail "$target_id $profile pinned-musl reference failed: $(first_diagnostic "$reference_trace")"
        fi
        check_trace reference "$target_id" "$target_header" "$profile" "$reference_trace"
        if ! compile_profile candidate "$target_selector" "$profile" "$candidate_trace"; then
            fail "$target_id $profile project-header candidate failed: $(first_diagnostic "$candidate_trace")"
        fi
        check_trace candidate "$target_id" "$target_header" "$profile" "$candidate_trace"
    done
done

printf 'x86 pinned-musl/project timeval transitive-header ABI matrix: PASS (%s rows; compile-only)\n' \
    "$EXPECTED_ROW_COUNT"
