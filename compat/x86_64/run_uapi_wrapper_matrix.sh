#!/usr/bin/env bash
# Native Linux/x86-64 Linux-5.10 UAPI wrapper profile/ABI matrix.
#
# This runner first validates the pinned musl and Linux 5.10 UAPI inputs, then
# compiles the same selected constant/layout assertions through each input in
# five C11 and two C++17 feature profiles.  It is compile-only: this is not a
# device, ioctl, C-runtime, callable-linkage, installed-header, or public-x86
# support claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly LINUX_UAPI_ROOT=/opt/linux-5.10-uapi
readonly LINUX_UAPI_INCLUDE="$LINUX_UAPI_ROOT/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/uapi_wrappers_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/uapi_wrappers_header_abi_probe.cpp"
readonly EXPECTED_HEADER_COUNT=3
readonly EXPECTED_PROFILE_COUNT=7
readonly EXPECTED_ROW_COUNT=21
readonly -a WRAPPER_HEADERS=(sys/kd.h sys/soundcard.h sys/vt.h)
readonly -a UAPI_HEADERS=(linux/kd.h linux/soundcard.h linux/vt.h)
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 Linux 5.10 UAPI wrapper matrix: %s\n' "$*" >&2
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

trace_has_header() {
    local trace="$1"
    local root="$2"
    local header="$3"

    grep -Fq "$root/$header" "$trace"
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
                    "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*) ;;
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
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) ;;
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
        -isystem "$LINUX_UAPI_INCLUDE"
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

check_candidate_trace() {
    local profile="$1"
    local trace="$2"
    local index

    if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
        fail "$profile candidate trace reached pinned musl despite -nostdinc"
    fi
    if trace_has_unapproved_path candidate "$trace"; then
        fail "$profile candidate trace escaped project/builtin/Linux-5.10 roots"
    fi
    for index in "${!WRAPPER_HEADERS[@]}"; do
        trace_has_header "$trace" "$PROJECT_INCLUDE" "${WRAPPER_HEADERS[$index]}" ||
            fail "$profile candidate trace omitted project ${WRAPPER_HEADERS[$index]}"
        trace_has_header "$trace" "$LINUX_UAPI_INCLUDE" "${UAPI_HEADERS[$index]}" ||
            fail "$profile candidate trace omitted pinned ${UAPI_HEADERS[$index]}"
    done
    trace_has_header "$trace" "$PROJECT_INCLUDE" endian.h ||
        fail "$profile candidate trace omitted project endian.h through linux/soundcard.h"
}

check_reference_trace() {
    local profile="$1"
    local trace="$2"
    local index
    local bits_header

    if trace_has_unapproved_path reference "$trace"; then
        fail "$profile reference trace escaped musl/builtin/Linux-5.10 roots"
    fi
    for index in "${!WRAPPER_HEADERS[@]}"; do
        trace_has_header "$trace" "$MUSL_ROOT/include" "${WRAPPER_HEADERS[$index]}" ||
            fail "$profile reference trace omitted pinned-musl ${WRAPPER_HEADERS[$index]}"
        bits_header="bits/${WRAPPER_HEADERS[$index]#sys/}"
        trace_has_header "$trace" "$MUSL_ROOT/include" "$bits_header" ||
            fail "$profile reference trace omitted pinned-musl $bits_header"
        trace_has_header "$trace" "$LINUX_UAPI_INCLUDE" "${UAPI_HEADERS[$index]}" ||
            fail "$profile reference trace omitted pinned ${UAPI_HEADERS[$index]}"
    done
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
[ -d "$LINUX_UAPI_INCLUDE" ] || fail "missing pinned Linux 5.10 UAPI include tree"
[ -f "$C_PROBE" ] || fail "missing C wrapper ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ wrapper ABI probe"
[ "${#WRAPPER_HEADERS[@]}" = "$EXPECTED_HEADER_COUNT" ] || fail "wrapper-header roster drifted"
[ "${#UAPI_HEADERS[@]}" = "$EXPECTED_HEADER_COUNT" ] || fail "Linux-UAPI dependency roster drifted"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"
[ "$((EXPECTED_HEADER_COUNT * EXPECTED_PROFILE_COUNT))" = "$EXPECTED_ROW_COUNT" ] ||
    fail "wrapper/profile row-count contract drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] || fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases the pinned musl tree"

work_dir="$(mktemp -d /tmp/crabc-x86-64-uapi-wrapper-matrix.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
row_count=0

for profile in "${PROFILES[@]}"; do
    reference_trace="$work_dir/$profile.reference.trace"
    candidate_trace="$work_dir/$profile.candidate.trace"
    if ! compile_profile reference "$profile" "$reference_trace"; then
        fail "$profile pinned-musl reference failed: $(first_diagnostic "$reference_trace")"
    fi
    check_reference_trace "$profile" "$reference_trace"
    if ! compile_profile candidate "$profile" "$candidate_trace"; then
        fail "$profile project-header candidate failed: $(first_diagnostic "$candidate_trace")"
    fi
    check_candidate_trace "$profile" "$candidate_trace"
    row_count="$((row_count + EXPECTED_HEADER_COUNT))"
done

[ "$row_count" = "$EXPECTED_ROW_COUNT" ] ||
    fail "completed wrapper/profile rows drifted: expected $EXPECTED_ROW_COUNT, got $row_count"
printf 'x86 Linux 5.10 UAPI wrapper profile ABI matrix: PASS (%s rows; compile-only)\n' "$row_count"
