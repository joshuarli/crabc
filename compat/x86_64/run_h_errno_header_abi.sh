#!/usr/bin/env bash
# Native Linux/x86-64 <netdb.h> h_errno visibility, type, and C++ linkage gate.
#
# Pinned musl 1.2.6 is the declaration oracle. The same native Clang profile
# compiler as the callable inventory reads each isolated header root, so an
# ambient libc cannot hide a macro, type, or linkage mismatch. Clang's C++17
# driver defines _GNU_SOURCE even for the strict profile; both header roots
# therefore expose the accessor there, matching the checked inventory. This
# seven-profile matrix proves only the historical h_errno macro/accessor
# boundary; it neither links an archive nor selects resolver configuration,
# DNS, netdb runtime, or header-family closure.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly COMPILER=/usr/bin/clang
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/h_errno_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/h_errno_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly EXPECTED_REFERENCE_VISIBLE_PROFILE_COUNT=4
readonly EXPECTED_CANDIDATE_VISIBLE_PROFILE_COUNT=4
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 h_errno headers: %s\n' "$*" >&2
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
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

profile_arguments() {
    local tree="$1" profile="$2" expected=0

    case "$profile" in
        c11-gnu|cxx17-gnu)
            expected=1
            printf '%s\n' '-D_GNU_SOURCE'
            ;;
        c11-bsd)
            expected=1
            printf '%s\n' '-D_BSD_SOURCE'
            ;;
        cxx17-strict) expected=1 ;;
        c11-strict)
            printf '%s\n' '-D__STRICT_ANSI__'
            ;;
        c11-posix-2008)
            printf '%s\n' '-D_POSIX_C_SOURCE=200809L'
            ;;
        c11-xopen-700)
            printf '%s\n' '-D_XOPEN_SOURCE=700'
            ;;
        *) fail "unknown profile: $profile" ;;
    esac
    printf '%s\n' "-DCRABC_EXPECT_H_ERRNO=$expected"
}

profile_is_visible() {
    local tree="$1" profile="$2"
    case "$profile" in
        c11-gnu|cxx17-gnu|c11-bsd|cxx17-strict) return 0 ;;
        *) return 1 ;;
    esac
}

compile_profile() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local include_root source
    local -a profile_args common_args

    case "$tree" in
        reference) include_root="$MUSL_ROOT/include" ;;
        candidate) include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$tree" "$profile")
    common_args=(
        -nostdinc -I "$include_root" -isystem "$candidate_compiler_builtin_include"
        -H -fno-builtin
    )
    case "$profile" in
        c11-*)
            source="$C_PROBE"
            run_compiler "$COMPILER" -x c -std=c11 "${common_args[@]}" \
                "${profile_args[@]}" -fsyntax-only "$source" >/dev/null 2>"$trace"
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            run_compiler "$COMPILER" -x c++ -std=c++17 -nostdinc++ \
                "${common_args[@]}" "${profile_args[@]}" -c "$source" \
                -o "$object" >/dev/null 2>"$trace"
            ;;
        *) fail "unknown profile language: $profile" ;;
    esac
}

check_trace() {
    local tree="$1" profile="$2" trace="$3" root path
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate)
            root="$PROJECT_INCLUDE"
            grep -Fq "$MUSL_ROOT/include/" "$trace" &&
                fail "$profile candidate trace reached pinned musl"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$profile $tree trace escaped its declared roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$root/netdb.h" "$trace" ||
        fail "$profile $tree trace omitted $root/netdb.h"
}

check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" undefined
    undefined="$(nm --undefined-only "$object")"
    if profile_is_visible "$tree" "$profile"; then
        printf '%s\n' "$undefined" | grep -Eq '[[:space:]]__h_errno_location$' ||
            fail "$profile C++ probe lacks unmangled __h_errno_location"
        if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*h_errno'; then
            fail "$profile C++ probe retained a mangled h_errno reference"
        fi
    elif printf '%s\n' "$undefined" | grep -Eq '[[:space:]]__h_errno_location$'; then
        fail "$profile hidden C++ probe retained h_errno macro linkage"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath sed uname; do require_tool "$tool"; done
[ -x "$COMPILER" ] || fail "missing native Clang profile compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C h_errno header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ h_errno header ABI probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$COMPILER" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "Clang did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] || fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-h-errno-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
reference_visible_count=0
candidate_visible_count=0
for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            sed -n '1,160p' "$trace" >&2
            fail "$profile $tree h_errno macro/type probe failed"
        fi
        check_trace "$tree" "$profile" "$trace"
        case "$profile" in
            cxx17-*) check_cxx_linkage "$tree" "$profile" "$object" ;;
        esac
        if profile_is_visible "$tree" "$profile"; then
            case "$tree" in
                reference) reference_visible_count=$((reference_visible_count + 1)) ;;
                candidate) candidate_visible_count=$((candidate_visible_count + 1)) ;;
            esac
        fi
    done
done
[ "$reference_visible_count" -eq "$EXPECTED_REFERENCE_VISIBLE_PROFILE_COUNT" ] ||
    fail "pinned-musl h_errno macro visibility roster drifted"
[ "$candidate_visible_count" -eq "$EXPECTED_CANDIDATE_VISIBLE_PROFILE_COUNT" ] ||
    fail "project h_errno macro visibility roster drifted"

printf 'x86 pinned-musl/project h_errno macro C/C++ ABI: PASS (%s profiles; reference=%s candidate=%s visible)\n' \
    "$EXPECTED_PROFILE_COUNT" "$EXPECTED_REFERENCE_VISIBLE_PROFILE_COUNT" \
    "$EXPECTED_CANDIDATE_VISIBLE_PROFILE_COUNT"
