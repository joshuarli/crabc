#!/usr/bin/env bash
# Native Linux/x86-64 GNU sync_file_range C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration, off_t, flag, and unmangled C-linkage
# oracle.
# The project pass uses only project headers plus compiler builtin headers, so
# an ambient libc cannot make the GNU-only `<fcntl.h>` entry appear. This gate
# establishes one descriptor-range writeback declaration, not a descriptor or
# filesystem capability family, durability policy, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sync_file_range_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sync_file_range_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=5
readonly EXPECTED_VISIBLE_PROFILE_COUNT=1
readonly EXPECTED_HIDDEN_PROFILE_COUNT=4

fail() {
    printf 'ERROR: x86 fcntl.h sync_file_range ABI: %s\n' "$*" >&2
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

set_profile_args() {
    local tree="$1"

    case "$tree" in
        oracle)
            compiler="$ORACLE_CC"
            include_args=()
            ;;
        project)
            compiler="$CANDIDATE_CC"
            include_args=(
                -nostdinc
                -I "$PROJECT_INCLUDE"
                -isystem "$candidate_compiler_builtin_include"
            )
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
}

compile_hidden_profile() {
    local label="$1"
    shift
    local language tree diagnostic

    for language in c cxx; do
        for tree in oracle project; do
            set_profile_args "$tree"
            diagnostic="$work_dir/${tree}-${language}-${label}-diagnostic"
            if [ "$language" = c ]; then
                if run_compiler "$compiler" -std=c11 -U_GNU_SOURCE \
                    -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                    -U_DEFAULT_SOURCE "$@" -DCRABC_REQUIRE_SYNC_FILE_RANGE_HIDDEN \
                    -Werror=implicit-function-declaration "${include_args[@]}" \
                    -fsyntax-only "$C_PROBE" >"$diagnostic" 2>&1; then
                    fail "sync_file_range is visible under ${label} C (${tree})"
                fi
            elif run_compiler "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE \
                -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_DEFAULT_SOURCE "$@" -DCRABC_REQUIRE_SYNC_FILE_RANGE_HIDDEN \
                -nostdinc++ "${include_args[@]}" -fsyntax-only "$CXX_PROBE" \
                >"$diagnostic" 2>&1; then
                fail "sync_file_range is visible under ${label} C++ (${tree})"
            fi
        done
    done
}

compile_gnu_profile() {
    local language tree object undefined

    for language in c cxx; do
        for tree in oracle project; do
            set_profile_args "$tree"
            if [ "$language" = c ]; then
                run_compiler "$compiler" -std=c11 -U_GNU_SOURCE \
                    -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                    -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                    -DCRABC_EXPECT_SYNC_FILE_RANGE \
                    -Werror=implicit-function-declaration "${include_args[@]}" \
                    -fsyntax-only "$C_PROBE"
            else
                object="$work_dir/${tree}-sync-file-range.o"
                run_compiler "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE \
                    -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                    -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                    -DCRABC_EXPECT_SYNC_FILE_RANGE -nostdinc++ \
                    "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
                undefined="$(nm --undefined-only "$object")"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]sync_file_range$' ||
                    fail "C++ probe does not retain C linkage (${tree})"
                if printf '%s\n' "$undefined" | grep -Eq '_Z.*sync_file_range'; then
                    fail "C++ probe retained a mangled sync_file_range reference (${tree})"
                fi
            fi
        done
    done
}

require_native_linux_x86_64
for tool in env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C sync_file_range ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sync_file_range ABI probe"
[ "$EXPECTED_PROFILE_COUNT" -eq 5 ] || fail "profile roster drifted"
[ "$EXPECTED_VISIBLE_PROFILE_COUNT" -eq 1 ] || fail "visible profile count drifted"
[ "$EXPECTED_HIDDEN_PROFILE_COUNT" -eq 4 ] || fail "hidden profile count drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-sync-file-range-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

compile_hidden_profile strict -D__STRICT_ANSI__
compile_hidden_profile posix -D_POSIX_C_SOURCE=200809L
compile_hidden_profile xopen -D_XOPEN_SOURCE=700
compile_hidden_profile bsd -D_BSD_SOURCE
compile_gnu_profile

set_profile_args project
header_trace="$work_dir/project-gnu-header-trace"
run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE \
    -DCRABC_EXPECT_SYNC_FILE_RANGE "${include_args[@]}" -H -fsyntax-only \
    "$C_PROBE" >/dev/null 2>"$header_trace"
while IFS= read -r path; do
    case "$path" in
        "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
        *) fail "project GNU header trace escaped its declared roots: $path" ;;
    esac
done < <(trace_paths "$header_trace")
for header in fcntl.h features.h sys/types.h; do
    grep -Fq "$PROJECT_INCLUDE/$header" "$header_trace" ||
        fail "GNU C probe did not use the project <$header>"
done

printf 'x86 pinned-musl/project GNU C/C++ <fcntl.h> sync_file_range ABI: PASS (profiles=%s visible=%s hidden=%s)\n' \
    "$EXPECTED_PROFILE_COUNT" "$EXPECTED_VISIBLE_PROFILE_COUNT" "$EXPECTED_HIDDEN_PROFILE_COUNT"
