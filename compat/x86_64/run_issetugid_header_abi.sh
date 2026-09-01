#!/usr/bin/env bash
# Native Linux/x86-64 GNU/BSD issetugid C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. The raw project
# pass uses only project headers plus raw compiler builtin headers, preventing
# host-libc header leakage. `issetugid` is visible only under GNU or BSD
# feature selection; strict, POSIX.1-2008, and X/Open 700 selection hide it.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/issetugid_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/issetugid_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 unistd.h issetugid ABI: %s\n' "$*" >&2
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

require_native_linux_x86_64
for tool in env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-issetugid-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

set_profile_args() {
    local variant="$1"
    case "$variant" in
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
        *) fail "unknown header tree: $variant" ;;
    esac
}

compile_hidden_profile() {
    local label="$1"
    shift
    local language variant errors

    for language in c cxx; do
        for variant in oracle project; do
            set_profile_args "$variant"
            errors="$work_dir/${variant}-${language}-${label}-errors"
            if [ "$language" = c ]; then
                if run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE "$@" \
                    -DCRABC_REQUIRE_ISSETUGID_HIDDEN \
                    -Werror=implicit-function-declaration "${include_args[@]}" \
                    -fsyntax-only "$C_PROBE" >"$errors" 2>&1; then
                    fail "issetugid is visible under ${label} C (${variant})"
                fi
            elif run_compiler "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE \
                -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                "$@" -DCRABC_REQUIRE_ISSETUGID_HIDDEN -nostdinc++ \
                "${include_args[@]}" -fsyntax-only "$CXX_PROBE" >"$errors" 2>&1; then
                fail "issetugid is visible under ${label} C++ (${variant})"
            fi
        done
    done
}

compile_visible_profile() {
    local label="$1"
    shift
    local language variant object undefined

    for language in c cxx; do
        for variant in oracle project; do
            set_profile_args "$variant"
            if [ "$language" = c ]; then
                run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE "$@" \
                    -DCRABC_EXPECT_ISSETUGID \
                    -Werror=implicit-function-declaration "${include_args[@]}" \
                    -fsyntax-only "$C_PROBE"
            else
                object="$work_dir/${variant}-${label}-issetugid.o"
                run_compiler "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE \
                    -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                    -U_DEFAULT_SOURCE "$@" -DCRABC_EXPECT_ISSETUGID \
                    -nostdinc++ "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
                undefined="$(nm --undefined-only "$object")"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]issetugid$' ||
                    fail "C++ probe does not retain C linkage for issetugid (${label}, ${variant})"
                if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*issetugid'; then
                    fail "C++ probe retained a mangled issetugid reference (${label}, ${variant})"
                fi
            fi
        done
    done
}

compile_hidden_profile strict -D__STRICT_ANSI__
compile_hidden_profile posix -D_POSIX_C_SOURCE=200809L
compile_hidden_profile xopen -D_XOPEN_SOURCE=700
compile_visible_profile gnu -D_GNU_SOURCE
compile_visible_profile bsd -D_BSD_SOURCE

set_profile_args project
header_trace="$work_dir/project-gnu-header-trace"
run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
    -D_GNU_SOURCE -DCRABC_EXPECT_ISSETUGID "${include_args[@]}" \
    -H -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"
while IFS= read -r path; do
    case "$path" in
        "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
        *) fail "project GNU header trace escaped its declared roots: $path" ;;
    esac
done < <(trace_paths "$header_trace")
for header in unistd.h features.h sys/types.h stdint.h; do
    grep -Fq "$PROJECT_INCLUDE/$header" "$header_trace" ||
        fail "GNU C probe did not use the project <$header>"
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> issetugid ABI: PASS\n'
