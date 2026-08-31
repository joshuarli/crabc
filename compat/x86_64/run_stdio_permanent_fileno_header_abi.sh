#!/usr/bin/env bash
# Native Linux/x86-64 permanent-stream fileno <stdio.h> ABI proof.
#
# Pinned musl 1.2.6 is the POSIX declaration and C++ C-linkage oracle. The
# candidate has only project and compiler-builtin include trees, so ambient
# headers cannot conceal a mismatch. This compile-only proof selects no
# archive, runtime, stream state, or public-x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdio_permanent_fileno_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdio_permanent_fileno_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 stdio permanent-stream fileno header ABI: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$compiler" "$@"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

assert_header_provenance() {
    local tree="$1"
    local trace="$2"
    local root path

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$tree header trace escaped its declared roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    for header in stdio.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree trace omitted $root/$header"
    done
}

compiler_for_tree() {
    case "$1" in
        reference) printf '%s\n' "$ORACLE_CC" ;;
        candidate) printf '%s\n' "$CANDIDATE_CC" ;;
        *) fail "unknown header tree: $1" ;;
    esac
}

include_for_tree() {
    case "$1" in
        reference) printf '%s\n' "$MUSL_ROOT/include" ;;
        candidate) printf '%s\n' "$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $1" ;;
    esac
}

compile_positive_c() {
    local tree="$1" trace="$2"
    local compiler include_root
    compiler="$(compiler_for_tree "$tree")"
    include_root="$(include_for_tree "$tree")"
    run_compiler "$compiler" -x c -std=c11 -nostdinc -I "$include_root" \
        -isystem "$candidate_compiler_builtin_include" -H -fno-builtin \
        -D_POSIX_C_SOURCE=200809L -DCRABC_STDIO_PERMANENT_FILENO_C11 \
        -fsyntax-only "$C_PROBE" >/dev/null 2>"$trace"
}

compile_positive_cxx() {
    local tree="$1" trace="$2" object="$3"
    local compiler include_root
    compiler="$(compiler_for_tree "$tree")"
    include_root="$(include_for_tree "$tree")"
    run_compiler "$compiler" -x c++ -std=c++17 -nostdinc -nostdinc++ \
        -I "$include_root" -isystem "$candidate_compiler_builtin_include" \
        -H -fno-builtin -D_POSIX_C_SOURCE=200809L \
        -DCRABC_STDIO_PERMANENT_FILENO_CXX17 -c "$CXX_PROBE" -o "$object" \
        >/dev/null 2>"$trace"
}

assert_cxx_c_linkage() {
    local tree="$1" object="$2"
    local undefined

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    printf '%s\n' "$undefined" | grep -Fxq fileno ||
        fail "$tree C++ probe does not retain C spelling fileno"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*fileno'; then
        fail "$tree C++ probe retained a mangled fileno reference"
    fi
}

assert_strict_hidden() {
    local tree="$1" language="$2" diagnostic="$3"
    local compiler include_root source standard
    local -a language_args
    compiler="$(compiler_for_tree "$tree")"
    include_root="$(include_for_tree "$tree")"
    case "$language" in
        c)
            source="$C_PROBE"; standard=c11; language_args=(-x c) ;;
        cxx)
            source="$CXX_PROBE"; standard=c++17; language_args=(-x c++) ;;
        *) fail "unknown strict-hidden language: $language" ;;
    esac

    set +e
    run_compiler "$compiler" "${language_args[@]}" -std="$standard" \
        -nostdinc -nostdinc++ -I "$include_root" \
        -isystem "$candidate_compiler_builtin_include" -H -fno-builtin \
        -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
        -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
        -DCRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN -fsyntax-only "$source" \
        >/dev/null 2>"$diagnostic"
    local status=$?
    set -e
    [ "$status" -ne 0 ] ||
        fail "$tree $language strict profile unexpectedly declares fileno"
    grep -Eq 'fileno|undeclared|not declared' "$diagnostic" ||
        fail "$tree $language strict profile did not diagnose hidden fileno"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C permanent-stream fileno header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ permanent-stream fileno header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdio-permanent-fileno-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
for tree in reference candidate; do
    c_trace="$work_dir/$tree-c.trace"
    cxx_trace="$work_dir/$tree-cxx.trace"
    cxx_object="$work_dir/$tree-cxx.o"
    compile_positive_c "$tree" "$c_trace"
    assert_header_provenance "$tree" "$c_trace"
    compile_positive_cxx "$tree" "$cxx_trace" "$cxx_object"
    assert_header_provenance "$tree" "$cxx_trace"
    assert_cxx_c_linkage "$tree" "$cxx_object"
    assert_strict_hidden "$tree" c "$work_dir/$tree-c-strict.trace"
    assert_strict_hidden "$tree" cxx "$work_dir/$tree-cxx-strict.trace"
done

printf 'x86 stdio permanent-stream fileno header ABI: PASS\n'
