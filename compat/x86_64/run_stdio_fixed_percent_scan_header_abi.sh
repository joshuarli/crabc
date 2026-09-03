#!/usr/bin/env bash
# Native Linux/x86-64 C11/C++17 literal-percent scanf declaration/linkage proof.
#
# Pinned musl 1.2.6 is the header oracle. The candidate sees only project and
# compiler-builtin include trees, making this a narrow declaration proof for
# `sscanf`/`vsscanf`, not a stdio runtime or header-completion claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdio_fixed_percent_scan_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdio_fixed_percent_scan_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 stdio literal-percent scan header ABI: %s\n' "$*" >&2
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
    # stdarg.h is explicitly included by both probes. The candidate must resolve
    # it from the project tree; the pinned-musl compiler may use its permitted
    # compiler-builtin copy. stdio.h, features.h, and bits/alltypes.h must still
    # resolve from the selected tree.
    if [ "$tree" = candidate ]; then
        grep -Fq "$root/stdarg.h" "$trace" ||
            fail "$tree trace omitted $root/stdarg.h"
    fi
    for header in stdio.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree trace omitted $root/$header"
    done
}

compile_c() {
    local tree="$1"
    local trace="$2"
    local compiler include_root

    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    run_compiler "$compiler" -x c -std=c11 -nostdinc -I "$include_root" \
        -isystem "$candidate_compiler_builtin_include" -H -fno-builtin \
        -DCRABC_STDIO_FIXED_PERCENT_SCAN_HEADER_C11 -fsyntax-only "$C_PROBE" \
        >/dev/null 2>"$trace"
}

compile_cxx() {
    local tree="$1"
    local trace="$2"
    local object="$3"
    local compiler include_root

    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    run_compiler "$compiler" -x c++ -std=c++17 -nostdinc -nostdinc++ \
        -I "$include_root" -isystem "$candidate_compiler_builtin_include" \
        -H -fno-builtin -fno-stack-protector \
        -DCRABC_STDIO_FIXED_PERCENT_SCAN_HEADER_CXX17 \
        -c "$CXX_PROBE" -o "$object" >/dev/null 2>"$trace"
}

assert_cxx_c_linkage() {
    local tree="$1"
    local object="$2"
    local undefined

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    for symbol in sscanf vsscanf; do
        printf '%s\n' "$undefined" | grep -Fxq "$symbol" ||
            fail "$tree C++ probe does not retain C spelling $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(sscanf|vsscanf)'; then
        fail "$tree C++ probe retained a mangled scanf reference"
    fi
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
[ -f "$C_PROBE" ] || fail "missing C literal-percent scan header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ literal-percent scan header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdio-fixed-percent-scan-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
for tree in reference candidate; do
    c_trace="$work_dir/$tree-c.trace"
    cxx_trace="$work_dir/$tree-cxx.trace"
    cxx_object="$work_dir/$tree-cxx.o"
    compile_c "$tree" "$c_trace"
    assert_header_provenance "$tree" "$c_trace"
    compile_cxx "$tree" "$cxx_trace" "$cxx_object"
    assert_header_provenance "$tree" "$cxx_trace"
    assert_cxx_c_linkage "$tree" "$cxx_object"
done

printf 'x86 stdio literal-percent scan header ABI: PASS\n'
