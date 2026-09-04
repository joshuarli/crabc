#!/usr/bin/env bash
# Native Linux/x86-64 GNU <fcntl.h> file-handle ABI/profile evidence.
#
# This is declaration/layout evidence only. It deliberately does not link or
# select a libc provider; the private callable artifact has a separate gate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly MUSL_ROOT=/opt/musl-1.2.6

fail() {
    printf 'ERROR: x86 file-handle headers: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl headers"

header_c="$ROOT_DIR/compat/x86_64/file_handles_header_abi_probe.c"
header_cpp="$ROOT_DIR/compat/x86_64/file_handles_header_abi_probe.cpp"
hidden_c="$ROOT_DIR/compat/x86_64/file_handles_header_hidden_probe.c"
hidden_cpp="$ROOT_DIR/compat/x86_64/file_handles_header_hidden_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-file-handles-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

run_compiler() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$@"
}

builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
[ -d "$builtin_include" ] || fail "missing compiler builtin include directory"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

for tree in oracle candidate; do
    if [ "$tree" = oracle ]; then
        cc="$ORACLE_CC"
        include_root="$MUSL_ROOT/include"
    else
        cc="$CANDIDATE_CC"
        include_root="$PROJECT_INCLUDE"
    fi
    run_compiler "$cc" -std=c11 -D_GNU_SOURCE -nostdinc -I "$include_root" \
        -isystem "$builtin_include" \
        -fsyntax-only "$header_c"
    run_compiler "$cc" -std=c++17 -x c++ -D_GNU_SOURCE -nostdinc \
        -nostdinc++ -I "$include_root" -isystem "$builtin_include" \
        -fsyntax-only "$header_cpp"
    if run_compiler "$cc" -std=c11 -U_GNU_SOURCE -nostdinc -I "$include_root" \
        -isystem "$builtin_include" \
        -Werror=implicit-function-declaration -fsyntax-only "$hidden_c" \
        >"$work_dir/$tree-hidden-c.out" 2>&1; then
        fail "$tree exposes file-handle declarations outside GNU profile"
    fi
    if run_compiler "$cc" -std=c++17 -x c++ -U_GNU_SOURCE -nostdinc -nostdinc++ \
        -I "$include_root" -isystem "$builtin_include" \
        -fsyntax-only "$hidden_cpp" \
        >"$work_dir/$tree-hidden-cxx.out" 2>&1; then
        fail "$tree C++ exposes file-handle declarations outside GNU profile"
    fi
done

printf 'x86 pinned-musl/project GNU <fcntl.h> file-handle ABI: PASS\n'
