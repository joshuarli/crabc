#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <string.h> memory-search ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
# memchr is unconditional, memmem is POSIX-visible, and memrchr is GNU-only.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 string.h memory-search ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/memory_search_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/memory_search_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-memory-search-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

# Strict C contains only the unconditional declaration. Feature-selected C
# and C++ passes then prove the POSIX/GNU declarations against pinned musl.
strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_MEMMEM)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_MEMMEM -DCRABC_EXPECT_MEMRCHR)

"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${posix_definitions[@]}" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${gnu_definitions[@]}" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -fsyntax-only "$cxx_probe"

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever host string.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project strict C memory-search header contract drifted"
fi
grep -Fq "$ROOT_DIR/include/string.h" "$header_trace" || {
    fail "C probe did not use the project <string.h>"
}

"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${posix_definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${gnu_definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

# Strict C must reject feature-gated declarations in both header trees. Do
# not repeat these negative checks in C++: g++ implicitly enables GNU names.
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -DCRABC_EXPECT_MEMMEM_HIDDEN \
    -fsyntax-only "$c_probe" >"$work_dir/oracle-memmem-hidden.out" 2>&1; then
    fail "pinned musl exposes memmem outside POSIX selectors"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -DCRABC_EXPECT_MEMRCHR_HIDDEN \
    -fsyntax-only "$c_probe" >"$work_dir/oracle-memrchr-hidden.out" 2>&1; then
    fail "pinned musl exposes memrchr outside GNU selectors"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -I "$ROOT_DIR/include" \
    -DCRABC_EXPECT_MEMMEM_HIDDEN -fsyntax-only "$c_probe" \
    >"$work_dir/project-memmem-hidden.out" 2>&1; then
    fail "project string.h exposes memmem outside POSIX selectors"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -I "$ROOT_DIR/include" \
    -DCRABC_EXPECT_MEMRCHR_HIDDEN -fsyntax-only "$c_probe" \
    >"$work_dir/project-memrchr-hidden.out" 2>&1; then
    fail "project string.h exposes memrchr outside GNU selectors"
fi

printf 'x86 pinned-musl/project C/C++ <string.h> memory-search ABI: PASS\n'
