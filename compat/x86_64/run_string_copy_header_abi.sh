#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <string.h> C-string-copy ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
# The ordinary C names are unconditional, stpcpy/stpncpy are POSIX-selected,
# and strlcpy/strlcat are GNU/BSD-selected.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 string.h C-string-copy ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/string_copy_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/string_copy_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-string-copy-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_POSIX_COPY)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_POSIX_COPY -DCRABC_EXPECT_GNU_COPY)

for definitions_name in strict_definitions posix_definitions gnu_definitions; do
    definitions=("${!definitions_name}")
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
done
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -fsyntax-only "$cxx_probe"

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever system string.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${strict_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project strict C C-string-copy header contract drifted"
fi
grep -Fq "$ROOT_DIR/include/string.h" "$header_trace" || {
    fail "C probe did not use the project <string.h>"
}
for definitions_name in posix_definitions gnu_definitions; do
    definitions=("${!definitions_name}")
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
done
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

# Strict C must reject every feature-gated declaration in both header trees.
# Do not repeat these negative checks in C++: g++ implicitly enables GNU names.
for hidden_macro in CRABC_REQUIRE_POSIX_COPY_HIDDEN CRABC_REQUIRE_GNU_COPY_HIDDEN; do
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${strict_definitions[@]}" -D"$hidden_macro" -fsyntax-only "$c_probe" \
        >"$work_dir/oracle-${hidden_macro}.out" 2>&1; then
        fail "pinned musl exposes ${hidden_macro} outside its feature selectors"
    fi
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${strict_definitions[@]}" -I "$ROOT_DIR/include" -D"$hidden_macro" \
        -fsyntax-only "$c_probe" >"$work_dir/project-${hidden_macro}.out" 2>&1; then
        fail "project string.h exposes ${hidden_macro} outside its feature selectors"
    fi
done

# POSIX selectors expose stpcpy/stpncpy but keep GNU/BSD strl* declarations
# hidden, matching the pinned header exactly.
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${posix_definitions[@]}" -DCRABC_REQUIRE_GNU_COPY_HIDDEN \
    -fsyntax-only "$c_probe" >"$work_dir/oracle-posix-strl-hidden.out" 2>&1; then
    fail "pinned musl exposes strlcpy outside GNU/BSD selectors"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${posix_definitions[@]}" -I "$ROOT_DIR/include" \
    -DCRABC_REQUIRE_GNU_COPY_HIDDEN -fsyntax-only "$c_probe" \
    >"$work_dir/project-posix-strl-hidden.out" 2>&1; then
    fail "project string.h exposes strlcpy outside GNU/BSD selectors"
fi

printf 'x86 pinned-musl/project C/C++ <string.h> C-string-copy ABI: PASS\n'
