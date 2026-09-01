#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <string.h> C-string-copy ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
# The ordinary C names are unconditional, stpcpy/stpncpy are POSIX-selected,
# strlcpy/strlcat are GNU/BSD-selected, and strdupa is exact GNU C syntax.
# It intentionally relies on a consumer-provided <alloca.h> macro and remains
# source-faithful C++ syntax rather than acquiring a project-only cast.
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

strict_definitions=(-D__STRICT_ANSI__ -DCRABC_REQUIRE_STRDUPA_HIDDEN)
posix_definitions=(-D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_POSIX_COPY -DCRABC_REQUIRE_STRDUPA_HIDDEN)
xopen_definitions=(-D_XOPEN_SOURCE=700 -DCRABC_EXPECT_POSIX_COPY -DCRABC_REQUIRE_STRDUPA_HIDDEN)
bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_POSIX_COPY -DCRABC_EXPECT_GNU_COPY -DCRABC_REQUIRE_STRDUPA_HIDDEN)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_POSIX_COPY -DCRABC_EXPECT_GNU_COPY -DCRABC_EXPECT_STRDUPA)
cxx_strict_definitions=(-DCRABC_EXPECT_STRDUPA)

for definitions_name in strict_definitions posix_definitions xopen_definitions bsd_definitions gnu_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
done
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${cxx_strict_definitions[@]}" \
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
for definitions_name in posix_definitions xopen_definitions bsd_definitions gnu_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
done
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${cxx_strict_definitions[@]}" \
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

# POSIX/XOPEN selectors expose stpcpy/stpncpy but keep GNU/BSD strl*
# declarations hidden, matching the pinned header exactly.
for definitions_name in posix_definitions xopen_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -DCRABC_REQUIRE_GNU_COPY_HIDDEN \
        -fsyntax-only "$c_probe" >"$work_dir/oracle-${definitions_name}-strl-hidden.out" 2>&1; then
        fail "pinned musl exposes strlcpy outside GNU/BSD selectors in ${definitions_name}"
    fi
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" \
        -DCRABC_REQUIRE_GNU_COPY_HIDDEN -fsyntax-only "$c_probe" \
        >"$work_dir/project-${definitions_name}-strl-hidden.out" 2>&1; then
        fail "project string.h exposes strlcpy outside GNU/BSD selectors in ${definitions_name}"
    fi
done

# In normal GNU and compiler-native strict C++ modes, musl publishes the raw
# C macro but its alloca(void *) result cannot satisfy C++ strcpy(char *, ...).
# Keep that intentionally surprising source behavior equal in both trees.
for definitions_name in gnu_definitions cxx_strict_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    if "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" \
        -DCRABC_REQUIRE_STRDUPA_CPP_EXPANSION_REJECTED -fsyntax-only "$cxx_probe" \
        >"$work_dir/oracle-${definitions_name}-strdupa-cxx.out" 2>&1; then
        fail "pinned musl unexpectedly accepts strdupa expansion in ${definitions_name}"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" -I "$ROOT_DIR/include" \
        -DCRABC_REQUIRE_STRDUPA_CPP_EXPANSION_REJECTED -fsyntax-only "$cxx_probe" \
        >"$work_dir/project-${definitions_name}-strdupa-cxx.out" 2>&1; then
        fail "project string.h changed strdupa C++ expansion in ${definitions_name}"
    fi
done

printf 'x86 pinned-musl/project C/C++ <string.h> C-string-copy ABI: PASS\n'
