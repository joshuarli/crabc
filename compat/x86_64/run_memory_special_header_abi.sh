#!/usr/bin/env bash
# Native Linux/x86-64 explicit_bzero/swab C/C++ header ABI gate.
#
# Pinned musl 1.2.6 and the project headers must agree that explicit_bzero is
# GNU/BSD-only and swab is X/Open/GNU/BSD-only. This proves declaration gates,
# LP64 sizes, and C++ C linkage only; it selects neither memory runtime nor
# general header closure.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/memory_special_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/memory_special_header_abi_probe.cpp"

fail() { printf 'ERROR: x86 explicit_bzero/swab header ABI: %s\n' "$*" >&2; exit 1; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
}

compile_c() {
    local tree="$1"
    shift
    local -a include_args=()

    [ "$tree" = oracle ] || include_args=(-I "$ROOT_DIR/include")
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration -fno-builtin \
        "${include_args[@]}" "$@" -fsyntax-only "$C_PROBE"
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-memory-special-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

strict_definitions=(-D__STRICT_ANSI__ -U_GNU_SOURCE -U_BSD_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE)
posix_definitions=(-D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE)
xopen_definitions=(-D_XOPEN_SOURCE=700 -U_GNU_SOURCE -U_BSD_SOURCE -DCRABC_EXPECT_SWAB)
gnu_definitions=(-D_GNU_SOURCE -U_BSD_SOURCE -DCRABC_EXPECT_EXPLICIT_BZERO -DCRABC_EXPECT_SWAB)
bsd_definitions=(-D_BSD_SOURCE -U_GNU_SOURCE -DCRABC_EXPECT_EXPLICIT_BZERO -DCRABC_EXPECT_SWAB)

for tree in oracle project; do
    compile_c "$tree" "${strict_definitions[@]}"
    compile_c "$tree" "${posix_definitions[@]}"
    compile_c "$tree" "${xopen_definitions[@]}"
    compile_c "$tree" "${gnu_definitions[@]}"
    compile_c "$tree" "${bsd_definitions[@]}"
done

# g++ enables GNU names even under a nominal strict selector, so one explicit
# GNU C++ witness proves both declarations retain unmangled C linkage.
for tree in oracle project; do
    include_args=()
    [ "$tree" = oracle ] || include_args=(-I "$ROOT_DIR/include")
    "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "${gnu_definitions[@]}" \
        "${include_args[@]}" -fsyntax-only "$CXX_PROBE"
    object="$work_dir/$tree-gnu-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "${gnu_definitions[@]}" \
        "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]explicit_bzero$' ||
        fail "$tree C++ witness lacks unmangled explicit_bzero"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]swab$' ||
        fail "$tree C++ witness lacks unmangled swab"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(explicit_bzero|swab)'; then
        fail "$tree C++ witness retained a mangled explicit_bzero or swab reference"
    fi
done

# Negative C checks make the feature visibility boundaries observable instead
# of merely compiling the positive profiles.
for tree in oracle project; do
    for definitions_name in strict_definitions posix_definitions; do
        declare -n definitions="$definitions_name"
        if compile_c "$tree" "${definitions[@]}" \
            -DCRABC_REQUIRE_EXPLICIT_BZERO_HIDDEN -DCRABC_REQUIRE_SWAB_HIDDEN \
            >"$work_dir/$tree-$definitions_name.out" 2>&1; then
            fail "$tree exposes explicit_bzero or swab outside its feature selectors"
        fi
    done
    if compile_c "$tree" "${xopen_definitions[@]}" \
        -DCRABC_REQUIRE_EXPLICIT_BZERO_HIDDEN \
        >"$work_dir/$tree-xopen-explicit-bzero.out" 2>&1; then
        fail "$tree exposes explicit_bzero under X/Open"
    fi
done

header_trace="$work_dir/project-gnu-header-trace"
"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration -fno-builtin \
    "${gnu_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace"
for header in string.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project trace omitted $header"
done

printf 'x86 pinned-musl/project explicit_bzero/swab C/C++ header ABI: PASS\n'
