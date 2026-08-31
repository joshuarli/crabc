#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <string.h> strsignal declaration evidence.
#
# Pinned musl 1.2.6 is the declaration oracle. `strsignal` is hidden under
# strict C/C++ and visible with POSIX, XOPEN, GNU, and BSD feature selection.
# Positive C++ objects retain its unmangled C linkage.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 string.h strsignal ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/strsignal_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/strsignal_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-strsignal-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_positive_profile() {
    local -a definitions=("$@")
    local variant
    for variant in oracle project; do
        local -a include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -DCRABC_EXPECT_STRSIGNAL \
            "${definitions[@]}" -fsyntax-only "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
            -DCRABC_EXPECT_STRSIGNAL "${definitions[@]}" -fsyntax-only \
            "${include_args[@]}" "$cxx_probe"
    done
}

compile_positive_profile -D_POSIX_C_SOURCE=200809L
compile_positive_profile -D_XOPEN_SOURCE=700
compile_positive_profile -D_GNU_SOURCE
compile_positive_profile -D_BSD_SOURCE

for language in c cxx; do
    for variant in oracle project; do
        include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        errors="$work_dir/${variant}-${language}-strict-errors"
        if [ "$language" = c ]; then
            if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D__STRICT_ANSI__ \
                -DCRABC_REQUIRE_STRSIGNAL_HIDDEN \
                -Werror=implicit-function-declaration "${include_args[@]}" \
                -fsyntax-only "$c_probe" >"$errors" 2>&1; then
                fail "strsignal is visible under strict C (${variant})"
            fi
        elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D__STRICT_ANSI__ \
            -DCRABC_REQUIRE_STRSIGNAL_HIDDEN "${include_args[@]}" \
            -fsyntax-only "$cxx_probe" >"$errors" 2>&1; then
            fail "strsignal is visible under strict C++ (${variant})"
        fi
    done
done

"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_STRSIGNAL -I "$ROOT_DIR/include" -H -fsyntax-only \
    "$c_probe" >/dev/null 2>"$header_trace"
for header in string.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-strsignal-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
        -D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_STRSIGNAL \
        "${include_args[@]}" -c "$cxx_probe" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]strsignal$' ||
        fail "C++ probe does not retain C linkage for strsignal (${variant})"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*strsignal'; then
        fail "C++ probe retained a mangled strsignal reference (${variant})"
    fi
done

printf 'x86 pinned-musl/project C/C++ <string.h> strsignal ABI: PASS\n'
