#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <string.h> error-string ABI slice.
#
# Pinned musl 1.2.6 is the declaration oracle. `strerror` is unconditional;
# POSIX/XOPEN/GNU/BSD selectors expose the XSI/POSIX `int strerror_r` form.
# Musl's private weak `__xpg_strerror_r` spelling is intentionally absent from
# the public header and belongs to the separate selected-artifact proof.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 string.h error strings ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/error_strings_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/error_strings_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-error-strings-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_profile() {
    local -a definitions=("$@")
    local variant
    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$cxx_probe"
    done
}

compile_profile -D__STRICT_ANSI__
compile_profile -D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_STRERROR_R
compile_profile -D_XOPEN_SOURCE=700 -DCRABC_EXPECT_STRERROR_R
compile_profile -D_GNU_SOURCE -DCRABC_EXPECT_STRERROR_R
compile_profile -D_BSD_SOURCE -DCRABC_EXPECT_STRERROR_R

if ! "$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_STRERROR_R -I "$ROOT_DIR/include" -H -fsyntax-only \
    "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project error-string C header contract drifted"
fi
for header in string.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "C probe did not use the project <$header>"
done

for language in c cxx; do
    for variant in oracle project; do
        include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        errors="$work_dir/${variant}-${language}-strict-errors"
        if [ "$language" = c ]; then
            if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D__STRICT_ANSI__ \
                -DCRABC_REQUIRE_STRERROR_R_HIDDEN "${include_args[@]}" \
                -fsyntax-only "$c_probe" >"$errors" 2>&1; then
                fail "strerror_r is visible under strict C (${variant})"
            fi
        elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D__STRICT_ANSI__ \
            -DCRABC_REQUIRE_STRERROR_R_HIDDEN "${include_args[@]}" \
            -fsyntax-only "$cxx_probe" >"$errors" 2>&1; then
            fail "strerror_r is visible under strict C++ (${variant})"
        fi
    done
done

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-error-strings-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
        -DCRABC_EXPECT_STRERROR_R "${include_args[@]}" -c "$cxx_probe" \
        -o "$object"
    undefined="$(nm --undefined-only "$object")"
    for symbol in strerror strerror_r; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" \
            || fail "C++ probe does not retain C linkage for ${symbol} (${variant})"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*strerror'; then
        fail "C++ probe retained a mangled error-string reference (${variant})"
    fi
done

printf 'x86 pinned-musl/project C/C++ <string.h> error strings ABI: PASS\n'
