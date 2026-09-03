#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/project psignal and psiginfo header ABI.
#
# Pinned musl 1.2.6 exposes these historical reporting declarations in its
# POSIX-or-later block, not in strict source mode. Keep their C and C++
# spelling/linkage proof separate from the runtime differential: it must not
# accidentally select a diagnostics or general stdio contract.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 signal.h psignal ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v grep >/dev/null 2>&1 || fail "requires grep"
command -v mktemp >/dev/null 2>&1 || fail "requires mktemp"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

readonly C_PROBE="$ROOT_DIR/compat/x86_64/psignal_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/psignal_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-psignal-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_profile() {
    local -a definitions=("$@")
    local variant

    for variant in oracle project; do
        local -a include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -DCRABC_EXPECT_PSIGNAL "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$C_PROBE"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -DCRABC_EXPECT_PSIGNAL "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$CXX_PROBE"
    done
}

# psignal/psiginfo are available from every musl POSIX-or-later source
# profile. Check POSIX, X/Open, GNU, and BSD positives and strict negatives.
compile_profile -D_POSIX_C_SOURCE=200809L
compile_profile -D_XOPEN_SOURCE=700
compile_profile -D_GNU_SOURCE
compile_profile -D_BSD_SOURCE

for language in c cxx; do
    for variant in oracle project; do
        include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        errors="$work_dir/${variant}-${language}-strict-errors"
        if [ "$language" = c ]; then
            if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D__STRICT_ANSI__ \
                -DCRABC_REQUIRE_PSIGNAL_HIDDEN -Werror=implicit-function-declaration \
                "${include_args[@]}" -fsyntax-only "$C_PROBE" >"$errors" 2>&1; then
                fail "psignal/psiginfo are visible under strict C (${variant})"
            fi
        elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D__STRICT_ANSI__ \
            -DCRABC_REQUIRE_PSIGNAL_HIDDEN "${include_args[@]}" \
            -fsyntax-only "$CXX_PROBE" >"$errors" 2>&1; then
            fail "psignal/psiginfo are visible under strict C++ (${variant})"
        fi
    done
done

"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_PSIGNAL \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace"
for header in signal.h features.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-psignal-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
        -DCRABC_EXPECT_PSIGNAL \
        "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    for symbol in psignal psiginfo; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ probe does not retain C linkage for ${symbol} (${variant})"
        if printf '%s\n' "$undefined" | grep -Eq "_Z[0-9].*${symbol}"; then
            fail "C++ probe retained a mangled ${symbol} reference (${variant})"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ <signal.h> psignal ABI: PASS\n'
