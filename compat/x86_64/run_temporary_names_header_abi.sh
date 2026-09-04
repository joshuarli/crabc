#!/usr/bin/env bash
# Native Linux/x86-64 <stdio.h> temporary-name C/C++ declaration evidence.
#
# Pinned musl 1.2.6 is the feature-selection and C-linkage oracle. tmpnam and
# L_tmpnam are unconditional ISO C surface. Its legacy tempnam/P_tmpdir pair
# is visible only for GNU, BSD, or any X/Open C profile, including X/Open 800.
# The GNU C++ driver normally defines _GNU_SOURCE even in its strict language
# mode, so both C++ profiles below intentionally retain that oracle behavior.
# This compile-only gate selects neither a temporary-name implementation nor
# any file-creation policy.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/temporary_names_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/temporary_names_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 stdio.h temporary names: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_c_visible() {
    local profile="$1"
    shift
    local tree

    for tree in oracle project; do
        local -a include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -DCRABC_EXPECT_TEMPNAM \
            -fno-builtin "$@" "${include_args[@]}" -fsyntax-only "$C_PROBE" ||
            fail "$tree C $profile profile lost tempnam/P_tmpdir"
    done
}

compile_c_universal() {
    local profile="$1"
    shift
    local tree

    for tree in oracle project; do
        local -a include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -fno-builtin "$@" \
            "${include_args[@]}" -fsyntax-only "$C_PROBE" ||
            fail "$tree C $profile profile lost universal tmpnam/L_tmpnam"
    done
}

reject_c_tempnam() {
    local profile="$1"
    shift
    local tree

    for tree in oracle project; do
        local -a include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE \
            -DCRABC_REQUIRE_TEMPNAM_HIDDEN \
            -Werror=implicit-function-declaration -fno-builtin "$@" \
            "${include_args[@]}" -fsyntax-only "$C_PROBE" \
            >"$work_dir/$tree.$profile.c.out" 2>&1; then
            fail "$tree C $profile profile unexpectedly exposes tempnam/P_tmpdir"
        fi
    done
}

compile_cxx_visible() {
    local profile="$1"
    shift
    local tree

    for tree in oracle project; do
        local -a include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        "$ORACLE_CC" -std=c++17 -x c++ -DCRABC_EXPECT_TEMPNAM \
            -fno-builtin "$@" "${include_args[@]}" -fsyntax-only "$CXX_PROBE" ||
            fail "$tree C++ $profile profile lost tempnam/P_tmpdir"
    done
}

assert_unmangled_references() {
    local object="$1" tree="$2" profile="$3"
    local symbol undefined

    undefined="$(nm --undefined-only "$object")"
    for symbol in tmpnam tempnam; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree C++ $profile probe does not retain C linkage for $symbol"
        if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
            fail "$tree C++ $profile probe retained a mangled $symbol reference"
        fi
    done
}

require_native_linux_x86_64
for tool in grep mktemp nm uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$C_PROBE" ] || fail "missing temporary-name C header probe"
[ -f "$CXX_PROBE" ] || fail "missing temporary-name C++ header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-temporary-names-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_c_visible gnu -D_GNU_SOURCE
compile_c_visible bsd -D_BSD_SOURCE
compile_c_visible xopen700 -D_XOPEN_SOURCE=700
compile_c_visible xopen800 -D_XOPEN_SOURCE=800

compile_c_universal strict -D__STRICT_ANSI__
compile_c_universal posix -D_POSIX_C_SOURCE=200809L
reject_c_tempnam strict -D__STRICT_ANSI__
reject_c_tempnam posix -D_POSIX_C_SOURCE=200809L

# Do not pass -U_GNU_SOURCE here: this records the pinned GNU C++ driver's
# normal default-source behavior for both an explicit GNU and a strict mode.
compile_cxx_visible gnu -D_GNU_SOURCE
compile_cxx_visible strict -D__STRICT_ANSI__

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_XOPEN_SOURCE=800 \
    -DCRABC_EXPECT_TEMPNAM -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C X/Open-800 temporary-name header contract drifted"
fi
for header in stdio.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done

for profile in gnu strict; do
    case "$profile" in
        gnu) profile_args=(-D_GNU_SOURCE) ;;
        strict) profile_args=(-D__STRICT_ANSI__) ;;
    esac
    for tree in oracle project; do
        include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        object="$work_dir/$tree.$profile.temporary-names.cxx.o"
        "$ORACLE_CC" -std=c++17 -x c++ -DCRABC_EXPECT_TEMPNAM \
            -fno-builtin "${profile_args[@]}" "${include_args[@]}" -c \
            "$CXX_PROBE" -o "$object"
        assert_unmangled_references "$object" "$tree" "$profile"
    done
done

printf 'x86 pinned-musl/project C/C++ <stdio.h> temporary-name ABI: PASS\n'
