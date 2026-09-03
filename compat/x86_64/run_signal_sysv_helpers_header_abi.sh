#!/usr/bin/env bash
# Native Linux/x86-64 SysV signal-helper C/C++ declaration matrix.
#
# Pinned musl 1.2.6 is the source and declaration oracle. The project keeps
# its post-POSIX.1-2024 X/Open contract: the historical declarations are visible
# in XOPEN=700, GNU, BSD, and default-source profiles, but deliberately hidden
# in XOPEN=800 even though musl 1.2.6 still exposes them there. This check is
# header-only and does not select a signal runtime.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/signal_sysv_helpers_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/signal_sysv_helpers_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 signal.h SysV helpers: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_visible() {
    local language="$1" profile="$2"
    shift 2
    local tree

    for tree in oracle project; do
        local -a include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        if [ "$language" = c ]; then
            "$ORACLE_CC" -std=c11 -U_GNU_SOURCE \
                -DCRABC_EXPECT_SYSV_SIGNAL_HELPERS "$@" "${include_args[@]}" \
                -fsyntax-only "$C_PROBE" ||
                fail "$tree C $profile profile lost SysV helper declarations"
        else
            "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
                -DCRABC_EXPECT_SYSV_SIGNAL_HELPERS "$@" "${include_args[@]}" \
                -fsyntax-only "$CXX_PROBE" ||
                fail "$tree C++ $profile profile lost SysV helper declarations"
        fi
    done
}

reject_hidden() {
    local language="$1" profile="$2"
    shift 2
    local tree

    for tree in oracle project; do
        local -a include_args=()
        [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
        if [ "$language" = c ]; then
            if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE \
                -DCRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN \
                -Werror=implicit-function-declaration "$@" "${include_args[@]}" \
                -fsyntax-only "$C_PROBE" >"$work_dir/$tree.$profile.c.out" 2>&1; then
                fail "$tree C $profile profile unexpectedly exposes SysV helpers"
            fi
        elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
            -DCRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN "$@" "${include_args[@]}" \
            -fsyntax-only "$CXX_PROBE" >"$work_dir/$tree.$profile.cpp.out" 2>&1; then
            fail "$tree C++ $profile profile unexpectedly exposes SysV helpers"
        fi
    done
}

assert_xopen800_header_divergence() {
    local language

    for language in c cpp; do
        if [ "$language" = c ]; then
            "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_XOPEN_SOURCE=800 \
                -DCRABC_EXPECT_SYSV_SIGNAL_HELPERS -fsyntax-only "$C_PROBE" ||
                fail "oracle C X/Open-800 profile lost musl declarations"
            if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_XOPEN_SOURCE=800 \
                -DCRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN \
                -Werror=implicit-function-declaration -I "$ROOT_DIR/include" \
                -fsyntax-only "$C_PROBE" >"$work_dir/project.xopen800.c.out" 2>&1; then
                fail "project C X/Open-800 profile lost legacy-XSI hiding"
            fi
        else
            "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_XOPEN_SOURCE=800 \
                -DCRABC_EXPECT_SYSV_SIGNAL_HELPERS -fsyntax-only "$CXX_PROBE" ||
                fail "oracle C++ X/Open-800 profile lost musl declarations"
            if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_XOPEN_SOURCE=800 \
                -DCRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN -I "$ROOT_DIR/include" \
                -fsyntax-only "$CXX_PROBE" >"$work_dir/project.xopen800.cpp.out" 2>&1; then
                fail "project C++ X/Open-800 profile lost legacy-XSI hiding"
            fi
        fi
    done
}

assert_unmangled_references() {
    local object="$1" tree="$2"
    local symbol undefined

    undefined="$(nm --undefined-only "$object")"
    for symbol in sighold sigignore sigrelse sigset; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree C++ probe does not retain unmangled $symbol"
        if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
            fail "$tree C++ probe retained a mangled $symbol reference"
        fi
    done
}

require_native_linux_x86_64
for tool in grep mktemp nm uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$C_PROBE" ] || fail "missing SysV helper C header probe"
[ -f "$CXX_PROBE" ] || fail "missing SysV helper C++ header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-signal-sysv-helpers-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

for language in c cpp; do
    reject_hidden "$language" strict -D__STRICT_ANSI__
    reject_hidden "$language" posix -D_POSIX_C_SOURCE=200809L
    compile_visible "$language" xopen700 -D_XOPEN_SOURCE=700
    compile_visible "$language" gnu -D_GNU_SOURCE
    compile_visible "$language" bsd -D_BSD_SOURCE
    compile_visible "$language" default-source -D_DEFAULT_SOURCE
done
assert_xopen800_header_divergence

"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_EXPECT_SYSV_SIGNAL_HELPERS -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace" ||
    fail "project SysV signal helper C header contract drifted"
for header in signal.h features.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done

for tree in oracle project; do
    include_args=()
    [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/$tree.signal-sysv-helpers.cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
        -DCRABC_EXPECT_SYSV_SIGNAL_HELPERS "${include_args[@]}" -c \
        "$CXX_PROBE" -o "$object"
    assert_unmangled_references "$object" "$tree"
done

printf 'x86 pinned-musl/project C/C++ <signal.h> SysV helper ABI: PASS\n'
