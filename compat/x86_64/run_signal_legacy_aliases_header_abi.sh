#!/usr/bin/env bash
# Native Linux/x86-64 GNU-only bsd_signal declaration and C++ linkage matrix.
#
# Musl 1.2.6 exposes bsd_signal only under _GNU_SOURCE and leaves
# __sysv_signal ABI-only. This compile-only evidence checks that exact public
# split against both the pinned oracle and project headers; it selects no C
# signal implementation.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/signal_legacy_aliases_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/signal_legacy_aliases_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 GNU bsd_signal header ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_gnu() {
    local language="$1" tree="$2" object="$3" trace="$4"
    local -a include_args=()
    [ "$tree" = project ] && include_args=(-I "$ROOT_DIR/include")

    if [ "$language" = c ]; then
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_GNU_SOURCE \
            -DCRABC_EXPECT_BSD_SIGNAL -fno-builtin "${include_args[@]}" \
            -H -c "$C_PROBE" -o "$object" >/dev/null 2>"$trace" ||
            fail "$tree c11-gnu profile lost bsd_signal"
    else
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_GNU_SOURCE \
            -DCRABC_EXPECT_BSD_SIGNAL -fno-builtin "${include_args[@]}" \
            -H -c "$CXX_PROBE" -o "$object" >/dev/null 2>"$trace" ||
            fail "$tree cxx17-gnu profile lost bsd_signal"
    fi
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
                -DCRABC_REQUIRE_BSD_SIGNAL_HIDDEN \
                -Werror=implicit-function-declaration "$@" \
                "${include_args[@]}" -fsyntax-only "$C_PROBE" \
                >"$work_dir/$tree.$profile.c.out" 2>&1; then
                fail "$tree C $profile profile unexpectedly exposes bsd_signal"
            fi
        elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
            -DCRABC_REQUIRE_BSD_SIGNAL_HIDDEN "$@" "${include_args[@]}" \
            -fsyntax-only "$CXX_PROBE" \
            >"$work_dir/$tree.$profile.cpp.out" 2>&1; then
            fail "$tree C++ $profile profile unexpectedly exposes bsd_signal"
        fi
    done
}

assert_unmangled_reference() {
    local object="$1" tree="$2" profile="$3"
    local undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]bsd_signal$' ||
        fail "$tree $profile probe does not retain unmangled bsd_signal"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*bsd_signal'; then
        fail "$tree $profile probe retained a mangled bsd_signal reference"
    fi
}

require_native_linux_x86_64
for tool in grep mktemp nm uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$C_PROBE" ] || fail "missing C bsd_signal header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ bsd_signal header ABI probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-signal-legacy-aliases-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for language in c cpp; do
    for tree in oracle project; do
        object="$work_dir/$tree.$language.gnu.o"
        trace="$work_dir/$tree.$language.gnu.trace"
        compile_gnu "$language" "$tree" "$object" "$trace"
        assert_unmangled_reference "$object" "$tree" \
            "$( [ "$language" = c ] && printf c11-gnu || printf cxx17-gnu )"
        if [ "$tree" = project ]; then
            grep -Fq "$ROOT_DIR/include/signal.h" "$trace" ||
                fail "project $language GNU probe did not use project <signal.h>"
            grep -Fq "$ROOT_DIR/include/features.h" "$trace" ||
                fail "project $language GNU probe did not use project <features.h>"
            grep -Fq "$ROOT_DIR/include/bits/alltypes.h" "$trace" ||
                fail "project $language GNU probe did not use project <bits/alltypes.h>"
        fi
    done
done

for language in c cpp; do
    reject_hidden "$language" strict -D__STRICT_ANSI__
    reject_hidden "$language" posix -D_POSIX_C_SOURCE=200809L
    reject_hidden "$language" xopen -D_XOPEN_SOURCE=700
    reject_hidden "$language" bsd -D_BSD_SOURCE
done

printf 'x86 pinned-musl/project C/C++ GNU bsd_signal header ABI: PASS (GNU visible; strict/POSIX/XSI/BSD hidden)\n'
