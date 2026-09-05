#!/usr/bin/env bash
# Native Linux/x86-64 siginterrupt C/C++ declaration evidence.
#
# Pinned musl 1.2.6 is the source/feature-selection and C linkage oracle. This
# compile-only matrix selects no signal action, signal set, wait, or runtime.
# The x86 project header uses the same X/Open gate as musl, including positive
# X/Open-800 visibility. Keep the paired C and C++ X/Open-800 declaration
# proof here so a legacy-XSI rule from another target cannot hide this x86 API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 signal.h siginterrupt ABI: %s\n' "$*" >&2
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
    local variant

    for variant in oracle project; do
        local -a include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        if [ "$language" = c ]; then
            "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -DCRABC_EXPECT_SIGINTERRUPT \
                "$@" "${include_args[@]}" -fsyntax-only \
                "$ROOT_DIR/compat/x86_64/siginterrupt_header_abi_probe.c" ||
                fail "${variant} C ${profile} profile lost declaration"
        else
            "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
                -DCRABC_EXPECT_SIGINTERRUPT "$@" "${include_args[@]}" \
                -fsyntax-only \
                "$ROOT_DIR/compat/x86_64/siginterrupt_header_abi_probe.cpp" ||
                fail "${variant} C++ ${profile} profile lost declaration"
        fi
    done
}

reject_hidden() {
    local language="$1" profile="$2"
    shift 2
    local variant

    for variant in oracle project; do
        local -a include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        if [ "$language" = c ]; then
            if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE \
                -DCRABC_REQUIRE_SIGINTERRUPT_HIDDEN \
                -Werror=implicit-function-declaration "$@" "${include_args[@]}" \
                -fsyntax-only \
                "$ROOT_DIR/compat/x86_64/siginterrupt_header_abi_probe.c" \
                >/dev/null 2>&1; then
                fail "${variant} C ${profile} profile unexpectedly exposes declaration"
            fi
        elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
            -DCRABC_REQUIRE_SIGINTERRUPT_HIDDEN "$@" "${include_args[@]}" \
            -fsyntax-only \
            "$ROOT_DIR/compat/x86_64/siginterrupt_header_abi_probe.cpp" \
            >/dev/null 2>&1; then
            fail "${variant} C++ ${profile} profile unexpectedly exposes declaration"
        fi
    done
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-siginterrupt-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

for language in c cpp; do
    reject_hidden "$language" strict -D__STRICT_ANSI__
    reject_hidden "$language" posix -D_POSIX_C_SOURCE=200809L
    compile_visible "$language" xopen700 -D_XOPEN_SOURCE=700
    compile_visible "$language" xopen800 -D_XOPEN_SOURCE=800
    compile_visible "$language" gnu -D_GNU_SOURCE
    compile_visible "$language" bsd -D_BSD_SOURCE
    compile_visible "$language" default-source -D_DEFAULT_SOURCE
done

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_EXPECT_SIGINTERRUPT -I "$ROOT_DIR/include" -H -fsyntax-only \
    "$ROOT_DIR/compat/x86_64/siginterrupt_header_abi_probe.c" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project siginterrupt header contract drifted"
fi
for header in signal.h features.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-siginterrupt-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
        -DCRABC_EXPECT_SIGINTERRUPT "${include_args[@]}" -c \
        "$ROOT_DIR/compat/x86_64/siginterrupt_header_abi_probe.cpp" \
        -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]siginterrupt$' ||
        fail "C++ probe does not retain C linkage for siginterrupt (${variant})"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*siginterrupt'; then
        fail "C++ probe retained a mangled siginterrupt reference (${variant})"
    fi
done

printf 'x86 pinned-musl/project C/C++ <signal.h> siginterrupt ABI: PASS\n'
