#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <time.h> timer_settime ABI gate.
#
# Pinned musl 1.2.6 is the declaration and linkage oracle. Strict C11/C++17
# must hide this POSIX spelling; POSIX, X/Open, and GNU profiles expose its
# exact opaque-timer, flags, and itimerspec external-C declaration. This is
# header-only evidence, not POSIX timer control, lifecycle, or time support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 time.h timer_settime ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_hidden_profile() {
    local language variant compiler include_args errors

    for language in c cxx; do
        for variant in oracle project; do
            compiler="$ORACLE_CC"
            include_args=()
            if [ "$variant" = project ]; then
                include_args=(-I "$ROOT_DIR/include")
            fi
            errors="$work_dir/${variant}-${language}-strict-hidden-errors"
            if [ "$language" = c ]; then
                if "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                    -D__STRICT_ANSI__ -DCRABC_TIMER_SETTIME_EXPECT_HIDDEN \
                    -Werror=implicit-function-declaration "${include_args[@]}" \
                    -fsyntax-only "$c_probe" >"$errors" 2>&1; then
                    fail "timer_settime is visible under strict C11 (${variant})"
                fi
            elif "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
                -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                -D__STRICT_ANSI__ -DCRABC_TIMER_SETTIME_EXPECT_HIDDEN \
                "${include_args[@]}" -fsyntax-only "$cxx_probe" \
                >"$errors" 2>&1; then
                fail "timer_settime is visible under strict C++17 (${variant})"
            fi
        done
    done
}

compile_visible_profile() {
    local profile="$1" definition="$2" language variant compiler include_args object undefined

    for language in c cxx; do
        for variant in oracle project; do
            compiler="$ORACLE_CC"
            include_args=()
            if [ "$variant" = project ]; then
                include_args=(-I "$ROOT_DIR/include")
            fi
            if [ "$language" = c ]; then
                "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                    "$definition" -Werror=implicit-function-declaration \
                    "${include_args[@]}" -fsyntax-only "$c_probe"
            else
                object="$work_dir/${variant}-${profile}-timer-settime-cxx.o"
                "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                    "$definition" "${include_args[@]}" -c "$cxx_probe" -o "$object"
                undefined="$(nm --undefined-only "$object")"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]timer_settime$' ||
                    fail "C++ probe does not retain C linkage for timer_settime (${variant}, ${profile})"
                if printf '%s\n' "$undefined" | grep -Eq '_Z.*timer_settime'; then
                    fail "C++ probe retained a mangled timer_settime reference (${variant}, ${profile})"
                fi
            fi
        done
    done
}

require_native_linux_x86_64
for tool in grep mktemp nm uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/timer_settime_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/timer_settime_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-timer-settime-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

compile_hidden_profile
compile_visible_profile posix -D_POSIX_C_SOURCE=200809L
compile_visible_profile xopen -D_XOPEN_SOURCE=700
compile_visible_profile gnu -D_GNU_SOURCE

header_trace="$work_dir/project-posix-header-trace"
if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
    -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project POSIX C timer_settime header contract drifted"
fi
for header in time.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "POSIX C probe did not use the project <$header>"
done

printf 'x86 pinned-musl/project C/C++ <time.h> timer_settime ABI: PASS\n'
