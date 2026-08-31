#!/usr/bin/env bash
# Native Linux/x86-64 clock_getcpuclockid C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the feature-selection, declaration, layout, and C
# linkage oracle. The project pass puts only crabc's headers first. This
# compile-only gate selects no clock implementation or runtime state.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 time.h clock_getcpuclockid ABI: %s\n' "$*" >&2
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
    local language="$1" include_mode="$2" profile="$3"
    shift 3
    local -a include_args=() compiler_args=()

    [ "$include_mode" = project ] && include_args=(-I "$ROOT_DIR/include")
    if [ "$language" = c ]; then
        compiler_args=(-std=c11)
    else
        compiler_args=(-std=c++17 -x c++ -U_GNU_SOURCE)
    fi
    "$ORACLE_CC" "${compiler_args[@]}" "${include_args[@]}" \
        -DCRABC_EXPECT_CLOCK_GETCPUCLOCKID "$@" -fsyntax-only \
        "$ROOT_DIR/compat/x86_64/clock_getcpuclockid_header_abi_probe.${language}" ||
        fail "${include_mode} ${language} ${profile} profile lost declaration"
}

reject_hidden() {
    local language="$1" include_mode="$2" profile="$3"
    shift 3
    local -a include_args=() compiler_args=()

    [ "$include_mode" = project ] && include_args=(-I "$ROOT_DIR/include")
    if [ "$language" = c ]; then
        compiler_args=(-std=c11)
    else
        compiler_args=(-std=c++17 -x c++ -U_GNU_SOURCE)
    fi
    if "$ORACLE_CC" "${compiler_args[@]}" "${include_args[@]}" "$@" \
        -fsyntax-only "$ROOT_DIR/compat/x86_64/clock_getcpuclockid_header_abi_probe.${language}" \
        >/dev/null 2>&1; then
        fail "${include_mode} ${language} ${profile} profile unexpectedly exposes declaration"
    fi
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/clock_getcpuclockid_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/clock_getcpuclockid_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-clock-getcpuclockid-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-clock-getcpuclockid-cxx.o"
candidate_cxx_object="$work_dir/candidate-clock-getcpuclockid-cxx.o"

for language in c cpp; do
    for include_mode in oracle project; do
        reject_hidden "$language" "$include_mode" default
        reject_hidden "$language" "$include_mode" strict -D__STRICT_ANSI__
        compile_visible "$language" "$include_mode" posix -D_POSIX_C_SOURCE=200809L
        compile_visible "$language" "$include_mode" xopen -D_XOPEN_SOURCE=700
        compile_visible "$language" "$include_mode" gnu -D_GNU_SOURCE
    done
done

if ! "$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" \
    -H -fsyntax-only -DCRABC_EXPECT_CLOCK_GETCPUCLOCKID "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project clock_getcpuclockid header contract drifted"
fi
for header in time.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_CLOCK_GETCPUCLOCKID -c "$cxx_probe" -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_CLOCK_GETCPUCLOCKID -I "$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]clock_getcpuclockid$' ||
        fail "C++ probe does not retain C linkage for clock_getcpuclockid"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*clock_getcpuclockid'; then
        fail "C++ probe retained a mangled clock_getcpuclockid reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <time.h> clock_getcpuclockid ABI: PASS\n'
