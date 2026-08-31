#!/usr/bin/env bash
# Native Linux/x86-64 GNU <sched.h> CPU-count helper declaration/linkage gate.
#
# Pinned musl 1.2.6 is the C/C++ declaration oracle. This gate proves only
# GNU visibility of __sched_cpucount plus CPU_COUNT_S/CPU_COUNT expansion and
# unmangled C linkage; it neither selects affinity, CPU topology, scheduler
# policy, timer/clock behavior, nor public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 GNU sched CPU-count header ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

expect_hidden_c() {
    if "$ORACLE_CC" -std=c11 -fno-builtin \
        -Werror=implicit-function-declaration "$@" \
        -fsyntax-only "$c_probe" >/dev/null 2>&1; then
        fail "__sched_cpucount escaped its GNU declaration profile in C"
    fi
}

expect_hidden_cxx() {
    if "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "$@" \
        -fsyntax-only "$cxx_probe" >/dev/null 2>&1; then
        fail "__sched_cpucount escaped its GNU declaration profile in C++"
    fi
}

require_native_linux_x86_64
for tool in grep mktemp nm; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/sched_cpucount_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/sched_cpucount_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-cpucount-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-sched-cpucount-cxx.o"
candidate_cxx_object="$work_dir/candidate-sched-cpucount-cxx.o"

for feature in strict posix xopen; do
    case "$feature" in
        strict) feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE) ;;
        posix) feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L) ;;
        xopen) feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D_XOPEN_SOURCE=700) ;;
    esac
    expect_hidden_c "${feature_args[@]}"
    expect_hidden_cxx "${feature_args[@]}"
    expect_hidden_c "${feature_args[@]}" -I "$ROOT_DIR/include"
    expect_hidden_cxx "${feature_args[@]}" -I "$ROOT_DIR/include"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -I "$ROOT_DIR/include" \
    -H -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
for header in sched.h sys/types.h time.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "GNU C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]__sched_cpucount$' ||
        fail "C++ probe does not retain C linkage for __sched_cpucount"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*sched_cpucount'; then
        fail "C++ probe retained a mangled __sched_cpucount reference"
    fi
done

printf 'x86 pinned-musl/project GNU C/C++ <sched.h> CPU-count ABI: PASS\n'
