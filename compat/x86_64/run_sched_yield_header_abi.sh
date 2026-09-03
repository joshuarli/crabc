#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <sched.h> sched_yield ABI declaration gate.
#
# Pinned musl 1.2.6 supplies the strict/POSIX/XOPEN/GNU declaration and C
# linkage oracle. The project-header branch remains compile-only; it does not
# select sched_yield runtime behavior, scheduler policy, a thread runtime, a
# CRT, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sched.h sched_yield ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_profile() {
    local profile="$1"
    local -a feature_args

    case "$profile" in
        strict)
            feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE)
            ;;
        posix)
            feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE
                -D_POSIX_C_SOURCE=200809L)
            ;;
        xopen)
            feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE
                -D_XOPEN_SOURCE=700)
            ;;
        gnu)
            feature_args=(-D_GNU_SOURCE)
            ;;
        *) fail "unknown C/C++ profile $profile" ;;
    esac

    "$ORACLE_CC" -std=c11 -fno-builtin "${feature_args[@]}" \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "${feature_args[@]}" \
        -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 -fno-builtin "${feature_args[@]}" \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "${feature_args[@]}" \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/sched_yield_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/sched_yield_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-yield-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-sched-yield-cxx.o"
candidate_cxx_object="$work_dir/candidate-sched-yield-cxx.o"

for profile in strict posix xopen gnu; do
    compile_profile "$profile"
done

if ! "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C sched_yield header contract drifted"
fi
for header in sched.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

# C++ references must retain the public C name, not merely a compatible type.
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
    -U_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
    -U_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -fno-builtin \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]sched_yield$' ||
        fail "C++ probe does not retain C linkage for sched_yield"
    if printf '%s\n' "$undefined" | grep -Eq '_Z11sched_yieldv'; then
        fail "C++ probe retained a mangled sched_yield reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sched.h> sched_yield ABI: PASS\n'
