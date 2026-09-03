#!/usr/bin/env bash
# Native Linux/x86-64 GNU sched_getaffinity C/C++ header ABI gate.
#
# Pinned musl 1.2.6 and the project header tree must hide the CPU-mask API in
# strict/POSIX/X/Open profiles, then retain the same GNU-only
# `int sched_getaffinity(pid_t, size_t, cpu_set_t *)` spelling, LP64 layout,
# and C++ C linkage. This does not select CPU_* helpers, mutation, pthreads,
# or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sched_getaffinity_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sched_getaffinity_header_abi_probe.cpp"
readonly VISIBILITY_PROBE="$ROOT_DIR/compat/x86_64/sched_getaffinity_header_visibility_probe.c"

fail() { printf 'ERROR: x86 sched_getaffinity header ABI: %s\n' "$*" >&2; exit 1; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
}

profile_args() {
    case "$1" in
        strict) printf '%s\n' '-U_GNU_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE' ;;
        posix) printf '%s\n' '-U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L' ;;
        xopen) printf '%s\n' '-U_GNU_SOURCE -D_XOPEN_SOURCE=700' ;;
        *) fail "unknown feature profile $1" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-getaffinity-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for tree in oracle project; do
    include_args=()
    [ "$tree" = oracle ] || include_args=(-I "$ROOT_DIR/include")
    for profile in strict posix xopen; do
        read -r -a feature_args <<<"$(profile_args "$profile")"
        if "$ORACLE_CC" -std=c11 "${feature_args[@]}" -Werror=implicit-function-declaration \
            "${include_args[@]}" -fsyntax-only "$VISIBILITY_PROBE" >/dev/null 2>&1; then
            fail "$tree $profile unexpectedly exposes sched_getaffinity"
        fi
        if "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" \
            "${include_args[@]}" -fsyntax-only "$VISIBILITY_PROBE" >/dev/null 2>&1; then
            fail "$tree $profile C++ unexpectedly exposes sched_getaffinity"
        fi
    done

    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin \
        "${include_args[@]}" -fsyntax-only "$C_PROBE"
    "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
        "${include_args[@]}" -fsyntax-only "$CXX_PROBE"

    object="$work_dir/$tree-gnu-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
        "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]sched_getaffinity$' ||
        fail "$tree GNU C++ witness lacks unmangled sched_getaffinity"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*sched_getaffinity'; then
        fail "$tree GNU C++ witness retained a mangled sched_getaffinity reference"
    fi
done

header_trace="$work_dir/project-gnu-header-trace"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -H -fsyntax-only \
    "$C_PROBE" >/dev/null 2>"$header_trace"
for header in sched.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project trace omitted $header"
done

printf 'x86 pinned-musl/project sched_getaffinity GNU C/C++ header ABI: PASS\n'
