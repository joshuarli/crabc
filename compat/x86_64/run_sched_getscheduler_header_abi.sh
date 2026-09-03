#!/usr/bin/env bash
# Native Linux/x86-64 sched_getscheduler C/C++ header ABI gate.
#
# Pinned musl 1.2.6 and the project header tree must retain the same public
# `int sched_getscheduler(pid_t)` spelling under strict, POSIX, X/Open, and
# GNU profiles. This proves declaration and C++ C-linkage only; it does not
# select scheduler implementation, policy mutation, parameters, affinity,
# lifecycle, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sched_getscheduler_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sched_getscheduler_header_abi_probe.cpp"

fail() { printf 'ERROR: x86 sched_getscheduler header ABI: %s\n' "$*" >&2; exit 1; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-getscheduler-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for tree in oracle project; do
    include_args=()
    [ "$tree" = oracle ] || include_args=(-I "$ROOT_DIR/include")
    for profile in strict posix xopen gnu; do
        case "$profile" in
            strict) feature_args=(-U_GNU_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE) ;;
            posix) feature_args=(-U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L) ;;
            xopen) feature_args=(-U_GNU_SOURCE -D_XOPEN_SOURCE=700) ;;
            gnu) feature_args=(-D_GNU_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE) ;;
        esac
        "$ORACLE_CC" -std=c11 "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -fsyntax-only "$C_PROBE"
        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -fsyntax-only "$CXX_PROBE"

        object="$work_dir/$tree-$profile-cxx.o"
        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
        undefined="$(nm --undefined-only "$object")"
        printf '%s\n' "$undefined" | grep -Eq '[[:space:]]sched_getscheduler$' ||
            fail "$tree $profile C++ witness lacks unmangled sched_getscheduler"
        if printf '%s\n' "$undefined" | grep -Eq '_Z.*sched_getscheduler'; then
            fail "$tree $profile C++ witness retained a mangled sched_getscheduler reference"
        fi
    done
done

header_trace="$work_dir/project-posix-header-trace"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -I"$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"
for header in sched.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project trace omitted $header"
done

printf 'x86 pinned-musl/project sched_getscheduler C/C++ header ABI: PASS\n'
