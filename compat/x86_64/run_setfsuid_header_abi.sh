#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ setfsuid declaration gate.
#
# Pinned musl 1.2.6 exposes <sys/fsuid.h>'s one-word Linux extension without
# feature-profile gating. The project-first pass proves the same strict,
# POSIX, X/Open, and GNU C/C++ declaration and unmangled linkage only; it does
# not select a credential transition or a static archive result.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/setfsuid_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/setfsuid_header_abi_probe.cpp"

fail() { printf 'ERROR: x86 sys/fsuid.h setfsuid ABI: %s\n' "$*" >&2; exit 1; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
}

profile_args() {
    case "$1" in
        strict) printf '%s\n' '-U_GNU_SOURCE -U_POSIX_C_SOURCE -U_XOPEN_SOURCE' ;;
        posix) printf '%s\n' '-U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L' ;;
        xopen) printf '%s\n' '-U_GNU_SOURCE -D_XOPEN_SOURCE=700' ;;
        gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        *) fail "unknown feature profile $1" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-setfsuid-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for tree in oracle project; do
    include_args=()
    [ "$tree" = oracle ] || include_args=(-I "$ROOT_DIR/include")
    for profile in strict posix xopen gnu; do
        read -r -a feature_args <<<"$(profile_args "$profile")"
        "$ORACLE_CC" -std=c11 "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -fsyntax-only "$C_PROBE"
        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -fsyntax-only "$CXX_PROBE"
    done

    object="$work_dir/$tree-setfsuid-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
        "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]setfsuid$' ||
        fail "$tree C++ witness lacks unmangled setfsuid"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*setfsuid'; then
        fail "$tree C++ witness retained a mangled setfsuid reference"
    fi
done

header_trace="$work_dir/project-header-trace"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"
for header in stdint.h sys/fsuid.h sys/syscall.h bits/syscall.h sys/types.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project trace omitted <$header>"
done

printf 'x86 pinned-musl/project sys/fsuid.h setfsuid C/C++ ABI: PASS\n'
