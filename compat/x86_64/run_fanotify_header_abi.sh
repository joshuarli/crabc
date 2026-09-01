#!/usr/bin/env bash
# Native Linux/x86-64 <sys/fanotify.h> event-traversal macro ABI proof.
#
# Pinned musl 1.2.6 is the header oracle. This project-first/pinned-musl
# compile-only gate compares C/C++ syntax in seven profiles, including
# canonical strict C++17. It checks only caller-buffer record layout and
# FAN_EVENT_NEXT/FAN_EVENT_OK formation; it does not link or execute fanotify runtime calls,
# open a descriptor, or select watcher policy.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_INCLUDE=/opt/musl-1.2.6/include
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/fanotify_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/fanotify_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 fanotify traversal macro ABI proof: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_c_profile() {
    local include_root="$1"
    shift
    local -a flags=("$@")

    "$ORACLE_CC" -x c -std=c11 -nostdinc -I "$include_root" \
        -isystem "$compiler_builtin_include" -fno-builtin \
        "${flags[@]}" -fsyntax-only "$C_PROBE"
}

compile_cxx_profile() {
    local include_root="$1"
    shift
    local -a flags=("$@")

    "$ORACLE_CC" -x c++ -std=c++17 -nostdinc -nostdinc++ -I "$include_root" \
        -isystem "$compiler_builtin_include" -fno-builtin \
        "${flags[@]}" -fsyntax-only "$CXX_PROBE"
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
for tool in grep mktemp realpath uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -d "$MUSL_INCLUDE" ] || fail "missing pinned musl include tree"
[ -f "$C_PROBE" ] || fail "missing C fanotify macro probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ fanotify macro probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
compiler_builtin_include="$($ORACLE_CC -print-file-name=include)"
case "$compiler_builtin_include" in
    /*) ;;
    *) fail "oracle compiler did not report an absolute builtin include directory" ;;
esac
compiler_builtin_include="$(realpath "$compiler_builtin_include")"
[ -d "$compiler_builtin_include" ] || fail "missing compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-fanotify-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/project-header-trace"

strict_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D__STRICT_ANSI__)
posix_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L)
xopen_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D_XOPEN_SOURCE=700)
bsd_definitions=(-U_GNU_SOURCE -D_BSD_SOURCE=1)
gnu_definitions=(-D_GNU_SOURCE)
cxx_strict_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE)

for definitions_name in strict_definitions posix_definitions xopen_definitions bsd_definitions gnu_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    compile_c_profile "$MUSL_INCLUDE" "${definitions[@]}"
    compile_c_profile "$ROOT_DIR/include" "${definitions[@]}"
done

for definitions_name in gnu_definitions cxx_strict_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    compile_cxx_profile "$MUSL_INCLUDE" "${definitions[@]}"
    compile_cxx_profile "$ROOT_DIR/include" "${definitions[@]}"
done

# -H makes project-first header provenance observable while preserving a pure
# compile-only boundary: no archive, CRT, descriptor, or runtime call enters.
if ! "$ORACLE_CC" -x c -std=c11 -nostdinc -I "$ROOT_DIR/include" \
    -isystem "$compiler_builtin_include" -fno-builtin "${strict_definitions[@]}" \
    -H -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project strict C fanotify macro contract drifted"
fi
for header in sys/fanotify.h stdint.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "strict C probe did not use project <$header>"
done

printf 'x86 pinned-musl/project C/C++ <sys/fanotify.h> traversal macros: PASS (seven profiles; compile-only)\n'
