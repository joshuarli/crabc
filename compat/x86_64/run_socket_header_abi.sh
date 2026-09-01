#!/usr/bin/env bash
# Native Linux/x86-64 compile-only base socket transport header ABI slice.
#
# Pinned musl 1.2.6 is the declaration/value/layout oracle. The project
# headers are placed first for the candidate pass; neither pass links or
# selects crabc-libc. A separate tiny C executable evaluates installed
# IPv4/IPv6 address-equality/classification and GNU/BSD multicast source-filter layouts/size macros against both
# header sets, while the C/C++ probes retain the immutable in6addr_any and
# in6addr_loopback declarations and C++ data-symbol linkage. The slice excludes
# socket membership, packet I/O, socket options, and vectored/ancillary-message
# APIs.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 base socket transport header ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/socket_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/socket_header_abi_probe.cpp"
ipv6_macro_probe="$ROOT_DIR/compat/x86_64/socket_header_ipv6_macro_probe.c"
work_dir="$(mktemp -d /tmp/crabc-x86-64-socket-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
musl_ipv6_macro="$work_dir/musl-ipv6-macro"
project_ipv6_macro="$work_dir/project-ipv6-macro"
musl_cxx_object="$work_dir/musl-socket-header-cxx.o"
project_cxx_object="$work_dir/project-socket-header-cxx.o"

check_cxx_in6addr_any_linkage() {
    local tree="$1"
    local object="$2"
    local undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]in6addr_any$' ||
        fail "$tree C++ probe does not retain C linkage for in6addr_any"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*in6addr_any'; then
        fail "$tree C++ probe retained a mangled in6addr_any reference"
    fi
}

check_cxx_in6addr_loopback_linkage() {
    local tree="$1"
    local object="$2"
    local undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]in6addr_loopback$' ||
        fail "$tree C++ probe does not retain C linkage for in6addr_loopback"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*in6addr_loopback'; then
        fail "$tree C++ probe retained a mangled in6addr_loopback reference"
    fi
}

# First prove that the fixtures match the pinned musl declarations themselves.
"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -c "$cxx_probe" -o "$musl_cxx_object"
check_cxx_in6addr_any_linkage pinned-musl "$musl_cxx_object"
check_cxx_in6addr_loopback_linkage pinned-musl "$musl_cxx_object"
"$ORACLE_CC" -std=c11 "$ipv6_macro_probe" -o "$musl_ipv6_macro"
"$musl_ipv6_macro"

# `-H` makes the project-header provenance explicit. Compile-only is
# intentional: this slice makes no claim about a crabc C runtime implementation.
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/sys/socket.h" "$header_trace" || {
    fail "C probe did not use the project <sys/socket.h>"
}
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$project_cxx_object"
check_cxx_in6addr_any_linkage project "$project_cxx_object"
check_cxx_in6addr_loopback_linkage project "$project_cxx_object"
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" "$ipv6_macro_probe" \
    -o "$project_ipv6_macro"
"$project_ipv6_macro"

printf 'x86 pinned-musl C/C++ base socket transport header ABI: PASS\n'
