#!/usr/bin/env bash
# Native Linux/x86-64 <resolv.h> selected nameserver declaration ABI proof.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. This header-only
# gate proves one caller-owned DNS wire-name span function, one caller-owned
# DNS wire-name expansion function, one immutable nameserver flag-accessor
# data object, one caller-owned 16-bit wire-read function, one caller-owned
# 32-bit wire-read function, caller-owned 16/32-bit wire-write functions, and
# one resource-record span function, exact unconditional DNS record-
# classification macros, and exact DNS bitmap helpers through C and C++. It
# selects no resolver state or `/etc/resolv.conf`.
# DNS packet I/O, socket, netdb, and general nameserver API behavior stay out.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 resolv dn_skipname header ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

check_cxx_c_linkage() {
    local tree="$1"
    local object="$2"
    local symbol mangled undefined

    undefined="$(nm --undefined-only "$object")"
    for symbol in dn_skipname dn_expand _ns_flagdata ns_get16 ns_get32 ns_put16 ns_put32 ns_skiprr; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree C++ probe does not retain C linkage for ${symbol}"
    done
    for mangled in '_Z.*dn_skipname' '_Z.*dn_expand' '_Z.*_ns_flagdata' '_Z.*ns_get16' '_Z.*ns_get32' '_Z.*ns_put16' '_Z.*ns_put32' '_Z.*ns_skiprr'; do
        if printf '%s\n' "$undefined" | grep -Eq "$mangled"; then
            fail "$tree C++ probe retained a mangled selected-nameserver reference"
        fi
    done
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
for tool in grep mktemp nm uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

readonly C_PROBE="$ROOT_DIR/compat/x86_64/nameser_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/nameser_header_abi_probe.cpp"
[ -f "$C_PROBE" ] || fail "missing C selected-nameserver header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ selected-nameserver header ABI probe"

work_dir="$(mktemp -d /tmp/crabc-x86-64-nameser-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/project-header-trace"
compile_profile() {
    local name="$1"
    shift
    local -a flags=("$@")
    local musl_c="$work_dir/musl-${name}-c"
    local project_c="$work_dir/project-${name}-c"

    "$ORACLE_CC" -std=c11 "${flags[@]}" -fsyntax-only "$C_PROBE"
    "$ORACLE_CC" -std=c11 "${flags[@]}" \
        -DCRABC_NAMESER_RECORD_MACRO_RUNTIME "$C_PROBE" -o "$musl_c"
    "$musl_c"
    "$ORACLE_CC" -std=c11 "${flags[@]}" -I "$ROOT_DIR/include" \
        -fsyntax-only "$C_PROBE"
    "$ORACLE_CC" -std=c11 "${flags[@]}" -I "$ROOT_DIR/include" \
        -DCRABC_NAMESER_RECORD_MACRO_RUNTIME "$C_PROBE" -o "$project_c"
    "$project_c"
}

compile_cxx_profile() {
    local name="$1"
    shift
    local -a flags=("$@")
    local musl_cxx_object="$work_dir/musl-${name}-cxx.o"
    local project_cxx_object="$work_dir/project-${name}-cxx.o"

    "$ORACLE_CC" -std=c++17 -x c++ "${flags[@]}" -c "$CXX_PROBE" \
        -o "$musl_cxx_object"
    check_cxx_c_linkage pinned-musl "$musl_cxx_object"
    "$ORACLE_CC" -std=c++17 -x c++ "${flags[@]}" -I "$ROOT_DIR/include" \
        -c "$CXX_PROBE" -o "$project_cxx_object"
    check_cxx_c_linkage project "$project_cxx_object"
}

# These exact `ns_t_qt_p`/`ns_t_mrr_p`/`ns_t_rr_p`/`ns_t_udp_p`/`ns_t_xfr_p`
# record-classification macros and `NS_NXT_BIT_SET`/`NS_NXT_BIT_CLEAR`/
# `NS_NXT_BIT_ISSET` bitmap helpers are unconditional. Every fixed C profile
# executes the exact bitmap mutation behavior; GNU and no-define C++17 each
# check the C++ spelling and unmangled C declarations without selecting any
# resolver runtime.
compile_profile strict -U_GNU_SOURCE -U_BSD_SOURCE -D__STRICT_ANSI__
compile_profile posix -U_GNU_SOURCE -U_BSD_SOURCE -D_POSIX_C_SOURCE=200809L
compile_profile xopen -U_GNU_SOURCE -U_BSD_SOURCE -D_XOPEN_SOURCE=700
compile_profile gnu -U_BSD_SOURCE -D_GNU_SOURCE
compile_profile bsd -U_GNU_SOURCE -D_BSD_SOURCE
compile_cxx_profile gnu -U_BSD_SOURCE -D_GNU_SOURCE
compile_cxx_profile cxx17-strict -U_GNU_SOURCE -U_BSD_SOURCE

# Project headers must be first and self-contained. The runtime checks above
# exercise only header macros; no crabc resolver archive or state is linked.
"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -D__STRICT_ANSI__ \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace"
for header in resolv.h arpa/nameser.h netinet/in.h stddef.h stdint.h \
    sys/socket.h sys/types.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done

printf 'x86 pinned-musl/project C/C++ <resolv.h> selected nameserver ABI: PASS\n'
