#!/usr/bin/env bash
# Native Linux/x86-64 <resolv.h> selected nameserver declaration ABI proof.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. This header-only
# gate proves one caller-owned DNS wire-name span function and one caller-owned
# 16-bit wire-read function through C and C++. It selects no resolver state,
# `/etc/resolv.conf`, DNS packet I/O, socket, netdb, or general nameserver API
# behavior.
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
    for symbol in dn_skipname ns_get16; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree C++ probe does not retain C linkage for ${symbol}"
    done
    for mangled in '_Z.*dn_skipname' '_Z.*ns_get16'; do
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

c_probe="$ROOT_DIR/compat/x86_64/nameser_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/nameser_header_abi_probe.cpp"
[ -f "$c_probe" ] || fail "missing C selected-nameserver header ABI probe"
[ -f "$cxx_probe" ] || fail "missing C++ selected-nameserver header ABI probe"

work_dir="$(mktemp -d /tmp/crabc-x86-64-nameser-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/project-header-trace"
musl_cxx_object="$work_dir/musl-nameser-header-cxx.o"
project_cxx_object="$work_dir/project-nameser-header-cxx.o"

# First prove that the fixture matches pinned musl's C and C++ declarations.
"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -c "$cxx_probe" -o "$musl_cxx_object"
check_cxx_c_linkage pinned-musl "$musl_cxx_object"

# Project headers must be first and self-contained. Compile-only is
# intentional: declaration evidence does not select any C resolver runtime.
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"
for header in resolv.h arpa/nameser.h netinet/in.h stddef.h stdint.h \
    sys/socket.h sys/types.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$project_cxx_object"
check_cxx_c_linkage project "$project_cxx_object"

printf 'x86 pinned-musl/project C/C++ <resolv.h> selected nameserver ABI: PASS\n'
