#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl <sys/utsname.h>/<sys/sysinfo.h> ABI check.
#
# Both probes are compile-only and are checked against pinned musl, then with
# the project include tree first. No crabc-libc object is selected or linked.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 system header ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/system_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/system_header_abi_probe.cpp"

"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

printf 'x86 pinned-musl C/C++ <sys/utsname.h>/<sys/sysinfo.h> ABI: PASS\n'
