#!/usr/bin/env bash
# Native Linux/x86-64 compile-only integer-parsing C/C++ declaration slice.
#
# Pinned musl 1.2.6 is the declaration oracle. The candidate pass puts the
# project headers first, but does not link crabc-libc or promote general C
# text/locale behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 integer parsing header ABI: %s\n' "$*" >&2
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
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/integer_parse_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/integer_parse_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-integer-parse-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"

if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project C integer-parsing header contract drifted"
fi
for header in inttypes.h stdint.h stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" \
    -fsyntax-only "$cxx_probe"

printf 'x86 pinned-musl/project C/C++ integer parsing ABI: PASS\n'
