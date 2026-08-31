#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <mqueue.h> mq_setattr ABI slice.
#
# Pinned musl 1.2.6 is the declaration/value oracle. The project header is
# then placed first; neither pass links or selects crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 mqueue.h mq_setattr ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/mq_setattr_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/mq_setattr_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-mq-setattr-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"
for header in mqueue.h sys/types.h sys/syscall.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -fsyntax-only \
    "$cxx_probe"

printf 'x86 pinned-musl C/C++ <mqueue.h> mq_setattr ABI: PASS\n'
