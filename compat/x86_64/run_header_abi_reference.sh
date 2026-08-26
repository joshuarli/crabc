#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl C header/ABI reference baseline.
#
# This proves the x86 SysV LP64/x87 values a future crabc public-header split
# must meet. It deliberately does not include crabc headers or select a
# crabc-libc artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 header ABI reference: %s\n' "$*" >&2
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

# The reference probe inherits the provenance and runtime proof rather than
# trusting that an ambient C compiler happened to have x86-compatible headers.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-header-abi.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/header-abi-reference"
disassembly="$work_dir/disassembly"

"$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/header_abi_probe.c" -o "$probe"

expected='ptr=8 long=8 size=8 ptrdiff=8 ld=16/16 ldc=32/16 fexcept=2/2 fenv=32/4 mxcsr=28 flags=1,4,8,16,32,63 rounds=0,1024,2048,3072 ldbl=64,16384,18,21'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 header ABI reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

command -v objdump >/dev/null 2>&1 || fail "requires objdump"
objdump -d -- "$probe" >"$disassembly"
if ! grep -Eq '[[:space:]](fldt|fstpt)[[:space:]]' "$disassembly"; then
    fail "x86 long-double reference emitted no x87 load/store instruction"
fi

printf 'x86 pinned-musl header ABI reference: PASS\n'
