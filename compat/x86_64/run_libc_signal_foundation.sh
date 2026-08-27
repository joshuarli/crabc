#!/usr/bin/env bash
# Source-only native Linux/x86-64 musl-shaped signal-record evidence.
#
# The pinned-musl reference branch validates the public x86 record layout and
# the selected conversion rule. The candidate compiles only the private leaf;
# neither branch installs a disposition or selects crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 signal foundation source-only probe: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64
for tool in cc readelf objdump rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-signal-foundation.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
object="$work_dir/leaf.o"
reference="$work_dir/musl-signal-reference"
candidate="$work_dir/crabc-signal-candidate"
object_symbols="$work_dir/object-symbols"
object_relocations="$work_dir/object-relocations"
object_disassembly="$work_dir/object-disassembly"
object_sections="$work_dir/object-sections"
header_trace="$work_dir/header-trace"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SIGNAL_REFERENCE \
    compat/x86_64/libc_signal_foundation_probe.c -o "$reference"
"$reference"

bash "$ROOT_DIR/compat/x86_64/run_signal_header_abi.sh" >/dev/null
cc -E -H -D_GNU_SOURCE -I"$ROOT_DIR/include" \
    compat/x86_64/libc_signal_foundation_probe.c >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/signal.h" "$header_trace" \
    || fail "candidate fixture did not use the project signal header"

rustup run nightly-2026-07-24 rustc --edition=2021 \
    --target x86_64-unknown-linux-musl \
    --crate-type=lib \
    --emit=obj \
    -C relocation-model=static \
    -C code-model=small \
    -C panic=abort \
    compat/x86_64/libc_signal_foundation_probe.rs \
    -o "$object"

readelf --symbols --wide "$object" >"$object_symbols"
readelf --relocs --wide "$object" >"$object_relocations"
readelf --sections --wide "$object" >"$object_sections"
objdump -d "$object" >"$object_disassembly"

for symbol in crabc_x86_64_signal_action_pack crabc_x86_64_signal_restorer; do
    grep -Eq "[[:space:]]${symbol}$" "$object_symbols" \
        || fail "object does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*crabc_x86_64_signal_restorer$' "$object_symbols" \
    || fail "restorer is not hidden from a public dynamic surface"
if grep -Eq '[[:space:]](sigaction|signal)$' "$object_symbols"; then
    fail "object exposes a public signal symbol"
fi
if grep -Eq '__tls_get_addr|crabc_core|crabc_libc' "$object_relocations"; then
    fail "source-only signal object depends on a runtime artifact or dynamic TLS"
fi
grep -Eq '\bsyscall\b' "$object_disassembly" \
    || fail "restorer lacks x86 syscall instruction"
grep -Eq '\$0xf,\%rax|\$0x0*15,\%rax' "$object_disassembly" \
    || fail "restorer lacks rt_sigreturn syscall number 15"
grep -Fq '.note.GNU-stack' "$object_sections" \
    || fail "object lacks GNU-stack metadata"

cc -std=c11 -D_GNU_SOURCE -no-pie -I"$ROOT_DIR/include" \
    compat/x86_64/libc_signal_foundation_probe.c "$object" -o "$candidate"
"$candidate"

printf 'x86 C signal foundation source-only probe: PASS\n'
