#!/usr/bin/env bash
# Native Linux/x86-64 source-only C-ABI atomic-helper evidence.
#
# This runner compiles the isolated x86 atomic module and executes its Rust
# behavior probe. It never selects crabc-libc or produces an x86 libc
# artifact; the assembly is admitted only as a prerequisite evidence slice.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
	printf 'ERROR: x86 atomic source-only probe: %s\n' "$*" >&2
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
require_tool rustup
require_tool objdump

work_dir="$(mktemp -d /tmp/crabc-x86-64-atomic.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/atomic-probe"
disassembly="$work_dir/atomic-disassembly"

cd "$ROOT_DIR"
rustup run nightly-2026-07-24 rustc --edition=2021 \
	--target x86_64-unknown-linux-musl \
	-C opt-level=2 \
	-C panic=abort \
	compat/x86_64/libc_atomic_probe.rs \
	-o "$probe"

# Disassemble the explicit no-inline probe wrappers rather than searching the
# whole executable: std may use unrelated atomics, which would not prove this
# source-only leaf lowered to the intended instructions.
objdump -d --disassemble=crabc_x86_atomic_probe_compare_exchange "$probe" >"$disassembly"
grep -Eq 'lock[[:space:]]+cmpxchg' "$disassembly" \
	|| fail "compare-exchange wrapper lacks locked cmpxchg"
if grep -Eq '__atomic_(compare_exchange|exchange|fetch_add)|__aarch64_' "$disassembly"; then
	fail "compare-exchange wrapper contains an outlined non-x86 atomic helper"
fi
objdump -d --disassemble=crabc_x86_atomic_probe_swap "$probe" >"$disassembly"
grep -Eq '(^|[[:space:]])xchg[[:space:]]' "$disassembly" \
	|| fail "swap wrapper lacks xchg"
if grep -Eq '__atomic_(compare_exchange|exchange|fetch_add)|__aarch64_' "$disassembly"; then
	fail "swap wrapper contains an outlined non-x86 atomic helper"
fi
objdump -d --disassemble=crabc_x86_atomic_probe_fetch_add "$probe" >"$disassembly"
grep -Eq 'lock[[:space:]]+xadd' "$disassembly" \
	|| fail "fetch-add wrapper lacks locked xadd"
if grep -Eq '__atomic_(compare_exchange|exchange|fetch_add)|__aarch64_' "$disassembly"; then
	fail "fetch-add wrapper contains an outlined non-x86 atomic helper"
fi
objdump -d --disassemble=crabc_x86_atomic_probe_fetch_sub "$probe" >"$disassembly"
grep -Eq 'lock[[:space:]]+xadd' "$disassembly" \
	|| fail "fetch-sub wrapper lacks the locked xadd implementation"
if grep -Eq '__atomic_(compare_exchange|exchange|fetch_add)|__aarch64_' "$disassembly"; then
	fail "fetch-sub wrapper contains an outlined non-x86 atomic helper"
fi

"$probe"
printf 'x86 atomic source-only probe: PASS\n'
