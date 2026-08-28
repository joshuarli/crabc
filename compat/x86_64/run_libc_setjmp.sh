#!/usr/bin/env bash
# Source-only native x86-64 C setjmp/signal-mask ABI evidence.
#
# This runner compares a focused C fixture with the pinned musl 1.2.6 oracle,
# then links that same fixture with the isolated crabc x86 assembly object and
# project header tree. It does not build the selected archive; that separate
# artifact use is bootstrap-only.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
	printf 'ERROR: x86 setjmp source-only ABI: %s\n' "$*" >&2
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
require_tool cc
require_tool readelf
require_tool rustup
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-setjmp.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
object="$work_dir/setjmp.o"
reference="$work_dir/musl-setjmp-reference"
candidate="$work_dir/crabc-setjmp-candidate"
header_trace="$work_dir/header-trace"
object_symbols="$work_dir/object-symbols"
object_relocations="$work_dir/object-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_dynamic_symbols="$work_dir/candidate-dynamic-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -fno-builtin compat/x86_64/libc_setjmp_probe.c -o "$reference"
"$reference"

cc -E -H -I"$ROOT_DIR/include" compat/x86_64/libc_setjmp_probe.c \
	>/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/setjmp.h" "$header_trace" || {
	fail "candidate fixture did not use the project setjmp header"
}
grep -Fq "$ROOT_DIR/include/bits/setjmp.h" "$header_trace" || {
	fail "candidate fixture did not use the project x86 machine-save header"
}

rustup run nightly-2026-07-24 rustc --edition=2021 \
	--target x86_64-unknown-linux-musl \
	--crate-type=lib \
	--emit=obj \
	-C relocation-model=static \
	-C code-model=small \
	-C panic=abort \
	compat/x86_64/libc_setjmp_probe.rs \
	-o "$object"

# Save ELF tables before searching them. With `pipefail`, a `grep -q` reader
# can otherwise close a pipe early and turn readelf's harmless SIGPIPE into a
# nondeterministic false negative.
readelf --symbols --wide "$object" >"$object_symbols"
readelf --relocs --wide "$object" >"$object_relocations"

symbol_address() {
	awk -v symbol="$1" '$NF == symbol { print $2; exit }' "$object_symbols"
}

for symbol in setjmp __setjmp _setjmp longjmp _longjmp sigsetjmp __sigsetjmp siglongjmp; do
	address="$(symbol_address "$symbol")"
	[ -n "$address" ] || fail "object does not define ${symbol}"
done
[ "$(symbol_address setjmp)" = "$(symbol_address __setjmp)" ] || {
	fail "setjmp and __setjmp are not direct aliases"
}
[ "$(symbol_address setjmp)" = "$(symbol_address _setjmp)" ] || {
	fail "setjmp and _setjmp are not direct aliases"
}
[ "$(symbol_address longjmp)" = "$(symbol_address _longjmp)" ] || {
	fail "longjmp and _longjmp are not direct aliases"
}
[ "$(symbol_address sigsetjmp)" = "$(symbol_address __sigsetjmp)" ] || {
	fail "sigsetjmp and __sigsetjmp are not direct aliases"
}
if grep -Eq '__tls_get_addr|crabc_libc' "$object_relocations"; then
	fail "source-only setjmp object depends on a runtime artifact"
fi

cc -no-pie -fno-builtin -I"$ROOT_DIR/include" \
	compat/x86_64/libc_setjmp_probe.c "$object" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --dyn-syms --wide "$candidate" >"$candidate_dynamic_symbols"
for symbol in setjmp __setjmp _setjmp longjmp _longjmp sigsetjmp __sigsetjmp siglongjmp; do
	grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
		|| fail "candidate does not define ${symbol}"
done
if grep -Eq '[[:space:]]UND[[:space:]].*(setjmp|longjmp)$' \
	"$candidate_dynamic_symbols"; then
	fail "candidate leaves a setjmp-family symbol to the ambient C runtime"
fi
"$candidate"

printf 'x86 setjmp source-only ABI probe: PASS\n'
