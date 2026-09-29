#!/usr/bin/env bash
# Source-only native x86-64 C setjmp/signal-mask ABI evidence.
#
# The same C fixture runs with pinned musl 1.2.6 and with the isolated crabc
# x86 assembly object and project headers. Retained ELFs and streams permit a
# physical, byte-for-byte control-transfer and signal-mask comparison.
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
require_tool sha256sum
require_tool cmp
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

report_root="$ROOT_DIR/.work/libc-setjmp"
mkdir -p "$report_root"
work_dir="$(mktemp -d "$report_root/run.XXXXXXXX")"
# The container writes as root; retain readable evidence for the checkout user.
trap 'chmod -R a+rX "$work_dir"' EXIT
object="$work_dir/setjmp.o"
reference="$work_dir/musl-setjmp-reference"
candidate="$work_dir/crabc-setjmp-candidate"
header_trace="$work_dir/header-trace"
object_symbols="$work_dir/object-symbols"
object_relocations="$work_dir/object-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_dynamic_symbols="$work_dir/candidate-dynamic-symbols"
reference_program_headers="$work_dir/musl-program-headers"
candidate_program_headers="$work_dir/candidate-program-headers"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -O2 -fno-builtin compat/x86_64/libc_setjmp_probe.c -o "$reference"
readelf --program-headers --wide "$reference" >"$reference_program_headers"
grep -Fq '/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1' \
	"$reference_program_headers" || fail "reference ELF does not select the pinned musl loader"

cc -E -H -I"$ROOT_DIR/include" compat/x86_64/libc_setjmp_probe.c \
	>/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/setjmp.h" "$header_trace" || {
	fail "candidate fixture did not use the project setjmp header"
}
grep -Fq "$ROOT_DIR/include/bits/setjmp.h" "$header_trace" || {
	fail "candidate fixture did not use the project x86 machine-save header"
}

rustup run "$(python3 "$ROOT_DIR/scripts/rust_toolchain.py")" rustc --edition=2021 \
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

cc -no-pie -O2 -fno-builtin -I"$ROOT_DIR/include" \
	compat/x86_64/libc_setjmp_probe.c "$object" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --dyn-syms --wide "$candidate" >"$candidate_dynamic_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
for symbol in setjmp __setjmp _setjmp longjmp _longjmp sigsetjmp __sigsetjmp siglongjmp; do
	grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
		|| fail "candidate does not define ${symbol}"
done
if awk '$7 == "UND" && $8 ~ /(^|_)(sig)?(setjmp|longjmp)(@|$)/ { found = 1 } END { exit !found }' \
	"$candidate_dynamic_symbols"; then
	fail "candidate leaves a setjmp-family symbol to the ambient C runtime"
fi

if "$reference" >"$work_dir/musl.stdout" 2>"$work_dir/musl.stderr"; then
	reference_status=0
else
	reference_status=$?
fi
if "$candidate" >"$work_dir/candidate.stdout" 2>"$work_dir/candidate.stderr"; then
	candidate_status=0
else
	candidate_status=$?
fi
printf '%s\n' "$reference_status" >"$work_dir/musl.status"
printf '%s\n' "$candidate_status" >"$work_dir/candidate.status"
(
	cd "$work_dir"
	sha256sum musl-setjmp-reference crabc-setjmp-candidate setjmp.o \
		musl.stdout candidate.stdout musl.stderr candidate.stderr \
		musl.status candidate.status >sha256sum.txt
)

[ "$reference_status" -eq 0 ] || fail "pinned musl fixture failed ($reference_status); evidence: $work_dir"
[ "$candidate_status" -eq 0 ] || fail "candidate fixture failed ($candidate_status); evidence: $work_dir"
cmp "$work_dir/musl.status" "$work_dir/candidate.status" \
	|| fail "exit statuses differ; evidence: $work_dir"
cmp "$work_dir/musl.stdout" "$work_dir/candidate.stdout" \
	|| fail "stdout differs; evidence: $work_dir"
cmp "$work_dir/musl.stderr" "$work_dir/candidate.stderr" \
	|| fail "stderr differs; evidence: $work_dir"

printf 'x86 setjmp physical differential: PASS (%s)\n' "$work_dir"
