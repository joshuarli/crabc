#!/usr/bin/env bash
# Native Linux/x86-64 selected static long-double/complex ABI evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc math/complex: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

assert_selected_c_abi_surface() {
	local archive_path="$1" symbols_path="$2" expected_path="$3"
	local members_path="$work_dir/selected-c-abi-members"; local -a members
	mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
	[ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
	mkdir "$members_path"
	( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
	  nm -g --defined-only --format=posix "${members[@]}" ) |
		awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
		sort -u >"$symbols_path"
	[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
	grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
	if ! cmp -s "$expected_path" "$symbols_path"; then
		diff -u "$expected_path" "$symbols_path" >&2 || true
		fail "selected static C ABI export surface drifted"
	fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-math-complex.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-math-complex-reference"; candidate="$work_dir/crabc-static-math-complex-candidate"
x87_reference="$work_dir/musl-math-complex-reference-x87"; x87_candidate="$work_dir/crabc-static-math-complex-candidate-x87"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"; disassembly="$work_dir/candidate-disassembly"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_math_complex_probe.c >/dev/null 2>"$trace"
for header in complex.h float.h math.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" || fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector compat/x86_64/libc_math_complex_probe.c -o "$reference"
"$reference" || fail "pinned-musl math/complex fixture failed"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __fpclassify __fpclassifyf __fpclassifyl __signbit __signbitf \
	__signbitl creal crealf creall cimag cimagf cimagl conj conjf conjl \
	cproj cprojf cprojl; do
	grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" || fail "archive does not define $symbol"
done
# The adjacent complete math.complex slice now owns the wider complex surface.
# `sinl` is public under the separately selected math.elementary-long-double
# capability, so this foundation gate rejects only the still-unselected
# binary32/binary64 scalar providers.
for unselected in sin sinf; do
	if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
		fail "archive accidentally exports unselected ${unselected}"
	fi
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_COMPLEX_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections compat/x86_64/libc_math_complex_probe.c compat/x86_64/libc_math_complex_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"; readelf --program-headers --wide "$candidate" >"$headers"; readelf --dynamic --wide "$candidate" >"$dynamic" || true; readelf --relocs --wide "$candidate" >"$relocs"; objdump -d "$candidate" >"$disassembly"
for symbol in __fpclassify __fpclassifyf __fpclassifyl __signbit __signbitf \
	__signbitl creal crealf creall cimag cimagf cimagl conj conjf conjl \
	cproj cprojf cprojl; do
	grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then fail "candidate has unresolved symbols"; fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then fail "candidate is dynamic"; fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' "$headers" "$relocs" "$symbols" "$disassembly"; then fail "candidate retains TLS"; fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|libm' "$symbols" "$disassembly"; then fail "candidate selects an unowned math/runtime dependency"; fi
for instruction in fldt fldz fchs; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" || fail "candidate lacks ${instruction}"
done
if "$candidate"; then
	:
else
	status=$?
	fail "freestanding math/complex fixture failed with exit status ${status}"
fi
# Repeat the ABI calls under x87 expression evaluation. The reference remains
# an ordinary pinned-musl executable; only the candidate is the closed static
# archive whose dependency boundary this runner owns.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -mfpmath=387 -fno-builtin -fno-stack-protector compat/x86_64/libc_math_complex_probe.c -o "$x87_reference"
"$x87_reference" || fail "pinned-musl x87 math/complex fixture failed"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_COMPLEX_FREESTANDING -I"$ROOT_DIR/include" -mfpmath=387 -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections compat/x86_64/libc_math_complex_probe.c compat/x86_64/libc_math_complex_start.S "$archive" -o "$x87_candidate"
if "$x87_candidate"; then
	:
else
	status=$?
	fail "freestanding x87 math/complex fixture failed with exit status ${status}"
fi
printf 'x86 static libc long-double/complex projection foundation: PASS\n'
