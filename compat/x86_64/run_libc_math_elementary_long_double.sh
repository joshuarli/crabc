#!/usr/bin/env bash
# Pinned-musl differential for complete x86 math.elementary-long-double.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly RECORD_SIZE=40
readonly EXPECTED_RECORDS=2764
readonly SELECTED_SYMBOLS=(
	acoshl acosl asinhl asinl atan2l atanhl atanl cbrtl ceill copysignl coshl
	cosl exp2l expl expm1l fabsl floorl fmal fmaxl fminl fmodl hypotl log10l
	log1pl log2l logl powl roundl sincosl sinhl sinl sqrtl tanhl tanl truncl
)
readonly NEW_SYMBOLS=(
	acoshl asinhl atanhl cbrtl copysignl coshl cosl fmal fmaxl fminl hypotl
	powl roundl sincosl sinhl sinl tanhl tanl
)

fail() { printf 'ERROR: x86 static libc math.elementary-long-double: %s\n' "$*" >&2; exit 1; }
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
	grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
	if ! cmp -s "$expected_path" "$symbols_path"; then
		diff -u "$expected_path" "$symbols_path" >&2 || true
		fail "selected static C ABI export surface drifted"
	fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep nm objdump readelf rustup sort wc; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_math_elementary_long_double_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-math-elementary-long-double.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/crabc-candidate"
reference_output="$work_dir/reference.records"
candidate_output="$work_dir/candidate.records"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_globals="$work_dir/archive-globals"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
	compat/x86_64/libc_math_elementary_long_double_probe.c >/dev/null 2>"$trace"
for header in fenv.h float.h math.h stddef.h stdint.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
		fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-frounding-math -fno-stack-protector \
	compat/x86_64/libc_math_elementary_long_double_probe.c -lm -o "$reference"
"$reference" >"$reference_output" || fail "pinned-musl math.elementary-long-double fixture failed"
reference_bytes="$(wc -c < "$reference_output")"
[ "$reference_bytes" -gt 0 ] || fail "pinned-musl fixture emitted no records"
[ "$((reference_bytes % RECORD_SIZE))" -eq 0 ] ||
	fail "pinned-musl fixture emitted a partial record"
record_count="$((reference_bytes / RECORD_SIZE))"
[ "$record_count" -eq "$EXPECTED_RECORDS" ] ||
	fail "pinned-musl fixture did not produce ${EXPECTED_RECORDS} complete records"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
	--target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
nm -A -g --defined-only "$archive" >"$archive_globals"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in "${SELECTED_SYMBOLS[@]}"; do
	grep -Eq "[[:space:]][TWVDBR][[:space:]]${symbol}$" "$archive_symbols" ||
		fail "archive does not define ${symbol}"
done
for helper in internal_rem_pio2l internal_sinl internal_tanl provider_floor provider_scalbn; do
	grep -Eq "[[:space:]][trdb][[:space:]]crabc_x86_math_elementary_long_double_${helper}$" \
		"$archive_symbols" || fail "archive lacks local ${helper} provider"
	if grep -Eq "[[:space:]][TWVDBR][[:space:]]crabc_x86_math_elementary_long_double_${helper}$" \
		"$archive_globals"; then
		fail "archive exposes private ${helper} provider"
	fi
done
for unselected in floor __cosl __p1evll __polevll __rem_pio2l __rem_pio2_large __sinl __tanl; do
	if grep -Fxq "$unselected" "$selected_symbols"; then
		fail "archive accidentally exports private elementary provider ${unselected}"
	fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
	-Wl,--gc-sections compat/x86_64/libc_math_elementary_long_double_probe.c \
	compat/x86_64/libc_math_elementary_long_double_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in "${SELECTED_SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
	fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
	fail "candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
	"$headers" "$relocs" "$symbols" "$disassembly"; then
	fail "candidate retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|float_parse|libm' "$symbols" "$disassembly"; then
	fail "candidate selects an unowned runtime dependency"
fi
for helper in internal_rem_pio2l internal_sinl internal_tanl provider_floor provider_scalbn; do
	grep -Fq "crabc_x86_math_elementary_long_double_${helper}" "$symbols" ||
		fail "candidate lacks local ${helper} provider"
done
for instruction in fldt fstpt faddp fmulp fsqrt fdivp; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" ||
		fail "candidate lacks selected ${instruction} path"
done

"$candidate" >"$candidate_output" || fail "freestanding math.elementary-long-double fixture failed"
if ! cmp -s "$reference_output" "$candidate_output"; then
	cmp -l "$reference_output" "$candidate_output" | sed -n '1,120p' >&2 || true
	fail "candidate math.elementary-long-double record stream differs from pinned musl"
fi

printf 'x86 static libc math.elementary-long-double: PASS (%s records)\n' "$record_count"
