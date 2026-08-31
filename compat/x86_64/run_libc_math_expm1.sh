#!/usr/bin/env bash
# Pinned-musl differential for the private x86 scalar expm1/expm1f artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly RECORD_SIZE=32
readonly EXPECTED_RECORDS=248
readonly SELECTED_SYMBOLS=(expm1 expm1f)
readonly FENV_SIBLINGS=(feclearexcept fegetenv fegetround fesetenv fesetround fetestexcept)

fail() { printf 'ERROR: x86 static libc expm1/expm1f: %s\n' "$*" >&2; exit 1; }
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
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort wc; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_math_expm1_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-math-expm1.XXXXXX)"
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
candidate_symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
	compat/x86_64/libc_math_expm1_probe.c >/dev/null 2>"$trace"
for header in fenv.h float.h math.h stddef.h stdint.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
		fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-fno-stack-protector compat/x86_64/libc_math_expm1_probe.c -lm -o "$reference"
"$reference" >"$reference_output" || fail "pinned-musl expm1/expm1f fixture failed"
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
for symbol in "${SELECTED_SYMBOLS[@]}" "${FENV_SIBLINGS[@]}"; do
	grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
		fail "archive does not define ${symbol}"
done
for symbol in "${SELECTED_SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
		fail "archive does not provide a strong crabc-owned ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_EXPM1_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
	-Wl,--gc-sections compat/x86_64/libc_math_expm1_probe.c \
	compat/x86_64/libc_math_expm1_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in "${SELECTED_SYMBOLS[@]}" "${FENV_SIBLINGS[@]}"; do
	grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
		fail "candidate lacks ${symbol}"
done
for symbol in "${SELECTED_SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]${symbol}$" \
		"$candidate_symbols" || fail "candidate does not retain strong ${symbol}"
	if grep -Eq "[[:space:]]FUNC[[:space:]]+WEAK[[:space:]].*[[:space:]]${symbol}$" \
		"$candidate_symbols"; then
		fail "candidate falls through to weak compiler-builtins ${symbol}"
	fi
done
for unselected in expm1l exp expf expl exp2 exp2f exp2l exp10 exp10f exp10l \
	log logf logl log1p log1pf log1pl pow powf powl fma fmaf fmal fmod fmodf fmodl \
	remainder remainderf remainderl remquo remquof remquol modf modff modfl \
	fdim fdimf fdiml fmax fmaxf fmaxl fmin fminf fminl trunc truncf truncl \
	rint rintf rintl nearbyint nearbyintf nearbyintl round roundf roundl \
	ceil ceilf ceill floor floorf floorl sqrt sqrtf sqrtl cbrt cbrtf cbrtl \
	cabs cabsf cabsl carg cargf cargl cproj cprojf cprojl; do
	if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
		fail "candidate accidentally retains unselected ${unselected}"
	fi
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
	fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
	fail "candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
	"$headers" "$relocs" "$candidate_symbols" "$disassembly"; then
	fail "candidate retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|float_parse|math_special|math_complex|math_elementary_long_double|libm' \
	"$candidate_symbols" "$disassembly"; then
	fail "candidate selects an unowned math/runtime dependency"
fi
for instruction in addsd addss subsd subss mulsd mulss divsd divss cvtsd2ss; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" ||
		fail "candidate lacks scalar ${instruction} path"
done
if grep -Eq '[[:space:]](fldt|fstpt)([[:space:]]|$)' "$disassembly"; then
	fail "candidate accidentally retains binary80 instructions"
fi
if grep -Eq '[[:space:]](v[a-z0-9]+|addp[sd]|subp[sd]|mulp[sd]|divp[sd]|sqrtp[sd])([[:space:]]|$)' "$disassembly"; then
	fail "candidate accidentally retains AVX or packed-SIMD math"
fi
if grep -Eq 'vfmadd|vfnmadd|vfmsub|vfnmsub' "$disassembly"; then
	fail "candidate accidentally retains an FMA ISA instruction"
fi

"$candidate" >"$candidate_output" || fail "freestanding expm1/expm1f fixture failed"
if ! cmp -s "$reference_output" "$candidate_output"; then
	cmp -l "$reference_output" "$candidate_output" | sed -n '1,120p' >&2 || true
	fail "candidate expm1/expm1f record stream differs from pinned musl"
fi

printf 'x86 static libc expm1/expm1f: PASS (%s records)\n' "$record_count"
