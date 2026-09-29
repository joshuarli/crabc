#!/usr/bin/env bash
# Pinned-musl differential for the private x86 scalar log/logf artifact.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly RECORD_SIZE=40
readonly SELECTED_SYMBOLS=(log logf)
readonly FENV_SIBLINGS=(feclearexcept fegetenv fegetround feraiseexcept fesetenv fesetround fetestexcept)

fail() { printf 'ERROR: x86 static libc log/logf: %s\n' "$*" >&2; exit 1; }
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
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump python3 readelf rm rustup sort wc; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_math_log_header_abi.sh" >/dev/null

evidence_dir="$ROOT_DIR/.work/libc-math-log"
mkdir -p "$evidence_dir"
work_dir="$(mktemp -d "$evidence_dir/run.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/crabc-candidate"
reference_output="$evidence_dir/reference.records"
candidate_output="$evidence_dir/candidate.records"
rm -f -- "$reference_output" "$candidate_output"
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
	compat/x86_64/libc_math_log_probe.c >/dev/null 2>"$trace"
for header in errno.h fenv.h float.h math.h stddef.h stdint.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
		fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-fno-stack-protector compat/x86_64/libc_math_log_probe.c -lm -o "$reference"
"$reference" >"$reference_output" || fail "pinned-musl log/logf fixture failed"
reference_bytes="$(wc -c < "$reference_output")"
[ "$reference_bytes" -gt 0 ] || fail "pinned-musl fixture emitted no records"
[ "$((reference_bytes % RECORD_SIZE))" -eq 0 ] ||
	fail "pinned-musl fixture emitted a partial record"
record_count="$((reference_bytes / RECORD_SIZE))"

build_source_runtime_libc "$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
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

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_LOG_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
	-Wl,--gc-sections compat/x86_64/libc_math_log_probe.c \
	compat/x86_64/libc_math_log_start.S "$archive" -o "$candidate"
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
for unselected in logl log1p log1pf log1pl log2 log2f log2l log10 log10f log10l \
	exp expf expl exp2 exp2f exp2l expm1 expm1f expm1l exp10 exp10f exp10l \
	pow powf powl fma fmaf fmal fmod fmodf fmodl remainder remainderf remainderl \
	remquo remquof remquol modf modff modfl fdim fdimf fdiml fmax fmaxf fmaxl \
	fmin fminf fminl trunc truncf truncl rint rintf rintl nearbyint nearbyintf \
	nearbyintl round roundf roundl ceil ceilf ceill floor floorf floorl sqrt sqrtf sqrtl \
	cbrt cbrtf cbrtl cabs cabsf cabsl carg cargf cargl cproj cprojf cprojl; do
	if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
		fail "candidate accidentally retains unselected ${unselected}"
	fi
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep . >/dev/null; then
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
for instruction in addsd subsd subss mulsd mulss divsd divss cvtsd2ss cvtss2sd; do
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

"$candidate" >"$candidate_output" || fail "freestanding log/logf fixture failed"
python3 - "$reference_output" "$candidate_output" <<'PY' || fail "candidate log/logf differs from pinned musl"
import struct
import sys
from pathlib import Path


def fail(index, reason, reference, candidate):
    raise SystemExit(
        f"record {index}: {reason}; "
        f"musl={tuple(hex(word) for word in reference)} "
        f"crabc={tuple(hex(word) for word in candidate)}"
    )


def is_nan(bits, is_float):
    exponent = 0x7f800000 if is_float else 0x7ff0000000000000
    fraction = 0x007fffff if is_float else 0x000fffffffffffff
    return bits & exponent == exponent and bits & fraction != 0


def check_semantics(index, record):
    input_bits, result_bits, mode_word, flags, errno = record
    request = mode_word >> 32
    is_float = bool(request & 0x80000000)
    dirty = bool(request & 0x40000000)
    requested_round = request & 0xffff
    if requested_round != mode_word & 0xffffffff:
        fail(index, "rounding direction changed", record, record)
    if errno != (119 if dirty else 77):
        fail(index, "caller errno changed", record, record)
    if dirty and flags & 0x28 != 0x28:
        fail(index, "preexisting overflow/inexact flags cleared", record, record)
    if is_float and input_bits >> 32 != 1:
        fail(index, "binary32 input tag is invalid", record, record)
    if is_float and result_bits >> 32:
        fail(index, "binary32 result has upper bits", record, record)
    input_bits &= 0xffffffff if is_float else 0xffffffffffffffff
    sign = 0x80000000 if is_float else 0x8000000000000000
    infinity = 0x7f800000 if is_float else 0x7ff0000000000000
    one = 0x3f800000 if is_float else 0x3ff0000000000000
    expected_flags = 0x28 if dirty else 0
    if input_bits & ~sign == 0:
        if result_bits != sign | infinity or flags != expected_flags | 0x04:
            fail(index, "signed zero must divide by zero to negative infinity", record, record)
    elif input_bits == one:
        if result_bits != 0 or flags != expected_flags:
            fail(index, "log(1) must be exact positive zero", record, record)
    elif input_bits == infinity:
        if result_bits != infinity or flags != expected_flags:
            fail(index, "positive infinity must be unchanged", record, record)
    elif is_nan(input_bits, is_float):
        quiet_bit = 0x00400000 if is_float else 0x0008000000000000
        expected_nan_flags = expected_flags | (0 if input_bits & quiet_bit else 0x01)
        if not is_nan(result_bits, is_float) or flags != expected_nan_flags:
            fail(index, "quiet/signaling NaN exception behavior differs", record, record)
    elif input_bits & sign:
        if not is_nan(result_bits, is_float) or flags & 0x01 == 0:
            fail(index, "negative argument must signal invalid and return NaN", record, record)


reference_bytes = Path(sys.argv[1]).read_bytes()
candidate_bytes = Path(sys.argv[2]).read_bytes()
if len(reference_bytes) != len(candidate_bytes):
    raise SystemExit(
        f"record length differs: musl={len(reference_bytes)} crabc={len(candidate_bytes)}"
    )
for index, (reference, candidate) in enumerate(zip(
    struct.iter_unpack('<5Q', reference_bytes),
    struct.iter_unpack('<5Q', candidate_bytes),
)):
    check_semantics(index, reference)
    check_semantics(index, candidate)
    if reference[0] != candidate[0] or reference[2:] != candidate[2:]:
        fail(index, "input, rounding, flags, or errno differs", reference, candidate)
    is_float = bool(reference[2] >> 63)
    reference_nan = is_nan(reference[1], is_float)
    candidate_nan = is_nan(candidate[1], is_float)
    # The C/IEEE result contract specifies a NaN class, not its sign or payload.
    # Finite and infinite bits retain the stronger pinned-musl differential.
    if reference_nan != candidate_nan or (
        not reference_nan and reference[1] != candidate[1]
    ):
        fail(index, "result differs", reference, candidate)
PY

printf 'x86 static libc log/logf: PASS (%s records)\n' "$record_count"
