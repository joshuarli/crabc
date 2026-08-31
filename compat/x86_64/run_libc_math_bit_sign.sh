#!/usr/bin/env bash
# Native Linux/x86-64 selected static fabs/fabsf/copysign/copysignf evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc math bit-sign: %s\n' "$*" >&2; exit 1; }
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
for tool in ar awk cargo cmp diff grep mktemp nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-math-bit-sign.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-math-bit-sign-reference"
candidate="$work_dir/crabc-static-math-bit-sign-candidate"
header_cxx_reference="$work_dir/musl-math-bit-sign-header.o"
header_cxx_candidate="$work_dir/project-math-bit-sign-header.o"
header_trace="$work_dir/header-trace"
cxx_header_trace="$work_dir/cxx-header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
	compat/x86_64/libc_math_bit_sign_probe.c >/dev/null 2>"$header_trace"
for header in fenv.h float.h math.h stdint.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
		fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
	compat/x86_64/libc_math_bit_sign_probe.c -o "$reference"
"$reference" || fail "pinned-musl math bit-sign fixture failed"

for mode in sse x87; do
	case "$mode" in
		sse) arguments=() ;;
		x87) arguments=(-mfpmath=387) ;;
	esac
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -c compat/x86_64/math_bit_sign_header_abi_probe.cpp \
		-o "$header_cxx_reference"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" \
		-c compat/x86_64/math_bit_sign_header_abi_probe.cpp -o "$header_cxx_candidate"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only \
		compat/x86_64/math_bit_sign_header_abi_probe.cpp >/dev/null 2>"$cxx_header_trace"
	for header in math.h features.h bits/alltypes.h; do
		grep -Fq "$ROOT_DIR/include/$header" "$cxx_header_trace" ||
			fail "C++ probe did not use project $header"
	done
	for object in "$header_cxx_reference" "$header_cxx_candidate"; do
		undefined="$(nm --undefined-only "$object")"
		for symbol in fabs fabsf copysign copysignf; do
			printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
				fail "C++ ${mode} probe does not retain unmangled ${symbol}"
		done
		if printf '%s\n' "$undefined" | grep -Eq '_Z.*(fabs|copysign)'; then
			fail "C++ ${mode} probe retained a mangled math-bit-sign reference"
		fi
	done
done

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
	--target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in fabs fabsf copysign copysignf feclearexcept fegetenv feraiseexcept fesetenv fesetround fetestexcept; do
	grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
		fail "archive does not define ${symbol}"
done
for symbol in fabs fabsf copysign copysignf; do
	grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
		fail "archive does not provide a strong crabc-owned ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_BIT_SIGN_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static \
	-fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector \
	-Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
	compat/x86_64/libc_math_bit_sign_probe.c compat/x86_64/libc_math_bit_sign_start.S \
	"$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in fabs fabsf copysign copysignf feclearexcept fegetenv feraiseexcept fesetenv fesetround fetestexcept; do
	grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
		fail "candidate lacks ${symbol}"
done
for symbol in fabs fabsf copysign copysignf; do
	grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]${symbol}$" \
		"$candidate_symbols" || fail "candidate does not retain strong ${symbol}"
	if grep -Eq "[[:space:]]FUNC[[:space:]]+WEAK[[:space:]].*[[:space:]]${symbol}$" \
		"$candidate_symbols"; then
		fail "candidate falls through to weak compiler-builtins ${symbol}"
	fi
done
for unselected in fabsl copysignl fdim fdimf fdiml fmax fmaxf fmaxl fmin fminf fminl \
	rint rintf rintl nearbyint nearbyintf nearbyintl sqrt sqrtf sqrtl; do
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
if grep -Eq 'crabc_core|mimalloc|sha_crypt|libm' "$candidate_symbols" "$disassembly"; then
	fail "candidate selects an unowned math/runtime dependency"
fi
for instruction in andpd andps orpd orps; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" ||
		fail "candidate lacks ${instruction}"
done
"$candidate" || fail "freestanding math bit-sign fixture failed"

printf 'x86 static libc math bit-sign: PASS\n'
