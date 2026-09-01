#!/usr/bin/env bash
# Pinned-musl x87 binary80 fdiml/exp10l/pow10l differential.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-math-long-double-completion
readonly EXPECTED_ADDITIONS=(exp10l fdiml pow10l)
readonly EXPECTED_ASSEMBLY_SHA256=e6177957125604374b2d685799a30bad5aada4ecd3f6392e160e6140823ffa53
# The final executable has only this source-closed binary80 computation,
# existing fenv evidence plumbing, and its raw probe entry.  `powl`'s two
# target-owned helpers remain local and are asserted below rather than added
# to this public surface.
readonly CANDIDATE_FUNCTIONS=(
	__fesetround __fpclassifyl __signbitl _start
	crabc_x86_64_math_long_double_completion_probe
	exp10l exp2l fabsl fdiml
	feclearexcept fegetenv fegetround feraiseexcept fesetenv fesetround fetestexcept
	floorl frexpl modfl pow10l powl scalbnl
)
readonly AGGREGATE_SELECTED_FUNCTIONS=(
	exp10 exp10f exp10l
	fdim fdimf fdiml
	nearbyint nearbyintf nearbyintl
	pow10 pow10f pow10l
	rint rintf rintl
)
# This is the complete global/weak function closure after one freestanding
# program takes every selected fenv-sensitive math address. The two hidden
# Rust bit observers remain implementation-private, but retaining them here
# makes this a true defined-global ratchet rather than a public-name subset.
readonly AGGREGATE_CANDIDATE_FUNCTIONS=(
	__fesetround __fpclassifyl __signbitl
	_RNvNtNtCsht2h7vNWJAf_1c19x86_64_static_c_abi4fdim19observed_float_bits
	_RNvNtNtCsht2h7vNWJAf_1c19x86_64_static_c_abi4fdim20observed_double_bits
	_start crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe
	exp10 exp10f exp10l exp2l fabsl fdim fdimf fdiml
	feclearexcept fegetenv fegetround feraiseexcept fesetenv fetestexcept
	floorl frexpl modfl nearbyint nearbyintf nearbyintl
	pow10 pow10f pow10l powl rint rintf rintl scalbnl
)

fail() { printf 'ERROR: x86 binary80 fdiml/exp10l: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

collect_global_surface() {
	local archive_path="$1" output_path="$2" members_path="$3"
	local -a members
	mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
	[ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
	mkdir "$members_path"
	(
		cd "$members_path"
		ar x "$archive_path" "${members[@]}"
		nm -g --defined-only --format=posix "${members[@]}"
	) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
		sort -u >"$output_path"
}

collect_global_bindings() {
	local archive_path="$1" output_path="$2" members_path="$3"
	local -a members
	mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
	[ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
	mkdir "$members_path"
	(
		cd "$members_path"
		ar x "$archive_path" "${members[@]}"
		nm -g --defined-only --format=posix "${members[@]}"
	) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1, $2 }' |
		sort -u >"$output_path"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm objdump readelf rustup sha256sum sort wc python3; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_math_long_double_completion_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-math-long-double-completion.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
base_target="$work_dir/base-target"
feature_target="$work_dir/feature-target"
base_archive="$base_target/x86_64-unknown-linux-musl/debug/libc.a"
archive="$feature_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/crabc-candidate"
reference_output="$work_dir/reference.records"
candidate_output="$work_dir/candidate.records"
trace="$work_dir/header-trace"
base_surface="$work_dir/base-surface"
feature_surface="$work_dir/feature-surface"
expected_feature_surface="$work_dir/expected-feature-surface"
base_bindings="$work_dir/base-bindings"
feature_bindings="$work_dir/feature-bindings"
feature_baseline_bindings="$work_dir/feature-baseline-bindings"
expected_surface="$work_dir/expected-surface"
observed_additions="$work_dir/observed-additions"
expected_additions="$work_dir/expected-additions"
archive_symbols="$work_dir/archive-symbols"
archive_globals="$work_dir/archive-globals"
candidate_symbols="$work_dir/candidate-symbols"
candidate_functions="$work_dir/candidate-functions"
expected_candidate_functions="$work_dir/expected-candidate-functions"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"
aggregate_candidate="$work_dir/crabc-aggregate-candidate"
aggregate_symbols="$work_dir/aggregate-candidate-symbols"
aggregate_headers="$work_dir/aggregate-candidate-headers"
aggregate_dynamic="$work_dir/aggregate-candidate-dynamic"
aggregate_relocs="$work_dir/aggregate-candidate-relocations"
aggregate_disassembly="$work_dir/aggregate-candidate-disassembly"
aggregate_functions="$work_dir/aggregate-candidate-functions"
expected_aggregate_functions="$work_dir/expected-aggregate-functions"

cd "$ROOT_DIR"
assembly_digest="$(sha256sum libc/src/c_abi/x86_64/math_long_double_completion_musl_x86_64.S | awk '{ print $1 }')"
[ "$assembly_digest" = "$EXPECTED_ASSEMBLY_SHA256" ] ||
	fail "checked binary80 assembly digest drifted from the pinned generator output"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
	compat/x86_64/libc_math_long_double_completion_probe.c >/dev/null 2>"$trace"
for header in fenv.h float.h math.h stddef.h stdint.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
		fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-frounding-math -fno-stack-protector \
	compat/x86_64/libc_math_long_double_completion_probe.c -lm -o "$reference"
"$reference" >"$reference_output" || fail "pinned-musl binary80 fixture failed"
python3 "$ROOT_DIR/compat/x86_64/validate_libc_math_long_double_completion.py" "$reference_output" ||
	fail "pinned-musl record contract failed"

# The unfeatured archive remains the frozen selected-static surface.  The
# opt-in archive is allowed to add exactly this private binary80 closure.
CARGO_TARGET_DIR="$base_target" cargo rustc --locked -p crabc-libc --lib \
	--target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$base_archive" ] || fail "cargo did not emit the unfeatured x86 archive"
collect_global_surface "$base_archive" "$base_surface" "$work_dir/base-members"
collect_global_bindings "$base_archive" "$base_bindings" "$work_dir/base-binding-members"
grep -Ev '^(#|$)' "$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt" | LC_ALL=C sort -u >"$expected_surface"
if ! cmp -s "$expected_surface" "$base_surface"; then
	diff -u "$expected_surface" "$base_surface" >&2 || true
	fail "unfeatured selected-static C ABI export surface drifted"
fi

CARGO_TARGET_DIR="$feature_target" cargo rustc --locked -p crabc-libc --lib \
	--features "$FEATURE" --target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the opt-in binary80 archive"
collect_global_surface "$archive" "$feature_surface" "$work_dir/feature-members"
collect_global_bindings "$archive" "$feature_bindings" "$work_dir/feature-binding-members"
comm -13 "$base_surface" "$feature_surface" >"$observed_additions"
printf '%s\n' "${EXPECTED_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
	diff -u "$expected_additions" "$observed_additions" >&2 || true
	fail "opt-in binary80 feature changed more than its exact public closure"
fi
LC_ALL=C sort -u "$base_surface" "$expected_additions" >"$expected_feature_surface"
if ! cmp -s "$expected_feature_surface" "$feature_surface"; then
	diff -u "$expected_feature_surface" "$feature_surface" >&2 || true
	fail "opt-in binary80 feature did not preserve the complete frozen export surface"
fi
awk 'NR == FNR { baseline[$1] = 1; next } $1 in baseline { print }' \
	"$base_bindings" "$feature_bindings" >"$feature_baseline_bindings"
if ! cmp -s "$base_bindings" "$feature_baseline_bindings"; then
	diff -u "$base_bindings" "$feature_baseline_bindings" >&2 || true
	fail "opt-in binary80 feature changed a frozen baseline export binding or type"
fi
nm -A --defined-only "$archive" >"$archive_symbols"
nm -A -g --defined-only "$archive" >"$archive_globals"
grep -Eq '[[:space:]]T[[:space:]]fdiml$' "$archive_symbols" ||
	fail "archive does not provide strong crabc-owned fdiml"
grep -Eq '[[:space:]]T[[:space:]]exp10l$' "$archive_symbols" ||
	fail "archive does not provide strong crabc-owned exp10l"
grep -Eq '[[:space:]]W[[:space:]]pow10l$' "$archive_symbols" ||
	fail "archive does not preserve weak pow10l alias"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start \
	-Wl,--no-undefined -Wl,--gc-sections \
	compat/x86_64/libc_math_long_double_completion_probe.c \
	compat/x86_64/libc_math_long_double_completion_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
awk '$4 == "FUNC" && ($5 == "GLOBAL" || $5 == "WEAK") { print $8 }' \
	"$candidate_symbols" | LC_ALL=C sort -u >"$candidate_functions"
printf '%s\n' "${CANDIDATE_FUNCTIONS[@]}" | LC_ALL=C sort -u >"$expected_candidate_functions"
if ! cmp -s "$expected_candidate_functions" "$candidate_functions"; then
	diff -u "$expected_candidate_functions" "$candidate_functions" >&2 || true
	fail "candidate retained an unowned public math/runtime sibling"
fi
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in fdiml exp10l pow10l __fpclassifyl modfl exp2l powl feclearexcept fegetenv \
	fegetround fesetenv fesetround fetestexcept; do
	grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
		fail "candidate lacks required binary80 closure symbol ${symbol}"
done
exp10l_value="$(awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $8 == "exp10l" { print $2 }' "$candidate_symbols")"
pow10l_value="$(awk '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $8 == "pow10l" { print $2 }' "$candidate_symbols")"
[ -n "$exp10l_value" ] || fail "candidate does not retain strong exp10l"
[ -n "$pow10l_value" ] || fail "candidate does not retain weak pow10l"
[ "$exp10l_value" = "$pow10l_value" ] ||
	fail "candidate does not retain musl same-address exp10l/pow10l alias"
for provider in \
	crabc_x86_math_elementary_long_double_internal_polevll \
	crabc_x86_math_elementary_long_double_internal_p1evll; do
	grep -Eq "[[:space:]]FUNC[[:space:]]+LOCAL[[:space:]]+(DEFAULT|HIDDEN)[[:space:]]+[0-9]+[[:space:]]${provider}$" \
		"$candidate_symbols" || fail "candidate lacks local powl provider ${provider}"
	if grep -Eq "[[:space:]]FUNC[[:space:]]+(GLOBAL|WEAK)[[:space:]].*[[:space:]]${provider}$" \
		"$candidate_symbols"; then
		fail "candidate exposes private powl provider ${provider}"
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
if grep -Eq 'crabc_core|mimalloc|float_parse|math_compat|libm\.so|libm-' \
	"$candidate_symbols" "$disassembly"; then
	fail "candidate selects an ambient math/runtime dependency"
fi
for instruction in fldt fstpt fsubp f2xm1 fscale; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" ||
		fail "candidate lacks required x87 binary80 ${instruction} path"
done

"$candidate" >"$candidate_output" || fail "freestanding binary80 fixture failed"
python3 "$ROOT_DIR/compat/x86_64/validate_libc_math_long_double_completion.py" "$candidate_output" ||
	fail "candidate record contract failed"
if ! cmp -s "$reference_output" "$candidate_output"; then
	cmp -l "$reference_output" "$candidate_output" | sed -n '1,120p' >&2 || true
	fail "candidate binary80 record stream differs from pinned musl"
fi

# One feature-gated archive must also resolve every selected elementary/fenv
# provider together. The focused leaf runners retain the behavioral oracle;
# this aggregate only ratchets the shared static-link closure and ELF ABI.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_ELEMENTARY_FENV_SENSITIVE_AGGREGATE_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start \
	-Wl,--no-undefined -Wl,--gc-sections \
	compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_probe.c \
	compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_start.S \
	"$archive" -o "$aggregate_candidate"
readelf --symbols --wide "$aggregate_candidate" >"$aggregate_symbols"
readelf --program-headers --wide "$aggregate_candidate" >"$aggregate_headers"
readelf --dynamic --wide "$aggregate_candidate" >"$aggregate_dynamic" || true
readelf --relocs --wide "$aggregate_candidate" >"$aggregate_relocs"
objdump -d "$aggregate_candidate" >"$aggregate_disassembly"
awk '$4 == "FUNC" && ($5 == "GLOBAL" || $5 == "WEAK") { print $8 }' \
	"$aggregate_symbols" | LC_ALL=C sort -u >"$aggregate_functions"
printf '%s\n' "${AGGREGATE_CANDIDATE_FUNCTIONS[@]}" | LC_ALL=C sort -u >"$expected_aggregate_functions"
if ! cmp -s "$expected_aggregate_functions" "$aggregate_functions"; then
	diff -u "$expected_aggregate_functions" "$aggregate_functions" >&2 || true
	fail "aggregate candidate changed its exact defined-global function closure"
fi
for symbol in "${AGGREGATE_SELECTED_FUNCTIONS[@]}"; do
	grep -Fxq "$symbol" "$aggregate_functions" ||
		fail "aggregate candidate does not retain selected ${symbol}"
done
for symbol in exp10 exp10f exp10l fdim fdimf fdiml rint rintf rintl \
	nearbyint nearbyintf nearbyintl; do
	grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]${symbol}$" \
		"$aggregate_symbols" || fail "aggregate candidate does not retain strong ${symbol}"
done
for pair in 'exp10:pow10' 'exp10f:pow10f' 'exp10l:pow10l'; do
	strong="${pair%%:*}"
	weak="${pair##*:}"
	strong_value="$(awk -v symbol="$strong" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $8 == symbol { print $2 }' "$aggregate_symbols")"
	weak_value="$(awk -v symbol="$weak" '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $8 == symbol { print $2 }' "$aggregate_symbols")"
	[ -n "$strong_value" ] || fail "aggregate candidate does not retain strong ${strong}"
	[ -n "$weak_value" ] || fail "aggregate candidate does not retain weak ${weak}"
	[ "$strong_value" = "$weak_value" ] ||
		fail "aggregate candidate does not retain same-address ${strong}/${weak} alias"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$aggregate_symbols" | grep -q .; then
	fail "aggregate candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$aggregate_headers" "$aggregate_dynamic"; then
	fail "aggregate candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
	"$aggregate_headers" "$aggregate_relocs" "$aggregate_symbols" "$aggregate_disassembly"; then
	fail "aggregate candidate retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|float_parse|math_compat|libm\.so|libm-' \
	"$aggregate_symbols" "$aggregate_disassembly"; then
	fail "aggregate candidate selects an ambient math/runtime dependency"
fi
"$aggregate_candidate" || fail "freestanding all-provider aggregate fixture failed"
printf 'x86 binary80 fdiml/exp10l/pow10l: PASS (%s records)\n' \
	"$(( $(wc -c < "$candidate_output") / 42 ))"
