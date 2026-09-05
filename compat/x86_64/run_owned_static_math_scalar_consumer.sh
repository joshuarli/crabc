#!/usr/bin/env bash
# Pinned-musl scalar-math differential, raw-closure, and installed-link gate.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly RECORD_SIZE=56
readonly EXPECTED_RECORDS=304
readonly ASSEMBLY_SHA256=958284a9c8bc67fe5048c0209a41f418778ee4518b565e3e33b3a26e0f2cb467
readonly SYMBOLS=(fma fmaf hypot hypotf log1p log1pf)
readonly FENV_SIBLINGS=(feclearexcept fegetenv fegetround fesetenv fesetround fetestexcept feraiseexcept)
readonly ROOT_SIBLINGS=(sqrt sqrtf)

fail() { printf 'ERROR: x86 owned scalar math: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp grep mkdir mktemp nm objdump python3 readelf realpath rustup sha256sum sort wc; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$BUILDER" ] || fail "missing owned-static sysroot builder"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"
checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
	"$checkout_physical"/.work/*) ;;
	*) fail "TMPDIR physically escapes checkout .work: $tmpdir_physical" ;;
esac
ulimit -c 0
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-math-scalar.XXXXXX")"
cleanup() {
	local status=$?
	trap - EXIT
	if [ "$status" -eq 0 ]; then
		rm -rf -- "$work_dir"
	else
		printf 'x86 owned scalar math: retained failure evidence at %s\n' "$work_dir" >&2
	fi
	exit "$status"
}
trap cleanup EXIT

target_dir="$work_dir/cargo-target"
default_target_dir="$work_dir/default-cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
default_archive="$default_target_dir/x86_64-unknown-linux-musl/debug/libc.a"
probe="$ROOT_DIR/compat/x86_64/owned_static_math_scalar_consumer.c"
start="$ROOT_DIR/compat/x86_64/owned_static_math_scalar_consumer_start.S"
musl_raw="$work_dir/musl-freestanding"
candidate_raw="$work_dir/crabc-freestanding"
musl_installed="$work_dir/musl-installed"
reference_raw_output="$work_dir/musl-freestanding.records"
candidate_raw_output="$work_dir/crabc-freestanding.records"
reference_installed_output="$work_dir/musl-installed.records"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
default_symbols="$work_dir/default-archive-symbols"
candidate_symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"
sysroot="$work_dir/owned-static-sysroot"
raw_members="$work_dir/raw-component-members"

archive_member_for_symbol() {
	local symbol="$1"
	nm -A --defined-only "$archive" | awk -v symbol="$symbol" '
		$0 ~ (" T " symbol "$") && !found {
			member = $1
			sub(/^.*\//, "", member)
			sub(/^[^:]*:/, "", member)
			sub(/:.*/, "", member)
			print member
			found = 1
		}
	'
}

cd "$ROOT_DIR"
assembly_digest="$(sha256sum libc/src/c_abi/x86_64/math_scalar_completion_musl_x86_64.S | awk '{ print $1 }')"
[ "$assembly_digest" = "$ASSEMBLY_SHA256" ] ||
	fail "checked scalar-math assembly digest drifted from pinned generator output"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H "$probe" \
	>/dev/null 2>"$trace"
for header in fenv.h math.h stddef.h stdint.h unistd.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" || fail "fixture did not use project $header"
done

# The installed oracle stream is the semantic reference for the sealed driver;
# the separate raw stream proves this component's source closure without CRT or
# allocator state.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-frounding-math -fno-stack-protector "$probe" -lm -o "$musl_installed"
"$musl_installed" >"$reference_installed_output" || fail "pinned-musl installed fixture failed"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_SCALAR_COMPLETION_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start \
	-Wl,--no-undefined -Wl,--gc-sections "$probe" "$start" \
	/opt/musl-1.2.6/lib/libc.a -o "$musl_raw"
"$musl_raw" >"$reference_raw_output" || fail "pinned-musl raw fixture failed"
for output in "$reference_installed_output" "$reference_raw_output"; do
	bytes="$(wc -c <"$output")"
	[ "$bytes" -eq "$((RECORD_SIZE * EXPECTED_RECORDS))" ] ||
		fail "reference emitted ${bytes} bytes, expected $((RECORD_SIZE * EXPECTED_RECORDS))"
done

# This completion belongs to the owned-static aggregate. The frozen default
# archive may retain compiler-builtins' weak fma/fmaf fallbacks, but it must
# not gain any strong crabc provider before this explicit feature is selected.
CARGO_TARGET_DIR="$default_target_dir" cargo rustc --locked -p crabc-libc --lib \
	--target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$default_archive" ] || fail "cargo did not emit default x86 static libc archive"
nm -A -g --defined-only "$default_archive" >"$default_symbols"
for symbol in "${SYMBOLS[@]}"; do
	if grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$default_symbols"; then
		fail "frozen default archive unexpectedly provides strong ${symbol}"
	fi
done

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
	--features x86-owned-static-runtime --target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit feature-selected x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
for symbol in "${SYMBOLS[@]}" "${FENV_SIBLINGS[@]}" "${ROOT_SIBLINGS[@]}"; do
	grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
		fail "feature archive does not define ${symbol}"
done
for symbol in "${SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
		fail "feature archive does not provide a strong crabc-owned ${symbol}"
done

# The aggregate archive intentionally has unrelated allocator/runtime TLS.
# Extract just the direct source closure for the freestanding purity proof;
# the installed executions below cover the actual CRT/TLS product path.
mkdir "$raw_members"
declare -A extracted_members=()
for symbol in "${SYMBOLS[@]}" "${FENV_SIBLINGS[@]}" "${ROOT_SIBLINGS[@]}"; do
	member="$(archive_member_for_symbol "$symbol")"
	[ -n "$member" ] || fail "feature archive has no member for ${symbol}"
	if [ -z "${extracted_members[$member]+present}" ]; then
		(
			cd "$raw_members"
			ar x "$archive" "$member"
		)
		extracted_members[$member]=1
	fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_SCALAR_COMPLETION_FREESTANDING \
	-I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
	-fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start \
	-Wl,--no-undefined -Wl,--gc-sections "$probe" "$start" "$raw_members"/*.o \
	-o "$candidate_raw"
readelf --symbols --wide "$candidate_raw" >"$candidate_symbols"
readelf --program-headers --wide "$candidate_raw" >"$headers"
readelf --dynamic --wide "$candidate_raw" >"$dynamic" || true
readelf --relocs --wide "$candidate_raw" >"$relocs"
objdump -d "$candidate_raw" >"$disassembly"
for symbol in "${SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]${symbol}$" \
		"$candidate_symbols" || fail "raw candidate lacks strong ${symbol}"
	if grep -Eq "[[:space:]]FUNC[[:space:]]+WEAK[[:space:]].*[[:space:]]${symbol}$" "$candidate_symbols"; then
		fail "raw candidate falls through to weak ${symbol}"
	fi
done
grep -Eq '[[:space:]]FUNC[[:space:]]+LOCAL[[:space:]]+(DEFAULT|HIDDEN)[[:space:]]+[0-9]+[[:space:]]crabc_x86_math_scalar_completion_provider_scalbn$' "$candidate_symbols" ||
	fail "raw candidate lacks local fma scalbn provider"
if grep -Eq '[[:space:]](FUNC|NOTYPE)[[:space:]]+(GLOBAL|WEAK)[[:space:]].*crabc_x86_math_scalar_completion_provider_scalbn$' "$candidate_symbols"; then
	fail "raw candidate exposes the private fma scalbn provider"
fi
if grep -Eq '[[:space:]](fldt|fstpt)([[:space:]]|$)' \
	"$ROOT_DIR/libc/src/c_abi/x86_64/math_scalar_completion_musl_x86_64.S"; then
	fail "checked scalar-math assembly retains binary80 instructions"
fi
if grep -Eq '[[:space:]](call|jmp)[[:space:]].*<(fmal|hypotl|log1pl|sqrtl)>' "$disassembly"; then
	fail "raw scalar-math path calls a binary80 provider"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
	fail "raw candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
	fail "raw candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
	"$headers" "$relocs" "$candidate_symbols" "$disassembly"; then
	fail "raw candidate retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|float_parse|math_special|math_complex|math_elementary_long_double|libm' \
	"$candidate_symbols" "$disassembly"; then
	fail "raw candidate selects an unowned math/runtime dependency"
fi
for instruction in addsd addss subsd subss mulsd mulss divsd divss sqrtsd sqrtss cvtsd2ss cvtss2sd; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" ||
		fail "raw candidate lacks scalar ${instruction} path"
done
for symbol in "${ROOT_SIBLINGS[@]}"; do
	grep -Eq "(call|jmp)[[:space:]].*<${symbol}>" "$disassembly" ||
		fail "raw candidate does not retain source-level ${symbol} sibling call"
done
if grep -Eq '[[:space:]](v[a-z0-9]+|addp[sd]|subp[sd]|mulp[sd]|divp[sd]|sqrtp[sd])([[:space:]]|$)' "$disassembly" ||
	grep -Eq 'vfmadd|vfnmadd|vfmsub|vfnmsub' "$disassembly"; then
	fail "raw candidate accidentally retains AVX, packed SIMD, or FMA"
fi
"$candidate_raw" >"$candidate_raw_output" || fail "raw candidate fixture failed"
cmp -s "$reference_raw_output" "$candidate_raw_output" || {
	cmp -l "$reference_raw_output" "$candidate_raw_output" | sed -n '1,120p' >&2 || true
	fail "raw result/fenv/rounding record stream differs from pinned musl"
}

audit_installed_mode() {
	local mode="$1"
	local label="$2"
	local mode_root="$work_dir/installed-${label}"
	local candidate="$mode_root/candidate"
	local receipt="$mode_root/link.receipt.json"
	local candidate_output="$mode_root/candidate.records"
	local file_header="$mode_root/file-header"
	local program_headers="$mode_root/program-headers"
	local installed_dynamic="$mode_root/dynamic"
	local symbols="$mode_root/symbols"
	local relocations="$mode_root/relocations"

	python3 - "$mode" "$candidate" "$receipt" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

mode, candidate_text, receipt_text = sys.argv[1:]
candidate = Path(candidate_text)
receipt_path = Path(receipt_text)
expected = {
    "-static": ("static-et-exec", "ET_EXEC", "crt1.o"),
    "-static-pie": ("static-pie", "ET_DYN", "rcrt1.o"),
}[mode]

def fail(message: str) -> None:
    raise SystemExit(f"owned scalar-math installed receipt: {message}")

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    fail(f"unreadable receipt: {error}")
if not isinstance(receipt, dict):
    fail("receipt is not an object")
if receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-sealed-static-driver-v1":
    fail("schema or format drifted")
if receipt.get("target") != "x86_64-unknown-linux-musl":
    fail("target drifted")
selected = receipt.get("mode")
if not isinstance(selected, dict) or (
    selected.get("id"), selected.get("elf_type"), selected.get("crt_object"), selected.get("interpreter")
) != (*expected, "absent"):
    fail("selected mode drifted")
records = receipt.get("input_receipts")
if not isinstance(records, list) or [record.get("role") for record in records] != [
    "crt-entry", "crt-prologue", "libc", "builtins", "crt-epilogue", "application"
]:
    fail("input receipt roles drifted")
for field, expected_path in (("output", candidate.name), ("map", receipt_path.with_suffix(".map").name),
                             ("trace", receipt_path.with_suffix(".trace").name)):
    record = receipt.get(field)
    path = candidate if field == "output" else receipt_path.with_suffix("." + field)
    if not isinstance(record, dict) or record.get("path") != expected_path or record.get("sha256") != digest(path):
        fail(f"{field} receipt drifted")
PY
	readelf --file-header --wide "$candidate" >"$file_header"
	readelf --program-headers --wide "$candidate" >"$program_headers"
	readelf --dynamic --wide "$candidate" >"$installed_dynamic" || true
	readelf --symbols --wide "$candidate" >"$symbols"
	readelf --relocs --wide "$candidate" >"$relocations"
	grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' "$file_header" ||
		fail "${label} installed candidate is not EM_X86_64"
	case "$mode" in
		-static)
			grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$file_header" ||
				fail "${label} installed candidate is not ET_EXEC"
			;;
		-static-pie)
			grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' "$file_header" ||
				fail "${label} installed candidate is not ET_DYN"
			awk '$1 == "PHDR" { found = 1 } END { exit !found }' "$program_headers" ||
				fail "${label} installed candidate lacks PT_PHDR"
			;;
	esac
	if grep -Eq 'Requesting program interpreter|INTERP' "$program_headers" ||
		grep -Eq 'NEEDED|JMPREL|PLTGOT' "$installed_dynamic"; then
		fail "${label} installed candidate selected dynamic runtime state"
	fi
	if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
		fail "${label} installed candidate has unresolved symbols"
	fi
	if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT|TLSGD|TLSLD|TLSDESC|DTPMOD|DTPOFF)' \
		"$relocations" "$symbols"; then
		fail "${label} installed candidate retains dynamic relocation or TLS form"
	fi
	if [ "$mode" = -static-pie ]; then
		if grep -Eq 'R_X86_64_GOTTPOFF|__tls_get_addr' "$relocations" "$symbols"; then
			fail "${label} installed candidate retains unrelaxed initial TLS"
		fi
		awk '$3 ~ /^R_X86_64_/ && $3 != "R_X86_64_RELATIVE" { exit 1 }' "$relocations" ||
			fail "${label} installed candidate retains a non-relative relocation"
	fi
	env -i "$candidate" >"$candidate_output" || fail "${label} installed candidate fixture failed"
	cmp -s "$reference_installed_output" "$candidate_output" || {
		cmp -l "$reference_installed_output" "$candidate_output" | sed -n '1,120p' >&2 || true
		fail "${label} installed result/fenv/rounding record stream differs from pinned musl"
	}
}

run_installed_mode() {
	local mode="$1"
	local label="$2"
	local mode_root="$work_dir/installed-${label}"

	mkdir "$mode_root"
	(
		cd "$mode_root"
		"$sysroot/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE -fno-builtin \
			-fno-stack-protector -c "$probe" -o probe.o
		"$sysroot/bin/crabc-cc" "$mode" --link-receipt link.receipt.json probe.o -o candidate
	)
	audit_installed_mode "$mode" "$label"
}

python3 "$BUILDER" --output "$sysroot" >"$work_dir/sysroot-build.json"
run_installed_mode -static et-exec
run_installed_mode -static-pie static-pie

printf 'x86 owned scalar math: PASS (%s records; raw fenv + installed link in ET_EXEC and static PIE)\n' \
	"$EXPECTED_RECORDS"
