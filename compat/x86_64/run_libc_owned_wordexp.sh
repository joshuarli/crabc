#!/usr/bin/env bash
# Pinned-musl differential and installed-link gate for owned x86 wordexp.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly PROBE="$ROOT_DIR/compat/x86_64/owned_wordexp_probe.c"
readonly SYMBOLS=(wordexp wordfree)

fail() { printf 'ERROR: x86 owned wordexp: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in cargo cmp grep mktemp nm python3 readelf realpath rustup; do
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

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-wordexp.XXXXXX")"
cleanup() {
	local status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -eq 0 ]; then
		rm -rf -- "$work_dir"
	else
		printf 'x86 owned wordexp: retained failure evidence at %s\n' "$work_dir" >&2
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

target_dir="$work_dir/cargo-target"
default_target_dir="$work_dir/default-cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
default_archive="$default_target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-static-et-exec"
reference_output="$work_dir/musl.records"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
default_symbols="$work_dir/default-archive-symbols"
sysroot="$work_dir/owned-static-sysroot"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H "$PROBE" \
	>/dev/null 2>"$trace"
for header in wordexp.h stdio.h stdlib.h string.h features.h bits/alltypes.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
		fail "fixture did not use project $header"
done

# This deliberately pins the semantic oracle to a separately linked musl
# static ET_EXEC. Pinned-musl static PIE is a known wrapper diagnostic, while
# each crabc candidate below independently proves its requested ELF mode.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
	-static -fno-pie -no-pie "$PROBE" -o "$reference"
readelf --file-header --wide "$reference" >"$work_dir/reference-file-header"
grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$work_dir/reference-file-header" ||
	fail "pinned-musl wordexp oracle is not static ET_EXEC"
env -i CRABC_WORDEXP='bar baz' "$reference" >"$reference_output" ||
	fail "pinned-musl wordexp oracle failed"

# The frozen default archive remains free of both public entries.
CARGO_TARGET_DIR="$default_target_dir" cargo rustc --locked -p crabc-libc --lib \
	--target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$default_archive" ] || fail "cargo did not emit default x86 static libc archive"
nm -A -g --defined-only "$default_archive" >"$default_symbols"
for symbol in "${SYMBOLS[@]}"; do
	if grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$default_symbols"; then
		fail "frozen default archive unexpectedly exports ${symbol}"
	fi
done

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
	--features x86-owned-static-runtime --target x86_64-unknown-linux-musl -- \
	-C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit feature-selected x86 static libc archive"
nm -A -g --defined-only "$archive" >"$archive_symbols"
for symbol in "${SYMBOLS[@]}"; do
	grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
		fail "feature archive does not provide strong crabc-owned ${symbol}"
done

audit_receipt_and_elf() {
	local mode="$1"
	local label="$2"
	local candidate="$work_dir/installed-${label}/candidate"
	local receipt="$work_dir/installed-${label}/link.receipt.json"
	local file_header="$work_dir/installed-${label}/file-header"
	local programs="$work_dir/installed-${label}/programs"
	local dynamic="$work_dir/installed-${label}/dynamic"
	local symbols="$work_dir/installed-${label}/symbols"
	local relocations="$work_dir/installed-${label}/relocations"

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
    raise SystemExit(f"owned wordexp receipt: {message}")

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
for field, path in (("output", candidate), ("map", receipt_path.with_suffix(".map")),
                    ("trace", receipt_path.with_suffix(".trace"))):
    record = receipt.get(field)
    if not isinstance(record, dict) or record.get("path") != path.name or record.get("sha256") != digest(path):
        fail(f"{field} receipt drifted")
PY
	readelf --file-header --wide "$candidate" >"$file_header"
	readelf --program-headers --wide "$candidate" >"$programs"
	readelf --dynamic --wide "$candidate" >"$dynamic" || true
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
			awk '$1 == "PHDR" { found = 1 } END { exit !found }' "$programs" ||
				fail "${label} installed candidate lacks PT_PHDR"
			;;
	esac
	if grep -Eq 'Requesting program interpreter|INTERP' "$programs" ||
		grep -Eq 'NEEDED|JMPREL|PLTGOT' "$dynamic"; then
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
	env -i CRABC_WORDEXP='bar baz' "$candidate" >"$work_dir/installed-${label}/candidate.records" ||
		fail "${label} installed candidate fixture failed"
	cmp -s "$reference_output" "$work_dir/installed-${label}/candidate.records" ||
		fail "${label} installed wordexp result stream differs from pinned musl static ET_EXEC"
}

run_installed_mode() {
	local mode="$1"
	local label="$2"
	local mode_root="$work_dir/installed-${label}"

	mkdir "$mode_root"
	(
		cd "$mode_root"
		"$sysroot/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE -fno-builtin \
			-c "$PROBE" -o probe.o
		"$sysroot/bin/crabc-cc" "$mode" --link-receipt link.receipt.json probe.o -o candidate
	)
	audit_receipt_and_elf "$mode" "$label"
}

python3 "$BUILDER" --output "$sysroot" >"$work_dir/sysroot-build.json"
run_installed_mode -static et-exec
run_installed_mode -static-pie static-pie

printf 'x86 owned wordexp: PASS (pinned static ET_EXEC oracle; installed ET_EXEC/static PIE shell, scanner, ownership, cleanup)\n'
