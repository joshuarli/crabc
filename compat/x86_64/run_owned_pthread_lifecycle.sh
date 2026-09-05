#!/usr/bin/env bash
# Ordinary installed x86 pthread/C11 lifecycle consumer evidence.
#
# This one composition runner first executes the project-header consumer with
# pinned musl 1.2.6, then builds the installed owned static product and runs
# the same ordinary program through its sealed driver in ET_EXEC and static
# PIE modes. It is deliberately not a dynamic-product substitute: dynamic
# TLS/TCB construction and installed libc.so ownership stay with the general
# loader composition lane.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly PROBE="$ROOT_DIR/compat/x86_64/owned_pthread_lifecycle_consumer.c"

fail() {
    printf 'ERROR: x86 owned pthread lifecycle: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in cmp grep mkdir mktemp objdump python3 readelf realpath timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$BUILDER" ] || fail "missing installed static sysroot builder"
[ -f "$PROBE" ] || fail "missing ordinary pthread lifecycle consumer"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"
checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
    "$checkout_physical"/.work/*) ;;
    *) fail "TMPDIR physically escapes checkout .work: $tmpdir_physical" ;;
esac
ulimit -c 0

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-pthread-lifecycle.XXXXXX")"
cleanup() {
    local status=$?

    trap - EXIT
    if [ "$status" -eq 0 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 owned pthread lifecycle: retained failure evidence at %s\n' \
            "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

reference="$work_dir/musl-pthread-lifecycle"
reference_output="$work_dir/musl-output"
header_trace="$work_dir/header-trace"
sysroot="$work_dir/owned-static-sysroot"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in errno.h limits.h pthread.h sched.h threads.h sys/mman.h sys/wait.h unistd.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "consumer did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" "$PROBE" -o "$reference"
timeout 30 env -i "$reference" >"$reference_output" ||
    fail "pinned-musl lifecycle consumer failed"
[ ! -s "$reference_output" ] || fail "pinned-musl lifecycle consumer emitted output"

python3 "$BUILDER" --output "$sysroot" >"$work_dir/sysroot-build.json"

audit_receipt_and_elf() {
    local mode="$1"
    local label="$2"
    local mode_root="$3"
    local candidate="$mode_root/candidate"
    local receipt="$mode_root/link.receipt.json"
    local output="$mode_root/output"
    local file_header="$mode_root/file-header"
    local program_headers="$mode_root/program-headers"
    local dynamic="$mode_root/dynamic"
    local symbols="$mode_root/symbols"
    local relocations="$mode_root/relocations"

    python3 - "$mode" "$candidate" "$receipt" <<'PY'
import hashlib
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"owned pthread lifecycle receipt: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


mode, candidate_text, receipt_text = sys.argv[1:]
candidate = Path(candidate_text)
receipt_path = Path(receipt_text)
expected = {
    "-static": ("static-et-exec", "ET_EXEC", "crt1.o"),
    "-static-pie": ("static-pie", "ET_DYN", "rcrt1.o"),
}[mode]
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
for field, path in (
    ("output", candidate),
    ("map", receipt_path.with_suffix(".map")),
    ("trace", receipt_path.with_suffix(".trace")),
):
    record = receipt.get(field)
    if not isinstance(record, dict) or record.get("path") != path.name or record.get("sha256") != digest(path):
        fail(f"{field} receipt drifted")
PY

    readelf --file-header --wide "$candidate" >"$file_header"
    readelf --program-headers --wide "$candidate" >"$program_headers"
    readelf --dynamic --wide "$candidate" >"$dynamic" || true
    readelf --symbols --wide "$candidate" >"$symbols"
    readelf --relocs --wide "$candidate" >"$relocations"
    grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' "$file_header" ||
        fail "$label candidate is not EM_X86_64"
    case "$mode" in
        -static)
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$file_header" ||
                fail "$label candidate is not ET_EXEC"
            ;;
        -static-pie)
            grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' \
                "$file_header" || fail "$label candidate is not ET_DYN"
            awk '$1 == "PHDR" { found = 1 } END { exit !found }' "$program_headers" ||
                fail "$label candidate lacks PT_PHDR"
            ;;
    esac
    if grep -Eq 'Requesting program interpreter|INTERP' "$program_headers" ||
        grep -Eq 'NEEDED|JMPREL|PLTGOT' "$dynamic"; then
        fail "$label candidate selected dynamic runtime state"
    fi
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
        fail "$label candidate retains an unresolved symbol"
    fi
    if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT|TLSGD|TLSLD|TLSDESC|DTPMOD|DTPOFF)' \
        "$relocations" "$symbols"; then
        fail "$label candidate retains dynamic relocation or TLS form"
    fi
    if [ "$mode" = -static-pie ]; then
        if grep -Eq 'R_X86_64_GOTTPOFF|__tls_get_addr' "$relocations" "$symbols"; then
            fail "$label candidate retains unrelaxed initial TLS"
        fi
        awk '$3 ~ /^R_X86_64_/ && $3 != "R_X86_64_RELATIVE" { exit 1 }' "$relocations" ||
            fail "$label candidate retains a non-relative relocation"
    fi
    timeout 30 env -i "$candidate" >"$output" ||
        fail "$label installed lifecycle consumer failed"
    [ ! -s "$output" ] || fail "$label installed lifecycle consumer emitted output"
    cmp -s "$reference_output" "$output" ||
        fail "$label output differs from the pinned-musl lifecycle consumer"
}

run_installed_mode() {
    local mode="$1"
    local label="$2"
    local mode_root="$work_dir/installed-$label"

    mkdir "$mode_root"
    (
        cd "$mode_root"
        "$sysroot/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE \
            -fno-builtin -fno-stack-protector -c "$PROBE" -o consumer.o
        "$sysroot/bin/crabc-cc" "$mode" --link-receipt link.receipt.json \
            consumer.o -o candidate
    )
    audit_receipt_and_elf "$mode" "$label" "$mode_root"
}

run_installed_mode -static et-exec
run_installed_mode -static-pie static-pie

printf '%s\n' \
    'x86 owned pthread lifecycle: PASS (pinned musl + installed ET_EXEC/static-PIE attributes, C11, explicit/condition cancellation teardown, normal robust owner-death/recovery, detached reaping, atfork)'
