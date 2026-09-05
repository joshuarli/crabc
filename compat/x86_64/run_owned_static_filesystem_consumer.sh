#!/usr/bin/env bash
# Focused ordinary installed Linux/x86-64 directory consumer.
#
# The caller supplies an already materialized owned static sysroot. This runner
# first checks the same project-header consumer with pinned musl 1.2.6, then
# compiles it through the sealed installed driver in ET_EXEC and static-PIE
# modes. It exercises the owned aggregate's inherited scandir/ftw/nftw
# providers without widening the default archive, selecting legacy temporary
# names/file handles, or claiming product completion or public x86 support.
set -euo pipefail
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH \
    COMPILER_PATH GCC_EXEC_PREFIX LD_LIBRARY_PATH LD_PRELOAD || true

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT_DIR/compat/x86_64/owned_static_filesystem_consumer.c"

fail() {
    printf 'ERROR: x86 owned static filesystem consumer: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf 'usage: %s <installed-owned-static-sysroot>\n' "$0" >&2
    exit 64
}

[ "$#" -eq 1 ] || usage
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in cmp env grep mkdir mktemp nm python3 readelf realpath rm timeout touch; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$PROBE" ] || fail "missing ordinary filesystem consumer"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"

checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
    "$checkout_physical"/.work/*) ;;
    *) fail "TMPDIR physically escapes checkout .work: $tmpdir_physical" ;;
esac

sysroot="$(realpath -e "$1")" || fail "cannot resolve installed sysroot"
case "$sysroot" in
    /*) ;;
    *) fail "installed sysroot is not absolute" ;;
esac
for required in bin/crabc-cc usr/include/dirent.h usr/include/ftw.h usr/lib/libc.a; do
    [ -f "$sysroot/$required" ] || fail "installed sysroot lacks $required"
done
[ -x "$sysroot/bin/crabc-cc" ] || fail "installed sysroot driver is not executable"

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-static-filesystem.XXXXXX")"
cleanup() {
    local status=$?

    trap - EXIT
    if [ "$status" -eq 0 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 owned static filesystem consumer: retained failure evidence at %s\n' \
            "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

fixture_root="$work_dir/directory"
reference="$work_dir/musl-filesystem-consumer"
reference_output="$work_dir/musl-output"
mkdir "$fixture_root" "$fixture_root/nested"
touch "$fixture_root/alpha" "$fixture_root/beta"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" "$PROBE" -o "$reference"
timeout 30 env -i "$reference" "$fixture_root" >"$reference_output" ||
    fail "pinned-musl filesystem consumer failed"
[ ! -s "$reference_output" ] || fail "pinned-musl filesystem consumer emitted output"

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

    python3 - "$ROOT_DIR" "$sysroot" "$mode" "$mode_root/consumer.o" \
        "$candidate" "$receipt" <<'PY'
import hashlib
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"owned filesystem receipt: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


checkout_text, sysroot_text, mode, application_text, candidate_text, receipt_text = sys.argv[1:]
checkout = Path(checkout_text).resolve()
sysroot = Path(sysroot_text).resolve()
application = Path(application_text).resolve()
candidate = Path(candidate_text).resolve()
receipt_path = Path(receipt_text).resolve()
sys.path.insert(0, str(checkout / "scripts"))
from crabc_sysroot import audit_linker_trace

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

library = sysroot / "usr" / "lib"
expected_runtime = [
    ("crt-entry", library / expected[2]),
    ("crt-prologue", library / "crti.o"),
    ("libc", library / "libc.a"),
    ("builtins", library / "libcrabc-builtins.a"),
    ("crt-epilogue", library / "crtn.o"),
]
expected_records = [
    {"role": role, "path": str(path.relative_to(sysroot)), "sha256": digest(path)}
    for role, path in expected_runtime
]
expected_records.append(
    {"role": "application", "path": str(application), "sha256": digest(application)}
)
if receipt.get("input_receipts") != expected_records:
    fail("runtime allowlist or exact application-object receipt drifted")

for field, path in (
    ("output", candidate),
    ("map", receipt_path.with_suffix(".map")),
    ("trace", receipt_path.with_suffix(".trace")),
):
    record = receipt.get(field)
    if record != {"path": path.name, "sha256": digest(path)}:
        fail(f"{field} receipt drifted")

# The exact receipt above admits only this one application object. Reuse the
# sysroot helper for the resolved linker trace, whose runtime roots remain the
# installed sysroot and whose sole external input is the same exact object.
trace_audit = audit_linker_trace(
    receipt_path.with_suffix(".trace").read_bytes(),
    sysroot,
    application_paths=(application,),
)
if trace_audit.get("status") != "passed":
    fail(f"resolved trace escapes the installed runtime allowlist: {trace_audit}")
if str(application) not in trace_audit.get("trace_paths", []):
    fail("resolved trace omitted the exact application object")
PY

    readelf --file-header --wide "$candidate" >"$file_header"
    readelf --program-headers --wide "$candidate" >"$program_headers"
    readelf --dynamic --wide "$candidate" >"$dynamic" || true
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
            ;;
    esac
    if grep -Eq 'Requesting program interpreter|INTERP' "$program_headers" ||
        grep -Eq 'NEEDED|JMPREL|PLTGOT' "$dynamic"; then
        fail "$label candidate selected dynamic runtime state"
    fi
    nm --defined-only "$candidate" >"$symbols"
    for symbol in scandir ftw nftw pthread_cancel pthread_setcancelstate pthread_testcancel; do
        grep -Eq "[[:space:]][T][[:space:]]${symbol}$" "$symbols" ||
            fail "$label installed filesystem consumer lacks ${symbol}"
    done
    timeout 30 env -i "$candidate" "$fixture_root" >"$output" ||
        fail "$label installed filesystem consumer failed"
    [ ! -s "$output" ] || fail "$label installed filesystem consumer emitted output"
    cmp -s "$reference_output" "$output" ||
        fail "$label output differs from the pinned-musl filesystem consumer"
}

run_installed_mode() {
    local mode="$1"
    local label="$2"
    local mode_root="$work_dir/installed-$label"

    mkdir "$mode_root"
    (
        cd "$mode_root"
        "$sysroot/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE -fno-builtin \
            -fno-stack-protector -c "$PROBE" -o consumer.o
        "$sysroot/bin/crabc-cc" "$mode" --link-receipt link.receipt.json \
            consumer.o -o candidate
    )
    audit_receipt_and_elf "$mode" "$label" "$mode_root"
}

run_installed_mode -static et-exec
run_installed_mode -static-pie static-pie

printf '%s\n' \
    'x86 owned static filesystem consumer: PASS (pinned musl + installed ET_EXEC/static-PIE scandir, nftw/ftw cancellation-state restoration)'
