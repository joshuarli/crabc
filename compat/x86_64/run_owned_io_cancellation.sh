#!/usr/bin/env bash
# Ordinary installed x86 syscall cancellation and explicit FILE cleanup evidence.
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
readonly PROBE_NAMES=(owned_io_cancellation owned_descriptor_cancellation owned_socket_cancellation owned_sleep_wait_cancellation owned_open_lock_cancellation owned_semaphore_wait_cancellation owned_semaphore_cancellation owned_signal_wait_cancellation owned_entropy_cancellation)

fail() {
    printf 'ERROR: x86 owned I/O cancellation: %s\n' "$*" >&2
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
for probe_name in "${PROBE_NAMES[@]}"; do
    [ -f "$ROOT_DIR/compat/x86_64/${probe_name}_probe.c" ] || fail "missing $probe_name consumer"
done
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"
checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
    "$checkout_physical"/.work/*) ;;
    *) fail "TMPDIR physically escapes checkout .work: $tmpdir_physical" ;;
esac
ulimit -c 0

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-io-cancellation.XXXXXX")"
cleanup() {
    local status=$?

    trap - EXIT
    if [ "$status" -eq 0 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 owned I/O cancellation: retained failure evidence at %s\n' \
            "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

sysroot="$work_dir/owned-static-sysroot"
cd "$ROOT_DIR"
for probe_name in "${PROBE_NAMES[@]}"; do
    PROBE="$ROOT_DIR/compat/x86_64/${probe_name}_probe.c"
    reference="$work_dir/$probe_name-musl"
    reference_output="$work_dir/$probe_name-musl-output"
    header_trace="$work_dir/$probe_name-header-trace"
    "$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H "$PROBE" \
        >/dev/null 2>"$header_trace"
    headers=(errno.h pthread.h stdio.h unistd.h bits/alltypes.h)
    case "$probe_name" in
        owned_io_cancellation) headers+=(ucontext.h sys/wait.h sys/uio.h) ;;
        owned_open_lock_cancellation) headers+=(fcntl.h sys/stat.h sys/mman.h) ;;
        owned_semaphore_wait_cancellation) headers+=(semaphore.h) ;;
        owned_semaphore_cancellation) headers+=(semaphore.h sys/mman.h) ;;
        owned_signal_wait_cancellation) headers+=(signal.h time.h) ;;
        owned_entropy_cancellation) headers+=(sys/random.h sys/mman.h) ;;
        owned_socket_cancellation) headers+=(sys/socket.h sys/un.h sys/uio.h) ;;
        owned_sleep_wait_cancellation) headers+=(time.h threads.h sys/wait.h sys/resource.h) ;;
        owned_descriptor_cancellation) headers+=(sys/uio.h poll.h signal.h sys/select.h sys/epoll.h sys/eventfd.h sys/mman.h) ;;
    esac
    for header in "${headers[@]}"; do
        grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
            fail "$probe_name consumer did not use project $header"
    done
    "$ORACLE_CC" -std=c11 -pthread -fno-builtin \
        -fno-stack-protector -I"$ROOT_DIR/include" "$PROBE" -o "$reference"
    reference_arguments=()
    if [ "$probe_name" = owned_open_lock_cancellation ]; then reference_arguments=("$work_dir/$probe_name-state"); fi
    timeout 30 env -i "$reference" "${reference_arguments[@]}" >"$reference_output" ||
        fail "pinned-musl $probe_name consumer failed"
    grep -qx "${probe_name//_/-}-ok" "$reference_output" || fail "$probe_name oracle completion missing"
    if [ "${1:-}" = --oracle-only ]; then cat "$reference_output"; fi
done
if [ "${1:-}" = --oracle-only ]; then exit 0; fi

if [ "${1:-}" = --sysroot ]; then
    [ "$#" -eq 2 ] || fail "--sysroot requires one existing owned product"
    sysroot="$(realpath -e "$2")"
    case "$sysroot" in "$checkout_physical"/.work/*) ;; *) fail "sysroot escapes checkout .work" ;; esac
else
    [ "$#" -eq 0 ] || fail "expected no arguments, --oracle-only, or --sysroot PATH"
    python3 "$BUILDER" --output "$sysroot" >"$work_dir/sysroot-build.json"
fi

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
    raise SystemExit(f"owned I/O cancellation receipt: {message}")


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
    local -a candidate_arguments=()
    if [ "$probe_name" = owned_open_lock_cancellation ]; then candidate_arguments=("$mode_root/files"); fi
    timeout 30 env -i "$candidate" "${candidate_arguments[@]}" >"$output" ||
        fail "$label installed cancellation consumer failed"
    grep -qx "${probe_name//_/-}-ok" "$output" || fail "$label completion missing"
    cmp -s "$reference_output" "$output" ||
        fail "$label output differs from the pinned-musl cancellation consumer"
}

run_installed_mode() {
    local mode="$1"
    local label="$2"
    local mode_root="$work_dir/$probe_name-installed-$label"

    mkdir "$mode_root"
    (
        cd "$mode_root"
        "$sysroot/bin/crabc-cc" "$mode" -std=c11 \
            -fno-builtin -fno-stack-protector -c "$PROBE" -o consumer.o
        "$sysroot/bin/crabc-cc" "$mode" --link-receipt link.receipt.json \
            consumer.o -o candidate
    )
    audit_receipt_and_elf "$mode" "$label" "$mode_root"
}

for probe_name in "${PROBE_NAMES[@]}"; do
    PROBE="$ROOT_DIR/compat/x86_64/${probe_name}_probe.c"
    reference_output="$work_dir/$probe_name-musl-output"
    run_installed_mode -static et-exec
    run_installed_mode -static-pie static-pie
done

printf '%s\n' \
    'x86 owned I/O cancellation: PASS (pinned musl + installed ET_EXEC/static-PIE scalar/positioned/vector I/O, close/sync, readiness/signal/event waits, sockets, sleep/child waits, open/record-lock/msync, semaphore waits, signal waits, entropy, cancellation states, FILE locks, fork inheritance)'
