#!/usr/bin/env bash
# Private installed Linux/x86-64 static sysroot and pthread/TLS consumer gate.
#
# Two clean builds must produce byte-identical regular-file trees. The actual
# consumer setup first proves header isolation, then each independent TLS,
# allocator, POSIX, and stdio job compiles, links, and executes through the
# installed sealed driver in both ET_EXEC and static-PIE modes. It also packs
# and safely extracts the regular-file tree before running the same matrix.
# This remains a narrow non-promoting product slice: no loader, libc.so,
# dynamic mode, family completion, x86 promotion, or public-support claim.
set -euo pipefail
# The stack-protector negative child deliberately faults; do not leave cores
# in the checkout or make parallel test runs compete for a core filename.
ulimit -c 0
export LC_ALL=C
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH \
    COMPILER_PATH GCC_EXEC_PREFIX LD_LIBRARY_PATH LD_PRELOAD || true

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly PACKAGE="$ROOT_DIR/compat/x86_64/owned_static_sysroot_package.py"
readonly CONSUMER_MATRIX="$ROOT_DIR/compat/x86_64/owned_static_consumer_matrix.py"
readonly CONSUMER_MATRIX_DEFAULT_WORKERS=4
readonly CONSUMER_MATRIX_MAX_WORKERS=8
readonly CONSUMER_MATRIX_TIMEOUT_SECONDS=300
readonly ELF64_PROGRAM_HEADER_SIZE=56
readonly ELF64_PROGRAM_HEADER_COUNT_OFFSET=56
readonly ELF64_PROGRAM_HEADER_OFFSET=32
readonly ELF64_P_FILESZ_OFFSET=32

# Use the producer's checked checkout-state boundary for compiler scratch and
# test fixtures too, even when called directly inside the pinned container.
# The dispatcher still binds legacy /tmp spellings for older runners.
TMPDIR="$(python3 -B - "$ROOT_DIR" <<'PY'
import sys

sys.path.insert(0, sys.argv[1] + "/scripts")
from build_x86_64_owned_sysroot import deterministic_environment

print(deterministic_environment()["TMPDIR"])
PY
)"
export TMPDIR

fail() {
    printf 'ERROR: x86 owned static sysroot: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

selected_consumer_workers() {
    local workers="${CRABC_X86_64_OWNED_STATIC_CONSUMER_WORKERS:-$CONSUMER_MATRIX_DEFAULT_WORKERS}"

    # `1` intentionally remains available when a developer needs a serial
    # replay. The default four-worker run additionally compares itself with a
    # serial pass over the same already-built installed trees; validating
    # before the cold producer work avoids spending two builds on a malformed
    # setting.
    case "$workers" in
        [1-8]) printf '%s\n' "$workers" ;;
        *) fail "CRABC_X86_64_OWNED_STATIC_CONSUMER_WORKERS must be an integer from 1 through $CONSUMER_MATRIX_MAX_WORKERS" ;;
    esac
}

owned_work_dir_is_safe() {
    local candidate="$1"
    local physical

    case "$candidate" in
        "$TMPDIR"/crabc-x86-64-owned-static-sysroot.*) ;;
        *) return 1 ;;
    esac
    physical="$(cd -P "$candidate" 2>/dev/null && pwd)" || return 1
    [ "$physical" = "$candidate" ]
}

finish_owned_work_dir() {
    local status=$?

    trap - EXIT
    if [ "$status" -eq 0 ]; then
        if owned_work_dir_is_safe "$work_dir"; then
            rm -rf -- "$work_dir"
        else
            printf 'ERROR: x86 owned static sysroot: refusing unsafe successful-work cleanup: %s\n' \
                "$work_dir" >&2
            status=1
        fi
    else
        printf 'ERROR: x86 owned static sysroot: retained failure artifacts: %s\n' \
            "$work_dir" >&2
    fi
    exit "$status"
}

consumer_matrix_pid=''

interrupt_consumer_matrix() {
    local signal_name="$1"
    local exit_status="$2"

    trap - INT TERM
    if [ -n "$consumer_matrix_pid" ]; then
        kill -s "$signal_name" "$consumer_matrix_pid" >/dev/null 2>&1 || true
        wait "$consumer_matrix_pid" || true
        consumer_matrix_pid=''
    fi
    # The helper owns and reaps every child process group before it returns;
    # retaining this run's artifacts is then safe for failure triage.
    exit "$exit_status"
}

write_tree_manifest() {
    local root="$1"
    local destination="$2"

    (
        cd "$root"
        find . -type f -print0 | sort -z | xargs -0 sha256sum
    ) >"$destination"
}

audit_installed_tree() {
    local root="$1"
    local path

    [ -f "$root/share/crabc/manifest.json" ] || fail "installed manifest is missing"
    [ -f "$root/usr/lib/crt1.o" ] || fail "installed crt1.o is missing"
    [ -f "$root/usr/lib/libc.a" ] || fail "installed libc.a is missing"
    [ -f "$root/usr/lib/libcrabc-builtins.a" ] || fail "installed builtins are missing"
    [ ! -e "$root/usr/lib/libc.so" ] || fail "private static slice installed libc.so"
    [ ! -e "$root/lib" ] || fail "private static slice installed a loader directory"
    [ -f "$root/bin/crabc-cc" ] || fail "installed static slice lacks crabc-cc"
    [ -x "$root/bin/crabc-cc" ] || fail "installed crabc-cc is not executable"
    while IFS= read -r path; do
        fail "installed tree contains a symlink: ${path#"$root"/}"
    done < <(find "$root" -type l -print)
    python3 - "$root/share/crabc/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if manifest.get("format") != "crabc-x86-64-owned-static-sysroot-v1":
    raise SystemExit("unexpected installed format")
if manifest.get("target") != "x86_64-unknown-linux-musl":
    raise SystemExit("unexpected installed target")
scope = manifest.get("scope", "")
for phrase in ("private-static-pthread-tls-consumer-slice", "not-family-completion", "not-public-support"):
    if phrase not in scope:
        raise SystemExit(f"manifest scope omits {phrase}")
not_selected = set(manifest.get("not_selected", []))
for item in (
    "shared libc",
    "dynamic loader or PT_INTERP",
    "complete compiler-helper closure",
    "sysroot.static-tls family completion",
    "sysroot.owned-artifact family completion",
    "x86-64 promotion or public support",
):
    if item not in not_selected:
        raise SystemExit(f"manifest non-selection omits {item}")
driver = manifest.get("sealed_static_driver")
if not isinstance(driver, dict):
    raise SystemExit("manifest lacks sealed static driver record")
if driver.get("path") != "bin/crabc-cc":
    raise SystemExit("manifest sealed static driver path drifted")
if driver.get("status") != "planned-owned-static-product-seed-not-family-completion-not-public-support":
    raise SystemExit("manifest sealed static driver incorrectly promotes the product")
expected_modes = [
    {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"},
    {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"},
]
if driver.get("modes") != expected_modes:
    raise SystemExit("manifest sealed static driver modes drifted")
if "declared static-product coverage suite" not in driver.get("not_proven_by_this_seed", []):
    raise SystemExit("manifest sealed static driver incorrectly claims product coverage")
if "distribution archive or extracted smoke" in not_selected:
    raise SystemExit("manifest incorrectly excludes the exercised extracted-tree smoke")
if "two-clean-build and extracted-install product reproducibility" in driver.get("not_proven_by_this_seed", []):
    raise SystemExit("manifest incorrectly excludes the exercised reproducibility proof")
PY
}

audit_static_driver_plan() {
    local root="$1"
    local mode="$2"
    local plan="$3"

    "$root/bin/crabc-cc" --print-link-plan "$mode" >"$plan"
    python3 - "$root" "$mode" "$plan" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
plan = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
expected = {
    "-static": ("ET_EXEC", "crt1.o", False),
    "-static-pie": ("ET_DYN", "rcrt1.o", True),
}[mode]
selected = plan.get("mode")
if not isinstance(selected, dict):
    raise SystemExit("sealed driver plan has no mode record")
if (selected.get("elf_type"), selected.get("crt_object")) != expected[:2]:
    raise SystemExit("sealed driver selected the wrong CRT or ELF mode")
if plan.get("headers") != str(root / "usr" / "include"):
    raise SystemExit("sealed driver selected non-owned headers")
linker = plan.get("linker")
if not isinstance(linker, list):
    raise SystemExit("sealed driver plan has no linker argv")
for runtime in ("crti.o", "libc.a", "libcrabc-builtins.a", "crtn.o"):
    if str(root / "usr" / "lib" / runtime) not in linker:
        raise SystemExit(f"sealed driver plan omits owned {runtime}")
for entry in linker:
    if isinstance(entry, str) and entry.startswith("/") and not entry.startswith(str(root)):
        raise SystemExit(f"sealed driver plan names ambient target input: {entry}")
if ("-pie" in linker) != expected[2]:
    raise SystemExit("sealed driver static mode changed unexpectedly")
if plan.get("status") != "planned-owned-static-product-seed-not-family-completion-not-public-support":
    raise SystemExit("sealed driver plan incorrectly promotes the product")
if "declared static-product coverage suite" not in plan.get("not_proven_by_this_seed", []):
    raise SystemExit("sealed driver plan incorrectly claims product coverage")
PY
}

audit_header_dependencies() {
    local dependency_file="$1"
    local installed_root="$2"
    local source_file="$3"

    python3 - "$dependency_file" "$installed_root/usr/include" "$source_file" <<'PY'
import sys
from pathlib import Path

dependency_file, include_root, source_file = map(Path, sys.argv[1:])
text = dependency_file.read_text(encoding="utf-8").replace("\\\n", " ")
try:
    dependencies = text.split(":", 1)[1].split()
except IndexError as error:
    raise SystemExit("dependency trace lacks a target separator") from error
include_root = include_root.resolve()
source_file = source_file.resolve()
for dependency in dependencies:
    path = Path(dependency)
    if not path.is_absolute():
        raise SystemExit(f"dependency trace contains a relative input: {dependency}")
    resolved = path.resolve()
    if resolved == source_file:
        continue
    try:
        resolved.relative_to(include_root)
    except ValueError as error:
        raise SystemExit(f"dependency trace contains an ambient input: {resolved}") from error
PY
}

audit_link_receipt() {
    local installed_root="$1"
    local consumer_root="$2"
    local mode="$3"
    local candidate="$4"
    local receipt="$5"

    python3 - "$installed_root" "$consumer_root" "$mode" "$candidate" "$receipt" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


root = Path(sys.argv[1]).resolve()
consumer = Path(sys.argv[2]).resolve()
mode = sys.argv[3]
candidate = Path(sys.argv[4]).resolve()
receipt_path = Path(sys.argv[5]).resolve()
expected = {
    "-static": ("static-et-exec", "ET_EXEC", "crt1.o", False),
    "-static-pie": ("static-pie", "ET_DYN", "rcrt1.o", True),
}[mode]
try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    fail(f"sealed driver receipt is unreadable: {error}")
if not isinstance(receipt, dict):
    fail("sealed driver receipt is not an object")
if receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-sealed-static-driver-v1":
    fail("sealed driver receipt schema or format drifted")
if receipt.get("target") != "x86_64-unknown-linux-musl":
    fail("sealed driver receipt target drifted")
resolved_linker = receipt.get("resolved_linker")
if not isinstance(resolved_linker, dict):
    fail("sealed driver receipt lacks its resolved linker identity")
linker_path = Path(resolved_linker.get("path", ""))
if linker_path.name != "ld.lld" or not linker_path.is_file() or linker_path.is_symlink():
    fail("sealed driver receipt resolved an unsafe linker")
if resolved_linker.get("sha256") != digest(linker_path):
    fail("sealed driver receipt linker identity hash drifted")
selected = receipt.get("mode")
if not isinstance(selected, dict) or (
    selected.get("id"), selected.get("elf_type"), selected.get("crt_object"), selected.get("interpreter")
) != (*expected[:3], "absent"):
    fail("sealed driver receipt selected the wrong mode")

library = root / "usr" / "lib"
expected_runtime = [
    ("crt-entry", library / expected[2]),
    ("crt-prologue", library / "crti.o"),
    ("libc", library / "libc.a"),
    ("builtins", library / "libcrabc-builtins.a"),
    ("crt-epilogue", library / "crtn.o"),
]
objects = [consumer / name for name in ("probe.o", "peer.o", "builtins.o")]
records = receipt.get("input_receipts")
if not isinstance(records, list) or len(records) != len(expected_runtime) + len(objects):
    fail("sealed driver receipt has the wrong input-record count")
for actual, (role, path) in zip(records[: len(expected_runtime)], expected_runtime):
    expected_record = {"role": role, "path": str(path.relative_to(root)), "sha256": digest(path)}
    if actual != expected_record:
        fail(f"sealed driver runtime input receipt drifted: {role}")
for actual, path in zip(records[len(expected_runtime) :], objects):
    expected_record = {"role": "application", "path": str(path), "sha256": digest(path)}
    if actual != expected_record:
        fail(f"sealed driver application input receipt drifted: {path.name}")

output = receipt.get("output")
if output != {"path": "candidate", "sha256": digest(candidate)}:
    fail("sealed driver output receipt drifted")
for field, suffix in (("map", ".map"), ("trace", ".trace")):
    sidecar = receipt_path.with_suffix(suffix)
    expected_record = {"path": sidecar.name, "sha256": digest(sidecar)}
    if receipt.get(field) != expected_record:
        fail(f"sealed driver {field} receipt drifted")

contract = receipt.get("owned_link_contract")
if not isinstance(contract, list):
    fail("sealed driver receipt lacks its fixed link contract")
expected_contract = [
    "ld.lld",
    "-static",
    *( ["-pie"] if expected[3] else [] ),
    "--no-dynamic-linker",
    "--no-undefined",
    "--gc-sections",
    "-z",
    "relro",
    "-z",
    "now",
    "-e",
    "_start",
    str(library / expected[2]),
    str(library / "crti.o"),
    "<application-objects>",
    str(library / "libc.a"),
    str(library / "libcrabc-builtins.a"),
    str(library / "crtn.o"),
    "-o",
    "<output>",
]
if contract != expected_contract:
    fail("sealed driver receipt link contract drifted")

trace_path = receipt_path.with_suffix(".trace")
trace = [line for line in trace_path.read_text(encoding="utf-8").splitlines() if line]
saw = {"entry": False, "crti": False, "crtn": False, "libc": False, "builtins": False, "builtins_member": False}
allowed_objects = {str(path) for path in objects}
for line in trace:
    if line == str(library / expected[2]):
        saw["entry"] = True
    elif line == str(library / "crti.o"):
        saw["crti"] = True
    elif line == str(library / "crtn.o"):
        saw["crtn"] = True
    elif line.startswith(str(library / "libc.a")):
        saw["libc"] = True
    elif line.startswith(str(library / "libcrabc-builtins.a")):
        saw["builtins"] = True
        if "libcrabc-builtins.a(crabc-builtins.o)" in line:
            saw["builtins_member"] = True
    elif line not in allowed_objects:
        fail(f"resolved final-link input escapes the owned set: {line}")
if not all(saw.values()):
    missing = ", ".join(name for name, found in saw.items() if not found)
    fail(f"sealed driver trace omitted required owned inputs: {missing}")

map_text = receipt_path.with_suffix(".map").read_text(encoding="utf-8")
for pattern in (
    r"/opt/musl-",
    r"/usr/lib/(gcc|clang)",
    r"/lib/ld-",
    r"crt(begin|end)",
    r"lib(gcc|ssp|atomic)",
    r"compiler-rt",
    r"libc\.so",
):
    if re.search(pattern, "\n".join(trace) + "\n" + map_text, flags=re.IGNORECASE):
        fail(f"sealed driver evidence contains an ambient target runtime input: {pattern}")
PY
}

assert_forged_link_traces_rejected() {
    local installed_root="$1"
    local consumer_root="$2"
    local mode="$3"
    local candidate="$4"
    local receipt="$5"
    local forged_root

    # `audit_link_receipt` is the closed resolved-input boundary, not merely
    # a report formatter.  Preserve the genuine receipt used for the later
    # installed-versus-extracted comparison, then give the auditor a complete
    # but forged receipt/sidecar set for each disallowed target-runtime class.
    forged_root="$consumer_root/forged-link-traces"
    python3 - "$receipt" "$forged_root" <<'PY'
import hashlib
import json
import shutil
import sys
from pathlib import Path


receipt_path = Path(sys.argv[1])
forged_root = Path(sys.argv[2])
record = json.loads(receipt_path.read_text(encoding="utf-8"))
original_map = receipt_path.with_suffix(".map")
original_trace = receipt_path.with_suffix(".trace")
for label, forged_input in (
    ("crt", "/ambient/crt1.o"),
    ("musl-libc", "/opt/musl-1.2.6/lib/libc.a"),
    ("libgcc", "/usr/lib/gcc/x86_64-linux-gnu/0/libgcc.a"),
    ("compiler-runtime", "/usr/lib/llvm/compiler-rt/libclang_rt.builtins-x86_64.a"),
    ("loader", "/lib/ld-musl-x86_64.so.1"),
):
    destination = forged_root / label
    destination.mkdir(parents=True)
    forged_receipt = destination / receipt_path.name
    forged_map = forged_receipt.with_suffix(".map")
    forged_trace = forged_receipt.with_suffix(".trace")
    shutil.copyfile(original_map, forged_map)
    trace = original_trace.read_bytes() + forged_input.encode("utf-8") + b"\n"
    forged_trace.write_bytes(trace)
    forged_record = dict(record)
    forged_record["map"] = {
        "path": forged_map.name,
        "sha256": hashlib.sha256(forged_map.read_bytes()).hexdigest(),
    }
    forged_record["trace"] = {
        "path": forged_trace.name,
        "sha256": hashlib.sha256(trace).hexdigest(),
    }
    forged_receipt.write_text(
        json.dumps(forged_record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
PY

    local label
    for label in crt musl-libc libgcc compiler-runtime loader; do
        if audit_link_receipt "$installed_root" "$consumer_root" "$mode" "$candidate" \
            "$forged_root/$label/$(basename "$receipt")" >/dev/null 2>&1; then
            fail "link receipt audit accepted a forged ambient ${label} trace"
        fi
    done
}

assert_final_static_image() {
    local candidate="$1"
    local mode="$2"
    local file_header="$3"
    local program_headers="$4"
    local dynamic="$5"
    local symbols="$6"
    local relocations="$7"
    local minimum_tls_alignment="${8:-4096}"
    local tls_count tls_filesz tls_memsz tls_alignment unresolved

    grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' "$file_header" ||
        fail "${mode} candidate is not EM_X86_64"
    case "$mode" in
        -static)
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$file_header" ||
                fail "static candidate is not ET_EXEC"
            ;;
        -static-pie)
            grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' \
                "$file_header" || fail "static PIE candidate is not ET_DYN"
            awk '$1 == "PHDR" { found = 1 } END { exit !found }' "$program_headers" ||
                fail "static PIE candidate lacks PT_PHDR"
            ;;
        *) fail "unknown static image mode: $mode" ;;
    esac
    if grep -Eq 'Requesting program interpreter|INTERP' "$program_headers" ||
        grep -Eq 'NEEDED|JMPREL|PLTGOT' "$dynamic"; then
        fail "${mode} candidate selected an interpreter, dynamic dependency, or PLT"
    fi
    awk '$1 == "GNU_RELRO" { count += 1 } END { exit count != 1 }' "$program_headers" ||
        fail "${mode} candidate must have exactly one GNU_RELRO segment"
    awk '$1 == "GNU_STACK" { count += 1; if ($7 ~ /E/) executable = 1 }
        END { exit count != 1 || executable }' "$program_headers" ||
        fail "${mode} candidate must have one non-executable GNU_STACK segment"
    tls_count="$(awk '$1 == "TLS" { count += 1 } END { print count + 0 }' "$program_headers")"
    [ "$tls_count" = 1 ] || fail "${mode} candidate must have exactly one PT_TLS segment"
    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "${mode} candidate PT_TLS line is not parseable"
    if (( tls_filesz == 0 || tls_memsz <= tls_filesz )); then
        fail "${mode} candidate TLS lacks initialized and TBSS content"
    fi
    if (( tls_alignment < minimum_tls_alignment || (tls_alignment & (tls_alignment - 1)) != 0 )); then
        fail "${mode} candidate TLS lost the fixture's required alignment"
    fi
    unresolved="$(awk '$7 == "UND" && NF >= 8 { print }' "$symbols")"
    [ -z "$unresolved" ] || fail "${mode} candidate retains unresolved symbols: $unresolved"
    grep -Eq '[[:space:]]__udivti3$' "$symbols" ||
        fail "${mode} candidate lacks the owned __udivti3 helper"
    if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT|TLSGD|TLSLD|TLSDESC|DTPMOD|DTPOFF)' \
        "$relocations" "$symbols"; then
        fail "${mode} candidate retains a dynamic relocation or dynamic TLS form"
    fi
    if [ "$mode" = -static-pie ]; then
        if grep -Eq 'R_X86_64_GOTTPOFF|__tls_get_addr' "$relocations" "$symbols"; then
            fail "static PIE candidate retained an unrelaxed initial-TLS access"
        fi
        awk '$3 ~ /^R_X86_64_/ && $3 != "R_X86_64_RELATIVE" { exit 1 }' "$relocations" ||
            fail "static PIE candidate retains a non-relative relocation"
    fi
    [ -x "$candidate" ] || chmod 755 "$candidate"
}

assert_malformed_tls_rejected() {
    local candidate="$1"
    local label="$2"
    local malformed="${candidate}.bad-filesz"
    local candidate_phoff candidate_phnum tls_header_index tls_filesz_offset header_offset header_type status

    candidate_phoff="$(od -An -tu8 -j "$ELF64_PROGRAM_HEADER_OFFSET" -N 8 "$candidate" | tr -d '[:space:]')"
    candidate_phnum="$(od -An -tu2 -j "$ELF64_PROGRAM_HEADER_COUNT_OFFSET" -N 2 "$candidate" | tr -d '[:space:]')"
    [ -n "$candidate_phoff" ] && [ -n "$candidate_phnum" ] ||
        fail "${label} candidate ELF metadata is unreadable"
    tls_header_index=''
    for ((header_index = 0; header_index < candidate_phnum; header_index += 1)); do
        header_offset=$((candidate_phoff + header_index * ELF64_PROGRAM_HEADER_SIZE))
        header_type="$(od -An -tu4 -j "$header_offset" -N 4 "$candidate" | tr -d '[:space:]')"
        if [ "$header_type" = 7 ]; then
            tls_header_index="$header_index"
            break
        fi
    done
    [ -n "$tls_header_index" ] || fail "${label} candidate has no PT_TLS header to mutate"
    tls_filesz_offset=$((candidate_phoff + tls_header_index * ELF64_PROGRAM_HEADER_SIZE + ELF64_P_FILESZ_OFFSET))
    cp "$candidate" "$malformed"
    printf '\377\377\377\377\377\377\377\377' | dd of="$malformed" bs=1 \
        seek="$tls_filesz_offset" conv=notrunc status=none
    if "$malformed" >/dev/null 2>&1; then
        fail "${label} malformed PT_TLS candidate unexpectedly completed"
    else
        status=$?
    fi
    [ "$status" = 127 ] || fail "${label} malformed PT_TLS candidate exited $status, not 127"
}

run_static_mode() {
    local installed_root="$1"
    local mode="$2"
    local mode_root="$3"
    local label="$4"
    local consumer_kind="${5:-tls}"
    local candidate receipt candidate_output
    local -a candidate_arguments=()
    local probe=libc_crt_static_tls_probe.c
    local expected_output=PIMBCAF
    local minimum_tls_alignment=4096

    # The malformed-PT_TLS executable is deliberately rejected by the owned
    # startup code. A rejected image may fault before it can install any
    # application policy, so do not let a concurrent consumer emit an
    # uncontrolled `core` file into the inherited checkout CWD.
    ulimit -c 0

    case "$consumer_kind" in
        tls) ;;
        allocator)
            probe=libc_allocator_basic_runtime_v1_probe.c
            expected_output=ALLOCATOR_BASIC_RUNTIME_V1_ATEXIT
            minimum_tls_alignment=1
            ;;
        posix)
            probe=owned_static_posix_probe.c
            expected_output='owned-static-posix: PASS'
            minimum_tls_alignment=1
            ;;
        stdio)
            probe=owned_static_stdio_probe.c
            expected_output=owned-stdio-ok
            minimum_tls_alignment=1
            candidate_arguments=("$mode_root/stream-data" "$mode_root/exit-data")
            ;;
        *) fail "unknown installed consumer: $consumer_kind" ;;
    esac

    mkdir "$mode_root"
    (
        cd "$mode_root"
        "$installed_root/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE \
            -DCRABC_CRT_STATIC_TLS_CANDIDATE -DCRABC_STATIC_STACK_GUARD \
            -DCRABC_ALLOCATOR_BASIC_RUNTIME_V1_CANDIDATE -c \
            "$ROOT_DIR/compat/x86_64/$probe" -o probe.o
        "$installed_root/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE -DCRABC_STATIC_STACK_GUARD -c \
            "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c" -o peer.o
        "$installed_root/bin/crabc-cc" "$mode" -std=c11 -D_GNU_SOURCE -c \
            "$ROOT_DIR/compat/x86_64/owned_static_sysroot_builtins.c" -o builtins.o
        "$installed_root/bin/crabc-cc" "$mode" --link-receipt link.receipt.json -o candidate \
            probe.o peer.o builtins.o
    )
    candidate="$mode_root/candidate"
    receipt="$mode_root/link.receipt.json"
    nm -u "$mode_root/peer.o" | grep -Eq '[[:space:]]U[[:space:]]+__stack_chk_fail$' ||
        fail "${label} protected peer did not emit a compiler stack check"
    nm -u "$mode_root/builtins.o" | grep -Eq '[[:space:]]U[[:space:]]+__udivti3$' ||
        fail "${label} compiler-helper consumer did not retain an undefined __udivti3 boundary"
    audit_link_receipt "$installed_root" "$mode_root" "$mode" "$candidate" "$receipt"
    assert_forged_link_traces_rejected "$installed_root" "$mode_root" "$mode" "$candidate" "$receipt"
    readelf --file-header --wide "$candidate" >"$mode_root/file-header"
    readelf --program-headers --wide "$candidate" >"$mode_root/program-headers"
    readelf --dynamic --wide "$candidate" >"$mode_root/dynamic" || true
    readelf --symbols --wide "$candidate" >"$mode_root/symbols"
    readelf --relocs --wide "$candidate" >"$mode_root/relocations"
    assert_final_static_image "$candidate" "$mode" "$mode_root/file-header" \
        "$mode_root/program-headers" "$mode_root/dynamic" "$mode_root/symbols" \
        "$mode_root/relocations" "$minimum_tls_alignment"
    candidate_output="$(env -i "$candidate" "${candidate_arguments[@]}")" || fail "${label} candidate failed"
    [ "$candidate_output" = "$expected_output" ] ||
        fail "${label} candidate output drifted: $candidate_output"
    if [ "$consumer_kind" = stdio ]; then
        nm --defined-only "$candidate" | grep -Eq '[[:space:]]T[[:space:]]+__stdio_exit$' ||
            fail "${label} lacks the strong owned stdio exit hook"
        printf 'exit-flushed\n' >"$mode_root/expected-exit-data"
        cmp "$mode_root/expected-exit-data" "$mode_root/exit-data" ||
            fail "${label} did not flush its dynamic stream at ordinary exit"
    fi
    assert_malformed_tls_rejected "$candidate" "$label"
    sha256sum "$candidate" | awk '{ print $1 }' >"$mode_root/candidate.sha256"
}

assert_missing_builtins_rejected() {
    local installed_root="$1"
    local mode_root="$2"

    if "$link_editor" -static --no-dynamic-linker --no-undefined -e _start \
        "$installed_root/usr/lib/crt1.o" "$installed_root/usr/lib/crti.o" \
        "$mode_root/probe.o" "$mode_root/peer.o" "$mode_root/builtins.o" \
        "$installed_root/usr/lib/libc.a" "$installed_root/usr/lib/crtn.o" \
        -o "$mode_root/without-builtins" >"$mode_root/without-builtins.stdout" \
        2>"$mode_root/without-builtins.stderr"; then
        fail "consumer unexpectedly linked without installed compiler helpers"
    fi
    grep -Fq '__udivti3' "$mode_root/without-builtins.stderr" ||
        fail "missing-builtins link did not fail at the selected helper boundary"
}

write_consumer_matrix_manifest() {
    local destination="$1"
    local primary="$2"
    local extracted="$3"
    local primary_consumer="$4"
    local extracted_consumer="$5"

    python3 - "$destination" "$ROOT_DIR/compat/x86_64/run_owned_static_sysroot.sh" \
        "$primary" "$extracted" "$primary_consumer" "$extracted_consumer" <<'PY'
import json
import sys
from pathlib import Path


destination = Path(sys.argv[1])
runner = sys.argv[2]
primary, extracted, primary_consumer, extracted_consumer = map(Path, sys.argv[3:])
jobs: list[dict[str, object]] = []
consumer_specs = (
    ("tls", "static-et-exec", "-static", "ET_EXEC", "et-exec"),
    ("tls", "static-pie", "-static-pie", "static PIE", "static-pie"),
    ("allocator", "allocator-et-exec", "-static", "allocator ET_EXEC", "et-exec"),
    ("allocator", "allocator-pie", "-static-pie", "allocator static PIE", "static-pie"),
    ("posix", "posix-et-exec", "-static", "POSIX ET_EXEC", "et-exec"),
    ("posix", "posix-pie", "-static-pie", "POSIX static PIE", "static-pie"),
    ("stdio", "stdio-et-exec", "-static", "stdio ET_EXEC", "et-exec"),
    ("stdio", "stdio-pie", "-static-pie", "stdio static PIE", "static-pie"),
)
for tree_name, installed_root, consumer_root in (
    ("primary", primary, primary_consumer),
    ("extracted", extracted, extracted_consumer),
):
    for kind, mode_root_name, mode, label, mode_name in consumer_specs:
        jobs.append(
            {
                "name": f"{tree_name}-{kind}-{mode_name}",
                "argv": [
                    runner,
                    "--consumer-job",
                    str(installed_root),
                    mode,
                    str(consumer_root / mode_root_name),
                    label if tree_name == "primary" else f"extracted {label}",
                    kind,
                ],
            }
        )
with destination.open("x", encoding="utf-8", newline="\n") as stream:
    json.dump({"schema": 1, "jobs": jobs}, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

run_consumer_matrix() {
    local work_root="$1"
    local primary="$2"
    local extracted="$3"
    local primary_consumer="$4"
    local extracted_consumer="$5"
    local workers="$6"
    local matrix_name="${7:-consumer-matrix}"
    local manifest="$work_root/$matrix_name.json"
    local logs="$work_root/$matrix_name-logs"
    local status=0

    write_consumer_matrix_manifest "$manifest" "$primary" "$extracted" \
        "$primary_consumer" "$extracted_consumer"
    python3 "$CONSUMER_MATRIX" --state-root "$work_root" --manifest "$manifest" \
        --log-directory "$logs" --workers "$workers" \
        --timeout "$CONSUMER_MATRIX_TIMEOUT_SECONDS" &
    consumer_matrix_pid=$!
    wait "$consumer_matrix_pid" || status=$?
    consumer_matrix_pid=''
    return "$status"
}

compare_consumer_matrix_runs() {
    local serial_primary="$1"
    local serial_extracted="$2"
    local parallel_primary="$3"
    local parallel_extracted="$4"
    local serial_logs="$5"
    local parallel_logs="$6"
    local mode_root

    # Every job already checks its observable C result. Candidate hashes make
    # the serial/parallel comparison an additional determinism check rather
    # than just a timing report, while both passes reuse the same cold-built
    # primary and extracted trees.
    for mode_root in static-et-exec static-pie allocator-et-exec allocator-pie posix-et-exec posix-pie stdio-et-exec stdio-pie; do
        cmp "$serial_primary/$mode_root/candidate.sha256" \
            "$parallel_primary/$mode_root/candidate.sha256" ||
            fail "${mode_root} primary output differs between serial and parallel consumers"
        cmp "$serial_extracted/$mode_root/candidate.sha256" \
            "$parallel_extracted/$mode_root/candidate.sha256" ||
            fail "${mode_root} extracted output differs between serial and parallel consumers"
    done
    python3 - "$serial_logs/summary.json" "$parallel_logs/summary.json" <<'PY'
import json
import math
import sys
from pathlib import Path


serial_path, parallel_path = map(Path, sys.argv[1:])


def read_summary(path: Path, expected_workers: int) -> tuple[float, list[str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read consumer timing summary {path}: {error}") from error
    jobs = value.get("jobs")
    if (
        value.get("schema") != 1
        or value.get("workers") != expected_workers
        or not isinstance(jobs, list)
        or len(jobs) != 16
        or any(not isinstance(job, dict) or job.get("status") != "passed" for job in jobs)
    ):
        raise SystemExit(f"consumer timing summary is not a complete passing 16-job run: {path}")
    elapsed = value.get("elapsed_seconds")
    if not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed <= 0:
        raise SystemExit(f"consumer timing summary has no finite elapsed time: {path}")
    names = [job.get("name") for job in jobs]
    if any(not isinstance(name, str) for name in names):
        raise SystemExit(f"consumer timing summary has an invalid job name: {path}")
    return float(elapsed), names


serial_seconds, serial_names = read_summary(serial_path, 1)
parallel_seconds, parallel_names = read_summary(parallel_path, 4)
if serial_names != parallel_names:
    raise SystemExit("serial and parallel consumer summaries name different jobs")
print(
    "owned-static consumer timing: "
    f"workers=1 {serial_seconds:.1f}s; workers=4 {parallel_seconds:.1f}s; "
    f"same-input speedup={serial_seconds / parallel_seconds:.2f}x"
)
PY
}

assert_mode_evidence_reproducible() {
    local primary_root="$1"
    local primary_mode_root="$2"
    local extracted_root="$3"
    local extracted_mode_root="$4"
    local label="$5"

    python3 - "$primary_root" "$primary_mode_root" "$extracted_root" \
        "$extracted_mode_root" "$label" <<'PY'
import hashlib
import json
import sys
from pathlib import Path


primary_root, primary_mode, extracted_root, extracted_mode = (
    Path(value).resolve() for value in sys.argv[1:5]
)
label = sys.argv[5]
replacements = sorted(
    (
        (str(primary_mode), "<application>"),
        (str(extracted_mode), "<application>"),
        (str(primary_root), "<sysroot>"),
        (str(extracted_root), "<sysroot>"),
    ),
    key=lambda item: len(item[0]),
    reverse=True,
)


def normalize(value: object) -> object:
    if isinstance(value, str):
        for source, replacement in replacements:
            value = value.replace(source, replacement)
        return value
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    return value


def evidence(mode_root: Path) -> tuple[str, str, str]:
    receipt_path = mode_root / "link.receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    sidecars: list[str] = []
    for field, suffix in (("map", ".map"), ("trace", ".trace")):
        content = normalize(receipt_path.with_suffix(suffix).read_text(encoding="utf-8"))
        assert isinstance(content, str)
        receipt[field]["sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        sidecars.append(content)
    normalized = normalize(receipt)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")), *sidecars


primary = evidence(primary_mode)
extracted = evidence(extracted_mode)
if primary != extracted:
    raise SystemExit(f"{label} normalized receipt/map/trace differs after extraction")
PY
}

if [ "${1:-}" = "--consumer-job" ]; then
    shift
    [ "$#" -eq 5 ] || fail "usage: $0 --consumer-job <installed-root> <mode> <consumer-root> <label> <kind>"
    run_static_mode "$@"
    exit
fi

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
consumer_workers="$(selected_consumer_workers)"
for tool in awk cmp cp dd env find gcc grep nm od python3 readelf rustup sha256sum sort tr xargs; do
    require_tool "$tool"
done
[ -f "$BUILDER" ] || fail "missing x86 owned-sysroot builder"
[ -f "$PACKAGE" ] || fail "missing x86 owned-sysroot package helper"
[ -f "$CONSUMER_MATRIX" ] || fail "missing owned-static consumer matrix helper"
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_root="$(rustup run nightly-2026-07-24 rustc --print sysroot)"
    link_editor="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    [ -x "$link_editor" ] || fail "requires a pinned Rust-toolchain ld.lld"
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
python3 -B -m unittest -v \
    scripts.tests.test_build_x86_64_owned_sysroot \
    compat.x86_64.tests.test_owned_static_sysroot_package \
    compat.x86_64.tests.test_owned_static_consumer_matrix

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-64-owned-static-sysroot.XXXXXX")"
chmod 2770 "$work_dir"
trap finish_owned_work_dir EXIT
trap 'interrupt_consumer_matrix INT 130' INT
trap 'interrupt_consumer_matrix TERM 143' TERM
primary="$work_dir/primary"
reproduction="$work_dir/reproduction"
python3 "$BUILDER" --output "$primary" >"$work_dir/primary-build.json"
python3 "$BUILDER" --output "$reproduction" >"$work_dir/reproduction-build.json"
audit_installed_tree "$primary"
audit_installed_tree "$reproduction"
audit_static_driver_plan "$primary" -static "$work_dir/primary-et-exec-plan.json"
audit_static_driver_plan "$primary" -static-pie "$work_dir/primary-static-pie-plan.json"
write_tree_manifest "$primary" "$work_dir/primary-tree.sha256"
write_tree_manifest "$reproduction" "$work_dir/reproduction-tree.sha256"
cmp "$work_dir/primary-tree.sha256" "$work_dir/reproduction-tree.sha256" ||
    fail "two clean installed trees are not byte-identical"
python3 "$PACKAGE" create --source "$primary" --archive "$work_dir/primary.tar.xz"
python3 "$PACKAGE" create --source "$reproduction" --archive "$work_dir/reproduction.tar.xz"
cmp "$work_dir/primary.tar.xz" "$work_dir/reproduction.tar.xz" ||
    fail "two clean owned-static packages are not byte-identical"
python3 "$PACKAGE" extract --archive "$work_dir/primary.tar.xz" \
    --destination "$work_dir/extracted-tree" >/dev/null
extracted="$work_dir/extracted-tree/crabc-x86_64-owned-static-sysroot"
audit_installed_tree "$extracted"
audit_static_driver_plan "$extracted" -static "$work_dir/extracted-et-exec-plan.json"
audit_static_driver_plan "$extracted" -static-pie "$work_dir/extracted-static-pie-plan.json"

header_consumer="$work_dir/header-consumer"
mkdir "$header_consumer"
probe_object="$header_consumer/probe.o"
peer_object="$header_consumer/peer.o"
builtins_object="$header_consumer/builtins.o"
dependency_file="$header_consumer/probe.d"
peer_dependency_file="$header_consumer/peer.d"
builtins_dependency_file="$header_consumer/builtins.d"
forged_dependency="$header_consumer/forged.d"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CRT_STATIC_TLS_MUSL_REFERENCE -DCRABC_STATIC_STACK_GUARD \
    -pthread -fno-builtin -fno-stack-protector -ftls-model=local-exec \
    -I"$ROOT_DIR/include" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c" \
    -o "$header_consumer/reference"
reference_output="$(env -i "$header_consumer/reference")" || fail "pinned-musl reference failed"
[ "$reference_output" = PIMBCAF ] || fail "pinned-musl reference output drifted: $reference_output"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -I"$ROOT_DIR/include" \
    "$ROOT_DIR/compat/x86_64/libc_allocator_basic_runtime_v1_probe.c" \
    -o "$header_consumer/allocator-reference"
reference_output="$(env -i "$header_consumer/allocator-reference")" ||
    fail "pinned-musl allocator reference failed"
[ "$reference_output" = ALLOCATOR_BASIC_RUNTIME_V1_ATEXIT ] ||
    fail "pinned-musl allocator reference output drifted: $reference_output"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -I"$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/owned_static_posix_probe.c" \
    -o "$header_consumer/posix-reference"
reference_output="$(env -i "$header_consumer/posix-reference")" ||
    fail "pinned-musl POSIX reference failed"
[ "$reference_output" = 'owned-static-posix: PASS' ] ||
    fail "pinned-musl POSIX reference output drifted: $reference_output"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -I"$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/owned_static_stdio_probe.c" \
    -o "$header_consumer/stdio-reference"
reference_output="$(env -i "$header_consumer/stdio-reference" \
    "$header_consumer/stdio-data" "$header_consumer/stdio-exit-data")" ||
    fail "pinned-musl stdio reference failed"
[ "$reference_output" = owned-stdio-ok ] ||
    fail "pinned-musl stdio reference output drifted: $reference_output"
printf 'exit-flushed\n' >"$header_consumer/expected-stdio-exit-data"
cmp "$header_consumer/expected-stdio-exit-data" "$header_consumer/stdio-exit-data" ||
    fail "pinned-musl stdio reference did not flush its dynamic stream at exit"

common_compile=(
    gcc -std=c11 -D_GNU_SOURCE -fno-pie -ffreestanding -fno-builtin
    -fno-stack-protector -ftls-model=local-exec -nostdinc
    -isystem "$primary/usr/include"
)
"${common_compile[@]}" -DCRABC_CRT_STATIC_TLS_CANDIDATE -MD -MF "$dependency_file" \
    -c "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c" -o "$probe_object"
"${common_compile[@]}" -MD -MF "$peer_dependency_file" \
    -c "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c" -o "$peer_object"
"${common_compile[@]}" -MD -MF "$builtins_dependency_file" \
    -c "$ROOT_DIR/compat/x86_64/owned_static_sysroot_builtins.c" -o "$builtins_object"
audit_header_dependencies "$dependency_file" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c"
audit_header_dependencies "$peer_dependency_file" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c"
audit_header_dependencies "$builtins_dependency_file" "$primary" \
    "$ROOT_DIR/compat/x86_64/owned_static_sysroot_builtins.c"
"${common_compile[@]}" -DCRABC_ALLOCATOR_BASIC_RUNTIME_V1_CANDIDATE \
    -MD -MF "$header_consumer/allocator.d" \
    -c "$ROOT_DIR/compat/x86_64/libc_allocator_basic_runtime_v1_probe.c" \
    -o "$header_consumer/allocator.o"
audit_header_dependencies "$header_consumer/allocator.d" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_allocator_basic_runtime_v1_probe.c"
"${common_compile[@]}" -MD -MF "$header_consumer/posix.d" \
    -c "$ROOT_DIR/compat/x86_64/owned_static_posix_probe.c" \
    -o "$header_consumer/posix.o"
audit_header_dependencies "$header_consumer/posix.d" "$primary" \
    "$ROOT_DIR/compat/x86_64/owned_static_posix_probe.c"
"${common_compile[@]}" -MD -MF "$header_consumer/stdio.d" \
    -c "$ROOT_DIR/compat/x86_64/owned_static_stdio_probe.c" \
    -o "$header_consumer/stdio.o"
audit_header_dependencies "$header_consumer/stdio.d" "$primary" \
    "$ROOT_DIR/compat/x86_64/owned_static_stdio_probe.c"
grep -Fq "$primary/usr/include/errno.h" "$dependency_file" ||
    fail "consumer dependency trace did not resolve installed errno.h"
grep -Fq "$primary/usr/include/pthread.h" "$dependency_file" ||
    fail "consumer dependency trace did not resolve installed pthread.h"
printf '%s: %s %s %s\n' "$probe_object" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c" \
    "$primary/usr/include/errno.h" /usr/include/stdint.h >"$forged_dependency"
if (audit_header_dependencies "$forged_dependency" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c") >/dev/null 2>&1; then
    fail "header audit admitted an ambient target header"
fi

primary_consumer="$work_dir/primary-consumer"
extracted_consumer="$work_dir/extracted-consumer"
mkdir "$primary_consumer" "$extracted_consumer"
run_consumer_matrix "$work_dir" "$primary" "$extracted" "$primary_consumer" \
    "$extracted_consumer" "$consumer_workers"
assert_missing_builtins_rejected "$primary" "$primary_consumer/static-et-exec"
if [ "$consumer_workers" = "$CONSUMER_MATRIX_DEFAULT_WORKERS" ]; then
    serial_primary_consumer="$work_dir/primary-consumer-serial"
    serial_extracted_consumer="$work_dir/extracted-consumer-serial"
    mkdir "$serial_primary_consumer" "$serial_extracted_consumer"
    run_consumer_matrix "$work_dir" "$primary" "$extracted" "$serial_primary_consumer" \
        "$serial_extracted_consumer" 1 consumer-matrix-serial
    compare_consumer_matrix_runs "$serial_primary_consumer" "$serial_extracted_consumer" \
        "$primary_consumer" "$extracted_consumer" \
        "$work_dir/consumer-matrix-serial-logs" "$work_dir/consumer-matrix-logs"
fi
for mode_root in static-et-exec static-pie allocator-et-exec allocator-pie posix-et-exec posix-pie stdio-et-exec stdio-pie; do
    cmp "$primary_consumer/$mode_root/candidate.sha256" \
        "$extracted_consumer/$mode_root/candidate.sha256" ||
        fail "${mode_root} output differs after deterministic package extraction"
    assert_mode_evidence_reproducible "$primary" "$primary_consumer/$mode_root" \
        "$extracted" "$extracted_consumer/$mode_root" "$mode_root"
done

printf 'x86 owned static sysroot dual-mode + extracted TLS, allocator, POSIX, and stdio consumers: PASS\n'
