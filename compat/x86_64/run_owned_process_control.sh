#!/usr/bin/env bash
# Installed residual POSIX process-control evidence.
#
# One object compiled by the supplied owned dynamic driver is linked first to
# pinned musl and then through each installed static and dynamic mode.  The
# 31-name workload owns the residual exec/nice/group-session/wait/spawnattr
# names;
# `run_owned_process_trio.sh` and `run_owned_dynamic_spawn.sh` retain their
# already-qualified clone/vfork/daemon and spawn/file-action matrices.  This
# case is one contribution to `process.control`, never a family transition or
# public x86 support claim.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_process_control_probe.c"
readonly CHROOT="$(command -v chroot)"
readonly RESIDUAL_SYMBOLS='execl execle execlp execv execve execvp execvpe fexecve nice setpgid setpgrp setsid wait wait3 wait4 waitid waitpid posix_spawnattr_destroy posix_spawnattr_getflags posix_spawnattr_getpgroup posix_spawnattr_getschedparam posix_spawnattr_getschedpolicy posix_spawnattr_getsigdefault posix_spawnattr_getsigmask posix_spawnattr_init posix_spawnattr_setflags posix_spawnattr_setpgroup posix_spawnattr_setschedparam posix_spawnattr_setschedpolicy posix_spawnattr_setsigdefault posix_spawnattr_setsigmask'

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath "$provided_dynamic")"
fi

# Reject an ambient or incomplete supplied product before this runner creates
# mutable evidence.  The link receipts below bind each consumer to this exact
# manifest again, including an extracted product in qualification.
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from hashlib import sha256
import json
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("process-control TMPDIR must be a physical checkout .work directory")
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("process-control product must be a checkout .work directory")
    manifest_path = product / "share/crabc/manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise SystemExit("process-control product lacks a regular manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != "crabc-x86-64-owned-dynamic-sysroot-v1":
        raise SystemExit("process-control product has the wrong dynamic format")
    for relative, digest in manifest.get("files", {}).items():
        path = product / relative
        if not path.is_file() or path.is_symlink() or sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit(f"process-control product payload drifted: {relative}")
    for relative in ("bin/crabc-cc-dynamic", "usr/lib/libc.so", "lib/ld-crabc-x86_64.so.1"):
        if not (product / relative).is_file():
            raise SystemExit(f"process-control product lacks {relative}")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-process-control.XXXXXX")"
chmod a+rx "$work"
finish() {
    local status=$?
    chmod -R a+rX "$work"
    printf 'owned process-control evidence: %s\n' "$work"
    exit "$status"
}
trap finish EXIT

run_in_root() {
    local root="$1" output="$2"
    shift 2
    timeout 40 env -i PATH=/ EXEC_TOKEN=parent LC_ALL=C "$CHROOT" "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr"
}

assert_static_symbols() {
    local archive="$1" symbols="$work/static-symbols.txt" symbol
    nm -g --defined-only "$archive" >"$symbols"
    for symbol in $RESIDUAL_SYMBOLS; do
        [ "$(awk -v symbol="$symbol" '$2 ~ /^[TW]$/ && $3 == symbol { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] || {
            printf 'process-control static provider missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_static_receipt_and_elf() {
    local product="$1" consumer="$2" mode="$3" object="$4" receipt="$5"
    readelf -hW "$consumer" >"${consumer}.header"
    readelf -lW "$consumer" >"${consumer}.segments"
    readelf -dW "$consumer" >"${consumer}.dynamic"
    python3 -B - "$product" "$consumer" "$mode" "$object" "$receipt" <<'PY_STATIC'
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def fail(message):
    raise SystemExit("process-control static receipt " + message)


root = Path(sys.argv[1]).resolve()
consumer = Path(sys.argv[2]).resolve()
mode = sys.argv[3]
object_path = Path(sys.argv[4]).resolve()
receipt_path = Path(sys.argv[5]).resolve()
expected = {
    "static": ("static-et-exec", "ET_EXEC", "EXEC", "crt1.o", False),
    "static-pie": ("static-pie", "ET_DYN", "DYN", "rcrt1.o", True),
}[mode]
manifest_path = root / "share/crabc/manifest.json"
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    fail(f"is unreadable: {error}")
if manifest_path.is_symlink() or not isinstance(manifest, dict):
    fail("manifest identity drifted")
if (manifest.get("format") != "crabc-x86-64-owned-static-sysroot-v1" or
        manifest.get("target") != "x86_64-unknown-linux-musl"):
    fail("manifest identity drifted")
installed = manifest.get("installed")
payload = installed.get("files") if isinstance(installed, dict) else None
if not isinstance(payload, dict):
    fail("manifest payload roster drifted")
if not isinstance(receipt, dict):
    fail("is not an object")
if (receipt.get("schema") != 1 or
        receipt.get("format") != "crabc-x86-64-sealed-static-driver-v1" or
        receipt.get("target") != "x86_64-unknown-linux-musl"):
    fail("schema or format drifted")
selected = receipt.get("mode")
if not isinstance(selected, dict) or (
        selected.get("id"), selected.get("elf_type"),
        selected.get("crt_object"), selected.get("interpreter")
    ) != (expected[0], expected[1], expected[3], "absent"):
    fail("mode drifted")

library = root / "usr/lib"
runtime = (
    ("crt-entry", library / expected[3]),
    ("crt-prologue", library / "crti.o"),
    ("libc", library / "libc.a"),
    ("builtins", library / "libcrabc-builtins.a"),
    ("crt-epilogue", library / "crtn.o"),
)
for role, path in runtime:
    relative = path.relative_to(root).as_posix()
    if not path.is_file() or path.is_symlink() or payload.get(relative) != digest(path):
        fail(f"manifest/runtime identity drifted: {role}")
if not object_path.is_file() or object_path.is_symlink():
    fail("workload object identity drifted")
expected_records = [
    {"role": role, "path": path.relative_to(root).as_posix(), "sha256": digest(path)}
    for role, path in runtime
] + [{"role": "application", "path": str(object_path), "sha256": digest(object_path)}]
if receipt.get("input_receipts") != expected_records:
    fail("runtime or workload input receipt drifted")

linker = receipt.get("resolved_linker")
if not isinstance(linker, dict):
    fail("lacks resolved linker identity")
linker_path = Path(linker.get("path", ""))
if (linker_path.name != "ld.lld" or not linker_path.is_file() or
        linker_path.is_symlink() or linker.get("sha256") != digest(linker_path)):
    fail("resolved linker identity drifted")
expected_contract = [
    "ld.lld", "-static", *(["-pie"] if expected[4] else []),
    "--no-dynamic-linker", "--no-undefined", "--gc-sections", "-z", "relro",
    "-z", "now", "-e", "_start", str(library / expected[3]),
    str(library / "crti.o"), "<application-objects>", str(library / "libc.a"),
    str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", "<output>",
]
if receipt.get("owned_link_contract") != expected_contract:
    fail("owned link contract drifted")
if receipt.get("output") != {"path": str(consumer), "sha256": digest(consumer)}:
    fail("output identity drifted")
for field, suffix in (("map", ".map"), ("trace", ".trace")):
    sidecar = receipt_path.with_suffix(suffix)
    if receipt.get(field) != {"path": sidecar.name, "sha256": digest(sidecar)}:
        fail(f"{field} identity drifted")

trace = [line for line in receipt_path.with_suffix(".trace").read_text(encoding="utf-8").splitlines()
         if line]
direct_inputs = {str(path) for _, path in runtime if path.name not in ("libc.a", "libcrabc-builtins.a")}
direct_inputs.add(str(object_path))
archives = {str(library / "libc.a"), str(library / "libcrabc-builtins.a")}
seen = set()
for line in trace:
    if line in direct_inputs:
        seen.add(line)
    elif any(line == archive or (line.startswith(archive + "(") and line.endswith(")"))
             for archive in archives):
        seen.add(next(archive for archive in archives
                      if line == archive or (line.startswith(archive + "(") and line.endswith(")"))))
    else:
        fail(f"trace escaped the owned inputs: {line}")
if seen != direct_inputs | archives:
    fail("trace omitted an owned or workload input")
map_text = receipt_path.with_suffix(".map").read_text(encoding="utf-8")
for pattern in (r"/opt/musl-", r"/usr/lib/(gcc|clang)", r"/lib/ld-",
                r"crt(begin|end)", r"lib(gcc|ssp|atomic)", r"compiler-rt", r"libc\.so"):
    if re.search(pattern, "\n".join(trace) + "\n" + map_text, flags=re.IGNORECASE):
        fail(f"evidence contains an ambient target runtime input: {pattern}")

header = Path(str(consumer) + ".header").read_text(encoding="utf-8")
segments = Path(str(consumer) + ".segments").read_text(encoding="utf-8")
dynamic = Path(str(consumer) + ".dynamic").read_text(encoding="utf-8")
if (not re.search(r"Type:\s+" + expected[2] + r"\s", header) or
        "Advanced Micro Devices X86-64" not in header):
    fail("consumer ELF type or machine drifted")
if "INTERP" in segments or "Shared library:" in dynamic:
    fail("consumer acquired a dynamic runtime")
PY_STATIC
}

assert_static_receipt_tampering_rejected() {
    local product="$1" consumer="$2" mode="$3" object="$4" receipt="$5"
    local forged_root="$work/forged-static-receipts-$mode" label expected stderr
    python3 -B - "$receipt" "$forged_root" <<'PY_TAMPER'
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys

receipt_path = Path(sys.argv[1])
forged_root = Path(sys.argv[2])
record = json.loads(receipt_path.read_text(encoding="utf-8"))
source_map = receipt_path.with_suffix(".map")
source_trace = receipt_path.with_suffix(".trace")

for label in ("application", "runtime", "output"):
    destination = forged_root / label
    destination.mkdir(parents=True)
    forged = destination / receipt_path.name
    forged_map = forged.with_suffix(".map")
    forged_trace = forged.with_suffix(".trace")
    shutil.copyfile(source_map, forged_map)
    shutil.copyfile(source_trace, forged_trace)
    changed = deepcopy(record)
    changed["map"] = {"path": forged_map.name, "sha256": sha256(forged_map.read_bytes()).hexdigest()}
    changed["trace"] = {"path": forged_trace.name, "sha256": sha256(forged_trace.read_bytes()).hexdigest()}
    if label == "application":
        changed["input_receipts"][-1]["sha256"] = "0" * 64
    elif label == "runtime":
        changed["input_receipts"][0]["path"] = "usr/lib/forged-crt.o"
    else:
        changed["output"]["sha256"] = "0" * 64
    forged.write_text(json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY_TAMPER
    for label in application runtime output; do
        case "$label" in
            application|runtime)
                expected='process-control static receipt runtime or workload input receipt drifted'
                ;;
            output)
                expected='process-control static receipt output identity drifted'
                ;;
        esac
        stderr="$forged_root/$label/audit.stderr"
        if assert_static_receipt_and_elf "$product" "$consumer" "$mode" "$object" \
            "$forged_root/$label/$(basename "$receipt")" \
            >"$forged_root/$label/audit.stdout" 2>"$stderr"; then
            printf 'process-control static receipt audit accepted %s tampering\n' "$label" >&2
            return 1
        fi
        if ! grep -Fxq "$expected" "$stderr"; then
            printf 'process-control static receipt %s tampering reported the wrong failure\n' \
                "$label" >&2
            cat "$stderr" >&2
            return 1
        fi
    done
}

assert_static_manifest_tampering_rejected() {
    local product="$1" consumer="$2" mode="$3" object="$4" receipt="$5"
    local forged_product="$work/forged-static-manifest"
    local receipt_root="$work/forged-static-manifest-receipt"
    local forged_receipt="$receipt_root/$(basename "$receipt")"
    local expected='process-control static receipt manifest/runtime identity drifted: libc'
    cp -a "$product" "$forged_product"
    python3 -B - "$product" "$forged_product" "$receipt" "$forged_receipt" <<'PY_REBIND'
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys

source_product = Path(sys.argv[1]).resolve()
forged_product = Path(sys.argv[2]).resolve()
source_receipt = Path(sys.argv[3]).resolve()
forged_receipt = Path(sys.argv[4])
record = json.loads(source_receipt.read_text(encoding="utf-8"))
source_map = source_receipt.with_suffix(".map")
source_trace = source_receipt.with_suffix(".trace")
forged_receipt.parent.mkdir(parents=True)
forged_map = forged_receipt.with_suffix(".map")
forged_trace = forged_receipt.with_suffix(".trace")

def rebind(data):
    return data.replace(str(source_product).encode(), str(forged_product).encode())

if str(source_product) not in "\n".join(record.get("owned_link_contract", [])):
    raise SystemExit("process-control static manifest tamper fixture lacks the source contract root")
if str(source_product).encode() not in source_trace.read_bytes():
    raise SystemExit("process-control static manifest tamper fixture lacks the source trace root")
shutil.copyfile(source_map, forged_map)
forged_trace.write_bytes(rebind(source_trace.read_bytes()))
record["owned_link_contract"] = [
    field.replace(str(source_product), str(forged_product))
    if isinstance(field, str) else field
    for field in record["owned_link_contract"]
]
record["map"] = {"path": forged_map.name, "sha256": sha256(forged_map.read_bytes()).hexdigest()}
record["trace"] = {"path": forged_trace.name, "sha256": sha256(forged_trace.read_bytes()).hexdigest()}
forged_receipt.write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
PY_REBIND
    # First prove the copied product and rebound receipt form a valid receipt
    # boundary. The later failure then isolates the manifest mutation itself.
    assert_static_receipt_and_elf "$forged_product" "$consumer" "$mode" "$object" \
        "$forged_receipt"
    python3 -B - "$forged_product/share/crabc/manifest.json" <<'PY_MANIFEST'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
manifest["installed"]["files"]["usr/lib/libc.a"] = "0" * 64
path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY_MANIFEST
    if assert_static_receipt_and_elf "$forged_product" "$consumer" "$mode" "$object" "$forged_receipt" \
        >"$receipt_root/manifest-tamper.stdout" 2>"$receipt_root/manifest-tamper.stderr"; then
        printf 'process-control static receipt audit accepted manifest tampering\n' >&2
        return 1
    fi
    if ! grep -Fxq "$expected" "$receipt_root/manifest-tamper.stderr"; then
        printf 'process-control static receipt manifest tampering reported the wrong failure\n' >&2
        cat "$receipt_root/manifest-tamper.stderr" >&2
        return 1
    fi
}

assert_dynamic_symbols() {
    local shared="$1" symbols="$work/dynamic-symbols.txt" symbol
    readelf --dyn-syms -W "$shared" >"$symbols"
    for symbol in $RESIDUAL_SYMBOLS; do
        [ "$(awk -v symbol="$symbol" '$4 == "FUNC" && $5 ~ /^(GLOBAL|WEAK)$/ && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] || {
            printf 'process-control dynamic provider missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_receipt_and_elf() {
    local product="$1" consumer="$2" mode="$3" object="$4"
    local receipt="${consumer}.crabc-link.json"
    readelf -hW "$consumer" >"${consumer}.header"
    readelf -lW "$consumer" >"${consumer}.segments"
    readelf -dW "$consumer" >"${consumer}.dynamic"
    python3 -B - "$product" "$consumer" "$mode" "$object" "$receipt" <<'PY'
from hashlib import sha256
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
consumer = Path(sys.argv[2]).resolve()
mode = sys.argv[3]
object_path = Path(sys.argv[4]).resolve()
receipt_path = Path(sys.argv[5]).resolve()
digest = lambda path: sha256(path.read_bytes()).hexdigest()
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
manifest = root / "share/crabc/manifest.json"
expected_runtime = sorted("usr/lib/" + entry for entry in (
    "Scrt1.o" if mode == "pie" else "crt1.o",
    "crabc-dynamic-attach.o", "crti.o", "libc.so", "libcrabc-builtins.a", "crtn.o",
))
if receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-owned-dynamic-sysroot-v1":
    raise SystemExit("process-control dynamic receipt schema drifted")
if receipt.get("mode") != ("pie" if mode == "pie" else "exec") or receipt.get("binding") != "now":
    raise SystemExit("process-control dynamic receipt mode drifted")
if receipt.get("runtime_imports") != [] or receipt.get("application_dsos") != {}:
    raise SystemExit("process-control dynamic receipt has an application runtime dependency")
if receipt.get("output_path") != str(consumer) or receipt.get("output_sha256") != digest(consumer):
    raise SystemExit("process-control dynamic receipt consumer identity drifted")
if receipt.get("manifest_sha256") != digest(manifest):
    raise SystemExit("process-control dynamic receipt uses another installed product")
if receipt.get("owned_runtime_inputs") != expected_runtime or not receipt.get("link_trace"):
    raise SystemExit("process-control dynamic runtime roster or trace drifted")
records = receipt.get("input_receipts")
if not isinstance(records, list) or not any(Path(record.get("path", "")).resolve() == object_path for record in records):
    raise SystemExit("process-control dynamic receipt omits the one workload object")
for record in records:
    path = Path(record.get("path", ""))
    if not path.is_file() or record.get("sha256") != digest(path):
        raise SystemExit("process-control dynamic receipt input identity drifted")
header = Path(str(consumer) + ".header").read_text(encoding="utf-8")
segments = Path(str(consumer) + ".segments").read_text(encoding="utf-8")
dynamic = Path(str(consumer) + ".dynamic").read_text(encoding="utf-8")
if ("DYN" if mode == "pie" else "EXEC") not in header or "Advanced Micro Devices X86-64" not in header:
    raise SystemExit("process-control consumer ELF type or machine drifted")
if "Requesting program interpreter: /lib/ld-crabc-x86_64.so.1" not in segments:
    raise SystemExit("process-control consumer interpreter drifted")
if "Shared library: [libc.so]" not in dynamic or "/opt/musl-" in dynamic or "libc.so.6" in dynamic:
    raise SystemExit("process-control consumer dynamic dependency drifted")
PY
}

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-sysroot"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

# Compile exactly once through the installed product.  This object is then the
# common input to musl, static, static-PIE, dynamic PIE, and dynamic non-PIE.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    '-DCRABC_PROCESS_CONTROL_EXECUTABLE="/consumer"' -c "$PROBE" \
    -o "$work/workload.o" >"$work/workload-compile.stdout"

mkdir "$work/oracle-root"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" \
    -o "$work/oracle-root/consumer"
run_in_root "$work/oracle-root" "$work/oracle.stdout" /consumer
[ ! -s "$work/oracle.stderr" ]
grep -qx 'owned-process-control-ok fexecve-seccomp=9' "$work/oracle.stdout"
printf '%s\n' 'owned-process-control-ok fexecve-seccomp=38' >"$work/crabc.expected"

if [ -z "${1:-}" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    assert_static_symbols "$work/static-sysroot/usr/lib/libc.a"
    for mode in static static-pie; do
        consumer="$work/consumer-$mode"
        receipt="$work/consumer-$mode.receipt.json"
        (
            cd "$work"
            "$work/static-sysroot/bin/crabc-cc" "-$mode" \
                --link-receipt "$(basename "$receipt")" "$work/workload.o" -o "$consumer"
        )
        assert_static_receipt_and_elf "$work/static-sysroot" "$consumer" "$mode" \
            "$work/workload.o" "$receipt"
        assert_static_receipt_tampering_rejected "$work/static-sysroot" "$consumer" "$mode" \
            "$work/workload.o" "$receipt"
        if [ "$mode" = static ]; then
            assert_static_manifest_tampering_rejected "$work/static-sysroot" "$consumer" "$mode" \
                "$work/workload.o" "$receipt"
        fi
        mkdir "$work/$mode-root"
        cp "$consumer" "$work/$mode-root/consumer"
        run_in_root "$work/$mode-root" "$work/$mode.stdout" /consumer
        [ ! -s "$work/$mode.stderr" ]
        cmp "$work/crabc.expected" "$work/$mode.stdout"
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so"
for mode in pie non-pie; do
    consumer="$work/consumer-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$consumer"
    assert_dynamic_receipt_and_elf "$installed" "$consumer" "$mode" "$work/workload.o"
    for entry in kernel direct; do
        root="$work/$mode-$entry-root"
        cp -a "$installed" "$root"
        cp "$consumer" "$root/consumer"
        if [ "$entry" = direct ]; then
            run_in_root "$root" "$work/$mode-$entry.stdout" \
                /lib/ld-crabc-x86_64.so.1 /consumer
        else
            run_in_root "$root" "$work/$mode-$entry.stdout" /consumer
        fi
        [ ! -s "$work/$mode-$entry.stderr" ]
        cmp "$work/crabc.expected" "$work/$mode-$entry.stdout"
    done
done

printf '%s\n' 'owned process-control: PASS (one installed object; musl/static/static-PIE/dynamic PIE/non-PIE kernel/direct; residual exec aliases, Linux-5.10 fexecve direct execveat ENOSYS distinction, child-contained nice/session mutations, deterministic waits, and complete spawnattr roundtrips)'
