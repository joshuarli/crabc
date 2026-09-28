#!/usr/bin/env bash
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || { echo "usage: $0 DYNAMIC-SYSROOT" >&2; exit 2; }
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) echo "TMPDIR must be under $ROOT/.work" >&2; exit 2;; esac
exec python3 -B - "$ROOT" "$1" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1])
product = Path(sys.argv[2])
runner = root / "compat/ldso/run_x86.py"
command = [sys.executable, "-B", str(runner), "--dynamic-sysroot", str(product)]
provenance = product / "share/crabc/libc-shared.provenance.json"
try:
    backend = json.loads(provenance.read_text()).get("allocator_backend")
except (OSError, ValueError):
    backend = None
if backend != "native-shadow":
    os.execv(sys.executable, command)

sys.path.insert(0, str(root / "compat/x86_64"))
from native_shadow_receipt import receipt_directory, source_seal, write_receipt

receipt_runner = "owned-loader-synthetic"
latest = receipt_directory(root, receipt_runner)
if latest.exists():
    shutil.rmtree(latest)
source_before = source_seal(root)
completed = subprocess.run(command, cwd=root, capture_output=True)
sys.stdout.buffer.write(completed.stdout)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(completed.stderr)
sys.stderr.buffer.flush()
prefix = b"owned synthetic loader evidence: "
evidence = [line[len(prefix):] for line in completed.stdout.splitlines() if line.startswith(prefix)]
if len(evidence) != 1:
    raise SystemExit(completed.returncode or 1)
work = Path(os.fsdecode(evidence[0]))
if work.parent != root / ".work/x86_64" or not work.is_dir() or work.is_symlink():
    raise SystemExit("owned-loader-synthetic: unsafe evidence directory")
(work / "runner.stdout").write_bytes(completed.stdout)
(work / "runner.stderr").write_bytes(completed.stderr)
(work / "runner.status").write_text(f"{completed.returncode}\n")
report = json.loads((work / "report.json").read_text())
if completed.returncode != 0 or report.get("component_complete") is not True:
    raise SystemExit(completed.returncode or 1)
if source_seal(root) != source_before:
    raise SystemExit("owned-loader-synthetic: source changed during the run")

selected = report["selected"]
cases = []
for name in selected:
    case = work / "cases" / name
    raw = case / "raw"
    logs = [case / "case.json", *sorted(raw.iterdir())]
    if report["cases"][name]["status"] != "pass" or not all(path.is_file() for path in logs):
        raise SystemExit(f"owned-loader-synthetic: incomplete {name} workload")
    cases.append((name, 0, logs))
cases.append(("runner", completed.returncode,
              [work / "runner.stdout", work / "runner.stderr", work / "runner.status", work / "report.json"]))

products = {
    "dynamic-loader": product / "lib/ld-crabc-x86_64.so.1",
    "dynamic-libc": product / "usr/lib/libc.so",
    "dynamic-driver": product / "bin/crabc-cc-dynamic",
    "dynamic-driver-shared": product / "share/crabc/crabc_cc_static.py",
    "dynamic-manifest": product / "share/crabc/manifest.json",
    "dynamic-libc-provenance": provenance,
    "dynamic-product-state": product / "share/crabc/dynamic-product-state.json",
    "dynamic-scrt": product / "usr/lib/Scrt1.o",
    "dynamic-crti": product / "usr/lib/crti.o",
    "dynamic-crtn": product / "usr/lib/crtn.o",
    "dynamic-attach": product / "usr/lib/crabc-dynamic-attach.o",
    "dynamic-builtins": product / "usr/lib/libcrabc-builtins.a",
    "pinned-musl-libc": Path("/opt/musl-1.2.6/lib/libc.so"),
    "pinned-musl-compiler": Path("/usr/local/bin/crabc-x86_64-musl-gcc"),
}
baseline = {entry["path"]: entry for entry in report["product_before"]["entries"]}
oracle_libc = report["oracle_before"]["libc_sha256"]
fixtures = []
symlinks = []
for name in selected:
    case = work / "cases" / name
    index = 0
    for path in sorted(case.rglob("*")):
        relative = path.relative_to(case)
        if relative.parts[0] == "raw" or relative.as_posix() == "case.json":
            continue
        if path.is_symlink():
            symlinks.append({"path": path.relative_to(work).as_posix(), "target": os.readlink(path)})
            continue
        if not path.is_file():
            continue
        arm_path = Path(*relative.parts[1:]).as_posix()
        if relative.parts[0] == "candidate-root":
            original = baseline.get(arm_path)
            if original and original.get("kind") == "file" and original["size"] == path.stat().st_size:
                if hashlib.sha256(path.read_bytes()).hexdigest() == original["sha256"]:
                    continue
        if relative.parts[0] == "oracle-root" and arm_path in {
            "lib/ld-musl-x86_64.so.1", "usr/lib/libc.so",
        } and hashlib.sha256(path.read_bytes()).hexdigest() == oracle_libc:
            continue
        product_name = f"fixture-{name}-{index:04d}"
        index += 1
        products[product_name] = path
        fixtures.append({"product": product_name, "path": path.relative_to(work).as_posix(),
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})

fixture_hashes = {entry["sha256"] for entry in fixtures}
for name in selected:
    for link in report["cases"][name]["links"]:
        if link["output_sha256"] not in fixture_hashes or link["object_sha256"] not in fixture_hashes:
            raise SystemExit(f"owned-loader-synthetic: unretained linked fixture {link['output']}")
fixture_map = work / "fixture-map.json"
fixture_map.write_text(json.dumps({"fixtures": fixtures, "symlinks": symlinks}, indent=2, sort_keys=True) + "\n")
products["fixture-map"] = fixture_map
parameters = {
    "BACKEND": "native-shadow", "CASES": "21-frozen", "CASE_TIMEOUT": "20",
    "ORACLE": "pinned-musl", "PRODUCT": "supplied-dynamic-sysroot",
}
path = write_receipt(root, receipt_runner, work, products, cases, parameters, True)
if source_seal(root) != source_before:
    shutil.rmtree(latest)
    raise SystemExit("owned-loader-synthetic: source changed while publishing the receipt")
print(f"owned-loader-synthetic native-shadow receipt: {path}")
PY
