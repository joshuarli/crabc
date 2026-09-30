#!/usr/bin/env python3
"""Compare quiescent subprocess statistics and callback lifetime with pinned C."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_heap_convenience import record, receipts
from x86_64_m6_upstream_heap_stress import stress

RUNNER = "allocator-subproc-stats-lifetime"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_subproc_stats_lifetime_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-subproc-stats-lifetime"


def run(current_only=False):
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "include/mimalloc-stats.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "current_only": current_only, "boundary": "explicit native mi_*; pinned musl process/pthread substrate",
        "owners": "main/child/nested; condition-variable parked for foreign snapshots",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Subprocess statistics raw: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()
        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))
        common = [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *m4.api_profile_flags(profile), *(("-DCRABC_MI_SUBPROC_CURRENT_ONLY=1",) if current_only else ()), "-UNDEBUG", "-I", str(source / "include")]
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        traces = {}
        for backend, allocator in (("c", source / "src/static.c"), ("native", library)):
            binary = directory / backend
            passed(f"{backend}-link", [*common, str(DRIVER), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            result, logs = record(output, f"{profile}-{backend}-run", [str(binary)], directory, True)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{backend} runtime failure; see {logs[0]}")
            traces[backend] = stress.byte_record_payload(result["stdout"], backend)
            cases.append((f"{profile}-{backend}-run", 0, logs))
        if traces["c"] != traces["native"]:
            raise harness.HarnessError(f"{profile} subprocess statistics differ; raw in {output}")
        print(f"Subprocess statistics {profile}: C/native PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during subprocess statistics matrix")
    if current_only:
        print("Isolated current-subprocess statistics regression: PASS; full lifetime receipt remains separate")
        return
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "native-mi-adapter", "watchdog-seconds": "60",
         "ownership": "main-child-nested; joined then nested-before-parent destruction"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Subprocess statistics lifetime: PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-only", action="store_true", help="run the existing-export current-subprocess regression without publishing lifetime admission")
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run(args.current_only)
        return
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    print("Subprocess statistics exact-source physical receipt: PASS")
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
        harness.native_execution_attestation(inputs["execution"], execution)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="subproc-stats-replay-", dir=harness.TEMP_ROOT))
        print(f"Reader raw: {scratch}", flush=True)
        for profile in PROFILES:
            for backend in ("c", "native"):
                binary = scratch / f"{profile}-{backend}"
                shutil.copyfile(receipt.path.parent / "products" / binary.name, binary)
                binary.chmod(0o755)
                result, _ = record(scratch, binary.name, [str(binary)], scratch, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {binary.name} failed; see {scratch}")
                case = next(c for c in receipt.cases if c["id"] == f"{binary.name}-run")
                stdout = next(p for p in case["logs"] if p.endswith(".stdout"))
                if stress.byte_record_payload(result["stdout"], binary.name) != (receipt.path.parent / "logs" / stdout).read_bytes():
                    raise harness.HarnessError(f"retained {binary.name} statistics differ; see {scratch}")
        print("Subprocess statistics retained C/native replay: PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Subprocess statistics failed: {error}", file=sys.stderr)
        raise SystemExit(1)
