#!/usr/bin/env python3
"""Compare public Heap collection and reuse in the selected allocator profiles."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_heap_convenience import record
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_collect_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-heap-collect-profiles"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-collect-profiles"
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_collect_profiles_driver.c"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
STAGES = {
    "retained": ("retained_live", "retained_normal", "retained_forced", "retained_root",
                 "retained_empty", "retained_reuse", "retained_deleted"),
    "moved": ("moved_live", "moved_normal", "moved_forced", "moved_reuse", "moved_empty"),
    "child": ("child_live", "child_normal", "child_forced", "child_empty", "child_reuse",
              "child_reuse_collect", "child_joined"),
}
BEGIN, END = "CRABC_MI_HEAP_COLLECT_BEGIN", "CRABC_MI_HEAP_COLLECT_END"


def run():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "scenarios": STAGES, "runtime_watchdog_seconds": 60,
        "boundary": "explicit native mi_*; pinned musl supplies C and joined pthread substrate",
        "fixture_sha256": hashlib.sha256(DRIVER.read_bytes()).hexdigest(),
        "page_requests": [80, 256 * 1024 + 17, 10 * 1024 + 1], "alignment": 4096,
        "hardware_large_pages": False}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap collection raw products: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))

        common = ["-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include")]
        oracle = directory / "oracle.o"
        passed("oracle-build", [compiler, *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        products[f"{profile}-oracle.o"] = oracle
        traces = {}
        for backend, allocator in (("c", oracle), ("native", library)):
            caller = directory / f"{backend}.o"
            binary = directory / backend
            passed(f"{backend}-compile", [compiler, *common, "-c", str(DRIVER), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            for scenario, stages in STAGES.items():
                name = f"{profile}-{backend}-{scenario}"
                result, logs = record(output, name, [str(binary), scenario], directory, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"{name} unsuccessful; see {logs[0]}")
                stdout = stress.byte_record_payload(result["stdout"], name)
                trace = m7.parse_options_trace(stdout.decode(), name, BEGIN, END)
                expected = {f"collect.{stage}": "1,1,1" for stage in stages}
                if trace != expected:
                    raise harness.HarnessError(f"{name}: caller observations differ: {trace}")
                traces[backend, scenario] = stdout
                cases.append((name, 0, logs))
        for scenario in STAGES:
            if traces["c", scenario] != traces["native", scenario]:
                raise harness.HarnessError(f"{profile}-{scenario}: C/native trace differs; raw in {output}")
        print(f"Heap collection {profile}: all three actual C/native callers PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap collection execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "scenarios": ",".join(STAGES),
         "boundary": "explicit native-mi-adapter", "c-substrate": "pinned-musl-1.2.6",
         "watchdog-seconds": "60", "hardware-large-pages": "disabled"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Heap collection: all four profiles PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true", help="read existing exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read receipt and rerun all retained callers")
    args = parser.parse_args()
    if args.read or args.replay:
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        print("Heap collection exact-source physical receipt: PASS")
        if args.replay:
            harness.require_native_x86_64(require_image_identity=True)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="heap-collect-replay-", dir=harness.TEMP_ROOT))
            print(f"Heap collection reader raw executions: {scratch}", flush=True)
            for profile in PROFILES:
                for backend in ("c", "native"):
                    product = f"{profile}-{backend}"
                    binary = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, binary)
                    binary.chmod(0o755)
                    for scenario in STAGES:
                        case = f"{product}-{scenario}"
                        result, _ = record(scratch, case, [str(binary), scenario], scratch, True)
                        if result["kind"] != "process" or result["status"] != 0:
                            raise harness.HarnessError(f"retained caller {case} unsuccessful; see {scratch}")
                        recorded = next(c for c in receipt.cases if c["id"] == case)
                        stdout = next(p for p in recorded["logs"] if p.endswith(".stdout"))
                        if stress.byte_record_payload(result["stdout"], case) != (receipt.path.parent / "logs" / stdout).read_bytes():
                            raise harness.HarnessError(f"retained caller {case} output differs; see {scratch}")
            print("Heap collection retained C/native caller replay: four profiles PASS")
    else:
        run()


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap collection failed: {error}", file=sys.stderr)
        raise SystemExit(1)
