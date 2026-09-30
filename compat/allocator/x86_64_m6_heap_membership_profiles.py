#!/usr/bin/env python3
"""Compare retained live Heap membership and quiescent utilization with pinned C."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_membership_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-heap-membership-profiles"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-membership-profiles"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_membership_profiles_driver.c"

def record(output, name, argv, cwd, runtime=False):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ), timeout=60 if runtime else 3600)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream not in result:
            continue
        path = output / f"{name}.{stream}"
        path.write_bytes(stress.byte_record_payload(result[stream], name))
        logs.append(path)
    return result, logs


def run():
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
        "profiles": PROFILES, "boundary": "retained live clients and Heaps; quiescent utilization",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap membership raw products: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))

        common = ["-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include")]
        oracle = directory / "oracle.o"
        passed("oracle-build", [compiler, "-std=c11", *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / "native-mi-adapter.a"
        shutil.copy2(library, retained_library)
        products[f"{profile}-native-mi-adapter.a"] = retained_library
        products[f"{profile}-oracle.o"] = oracle
        traces = {}
        for backend, allocator in (("c", oracle), ("native", retained_library)):
            binary = directory / backend
            caller = directory / f"{backend}.o"
            passed(f"{backend}-compile", [compiler, "-std=c11", *common, "-c", str(DRIVER), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            name = f"{profile}-{backend}-run"
            result, logs = record(output, name, [str(binary)], directory, True)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{name} failed; see {logs[0]}")
            cases.append((name, 0, logs))
            traces[backend] = tuple(stress.byte_record_payload(result[stream], name)
                for stream in ("stdout", "stderr"))
        if traces["c"] != traces["native"]:
            raise harness.HarnessError(f"{profile}: exact C/native membership traces differ; raw in {output}")
        print(f"Heap membership {profile}: actual C/native PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap membership execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "retained-clients-quiescent-utilization",
         "c-substrate": "pinned-musl-1.2.6", "watchdog-seconds": "60"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Heap membership four-profile original receipt: PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run()
        return
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    print("Heap membership exact-source original physical receipt: PASS")
    if args.replay:
        harness.require_native_x86_64(require_image_identity=True)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="heap-membership-replay-", dir=harness.TEMP_ROOT))
        print(f"Heap membership reader executions: {scratch}", flush=True)
        for profile in PROFILES:
            for backend in ("c", "native"):
                product = f"{profile}-{backend}"
                binary = scratch / product
                shutil.copyfile(receipt.path.parent / "products" / product, binary)
                binary.chmod(0o755)
                name = f"{product}-run"
                result, _ = record(scratch, name, [str(binary)], scratch, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained caller {name} failed; see {scratch}")
                recorded = next(c for c in receipt.cases if c["id"] == name)
                for stream in ("stdout", "stderr"):
                    path = next(p for p in recorded["logs"] if p.endswith("." + stream))
                    if stress.byte_record_payload(result[stream], name) != (receipt.path.parent / "logs" / path).read_bytes():
                        raise harness.HarnessError(f"retained caller {name} {stream} differs; see {scratch}")
        print("Heap membership retained physical replay: four profiles PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap membership failed: {error}", file=sys.stderr)
        raise SystemExit(1)
