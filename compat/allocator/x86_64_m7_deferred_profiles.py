#!/usr/bin/env python3
"""Compare public deferred-free callbacks in four native allocator profiles."""

import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("deferred_profile_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-deferred-profiles"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m7-deferred-profiles"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
MODES = ("same", "null", "worker", "same-small", "null-small", "worker-small")
FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_deferred_profiles_driver.c"

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
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    print(f"Deferred public caller raw products: {output}", flush=True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures = {}, [], []
    for original in (FIXTURE, source / "include/mimalloc.h", source / "LICENSE", archive):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "modes": MODES, "boundary": "explicit public mi_* over pinned musl threads"}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()
        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))
        common = ["-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
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
        traces, runtime_logs = {}, {}
        for backend, allocator in (("c", oracle), ("native", retained_library)):
            binary = directory / backend
            caller = directory / f"{backend}.o"
            passed(f"{backend}-compile", [compiler, "-std=c11", *common, "-c", str(FIXTURE), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            for mode in MODES:
                name = f"{profile}-{backend}-{mode}"
                result, logs = record(output, name, [str(binary), mode], directory, True)
                status = result.get("status", 1) if result["kind"] == "process" else 1
                if status != 0:
                    failures.append(f"{name}: runtime status {status}; actual raw in {logs[0]}")
                traces[backend, mode] = stress.byte_record_payload(result["stdout"], name)
                cases.append((name, status, logs))
                runtime_logs[backend, mode] = logs
        for mode in MODES:
            different = traces["c", mode] != traces["native", mode]
            cases.append((f"{profile}-comparison-{mode}", int(different),
                runtime_logs["c", mode] + runtime_logs["native", mode]))
            if different:
                failures.append(f"{profile}-{mode}: actual C/native callback traces differ; raw in {output}")
        print(f"Deferred public caller {profile}: compared all six C/native pairs; failures={len(failures)}", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during public deferred caller execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "contexts": ",".join(MODES), "boundary": "public native-mi-adapter over pinned musl"}, True)
    if failures:
        for failure in failures:
            print(f"RED: {failure}", flush=True)
        raise harness.HarnessError(f"public deferred caller has {len(failures)} failures; physical receipt {path}")
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Deferred public caller: four profiles PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run()
        return
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    print("Deferred public caller exact-source physical receipt: PASS")
    if args.replay:
        harness.require_native_x86_64(require_image_identity=True)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="deferred-replay-", dir=harness.TEMP_ROOT))
        for profile in PROFILES:
            for backend in ("c", "native"):
                product = f"{profile}-{backend}"
                binary = receipt.path.parent / "products" / product
                for mode in MODES:
                    case = f"{product}-{mode}"
                    result, logs = record(scratch, case, [str(binary), mode], scratch, True)
                    if result["kind"] != "process" or result["status"] != 0:
                        raise harness.HarnessError(f"retained caller {case} failed; see {logs[0]}")
                    recorded = next(c for c in receipt.cases if c["id"] == case)
                    stdout = next(p for p in recorded["logs"] if p.endswith(".stdout"))
                    if stress.byte_record_payload(result["stdout"], case) != (receipt.path.parent / "logs" / stdout).read_bytes():
                        raise harness.HarnessError(f"retained caller {case} output differs; see {scratch}")
        print("Deferred public caller retained physical replay: twenty-four C/native pairs PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Deferred public caller failed: {error}", file=sys.stderr)
        raise SystemExit(1)
