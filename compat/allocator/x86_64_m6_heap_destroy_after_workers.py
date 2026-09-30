#!/usr/bin/env python3
"""Compare destruction of a Heap used by two exited workers."""

import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("callback_lifetime_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-heap-destroy-after-workers"
TITLE = "Heap destroy after workers"
MANAGED = False

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_destroy_after_workers_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-destroy-after-workers"
BEGIN = "CRABC_MI_M6_HEAP_DESTROY_AFTER_WORKERS_BEGIN"
END = "CRABC_MI_M6_HEAP_DESTROY_AFTER_WORKERS_END"
EXPECTED = {
    "workers.first": "1,1",
    "workers.second": "1,1,1,1",
    "workers.destroy": "37,0,0,0",
    "workers.stats": "-3,0",
    "workers.collect": "0,0,0",
}


def record(output, name, argv, cwd, runtime=False):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ), timeout=60 if runtime else 3600)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream in result:
            path = output / f"{name}.{stream}"
            path.write_bytes(stress.byte_record_payload(result[stream], name))
            logs.append(path)
    return result, logs


def run_profiles(profiles):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    print(f"{TITLE} raw products: {output}", flush=True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures = {}, [], []
    fixture = output / DRIVER.name
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE", archive):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "boundary": "public native-mi-adapter over pinned musl threads",
        "fixture": DRIVER.name}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    for profile in profiles:
        directory = output / profile
        directory.mkdir()
        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))
        common = ["-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include"),
                  "-I", str(source / "src")]
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
        results, runtime_logs = {}, {}
        for backend, allocator in (("c", oracle), ("native", retained_library)):
            binary = directory / backend
            caller = directory / f"{backend}.o"
            internal = ["-DCRABC_M6_SOURCE_INTERNAL=1"] if MANAGED and backend == "c" else []
            passed(f"{backend}-compile", [compiler, "-std=c11", *common, *internal,
                "-c", str(fixture), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            result, logs = record(output, f"{profile}-{backend}-run", [str(binary)], directory, True)
            status = result.get("status", 1) if result["kind"] == "process" else 1
            cases.append((f"{profile}-{backend}-run", status, logs))
            results[backend], runtime_logs[backend] = result, logs
            if status != 0:
                failures.append(f"{profile}-{backend}: runtime status {status}; actual raw in {logs[0]}")
        comparison_logs = runtime_logs["c"] + runtime_logs["native"]
        try:
            c_stdout = stress.byte_record_payload(results["c"]["stdout"], profile).decode()
            c_stderr = stress.byte_record_payload(results["c"]["stderr"], profile).decode()
            native_stdout = stress.byte_record_payload(results["native"]["stdout"], profile).decode()
            native_stderr = stress.byte_record_payload(results["native"]["stderr"], profile).decode()
            c_trace = m7.parse_options_trace(c_stdout, "C " + TITLE, BEGIN, END)
            native_trace = m7.parse_options_trace(native_stdout, "native " + TITLE, BEGIN, END)
            if profile == "release" and c_trace != EXPECTED:
                raise harness.HarnessError(f"pinned release trace changed: {c_trace}")
            if set(c_trace) != set(EXPECTED):
                raise harness.HarnessError(f"pinned {profile} trace fields changed: {c_trace}")
            m7.compare_options_traces(c_trace, native_trace)
            if MANAGED:
                source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$", c_stderr, re.MULTILINE))
                if source_rows != {"source.callback": "1,1"}:
                    raise harness.HarnessError(f"pinned callback source image changed: {source_rows}")
                if c_stderr.count(WARNING) != 1 or native_stderr.count(WARNING) != 1:
                    raise harness.HarnessError("managed callback rejection warning differs")
            elif c_stderr != native_stderr:
                raise harness.HarnessError("Heap destruction diagnostics differ")
        except (harness.HarnessError, UnicodeError) as error:
            failures.append(f"{profile}: {error}; raw in {output}")
            cases.append((f"{profile}-comparison", 1, comparison_logs))
        else:
            cases.append((f"{profile}-comparison", 0, comparison_logs))
        print(f"{TITLE} {profile}: actual C/native compared; failures={len(failures)}", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during callback lifetime execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), "boundary": "public native-mi-adapter over pinned musl"}, True)
    if failures:
        for failure in failures:
            print(f"RED: {failure}", flush=True)
        raise harness.HarnessError(f"{TITLE} has {len(failures)} failures; physical receipt {path}")
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"{TITLE}: selected profiles PASS; {path}")
    return len(EXPECTED)


def run_differential():
    return run_profiles(("release",))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", action="store_true", help="run all four selected profiles")
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run_profiles(PROFILES if args.matrix else ("release",))
        return
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    profiles = tuple(receipt.parameters["profiles"].split(","))
    if args.matrix and profiles != PROFILES:
        raise harness.HarnessError("retained receipt does not cover all selected profiles")
    print(f"{TITLE} exact-source physical receipt: PASS")
    if args.replay:
        harness.require_native_x86_64(require_image_identity=True)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="callback-lifetime-replay-", dir=harness.TEMP_ROOT))
        for profile in profiles:
            for backend in ("c", "native"):
                product = f"{profile}-{backend}"
                binary = scratch / product
                shutil.copyfile(receipt.path.parent / "products" / product, binary)
                binary.chmod(0o755)
                case = f"{product}-run"
                result, logs = record(scratch, case, [str(binary)], scratch, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained caller {case} failed; see {logs[0]}")
                recorded = next(c for c in receipt.cases if c["id"] == case)
                for stream in ("stdout", "stderr"):
                    original = next(p for p in recorded["logs"] if p.endswith("." + stream))
                    if stress.byte_record_payload(result[stream], case) != (receipt.path.parent / "logs" / original).read_bytes():
                        raise harness.HarnessError(f"retained caller {case} {stream} differs; see {scratch}")
        print(f"{TITLE} retained physical replay: selected C/native pairs PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"{TITLE} failed: {error}", file=sys.stderr)
        raise SystemExit(1)
