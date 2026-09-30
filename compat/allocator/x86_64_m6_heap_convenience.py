#!/usr/bin/env python3
"""Run pinned header-only Heap conveniences against C and native allocator exports.

C callers use pinned musl; C++ callers use the native image's musl/libstdc++
substrate. Neither caller overrides
global allocation. Only explicit mi_* calls exercise the allocator candidate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_convenience_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-heap-convenience"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-convenience"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
C_SOURCE = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_convenience_driver.c"
CXX_SOURCE = C_SOURCE.with_suffix(".cpp")


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
    # Expected abort processes need their signal and diagnostics, not core files.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    # Keep inputs and products after a partial failure as well as after success.
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (C_SOURCE, CXX_SOURCE, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "boundary": "explicit native mi_*; host musl and C++ standard library substrate",
        "header_sha256": hashlib.sha256((source / "include/mimalloc.h").read_bytes()).hexdigest(),
        "expected_abort": -signal.SIGABRT, "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap convenience raw products: {output}", flush=True)
    c_compiler, cxx_compiler = harness.require_tool("musl-gcc"), harness.require_tool("g++")
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
        passed("oracle-build", [c_compiler, "-std=c11", *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / "native-mi-adapter.a"
        shutil.copy2(library, retained_library)
        products[f"{profile}-native-mi-adapter.a"] = retained_library
        products[f"{profile}-oracle.o"] = oracle
        for language, compiler, fixture, flags in (
            ("c", c_compiler, C_SOURCE, ["-std=c11"]),
            ("cxx", cxx_compiler, CXX_SOURCE, ["-std=c++17", "-static-libstdc++", "-static-libgcc",
                "-Wl,--wrap=mi_heap_delete", "-Wl,--wrap=mi_heap_destroy"]),
        ):
            traces = {}
            for backend, allocator in (("c", oracle), ("native", retained_library)):
                binary = directory / f"{language}-{backend}"
                # Compile the actual caller separately, so the imported mi_*
                # entries can be inspected without attributing runtime code.
                caller = directory / f"{language}-{backend}.o"
                passed(f"{language}-{backend}-compile", [compiler, *flags, *common, "-c", str(fixture), "-o", str(caller)])
                passed(f"{language}-{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
                passed(f"{language}-{backend}-link", [compiler, *flags, str(caller), str(allocator), "-pthread", "-o", str(binary)])
                products[f"{profile}-{language}-{backend}"] = binary
                products[f"{profile}-{language}-{backend}.o"] = caller
                modes = ("normal",) if language == "c" else ("normal", "overflow-handler", "refusal-handler", "overflow-throw", "refusal-throw", "overflow-abort")
                for mode in modes:
                    name = f"{profile}-{language}-{backend}-{mode}"
                    args = [] if mode == "normal" else [mode]
                    result, logs = record(output, name, [str(binary), *args], directory, True)
                    expected_status = -signal.SIGABRT if mode == "overflow-abort" else 0
                    if result["kind"] != "process" or result["status"] != expected_status:
                        raise harness.HarnessError(f"{name} unexpected runtime result; see {logs[0]}")
                    stdout = stress.byte_record_payload(result["stdout"], name)
                    traces[backend, mode] = stdout
                    # Status zero here means the ordered case contract passed;
                    # the raw process record retains actual SIGABRT unchanged.
                    cases.append((name, 0, logs))
            for mode in modes:
                if traces["c", mode] != traces["native", mode]:
                    raise harness.HarnessError(f"{profile}-{language}-{mode}: C/native caller traces differ; raw in {output}")
        print(f"Heap convenience {profile}: actual C/native callers PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap convenience execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "explicit native-mi-adapter",
         "c-substrate": "pinned-musl-1.2.6", "cxx-substrate": "native-image-musl-libstdc++",
         "expected-overflow-abort": "SIGABRT", "watchdog-seconds": "60"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Heap convenience: all four profiles PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true", help="read existing exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read receipt and rerun retained caller products in private scratch")
    args = parser.parse_args()
    if args.read or args.replay:
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        print("Heap convenience exact-source physical receipt: PASS")
        if args.replay:
            harness.require_native_x86_64(require_image_identity=True)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="heap-convenience-replay-", dir=harness.TEMP_ROOT))
            print(f"Heap convenience reader raw executions: {scratch}", flush=True)
            for profile in PROFILES:
                for language in ("c", "cxx"):
                    for backend in ("c", "native"):
                        product = f"{profile}-{language}-{backend}"
                        binary = scratch / product
                        shutil.copyfile(receipt.path.parent / "products" / product, binary)
                        binary.chmod(0o755)
                        modes = ("normal",) if language == "c" else ("normal", "overflow-handler", "refusal-handler", "overflow-throw", "refusal-throw", "overflow-abort")
                        for mode in modes:
                            case = f"{product}-{mode}"
                            result, _ = record(scratch, case, [str(binary), *([] if mode == "normal" else [mode])], scratch, True)
                            expected = -signal.SIGABRT if mode == "overflow-abort" else 0
                            if result["kind"] != "process" or result["status"] != expected:
                                raise harness.HarnessError(f"retained caller {case} failed; see {scratch}")
                            recorded = next(c for c in receipt.cases if c["id"] == case)
                            stdout = next(p for p in recorded["logs"] if p.endswith(".stdout"))
                            if stress.byte_record_payload(result["stdout"], case) != (receipt.path.parent / "logs" / stdout).read_bytes():
                                raise harness.HarnessError(f"retained caller {case} output differs; see {scratch}")
            print("Heap convenience retained C/C++ caller replay: four profiles PASS")
    else:
        run()


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap convenience failed: {error}", file=sys.stderr)
        raise SystemExit(1)
