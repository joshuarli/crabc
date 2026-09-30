#!/usr/bin/env python3
"""Compare public external arena capacity, partial publication and destruction."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_heap_convenience import record, receipts
from x86_64_m6_upstream_heap_stress import stress

RUNNER = "allocator-management-capacity"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m2_management_capacity_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-management-capacity"
SOURCE_AUDIT = b"source.capacity=1,1,1,1,1\n"


def run():
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures, c_runs = {}, [], [], {}
    for original in (DRIVER, archive, source / "include/mimalloc.h",
                     source / "include/mimalloc-stats.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "boundary": "public native-mi-adapter over pinned musl",
        "ownership": "distinct external spans; live child; joined exit; destroy; caller release",
        "capacity": 160, "partial-parent-bytes": 16 * 1024**3,
        "runtime-watchdog-seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Management capacity raw: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")

    def passed(name, argv, cwd=source):
        result, logs = record(output, name, argv, cwd)
        if result["kind"] != "process" or result["status"] != 0:
            raise harness.HarnessError(f"{name} failed; see {logs[0]}")
        cases.append((name, 0, logs))

    def runtime(profile, backend):
        binary = output / profile / backend
        products[f"{profile}-{backend}"] = binary
        result, logs = record(output, f"{profile}-{backend}-run", [str(binary)], binary.parent, True)
        status = result.get("status", 1) if result["kind"] == "process" else 1
        cases.append((f"{profile}-{backend}-run", status, logs))
        if status != 0:
            failures.append(f"{profile}-{backend} runtime status {status}; see {logs[0]}")
        return result, logs

    # Establish every selected source configuration before building a native
    # candidate. The source assertions check real live identities and ranges.
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()
        common = [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
            "-DMI_LIBC_MUSL=1", *m4.api_profile_flags(profile), "-UNDEBUG",
            "-I", str(source / "include"), "-I", str(source / "src")]
        passed(f"{profile}-c-link", [*common, "-DCRABC_SOURCE_AUDIT=1",
            str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(directory / "c")])
        result, logs = runtime(profile, "c")
        c_runs[profile] = result, logs
        if stress.byte_record_payload(result["stderr"], profile) != SOURCE_AUDIT:
            failures.append(f"{profile} pinned live source geometry/diagnostic audit differs; see {logs[0]}")
        print(f"Management capacity {profile}: original C caller completed", flush=True)
    if failures:
        raise harness.HarnessError("; ".join(failures))

    target = output / "cargo-target"
    for profile in PROFILES:
        directory = output / profile
        passed(f"{profile}-native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline",
            "--release", "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE,
            "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        passed(f"{profile}-native-link", [compiler, "-std=c11", "-D_GNU_SOURCE", "-UNDEBUG",
            "-I", str(source / "include"), str(DRIVER), str(library), "-pthread", "-o", str(directory / "native")])
        native, logs = runtime(profile, "native")
        c, c_logs = c_runs[profile]
        if (stress.byte_record_payload(native["stdout"], profile) != stress.byte_record_payload(c["stdout"], profile)
                or stress.byte_record_payload(native["stderr"], profile) != b""):
            failures.append(f"{profile} actual public caller/statistics/diagnostics differ; raw in {output}")
            cases.append((f"{profile}-comparison", 1, c_logs + logs))
        else:
            cases.append((f"{profile}-comparison", 0, c_logs + logs))
        print(f"Management capacity {profile}: actual C/native compared; failures={len(failures)}", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during management capacity matrix")
    if failures:
        raise harness.HarnessError("; ".join(failures))
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "native-mi-adapter", "watchdog-seconds": "60",
         "ownership": "external-capacity; partial-parent; child-destroy; caller-release"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Management capacity: PASS; {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if not (args.read or args.replay):
        run()
        return
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    if receipt.parameters["profiles"] != ",".join(PROFILES):
        raise harness.HarnessError("receipt does not cover all selected profiles")
    print("Management capacity exact-source physical receipt: PASS")
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
        harness.native_execution_attestation(inputs["execution"], execution)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="management-capacity-replay-", dir=harness.TEMP_ROOT))
        for profile in PROFILES:
            for backend in ("c", "native"):
                binary = scratch / f"{profile}-{backend}"
                shutil.copyfile(receipt.path.parent / "products" / binary.name, binary)
                binary.chmod(0o755)
                result, _ = record(scratch, binary.name, [str(binary)], scratch, True)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {binary.name} failed; see {scratch}")
                case = next(c for c in receipt.cases if c["id"] == f"{binary.name}-run")
                for stream in ("stdout", "stderr"):
                    log = next(p for p in case["logs"] if p.endswith("." + stream))
                    if stress.byte_record_payload(result[stream], binary.name) != (receipt.path.parent / "logs" / log).read_bytes():
                        raise harness.HarnessError(f"retained {binary.name} {stream} differs; see {scratch}")
        print("Management capacity retained C/native replay: PASS")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Management capacity failed: {error}", file=sys.stderr)
        raise SystemExit(1)
