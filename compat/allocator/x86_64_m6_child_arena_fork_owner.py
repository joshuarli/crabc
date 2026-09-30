#!/usr/bin/env python3
"""Compare public arena lifetime behavior with pinned mimalloc in selected profiles."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import load_module, stress

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_arena_fork_owner_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-arena-fork-owner"
BEGIN = "CRABC_MI_M6_CHILD_ARENA_FORK_OWNER_BEGIN"
END = "CRABC_MI_M6_CHILD_ARENA_FORK_OWNER_END"
EXPECTED = {
    "fork.owner_exited": "1,1",
    "fork.child.inherited": "1,1",
    "fork.child.remote": "1",
    "fork.child.heap_destroyed": "1",
    "fork.child.retired": "1",
    "fork.wait": "1",
    "fork.parent.inherited": "1,1",
    "fork.parent.remote": "1",
    "fork.parent.heap_destroyed": "1",
    "fork.parent.retired": "1",
    "fork.attached_live": "1,1",
    "fork.vanished_retired": "1",
    "fork.vanished_wait": "1",
    "fork.parent_owner_exited": "1",
    "fork.parent_live_retired": "1",
}


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-child-arena-fork-owner"
receipts = load_module("child_arena_fork_owner_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")


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
    if result["kind"] != "process" or result["status"] != 0:
        raise harness.HarnessError(f"{name} failed; actual process record: {logs[0]}")
    return result, logs


def run_profiles(profiles):
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(harness.fetch_archive(pin, True), output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "source_internal_checks": False,
        "boundary": "explicit mi_* native adapter; pinned musl provides pthreads and fork",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    print(f"Child arena fork owner raw products: {output}", flush=True)
    for profile in profiles:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source, runtime=False):
            result, logs = record(output, f"{profile}-{name}", argv, cwd, runtime)
            cases.append((f"{profile}-{name}", 0, logs))
            return result

        common = ["-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include"), "-I", str(source / "src")]
        c_binary = directory / "c"
        passed("c-build", [compiler, *common, 
            str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_binary)])
        products[f"{profile}-c"] = c_binary
        c_run = passed("c-run", [str(c_binary)], directory, True)
        c_stdout = stress.byte_record_payload(c_run["stdout"], profile).decode()
        c_stderr = stress.byte_record_payload(c_run["stderr"], profile).decode()

        c_trace = m7.parse_options_trace(c_stdout, "C Child arena fork owner", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"{profile} pinned C arena trace changed: {c_trace}; raw {output}")
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / m4.ADAPTER_STATICLIB
        shutil.copy2(library, retained_library)
        products[f"{profile}-native-library"] = retained_library
        native_binary = directory / "native"
        passed("native-link", [compiler, *common, str(DRIVER), str(retained_library), "-pthread", "-o", str(native_binary)])
        products[f"{profile}-native"] = native_binary
        native_run = passed("native-run", [str(native_binary)], directory, True)
        native_stdout = stress.byte_record_payload(native_run["stdout"], profile).decode()
        m7.compare_options_traces(c_trace, m7.parse_options_trace(native_stdout, "native Child arena fork owner", BEGIN, END))
        if stress.byte_record_payload(c_run["stderr"], profile) != stress.byte_record_payload(native_run["stderr"], profile):
            raise harness.HarnessError(f"{profile} C/native fork-owner stderr differs; raw {output}")
        print(f"Child arena fork owner {profile}: {len(c_trace)} C/native keys PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during arena lifetime comparison")
    canonical = tuple(profiles) == PROFILES
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), "boundary": "explicit native-mi-adapter",
         "source-internal-checks": "false", "watchdog-seconds": "60"}, canonical)
    if canonical:
        receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Child arena fork owner {'canonical four-profile' if canonical else 'development-only'} receipt: {path}")
    return len(EXPECTED)


def run_differential() -> int:
    return run_profiles(("release",))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=PROFILES, help="development-only selected profile")
    selection.add_argument("--matrix", action="store_true", help="canonical four-profile lifetime comparison")
    parser.add_argument("--read", action="store_true", help="read exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read and execute all retained C/native products")
    args = parser.parse_args()
    if args.read or args.replay:
        if args.profile or args.matrix:
            parser.error("reading a canonical receipt cannot select profiles")
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        print("Child arena fork owner exact-source physical receipt: PASS")
        if args.replay:
            harness.require_native_x86_64(require_image_identity=True)
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="child_arena_fork_owner-replay-", dir=harness.TEMP_ROOT))
            for profile in PROFILES:
                for backend in ("c", "native"):
                    product = f"{profile}-{backend}"
                    binary = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, binary)
                    binary.chmod(0o755)
                    result, _ = record(scratch, product, [str(binary)], scratch, True)
                    case = next(case for case in receipt.cases if case["id"] == f"{profile}-{backend}-run")
                    for stream in ("stdout", "stderr"):
                        original = next(path for path in case["logs"] if path.endswith(f".{stream}"))
                        if stress.byte_record_payload(result[stream], product) != (receipt.path.parent / "logs" / original).read_bytes():
                            raise harness.HarnessError(f"retained {product} {stream} differs; raw {scratch}")
            print(f"Child arena fork owner retained four-profile products: PASS; raw {scratch}")
    else:
        run_profiles(PROFILES if args.matrix else (args.profile or "release",))


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, receipts.ReceiptError, stress.EvidenceError) as error:
        print(f"Child arena fork owner failed: {error}", file=sys.stderr)
        raise SystemExit(1)
