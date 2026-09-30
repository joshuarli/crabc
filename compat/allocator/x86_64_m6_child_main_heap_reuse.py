#!/usr/bin/env python3
"""Compare child main-Heap allocation and visitation across successive owners."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_heap_convenience import record
from x86_64_m6_upstream_heap_stress import load_module, stress


receipts = load_module("child_main_heap_reuse_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-child-main-heap-reuse"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_main_heap_reuse_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-main-heap-reuse"
BEGIN = "CRABC_MI_M6_CHILD_MAIN_HEAP_REUSE_BEGIN"
END = "CRABC_MI_M6_CHILD_MAIN_HEAP_REUSE_END"
STAGES = (
    "first_owner", "first_live", "reattached", "first_exited",
    "second_owner", "second_live", "second_abandoned",
    "final_reattached", "second_exited", "freed",
)
SOURCE_TRACE = {
    "reuse.first_owner": "1,1,1",
    "reuse.first_live": "1,2,2,2,A1O3",
    "reuse.reattached": "1,1,1,1",
    "reuse.first_exited": "1,2,2,2,A1O3",
    "reuse.second_owner": "1,1,1,1",
    "reuse.second_live": "1,3,4,4,A12P4O3",
    "reuse.second_abandoned": "1,2,2,2,P4O3",
    "reuse.final_reattached": "1,1",
    "reuse.second_exited": "1,3,4,4,A12P4O3",
    "reuse.freed": "1,0,0,0,",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"reuse.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} child main Heap reuse keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in ("first_live", "first_exited", "second_live",
                  "second_abandoned", "second_exited", "freed"):
        if not re.fullmatch(r"[01](?:,[0-9]+){3},[ABOP1234]*", trace[f"reuse.{stage}"]):
            raise harness.HarnessError(f"{side} reuse.{stage} is malformed")
    if side == "c" and trace != SOURCE_TRACE:
        raise harness.HarnessError(f"pinned C child main Heap reuse image changed: {trace}")


def observations(stdout: str, stderr: str, backend: str) -> dict[str, str]:
    trace = m7.parse_options_trace(stdout, backend + " child main Heap reuse", BEGIN, END)
    if backend == "c" and re.findall(r"^source\.reuse=([01](?:,[01]){8},[0-9]+)$",
                                    stderr, re.MULTILINE) != ["1,1,1,1,1,1,1,1,1,1"]:
        raise harness.HarnessError("pinned C child main Heap reuse source image changed")
    require_trace(trace, "c" if backend == "c" else "rust")
    return trace


def run_differential(profile: str = "release") -> int:
    if profile not in PROFILES:
        raise harness.HarnessError(f"unsupported child Heap profile: {profile}")
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = ARTIFACTS if profile == "release" else ARTIFACTS / profile
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "source-seal.txt").write_text(
        f"mimalloc {pin['version']} {pin['revision']}\n"
        f"archive sha256 {hashlib.sha256(archive.read_bytes()).hexdigest()}\n"
        f"driver sha256 {hashlib.sha256(DRIVER.read_bytes()).hexdigest()}\n"
    )
    with harness.temporary_directory("crabc-mimalloc-m6-child-main-heap-reuse-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "child-main-heap-reuse-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *(harness.CONFIGURATION_PROFILES["release"] if profile == "release" else m4.api_profile_flags(profile)),
             "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (artifacts / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "child main Heap reuse C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (artifacts / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "child main Heap reuse C run")
        c_trace = observations(str(c_run["stdout"]), str(c_run["stderr"]), "c")
        library = m4.build_adapter_library(temporary, profile)
        rust_driver = temporary / "child-main-heap-reuse-rust"
        link = harness.command_record(
            [compiler, "-std=c11", *(("-O2",) if profile == "release" else m4.api_profile_flags(profile)), "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (artifacts / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "child main Heap reuse Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (artifacts / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "child main Heap reuse Rust run")
        rust_trace = observations(str(rust_run["stdout"]), str(rust_run["stderr"]), "native")
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


def run_matrix() -> Path:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="matrix-", dir=ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(harness.fetch_archive(pin, True), output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": PROFILES, "source_internal_assertions": True, "runtime_watchdog_seconds": 60,
        "boundary": "explicit native mi_*; pinned musl supplies joined pthread substrate"}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    print(f"child Heap matrix raw products: {output}", flush=True)
    for profile in PROFILES:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source, runtime=False):
            result, logs = record(output, f"{profile}-{name}", argv, cwd, runtime)
            if result["kind"] != "process" or result["status"] != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            cases.append((f"{profile}-{name}", 0, logs))
            return result

        common = ["-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include"), "-I", str(source / "src")]
        c_binary = directory / "c"
        passed("c-build", [compiler, *common, "-DCRABC_M6_SOURCE_INTERNAL=1", str(DRIVER),
                           str(source / "src/static.c"), "-pthread", "-o", str(c_binary)])
        products[f"{profile}-c"] = c_binary
        c_run = passed("c-run", [str(c_binary)], directory, True)
        c_trace = observations(stress.byte_record_payload(c_run["stdout"], profile).decode(),
                               stress.byte_record_payload(c_run["stderr"], profile).decode(), "c")
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-mi-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-mi-adapter.a"] = library
        native_binary = directory / "native"
        passed("native-link", [compiler, *common, str(DRIVER), str(library), "-pthread", "-o", str(native_binary)])
        products[f"{profile}-native"] = native_binary
        native_run = passed("native-run", [str(native_binary)], directory, True)
        native_trace = observations(stress.byte_record_payload(native_run["stdout"], profile).decode(),
                                    stress.byte_record_payload(native_run["stderr"], profile).decode(), "native")
        m7.compare_options_traces(c_trace, native_trace)
        print(f"child Heap {profile}: full C/native workload PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during child Heap matrix")
    harness.native_execution_attestation(execution, harness.require_native_x86_64(require_image_identity=True))
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(PROFILES), "boundary": "explicit native-mi-adapter",
         "source-internal-assertions": "active", "watchdog-seconds": "60"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"child Heap four-profile receipt: {path}")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--profile", choices=PROFILES, help="development-only full single-profile workload")
    modes.add_argument("--matrix", action="store_true", help="retain the full four-profile C/native matrix")
    modes.add_argument("--read", action="store_true", help="read the exact-source canonical matrix receipt")
    modes.add_argument("--replay", action="store_true", help="read and execute every retained C/native caller")
    args = parser.parse_args(argv)
    if args.matrix:
        run_matrix()
    elif args.read or args.replay:
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        wanted = {f"{profile}-{backend}-run" for profile in PROFILES for backend in ("c", "native")}
        if receipt.parameters.get("profiles") != ",".join(PROFILES) or not wanted <= set(receipt.case_ids()):
            raise receipts.ReceiptError("child Heap receipt does not cover the complete profile matrix")
        print("child Heap exact-source four-profile physical receipt: PASS")
        if args.replay:
            execution = harness.require_native_x86_64(require_image_identity=True)
            inputs = harness.read_json(receipt.path.parent / "products/inputs.json")
            harness.native_execution_attestation(inputs.get("execution"), execution)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="child-heap-replay-", dir=harness.TEMP_ROOT))
            print(f"child Heap replay raw executions: {scratch}", flush=True)
            for profile in PROFILES:
                for backend in ("c", "native"):
                    product = f"{profile}-{backend}"
                    binary = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, binary)
                    binary.chmod(0o755)
                    result, _ = record(scratch, product, [str(binary)], scratch, True)
                    observations(stress.byte_record_payload(result["stdout"], product).decode(),
                                 stress.byte_record_payload(result["stderr"], product).decode(), backend)
                    case = next(case for case in receipt.cases if case["id"] == product + "-run")
                    stdout = next(path for path in case["logs"] if path.endswith(".stdout"))
                    if stress.byte_record_payload(result["stdout"], product) != (receipt.path.parent / "logs" / stdout).read_bytes():
                        raise harness.HarnessError(f"retained caller {product} output differs; raw in {scratch}")
            print("child Heap retained full C/native matrix replay: four profiles PASS")
    else:
        count = run_differential(args.profile or "release")
        print(f"child main Heap reuse: {count} source-built C/Rust keys match")


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"child Heap failed: {error}", file=sys.stderr)
        raise SystemExit(1)
