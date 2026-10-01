#!/usr/bin/env python3
"""Compare child Heap visitation with pinned mimalloc in selected profiles."""

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

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_abandoned_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-abandoned-visitor"
STAGES = ("areas", "blocks", "stop_regular_area", "stop_regular_block", "ordinary")
BEGIN = "CRABC_MI_M6_CHILD_ABANDONED_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_CHILD_ABANDONED_VISITOR_TRACE_END"
SOURCE_CHILD_ABANDONED_PAGES = {
    "child.areas": "1,1,1,0,0,0,2,1,RO",
    "child.blocks": "1,1,1,2,1,0,2,1,R13OS",
    "child.stop_regular_area": "0,1,0,0,0,0,2,0,R",
    "child.stop_regular_block": "0,1,0,1,0,0,2,0,R1",
    "child.ordinary": "1,1,1,2,1,0,2,1,R13OS",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"child.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} child visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){7},[RO13FS]*", trace[f"child.{stage}"]):
            raise harness.HarnessError(f"{side} child.{stage} is malformed")
    if side == "c" and trace != SOURCE_CHILD_ABANDONED_PAGES:
        raise harness.HarnessError(f"pinned C child abandoned-page image changed: {trace}")


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
AVAILABLE_PROFILES = (*PROFILES, "secure-1", "secure-2")
RUNNER = "allocator-child-abandoned-visitor"
receipts = load_module("child_abandoned_visitor_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")


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


def run_profiles(profiles, *, canonical=False):
    if (not profiles or len(set(profiles)) != len(profiles)
            or any(profile not in AVAILABLE_PROFILES for profile in profiles)):
        raise harness.HarnessError("unknown or duplicate visitation profile selection")
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
        "profiles": profiles, "source_internal_checks": True,
        "boundary": "explicit mi_* native adapter; pinned musl provides pthreads",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    print(f"child abandoned visitor raw products: {output}", flush=True)
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
        passed("c-build", [compiler, *common, "-DCRABC_M6_SOURCE_INTERNAL=1",
            str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_binary)])
        products[f"{profile}-c"] = c_binary
        c_run = passed("c-run", [str(c_binary)], directory, True)
        c_stdout = stress.byte_record_payload(c_run["stdout"], profile).decode()
        c_stderr = stress.byte_record_payload(c_run["stderr"], profile).decode()
        if re.findall(r"^source\.transfer=([01]),([01]),([01]),([01]),([01])$", c_stderr, re.MULTILINE) != [("1",) * 5]:
            raise harness.HarnessError(f"{profile} pinned child page owners changed; raw {output}")
        c_trace = m7.parse_options_trace(c_stdout, "C child abandoned visitor", BEGIN, END)
        require_trace(c_trace, "c")
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
        native_trace = m7.parse_options_trace(native_stdout, "native", BEGIN, END)
        require_trace(native_trace, "native")
        m7.compare_options_traces(c_trace, native_trace)
        native_stderr = stress.byte_record_payload(native_run["stderr"], profile).decode()
        if not re.findall(r"^geometry\..+$", c_stderr, re.MULTILINE) or re.findall(r"^geometry\..+$", c_stderr, re.MULTILINE) != re.findall(r"^geometry\..+$", native_stderr, re.MULTILINE):
            raise harness.HarnessError(f"{profile} child client geometry differs; raw {output}")

        print(f"child abandoned visitor {profile}: {len(c_trace)} C/native keys PASS", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during child Heap visitation")
    canonical = canonical or tuple(profiles) == PROFILES
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), "boundary": "explicit native-mi-adapter",
         "source-internal-checks": "true", "geometry": "ordered retained clients and areas", "watchdog-seconds": "60"}, canonical)
    if canonical:
        receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"child abandoned visitor {'canonical requested-profile' if canonical else 'development-only'} receipt: {path}")
    return len(STAGES)


def run_differential() -> int:
    return run_profiles(("release",))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=AVAILABLE_PROFILES, help="development-only selected profile")
    selection.add_argument("--matrix", action="store_true", help="canonical four-profile visitation comparison")
    selection.add_argument("--profiles", nargs="+", choices=AVAILABLE_PROFILES,
        help="complete ordered profile cohort for production or retained reading")
    parser.add_argument("--read", action="store_true", help="read exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read and execute all retained C/native products")
    args = parser.parse_args()
    profiles = tuple(args.profiles) if args.profiles else PROFILES
    if len(set(profiles)) != len(profiles):
        parser.error("profile selection cannot contain duplicates")
    if args.read or args.replay:
        if args.profile or args.matrix:
            parser.error("reading a canonical receipt cannot select profiles")
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        inputs = harness.read_json(receipt.path.parent / "products/inputs.json")
        wanted = [f"{profile}-{backend}-run" for profile in profiles for backend in ("c", "native")]
        recorded = [case for case in receipt.case_ids() if case.endswith("-run")]
        if (receipt.parameters.get("profiles") != ",".join(profiles)
                or inputs.get("profiles") != list(profiles) or recorded != wanted):
            raise receipts.ReceiptError("visitation receipt does not cover the exact requested profile cohort")
        print("child abandoned visitor exact-source physical receipt: PASS")
        if args.replay:
            execution = harness.require_native_x86_64(require_image_identity=True)
            harness.native_execution_attestation(inputs.get("execution"), execution)
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="child_abandoned_visitor-replay-", dir=harness.TEMP_ROOT))
            for profile in profiles:
                for backend in ("c", "native"):
                    product = f"{profile}-{backend}"
                    binary = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, binary)
                    binary.chmod(0o755)
                    result, _ = record(scratch, product, [str(binary)], scratch, True)
                    case = next(case for case in receipt.cases if case["id"] == f"{profile}-{backend}-run")
                    for stream in ("stdout",):
                        original = next(path for path in case["logs"] if path.endswith(f".{stream}"))
                        if stress.byte_record_payload(result[stream], product) != (receipt.path.parent / "logs" / original).read_bytes():
                            raise harness.HarnessError(f"retained {product} {stream} differs; raw {scratch}")
                    stderr = stress.byte_record_payload(result["stderr"], product).decode()
                    original = next(path for path in case["logs"] if path.endswith(".stderr"))
                    recorded_stderr = (receipt.path.parent / "logs" / original).read_text()
                    if re.findall(r"^geometry\..+$", stderr, re.MULTILINE) != re.findall(r"^geometry\..+$", recorded_stderr, re.MULTILINE):
                        raise harness.HarnessError(f"retained {product} client geometry differs; raw {scratch}")
                    if backend == "c" and re.findall(r"^source\.transfer=([01]),([01]),([01]),([01]),([01])$", stderr, re.MULTILINE) != [("1",) * 5]:
                        raise harness.HarnessError(f"retained {product} source owners differ; raw {scratch}")
            print(f"child abandoned visitor retained requested-profile products: PASS; raw {scratch}")
    else:
        if args.profiles:
            run_profiles(profiles, canonical=True)
        else:
            run_profiles(PROFILES if args.matrix else (args.profile or "release",))


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, receipts.ReceiptError, stress.EvidenceError) as error:
        print(f"child abandoned visitor failed: {error}", file=sys.stderr)
        raise SystemExit(1)
