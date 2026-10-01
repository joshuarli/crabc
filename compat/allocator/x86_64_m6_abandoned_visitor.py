#!/usr/bin/env python3
"""Compare bounded abandoned regular-page visitation against pinned C."""

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

receipts = load_module("abandoned_visitor_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-abandoned-visitor"


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_abandoned_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-abandoned-visitor"
STAGES = ("before", "areas", "blocks", "stop_area", "stop_block", "ordinary")
BEGIN = "CRABC_MI_M6_ABANDONED_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_ABANDONED_VISITOR_TRACE_END"
SOURCE_REGULAR_PAGE = {
    "abandoned.before": "1,0,0,0,0,0",
    "abandoned.areas": "1,1,0,2,128,0",
    "abandoned.blocks": "1,1,2,2,128,13",
    "abandoned.stop_area": "0,1,0,2,128,0",
    "abandoned.stop_block": "0,1,1,2,128,1",
    "abandoned.ordinary": "1,1,2,2,128,13",
}


def require_trace(trace: dict[str, str], side: str, profile="release") -> None:
    expected = {f"abandoned.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} abandoned visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){5}", trace[f"abandoned.{stage}"]):
            raise harness.HarnessError(f"{side} abandoned.{stage} is malformed")
    before = trace["abandoned.before"].split(",")
    areas = trace["abandoned.areas"].split(",")
    blocks = trace["abandoned.blocks"].split(",")
    stop_area = trace["abandoned.stop_area"].split(",")
    stop_block = trace["abandoned.stop_block"].split(",")
    if before != ["1", "0", "0", "0", "0", "0"] \
            or areas[:3] != ["1", "1", "0"] \
            or blocks[:3] != ["1", "1", "2"] \
            or stop_area[:3] != ["0", "1", "0"] \
            or stop_block[:3] != ["0", "1", "1"]:
        raise harness.HarnessError(f"{side} did not visit one abandoned page with early stops")
    expected = dict(SOURCE_REGULAR_PAGE)
    block_size = int(areas[4])
    if block_size < 128:
        raise harness.HarnessError(f"{side} regular page cannot hold the requested payload")
    if profile != "release":
        for stage in STAGES[1:]:
            row = expected[f"abandoned.{stage}"].split(",")
            row[4] = str(block_size)
            expected[f"abandoned.{stage}"] = ",".join(row)
    if trace != expected:
        raise harness.HarnessError(f"{side} abandoned-page content, geometry or early stops changed: {trace}")



def compare_runs(c_stdout, c_stderr, native_stdout, native_stderr, profile):
    c_trace = m7.parse_options_trace(c_stdout, "c", BEGIN, END)
    native_trace = m7.parse_options_trace(native_stdout, "native", BEGIN, END)
    require_trace(c_trace, "c", profile)
    require_trace(native_trace, "native", profile)
    m7.compare_options_traces(c_trace, native_trace)
    if c_stdout != native_stdout:
        raise harness.HarnessError("abandoned visitor complete stdout differs")
    if c_stderr or native_stderr:
        raise harness.HarnessError("abandoned visitor unexpected diagnostics")

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


def run_profiles(profiles, driver, artifacts, runner, compare, source_internal=False):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=artifacts))
    output.chmod(0o755)
    print(f"{runner} raw products: {output}", flush=True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures = {}, [], []
    fixture = output / driver.name
    for original in (driver, source / "include/mimalloc.h", source / "LICENSE", archive):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "boundary": "public native-mi-adapter over pinned musl threads",
        "profile_flags": {profile: list(m4.api_profile_flags(profile)) for profile in profiles},
        "profile_features": {profile: list(m4.api_profile_features(profile)) for profile in profiles},
        "fixture": driver.name}, indent=2) + "\n")
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
        features = m4.api_profile_features(profile)
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", ",".join(f"crabc-mimalloc/{feature}" for feature in features)) if features else ())], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / "native-mi-adapter.a"
        shutil.copy2(library, retained_library)
        products[f"{profile}-native-mi-adapter.a"] = retained_library
        products[f"{profile}-oracle.o"] = oracle
        results, runtime_logs = {}, {}
        for backend, allocator in (("c", oracle), ("native", retained_library)):
            binary = directory / backend
            caller = directory / f"{backend}.o"
            internal = ["-DCRABC_M6_SOURCE_INTERNAL=1"] if source_internal and backend == "c" else []
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
            compare(c_stdout, c_stderr, native_stdout, native_stderr, profile)
        except (harness.HarnessError, UnicodeError) as error:
            failures.append(f"{profile}: {error}; raw in {output}")
            cases.append((f"{profile}-comparison", 1, comparison_logs))
        else:
            cases.append((f"{profile}-comparison", 0, comparison_logs))
        print(f"{runner} {profile}: actual C/native compared; failures={len(failures)}", flush=True)
        # The retained static archive and callers own every execution input;
        # completed profile build caches are no longer needed by the reader.
        shutil.rmtree(target)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during abandoned visitor execution")
    path = receipts.write_receipt(harness.ROOT, runner, output, products, cases,
        {"profiles": ",".join(profiles), "boundary": "public native-mi-adapter over pinned musl"}, True)
    if failures:
        for failure in failures:
            print(f"RED: {failure}", flush=True)
        raise harness.HarnessError(f"{runner} has {len(failures)} failures; physical receipt {path}")
    receipts.read_receipt(harness.ROOT, runner)
    print(f"{runner}: selected profiles PASS; {path}")
    return len(profiles)



def read_and_replay(profiles, runner, compare, replay=False, *, fixture=DRIVER.name,
                    available_profiles=PROFILES, validate_inputs=False, source_internal=False):
    receipt = receipts.read_receipt(harness.ROOT, runner)
    covered = tuple(receipt.parameters["profiles"].split(","))
    if any(profile not in covered for profile in profiles):
        raise harness.HarnessError("retained visitor receipt does not cover selected profiles")
    if covered != tuple(profile for profile in available_profiles if profile in covered):
        raise harness.HarnessError("retained visitor profiles are not an ordered selected profile set")
    expected_cases = []
    expected_products = {fixture, "mimalloc.h", "LICENSE", "mimalloc-3.5.0.tar.gz", "inputs.json"}
    for profile in covered:
        expected_cases.extend(f"{profile}-{phase}" for phase in ("oracle-build", "native-build"))
        for backend in ("c", "native"):
            expected_cases.extend(f"{profile}-{backend}-{phase}"
                for phase in ("compile", "imports", "link", "run"))
        expected_cases.append(f"{profile}-comparison")
        expected_products.update(f"{profile}-{suffix}"
            for suffix in ("oracle.o", "native-mi-adapter.a", "c", "native", "c.o", "native.o"))
    if receipt.case_ids() != expected_cases:
        raise harness.HarnessError("retained visitor build, caller and comparison phases differ")
    if set(receipt.products) != expected_products:
        raise harness.HarnessError("retained visitor inputs and profile products differ")
    if validate_inputs:
        products = receipt.path.parent / "products"
        inputs = json.loads((products / "inputs.json").read_text())
        pin = harness.load_pin()
        if (inputs.get("upstream") != pin or inputs.get("profiles") != list(covered)
                or harness.sha256_file(products / "mimalloc-3.5.0.tar.gz") != pin["sha256"]
                or (products / fixture).read_bytes() != (harness.ALLOCATOR_ROOT / fixture).read_bytes()
                or inputs.get("profile_flags") != {p: list(m4.api_profile_flags(p)) for p in covered}
                or inputs.get("profile_features") != {p: list(m4.api_profile_features(p)) for p in covered}):
            raise harness.HarnessError("retained visitor source or compiler configuration differs")
        for profile in covered:
            flags = ["-DMI_LIBC_MUSL=1", *[flag for flag in m4.api_profile_flags(profile)
                if flag.startswith(("-DMI_", "-UMI_"))]]
            for phase in ("oracle-build", "c-compile", "native-compile", "native-build"):
                case = next(case for case in receipt.cases if case["id"] == f"{profile}-{phase}")
                log = next(path for path in case["logs"] if path.endswith(".json"))
                argv = json.loads((receipt.path.parent / "logs" / log).read_text()).get("command", [])
                if phase == "native-build":
                    features = m4.api_profile_features(profile)
                    selected = ",".join(f"crabc-mimalloc/{feature}" for feature in features)
                    if ((features and ("--features" not in argv or argv[argv.index("--features") + 1:] != [selected]))
                            or (not features and "--features" in argv)):
                        raise harness.HarnessError("retained visitor native feature arguments differ")
                elif [arg for arg in argv if arg.startswith(("-DMI_", "-UMI_"))] != flags:
                    raise harness.HarnessError("retained visitor C compiler configuration differs")
                if phase in ("c-compile", "native-compile"):
                    internal = "-DCRABC_M6_SOURCE_INTERNAL=1" in argv
                    if internal != (source_internal and phase == "c-compile"):
                        raise harness.HarnessError("retained visitor source ownership assertions differ")
    print(f"{runner} exact-source physical receipt: PASS")
    if not replay:
        return
    execution = harness.require_native_x86_64(require_image_identity=True)
    inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
    harness.validate_native_execution_provenance(inputs["execution"], expected_image_id=execution["image_id"])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="abandoned-visitor-replay-", dir=harness.TEMP_ROOT))
    scratch.chmod(0o755)
    for profile in profiles:
        streams = {}
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
                actual = stress.byte_record_payload(result[stream], case)
                previous = (receipt.path.parent / "logs" / original).read_bytes()
                if actual != previous:
                    raise harness.HarnessError(f"retained caller {case} entire {stream} differs; see {scratch}")
                streams[backend, stream] = actual.decode()
        compare(streams["c", "stdout"], streams["c", "stderr"],
                streams["native", "stdout"], streams["native", "stderr"], profile)
        print(f"{runner} retained {profile} full C/native workload replay PASS")


def visitor_main(driver, artifacts, runner, compare, source_internal=False, *, available_profiles=PROFILES):
    parser = argparse.ArgumentParser(description="Compare full abandoned-page visitor workloads with pinned C")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--matrix", action="store_true")
    selection.add_argument("--profile", choices=available_profiles, default="release")
    selection.add_argument("--profiles", nargs="+", choices=available_profiles)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    profiles = tuple(args.profiles) if args.profiles else PROFILES if args.matrix else (args.profile,)
    if len(set(profiles)) != len(profiles) or profiles != tuple(p for p in available_profiles if p in profiles):
        parser.error("profiles must be an ordered selection without duplicates")
    try:
        if args.read or args.replay:
            read_and_replay(profiles, runner, compare, args.replay, fixture=driver.name,
                available_profiles=available_profiles, validate_inputs=True, source_internal=source_internal)
        else:
            run_profiles(profiles, driver, artifacts, runner, compare, source_internal)
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"{runner} failed: {error}", file=sys.stderr)
        raise SystemExit(1)


def main():
    visitor_main(DRIVER, ARTIFACTS, RUNNER, compare_runs)


if __name__ == "__main__":
    main()
