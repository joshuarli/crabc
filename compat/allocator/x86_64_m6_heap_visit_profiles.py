#!/usr/bin/env python3
"""Compare quiescent public Heap and Theap visitation in selected build profiles."""

import argparse
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_visit_profiles_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-heap-visit-profiles"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-visit-profiles"
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
GUARDED_PROFILES = ("guarded", "guarded-debug-1", "guarded-secure-3", "guarded-stat-2")
AVAILABLE_PROFILES = (*PROFILES, "secure-1", "secure-2", *GUARDED_PROFILES)
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_visit_profiles_driver.c"
ALIASES = ("mi_heap_visit_blocks", "mi_heap_visit_abandoned_blocks", "mi_theap_visit_blocks")


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


def run(profiles, *, canonical=False):
    if (not profiles or len(set(profiles)) != len(profiles)
            or any(profile not in AVAILABLE_PROFILES for profile in profiles)):
        raise harness.HarnessError("unknown or duplicate visitation profile selection")
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    archive = harness.fetch_archive(pin, True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {"upstream-archive": archive}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "aliases": ALIASES,
        "profile_flags": {profile: list(m4.api_profile_flags(profile)) for profile in profiles},
        "profile_features": {profile: list(m4.api_profile_features(profile)) for profile in profiles},
        "boundary": "explicit mi_* native adapter; pinned musl provides pthreads",
        "callback": "quiescent scalar capture and retained client reads only",
        "runtime_watchdog_seconds": 60}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    print(f"Heap visitation raw products: {output}", flush=True)
    for profile in profiles:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source, runtime=False):
            result, logs = record(output, f"{profile}-{name}", argv, cwd, runtime)
            cases.append((f"{profile}-{name}", 0, logs))
            return result

        common = ["-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include")]
        oracle = directory / "oracle.o"
        passed("oracle-build", [compiler, *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        products[f"{profile}-oracle.o"] = oracle
        caller = directory / "caller.o"
        passed("caller-build", [compiler, *common, "-c", str(DRIVER), "-o", str(caller)])
        imports = passed("caller-imports", [harness.require_tool("nm"), "-u", str(caller)])
        names = {line.split()[-1] for line in stress.byte_record_payload(imports["stdout"], "caller imports").decode().splitlines() if line.split()}
        if not set(ALIASES) <= names:
            raise harness.HarnessError(f"visitation caller does not import all public aliases: {names}")
        target = directory / "cargo-target"
        c_binary = directory / "c"
        passed("c-link", [compiler, str(caller), str(oracle), "-pthread", "-o", str(c_binary)])
        products[f"{profile}-c"] = c_binary
        c_run = passed("c-run", [str(c_binary)], directory, True)
        features = m4.api_profile_features(profile)
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", ",".join(f"crabc-mimalloc/{feature}" for feature in features)) if features else ())], harness.ROOT)
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        retained_library = directory / "adapter.a"
        shutil.copy2(library, retained_library)
        products[f"{profile}-adapter.a"] = retained_library
        native_binary = directory / "native"
        passed("native-link", [compiler, str(caller), str(library), "-pthread", "-o", str(native_binary)])
        products[f"{profile}-native"] = native_binary
        products[f"{profile}-caller.o"] = caller
        native_run = passed("native-run", [str(native_binary)], directory, True)
        trace = stress.byte_record_payload(c_run["stdout"], profile)
        if trace != stress.byte_record_payload(native_run["stdout"], profile):
            raise harness.HarnessError(f"{profile} C/native visitation traces differ; raw in {output}")
        if profile in GUARDED_PROFILES and not re.search(rb"^populated\.heap\.guarded=[1-9][0-9]*$", trace, re.MULTILINE):
            raise harness.HarnessError(f"{profile} did not visit a populated tagged guarded client cohort")
        print(f"Heap visitation {profile}: all public aliases PASS", flush=True)
        # The compiled library has been transferred to the retained product;
        # completed per-profile Cargo caches are no longer execution inputs.
        shutil.rmtree(target)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap visitation")
    canonical = canonical or tuple(profiles) == PROFILES
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), "aliases": ",".join(ALIASES),
         "boundary": "explicit native-mi-adapter", "watchdog-seconds": "60"}, canonical)
    if canonical:
        receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Heap visitation {'canonical requested-profile' if canonical else 'development-only'} receipt: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=AVAILABLE_PROFILES, help="development-only single-profile execution")
    selection.add_argument("--profiles", nargs="+", choices=AVAILABLE_PROFILES,
        help="complete ordered profile cohort for production or retained reading")
    parser.add_argument("--read", action="store_true", help="read exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read and execute all retained C/native aliases")
    args = parser.parse_args()
    profiles = tuple(args.profiles) if args.profiles else PROFILES
    if len(set(profiles)) != len(profiles):
        parser.error("profile selection cannot contain duplicates")
    if args.read or args.replay:
        if args.profile:
            parser.error("reading a canonical receipt cannot select one profile")
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        inputs = harness.read_json(receipt.path.parent / "products/inputs.json")
        wanted = [f"{profile}-{backend}-run" for profile in profiles for backend in ("c", "native")]
        recorded = [case for case in receipt.case_ids() if case.endswith("-run")]
        if (receipt.parameters.get("profiles") != ",".join(profiles)
                or inputs.get("profiles") != list(profiles) or recorded != wanted):
            raise receipts.ReceiptError("visitation receipt does not cover the exact requested profile cohort")
        pin = harness.load_pin()
        products = receipt.path.parent / "products"
        logs = receipt.path.parent / "logs"
        if (inputs.get("upstream") != pin
                or harness.sha256_file(products / "upstream-archive") != pin["sha256"]
                or (products / DRIVER.name).read_bytes() != DRIVER.read_bytes()
                or inputs.get("profile_flags") != {profile: list(m4.api_profile_flags(profile)) for profile in profiles}
                or inputs.get("profile_features") != {profile: list(m4.api_profile_features(profile)) for profile in profiles}):
            raise receipts.ReceiptError("visitation compiler inputs or selected guarded feature closure differ")
        for profile in profiles:
            for backend in ("c", "native"):
                case = next(case for case in receipt.cases if case["id"] == f"{profile}-{backend}-run")
                stdout = next(path for path in case["logs"] if path.endswith(".stdout"))
                if profile in GUARDED_PROFILES and not re.search(rb"^populated\.heap\.guarded=[1-9][0-9]*$",
                        (logs / stdout).read_bytes(), re.MULTILINE):
                    raise receipts.ReceiptError("guarded visitation receipt lacks an executed tagged client population")
            expected_flags = ["-DMI_LIBC_MUSL=1", *[flag for flag in m4.api_profile_flags(profile)
                if flag.startswith(("-DMI_", "-UMI_"))]]
            for label in ("oracle-build", "caller-build"):
                build = next(case for case in receipt.cases if case["id"] == f"{profile}-{label}")
                record_path = next(path for path in build["logs"] if path.endswith(".json"))
                argv = harness.read_json(logs / record_path).get("command", [])
                selected_flags = [arg for arg in argv if arg.startswith(("-DMI_", "-UMI_"))]
                if selected_flags != expected_flags:
                    raise receipts.ReceiptError("visitation C compiler configuration differs")
            build = next(case for case in receipt.cases if case["id"] == f"{profile}-native-build")
            record_path = next(path for path in build["logs"] if path.endswith(".json"))
            argv = harness.read_json(logs / record_path).get("command", [])
            features = m4.api_profile_features(profile)
            expected_features = ",".join(f"crabc-mimalloc/{feature}" for feature in features)
            if ((features and ("--features" not in argv or argv[argv.index("--features") + 1:] != [expected_features]))
                    or (not features and "--features" in argv)):
                raise receipts.ReceiptError("visitation native compiler feature arguments differ")
        print("Heap visitation exact-source physical receipt: PASS")
        if args.replay:
            execution = harness.require_native_x86_64(require_image_identity=True)
            harness.native_execution_attestation(inputs.get("execution"), execution)
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="heap-visit-profiles-replay-", dir=harness.TEMP_ROOT))
            for profile in profiles:
                for backend in ("c", "native"):
                    product = f"{profile}-{backend}"
                    binary = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, binary)
                    binary.chmod(0o755)
                    result, _ = record(scratch, product, [str(binary)], scratch, True)
                    case = next(case for case in receipt.cases if case["id"] == f"{profile}-{backend}-run")
                    stdout = next(path for path in case["logs"] if path.endswith(".stdout"))
                    if stress.byte_record_payload(result["stdout"], product) != (receipt.path.parent / "logs" / stdout).read_bytes():
                        raise harness.HarnessError(f"retained {product} visitation output differs; raw in {scratch}")
            print(f"Heap visitation retained requested-profile aliases: PASS; raw {scratch}")
    else:
        if args.profiles:
            run(profiles, canonical=True)
        else:
            run((args.profile,) if args.profile else PROFILES)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, receipts.ReceiptError, stress.EvidenceError) as error:
        print(f"Heap visitation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
