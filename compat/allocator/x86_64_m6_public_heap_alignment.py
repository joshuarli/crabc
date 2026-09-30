#!/usr/bin/env python3
"""Compare public Heap allocation content, failure, and ownership with pinned source."""

import argparse
import json
import os
from pathlib import Path
import re
import resource
import sys
import tempfile
import shutil

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_allocation_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-public-heap-allocation"
CONTRACT = "heap_requests_preserve_content_failure_and_legal_release_lifetimes"

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_heap_alignment_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-heap-alignment"
BEGIN = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_BEGIN"
END = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END"
EXPECTED = {
    "alignment.heap": "1,1",
    "alignment.case0": "1,1,1,1,1,1",
    "alignment.case1": "1,1,1,1,1,1",
    "alignment.case2": "1,1,1,1,1,1",
    "alignment.case3": "1,1,1,1,1,1",
    "alignment.case4": "1,1,1,1,1,1",
    "alignment.case5": "1,1,1,1,1,1",
    "alignment.failure0": "1,22",
    "alignment.failure1": "1,22",
    "alignment.failure2": "1,22",
    "alignment.failure3": "1,12",
    "alignment.worker": "1,1,1,1,1,1",
    "alignment.before_delete": "1,1",
    "alignment.after_delete": "1,0,1",
    "alignment.freed_after_delete": "1",
    "alignment.second_heap": "1",
    "alignment.second_block": "1",
    "alignment.second_destroyed": "1",
    "alignment.destroy": "1,1",
    "contract.growth": "1",
    "contract.allocations": "1",
    "contract.strings": "1",
    "contract.failures": "1",
    "contract.replacements": "1",
    "contract.lifetime": "1",
}


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
ALLOCATIONS = (
    "mi_heap_malloc", "mi_heap_zalloc", "mi_heap_calloc", "mi_heap_mallocn",
    "mi_heap_malloc_small", "mi_heap_zalloc_small", "mi_heap_malloc_aligned",
    "mi_heap_malloc_aligned_at", "mi_heap_zalloc_aligned", "mi_heap_zalloc_aligned_at",
    "mi_heap_calloc_aligned", "mi_heap_calloc_aligned_at", "mi_heap_alloc_new", "mi_heap_alloc_new_n",
)
REPLACEMENTS = (
    "mi_heap_realloc", "mi_heap_reallocn", "mi_heap_rezalloc", "mi_heap_recalloc",
    "mi_heap_realloc_aligned", "mi_heap_realloc_aligned_at", "mi_heap_rezalloc_aligned",
    "mi_heap_rezalloc_aligned_at", "mi_heap_recalloc_aligned", "mi_heap_recalloc_aligned_at",
)
STRINGS = ("mi_heap_strdup", "mi_heap_strndup", "mi_heap_realpath")


def expected_observations(profile: str) -> dict[str, str]:
    if profile not in PROFILES:
        raise harness.HarnessError(f"unsupported public Heap allocation profile: {profile}")
    expected = {key: value for key, value in EXPECTED.items()
                if profile == "release" or key.startswith("contract.")}
    count_errno = 12 if profile == "debug-1" else 0
    for index, entry in enumerate(ALLOCATIONS):
        expected[f"entry.{entry}.normal"] = "1,1,1,1,1"
        expected[f"entry.{entry}.refusal"] = "1,12,1"
        if index in (4, 5):
            # The small API has a size precondition; refusal uses a valid size.
            value = "source-small-size-precondition"
        else:
            errno = count_errno if index in (2, 3, 10, 11, 13) else 22 if 6 <= index <= 9 else 12
            value = f"1,{errno},1"
        expected[f"entry.{entry}.overflow"] = value
        if index >= 12:
            expected[f"entry.{entry}.refusal_handler"] = "4"
    for index, entry in enumerate(REPLACEMENTS):
        expected[f"entry.{entry}.normal"] = "1,1,1,1"
        expected[f"entry.{entry}.refusal"] = "1,12,1"
        expected[f"entry.{entry}.overflow"] = f"1,{22 if index >= 4 else 12},1"
        if index in (1, 3, 8, 9):
            expected[f"entry.{entry}.count_overflow"] = f"1,{count_errno},1"
    for entry in (*STRINGS, "mi_heap_reallocf"):
        expected[f"entry.{entry}.normal"] = "1,1,1"
        expected[f"entry.{entry}.refusal"] = "1,12,1"
    for entry in STRINGS[:2]:
        expected[f"entry.{entry}.null"] = "1"
    for entry in (*ALLOCATIONS, *REPLACEMENTS, *STRINGS, "mi_heap_reallocf"):
        expected[f"entry.{entry}.lifetime"] = "1,1,1"
    expected["entry.mi_heap_reallocf.overflow"] = "1,12,1"
    return expected


def observations(result: dict, profile: str, label: str) -> dict[str, str]:
    harness.require_success(result, label)
    actual = m7.parse_options_trace(str(result["stdout"]), label, BEGIN, END)
    expected = expected_observations(profile)
    if actual != expected:
        differences = {key: (expected.get(key), actual.get(key))
                       for key in expected.keys() | actual.keys() if expected.get(key) != actual.get(key)}
        raise harness.HarnessError(f"{label} observations differ: {differences}")
    return actual


def compare_runs(c_run: dict, rust_run: dict, profile: str) -> int:
    c_trace = observations(c_run, profile, "pinned C public Heap allocation")
    rust_trace = observations(rust_run, profile, "native Rust public Heap allocation")
    m7.compare_options_traces(c_trace, rust_trace)
    c_errors = re.findall(r"(?:aligned allocation[^\n]*|out of memory[^\n]*)", str(c_run["stderr"]))
    rust_errors = re.findall(r"(?:aligned allocation[^\n]*|out of memory[^\n]*)", str(rust_run["stderr"]))
    if c_errors != rust_errors:
        raise harness.HarnessError(f"Heap alignment diagnostics differ: {c_errors!r} != {rust_errors!r}")
    return len(c_trace)


def record(output, name, argv, cwd, *, runtime=False, timeout=None):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ),
        timeout=timeout if timeout is not None else 60 if runtime else 3600)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream in result:
            path = output / f"{name}.{stream}"
            path.write_bytes(stress.byte_record_payload(result[stream], name))
            logs.append(path)
    return result, logs


def decoded(result):
    return {"status": result.get("status", 1),
            **{stream: stress.byte_record_payload(result[stream], stream).decode()
               for stream in ("stdout", "stderr")}}


def run_profiles(profiles, output=ARTIFACTS):
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for profile in profiles:
        expected_observations(profile)
    output = output.resolve()
    try:
        output.relative_to(harness.ARTIFACT_ROOT.resolve())
    except ValueError as error:
        raise harness.HarnessError("public Heap output must stay inside the owning artifact root") from error
    output.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    output.chmod(0o755)
    print(f"Public Heap allocation raw products: {output}", flush=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures = {}, [], []
    fixture = output / DRIVER.name
    for original in (DRIVER, harness.ROOT / "crabc-mimalloc/tests/native_heap_allocation_contract.rs",
                     source / "include/mimalloc.h", source / "LICENSE", archive):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    scope = {profile: "legacy alignment and entry transactions" if profile == "release"
             else "entry transactions only" for profile in profiles}
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "scope": scope,
        "boundary": "public native-mi-adapter over pinned musl; native Rust Heap contract"}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    for profile in profiles:
        directory = output / profile
        directory.mkdir()
        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            status = result.get("status", 1) if result["kind"] == "process" else 1
            cases.append((f"{profile}-{name}", status, logs))
            if status != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; see {logs[0]}")
            return result
        client_flags = ("-DCRABC_MI_HEAP_ALLOCATION_CONTRACT_ONLY=1",) if profile != "release" else ()
        common = ["-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include"), "-I", str(source / "src")]
        oracle = directory / "oracle.o"
        passed("oracle-build", [compiler, "-std=c11", *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        target = directory / "cargo-target"
        passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
        library = directory / "native-adapter.a"
        shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
        products[f"{profile}-native-adapter.a"] = library
        products[f"{profile}-oracle.o"] = oracle
        results, runtime_logs = {}, {}
        for backend, allocator in (("c", oracle), ("native", library)):
            binary = directory / backend
            caller = directory / f"{backend}.o"
            passed(f"{backend}-compile", [compiler, "-std=c11", *common, *client_flags,
                "-c", str(fixture), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            result, logs = record(output, f"{profile}-{backend}-run", [str(binary)], directory, runtime=True)
            status = result.get("status", 1) if result["kind"] == "process" else 1
            cases.append((f"{profile}-{backend}-run", status, logs))
            results[backend], runtime_logs[backend] = result, logs
            if status != 0:
                failures.append(f"{profile}-{backend}: actual runtime status {status}; see {logs[0]}")
        try:
            count = compare_runs(decoded(results["c"]), decoded(results["native"]), profile)
        except (harness.HarnessError, UnicodeError) as error:
            failures.append(f"{profile}: {error}; raw in {output}")
            cases.append((f"{profile}-comparison", 1, runtime_logs["c"] + runtime_logs["native"]))
        else:
            cases.append((f"{profile}-comparison", 0, runtime_logs["c"] + runtime_logs["native"]))
            print(f"Public Heap allocation {profile} ({scope[profile]}): {count} actual C/native observations match", flush=True)
        contract_build = passed("native-contract-build", [harness.require_tool("cargo"), "test",
            "--locked", "--offline", "--no-run", "--message-format=json", "--target", m4.RUST_TARGET,
            "--target-dir", str(target), "-p", "crabc-mimalloc", "--no-default-features",
            *(("--features", f"mi-{profile}") if profile != "release" else ()),
            "--test", "native_heap_allocation_contract"], harness.ROOT)
        executables = []
        for line in stress.byte_record_payload(contract_build["stdout"], profile).decode().splitlines():
            try:
                artifact = json.loads(line)
            except ValueError:
                continue
            if (artifact.get("reason") == "compiler-artifact"
                and artifact.get("target", {}).get("name") == "native_heap_allocation_contract"
                and artifact.get("executable")):
                executables.append(Path(artifact["executable"]))
        if len(executables) != 1:
            raise harness.HarnessError(f"{profile}: native Heap contract build did not identify one executable")
        contract = directory / "native-contract"
        shutil.copy2(executables[0], contract)
        products[f"{profile}-native-contract"] = contract
        result, logs = record(output, f"{profile}-native-contract-run",
            [str(contract), "--exact", CONTRACT, "--nocapture", "--test-threads=1"], directory,
            runtime=True, timeout=900)
        status = result.get("status", 1) if result["kind"] == "process" else 1
        if status == 0 and harness.parse_rust_test_count(decoded(result)["stdout"] + decoded(result)["stderr"]) != 1:
            status = 1
        cases.append((f"{profile}-native-contract-run", status, logs))
        if status != 0:
            failures.append(f"{profile}: actual native Heap contract failed; see {logs[0]}")
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during public Heap allocation execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), **{f"scope.{profile}": scope[profile] for profile in profiles}}, True)
    if failures:
        for failure in failures:
            print(f"RED: {failure}", flush=True)
        raise harness.HarnessError(f"public Heap allocation has {len(failures)} failures; physical receipt {path}")
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Public Heap allocation selected scope PASS; {path}")
    return len(expected_observations(profiles[0]))


def read_and_replay(profiles, replay=False):
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    covered = receipt.parameters["profiles"].split(",")
    if any(profile not in covered for profile in profiles):
        raise harness.HarnessError("retained receipt does not cover the selected profiles")
    print("Public Heap allocation exact-source physical receipt: PASS")
    if replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
        harness.validate_native_execution_provenance(inputs["execution"],
            expected_image_id=execution["image_id"])
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="heap-allocation-replay-", dir=harness.TEMP_ROOT))
        scratch.chmod(0o755)
        for profile in profiles:
            results = {}
            for backend in ("c", "native", "native-contract"):
                name = f"{profile}-{backend}"
                binary = scratch / name
                shutil.copyfile(receipt.path.parent / "products" / name, binary)
                binary.chmod(0o755)
                argv = [str(binary)]
                if backend == "native-contract":
                    argv += ["--exact", CONTRACT, "--nocapture", "--test-threads=1"]
                result, logs = record(scratch, name, argv, scratch, runtime=True,
                    timeout=900 if backend == "native-contract" else 60)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {name} failed; see {logs[0]}")
                results[backend] = decoded(result)
                recorded = next(case for case in receipt.cases if case["id"] == name + "-run")
                previous = next(log for log in recorded["logs"] if log.endswith(".stdout"))
                if backend != "native-contract" and stress.byte_record_payload(result["stdout"], name) != (receipt.path.parent / "logs" / previous).read_bytes():
                    raise harness.HarnessError(f"retained {name} observations differ; see {scratch}")
            compare_runs(results["c"], results["native"], profile)
            if harness.parse_rust_test_count(results["native-contract"]["stdout"] + results["native-contract"]["stderr"]) != 1:
                raise harness.HarnessError(f"retained {profile} native Heap contract did not execute exactly one test")
            scope = "legacy alignment and entry transactions" if profile == "release" else "entry transactions only"
            print(f"Public Heap allocation retained {profile} ({scope}) replay PASS")
    return len(expected_observations(profiles[0]))


def run_differential(profile="release", *, output=ARTIFACTS, replay_only=False):
    return read_and_replay((profile,), replay=True) if replay_only else run_profiles((profile,), output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=(*PROFILES, "all"), default="release")
    parser.add_argument("--output", type=Path, default=ARTIFACTS)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    profiles = PROFILES if args.profile == "all" else (args.profile,)
    if args.read or args.replay:
        read_and_replay(profiles, replay=args.replay)
    else:
        run_profiles(profiles, args.output)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Public Heap allocation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
