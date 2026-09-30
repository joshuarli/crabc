#!/usr/bin/env python3
"""Compare the complete public Heap/subprocess workload with pinned C across profiles."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys
import tempfile
from typing import Any

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("public_adapter_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-public-heap-subprocess"
CONTRACT = "public_heap_visitation_tracks_live_population_early_stop_and_collection"
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_adapter_driver.c"
TRACE_BEGIN = "CRABC_MI_M6_ADAPTER_TRACE_BEGIN"
TRACE_END = "CRABC_MI_M6_ADAPTER_TRACE_END"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-adapter"
EXPECTED_KEYS = frozenset("""
collect.deferred
collect.pages
collect.setup.pages
delete.usable
destroy.failed
destroy.heaps.after
destroy.pages.after
destroy.pages.during
final.messages
heap.aligned
heap.aligned_at
heap.bad_alignment
heap.bad_alignment.codes
heap.bad_alignment.messages
heap.calloc
heap.calloc.overflow
heap.calloc.usable
heap.calloc_aligned
heap.calloc_aligned_at
heap.destroy.messages
heap.huge
heap.main
heap.main.malloc
heap.main.release.messages
heap.malloc
heap.malloc.reuse_usable
heap.malloc.usable
heap.mallocn.usable
heap.new
heap.new.not_main
heap.null.release.messages
heap.small
heap.too_large
heap.too_large.codes
heap.too_large.messages
heap.zalloc
heap.zalloc_aligned
heap.zalloc_aligned_at
many.heaps
many.ok
membership.live
membership.moved
membership.moved_queries
membership.region
membership.unmapped
membership.utilization
membership.utilization_nonhead
new.heap
realloc.default.same_size
realloc.heap.aligned_at
realloc.heap.aligned_fit
realloc.heap.bad_alignment
realloc.heap.bad_alignment.codes
realloc.heap.bad_alignment.messages
realloc.heap.foreign
realloc.heap.foreign_aligned_theap
realloc.heap.grow
realloc.heap.overflow_theap
realloc.heap.reallocf_fail
realloc.heap.reallocf_fail.codes
realloc.heap.reallocf_fail.messages
realloc.heap.reallocn
realloc.heap.recalloc
realloc.heap.recalloc_aligned
realloc.heap.recalloc_overflow
realloc.heap.rezalloc
realloc.heap.rezalloc_aligned
realloc.heap.rezalloc_aligned_at
realloc.heap.shrink
realloc.main
reserve.commit.arena_count
reserve.commit.committed
reserve.commit.rc
reserve.commit.reserved
reserve.exclusive.after_malloc
reserve.exclusive.id
reserve.exclusive.rc
reserve.lazy.committed
reserve.lazy.rc
reserve.lazy.reserved
reserve.over_max.codes
reserve.over_max.errno
reserve.over_max.messages
reserve.over_max.rc
reserve.small.rc
reserve.too_large.codes
reserve.too_large.errno
reserve.too_large.id
reserve.too_large.messages
reserve.too_large.rc
strings.dup
strings.realpath
subproc.add_main.messages
subproc.add_other.messages
subproc.child.cross_heap_realloc
subproc.child.destroyed.heaps
subproc.child.destroyed.threads
subproc.child.facts
subproc.child.heap_realloc
subproc.child.heap_variants
subproc.child.large_alignment
subproc.child.large_alignment.codes
subproc.child.membership
subproc.child.run
subproc.child.visit
subproc.live.current
subproc.live.destroyed.heaps
subproc.live.destroyed.theaps
subproc.live.destroyed.threads
subproc.live.main_malloc
subproc.live.messages
subproc.live.visit
subproc.main
subproc.main.destroy_ignored
subproc.main.visit
subproc.main.visit_after
subproc.main.visit_stop
subproc.messages
subproc.new
thread.blocks
thread.destroy.heaps
thread.realloc_in_place
thread.run
visit.heap.area256
visit.heap.area64
visit.heap.area_order
visit.heap.area_stop
visit.heap.areas_only
visit.heap.block_stop
visit.heap.collected
visit.heap.empty
visit.heap.full
visit.heap.reentry
visit.heap.remote_joined
visit.main.area_stop
visit.main.areas
visit.main.baseline
visit.main.block_stop
visit.main.child
visit.main.full
visit.main.population
visit.main.setup
""".split())


def compare_runs(c_run, native_run, profile):
    traces = {side: m7.parse_options_trace(result["stdout"], side, TRACE_BEGIN, TRACE_END)
              for side, result in (("c", c_run), ("native", native_run))}
    for side, trace in traces.items():
        if set(trace) != EXPECTED_KEYS:
            raise harness.HarnessError(f"{profile} {side} original public workload fields differ: "
                f"missing={sorted(EXPECTED_KEYS-set(trace))} extra={sorted(set(trace)-EXPECTED_KEYS)}")
    m7.compare_options_traces(traces["c"], traces["native"])
    for stream in ("stdout", "stderr"):
        if c_run[stream] != native_run[stream]:
            raise harness.HarnessError(f"{profile} complete public adapter {stream} differs")
    return len(traces["c"])

def record(output, name, argv, cwd, *, runtime=False, timeout=None):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ),
        timeout=timeout if timeout is not None else 600 if runtime else 3600)
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
    output = output.resolve()
    try:
        output.relative_to(harness.ARTIFACT_ROOT.resolve())
    except ValueError as error:
        raise harness.HarnessError("public Heap output must stay inside the owning artifact root") from error
    output.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    output.chmod(0o755)
    print(f"Public Heap/subprocess adapter raw products: {output}", flush=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, failures = {}, [], []
    fixture = output / DRIVER.name
    for original in (DRIVER, harness.ROOT / "crabc-mimalloc/tests/native_heap_visit_contract.rs",
                     source / "include/mimalloc.h", source / "LICENSE", archive):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    scope = {profile: "full original public Heap and subprocess workload" for profile in profiles}
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
        client_flags = ()
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
            print(f"Public Heap/subprocess adapter {profile} ({scope[profile]}): {count} actual C/native observations match", flush=True)
        contract_build = passed("native-contract-build", [harness.require_tool("cargo"), "test",
            "--locked", "--offline", "--no-run", "--message-format=json", "--target", m4.RUST_TARGET,
            "--target-dir", str(target), "-p", "crabc-mimalloc", "--no-default-features",
            *(("--features", f"mi-{profile}") if profile != "release" else ()),
            "--test", "native_heap_visit_contract"], harness.ROOT)
        executables = []
        for line in stress.byte_record_payload(contract_build["stdout"], profile).decode().splitlines():
            try:
                artifact = json.loads(line)
            except ValueError:
                continue
            if (artifact.get("reason") == "compiler-artifact"
                and artifact.get("target", {}).get("name") == "native_heap_visit_contract"
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
        raise harness.HarnessError("source changed during public Heap/subprocess adapter execution")
    path = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), **{f"scope.{profile}": scope[profile] for profile in profiles}}, True)
    if failures:
        for failure in failures:
            print(f"RED: {failure}", flush=True)
        raise harness.HarnessError(f"public Heap/subprocess adapter has {len(failures)} failures; physical receipt {path}")
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Public Heap/subprocess adapter selected scope PASS; {path}")
    return count


def read_and_replay(profiles, replay=False):
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    covered = receipt.parameters["profiles"].split(",")
    if any(profile not in covered for profile in profiles):
        raise harness.HarnessError("retained receipt does not cover the selected profiles")
    if tuple(covered) != tuple(profile for profile in PROFILES if profile in covered):
        raise harness.HarnessError("retained adapter profiles are not an ordered selected set")
    expected_cases = []
    expected_products = {DRIVER.name, "native_heap_visit_contract.rs", "mimalloc.h", "LICENSE",
                         "mimalloc-3.5.0.tar.gz", "inputs.json"}
    for profile in covered:
        expected_cases.extend(f"{profile}-{phase}" for phase in ("oracle-build", "native-build"))
        for backend in ("c", "native"):
            expected_cases.extend(f"{profile}-{backend}-{phase}" for phase in ("compile", "imports", "link", "run"))
        expected_cases.extend(f"{profile}-{phase}" for phase in ("comparison", "native-contract-build", "native-contract-run"))
        expected_products.update(f"{profile}-{suffix}" for suffix in
            ("native-adapter.a", "oracle.o", "c", "native", "c.o", "native.o", "native-contract"))
    if receipt.case_ids() != expected_cases or set(receipt.products) != expected_products:
        raise harness.HarnessError("retained adapter build, workload, contract or products roster differs")
    print("Public Heap/subprocess adapter exact-source physical receipt: PASS")
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
                    timeout=900 if backend == "native-contract" else 600)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {name} failed; see {logs[0]}")
                results[backend] = decoded(result)
                recorded = next(case for case in receipt.cases if case["id"] == name + "-run")
                previous = next(log for log in recorded["logs"] if log.endswith(".stdout"))
                if backend != "native-contract" and stress.byte_record_payload(result["stdout"], name) != (receipt.path.parent / "logs" / previous).read_bytes():
                    raise harness.HarnessError(f"retained {name} observations differ; see {scratch}")
            count = compare_runs(results["c"], results["native"], profile)
            if harness.parse_rust_test_count(results["native-contract"]["stdout"] + results["native-contract"]["stderr"]) != 1:
                raise harness.HarnessError(f"retained {profile} native Heap contract did not execute exactly one test")
            scope = "full original public Heap and subprocess workload"
            print(f"Public Heap/subprocess adapter retained {profile} ({scope}) replay PASS")
    case = next(case for case in receipt.cases if case["id"] == profiles[0] + "-c-run")
    log = next(log for log in case["logs"] if log.endswith(".stdout"))
    return len(m7.parse_options_trace((receipt.path.parent / "logs" / log).read_text(),
        "retained public adapter", TRACE_BEGIN, TRACE_END))



def run_adapter_differential(offline: bool = True) -> dict[str, Any]:
    count = run_profiles(("release",))
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    case = next(case for case in receipt.cases if case["id"] == "release-c-run")
    log = next(log for log in case["logs"] if log.endswith(".stdout"))
    trace = m7.parse_options_trace((receipt.path.parent / "logs" / log).read_text(),
        "source public adapter", TRACE_BEGIN, TRACE_END)
    report = {"compared_key_count": count, "status": "passed", "trace": trace}
    harness.write_json(ARTIFACTS / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--profile", choices=PROFILES, default="release")
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    profiles = PROFILES if args.matrix else (args.profile,)
    try:
        if args.read or args.replay:
            read_and_replay(profiles, args.replay)
        elif not args.matrix and args.profile == "release":
            report = run_adapter_differential()
            print(f"Public adapter differential passed: {report['compared_key_count']} keys")
        else:
            run_profiles(profiles)
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Public adapter failed: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
