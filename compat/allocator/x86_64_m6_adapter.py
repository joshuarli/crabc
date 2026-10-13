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
CONTRACT = "public_heap_and_theap_visitation_preserve_live_population_after_prior_heap_history"
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
unabandon.pages
unabandon.pages_abandoned
unabandon.os.pages
unabandon.os.pages_abandoned
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

_FALLBACK_WARNING = (
    "unable to allocate aligned OS memory directly, fall back to over-allocation "
    "(size: {size} bytes, address: {address}, alignment: {alignment}, commit: {commit})\n"
)
_DEBUG_SUBPROC_DIAGNOSTICS = {
    "subproc.add_main.messages": (
        ("error", "allocation request is too large (9223372036854775807 * 3 bytes)\n"),
        *(("warning", (0x340000, 0x10000000, 0)) for _ in range(10)),
    ),
    "subproc.live.messages": (
        ("warning", (0x40000000, 0x10000000, 1)),
    ),
    "subproc.messages": (
        ("warning", (0x40000000, 0x10000000, 1)),
        ("warning", (0x110000, 0x10000000, 0)),
        ("warning", (0x240000, 0x10000000, 0)),
        ("warning", (0x8400000, 0x10000000, 0)),
        ("error", "aligned allocation with a large alignment cannot be used with an alignment offset "
                   "(size 4096, alignment 1048576, offset 7)\n"),
        ("error", "allocation request is too large (9223372036854775807 * 3 bytes)\n"),
        ("warning", "requested alignment is too large (262144 KiB)\n"),
        ("warning", "requested alignment is too large (262144 KiB)\n"),
        ("error", "unable to allocate memory (4096 bytes)\n"),
        ("error", "allocation request is too large (9223372036854775807 * 3 bytes)\n"),
        ("error", "allocation request is too large (9223372036854775807 * 3 bytes)\n"),
    ),
}
_FALLBACK_WARNING_RE = re.compile(
    r"unable to allocate aligned OS memory directly, fall back to over-allocation "
    r"\(size: (0x[0-9A-Fa-f]+) bytes, address: (0x[0-9A-Fa-f]+), "
    r"alignment: (0x[0-9A-Fa-f]+), commit: ([01])\)\n"
)


def _canonicalize_debug_subproc_diagnostics(trace, side):
    """Pin these source warnings while masking only their released map address."""

    canonical = dict(trace)
    for key, expected in _DEBUG_SUBPROC_DIAGNOSTICS.items():
        try:
            chunks = [bytes.fromhex(part).decode("utf-8") for part in trace[key].split(":") if part]
        except (ValueError, UnicodeDecodeError) as error:
            raise harness.HarnessError(f"debug-1 {side} {key} has malformed callback bytes") from error
        if len(chunks) != 2 * len(expected):
            raise harness.HarnessError(f"debug-1 {side} {key} diagnostic count differs: "
                                       f"expected={len(expected)} observed={len(chunks) // 2}")

        normalized = []
        for index, (severity, expected_body) in enumerate(expected):
            prefix, body = chunks[2 * index:2 * index + 2]
            if prefix != f"mimalloc: {severity}: thread 0xTID: ":
                raise harness.HarnessError(f"debug-1 {side} {key} diagnostic {index} prefix differs")
            if isinstance(expected_body, tuple):
                match = _FALLBACK_WARNING_RE.fullmatch(body)
                if match is None:
                    raise harness.HarnessError(f"debug-1 {side} {key} aligned-OS warning {index} schema differs")
                size, address, alignment, commit = match.groups()
                expected_size, expected_alignment, expected_commit = expected_body
                address_value = int(address, 16)
                alignment_value = int(alignment, 16)
                if (int(size, 16) != expected_size or alignment_value != expected_alignment
                        or int(commit) != expected_commit):
                    raise harness.HarnessError(f"debug-1 {side} {key} aligned-OS warning {index} fields differ")
                if (address_value == 0 or address_value > (1 << 64) - 1
                        or address_value % 4096 != 0
                        or address_value % alignment_value == 0):
                    raise harness.HarnessError(f"debug-1 {side} {key} aligned-OS warning {index} candidate geometry differs")
                body = (body[:match.start(2)] + "0xADDRESS" + body[match.end(2):])
            elif body != expected_body:
                raise harness.HarnessError(f"debug-1 {side} {key} diagnostic {index} body differs")
            normalized.extend((prefix.encode().hex(), body.encode().hex()))
        canonical[key] = ":".join(normalized)
    return canonical


def compare_runs(c_run, native_run, profile):
    traces = {side: m7.parse_options_trace(result["stdout"], side, TRACE_BEGIN, TRACE_END)
              for side, result in (("c", c_run), ("native", native_run))}
    for side, trace in traces.items():
        if set(trace) != EXPECTED_KEYS:
            raise harness.HarnessError(f"{profile} {side} original public workload fields differ: "
                f"missing={sorted(EXPECTED_KEYS-set(trace))} extra={sorted(set(trace)-EXPECTED_KEYS)}")
    if profile == "debug-1":
        traces = {side: _canonicalize_debug_subproc_diagnostics(trace, side)
                  for side, trace in traces.items()}
    m7.compare_options_traces(traces["c"], traces["native"])
    for key in ("unabandon.pages_abandoned", "unabandon.os.pages_abandoned"):
        if traces["c"][key] != "1,0":
            raise harness.HarnessError(f"{profile} {key} did not return to its pre-allocation count: "
                f"{traces['c'][key]}")
    stdout = {"c": c_run["stdout"], "native": native_run["stdout"]}
    stderr = {"c": c_run["stderr"], "native": native_run["stderr"]}
    if profile == "debug-1":
        for side in ("c", "native"):
            for key in _DEBUG_SUBPROC_DIAGNOSTICS:
                pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
                stdout[side], count = pattern.subn(f"{key}={traces[side][key]}", stdout[side])
                if count != 1:
                    raise harness.HarnessError(f"debug-1 {side} {key} stdout row is not unique")
        expected = {
            "c": "m6-valid-domain profile=debug-1 backend=c guarded_precise=1",
            "native": "m6-valid-domain profile=debug-1 backend=native guarded_precise=0",
        }
        for side, record in (("c", c_run), ("native", native_run)):
            marker = expected[side]
            markers = re.findall(r"^m6-valid-domain .*?$", record["stderr"], re.MULTILINE)
            if markers != [marker]:
                raise harness.HarnessError(f"debug-1 {side} valid-client source/profile marker differs")
            stderr[side] = re.sub(r"^m6-valid-domain .*?\n", "", record["stderr"], count=1,
                                  flags=re.MULTILINE)
    for stream, c_value, native_value in (
        ("stdout", stdout["c"], stdout["native"]),
        ("stderr", stderr["c"], stderr["native"]),
    ):
        if c_value != native_value:
            raise harness.HarnessError(f"{profile} complete public adapter {stream} differs")
    return len(traces["c"])


def compare_precondition_control(profile, c_run, native_run):
    arguments = "100,64;200,24"
    expected = {"control.input": arguments, "control.outcome": "1,0,1", "control.codes": "22"}
    if native_run["status"] != 0:
        raise harness.HarnessError(f"{profile} native invalid-alignment control did not return normally")
    native_trace = m7.parse_options_trace(native_run["stdout"], "native invalid-alignment control",
        TRACE_BEGIN, TRACE_END)
    if (set(native_trace) != {*expected, "control.messages"}
            or any(native_trace.get(key) != value for key, value in expected.items())
            or not native_trace["control.messages"]):
        raise harness.HarnessError(f"{profile} native invalid-alignment control differs: {native_trace}")
    if profile == "debug-1":
        if c_run["status"] != 0:
            raise harness.HarnessError("debug-1 C invalid-alignment control did not contain its source assertion")
        c_trace = m7.parse_options_trace(c_run["stdout"], "debug-1 C invalid-alignment control",
            TRACE_BEGIN, TRACE_END)
        diagnostic = c_run["stderr"]
        if (set(c_trace) != {"control.input", "control.source_abort"}
                or c_trace != {"control.input": arguments, "control.source_abort": "1,6"}
                or 'assertion: "mi_alignment_is_valid(alignment)"' not in diagnostic
                or "mi_theap_realloc_zero_aligned_at" not in diagnostic):
            raise harness.HarnessError("debug-1 C invalid-alignment control missed the pinned source assertion")
    else:
        if c_run["status"] != 0:
            raise harness.HarnessError(f"{profile} C invalid-alignment control did not return normally")
        c_trace = m7.parse_options_trace(c_run["stdout"], "C invalid-alignment control",
            TRACE_BEGIN, TRACE_END)
        if (set(c_trace) != {*expected, "control.messages"}
                or any(c_trace.get(key) != value for key, value in expected.items())):
            raise harness.HarnessError(f"{profile} C invalid-alignment control differs: {c_trace}")
        m7.compare_options_traces(c_trace, native_trace)


def compare_aligned_offset_control(c_run, native_run):
    """Require the source debug word-alignment rejection as a bounded control."""

    expected_markers = {
        "c": "m6-alignment-control profile=debug-1 backend=c guarded_precise=0",
        "native": "m6-alignment-control profile=debug-1 backend=native guarded_precise=0",
    }
    parsed = {}
    for side, record in (("c", c_run), ("native", native_run)):
        if record["status"] != 0:
            raise harness.HarnessError(f"debug-1 {side} aligned-offset control failed")
        markers = re.findall(r"^m6-alignment-control .*?$", record["stderr"], re.MULTILINE)
        if markers != [expected_markers[side]]:
            raise harness.HarnessError(f"debug-1 {side} aligned-offset option marker differs")
        if re.sub(r"^m6-alignment-control .*?\n", "", record["stderr"], count=1,
                  flags=re.MULTILINE):
            raise harness.HarnessError(f"debug-1 {side} aligned-offset control wrote unexpected stderr")
        parsed[side] = m7.parse_options_trace(record["stdout"], f"debug-1 {side} aligned-offset control",
            TRACE_BEGIN, TRACE_END)
        if set(parsed[side]) != {"control.pointer", "control.pages", "control.codes", "control.messages"}:
            raise harness.HarnessError(f"debug-1 {side} aligned-offset control fields differ")

    pointer = [parsed[side]["control.pointer"].split(",") for side in ("c", "native")]
    if any(values != ["1", "28"] for values in pointer):
        raise harness.HarnessError("debug-1 aligned-offset control did not return the valid offset pointer")

    pages = {side: [int(value) for value in parsed[side]["control.pages"].split(",")]
             for side in ("c", "native")}
    if any(len(values) != 2 or values[0] <= 0 for values in pages.values()):
        raise harness.HarnessError("debug-1 aligned-offset control did not allocate a page")
    if pages != {"c": [2, 2], "native": [2, 1]}:
        raise harness.HarnessError("debug-1 aligned-offset option-0 control page counts differ")

    c_messages = [bytes.fromhex(message).decode()
                  for message in parsed["c"]["control.messages"].split(":") if message]
    if (parsed["c"]["control.codes"] != "22" or c_messages != [
            "mimalloc: error: thread 0xTID: ",
            "mi_free: invalid (unaligned) pointer: 0xCLIENT\n"]):
        raise harness.HarnessError("debug-1 C option-0 control missed its diagnostic or EINVAL callback")
    if parsed["native"]["control.codes"] or parsed["native"]["control.messages"]:
        raise harness.HarnessError("debug-1 native option-0 valid client reported an invalid pointer")

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
    scope = {profile: "full valid public Heap and subprocess workload with arena and OS abandoned-singleton release witnesses; separate invalid alignment violates the source debug precondition (C asserts, Rust reports EINVAL), so this bounded control does not claim matched valid-client fatal semantics"
             for profile in profiles}
    if "debug-1" in profiles:
        scope["debug-1"] += "; the source C valid-client run enables guarded_precise only after the pinned debug source's single active option-use is proved; Rust remains at option 0, and a separate option-0 aligned-offset control retains the C rejection, EINVAL, diagnostic, and live page"
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
        common = ["-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-I", str(source / "include"), "-I", str(source / "src")]
        oracle = directory / "oracle.o"
        passed("oracle-build", [compiler, "-std=c11", *common, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        if profile == "debug-1":
            preprocess, logs = record(output, "debug-1-source-debug-preprocess", [
                compiler, "-std=c11", *m4.api_profile_flags(profile), "-DMI_LIBC_MUSL=1",
                "-I", str(source / "include"), "-E", str(source / "src/static.c"),
            ], source)
            status = preprocess.get("status", 1) if preprocess["kind"] == "process" else 1
            cases.append(("debug-1-source-debug-preprocess", status, logs))
            if status != 0:
                raise harness.HarnessError("debug-1 source option-use preprocessing failed")
            m4.source_debug_option_scope(preprocess, {"compiler": compiler, "source_directory": source})
            products[logs[0].name] = logs[0]
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
            client_flags = ("-DCRABC_NATIVE_MI_ADAPTER=1",) if backend == "native" else ()
            binary = directory / backend
            caller = directory / f"{backend}.o"
            passed(f"{backend}-compile", [compiler, "-std=c11", *common, *client_flags,
                "-c", str(fixture), "-o", str(caller)])
            passed(f"{backend}-imports", [harness.require_tool("nm"), "-u", str(caller)])
            passed(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)])
            products[f"{profile}-{backend}"] = binary
            products[f"{profile}-{backend}.o"] = caller
            run_arguments = [str(binary)]
            if profile == "debug-1":
                run_arguments += ["--valid-domain", "debug-1"]
            result, logs = record(output, f"{profile}-{backend}-run", run_arguments, directory, runtime=True)
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
        if profile == "debug-1":
            control_results, control_logs = {}, []
            for backend in ("c", "native"):
                result, logs = record(output, f"{profile}-{backend}-aligned-offset-control-run",
                    [str(directory / backend), "source-aligned-offset-control"], directory, runtime=True)
                status = result.get("status", 1) if result["kind"] == "process" else 1
                cases.append((f"{profile}-{backend}-aligned-offset-control-run", status, logs))
                control_results[backend] = decoded(result)
                control_logs.extend(logs)
            try:
                compare_aligned_offset_control(control_results["c"], control_results["native"])
            except (harness.HarnessError, UnicodeError, ValueError) as error:
                failures.append(f"{profile}: {error}; raw in {output}")
                cases.append((f"{profile}-aligned-offset-control-comparison", 1, control_logs))
            else:
                cases.append((f"{profile}-aligned-offset-control-comparison", 0, control_logs))
        control_results, control_logs = {}, []
        for backend in ("c", "native"):
            result, logs = record(output, f"{profile}-{backend}-precondition-aligned-invalid-run",
                [str(directory / backend), "precondition:realloc-aligned-invalid"], directory, runtime=True)
            status = result.get("status", 1) if result["kind"] == "process" else 1
            cases.append((f"{profile}-{backend}-precondition-aligned-invalid-run", status, logs))
            control_results[backend] = decoded(result)
            control_logs.extend(logs)
        try:
            compare_precondition_control(profile, control_results["c"], control_results["native"])
        except (harness.HarnessError, UnicodeError) as error:
            failures.append(f"{profile}: {error}; raw in {output}")
            cases.append((f"{profile}-precondition-aligned-invalid-comparison", 1, control_logs))
        else:
            cases.append((f"{profile}-precondition-aligned-invalid-comparison", 0, control_logs))
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
        expected_cases.append(f"{profile}-oracle-build")
        if profile == "debug-1":
            expected_cases.append("debug-1-source-debug-preprocess")
            expected_products.add("debug-1-source-debug-preprocess.json")
        expected_cases.append(f"{profile}-native-build")
        for backend in ("c", "native"):
            expected_cases.extend(f"{profile}-{backend}-{phase}" for phase in ("compile", "imports", "link", "run"))
        expected_cases.append(f"{profile}-comparison")
        if profile == "debug-1":
            expected_cases.extend((f"{profile}-c-aligned-offset-control-run",
                f"{profile}-native-aligned-offset-control-run",
                f"{profile}-aligned-offset-control-comparison"))
        expected_cases.extend((
            f"{profile}-c-precondition-aligned-invalid-run",
            f"{profile}-native-precondition-aligned-invalid-run",
            f"{profile}-precondition-aligned-invalid-comparison",
            f"{profile}-native-contract-build", f"{profile}-native-contract-run"))
        expected_products.update(f"{profile}-{suffix}" for suffix in
            ("native-adapter.a", "oracle.o", "c", "native", "c.o", "native.o", "native-contract"))
    if receipt.case_ids() != expected_cases or set(receipt.products) != expected_products:
        raise harness.HarnessError("retained adapter build, workload, contract or products roster differs")
    if "debug-1" in covered:
        preprocess = harness.read_json(receipt.path.parent / "products/debug-1-source-debug-preprocess.json")
        command = preprocess.get("command", [])
        if len(command) < 2 or not command[-1].endswith("/src/static.c"):
            raise harness.HarnessError("retained debug source option proof has no pinned source input")
        source_directory = Path(command[-1]).parent.parent
        m4.source_debug_option_scope(preprocess, {"compiler": command[0], "source_directory": source_directory})
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
                elif profile == "debug-1":
                    argv += ["--valid-domain", "debug-1"]
                result, logs = record(scratch, name, argv, scratch, runtime=True,
                    timeout=900 if backend == "native-contract" else 600)
                if result["kind"] != "process" or result["status"] != 0:
                    raise harness.HarnessError(f"retained {name} failed; see {logs[0]}")
                results[backend] = decoded(result)
                recorded = next(case for case in receipt.cases if case["id"] == name + "-run")
                if backend != "native-contract":
                    for stream in ("stdout", "stderr"):
                        previous = next(log for log in recorded["logs"] if log.endswith(f".{stream}"))
                        if stress.byte_record_payload(result[stream], name) != (receipt.path.parent / "logs" / previous).read_bytes():
                            raise harness.HarnessError(f"retained {name} {stream} differs; see {scratch}")
            count = compare_runs(results["c"], results["native"], profile)
            if profile == "debug-1":
                controls = {}
                for backend in ("c", "native"):
                    control_name = f"{profile}-{backend}-aligned-offset-control-run"
                    binary = scratch / f"{profile}-{backend}"
                    result, _ = record(scratch, control_name,
                        [str(binary), "source-aligned-offset-control"], scratch, runtime=True)
                    controls[backend] = decoded(result)
                    retained = next(case for case in receipt.cases if case["id"] == control_name)
                    for stream in ("stdout", "stderr"):
                        retained_log = next(log for log in retained["logs"] if log.endswith(f".{stream}"))
                        if stress.byte_record_payload(result[stream], control_name) != (receipt.path.parent / "logs" / retained_log).read_bytes():
                            raise harness.HarnessError(f"retained {control_name} {stream} differs; see {scratch}")
                compare_aligned_offset_control(controls["c"], controls["native"])
            controls = {}
            for backend in ("c", "native"):
                control_name = f"{profile}-{backend}-precondition-aligned-invalid-run"
                binary = scratch / f"{profile}-{backend}"
                result, _ = record(scratch, control_name,
                    [str(binary), "precondition:realloc-aligned-invalid"], scratch, runtime=True)
                controls[backend] = decoded(result)
                retained = next(case for case in receipt.cases if case["id"] == control_name)
                retained_stdout = next(log for log in retained["logs"] if log.endswith(".stdout"))
                retained_stderr = next(log for log in retained["logs"] if log.endswith(".stderr"))
                if (result["kind"] != "process" or result["status"] != retained["status"]
                        or stress.byte_record_payload(result["stdout"], control_name)
                            != (receipt.path.parent / "logs" / retained_stdout).read_bytes()
                        or stress.byte_record_payload(result["stderr"], control_name)
                            != (receipt.path.parent / "logs" / retained_stderr).read_bytes()):
                    raise harness.HarnessError(f"retained {control_name} differs; see {scratch}")
            compare_precondition_control(profile, controls["c"], controls["native"])
            if harness.parse_rust_test_count(results["native-contract"]["stdout"] + results["native-contract"]["stderr"]) != 1:
                raise harness.HarnessError(f"retained {profile} native Heap contract did not execute exactly one test")
            scope = "full valid public Heap and subprocess workload with arena and OS abandoned-singleton release witnesses; separate invalid alignment violates the source debug precondition (C asserts, Rust reports EINVAL), so this bounded control does not claim matched valid-client fatal semantics"
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
