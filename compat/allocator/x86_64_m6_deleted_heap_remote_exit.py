#!/usr/bin/env python3
"""Compare a deleted Heap's remote final free and former owner exit."""

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
import x86_64_m6_adapter as m6_adapter
from x86_64_m6_heap_convenience import record
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_ownership_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-deleted-heap-remote-exit"


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_deleted_heap_remote_exit_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-deleted-heap-remote-exit"
BEGIN = "CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_BEGIN"
END = "CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_END"
EXPECTED = {
    "before": {
        "remote.event_alloc": "1",
        "remote.event_deleted": "1",
        "remote.event_owner_return": "1",
        "remote.event_owner_exit": "1",
        "remote.event_free_start": "1",
        "remote.event_free_done": "1",
        "remote.mode": "0,1",
        "remote.ready": "1,1,1",
        "remote.published": "1,1,1,37",
        "remote.exit": "1,1",
        "remote.collect": "1,1",
        "remote.stats": "0,0,0,0,-1,0",
    },
    "after": {
        "remote.event_alloc": "1",
        "remote.event_deleted": "1",
        "remote.event_owner_return": "1",
        "remote.event_owner_exit": "1",
        "remote.event_free_start": "1",
        "remote.event_free_done": "1",
        "remote.mode": "1,1",
        "remote.ready": "1,1,1",
        "remote.published": "1,1,1,37",
        "remote.exit": "1,1",
        "remote.collect": "1,1",
        "remote.stats": "0,0,0,-1,0,0",
    },
}
EVENT_ORDER = {
    "before": ("alloc", "deleted", "free_start", "free_done", "owner_return", "owner_exit"),
    "after": ("alloc", "deleted", "owner_return", "owner_exit", "free_start", "free_done"),
}


def check_event_order(stdout: str, mode: str, label: str) -> None:
    events = tuple(
        line.removeprefix("remote.event_").split("=", 1)[0]
        for line in stdout.splitlines()
        if line.startswith("remote.event_")
    )
    if events != EVENT_ORDER[mode]:
        raise harness.HarnessError(f"{label} event order changed: {events}")


def require_diagnostic_target(record, profile, mode):
    if profile != "debug-1" or mode not in EVENT_ORDER:
        raise harness.HarnessError("heap ownership diagnostics require one debug-1 remote-free mode")
    if record.get("kind") != "process" or record.get("status") != -11:
        raise harness.HarnessError("heap ownership diagnostics require the retained pinned-C SIGSEGV")
    stdout = stress.byte_record_payload(record.get("stdout"), "remote-free crash stdout").decode()
    stderr = stress.byte_record_payload(record.get("stderr"), "remote-free crash stderr").decode()
    events = tuple(
        line.removeprefix("remote.event_").split("=", 1)[0]
        for line in stdout.splitlines()
        if line.startswith("remote.event_")
    )
    free_start = EVENT_ORDER[mode].index("free_start")
    if (events != EVENT_ORDER[mode][:free_start + 1]
            or "CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_END" in stdout):
        raise harness.HarnessError("retained remote-free SIGSEGV did not occur at the expected free boundary")
    if m6_adapter.strip_valid_client_profile_marker(profile, "c", stderr):
        raise harness.HarnessError("retained remote-free SIGSEGV has unexpected pinned-C stderr")


def _retained_diagnostic_run(mode):
    runs = sorted(ARTIFACTS.glob("run-*"), key=lambda path: path.stat().st_mtime_ns, reverse=True)
    for output in runs:
        inputs_path = output / "inputs.json"
        raw_path = output / f"debug-1-c-{mode}.json"
        retained_driver = output / DRIVER.name
        if not inputs_path.is_file() or not raw_path.is_file() or not retained_driver.is_file():
            continue
        inputs = harness.read_json(inputs_path)
        if ("debug-1" not in inputs.get("profiles", ())
                or mode not in inputs.get("modes", ())
                or inputs.get("fixture_sha256") != hashlib.sha256(retained_driver.read_bytes()).hexdigest()):
            continue
        raw = harness.read_json(raw_path)
        if raw.get("status") == -11:
            require_diagnostic_target(raw, "debug-1", mode)
            return output, inputs, raw_path, raw
    raise harness.HarnessError(f"no retained debug-1 {mode} pinned-C SIGSEGV matches this fixture")


def retained_diagnostic_runs(modes):
    return [(mode, *_retained_diagnostic_run(mode)) for mode in modes]


def diagnose_retained_crashes(modes):
    selected = retained_diagnostic_runs(modes)
    output, inputs = selected[0][1], selected[0][2]
    source = Path(inputs["source_directory"])
    if not (source / "src/static.c").is_file():
        raise harness.HarnessError("retained pinned-C source directory is missing")
    diagnostic = output / "diagnostic"
    diagnostic.mkdir(exist_ok=True)
    driver = diagnostic / DRIVER.name
    helper = diagnostic / "x86_64_m6_heap_ownership_diagnostic.h"
    shutil.copy2(DRIVER, driver)
    shutil.copy2(DRIVER.with_name(helper.name), helper)
    binary = diagnostic / "deleted-heap-remote-exit-c"
    compiler = inputs["compiler"]
    flags = [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
        *m4.api_profile_flags("debug-1"), "-UNDEBUG", "-g", "-fno-omit-frame-pointer", "-no-pie",
        "-DCRABC_MI_M6_POINTER_DIAGNOSTIC=1", "-I", str(source / "include"), "-I", str(source / "src")]
    build, _ = record(diagnostic, "c-debug1-diagnostic-build",
        [*flags, str(driver), str(source / "src/static.c"), "-pthread", "-o", str(binary)], source)
    if build["kind"] != "process" or build["status"] != 0:
        raise harness.HarnessError(f"diagnostic-only pinned-C build failed; raw {diagnostic}")
    diagnostic_inputs = diagnostic / "inputs.json"
    diagnostic_inputs.write_text(json.dumps({
        "profile": "debug-1", "raw_failures": [str(raw_path) for _, _, _, raw_path, _ in selected],
        "driver_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "compiler": compiler, "flags": flags[1:],
    }, indent=2) + "\n")
    for mode, _, _, raw_path, _ in selected:
        case = f"c-debug1-diagnostic-{mode}"
        result, _ = record(diagnostic, case, [str(binary), "--valid-domain", "debug-1", mode], source, True)
        print(f"Retained pinned-C {mode} raw status: -11 ({raw_path})", flush=True)
        print(f"Diagnostic-only pinned-C {mode} status: {result['status']}", flush=True)
        stderr = stress.byte_record_payload(result.get("stderr"), f"{case} stderr").decode()
        match = re.search(r"^m6-pointer-diagnostic signal=11 address=(0x[0-9a-f]+) instruction=(0x[0-9a-f]+) frame=(0x[0-9a-f]+)$",
            stderr, re.MULTILINE)
        if match is None:
            print(f"Diagnostic-only pinned-C {mode} did not capture SIGSEGV; raw {diagnostic}", flush=True)
            continue
        symbolizer = harness.require_tool("addr2line")
        symbol_result, _ = record(diagnostic, f"{case}-symbol", [symbolizer, "-f", "-C", "-e",
            str(binary), match.group(2)], diagnostic)
        print(f"Pinned-C {mode} signal address={match.group(1)} instruction={match.group(2)} frame={match.group(3)}",
            flush=True)
        print(stress.byte_record_payload(symbol_result["stdout"], f"{case} symbol").decode().strip(), flush=True)
    return 0


def check_ownership_observations(trace, expected, label):
    """Check fixed ownership facts while keeping source-dependent region bits.

    A freed aligned block may still occupy a registered source Page in a
    padding profile. Those boolean components come from the complete C
    caller; every native byte must still match that caller independently.
    """
    if set(trace) != set(expected):
        raise harness.HarnessError(f"{label}: original ownership observation fields differ")
    for name, wanted in expected.items():
        observed = trace[name]
        if isinstance(wanted, tuple):
            components = observed.split(",")
            matches = len(components) == len(wanted) and all(
                component in ("0", "1") if value is None else component == value
                for component, value in zip(components, wanted)
            )
        else:
            matches = observed == wanted
        if not matches:
            raise harness.HarnessError(f"{label}: original ownership observation {name} differs: {observed}")


def ownership_matrix(driver, artifacts, runner, profiles, modes, begin, end, expected,
                     order=None, source_only=False, read=False, replay=False):
    """Retain both ownership workloads without stopping at a failed profile.

    Runtime statuses stay separate from observation failures. A zero exit
    that leaves a block unfreed cannot become a passing ownership receipt.
    """
    selected_runner = runner + ("-matrix" if profiles == PROFILES else "-" + profiles[0])
    parameters = {"profiles": ",".join(profiles), "modes": ",".join(modes),
                  "watchdog-seconds": "60", "workload": "original-full",
                  "boundary": "explicit-native-mi-adapter", "source-assertions": "active"}
    if read or replay:
        receipt = receipts.read_receipt(harness.ROOT, selected_runner)
        if dict(receipt.parameters) != parameters:
            raise harness.HarnessError("ownership receipt profile or workload selection differs")
        expected_cases = []
        for profile in profiles:
            expected_cases.append(f"{profile}-oracle-build")
            if profile == "debug-1":
                expected_cases.append("debug-1-source-debug-preprocess")
            expected_cases.append(f"{profile}-native-build")
            for backend in ("c", "native"):
                expected_cases.extend(f"{profile}-{backend}-{step}" for step in ("compile", "link", *modes))
            expected_cases.extend(f"{profile}-{mode}-observations" for mode in modes)
        if receipt.case_ids() != expected_cases:
            raise harness.HarnessError("ownership receipt lacks the ordered full build/runtime/observation roster")
        if "debug-1" in profiles:
            inputs = harness.read_json(receipt.path.parent / "products" / "inputs.json")
            proof = harness.read_json(receipt.path.parent / "products" / "debug-1-source-debug-preprocess.json")
            proof = {**proof, "stdout": stress.byte_record_payload(proof["stdout"], "source debug proof").decode()}
            m4.source_debug_option_scope(proof, inputs)
        print("Heap ownership exact-source physical receipt: PASS", flush=True)
        if replay:
            execution = harness.require_native_x86_64(require_image_identity=True)
            inputs = harness.read_json(receipt.path.parent / "products" / "inputs.json")
            harness.validate_native_execution_provenance(inputs["execution"], expected_image_id=execution["image_id"])
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix="heap-ownership-replay-", dir=harness.TEMP_ROOT))
            for profile in profiles:
                for backend in ("c", "native"):
                    name = f"{profile}-{backend}"
                    binary = scratch / name
                    shutil.copyfile(receipt.path.parent / "products" / name, binary)
                    binary.chmod(0o755)
                    for mode in modes:
                        case = f"{name}-{mode}"
                        arguments = [*m6_adapter.valid_client_arguments(profile),
                                     *([] if mode == "joined" else [mode])]
                        result, _ = record(scratch, case, [str(binary), *arguments], scratch, True)
                        if result["kind"] != "process" or result["status"] != 0:
                            raise harness.HarnessError(f"retained ownership caller {case} failed; raw {scratch}")
                        m6_adapter.strip_valid_client_profile_marker(
                            profile, backend, stress.byte_record_payload(result["stderr"], case).decode())
                        recorded = next(c for c in receipt.cases if c["id"] == case)
                        for stream in ("stdout", "stderr"):
                            log = next(p for p in recorded["logs"] if p.endswith("." + stream))
                            if stress.byte_record_payload(result[stream], case) != (receipt.path.parent / "logs" / log).read_bytes():
                                raise harness.HarnessError(f"retained ownership caller {case} {stream} differs; raw {scratch}")
            print("Heap ownership retained full caller replay: PASS", flush=True)
        return
    execution = harness.require_native_x86_64(require_image_identity=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=artifacts))
    output.chmod(0o755)
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (driver, source / "include/mimalloc.h", source / "include/mimalloc-stats.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    compiler = harness.require_tool("musl-gcc")
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "modes": modes, "parameters": parameters,
        "compiler": compiler, "source_directory": str(source),
        "fixture_sha256": hashlib.sha256(driver.read_bytes()).hexdigest()}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap ownership raw products: {output}", flush=True)
    for profile in profiles:
        directory = output / profile
        directory.mkdir()
        flags = ["-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                 *m4.api_profile_flags(profile), "-UNDEBUG", "-I", str(source / "include"), "-I", str(source / "src")]

        def build(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            # A timeout has no child exit status; its raw record keeps that
            # distinction while the receipt marks the executed case failed.
            cases.append((f"{profile}-{name}", result["status"] if result["kind"] == "process" else 1, logs))
            return result["kind"] == "process" and result["status"] == 0

        oracle = directory / "oracle.o"
        oracle_ok = build("oracle-build", [compiler, *flags, "-c", str(source / "src/static.c"), "-o", str(oracle)])
        if oracle_ok:
            products[f"{profile}-oracle.o"] = oracle
        if profile == "debug-1":
            proof_command = [compiler, "-std=c11", *m4.api_profile_flags(profile), "-DMI_LIBC_MUSL=1",
                             "-I", str(source / "include"), "-E", str(source / "src/static.c")]
            proof, proof_logs = record(output, "debug-1-source-debug-preprocess", proof_command, source)
            cases.append(("debug-1-source-debug-preprocess",
                          proof["status"] if proof["kind"] == "process" else 1, proof_logs))
            if proof["kind"] != "process" or proof["status"] != 0:
                raise harness.HarnessError("debug-1 source option-use preprocessing failed")
            decoded_proof = {**proof, "stdout": stress.byte_record_payload(
                proof["stdout"], "debug-1 source debug preprocess").decode()}
            m4.source_debug_option_scope(decoded_proof, {"compiler": compiler, "source_directory": source})
            products[proof_logs[0].name] = proof_logs[0]
        library = directory / "native-mi-adapter.a"
        target = directory / "cargo-target"
        native_ok = False
        if not source_only:
            native_ok = build("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
                "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
                *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
            if native_ok:
                shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
                products[f"{profile}-native-mi-adapter.a"] = library
        observations = {}
        backends = (("c", oracle, oracle_ok),) if source_only else (("c", oracle, oracle_ok), ("native", library, native_ok))
        for backend, allocator, ready in backends:
            if not ready:
                continue
            binary = directory / backend
            caller = directory / f"{backend}.o"
            client_flags = ["-DCRABC_NATIVE_MI_ADAPTER=1"] if backend == "native" else []
            if not build(f"{backend}-compile", [compiler, *flags, *client_flags,
                                                 "-c", str(driver), "-o", str(caller)]):
                continue
            products[f"{profile}-{backend}.o"] = caller
            if not build(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)]):
                continue
            products[f"{profile}-{backend}"] = binary
            for mode in modes:
                name = f"{profile}-{backend}-{mode}"
                arguments = [*m6_adapter.valid_client_arguments(profile),
                             *([] if mode == "joined" else [mode])]
                result, logs = record(output, name, [str(binary), *arguments], directory, True)
                cases.append((name, result["status"] if result["kind"] == "process" else 1, logs))
                observations[backend, mode] = result
                print(f"Heap ownership {name}: {result['kind']} status {result['status']}", flush=True)
        for mode in modes:
            failure = []
            traces = {}
            diagnostics = {}
            raw_stdout = {}
            for backend, _, _ in backends:
                result = observations.get((backend, mode))
                if result is None or result["kind"] != "process" or result["status"] != 0:
                    failure.append(f"{backend}: caller did not complete successfully")
                    continue
                raw_stdout[backend] = stress.byte_record_payload(result["stdout"], backend)
                stdout = raw_stdout[backend].decode()
                raw_stderr = stress.byte_record_payload(result["stderr"], backend).decode()
                try:
                    diagnostics[backend] = m6_adapter.strip_valid_client_profile_marker(profile, backend, raw_stderr).encode()
                except harness.HarnessError as error:
                    failure.append(str(error))
                    diagnostics[backend] = raw_stderr.encode()
                if diagnostics[backend]:
                    failure.append(f"{backend}: ownership caller reported allocator diagnostics")
                try:
                    traces[backend] = m7.parse_options_trace(stdout, backend, begin, end)
                    if order is not None:
                        order(stdout, mode, backend)
                    check_ownership_observations(traces[backend], expected[mode], backend)
                except harness.HarnessError as error:
                    failure.append(str(error))
            if not source_only and traces.get("c") != traces.get("native"):
                failure.append("C/native ownership traces differ")
            if not source_only and raw_stdout.get("c") != raw_stdout.get("native"):
                failure.append("C/native complete caller stdout differs")
            if not source_only and diagnostics.get("c") != diagnostics.get("native"):
                failure.append("C/native diagnostics differ")
            verdict = output / f"{profile}-{mode}-observations.json"
            verdict.write_text(json.dumps({"failures": failure, "traces": traces}, indent=2) + "\n")
            cases.append((f"{profile}-{mode}-observations", int(bool(failure)), [verdict]))
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap ownership execution")
    if source_only:
        if any(status != 0 for _, status, _ in cases):
            raise harness.HarnessError(f"source ownership controls failed; raw {output}")
        return
    path = receipts.write_receipt(harness.ROOT, selected_runner, output, products, cases, parameters, True)
    print(f"Heap ownership receipt retained: {path}", flush=True)
    receipts.read_receipt(harness.ROOT, selected_runner)
    print("Heap ownership full selected profiles: PASS", flush=True)


def run_differential(source_only: bool, modes: tuple[str, ...], profiles=("release",)):
    ownership_matrix(DRIVER, ARTIFACTS, RUNNER, profiles, modes, BEGIN, END, EXPECTED,
                     check_event_order, source_only)
    return {mode: len(EXPECTED[mode]) for mode in modes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=PROFILES, default="release")
    selection.add_argument("--matrix", action="store_true", help="execute every unchanged workload in all four profiles")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--source-only", action="store_true")
    action.add_argument("--read", action="store_true")
    action.add_argument("--replay", action="store_true")
    action.add_argument("--diagnose", action="store_true")
    parser.add_argument("--mode", choices=("before", "after", "both"), default="both")
    args = parser.parse_args()
    profiles = PROFILES if args.matrix else (args.profile,)
    modes = ("before", "after") if args.mode == "both" else (args.mode,)
    if args.diagnose:
        if profiles != ("debug-1",):
            raise harness.HarnessError("--diagnose requires --profile debug-1")
        return diagnose_retained_crashes(modes)
    ownership_matrix(DRIVER, ARTIFACTS, RUNNER, profiles, modes, BEGIN, END, EXPECTED,
                     check_event_order, args.source_only, args.read, args.replay)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Deleted Heap remote exit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
