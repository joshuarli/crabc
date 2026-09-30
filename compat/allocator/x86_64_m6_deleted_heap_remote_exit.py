#!/usr/bin/env python3
"""Compare a deleted Heap's remote final free and former owner exit."""

import argparse
import hashlib
import json
from pathlib import Path
import resource
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
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
                        result, _ = record(scratch, case, [str(binary), *([] if mode == "joined" else [mode])], scratch, True)
                        if result["kind"] != "process" or result["status"] != 0:
                            raise harness.HarnessError(f"retained ownership caller {case} failed; raw {scratch}")
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
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "modes": modes, "parameters": parameters,
        "fixture_sha256": hashlib.sha256(driver.read_bytes()).hexdigest()}, indent=2) + "\n")
    products[inputs.name] = inputs
    print(f"Heap ownership raw products: {output}", flush=True)
    compiler = harness.require_tool("musl-gcc")
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
            if not build(f"{backend}-compile", [compiler, *flags, "-c", str(driver), "-o", str(caller)]):
                continue
            products[f"{profile}-{backend}.o"] = caller
            if not build(f"{backend}-link", [compiler, str(caller), str(allocator), "-pthread", "-o", str(binary)]):
                continue
            products[f"{profile}-{backend}"] = binary
            for mode in modes:
                name = f"{profile}-{backend}-{mode}"
                result, logs = record(output, name, [str(binary), *([] if mode == "joined" else [mode])], directory, True)
                cases.append((name, result["status"] if result["kind"] == "process" else 1, logs))
                observations[backend, mode] = result
                print(f"Heap ownership {name}: {result['kind']} status {result['status']}", flush=True)
        for mode in modes:
            failure = []
            traces = {}
            diagnostics = {}
            for backend, _, _ in backends:
                result = observations.get((backend, mode))
                if result is None or result["kind"] != "process" or result["status"] != 0:
                    failure.append(f"{backend}: caller did not complete successfully")
                    continue
                stdout = stress.byte_record_payload(result["stdout"], backend).decode()
                diagnostics[backend] = stress.byte_record_payload(result["stderr"], backend)
                try:
                    traces[backend] = m7.parse_options_trace(stdout, backend, begin, end)
                    if order is not None:
                        order(stdout, mode, backend)
                    if traces[backend] != expected[mode]:
                        failure.append(f"{backend}: original ownership observations differ: {traces[backend]}")
                except harness.HarnessError as error:
                    failure.append(str(error))
            if not source_only and traces.get("c") != traces.get("native"):
                failure.append("C/native ownership traces differ")
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
    parser.add_argument("--mode", choices=("before", "after", "both"), default="both")
    args = parser.parse_args()
    profiles = PROFILES if args.matrix else (args.profile,)
    modes = ("before", "after") if args.mode == "both" else (args.mode,)
    ownership_matrix(DRIVER, ARTIFACTS, RUNNER, profiles, modes, BEGIN, END, EXPECTED,
                     check_event_order, args.source_only, args.read, args.replay)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Deleted Heap remote exit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
