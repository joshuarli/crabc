#!/usr/bin/env python3
"""Run unmodified pinned Heap stress against the C oracle and native adapter."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import run as harness
import x86_64_m4_gate as m4


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise harness.HarnessError(f"cannot load evidence helpers: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


stress = load_module("allocator_upstream_stress_bytes", harness.ALLOCATOR_ROOT / "upstream-stress/run.py")
receipts = load_module("allocator_heap_stress_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-upstream-heap-stress"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-upstream-heap-stress"
SOURCE_HASHES = {
    "test/test-stress-heaps.c": "0461dbb58b5a9962572ca555aca58438f88ea8855632b442ee079acd5b4abbf6",
    "test/test-stress.c": "e2bed5f2be12239b1fa696dafffda384d19140cb50a6ee2f6e096f70934d73df",
}
# Eight iterations retire Heaps after their four-iteration rolling lifetime.
# The wrapper enables large objects even at scale one; scale 101 increases
# allocation pressure without changing that source conditional.
MATRIX = ((1, 1, 1),) + tuple((workers, scale, iterations)
               for workers in (1, 2, 4, 8)
               for scale, iterations in ((1, 8), (10, 8), (101, 1)))
WATCHDOG_SECONDS = 120


def record_command(output: Path, name: str, command: list[str], cwd: Path, *, runtime: bool = False):
    record = stress.command_record(command, cwd=cwd,
                                   environment={} if runtime else dict(os.environ),
                                   timeout=WATCHDOG_SECONDS if runtime else 3600)
    record_path = output / f"{name}.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    logs = [record_path]
    for stream in ("stdout", "stderr"):
        if stream in record:
            path = output / f"{name}.{stream}"
            path.write_bytes(stress.byte_record_payload(record[stream], f"{name} {stream}"))
            logs.append(path)
    return record, logs


def require_pass(record, name: str) -> None:
    if record["kind"] != "process" or record["status"] != 0:
        raise harness.HarnessError(f"{name}: {record['kind']} status={record['status']}; raw evidence in {ARTIFACTS}")


def run_differential() -> int:
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    output.chmod(0o755)
    cases = []
    control_source = harness.ALLOCATOR_ROOT / "x86_64_m6_subproc_heap_stats_driver.c"
    retained_control = output / control_source.name
    shutil.copyfile(control_source, retained_control)
    products = {control_source.name: retained_control}
    with harness.temporary_directory("crabc-mimalloc-upstream-heap-stress-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        for relative, expected in SOURCE_HASHES.items():
            path = source / relative
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise harness.HarnessError(f"authenticated Heap stress source changed: {relative}")
            retained = output / path.name
            shutil.copyfile(path, retained)
            products[path.name] = retained
        provenance = output / "inputs.json"
        provenance.write_text(json.dumps({"upstream": pin, "source_hashes": SOURCE_HASHES,
            "matrix": MATRIX, "watchdog_seconds": WATCHDOG_SECONDS,
            "control_source_sha256": hashlib.sha256(retained_control.read_bytes()).hexdigest(),
            "execution": execution, "source": seal,
            "boundary": "mi_* native adapter; host musl provides pthreads and C process substrate",
            "profile": "release", "workload_assertions": True, "workload_modified": False}, indent=2) + "\n")
        compiler = harness.require_tool("musl-gcc")
        fixture = source / "test/test-stress-heaps.c"
        c_driver = temporary / "heap-stress-c"
        common = [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
                  "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"], "-UNDEBUG",
                  "-I", str(source / "include"), "-I", str(source / "src")]
        record, logs = record_command(output, "c-build", [*common, str(fixture), str(source / "src/static.c"),
                                                   "-pthread", "-o", str(c_driver)], source)
        require_pass(record, "unmodified Heap stress C build")
        cases.append(("c-build", 0, logs))
        shutil.copy2(c_driver, output / "heap-stress-c")
        target = temporary / "cargo-target"
        record, logs = record_command(output, "rust-build", [harness.require_tool("cargo"), "build", "--locked",
            "--release", "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE,
            "--target-dir", str(target)], harness.ROOT)
        require_pass(record, "native Heap stress adapter build")
        cases.append(("rust-build", 0, logs))
        library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        shutil.copyfile(library, output / "native-mi-adapter.a")
        rust_driver = temporary / "heap-stress-rust"
        record, logs = record_command(output, "rust-link", [*common, str(fixture), str(library),
                                                       "-pthread", "-o", str(rust_driver)], source)
        require_pass(record, "unmodified Heap stress Rust link")
        cases.append(("rust-link", 0, logs))
        shutil.copy2(rust_driver, output / "heap-stress-rust")
        expected_controls = {
            "null": b"null-output=empty\n",
            "main": b"heap 2\nheap 1\nheap 0\nmeta 0\nsubproc 0\nformat-and-reentry=ok\n",
            "empty": b"heap 0\nmeta 1\nsubproc 1\nformat-and-reentry=ok\n",
            "live-child": b"heap 2\nheap 1\nheap 0\nmeta 1\nsubproc 1\nformat-and-reentry=ok\n",
            "default": b"default-route=stderr\n",
        }
        for backend, allocator in (("c", source / "src/static.c"), ("rust", library)):
            control = temporary / f"heap-stats-{backend}"
            record, logs = record_command(output, f"stats-{backend}-build",
                [*common, str(retained_control), str(allocator), "-pthread", "-o", str(control)], source)
            require_pass(record, f"selected-subprocess statistics {backend} build")
            cases.append((f"stats-{backend}-build", 0, logs))
            shutil.copy2(control, output / control.name)
            products[control.name] = output / control.name
            for mode, expected in expected_controls.items():
                case = f"stats-{backend}-{mode}"
                record, logs = record_command(output, case, [str(control), mode], temporary, runtime=True)
                require_pass(record, case)
                stdout = stress.byte_record_payload(record["stdout"], case)
                stderr = stress.byte_record_payload(record["stderr"], case)
                if stdout != expected:
                    raise harness.HarnessError(f"{case}: selected Heap/meta/subprocess order or callback differs; raw evidence in {output}")
                if mode == "default":
                    headers = [line for line in stderr.splitlines()
                               if line.startswith((b"heap ", b"meta ", b"subproc "))]
                    if headers != [b"heap 0", b"meta 1", b"subproc 1"]:
                        raise harness.HarnessError(f"{case}: process default output route differs")
                elif stderr:
                    raise harness.HarnessError(f"{case}: unexpected callback-route diagnostics; raw evidence in {output}")
                cases.append((case, 0, logs))
        for workers, scale, iterations in MATRIX:
            expected = (f"Using {workers} threads with a {scale}% load-per-thread and {iterations} iterations"
                        " (allow large objects) (using 4 rolling heaps)\n").encode()
            for backend, binary in (("c", c_driver), ("rust", rust_driver)):
                case = f"{backend}-workers-{workers}-scale-{scale}-iterations-{iterations}"
                record, logs = record_command(output, case, [str(binary), str(workers), str(scale), str(iterations)],
                                               temporary, runtime=True)
                require_pass(record, case)
                stdout = stress.byte_record_payload(record["stdout"], case)
                if stdout != expected:
                    raise harness.HarnessError(f"{case}: source workload announcement differs; raw evidence in {ARTIFACTS}")
                cases.append((case, 0, logs))
        products.update({"heap-stress-c": output / "heap-stress-c", "heap-stress-rust": output / "heap-stress-rust",
                         "native-mi-adapter.a": output / "native-mi-adapter.a", "inputs.json": provenance})
        if receipts.source_seal(harness.ROOT) != seal:
            raise harness.HarnessError("source changed during upstream Heap stress execution")
        receipt = receipts.write_receipt(harness.ROOT, RUNNER, ARTIFACTS, products, cases,
            {"workers": "1,2,4,8", "scale-iterations": "1:8,10:8,101:1", "rolling-heaps": "4",
             "watchdog-seconds": str(WATCHDOG_SECONDS), "boundary": "native-mi-adapter", "profile": "release", "workload-assertions": "active"}, True)
        receipts.read_receipt(harness.ROOT, RUNNER)
        print(f"unmodified upstream Heap stress: {len(MATRIX)} C/Rust pairs passed; {receipt}")
    return len(MATRIX)


if __name__ == "__main__":
    try:
        run_differential()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap stress failed: {error}", file=sys.stderr)
        raise SystemExit(1)
