#!/usr/bin/env python3
"""Compare Heap affinity state and logical arena selection with pinned C.

Logical node selection does not prove hardware placement or huge-page policy.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
from x86_64_m6_upstream_heap_stress import load_module, stress

receipts = load_module("heap_numa_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
RUNNER = "allocator-heap-numa-affinity"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/heap-numa-affinity"
DRIVER = harness.ALLOCATOR_ROOT / "x86_64_heap_numa_affinity_driver.c"
ENVIRONMENT = {"MIMALLOC_USE_NUMA_NODES": "3", "MIMALLOC_ARENA_IS_NUMA_LOCAL": "1"}

def trace(output):
    rows = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in rows:
            raise harness.HarnessError(f"malformed NUMA observation: {line!r}")
        rows[key] = value
    expected = {}
    for label in ("main", "child"):
        expected.update({f"{label}.{key}": value for key, value in {
            "initial":"-1", "null":"2,1", "negative":"-1", "zero":"0", "new0":"-1", "new1":"-1",
            "selected0":"1,1,1", "selected1":"2,1,1", "wrapped0":"1", "wrapped1":"1",
            "cleared0":"-1", "cleared1":"-1", "changed0":"2,1,1", "changed1":"1,1,1", "cached_count":"2", "main_selected":"1,1", "exclusive":"2,1", "refusal":"1,1,2",
        }.items()})
    if rows != expected:
        raise harness.HarnessError(f"Heap NUMA observations differ: {rows}")
    return rows


def record(output, name, command, cwd, runtime=False):
    result = stress.command_record(command, cwd=cwd,
        environment=ENVIRONMENT if runtime else dict(os.environ), timeout=60 if runtime else 3600)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream in result:
            path = output / f"{name}.{stream}"
            path.write_bytes(stress.byte_record_payload(result[stream], name))
            logs.append(path)
    return result, logs


def select_output(output=None):
    if output is None:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
        path.chmod(0o755)
        return path
    path = output.resolve()
    try:
        path.relative_to(harness.ARTIFACT_ROOT.resolve())
    except ValueError as error:
        raise harness.HarnessError("NUMA output must stay inside the owning artifact root") from error
    if path.exists():
        raise harness.HarnessError("NUMA output already exists; preserve the earlier attempt")
    path.mkdir(parents=True)
    return path


def run(output=None):
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    output = select_output(output)
    print(f"Heap NUMA raw products: {output}", flush=True)
    pin = harness.load_pin()
    source = harness.safe_extract(harness.fetch_archive(pin, True), output / "source", pin["archive_root"])
    products, cases = {}, []
    for original in (DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "environment": ENVIRONMENT, "profile": "release", "runtime_watchdog_seconds": 60,
        "boundary": "main/child logical arena affinity selection; no hardware placement claim"},
        indent=2) + "\n")
    products[inputs.name] = inputs

    def passed(name, command, cwd=source, runtime=False):
        result, logs = record(output, name, command, cwd, runtime)
        if result["kind"] != "process" or result["status"] != 0:
            raise harness.HarnessError(f"Heap NUMA {name} failed; see {logs[0]}")
        cases.append((name, 0, logs))
        return result

    compiler = harness.require_tool("musl-gcc")
    passed("c-build", [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
        "-DCRABC_NUMA_SOURCE=1", *harness.CONFIGURATION_PROFILES["release"],
        "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
        "-pthread", "-o", str(output / "numa-c")])
    # Retain the oracle's observations before building or linking the candidate.
    c_result = passed("c-run", [str(output / "numa-c")], output, True)
    c_stdout = stress.byte_record_payload(c_result["stdout"], "c-run")
    trace(c_stdout.decode("utf-8"))
    target = output / "cargo-target"
    passed("rust-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
        "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target)], harness.ROOT)
    library = output / "native-adapter.a"
    shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
    passed("rust-link", [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
        str(library), "-pthread", "-o", str(output / "numa-rust")])
    rust_result = passed("rust-run", [str(output / "numa-rust")], output, True)
    rust_stdout = stress.byte_record_payload(rust_result["stdout"], "rust-run")
    trace(rust_stdout.decode("utf-8"))
    if c_stdout != rust_stdout:
        raise harness.HarnessError("C/Rust Heap NUMA observations differ")
    products.update({name: output / name for name in ("numa-c", "numa-rust", "native-adapter.a")})
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Heap NUMA execution")
    receipt = receipts.write_receipt(harness.ROOT, RUNNER, output, products, cases,
        {"profile": "release", "boundary": "logical-affinity-selection", **ENVIRONMENT,
         "c-substrate": "pinned-musl-1.2.6", "watchdog-seconds": "60"}, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f"Heap affinity main/child logical selection and exclusive refusal: PASS; {receipt}")


def read(replay=False, output=None):
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    if output is not None:
        # --output remains a selector for callers of the earlier replay CLI.
        value = json.loads(receipt.path.read_text())["work"]
        if output.resolve() != (harness.ROOT / value).resolve():
            raise harness.HarnessError("NUMA output differs from the published receipt's work directory")
    print("Heap NUMA exact-source physical receipt: PASS")
    if not replay:
        return
    execution = harness.require_native_x86_64(require_image_identity=True)
    inputs = json.loads((receipt.path.parent / "products/inputs.json").read_text())
    harness.validate_native_execution_provenance(
        inputs["execution"], expected_image_id=execution["image_id"])
    harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="heap-numa-replay-", dir=harness.TEMP_ROOT))
    print(f"Heap NUMA reader executions: {scratch}", flush=True)
    for side in ("c", "rust"):
        binary = scratch / f"numa-{side}"
        shutil.copyfile(receipt.path.parent / "products" / binary.name, binary)
        binary.chmod(0o755)
        name = f"{side}-run"
        result, _ = record(scratch, name, [str(binary)], scratch, True)
        if result["kind"] != "process" or result["status"] != 0:
            raise harness.HarnessError(f"retained Heap NUMA {side} failed; see {scratch}")
        case = next(c for c in receipt.cases if c["id"] == name)
        for stream in ("stdout", "stderr"):
            log = next(p for p in case["logs"] if p.endswith("." + stream))
            if stress.byte_record_payload(result[stream], name) != (receipt.path.parent / "logs" / log).read_bytes():
                raise harness.HarnessError(f"retained Heap NUMA {side} {stream} differs; see {scratch}")
    print("Heap NUMA retained C/Rust physical replay: PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="fresh output inside the owning artifact root")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--read", action="store_true")
    mode.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if args.read or args.replay:
        read(args.replay, args.output)
    else:
        run(args.output)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, stress.EvidenceError, receipts.ReceiptError) as error:
        print(f"Heap NUMA failed: {error}", file=sys.stderr)
        raise SystemExit(1)
