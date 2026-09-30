#!/usr/bin/env python3
"""Compare Heap affinity state and logical arena selection with pinned C."""
import argparse
import hashlib
import json
import shutil
import os
from pathlib import Path
import run as harness
import x86_64_m4_gate as m4

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

def execute(output):
    rows = {}
    for side in ("c", "rust"):
        result = harness.command_record([str(output / f"numa-{side}")], cwd=output, env=ENVIRONMENT, timeout_seconds=60)
        (output / f"{side}.execution.json").write_text(json.dumps(result, indent=2)+"\n")
        harness.require_success(result, f"Heap NUMA {side} runtime")
        rows[side] = trace(result["stdout"])
    if rows["c"] != rows["rust"]:
        raise harness.HarnessError("C/Rust Heap NUMA observations differ")
    print("Heap affinity state, main/child allocation selection and exclusive refusal: PASS")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64()
    output = args.output.resolve()
    try:
        output.relative_to(harness.ARTIFACT_ROOT.resolve())
    except ValueError as error:
        raise harness.HarnessError("NUMA output must stay inside the owning artifact root") from error
    if args.replay:
        identities = json.loads((output / "artifacts.json").read_text())
        for name, digest in identities.items():
            if name not in {"numa-c", "numa-rust", "native-adapter.a"}:
                raise harness.HarnessError("unexpected retained NUMA input")
            if hashlib.sha256((output / name).read_bytes()).hexdigest() != digest:
                raise harness.HarnessError(f"retained NUMA bytes changed: {name}")
        if set(identities) != {"numa-c", "numa-rust", "native-adapter.a"}:
            raise harness.HarnessError("missing retained NUMA input")
        for side in ("c", "rust"):
            old = json.loads((output / f"{side}.execution.json").read_text())
            harness.require_success(old, f"original Heap NUMA {side}")
            result = harness.command_record([str(output / f"numa-{side}")], cwd=output, env=ENVIRONMENT, timeout_seconds=60)
            harness.require_success(result, f"retained Heap NUMA {side}")
            if trace(old["stdout"]) != trace(result["stdout"]):
                raise harness.HarnessError(f"retained {side} observations changed")
        print("Retained C/Rust NUMA executable replay: PASS")
        return
    if output.exists():
        raise harness.HarnessError("NUMA output already exists; preserve the earlier attempt")
    output.mkdir(parents=True)
    source = harness.safe_extract(harness.fetch_archive(harness.load_pin(), True), output / "source", harness.load_pin()["archive_root"])
    compiler = harness.require_tool("musl-gcc")
    command = [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1", "-DCRABC_NUMA_SOURCE=1", *harness.CONFIGURATION_PROFILES["release"], "-I", str(source/"include"), str(DRIVER), str(source/"src/static.c"), "-pthread", "-o", str(output/"numa-c")]
    result = harness.command_record(command, cwd=source)
    (output/"c-build.json").write_text(json.dumps(result,indent=2)+"\n")
    harness.require_success(result,"Heap NUMA pinned C build")
    # Keep the oracle's actual observations even when the absent candidate export cannot link.
    result = harness.command_record([str(output/"numa-c")],cwd=output,env=ENVIRONMENT,timeout_seconds=60)
    (output/"c.execution.json").write_text(json.dumps(result,indent=2)+"\n")
    harness.require_success(result,"Heap NUMA pinned C runtime")
    trace(result["stdout"])
    target = output.parent / "heap-numa-shared-build" / "cargo-target"
    build = harness.command_record(
        [harness.require_tool("cargo"), "build", "--locked", "--release", "--target",
         m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target)],
        cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m4.EVIDENCE_TIMEOUT_SECONDS,
    )
    (output / "rust-build.json").write_text(json.dumps(build, indent=2) + "\n")
    harness.require_success(build, "Heap NUMA native adapter build")
    library = output / "native-adapter.a"
    shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
    result = harness.command_record([compiler,"-std=c11","-O2","-I",str(source/"include"),str(DRIVER),str(library),"-pthread","-o",str(output/"numa-rust")],cwd=source)
    (output/"rust-link.json").write_text(json.dumps(result,indent=2)+"\n")
    harness.require_success(result,"Heap NUMA native adapter link")
    (output / "artifacts.json").write_text(json.dumps({
        name: hashlib.sha256((output / name).read_bytes()).hexdigest()
        for name in ("numa-c", "numa-rust", "native-adapter.a")
    }, indent=2) + "\n")
    execute(output)

if __name__ == "__main__":
    main()
