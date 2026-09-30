#!/usr/bin/env python3
"""Compare Heap destruction while an exited creator's second worker stays attached."""

import argparse
from pathlib import Path
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import receipts


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_delete_with_attached_worker_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-delete-with-attached-worker"
BEGIN = "CRABC_MI_M6_HEAP_DELETE_WITH_ATTACHED_WORKER_BEGIN"
END = "CRABC_MI_M6_HEAP_DELETE_WITH_ATTACHED_WORKER_END"
EXPECTED = {
    "attached.owner": "1,1",
    "attached.live": "1,1,1,1",
    "attached.delete": "37,1,1,1",
    "attached.stats": "2,0",
    "attached.joined": "0,1,1",
}


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-heap-delete-attached-worker"


def observe(fixture, drivers, output, cases, profile):
    records, traces = {}, {}
    for side in ("c", "rust"):
        record = harness.command_record([str(drivers[side])], cwd=output, env={}, timeout_seconds=60)
        raw, log = output / f"{side}.json", output / f"{side}.log"
        harness.write_json(raw, record)
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        harness.require_success(record, f"{profile} {side} attached-worker Heap run")
        records[side] = record
        traces[side] = m7.parse_options_trace(str(record["stdout"]), side, fixture.BEGIN, fixture.END)
        if side == "c" and traces[side] != fixture.EXPECTED:
            raise harness.HarnessError(f"pinned {profile} attached-worker Heap changed: {traces[side]}")
        cases.append((f"{profile}-{side}-run", 0, [raw, log]))
    m7.compare_options_traces(traces["c"], traces["rust"])
    if str(records["c"]["stderr"]) != str(records["rust"]["stderr"]):
        raise harness.HarnessError(f"{profile} attached-worker Heap diagnostics differ")
    return len(traces["c"])


def run_profile(fixture, profile, cases):
    execution = harness.require_native_x86_64(require_image_identity=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    output = fixture.ARTIFACTS if profile == "release" else fixture.ARTIFACTS / profile
    output.mkdir(parents=True, exist_ok=True)
    retained_driver = output / fixture.DRIVER.name
    shutil.copy2(fixture.DRIVER, retained_driver)
    inputs = output / "inputs.json"
    harness.write_json(inputs, {"upstream": pin, "archive_sha256": harness.sha256_file(archive),
        "driver_sha256": harness.sha256_file(retained_driver), "profile": profile,
        "allocator_flags": list(m4.api_profile_flags(profile)), "workload_assertions": True,
        "diagnostics": "exact", "execution": execution, "source": receipts.source_seal(harness.ROOT)})
    with harness.temporary_directory("crabc-mimalloc-attached-worker-heap-") as name:
        source = harness.safe_extract(archive, Path(name) / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        drivers = {side: output / f"attached-worker-heap-{side}" for side in ("c", "rust")}
        common = [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-UNDEBUG", "-I", str(source / "include")]
        build = harness.command_record([*common, "-I", str(source / "src"), str(retained_driver),
            str(source / "src/static.c"), "-pthread", "-o", str(drivers["c"])], cwd=source)
        harness.write_json(output / "c-build.json", build)
        (output / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, f"{profile} attached-worker Heap C build")
        cases.append((f"{profile}-c-build", 0, [output / "c-build.json", output / "c-build.log"]))
        library = m4.build_adapter_library(output, profile)
        link = harness.command_record([*common, str(retained_driver), str(library), "-pthread",
                                       "-o", str(drivers["rust"])], cwd=source)
        harness.write_json(output / "rust-link.json", link)
        (output / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, f"{profile} attached-worker Heap Rust link")
        cases.append((f"{profile}-rust-link", 0, [output / "rust-link.json", output / "rust-link.log"]))
        count = observe(fixture, drivers, output, cases, profile)
    native = output / "native-execution-provenance.json"
    harness.write_json(native, harness.native_execution_attestation(
        execution, harness.require_native_x86_64(require_image_identity=True)))
    products = {f"{profile}-{side}": path for side, path in drivers.items()}
    products.update({f"{profile}-adapter.a": library, f"{profile}-inputs.json": inputs,
        f"{profile}-driver.c": retained_driver, f"{profile}-upstream-archive": archive,
        f"{profile}-native-execution-provenance.json": native})
    return count, products


def parameters(profiles):
    return {"profiles": ",".join(profiles), "watchdog-seconds": "60", "workload-assertions": "active",
            "diagnostics": "exact"}


def run_fixture(fixture, profiles):
    seal = receipts.source_seal(harness.ROOT)
    cases, products, total = [], {}, 0
    for profile in profiles:
        count, selected = run_profile(fixture, profile, cases)
        total += count
        products.update(selected)
        print(f"{profile} attached-worker Heap: {count} C/Rust keys and exact diagnostics match", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during attached-worker Heap profile cohort")
    receipts.write_receipt(harness.ROOT, fixture.RUNNER, fixture.ARTIFACTS, products, cases,
                           parameters(profiles), True)
    receipts.read_receipt(harness.ROOT, fixture.RUNNER)
    return total


def run_differential() -> int:
    return run_fixture(sys.modules[__name__], ("release",))


def main(fixture, argv=None):
    parser = argparse.ArgumentParser(description=fixture.__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=PROFILES, default="release")
    selection.add_argument("--matrix", action="store_true")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--read", action="store_true")
    action.add_argument("--replay", action="store_true")
    args = parser.parse_args(argv)
    profiles = PROFILES if args.matrix else (args.profile,)
    if not (args.read or args.replay):
        run_fixture(fixture, profiles)
        return 0
    receipt = receipts.read_receipt(harness.ROOT, fixture.RUNNER)
    if dict(receipt.parameters) != parameters(profiles):
        raise harness.HarnessError("attached-worker Heap receipt profile or workload parameters differ")
    for profile in profiles:
        expected = [f"{profile}-{label}" for label in ("c-build", "rust-link", "c-run", "rust-run")]
        if receipt.case_ids(f"{profile}-") != expected:
            raise harness.HarnessError(f"{profile} attached-worker Heap receipt lacks the full build/run cohort")
    print("attached-worker Heap exact-source physical receipt: PASS", flush=True)
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="attached-worker-heap-replay-", dir=harness.TEMP_ROOT))
        print(f"attached-worker Heap reader raw executions: {scratch}", flush=True)
        for profile in profiles:
            products = receipt.path.parent / "products"
            native = harness.read_json(products / f"{profile}-native-execution-provenance.json")
            harness.validate_native_execution_provenance(native, expected_image_id=execution["image_id"])
            output = scratch / profile
            output.mkdir()
            drivers = {}
            for side in ("c", "rust"):
                binary = output / side
                shutil.copyfile(products / f"{profile}-{side}", binary)
                binary.chmod(0o755)
                drivers[side] = binary
            observe(fixture, drivers, output, [], profile)
        print("attached-worker Heap retained full-profile replay: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.modules[__name__]))
    except (harness.HarnessError, receipts.ReceiptError) as error:
        print(f"attached-worker Heap failed: {error}", file=sys.stderr)
        raise SystemExit(1)
