#!/usr/bin/env python3
"""Compare public Heap arena selection with pinned mimalloc source."""

import argparse
from pathlib import Path
import re
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import receipts


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_heap_in_arena_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-heap-in-arena"
BEGIN = "CRABC_MI_M6_CHILD_HEAP_IN_ARENA_BEGIN"
END = "CRABC_MI_M6_CHILD_HEAP_IN_ARENA_END"
EXPECTED = {
    "child.attached": "1,1",
    "child.reserved": "1,1,1,1,1",
    "child.selected": "1,1,1,1",
    "child.allocated": "1,1,1",
    "child.no_os_fallback": "1,1,1",
    "child.deleted": "1,1",
    "child.recreated": "1,1,1",
    "child.destroyed": "1",
    "child.failed_reserve": "1,1,1",
    "child.no_selection": "1,1,1",
    "child.joined": "1",
    "child.teardown": "1",
}
SOURCE = {"source.child_binding": "1,1", "source.child_no_selection": "1"}


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
RUNNER = "allocator-child-heap-in-arena"


def observe(fixture, drivers, output, cases, profile):
    traces = {}
    for side in ("c", "rust"):
        record = harness.command_record([str(drivers[side])], cwd=output, env={}, timeout_seconds=60)
        raw = output / f"{side}.json"
        log = output / f"{side}.log"
        harness.write_json(raw, record)
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        harness.require_success(record, f"{profile} {side} Child Heap arena run")
        if side == "c":
            source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$",
                                         str(record["stderr"]), re.MULTILINE))
            if source_rows != fixture.SOURCE:
                raise harness.HarnessError(f"pinned {profile} Heap arena source image changed: {source_rows}")
        traces[side] = m7.parse_options_trace(str(record["stdout"]),
            f"{profile} {side} Child Heap arena", fixture.BEGIN, fixture.END)
        if side == "c" and traces[side] != fixture.EXPECTED:
            raise harness.HarnessError(f"pinned {profile} Heap arena trace changed: {traces[side]}")
        cases.append((f"{profile}-{side}-run", 0, [raw, log]))
    m7.compare_options_traces(traces["c"], traces["rust"])
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
        "execution": execution, "source": receipts.source_seal(harness.ROOT)})
    with harness.temporary_directory("crabc-mimalloc-child-heap-arena-") as name:
        source = harness.safe_extract(archive, Path(name) / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        drivers = {side: output / f"child-heap-in-arena-{side}" for side in ("c", "rust")}
        common = [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-UNDEBUG", "-I", str(source / "include")]
        c_command = [*common, "-DCRABC_M6_SOURCE_INTERNAL=1", "-I", str(source / "src"),
                     str(retained_driver), str(source / "src/static.c"), "-pthread", "-o", str(drivers["c"])]
        build = harness.command_record(c_command, cwd=source)
        harness.write_json(output / "c-build.json", build)
        (output / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, f"{profile} Child Heap arena C build")
        cases.append((f"{profile}-c-build", 0, [output / "c-build.json", output / "c-build.log"]))
        library = m4.build_adapter_library(output, profile)
        link = harness.command_record([*common, str(retained_driver), str(library), "-pthread",
                                       "-o", str(drivers["rust"])], cwd=source)
        harness.write_json(output / "rust-link.json", link)
        (output / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, f"{profile} Child Heap arena Rust link")
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


def run_fixture(fixture, profiles):
    seal = receipts.source_seal(harness.ROOT)
    cases, products, total = [], {}, 0
    for profile in profiles:
        count, selected = run_profile(fixture, profile, cases)
        total += count
        products.update(selected)
        print(f"{profile} Child Heap arena: {count} source-built C/Rust keys match", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during Child Heap arena profile cohort")
    receipts.write_receipt(harness.ROOT, fixture.RUNNER, fixture.ARTIFACTS, products, cases,
        {"profiles": ",".join(profiles), "watchdog-seconds": "60", "workload-assertions": "active"}, True)
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
    parameters = {"profiles": ",".join(profiles), "watchdog-seconds": "60", "workload-assertions": "active"}
    if dict(receipt.parameters) != parameters:
        raise harness.HarnessError("Child Heap arena receipt profile or workload parameters differ")
    for profile in profiles:
        expected = [f"{profile}-{name}" for name in ("c-build", "rust-link", "c-run", "rust-run")]
        if receipt.case_ids(f"{profile}-") != expected:
            raise harness.HarnessError(f"{profile} Child Heap arena receipt lacks the full build/run cohort")
    print("Child Heap arena exact-source physical receipt: PASS", flush=True)
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="child-heap-arena-replay-", dir=harness.TEMP_ROOT))
        print(f"Child Heap arena reader raw executions: {scratch}", flush=True)
        for profile in profiles:
            products = receipt.path.parent / "products"
            native = harness.read_json(products / f"{profile}-native-execution-provenance.json")
            harness.validate_native_execution_provenance(native,
                                                       expected_image_id=execution["image_id"])
            output = scratch / profile
            output.mkdir()
            drivers = {}
            for side in ("c", "rust"):
                binary = output / side
                shutil.copyfile(products / f"{profile}-{side}", binary)
                binary.chmod(0o755)
                drivers[side] = binary
            observe(fixture, drivers, output, [], profile)
        print("Child Heap arena retained full-profile replay: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.modules[__name__]))
    except (harness.HarnessError, receipts.ReceiptError) as error:
        print(f"Child Heap arena failed: {error}", file=sys.stderr)
        raise SystemExit(1)
