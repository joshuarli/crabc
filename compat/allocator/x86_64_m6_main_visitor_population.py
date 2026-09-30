#!/usr/bin/env python3
"""Compare complete main-Heap populations in selected allocator profiles."""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import load_module, stress

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_main_visitor_population_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-main-visitor-population"
CASES = (
    ("direct", "plain", "one"),
    ("fork", "plain", "one"),
    ("direct", "plain", "2"),
    ("direct", "plain", "10"),
    ("direct", "plain", "100"),
    ("direct", "plain", "250"),
    ("direct", "plain", "500"),
    ("direct", "plain", "many"),
    ("direct", "reserve", "many"),
    ("fork", "reserve", "many"),
)

THEAP_LINE = re.compile(
    r"^source\.theap_(live|destroyed|after_visit)=(0x[0-9a-f]+),(\d+),(\d+),(\d+),(\d+)$",
    re.MULTILINE,
)
CLASS_LINE = re.compile(r"^population\.class=(\d+),(\d+)$", re.MULTILINE)
REPLACED_SLOT_SIZES = (320, 640, 1280, 2560, 5120, 10240, 20480)
POPULATION_STAGES = ("before", "live", "destroyed", "visited_blocks", "after_visit", "collected")
IMAGE_STAGES = ("live", "destroyed", "after_visit")


def require_population_trace(trace: dict[str, str], case: tuple[str, str, str], side: str) -> None:
    expected = {f"population.{stage}{suffix}"
                for stage in POPULATION_STAGES for suffix in ("", "_classes")}
    expected.update(f"population.image_{stage}" for stage in IMAGE_STAGES)
    expected.update(("population.allocated", "population.image_usable"))
    if case[0] == "fork":
        expected.add("population.child")
    if case[1] == "reserve":
        expected.update(("population.reserve", "population.reserved", "population.reserved_classes"))
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} population keys differ: missing={sorted(expected - set(trace))} "
            f"extra={sorted(set(trace) - expected)}"
        )
    count = 1 if case[2] == "one" else 1000 if case[2] == "many" else int(case[2])
    if trace["population.allocated"] != str(count) or not trace["population.image_usable"].isdigit() \
            or int(trace["population.image_usable"]) == 0:
        raise harness.HarnessError(f"{side} did not create all requested live Heaps")
    if case[1] == "reserve" and trace["population.reserve"] != "0":
        raise harness.HarnessError(f"{side} did not establish the requested OS reservation")
    for stage in POPULATION_STAGES + (("reserved",) if case[1] == "reserve" else ()):
        if not re.fullmatch(r"[01](?:,[0-9]+){6},-?[0-9]+", trace[f"population.{stage}"]):
            raise harness.HarnessError(f"{side} population.{stage} is malformed")
        if not re.fullmatch(r"[0-9]+(?:,[0-9]+){5}", trace[f"population.{stage}_classes"]):
            raise harness.HarnessError(f"{side} population.{stage}_classes is malformed")
    for stage in IMAGE_STAGES:
        if not re.fullmatch(r"[01],[0-9]+,[0-9]+", trace[f"population.image_{stage}"]):
            raise harness.HarnessError(f"{side} population.image_{stage} is malformed")
    if case[0] == "fork" and trace["population.child"] != "1":
        raise harness.HarnessError(f"{side} forked population child did not complete")


def check_source_theap_collection(stderr: str, profile="release") -> None:
    states = {stage: (address, int(size), int(thread), int(used), int(head))
              for stage, address, size, thread, used, head in THEAP_LINE.findall(stderr)}
    if set(states) != {"live", "destroyed", "after_visit"}:
        raise harness.HarnessError("source detached Theap lifetime observations are incomplete")
    theap_size = 8112 if profile == "debug-1" else 8104
    live, destroyed, after = (states[stage] for stage in ("live", "destroyed", "after_visit"))
    if (live[:4], destroyed[:4], after[:4]) != (
        (live[0], theap_size, 8, 1), (live[0], theap_size, 8, 1), (live[0], theap_size, 8, 0)
    ) or live[4] != 1 or destroyed[4] & 1 != 1 or destroyed[4] & ~1 == 0 or after[4] != 1:
        raise harness.HarnessError("source detached Theap was not remotely freed then visitor-collected")


def check_replaced_slot_images(c_stderr: str, rust_stderr: str, profile="release") -> None:
    expected = sorted(SOURCE_SLOT_IMAGES[profile])
    for side, stderr in (("C", c_stderr), ("Rust", rust_stderr)):
        actual = sorted((int(size), int(used)) for size, used in CLASS_LINE.findall(stderr))
        if actual != expected:
            raise harness.HarnessError(f"{side} live detached slot images differ: {actual}")


RUNNER = "allocator-main-visitor-population"
BEGIN = "CRABC_MI_M6_MAIN_POPULATION_TRACE_BEGIN"
END = "CRABC_MI_M6_MAIN_POPULATION_TRACE_END"
WATCHDOG = 300
SOURCE_INTERNAL = True
# Padding shifts usable class labels, so the driver's release-size exclusions
# also expose ordinary metadata pages. Preserve every observed class and use.
SOURCE_SLOT_IMAGES = {
    "release": [(size, 1) for size in REPLACED_SLOT_SIZES],
    "stat-1": [(size, 1) for size in REPLACED_SLOT_SIZES],
    "stat-2": [(size, 1) for size in REPLACED_SLOT_SIZES],
    "debug-1": (
        [(size, 1) for size in (312, 376, 632, 1272, 2552, 5112, 7160, 10232, 20472)]
        + [(7160, 9)] * 111 + [(8184, 8)] * 125 + [(163832, 25)] * 40
    ),
}


def validate_population(trace, case, side):
    require_population_trace(trace, case, side)


def check_population_diagnostics(c_stderr, native_stderr, case, profile):
    if case == ("direct", "plain", "one"):
        check_source_theap_collection(c_stderr, profile)
    if case == ("direct", "plain", "many"):
        check_replaced_slot_images(c_stderr, native_stderr, profile)

PROFILES = ("release", "debug-1", "stat-1", "stat-2")
receipts = load_module("main_population_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")


def record(output, name, argv, cwd, timeout=3600, runtime=False):
    result = stress.command_record(argv, cwd=cwd,
        environment={} if runtime else dict(os.environ), timeout=timeout)
    logs = [output / f"{name}.json"]
    logs[0].write_text(json.dumps(result, indent=2) + "\n")
    for stream in ("stdout", "stderr"):
        if stream in result:
            path = output / f"{name}.{stream}"
            path.write_bytes(stress.byte_record_payload(result[stream], name))
            logs.append(path)
    return result, logs


def observe(fixture, drivers, output, cases, profile):
    differences = []
    count = 0
    for case in fixture.CASES:
        observations = {}
        for side in ("c", "native"):
            label = "-".join((profile, side, *case, "run"))
            result, logs = record(output, label, [str(drivers[side]), *case], output,
                fixture.WATCHDOG, True)
            status = result.get("status", 1)
            cases.append((label, status, logs))
            if result["kind"] != "process" or status != 0:
                differences.append(f"{label}: actual process failed; raw {logs[0]}")
            else:
                observations[side] = result
        if len(observations) != 2:
            continue
        try:
            traces = {}
            diagnostics = {}
            for side, result in observations.items():
                stdout = stress.byte_record_payload(result["stdout"], side).decode()
                diagnostics[side] = stress.byte_record_payload(result["stderr"], side).decode()
                traces[side] = m7.parse_options_trace(stdout, side, fixture.BEGIN, fixture.END)
                fixture.validate_population(traces[side], case, side)
            m7.compare_options_traces(traces["c"], traces["native"])
            fixture.check_population_diagnostics(diagnostics["c"], diagnostics["native"], case, profile)
        except harness.HarnessError as error:
            differences.append(f"{'/'.join((profile, *case))}: {error}")
        else:
            count = len(traces["c"])
            print(f"{fixture.RUNNER} {'/'.join((profile, *case))}: {count} keys PASS", flush=True)
    if differences:
        raise harness.HarnessError("\n".join(differences))
    return count


def run_profiles(fixture, profiles):
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    pin = harness.load_pin()
    fixture.ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=fixture.ARTIFACTS))
    output.chmod(0o755)
    source = harness.safe_extract(harness.fetch_archive(pin, True), output / "source", pin["archive_root"])
    products, cases, failures = {}, [], []
    for original in (fixture.DRIVER, source / "include/mimalloc.h", source / "LICENSE"):
        retained = output / original.name
        shutil.copy2(original, retained)
        products[retained.name] = retained
    inputs = output / "inputs.json"
    inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
        "profiles": profiles, "cases": fixture.CASES, "source_internal_checks": fixture.SOURCE_INTERNAL,
        "boundary": "explicit mi_* native adapter; pinned musl provides pthreads and fork",
        "runtime_watchdog_seconds": fixture.WATCHDOG}, indent=2) + "\n")
    products[inputs.name] = inputs
    compiler = harness.require_tool("musl-gcc")
    print(f"{fixture.RUNNER} raw products: {output}", flush=True)
    count = 0
    for profile in profiles:
        directory = output / profile
        directory.mkdir()

        def passed(name, argv, cwd=source):
            result, logs = record(output, f"{profile}-{name}", argv, cwd)
            cases.append((f"{profile}-{name}", result.get("status", 1), logs))
            if result["kind"] != "process" or result.get("status") != 0:
                raise harness.HarnessError(f"{profile}-{name} failed; raw {logs[0]}")

        try:
            common = ["-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                *m4.api_profile_flags(profile), "-I", str(source / "include")]
            drivers = {side: directory / side for side in ("c", "native")}
            passed("c-build", [compiler, *common,
                *(("-DCRABC_M6_SOURCE_INTERNAL=1",) if fixture.SOURCE_INTERNAL else ()),
                str(fixture.DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(drivers["c"])])
            products[f"{profile}-c"] = drivers["c"]
            target = directory / "cargo-target"
            passed("native-build", [harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
                "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
                *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())], harness.ROOT)
            library = directory / m4.ADAPTER_STATICLIB
            shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
            products[f"{profile}-native-library"] = library
            passed("native-link", [compiler, *common, str(fixture.DRIVER), str(library), "-pthread", "-o", str(drivers["native"])])
            products[f"{profile}-native"] = drivers["native"]
            count = observe(fixture, drivers, output, cases, profile)
        except harness.HarnessError as error:
            failures.append(str(error))
    if receipts.source_seal(harness.ROOT) != seal:
        failures.append("source changed during main population comparison")
    if failures:
        raise harness.HarnessError("\n".join(failures))
    canonical = tuple(profiles) == PROFILES
    path = receipts.write_receipt(harness.ROOT, fixture.RUNNER, output, products, cases,
        {"profiles": ",".join(profiles), "cases": json.dumps(fixture.CASES),
         "boundary": "explicit native-mi-adapter", "watchdog-seconds": str(fixture.WATCHDOG)}, canonical)
    if canonical:
        receipts.read_receipt(harness.ROOT, fixture.RUNNER)
    print(f"{fixture.RUNNER} {'canonical four-profile' if canonical else 'development-only'} receipt: {path}")
    return count


def dispatch(fixture, arguments=None):
    parser = argparse.ArgumentParser(description=fixture.__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=PROFILES, help="development-only selected profile")
    selection.add_argument("--matrix", action="store_true", help="canonical full four-profile population workload")
    parser.add_argument("--read", action="store_true", help="read exact-source physical receipt")
    parser.add_argument("--replay", action="store_true", help="read and execute every retained C/native workload")
    args = parser.parse_args(arguments)
    if args.read or args.replay:
        if args.profile or args.matrix:
            parser.error("reading a canonical receipt cannot select profiles")
        receipt = receipts.read_receipt(harness.ROOT, fixture.RUNNER)
        print(f"{fixture.RUNNER} exact-source physical receipt: PASS")
        if args.replay:
            harness.require_native_x86_64(require_image_identity=True)
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix=fixture.RUNNER + "-replay-", dir=harness.TEMP_ROOT))
            for profile in PROFILES:
                drivers = {}
                for side in ("c", "native"):
                    product = f"{profile}-{side}"
                    drivers[side] = scratch / product
                    shutil.copyfile(receipt.path.parent / "products" / product, drivers[side])
                    drivers[side].chmod(0o755)
                replay_cases = []
                observe(fixture, drivers, scratch, replay_cases, profile)
                for case_id, _, logs in replay_cases:
                    case = next(case for case in receipt.cases if case["id"] == case_id)
                    original = next(path for path in case["logs"] if path.endswith(".stdout"))
                    replay_stdout = next(path for path in logs if path.name.endswith(".stdout"))
                    if replay_stdout.read_bytes() != (receipt.path.parent / "logs" / original).read_bytes():
                        raise harness.HarnessError(f"retained {case_id} output differs; raw {scratch}")
            print(f"{fixture.RUNNER} retained full four-profile workloads: PASS; raw {scratch}")
    elif not args.matrix and not args.profile:
        return fixture.run_differential()
    else:
        return run_profiles(fixture, PROFILES if args.matrix else (args.profile,))


def run_differential() -> int:
    return run_profiles(sys.modules[__name__], ("release",))


def main(arguments=None):
    return dispatch(sys.modules[__name__], arguments)


if __name__ == "__main__":
    try:
        main()
    except (harness.HarnessError, receipts.ReceiptError, stress.EvidenceError) as error:
        print(f"main population failed: {error}", file=sys.stderr)
        raise SystemExit(1)
