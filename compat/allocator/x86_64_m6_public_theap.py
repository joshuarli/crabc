#!/usr/bin/env python3
"""Compare public default-Theap switching and direct allocation with pinned C."""

import argparse
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
from x86_64_m6_upstream_heap_stress import receipts


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_theap_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-theap"
BEGIN = "CRABC_MI_M6_PUBLIC_THEAP_TRACE_BEGIN"
END = "CRABC_MI_M6_PUBLIC_THEAP_TRACE_END"
SOURCE_STAGES = {
    "base": "1,1,0",
    "other": "1,1,1",
    "reject": "1,1",
    "direct_before": "1,1",
    "switch": "1,1,1",
    "allocate": "1,1,1,1",
    "still_switched": "1,1",
    "interleaved": "1",
    "variants": "1,1,1,1,1,1,1,1,1",
    "overflow": "1,1",
    "bad_alignment": "1,1",
    "aligned_selection": "1,1,1,1",
    "default_aligned_growth": "1,1,1",
    "reuse": "1,1,1",
    "expand": "1,1,1",
    "failed_realloc": "1,1,1,1",
    "cross_heap": "1,1,1,1",
    "zero_realloc": "1,1",
    "null_rezalloc": "1,1",
    "guarded": "1,1,1,1,1,1,1,1,1",
    "stats": "1,1,1,1,1,1,1",
    "visitor": "1,1,1,1,1,1,1,1",
    "collect": "1,1,1,1",
    "restore": "1,1",
    "after": "1,1",
    "delete_live": "1,1,1",
    "done": "1",
}
SOURCE_TRACE = {
    **{f"{context}.{stage}": value
       for context in ("main", "worker", "child", "fork")
       for stage, value in SOURCE_STAGES.items()},
    "main.after_worker": "1",
    "main.after_child": "1",
    "main.after_fork": "1,1",
    "fork.base": "1,0,1",
}


def require_trace(trace: dict[str, str], side: str, guarded_only: bool = False) -> None:
    selected_stages = {"base", "other", "reject", "direct_before", "switch", "guarded", "restore", "done"}
    expected = ({key: value for key, value in SOURCE_TRACE.items()
                 if key.rsplit(".", 1)[-1] in selected_stages or key.startswith("main.after_")}
                if guarded_only else SOURCE_TRACE)
    if set(trace) != set(expected):
        raise harness.HarnessError(
            f"{side} public Theap keys differ: "
            f"missing={sorted(set(expected) - set(trace))} "
            f"extra={sorted(set(trace) - set(expected))}"
        )
    for key, value in trace.items():
        if not re.fullmatch(r"[01](?:,[01])*", value):
            raise harness.HarnessError(f"{side} {key} is malformed: {value}")
    if side == "c" and trace != expected:
        raise harness.HarnessError(f"pinned C public Theap image changed: {trace}")


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
AVAILABLE_PROFILES = (*PROFILES, "secure-1", "secure-2", "secure-3", "debug-2", "debug-3")
RUNNER = "allocator-public-theap"
DIRECT_TEST = "public_theap_selection_allocation_collection_and_lifetime"
UNIT_TESTS = (
    "source_api::tests::switched_default_aligned_allocation_keeps_selected_heap",
    "source_api::tests::switched_default_reallocation_keeps_selected_heap",
    "source_api::tests::direct_theap_variants_preserve_roots_and_reallocation_lifetime",
    "runtime_lifecycle::tests::worker_fixed_theap_collection_preserves_auxiliary_default",
    "runtime_lifecycle::tests::runtime_loader_tail_releases_once_before_delayed_output",
)


def command(output, label, argv, cwd, *, runtime=False, timeout=900):
    record = harness.command_record(argv, cwd=cwd, **({"env": {}} if runtime else {}),
                                    timeout_seconds=timeout)
    raw, log = output / f"{label}.json", output / f"{label}.log"
    harness.write_json(raw, record)
    log.write_text(str(record["stdout"]) + str(record["stderr"]))
    harness.require_success(record, f"public Theap {label}")
    return record, [raw, log]


def observe(drivers, output, profile, guarded_only, cases):
    traces = {}
    for side in ("c", "rust"):
        record, logs = command(output, side, [str(drivers[side])], output, runtime=True, timeout=60)
        if side == "c":
            for context in ("main", "worker", "child", "fork"):
                if re.findall(rf"^source\.{context}=([01]),([01]),([01])$",
                              str(record["stderr"]), re.MULTILINE) != [("1", "1", "1")]:
                    raise harness.HarnessError(f"pinned C {context} Theap ownership differs")
            for context in (() if guarded_only else ("main", "worker", "child", "fork")):
                if re.findall(rf"^source\.{context}\.collect_empty=([01])$",
                              str(record["stderr"]), re.MULTILINE) != ["1"]:
                    raise harness.HarnessError(f"pinned C {context} force collection leaves live Theap pages")
        traces[side] = m7.parse_options_trace(str(record["stdout"]), side, BEGIN, END)
        require_trace(traces[side], side, guarded_only)
        cases.append((f"{profile}-{side}-run", 0, logs))
    m7.compare_options_traces(traces["c"], traces["rust"])
    return len(traces["c"])


def require_one_native_test(record, label):
    if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;",
                      str(record["stdout"]), re.MULTILINE)) != 1:
        raise harness.HarnessError(f"public Theap {label} did not execute exactly one passing test")


def native_controls(output, profile, cases):
    products = {}
    for index, test in enumerate((DIRECT_TEST, *UNIT_TESTS)):
        label = "native_theap_contract" if index == 0 else test.rsplit("::", 1)[-1]
        target = "native_theap_contract" if index == 0 else "crabc_mimalloc"
        record, logs = command(output, label,
            [harness.require_tool("cargo"), "test", "--locked", "--offline", "--target", m4.RUST_TARGET,
             "-p", "crabc-mimalloc", "--no-default-features", "--message-format=json",
             *(("--features", f"mi-{profile}") if profile != "release" else ()),
             *(("--test", "native_theap_contract") if index == 0 else ("--lib",)),
             test, "--", "--exact", "--nocapture", "--test-threads=1"], harness.ROOT)
        require_one_native_test(record, label)
        executables = set()
        for line in str(record["stdout"]).splitlines():
            if not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if (message.get("reason") == "compiler-artifact" and
                    message.get("target", {}).get("name") == target and message.get("executable")):
                executables.add(message["executable"])
        if len(executables) != 1:
            raise harness.HarnessError(f"public Theap {label} lacks one compiler-identified test executable")
        retained = output / target
        shutil.copy2(Path(executables.pop()), retained)
        products[f"{profile}-{target}"] = retained
        cases.append((f"{profile}-{label}", 0, logs))
    return products


def run_profile(profile, guarded_only, cases):
    execution = harness.require_native_x86_64(require_image_identity=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    output = ARTIFACTS if profile == "release" else ARTIFACTS / profile
    if guarded_only:
        output = output / "guarded-configuration"
    output.mkdir(parents=True, exist_ok=True)
    retained_driver = output / DRIVER.name
    shutil.copy2(DRIVER, retained_driver)
    inputs = output / "inputs.json"
    harness.write_json(inputs, {"profile": profile, "guarded_only": guarded_only, "upstream": pin,
        "archive_sha256": harness.sha256_file(archive), "driver_sha256": harness.sha256_file(retained_driver),
        "source": receipts.source_seal(harness.ROOT), "execution": execution,
        "workload_assertions": True, "allocator_flags": list(m4.api_profile_flags(profile))})
    with harness.temporary_directory("crabc-mimalloc-m6-public-theap-") as name:
        source = harness.safe_extract(archive, Path(name) / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        client_flags = ("-DCRABC_PUBLIC_GUARDED_CONFIGURATION_ONLY=1",) if guarded_only else ()
        common = [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-UNDEBUG", *client_flags, "-I", str(source / "include")]
        drivers = {side: output / f"public-theap-{side}" for side in ("c", "rust")}
        _, logs = command(output, "c-build", [*common, "-DCRABC_M6_SOURCE_INTERNAL=1",
            "-I", str(source / "src"), str(retained_driver), str(source / "src/static.c"),
            "-pthread", "-o", str(drivers["c"])], source)
        cases.append((f"{profile}-c-build", 0, logs))
        library = m4.build_adapter_library(output, profile)
        _, logs = command(output, "rust-link", [*common, str(retained_driver), str(library),
                          "-pthread", "-o", str(drivers["rust"])], source)
        cases.append((f"{profile}-rust-link", 0, [*logs, output / "adapter-build.json"]))
        count = observe(drivers, output, profile, guarded_only, cases)
    products = {f"{profile}-{side}": path for side, path in drivers.items()}
    if not guarded_only:
        products.update(native_controls(output, profile, cases))
    native = output / "native-execution-provenance.json"
    harness.write_json(native, harness.native_execution_attestation(
        execution, harness.require_native_x86_64(require_image_identity=True)))
    products.update({f"{profile}-adapter.a": library, f"{profile}-driver.c": retained_driver,
        f"{profile}-upstream-archive": archive, f"{profile}-inputs.json": inputs,
        f"{profile}-native-execution-provenance.json": native})
    return count, products


def run_cohort(profiles, guarded_only=False):
    if (not profiles or len(set(profiles)) != len(profiles)
            or any(profile not in AVAILABLE_PROFILES for profile in profiles)):
        raise harness.HarnessError("unsupported public Theap profile")
    seal = receipts.source_seal(harness.ROOT)
    cases, products, total = [], {}, 0
    for profile in profiles:
        count, selected = run_profile(profile, guarded_only, cases)
        total += count
        products.update(selected)
        print(f"public Theap ({profile}): {count} source-built C/Rust keys match", flush=True)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during public Theap profile cohort")
    receipts.write_receipt(harness.ROOT, RUNNER, ARTIFACTS, products, cases,
        parameters(profiles, guarded_only), True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    return total


def parameters(profiles, guarded_only):
    return {"profiles": ",".join(profiles), "guarded-only": str(int(guarded_only)),
            "watchdog-seconds": "60", "workload-assertions": "active"}


def main(profile: str = "release", guarded_only: bool = False) -> None:
    run_cohort((profile,), guarded_only)


def run_differential() -> int:
    return run_cohort(("release",))


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=AVAILABLE_PROFILES, default="release")
    selection.add_argument("--matrix", action="store_true")
    selection.add_argument("--profiles", nargs="+", choices=AVAILABLE_PROFILES,
        help="complete ordered profile cohort for production or retained reading")
    parser.add_argument("--guarded-only", action="store_true")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--read", action="store_true")
    action.add_argument("--replay", action="store_true")
    args = parser.parse_args(argv)
    profiles = tuple(args.profiles) if args.profiles else (PROFILES if args.matrix else (args.profile,))
    if len(set(profiles)) != len(profiles):
        parser.error("profile selection cannot contain duplicates")
    if not (args.read or args.replay):
        run_cohort(profiles, args.guarded_only)
        return 0
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    if dict(receipt.parameters) != parameters(profiles, args.guarded_only):
        raise harness.HarnessError("public Theap receipt profile or workload parameters differ")
    labels = ["c-build", "rust-link", "c-run", "rust-run"]
    if not args.guarded_only:
        labels += ["native_theap_contract", *(test.rsplit("::", 1)[-1] for test in UNIT_TESTS)]
    if receipt.case_ids() != [f"{profile}-{label}" for profile in profiles for label in labels]:
        raise harness.HarnessError("public Theap receipt lacks the exact ordered executed cohort")
    products = receipt.path.parent / "products"
    logs = receipt.path.parent / "logs"
    data = harness.read_json(receipt.path)
    work_relative = Path(data["work"])
    if work_relative.is_absolute() or ".." in work_relative.parts or work_relative.parts[:1] != (".work",):
        raise harness.HarnessError("public Theap receipt work escapes its checkout")
    work = harness.ROOT / work_relative
    pin = harness.load_pin()
    for profile in profiles:
        output = work if profile == "release" else work / profile
        if args.guarded_only:
            output = output / "guarded-configuration"
        inputs = harness.read_json(products / f"{profile}-inputs.json")
        if (inputs.get("profile") != profile or inputs.get("guarded_only") is not args.guarded_only
                or inputs.get("upstream") != pin or inputs.get("archive_sha256") != pin["sha256"]
                or inputs.get("source") != dict(receipt.source) or inputs.get("workload_assertions") is not True
                or inputs.get("allocator_flags") != list(m4.api_profile_flags(profile))):
            raise harness.HarnessError(f"{profile} public Theap retained selector or source inputs differ")
        if (harness.sha256_file(products / f"{profile}-upstream-archive") != pin["sha256"]
                or inputs.get("driver_sha256") != harness.sha256_file(products / f"{profile}-driver.c")
                or (products / f"{profile}-driver.c").read_bytes() != DRIVER.read_bytes()):
            raise harness.HarnessError(f"{profile} public Theap physical compiler inputs differ")
        records = {}
        for label in labels:
            case = next(case for case in receipt.cases if case["id"] == f"{profile}-{label}")
            stem = {"c-run": "c", "rust-run": "rust"}.get(label, label)
            expected = (output / f"{stem}.json").relative_to(work).as_posix()
            if expected not in case["logs"]:
                raise harness.HarnessError(f"{profile} public Theap {label} raw path differs")
            records[label] = harness.read_json(logs / expected)
            harness.require_success(records[label], f"retained {profile} {label}")
        # The source extraction was temporary. Authenticate its declared
        # include/static input structure against the pinned archive and
        # original builder, without asserting those removed paths are live.
        c_argv = records["c-build"].get("command", [])
        if not isinstance(c_argv, list) or len(c_argv) < 5:
            raise harness.HarnessError(f"{profile} public Theap compiler argv is missing")
        source = Path(c_argv[-4]).parent.parent
        temporary = source.parent.parent
        if (source.name != pin["archive_root"] or source.parent.name != "source"
                or temporary.parent != harness.TEMP_ROOT
                or not temporary.name.startswith("crabc-mimalloc-m6-public-theap-")):
            raise harness.HarnessError(f"{profile} public Theap compiler source path differs")
        compiler = harness.require_tool("musl-gcc")
        cargo = harness.require_tool("cargo")
        client_flags = ("-DCRABC_PUBLIC_GUARDED_CONFIGURATION_ONLY=1",) if args.guarded_only else ()
        common = [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *m4.api_profile_flags(profile), "-UNDEBUG", *client_flags, "-I", str(source / "include")]
        retained_driver = output / DRIVER.name
        library = output / "cargo-target" / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        expected_commands = {
            "c-build": [*common, "-DCRABC_M6_SOURCE_INTERNAL=1", "-I", str(source / "src"),
                        str(retained_driver), str(source / "src/static.c"), "-pthread", "-o", str(output / "public-theap-c")],
            "rust-link": [*common, str(retained_driver), str(library), "-pthread", "-o", str(output / "public-theap-rust")],
            "c-run": [str(output / "public-theap-c")],
            "rust-run": [str(output / "public-theap-rust")],
        }
        if not args.guarded_only:
            for index, test in enumerate((DIRECT_TEST, *UNIT_TESTS)):
                label = "native_theap_contract" if index == 0 else test.rsplit("::", 1)[-1]
                expected_commands[label] = [cargo, "test", "--locked", "--offline", "--target", m4.RUST_TARGET,
                    "-p", "crabc-mimalloc", "--no-default-features", "--message-format=json",
                    *(("--features", f"mi-{profile}") if profile != "release" else ()),
                    *(("--test", "native_theap_contract") if index == 0 else ("--lib",)),
                    test, "--", "--exact", "--nocapture", "--test-threads=1"]
                require_one_native_test(records[label], f"retained {profile} {label}")
        for label, expected in expected_commands.items():
            if records[label].get("command") != expected:
                raise harness.HarnessError(f"{profile} public Theap {label} compiler/provider argv differs")
        adapter_path = (output / "adapter-build.json").relative_to(work).as_posix()
        link_case = next(case for case in receipt.cases if case["id"] == f"{profile}-rust-link")
        if adapter_path not in link_case["logs"]:
            raise harness.HarnessError(f"{profile} public Theap native compiler record is missing")
        adapter = harness.read_json(logs / adapter_path)
        harness.require_success(adapter, f"retained {profile} native adapter build")
        expected_adapter = [cargo, "build", "--locked", "--release", "--message-format=json",
            "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(output / "cargo-target"),
            *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())]
        artifact = adapter.get("artifact", {})
        retained_adapter = products / f"{profile}-adapter.a"
        if (adapter.get("command") != expected_adapter
                or artifact.get("path") != library.relative_to(harness.ROOT).as_posix()
                or artifact.get("bytes") != retained_adapter.stat().st_size
                or artifact.get("sha256") != harness.sha256_file(retained_adapter)):
            raise harness.HarnessError(f"{profile} public Theap native selector or physical library differs")
    print("public Theap exact-source physical receipt: PASS", flush=True)
    if args.replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="public-theap-replay-", dir=harness.TEMP_ROOT))
        print(f"public Theap reader raw executions: {scratch}", flush=True)
        for profile in profiles:
            source = receipt.path.parent / "products"
            native = harness.read_json(source / f"{profile}-native-execution-provenance.json")
            harness.validate_native_execution_provenance(native, expected_image_id=execution["image_id"])
            output = scratch / profile
            output.mkdir()
            drivers = {}
            for target in ("c", "rust", *(("native_theap_contract", "crabc_mimalloc") if not args.guarded_only else ())):
                binary = output / target
                shutil.copyfile(source / f"{profile}-{target}", binary)
                binary.chmod(0o755)
                drivers[target] = binary
            observe(drivers, output, profile, args.guarded_only, [])
            if not args.guarded_only:
                for index, test in enumerate((DIRECT_TEST, *UNIT_TESTS)):
                    target = "native_theap_contract" if index == 0 else "crabc_mimalloc"
                    label = target if index == 0 else test.rsplit("::", 1)[-1]
                    record, _ = command(output, label,
                        [str(drivers[target]), test, "--exact", "--nocapture", "--test-threads=1"],
                        output, runtime=True)
                    require_one_native_test(record, label)
        print("public Theap retained full-profile replay: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(cli())
    except (harness.HarnessError, receipts.ReceiptError) as error:
        print(f"public Theap failed: {error}", file=sys.stderr)
        raise SystemExit(1)
