#!/usr/bin/env python3
"""Compare Heap destruction while an exited creator's second worker stays attached."""

from pathlib import Path
import argparse
import os
import shutil
import sys
import tempfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7
import x86_64_m6_heap_delete_with_attached_worker as attached


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_destroy_racing_detach_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-destroy-racing-detach"
BEGIN = "CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_BEGIN"
END = "CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_END"
EXPECTED = {"race.completed": "64", "race.owners": "0,0"}
REPETITIONS = 32
PROFILES = attached.PROFILES
RUNNER = "allocator-heap-destroy-racing-detach"
receipts = attached.receipts
AUDIT_RUSTFLAGS = "--cfg crabc_native_thread_done_audit --check-cfg=cfg(crabc_native_thread_done_audit)"


def profile_output(profile, root=None):
    output = (root if root is not None else ARTIFACTS) / "thread-done-interleave"
    return output if profile == "release" else output / profile


def observed_trace(record, side, audit=False, interleave=False):
    trace = m7.parse_options_trace(str(record["stdout"]), side, BEGIN, END)
    expected = dict(EXPECTED)
    if interleave:
        # Retry totals depend on how many attempts run before the observer is
        # scheduled. Preserve their exact raw values; qualification requires
        # a failed try-lock while the owner drain remains parked.
        waits = trace.pop("race.contention_waits", None)
        if not isinstance(waits, str) or not waits.isdecimal() or int(waits) <= 0:
            raise harness.HarnessError(f"{side} lock-contention rendezvous lacks an actual failed try-lock")
        expected.update({"race.destroy_before_drain": "0", "race.preserved_before_retry": "1"})
    if side == "rust" and audit:
        finish = trace.pop("race.finish", None)
        refusal = trace.pop("race.refusal", None)
        finished = 129 if interleave else 128
        if finish != f"{finished},0,0,0,0" or refusal != "0,0,0,0":
            raise harness.HarnessError(f"joined worker teardown refused: finish={finish} refusal={refusal}")
    if trace != expected:
        raise harness.HarnessError(f"{side} Heap destroy overlap observations differ: {trace}")
    return trace


def run_differential(audit: bool = False, interleave: bool = False, profile: str = "release", output_root=None) -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    root = output_root if output_root is not None else ARTIFACTS
    artifacts = root / ("thread-done-interleave" if interleave else "thread-done-audit") if audit else root
    if profile != "release":
        artifacts = artifacts / profile
    artifacts.mkdir(parents=True, exist_ok=True)
    retained_driver = artifacts / DRIVER.name
    shutil.copy2(DRIVER, retained_driver)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-destroy-racing-detach-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = artifacts / "heap-destroy-racing-detach-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *m4.api_profile_flags(profile), "-UNDEBUG",
             *(("-DCRABC_C_THREAD_DONE_INTERLEAVE=1",) if interleave else ()),
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(retained_driver), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (artifacts / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.write_json(artifacts / "c-build.json", c_build)
        harness.require_success(c_build, "Heap destroy racing detach C build")
        c_logs = []
        c_records = []
        for attempt in range(REPETITIONS):
            c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
            harness.write_json(artifacts / f"c-run-{attempt:02d}.json", c_run)
            c_logs.append(str(c_run["stdout"]) + str(c_run["stderr"]))
            c_records.append(c_run)
            (artifacts / "c.log").write_text("\n".join(c_logs))
            harness.require_success(c_run, f"Heap destroy racing detach C run {attempt}")
            c_trace = observed_trace(c_run, "c", interleave=interleave)
        if audit:
            target = artifacts / "cargo-target"
            environment = dict(os.environ)
            environment["RUSTFLAGS"] = AUDIT_RUSTFLAGS
            build = harness.command_record(
                [harness.require_tool("cargo"), "build", "--locked", "--release",
                 "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
                 *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())],
                cwd=harness.ROOT, env=environment, timeout_seconds=m4.EVIDENCE_TIMEOUT_SECONDS,
            )
            (artifacts / "rust-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
            harness.write_json(artifacts / "rust-build.json", build)
            harness.require_success(build, "isolated thread-done observation adapter build")
            library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        else:
            library = m4.build_adapter_library(artifacts, profile)
        rust_driver = artifacts / "heap-destroy-racing-detach-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", *m4.api_profile_flags(profile), "-UNDEBUG",
             *(("-DCRABC_NATIVE_THREAD_DONE_AUDIT=1",) if audit else ()),
             *(("-DCRABC_NATIVE_THREAD_DONE_INTERLEAVE=1",) if interleave else ()),
             "-I", str(source / "include"), str(retained_driver), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (artifacts / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.write_json(artifacts / "rust-link.json", link)
        harness.require_success(link, "Heap destroy racing detach Rust link")
        rust_logs = []
        for attempt in range(REPETITIONS):
            rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
            harness.write_json(artifacts / f"rust-run-{attempt:02d}.json", rust_run)
            rust_logs.append(str(rust_run["stdout"]) + str(rust_run["stderr"]))
            (artifacts / "rust.log").write_text("\n".join(rust_logs))
            harness.require_success(rust_run, f"Heap destroy racing detach Rust run {attempt}")
            rust_trace = observed_trace(rust_run, "rust", audit, interleave)
            m7.compare_options_traces(c_trace, rust_trace)
            if str(c_records[attempt]["stderr"]) != str(rust_run["stderr"]):
                raise harness.HarnessError(f"Heap destroy racing detach diagnostics differ on run {attempt}")
        return len(c_trace) * REPETITIONS


def parameters(profiles):
    return {"profiles": ",".join(profiles), "rounds": "64", "repetitions": str(REPETITIONS),
            "watchdog-seconds": "60", "rendezvous": "failed-detach-try-lock-counter",
            "drain-park": "source-deferred-callback/native-thread-done-audit", "diagnostics": "exact"}


def run_cohort(profiles):
    source = receipts.source_seal(harness.ROOT)
    execution = harness.require_native_x86_64(require_image_identity=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=ARTIFACTS))
    print(f"Heap destroy causal profile raw: {work}", flush=True)
    cases, products, count = [], {}, 0
    for profile in profiles:
        count += run_differential(True, True, profile, work)
        output = profile_output(profile, work)
        inputs = output / "inputs.json"
        harness.write_json(inputs, {"source": source, "upstream": pin,
            "archive_sha256": harness.sha256_file(archive), "profile": profile,
            "allocator_flags": list(m4.api_profile_flags(profile)), "execution": execution,
            "driver_sha256": harness.sha256_file(DRIVER), "parameters": parameters(profiles),
            "rustflags": AUDIT_RUSTFLAGS, "compiler_sha256": harness.sha256_file(Path(harness.require_tool("musl-gcc")))})
        native = output / "native-execution-provenance.json"
        harness.write_json(native, harness.native_execution_attestation(
            execution, harness.require_native_x86_64(require_image_identity=True)))
        cases.append((f"{profile}-c-build", 0, [output / "c-build.json", output / "c-build.log"]))
        for side in ("c", "rust"):
            if side == "rust":
                for label in ("rust-build", "rust-link"):
                    cases.append((f"{profile}-{label}", 0, [output / f"{label}.json", output / f"{label}.log"]))
            for attempt in range(REPETITIONS):
                cases.append((f"{profile}-{side}-run-{attempt:02d}", 0,
                              [output / f"{side}-run-{attempt:02d}.json"]))
            products[f"{profile}-{side}"] = output / f"heap-destroy-racing-detach-{side}"
        products.update({f"{profile}-adapter.a": output / "cargo-target" / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB,
            f"{profile}-driver.c": output / DRIVER.name, f"{profile}-inputs.json": inputs,
            f"{profile}-upstream-archive": archive, f"{profile}-native-execution-provenance.json": native,
            f"{profile}-compiler": Path(harness.require_tool("musl-gcc"))})
        print(f"{profile} Heap destroy: all {REPETITIONS} causal C/native processes passed", flush=True)
    if receipts.source_seal(harness.ROOT) != source:
        raise harness.HarnessError("source changed during Heap destroy profile cohort")
    receipts.write_receipt(harness.ROOT, RUNNER, work, products, cases, parameters(profiles), True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    return count


def read_cohort(profiles, replay=False):
    receipt = receipts.read_receipt(harness.ROOT, RUNNER)
    if dict(receipt.parameters) != parameters(profiles):
        raise harness.HarnessError("Heap destroy receipt profile or causal rendezvous parameters differ")
    execution = harness.require_native_x86_64(require_image_identity=True)
    products = receipt.path.parent / "products"
    for profile in profiles:
        expected = [f"{profile}-c-build"]
        expected += [f"{profile}-c-run-{attempt:02d}" for attempt in range(REPETITIONS)]
        expected += [f"{profile}-{label}" for label in ("rust-build", "rust-link")]
        expected += [f"{profile}-rust-run-{attempt:02d}" for attempt in range(REPETITIONS)]
        if receipt.case_ids(f"{profile}-") != expected:
            raise harness.HarnessError(f"{profile} Heap destroy receipt lacks the complete causal cohort")
        inputs = harness.read_json(products / f"{profile}-inputs.json")
        if inputs != {"source": dict(receipt.source), "upstream": harness.load_pin(),
            "archive_sha256": harness.sha256_file(products / f"{profile}-upstream-archive"),
            "profile": profile, "allocator_flags": list(m4.api_profile_flags(profile)),
            "execution": execution, "driver_sha256": harness.sha256_file(DRIVER),
            "parameters": parameters(profiles), "rustflags": AUDIT_RUSTFLAGS,
            "compiler_sha256": harness.sha256_file(Path(harness.require_tool("musl-gcc")))}:
            raise harness.HarnessError(f"{profile} Heap destroy source/profile inputs differ")
        if harness.sha256_file(products / f"{profile}-driver.c") != inputs["driver_sha256"]:
            raise harness.HarnessError(f"{profile} Heap destroy retained driver differs")
        if harness.sha256_file(products / f"{profile}-compiler") != inputs["compiler_sha256"]:
            raise harness.HarnessError(f"{profile} Heap destroy retained compiler differs")
        harness.validate_native_execution_provenance(
            harness.read_json(products / f"{profile}-native-execution-provenance.json"),
            expected_image_id=execution["image_id"])
        binary_outputs = {}
        for label in ("c-build", "rust-build", "rust-link"):
            case = next(row for row in receipt.cases if row["id"] == f"{profile}-{label}")
            path = next(receipt.path.parent / "logs" / name for name in case["logs"] if name.endswith(".json"))
            record = harness.read_json(path)
            harness.require_success(record, f"{profile} recorded {label}")
            command = record["command"]
            if label == "rust-build":
                prefix = [harness.require_tool("cargo"), "build", "--locked", "--release",
                          "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir"]
                suffix = ["--features", f"crabc-mimalloc/mi-{profile}"] if profile != "release" else []
                if command[:len(prefix)] != prefix or command[len(prefix) + 1:] != suffix:
                    raise harness.HarnessError(f"{profile} Heap destroy adapter command differs")
            else:
                binary_outputs["c" if label == "c-build" else "rust"] = command[-1]
                prefix = [harness.require_tool("musl-gcc"), "-std=c11", "-D_GNU_SOURCE"]
                if label == "c-build":
                    prefix += ["-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1"]
                prefix += [*m4.api_profile_flags(profile), "-UNDEBUG"]
                prefix += (["-DCRABC_C_THREAD_DONE_INTERLEAVE=1"] if label == "c-build" else
                           ["-DCRABC_NATIVE_THREAD_DONE_AUDIT=1", "-DCRABC_NATIVE_THREAD_DONE_INTERLEAVE=1"])
                if command[:len(prefix)] != prefix or command[-3:-1] != ["-pthread", "-o"]:
                    raise harness.HarnessError(f"{profile} Heap destroy compiler command differs")
        records = {side: [] for side in ("c", "rust")}
        for side in ("c", "rust"):
            for attempt in range(REPETITIONS):
                case = next(row for row in receipt.cases if row["id"] == f"{profile}-{side}-run-{attempt:02d}")
                path = next(receipt.path.parent / "logs" / name for name in case["logs"] if name.endswith(".json"))
                record = harness.read_json(path)
                harness.require_success(record, f"{profile} recorded {side} controlled Heap destroy")
                if record["command"] != [binary_outputs[side]]:
                    raise harness.HarnessError(f"{profile} recorded {side} Heap destroy executable differs")
                observed_trace(record, side, audit=(side == "rust"), interleave=True)
                records[side].append(record)
        for source, native in zip(records["c"], records["rust"]):
            if str(source["stderr"]) != str(native["stderr"]):
                raise harness.HarnessError(f"{profile} retained Heap destroy diagnostics differ")
        print(f"{profile} Heap destroy retained source/profile/causal observations: PASS", flush=True)
    if replay:
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="heap-destroy-overlap-replay-", dir=harness.TEMP_ROOT))
        print(f"Heap destroy independent replay raw: {scratch}", flush=True)
        for profile in profiles:
            output = scratch / profile
            output.mkdir()
            records = {side: [] for side in ("c", "rust")}
            for side in ("c", "rust"):
                binary = output / side
                shutil.copyfile(products / f"{profile}-{side}", binary)
                binary.chmod(0o755)
                for attempt in range(REPETITIONS):
                    record = harness.command_record([str(binary)], cwd=output, env={}, timeout_seconds=60)
                    harness.write_json(output / f"{side}-{attempt:02d}.json", record)
                    harness.require_success(record, f"{profile} replay {side} controlled Heap destroy")
                    observed_trace(record, side, audit=(side == "rust"), interleave=True)
                    records[side].append(record)
                    if side == "rust" and str(records["c"][attempt]["stderr"]) != str(record["stderr"]):
                        raise harness.HarnessError(f"{profile} replay Heap destroy diagnostics differ")
            print(f"{profile} all {REPETITIONS} causal C/native replays: PASS", flush=True)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profile", choices=PROFILES)
    selection.add_argument("--matrix", action="store_true")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--read", action="store_true")
    action.add_argument("--replay", action="store_true")
    action.add_argument("--thread-done-audit", action="store_true")
    action.add_argument("--thread-done-interleave", action="store_true")
    args = parser.parse_args(argv)
    if args.thread_done_audit:
        if args.matrix or args.profile or args.read or args.replay:
            parser.error("thread-done-audit is the release-only diagnostic workload")
        run_differential(True, False)
        return 0
    profiles = (args.profile,) if args.profile else PROFILES
    if args.read or args.replay:
        return read_cohort(profiles, args.replay)
    if not (args.profile or args.matrix or args.thread_done_interleave):
        run_differential()
    count = run_cohort(profiles)
    print(f"Heap destroy racing detach: {count} source-built C/native keys match; causal drain/detach retry passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (harness.HarnessError, receipts.ReceiptError) as error:
        print(f"Heap destroy racing detach failed: {error}", file=sys.stderr)
        raise SystemExit(1)
