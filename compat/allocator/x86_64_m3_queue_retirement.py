#!/usr/bin/env python3
"""Compare pinned C and Rust bin queues, direct caches, and local free lists."""

from __future__ import annotations

import argparse
import shutil
import re
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
C_FIXTURE = ROOT / "compat/allocator/x86_64_m3_queue_retirement.c"
RUST_TEST = "types::page_queue::tests::queue_retirement_and_reuse_preserve_owner_state"
RUST_MATRIX_TEST = "types::page_queue::tests::queue_bin_transition_matrix_preserves_source_owner_state"
RUST_FREE_TEST = "free_list::tests::source_bin_free_list_matrix_preserves_order_and_zeroing"

sys.path.insert(0, str(ROOT / "compat/allocator"))
import run

sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipts

RECEIPT_RUNNER = "queue-retirement-x86-64"
TESTS = (RUST_TEST, RUST_MATRIX_TEST, RUST_FREE_TEST)
EXECUTION = {"package": "crabc-mimalloc", "no_default_features": True,
             "rust_target": "x86_64-unknown-linux-musl", "timeout_seconds": 1800}


def read_report(*, replay: bool = False) -> dict:
    # Compiler output selects the executable; a path supplied by a producer is
    # insufficient authority even when its current bytes match a recorded hash.
    sys.path.insert(0, str(ROOT / "compat/allocator"))
    import x86_64_foundation_gate_receipts as foundation

    retained = receipts.read_receipt(ROOT, RECEIPT_RUNNER)
    report = run.read_json(retained.path.parent / "products/queue-retirement-driver.json")
    physical = report["physical_inputs"]
    if (retained.parameters != {"configuration": "release", "test_threads": "1"}
            or retained.case_ids() != ["c", "rust"]
            or set(retained.products) != {"queue-retirement-driver.json", "c-program", "unit-program", "c-source", "upstream-archive"}):
        raise run.HarnessError("queue receipt differs from its original workload")
    for name, record in (("c-program", physical["c_program"]),
                         ("unit-program", physical["unit_program"]["artifact"]),
                         ("c-source", physical["fixture"]), ("upstream-archive", physical["archive"])):
        if retained.products[name] != {"sha256": record["sha256"], "size": record["bytes"]}:
            raise run.HarnessError("queue receipt and original physical inputs disagree")
    execution = run.require_native_x86_64(require_image_identity=True)
    run.validate_native_execution_provenance(report["execution"], expected_image_id=execution["image_id"])
    if report["source"] != dict(retained.source) or report["pin"] != run.load_pin():
        raise run.HarnessError("queue source or pinned oracle changed")
    work = ROOT / report["work"]
    if not work.resolve().is_relative_to(run.ARTIFACT_ROOT.resolve()) or work.is_symlink():
        raise run.HarnessError("queue artifacts are outside owned persistent storage")
    if (ROOT / physical["c_program"]["path"] != work / "m3-queue-retirement-c"
            or ROOT / physical["archive"]["path"] != work / "upstream.tar.gz"):
        raise run.HarnessError("queue C inputs are outside the original work directory")
    program = physical["unit_program"]
    expected_build = ["cargo", "test", "-p", "crabc-mimalloc", "--no-default-features",
                      "--target", "x86_64-unknown-linux-musl", "--locked", "--lib",
                      "--no-run", "--message-format=json"]
    if (program["execution"] != EXECUTION or program["build_command"] != expected_build
            or Path(program["cargo_target"]) != work / "cargo-target"):
        raise run.HarnessError("queue unit build differs from its source contract")
    foundation.authenticate_unit_program(program)
    foundation.authenticate_artifacts(physical, work / "source" / report["pin"]["archive_root"])
    if physical["fixture"] != run.artifact_record(C_FIXTURE):
        raise run.HarnessError("queue C driver changed")
    archive = ROOT / physical["archive"]["path"]
    if report["archive_sha256"] != report["pin"]["sha256"] or run.sha256_file(archive) != report["pin"]["sha256"]:
        raise run.HarnessError("queue oracle archive differs from its pin")
    with run.temporary_directory(prefix="queue-receipt-oracle-") as directory:
        pinned = run.safe_extract(archive, Path(directory) / "source", report["pin"]["archive_root"])
        expected_sources = sorted(path.relative_to(pinned).as_posix()
                                  for parent in (pinned / "include", pinned / "src")
                                  for path in parent.rglob("*") if path.is_file())
        if physical["oracle_source"] != run.source_file_records(pinned, expected_sources):
            raise run.HarnessError("queue pinned compiler input roster changed")
        foundation.authenticate_artifacts(physical["oracle_source"], pinned)
    if set(report["tools"]) != {"musl-gcc", "cargo", "rustc"}:
        raise run.HarnessError("queue compiler tool roster changed")
    for name, tool in report["tools"].items():
        path = Path(run.require_tool(name)).resolve()
        if str(path) != tool["path"] or run.sha256_file(path) != tool["sha256"]:
            raise run.HarnessError(f"queue tool changed: {name}")
        command = [str(path), "-vV" if name == "rustc" else "--version"]
        actual = run.command_record(command, cwd=ROOT)
        if actual != tool["version"] or actual["status"] != 0:
            raise run.HarnessError(f"queue tool version changed: {name}")
    source = work / "source" / report["pin"]["archive_root"]
    binary = ROOT / physical["c_program"]["path"]
    expected_c = [report["tools"]["musl-gcc"]["path"], "-std=c11", "-ffunction-sections",
                  "-fdata-sections", "-Wl,--gc-sections", "-DMI_SHARED_LIB",
                  "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", *run.CONFIGURATION_PROFILES["release"],
                  "-I", str(source / "include"), "-I", str(source / "src"),
                  str(C_FIXTURE), "-pthread", "-o", str(binary)]
    if report["c_build"]["command"] != expected_c or report["c_build"]["status"] != 0:
        raise run.HarnessError("queue C build differs from the original driver")
    c_runs = (report["c_runtime"], report["c_runtime_repeat"])
    rust_runs = report["rust_runtime"]
    commands = [[str(ROOT / program["artifact"]["path"]), test, "--exact", "--nocapture", "--test-threads=1"]
                for test in TESTS]
    if len(rust_runs) != len(commands):
        raise run.HarnessError("queue unit execution roster changed")
    for recorded, expected in zip((*c_runs, *rust_runs), ([[str(binary)]] * 2 + commands)):
        if recorded["command"] != expected or recorded["status"] != 0:
            raise run.HarnessError("queue execution differs from its original caller")
    if any(run.parse_rust_test_count(str(row["stdout"])) != 1 for row in rust_runs):
        raise run.HarnessError("queue exact unit execution count changed")
    c_lines = str(c_runs[0]["stdout"]).splitlines()
    rust_lines = [line for row in rust_runs for line in re.findall(r"M3[RBF] [^\r\n]+", str(row["stdout"]))]
    if not c_lines or c_runs[0]["stdout"] != c_runs[1]["stdout"] or c_lines != rust_lines:
        raise run.HarnessError("queue retained differential observations disagree")
    if replay:
        run.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="queue-replay-", dir=run.TEMP_ROOT))
        for index, recorded in enumerate((*c_runs, *rust_runs)):
            actual = run.command_record(recorded["command"], cwd=ROOT, timeout_seconds=1800)
            run.write_json(scratch / f"execution-{index}.json", actual)
            run.require_success(actual, "queue retained execution")
            if index < 2:
                equal = actual["stdout"] == recorded["stdout"]
            else:
                equal = (run.parse_rust_test_count(str(actual["stdout"])) == 1
                         and re.findall(r"M3[RBF] [^\r\n]+", str(actual["stdout"]))
                         == re.findall(r"M3[RBF] [^\r\n]+", str(recorded["stdout"])))
            if not equal:
                raise run.HarnessError(f"queue replay observations changed: {index}")
        if receipts.source_seal(ROOT) != report["source"]:
            raise run.HarnessError("queue source changed during replay")
        run.native_execution_attestation(execution, run.require_native_x86_64(require_image_identity=True))
    return report


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--read", action="store_true")
    modes.add_argument("--replay", action="store_true")
    args = parser.parse_args([] if arguments is None else arguments)
    if args.read or args.replay:
        read_report(replay=args.replay)
        return 0
    execution = run.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(ROOT)
    pin = run.load_pin()
    archive = run.fetch_archive(pin, offline=True)
    artifact_root = run.ARTIFACT_ROOT / "x86_64/m3-local-engine"
    artifact_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="queue-retirement-", dir=artifact_root))
    receipt_path = artifact_root / "queue-retirement-driver.json"
    c_trace_path = artifact_root / "queue-retirement.c.trace"
    rust_log_path = artifact_root / "queue-retirement.rust.log"
    rust_trace_path = artifact_root / "queue-retirement.rust.trace"
    source = run.safe_extract(archive, work / "source", pin["archive_root"])
    binary = work / "m3-queue-retirement-c"
    command = [
        run.require_tool("musl-gcc"), "-std=c11", "-ffunction-sections",
        "-fdata-sections", "-Wl,--gc-sections", "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
        *run.CONFIGURATION_PROFILES["release"],
        "-I", str(source / "include"), "-I", str(source / "src"),
        str(C_FIXTURE), "-pthread", "-o", str(binary),
    ]
    tools = {}
    for name in ("musl-gcc", "cargo", "rustc"):
        path = Path(run.require_tool(name)).resolve()
        version = run.command_record([str(path), "-vV" if name == "rustc" else "--version"], cwd=ROOT)
        run.require_success(version, f"queue {name} identity")
        tools[name] = {"path": str(path), "sha256": run.sha256_file(path), "version": version}
    command[0] = tools["musl-gcc"]["path"]
    retained_archive = work / "upstream.tar.gz"
    shutil.copyfile(archive, retained_archive)
    receipt = {"archive_sha256": run.sha256_file(archive), "pin": pin, "source": seal,
               "execution": execution, "work": run.relative(work), "tools": tools}
    c_build = run.command_record(command, cwd=ROOT, timeout_seconds=600)
    receipt["c_build"] = c_build
    if c_build["status"] != 0:
        run.write_json(receipt_path, receipt)
        sys.stderr.write(str(c_build["stdout"]) + str(c_build["stderr"]))
        return 1
    c = run.command_record((str(binary),), cwd=ROOT, timeout_seconds=600)
    receipt["c_runtime"] = c
    c_trace_path.write_text(str(c["stdout"]), encoding="utf-8")
    if c["status"] != 0:
        run.write_json(receipt_path, receipt)
        sys.stderr.write(str(c["stderr"]))
        return 1
    repeated = run.command_record((str(binary),), cwd=ROOT, timeout_seconds=600)
    receipt["c_runtime_repeat"] = repeated
    if repeated["status"] != 0 or repeated["stdout"] != c["stdout"]:
        run.write_json(receipt_path, receipt)
        sys.stderr.write("pinned C local primitive trace is not repeatable\n" + str(repeated["stderr"]))
        return 1
    run.write_json(receipt_path, receipt)
    program = run._x86_64_unit_test_program(EXECUTION, work / "cargo-target", gate_name="queue retirement")
    program["artifact"] = run.artifact_record(program.pop("path"))
    source_paths = sorted(path.relative_to(source).as_posix() for parent in (source / "include", source / "src")
                          for path in parent.rglob("*") if path.is_file())
    receipt["physical_inputs"] = {"unit_program": program, "c_program": run.artifact_record(binary),
                                  "archive": run.artifact_record(retained_archive),
                                  "fixture": run.artifact_record(C_FIXTURE),
                                  "oracle_source": run.source_file_records(source, source_paths)}
    rust_runs = [run.command_record(
        [str(ROOT / program["artifact"]["path"]), test, "--exact", "--nocapture", "--test-threads=1"],
        cwd=ROOT, timeout_seconds=1800,
    ) for test in TESTS]
    receipt["rust_runtime"] = rust_runs
    run.write_json(receipt_path, receipt)
    rust_log_path.write_text("\n".join(str(rust["stdout"]) + str(rust["stderr"]) for rust in rust_runs), encoding="utf-8")
    c_lines = str(c["stdout"]).splitlines()
    rust_lines = [line for rust in rust_runs for line in re.findall(r"M3[RBF] [^\r\n]+", str(rust["stdout"]))]
    rust_trace_path.write_text("\n".join(rust_lines) + "\n", encoding="utf-8")
    if any(rust["status"] != 0 or "1 passed; 0 failed" not in str(rust["stdout"]) for rust in rust_runs):
        sys.stderr.write(rust_log_path.read_text(encoding="utf-8"))
        return 1
    if not c_lines or c_lines != rust_lines:
        mismatch = next((index for index, (c_line, rust_line) in enumerate(zip(c_lines, rust_lines)) if c_line != rust_line), min(len(c_lines), len(rust_lines)))
        sys.stderr.write(f"C/Rust trace mismatch at record {mismatch}: C={c_lines[mismatch:mismatch+1]!r} Rust={rust_lines[mismatch:mismatch+1]!r}\n")
        return 1
    if receipts.source_seal(ROOT) != seal:
        raise run.HarnessError("queue source changed during production")
    run.native_execution_attestation(execution, run.require_native_x86_64(require_image_identity=True))
    receipts.write_receipt(ROOT, RECEIPT_RUNNER, artifact_root,
        {"queue-retirement-driver.json": receipt_path, "c-program": binary,
         "unit-program": ROOT / program["artifact"]["path"], "c-source": C_FIXTURE,
         "upstream-archive": retained_archive},
        [("c", 0, [c_trace_path]), ("rust", 0, [rust_log_path, rust_trace_path])],
        {"configuration": "release", "test_threads": "1"}, canonical=True)
    sys.stdout.write("\n".join(c_lines) + "\n")
    return 0



if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
