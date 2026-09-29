#!/usr/bin/env python3
"""Compare pinned C and Rust bin queues, direct caches, and local free lists."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "compat/allocator/run.py"
C_FIXTURE = ROOT / "compat/allocator/x86_64_m3_queue_retirement.c"
RUST_TEST = "types::page_queue::tests::queue_retirement_and_reuse_preserve_owner_state"
RUST_MATRIX_TEST = "types::page_queue::tests::queue_bin_transition_matrix_preserves_source_owner_state"
RUST_FREE_TEST = "free_list::tests::source_bin_free_list_matrix_preserves_order_and_zeroing"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def main() -> int:
    run.require_native_x86_64()
    pin = run.load_pin()
    archive = run.fetch_archive(pin, offline=True)
    with run.temporary_directory(prefix="crabc-m3-queue-retirement-") as directory:
        work = Path(directory)
        artifact_root = run.ARTIFACT_ROOT / "x86_64/m3-local-engine"
        artifact_root.mkdir(parents=True, exist_ok=True)
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
        receipt = {"archive_sha256": run.sha256_file(archive)}
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
        rust_runs = [run.command_record(
            ["cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
             "-p", "crabc-mimalloc", "--lib", "--no-default-features", test,
             "--", "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, timeout_seconds=1800,
        ) for test in (RUST_TEST, RUST_MATRIX_TEST, RUST_FREE_TEST)]
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
        sys.stdout.write("\n".join(c_lines) + "\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
