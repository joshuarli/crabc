#!/usr/bin/env python3
"""Compare pinned C and Rust head removal, full membership, and reuse traces."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "compat/allocator/run.py"
C_FIXTURE = ROOT / "compat/allocator/x86_64_m3_queue_retirement.c"
RUST_TEST = "types::page_queue::tests::queue_retirement_and_reuse_preserve_owner_state"

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
            str(C_FIXTURE), "-o", str(binary),
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
        rust = run.command_record(
            ["cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
             "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST,
             "--", "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, timeout_seconds=1800,
        )
        receipt["rust_runtime"] = rust
        run.write_json(receipt_path, receipt)
        rust_log_path.write_text(str(rust["stdout"]) + str(rust["stderr"]), encoding="utf-8")
        c_lines = str(c["stdout"]).splitlines()
        rust_lines = re.findall(r"M3R [^\r\n]+", str(rust["stdout"]))
        rust_trace_path.write_text("\n".join(rust_lines) + "\n", encoding="utf-8")
        if rust["status"] != 0:
            sys.stderr.write(str(rust["stdout"]) + str(rust["stderr"]))
            return 1
        if len(c_lines) != 10 or c_lines != rust_lines:
            sys.stderr.write(f"C: {c_lines!r}\nRust: {rust_lines!r}\n")
            return 1
        sys.stdout.write("\n".join(c_lines) + "\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
