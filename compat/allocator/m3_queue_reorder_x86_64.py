#!/usr/bin/env python3
"""Compare pinned C and Rust owner-local queue transitions in the native image."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "compat/allocator/run.py"
C_FIXTURE = ROOT / "compat/allocator/m3_queue_reorder_x86_64.c"
RUST_TEST = "types::page_queue::tests::full_queue_reordering_preserves_owner_membership_and_bytes"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def main() -> int:
    run.require_native_x86_64()
    pin = run.load_pin()
    archive = run.fetch_archive(pin, offline=True)
    with run.temporary_directory(prefix="crabc-m3-queue-reorder-") as directory:
        work = Path(directory)
        source = run.safe_extract(archive, work / "source", pin["archive_root"])
        binary = work / "m3-queue-reorder-c"
        command = [
            run.require_tool("musl-gcc"), "-std=c11", "-ffunction-sections",
            "-fdata-sections", "-Wl,--gc-sections", "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            *run.CONFIGURATION_PROFILES["release"],
            "-I", str(source / "include"), "-I", str(source / "src"),
            str(C_FIXTURE), "-o", str(binary),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        c = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, text=True, check=True)
        rust = subprocess.run(
            ["cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
             "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST,
             "--", "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, capture_output=True, text=True,
        )
        if rust.returncode != 0:
            sys.stderr.write(rust.stdout + rust.stderr)
            return rust.returncode
        c_lines = c.stdout.splitlines()
        rust_lines = re.findall(r"M3Q [^\r\n]+", rust.stdout)
        if len(c_lines) != 6 or c_lines != rust_lines:
            sys.stderr.write(f"C: {c_lines!r}\nRust: {rust_lines!r}\n")
            return 1
        sys.stdout.write("\n".join(c_lines) + "\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
