#!/usr/bin/env python3
"""Compare pinned C and Rust after the preferred clock query fails."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

import run as harness


BEGIN = "CRABC_M1_CLOCK_FALLBACK_BEGIN"
END = "CRABC_M1_CLOCK_FALLBACK_END"
TARGET = "os::tests::emit_m1_clock_fallback_after_monotonic_failure_c_rust_trace"
EXPECTED = {
    "preferred.calls": "1",
    "fallback.calls": "1",
    "clock.milliseconds": "1234",
}
LINE = re.compile(r"^([a-z.]+)=([0-9]+)$")
FIXTURE = Path(__file__).with_suffix(".c")


def trace(output: str, source: str) -> dict[str, str]:
    if output.count(BEGIN) != 1 or output.count(END) != 1:
        raise harness.HarnessError(f"{source} clock fallback trace must have one complete record")
    body = output.split(BEGIN, 1)[1].split(END, 1)[0]
    result = {}
    for line in body.strip().splitlines():
        match = LINE.fullmatch(line)
        if match is None or match.group(1) in result:
            raise harness.HarnessError(f"{source} clock fallback trace has an invalid row: {line}")
        result[match.group(1)] = match.group(2)
    if result != EXPECTED:
        raise harness.HarnessError(f"{source} clock fallback trace differs: {result}")
    return result


def execute(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    record = harness.command_record(command, cwd=cwd, env=env, timeout_seconds=1800)
    harness.require_success(record, "clock fallback differential command")
    return str(record["stdout"])


def run(offline: bool) -> dict[str, str]:
    harness.require_native_x86_64(require_image_identity=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    environment = dict(os.environ)
    with harness.temporary_directory("m1-clock-fallback-") as directory:
        temporary = Path(directory)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        binary = temporary / "oracle"
        flags = harness.CONFIGURATION_PROFILES["release"]
        execute([
            harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec",
            "-DMI_LIBC_MUSL=1", *flags, "-I", str(source / "include"),
            "-I", str(source / "src"), str(FIXTURE), "-Wl,--wrap=clock_gettime",
            "-Wl,--wrap=clock", "-pthread", "-o", str(binary),
        ], cwd=source)
        c_trace = trace(execute([str(binary)], cwd=temporary), "pinned C")
        rust_output = execute([
            harness.require_tool("cargo"), "test", "--locked", "--offline",
            "--target", "x86_64-unknown-linux-musl", "-p", "crabc-mimalloc",
            "--no-default-features", "--lib", TARGET, "--", "--exact", "--nocapture",
        ], cwd=harness.ROOT, env=environment)
        rust_trace = trace(rust_output, "Rust")
        if c_trace != rust_trace:
            raise harness.HarnessError("pinned C and Rust clock fallback traces differ")
    return c_trace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    result = run(args.offline)
    print(BEGIN)
    for key, value in result.items():
        print(f"{key}={value}")
    print(END)
    print("pinned C and production Rust clock fallback: matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
