#!/usr/bin/env python3
"""Compare pinned C and production Rust cold-arena prefix refusal retries."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import run as harness


BEGIN = "CRABC_COLD_ARENA_PREFIX_RETRY_BEGIN"
END = "CRABC_COLD_ARENA_PREFIX_RETRY_END"
EXPECTED = {
    "metadata.calls": "1", "metadata.bytes": "524288",
    "prefix.calls": "2", "prefix.bytes": "114688", "prefix.refused_bytes": "114688", "prefix.same": "1",
    "client.in_arena": "1", "client.owned": "1", "client.bytes": "1",
}


def trace(output: str) -> dict[str, str]:
    if output.count(BEGIN) != 1 or output.count(END) != 1:
        raise harness.HarnessError("cold-arena trace must have exactly one complete record")
    body = output.split(BEGIN, 1)[1].split(END, 1)[0]
    result = {}
    for line in body.strip().splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise harness.HarnessError(f"invalid cold-arena trace row: {line}")
        result[key] = value
    if result != EXPECTED:
        raise harness.HarnessError(f"cold-arena prefix retry differs: {result}")
    return result


def execute(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    record = harness.command_record(command, cwd=cwd, env=env, timeout_seconds=1800)
    harness.require_success(record, "cold-arena prefix retry command")
    return str(record["stdout"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64(require_image_identity=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    environment = {
        **os.environ,
        "mimalloc_page_commit_on_demand": "1", "mimalloc_arena_eager_commit": "0",
        "mimalloc_purge_delay": "-1", "mimalloc_arena_reserve": "0",
    }
    with harness.temporary_directory("cold-arena-prefix-retry-") as directory:
        temporary = Path(directory)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        binary = temporary / "oracle"
        flags = ["-O0" if flag == "-O3" else flag for flag in harness.CONFIGURATION_PROFILES["release"]]
        execute([harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec",
                 "-DMI_LIBC_MUSL=1", *flags, "-I", str(source / "include"),
                 str(harness.ALLOCATOR_ROOT / "x86_64_cold_arena_prefix_retry.c"),
                 str(source / "src/static.c"), "-pthread", "-o", str(binary)], cwd=source)
        c_trace = trace(execute([str(binary)], cwd=temporary, env=environment))
        rust = execute([harness.require_tool("cargo"), "test", "--locked", "--offline",
                        "--target", "x86_64-unknown-linux-musl", "-p", "crabc-mimalloc",
                        "--no-default-features", "--test", "native_cold_arena_prefix_retry",
                        "--", "--nocapture", "--test-threads=1"], cwd=harness.ROOT, env=environment)
        rust_trace = trace(rust)
        if c_trace != rust_trace:
            raise harness.HarnessError("pinned C and Rust prefix retry traces differ")
        print(BEGIN)
        for key, value in c_trace.items():
            print(f"{key}={value}")
        print(END)
        print("pinned C and production Rust cold-arena prefix retry: matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
