#!/usr/bin/env python3
"""Pinned C/Rust `mi_abandoned_page_try_reclaim` decision differential.

The C oracle (`reclaim_on_free.c`) and the Rust integration test
`native_reclaim_on_free` run the same four worker-thread cases through the
ordinary free entry and print, for each, whether the freeing thread now owns
the page plus its `used` count and regular queue length.
"""

from pathlib import Path
import re

import run as harness


RUST_TEST = "native_reclaim_on_free"
CASES = ("own_full", "foreign_empty_queue", "foreign_nonempty_queue", "foreign_large")
FIELDS = ("reclaimed", "used", "queue_count")


def trace(output: str, origin: str) -> dict[str, int]:
    rows = dict(re.findall(r"reclaim\.([a-z_]+\.[a-z_]+)=(\d+)$", output, re.MULTILINE))
    expected = [f"{case}.{field}" for case in CASES for field in FIELDS]
    if sorted(rows) != sorted(expected):
        raise harness.HarnessError(f"{origin} reclaim-on-free trace has fields {sorted(rows)}")
    return {key: int(rows[key]) for key in expected}


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/reclaim-on-free"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="reclaim-on-free-source-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [harness.require_tool("musl-gcc"), "-std=c11", "-fPIC",
            "-ftls-model=initial-exec", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(Path(__file__).with_suffix(".c").resolve()), "-pthread",
            "-o", str(artifacts / "oracle")]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        (artifacts / "c-build.log").write_text(build["stdout"] + build["stderr"])
        harness.require_success(build, "reclaim-on-free C build")
        oracle = harness.command_record([str(artifacts / "oracle")], cwd=source, timeout_seconds=60)
        (artifacts / "c.log").write_text(oracle["stdout"] + oracle["stderr"])
        harness.require_success(oracle, "reclaim-on-free C cases")
    rust = harness.command_record(
        ["cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
         "-p", "crabc-mimalloc", "--no-default-features",
         "--features", "native-runtime-test-audit", "--test", RUST_TEST,
         "--", "--nocapture", "--test-threads=1"],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust.log").write_text(rust["stdout"] + rust["stderr"])
    harness.require_success(rust, "reclaim-on-free Rust cases")
    c_trace = trace(oracle["stdout"], "pinned C")
    rust_trace = trace(rust["stdout"], "Rust")
    differences = [key for key in c_trace if c_trace[key] != rust_trace[key]]
    if differences:
        raise harness.HarnessError("pinned C/Rust reclaim-on-free differs: " + ", ".join(
            f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})" for key in differences))
    print(f"reclaim-on-free: {len(c_trace)} pinned C/Rust values match; {artifacts}")


if __name__ == "__main__":
    main()
