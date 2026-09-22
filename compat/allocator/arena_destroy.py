#!/usr/bin/env python3
"""Development differential for persistent arena destruction; no M2 promotion."""

from pathlib import Path
import re

import run as harness


TEST = "arena::owned::tests::destroy_all_retires_regular_external_and_huge_owners_with_exact_retries"


def trace(output: str) -> list[int]:
    rows = re.findall(r"^m2\.arena\.destroy\.(\d+)=(-?\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(13)):
        raise harness.HarnessError("arena destruction trace must contain exactly thirteen ordered fields")
    return [int(value) for _, value in rows]


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/arena-destroy"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="arena-destroy-source-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [harness.require_tool("musl-gcc"), "-std=c11", "-fPIC",
            "-ftls-model=initial-exec", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(Path(__file__).with_suffix(".c").resolve()), "-pthread", "-Wl,--wrap=munmap",
            "-o", str(artifacts / "oracle")]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "arena destruction C oracle build")
        oracle = harness.command_record([str(artifacts / "oracle")], cwd=source, timeout_seconds=60)
        harness.require_success(oracle, "arena destruction C oracle")
    rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    harness.require_success(rust, "arena destruction Rust ownership checks")
    (artifacts / "c.log").write_text(oracle["stdout"])
    (artifacts / "rust.log").write_text(rust["stdout"])
    if trace(oracle["stdout"]) != trace(rust["stdout"]):
        raise harness.HarnessError("pinned C/Rust arena destruction differs")
    print(f"arena destruction: pinned C/Rust match; {artifacts}")


if __name__ == "__main__":
    main()
