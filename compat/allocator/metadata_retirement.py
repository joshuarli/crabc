#!/usr/bin/env python3
"""Direct OS metadata retention: full pinned C destruction versus Rust engine sealing."""

from pathlib import Path
import re

import run as harness


TEST = "meta::tests::process_metadata_terminal_close_retains_source_direct_os_mapping"


def trace(output: str) -> list[int]:
    output = re.sub(
        rf"^test {re.escape(TEST)} \.\.\. (?=m2\.metadata\.retirement\.0=)",
        "", output, count=1, flags=re.MULTILINE,
    )
    rows = re.findall(r"^m2\.metadata\.retirement\.(\d+)=(\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(4)):
        raise harness.HarnessError("metadata retirement trace requires four ordered fields")
    return [int(value) for _, value in rows]


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/metadata-retirement"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="metadata-retirement-source-") as directory:
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
        harness.require_success(build, "metadata retirement C build")
        oracle = harness.command_record([str(artifacts / "oracle")], cwd=source, timeout_seconds=60)
        (artifacts / "c.log").write_text(oracle["stdout"] + oracle["stderr"])
        harness.require_success(oracle, "metadata retirement C lifecycle")
    rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust.log").write_text(rust["stdout"] + rust["stderr"])
    harness.require_success(rust, "metadata retirement Rust ownership checks")
    if trace(oracle["stdout"]) != trace(rust["stdout"]):
        raise harness.HarnessError("pinned C/Rust metadata retirement differs")
    print(f"OS metadata retirement: four pinned C/Rust values match; {artifacts}")


if __name__ == "__main__":
    main()
