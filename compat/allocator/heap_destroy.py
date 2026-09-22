#!/usr/bin/env python3
"""Development main-Heap Theap destruction differential; no process teardown admission."""

from pathlib import Path
import re

import run as harness


TEST = "main_heap_thread::tests::source_retained_workers_transfer_before_tls_exit_and_force_destroy_reclaims_all_theaps"


def trace(output: str) -> list[int]:
    output = re.sub(
        rf"^test {re.escape(TEST)} \.\.\. (?=m2\.heap\.destroy\.0=)",
        "", output, count=1, flags=re.MULTILINE,
    )
    rows = re.findall(r"^m2\.heap\.destroy\.(\d+)=(\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(11)):
        raise harness.HarnessError("main-Heap destruction trace requires seven ordered fields")
    return [int(value) for _, value in rows]


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/heap-destroy"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="heap-destroy-source-") as directory:
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
        harness.require_success(build, "main-Heap destruction C build")
        oracle = harness.command_record([str(artifacts / "oracle")], cwd=source, timeout_seconds=60)
        (artifacts / "c.log").write_text(oracle["stdout"] + oracle["stderr"])
        harness.require_success(oracle, "main-Heap destruction C lifecycle")
    rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust.log").write_text(rust["stdout"] + rust["stderr"])
    harness.require_success(rust, "main-Heap destruction Rust ownership checks")
    if trace(oracle["stdout"]) != trace(rust["stdout"]):
        raise harness.HarnessError("pinned C/Rust main-Heap destruction differs")
    print(f"main-Heap Theap destruction: seven pinned C/Rust values match; {artifacts}")


if __name__ == "__main__":
    main()
