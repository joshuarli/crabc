#!/usr/bin/env python3
"""Development physical destroy_on_exit C/Rust ownership differential."""
from pathlib import Path
import re

import run as harness

TESTS = (
    "runtime_lifecycle::destroy::tests::physical_destroy_transfers_live_worker_before_arena_and_page_map_release",
    "runtime_lifecycle::destroy::tests::physical_destroy_os_only_retains_source_pages_but_seals_all_native_access",
)


def trace(output: str, test: str = "") -> list[int]:
    if test:
        output = re.sub(rf"^test {re.escape(test)} \.\.\. (?=m2\.process\.destroy\.0=)",
                        "", output, count=1, flags=re.MULTILINE)
    rows = re.findall(r"^m2\.process\.destroy\.(\d+)=(\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(7)):
        raise harness.HarnessError("physical process destruction requires seven ordered fields")
    return [int(value) for _, value in rows]


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/process-destroy"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="process-destroy-source-") as directory:
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
        harness.require_success(build, "physical process destruction C build")
        for mode, test in enumerate(TESTS):
            oracle = harness.command_record([str(artifacts / "oracle"), str(mode)],
                cwd=source, timeout_seconds=60)
            (artifacts / f"c-{mode}.log").write_text(oracle["stdout"] + oracle["stderr"])
            harness.require_success(oracle, f"physical C destruction mode {mode}")
            rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", test],
                cwd=harness.ROOT, timeout_seconds=900)
            (artifacts / f"rust-{mode}.log").write_text(rust["stdout"] + rust["stderr"])
            harness.require_success(rust, f"physical Rust destruction mode {mode}")
            if trace(oracle["stdout"]) != trace(rust["stdout"], test):
                raise harness.HarnessError(f"pinned C/Rust physical destruction differs in mode {mode}")
    print(f"physical process destruction: two seven-field pinned C/Rust lifecycles match; {artifacts}")


if __name__ == "__main__":
    main()
