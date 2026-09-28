#!/usr/bin/env python3
"""Compare the public managed-OS-memory alias against pinned source."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_manage_os_memory_alias_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-manage-os-memory-alias"
BEGIN = "CRABC_MI_M6_MANAGE_OS_MEMORY_ALIAS_BEGIN"
END = "CRABC_MI_M6_MANAGE_OS_MEMORY_ALIAS_END"
EXPECTED = {
    "alias.main": "1,1,1,1",
    "alias.child": "1,1,1,1,1",
    "alias.child_terminal": "1,1",
}
SOURCE = {
    "source.main_alias": "1,1,1,1",
    "source.child_alias": "1,1,1,1",
}
WARNING = "cannot use OS memory since it is not large enough"


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-manage-os-memory-alias-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "manage-os-memory-alias-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", "-DCRABC_M6_SOURCE_INTERNAL=1",
             *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Managed OS alias C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Managed OS alias C run")
        if str(c_run["stderr"]).count(WARNING) != 2:
            raise harness.HarnessError("pinned alias C short-region warnings changed")
        source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$", str(c_run["stderr"]), re.MULTILINE))
        if source_rows != SOURCE:
            raise harness.HarnessError(f"pinned alias source image changed: {source_rows}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C managed OS alias", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned alias C trace changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "manage-os-memory-alias-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Managed OS alias Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Managed OS alias Rust run")
        if str(rust_run["stderr"]).count(WARNING) != 2:
            raise harness.HarnessError("managed OS alias Rust short-region warnings differ")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust managed OS alias", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


if __name__ == "__main__":
    print(f"Managed OS alias: {run_differential()} source-built C/Rust keys match")
