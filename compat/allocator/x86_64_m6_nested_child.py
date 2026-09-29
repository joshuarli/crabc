#!/usr/bin/env python3
"""Compare nested child subprocess allocation and lifetime with pinned C."""

import hashlib
from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_nested_child_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-nested-child"
BEGIN = "CRABC_MI_M6_NESTED_CHILD_BEGIN"
END = "CRABC_MI_M6_NESTED_CHILD_END"
EXPECTED = {
    "nested.create": "1,1,1,1",
    "nested.owner": "1,1,1,1,1",
    "nested.after_exit": "1,1",
    "nested.destroyed": "1",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "source-seal.txt").write_text(
        f"mimalloc {pin['version']} {pin['revision']}\n"
        f"archive sha256 {hashlib.sha256(archive.read_bytes()).hexdigest()}\n"
        f"driver sha256 {hashlib.sha256(DRIVER.read_bytes()).hexdigest()}\n"
    )
    with harness.temporary_directory("crabc-mimalloc-m6-nested-child-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "nested-child-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "nested child C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "nested child C run")
        if re.findall(r"^source\.nested_parent=([01],[01])$", str(c_run["stderr"]), re.MULTILINE) != ["1,1"]:
            raise harness.HarnessError("pinned C nested parent source image changed")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C nested child", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned C nested child trace changed: {c_trace}")

        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "nested-child-rust"
        rust_link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(rust_link["stdout"]) + str(rust_link["stderr"]))
        harness.require_success(rust_link, "nested child Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "nested child Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust nested child", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


if __name__ == "__main__":
    print(f"Nested child subprocess: {run_differential()} source-built C/Rust keys match")
