#!/usr/bin/env python3
"""Compare public Heap arena selection with pinned mimalloc source."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_heap_in_arena_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-heap-in-arena"
BEGIN = "CRABC_MI_M6_CHILD_HEAP_IN_ARENA_BEGIN"
END = "CRABC_MI_M6_CHILD_HEAP_IN_ARENA_END"
EXPECTED = {
    "child.attached": "1,1",
    "child.reserved": "1,1,1,1,1",
    "child.selected": "1,1,1,1",
    "child.allocated": "1,1,1",
    "child.no_os_fallback": "1,1,1",
    "child.deleted": "1,1",
    "child.recreated": "1,1,1",
    "child.destroyed": "1",
    "child.failed_reserve": "1,1,1",
    "child.no_selection": "1,1,1",
    "child.joined": "1",
    "child.teardown": "1",
}
SOURCE = {"source.child_binding": "1,1", "source.child_no_selection": "1"}



def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-in-arena-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "child-heap-in-arena-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Child Heap in arena C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Child Heap in arena C run")
        source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$", str(c_run["stderr"]), re.MULTILINE))
        if source_rows != SOURCE:
            raise harness.HarnessError(f"pinned Heap arena source image changed: {source_rows}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C Child Heap in arena", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned C Heap arena trace changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "child-heap-in-arena-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Child Heap in arena Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Child Heap in arena Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust Child Heap in arena", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


if __name__ == "__main__":
    print(f"Child Heap in arena: {run_differential()} source-built C/Rust keys match")
