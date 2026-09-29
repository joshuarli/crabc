#!/usr/bin/env python3
"""Compare terminal Heap release of one live aligned block."""

from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_heap_alignment_terminal_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-heap-alignment-terminal"
BEGIN = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_TERMINAL_BEGIN"
END = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_TERMINAL_END"
EXPECTED = {
    "terminal.ready": "1",
    "terminal.deleted": "1,1",
    "terminal.freed": "1",
    "terminal.second": "1",
    "terminal.destroyed": "1",
    "terminal.after": "1,1",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-public-heap-alignment-terminal-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "public-heap-alignment-terminal-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Terminal aligned Heap C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Terminal aligned Heap C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C terminal aligned Heap", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned terminal Heap trace changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "public-heap-alignment-terminal-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Terminal aligned Heap Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Terminal aligned Heap Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust terminal aligned Heap", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


if __name__ == "__main__":
    print(f"Terminal aligned Heap: {run_differential()} source-built C/Rust keys match")
