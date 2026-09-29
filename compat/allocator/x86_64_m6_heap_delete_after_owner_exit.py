#!/usr/bin/env python3
"""Compare Heap deletion after the creating thread has exited."""

from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_delete_after_owner_exit_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-delete-after-owner-exit"
BEGIN = "CRABC_MI_M6_HEAP_DELETE_AFTER_OWNER_EXIT_BEGIN"
END = "CRABC_MI_M6_HEAP_DELETE_AFTER_OWNER_EXIT_END"
EXPECTED = {
    "exit.created": "1",
    "exit.live": "1,1,1,1",
    "exit.deleted": "0,0,1,1",
    "exit.freed": "37,0,0",
    "exit.collected": "0,0",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-delete-after-owner-exit-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "heap-delete-after-owner-exit-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Heap delete after owner exit C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Heap delete after owner exit C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C Heap delete after owner exit", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned Heap delete after owner exit changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "heap-delete-after-owner-exit-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Heap delete after owner exit Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Heap delete after owner exit Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust Heap delete after owner exit", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        if str(c_run["stderr"]) != str(rust_run["stderr"]):
            raise harness.HarnessError("Heap delete after owner exit diagnostics differ")
        return len(c_trace)


if __name__ == "__main__":
    print(f"Heap delete after owner exit: {run_differential()} source-built C/Rust keys match")
