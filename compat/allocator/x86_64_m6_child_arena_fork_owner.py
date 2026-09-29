#!/usr/bin/env python3
"""Compare child arena Heap retirement in both copies after fork."""

from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_arena_fork_owner_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-arena-fork-owner"
BEGIN = "CRABC_MI_M6_CHILD_ARENA_FORK_OWNER_BEGIN"
END = "CRABC_MI_M6_CHILD_ARENA_FORK_OWNER_END"
EXPECTED = {
    "fork.owner_exited": "1,1",
    "fork.child.inherited": "1,1",
    "fork.child.remote": "1",
    "fork.child.heap_destroyed": "1",
    "fork.child.retired": "1",
    "fork.wait": "1",
    "fork.parent.inherited": "1,1",
    "fork.parent.remote": "1",
    "fork.parent.heap_destroyed": "1",
    "fork.parent.retired": "1",
    "fork.attached_live": "1,1",
    "fork.vanished_retired": "1",
    "fork.vanished_wait": "1",
    "fork.parent_owner_exited": "1",
    "fork.parent_live_retired": "1",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-child-arena-fork-owner-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "child-arena-fork-owner-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "child arena fork owner C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "child arena fork owner C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C child arena fork owner", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned child arena fork owner changed: {c_trace}")

        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "child-arena-fork-owner-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "child arena fork owner Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "child arena fork owner Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust child arena fork owner", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        if str(c_run["stderr"]) != str(rust_run["stderr"]):
            raise harness.HarnessError("child arena fork owner diagnostics differ")
        return len(c_trace)


if __name__ == "__main__":
    print(f"Child arena fork owner: {run_differential()} source-built C/Rust keys match")
