#!/usr/bin/env python3
"""Compare Heap destruction while an exited creator's second worker stays attached."""

from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_delete_with_attached_worker_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-delete-with-attached-worker"
BEGIN = "CRABC_MI_M6_HEAP_DELETE_WITH_ATTACHED_WORKER_BEGIN"
END = "CRABC_MI_M6_HEAP_DELETE_WITH_ATTACHED_WORKER_END"
EXPECTED = {
    "attached.owner": "1,1",
    "attached.live": "1,1,1,1",
    "attached.delete": "37,1,1,1",
    "attached.stats": "2,0",
    "attached.joined": "0,1,1",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-delete-with-attached-worker-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "heap-delete-with-attached-worker-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Heap delete with attached worker C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Heap delete with attached worker C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C Heap delete with attached worker", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned Heap delete with attached worker changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "heap-delete-with-attached-worker-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Heap delete with attached worker Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Heap delete with attached worker Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust Heap delete with attached worker", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        if str(c_run["stderr"]) != str(rust_run["stderr"]):
            raise harness.HarnessError("Heap delete with attached worker diagnostics differ")
        return len(c_trace)


if __name__ == "__main__":
    print(f"Heap delete with attached worker: {run_differential()} source-built C/Rust keys match")
