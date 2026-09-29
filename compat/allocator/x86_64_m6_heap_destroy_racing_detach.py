#!/usr/bin/env python3
"""Compare Heap destruction while an exited creator's second worker stays attached."""

from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_destroy_racing_detach_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-destroy-racing-detach"
BEGIN = "CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_BEGIN"
END = "CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_END"
EXPECTED = {"race.completed": "64", "race.owners": "0,0"}
REPETITIONS = 12


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-destroy-racing-detach-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "heap-destroy-racing-detach-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Heap destroy racing detach C build")
        c_logs = []
        for attempt in range(REPETITIONS):
            c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
            c_logs.append(str(c_run["stdout"]) + str(c_run["stderr"]))
            (ARTIFACTS / "c.log").write_text("\n".join(c_logs))
            harness.require_success(c_run, f"Heap destroy racing detach C run {attempt}")
            c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C Heap destroy racing detach", BEGIN, END)
            if c_trace != EXPECTED:
                raise harness.HarnessError(f"pinned Heap destroy racing detach changed on run {attempt}: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "heap-destroy-racing-detach-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Heap destroy racing detach Rust link")
        rust_logs = []
        for attempt in range(REPETITIONS):
            rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
            rust_logs.append(str(rust_run["stdout"]) + str(rust_run["stderr"]))
            (ARTIFACTS / "rust.log").write_text("\n".join(rust_logs))
            harness.require_success(rust_run, f"Heap destroy racing detach Rust run {attempt}")
            rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust Heap destroy racing detach", BEGIN, END)
            m7.compare_options_traces(c_trace, rust_trace)
            if str(c_run["stderr"]) != str(rust_run["stderr"]):
                raise harness.HarnessError(f"Heap destroy racing detach diagnostics differ on run {attempt}")
        return len(c_trace) * REPETITIONS


if __name__ == "__main__":
    print(f"Heap destroy racing detach: {run_differential()} source-built C/Rust keys match")
