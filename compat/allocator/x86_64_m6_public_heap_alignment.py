#!/usr/bin/env python3
"""Compare public Heap allocation content, failure, and ownership with pinned source."""

from pathlib import Path
import re
import shutil

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_heap_alignment_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-heap-alignment"
BEGIN = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_BEGIN"
END = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END"
EXPECTED = {
    "alignment.heap": "1,1",
    "alignment.case0": "1,1,1,1,1,1",
    "alignment.case1": "1,1,1,1,1,1",
    "alignment.case2": "1,1,1,1,1,1",
    "alignment.case3": "1,1,1,1,1,1",
    "alignment.case4": "1,1,1,1,1,1",
    "alignment.case5": "1,1,1,1,1,1",
    "alignment.failure0": "1,22",
    "alignment.failure1": "1,22",
    "alignment.failure2": "1,22",
    "alignment.failure3": "1,12",
    "alignment.worker": "1,1,1,1,1,1",
    "alignment.before_delete": "1,1",
    "alignment.after_delete": "1,0,1",
    "alignment.freed_after_delete": "1",
    "alignment.second_heap": "1",
    "alignment.second_block": "1",
    "alignment.second_destroyed": "1",
    "alignment.destroy": "1,1",
    "contract.growth": "1",
    "contract.allocations": "1",
    "contract.strings": "1",
    "contract.failures": "1",
    "contract.replacements": "1",
    "contract.lifetime": "1",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-public-heap-alignment-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "public-heap-alignment-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Public Heap alignment C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Public Heap alignment C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C public Heap alignment", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned Heap alignment trace changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "public-heap-alignment-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Public Heap alignment Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Public Heap alignment Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust public Heap alignment", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        c_errors = re.findall(r"(?:aligned allocation[^\n]*|out of memory[^\n]*)", str(c_run["stderr"]))
        rust_errors = re.findall(r"(?:aligned allocation[^\n]*|out of memory[^\n]*)", str(rust_run["stderr"]))
        if c_errors != rust_errors:
            raise harness.HarnessError(f"Heap alignment diagnostics differ: {c_errors!r} != {rust_errors!r}")
        shutil.copy2(c_driver, ARTIFACTS / "public-heap-alignment-c")
        shutil.copy2(rust_driver, ARTIFACTS / "public-heap-alignment-rust")
        direct = harness.command_record(
            [harness.require_tool("cargo"), "test", "--locked", "--offline", "--target", m4.RUST_TARGET,
             "-p", "crabc-mimalloc", "--no-default-features",
             "--test", "native_heap_allocation_contract",
             "heap_requests_preserve_content_failure_and_legal_release_lifetimes",
             "--", "--exact", "--nocapture", "--test-threads=1"],
            cwd=harness.ROOT, timeout_seconds=900,
        )
        (ARTIFACTS / "native_heap_allocation_contract.log").write_text(
            str(direct["stdout"]) + str(direct["stderr"]))
        harness.require_success(direct, "public Heap direct allocation ownership contract")
        if harness.parse_rust_test_count(str(direct["stdout"]) + str(direct["stderr"])) != 1:
            raise harness.HarnessError("public Heap direct allocation ownership contract did not execute exactly one test")
        return len(c_trace)


if __name__ == "__main__":
    print(f"Public Heap alignment: {run_differential()} source-built C/Rust keys match")
