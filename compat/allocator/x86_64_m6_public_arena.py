#!/usr/bin/env python3
"""Compare public arena reservation, registration, queries, and ownership with pinned C."""

from pathlib import Path
import os
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_arena_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-arena"
BEGIN = "CRABC_MI_M6_PUBLIC_ARENA_BEGIN"
END = "CRABC_MI_M6_PUBLIC_ARENA_END"
EXPECTED = {
    "arena.sizes": "1,1,1",
    "arena.reserve": "1,1,1,1,1",
    "arena.manage": "1,1,1,1,1",
    "arena.manage_reject": "1,1,1",
    "arena.reserve_reject": "1,1,1",
    "arena.owned": "1,1,1,1",
    "arena.exclusive": "1,1,1,1",
    "arena.worker": "1,1,1,1,1,1",
    "arena.areas_retained": "1,1",
    "arena.external_retained": "1,1,1",
    "arena.reserved_manage": "1,1,1,1",
    "arena.reserved_selected": "1,1,1,1",
    "arena.reserved_retained": "1,1",
    "arena.child_reject": "1,1,1,1",
    "arena.child_manage": "1,1,1,1,1",
    "arena.child_selected": "1,1,1,1,1",
    "arena.child_worker": "1,1,1,1,1,1",
    "arena.child_terminal": "1,1,1",
    "arena.split_manage": "1,1,1,1,1",
    "arena.split_contains": "1,1,1,1,1",
    "arena.split_worker": "1,1,1,1,1,1",
    "arena.split_selected": "1,1,1",
    "arena.split_terminal": "1,1",
}
SOURCE = {
    "source.arena_owners": "1,1,1",
    "source.slices_released": "1,1",
    "source.external_forced_purge": "1,1",
    "source.reserved_external_callback": "1",
    "source.child_external_owner": "1,1,1",
    "source.child_external_purge": "1,1",
    "source.split_arena": "1,1,1",
}


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-public-arena-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "public-arena-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", "-DCRABC_M6_SOURCE_INTERNAL=1",
             *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Public arena C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Public arena C run")
        source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$", str(c_run["stderr"]), re.MULTILINE))
        if source_rows != SOURCE:
            raise harness.HarnessError(f"pinned public arena source image changed: {source_rows}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C public arena", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned C public arena trace changed: {c_trace}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "public-arena-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Public arena Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Public arena Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust public arena", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


def run_native_contract() -> None:
    """Exercise public arena ownership through the non-test Rust runtime."""
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(ARTIFACTS / "native-contract-cargo")
    execution = harness.command_record(
        [harness.require_tool("cargo"), "test", "--locked", "--offline",
         "--target", "x86_64-unknown-linux-musl", "-p", "crabc-mimalloc",
         "--no-default-features", "--test", "native_arena_contract",
         "--", "--test-threads=1", "--nocapture"],
        cwd=harness.ROOT, env=environment,
    )
    output = str(execution["stdout"]) + str(execution["stderr"])
    (ARTIFACTS / "native-contract.log").write_text(output)
    harness.require_success(execution, "Public arena native runtime contract")
    summaries = [line for line in output.splitlines() if line.startswith("test result:")]
    if len(summaries) != 1 or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in summaries[0]:
        raise harness.HarnessError("public arena native runtime contract did not execute its ownership test")


if __name__ == "__main__":
    print(f"Public arena: {run_differential()} source-built C/Rust keys match")
    run_native_contract()
    print("Public arena native runtime contract: 1 test passed")
