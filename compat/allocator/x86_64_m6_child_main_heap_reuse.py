#!/usr/bin/env python3
"""Compare child main-Heap allocation and visitation across successive owners."""

import hashlib
from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_main_heap_reuse_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-main-heap-reuse"
BEGIN = "CRABC_MI_M6_CHILD_MAIN_HEAP_REUSE_BEGIN"
END = "CRABC_MI_M6_CHILD_MAIN_HEAP_REUSE_END"
STAGES = (
    "first_owner", "first_live", "reattached", "first_exited",
    "second_owner", "second_live", "second_abandoned",
    "final_reattached", "second_exited", "freed",
)
SOURCE_TRACE = {
    "reuse.first_owner": "1,1,1",
    "reuse.first_live": "1,2,2,2,A1O3",
    "reuse.reattached": "1,1,1,1",
    "reuse.first_exited": "1,2,2,2,A1O3",
    "reuse.second_owner": "1,1,1,1",
    "reuse.second_live": "1,3,4,4,A12P4O3",
    "reuse.second_abandoned": "1,2,2,2,P4O3",
    "reuse.final_reattached": "1,1",
    "reuse.second_exited": "1,3,4,4,A12P4O3",
    "reuse.freed": "1,0,0,0,",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"reuse.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} child main Heap reuse keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in ("first_live", "first_exited", "second_live",
                  "second_abandoned", "second_exited", "freed"):
        if not re.fullmatch(r"[01](?:,[0-9]+){3},[ABOP1234]*", trace[f"reuse.{stage}"]):
            raise harness.HarnessError(f"{side} reuse.{stage} is malformed")
    if side == "c" and trace != SOURCE_TRACE:
        raise harness.HarnessError(f"pinned C child main Heap reuse image changed: {trace}")


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
    with harness.temporary_directory("crabc-mimalloc-m6-child-main-heap-reuse-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "child-main-heap-reuse-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "child main Heap reuse C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "child main Heap reuse C run")
        if re.findall(r"^source\.reuse=([01](?:,[01]){8},[0-9]+)$",
                      str(c_run["stderr"]), re.MULTILINE) != ["1,1,1,1,1,1,1,1,1,1"]:
            raise harness.HarnessError("pinned C child main Heap reuse source image changed")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C child main Heap reuse", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "child-main-heap-reuse-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "child main Heap reuse Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "child main Heap reuse Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust child main Heap reuse", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


if __name__ == "__main__":
    print(f"child main Heap reuse: {run_differential()} source-built C/Rust keys match")
