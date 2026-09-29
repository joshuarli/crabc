#!/usr/bin/env python3
"""Compare child main-Heap visitation across owner exit against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_child_main_heap_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-child-main-heap-visitor"
STAGES = (
    "owner_ordinary", "owner_abandoned", "areas", "blocks", "stop_area",
    "stop_block", "null_heap", "ordinary", "after_free",
)
BEGIN = "CRABC_MI_M6_CHILD_MAIN_HEAP_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_CHILD_MAIN_HEAP_VISITOR_TRACE_END"
SOURCE_CHILD_MAIN = {
    "child_main.owner_ordinary": "1,2,3,3,R13OS",
    "child_main.owner_abandoned": "1,1,1,1,OS",
    "child_main.areas": "1,2,0,3,RO",
    "child_main.blocks": "1,2,3,3,R13OS",
    "child_main.stop_area": "0,1,0,2,R",
    "child_main.stop_block": "0,1,1,2,R1",
    "child_main.null_heap": "1,2,3,3,R13OS",
    "child_main.ordinary": "1,2,3,3,R13OS",
    "child_main.after_free": "1,0,0,0,",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"child_main.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} child main visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){3},[RO13SF]*", trace[f"child_main.{stage}"]):
            raise harness.HarnessError(f"{side} child_main.{stage} is malformed")
    if side == "c" and trace != SOURCE_CHILD_MAIN:
        raise harness.HarnessError(f"pinned C child main Heap visitor image changed: {trace}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-child-main-heap-visitor-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "child-main-heap-visitor-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "child main Heap visitor C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "child main Heap visitor C run")
        if re.findall(r"^source\.child_main=([01]),([01]),([01]),([01])$",
                      str(c_run["stderr"]), re.MULTILINE) != [("1", "1", "1", "1")]:
            raise harness.HarnessError("pinned C child main pages did not retain their owners")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "child-main-heap-visitor-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "child main Heap visitor Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "child main Heap visitor Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        print(f"child main Heap visitor: {len(c_trace)} source-built C/Rust keys match")


if __name__ == "__main__":
    main()
