#!/usr/bin/env python3
"""Compare combined regular and OS abandoned-page visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_abandoned_combined_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-abandoned-combined-visitor"
STAGES = ("areas", "blocks", "stop_regular_area", "stop_regular_block", "ordinary")
BEGIN = "CRABC_MI_M6_ABANDONED_COMBINED_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_ABANDONED_COMBINED_VISITOR_TRACE_END"
SOURCE_COMBINED_PAGES = {
    "combined.areas": "1,1,1,0,0,0,2,1,RO",
    "combined.blocks": "1,1,1,2,1,0,2,1,R13OS",
    "combined.stop_regular_area": "0,1,0,0,0,0,2,0,R",
    "combined.stop_regular_block": "0,1,0,1,0,0,2,0,R1",
    "combined.ordinary": "1,1,1,2,1,0,2,1,R13OS",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"combined.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} combined visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){7},[RO13FS]*", trace[f"combined.{stage}"]):
            raise harness.HarnessError(f"{side} combined.{stage} is malformed")
    if side == "c" and trace != SOURCE_COMBINED_PAGES:
        raise harness.HarnessError(f"pinned C combined abandoned-page image changed: {trace}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-abandoned-combined-visitor-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "abandoned-combined-visitor-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "combined abandoned visitor C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "combined abandoned visitor C run")
        if re.findall(r"^source\.transfer=([01]),([01]),([01]),([01]),([01])$",
                      str(c_run["stderr"]), re.MULTILINE) != [("1", "1", "1", "1", "1")]:
            raise harness.HarnessError("pinned C did not retain both abandoned page owners")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "abandoned-combined-visitor-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "combined abandoned visitor Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "combined abandoned visitor Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        print(f"combined abandoned visitor: {len(c_trace)} source-built C/Rust keys match")


if __name__ == "__main__":
    main()
