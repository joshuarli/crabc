#!/usr/bin/env python3
"""Compare OS singleton abandoned-page visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_abandoned_os_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-abandoned-os-visitor"
STAGES = ("areas", "blocks", "stop_area", "stop_block", "ordinary")
BEGIN = "CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_END"
SOURCE_OS_SINGLETON = {
    "os.areas": "1,1,0,1,1,0,0,0,1",
    "os.blocks": "1,1,1,1,1,1,0,0,12",
    "os.stop_area": "0,1,0,1,1,0,0,0,1",
    "os.stop_block": "0,1,1,1,1,1,0,0,12",
    "os.ordinary": "1,1,1,1,1,1,0,0,12",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"os.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} OS abandoned visitor keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){8}", trace[f"os.{stage}"]):
            raise harness.HarnessError(f"{side} os.{stage} is malformed")
    if trace["os.areas"].split(",")[:3] != ["1", "1", "0"] \
            or trace["os.blocks"].split(",")[:3] != ["1", "1", "1"] \
            or trace["os.stop_area"].split(",")[:3] != ["0", "1", "0"] \
            or trace["os.stop_block"].split(",")[:3] != ["0", "1", "1"]:
        raise harness.HarnessError(f"{side} did not visit one live OS singleton with early stops")
    if side == "c" and trace != SOURCE_OS_SINGLETON:
        raise harness.HarnessError(f"pinned C abandoned OS singleton image changed: {trace}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-abandoned-os-visitor-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "abandoned-os-visitor-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "OS abandoned visitor C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "OS abandoned visitor C run")
        if re.findall(r"^source\.os=([01]),([01])$", str(c_run["stderr"]), re.MULTILINE) != [("1", "1")]:
            raise harness.HarnessError("pinned C did not allocate two OS singleton pages")
        if re.findall(r"^source\.transfer=([01]),([01]),([01])$", str(c_run["stderr"]), re.MULTILINE) \
                != [("1", "1", "1")]:
            raise harness.HarnessError("pinned C did not abandon the live page onto its Heap OS list")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "abandoned-os-visitor-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "OS abandoned visitor Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "OS abandoned visitor Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        print(f"OS abandoned visitor: {len(c_trace)} source-built C/Rust keys match")


if __name__ == "__main__":
    main()
