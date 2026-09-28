#!/usr/bin/env python3
"""Compare process-main OS abandoned-page visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_main_abandoned_os_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-main-abandoned-os-visitor"
STAGES = ("before", "areas", "blocks", "stop_area", "stop_block", "null_heap")
BEGIN = "CRABC_MI_M6_MAIN_ABANDONED_OS_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_MAIN_ABANDONED_OS_VISITOR_TRACE_END"
SOURCE_MAIN_OS = {
    "main_os.before": "1,1,0,0,1,0,0,0,1,K",
    "main_os.areas": "1,2,1,0,1,0,0,0,2,OK",
    "main_os.blocks": "1,2,1,0,1,1,0,1,2,O1KK",
    "main_os.stop_area": "0,1,1,0,0,0,0,0,1,O",
    "main_os.stop_block": "0,1,1,0,0,1,0,0,1,O1",
    "main_os.null_heap": "1,2,1,0,1,1,0,1,2,O1KK",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"main_os.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} process-main OS abandoned keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){8},[O1FKXx]*", trace[f"main_os.{stage}"]):
            raise harness.HarnessError(f"{side} main_os.{stage} is malformed")
    if side == "c" and trace != SOURCE_MAIN_OS:
        raise harness.HarnessError(f"pinned C process-main OS abandoned image changed: {trace}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-main-abandoned-os-visitor-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "main-abandoned-os-visitor-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "process-main OS abandoned visitor C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "process-main OS abandoned visitor C run")
        for name, count in (("source.keeper", 4), ("source.worker_os", 2),
                            ("source.freed_removed", 2), ("source.selected", 7)):
            pattern = rf"^{re.escape(name)}=" + ",".join(["([01])"] * count) + "$"
            if re.findall(pattern, str(c_run["stderr"]), re.MULTILINE) \
                    != [tuple("1" for _ in range(count))]:
                raise harness.HarnessError(f"pinned C process-main OS ownership differs: {name}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "main-abandoned-os-visitor-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "process-main OS abandoned visitor Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "process-main OS abandoned visitor Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        print(f"process-main OS abandoned visitor: {len(c_trace)} source-built C/Rust keys match")


if __name__ == "__main__":
    main()
