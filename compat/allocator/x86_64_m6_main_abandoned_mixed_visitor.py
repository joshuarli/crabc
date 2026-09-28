#!/usr/bin/env python3
"""Compare mixed process-main abandoned visitation against pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_main_abandoned_mixed_visitor_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-main-abandoned-mixed-visitor"
STAGES = (
    "before", "areas", "blocks", "stop_low_area", "stop_low_block",
    "stop_high_area", "stop_high_block", "stop_os_area", "stop_os_block",
    "null_heap",
)
BEGIN = "CRABC_MI_M6_MAIN_ABANDONED_MIXED_VISITOR_TRACE_BEGIN"
END = "CRABC_MI_M6_MAIN_ABANDONED_MIXED_VISITOR_TRACE_END"
SOURCE_MIXED = {
    "mixed.before": "1,0,0,0,1,0,0,0,1,0,0,1,KT",
    "mixed.areas": "1,1,1,1,1,0,0,0,0,0,0,6,LHOK",
    "mixed.blocks": "1,1,1,1,1,2,2,1,1,0,0,6,L13H46OSKT",
    "mixed.stop_low_area": "0,1,0,0,0,0,0,0,0,0,0,2,L",
    "mixed.stop_low_block": "0,1,0,0,0,1,0,0,0,0,0,2,L1",
    "mixed.stop_high_area": "0,1,1,0,0,2,0,0,0,0,0,4,L13H",
    "mixed.stop_high_block": "0,1,1,0,0,2,1,0,0,0,0,4,L13H4",
    "mixed.stop_os_area": "0,1,1,1,0,2,2,0,0,0,0,5,L13H46O",
    "mixed.stop_os_block": "0,1,1,1,0,2,2,1,0,0,0,5,L13H46OS",
    "mixed.null_heap": "1,1,1,1,1,2,2,1,1,0,0,6,L13H46OSKT",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    expected = {f"mixed.{stage}" for stage in STAGES}
    if set(trace) != expected:
        raise harness.HarnessError(
            f"{side} mixed process-main keys differ: "
            f"missing={sorted(expected - set(trace))} extra={sorted(set(trace) - expected)}"
        )
    for stage in STAGES:
        if not re.fullmatch(r"[01](?:,[0-9]+){11},[LHOKT1346SFNn]*", trace[f"mixed.{stage}"]):
            raise harness.HarnessError(f"{side} mixed.{stage} is malformed")
    if side == "c" and trace != SOURCE_MIXED:
        raise harness.HarnessError(f"pinned C mixed process-main abandoned image changed: {trace}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-main-abandoned-mixed-visitor-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "main-abandoned-mixed-visitor-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "mixed process-main abandoned visitor C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "mixed process-main abandoned visitor C run")
        for name, count in (("source.freed_os", 2), ("source.regular", 10),
                            ("source.os", 5)):
            pattern = rf"^{re.escape(name)}=" + ",".join(["([01])"] * count) + "$"
            if re.findall(pattern, str(c_run["stderr"]), re.MULTILINE) \
                    != [tuple("1" for _ in range(count))]:
                raise harness.HarnessError(f"pinned C mixed page ownership differs: {name}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "main-abandoned-mixed-visitor-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "mixed process-main abandoned visitor Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "mixed process-main abandoned visitor Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        print(f"mixed process-main abandoned visitor: {len(c_trace)} source-built C/Rust keys match")


if __name__ == "__main__":
    main()
