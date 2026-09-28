#!/usr/bin/env python3
"""Compare the public huge-page reservation entry with pinned source."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_huge_at_ex_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-huge-at-ex"
BEGIN = "CRABC_MI_M6_HUGE_AT_EX_BEGIN"
END = "CRABC_MI_M6_HUGE_AT_EX_END"
ZERO = {
    "zero.negative": "0,1,1",
    "zero.timeout": "0,1,1",
    "zero.null": "0,1",
}
WARNING = "failed to reserve 1 GiB huge pages"


def warning_bodies(output: str) -> list[str]:
    bodies = re.findall(r"^mimalloc: warning: thread 0x[0-9A-Fa-f]+: (.+)$", output, re.MULTILINE)
    return [re.sub(r"address: 0x[0-9A-Fa-f]+", "address: <address>", body)
            for body in bodies]


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-huge-at-ex-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "huge-at-ex-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Huge at-ex C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Huge at-ex C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C huge at-ex", BEGIN, END)
        if {key: c_trace.get(key) for key in ZERO} != ZERO:
            raise harness.HarnessError(f"pinned zero-page image changed: {c_trace}")
        if len(c_trace) != 5:
            raise harness.HarnessError(f"pinned huge at-ex row count changed: {c_trace}")
        c_failures = sum(c_trace[key].startswith("12,1,") for key in ("one.negative", "one.node_zero"))
        c_warnings = warning_bodies(str(c_run["stderr"]))
        if sum(WARNING in body for body in c_warnings) != c_failures:
            raise harness.HarnessError("pinned huge-reservation warning count changed")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "huge-at-ex-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Huge at-ex Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Huge at-ex Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust huge at-ex", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        rust_warnings = warning_bodies(str(rust_run["stderr"]))
        if rust_warnings != c_warnings:
            raise harness.HarnessError(
                f"huge-reservation warning order differs: C {c_warnings}, Rust {rust_warnings}")
        return len(c_trace)


if __name__ == "__main__":
    print(f"Huge at-ex: {run_differential()} source-built C/Rust keys match")
