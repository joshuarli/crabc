#!/usr/bin/env python3
"""Compare public regular-arena map failure across pinned C and Rust."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_reservation_warning_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-reservation-warning"
BEGIN = "CRABC_MI_M6_RESERVATION_WARNING_BEGIN"
END = "CRABC_MI_M6_RESERVATION_WARNING_END"
EXPECTED = {
    "main.reserve": "12,1,12",
    "child.reserve": "1,12,1,12",
    "child.terminal": "1",
}
ONE_FAILURE_WARNINGS = [
    "unable to allocate OS memory (error: 12 (0x0C), addr: 0x00000000, size: 0x4000000000000000 bytes, align: 0x10000000, commit: 1, allow large: 0)",
    "unable to allocate aligned OS memory directly, fall back to over-allocation (size: 0x4000000000000000 bytes, address: <address>, alignment: 0x10000000, commit: 1)",
    "unable to allocate OS memory (error: 12 (0x0C), addr: 0x00000000, size: 0x4000000010000000 bytes, align: 0x200000, commit: 1, allow large: 0)",
]
EXPECTED_WARNINGS = ONE_FAILURE_WARNINGS * 2


def warnings(output: str) -> list[str]:
    bodies = re.findall(r"^mimalloc: warning: thread 0x[0-9A-Fa-f]+: (.+)$", output, re.MULTILINE)
    return [re.sub(r"(hint )?address: 0x[0-9A-Fa-f]+", r"\1address: <address>", body)
            for body in bodies]


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-reservation-warning-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "reservation-warning-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Reservation warning C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Reservation warning C run")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C reservation warning", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned reservation failure image changed: {c_trace}")
        c_warnings = warnings(str(c_run["stderr"]))
        if c_warnings != EXPECTED_WARNINGS:
            raise harness.HarnessError(f"pinned reservation warning image changed: {c_warnings}")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "reservation-warning-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Reservation warning Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Reservation warning Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust reservation warning", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        rust_warnings = warnings(str(rust_run["stderr"]))
        if c_warnings != rust_warnings:
            raise harness.HarnessError(f"warning order differs: C {c_warnings}; Rust {rust_warnings}")
        return len(c_trace)


if __name__ == "__main__":
    print(f"Reservation warning: {run_differential()} C/Rust lifecycle keys match")
