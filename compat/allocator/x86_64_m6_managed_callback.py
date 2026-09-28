#!/usr/bin/env python3
"""Compare public callback-managed memory with pinned source."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_managed_callback_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-managed-callback"
BEGIN = "CRABC_MI_M6_MANAGED_CALLBACK_BEGIN"
END = "CRABC_MI_M6_MANAGED_CALLBACK_END"
EXPECTED = {
    "callback.reject": "1,1,1,1",
    "callback.manage": "1,1,1,1",
    "callback.allocation": "1,1",
    "callback.release": "1,6",
    "callback.event0": "1,0,589824,0",
    "callback.event1": "1,589824,65536,1",
    "callback.event2": "1,655360,65536,1",
    "callback.event3": "1,0,524288,0",
    "callback.event4": "0,589824,65536,0",
    "callback.event5": "0,655360,65536,0",
    "callback.terminal": "1,1,1",
}
WARNING = (
    "cannot use OS memory since it is not large enough "
    "(size 32767 KiB, minimum required is 32768 KiB)"
)


def run_differential() -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-managed-callback-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "managed-callback-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", "-DCRABC_M6_SOURCE_INTERNAL=1",
             *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Callback-managed C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "Callback-managed C run")
        source_rows = dict(re.findall(r"^(source\.[a-z_]+)=([0-9,]+)$", str(c_run["stderr"]), re.MULTILINE))
        if source_rows != {"source.callback": "1,1"}:
            raise harness.HarnessError(f"pinned callback source image changed: {source_rows}")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C managed callback", BEGIN, END)
        if c_trace != EXPECTED:
            raise harness.HarnessError(f"pinned callback C trace changed: {c_trace}")
        if str(c_run["stderr"]).count(WARNING) != 1:
            raise harness.HarnessError("pinned callback rejection warning changed")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "managed-callback-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Callback-managed Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "Callback-managed Rust run")
        if str(rust_run["stderr"]).count(WARNING) != 1:
            raise harness.HarnessError("managed callback rejection warning differs")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust managed callback", BEGIN, END)
        m7.compare_options_traces(c_trace, rust_trace)
        return len(c_trace)


if __name__ == "__main__":
    print(f"Managed callback: {run_differential()} source-built C/Rust keys match")
