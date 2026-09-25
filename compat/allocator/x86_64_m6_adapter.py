#!/usr/bin/env python3
"""Pinned-C/native-adapter differential for the M6 Heap and reservation entries.

The shared driver `x86_64_m6_adapter_driver.c` is linked once against the
pinned mimalloc release sources and once against the native `mi_*` adapter;
each binary runs in its own process with an empty environment, and the two
marked `key=value` traces must be identical. The M4 gate owns the adapter
build and the M7 gate the trace reader; both are reused here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_adapter_driver.c"
TRACE_BEGIN = "CRABC_MI_M6_ADAPTER_TRACE_BEGIN"
TRACE_END = "CRABC_MI_M6_ADAPTER_TRACE_END"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-adapter"


def run_adapter_differential(offline: bool = True) -> dict[str, Any]:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m6-adapter-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "m6-adapter-c"
        build = harness.command_record(
            [
                compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                *harness.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
                str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver),
            ],
            cwd=source,
        )
        harness.require_success(build, "M6 adapter C driver build")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "m6-adapter-rust"
        link = harness.command_record(
            [
                compiler, "-std=c11", "-O2", "-I", str(source / "include"),
                str(DRIVER), str(library), "-pthread", "-o", str(rust_driver),
            ],
            cwd=source,
        )
        harness.require_success(link, "M6 adapter Rust driver link")
        executions = {
            side: harness.command_record((str(driver),), cwd=temporary, env={}, timeout_seconds=600)
            for side, driver in (("c", c_driver), ("rust", rust_driver))
        }
    for side, execution in executions.items():
        (ARTIFACTS / f"{side}.log").write_text(str(execution["stdout"]) + str(execution["stderr"]))
        harness.require_success(execution, f"M6 adapter {side} driver")
    traces = {
        side: m7.parse_options_trace(str(execution["stdout"]), f"{side} M6 adapter trace", TRACE_BEGIN, TRACE_END)
        for side, execution in executions.items()
    }
    m7.compare_options_traces(traces["c"], traces["rust"])
    report = {"compared_key_count": len(traces["c"]), "status": "passed", "trace": traces["c"]}
    harness.write_json(ARTIFACTS / "report.json", report)
    return report


def main() -> int:
    report = run_adapter_differential()
    print(f"M6 adapter differential passed: {report['compared_key_count']} keys; {harness.relative(ARTIFACTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
