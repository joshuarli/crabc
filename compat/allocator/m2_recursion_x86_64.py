#!/usr/bin/env python3
"""Pinned C/Rust recursive diagnostic-output evidence for native x86-64 M2.

The allocator-recursion component's `recursive-diagnostic-output` row is the
pinned `src/options.c` `_mi_fputs`/`mi_vfprintf`/`_mi_warning_message` reentry
from an output callback. M7's options oracle
(`x86_64_m7_options_oracle.c`) drives it through three recursive-callback
scenarios (`invalid_verbose`, `show_errors`, `capped`) beside the option and
error scenarios; `diagnostic_output::tests::source_options_trace_for_pinned_c_comparison`
emits the same keyed trace. This producer reuses M7's parser and
completeness/equality rules against the aggregate M2 gate's prebuilt test
binary, so M2 records the same comparison M7 qualifies without rebuilding.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Mapping


CHECK_ID = "recursive-diagnostic-output-c-rust-differential"
TARGET = "diagnostic_output::tests::source_options_trace_for_pinned_c_comparison"


def _m7_gate(harness: Any) -> Any:
    path = harness.ALLOCATOR_ROOT / "x86_64_m7_gate.py"
    spec = importlib.util.spec_from_file_location("crabc_m2_recursion_m7_gate", path)
    if spec is None or spec.loader is None:
        raise harness.HarnessError("native x86 M7 options differential is absent")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_evidence(
    harness: Any, *, offline: bool, test_program: Mapping[str, Any], check: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare the pinned C options oracle with the prebuilt Rust trace."""

    harness.require_native_x86_64()
    if check.get("id") != CHECK_ID or check.get("target") != TARGET:
        raise harness.HarnessError("native x86 recursive-output check changed")
    gate = _m7_gate(harness)
    if gate.OPTIONS_RUST_TEST != TARGET:
        raise harness.HarnessError("native x86 recursive-output target no longer names M7's options trace")
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m2-recursion-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_execution = gate.c_oracle_trace(gate.OPTIONS_ORACLE, "options", source, temporary)
    rust, rust_output = harness._x86_64_run_exact_program_check(
        test_program, check, nocapture=True, gate_name="native x86 M2 recursive output",
    )
    c_trace = gate.parse_options_trace(
        str(c_execution["stdout"]), "pinned C options trace",
        gate.OPTIONS_TRACE_BEGIN, gate.OPTIONS_TRACE_END,
    )
    rust_trace = gate.parse_options_trace(
        rust_output, "Rust options trace", gate.OPTIONS_TRACE_BEGIN, gate.OPTIONS_TRACE_END,
    )
    gate.require_complete_options_trace(c_trace, "pinned C options trace")
    gate.require_complete_options_trace(rust_trace, "Rust options trace")
    gate.compare_options_traces(c_trace, rust_trace)
    recursion_keys = sorted(key for key in c_trace if key.startswith("recursion."))
    evidence = {
        "c_command": c_execution["command"],
        "comparison": {"compared_value_count": len(c_trace), "status": "matched"},
        "recursion_key_count": len(recursion_keys),
        "recursion_scenarios": list(gate.OPTIONS_RECURSION_SCENARIOS),
        "rust_command": rust["command"],
        "rust_passed_test_count": rust["passed_test_count"],
        "status": "passed",
    }
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-recursive-output"
    artifacts.mkdir(parents=True, exist_ok=True)
    harness.write_json(artifacts / "evidence.json", evidence)
    return evidence
