#!/usr/bin/env python3
"""Compare pinned C and Rust chunk-bin owner merge and reset transitions."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import run as harness
from x86_64_m7_gate import c_oracle_trace, parse_options_trace, rust_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_chunk_bin_merge_oracle.c"
RUST_SOURCE = harness.ROOT / "crabc-mimalloc/src/statistics.rs"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-statistics-chunk-bin-merge/profile.json"
BEGIN = "CRABC_MI_M7_STATISTICS_CHUNK_BIN_MERGE_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_CHUNK_BIN_MERGE_TRACE_END"


def expected_trace() -> dict[str, str]:
    zero = (0, 0, 0)
    values = {
        "empty": {},
        "first.process": {0: (3, 3, 3), 4: (2, 2, 2), 5: (7, 7, 7)},
        "first.source_reset": {},
        "second.process": {0: (8, 8, 6), 4: (2, 2, 1), 5: (7, 7, 5)},
        "second.source_reset": {},
    }
    return {
        f"{stage}.bin{index}": ",".join(str(value) for value in bins.get(index, zero))
        for stage, bins in values.items()
        for index in range(6)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    with harness.temporary_directory("crabc-m7-statistics-chunk-bin-merge-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_execution = c_oracle_trace(
            FIXTURE, "statistics-chunk-bin-merge", source, temporary,
            compile_defines=("-DMI_STAT=2",),
        )
    rust_execution = rust_trace(
        "statistics::tests::chunk_bin_owner_merge_trace_for_pinned_c_comparison",
        "statistics-chunk-bin-merge", rust_features=("mi-stat-2",),
    )
    traces = {
        "c": parse_options_trace(str(c_execution["stdout"]), "pinned C", BEGIN, END),
        "rust": parse_options_trace(str(rust_execution["stdout"]), "Rust", BEGIN, END),
    }
    expected = expected_trace()
    mismatch = sorted(key for key in expected
                      if traces["c"].get(key) != traces["rust"].get(key))
    report = {
        "status": "passed" if traces["c"] == expected and traces["rust"] == expected else "failed",
        "pin": {key: pin[key] for key in ("revision", "sha256")},
        "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
        "rust_source_sha256": hashlib.sha256(RUST_SOURCE.read_bytes()).hexdigest(),
        "c_command": c_execution["command"],
        "rust_command": rust_execution["command"],
        "c_trace": traces["c"],
        "rust_trace": traces["rust"],
        "mismatch_keys": mismatch,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    if report["status"] != "passed":
        raise harness.HarnessError(f"chunk-bin merge differs from pinned source; see {REPORT}")
    print(f"M7 chunk-bin owner merge matched pinned C: {len(expected)} fields; {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
