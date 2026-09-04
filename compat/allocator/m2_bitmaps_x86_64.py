#!/usr/bin/env python3
"""Native x86 M2 scalar bitmap component producer, for the aggregate M2 gate.

The producer owns no milestone state. It runs the complete bitmap unit module
and compares an ordered C/Rust transcript against freshly extracted pinned
source. The aggregate owns clean-revision attestation and component promotion.
All build/cache/report/temporary paths come from the canonical allocator
runner's contained native environment.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "m2.bitmap.native."
EXPECTED_OBSERVATION_COUNT = 132184
EXPECTED_RUST_TEST_COUNT = 41
SOURCE_FILES = (
    "src/bitmap.c", "src/bitmap.h", "include/mimalloc/internal.h",
    "include/mimalloc/atomic.h", "include/mimalloc/bits.h",
    "include/mimalloc/types.h", "include/mimalloc-stats.h", "src/stats.c",
    "src/prim/prim.c", "src/prim/unix/prim.c",
)


def transcript(output: str) -> list[int]:
    """Reject missing/repeated/reordered numbered observations."""
    matches = re.findall(r"m2\.bitmap\.native\.(\d+)=(\d+)(?=\r?$)", output, re.MULTILINE)
    if (not matches or output.count(PREFIX) != len(matches)
            or [int(index) for index, _ in matches] != list(range(len(matches)))
            or any(int(value) > (1 << 64) - 1 for _, value in matches)):
        raise ValueError("native bitmap transcript is empty or its observation order changed")
    return [int(value) for _, value in matches]


def run_evidence(harness, *, offline: bool) -> dict:
    """Run inside the pinned native allocator image; do not infer M2 closure."""
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m2-bitmaps"
    artifacts.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).with_suffix(".c")
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="m2-native-bitmaps-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        command = [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
                   "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
                   "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-DMI_OPT_SIMD=0",
                   "-I", str(source / "include"), "-I", str(source / "src"),
                   *harness.CONFIGURATION_PROFILES["release"],
                   "-ffunction-sections", "-fdata-sections", str(fixture), str(source / "src/stats.c"),
                   str(source / "src/prim/prim.c"),
                   "-Wl,--gc-sections", "-pthread", "-o", str(artifacts / "oracle")]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "native bitmap source oracle build")
        c_run = harness.command_record([str(artifacts / "oracle")], cwd=source,
                                       timeout_seconds=180)
        harness.require_success(c_run, "native bitmap source oracle")
        sources = harness.source_file_records(source, SOURCE_FILES)

    program = harness._m1_foundations_test_program(
        {"package": "crabc-mimalloc", "features": [], "no_default_features": True,
         "rust_target": "x86_64-unknown-linux-musl", "test_threads": 1,
         "timeout_seconds": 600}, harness.WORK_ROOT / "target")
    listed = harness.command_record([str(program["path"]), "bitmap::", "--list"],
                                    cwd=ROOT, timeout_seconds=30)
    harness.require_success(listed, "native bitmap test inventory")
    test_names = [line.removesuffix(": test") for line in str(listed["stdout"]).splitlines()
                  if line.endswith(": test")]
    if (len(test_names) != EXPECTED_RUST_TEST_COUNT or len(set(test_names)) != len(test_names)
            or any(not name.startswith("bitmap::") for name in test_names)):
        raise harness.HarnessError("native bitmap test inventory changed")
    rust_command = [str(program["path"]), "bitmap::", "--test-threads=1", "--nocapture"]
    rust_run = harness.command_record(rust_command, cwd=ROOT, timeout_seconds=300)
    harness.require_success(rust_run, "native bitmap unit and invariant suite")
    output = str(rust_run["stdout"]) + "\n" + str(rust_run["stderr"])
    if harness.parse_rust_test_count(output) != len(test_names):
        raise harness.HarnessError("native bitmap test inventory did not all pass")
    expected, observed = transcript(str(c_run["stdout"])), transcript(output)
    if len(expected) != EXPECTED_OBSERVATION_COUNT:
        raise harness.HarnessError("native bitmap source observation inventory changed")
    if expected != observed:
        index = next((i for i, pair in enumerate(zip(expected, observed))
                      if pair[0] != pair[1]), min(len(expected), len(observed)))
        raise harness.HarnessError(
            f"native bitmap differential mismatch at observation {index}: "
            f"C={expected[index:index+1]}, Rust={observed[index:index+1]} "
            f"(counts {len(expected)}/{len(observed)})")
    payload = "\n".join(str(value) for value in expected).encode()
    report = {
        "schema": "crabc-mimalloc-x86_64-m2-bitmaps-evidence", "format": 1,
        "status": "passed", "architecture": "x86_64", "profile": "scalar-release-stat0",
        "upstream": {"revision": pin["revision"], "archive_sha256": pin["sha256"]},
        "c_source_files": sources, "c_command": command,
        "fixture": harness.artifact_record(fixture),
        "rust_build_command": program["build_command"], "rust_command": rust_command,
        "rust_tests": test_names, "rust_passed_test_count": len(test_names),
        "compared_value_count": len(expected),
        "transcript_sha256": hashlib.sha256(payload).hexdigest(),
        "nonclaims": ["Full mi_stats_t ABI/reporting and optional SIMD/modes are not qualified",
                      "No Heap/Page/Arena ownership, lifecycle, or full M2 claim"],
    }
    evidence_path = artifacts / "evidence.json"
    harness.write_json(evidence_path, report)
    evidence_path.chmod(0o644)
    return report


def main() -> int:
    spec = importlib.util.spec_from_file_location("allocator_bitmap_runner", ROOT / "compat/allocator/run.py")
    assert spec is not None and spec.loader is not None
    harness = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = harness
    spec.loader.exec_module(harness)
    print(json.dumps(run_evidence(harness, offline=True), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
