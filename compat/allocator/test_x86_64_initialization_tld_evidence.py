#!/usr/bin/env python3
"""Host regressions for the fixed native x86 initialization TLD receipt."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from x86_64_initialization_tld_evidence import (  # type: ignore[import-not-found]
    BRANCH_C_ORACLE_SOURCES,
    BRANCH_C_PROBE_NAMES,
    BRANCH_C_SOURCE_FILE_RECORDS,
    BRANCH_RUST_SOURCES,
    BRANCH_TARGETS,
    EvidenceError,
    INITIALIZATION_TLD_BRANCH_IDS,
    NORMALIZED_EVIDENCE_ROOT,
    NORMALIZED_PINNED_SOURCE,
    TARGET,
    branch_c_fixture,
    branch_trace_keys,
    load_fragment,
    sha256_bytes,
    validate_c_probe,
    validate_initialization_tld_branch_rows,
    validate_rust_probe,
)


class InitializationTldMatrixReaderTests(unittest.TestCase):
    @staticmethod
    def branch_rows() -> list[dict]:
        return [
            {
                "id": branch_id,
                "comparison": {
                    "compared_value_count": len(branch_trace_keys(branch_id)),
                    "status": "matched",
                },
                "c_trace": {key: 1 for key in branch_trace_keys(branch_id)},
                "rust_trace": {key: 1 for key in branch_trace_keys(branch_id)},
            }
            for branch_id in INITIALIZATION_TLD_BRANCH_IDS
        ]

    def test_branch_rows_have_the_complete_fixed_schemas(self) -> None:
        validate_initialization_tld_branch_rows(self.branch_rows())

    def test_branch_rows_reject_missing_renamed_added_or_unmet_relations(self) -> None:
        rows = self.branch_rows()
        key = branch_trace_keys(INITIALIZATION_TLD_BRANCH_IDS[0])[0]
        missing = copy.deepcopy(rows)
        del missing[0]["c_trace"][key]
        renamed = copy.deepcopy(rows)
        renamed[0]["rust_trace"]["m2.initialization.invented_relation"] = renamed[0]["rust_trace"].pop(key)
        added = copy.deepcopy(rows)
        added[0]["c_trace"]["m2.initialization.forbidden_extra_relation"] = 1
        unmet = copy.deepcopy(rows)
        unmet[0]["rust_trace"][key] = 0
        for malformed in (missing, renamed, added, unmet):
            with self.subTest(rows=malformed), self.assertRaises(EvidenceError):
                validate_initialization_tld_branch_rows(malformed)

    @staticmethod
    def c_probe(branch_id: str) -> dict:
        index = INITIALIZATION_TLD_BRANCH_IDS.index(branch_id)
        probe = BRANCH_C_PROBE_NAMES[index]
        fixture = branch_c_fixture(branch_id).encode("utf-8")
        return {
            "branch": branch_id,
            "command": [
                "musl-gcc", "-std=c11", "-fPIC", "-ftls-model=initial-exec",
                "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
                "-O3", "-DNDEBUG", "-DMI_BUILD_RELEASE=1", "-DMI_DEBUG=0", "-DMI_STAT=0", "-DMI_SECURE=0", "-DMI_GUARDED=0",
                f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe}.c",
                *(f"{NORMALIZED_PINNED_SOURCE}/{source}" for source in BRANCH_C_ORACLE_SOURCES[index]),
                "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe}",
            ],
            "compiled_source_closure": {
                "direct_fixture_includes": ["src/init.c"],
                "translation_units": list(BRANCH_C_ORACLE_SOURCES[index]),
            },
            "fixture": {
                "bytes": len(fixture),
                "path": f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe}.c",
                "sha256": sha256_bytes(fixture),
            },
            "source_files": [dict(record) for record in BRANCH_C_SOURCE_FILE_RECORDS[index]],
        }

    @staticmethod
    def rust_probe(branch_id: str) -> dict:
        index = INITIALIZATION_TLD_BRANCH_IDS.index(branch_id)
        return {
            "branch": branch_id,
            "command": [
                "cargo", "test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
                "-p", "crabc-mimalloc", "--lib", "--no-default-features", BRANCH_TARGETS[index],
                "--", "--exact", "--nocapture", "--test-threads=1",
            ],
            "passed_test_count": 1,
            "source": {
                "path": BRANCH_RUST_SOURCES[index],
                "sha256": hashlib.sha256(
                    (Path(__file__).resolve().parents[2] / BRANCH_RUST_SOURCES[index]).read_bytes()
                ).hexdigest(),
            },
        }

    def test_c_and_rust_provenance_rejects_changed_closure_architecture_or_filter(self) -> None:
        branch = INITIALIZATION_TLD_BRANCH_IDS[1]
        c_probe = self.c_probe(branch)
        rust_probe = self.rust_probe(branch)
        validate_c_probe(branch, c_probe)
        validate_rust_probe(branch, rust_probe)
        wrong_source_closure = copy.deepcopy(c_probe)
        wrong_source_closure["compiled_source_closure"]["translation_units"].pop()
        wrong_fixture = copy.deepcopy(c_probe)
        wrong_fixture["fixture"]["sha256"] = "b" * 64
        wrong_architecture = copy.deepcopy(rust_probe)
        wrong_architecture["command"][4] = "aarch64-unknown-linux-musl"
        wrong_filter = copy.deepcopy(rust_probe)
        wrong_filter["command"][11] = "types::tests::emit_m2_detached_tld_static_preimage_c_rust_trace"
        for validator, malformed in (
            (validate_c_probe, wrong_source_closure),
            (validate_c_probe, wrong_fixture),
            (validate_rust_probe, wrong_architecture),
            (validate_rust_probe, wrong_filter),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(EvidenceError):
                validator(branch, malformed)


class InitializationM2FragmentReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fragment_path = Path(__file__).with_name(
            "m2-initialization-x86_64-v3.5.0.fragment.json"
        )
        self.scratch = Path(__file__).resolve().parents[2] / ".work/allocator-x86_64/test-initialization-tld"
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=self.scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fragment = json.loads(self.fragment_path.read_text(encoding="utf-8"))

    def write_fragment(self, fragment: dict) -> Path:
        path = Path(self.temporary.name) / "fragment.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        return path

    def test_fragment_has_only_the_fixed_direct_tld_matrix(self) -> None:
        loaded = load_fragment(self.write_fragment(self.fragment))
        self.assertEqual(
            [branch["id"] for branch in loaded["component"]["branch_matrix"]],
            list(INITIALIZATION_TLD_BRANCH_IDS),
        )
        self.assertEqual(
            [check["expected_passed_test_count"] for check in loaded["component"]["checks"]],
            [3, 1],
        )

    def test_fragment_rejects_changed_anchor_or_missing_direct_branch(self) -> None:
        altered_anchor = copy.deepcopy(self.fragment)
        altered_anchor["component"]["bounded_source_definitions"][0]["source_anchor"]["end_line"] = 193
        missing_branch = copy.deepcopy(self.fragment)
        del missing_branch["component"]["branch_matrix"][-1]
        altered_branch_anchor = copy.deepcopy(self.fragment)
        altered_branch_anchor["component"]["branch_matrix"][0]["source_anchors"][0]["end_line"] = 191
        for malformed in (altered_anchor, missing_branch, altered_branch_anchor):
            with self.subTest(fragment=malformed), self.assertRaises(EvidenceError):
                load_fragment(self.write_fragment(malformed))


if __name__ == "__main__":
    unittest.main()
