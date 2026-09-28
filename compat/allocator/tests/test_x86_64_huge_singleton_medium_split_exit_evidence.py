#!/usr/bin/env python3
"""Raw trace and receipt boundaries for huge singleton and medium owner exit."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_huge_singleton_medium_split_exit_evidence.py"
spec = importlib.util.spec_from_file_location("huge_singleton_medium_split_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class HugeSingletonMediumSplitExitReceiptTests(unittest.TestCase):
    def report(self):
        trace = dict(evidence.EXPECTED)
        def record(stdout, stderr=""):
            return {"command": ["fixture"], "status": 0, "stdout": stdout, "stderr": stderr}
        return {
            "kind": "pinned-c-native-rust-huge-singleton-medium-split-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": evidence.source_seal(),
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE)],
                  "build": record(""), "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.render_trace(trace) + "\nCRABC_MI_C_HUGE_SOURCE_STATE medium_retire_expire=4\n", "\n"),
                  "trace": dict(trace)},
            "rust": {"command": ["--test", evidence.RUST_TEST, evidence.RUST_FILTER,
                                  "native-runtime-test-audit,native-runtime-test-fault"],
                     "execution": record(evidence.render_trace(trace) +
                                         "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n"),
                     "trace": dict(trace)},
            "comparison": {"status": "matched", "values": len(trace), "trace": dict(trace)},
        }

    def test_source_trace_binds_both_release_routes(self):
        report = self.report()
        self.assertEqual(evidence.validate_report(report), evidence.EXPECTED)

    def test_wrong_clipped_page_map_span_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "huge_map_count=63", "huge_map_count=84")
        report["c"]["trace"]["huge_map_count"] = 84
        report["comparison"]["trace"]["huge_map_count"] = 84
        with self.assertRaisesRegex(evidence.EvidenceError, "huge_map_count"):
            evidence.validate_report(report)

    def test_rehashed_wrong_vm_counter_fails(self):
        report = self.report()
        report["rust"]["execution"]["stdout"] = report["rust"]["execution"]["stdout"].replace(
            "huge_purge_after_release=84", "huge_purge_after_release=0")
        report["rust"]["trace"]["huge_purge_after_release"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "huge_purge_after_release"):
            evidence.validate_report(report)

    def test_wrong_source_retirement_countdown_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "medium_retire_expire=4", "medium_retire_expire=0")
        with self.assertRaisesRegex(evidence.EvidenceError, "retirement countdown"):
            evidence.validate_report(report)

    def test_omitted_release_transition_fails(self):
        report = self.report()
        report["rust"]["execution"]["stdout"] = report["rust"]["execution"]["stdout"].replace(
            "medium_final_release=1\n", "")
        with self.assertRaisesRegex(evidence.EvidenceError, "missing or unexpected values"):
            evidence.validate_report(report)

    def test_unexpected_source_warning_fails(self):
        report = self.report()
        report["c"]["execution"]["stderr"] = "mimalloc: warning: release failed\n"
        with self.assertRaisesRegex(evidence.EvidenceError, "warning differs"):
            evidence.validate_report(report)

    def test_unexpected_native_warning_fails(self):
        report = self.report()
        report["rust"]["execution"]["stderr"] = "mimalloc: warning: release failed\n"
        with self.assertRaisesRegex(evidence.EvidenceError, "allocator warning differs"):
            evidence.validate_report(report)

    def test_changed_source_seal_fails(self):
        report = self.report()
        report["probe"]["options_sha256"] = "0" * 64
        with self.assertRaisesRegex(evidence.EvidenceError, "source seal"):
            evidence.validate_report(report)

    def test_missing_and_tampered_receipts_fail(self):
        work_root = ROOT / ".work"
        work_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work_root) as temporary:
            path = Path(temporary) / "report.json"
            with self.assertRaisesRegex(evidence.EvidenceError, "cannot read"):
                evidence.read_report(path)
            report = self.report()
            path.write_text(json.dumps(report))
            self.assertEqual(evidence.read_report(path), evidence.EXPECTED)
            report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
                "medium_retained_before_collect=1", "medium_retained_before_collect=0")
            report["c"]["trace"]["medium_retained_before_collect"] = 0
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(evidence.EvidenceError, "medium_retained_before_collect"):
                evidence.read_report(path)


if __name__ == "__main__":
    unittest.main()
