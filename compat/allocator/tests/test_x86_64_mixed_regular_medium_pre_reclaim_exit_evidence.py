#!/usr/bin/env python3
"""Raw trace and receipt boundaries for mixed medium owner exit."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_mixed_regular_medium_pre_reclaim_exit_evidence.py"
spec = importlib.util.spec_from_file_location("mixed_regular_medium_pre_reclaim_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class MixedRegularMediumPreReclaimExitReceiptTests(unittest.TestCase):
    def report(self):
        trace = dict(evidence.EXPECTED)
        def record(stdout, stderr=""):
            return {"command": ["fixture"], "status": 0, "stdout": stdout, "stderr": stderr}
        return {
            "kind": "pinned-c-native-rust-mixed-regular-medium-pre-reclaim-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": evidence.source_seal(),
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE)],
                  "build": record(""), "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.render_trace(trace) + "\n", "\n"),
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

    def test_rehashed_wrong_os_list_transition_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "os_list_while_arena_reclaimed=1", "os_list_while_arena_reclaimed=0")
        report["c"]["trace"]["os_list_while_arena_reclaimed"] = 0
        report["comparison"]["trace"]["os_list_while_arena_reclaimed"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "os_list_while_arena_reclaimed"):
            evidence.validate_report(report)

    def test_rehashed_wrong_vm_counter_fails(self):
        report = self.report()
        report["rust"]["execution"]["stdout"] = report["rust"]["execution"]["stdout"].replace(
            "os_committed_drop=524288", "os_committed_drop=0")
        report["rust"]["trace"]["os_committed_drop"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "os_committed_drop"):
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
                "arena_purge_after_final=8", "arena_purge_after_final=0")
            report["c"]["trace"]["arena_purge_after_final"] = 0
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(evidence.EvidenceError, "arena_purge_after_final"):
                evidence.read_report(path)


if __name__ == "__main__":
    unittest.main()
