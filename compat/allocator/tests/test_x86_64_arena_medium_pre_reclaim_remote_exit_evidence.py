#!/usr/bin/env python3
"""Raw trace and receipt boundaries for a remote free before OS-page reclaim."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_arena_medium_pre_reclaim_remote_exit_evidence.py"
spec = importlib.util.spec_from_file_location("arena_medium_pre_reclaim_remote_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class ArenaMediumPreReclaimRemoteExitReceiptTests(unittest.TestCase):
    def trace(self):
        return dict(evidence.EXPECTED)

    def c_arena_line(self):
        return evidence.C_ARENA_PREFIX + " ".join(f"{key}={value}" for key, value in evidence.C_ARENA_EXPECTED.items()) + "\n"

    def report(self):
        trace = self.trace()
        record = lambda stdout, stderr="": {"command": ["fixture"], "status": 0, "stdout": stdout, "stderr": stderr}
        return {
            "kind": "pinned-c-native-rust-arena-medium-pre-reclaim-remote-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": evidence.source_seal(),
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE)],
                  "build": record(""), "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.render_trace(trace) + "\n" + self.c_arena_line(), "\n"),
                  "arena_state": dict(evidence.C_ARENA_EXPECTED),
                  "trace": trace},
            "rust": {"command": ["--test", "native_arena_medium_pre_reclaim_remote_exit",
                                 evidence.RUST_FILTER, "native-runtime-test-audit"],
                     "execution": record(evidence.render_trace(trace) +
                                         "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n"),
                     "trace": trace},
            "comparison": {"status": "matched", "values": len(trace), "trace": trace},
        }

    def test_source_arena_page_and_terminal_page_map_trace(self):
        trace = self.trace()
        self.assertEqual(evidence.compare_traces(trace, trace), trace)
        self.assertEqual(evidence.parse_c_arena_state(self.c_arena_line()),
                         dict(evidence.C_ARENA_EXPECTED))

    def test_rehashed_wrong_source_state_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "os_list_empty_after_first_remote=1", "os_list_empty_after_first_remote=0")
        report["c"]["arena_state"]["os_list_empty_after_first_remote"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "source route"):
            evidence.validate_report(report)

    def test_first_remote_must_leave_page_abandoned(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "abandoned_after_first_remote=1", "abandoned_after_first_remote=0")
        report["c"]["trace"]["abandoned_after_first_remote"] = 0
        report["comparison"]["trace"]["abandoned_after_first_remote"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "abandoned_after_first_remote"):
            evidence.validate_report(report)

    def test_rehashed_missing_delayed_purge_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "purge_after_final=8", "purge_after_final=0")
        report["c"]["trace"]["purge_after_final"] = 0
        report["comparison"]["trace"]["purge_after_final"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "purge_after_final"):
            evidence.validate_report(report)

    def test_unexpected_loader_warning_fails(self):
        report = self.report()
        report["c"]["execution"]["stderr"] = "allocator warning\n"
        with self.assertRaisesRegex(evidence.EvidenceError, "loader-init stderr"):
            evidence.validate_report(report)

    def test_changed_production_source_seal_fails(self):
        report = self.report()
        report["probe"]["single_thread_sha256"] = "0" * 64
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
            self.assertEqual(evidence.read_report(path), self.trace())
            report["rust"]["execution"]["stdout"] = report["rust"]["execution"]["stdout"].replace(
                "terminal_map_clear=1", "terminal_map_clear=0")
            report["rust"]["trace"]["terminal_map_clear"] = 0
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(evidence.EvidenceError, "terminal_map_clear"):
                evidence.read_report(path)


if __name__ == "__main__":
    unittest.main()
