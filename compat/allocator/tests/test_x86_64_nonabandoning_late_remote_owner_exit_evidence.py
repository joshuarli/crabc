#!/usr/bin/env python3
"""Observable trace and retained-report contract for late remote owner exit."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_nonabandoning_late_remote_owner_exit_evidence.py"
spec = importlib.util.spec_from_file_location("late_remote_owner_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class TraceContractTests(unittest.TestCase):
    def report(self):
        trace = dict(evidence.EXPECTED_TRACE)
        record = lambda stdout: {"command": ["fixture"], "status": 0, "stdout": stdout, "stderr": ""}
        return {
            "kind": "pinned-c-native-rust-nonabandoning-late-remote-owner-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": {"path": evidence.base.relative(evidence.PROBE),
                      "sha256": evidence.base.sha256_file(evidence.PROBE),
                      "rust_source": evidence.base.relative(evidence.RUST_SOURCE),
                      "rust_sha256": evidence.base.sha256_file(evidence.RUST_SOURCE),
                      "lockfile_sha256": evidence.base.sha256_file(ROOT / "Cargo.lock")},
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE)], "build": record(""),
                  "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.render_trace(trace)), "trace": trace},
            "rust": {"command": [evidence.RUST_FILTER],
                     "execution": record(evidence.render_trace(trace) +
                                         "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n"),
                     "trace": trace},
            "comparison": {"status": "matched", "values": len(trace), "trace": trace},
        }

    def test_complete_late_remote_lifecycle(self):
        trace = dict(evidence.EXPECTED_TRACE)
        c = evidence.parse_trace(evidence.render_trace(trace), "C")
        rust = evidence.parse_trace(evidence.render_trace(trace), "Rust")
        self.assertEqual(evidence.compare_traces(c, rust), trace)

    def test_missing_abandoned_state_fails(self):
        trace = dict(evidence.EXPECTED_TRACE)
        trace.pop("medium_abandoned_after_exit")
        with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
            evidence.parse_trace(evidence.render_trace(trace), "C")

    def test_wrong_late_reclaim_fails(self):
        trace = dict(evidence.EXPECTED_TRACE)
        trace["medium_reclaimed_after_late_free"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "medium_reclaimed_after_late_free"):
            evidence.compare_traces(evidence.EXPECTED_TRACE, trace)

    def test_reader_rejects_missing_and_semantically_tampered_raw_report(self):
        work_root = ROOT / ".work"
        work_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work_root) as temporary:
            path = Path(temporary) / "report.json"
            with self.assertRaisesRegex(evidence.EvidenceError, "cannot read"):
                evidence.read_report(path)
            report = self.report()
            path.write_text(json.dumps(report))
            self.assertEqual(evidence.read_report(path), evidence.EXPECTED_TRACE)
            report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
                "medium_abandoned_after_exit=1", "medium_abandoned_after_exit=0")
            report["c"]["trace"]["medium_abandoned_after_exit"] = 0
            report["comparison"]["trace"]["medium_abandoned_after_exit"] = 0
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(evidence.EvidenceError, "medium_abandoned_after_exit"):
                evidence.read_report(path)


if __name__ == "__main__":
    unittest.main()
