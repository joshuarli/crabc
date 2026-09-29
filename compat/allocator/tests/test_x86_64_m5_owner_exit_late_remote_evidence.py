#!/usr/bin/env python3
"""Physical receipt checks for two remote producers around owner exit."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_m5_owner_exit_late_remote_evidence.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("owner_exit_late_remote_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


def marked(trace):
    return "\n".join((evidence.BEGIN, *(f"{key}={value}" for key, value in trace.items()), evidence.END))


def record(command, stdout="", stderr=""):
    return {"command": command, "status": 0, "stdout": stdout, "stderr": stderr}


class TwoPublisherReceiptTests(unittest.TestCase):
    def setUp(self):
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "report.json"

    def report(self):
        pin = evidence.run.load_pin()
        c_trace = dict(evidence.EXPECTED_C)
        rust_trace = dict(evidence.EXPECTED_RUST)
        return {
            "kind": "pinned-c-native-rust-m5-owner-exit-late-remote", "status": "matched",
            "source": {"revision": pin["revision"], "archive_sha256": pin["sha256"],
                       "c_probe_sha256": evidence.run.sha256_file(evidence.C_PROBE),
                       "rust_probe_sha256": evidence.run.sha256_file(evidence.RUST_PROBE),
                       "lockfile_sha256": evidence.run.sha256_file(ROOT / "Cargo.lock")},
            "c": {"build": record(["musl-gcc", str(evidence.C_PROBE)]),
                  "execution": record(["source-oracle"], marked(c_trace)),
                  "elf": evidence.EXPECTED_C_ELF, "trace": c_trace},
            "rust": {"build": record(["cargo", "build", "--manifest-path", "fixture/Cargo.toml"]),
                     "execution": record(["fixture"], marked(rust_trace)),
                     "elf": evidence.EXPECTED_C_ELF, "trace": rust_trace,
                     "manifest": evidence.RUST_MANIFEST},
            "comparison": evidence.compare(c_trace, rust_trace),
        }

    def read(self, report):
        self.path.write_text(json.dumps(report))
        return evidence.read_report(self.path)

    def test_full_raw_receipt_keeps_common_and_c_internal_observations(self):
        comparison = self.read(self.report())
        self.assertEqual(comparison["shared_values"], len(evidence.EXPECTED_RUST))
        self.assertEqual(comparison["c_only"], evidence.C_ONLY)

    def test_c_owner_exit_accounting_tamper_is_rejected(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "used_after_exit=2", "used_after_exit=3")
        report["c"]["trace"]["used_after_exit"] = 3
        with self.assertRaisesRegex(evidence.EvidenceError, "pinned C source trace differs"):
            self.read(report)

    def test_rust_post_exit_page_map_tamper_is_rejected(self):
        report = self.report()
        report["rust"]["execution"]["stdout"] = report["rust"]["execution"]["stdout"].replace(
            "registered_after_exit=1", "registered_after_exit=0")
        report["rust"]["trace"]["registered_after_exit"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "native Rust trace differs"):
            self.read(report)

    def test_runtime_warning_is_not_dropped(self):
        report = self.report()
        report["c"]["execution"]["stderr"] = "allocator warning\n"
        with self.assertRaisesRegex(evidence.EvidenceError, "source warning"):
            self.read(report)


if __name__ == "__main__":
    unittest.main()
