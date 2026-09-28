#!/usr/bin/env python3
"""Raw trace and receipt boundaries for arena-singleton regular owner exit."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_arena_singleton_regular_owner_exit_evidence.py"
spec = importlib.util.spec_from_file_location("arena_singleton_regular_owner_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class ArenaSingletonRegularExitReceiptTests(unittest.TestCase):
    def trace(self):
        return {**evidence.EXPECTED, "regular_reserved": 8}

    def c_arena_line(self):
        return evidence.C_ARENA_PREFIX + " ".join(f"{key}=1" for key in evidence.C_ARENA_KEYS) + "\n"

    def report(self):
        trace = self.trace()
        record = lambda stdout: {"command": ["fixture"], "status": 0, "stdout": stdout, "stderr": ""}
        return {
            "kind": "pinned-c-native-rust-arena-singleton-regular-owner-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": evidence.source_seal(),
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE)],
                  "build": record(""), "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.render_trace(trace) + "\n" + self.c_arena_line()),
                  "arena_transitions": {key: 1 for key in evidence.C_ARENA_KEYS},
                  "trace": trace},
            "rust": {"command": [evidence.RUST_FILTER, "native-runtime-test-audit"],
                     "execution": record(evidence.render_trace(trace) +
                                         "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n"),
                     "trace": trace},
            "comparison": {"status": "matched", "values": len(trace), "trace": trace},
        }

    def test_source_arena_and_shared_page_map_trace(self):
        trace = self.trace()
        self.assertEqual(evidence.compare_traces(trace, trace), trace)
        self.assertEqual(evidence.parse_c_arena(self.c_arena_line()),
                         {key: 1 for key in evidence.C_ARENA_KEYS})

    def test_rehashed_wrong_arena_transition_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "singleton_arena_clear=1", "singleton_arena_clear=0")
        report["c"]["arena_transitions"]["singleton_arena_clear"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "source route"):
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
                "regular_map_clear=1", "regular_map_clear=0")
            report["rust"]["trace"]["regular_map_clear"] = 0
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(evidence.EvidenceError, "regular_map_clear"):
                evidence.read_report(path)


if __name__ == "__main__":
    unittest.main()
