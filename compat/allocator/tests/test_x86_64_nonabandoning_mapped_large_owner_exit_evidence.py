#!/usr/bin/env python3
"""Source-bound trace and reread contract for mapped-large owner exit."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_nonabandoning_mapped_large_owner_exit_evidence.py"
spec = importlib.util.spec_from_file_location("mapped_large_owner_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class TraceContractTests(unittest.TestCase):
    def report(self):
        trace = dict(evidence.EXPECTED_TRACE)
        trace.update({"large_reserved": 25, "medium_reserved": 6,
                      "large_registered_slice_count": 63, "medium_registered_slice_count": 8})
        record = lambda stdout: {"command": ["fixture"], "status": 0, "stdout": stdout, "stderr": ""}
        source_state = {"large_mapped": 1, "medium_mapped": 1,
                        "large_unowned": 1, "medium_unowned": 1}
        return {
            "kind": "pinned-c-native-rust-nonabandoning-mapped-large-owner-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": {"path": evidence.base.relative(evidence.PROBE),
                      "sha256": evidence.base.sha256_file(evidence.PROBE),
                      "rust_source": evidence.base.relative(evidence.RUST_SOURCE),
                      "rust_sha256": evidence.base.sha256_file(evidence.RUST_SOURCE),
                      "runtime_source": evidence.base.relative(evidence.RUNTIME_SOURCE),
                      "runtime_sha256": evidence.base.sha256_file(evidence.RUNTIME_SOURCE),
                      "lib_source": evidence.base.relative(evidence.LIB_SOURCE),
                      "lib_sha256": evidence.base.sha256_file(evidence.LIB_SOURCE),
                      "lockfile_sha256": evidence.base.sha256_file(ROOT / "Cargo.lock")},
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE)],
                  "build": record(""), "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.C_SOURCE_STATE + evidence.C_LARGE_FIRST_FREE +
                                      evidence.C_FINAL_STATE +
                                      evidence.render_trace(trace)),
                  "source_state": source_state,
                  "large_first_free": {"mapped": 1, "unowned": 1, "used": 1},
                  "final_state": evidence.parse_c_final_state(evidence.C_FINAL_STATE),
                  "trace": trace},
            "rust": {"command": [evidence.RUST_FILTER, "native-runtime-test-audit"],
                     "execution": record(evidence.render_trace(trace) +
                                         "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n"),
                     "trace": trace},
            "comparison": {"status": "matched", "values": len(trace), "trace": trace},
        }

    def test_source_mapped_state_and_matched_regular_page_trace(self):
        trace = dict(evidence.EXPECTED_TRACE)
        trace.update({"large_reserved": 25, "medium_reserved": 6,
                      "large_registered_slice_count": 63, "medium_registered_slice_count": 8})
        c = evidence.parse_trace(evidence.C_SOURCE_STATE + evidence.C_LARGE_FIRST_FREE +
                                 evidence.C_FINAL_STATE +
                                 evidence.render_trace(trace), "C")
        rust = evidence.parse_trace(evidence.render_trace(trace), "Rust")
        self.assertEqual(evidence.compare_traces(c, rust), trace)
        self.assertEqual(evidence.parse_c_source_state(evidence.C_SOURCE_STATE),
                         {"large_mapped": 1, "medium_mapped": 1,
                          "large_unowned": 1, "medium_unowned": 1})
        self.assertEqual(evidence.parse_c_large_first_free(evidence.C_LARGE_FIRST_FREE),
                         {"mapped": 1, "unowned": 1, "used": 1})
        self.assertEqual(evidence.parse_c_final_state(evidence.C_FINAL_STATE)["medium_expire"], 4)

    def test_missing_page_and_wrong_source_mapping_fail(self):
        trace = dict(evidence.EXPECTED_TRACE)
        trace.update({"large_reserved": 25, "medium_reserved": 6,
                      "large_registered_slice_count": 63, "medium_registered_slice_count": 8})
        trace.pop("large_registered_after_exit")
        with self.assertRaisesRegex(evidence.EvidenceError, "missing"):
            evidence.parse_trace(evidence.render_trace(trace), "C")
        with self.assertRaisesRegex(evidence.EvidenceError, "large_mapped"):
            evidence.parse_c_source_state(evidence.C_SOURCE_STATE.replace("large_mapped=1", "large_mapped=0"))

    def test_missing_or_tampered_report_fails(self):
        work_root = ROOT / ".work"
        work_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work_root) as temporary:
            path = Path(temporary) / "report.json"
            with self.assertRaisesRegex(evidence.EvidenceError, "cannot read"):
                evidence.read_report(path)
            report = self.report()
            path.write_text(json.dumps(report))
            self.assertEqual(evidence.read_report(path), report["comparison"]["trace"])
            report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
                "large_mapped=1", "large_mapped=0")
            report["c"]["source_state"]["large_mapped"] = 0
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(evidence.EvidenceError, "large_mapped"):
                evidence.read_report(path)


if __name__ == "__main__":
    unittest.main()
