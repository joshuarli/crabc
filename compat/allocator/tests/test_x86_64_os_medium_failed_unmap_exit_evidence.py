#!/usr/bin/env python3
"""Raw failed-unmap warning, range, counter, and receipt boundaries."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_os_medium_failed_unmap_exit_evidence.py"
spec = importlib.util.spec_from_file_location("os_medium_failed_unmap_exit_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class OsMediumFailedUnmapExitReceiptTests(unittest.TestCase):
    def trace(self):
        return dict(evidence.EXPECTED)

    def c_os_line(self):
        return evidence.C_OS_PREFIX + " ".join(
            f"{key}={value}" for key, value in evidence.C_OS_EXPECTED.items()) + "\n"

    def range_line(self):
        return evidence.RANGE_PREFIX + "base=0x100000 length=589824\n"

    def c_warning(self):
        return ("warning[0]=mimalloc: warning: thread 0x1000: \n"
                "warning[1]=unable to free OS memory (error: 12 (0x0C), "
                "size: 0x90000 bytes, address: 0x100000)\n")

    def rust_warning(self):
        return ("mimalloc: warning: thread 0x1000: unable to free OS memory "
                "(error: 12 (0x0C), size: 0x90000 bytes, address: 0x100000)\n")

    def report(self):
        trace = self.trace()
        record = lambda stdout, stderr="": {"command": ["fixture"], "status": 0,
                                             "stdout": stdout, "stderr": stderr}
        return {
            "kind": "pinned-c-native-rust-os-medium-failed-unmap-exit",
            "status": "matched",
            "source": {"archive_sha256": evidence.base.EXPECTED_ARCHIVE_SHA256,
                       "revision": evidence.run.load_pin()["revision"],
                       "anchors": [{"member": member, "first": first, "last": last, "sha256": digest}
                                   for member, first, last, digest in evidence.SOURCE_ANCHORS]},
            "probe": evidence.source_seal(),
            "c": {"build_command": ["/workspace/" + evidence.base.relative(evidence.PROBE),
                                    "-Wl,--wrap=munmap"],
                  "build": record(""), "elf": evidence.base.EXPECTED_C_ELF,
                  "execution": record(evidence.render_trace(trace) + "\n" + self.range_line()
                                      + self.c_os_line(), self.c_warning()),
                  "os_state": dict(evidence.C_OS_EXPECTED),
                  "trace": trace},
            "rust": {"command": ["--test", "native_os_medium_failed_unmap_exit",
                                 evidence.RUST_FILTER, "native-runtime-test-audit,native-runtime-test-fault"],
                     "execution": record(evidence.render_trace(trace) +
                                         "\n" + self.range_line() +
                                         "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n",
                                         self.rust_warning()),
                     "trace": trace},
            "comparison": {"status": "matched", "values": len(trace), "trace": trace},
        }

    def test_source_os_page_and_terminal_page_map_trace(self):
        trace = self.trace()
        self.assertEqual(evidence.compare_traces(trace, trace), trace)
        self.assertEqual(evidence.parse_c_os_state(self.c_os_line()),
                         evidence.C_OS_EXPECTED)

    def test_warning_address_must_match_failed_range(self):
        report = self.report()
        report["rust"]["execution"]["stderr"] = self.rust_warning().replace(
            "address: 0x100000", "address: 0x200000")
        with self.assertRaisesRegex(evidence.EvidenceError, "range and warning disagree"):
            evidence.validate_report(report)

    def test_missing_failed_range_fails_after_rehashed_trace(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            self.range_line(), "")
        with self.assertRaisesRegex(evidence.EvidenceError, "range is missing"):
            evidence.validate_report(report)

    def test_rehashed_wrong_source_state_fails(self):
        report = self.report()
        report["c"]["execution"]["stdout"] = report["c"]["execution"]["stdout"].replace(
            "os_list_abandoned=1", "os_list_abandoned=0")
        report["c"]["os_state"]["os_list_abandoned"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "source route"):
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
