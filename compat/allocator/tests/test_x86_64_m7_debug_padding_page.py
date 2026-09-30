"""Physical receipt controls for the full debug-padding page workload."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m7_debug_padding_page as page


class DebugPaddingPageReceiptTests(unittest.TestCase):
    def setUp(self):
        scratch = page.harness.ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.work = self.root / ".work/raw"
        self.work.mkdir(parents=True)
        self.seal = {"revision": "a" * 40, "worktree_sha256": "b" * 64}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(page.harness, "ROOT", self.root).start()
        mock.patch.object(page.receipts, "source_seal", return_value=self.seal).start()
        names = ["c-build", "rust-build", "rust-link", "c-clean", "c-corrupt", "rust-clean", "rust-corrupt", "comparison"]
        self.cases = []
        for name in names:
            log = self.work / (name + ".json")
            log.write_text('{}\n')
            self.cases.append((name, 0, [log]))
        report = {"status": "passed", "mismatch_keys": {"clean": [], "corrupt": []},
                  "traces": {}, "executions": {}}
        for side in ("c", "rust"):
            for case in ("clean", "corrupt"):
                report["traces"][f"{side}.{case}"] = {"case": case, "owned.live": "1"}
                report["executions"][f"{side}.{case}"] = {"status": 0, "stdout": "", "stderr": ""}
        self.products = {}
        for name in ("c", "rust", page.FIXTURE.name, "mimalloc-3.5.0.tar.gz", "inputs.json", "page.json"):
            path = self.work / name
            path.write_text(json.dumps(report) if name == "page.json" else '{}\n')
            self.products[name] = path
        self.parameters = {"debug": "1", "padding": "1", "stat": "2"}

    def publish(self):
        return page.receipts.write_receipt(self.root, page.RUNNER, self.work,
                                          self.products, self.cases, self.parameters, True)

    def test_complete_retained_builds_callers_and_comparison_are_readable(self):
        self.publish()
        page.read_and_replay()

    def test_missing_or_extra_or_reordered_caller_phase_is_rejected(self):
        original = self.cases[:]
        for cases in (original[:-1], original + [("extra", 0, original[0][2])],
                      [original[1], original[0], *original[2:]]):
            with self.subTest(cases=[case[0] for case in cases]):
                self.cases = cases
                self.publish()
                with self.assertRaises(page.harness.HarnessError):
                    page.read_and_replay()

    def test_missing_or_extra_product_is_rejected(self):
        original = self.products.copy()
        for products in ({key: value for key, value in original.items() if key != "c"},
                         {**original, "extra": original["c"]}):
            self.products = products
            self.publish()
            with self.assertRaises(page.harness.HarnessError):
                page.read_and_replay()

    def test_changed_physical_product_is_rejected_by_generic_reader(self):
        receipt = self.publish()
        (receipt.parent / "products/c").write_bytes(b"changed ELF bytes")
        with self.assertRaises(page.receipts.ReceiptError):
            page.read_and_replay()

    def test_wrong_selected_numeric_configuration_is_rejected(self):
        self.parameters["stat"] = "1"
        self.publish()
        with self.assertRaises(page.harness.HarnessError):
            page.read_and_replay()

    def test_nonzero_actual_caller_status_cannot_be_admitted(self):
        name, _, logs = self.cases[3]
        self.cases[3] = (name, -6, logs)
        self.publish()
        with self.assertRaises(page.receipts.ReceiptError):
            page.read_and_replay()

    def test_disagreeing_native_page_observation_is_rejected(self):
        report = json.loads(self.products["page.json"].read_text())
        report["traces"]["rust.clean"]["owned.live"] = "0"
        self.products["page.json"].write_text(json.dumps(report))
        self.publish()
        with self.assertRaises(page.harness.HarnessError):
            page.read_and_replay()


if __name__ == "__main__":
    unittest.main()
