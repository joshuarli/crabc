"""The dynamic catalog requires full native loader and package evidence."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as qualification


class NativeLoaderCorpusQualificationTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / ".work/product"
        self.product = self.work / "installed"
        self.manifest = self.product / "share/crabc/manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text("{}\n")
        self.digest = qualification.digest(self.manifest)
        self.oracle = {"runtime_sha256": "a" * 64, "compiler_wrapper_sha256": "b" * 64}
        (self.work / "qualification-prepare.json").write_text(json.dumps({"oracle": self.oracle}))
        self.leaf = self.work / "native-evidence"
        self.leaf.mkdir()
        self.report = self.leaf / "report.json"
        self.report.write_text("{}\n")
        self.log = self.work / "qualification-cases/installed/package-corpus.log"
        self.log.parent.mkdir(parents=True)
        self.log.write_text(f"evidence: {self.leaf}\n")
        patch = mock.patch.object(qualification, "ROOT", self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def test_catalog_runs_full_rosters_with_exact_product_in_private_network(self):
        for case, script, flags in (
            ("loader-synthetic", "run_owned_loader_synthetic.sh", []),
            ("package-corpus", "run_owned_package_corpus.sh", ["--dynamic-sysroot"]),
        ):
            with self.subTest(case=case):
                self.assertEqual(qualification.CASES[case], (script, None))
                self.assertEqual(qualification.case_command(self.work, "installed", case),
                    ["unshare", "--net", "--", "bash", str(self.root / "compat/x86_64" / script),
                     *flags, str(self.product)])

    def reader(self, error=None):
        class EvidenceError(RuntimeError):
            pass
        loader = mock.Mock(side_effect=EvidenceError(error) if error else None)
        corpus = mock.Mock(side_effect=EvidenceError(error) if error else None)
        return types.SimpleNamespace(LoaderCorpusEvidenceError=EvidenceError,
            validate_loader_report=loader, validate_corpus_report=corpus)

    def test_native_report_reader_receives_exact_retained_root_and_product(self):
        reader = self.reader()
        with mock.patch.dict(sys.modules, {"owned_loader_corpus_evidence": reader}):
            for case, method in (("loader-synthetic", reader.validate_loader_report),
                                 ("package-corpus", reader.validate_corpus_report)):
                qualification.validate_loader_corpus_case(self.work, "installed", case,
                    self.log, str(self.root), self.digest)
                method.assert_called_once_with(self.report, self.product, root=self.root,
                    expected_oracle=self.oracle)

    def test_partial_or_false_native_report_cannot_be_replaced_by_exit_status(self):
        reader = self.reader("full native roster did not pass")
        with mock.patch.dict(sys.modules, {"owned_loader_corpus_evidence": reader}), \
             self.assertRaisesRegex(qualification.QualificationError, "full native roster"):
            qualification.validate_loader_corpus_case(self.work, "installed", "package-corpus",
                self.log, str(self.root), self.digest)

    def test_missing_ambiguous_or_cross_product_evidence_is_rejected_before_reader(self):
        reader = self.reader()
        second = self.work / "another-evidence"
        second.mkdir()
        for lines, manifest in (("no evidence\n", self.digest),
                                (f"evidence: {self.leaf}\nevidence: {second}\n", self.digest),
                                (f"evidence: {self.leaf}\n", "0" * 64)):
            self.log.write_text(lines)
            with mock.patch.dict(sys.modules, {"owned_loader_corpus_evidence": reader}), \
                 self.assertRaises(qualification.QualificationError):
                qualification.validate_loader_corpus_case(self.work, "installed", "package-corpus",
                    self.log, str(self.root), manifest)
        reader.validate_corpus_report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
