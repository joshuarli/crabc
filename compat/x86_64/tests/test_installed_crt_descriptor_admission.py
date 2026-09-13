"""Actual installed-main mutation controls for descriptor admission evidence."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import installed_crt_descriptor_admission as admission


class InstalledCrtDescriptorAdmissionTests(unittest.TestCase):
    _FED_MAIN = (
        admission.ROOT.parent
        / "native_crt_main_anchor_integration/.work/x86_64/crt-startup-evidence/"
        "clean-fed397b0/owned-pie-normal"
    )

    def test_duplicate_cli_option_rejects_before_report_access(self):
        with self.assertRaises(admission.DescriptorAdmissionError):
            admission.main(["validate-report", "--report=first", "--report", "second"])

    def test_retained_owned_main_has_one_mutable_descriptor_wire(self):
        """One fed main gives all four one-field negative controls their exact input."""
        if not self._FED_MAIN.is_file():
            self.skipTest("requires the retained fed owned PIE main")
        self.assertEqual(
            hashlib.sha256(self._FED_MAIN.read_bytes()).hexdigest(),
            "5cdfa442f1d96018a797f18c24e38862f229425fed093469f95822df273d4b97",
        )
        parent = admission.ROOT / ".work/x86_64/descriptor-admission-tests"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory)
            original = self._FED_MAIN.read_bytes()
            symbol, relocation, info = admission._elf_descriptor(original)
            for label, (field, value) in admission.CASES.items():
                with self.subTest(label=label):
                    output = work / label
                    mutation = admission.mutate_main(self._FED_MAIN, output, label)
                    self.assertEqual(mutation["symbol_file_offset"], symbol)
                    self.assertEqual(mutation["rela_file_offset"], relocation)
                    self.assertEqual(mutation["input"], admission.identity(self._FED_MAIN))
                    changed = output.read_bytes()
                    self.assertEqual(changed[:symbol + 4], original[:symbol + 4])
                    if field == "symbol-info":
                        self.assertEqual(changed[symbol + 4], value)
                    elif field == "relocation-kind":
                        self.assertEqual(changed[relocation + 8:relocation + 16],
                                         ((info & ~0xffffffff) | value).to_bytes(8, "little"))
                    else:
                        self.assertEqual(changed[relocation + 16:relocation + 24],
                                         value.to_bytes(8, "little", signed=True))
            self.assertEqual(self._FED_MAIN.read_bytes(), original)
