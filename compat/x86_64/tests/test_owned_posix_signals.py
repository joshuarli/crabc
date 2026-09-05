"""Signal spelling reuse and raw differential boundaries cannot be weakened."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_posix_signals as signals


class OwnedPosixSignalsTests(unittest.TestCase):
    def setUp(self):
        self.contract = tomllib.loads(signals.CONTRACT.read_text())
        self.scratch = ROOT / ".work/x86_64/tmp"
        self.scratch.mkdir(parents=True, exist_ok=True)

    def test_exact_spelling_partition_reuses_registered_positive_cases(self):
        signals.validate_contract(self.contract)
        owners = self.contract["primary_spelling_owner"]
        self.assertEqual(sum(map(len, owners.values())), 34)
        self.assertEqual(len(owners["signal-helpers"]), 8)
        self.assertEqual(len(owners["io-cancellation"]), 3)
        self.assertEqual(signals.qualification.CASES["signal-full"], ("run_owned_posix_signals.sh", None))
        source = (ROOT / "compat/x86_64/owned_posix_signals_probe.c").read_text()
        for scenario in self.contract["scenarios"]:
            self.assertIn('"' + scenario + '"', source)

    def test_omitted_duplicate_and_reassigned_spelling_fail(self):
        for change in ("omitted", "duplicate", "unknown-owner"):
            with self.subTest(change=change):
                document = deepcopy(self.contract)
                owners = document["primary_spelling_owner"]
                if change == "omitted": owners["sets"].pop()
                elif change == "duplicate": owners["sets"].append("signal")
                else: owners["unregistered"] = owners.pop("sets")
                with self.assertRaisesRegex(ValueError, "spelling"):
                    signals.validate_contract(document)

    def test_regression_scenario_cannot_be_dropped(self):
        self.contract["scenarios"].remove("sigpause-cancellation")
        with self.assertRaisesRegex(ValueError, "scenario roster"):
            signals.validate_contract(self.contract)

    def test_missing_existing_positive_case_cannot_be_implied(self):
        self.contract["reused_cases"].remove("io-cancellation")
        with self.assertRaisesRegex(ValueError, "reused case roster"):
            signals.validate_contract(self.contract)

    def test_raw_exit_stdout_and_stderr_each_participate(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            reference, candidate = Path(directory) / "oracle", Path(directory) / "candidate"
            baseline = {".status.json": json.dumps({"returncode": 0, "timed_out": False}), ".stdout": "errno=90\n", ".stderr": ""}
            for suffix, contents in baseline.items():
                Path(str(reference) + suffix).write_text(contents)
                Path(str(candidate) + suffix).write_text(contents)
            self.assertTrue(signals.same_observation(reference, candidate))
            for suffix, contents in baseline.items():
                with self.subTest(suffix=suffix):
                    Path(str(candidate) + suffix).write_text(contents + "changed")
                    self.assertFalse(signals.same_observation(reference, candidate))
                    Path(str(candidate) + suffix).write_text(contents)

    def test_product_resolution_rejects_direct_and_symlink_escape(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            link = Path(directory) / "escaped"
            link.symlink_to(ROOT, target_is_directory=True)
            for path in (ROOT, link):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(ValueError, "physical checkout .work"):
                        signals.contained_directory(path, "product")
            self.assertEqual(signals.contained_directory(directory, "product"), Path(directory))


if __name__ == "__main__":
    unittest.main()
