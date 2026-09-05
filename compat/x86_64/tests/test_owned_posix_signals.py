"""Signal spelling reuse and raw differential boundaries cannot be weakened."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_posix_signals as signals


class OwnedPosixSignalsTests(unittest.TestCase):
    def setUp(self):
        self.contract = tomllib.loads(signals.CONTRACT.read_text())
        self.scratch = ROOT / ".work/x86_64/tmp"
        self.scratch.mkdir(parents=True, exist_ok=True)

    def test_product_selection_preserves_producers_and_complete_cell_rosters(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            base = Path(directory)
            static, dynamic = base / "static", base / "dynamic"
            static.mkdir()
            dynamic.mkdir()
            cases = ((["--static-sysroot", str(static), str(dynamic)], 0, 4, 70),
                     ([str(dynamic)], 0, 2, 50),
                     (["--static-sysroot", str(static)], 1, 4, 70),
                     ([], 2, 4, 70))
            for arguments, producers, links, observations in cases:
                with patch.dict("os.environ", {"TMPDIR": str(base)}), \
                     patch.object(signals, "command") as command, \
                     patch.object(signals, "compile_workload", return_value=base / "workload.o") as compile_workload, \
                     patch.object(signals, "digest", return_value="a" * 64), \
                     patch.object(signals, "audit_link", return_value={"audited": True}) as audit, \
                     patch.object(signals, "observe", return_value={"returncode": 0, "timed_out": False}) as observe, \
                     patch.object(signals, "same_observation", return_value=True), \
                     patch.object(signals.shutil, "copytree"), patch.object(signals.shutil, "copy2"), \
                     patch.object(signals.qualification, "source_digest", return_value="source"), \
                     patch.object(signals.qualification, "git", return_value=b"revision"), \
                     patch.object(signals.product_evidence, "_validate_static_product"), \
                     patch.object(signals.product_evidence, "_validate_dynamic_product"):
                    signals.run(arguments)
                self.assertEqual(compile_workload.call_count, 1)
                self.assertEqual(compile_workload.call_args.args[0], dynamic if str(dynamic) in arguments else compile_workload.call_args.args[1] / "dynamic-sysroot")
                commands = [[str(arg) for arg in call.args[0]] for call in command.call_args_list]
                self.assertEqual(sum("build_x86_64_owned" in arg for args in commands for arg in args), producers)
                for call in command.call_args_list:
                    args = list(map(str, call.args[0]))
                    if "--link-receipt" in args:
                        receipt = args[args.index("--link-receipt") + 1]
                        self.assertEqual(receipt, Path(receipt).name)
                        self.assertEqual(call.kwargs["cwd"], compile_workload.call_args.args[1])
                self.assertEqual(audit.call_count, links)
                self.assertEqual(observe.call_count, observations)
                record = json.loads((compile_workload.call_args.args[1] / "signal-full.json").read_text())
                self.assertEqual(len(record["comparisons"]), observations - 10)
                self.assertEqual(len(record["links"]), links)
                self.assertEqual(record["static_product_manifest_sha256"], "a" * 64 if links == 4 else None)

    def test_shared_link_validator_rejection_cannot_be_recorded_as_success(self):
        with patch.object(signals.product_evidence, "validate_link", side_effect=signals.product_evidence.ProductEvidenceError("forged receipt")) as validate, \
             patch.object(signals, "command") as command:
            with self.assertRaisesRegex(signals.product_evidence.ProductEvidenceError, "forged receipt"):
                signals.audit_link(Path("consumer"), Path("receipt"), Path("object"), Path("product"), "static-pie")
            validate.assert_called_once_with(Path("product"), Path("object"), Path("consumer"), Path("receipt"), "static-pie")
            command.assert_not_called()

    def test_invalid_supplied_product_fails_before_output_or_producers(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            product = Path(directory)
            for args in ([str(product)], ["--static-sysroot", str(product)]):
                with self.subTest(args=args), patch.dict("os.environ", {"TMPDIR": directory}), \
                     patch.object(signals.tempfile, "mkdtemp") as output, patch.object(signals, "command") as command:
                    with self.assertRaises(signals.product_evidence.ProductEvidenceError):
                        signals.run(args)
                    output.assert_not_called()
                    command.assert_not_called()

    def test_argument_modes_and_invalid_paths_fail_before_output(self):
        self.assertEqual(signals.parse_arguments([]), (None, None))
        self.assertEqual(signals.parse_arguments(["dynamic"]), (None, "dynamic"))
        self.assertEqual(signals.parse_arguments(["--static-sysroot", "static"]), ("static", None))
        self.assertEqual(signals.parse_arguments(["--static-sysroot", "static", "dynamic"]), ("static", "dynamic"))
        for args in ([""], ["--static-sysroot"], ["--static-sysroot", ""],
                     ["--static-sysroot", "--other"], ["--other"],
                     ["dynamic", "extra"], ["--static-sysroot", "a", "--static-sysroot", "b"],
                     ["--static-sysroot", "a", ""], ["dynamic", "--static-sysroot", "static"]):
            with self.subTest(args=args), patch.object(signals.tempfile, "mkdtemp") as output, \
                 patch.object(signals, "command") as command:
                with self.assertRaisesRegex(ValueError, "usage"):
                    signals.run(args)
                output.assert_not_called()
                command.assert_not_called()

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
