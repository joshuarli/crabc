"""Focused contracts for the nine private loader-runtime protocol imports."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat/x86_64/loader_runtime_registry_evidence.py"
SPEC = importlib.util.spec_from_file_location("loader_runtime_registry_evidence_test", MODULE_PATH)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class LoaderRuntimeRegistryEvidenceTests(unittest.TestCase):
    def contract(self):
        return copy.deepcopy(EVIDENCE.load_contract(ROOT))

    def facts(self):
        rows = []
        for index, name in enumerate(EVIDENCE.RESOLVERS, start=1):
            row = {"name": name, "raw_name": name, "row_index": index,
                   "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
                   "section_index": "UND", "version": None, "version_default": False,
                   "size_bytes": 0, "value": "0000000000000000"}
            rows.append(row)
        return {
            "artifacts": {"candidate-shared": {}, "candidate-loader": {}},
            "facts": {
                "candidate-shared": {"symbol_tables": [
                    {"name": ".dynsym", "rows": copy.deepcopy(rows)},
                    {"name": ".symtab", "rows": copy.deepcopy(rows)},
                ]},
                "candidate-loader": {"symbol_tables": [{"name": ".dynsym", "rows": []}]},
            },
        }

    def test_contract_and_live_source_are_an_exact_closed_resolver(self):
        contract = self.contract()
        self.assertEqual({row["name"]: row["resolver"] for row in contract["operation"]}, EVIDENCE.RESOLVERS)
        resolution = EVIDENCE.source_resolution(ROOT)
        self.assertEqual(resolution["resolvers"], dict(sorted(EVIDENCE.RESOLVERS.items())))
        self.assertEqual(resolution["feature"], EVIDENCE.FEATURE)

    def test_non_pie_workload_label_requires_the_owned_driver_exec_receipt(self):
        self.assertEqual(EVIDENCE.DLOPEN_DRIVER_MODES, {"pie": "pie", "non-pie": "exec"})

    def test_workload_environment_retains_the_existing_chroot_search_path(self):
        self.assertIn("/usr/sbin", EVIDENCE.WORKLOAD_ENVIRONMENT["PATH"].split(":"))

    def test_bounded_dlfcn_capture_explicitly_excludes_the_separate_proc_mount_search_leaf(self):
        self.assertEqual(EVIDENCE.DLFCN_SKIP_SEARCH_ENV, "CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH")
        runner = (ROOT / "compat/x86_64/run_general_dynamic_dlopen.sh").read_text(encoding="utf-8")
        self.assertIn(EVIDENCE.DLFCN_SKIP_SEARCH_ENV, runner)

    def test_contract_rejects_ambiguous_unknown_and_promoting_operation(self):
        contract = self.contract()
        contract["operation"].append({"name": "__crabc_x86_64_runtime_unknown", "resolver": "unknown",
                                      "consumer": "general_dlfcn", "scenario": "runtime-tls-41-modules"})
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "operation roster"):
            EVIDENCE.validate_contract(contract)
        contract = self.contract()
        contract["operation"][0]["scenario"] = "inferred-from-runner"
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "scenario"):
            EVIDENCE.validate_contract(contract)
        contract = self.contract()
        contract["limits"]["public_provider"] = True
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "nonpromotion"):
            EVIDENCE.validate_contract(contract)

    def test_import_placement_requires_exactly_two_undefined_shared_rows_per_name(self):
        placement = EVIDENCE.import_placement(self.facts())
        self.assertEqual(set(placement), set(EVIDENCE.RESOLVERS))
        self.assertTrue(all(row["section_index"] == "UND" for row in placement.values()))
        malformed = self.facts()
        malformed["facts"]["candidate-shared"]["symbol_tables"][0]["rows"][0]["visibility"] = "HIDDEN"
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "metadata"):
            EVIDENCE.import_placement(malformed)
        malformed = self.facts()
        malformed["facts"]["candidate-shared"]["symbol_tables"][1]["rows"].pop()
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "once in dynsym and symtab"):
            EVIDENCE.import_placement(malformed)
        malformed = self.facts()
        malformed["facts"]["candidate-loader"]["symbol_tables"][0]["rows"].append(
            copy.deepcopy(malformed["facts"]["candidate-shared"]["symbol_tables"][0]["rows"][0])
        )
        with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "candidate loader"):
            EVIDENCE.import_placement(malformed)

    def test_raw_command_replay_requires_its_authoritative_streams_and_terminal_zero(self):
        scratch = ROOT / ".work/x86_64/loader-runtime-registry-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            raw = output / "raw"
            raw.mkdir()
            for suffix, contents in (("stdout", b"ok\n"), ("stderr", b""), ("status", b"0\n")):
                (raw / f"dlfcn-pie.{suffix}").write_bytes(contents)
            command = ["bash", "/fixture/run_general_dynamic_dlopen.sh", "/fixture/product"]
            environment = {"PATH": "/fixture/bin"}
            record = {"argv": command, "environment": environment,
                      **{suffix: EVIDENCE.identity(raw / f"dlfcn-pie.{suffix}", logical_path=f"raw/dlfcn-pie.{suffix}")
                         for suffix in ("stdout", "stderr", "status")}}
            EVIDENCE._validate_command(output, record, "dlfcn-pie", command, environment)
            changed = copy.deepcopy(record)
            changed["environment"] = {"PATH": "/usr/bin:/bin"}
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "environment drifted"):
                EVIDENCE._validate_command(output, changed, "dlfcn-pie", command, environment)
            changed = copy.deepcopy(record)
            changed["stdout"]["path"] = "raw/unrelated.stdout"
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "path drifted"):
                EVIDENCE._validate_command(output, changed, "dlfcn-pie", command, environment)
            (raw / "dlfcn-pie.status").write_bytes(b"1\n")
            changed["stdout"] = EVIDENCE.identity(raw / "dlfcn-pie.stdout", logical_path="raw/dlfcn-pie.stdout")
            changed["status"] = EVIDENCE.identity(raw / "dlfcn-pie.status", logical_path="raw/dlfcn-pie.status")
            with self.assertRaisesRegex(EVIDENCE.RuntimeRegistryEvidenceError, "did not succeed"):
                EVIDENCE._validate_command(output, changed, "dlfcn-pie", command, environment)

    def test_fork_reader_extension_is_a_replay_command_not_a_second_runner(self):
        source = (ROOT / "compat/x86_64/owned_dynamic_fork_evidence.py").read_text(encoding="utf-8")
        self.assertIn("def validate_observations(product: Path, work: Path)", source)
        self.assertIn("fork observation receipt does not reconstruct", source)
        self.assertIn('"validate-observations"', source)

    def test_cli_rejects_abbreviation_and_requires_both_runtime_product_inputs(self):
        with self.assertRaises(SystemExit):
            EVIDENCE.main(["collect", "--dynamic-prod", "x"])
        with self.assertRaises(SystemExit):
            EVIDENCE.main(["validate-report"])


if __name__ == "__main__":
    unittest.main()
