#!/usr/bin/env python3
"""Named, fail-closed conditions for each ordered x86 qualification gate."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))
import qualification_gates as gates  # noqa: E402


def family(identifier: str, status: str, depends_on: list[str], commands: list[str]) -> dict[str, object]:
    return {
        "id": identifier,
        "status": status,
        "depends_on": depends_on,
        "native_evidence": [{"state": "required", "command": command, "scope": "fixture"} for command in commands],
    }


def complete_chain_families(**overrides: dict[str, object]) -> dict[str, dict[str, object]]:
    """A minimal ledger where every chain gate depends on one foundation."""
    families = {"foundation": family("foundation", "foundation-verified", [], ["./scripts/dev-x86_64.sh base"])}
    for gate in gates.CHAIN:
        families[gate] = family(gate, "foundation-verified", ["foundation"], [f"./scripts/dev-x86_64.sh {gate}"])
    families.update(overrides)
    return families


def reader(gate: str, command: str, kind: str = "report", result: str = "read", error: Exception | None = None):
    def read(evaluation: gates.Evaluation) -> str:
        del evaluation
        if error is not None:
            raise error
        return result

    return gates.EvidenceReader(gate, command, kind, "fixture", read)


def rows(result: dict[str, object]) -> dict[str, dict[str, object]]:
    return {row["id"]: row for row in result["conditions"]}


CLEAN = {"revision": "a" * 40, "uncommitted": []}


class GateConditionTests(unittest.TestCase):
    def test_hardened_product_replay_rejects_changed_bytes_and_profiles(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as temporary:
            root = Path(temporary)
            source = "a" * 64
            products = {}
            paths = {}
            for name in ("static", "dynamic", "compatibility"):
                path = root / ".work" / name / "share/crabc/manifest.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"hardening_profile": "compatibility" if name == "compatibility" else "hardened",
                                            "build_profile": "release", "source_sha256": source}))
                paths[name] = path
                products[name] = {"manifest": path.relative_to(root).as_posix(),
                                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            qualification = SimpleNamespace(ROOT=root, product_identity=Mock())
            seal = SimpleNamespace(product_source_digest=Mock(return_value=source))
            evidence = SimpleNamespace(_validate_static_product=Mock(), validate_dynamic_product_source=Mock())
            modules = {"owned_dynamic_qualification": qualification, "owned_posix_product_evidence": evidence,
                       "source_seal": seal}
            with patch.object(gates, "ROOT", root), patch.object(gates, "_import_compat", side_effect=modules.__getitem__):
                self.assertEqual(gates.validate_hardened_products(products), products)
                evidence._validate_static_product.assert_called_once_with(paths["static"].parents[2])
                evidence.validate_dynamic_product_source.assert_called_once_with(paths["dynamic"].parents[2], source)
                qualification.product_identity.assert_called_once_with(paths["compatibility"].parents[2])
                paths["dynamic"].write_text("{}")
                with self.assertRaises(gates.EvidenceUnmet):
                    gates.validate_hardened_products(products)
                products["dynamic"]["sha256"] = hashlib.sha256(paths["dynamic"].read_bytes()).hexdigest()
                with self.assertRaises(gates.EvidenceUnmet):
                    gates.validate_hardened_products(products)
                with self.assertRaises(gates.EvidenceUnmet):
                    gates.validate_hardened_products({"static": products["static"]})

    def test_loader_gate_rejects_missing_or_duplicate_hardened_requirement(self):
        gate = "compat.loader-corpus"
        families = complete_chain_families()
        ordinary = f"./scripts/dev-x86_64.sh {gate}"
        readers = {(gate, ordinary): reader(gate, ordinary)}
        checks = {gate: (gates._hardened_runtime_requirement,)}
        with patch.object(self, "gate", gate):
            missing = self.evaluate(families, readers, checks=checks)
            self.assertFalse(missing["passed"])
            self.assertIn("hardened-runtime-required", missing["unmet"])
            families[gate]["native_evidence"].extend([
                {"state": "required", "command": gates.HARDENED_RUNTIME_COMMAND, "scope": "fixture"},
                {"state": "required", "command": gates.HARDENED_RUNTIME_COMMAND, "scope": "fixture"},
            ])
            readers[(gate, gates.HARDENED_RUNTIME_COMMAND)] = reader(gate, gates.HARDENED_RUNTIME_COMMAND)
            duplicate = self.evaluate(families, readers, checks=checks)
            self.assertFalse(duplicate["passed"])
            self.assertIn("hardened-runtime-required", duplicate["unmet"])
            families[gate]["native_evidence"].pop()
            passing = self.evaluate(families, readers, checks=checks)
            self.assertTrue(passing["passed"])

    def test_hardened_execution_requires_qualified_compatibility_and_passing_run(self):
        evaluation = Mock()
        evaluation.published.return_value = {
            "status": "installed-loader-component-verified", "component_complete": True,
            "inputs": {"before": {"qualification": {"path": ".work/cohort/qualification.json"}}},
        }
        qualification = Path("/workspace/.work/cohort/qualification.json")
        with patch.object(gates, "_physical_work_file", return_value=qualification), \
             patch.object(gates.subprocess, "run") as run, \
             patch.object(gates, "validate_hardened_products", side_effect=lambda value: value):
            run.return_value = SimpleNamespace(returncode=0, stdout=b"{}\nhardened runtime: PASS\n", stderr=b"")
            self.assertEqual(gates._execute_hardened_runtime(evaluation), {})
            self.assertEqual(run.call_args.args[0][-1], str(qualification.parent / "installed"))
            for status, stdout in ((1, b"{}\nhardened runtime: PASS\n"), (0, b"incomplete\n"),
                                   (0, b"not-json\nhardened runtime: PASS\n")):
                run.return_value = SimpleNamespace(returncode=status, stdout=stdout, stderr=b"failure")
                with self.subTest(status=status, stdout=stdout), self.assertRaises(gates.EvidenceUnmet):
                    gates._execute_hardened_runtime(evaluation)
        evaluation.published.side_effect = gates.EvidenceUnmet("missing compatibility qualification")
        with self.assertRaises(gates.EvidenceUnmet):
            gates._execute_hardened_runtime(evaluation)

    gate = gates.CHAIN[2]

    def test_performance_release_command_has_no_allocator_report_inputs(self):
        self.assertEqual(gates.PERFORMANCE_RELEASE_COMMAND,
                         "python3 compat/x86_64/performance_release_gate.py evaluate "
                         "--runtime-c-collector COLLECTOR.json --native-facade-report REPORT.json "
                         "--rustybench-source DIR --rustix-source DIR --output NEW_DIR")

    def test_parity_ledger_reader_requires_receipts(self):
        validation = Mock(return_value={"family_count": 16})
        ledger = SimpleNamespace(
            LEDGER_PATH=Path("parity.toml"),
            load_toml=Mock(return_value={"schema": "fixture"}),
            validate_ledger=validation,
        )
        inventory = SimpleNamespace(
            validate_frozen_baseline=Mock(),
            validate_inventory=Mock(),
        )
        modules = {"validate_parity_ledger": ledger, "aarch64_parity_inventory": inventory}
        with patch.object(gates, "_import_compat", side_effect=modules.__getitem__):
            detail = gates._read_parity_ledger(None)

        validation.assert_called_once_with({"schema": "fixture"}, require_receipts=True)
        inventory.validate_frozen_baseline.assert_called_once_with()
        inventory.validate_inventory.assert_called_once_with()
        self.assertIn("ledger (16 families)", detail)

    def evaluate(self, families, readers, *, native=True, checks=None, source=None):
        states = iter(source or (CLEAN, CLEAN))
        with patch.object(gates, "load_families", return_value=families), patch.object(
            gates, "READERS", readers
        ), patch.object(gates, "GATE_CHECKS", checks or {}), patch.object(
            gates, "source_state", side_effect=lambda: next(states)
        ):
            return gates.evaluate(self.gate, native=native)

    def test_prerequisites_name_dependency_and_chain_order_blockers(self):
        families = complete_chain_families()
        families["foundation"]["status"] = "planned"
        families[gates.CHAIN[0]]["status"] = "planned"
        command = f"./scripts/dev-x86_64.sh {self.gate}"
        result = self.evaluate(families, {(self.gate, command): reader(self.gate, command)})
        self.assertFalse(result["passed"])
        self.assertEqual(result["unmet"], ["prerequisite-families"])
        self.assertEqual(rows(result)["prerequisite-families"]["detail"], [
            {"family": "foundation", "status": "planned", "required_by": "depends_on"},
            {"family": gates.CHAIN[0], "status": "planned", "required_by": "chain-order"},
        ])

    def test_unregistered_and_prose_evidence_are_distinct_unmet_conditions(self):
        families = complete_chain_families()
        families[self.gate] = family(
            self.gate, "planned", ["foundation"],
            ["./scripts/dev-x86_64.sh unread-leaf", "Define a future gate"],
        )
        result = self.evaluate(families, {})
        self.assertEqual(result["unmet"], ["evidence[0]", "evidence[1]"])
        details = [rows(result)[f"evidence[{index}]"]["detail"] for index in range(2)]
        self.assertIn("no qualification reader is registered", details[0])
        self.assertIn("prose placeholder", details[1])

    def test_host_evaluation_names_native_reads_but_never_passes(self):
        families = complete_chain_families()
        command = f"./scripts/dev-x86_64.sh {self.gate}"
        result = self.evaluate(families, {(self.gate, command): reader(self.gate, command)}, native=False)
        self.assertFalse(result["passed"])
        self.assertEqual(result["unmet"], ["evidence[0]"])
        self.assertIsNone(rows(result)["evidence[0]"]["met"])
        self.assertNotIn("clean-committed-source", rows(result))

    def test_native_pass_requires_every_reader_and_gate_check(self):
        families = complete_chain_families()
        command = f"./scripts/dev-x86_64.sh {self.gate}"
        readers = {(self.gate, command): reader(self.gate, command)}
        self.assertTrue(self.evaluate(families, readers)["passed"])

        failing = {(self.gate, command): reader(self.gate, command, error=gates.EvidenceUnmet("receipt is stale"))}
        result = self.evaluate(families, failing)
        self.assertFalse(result["passed"])
        self.assertEqual(rows(result)["evidence[0]"]["detail"], "receipt is stale")

        crashing = {(self.gate, command): reader(self.gate, command, error=KeyError("coverage"))}
        self.assertIn("KeyError", rows(self.evaluate(families, crashing))["evidence[0]"]["detail"])

        check = lambda families: {"id": "completion", "met": False, "detail": "one capability remains"}  # noqa: E731
        result = self.evaluate(families, readers, checks={self.gate: (check,)})
        self.assertEqual(result["unmet"], ["completion"])

    def test_execution_reader_runs_only_after_every_other_condition_is_met(self):
        families = complete_chain_families()
        families[self.gate] = family(
            self.gate, "planned", ["foundation"],
            ["./scripts/dev-x86_64.sh execute", "./scripts/dev-x86_64.sh read"],
        )
        calls = []

        def execute(evaluation):
            calls.append("execute")
            return "executed"

        readers = {
            (self.gate, "./scripts/dev-x86_64.sh execute"): gates.EvidenceReader(
                self.gate, "./scripts/dev-x86_64.sh execute", "execution", "fixture", execute),
            (self.gate, "./scripts/dev-x86_64.sh read"): reader(
                self.gate, "./scripts/dev-x86_64.sh read", error=gates.EvidenceUnmet("missing report")),
        }
        result = self.evaluate(families, readers)
        self.assertEqual(calls, [])
        self.assertIsNone(rows(result)["evidence[0]"]["met"])
        self.assertIn("not executed", rows(result)["evidence[0]"]["detail"])

        readers[(self.gate, "./scripts/dev-x86_64.sh read")] = reader(self.gate, "./scripts/dev-x86_64.sh read")
        result = self.evaluate(families, readers)
        self.assertEqual(calls, ["execute"])
        self.assertTrue(result["passed"])
        self.assertEqual([row["id"] for row in result["conditions"]],
                         ["clean-committed-source", "prerequisite-families", "evidence[0]", "evidence[1]",
                          "source-unchanged"])

    def test_native_reads_require_clean_source_that_stays_unchanged(self):
        families = complete_chain_families()
        command = f"./scripts/dev-x86_64.sh {self.gate}"
        readers = {(self.gate, command): reader(self.gate, command)}
        dirty = {"revision": "a" * 40, "uncommitted": [" M compat/x86_64/parity.toml"]}
        result = self.evaluate(families, readers, source=(dirty, dirty))
        self.assertFalse(result["passed"])
        self.assertEqual(result["unmet"], ["clean-committed-source"])
        self.assertEqual(rows(result)["clean-committed-source"]["detail"]["uncommitted"],
                         [" M compat/x86_64/parity.toml"])

        moved = {"revision": "b" * 40, "uncommitted": []}
        result = self.evaluate(families, readers, source=(CLEAN, moved))
        self.assertEqual(result["unmet"], ["source-unchanged"])

    def test_entry_prints_the_completion_marker_only_on_a_native_pass(self):
        for passed in (True, False):
            with self.subTest(passed=passed):
                result = {"schema": gates.CONDITIONS_SCHEMA, "gate": self.gate, "native": True,
                          "passed": passed, "unmet": [] if passed else ["evidence[0]"], "conditions": []}
                output = io.StringIO()
                with patch.object(gates, "evaluate", return_value=result), redirect_stdout(output):
                    status = gates.main([self.gate])
                last = output.getvalue().splitlines()[-1]
                self.assertEqual(status, 0 if passed else 1)
                self.assertEqual(last == gates.pass_marker(self.gate), passed)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp/qualification-gate-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.receipt = self.root / ".work/x86_64/leaf/receipt.json"
        self.receipt.parent.mkdir(parents=True)
        self.receipt.write_text('{"status": "complete"}\n', encoding="utf-8")
        self.validated: list[Path] = []

        def validate(path: Path):
            self.validated.append(path)
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("status") != "complete":
                raise RuntimeError("leaf reader rejected the receipt")
            return value

        self.publication = gates.Publication("fixture", gates.CHAIN[0], "receipt.json", "./leaf", validate)
        for name, value in (
            ("ROOT", self.root),
            ("PUBLICATION_DIRECTORY", self.root / ".work/x86_64/qualification-evidence"),
            ("PUBLICATIONS", {"fixture": self.publication}),
        ):
            patcher = patch.object(gates, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_publish_validates_first_and_the_gate_rereads_the_receipt(self):
        pointer = gates.publish(gates.CHAIN[0], "fixture", ".work/x86_64/leaf/receipt.json")
        self.assertEqual(json.loads(pointer.read_text(encoding="utf-8")), {
            "schema": gates.PUBLICATION_SCHEMA,
            "gate": gates.CHAIN[0],
            "publication": "fixture",
            "receipt": ".work/x86_64/leaf/receipt.json",
            "receipt_sha256": hashlib.sha256(self.receipt.read_bytes()).hexdigest(),
        })
        self.assertEqual(gates.read_publication(gates.CHAIN[0], "fixture"), {"status": "complete"})
        self.assertEqual(self.validated, [self.receipt, self.receipt])

    def test_missing_changed_or_rejected_receipts_are_named_unmet_conditions(self):
        with self.assertRaisesRegex(gates.EvidenceUnmet, "qualification-manifest --publish"):
            gates.read_publication(gates.CHAIN[0], "fixture")
        gates.publish(gates.CHAIN[0], "fixture", str(self.receipt))
        self.receipt.write_text('{"status": "partial"}\n', encoding="utf-8")
        with self.assertRaisesRegex(gates.EvidenceUnmet, "changed after publication"):
            gates.read_publication(gates.CHAIN[0], "fixture")
        with self.assertRaisesRegex(gates.GateError, "leaf reader rejected"):
            gates.publish(gates.CHAIN[0], "fixture", str(self.receipt))

    def test_publication_rejects_other_gates_escapes_and_symlinks(self):
        with self.assertRaisesRegex(gates.GateError, "has no publication"):
            gates.publish(gates.CHAIN[1], "fixture", str(self.receipt))
        outside = self.root / "receipt.json"
        outside.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(gates.GateError, ".work path"):
            gates.publish(gates.CHAIN[0], "fixture", "receipt.json")
        link = self.root / ".work/x86_64/link"
        link.symlink_to(self.receipt.parent, target_is_directory=True)
        with self.assertRaisesRegex(gates.GateError, "symlink"):
            gates.publish(gates.CHAIN[0], "fixture", ".work/x86_64/link/receipt.json")


class ResolverNetworkPublicationTests(unittest.TestCase):
    """The resolver gate selects a retained producer copy, not a fixed report path."""

    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp/qualification-gate-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / ".work/x86_64/family/network"
        self.state.mkdir(parents=True)
        self.retained = self.state / "report.json"
        self.public = "/workspace/compat/reports/resolver-network/x86_64/family-run.json"
        self.document = {"published_report": self.public, "state_root": "/workspace/.work/x86_64/family/network",
                         "passed": True}
        self.retained.write_text(json.dumps(self.document), encoding="utf-8")
        patcher = patch.object(gates, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.reader = gates._import_compat("resolver_network_component_receipt")
        image = patch.object(self.reader, "trusted_image_manifest", return_value={"path": "/pinned/bin"})
        image.start()
        self.addCleanup(image.stop)
        process = patch.object(gates.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout="valid\n", stderr=""))
        self.run = process.start()
        self.addCleanup(process.stop)

    def test_the_published_report_is_replayed_and_must_retain_this_copy(self):
        with patch.dict(os.environ, {"PATH": "/qualification/bin"}):
            self.assertEqual(gates._validate_resolver_network(self.retained), self.document)
            self.assertEqual(os.environ["PATH"], "/qualification/bin")
        argv = self.run.call_args.args[0]
        self.assertEqual(argv, [sys.executable, "-B",
                               str(self.root / "compat/x86_64/resolver_network_component_receipt.py"),
                               "validate-report", "--root", str(self.root), "--report",
                               str(self.root / "compat/reports/resolver-network/x86_64/family-run.json")])
        self.assertEqual(self.run.call_args.kwargs["env"]["PATH"], "/pinned/bin")

        for changed, message in (
            ({"state_root": "/workspace/.work/x86_64/other"}, "retained copy"),
            ({"passed": False}, "did not pass"),
        ):
            with self.subTest(message=message):
                self.retained.write_text(json.dumps({**self.document, **changed}), encoding="utf-8")
                with self.assertRaisesRegex(gates.EvidenceUnmet, message):
                    gates._validate_resolver_network(self.retained)
        self.retained.write_text(json.dumps({"state_root": "x"}), encoding="utf-8")
        with self.assertRaisesRegex(gates.EvidenceUnmet, "names no published report"):
            gates._validate_resolver_network(self.retained)

    def test_child_failure_and_receipt_mutation_remain_unmet(self):
        self.run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="image identity differs")
        with patch.dict(os.environ, {"PATH": "/qualification/bin"}):
            with self.assertRaisesRegex(gates.EvidenceUnmet, "image identity differs"):
                gates._validate_resolver_network(self.retained)
            self.assertEqual(os.environ["PATH"], "/qualification/bin")

        def replace_receipt(*args, **kwargs):
            self.retained.write_text("{}", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="valid\n", stderr="")

        self.run.side_effect = replace_receipt
        with self.assertRaisesRegex(gates.EvidenceUnmet, "changed during replay"):
            gates._validate_resolver_network(self.retained)

class ResolverNetworkPublicationMutationTests(unittest.TestCase):
    def test_retained_newlines_are_compared_as_bytes(self):
        root = Path("/qualification-fixture")
        retained = root / ".work/x86_64/network/report.json"
        document = {"published_report": "/workspace/compat/reports/resolver-network/x86_64/report.json",
                    "state_root": "/workspace/.work/x86_64/network", "passed": True}
        original = (json.dumps(document) + "\n").encode("utf-8")
        changed = original.replace(b"\n", b"\r\n")
        reader = gates._import_compat("resolver_network_component_receipt")
        with patch.object(gates, "ROOT", root), \
             patch.object(reader, "trusted_image_manifest", return_value={"path": "/pinned/bin"}), \
             patch.object(gates.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout="valid\n", stderr="")), \
             patch.object(Path, "read_text", return_value=original.decode("utf-8")), \
             patch.object(Path, "read_bytes", side_effect=[original, changed]):
            with self.assertRaisesRegex(gates.EvidenceUnmet, "changed during replay"):
                gates._validate_resolver_network(retained)


class ResolverNetworkNativePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = os.environ.get("CRABC_RESOLVER_NETWORK_TEST_REPORT")
        if not report:
            raise unittest.SkipTest("set CRABC_RESOLVER_NETWORK_TEST_REPORT to a fresh native resolver receipt")
        cls.root = Path(os.environ.get("CRABC_RESOLVER_NETWORK_TEST_ROOT", "/workspace"))
        document = json.loads(Path(report).read_text(encoding="utf-8"))
        cls.retained = cls.root / Path(document["state_root"]).relative_to("/workspace") / "report.json"

    def test_real_receipt_replays_under_the_qualification_environment(self):
        import run_qualification_manifest as runner

        environment = runner.controlled_environment()
        with patch.dict(os.environ, environment, clear=True), patch.object(gates, "ROOT", self.root):
            report = gates._validate_resolver_network(self.retained)
            self.assertTrue(report["passed"])
            self.assertEqual(os.environ["PATH"], environment["PATH"])


class CheckedInGateRegistryTests(unittest.TestCase):
    def test_every_registered_reader_names_a_current_ledger_command_of_its_gate(self):
        families = gates.load_families()
        for (gate, command), registered in gates.READERS.items():
            with self.subTest(gate=gate, command=command):
                self.assertIn(gate, gates.CHAIN)
                self.assertEqual((registered.gate, registered.command), (gate, command))
                self.assertIn(command, [entry["command"] for entry in families[gate]["native_evidence"]])
                self.assertIn(registered.kind, {"publication", "report", "ledger", "execution"})
                if registered.kind == "publication":
                    self.assertEqual(gates.PUBLICATIONS[registered.source].gate, gate)

    def test_host_view_has_one_row_per_ledger_evidence_entry_for_every_gate(self):
        families = gates.load_families()
        for result in gates.evaluate_chain(native=False):
            with self.subTest(gate=result["gate"]):
                self.assertFalse(result["passed"])
                evidence = [row for row in result["conditions"] if row["id"].startswith("evidence[")]
                self.assertEqual(
                    [row["command"] for row in evidence],
                    [entry["command"] for entry in families[result["gate"]]["native_evidence"]],
                )
                for row in evidence:
                    registered = (result["gate"], row["command"]) in gates.READERS
                    self.assertIs(row["met"], None if registered else False)

    def test_capability_accounting_names_each_incomplete_capability(self):
        completion = gates._capability_completion({})
        inventory = gates._import_compat("aarch64_parity_inventory").build_inventory()
        incomplete = sorted(row["id"] for row in inventory["capabilities"]
                            if row["contract_state"] != "implemented-foundation")
        self.assertIs(completion["met"], not incomplete)
        if incomplete:
            named = sorted(identifier for states in completion["detail"]["by_family"].values()
                           for identifiers in states.values() for identifier in identifiers)
            self.assertEqual(named, incomplete)


if __name__ == "__main__":
    unittest.main()
