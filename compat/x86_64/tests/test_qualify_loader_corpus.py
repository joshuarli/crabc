"""Fail-closed contracts for the compat.loader-corpus qualification case."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import qualify_loader_corpus as qualify

SOURCE = {"revision": "a" * 40, "source_sha256": "b" * 64}


def ledger_report(open_families: set[str]) -> dict[str, object]:
    with (ROOT / "compat/x86_64/parity.toml").open("rb") as stream:
        families = tomllib.load(stream)["family"]
    return {"families": [
        {"id": family["id"], "dependencies": list(family["depends_on"]),
         "status": "planned" if family["id"] in open_families else "foundation-verified"}
        for family in families
    ]}


class LoaderCorpusCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/test-qualify-loader-corpus"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)

    def run_main(self) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = qualify.main([])
        return status, stdout.getvalue(), stderr.getvalue()

    def forbid_work(self) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        for owner, name in (
            (qualify.PRODUCT, "load_publication"),
            (qualify.INVENTORY, "collect"),
            (qualify.LOADER_FAMILY, "execute"),
            (qualify.LOADER_FAMILY, "validate_receipt"),
        ):
            stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError(f"{name} must not start")))
        return stack

    def test_open_prerequisites_are_named_before_any_cohort_or_inventory_work(self) -> None:
        report = ledger_report({"ldso.dynamic-runtime", "compat.abi-differential", "sysroot.owned-artifact"})
        with (
            self.forbid_work(),
            mock.patch.object(qualify.CASE, "clean_source_identity", return_value=SOURCE),
            mock.patch.object(qualify.CASE.CAMPAIGN, "build_report", return_value=report),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(qualify.PASS_MARKER, stdout)
        self.assertIn(
            "compat.loader-corpus prerequisites are not foundation-verified: "
            "ldso.dynamic-runtime, sysroot.owned-artifact, compat.abi-differential\n",
            stderr,
        )

    def test_dirty_source_refuses_before_prerequisites(self) -> None:
        with (
            self.forbid_work(),
            mock.patch.object(
                qualify.CASE.PRODUCT, "require_clean_source",
                side_effect=qualify.CASE.PRODUCT.QualificationError("qualification publication requires clean source"),
            ),
            mock.patch.object(qualify.CASE.CAMPAIGN, "build_report", side_effect=AssertionError("prerequisites read")),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(qualify.PASS_MARKER, stdout)
        self.assertIn("clean source", stderr)

    def closed(self) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(qualify.CASE, "clean_source_identity", return_value=SOURCE))
        stack.enter_context(mock.patch.object(qualify.CASE.CAMPAIGN, "build_report", return_value=ledger_report(set())))
        return stack

    def test_missing_current_cohort_publication_refuses_before_inventory(self) -> None:
        with self.closed(), self.forbid_work() as forbidden:
            forbidden.enter_context(mock.patch.object(qualify.PRODUCT, "load_publication", return_value=None))
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(qualify.PASS_MARKER, stdout)
        self.assertIn("no current qualified dynamic cohort", stderr)
        self.assertIn("materialized-dynamic-sysroot", stderr)

    def test_changed_frozen_rosters_refuse_before_the_cohort(self) -> None:
        roster = qualify.LOADER_FAMILY.load_roster()
        shortened = json.loads(json.dumps(roster))
        for row in shortened["required"]:
            if row["id"] == "synthetic-loader-catalog":
                row["synthetic_cases"] = row["synthetic_cases"][:-1]
        with self.closed(), self.forbid_work():
            with mock.patch.object(qualify.LOADER_FAMILY, "load_roster", return_value=shortened):
                status, _stdout, stderr = self.run_main()
            self.assertEqual(status, 1)
            self.assertIn("synthetic loader roster differs from the frozen ldso gate", stderr)
            real_git = qualify.git

            def changed_workloads(*arguments: str) -> str:
                if arguments[0] == "hash-object":
                    return "0" * 40
                return real_git(*arguments)

            with mock.patch.object(qualify, "git", side_effect=changed_workloads):
                status, _stdout, stderr = self.run_main()
            self.assertEqual(status, 1)
            self.assertIn("compat/corpus/manifest.toml differs from the frozen baseline commit", stderr)

    def test_closed_case_inventories_every_cohort_product_then_replays_the_family_receipt(self) -> None:
        cohort_work = self.scratch / "cohort"
        cohort_work.mkdir()
        calls: list[object] = []

        def collect(product: Path, oracle: Path, output: Path, readelf: Path) -> dict[str, object]:
            calls.append(("inventory", product.name))
            self.assertEqual((product.parent, oracle, readelf), (cohort_work, qualify.MUSL_ROOT, qualify.READELF))
            self.assertFalse(output.exists())
            return {}

        def execute(root: Path, run: Path) -> Path:
            calls.append("family")
            request = json.loads((run / "request.json").read_text(encoding="utf-8"))
            self.assertEqual(request["qualification"], (cohort_work / "qualification.json").relative_to(ROOT).as_posix())
            self.assertEqual(set(request["inventories"]), set(qualify.LOADER_FAMILY.PRODUCTS))
            for product, row in request["inventories"].items():
                self.assertEqual(row["receipt"], (run / "inventories" / product / "inventory.json").relative_to(ROOT).as_posix())
                self.assertTrue(row["oracle_capture"].endswith(f"{product}/inventory.json.inputs/oracle-capture.json"))
                self.assertTrue(row["readelf_capture"].endswith(f"{product}/inventory.json.inputs/readelf-capture.json"))
            return run / "receipt.json"

        def validate(root: Path, receipt: Path) -> dict[str, object]:
            calls.append("replay")
            return {}

        publication = {"work": cohort_work.relative_to(ROOT).as_posix(), "products": {p: "0" * 64 for p in qualify.LOADER_FAMILY.PRODUCTS}}
        with (
            self.closed(),
            mock.patch.object(qualify, "WORK_PARENT", self.scratch / "runs"),
            mock.patch.object(qualify.PRODUCT, "load_publication", return_value=publication),
            mock.patch.object(qualify.INVENTORY, "collect", side_effect=collect),
            mock.patch.object(qualify.LOADER_FAMILY, "execute", side_effect=execute),
            mock.patch.object(qualify.LOADER_FAMILY, "validate_receipt", side_effect=validate),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 0, stderr)
        self.assertEqual(calls, [("inventory", "installed"), ("inventory", "second"), ("inventory", "extracted"), "family", "replay"])
        lines = [line for line in stdout.splitlines() if line]
        self.assertEqual(lines.count(qualify.PASS_MARKER), 1)
        self.assertEqual(lines[-1], qualify.PASS_MARKER)
        summary = json.loads(lines[0])
        self.assertEqual(summary["rosters"]["synthetic_cases"], 21)
        self.assertEqual(summary["rosters"]["package_cases"], 34)

    def test_source_change_during_the_case_is_rejected(self) -> None:
        identities = iter((SOURCE, {**SOURCE, "source_sha256": "c" * 64}))
        publication = {"work": ".work/x86_64/cohort", "products": {p: "0" * 64 for p in qualify.LOADER_FAMILY.PRODUCTS}}
        with (
            mock.patch.object(qualify.CASE, "clean_source_identity", side_effect=lambda: next(identities)),
            mock.patch.object(qualify.CASE.CAMPAIGN, "build_report", return_value=ledger_report(set())),
            mock.patch.object(qualify, "WORK_PARENT", self.scratch / "runs"),
            mock.patch.object(qualify.PRODUCT, "load_publication", return_value=publication),
            mock.patch.object(qualify.INVENTORY, "collect", return_value={}),
            mock.patch.object(qualify.LOADER_FAMILY, "execute", side_effect=lambda root, run: run / "receipt.json"),
            mock.patch.object(qualify.LOADER_FAMILY, "validate_receipt", return_value={}),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(qualify.PASS_MARKER, stdout)
        self.assertIn("source changed", stderr)

    def test_frozen_synthetic_roster_is_the_frozen_ldso_gate_choice_list(self) -> None:
        source = subprocess.run(
            ["git", "show", f"{qualify.frozen_commit()}:compat/ldso/run.py"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True,
        ).stdout
        choices = re.search(r'"--case",\s*action="append",\s*choices=\((.*?)\),', source, re.S)
        assert choices is not None
        self.assertEqual(tuple(re.findall(r'"([a-z0-9-]+)"', choices.group(1))), qualify.FROZEN_SYNTHETIC_CASES)

    def test_runner_starts_under_the_scrubbed_qualification_environment(self) -> None:
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}
        completed = subprocess.run(
            [sys.executable, "-B", str(ROOT / "compat/x86_64/qualify_loader_corpus.py"), "--help"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))


class LoaderCorpusDeclarationTests(unittest.TestCase):
    def test_checked_in_gate_pins_only_this_case_and_reruns_every_predecessor(self) -> None:
        import generate_qualification_manifest as manifest
        import run_qualification_manifest as prefix

        report = manifest.load_contract()
        gate = {row["id"]: row for row in report["promotion_chain"]}["compat.loader-corpus"]
        self.assertEqual(gate["state"], "ready")
        cases = manifest.load_json(ROOT / gate["case_manifest"], "loader-corpus cases")["cases"]
        self.assertEqual(
            [(case["id"], case["command"], case["expected_stdout_line"]) for case in cases],
            [("loader-corpus-frozen-roster", ["python3", "compat/x86_64/qualify_loader_corpus.py"], qualify.PASS_MARKER)],
        )
        self.assertFalse(report["promotion_ready"])
        # The gate never runs alone: its prefix re-executes every ordered
        # predecessor in the same invocation, and each fails closed on its own
        # unmet conditions until the prerequisite families verify.
        selected = prefix.select_promotion_prefix(report, "compat.loader-corpus")
        self.assertEqual([row["id"] for row in selected], list(manifest.CHAIN[:4]))


if __name__ == "__main__":
    unittest.main()
