"""Behavior tests for the one-command native x86 qualification candidate run."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import qualification_candidate as candidate  # noqa: E402
import qualification_gates as gates  # noqa: E402


SOURCE = {"revision": "r" * 40, "content_sha256": "c" * 64}


class PlanTests(unittest.TestCase):
    def test_families_run_in_ledger_dependency_order(self) -> None:
        steps = candidate.plan()
        rows = candidate._ledger_rows(ROOT)
        # Gate producers only publish; the chain step evaluates gates in order.
        first = {}
        for index, step in enumerate(steps):
            if step.family not in gates.CHAIN:
                first.setdefault(step.family, index)
        for family, index in first.items():
            for dependency in rows.get(family, {}).get("depends_on", []):
                if dependency in first:
                    self.assertLess(first[dependency], index, f"{dependency} must precede {family}")
        self.assertEqual([step.id for step in steps][-2:], ["qualification-chain", "parity-ledger"])

    def test_every_publication_and_attachment_names_a_registered_contract(self) -> None:
        steps = candidate.plan()
        for step in steps:
            if step.publishes is not None:
                gate, publication = step.publishes
                registered = gates.PUBLICATIONS[publication]
                self.assertEqual(registered.gate, gate)
                self.assertEqual(Path(step.outputs[0].fixed or "").name, registered.receipt_name, step.id)
        published = {step.id for step in steps if step.id.startswith("publish-")}
        self.assertIn("publish-resolver-network", published)
        self.assertEqual(published, {f"publish-{publication}" for publication in gates.PUBLICATIONS})
        context = candidate.Context(ROOT, ROOT / ".work/x86_64/candidate-test", {}, dry_run=True)
        attached = candidate.attachments(ROOT, context, steps)
        self.assertEqual({record["family"] for record in attached},
                         {"libc.posix-runtime", "libc.pthread-tls", "libc.resolver", "libc.c-abi-compat"})

    def test_dry_run_resolves_placeholders_and_names_blockers_without_writing(self) -> None:
        work = ROOT / ".work/x86_64/candidate-dry-run-test"
        report = candidate.dry_run(ROOT, work, {})
        self.assertFalse(work.exists())
        by_step = {step["step"]: step for step in report["steps"]}
        self.assertIn("<static-products:preparation>", by_step["posix-family"]["argv"])
        self.assertIn("--report", by_step["text-family"]["argv"])
        self.assertIn("<input:rust_std_lto.provider_vendor>", by_step["rust-std-lto"]["argv"])
        self.assertTrue(any("rust_std_lto is not supplied" in blocker for blocker in report["preflight_blockers"]))
        prefix = candidate.dry_run(ROOT, work, {}, "posix-admission")
        self.assertEqual(prefix["steps"][-1]["step"], "posix-admission")
        self.assertFalse(any("rust_std_lto" in blocker for blocker in prefix["preflight_blockers"]))

    def test_lua_consumers_receive_the_existing_cohort_and_explicit_reports(self) -> None:
        work = ROOT / ".work/x86_64/candidate-lua-cohort-test"
        report = candidate.dry_run(ROOT, work, {})
        steps = {step["step"]: step["argv"] for step in report["steps"]}
        for name in ("lua-static", "lua-dynamic"):
            self.assertIn("--cohort-checkout", steps[name])
            self.assertIn("--archive-seed", steps[name])
        self.assertIn("<static-products:preparation>", steps["lua-static"])
        self.assertIn("<dynamic-products:qualification>", steps["lua-dynamic"])
        self.assertIn("<lua-static:report>", steps["lua-admission"])
        self.assertIn("<lua-dynamic:report>", steps["lua-admission"])

    def test_dynamic_cohort_is_planned_below_candidate_work(self) -> None:
        work = ROOT / ".work/x86_64/candidate-durable-cohort-test"
        report = candidate.dry_run(ROOT, work, {}, "dynamic-products")
        dynamic = report["steps"][-1]
        self.assertEqual(dynamic["argv"], ["./scripts/dev-x86_64.sh", "materialized-dynamic-sysroot",
                                           "--work", ".work/x86_64/candidate-durable-cohort-test/out/dynamic"])
        self.assertEqual(dynamic["outputs"],
                         [".work/x86_64/candidate-durable-cohort-test/out/dynamic/qualification.json"])


class ExecutionTests(unittest.TestCase):
    """Run the real plan against a runner that fakes each producer's outputs."""

    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="candidate-test.", dir=ROOT / ".work"))
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "compat/x86_64").mkdir(parents=True)
        shutil.copy(ROOT / "compat/x86_64/parity.toml", self.root / "compat/x86_64/parity.toml")
        (self.root / ".work/x86_64").mkdir(parents=True)
        self.work = self.root / ".work/x86_64/run"
        self.calls: list[str] = []
        self.fail: set[str] = set()
        self.inputs = {"lua_source_build": {"archive_seed": "lua.tar.gz"}, "rust_std_lto": {"provider_vendor": "v", "dependency_vendor": "d"},
                       "performance_release": {key: "x" for key in candidate.INPUT_KEYS["performance_release"]}}
        patcher = mock.patch.object(candidate, "preflight", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)
        products = mock.patch.object(candidate, "_validate_products", create=True)
        products.start()
        self.addCleanup(products.stop)

    def _runner(self, argv: list[str], stdout: Path, stderr: Path) -> int:
        identifier = stdout.parent.name.split("-", 1)[1]
        self.calls.append(identifier)
        step = next(step for step in candidate.plan() if step.id == identifier)
        context = candidate.Context(self.root, self.work, self.inputs, dry_run=True)
        printed = []
        if identifier in self.fail:
            stdout.write_text("", encoding="utf-8")
            stderr.write_text("simulated failure\n", encoding="utf-8")
            return 1
        for output in step.outputs:
            if output.fixed is not None:
                path = self.root / context.template(output.fixed)
            elif output.glob is not None:
                path = self.root / context.template(output.glob).replace("*", "x")
            else:
                path = self.root / ".work/x86_64/tmp" / identifier / (output.printed or "")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"step": identifier}), encoding="utf-8")
            printed.append(f"{identifier} evidence: /workspace/{path.relative_to(self.root).as_posix()}")
        stdout.write_text("\n".join(printed) + "\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return 0

    def _execute(self, **keywords: object) -> dict[str, object]:
        return candidate.execute(self.root, self.work, self.inputs, runner=self._runner, source=SOURCE, **keywords)

    def test_complete_run_writes_one_summary_and_a_restart_skips_every_step(self) -> None:
        summary = self._execute()
        self.assertTrue(summary["complete"], summary.get("error"))
        steps = [step.id for step in candidate.plan() if step.internal is None]
        self.assertEqual(self.calls, steps)
        written = json.loads((self.work / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(written["complete"], True)
        resolver = next(record for record in written["steps"] if record["step"] == "resolver-family")
        self.assertEqual(resolver["outputs"]["network"],
                         ".work/x86_64/run/out/resolver-family/network/run-x/report.json")
        publish = next(record for record in written["steps"] if record["step"] == "publish-resolver-network")
        self.assertEqual(publish["status"], "complete")
        request = json.loads((self.work / "out/loader-family/request.json").read_text(encoding="utf-8"))
        self.assertEqual(request["qualification"], ".work/x86_64/run/out/dynamic/qualification.json")

        self.calls.clear()
        again = self._execute()
        self.assertTrue(again["complete"])
        self.assertEqual(self.calls, [])
        self.assertTrue(all(record.get("resumed") for record in again["steps"]))

    def test_dynamic_cohort_receipt_survives_tmp_cleanup(self) -> None:
        summary = self._execute(through="dynamic-products")
        self.assertNotIn("error", summary)
        dynamic = next(record for record in summary["steps"] if record["step"] == "dynamic-products")
        receipt = self.root / dynamic["outputs"]["qualification"]
        self.assertEqual(receipt, self.work / "out/dynamic/qualification.json")
        temporary = self.root / ".work/x86_64/tmp"
        shutil.rmtree(temporary, ignore_errors=True)
        self.assertTrue(receipt.is_file())
        self.calls.clear()
        resumed = self._execute(through="dynamic-products")
        self.assertNotIn("error", resumed)
        self.assertEqual(self.calls, [])

    def test_printed_receipt_is_discovered_after_large_json_diagnostics(self) -> None:
        step = next(step for step in candidate.plan()
                    if len(step.outputs) == 1 and step.outputs[0].printed is not None
                    and step.outputs[0].fixed is None and step.outputs[0].glob is None)
        output = step.outputs[0]
        receipt = self.root / ".work/x86_64/tmp/leaf" / output.printed
        receipt.parent.mkdir(parents=True)
        receipt.write_text("{}\n", encoding="utf-8")
        printed_path = "/workspace/" + receipt.relative_to(self.root).as_posix()
        diagnostic = json.dumps({"product": printed_path, "details": "x" * 5000}, separators=(",", ":"))
        stdout = diagnostic + "\nretained evidence: " + printed_path + "\n"
        context = candidate.Context(self.root, self.work, self.inputs)
        self.assertEqual(candidate._discover(self.root, context, step, stdout),
                         {output.name: receipt.relative_to(self.root).as_posix()})

    def test_failure_stops_closed_and_a_restart_resumes_from_the_failed_step(self) -> None:
        self.fail = {"pthread-family"}
        summary = self._execute()
        self.assertFalse(summary["complete"])
        self.assertIn("pthread-family failed", summary["error"])
        self.assertEqual(summary["steps"][-1]["status"], "failed")
        self.assertIn("text-family", summary["not_run"])
        self.assertEqual(self.calls[-1], "pthread-family")

        self.fail = set()
        self.calls.clear()
        resumed = self._execute()
        self.assertTrue(resumed["complete"], resumed.get("error"))
        self.assertEqual(self.calls[0], "pthread-family")
        self.assertNotIn("posix-native", self.calls)
        failed = [path.name for path in (self.work / "steps").iterdir() if ".failed-" in path.name]
        self.assertEqual(len(failed), 1)

    def test_changed_output_or_another_revision_fails_closed(self) -> None:
        self.assertTrue(self._execute(through="posix-family")["steps"])
        (self.work / "out/posix-family/execution.json").write_text("changed", encoding="utf-8")
        summary = self._execute(through="posix-native")
        self.assertIn("changed after completion", summary["error"])
        with self.assertRaisesRegex(candidate.CandidateError, "another source revision"):
            candidate.execute(self.root, self.work, self.inputs, runner=self._runner,
                              source={**SOURCE, "revision": "o" * 40})

    def test_restart_rejects_changed_inputs_before_reusing_steps(self) -> None:
        self._execute(through="static-products")
        self.inputs["rust_std_lto"]["provider_vendor"] = "different-vendor"
        with self.assertRaisesRegex(candidate.CandidateError, "candidate inputs or environment"):
            self._execute(through="static-products")

    def test_restart_rejects_replaced_input_at_the_same_path(self) -> None:
        vendor = self.root / ".work/vendor"
        vendor.mkdir()
        (vendor / "crate.rs").write_text("original")
        self.inputs["rust_std_lto"]["provider_vendor"] = ".work/vendor"
        self._execute(through="static-products")
        (vendor / "crate.rs").write_text("changed")
        with self.assertRaisesRegex(candidate.CandidateError, "candidate inputs or environment"):
            self._execute(through="static-products")

    def test_restart_rejects_changed_completed_invocation(self) -> None:
        self._execute(through="static-products")
        path = self.work / "steps/00-static-products/record.json"
        record = json.loads(path.read_text())
        record["argv"].append("--different-backend")
        path.write_text(json.dumps(record))
        summary = self._execute(through="static-products")
        self.assertIn("invocation changed", summary["error"])
        self.assertEqual(self.calls, ["static-products"])

    def test_resume_revalidates_live_product_payload(self) -> None:
        self._execute(through="dynamic-products")
        self.calls.clear()
        with mock.patch.object(candidate, "_validate_products",
                               side_effect=candidate.CandidateError("retained payload changed")):
            summary = self._execute(through="dynamic-products")
        self.assertIn("retained payload changed", summary["error"])
        self.assertEqual(self.calls, [])

    def test_resume_rejects_output_symlink_even_when_bytes_match(self) -> None:
        self._execute(through="posix-family")
        path = self.work / "out/posix-family/execution.json"
        saved = path.with_name("saved.json")
        path.rename(saved)
        path.symlink_to(saved)
        summary = self._execute(through="posix-family")
        self.assertIn("physical checkout .work file", summary["error"])

    def test_prefix_is_never_reported_complete(self) -> None:
        summary = self._execute(through="static-products")
        self.assertFalse(summary["complete"])
        self.assertNotIn("error", summary)
        self.assertEqual(self.calls, ["static-products"])


class AttachmentTests(unittest.TestCase):
    def test_a_row_naming_another_receipt_is_a_preflight_blocker(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            root = Path(temporary)
            (root / "compat/x86_64").mkdir(parents=True)
            text = (ROOT / "compat/x86_64/parity.toml").read_text(encoding="utf-8")
            command = ('command = "./scripts/dev-x86_64.sh owned-c-abi-compat-family --static-preparation FILE '
                       '--dynamic-qualification FILE --output NEW_DIR"')
            self.assertEqual(text.count(command), 1)
            (root / "compat/x86_64/parity.toml").write_text(
                text.replace(command, command + ', receipt = ".work/x86_64/elsewhere/assessment.json"'),
                encoding="utf-8")
            context = candidate.Context(root, root / ".work/x86_64/run", {}, dry_run=True)
            records = {record["family"]: record for record in candidate.attachments(root, context, candidate.plan())}
            self.assertEqual(records["libc.c-abi-compat"]["state"], "mismatch")
            self.assertEqual(records["libc.resolver"]["state"], "unattached")
            blockers = candidate.preflight(root, context, candidate.plan())
            self.assertTrue(any("elsewhere/assessment.json" in blocker for blocker in blockers))


class DynamicWorkPathTests(unittest.TestCase):
    def test_candidate_work_rejects_existing_symlink(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            parent = Path(temporary)
            target = parent / "physical"
            target.mkdir()
            link = parent / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(candidate.CandidateError, "candidate --work must be physical"):
                candidate._work(ROOT, link)

    def test_new_cohort_rejects_existing_symlink_and_escape_paths_before_build(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="materialized-paths.", dir=scratch) as temporary:
            parent = Path(temporary)
            (parent / "existing").mkdir()
            (parent / "physical").mkdir()
            (parent / "link").symlink_to(parent / "physical", target_is_directory=True)
            paths = (parent / "existing", parent / "link" / "new", parent / "../../../escaped")
            for path in paths:
                with self.subTest(path=path):
                    result = subprocess.run(
                        ["bash", str(ROOT / "compat/x86_64/run_materialized_dynamic_sysroot.sh"),
                         "--work", str(path)], cwd=ROOT,
                        env={**os.environ, "TMPDIR": str(scratch)},
                        capture_output=True, text=True, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("new physical checkout .work directory", result.stderr)
                    self.assertFalse((parent / "new").exists())


if __name__ == "__main__":
    unittest.main()
