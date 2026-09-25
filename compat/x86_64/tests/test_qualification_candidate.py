"""Behavior tests for the one-command native x86 qualification candidate run."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
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
        self.inputs = {"rust_std_lto": {"provider_vendor": "v", "dependency_vendor": "d"},
                       "performance_release": {key: "x" for key in candidate.INPUT_KEYS["performance_release"]}}
        patcher = mock.patch.object(candidate, "preflight", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

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
            elif identifier == "dynamic-products":
                path = self.root / ".work/x86_64/tmp/materialized-dynamic.test/qualification.json"
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
        self.assertEqual(request["qualification"], ".work/x86_64/tmp/materialized-dynamic.test/qualification.json")

        self.calls.clear()
        again = self._execute()
        self.assertTrue(again["complete"])
        self.assertEqual(self.calls, [])
        self.assertTrue(all(record.get("resumed") for record in again["steps"]))

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


if __name__ == "__main__":
    unittest.main()
