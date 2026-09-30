#!/usr/bin/env python3
"""Executable isolation contracts for the native Lua static dispatcher."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "compat/lua/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_lua_dispatch_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NativeStaticDispatcherTests(unittest.TestCase):
    """Exercise isolated producer state and latest-report publication directly."""

    scratch_root = ROOT / ".work" / "lua-static-dispatcher-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="dispatcher-", dir=self.scratch_root))
        self.parent = self.temporary / "state-parent"
        self.latest = self.temporary / "reports" / "x86_64-static-latest.json"
        self.builder = self.temporary / "fake-builder.py"
        self.builder.write_text(
            textwrap.dedent(
                """\
                from pathlib import Path
                import sys

                output = Path(sys.argv[sys.argv.index("--output") + 1])
                output.mkdir(parents=True, exist_ok=False)
                (output / "producer.txt").write_text("private producer state\\n", encoding="utf-8")
                """
            ),
            encoding="utf-8",
        )
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        if self.temporary.exists() and not self.temporary.is_symlink():
            shutil.rmtree(self.temporary, ignore_errors=True)

    @staticmethod
    def passing_runner(args: object) -> dict[str, object]:
        report = getattr(args, "report")
        sysroot = getattr(args, "sysroot")
        assert (sysroot / "producer.txt").is_file()
        (report.parent / "runner.txt").write_text("private runner state\n", encoding="utf-8")
        return {"schema_version": 2, "runner": "fake-static-runner", "result": "pass", "passed": True}

    @staticmethod
    def failing_runner(args: object) -> dict[str, object]:
        report = getattr(args, "report")
        (report.parent / "runner.txt").write_text("private failed runner state\n", encoding="utf-8")
        return {"schema_version": 2, "runner": "fake-static-runner", "result": "fail", "passed": False}

    def dispatch(self, runner: object) -> tuple[dict[str, object], Path, Path | None]:
        return RUNNER.run_x86_static_dispatch(
            jobs=2,
            timeout=5.0,
            state_parent=self.parent,
            latest_report=self.latest,
            builder=self.builder,
            static_runner=runner,
        )

    def test_published_latest_report_is_readable_by_other_users(self) -> None:
        # The container publishes as root; host readers must still read it.
        private = self.temporary / "private-report.json"
        private.write_text("{}\n", encoding="utf-8")
        private.chmod(0o600)
        latest = RUNNER.publish_x86_static_dispatch_report(private, self.latest)
        self.assertEqual(latest.stat().st_mode & 0o777, 0o644)
        self.assertEqual(latest.read_text(encoding="utf-8"), "{}\n")

    def test_two_concurrent_invocations_get_distinct_state_and_valid_latest_report(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            completed = list(executor.map(lambda _: self.dispatch(self.passing_runner), range(2)))
        states = {report_path.parent for _, report_path, _ in completed}
        self.assertEqual(len(states), 2)
        parent = self.parent.resolve()
        for report, report_path, latest in completed:
            state = report_path.parent
            self.assertTrue(state.is_relative_to(parent))
            self.assertTrue((state / "sysroot/producer.txt").is_file())
            self.assertTrue((state / "runner.txt").is_file())
            self.assertEqual(report["passed"], True)
            self.assertEqual(report["dispatcher"]["state_root"], str(state))
            self.assertEqual(json.loads(report_path.read_text())["passed"], True)
            self.assertEqual(latest, self.latest)
        self.assertEqual(json.loads(self.latest.read_text())["passed"], True)

    def test_producer_keeps_its_own_import_path_under_a_safe_path_caller(self) -> None:
        # The ordered qualification runner starts its Lua case with
        # PYTHONSAFEPATH=1. Repository producers import script-directory
        # siblings, so that caller policy must not leak into their children.
        (self.temporary / "producer_sibling.py").write_text("MARKER = 'sibling'\n", encoding="utf-8")
        self.builder.write_text(
            "import producer_sibling\n" + self.builder.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"PYTHONSAFEPATH": "1", "PYTHONPATH": str(self.temporary / "absent")}):
            report, _report_path, latest = self.dispatch(self.passing_runner)
        producer = report["dispatcher"]["producer"]
        self.assertEqual(producer["status"], 0, producer["stderr"]["text"])
        self.assertEqual(report["passed"], True)
        self.assertEqual(latest, self.latest)

    def test_failed_invocation_retains_private_report_without_replacing_latest(self) -> None:
        original = b'{"passed":true,"result":"pass","sentinel":"prior"}\n'
        self.latest.parent.mkdir(parents=True, exist_ok=True)
        self.latest.write_bytes(original)
        report, report_path, published = self.dispatch(self.failing_runner)
        self.assertIsNone(published)
        self.assertEqual(report["passed"], False)
        self.assertEqual(self.latest.read_bytes(), original)
        self.assertTrue((report_path.parent / "sysroot/producer.txt").is_file())
        self.assertEqual(json.loads(report_path.read_text())["result"], "fail")

    def test_failed_producer_still_retains_its_private_authoritative_report(self) -> None:
        original = b'{"passed":true,"result":"pass","sentinel":"prior"}\n'
        self.latest.parent.mkdir(parents=True, exist_ok=True)
        self.latest.write_bytes(original)
        report, report_path, published = RUNNER.run_x86_static_dispatch(
            jobs=2,
            timeout=5.0,
            state_parent=self.parent,
            latest_report=self.latest,
            builder=self.temporary / "missing-builder.py",
            static_runner=self.passing_runner,
        )
        self.assertIsNone(published)
        self.assertEqual(report["passed"], False)
        self.assertIsNone(report["dispatcher"]["producer"])
        self.assertIn("native Lua static sysroot builder is absent", str(report["error"]))
        self.assertEqual(self.latest.read_bytes(), original)
        self.assertEqual(json.loads(report_path.read_text())["result"], "fail")


DISPATCH_SPEC = importlib.util.spec_from_file_location(
    "crabc_lua_static_entry", ROOT / "compat/lua/run_x86_static_dispatch.py")
assert DISPATCH_SPEC is not None and DISPATCH_SPEC.loader is not None
DISPATCH = importlib.util.module_from_spec(DISPATCH_SPEC)
DISPATCH_SPEC.loader.exec_module(DISPATCH)


class SuppliedStaticDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        parent = ROOT / ".work/lua-static-supplied-tests"
        parent.mkdir(parents=True, exist_ok=True)
        self.state = Path(tempfile.mkdtemp(dir=parent))
        self.addCleanup(shutil.rmtree, self.state)
        self.cohort = self.state / "cohort"
        self.products = self.cohort / ".work/products"
        self.products.mkdir(parents=True)
        reader = self.cohort / "compat/x86_64/owned_posix_static_products.py"
        reader.parent.mkdir(parents=True)
        reader.write_text("", encoding="utf-8")
        records = {}
        roots = []
        for label in DISPATCH.SUPPLIED_ROOTS:
            root = self.products / label
            root.mkdir()
            roots.append(root)
            records[label] = {"path": str(root.relative_to(self.cohort))}
        self.receipt = self.cohort / ".work/preparation.json"
        self.receipt.write_text(json.dumps({"products": records, "source": {"revision": "owned"}}))
        seed = self.state / "lua.tar.gz"
        seed.write_bytes(b"authenticated seed")
        self.arguments = DISPATCH.parse_args([
            "--cohort-checkout", str(self.cohort), "--static-preparation", str(self.receipt),
            "--installed-sysroot", str(roots[0]), "--rebuilt-sysroot", str(roots[1]),
            "--extracted-sysroot", str(roots[2]), "--archive-seed", str(seed),
            "--work-root", str(self.state / "runs")])

    def test_partial_supplied_arguments_fail_before_dispatch(self) -> None:
        with self.assertRaises(SystemExit), mock.patch.object(DISPATCH.LUA, "run_x86_static_dispatch") as producer:
            DISPATCH.parse_args(["--installed-sysroot", str(self.products / "primary")])
        producer.assert_not_called()

    def test_wrong_or_missing_root_is_rejected_before_owner_reader(self) -> None:
        for selected in (self.products / "wrong", self.products):
            with self.subTest(selected=selected), mock.patch.object(DISPATCH.LUA, "command_record") as reader:
                self.arguments.installed_sysroot = selected
                with self.assertRaises(DISPATCH.LUA.RunnerError):
                    DISPATCH.supplied_products(self.arguments, self.state)
                reader.assert_not_called()

    def test_incomplete_receipt_product_roster_is_rejected(self) -> None:
        record = json.loads(self.receipt.read_text())
        del record["products"]["reproduction"]
        self.receipt.write_text(json.dumps(record))
        with self.assertRaises(DISPATCH.LUA.RunnerError), mock.patch.object(DISPATCH.LUA, "command_record") as reader:
            DISPATCH.supplied_products(self.arguments, self.state)
        reader.assert_not_called()

    def test_owner_source_proof_failure_is_not_admitted(self) -> None:
        rejected = {"status": 1, "stderr": {"text": "source identity mismatch"}}
        with mock.patch.object(DISPATCH.LUA, "owned_static_sysroot"), \
                mock.patch.object(DISPATCH.LUA, "command_record", return_value=rejected):
            with self.assertRaises(DISPATCH.LUA.RunnerError):
                DISPATCH.supplied_products(self.arguments, self.state)

    def test_retained_reader_rejects_missing_or_extra_product(self) -> None:
        report = self.state / "retained.json"
        self.arguments.read = report
        for products in ({"primary": {}}, {name: {} for name in (*DISPATCH.SUPPLIED_ROOTS, "extra")}):
            with self.subTest(products=products):
                report.write_text(json.dumps({"passed": True, "result": "pass", "products": products}))
                with self.assertRaises(DISPATCH.LUA.RunnerError):
                    DISPATCH.read_supplied(self.arguments)

    def test_retained_reader_rejects_stale_consumer_source(self) -> None:
        report = self.state / "retained.json"
        self.arguments.read = report
        report.write_text(json.dumps({"passed": True, "result": "pass",
                                     "products": {name: {} for name in DISPATCH.SUPPLIED_ROOTS},
                                     "consumer_source": {"revision": "previous"}}))
        with mock.patch.object(DISPATCH.LUA, "current_source_identity", return_value={"revision": "current"}), \
                self.assertRaises(DISPATCH.LUA.RunnerError):
            DISPATCH.read_supplied(self.arguments)


    def test_consistent_failed_workload_cannot_acquire_a_passing_receipt(self) -> None:
        import source_build_admission as admission
        seed = self.arguments.archive_seed
        artifact = {"artifact": DISPATCH.LUA.artifact_record(seed)}
        failed = DISPATCH.LUA.result_comparison(
            DISPATCH.LUA.ProcessResult(0, b"reference", b""),
            DISPATCH.LUA.ProcessResult(0, b"different", b""))
        row = {role: {"artifacts": {name: artifact for name in ("lua", "luac")}}
               for role in ("candidate", "reference")}
        row["workloads"] = {"source": failed, "bytecode": failed}
        source = {"revision": "consumer"}
        payload = json.loads(self.receipt.read_text())
        roots = {label: self.products / label for label in DISPATCH.SUPPLIED_ROOTS}
        report = {"passed": True, "result": "pass", "consumer_source": source,
                  "supplied": {"source": payload["source"],
                               "preparation": DISPATCH.LUA.artifact_record(self.receipt)},
                  "products": {label: {"passed": True, "environment": {
                      "sysroot_manifest": {}, "sysroot": str(root)},
                      "modes": {mode: row for mode in ("static-et-exec", "static-pie")}}
                      for label, root in roots.items()}}
        selected = self.state / "false-receipt.json"
        selected.write_text(json.dumps(report))
        self.arguments.read = selected
        with mock.patch.object(DISPATCH.LUA, "current_source_identity", return_value=source), \
                mock.patch.object(DISPATCH, "supplied_products", return_value=(payload, roots, {"status": 0})), \
                mock.patch.object(DISPATCH.LUA, "owned_static_sysroot", return_value=(None, None, None, {})), \
                mock.patch.object(DISPATCH.LUA, "static_elf_record", return_value=artifact), \
                mock.patch.object(admission, "validate_pinned_input"), \
                self.assertRaisesRegex(DISPATCH.LUA.RunnerError, "workload did not pass"):
            DISPATCH.read_supplied(self.arguments)


    def test_all_three_roots_receive_full_offline_modes_without_producer_or_publication(self) -> None:
        payload = json.loads(self.receipt.read_text())
        roots = {label: self.products / label for label in DISPATCH.SUPPLIED_ROOTS}
        calls = []
        def execute(arguments):
            calls.append(arguments)
            return {"passed": True, "result": "pass"}
        manifest = {"lua": {"version": "5.4.8", "sha256": DISPATCH.LUA.sha256_file(self.arguments.archive_seed)}}
        with mock.patch.object(DISPATCH.subprocess, "run", return_value=mock.Mock(stdout=b"")), \
                mock.patch.object(DISPATCH, "supplied_products", return_value=(payload, roots, {"status": 0})), \
                mock.patch.object(DISPATCH.LUA, "current_source_identity", return_value={"revision": "consumer"}), \
                mock.patch.object(DISPATCH.LUA, "load_manifest", return_value=manifest), \
                mock.patch.object(DISPATCH.LUA, "run_x86_static", side_effect=execute), \
                mock.patch.object(DISPATCH.LUA, "run_x86_static_dispatch") as producer, \
                mock.patch.object(DISPATCH.LUA, "publish_x86_static_dispatch_report") as publish:
            report, path = DISPATCH.run_supplied(self.arguments)
        self.assertTrue(report["passed"], report)
        self.assertEqual([args.sysroot for args in calls], list(roots.values()))
        self.assertTrue(all(args.mode is None and args.offline for args in calls))
        self.assertEqual(len({args.work_root for args in calls}), 3)
        self.assertTrue(path.is_file())
        producer.assert_not_called()
        publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
