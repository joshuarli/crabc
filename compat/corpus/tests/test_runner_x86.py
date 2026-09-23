#!/usr/bin/env python3
"""Observable contract tests for the finite native package corpus."""
from __future__ import annotations

import importlib.util
import io
import os
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_x86.py"
SPEC = importlib.util.spec_from_file_location("crabc_corpus_runner_x86", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NativeManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = RUNNER.load_manifest()

    def test_native_manifest_seals_the_unchanged_34_case_workload(self) -> None:
        with self.manifest.source_manifest.open("rb") as stream:
            source = tomllib.load(stream)
        expected = [
            {"id": case["id"], "tier": case["tier"], "package": case["package"], "path": case["path"], "argv": case["argv"],
             "stdin": case.get("stdin", ""), "setup": case.get("setup", []), "cwd": case.get("cwd", "/tmp"),
             "stateful": case.get("stateful", False), "requires_dt_relr": case.get("requires_dt_relr", False)}
            for case in source["cases"]
        ]
        actual = [
            {"id": case.id, "tier": case.tier, "package": case.package, "path": case.path, "argv": list(case.argv),
             "stdin": case.stdin.decode("utf-8"), "setup": [{"path": item.path, "contents": item.contents.decode("utf-8")} for item in case.setup],
             "cwd": case.cwd, "stateful": case.stateful, "requires_dt_relr": case.requires_dt_relr}
            for case in self.manifest.cases
        ]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 34)

    def test_native_archive_closure_and_version_deltas_are_finite(self) -> None:
        with self.manifest.source_manifest.open("rb") as stream:
            source_packages = tomllib.load(stream)["packages"]
        self.assertEqual(len(self.manifest.archive_roster), 59)
        self.assertEqual(self.manifest.excluded_archives, {"musl-1.2.6-r2.apk"})
        self.assertEqual(
            {name for name, version in self.manifest.direct_packages.items() if version != source_packages[list(self.manifest.direct_packages).index(name)]["version"]},
            {"gzip", "sqlite", "curl", "openssl", "openssh-client-default"},
        )

    def test_signed_index_repin_keeps_the_exact_archive_and_signature_boundary(self) -> None:
        self.assertEqual(
            self.manifest.index_sha256,
            "2331ad1c0df007c2da75983e14948919068e3b50336a6e2d14ffbb158c911c31",
        )
        self.assertEqual(len(self.manifest.archive_roster), 59)
        archive_dir = Path("/workspace/.work/owned-package-corpus/apks")
        index = Path("/workspace/.work/owned-package-corpus/index/APKINDEX.tar.gz")
        identity = {"directory": str(archive_dir), "index": {"path": str(index)}}
        success = type("Completed", (), {"returncode": 0, "stdout": b"OK\n", "stderr": b""})()
        with mock.patch.object(RUNNER, "input_identity", return_value=identity), \
             mock.patch.object(RUNNER, "apk_metadata", return_value={"pkgname": "other", "pkgver": "1"}), \
             mock.patch.object(RUNNER.subprocess, "run", return_value=success) as verify:
            RUNNER.verify_inputs(self.manifest, archive_dir, index)
        self.assertEqual(verify.call_count, 60)
        self.assertEqual(
            verify.call_args_list[-1].args[0],
            [str(RUNNER.APK), "--keys-dir", str(RUNNER.KEYS), "verify", str(index)],
        )

        def reject_index(argv, **_kwargs):
            return type("Completed", (), {
                "returncode": int(argv[-1] == str(index)), "stdout": b"", "stderr": b"bad signature",
            })()

        with mock.patch.object(RUNNER, "input_identity", return_value=identity), \
             mock.patch.object(RUNNER, "apk_metadata", return_value={"pkgname": "other", "pkgver": "1"}), \
             mock.patch.object(RUNNER.subprocess, "run", side_effect=reject_index):
            with self.assertRaisesRegex(RUNNER.CorpusError, "index signature verification failed"):
                RUNNER.verify_inputs(self.manifest, archive_dir, index)


class PrivatePayloadTests(unittest.TestCase):
    def test_created_evidence_parents_are_readable_without_changing_existing_private_parents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            boundary = Path(temporary) / ".work"
            boundary.mkdir()
            private = boundary / "existing"
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            with mock.patch.object(RUNNER, "PRIVATE_WORK_ROOT", boundary):
                work = RUNNER.private_campaign_parent(boundary / "new/campaign")
                RUNNER.prepare_report_destination(boundary / "reports/latest.json")
                RUNNER.private_campaign_parent(private)
            self.assertEqual(work.stat().st_mode & 0o777, 0o755)
            self.assertEqual(work.parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual((boundary / "reports").stat().st_mode & 0o777, 0o755)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)

    def test_retained_readability_preserves_the_execution_tree_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            directory = root / "private"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            output = directory / "output"
            output.write_bytes(b"state after application execution\n")
            output.chmod(0o600)
            before_retention = RUNNER.tree_sha256(root, "completed execution tree")

            modes = RUNNER.make_tree_readable(root)

            self.assertEqual(modes, {"private": 0o700, "private/output": 0o600})
            self.assertEqual(root.stat().st_mode & 0o777, 0o755)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            self.assertNotEqual(RUNNER.tree_sha256(root, "readable tree"), before_retention)
            self.assertEqual(RUNNER.tree_sha256(root, "retained execution tree", retention_modes=modes), before_retention)
            output.write_bytes(b"changed retained execution bytes\n")
            self.assertNotEqual(RUNNER.tree_sha256(root, "changed tree", retention_modes=modes), before_retention)

    def test_retention_modes_cannot_hide_unrelated_permission_or_path_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            data = root / "data"
            data.write_bytes(b"retained")
            data.chmod(0o644)
            (root / "alias").symlink_to("data")
            for modes in ({"../data": 0o600}, {"/data": 0o600}, {"missing": 0o600},
                          {"alias": 0o600}, {"data": 0o644}, {"data": True}, {"data": 0o700}):
                with self.subTest(modes=modes), self.assertRaises(RUNNER.CorpusError):
                    RUNNER.tree_sha256(root, "invalid retained tree", retention_modes=modes)

    def test_retention_does_not_follow_private_tree_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / "outside"
            outside.mkdir(mode=0o700)
            secret = outside / "secret"
            secret.write_bytes(b"unrelated")
            secret.chmod(0o600)
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            (root / "outside").symlink_to(outside, target_is_directory=True)
            before = RUNNER.tree_sha256(root, "symlink tree")

            self.assertEqual(RUNNER.make_tree_readable(root), {})

            self.assertEqual(outside.stat().st_mode & 0o777, 0o700)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertEqual(RUNNER.tree_sha256(root, "retained symlink tree", retention_modes={}), before)

    def test_archive_members_reject_traversal_before_extraction(self) -> None:
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.safe_archive_members(["../outside"])
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.safe_archive_members(["/outside"])

    def test_archive_roster_rejects_missing_and_unpinned_payloads(self) -> None:
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.require_exact_archive_roster(["one.apk"], ["one.apk", "two.apk"])
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.require_exact_archive_roster(["one.apk", "extra.apk"], ["one.apk"])

    def test_hardlink_targets_are_archive_root_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            archive = Path(temporary) / "payload.tar"
            with tarfile.open(archive, "w") as stream:
                info = tarfile.TarInfo("bin/tool")
                data = b"payload"
                info.size = len(data)
                import io
                stream.addfile(info, io.BytesIO(data))
                link = tarfile.TarInfo("usr/bin/tool")
                link.type = tarfile.LNKTYPE
                link.linkname = "bin/tool"
                stream.addfile(link)
            RUNNER.extract_archive(archive, root)
            self.assertEqual((root / "usr/bin/tool").read_bytes(), b"payload")

    def test_apk_metadata_accepts_the_signed_alpine_spacing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture-1.0-r0.apk"
            with tarfile.open(archive, "w:gz") as stream:
                metadata = b"pkgname = fixture\npkgver = 1.0-r0\narch = x86_64\n"
                info = tarfile.TarInfo(".PKGINFO")
                info.size = len(metadata)
                import io
                stream.addfile(info, io.BytesIO(metadata))
            self.assertEqual(RUNNER.apk_metadata(archive), {"pkgname": "fixture", "pkgver": "1.0-r0", "arch": "x86_64"})

    def test_apk_metadata_accepts_noarch_payloads_from_the_x86_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture-1.0-r0.apk"
            with tarfile.open(archive, "w:gz") as stream:
                metadata = b"pkgname = fixture\npkgver = 1.0-r0\narch = noarch\n"
                info = tarfile.TarInfo(".PKGINFO")
                info.size = len(metadata)
                import io
                stream.addfile(info, io.BytesIO(metadata))
            self.assertEqual(RUNNER.apk_metadata(archive)["arch"], "noarch")

    def test_absolute_payload_symlink_resolves_inside_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "program").write_bytes(b"program")
            (root / "bin/start").symlink_to("/program")
            self.assertEqual(RUNNER.resolve_payload_path(root, "/bin/start"), root / "program")

    def test_foreign_libc_in_private_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lib").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            loader = root / "lib/ld-musl-x86_64.so.1"
            libc = root / "lib/libc.musl-x86_64.so.1"
            loader.write_bytes(b"loader")
            libc.write_bytes(b"libc")
            (root / "usr/lib/libc.so").write_bytes(b"foreign")
            runtime = {"loader": {"sha256": RUNNER.sha256_file(loader, "loader")}, "libc": {"sha256": RUNNER.sha256_file(libc, "libc")}}
            with self.assertRaises(RUNNER.CorpusError):
                RUNNER.assert_runtime_boundary(root, runtime)

    @unittest.skipUnless(os.geteuid() == 0, "private character devices require root")
    def test_private_base_records_a_real_sealed_null_device(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            record = RUNNER.stage_base_image_fixtures(RUNNER.load_manifest(), root)
            node = (root / "dev/null").lstat()
            self.assertTrue(__import__("stat").S_ISCHR(node.st_mode))
            self.assertEqual((node.st_mode & 0o777, os.major(node.st_rdev), os.minor(node.st_rdev)), (0o666, 1, 3))
            self.assertEqual(record["device"]["kind"], "character")
            self.assertEqual(len(RUNNER.tree_sha256(root, "private root")), 64)

    @unittest.skipUnless(os.geteuid() == 0, "private character devices require root")
    def test_each_execution_root_restages_the_private_null_device(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "application-payload"
            payload.mkdir()
            (payload / "bin").mkdir()
            (payload / "bin/program").write_bytes(b"application bytes")
            execution = Path(temporary) / "execution-root"
            RUNNER.stage_execution_root(RUNNER.load_manifest(), payload, execution)
            node = (execution / "dev/null").lstat()
            self.assertTrue(__import__("stat").S_ISCHR(node.st_mode))
            self.assertEqual((node.st_mode & 0o777, os.major(node.st_rdev), os.minor(node.st_rdev)), (0o666, 1, 3))
            self.assertFalse((payload / "dev/null").exists())


class RawOutcomeTests(unittest.TestCase):
    def test_dynamic_tag_match_does_not_accept_a_longer_tag(self) -> None:
        self.assertTrue(RUNNER.has_dynamic_tag("0x24 (RELR) 0x100\n", "RELR"))
        self.assertFalse(RUNNER.has_dynamic_tag("0x24 (RELRSZ) 0x100\n", "RELR"))

    def test_identical_nonzero_outcomes_never_become_a_pass(self) -> None:
        result = RUNNER.compare_results(RUNNER.ProcessResult(1, b"", b"failure\n"), RUNNER.ProcessResult(1, b"", b"failure\n"))
        self.assertTrue(result["status_match"])
        self.assertFalse(result["passed"])

    def test_any_raw_status_difference_is_retained(self) -> None:
        result = RUNNER.compare_results(RUNNER.ProcessResult(0, b"ok\n", b""), RUNNER.ProcessResult(127, b"", b"mainelf\n"))
        self.assertFalse(result["status_match"])
        self.assertFalse(result["passed"])


class NativeInvocationBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = RUNNER.load_manifest()
        (RUNNER.ROOT / ".work").mkdir(exist_ok=True)

    def test_run_rejects_a_campaign_parent_outside_checkout_work_before_staging(self) -> None:
        outside_work = RUNNER.ROOT / "compat/corpus/unsafe-owned-package-corpus-state"
        staged = mock.Mock(side_effect=AssertionError("outside state reached staging"))
        with mock.patch.object(RUNNER, "require_native_environment"), \
             mock.patch.object(RUNNER, "apk_identity", return_value={}), \
             mock.patch.object(RUNNER, "verify_inputs", return_value={}), \
             mock.patch.object(RUNNER, "validate_product", return_value={}), \
             mock.patch.object(RUNNER, "stage_application_payload", staged), \
             mock.patch.object(RUNNER.tempfile, "mkdtemp", return_value=str(RUNNER.ROOT / ".work/unused")):
            with self.assertRaisesRegex(RUNNER.CorpusError, "checkout .work"):
                RUNNER.run(self.manifest, Path("archives"), Path("index"), Path("product"), outside_work, ())
        staged.assert_not_called()

    def test_explicit_tier_does_not_append_to_the_default_all_selection(self) -> None:
        captured: list[tuple[str, ...]] = []

        def record(_manifest: object, _archives: Path, _index: Path, _product: Path, _work: Path, cases: object) -> dict[str, object]:
            captured.append(tuple(case.id for case in cases))
            root = RUNNER.ROOT / ".work/unused-run"
            return {"passed": True, "execution_root": str(root), "report_path": str(root / "report.json")}

        with mock.patch.object(RUNNER, "run", side_effect=record), \
             mock.patch.object(RUNNER, "write_new_report", return_value=Path("retained.json")), \
             mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(RUNNER.main(["--dynamic-sysroot", "product", "--tier", "B", "--quiet"]), 0)
        self.assertEqual(captured, [tuple(case.id for case in self.manifest.cases if case.tier == "B")])

    def test_disjoint_tier_and_case_selection_fails_before_execution(self) -> None:
        with mock.patch.object(RUNNER, "run", return_value={"passed": True}) as run, mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(
                RUNNER.main(["--dynamic-sysroot", "product", "--tier", "B", "--case", "tier-a-true", "--quiet"]),
                2,
            )
        run.assert_not_called()

    def test_report_outside_checkout_work_is_rejected_before_execution(self) -> None:
        report = RUNNER.ROOT / "compat/corpus/unsafe-owned-package-corpus-report.json"
        with mock.patch.object(RUNNER, "run", return_value={"passed": True}) as run, \
             mock.patch.object(Path, "write_text") as write, \
             mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(RUNNER.main(["--dynamic-sysroot", "product", "--report", str(report), "--quiet"]), 2)
        run.assert_not_called()
        write.assert_not_called()

    def test_report_parent_symlink_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            parent = Path(temporary) / "report-parent"
            parent.symlink_to(RUNNER.ROOT / "compat/corpus", target_is_directory=True)
            report = parent / "report.json"
            with mock.patch.object(RUNNER, "run", return_value={"passed": True}) as run, \
                 mock.patch.object(Path, "write_text") as write, \
                 mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(RUNNER.main(["--dynamic-sysroot", "product", "--report", str(report), "--quiet"]), 2)
            run.assert_not_called()
            write.assert_not_called()

    def test_existing_explicit_report_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            report = Path(temporary) / "retained.json"
            report.write_text("prior evidence\n", encoding="utf-8")
            with mock.patch.object(RUNNER, "run", return_value={"passed": True}) as run, mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(RUNNER.main(["--dynamic-sysroot", "product", "--report", str(report), "--quiet"]), 2)
            run.assert_not_called()
            self.assertEqual(report.read_text(encoding="utf-8"), "prior evidence\n")

    def test_report_parent_traversal_is_rejected(self) -> None:
        with self.assertRaisesRegex(RUNNER.CorpusError, "parent traversal"):
            RUNNER.prepare_report_destination(Path(".work/owned-package-corpus/../report.json"))

    def test_default_report_is_retained_below_the_private_run_root_and_emitted(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            run_root = Path(temporary) / "run"
            run_root.mkdir()
            report = run_root / "report.json"
            result = {"passed": True, "source_mount": str(RUNNER.ROOT), "execution_root": str(run_root), "report_path": str(report)}
            stderr = io.StringIO()
            with mock.patch.object(RUNNER, "run", return_value=result), \
                 mock.patch.object(sys, "stdout", io.StringIO()), \
                 mock.patch.object(sys, "stderr", stderr):
                self.assertEqual(RUNNER.main(["--dynamic-sysroot", "product", "--quiet"]), 0)
            self.assertEqual(__import__("json").loads(report.read_text(encoding="utf-8")), result)
            self.assertIn(f"owned package corpus evidence: {run_root}", stderr.getvalue())
            self.assertIn("owned x86_64 package corpus: status: pass", stderr.getvalue())
            self.assertIn(str(report), stderr.getvalue())

    def test_fresh_explicit_report_is_created_below_checkout_work(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            run_root = Path(temporary) / "run"
            run_root.mkdir()
            report = Path(temporary) / "explicit.json"
            result = {"passed": True, "execution_root": str(run_root), "report_path": str(run_root / "report.json")}
            with mock.patch.object(RUNNER, "run", return_value=result), \
                 mock.patch.object(sys, "stdout", io.StringIO()), \
                 mock.patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(
                    RUNNER.main(["--dynamic-sysroot", "product", "--report", str(report), "--quiet"]),
                    0,
                )
            self.assertEqual(__import__("json").loads(report.read_text(encoding="utf-8")), result)

    def test_explicit_report_keeps_the_canonical_receipt_in_its_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            run_root = Path(temporary) / "run"
            run_root.mkdir()
            primary = run_root / "report.json"
            exported = Path(temporary) / "explicit.json"
            result = {"passed": True, "execution_root": str(run_root), "report_path": str(primary)}
            with mock.patch.object(RUNNER, "run", return_value=result), \
                 mock.patch.object(sys, "stdout", io.StringIO()), \
                 mock.patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(RUNNER.main([
                    "--dynamic-sysroot", "product", "--report", str(exported), "--quiet",
                ]), 0)
            self.assertEqual(primary.read_bytes(), exported.read_bytes())
            self.assertEqual(primary.stat().st_mode & 0o777, 0o644)
            self.assertEqual(exported.stat().st_mode & 0o777, 0o644)

    def test_oracle_identity_changes_when_runtime_changes_but_source_marker_does_not(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            root = Path(temporary)
            (root / "lib").mkdir()
            runtime = root / "lib/libc.so"
            runtime.write_bytes(b"original musl runtime")
            (root / "lib/ld-musl-x86_64.so.1").symlink_to("libc.so")
            marker = root / ".crabc-oracle"
            marker.write_bytes(b"same pinned source marker")
            with mock.patch.object(RUNNER, "ORACLE_ROOT", root), \
                 mock.patch.object(RUNNER, "ORACLE_SOURCE_MANIFEST", marker):
                before = RUNNER.oracle_source_identity()
                runtime.write_bytes(b"changed runtime")
                after = RUNNER.oracle_source_identity()
            self.assertNotEqual(before, after)

    def test_source_identity_binds_the_actual_process_lifetime_helpers(self) -> None:
        identity = RUNNER.source_identity(self.manifest)
        self.assertEqual(identity["runner"]["path"], "compat/corpus/run_x86.py")
        self.assertEqual(identity["native_manifest"]["path"], "compat/corpus/manifest-x86_64.toml")
        self.assertEqual(identity["workload_source"]["path"], "compat/corpus/manifest.toml")
        self.assertEqual(
            {entry["path"] for entry in identity["process_lifetime_helpers"].values()},
            {"compat/x86_64/run_qualification_manifest.py", "compat/x86_64/generate_qualification_manifest.py"},
        )

    def test_run_fails_closed_when_its_source_identity_changes(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNNER.ROOT / ".work") as temporary:
            campaign = Path(temporary) / "campaign"
            campaign.mkdir()
            execution = campaign / "owned-package-corpus-fixed"
            execution.mkdir()
            before, after = {"source": "before"}, {"source": "after"}
            inputs = {"identity": {"input": "same"}}
            case = self.manifest.cases[0]
            with mock.patch.object(RUNNER, "require_native_environment"), \
                 mock.patch.object(RUNNER, "private_campaign_parent", return_value=campaign), \
                 mock.patch.object(RUNNER, "source_identity", side_effect=(before, after)), \
                 mock.patch.object(RUNNER, "apk_identity", return_value={"tool": "same"}), \
                 mock.patch.object(RUNNER, "verify_inputs", return_value=inputs), \
                 mock.patch.object(RUNNER, "oracle_source_identity", return_value={"oracle": "same"}), \
                 mock.patch.object(RUNNER, "validate_product", return_value={"product": "same"}), \
                 mock.patch.object(RUNNER, "input_identity", return_value=inputs["identity"]), \
                 mock.patch.object(RUNNER.tempfile, "mkdtemp", return_value=str(execution)), \
                 mock.patch.object(RUNNER, "stage_application_payload"), \
                 mock.patch.object(RUNNER, "audit_application_elf_closure", return_value=[]), \
                 mock.patch.object(RUNNER, "tree_sha256", return_value="payload-seal"), \
                 mock.patch.object(RUNNER, "stage_execution_root", return_value={}), \
                 mock.patch.object(RUNNER, "copy_runtime", return_value={}), \
                 mock.patch.object(RUNNER, "create_fixture"), \
                 mock.patch.object(RUNNER, "assert_base_image_fixtures", return_value={}), \
                 mock.patch.object(RUNNER, "assert_runtime_boundary"), \
                 mock.patch.object(RUNNER, "executable_elf_record", return_value={}), \
                 mock.patch.object(RUNNER, "execute_case", return_value=RUNNER.ProcessResult(0, b"", b"")):
                with self.assertRaisesRegex(RUNNER.CorpusError, "source changed"):
                    RUNNER.run(self.manifest, Path("archives"), Path("index"), Path("product"), campaign, (case,))


if __name__ == "__main__":
    unittest.main()
