"""Preparation receipts bind source, all three static products, and raw steps."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_posix_static_products as preparation
import owned_static_sysroot_package as package

spec = importlib.util.spec_from_file_location("package_fixtures", Path(__file__).with_name("test_owned_static_sysroot_package.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class StaticPreparationTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/test-posix-static-products"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / ".work/run"
        self.work.mkdir(parents=True)
        (self.root / ".gitignore").write_text(".work/\n")
        (self.root / "source").write_text("committed source\n")
        (self.root / "compat").mkdir()
        (self.root / "compat/upstreams.toml").write_text("oracle = 'musl 1.2.6'\n")
        (self.root / "rust-toolchain.toml").write_text("channel = 'pinned'\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")
        products = self.work / "products"
        products.mkdir()
        primary = products / "primary"
        fixtures.OwnedStaticSysrootPackageTests().populate_tree(primary)
        manifest_path = primary / package.MANIFEST_RELATIVE_PATH
        manifest = json.loads(manifest_path.read_text())
        manifest.update(toolchain="pinned", producer_tools={"fixture": "producer identity"})
        manifest_path.write_text(json.dumps(manifest))
        shutil.copytree(primary, products / "reproduction")
        archives = self.work / "archives"
        archives.mkdir()
        for label in ("primary", "reproduction"):
            package.create_archive(products / label, archives / f"{label}.tar.xz")
        package.extract_archive(archives / "primary.tar.xz", products / "extracted")
        source = preparation.source_identity(self.root)
        preparation.write_new(self.work / "source-before.json", source)
        preparation.write_new(self.work / "source-after.json", source)
        (self.work / "steps").mkdir()
        for step, command in preparation.commands(self.root, self.work).items():
            preparation.write_new(self.work / "steps" / f"{step}.command.json", command)
            (self.work / "steps" / f"{step}.stdout").write_bytes(b"raw output\n")
            (self.work / "steps" / f"{step}.stderr").write_bytes(b"")
            (self.work / "steps" / f"{step}.status").write_text("0\n")
        self.receipt = self.work / "preparation.json"
        preparation.write_new(self.receipt, preparation.collect(self.root, self.work))

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.STDOUT)

    def validate(self):
        return preparation.validate_receipt(self.root, self.receipt)

    def test_complete_receipt_is_preparation_only(self):
        record = self.validate()
        self.assertEqual(record["status"], "prepared-unqualified")
        self.assertEqual(set(record["products"]), {"primary", "reproduction", "extracted"})
        self.assertNotIn("runtime", record)

    def test_receipt_missing_extra_or_changed_fields_rejected(self):
        original = json.loads(self.receipt.read_text())
        for mutate in (
            lambda r: r["products"].pop("reproduction"),
            lambda r: r["products"].update(extra=r["products"]["primary"]),
            lambda r: r.update(status="qualified"),
            lambda r: r.update(runtime="passed"),
            lambda r: r["source"].update(revision="0" * 40),
            lambda r: r["products"]["primary"].update(path="/outside"),
            lambda r: r["steps"].pop("extract"),
            lambda r: r["steps"]["extract"].update(exit_status=False),
            lambda r: r["archives"]["primary"].update(size=float(r["archives"]["primary"]["size"])),
        ):
            with self.subTest(mutate=mutate):
                record = copy.deepcopy(original)
                mutate(record)
                self.receipt.write_text(json.dumps(record))
                with self.assertRaises(preparation.PreparationError):
                    self.validate()

    def test_dirty_source_rejected(self):
        (self.root / "source").write_text("dirty\n")
        with self.assertRaisesRegex(preparation.PreparationError, "clean"):
            self.validate()

    def test_duplicate_json_keys_rejected(self):
        for path in (self.receipt, self.work / "source-before.json"):
            original = path.read_text()
            key, value = next(iter(json.loads(original).items()))
            path.write_text("{" + json.dumps(key) + ":" + json.dumps(value) + "," + original[1:])
            with self.assertRaises(preparation.PreparationError):
                self.validate()
            path.write_text(original)

    def test_retention_makes_private_archives_readable_without_changing_write_or_execute_bits(self):
        archive = self.work / "archives/primary.tar.xz"
        archive.chmod(0o600)
        directory = self.work / "archives"
        directory.chmod(0o700)
        preparation.make_retained_evidence_readable(self.work)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o644)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        self.validate()

    def test_retention_does_not_follow_symlinks(self):
        outside = self.root / ".work/outside"
        outside.write_bytes(b"unrelated")
        outside.chmod(0o600)
        retained = self.root / ".work/retained"
        retained.mkdir()
        (retained / "alias").symlink_to(outside)
        preparation.make_retained_evidence_readable(retained)
        self.assertEqual(outside.stat().st_mode & 0o777, 0o600)

    def test_new_committed_source_rejected(self):
        (self.root / "source").write_text("new revision\n")
        self.git("add", "source")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "changed")
        with self.assertRaises(preparation.PreparationError):
            self.validate()

    def test_source_seal_tampering_rejected(self):
        (self.work / "source-after.json").write_text("{}")
        with self.assertRaises(preparation.PreparationError):
            self.validate()

    def test_each_product_payload_mutation_rejected(self):
        for label, product in preparation.product_paths(self.work).items():
            with self.subTest(product=label):
                path = product / "usr/lib/libc.a"
                saved = path.read_bytes()
                path.write_bytes(b"tampered")
                with self.assertRaises((preparation.PreparationError, package.PackageError)):
                    self.validate()
                path.write_bytes(saved)

    def test_missing_or_extra_physical_products_rejected(self):
        (self.work / "products/unexpected").mkdir()
        with self.assertRaises(preparation.PreparationError):
            self.validate()
        (self.work / "products/unexpected").rmdir()
        shutil.rmtree(self.work / "products/reproduction")
        with self.assertRaises(preparation.PreparationError):
            self.validate()

    def test_archive_mutation_rejected(self):
        path = self.work / "archives/primary.tar.xz"
        path.write_bytes(path.read_bytes() + b"tampered")
        with self.assertRaises(preparation.PreparationError):
            self.validate()

    def test_matching_wrong_archives_rejected(self):
        for label in ("primary", "reproduction"):
            (self.work / "archives" / f"{label}.tar.xz").write_bytes(b"same invalid archive")
        with self.assertRaises((preparation.PreparationError, package.PackageError)):
            self.validate()

    def test_log_command_and_status_mutation_rejected(self):
        for suffix, changed in (("stdout", b"changed"), ("command.json", b"[]"), ("status", b"1\n")):
            path = self.work / "steps" / f"primary-build.{suffix}"
            original = path.read_bytes()
            path.write_bytes(changed)
            with self.assertRaises(preparation.PreparationError):
                self.validate()
            path.write_bytes(original)

    def test_normalized_modes_match_package_but_executable_bit_change_rejected(self):
        path = self.work / "products/primary/usr/lib/libc.a"
        path.chmod(0o600)
        self.validate()
        path.chmod(0o700)
        with self.assertRaises(preparation.PreparationError):
            self.validate()

    def test_escaping_symlink_and_outside_work_rejected(self):
        alias = self.root / ".work/alias"
        alias.symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(preparation.PreparationError):
            preparation.validate_receipt(self.root, alias / "preparation.json")
        with self.assertRaises(preparation.PreparationError):
            preparation.prepare(self.root, self.root / "outside")

    def test_failed_step_retains_raw_diagnostics(self):
        command = [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"]
        with self.assertRaises(preparation.PreparationError):
            preparation.run_step(self.root, self.work, "failure", command)
        self.assertEqual((self.work / "steps/failure.status").read_text(), "7\n")
        self.assertEqual((self.work / "steps/failure.stdout").read_text(), "out\n")
        self.assertEqual((self.work / "steps/failure.stderr").read_text(), "err\n")


class StaticPreparationDispatchTests(unittest.TestCase):
    def test_host_path_maps_to_workspace_and_escapes_fail_before_docker(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            docker.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "else: raise SystemExit('unexpected Docker operation')\n")
            docker.chmod(0o755)
            environment = {**os.environ, "PATH": f"{work}{os.pathsep}{os.environ['PATH']}",
                "DISPATCH_CAPTURE": str(capture), "CRABC_X86_64_WORK_DIR": str(work / "state")}
            command = ["bash", str(ROOT / "scripts/dev-x86_64.sh"), "owned-posix-static-products"]
            for invalid in (ROOT / "outside", ROOT / ".work"):
                result = subprocess.run(command + [str(invalid)], cwd=ROOT, env=environment, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(capture.exists())
            redirected = work / "redirected"
            redirected.symlink_to(work, target_is_directory=True)
            result = subprocess.run(command + [str(redirected / "run")], cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(capture.exists())
            destination = work / "fresh-run"
            for spelling in (str(destination), destination.relative_to(ROOT).as_posix()):
                result = subprocess.run(command + [spelling], cwd=ROOT, env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertEqual(len(calls), 2)
            for call in calls:
                self.assertEqual(call[-5:], ["python3", "-B", "/workspace/compat/x86_64/owned_posix_static_products.py",
                    "prepare", "/workspace/" + destination.relative_to(ROOT).as_posix()])
                self.assertNotIn("--privileged", call)


if __name__ == "__main__":
    unittest.main()
