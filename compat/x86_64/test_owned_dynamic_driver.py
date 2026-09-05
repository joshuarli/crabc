"""Boundary regressions for the materialized shared-product driver."""
from pathlib import Path
import hashlib
import json
import os
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import crabc_cc_owned_dynamic as driver
import owned_dynamic_package as package
import io
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import build_x86_64_owned_dynamic_sysroot as producer


class InstalledDynamicDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dynamic-driver-test.", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "installed"
        self.root.mkdir()
        for relative in driver.REQUIRED:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"owned test payload")
        (self.root / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        (self.root / "share/crabc").mkdir(parents=True)
        self.manifest = {"schema": 1, "format": driver.FORMAT, "target": driver.shared.TARGET,
                         "files": {relative: hashlib.sha256(b"owned test payload").hexdigest()
                                   for relative in driver.REQUIRED}, "symlinks": driver.ALIASES}
        self.write_manifest()

    def write_manifest(self):
        (self.root / "share/crabc/manifest.json").write_text(json.dumps(self.manifest))

    def test_exact_payload_accepts_only_canonical_relative_alias(self):
        driver.validate(self.root)
        alias = self.root / "lib/ld-musl-x86_64.so.1"
        alias.unlink()
        alias.symlink_to("/lib/ld-crabc-x86_64.so.1")
        with self.assertRaisesRegex(driver.shared.DriverError, "roster"):
            driver.validate(self.root)

    def test_installed_driver_import_does_not_mutate_payload_without_python_environment(self):
        for relative, source in (("bin/crabc-cc-dynamic", Path(driver.__file__)),
                                 ("share/crabc/crabc_cc_static.py", Path(driver.shared.__file__))):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            self.manifest["files"][relative] = driver.shared.sha256_file(destination)
        self.write_manifest()
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        result = subprocess.run([sys.executable, str(self.root / "bin/crabc-cc-dynamic")],
                                env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("select --dynamic-pie", result.stderr)
        self.assertEqual(list(self.root.rglob("__pycache__")), [])
        driver.validate(self.root)

    def test_tampered_missing_and_undeclared_payloads_fail(self):
        libc = self.root / "usr/lib/libc.so"
        libc.write_bytes(b"foreign")
        with self.assertRaisesRegex(driver.shared.DriverError, "hash mismatch"):
            driver.validate(self.root)
        libc.unlink()
        with self.assertRaisesRegex(driver.shared.DriverError, "roster"):
            driver.validate(self.root)
        libc.write_bytes(b"owned test payload")
        (self.root / "usr/lib/libforeign.so").write_bytes(b"foreign")
        with self.assertRaisesRegex(driver.shared.DriverError, "roster"):
            driver.validate(self.root)

    def test_runtime_injection_rejected_before_tool_execution(self):
        for flag in ("-L/usr/lib", "-lc", "-Wl,-rpath,/foreign", "-I/usr/include",
                     "-static", "-fPIC", "--dynamic-non-pie", "-shared"):
            with self.subTest(flag=flag), patch.object(driver, "run") as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, ["--dynamic-pie", flag, "input.c"])
                run.assert_not_called()

    def test_install_output_cannot_be_modified(self):
        source = Path(self.temporary.name) / "input.c"
        source.write_text("int main(void) { return 0; }\n")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver, "run") as run:
            with self.assertRaisesRegex(driver.shared.DriverError, "installed sysroot"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(self.root / "consumer")])
            run.assert_not_called()

    def test_output_cannot_overwrite_application_source(self):
        source = Path(self.temporary.name) / "input.c"
        source.write_text("int main(void) { return 0; }\n")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver, "run") as run:
            with self.assertRaisesRegex(driver.shared.DriverError, "collides"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(source)])
            run.assert_not_called()

    def test_existing_receipt_regular_symlink_and_hardlink_reject_before_tools_and_preserve_bytes(self):
        source = Path(self.temporary.name) / "source.c"
        source.write_text("int main(void) { return 0; }\n")
        for kind in ("regular", "symlink", "hardlink"):
            output = Path(self.temporary.name) / kind
            receipt = Path(str(output) + ".crabc-link.json")
            original = Path(self.temporary.name) / (kind + ".original")
            original.write_bytes(b"old receipt bytes")
            if kind == "regular": receipt.write_bytes(b"old receipt bytes")
            elif kind == "symlink": receipt.symlink_to(original)
            else: os.link(original, receipt)
            with self.subTest(kind=kind), patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "run", side_effect=driver.shared.DriverError("tool was called")) as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
                run.assert_not_called()
                self.assertEqual(receipt.read_bytes(), b"old receipt bytes")
                self.assertEqual(original.read_bytes(), b"old receipt bytes")
                self.assertFalse(output.exists())

    def test_failed_translation_releases_only_its_new_receipt_reservation(self):
        source = Path(self.temporary.name) / "source.c"
        source.write_text("invalid")
        output = Path(self.temporary.name) / "consumer"
        receipt = Path(str(output) + ".crabc-link.json")
        def fail(command, temporary):
            self.assertTrue(receipt.is_file(), "receipt must be reserved before compiler execution")
            self.assertEqual(receipt.read_bytes(), b"")
            raise driver.shared.DriverError("isolated translation failure")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "run", side_effect=fail):
            with self.assertRaisesRegex(driver.shared.DriverError, "isolated translation failure"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
        self.assertFalse(receipt.exists())

    def test_failed_link_does_not_remove_a_competing_receipt_inode(self):
        source = Path(self.temporary.name) / "source.c"
        source.write_text("int main(void) { return 0; }\n")
        output = Path(self.temporary.name) / "consumer"
        receipt = Path(str(output) + ".crabc-link.json")
        def fail_link(command, temporary):
            self.assertEqual(receipt.read_bytes(), b"")
            if command[0] == "/owned/gcc": return ""
            receipt.unlink()
            receipt.write_bytes(b"competing receipt")
            raise driver.shared.DriverError("isolated link failure")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "dynamic_symbols", return_value=(set(), set())), patch.object(driver, "run", side_effect=fail_link):
            with self.assertRaisesRegex(driver.shared.DriverError, "isolated link failure"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
        self.assertEqual(receipt.read_bytes(), b"competing receipt")

    def test_receipt_replacement_is_rejected_before_publication(self):
        path = Path(self.temporary.name) / "receipt"
        with self.assertRaisesRegex(driver.shared.DriverError, "identity changed"):
            with driver.reserve_receipt(path) as publish:
                path.unlink()
                path.write_bytes(b"other publisher")
                publish("new receipt")
        self.assertEqual(path.read_bytes(), b"other publisher")

    def test_package_is_deterministic_and_extracted_payload_is_identical(self):
        one = Path(self.temporary.name) / "one.tar"
        two = Path(self.temporary.name) / "two.tar"
        extracted = Path(self.temporary.name) / "extracted"
        package.package(self.root, one)
        package.package(self.root, two)
        self.assertEqual(one.read_bytes(), two.read_bytes())
        package.extract(one, extracted)
        self.assertEqual(driver.validate(self.root), driver.validate(extracted))

    def test_package_path_escape_and_duplicate_rejected_before_output_creation(self):
        for name in ("../escape", "/escape", "duplicate"):
            with self.subTest(name=name):
                archive_path = Path(self.temporary.name) / "malformed.tar"
                with tarfile.open(archive_path, "w") as archive:
                    entry = tarfile.TarInfo(name)
                    entry.size = 1
                    archive.addfile(entry, io.BytesIO(b"x"))
                    if name == "duplicate": archive.addfile(entry, io.BytesIO(b"x"))
                output = Path(self.temporary.name) / "rejected"
                with self.assertRaises(driver.shared.DriverError):
                    package.extract(archive_path, output)
                self.assertFalse(output.exists())

    def test_package_nonobject_manifest_is_clean_error_before_output_creation(self):
        for value in ([], None, "manifest", 7, True):
            with self.subTest(value=value):
                archive_path = Path(self.temporary.name) / "bad-manifest.tar"
                payload = json.dumps(value).encode()
                with tarfile.open(archive_path, "w") as archive:
                    entry = tarfile.TarInfo("share/crabc/manifest.json")
                    entry.size = len(payload)
                    archive.addfile(entry, io.BytesIO(payload))
                output = Path(self.temporary.name) / "rejected"
                with self.assertRaises(driver.shared.DriverError):
                    package.extract(archive_path, output)
                self.assertFalse(output.exists())

    def test_producer_failure_keeps_partial_payload_private(self):
        output = Path(self.temporary.name) / "produced"
        def fail(staged, build):
            staged.mkdir()
            (staged / "partial-libc.so").write_bytes(b"partial")
            self.assertFalse(output.exists())
            raise producer.common.BuildError("isolated loader build failure")
        with patch.object(producer, "build_staged_payload", side_effect=fail, create=True), patch.object(producer.common, "resolve_pinned_producer_tools", side_effect=AssertionError("private staged payload owner required")):
            with self.assertRaisesRegex(producer.common.BuildError, "isolated loader build failure"):
                producer.build(output)
        self.assertFalse(output.exists())
        self.assertEqual((output.parent / (output.name + ".build") / "installed/partial-libc.so").read_bytes(), b"partial")

    def test_producer_final_validation_failure_and_competing_publication_preserve_destination(self):
        for failure in ("invalid-payload", "competing-publication"):
            with self.subTest(failure=failure):
                output = Path(self.temporary.name) / failure
                def finish(staged, build):
                    staged.mkdir()
                    (staged / "payload").write_bytes(b"private candidate")
                    if failure == "competing-publication":
                        output.mkdir()
                        (output / "competitor").write_bytes(b"other publisher")
                validator = (None if failure == "competing-publication" else driver.shared.DriverError("invalid payload"))
                with patch.object(producer, "build_staged_payload", side_effect=finish, create=True), patch.object(driver, "validate", side_effect=validator), patch.object(producer.common, "resolve_pinned_producer_tools", side_effect=AssertionError("private staged payload owner required")):
                    with self.assertRaises(producer.common.BuildError):
                        producer.build(output)
                if failure == "competing-publication":
                    self.assertEqual((output / "competitor").read_bytes(), b"other publisher")
                    self.assertEqual(list(output.iterdir()), [output / "competitor"])
                else:
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
