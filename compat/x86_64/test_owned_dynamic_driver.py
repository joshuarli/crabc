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


if __name__ == "__main__":
    unittest.main()
