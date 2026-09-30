#!/usr/bin/env python3
"""Installed compiler flag selection and static driver authentication tests."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import installed_compiler_translation as translation


class InstalledCompilerTranslationTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[2] / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.product = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def static_product(self, source=b'HOSTED_TRANSLATION_FLAGS = ("-fstack-protector-strong",)\n'):
        driver = self.product / 'bin/crabc-cc'
        driver.parent.mkdir(parents=True)
        driver.write_bytes(source)
        driver.chmod(0o755)
        manifest = self.product / 'share/crabc/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            'schema': 1, 'format': 'crabc-x86-64-owned-static-sysroot-v1',
            'target': 'x86_64-unknown-linux-musl',
            'installed': {'files': {'bin/crabc-cc': hashlib.sha256(source).hexdigest()}},
            'sealed_static_driver': {'format': 'crabc-x86-64-sealed-static-driver-v1',
                                     'path': 'bin/crabc-cc'},
        }))
        return driver, manifest

    def test_manifest_bound_static_driver_supplies_flags_without_execution(self):
        self.static_product(b'raise RuntimeError("must never execute installed Python")\n'
                            b'HOSTED_TRANSLATION_FLAGS = ("-fstack-protector-strong", "-D_INSTALLED=1")\n')
        self.assertEqual(translation.hosted_translation_flags(self.product),
                         ('-fstack-protector-strong', '-D_INSTALLED=1'))

    def test_changed_static_driver_is_rejected(self):
        driver, _ = self.static_product()
        driver.write_text('HOSTED_TRANSLATION_FLAGS = ("-D_TRANSPLANTED=1",)\n')
        with self.assertRaises(translation.TranslationFlagsError):
            translation.hosted_translation_flags(self.product)

    def test_dynamic_product_cannot_replace_its_missing_helper_with_static_driver(self):
        _, manifest = self.static_product()
        record = json.loads(manifest.read_text())
        record['format'] = 'crabc-x86-64-owned-dynamic-sysroot-v1'
        manifest.write_text(json.dumps(record))
        with self.assertRaises(translation.TranslationFlagsError):
            translation.hosted_translation_flags(self.product)

    def test_static_driver_path_must_be_the_declared_installed_path(self):
        _, manifest = self.static_product()
        record = json.loads(manifest.read_text())
        record['sealed_static_driver']['path'] = '../../foreign-driver'
        manifest.write_text(json.dumps(record))
        with self.assertRaises(translation.TranslationFlagsError):
            translation.hosted_translation_flags(self.product)

    def test_static_driver_symlink_is_rejected(self):
        driver, _ = self.static_product()
        target = driver.with_name('other')
        driver.rename(target)
        driver.symlink_to(target.name)
        with self.assertRaises(translation.TranslationFlagsError):
            translation.hosted_translation_flags(self.product)

    def test_static_driver_requires_one_literal_option_tuple(self):
        for source in (b'HOSTED_TRANSLATION_FLAGS = ["-fstack-protector-strong"]\n',
                       b'HOSTED_TRANSLATION_FLAGS = ("-fstack-protector-strong",)\nHOSTED_TRANSLATION_FLAGS = ()\n'):
            with self.subTest(source=source):
                driver, manifest = self.static_product(source)
                with self.assertRaises(translation.TranslationFlagsError):
                    translation.hosted_translation_flags(self.product)
                driver.unlink()
                manifest.unlink()
                driver.parent.rmdir()
                manifest.parent.rmdir()
                manifest.parent.parent.rmdir()

    def test_dynamic_copied_helper_keeps_its_literal_contract(self):
        helper = self.product / 'share/crabc/crabc_cc_static.py'
        helper.parent.mkdir(parents=True)
        helper.write_text('raise RuntimeError("must never execute installed Python")\n'
                          'HOSTED_TRANSLATION_FLAGS = ("-D_DYNAMIC=1",)\n')
        self.assertEqual(translation.hosted_translation_flags(self.product), ('-D_DYNAMIC=1',))


if __name__ == '__main__':
    unittest.main()
