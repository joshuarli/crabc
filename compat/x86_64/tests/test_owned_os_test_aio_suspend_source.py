"""The os-test aio_suspend repair admits exactly one frozen upstream source."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_os_test_aio_suspend_source as source_profile


class OwnedOsTestAioSuspendSourceTests(unittest.TestCase):
    def test_exact_frozen_source_is_admitted_and_keeps_the_one_completion_assertion(self) -> None:
        prepared, replacements = source_profile.prepare(source_profile.FROZEN_SOURCE)

        self.assertEqual(hashlib.sha256(source_profile.FROZEN_SOURCE).hexdigest(), source_profile.ORIGINAL_SHA256)
        self.assertEqual(hashlib.sha256(prepared).hexdigest(), source_profile.PREPARED_SHA256)
        self.assertEqual(replacements, [{
            "source_function": "main",
            "original_line": 10,
            "original_sha256": "5eec5442695da7bee10849fbdb481dc3bf18e1e5592b8588febaee38c954515b",
            "prepared_sha256": "3c833348ab73907d588c0d22a510825e32cf1148f2b04fb038fb0de9a54ca2f8",
        }])
        self.assertIn(b"if ( aio_suspend(aiop, 2, NULL) < 0 )", prepared)
        self.assertIn(b"if ( !done )", prepared)
        self.assertIn(b"reap_pending(fp, aiop, submitted, returned);", prepared)
        self.assertIn(b"if ( fclose(fp) < 0 && !failure )", prepared)

    def test_any_changed_source_is_rejected_before_a_derivative_can_be_created(self) -> None:
        for changed in (
            source_profile.FROZEN_SOURCE + b"/* drift */\n",
            source_profile.FROZEN_SOURCE.replace(b"aio_offset = 6", b"aio_offset = 7", 1),
        ):
            with self.subTest(digest=hashlib.sha256(changed).hexdigest()):
                with self.assertRaisesRegex(source_profile.SourcePreparationError, "SHA-256"):
                    source_profile.prepare(changed)

    def test_prepared_hash_is_a_real_output_seal(self) -> None:
        original = source_profile.PREPARED_SHA256
        try:
            source_profile.PREPARED_SHA256 = "0" * 64
            with self.assertRaisesRegex(source_profile.SourcePreparationError, "prepared"):
                source_profile.prepare(source_profile.FROZEN_SOURCE)
        finally:
            source_profile.PREPARED_SHA256 = original

    def test_standalone_replay_tree_keeps_exact_support_and_preparation_receipt(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            root = Path(temporary)
            destination = root / "fixture"
            receipt = root / "fixture.json"
            record = source_profile.write_prepared_fixture_receipt(destination, receipt)

            self.assertEqual(record, source_profile.prepared_fixture_receipt())
            self.assertEqual(receipt.read_text(), json.dumps(record, indent=2, sort_keys=True) + "\n")
            for relative, content in source_profile.prepared_fixture_files().items():
                with self.subTest(relative=relative):
                    self.assertEqual((destination / relative).read_bytes(), content)
            with self.assertRaisesRegex(source_profile.SourcePreparationError, "refusing"):
                source_profile.materialize_prepared_fixture(destination)


if __name__ == "__main__":
    unittest.main()
