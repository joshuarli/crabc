"""Regression contracts for the supplied-product cleanup consumer receipt."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))
import build  # noqa: E402
import owned_cleanup  # noqa: E402


class OwnedCleanupContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.provider = Path(self.temporary.name) / "provider"
        self.provider.mkdir()
        self.archive = self.provider / "libcrabc-unwind.a"
        self.archive.write_bytes(b"selected provider")
        defined = "\n".join(f"00000000 T {name}" for name in sorted(build.UNWIND_ABI)) + "\n"
        (self.provider / "defined-symbols.txt").write_text(defined)

    def tearDown(self):
        self.temporary.cleanup()

    def write_provenance(self, **changes):
        record = {
            "schema": 1,
            "target": owned_cleanup.TARGET,
            "qualified": False,
            "native_build_products": False,
            "personality_owner": "consumer Rust std",
            "archive": {"name": self.archive.name, "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()},
            "unwind_abi": sorted(build.UNWIND_ABI),
            "toolchain": "pinned compiler\n",
        }
        record.update(changes)
        (self.provider / "provenance.json").write_text(json.dumps(record))

    def test_provider_snapshot_binds_archive_abi_and_nonpromoting_state(self):
        self.write_provenance()
        snapshot = owned_cleanup.provider_snapshot(self.provider, "pinned compiler\n")
        self.assertEqual(snapshot["archive"]["path"], str(self.archive))
        self.assertEqual(snapshot["defined_unwind_abi"], sorted(build.UNWIND_ABI))

    def test_provider_snapshot_rejects_a_promoted_or_product_provider(self):
        for changes in ({"qualified": True}, {"native_build_products": True}):
            with self.subTest(changes=changes):
                self.write_provenance(**changes)
                with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "qualification or product"):
                    owned_cleanup.provider_snapshot(self.provider, "pinned compiler\n")

    def test_link_receipt_flags_must_remain_false(self):
        owned_cleanup.assert_nonpromoting(
            {"qualified": False, "family_completion": False, "promotion_ready": False, "public_support": False},
            "test receipt",
        )
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "promotion_ready"):
            owned_cleanup.assert_nonpromoting(
                {"qualified": False, "family_completion": False, "promotion_ready": True, "public_support": False},
                "test receipt",
            )


if __name__ == "__main__":
    unittest.main()
