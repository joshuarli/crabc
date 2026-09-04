"""Scratch admission for the standalone numerical assembly generator."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
sys.path.insert(0, str(ROOT / "scripts"))
import build_x86_64_owned_sysroot as producer
import generate_owned_printf_float as generator


class GeneratorScratch(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="test-printf-generator.", dir=producer.deterministic_environment()["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.root.mkdir()

    def test_ambient_tmpdir_cannot_select_generator_or_compiler_scratch(self):
        with patch.object(producer, "ROOT", self.root), patch.dict(os.environ,
                {"TMPDIR": "/outside-checkout/untrusted", "CPATH": "/ambient/include"}):
            environment = generator.generation_environment()
        self.assertEqual(environment["TMPDIR"], str(self.root / ".work/x86_64/tmp"))
        self.assertTrue(Path(environment["TMPDIR"]).is_dir())
        self.assertNotIn("CPATH", environment)

    def test_escaping_tmp_symlink_is_rejected_before_other_state_creation(self):
        state = self.root / ".work/x86_64"
        state.mkdir(parents=True)
        (state / "tmp").symlink_to(Path(self.temporary.name))
        with patch.object(producer, "ROOT", self.root):
            with self.assertRaisesRegex(producer.BuildError, "escapes checkout"):
                generator.generation_environment()
        self.assertFalse((state / "cargo").exists())

    def test_escaping_work_ancestor_is_rejected(self):
        (self.root / ".work").symlink_to(Path(self.temporary.name))
        with patch.object(producer, "ROOT", self.root):
            with self.assertRaisesRegex(producer.BuildError, "escapes checkout"):
                generator.generation_environment()


if __name__ == "__main__":
    unittest.main()
