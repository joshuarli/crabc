"""Replay argument rejection precedes mutable signal-helper evidence."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_signal_helpers.sh"


class OwnedSignalHelpersRunnerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = ROOT / ".work/x86_64/tmp"
        self.scratch.mkdir(parents=True, exist_ok=True)

    def invoke(self, arguments, temporary):
        return subprocess.run(["bash", str(RUNNER), *arguments], cwd=ROOT,
                              env=dict(os.environ, TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE="1"),
                              capture_output=True, text=True, check=False)

    def test_invalid_arguments_exit_two_before_any_evidence(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            for arguments in ([""], ["--unknown"], ["--static-sysroot"], ["--static-sysroot", ""],
                              ["--static-sysroot", "--unknown"], ["a", "b"],
                              ["--static-sysroot", "a", "--static-sysroot", "b"],
                              ["--static-sysroot", "a", ""], ["a", "--static-sysroot", "b"]):
                with self.subTest(arguments=arguments):
                    result = self.invoke(arguments, directory)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("usage:", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_supplied_modes_validate_products_before_output_or_producers(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            base = Path(directory)
            static, dynamic = base / "static", base / "dynamic"
            static.mkdir()
            dynamic.mkdir()
            for arguments in ([str(dynamic)], ["--static-sysroot", str(static)],
                              ["--static-sysroot", str(static), str(dynamic)]):
                with self.subTest(arguments=arguments):
                    result = self.invoke(arguments, directory)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("usage:", result.stderr)
                    self.assertEqual(set(base.iterdir()), {static, dynamic})
                    self.assertEqual(list(static.iterdir()), [])
                    self.assertEqual(list(dynamic.iterdir()), [])

    def test_symlink_and_parent_traversal_are_not_hidden_by_resolution(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            base = Path(directory)
            product = base / "product"
            product.mkdir()
            link = base / "alias"
            link.symlink_to(product, target_is_directory=True)
            for path in (str(link), str(product) + "/../product"):
                with self.subTest(path=path):
                    result = self.invoke(["--static-sysroot", path], directory)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("physical", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(set(base.iterdir()), {product, link})


if __name__ == "__main__":
    unittest.main()
