"""Behavior tests for the product-scoped source seal and its build guard."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import source_seal  # noqa: E402


BUILDER = """\
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "compat/x86_64"))
import product_helper


def build():
    import harness_only
    return harness_only


if __name__ == "__main__":
    for name in sys.argv[1:]:
        Path(name).read_bytes()
"""


class FixtureCheckout:
    """A committed checkout with product inputs, one helper and harness files."""

    def __init__(self, test: unittest.TestCase) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="source-seal-test.", dir=ROOT / ".work"))
        test.addCleanup(shutil.rmtree, self.root)
        for name in (*source_seal.PRODUCT_FILES, *source_seal.PRODUCT_LAZY_MODULES):
            self.write(name, f"{name}\n")
        for name in source_seal.PRODUCT_BUILDERS:
            self.write(name, BUILDER)
        self.write("compat/x86_64/product_helper.py", "VALUE = 1\n")
        self.write("compat/x86_64/harness_only.py", "VALUE = 1\n")
        self.write("compat/x86_64/run_case.sh", "echo case\n")
        self.write("libc/src/lib.rs", "pub fn f() {}\n")
        self.write(".gitignore", ".work/\n")
        self.git("init", "-q")
        self.commit("fixture")

    def write(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def git(self, *arguments: str) -> str:
        return subprocess.run(["git", "-c", f"safe.directory={self.root}", "-c", "user.name=t",
                               "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *arguments],
                              cwd=self.root, check=True, capture_output=True, text=True).stdout

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)


class ProductDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.checkout = FixtureCheckout(self)
        self.root = self.checkout.root

    def test_a_harness_only_commit_keeps_the_seal_and_moves_the_revision(self) -> None:
        before = source_seal.seal(self.root)
        self.checkout.write("compat/x86_64/run_case.sh", "echo changed case\n")
        self.checkout.write("compat/x86_64/harness_only.py", "VALUE = 2\n")
        self.checkout.commit("harness fix")
        after = source_seal.seal(self.root)
        self.assertTrue(source_seal.same_product(after, before))
        self.assertEqual(after["content_sha256"], before["content_sha256"])
        self.assertNotEqual(after["revision"], before["revision"])

    def test_a_product_source_change_is_a_different_seal(self) -> None:
        before = source_seal.seal(self.root)
        self.checkout.write("libc/src/lib.rs", "pub fn changed() {}\n")
        self.checkout.commit("product change")
        self.assertFalse(source_seal.same_product(source_seal.seal(self.root), before))

    def test_a_retained_tree_has_the_live_checkout_digest(self) -> None:
        files = {}
        for name in source_seal.product_files(self.root) + ("compat/x86_64/run_case.sh",):
            path = self.root / name
            files[name] = (path.stat().st_mode & 0o777, path.read_bytes())
        self.assertEqual(source_seal.product_source_digest_of(files), source_seal.product_source_digest(self.root))

    def test_a_product_input_change_changes_the_digest(self) -> None:
        before = source_seal.product_source_digest(self.root)
        for name, text in (("libc/src/lib.rs", "pub fn g() {}\n"),
                           ("libc/src/added.rs", "pub fn h() {}\n"),
                           ("compat/x86_64/product_helper.py", "VALUE = 2\n"),
                           (source_seal.PRODUCT_FILES[0], "changed\n")):
            with self.subTest(name=name):
                self.checkout.write(name, text)
                after = source_seal.product_source_digest(self.root)
                self.assertNotEqual(after, before)
                before = after

    def test_a_mode_change_on_a_product_input_changes_the_digest(self) -> None:
        before = source_seal.product_source_digest(self.root)
        (self.root / "libc/src/lib.rs").chmod(0o755)
        self.assertNotEqual(source_seal.product_source_digest(self.root), before)

    def test_a_dirty_checkout_has_no_seal(self) -> None:
        for name in ("compat/x86_64/run_case.sh", "untracked.txt"):
            with self.subTest(name=name):
                self.checkout.write(name, "dirty\n")
                with self.assertRaisesRegex(source_seal.SourceSealError, "clean committed source"):
                    source_seal.seal(self.root)
                self.checkout.commit("clean again")


class GuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.checkout = FixtureCheckout(self)
        self.root = self.checkout.root
        self.builder = self.root / source_seal.PRODUCT_BUILDERS[0]

    def guard(self, *command: str) -> tuple[int, str]:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = source_seal.guard(self.root, [sys.executable, "-B", *command])
        return status, errors.getvalue()

    def test_a_build_reading_only_product_inputs_passes(self) -> None:
        status, errors = self.guard(str(self.builder), "libc/src/lib.rs", "Cargo.toml")
        self.assertEqual((status, errors), (0, ""))

    def test_a_build_reading_a_harness_file_fails_and_names_it(self) -> None:
        status, errors = self.guard(str(self.builder), "libc/src/lib.rs", "compat/x86_64/run_case.sh")
        self.assertEqual(status, 1)
        self.assertIn("compat/x86_64/run_case.sh", errors)
        self.assertNotIn("libc/src/lib.rs", errors)

    def test_relative_reads_after_a_directory_change_are_resolved(self) -> None:
        script = "import os; os.chdir('compat'); os.stat('x86_64/run_case.sh')"
        status, errors = self.guard("-c", script)
        self.assertEqual(status, 1)
        self.assertIn("compat/x86_64/run_case.sh (stat", errors)

    def test_git_metadata_walks_are_not_build_reads(self) -> None:
        script = ("import subprocess; subprocess.run(['git', '-c', 'safe.directory=*', 'status', '--porcelain', "
                  "'--untracked-files=all'], check=True, stdout=subprocess.DEVNULL)")
        self.assertEqual(self.guard("-c", script), (0, ""))

    def test_a_failed_build_keeps_its_status(self) -> None:
        self.assertEqual(self.guard("-c", "raise SystemExit(7)")[0], 7)


if __name__ == "__main__":
    unittest.main()
