"""Keep dynamic tool resolvers bound to the product that selects their linker."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class DynamicLinkerProductRootTests(unittest.TestCase):
    def _resolve_linker_from_runner(self, relative):
        source = (ROOT / relative).read_text()
        match = re.search(r"resolve_tool\(\) \{.*?<<'PY'\n(.*?)\nPY\n", source, re.DOTALL)
        self.assertIsNotNone(match, f"{relative} must retain its exact tool resolver")
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            product = Path(temporary)
            helper = product / "share/crabc/crabc_cc_static.py"
            helper.parent.mkdir(parents=True)
            helper.write_text(
                "from pathlib import Path\n"
                "def compiler(): return '/bin/sh'\n"
                "def linker(root):\n"
                "    assert Path(root).resolve() == Path(__file__).resolve().parents[2]\n"
                "    return '/bin/sh'\n"
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", match.group(1), str(product), "linker"],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(Path("/bin/sh").resolve()))

    def test_math_fenv_resolver_passes_its_dynamic_product_to_linker(self):
        self._resolve_linker_from_runner("compat/x86_64/run_owned_math_fenv_all_entry.sh")

    def test_text_locale_resolver_passes_its_dynamic_product_to_linker(self):
        self._resolve_linker_from_runner("compat/x86_64/run_owned_text_locale_numeric_component.sh")


if __name__ == "__main__":
    unittest.main()
