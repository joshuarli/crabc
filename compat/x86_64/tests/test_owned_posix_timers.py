"""Installed POSIX timer runner product and object ownership boundaries."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_posix_timers.sh"


class OwnedPosixTimersTests(unittest.TestCase):
    def test_supplied_product_rejects_physical_escape_before_compilation(self):
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            scratch = Path(temporary)
            escaped = scratch / "product"
            escaped.symlink_to(ROOT, target_is_directory=True)
            for product in (ROOT, escaped):
                with self.subTest(product=product):
                    result = subprocess.run(
                        ["bash", str(RUNNER), str(product)],
                        env={**os.environ, "TMPDIR": str(scratch)},
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("product must be a physical checkout .work directory", result.stderr)
                    self.assertNotIn("evidence:", result.stdout)

    def test_installed_driver_compiles_shared_objects_before_runtime_links(self):
        source = RUNNER.read_text()
        probe_compile = '"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -c "$probe" -o "$work/probe.o"'
        tls_compile = '"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" -shared -std=c11 -c "$ROOT/compat/x86_64/owned_posix_timers_tls.c" -o "$work/tls.o"'
        self.assertIn(probe_compile, source)
        self.assertIn(tls_compile, source)
        self.assertLess(source.index('scripts/build_x86_64_owned_dynamic_sysroot.py'), source.index(probe_compile))
        self.assertLess(source.index(probe_compile), source.index('"$oracle_cc" -pthread "$work/probe.o"'))
        self.assertLess(source.index(tls_compile), source.index('"$oracle_cc" -shared "$work/tls.o"'))
        self.assertNotIn('-I"$ROOT/include"', source)


if __name__ == "__main__":
    unittest.main()
