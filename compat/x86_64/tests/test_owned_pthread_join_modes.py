"""Installed pthread join-mode runner product and object ownership boundaries."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_pthread_join_cancel.sh"
SCRATCH_ROOT = ROOT / ".work/x86_64/owned-pthread-join-modes-tests"


class OwnedPthreadJoinModesTests(unittest.TestCase):
    def test_supplied_product_physical_escape_is_rejected_before_work_creation(self) -> None:
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="product-escape-", dir=SCRATCH_ROOT) as temporary:
            scratch = Path(temporary)
            escaped = scratch / "product"
            escaped.symlink_to(ROOT, target_is_directory=True)
            result = subprocess.run(
                ["bash", str(RUNNER), str(escaped)],
                cwd=ROOT,
                env={**os.environ, "TMPDIR": str(scratch)},
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pthread-join-cancel product must be a checkout .work directory",
            result.stderr,
        )
        self.assertNotIn("pthread-join-cancel evidence:", result.stdout)

    def test_selected_dynamic_product_compiles_one_reused_object_before_links(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        compile_object = (
            '"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie '
            '-std=c11 -fno-builtin -c "$probe" -o "$work/probe.o"'
        )
        oracle_link = '"$oracle_cc" -pthread "$work/probe.o" -o "$work/oracle"'

        self.assertIn(compile_object, source)
        self.assertEqual(source.count(compile_object), 1)
        self.assertLess(
            source.index("scripts/build_x86_64_owned_dynamic_sysroot.py"),
            source.index(compile_object),
        )
        self.assertLess(source.index(compile_object), source.index(oracle_link))
        for link in (
            oracle_link,
            '"$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 "$work/probe.o" -o "$work/$mode"',
            '"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$work/probe.o" -o "$work/dynamic-$mode"',
        ):
            self.assertIn(link, source)
        self.assertNotIn("-fPIC", source)
        self.assertNotIn('-I"$ROOT/include"', source)


if __name__ == "__main__":
    unittest.main()
