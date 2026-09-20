#!/usr/bin/env python3
"""Native framing regression for the composed text/locale/numeric driver."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
DRIVER = ROOT / "compat/x86_64/owned_text_locale_numeric_component_driver.c"
SOURCE_SPECIFIC_DRIVER = ROOT / "compat/x86_64/owned_text_locale_numeric_source_specific_driver.c"
SCRATCH = ROOT / ".work/x86_64/tmp"
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_SPECS = Path("/opt/musl-1.2.6/lib/musl-gcc.specs")
ORACLE_ENV = {
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
    "PATH": "/opt/musl-1.2.6/bin:/usr/local/bin:/usr/bin:/bin",
}
ROLES = (
    "float_parse", "locale_ctype_locators", "locale_narrow", "locale_object_wide",
    "locale_wide_iconv", "locale_multibyte", "wide_character", "owned_strfmon",
    "owned_wide_conversion",
)
FRAME_NAMES = (
    "float-parse", "ctype-locators", "locale-narrow", "locale-object-wide",
    "locale-wide-iconv", "locale-multibyte", "wide-character", "strfmon", "wide-conversion",
)
SOURCE_SPECIFIC_ROLES = (
    "locale_object_wide", "locale_wide_iconv", "locale_multibyte",
)
SOURCE_SPECIFIC_FRAME_NAMES = (
    "locale-object-wide-profile", "locale-wide-iconv-profile", "locale-multibyte-profile",
)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"},
                     "driver framing is a native Linux/x86-64 check")
@unittest.skipUnless(ORACLE_CC.is_file() and ORACLE_SPECS.is_file(),
                     "driver framing requires the pinned musl-1.2.6 image")
class DriverFramingTests(unittest.TestCase):
    def _assert_buffered_frames(self, driver: Path, roles: tuple[str, ...], frame_names: tuple[str, ...],
                                prefix: str) -> None:
        self.assertTrue(os.access(ORACLE_CC, os.X_OK), "pinned musl compiler is not executable")
        wrapper = ORACLE_CC.read_text(encoding="utf-8")
        self.assertIn("x86-64 C/POSIX oracle compiler", wrapper)
        self.assertIn("exec /usr/bin/gcc -specs /opt/musl-1.2.6/lib/musl-gcc.specs", wrapper)
        specs = ORACLE_SPECS.read_text(encoding="utf-8")
        self.assertIn("-isystem /opt/musl-1.2.6/include", specs)
        self.assertIn("-L/opt/musl-1.2.6/lib", specs)
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="text-locale-numeric-driver.", dir=SCRATCH) as temporary:
            work = Path(temporary)
            fake = work / "fake-probes.c"
            definitions = "\n".join(
                f"int crabc_x86_64_{role}_probe(void) {{ printf(\"payload/{name}\\n\"); return 0; }}"
                for role, name in zip(roles, frame_names)
            )
            fake.write_text("#include <stdio.h>\n" + definitions + "\n", encoding="utf-8")
            executable = work / "driver"
            build = subprocess.run(
                [str(ORACLE_CC), "-std=c11", "-static", "-fno-pie", "-no-pie",
                 str(driver), str(fake), "-o", str(executable)],
                cwd=ROOT, env=ORACLE_ENV, capture_output=True, text=True, check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(executable)], env=ORACLE_ENV, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            expected = "".join(
                f"{prefix}/{name}:begin\npayload/{name}\n{prefix}/{name}:ok\n"
                for name in frame_names
            )
            self.assertEqual(run.stdout, expected)

    def test_buffered_probe_payload_stays_between_normal_frames(self) -> None:
        self._assert_buffered_frames(DRIVER, ROLES, FRAME_NAMES, "text-locale-numeric")

    def test_buffered_probe_payload_stays_between_source_specific_frames(self) -> None:
        self._assert_buffered_frames(SOURCE_SPECIFIC_DRIVER, SOURCE_SPECIFIC_ROLES,
                                     SOURCE_SPECIFIC_FRAME_NAMES,
                                     "text-locale-numeric-source-specific")


if __name__ == "__main__":
    unittest.main()
