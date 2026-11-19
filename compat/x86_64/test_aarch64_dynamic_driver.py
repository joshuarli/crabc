#!/usr/bin/env python3
"""Exercise the installed arm64 driver's search and hash choices."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import owned_dynamic_elf as elf


class Aarch64DynamicOptions(unittest.TestCase):
    def test_search_and_hash_choices(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_PRODUCT"])
        driver = product / "bin/crabc-cc-dynamic"
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            work = Path(directory)
            source = work / "fixture.c"
            source.write_text("int main(void) { return 0; }\n")
            for style, expected in (("sysv", ("(HASH)",)), ("gnu", ("(GNU_HASH)",)),
                                    ("both", ("(HASH)", "(GNU_HASH)"))):
                output = work / (style + ".so")
                subprocess.run([driver, "--dynamic-pie", "--application-hash-style", style,
                                "--application-rpath", "/fixture", source, "-o", output], check=True)
                dynamic = subprocess.check_output(["readelf", "-dW", output], text=True)
                facts = elf.inspect(output, architecture="aarch64")
                self.assertEqual(facts["machine"], "EM_AARCH64")
                inspection_path, link_map = elf.sidecar_paths(output)
                inspected = json.loads(inspection_path.read_text())
                self.assertEqual(inspected["facts"], facts)
                self.assertTrue(link_map.stat().st_size)
                elf.validate_record(inspected, output, output_format="crabc-aarch64-owned-dynamic-sysroot-v1",
                                    fail=self.fail, architecture="aarch64")
                self.assertTrue(all(tag in dynamic for tag in expected))
                self.assertIn("(RPATH)", dynamic)
                self.assertNotIn("(RUNPATH)", dynamic)
                receipt = json.loads(Path(str(output) + ".crabc-link.json").read_text())
                self.assertEqual((receipt["application_hash_style"], receipt["application_search_kind"],
                                  receipt["application_rpath"]), (style, "rpath", "/fixture"))
            plan = json.loads(subprocess.check_output([driver, "--dynamic-pie", "--application-hash-style", "both", "--application-rpath", "/legacy", "--print-link-plan"], text=True))
            self.assertEqual((plan["application_hash_style"], plan["application_search_kind"], plan["application_rpath"]), ("both", "rpath", "/legacy"))
            self.assertIn("--hash-style=both", plan["linker"])
            self.assertIn("--disable-new-dtags", plan["linker"])
            for options in (("--application-hash-style", "invalid"),
                            ("--application-hash-style", "gnu", "--application-hash-style", "sysv"),
                            ("--application-rpath", "/a", "--application-runpath", "/b")):
                result = subprocess.run([driver, "--dynamic-shared-object", *options, source,
                                         "-o", work / "invalid.so"], capture_output=True)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
