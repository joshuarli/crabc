#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class Aarch64DynamicNonPieTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT"), "requires a built aarch64 product")
    def test_non_pie_receipt_and_execution(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
            work = Path(tmp)
            source, obj, binary = (work / name for name in ("hello.c", "hello.o", "hello"))
            source.write_text("int main(void) { return 0; }\n")
            driver = str(product / "bin/crabc-cc-dynamic")
            subprocess.run([driver, "--dynamic-non-pie", "-c", str(source), "-o", str(obj)], check=True)
            subprocess.run([driver, "--dynamic-non-pie", str(obj), "-o", str(binary)], check=True)
            header = subprocess.check_output(["readelf", "-hW", str(binary)], text=True)
            segments = subprocess.check_output(["readelf", "-lW", str(binary)], text=True)
            self.assertIn("EXEC (Executable file)", header)
            self.assertIn("/lib/ld-crabc-aarch64.so.1", segments)
            receipt = json.loads(Path(str(binary) + ".crabc-link.json").read_text())
            self.assertEqual(receipt["mode"], "exec")
            self.assertIn("usr/lib/crt1.o", receipt["owned_runtime_inputs"])
            self.assertNotIn("usr/lib/Scrt1.o", receipt["owned_runtime_inputs"])
            subprocess.run([str(product / "lib/ld-crabc-aarch64.so.1"), str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
