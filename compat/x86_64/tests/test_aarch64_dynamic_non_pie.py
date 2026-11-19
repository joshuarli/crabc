#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class Aarch64DynamicNonPieTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT"), "requires a built aarch64 product")
    def test_application_dependency_file(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = str(product / "bin/crabc-cc-dynamic")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
            work = Path(tmp)
            source, header, obj, dep = (work / name for name in ("main.c", "local.h", "main.o", "main.d"))
            source.write_text('#include "local.h"\n#include <stddef.h>\nint x = VALUE;\n')
            header.write_text('#define VALUE 1\n')
            subprocess.run([driver, "-pie", "-c", str(source), "-o", str(obj),
                            "--application-dependency-file", str(dep)], check=True)
            content = dep.read_text()
            self.assertIn(str(source), content)
            self.assertIn(str(header), content)
            self.assertIn(str(product / "usr/include/stddef.h"), content)
            for args in (["-pie", str(source), "-o", str(work / "bin"), "--application-dependency-file", str(dep)],
                         ["-pie", "-c", str(source), "-o", str(obj), "--application-dependency-file", str(source)],
                         ["-pie", "-c", str(source), "-o", str(obj), "--application-dependency-file", str(dep),
                          "--application-dependency-file", str(dep)]):
                result = subprocess.run([driver, *args], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

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

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT"), "requires a built aarch64 product")
    def test_transitive_application_dso_is_validation_only(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = str(product / "bin/crabc-cc-dynamic")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
            work = Path(tmp)
            leaf, middle, main = (work / name for name in ("leaf.c", "middle.c", "main.c"))
            leaf.write_text("int leaf(void) { return 7; }\n")
            middle.write_text("int leaf(void); int middle(void) { return leaf(); }\n")
            main.write_text("int middle(void); int main(void) { return middle() != 7; }\n")
            leaf_so, middle_so, binary = (work / name for name in ("leaf.so", "middle.so", "main"))
            subprocess.run([driver, "-shared", str(leaf), "-o", str(leaf_so)], check=True)
            subprocess.run([driver, "-shared", str(middle), "--application-dso", str(leaf_so), "-o", str(middle_so)], check=True)
            subprocess.run([driver, "-pie", str(main), "--application-dso", str(middle_so),
                            "--transitive-application-dso", str(leaf_so), "-o", str(binary)], check=True)
            receipt = json.loads(Path(str(binary) + ".crabc-link.json").read_text())
            self.assertEqual(receipt["schema"], 3)
            self.assertEqual(receipt["application_dso_roles"], {"middle.so": "direct", "leaf.so": "transitive"})
            self.assertNotIn(str(leaf_so), receipt["link_command"])
            needed = subprocess.check_output(["readelf", "-dW", str(binary)], text=True)
            self.assertIn("[middle.so]", needed)
            self.assertNotIn("[leaf.so]", needed)
            rejected = subprocess.run([driver, "-pie", str(main), "--transitive-application-dso", str(leaf_so),
                                       "-o", str(work / "bad")], capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("require one direct", rejected.stderr)
            missing = subprocess.run([driver, "-pie", str(main), "--application-dso", str(middle_so),
                                      "--transitive-application-dso", str(middle_so), "-o", str(work / "duplicate")],
                                     capture_output=True, text=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("duplicate application DSO", missing.stderr)
            receipt_path = Path(str(middle_so) + ".crabc-link.json")
            middle_receipt = json.loads(receipt_path.read_text())
            middle_receipt["application_dsos"]["leaf.so"] = "0" * 64
            receipt_path.write_text(json.dumps(middle_receipt))
            tampered = subprocess.run([driver, "-pie", str(main), "--application-dso", str(middle_so),
                                       "--transitive-application-dso", str(leaf_so), "-o", str(work / "tampered")],
                                      capture_output=True, text=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("dependency identities differ", tampered.stderr)


if __name__ == "__main__":
    unittest.main()
