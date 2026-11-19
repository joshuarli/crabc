#!/usr/bin/env python3
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import platform
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


CAN_BUILD = platform.system() == "Linux" and platform.machine() in ("aarch64", "arm64") and Path("/opt/cargo/bin/rustup").is_file()


class Aarch64DynamicNonPieTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT"):
            return
        if not CAN_BUILD:
            return
        root = Path(__file__).resolve().parents[3]
        cls.product_dir = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        cls.addClassCleanup(cls.product_dir.cleanup)
        product = Path(cls.product_dir.name) / "sysroot"
        subprocess.run([sys.executable, "-B", str(root / "scripts/build_x86_64_owned_dynamic_sysroot.py"),
                        "--architecture", "aarch64", "--output", str(product)], cwd=root, check=True)
        os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"] = str(product)
        cls.addClassCleanup(os.environ.pop, "CRABC_AARCH64_DYNAMIC_SYSROOT", None)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_dso_declarations_validate_native_reserved_names_before_planning(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = product / "bin/crabc-cc-dynamic"
        for option in ("--application-dso", "--transitive-application-dso"):
            for name in ("libc.so", "ld-crabc-aarch64.so.1", "ld-musl-aarch64.so.1", "libapp.so.5beta"):
                with self.subTest(option=option, name=name):
                    result = subprocess.run([driver, "-pie", option, "/tmp/" + name, "--print-link-plan"],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue("reserved application DSO" in result.stderr or
                                    "unowned application DSO" in result.stderr, result.stderr)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_link_evidence_requires_exact_opt_in_and_retains_source_object(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = product / "bin/crabc-cc-dynamic"
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            work = Path(directory)
            source, output = work / "main.c", work / "main"
            source.write_text("int main(void) { return 0; }\n")
            for value in ("", "0", "true", "retain"):
                with self.subTest(value=value):
                    result = subprocess.run([driver, "-pie", source, "-o", output], capture_output=True, text=True,
                                            env={**os.environ, "CRABC_X86_64_RETAIN_LINK_EVIDENCE": value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("retain link evidence", result.stderr)
                    self.assertFalse(output.exists())
            subprocess.run([driver, "-pie", source, "-o", output], check=True,
                           env={**os.environ, "CRABC_X86_64_RETAIN_LINK_EVIDENCE": "1"})
            receipt = json.loads(Path(str(output) + ".crabc-link.json").read_text())
            objects = [Path(item["path"]) for item in receipt["input_receipts"]
                       if item["path"].endswith("/0.o")]
            self.assertEqual(len(objects), 1)
            self.assertTrue(objects[0].is_file())
            self.assertTrue(objects[0].parent.name.startswith("crabc-dynamic-link."))

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_link_plan_preserves_runpath_and_export_policy(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = product / "bin/crabc-cc-dynamic"
        plan = json.loads(subprocess.check_output([driver, "-pie", "-rdynamic", "--application-runpath",
                                                   "/app/lib:$ORIGIN/plugins", "--print-link-plan"], text=True))
        self.assertEqual(plan["application_runpath"], "/app/lib:$ORIGIN/plugins")
        self.assertIn("/app/lib:$ORIGIN/plugins", plan["linker"])
        self.assertIn("--export-dynamic", plan["linker"])
        result = subprocess.run([driver, "-shared", "-rdynamic", "--print-link-plan"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-rdynamic", result.stderr)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_receipt_reservations_precede_translation_and_preserve_existing_files(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = product / "bin/crabc-cc-dynamic"
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            work = Path(directory)
            source = work / "invalid.c"
            source.write_text("this is not C\n")
            for kind in ("regular", "symlink", "hardlink"):
                with self.subTest(kind=kind):
                    output = work / kind
                    receipt = Path(str(output) + ".crabc-link.json")
                    original = work / (kind + ".original")
                    original.write_bytes(b"existing receipt")
                    if kind == "regular":
                        receipt.write_bytes(b"existing receipt")
                    elif kind == "symlink":
                        receipt.symlink_to(original)
                    else:
                        os.link(original, receipt)
                    result = subprocess.run([driver, "-pie", source, "-o", output], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue("reserve dynamic link receipt" in result.stderr or "symlink" in result.stderr,
                                    result.stderr)
                    self.assertEqual(receipt.read_bytes(), b"existing receipt")
                    self.assertEqual(original.read_bytes(), b"existing receipt")
                    self.assertFalse(output.exists())
            output = work / "new"
            result = subprocess.run([driver, "-pie", source, "-o", output], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(Path(str(output) + ".crabc-link.json").exists())
            self.assertFalse(output.exists())

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_failed_link_preserves_replaced_receipt_inode(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        loader = importlib.machinery.SourceFileLoader("arm_driver_test", str(product / "bin/crabc-cc-dynamic"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            work = Path(directory)
            source, output = work / "main.c", work / "main"
            source.write_text("int main(void) { return 0; }\n")
            receipt = Path(str(output) + ".crabc-link.json")
            receipt.write_bytes(b"existing receipt")
            with mock.patch.object(module.dynamic_shared, "dynamic_symbols") as inspect:
                with self.assertRaises(module.shared.DriverError):
                    module.execute(["-pie", str(source), "-o", str(output)])
                inspect.assert_not_called()
            self.assertEqual(receipt.read_bytes(), b"existing receipt")
            receipt.unlink()

            def fail_link(*args, **kwargs):
                self.assertEqual(receipt.read_bytes(), b"")
                receipt.unlink()
                receipt.write_bytes(b"competing receipt")
                raise subprocess.CalledProcessError(1, args[0])

            with mock.patch.object(module.shared, "run_checked"), \
                 mock.patch.object(module.dynamic_shared, "dynamic_symbols", return_value=(set(), set())), \
                 mock.patch.object(module.subprocess, "run", side_effect=fail_link):
                with self.assertRaises(subprocess.CalledProcessError):
                    module.execute(["-pie", str(source), "-o", str(output)])
            self.assertEqual(receipt.read_bytes(), b"competing receipt")

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_resealed_crt_and_loader_provenance_drift_is_rejected(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            work = Path(temporary)
            source = work / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            for name in ("crt.provenance.json", "loader.provenance.json"):
                with self.subTest(name=name):
                    copy = work / name
                    shutil.copytree(product, copy, symlinks=True)
                    loader = copy / "lib/ld-crabc-aarch64.so.1"
                    loader.unlink()
                    os.link(copy / "usr/lib/libc.so", loader)
                    relative = "share/crabc/" + name
                    path = copy / relative
                    value = json.loads(path.read_text())
                    if name.startswith("crt"):
                        value["hardening_profile"] = "hardened"
                    else:
                        value["artifact"]["sha256"] = "0" * 64
                    path.write_text(json.dumps(value))
                    manifest_path = copy / "share/crabc/manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["files"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    manifest_path.write_text(json.dumps(manifest))
                    output = work / (name + ".o")
                    result = subprocess.run([copy / "bin/crabc-cc-dynamic", "--dynamic-pie", "-c", source,
                                             "-o", output], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_driver_rejects_target_input_injection_before_compiling(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            work = Path(temporary)
            source = work / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            for option in ("--sysroot=/", "-nostdinc", "-Wl,--dynamic-linker,/tmp/loader", "-L/tmp", "-lc"):
                with self.subTest(option=option):
                    output = work / "injected.o"
                    result = subprocess.run([product / "bin/crabc-cc-dynamic", "--dynamic-pie", "-c", option,
                                             source, "-o", output], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_driver_rejects_unsealed_payload_and_static_or_implicit_modes(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            work = Path(temporary)
            driver = product / "bin/crabc-cc-dynamic"
            source = work / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            for arguments in ([str(source)], ["-static", str(source)], ["-static-pie", str(source)],
                              ["--static-et-exec", str(source)], ["--static-pie", str(source)]):
                result = subprocess.run([driver, *arguments, "-o", work / "out"], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, arguments)
            copy = work / "product"
            shutil.copytree(product, copy, symlinks=True)
            loader = copy / "lib/ld-crabc-aarch64.so.1"
            loader.unlink()
            os.link(copy / "usr/lib/libc.so", loader)
            with (copy / "usr/include/stddef.h").open("ab") as target:
                target.write(b"tampered")
            result = subprocess.run([copy / "bin/crabc-cc-dynamic", "-pie", "-c", source,
                                     "-o", work / "tampered.o"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("payload hash mismatch", result.stderr)
            self.assertFalse((work / "tampered.o").exists())

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_direct_dso_rejects_undeclared_dependencies_and_unresolved_imports(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temporary:
            work = Path(temporary)
            leaf, middle, missing, main = (work / name for name in ("leaf.c", "middle.c", "missing.c", "main.c"))
            leaf.write_text("int leaf(void) { return 7; }\n")
            middle.write_text("int leaf(void); int middle(void) { return leaf(); }\n")
            missing.write_text("int absent(void); int call(void) { return absent(); }\n")
            main.write_text("int main(void) { return 0; }\n")
            driver = product / "bin/crabc-cc-dynamic"
            leaf_so, middle_so, missing_so = (work / name for name in ("leaf.so", "middle.so", "missing.so"))
            subprocess.run([driver, "-shared", leaf, "-o", leaf_so], check=True)
            subprocess.run([driver, "-shared", middle, "--application-dso", leaf_so, "-o", middle_so], check=True)
            subprocess.run(["gcc", "-shared", "-fPIC", "-nostdlib", "-Wl,-soname,missing.so", missing,
                            "-o", missing_so], check=True)
            for dso, expected in ((middle_so, "undeclared transitive"), (missing_so, "unresolved runtime imports")):
                result = subprocess.run([driver, "-pie", main, "--application-dso", dso,
                                         "-o", work / "bad"], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
            search_dso = work / "search.so"
            subprocess.run([driver, "-shared", leaf, "--application-runpath", "/fixture", "-o", search_dso], check=True)
            receipt_path = Path(str(search_dso) + ".crabc-link.json")
            receipt = json.loads(receipt_path.read_text())
            receipt["unreviewed"] = True
            receipt_path.write_text(json.dumps(receipt))
            result = subprocess.run([driver, "-pie", main, "--application-dso", search_dso,
                                     "-o", work / "bad-search"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fields do not match", result.stderr)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_posix_link_reader_rejects_tampered_native_receipt(self):
        root = Path(__file__).resolve().parents[3]
        sys.path.insert(0, str(root / "compat/x86_64"))
        import owned_posix_product_evidence as evidence
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = str(product / "bin/crabc-cc-dynamic")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
            work = Path(tmp)
            source, obj, binary = (work / name for name in ("main.c", "main.o", "main"))
            source.write_text("int main(void) { return 0; }\n")
            subprocess.run([driver, "-pie", "-c", str(source), "-o", str(obj)], check=True)
            subprocess.run([driver, "-pie", str(obj), "-o", str(binary)], check=True)
            receipt = Path(str(binary) + ".crabc-link.json")
            record = json.loads(receipt.read_text())
            evidence.validate_link(product, obj, binary, receipt, "pie")
            evidence.validate_retained_link(root, "/workspace", product, obj, binary, receipt, "pie", record["resolved_linker"])
            record["link_command"].insert(1, "--allow-multiple-definition")
            receipt.write_text(json.dumps(record))
            with self.assertRaises(evidence.ProductEvidenceError):
                evidence.validate_link(product, obj, binary, receipt, "pie")
            with self.assertRaises(evidence.ProductEvidenceError):
                evidence.validate_retained_link(root, "/workspace", product, obj, binary, receipt, "pie", record["resolved_linker"])

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_lazy_binding_requires_exact_runtime_imports(self):
        product = Path(os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]).resolve(strict=True)
        driver = str(product / "bin/crabc-cc-dynamic")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
            work = Path(tmp)
            source = work / "plugin.c"
            source.write_text("extern int missing(void); int call(void) { return missing(); }\n")
            for args in (["--binding", "lazy"], ["--binding", "lazy", "--runtime-import", "wrong"],
                         ["--binding", "now", "--runtime-import", "missing"],
                         ["--binding", "lazy", "--binding", "now"]):
                output = work / "bad.so"
                result = subprocess.run([driver, "-shared", *args, str(source), "-o", str(output)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(Path(str(output) + ".crabc-link.json").exists())
            output = work / "plugin.so"
            subprocess.run([driver, "-shared", "--binding", "lazy", "--runtime-import", "missing",
                            str(source), "-o", str(output)], check=True)
            dynamic = subprocess.check_output(["readelf", "-dW", str(output)], text=True)
            self.assertNotIn("BIND_NOW", dynamic)
            receipt = json.loads(Path(str(output) + ".crabc-link.json").read_text())
            self.assertEqual(receipt["binding"], "lazy")
            self.assertEqual(receipt["runtime_imports"], ["missing"])
            source.write_text("extern int missing(void); static int impl(void) { return 0; }\n"
                              "static void *resolve(void) { return impl; }\n"
                              "int witness(void) __attribute__((ifunc(\"resolve\")));\n"
                              "int call(void) { return missing(); }\n")
            obj = work / "ifunc.o"
            subprocess.run(["gcc", "-fPIC", "-c", source, "-o", obj], check=True)
            result = subprocess.run([driver, "-shared", "--binding", "lazy", "--runtime-import", "missing",
                                     obj, "-o", work / "ifunc.so"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("IFUNC", result.stderr)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
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

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
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

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
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
            receipt_path.write_text(json.dumps({**middle_receipt, "unreviewed": True}))
            extra = subprocess.run([driver, "-pie", str(main), "--application-dso", str(middle_so),
                                    "--transitive-application-dso", str(leaf_so), "-o", str(work / "extra")],
                                   capture_output=True, text=True)
            self.assertNotEqual(extra.returncode, 0)
            self.assertIn("fields do not match", extra.stderr)
            middle_receipt["application_dsos"]["leaf.so"] = "0" * 64
            receipt_path.write_text(json.dumps(middle_receipt))
            tampered = subprocess.run([driver, "-pie", str(main), "--application-dso", str(middle_so),
                                       "--transitive-application-dso", str(leaf_so), "-o", str(work / "tampered")],
                                      capture_output=True, text=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("application DSO input identity differs", tampered.stderr)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_errno_alias_regression(self):
        root = Path(__file__).resolve().parents[3]
        subprocess.run(["bash", str(root / "compat/x86_64/tests/test_aarch64_errno_alias.sh"),
                        os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]], cwd=root, check=True)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_dynamic_driver_regression(self):
        root = Path(__file__).resolve().parents[3]
        environment = {**os.environ, "CRABC_AARCH64_DYNAMIC_PRODUCT": os.environ["CRABC_AARCH64_DYNAMIC_SYSROOT"]}
        subprocess.run([sys.executable, "-B", str(root / "compat/x86_64/test_aarch64_dynamic_driver.py")],
                       cwd=root, env=environment, check=True)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_tls_trace_regression(self):
        root = Path(__file__).resolve().parents[3]
        subprocess.run([sys.executable, "-B", str(root / "compat/x86_64/test_aarch64_tls_trace.py")], cwd=root, check=True)

    @unittest.skipUnless(os.environ.get("CRABC_AARCH64_DYNAMIC_SYSROOT") or CAN_BUILD, "requires a built aarch64 product")
    def test_default_runtime_regression(self):
        root = Path(__file__).resolve().parents[3]
        subprocess.run(["bash", str(root / "compat/x86_64/run_aarch64_default_runtime_regression.sh")], cwd=root, check=True)


if __name__ == "__main__":
    unittest.main()
