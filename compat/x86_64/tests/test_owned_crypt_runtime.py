#!/usr/bin/env python3
"""Contracts for the bounded installed owned-crypt receipt."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_crypt_runtime.sh"
DOCUMENT = ROOT / "compat" / "x86_64" / "owned-crypt-runtime.md"
EVIDENCE = ROOT / "compat" / "x86_64" / "owned_crypt_runtime_evidence.py"


def load_evidence():
    spec = __import__("importlib.util").util.spec_from_file_location(
        "owned_crypt_runtime_evidence", EVIDENCE,
    )
    assert spec is not None and spec.loader is not None
    module = __import__("importlib.util").util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OwnedCryptRuntimeTests(unittest.TestCase):
    def assert_parser_usage(self, *arguments: str) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-crypt-parser.", dir=scratch) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            fake_python = tools / "python3"
            fake_python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            fake_python.chmod(0o755)
            result = subprocess.run(
                ["bash", str(RUNNER), *arguments],
                cwd=ROOT,
                env={**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"},
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_replay_parser_rejects_option_and_ambiguous_product_paths(self) -> None:
        for label, arguments in (
            ("missing static", ("--static-sysroot",)),
            ("empty static", ("--static-sysroot", "")),
            ("dash static", ("--static-sysroot", "-x")),
            ("empty dynamic", ("",)),
            ("dash dynamic", ("-x",)),
            ("duplicate static", ("--static-sysroot", "/one", "--static-sysroot", "/two")),
            ("duplicate dynamic", ("/one", "/two")),
        ):
            with self.subTest(label=label):
                self.assert_parser_usage(*arguments)

    def test_replay_product_must_be_checkout_local_physical_directory(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-crypt-product.", dir=scratch) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER), "--static-sysroot", str(ROOT)],
                cwd=ROOT,
                env={**os.environ, "TMPDIR": temporary},
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "owned crypt runtime static product must be a checkout .work directory",
            result.stderr,
        )
        self.assertNotIn("evidence:", result.stdout)

    def test_replay_rejects_lexical_parent_traversal_before_product_work(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-crypt-parent.", dir=scratch) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER), "--static-sysroot", str(ROOT / ".work" / "..")],
                cwd=ROOT,
                env={**os.environ, "TMPDIR": temporary},
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "owned crypt runtime static product has lexical parent traversal",
            result.stderr,
        )
        self.assertNotIn("evidence:", result.stdout)

    def test_one_installed_fixture_object_and_all_product_boundaries_are_explicit(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn('readonly PROBE="$ROOT/compat/x86_64/libc_crypt_probe.c"', runner)
        self.assertIn("-DCRABC_X86_CRYPT_CANDIDATE", runner)
        self.assertIn('"$installed/bin/crabc-cc-dynamic" --dynamic-pie', runner)
        self.assertIn('python3 -B "$PROFILE_EVIDENCE" abi-oracle --work "$work"', runner)
        self.assertIn('for mode in static static-pie; do', runner)
        self.assertIn('for mode in pie non-pie; do', runner)
        owner = (ROOT / 'compat/x86_64/owned_crypt_profile.py').read_text()
        self.assertIn("argv = ['/usr/sbin/chroot', str(directory), *([INTERPRETER] if entry == 'direct' else []), '/consumer']", owner)
        self.assertIn('from owned_posix_product_evidence import ProductEvidenceError, validate_link', runner)
        self.assertIn('readonly EXECUTION_EVIDENCE="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"', runner)
        self.assertIn('audit_execution_payload record', runner)
        self.assertIn('execution-pre.json', runner)
        self.assertIn('execution-post.json', runner)
        self.assertIn('execution-final.json', runner)
        self.assertLess(
            runner.index('audit_execution_payload record'),
            runner.index('run_capture "dynamic-$mode-kernel"'),
        )
        self.assertIn('assert_static_provider', runner)
        self.assertIn('assert_dynamic_provider', runner)
        self.assertIn('"crypt_r": "WEAK"', runner)
        self.assertIn('caller/shared-buffer overlap', runner)
        self.assertIn("functional/crypt", document)
        self.assertIn("not an upstream libc-test pass", document)
        self.assertIn("one installed-header fixture object", document)
        self.assertIn("every manifest symbolic-link alias", document)
        self.assertIn("candidate macro disabled", document)

    def test_compile_receipt_revalidates_the_installed_header_and_object(self) -> None:
        """The receipt binds inputs after sealing, rather than only recording them."""
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-crypt-compile.", dir=scratch) as temporary:
            fixture = Path(temporary)
            product = fixture / "product"
            headers = product / "usr" / "include"
            (headers / "bits").mkdir(parents=True)
            header_paths = [
                headers / "crypt.h", headers / "string.h", headers / "unistd.h",
                headers / "features.h", headers / "bits" / "alltypes.h",
            ]
            for header in header_paths:
                header.write_text("/* fixture header */\n", encoding="utf-8")
            source = fixture / "fixture.c"
            source.write_text("int fixture;\n", encoding="utf-8")
            driver = product / "bin" / "crabc-cc-dynamic"
            driver.parent.mkdir(parents=True)
            driver.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            driver.chmod(0o755)
            (product / "share" / "crabc").mkdir(parents=True)
            (product / "share" / "crabc" / "manifest.json").write_text("{}\n", encoding="utf-8")
            compiler = fixture / "dependency-compiler"
            dependency_line = " ".join(str(item) for item in header_paths)
            compiler.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                f"print('fixture.o: ' + sys.argv[-1] + ' {dependency_line}')\n",
                encoding="utf-8",
            )
            compiler.chmod(0o755)
            (product / "share" / "crabc" / "crabc_cc_static.py").write_text(
                "def compiler():\n"
                f"    return {str(compiler)!r}\n"
                "def clean_environment():\n"
                "    return {'PATH': '/usr/bin:/bin'}\n",
                encoding="utf-8",
            )
            work = fixture / "work"
            work.mkdir()
            runner = RUNNER.read_text(encoding="utf-8")
            start = runner.index("compile_receipt() {")
            end = runner.index("\nsource_sha256_before_compile=", start)
            compile_receipt = runner[start:end]

            def invoke(mutation: str | None) -> subprocess.CompletedProcess[str]:
                source_hash = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
                shell = "\n".join((
                    "set -euo pipefail",
                    compile_receipt,
                    f"installed={shlex.quote(str(product))}",
                    f"work={shlex.quote(str(work))}",
                    f"PROBE={shlex.quote(str(source))}",
                    f"source_sha256_before_compile={shlex.quote(source_hash)}",
                    "compile_receipt capture",
                    'printf \'immutable object\\n\' >"$work/workload.o"',
                    "compile_receipt seal",
                    "compile_receipt verify",
                    mutation or ":",
                    "compile_receipt verify",
                ))
                return subprocess.run(
                    ["bash", "-s"], input=shell, capture_output=True, text=True, check=False,
                )

            result = invoke(None)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = invoke('printf \'changed object\\n\' >"$work/workload.o"')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workload object changed", result.stderr)
            result = invoke('printf \'changed header\\n\' >' + shlex.quote(str(headers / "crypt.h")))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("installed dependency changed", result.stderr)

    def test_each_link_uses_the_shared_validator_with_its_single_object(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-crypt-link.", dir=scratch) as temporary:
            fixture = Path(temporary)
            checkout = fixture / "checkout"
            helper = checkout / "compat" / "x86_64" / "owned_posix_product_evidence.py"
            helper.parent.mkdir(parents=True)
            helper.write_text(
                "import json\n"
                "import os\n"
                "from pathlib import Path\n"
                "\n"
                "class ProductEvidenceError(RuntimeError):\n"
                "    pass\n"
                "\n"
                "def validate_link(product, workload, executable, receipt, linkage):\n"
                "    value = {'product': str(Path(product).resolve()),\n"
                "             'workload': str(Path(workload).resolve()),\n"
                "             'executable': str(Path(executable).resolve()),\n"
                "             'receipt': str(Path(receipt).resolve()), 'linkage': linkage}\n"
                "    Path(os.environ['OWNED_CRYPT_CAPTURE']).write_text(json.dumps(value), encoding='utf-8')\n"
                "    return {'linkage': linkage, 'product': value['product'],\n"
                "            'product_format': 'fixture', 'product_manifest_sha256': '0' * 64,\n"
                "            'workload_sha256': '1' * 64, 'executable_sha256': '2' * 64,\n"
                "            'receipt_sha256': '3' * 64}\n",
                encoding="utf-8",
            )
            product = fixture / "product"
            work = fixture / "work"
            product.mkdir()
            work.mkdir()
            object_path = work / "workload.o"
            candidate = work / "consumer"
            receipt = work / "consumer.receipt.json"
            object_path.write_bytes(b"one installed object\n")
            candidate.write_bytes(b"candidate\n")
            receipt.write_bytes(b"receipt\n")

            runner = RUNNER.read_text(encoding="utf-8")
            start = runner.index("audit_owned_link() {")
            end = runner.index("\nrun_capture() {", start)
            audit = runner[start:end]
            for mode in ("static", "non-pie"):
                with self.subTest(mode=mode):
                    capture = work / f"{mode}.capture.json"
                    identity = work / f"{mode}.identity.json"
                    shell = "\n".join((
                        "set -euo pipefail",
                        audit,
                        f"ROOT={shlex.quote(str(checkout))}",
                        "audit_owned_link " + " ".join(map(shlex.quote, (
                            str(product), str(object_path), str(candidate), str(receipt),
                            mode, str(identity),
                        ))),
                    ))
                    result = subprocess.run(
                        ["bash", "-s"], input=shell, capture_output=True, text=True,
                        env={**os.environ, "OWNED_CRYPT_CAPTURE": str(capture)},
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(capture.read_text(encoding="utf-8")), {
                        "product": str(product.resolve()),
                        "workload": str(object_path.resolve()),
                        "executable": str(candidate.resolve()),
                        "receipt": str(receipt.resolve()),
                        "linkage": mode,
                    })
                    self.assertEqual(json.loads(identity.read_text(encoding="utf-8"))["linkage"], mode)

    def test_execution_payload_seals_manifest_aliases_and_consumers(self) -> None:
        """A copied dynamic root cannot exchange an alias, payload, or consumer."""
        evidence = load_evidence()
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-crypt-execution.", dir=scratch) as temporary:
            fixture = Path(temporary)
            product = fixture / "product"
            execution_root = fixture / "execution-root"
            manifest = product / "share" / "crabc" / "manifest.json"
            payload = product / "usr" / "lib" / "libc.so"
            source_consumer = fixture / "consumer"
            copied_consumer = execution_root / "consumer"
            alias = "lib/ld-musl-x86_64.so.1"
            alias_target = "ld-crabc-x86_64.so.1"
            manifest.parent.mkdir(parents=True)
            payload.parent.mkdir(parents=True)
            (product / "lib").mkdir()
            payload.write_bytes(b"source payload\\n")
            manifest.write_text(
                json.dumps({
                    "files": {"usr/lib/libc.so": __import__("hashlib").sha256(payload.read_bytes()).hexdigest()},
                    "symlinks": {alias: alias_target},
                }),
                encoding="utf-8",
            )
            (product / alias).symlink_to(alias_target)
            (execution_root / "share" / "crabc").mkdir(parents=True)
            (execution_root / "usr" / "lib").mkdir(parents=True)
            (execution_root / "lib").mkdir()
            (execution_root / "share" / "crabc" / "manifest.json").write_bytes(manifest.read_bytes())
            (execution_root / "usr" / "lib" / "libc.so").write_bytes(payload.read_bytes())
            (execution_root / alias).symlink_to(alias_target)
            source_consumer.write_bytes(b"consumer\\n")
            copied_consumer.write_bytes(source_consumer.read_bytes())

            with patch.object(
                evidence, "_validate_dynamic_product", return_value=(manifest, {"usr/lib/libc.so": evidence.digest(payload)})
            ):
                record = fixture / "execution-payload.json"
                evidence.record_execution_payload(product, execution_root, source_consumer, copied_consumer, record)
                evidence.audit_execution_payload(product, execution_root, source_consumer, copied_consumer, record)

                copied_consumer.write_bytes(b"tampered consumer\\n")
                with self.assertRaisesRegex(evidence.CryptRuntimeEvidenceError, "execution consumer copy identity drifted"):
                    evidence.audit_execution_payload(product, execution_root, source_consumer, copied_consumer, record)
                copied_consumer.write_bytes(source_consumer.read_bytes())

                (execution_root / alias).unlink()
                (execution_root / alias).symlink_to("wrong-loader")
                with self.assertRaisesRegex(evidence.CryptRuntimeEvidenceError, "execution alias .* copy target drifted"):
                    evidence.audit_execution_payload(product, execution_root, source_consumer, copied_consumer, record)
                (execution_root / alias).unlink()
                (execution_root / alias).symlink_to(alias_target)

                (execution_root / "usr" / "lib" / "libc.so").write_bytes(b"tampered payload\\n")
                with self.assertRaisesRegex(evidence.CryptRuntimeEvidenceError, "execution payload .* copy identity drifted"):
                    evidence.audit_execution_payload(product, execution_root, source_consumer, copied_consumer, record)


if __name__ == "__main__":
    unittest.main()
