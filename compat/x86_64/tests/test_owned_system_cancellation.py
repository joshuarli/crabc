#!/usr/bin/env python3
"""The owned system-cancellation replay interface stays unambiguous."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_system_cancellation.sh"
DOCUMENT = ROOT / "compat/x86_64/owned-system-cancellation.md"


class OwnedSystemCancellationTests(unittest.TestCase):
    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _make_compile_receipt_fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        product = root / "dynamic-product"
        work = root / "work"
        headers = product / "usr/include"
        driver = product / "bin/crabc-cc-dynamic"
        helper = product / "share/crabc/crabc_cc_static.py"
        manifest = product / "share/crabc/manifest.json"
        compiler = product / "compiler"
        probe = root / "owned_system_cancellation_probe.c"
        child = root / "owned_system_cancellation_child.c"
        witness = root / "owned_cancellation_proc_witness.h"

        work.mkdir(parents=True)
        driver.parent.mkdir(parents=True)
        helper.parent.mkdir(parents=True)
        headers.mkdir(parents=True)
        driver.write_bytes(b"dynamic driver\n")
        manifest.write_bytes(b"manifest\n")
        compiler.write_bytes(b"compiler\n")
        helper.write_text(
            "from pathlib import Path\n"
            "\n"
            "def compiler():\n"
            "    return str(Path(__file__).resolve().parents[2] / 'compiler')\n"
            "\n"
            "def clean_environment():\n"
            "    return {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}\n",
            encoding="utf-8",
        )
        probe.write_text("consumer source\n", encoding="utf-8")
        child.write_text("child source\n", encoding="utf-8")
        witness.write_text("consumer local witness\n", encoding="utf-8")

        header_names = {
            "consumer": (
                "errno.h", "pthread.h", "stdio.h", "stdlib.h", "signal.h",
                "sys/wait.h", "poll.h", "bits/alltypes.h",
            ),
            "child": (
                "stdio.h", "stdlib.h", "string.h", "signal.h", "unistd.h",
                "bits/alltypes.h",
            ),
        }
        for name in sorted({name for names in header_names.values() for name in names}):
            header = headers / name
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(f"{name}\n", encoding="utf-8")

        clean_environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        caller_flags = ["-std=c11", "-fno-builtin", "-fno-stack-protector"]
        prefix = [
            "-nostdinc", "-isystem", str(headers), "-ffreestanding", "-fno-builtin",
            "-fstack-protector-strong",
        ]
        roles = (
            ("consumer", probe, (probe, witness)),
            ("child", child, (child,)),
        )
        objects = []
        for role, source, local_inputs in roles:
            object_path = work / f"{role}.o"
            dependency_path = work / f"{role}.d"
            relocation_path = work / f"{role}.relocations"
            object_path.write_bytes(f"{role} object\n".encode("utf-8"))
            dependency_path.write_bytes(f"{role} dependencies\n".encode("utf-8"))
            relocation_path.write_bytes(f"{role} relocations\n".encode("utf-8"))
            dependencies = {
                str(path): self._digest(path)
                for path in (*local_inputs, *(headers / name for name in header_names[role]))
            }
            objects.append({
                "role": role,
                "source": str(source),
                "source_sha256": self._digest(source),
                "object": str(object_path),
                "object_sha256": self._digest(object_path),
                "actual_compile_command": [
                    str(driver), "--dynamic-pie", *caller_flags, "-c", str(source),
                    "-o", str(object_path),
                ],
                "dependency_audit_command": [
                    str(compiler), *prefix, *caller_flags, "-fPIE", "-M", str(source),
                ],
                "dependency_audit": {
                    "path": dependency_path.name,
                    "sha256": self._digest(dependency_path),
                },
                "dependencies": dependencies,
                "relocations": {
                    "path": relocation_path.name,
                    "sha256": self._digest(relocation_path),
                },
            })
        record = {
            "schema": "crabc.system-cancellation-compile/v2",
            "installed_dynamic": {
                "root": str(product),
                "manifest": {"path": str(manifest), "sha256": self._digest(manifest)},
                "driver": {"path": str(driver), "sha256": self._digest(driver)},
                "installed_helper": {"path": str(helper), "sha256": self._digest(helper)},
                "compiler": {"path": str(compiler), "sha256": self._digest(compiler)},
                "clean_environment": clean_environment,
            },
            "translation": {
                "driver_mode": "--dynamic-pie",
                "effective_codegen_flag": "-fPIE",
                "driver_compile_prefix": prefix,
                "caller_flags": caller_flags,
                "not_selected": ["-fPIC", "-fno-pie"],
            },
            "objects": objects,
        }
        (work / "compile.json").write_text(json.dumps(record), encoding="utf-8")
        return product, work, probe, child

    @staticmethod
    def _run_canonical_compile_assertion(
        product: Path, work: Path, probe: Path, child: Path,
    ) -> subprocess.CompletedProcess[str]:
        runner = RUNNER.read_text(encoding="utf-8")
        start = runner.index("assert_canonical_compile_receipt() {")
        end = runner.index("\naudit_musl_links() {", start)
        assertion = runner[start:end]
        shell = "\n".join((
            "set -euo pipefail",
            assertion,
            f"work={shlex.quote(str(work))}",
            f"PROBE={shlex.quote(str(probe))}",
            f"CHILD={shlex.quote(str(child))}",
            f"assert_canonical_compile_receipt {shlex.quote(str(product))}",
        ))
        return subprocess.run(
            ["bash", "-s"], input=shell, capture_output=True, text=True,
        )

    def test_canonical_compile_receipt_keeps_exact_two_role_local_inputs(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            fixture = Path(temporary)
            product, work, probe, child = self._make_compile_receipt_fixture(fixture / "good")
            result = self._run_canonical_compile_assertion(product, work, probe, child)
            self.assertEqual(result.returncode, 0, result.stderr)

            record_path = work / "compile.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            for missing_role in ("consumer", "child"):
                with self.subTest(missing_role=missing_role):
                    changed = {**record, "objects": [
                        item for item in record["objects"] if item["role"] != missing_role
                    ]}
                    record_path.write_text(json.dumps(changed), encoding="utf-8")
                    result = self._run_canonical_compile_assertion(product, work, probe, child)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("object role roster drifted", result.stderr)

            swapped = json.loads(json.dumps(record))
            consumer, child_record = swapped["objects"]
            consumer["object"], child_record["object"] = child_record["object"], consumer["object"]
            consumer["object_sha256"], child_record["object_sha256"] = (
                child_record["object_sha256"], consumer["object_sha256"]
            )
            record_path.write_text(json.dumps(swapped), encoding="utf-8")
            result = self._run_canonical_compile_assertion(product, work, probe, child)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical compile source changed after links", result.stderr)

            unwitnessed = json.loads(json.dumps(record))
            unwitnessed["objects"][0]["dependencies"].pop(
                str(probe.parent / "owned_cancellation_proc_witness.h")
            )
            record_path.write_text(json.dumps(unwitnessed), encoding="utf-8")
            result = self._run_canonical_compile_assertion(product, work, probe, child)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("local dependency roster drifted", result.stderr)

    def test_each_role_link_uses_its_selected_canonical_object(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            fixture = Path(temporary)
            checkout = fixture / "checkout"
            module = checkout / "compat/x86_64/owned_posix_product_evidence.py"
            module.parent.mkdir(parents=True)
            module.write_text(
                "from hashlib import sha256\n"
                "import json\n"
                "import os\n"
                "from pathlib import Path\n"
                "\n"
                "def digest(path):\n"
                "    return sha256(Path(path).read_bytes()).hexdigest()\n"
                "\n"
                "def validate_link(product, workload, executable, receipt, linkage):\n"
                "    product = Path(product).resolve()\n"
                "    workload = Path(workload).resolve()\n"
                "    executable = Path(executable).resolve()\n"
                "    receipt = Path(receipt).resolve()\n"
                "    Path(os.environ['SYSTEM_CANCELLATION_CAPTURE']).write_text(\n"
                "        json.dumps({'product': str(product), 'workload': str(workload),\n"
                "                    'executable': str(executable), 'receipt': str(receipt),\n"
                "                    'linkage': linkage}), encoding='utf-8')\n"
                "    return {'linkage': linkage, 'product': str(product),\n"
                "            'product_format': 'fixture', 'product_manifest_sha256': '0' * 64,\n"
                "            'workload_sha256': digest(workload),\n"
                "            'executable_sha256': digest(executable),\n"
                "            'receipt_sha256': digest(receipt)}\n",
                encoding="utf-8",
            )
            product = fixture / "product"
            work = fixture / "work"
            product.mkdir()
            work.mkdir()
            (work / "compile.json").write_text("{}\n", encoding="utf-8")

            runner = RUNNER.read_text(encoding="utf-8")
            start = runner.index("audit_link() {")
            end = runner.index("\nrun_product() {", start)
            audit_link = runner[start:end]
            for role, family, linkage in (
                ("consumer", "static", "static"),
                ("child", "dynamic", "non-pie"),
            ):
                with self.subTest(role=role):
                    object_path = work / f"{role}.o"
                    candidate = work / f"{role}-consumer"
                    receipt = work / f"{role}.receipt.json"
                    capture = work / f"{role}.capture.json"
                    object_path.write_bytes(f"{role} object\n".encode("utf-8"))
                    candidate.write_bytes(f"{role} executable\n".encode("utf-8"))
                    receipt.write_bytes(f"{role} receipt\n".encode("utf-8"))
                    shell = "\n".join((
                        "set -euo pipefail",
                        "fail() { return 1; }",
                        audit_link,
                        f"ROOT={shlex.quote(str(checkout))}",
                        f"work={shlex.quote(str(work))}",
                        "audit_link " + " ".join(map(shlex.quote, (
                            family, str(product), linkage, role, str(candidate),
                            str(object_path), str(receipt),
                        ))),
                    ))
                    result = subprocess.run(
                        ["bash", "-s"], input=shell, capture_output=True, text=True,
                        env={**os.environ, "SYSTEM_CANCELLATION_CAPTURE": str(capture)},
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    invocation = json.loads(capture.read_text(encoding="utf-8"))
                    self.assertEqual(invocation, {
                        "product": str(product.resolve()),
                        "workload": str(object_path.resolve()),
                        "executable": str(candidate.resolve()),
                        "receipt": str(receipt.resolve()),
                        "linkage": linkage,
                    })
                    evidence = json.loads(
                        Path(str(candidate) + ".evidence.json").read_text(encoding="utf-8")
                    )
                    self.assertEqual(evidence["role"], role)
                    self.assertEqual(
                        evidence["canonical_object"],
                        {"path": str(object_path.resolve()), "sha256": self._digest(object_path)},
                    )
                    self.assertEqual(evidence["sealed_link"]["workload_sha256"], self._digest(object_path))

    def test_static_replay_parser_rejects_short_options_before_product_tools(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            tools = Path(temporary)
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = {**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"}
            for arguments in (("-x",), ("--static-sysroot", "-x")):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(RUNNER), *arguments], cwd=ROOT,
                        env=environment, capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                    )

    def test_static_replay_parser_rejects_incomplete_or_ambiguous_arguments(
        self,
    ) -> None:
        invalid_arguments = (
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "--not-a-product"),
            ("--static-sysroot", "first", "--static-sysroot", "second"),
            ("first-dynamic", "second-dynamic"),
        )

        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "usage: "
                    f"{RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                )

    def test_two_role_replay_keeps_installed_headers_and_sealed_raw_evidence(
        self,
    ) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = " ".join(DOCUMENT.read_text(encoding="utf-8").split())

        for required in (
            "provided_static=''",
            "provided_dynamic=''",
            "dynamic_was_supplied=0",
            "realpath -e --",
            "system cancellation {name} product must be a checkout .work directory",
            '"$installed_dynamic/bin/crabc-cc-dynamic" --dynamic-pie',
            '-fno-stack-protector -c "$PROBE" -o "$work/consumer.o"',
            '-fno-stack-protector -c "$CHILD" -o "$work/child.o"',
            "audit_canonical_objects",
            "audit_musl_links",
            "crabc.system-cancellation-compile/v2",
            '"effective_codegen_flag": "-fPIE"',
            '"not_selected": ["-fPIC", "-fno-pie"]',
            "consumer and child objects unexpectedly coincide",
            "--link-receipt",
            "crabc.system-cancellation-link/v2",
            "for suffix in stdout stderr status",
            "local -a modes=(static static-pie)",
            "modes=(pie non-pie)",
            "run_direct_consumer",
            "local dependency roster drifted",
            "from owned_posix_product_evidence import validate_link",
            "identity = validate_link(product, object_path, candidate, receipt, mode)",
        ):
            self.assertIn(required, runner)
        self.assertLess(
            runner.index('"$installed_dynamic/bin/crabc-cc-dynamic" --dynamic-pie'),
            runner.index('TMPDIR="$work" "$ORACLE_CC"'),
        )
        self.assertLess(
            runner.index('audit_canonical_objects "$installed_dynamic"'),
            runner.index("\naudit_musl_links\n"),
        )
        for required in (
            "two distinct installed-header objects",
            "consumer",
            "child",
            "-fPIE",
            "-fPIC",
            "pinned musl",
            "static/static-PIE",
            "dynamic PIE/non-PIE",
            "kernel and direct interpreter",
            "--static-sysroot STATIC_SYSROOT",
            "neither producer",
            "stdout, stderr, and status",
            "system(3)",
            "pclose(3)",
            "supervisor",
        ):
            self.assertIn(required, document)

    def test_compile_receipt_binds_each_actual_translation_and_rechecks_all_inputs(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")

        for required in (
            "crabc.system-cancellation-compile/v2",
            "actual_compile_command",
            "dependency_audit", "installed_helper", "compiler", "clean_environment",
            "compiler_contract.compiler()", "compiler_contract.clean_environment()",
            "assert_canonical_compile_receipt",
            "canonical compile source changed", "canonical compile header changed",
            '"consumer", probe', '"child", child',
        ):
            self.assertIn(required, runner)
        self.assertNotIn('"/usr/bin/gcc"', runner)
        self.assertLess(
            runner.index('actual_compile_command = [str(driver), "--dynamic-pie", *caller_flags'),
            runner.index('TMPDIR="$work" "$ORACLE_CC"'),
        )
        self.assertGreaterEqual(
            runner.count('assert_canonical_compile_receipt "$installed_dynamic"'), 4,
        )
        for required in (
            "actual installed-driver command", "installed helper and compiler", "after every link matrix",
        ):
            self.assertIn(required, document)


if __name__ == "__main__":
    unittest.main()
