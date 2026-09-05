#!/usr/bin/env python3
"""Contracts for the installed owned-syslog family witness."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_syslog.sh"
DOCUMENT = ROOT / "compat" / "x86_64" / "owned-syslog.md"
EVIDENCE_MODULE = ROOT / "compat" / "x86_64" / "owned_syslog_evidence.py"


class OwnedSyslogTests(unittest.TestCase):
    def assert_replay_parser_usage(self, *arguments: str) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-syslog-parser.", dir=scratch
        ) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
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

    def test_replay_parser_rejects_ambiguous_product_paths(self) -> None:
        for label, arguments in (
            ("missing static", ("--static-sysroot",)),
            ("empty static", ("--static-sysroot", "")),
            ("empty dynamic", ("",)),
            ("option static", ("--static-sysroot", "--not-a-sysroot")),
            ("short option static", ("--static-sysroot", "-e")),
            ("option dynamic", ("--not-a-sysroot",)),
            ("short option dynamic", ("-e",)),
            ("duplicate static", ("--static-sysroot", "/one", "--static-sysroot", "/two")),
            ("duplicate dynamic", ("/one", "/two")),
        ):
            with self.subTest(label=label):
                self.assert_replay_parser_usage(*arguments)

    def test_one_installed_driver_object_binds_every_link_receipt(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        evidence = EVIDENCE_MODULE.read_text(encoding="utf-8")
        link_product = runner.split("link_product() {", 1)[1].split("\n}\n", 1)[0]

        self.assertIn('"$installed/bin/crabc-cc-dynamic" --dynamic-pie', runner)
        self.assertIn('"$work/workload.o"', runner)
        self.assertIn('"$oracle_cc" -static', runner)
        self.assertNotIn('-c "$probe"', link_product)
        self.assertIn("capture-header-translation", runner)
        self.assertIn("shared.compiler()", evidence)
        self.assertIn("contract.clean_environment()", evidence)
        self.assertIn('"source_translation_command"', evidence)
        self.assertIn('"selected_path"', evidence)
        self.assertIn("R_X86_64_(32|32S)", runner)
        self.assertIn("owned_posix_product_evidence", runner)
        self.assertIn("validate_link", runner)
        self.assertIn("workload-object-binding.json", runner)
        self.assertIn("oracle-kernel-$scenario.status", runner)
        self.assertIn("provided static/static-PIE plus provided dynamic", runner)
        self.assertIn("single installed-header workload object", document)

    def test_relocation_audit_captures_before_matching_to_survive_sigpipe(self) -> None:
        """A matching grep can close a pipe before a large readelf stream ends."""
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-syslog-relocations.", dir=scratch
        ) as temporary:
            root = Path(temporary)
            readelf = root / "readelf"
            readelf.write_text(
                "#!/usr/bin/python3\n"
                "import sys\n"
                "sys.stdout.write('0000000000000000 R_X86_64_32 forbidden\\n')\n"
                "sys.stdout.write('filler\\n' * 1000000)\n",
                encoding="utf-8",
            )
            readelf.chmod(0o755)
            pipeline = subprocess.run(
                [
                    "bash",
                    "-o",
                    "pipefail",
                    "-c",
                    f'"{readelf}" -rW ignored | grep -Eq "R_X86_64_(32|32S)"',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(pipeline.returncode, 0)

            report = root / "relocations"
            with report.open("w", encoding="utf-8") as stream:
                subprocess.run(
                    [str(readelf), "-rW", "ignored"],
                    stdout=stream,
                    check=True,
                )
            found = subprocess.run(
                ["grep", "-Eq", "R_X86_64_(32|32S)", str(report)],
                check=False,
            )
            self.assertEqual(found.returncode, 0)

        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            'readelf -rW "$work/workload.o" >"$work/workload.relocations"',
            runner,
        )
        self.assertIn(
            'grep -Eq \'R_X86_64_(32|32S)\' "$work/workload.relocations"',
            runner,
        )
        self.assertNotIn('readelf -rW "$work/workload.o" | grep', runner)

    def test_workload_binding_rejects_boolean_schema(self) -> None:
        """JSON booleans must not pass the integer binding schema comparison."""
        import importlib.util

        specification = importlib.util.spec_from_file_location(
            "owned_syslog_evidence_test", EVIDENCE_MODULE
        )
        assert specification is not None and specification.loader is not None
        evidence = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = evidence
        specification.loader.exec_module(evidence)

        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-syslog-binding.", dir=scratch
        ) as temporary:
            root = Path(temporary)
            source = root / "probe.c"
            workload = root / "workload.o"
            relocation_report = root / "workload.relocations"
            translation = root / "installed-header-translation.json"
            identity = root / "link-evidence.json"
            binding = root / "workload-object-binding.json"
            source.write_bytes(b"owned syslog source\n")
            workload.write_bytes(b"one installed object\n")
            relocation_report.write_bytes(b"There are no relocations in this file.\n")
            translation.write_text('{"schema": 1}\n', encoding="utf-8")
            identity_record = {
                "linkage": "pie",
                "product": "/owned/product",
                "product_format": "crabc-x86-64-owned-dynamic-sysroot-v1",
                "product_manifest_sha256": "0" * 64,
                "workload_sha256": evidence.sha256_file(workload),
                "executable_sha256": "0" * 64,
                "receipt_sha256": "0" * 64,
            }
            identity.write_text(
                json.dumps(identity_record, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            source_sha256 = evidence.sha256_file(source)
            evidence.bind_workload_object(
                source,
                workload,
                source_sha256,
                identity,
                binding,
                relocation_report,
                translation,
            )
            record = json.loads(binding.read_text(encoding="utf-8"))
            record["schema"] = True
            binding.write_text(
                json.dumps(record, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                evidence.WorkloadBindingError, "binding drifted"
            ):
                evidence.bind_workload_object(
                    source,
                    workload,
                    source_sha256,
                    identity,
                    binding,
                    relocation_report,
                    translation,
                )

    def test_replay_products_must_stay_below_the_checkout_work_boundary(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        for label, arguments, expected in (
            (
                "static",
                ("--static-sysroot", str(ROOT)),
                "owned syslog static product must be a checkout .work directory",
            ),
            (
                "dynamic",
                (str(ROOT),),
                "owned syslog product must be a checkout .work directory",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=scratch) as temporary:
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    cwd=ROOT,
                    env={**os.environ, "TMPDIR": temporary},
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
