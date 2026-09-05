"""Bounded supplied-static fork workload adapter contracts."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_posix_static_fork.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_static_fork_evidence.py"
DOCUMENT = ROOT / "compat/x86_64/owned-posix-static-fork.md"

spec = importlib.util.spec_from_file_location("owned_static_fork_evidence", EVIDENCE)
evidence = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class OwnedPosixStaticForkTests(unittest.TestCase):
    def test_static_product_is_required_and_bad_arguments_fail_before_tools(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            tools = Path(temporary)
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = {**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"}
            usage = f"usage: {RUNNER} --static-sysroot STATIC_SYSROOT\n"
            for arguments in (
                (),
                ("--static-sysroot",),
                ("--static-sysroot", ""),
                ("--static-sysroot", "-not-a-product"),
                ("--static-sysroot", "one", "two"),
                ("unexpected",),
                ("--unknown",),
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(RUNNER), *arguments],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, usage)

    def test_static_product_escape_is_rejected_before_evidence_creation(self):
        temporary = ROOT / ".work/x86_64/tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["bash", str(RUNNER), "--static-sysroot", str(ROOT)],
            cwd=ROOT,
            env={**os.environ, "TMPDIR": str(temporary)},
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("product must be a physical checkout .work directory", result.stderr)

    def test_runner_keeps_two_immutable_static_only_roles(self):
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        helper = EVIDENCE.read_text(encoding="utf-8")
        for required in (
            "for role in atfork-registry static-posix-forkexec",
            "owned_atfork_registry_probe.c",
            "owned_static_posix_probe.c",
            '"$STATIC_DRIVER" -static-pie -std=c11 -c',
            '"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$role_dir/workload.o"',
            "for linkage in static static-pie",
            "--link-receipt receipt.json",
            "validate_link",
            "run_in_disposable_root",
            '"$CHROOT" "$execution_root" /workload/consumer',
            '"$raw_prefix.stdout"',
            "source-before.sha256",
            "source-after.sha256",
            "workload.after-$linkage.sha256",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("crabc-cc-dynamic", runner)
        self.assertNotIn("owned_process_trio", runner)
        for required in (
            "installed static driver differs from the current source translator contract",
            "dependency_audit_command",
            "compile record no longer describes the static-PIE object translation",
            "link identity does not bind the immutable object",
            "raw {suffix} differs from pinned musl",
        ):
            self.assertIn(required, helper)
        for required in (
            "required",
            "never built by this runner",
            "no positional dynamic-product argument",
            "does not rerun or subsume the dynamic `fork` case",
            "ordinary.{stdout,stderr,status}",
        ):
            self.assertIn(required, document)

    @staticmethod
    def _digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _make_role(self, root, role, *, mutate=None):
        root.mkdir()
        product = root / "product"
        product.mkdir()
        (product / "bin").mkdir()
        (product / "bin/crabc-cc").write_bytes(b"sealed static driver")
        (product / "share/crabc").mkdir(parents=True)
        (product / "share/crabc/manifest.json").write_bytes(b"sealed product manifest")
        (product / "usr/include").mkdir(parents=True)
        source = root / "source.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        role_directory = root / role
        role_directory.mkdir()
        workload = role_directory / "workload.o"
        workload.write_bytes(b"immutable workload")
        for name, path in (("source-before.sha256", source), ("source-after.sha256", source), ("workload.sha256", workload)):
            (role_directory / name).write_text(
                f"{self._digest(path)}  {path}\n", encoding="utf-8"
            )
        compile_record = {
            "schema": 1,
            "format": evidence.COMPILE_FORMAT,
            "role": role,
            "source": {"path": str(source), "sha256": self._digest(source)},
            "workload": {"path": str(workload), "sha256": self._digest(workload)},
            "product": {
                "path": str(product),
                "manifest_sha256": self._digest(product / "share/crabc/manifest.json"),
                "installed_static_driver_sha256": self._digest(product / "bin/crabc-cc"),
                "checkout_static_driver_sha256": "c" * 64,
            },
            "translation": {
                "compiler": {"path": "/compiler", "sha256": "d" * 64},
                "environment": {"PATH": "/usr/bin:/bin"},
                "compile_command": ["/compiler", "-nostdinc", "-fPIE", "-c", str(source), "-o", str(workload)],
                "dependency_audit_command": [
                    "/compiler", "-nostdinc", "-fPIE", "-M", "-H", str(source)
                ],
            },
            "headers": {
                "root": str(product / "usr/include"),
                "dependencies": [{"path": str(source), "sha256": self._digest(source)}],
                "dependency_trace": {"path": str(role_directory / "headers.d"), "sha256": "e" * 64},
                "include_trace": {"path": str(role_directory / "headers.trace"), "sha256": "f" * 64},
            },
        }
        (role_directory / "headers.d").write_bytes(b"dependencies\n")
        (role_directory / "headers.trace").write_bytes(b"headers\n")
        compile_record["headers"]["dependency_trace"]["sha256"] = self._digest(
            role_directory / "headers.d"
        )
        compile_record["headers"]["include_trace"]["sha256"] = self._digest(
            role_directory / "headers.trace"
        )
        (role_directory / "compile.json").write_text(json.dumps(compile_record), encoding="utf-8")
        for linkage in ("musl", "static", "static-pie"):
            directory = role_directory / linkage
            directory.mkdir()
            (directory / "ordinary.stdout").write_bytes(b"same output\n")
            (directory / "ordinary.stderr").write_bytes(b"")
            (directory / "ordinary.status").write_text("0\n", encoding="utf-8")
        (role_directory / "musl/consumer").write_bytes(b"musl consumer")
        for linkage in ("static", "static-pie"):
            (role_directory / linkage / "consumer").write_bytes(
                f"{linkage} consumer".encode("utf-8")
            )
            (role_directory / linkage / "receipt.json").write_bytes(
                f"{linkage} receipt".encode("utf-8")
            )
            identity = {
                "linkage": linkage,
                "product": str(product),
                "product_format": "crabc-x86-64-owned-static-sysroot-v1",
                "product_manifest_sha256": self._digest(product / "share/crabc/manifest.json"),
                "workload_sha256": self._digest(workload),
                "executable_sha256": self._digest(role_directory / linkage / "consumer"),
                "receipt_sha256": self._digest(role_directory / linkage / "receipt.json"),
            }
            (role_directory / linkage / "link-identity.json").write_text(
                json.dumps(identity), encoding="utf-8"
            )
        if mutate is not None:
            mutate(role_directory)
        return product, source, role_directory

    def test_role_receipt_rejects_changed_raw_output_and_object_binding(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)
            product, source, role_directory = self._make_role(base / "good", "atfork-registry")
            evidence.write_workload_evidence("atfork-registry", source, role_directory, product)
            record = json.loads((role_directory / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(record["workload"]["sha256"], self._digest(role_directory / "workload.o"))
            self.assertEqual(record["compile"]["sha256"], self._digest(role_directory / "compile.json"))

            for label, mutate in (
                (
                    "raw-output",
                    lambda directory: (directory / "static/ordinary.stdout").write_bytes(b"changed\n"),
                ),
                (
                    "object-binding",
                    lambda directory: (directory / "static/link-identity.json").write_text(
                        json.dumps({
                            **json.loads((directory / "static/link-identity.json").read_text(encoding="utf-8")),
                            "workload_sha256": "0" * 64,
                        }),
                        encoding="utf-8",
                    ),
                ),
            ):
                with self.subTest(label=label):
                    fixture = base / label
                    product, source, role_directory = self._make_role(fixture, "static-posix-forkexec", mutate=mutate)
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.write_workload_evidence(
                            "static-posix-forkexec", source, role_directory, product
                        )


if __name__ == "__main__":
    unittest.main()
