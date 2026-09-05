"""Bounded supplied-static fork workload adapter contracts."""

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_posix_static_fork.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_static_fork_evidence.py"
DOCUMENT = ROOT / "compat/x86_64/owned-posix-static-fork.md"
STATIC_DRIVER = ROOT / "compat/x86_64/crabc_cc_static.py"

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
            "candidate-before-execution.sha256",
            "executed-consumer-before-execution.sha256",
            "cmp -- \"$candidate\" \"$execution_consumer\"",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("crabc-cc-dynamic", runner)
        self.assertNotIn("owned_process_trio", runner)
        for required in (
            "ROLE_HEADER_CLOSURES",
            "derive_static_translation",
            "current checkout evidence helper",
            "reparsed dependency trace",
            "installed static driver differs from the current source translator contract",
            "dependency_audit_command",
            "compile record no longer describes the exact static-PIE translation",
            "link identity does not bind the immutable object",
            "executed consumer differs from its original candidate",
        ):
            self.assertIn(required, helper)
        for required in (
            "required",
            "never built by this runner",
            "no positional dynamic-product argument",
            "does not rerun or subsume the dynamic `fork` case",
            "ordinary.{stdout,stderr,status}",
            "copied consumer",
        ):
            self.assertIn(required, document)

    @staticmethod
    def _digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _checksum(path, artifact):
        path.write_text(f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {artifact}\n", encoding="utf-8")

    @contextmanager
    def _checkout(self, base):
        checkout = base / "checkout"
        helper = checkout / "compat/x86_64/owned_static_fork_evidence.py"
        driver = checkout / "compat/x86_64/crabc_cc_static.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(EVIDENCE, helper)
        shutil.copyfile(STATIC_DRIVER, driver)
        for relative in evidence.ROLE_SOURCES.values():
            target = checkout / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        with mock.patch.object(evidence, "__file__", str(helper)):
            yield checkout

    def _make_role(self, root, checkout, role, *, mutate=None):
        root.mkdir()
        product = root / "product"
        product.mkdir()
        (product / "bin").mkdir()
        shutil.copyfile(checkout / "compat/x86_64/crabc_cc_static.py", product / "bin/crabc-cc")
        (product / "share/crabc").mkdir(parents=True)
        (product / "share/crabc/manifest.json").write_bytes(b"sealed product manifest")
        headers = product / "usr/include"
        headers.mkdir(parents=True)
        source = checkout / evidence.ROLE_SOURCES[role]
        for relative in evidence.ROLE_HEADER_CLOSURES[role]:
            header = headers / relative
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(f"/* {relative} */\n", encoding="utf-8")
        role_directory = root / role
        role_directory.mkdir()
        workload = role_directory / "workload.o"
        workload.write_bytes(b"immutable workload")
        for name, path in (
            ("source-before.sha256", source),
            ("source-after.sha256", source),
            ("workload.sha256", workload),
        ):
            self._checksum(role_directory / name, path)

        translation = evidence.derive_static_translation(
            checkout, product, role, source, workload
        )
        dependencies = [source, *(headers / item for item in evidence.ROLE_HEADER_CLOSURES[role])]
        dependency_trace = role_directory / "headers.d"
        dependency_trace.write_text(
            "workload.o: \\\n " + " \\\n ".join(str(item) for item in dependencies) + "\n",
            encoding="utf-8",
        )
        include_trace = role_directory / "headers.trace"
        include_trace.write_text("header audit\n", encoding="utf-8")
        compile_record = {
            "schema": 2,
            "format": evidence.COMPILE_FORMAT,
            "role": role,
            "source": {"path": str(source), "sha256": self._digest(source)},
            "workload": {"path": str(workload), "sha256": self._digest(workload)},
            "product": translation["product"],
            "translation": translation["translation"],
            "evidence_helper": translation["evidence_helper"],
            "headers": {
                "root": str(headers),
                "dependencies": [
                    {"path": str(item), "sha256": self._digest(item)} for item in dependencies
                ],
                "dependency_trace": {
                    "path": str(dependency_trace),
                    "sha256": self._digest(dependency_trace),
                },
                "include_trace": {
                    "path": str(include_trace),
                    "sha256": self._digest(include_trace),
                },
            },
        }
        (role_directory / "compile.json").write_text(json.dumps(compile_record), encoding="utf-8")
        for linkage in ("musl", "static", "static-pie"):
            directory = role_directory / linkage
            directory.mkdir()
            (directory / "ordinary.stdout").write_bytes(b"same output\n")
            (directory / "ordinary.stderr").write_bytes(b"")
            (directory / "ordinary.status").write_text("0\n", encoding="utf-8")
            candidate = directory / "consumer"
            candidate.write_bytes(f"{linkage} consumer".encode("utf-8"))
            execution = directory / "root/workload"
            execution.mkdir(parents=True)
            copied = execution / "consumer"
            shutil.copyfile(candidate, copied)
            self._checksum(directory / "candidate-before-execution.sha256", candidate)
            self._checksum(directory / "executed-consumer-before-execution.sha256", copied)
        for linkage in ("static", "static-pie"):
            directory = role_directory / linkage
            (directory / "receipt.json").write_bytes(f"{linkage} receipt".encode("utf-8"))
            identity = {
                "linkage": linkage,
                "product": str(product),
                "product_format": "crabc-x86-64-owned-static-sysroot-v1",
                "product_manifest_sha256": self._digest(product / "share/crabc/manifest.json"),
                "workload_sha256": self._digest(workload),
                "executable_sha256": self._digest(directory / "consumer"),
                "receipt_sha256": self._digest(directory / "receipt.json"),
            }
            (directory / "link-identity.json").write_text(json.dumps(identity), encoding="utf-8")
        if mutate is not None:
            mutate(checkout, product, role_directory)
        return product, source, role_directory

    def test_role_receipt_recomputes_translation_header_and_execution_contracts(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)
            with self._checkout(base) as checkout:
                product, source, role_directory = self._make_role(
                    base / "good", checkout, "atfork-registry"
                )
                evidence.write_workload_evidence(
                    checkout, "atfork-registry", source, role_directory, product
                )
                record = json.loads((role_directory / "evidence.json").read_text(encoding="utf-8"))
                self.assertEqual(record["workload"]["sha256"], self._digest(role_directory / "workload.o"))
                self.assertEqual(record["compile"]["sha256"], self._digest(role_directory / "compile.json"))
                raw = record["links"]["static"]["raw"]["consumer"]
                self.assertEqual(raw["candidate"]["sha256"], raw["executed"]["sha256"])

    def test_role_receipt_rejects_mutated_translation_header_driver_helper_and_execution_boundaries(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)

            def record(directory):
                return json.loads((directory / "compile.json").read_text(encoding="utf-8"))

            def write_record(directory, value):
                (directory / "compile.json").write_text(json.dumps(value), encoding="utf-8")

            def source_only(checkout, product, directory):
                value = record(directory)
                source = checkout / evidence.ROLE_SOURCES["static-posix-forkexec"]
                value["headers"]["dependencies"] = [value["headers"]["dependencies"][0]]
                (directory / "headers.d").write_text(f"workload.o: {source}\n", encoding="utf-8")
                value["headers"]["dependency_trace"]["sha256"] = self._digest(directory / "headers.d")
                write_record(directory, value)

            def foreign_local(checkout, product, directory):
                value = record(directory)
                foreign = directory / "foreign.h"
                foreign.write_text("foreign\n", encoding="utf-8")
                (directory / "headers.d").write_text(
                    (directory / "headers.d").read_text(encoding="utf-8").rstrip()
                    + f" \\\n {foreign}\n",
                    encoding="utf-8",
                )
                value["headers"]["dependency_trace"]["sha256"] = self._digest(directory / "headers.d")
                write_record(directory, value)

            def compiler(checkout, product, directory):
                value = record(directory)
                value["translation"]["compiler"]["selected_path"] = "/wrong-gcc"
                write_record(directory, value)

            def compile_vector(checkout, product, directory):
                value = record(directory)
                value["translation"]["compile_command"].insert(1, "-wrong")
                write_record(directory, value)

            def dependency_vector(checkout, product, directory):
                value = record(directory)
                value["translation"]["dependency_audit_command"].insert(1, "-wrong")
                write_record(directory, value)

            def environment(checkout, product, directory):
                value = record(directory)
                value["translation"]["environment"]["TZ"] = "wrong"
                write_record(directory, value)

            def duplicate_header(checkout, product, directory):
                value = record(directory)
                duplicate = value["headers"]["dependencies"][1]["path"]
                (directory / "headers.d").write_text(
                    (directory / "headers.d").read_text(encoding="utf-8").rstrip()
                    + f" \\\n {duplicate}\n",
                    encoding="utf-8",
                )
                value["headers"]["dependency_trace"]["sha256"] = self._digest(directory / "headers.d")
                write_record(directory, value)

            def checkout_driver(checkout, product, directory):
                (checkout / "compat/x86_64/crabc_cc_static.py").write_text(
                    "changed checkout driver\n", encoding="utf-8"
                )

            def installed_driver(checkout, product, directory):
                (product / "bin/crabc-cc").write_text(
                    "changed installed driver\n", encoding="utf-8"
                )

            def helper(checkout, product, directory):
                (checkout / "compat/x86_64/owned_static_fork_evidence.py").write_text(
                    "changed helper\n", encoding="utf-8"
                )

            def executed_copy(checkout, product, directory):
                (directory / "static/root/workload/consumer").write_bytes(
                    b"replaced executed consumer"
                )

            def raw_output(checkout, product, directory):
                (directory / "static/ordinary.stdout").write_bytes(b"changed\n")

            def object_binding(checkout, product, directory):
                identity_path = directory / "static/link-identity.json"
                identity_path.write_text(
                    json.dumps({
                        **json.loads(identity_path.read_text(encoding="utf-8")),
                        "workload_sha256": "0" * 64,
                    }),
                    encoding="utf-8",
                )

            mutations = {
                "compiler": compiler,
                "compile-vector": compile_vector,
                "dependency-vector": dependency_vector,
                "environment": environment,
                "source-only-closure": source_only,
                "foreign-local-header": foreign_local,
                "duplicate-header": duplicate_header,
                "checkout-driver": checkout_driver,
                "installed-driver": installed_driver,
                "helper": helper,
                "executed-copy": executed_copy,
                "raw-output": raw_output,
                "object-binding": object_binding,
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    case = base / label
                    case.mkdir()
                    with self._checkout(case) as checkout:
                        product, source, role_directory = self._make_role(
                            case / "fixture",
                            checkout,
                            "static-posix-forkexec",
                            mutate=mutate,
                        )
                        with self.assertRaises(evidence.EvidenceError):
                            evidence.write_workload_evidence(
                                checkout,
                                "static-posix-forkexec",
                                source,
                                role_directory,
                                product,
                            )



if __name__ == "__main__":
    unittest.main()
