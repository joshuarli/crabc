#!/usr/bin/env python3
"""Rejection boundaries for retained owned-wordexp product evidence."""

from __future__ import annotations

import importlib.util
import shutil
import stat
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat/x86_64/owned_wordexp_evidence.py"
TMP_ROOT = ROOT / ".work/x86_64/test-owned-wordexp-evidence"


def load_module():
    spec = importlib.util.spec_from_file_location("owned_wordexp_evidence", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OwnedWordexpExecutionRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(self.root, ignore_errors=True)
        (self.root / "bin").mkdir(parents=True)
        self._write("consumer-pie", b"owned consumer\n", 0o755)
        self._write("oracle", b"musl oracle\n", 0o755)
        self._write("bin/sh", b"sealed external shell\n", 0o755)
        self._write("lib/libfixture.so", b"sealed shell dependency\n", 0o644)
        self._write("dev/null", b"", 0o666)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, relative: str, data: bytes, mode: int) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _record(self):
        return self.module.record_execution_root(
            self.root,
            product_files={},
            product_aliases={},
            consumers={"consumer": "consumer-pie", "oracle": "oracle"},
            fixture_files={
                "shell": "bin/sh",
                "shell-dependency": "lib/libfixture.so",
                "null": "dev/null",
            },
        )

    def test_extra_execution_file_is_rejected(self) -> None:
        record = self._record()
        self._write("unexpected", b"not part of the sealed root", 0o644)
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)

    def test_changed_shell_fixture_mode_or_bytes_is_rejected(self) -> None:
        record = self._record()
        shell = self.root / "bin/sh"
        shell.write_bytes(b"substituted shell\n")
        shell.chmod(0o644)
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)

    def test_product_aliases_are_bound_and_extra_aliases_rejected(self) -> None:
        self._write("lib/libc.so.1", b"product payload\n", 0o755)
        (self.root / "lib/libc.so").symlink_to("libc.so.1")
        record = self.module.record_execution_root(
            self.root,
            product_files={"runtime": "lib/libc.so.1"},
            product_aliases={"libc": "lib/libc.so"},
            consumers={"consumer": "consumer-pie", "oracle": "oracle"},
            fixture_files={
                "shell": "bin/sh",
                "shell-dependency": "lib/libfixture.so",
                "null": "dev/null",
            },
        )
        (self.root / "lib/extra-alias").symlink_to("libc.so.1")
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)


class OwnedWordexpCommandBindingTests(unittest.TestCase):
    def test_substituted_oracle_argv_cannot_satisfy_candidate_binding(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        argv = root / "candidate.argv.json"
        argv.write_text('["/oracle"]\n', encoding="utf-8")
        with self.assertRaises(module.EvidenceError):
            module.require_exact_command(argv, ["/consumer"], {}, "candidate")
        shutil.rmtree(root, ignore_errors=True)

class OwnedWordexpReconstructionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(self.root, ignore_errors=True)
        self.work = self.root / "work"
        self.product = self.root / "product"
        self.execution = self.work / "execution/dynamic-pie-kernel-normal"
        for path, data, mode in (
            (self.product / "share/crabc/manifest.json", b"manifest\n", 0o644),
            (self.product / "runtime", b"selected runtime\n", 0o755),
            (self.product / "lib/keep", b"selected alias target\n", 0o644),
            (self.work / "candidate", b"linked consumer\n", 0o755),
            (self.work / "oracle", b"linked oracle\n", 0o755),
            (self.work / "external-shell-fixture/bin/sh", b"fixture shell\n", 0o755),
            (self.work / "external-shell-fixture/lib/ld-musl-x86_64.so.1", b"fixture loader\n", 0o755),
            (self.work / "external-shell-fixture/dev/null", b"", 0o666),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        (self.product / "lib/ld-musl-x86_64.so.1").symlink_to("keep")
        (self.product / "lib/keep-alias").symlink_to("keep")
        shutil.copytree(self.product, self.execution, symlinks=True)
        self._copy(self.work / "candidate", self.execution / "consumer-pie")
        self._copy(self.work / "oracle", self.execution / "oracle")
        # The one allowed external alias replacement is intentionally a regular
        # pinned fixture loader, never an untracked product modification.
        (self.execution / "lib/ld-musl-x86_64.so.1").unlink()
        self._copy(self.work / "external-shell-fixture/bin/sh", self.execution / "bin/sh")
        self._copy(self.work / "external-shell-fixture/lib/ld-musl-x86_64.so.1",
                   self.execution / "lib/ld-musl-x86_64.so.1")
        self._copy(self.work / "external-shell-fixture/dev/null", self.execution / "dev/null")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def _copy(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    def _fixture(self):
        source = self.work / "external-shell-fixture"
        paths = {"shell": "bin/sh", "dependency:0": "lib/ld-musl-x86_64.so.1", "null": "dev/null"}
        records = {name: self.module._checkout_identity(ROOT, source / relative, name) for name, relative in paths.items()}
        return source, paths, records

    def _record(self):
        product_files = {"manifest": "share/crabc/manifest.json", "product:runtime": "runtime", "product:lib/keep": "lib/keep"}
        product_aliases = {"product:lib/keep-alias": "lib/keep-alias"}
        record = self.module.record_execution_root(
            self.execution, product_files=product_files, product_aliases=product_aliases,
            consumers={"candidate": "consumer-pie", "oracle": "oracle"},
            fixture_files={"shell": "bin/sh", "dependency:0": "lib/ld-musl-x86_64.so.1", "null": "dev/null"},
        )
        record["root"] = self.module._mounted(ROOT, self.execution)
        return record

    def _validate(self, record):
        record = dict(record)
        record["root"] = str(self.execution)
        with unittest.mock.patch.object(self.module, "SOURCE_MOUNT", str(ROOT)), \
             unittest.mock.patch.object(self.module.copies, "dynamic_product", return_value=(
                 self.product, self.product / "share/crabc/manifest.json", {"runtime": "unused", "lib/keep": "unused"},
                 {"lib/ld-musl-x86_64.so.1": "keep", "lib/keep-alias": "keep"},
             )):
            return self.module._validate_execution_binding(
                ROOT, self.work, "dynamic-pie-kernel-normal", "dynamic-pie-kernel", "normal", record,
                self.product, self.work / "candidate", self.work / "oracle", self._fixture(),
                ["lib/ld-musl-x86_64.so.1"],
            )

    def test_reconstructed_root_rejects_re_signed_consumer_runtime_fixture_and_alias(self) -> None:
        record = self._record()
        self._validate(record)
        for target, replacement, path in (
            ("consumer", b"oracle bytes substituted\n", self.execution / "consumer-pie"),
            ("runtime", b"runtime bytes substituted\n", self.execution / "runtime"),
            ("fixture", b"fixture bytes substituted\n", self.execution / "bin/sh"),
        ):
            with self.subTest(target=target):
                fresh = self._record()
                path.write_bytes(replacement)
                path.chmod(0o755)
                if target == "consumer":
                    fresh["consumers"]["candidate"]["sha256"] = self.module._sha(path)
                elif target == "runtime":
                    fresh["product_files"]["product:runtime"]["sha256"] = self.module._sha(path)
                else:
                    fresh["fixtures"]["shell"]["sha256"] = self.module._sha(path)
                with self.assertRaises(self.module.EvidenceError):
                    self._validate(fresh)
                # Restore this cell for the following independent substitution.
                if target == "consumer":
                    self._copy(self.work / "candidate", path)
                elif target == "runtime":
                    self._copy(self.product / "runtime", path)
                else:
                    self._copy(self.work / "external-shell-fixture/bin/sh", path)

        fresh = self._record()
        alias = self.execution / "lib/keep-alias"
        alias.unlink()
        alias.symlink_to("ld-musl-x86_64.so.1")
        fresh["product_aliases"]["product:lib/keep-alias"]["target"] = "ld-musl-x86_64.so.1"
        with self.assertRaises(self.module.EvidenceError):
            self._validate(fresh)

    def test_report_command_record_rejects_oracle_substitution(self) -> None:
        with unittest.mock.patch.object(self.module, "SOURCE_MOUNT", str(ROOT)):
            commands = self.work / "commands"
            commands.mkdir(parents=True)
            values = {
                "argv": b'["/oracle"]\n', "environment": b'{}\n', "stdout": b"ok\n",
                "stderr": b"", "status": b"0\n",
            }
            record = {}
            for name, content in values.items():
                path = commands / f"cell-candidate.{name}" if name not in {"argv", "environment"} else commands / f"cell-candidate.{name}.json"
                path.write_bytes(content)
                record[name] = self.module._checkout_identity(ROOT, path, name)
            with self.assertRaises(self.module.EvidenceError):
                self.module._command_record(ROOT, self.work, "cell-candidate", record, ["/consumer"], {}, "candidate")


class OwnedWordexpEnvironmentTests(unittest.TestCase):
    def test_ldd_closure_collapses_duplicate_loader_observations(self) -> None:
        module = load_module()
        closure = module._ldd_closure_candidates(
            "\t/lib/ld-musl-x86_64.so.1 (0x1)\n"
            "\tlibc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x1)\n"
        )
        self.assertEqual(closure, (Path("/lib/ld-musl-x86_64.so.1"),))

    def test_command_without_an_explicit_environment_is_rejected(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        with self.assertRaises(module.EvidenceError):
            module._run(root, "ambient", ["/bin/true"])
        shutil.rmtree(root, ignore_errors=True)

    def test_scrubbed_command_environment_does_not_inherit_injected_include_or_library_paths(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        inherited = {"CPATH": "/foreign/include", "LIBRARY_PATH": "/foreign/lib", "WORDEXP_MARKER": "ambient"}
        with unittest.mock.patch.dict("os.environ", inherited, clear=False):
            record = module._run(root, "environment", ["/usr/bin/python3", "-c",
                "import os; print('|'.join(os.environ.get(k, '') for k in ('CPATH','LIBRARY_PATH','WORDEXP_MARKER')))"],
                environment=module.evidence_environment(root))
        output = (ROOT / Path(record["stdout"]["path"]).relative_to(module.SOURCE_MOUNT)).read_bytes()
        self.assertEqual(output, b"||\n")
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
