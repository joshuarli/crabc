#!/usr/bin/env python3
"""Rejection boundaries for retained owned-wordexp product evidence."""

from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
import shutil
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


class OwnedWordexpPublicationTests(unittest.TestCase):
    def test_validated_report_is_discoverable_by_dynamic_qualification(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root)
        work = root / "evidence"
        work.mkdir()
        report = work / "owned-wordexp-products.json"
        output = io.StringIO()

        def validate(checkout, path, expected):
            self.assertEqual((checkout, path, expected), (ROOT, report, {"sealed": "inputs"}))
            self.assertEqual(json.loads(path.read_text()), {"retained": "report"})
            self.assertEqual(output.getvalue(), "")

        with contextlib.redirect_stdout(output), unittest.mock.patch.object(module, "validate_report", side_effect=validate):
            module._publish_report(report, {"retained": "report"}, {"sealed": "inputs"})
        self.assertEqual(output.getvalue().splitlines()[-1], str(report))
        log = root / "leaf.log"
        log.write_text(output.getvalue(), encoding="utf-8")
        snapshot = module.qualification.artifact_snapshot(log, str(ROOT))
        self.assertEqual(set(snapshot), {work.relative_to(ROOT).as_posix()})
        self.assertEqual(set(snapshot[work.relative_to(ROOT).as_posix()]), {report.name})

    def test_rejected_report_does_not_publish_a_success_marker(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), unittest.mock.patch.object(
                module, "validate_report", side_effect=module.EvidenceError("rejected")):
            with self.assertRaises(module.EvidenceError):
                module._publish_report(root / "owned-wordexp-products.json", {}, {})
        self.assertEqual(output.getvalue(), "")


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
        try:
            self.module._make_private_null(self.root / "dev/null", "test private null fixture")
        except self.module.EvidenceError as error:
            self.skipTest(f"requires a private character-device node: {error}")

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
            },
            fixture_devices={"null": "dev/null"},
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
            },
            fixture_devices={"null": "dev/null"},
        )
        (self.root / "lib/extra-alias").symlink_to("libc.so.1")
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)

class OwnedWordexpCommandBindingTests(unittest.TestCase):
    def test_temporary_fixture_requires_private_mode_and_complete_cleanup(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        temporary = root / "wordexp-tmp"
        temporary.mkdir(mode=0o700, parents=True)
        temporary.chmod(0o700)
        self.addCleanup(shutil.rmtree, root)
        module._validate_temporary_fixture(root)
        temporary.chmod(0o755)
        with self.assertRaises(module.EvidenceError):
            module._validate_temporary_fixture(root)
        temporary.chmod(0o700)
        (temporary / "leftover-marker").write_bytes(b"unexpected")
        with self.assertRaises(module.EvidenceError):
            module._validate_temporary_fixture(root)
        (temporary / "leftover-marker").unlink()
        temporary.rmdir()
        temporary.symlink_to(root, target_is_directory=True)
        with self.assertRaises(module.EvidenceError):
            module._validate_temporary_fixture(root)

    def test_owned_evaluator_requires_exact_source_observations_and_candidate_results(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root)

        def record(prefix: str, streams: tuple[bytes, bytes, bytes]):
            result = {}
            for name, value in zip(("status", "stdout", "stderr"), streams):
                path = root / f"{prefix}.{name}"
                path.write_bytes(value)
                result[name] = module._checkout_identity(ROOT, path, f"{prefix} {name}")
            return result

        cases = (
            ("missing", b"74\n", b"owned-wordexp-shell-unavailable: SOURCE-RED ordinary-requires-shell\n",
             b"owned-wordexp-shell-unavailable: PASS\n"),
            ("inaccessible", b"74\n", b"owned-wordexp-shell-unavailable: SOURCE-RED ordinary-requires-shell\n",
             b"owned-wordexp-shell-unavailable: PASS\n"),
            ("invalid", b"74\n", b"owned-wordexp-shell-unavailable: SOURCE-RED ordinary-requires-shell\n",
             b"owned-wordexp-shell-unavailable: PASS\n"),
            ("nocmd-source", b"106\n", b"owned-wordexp-nocmd-source: SOURCE-OBSERVATION subshell-badchar\n",
             b"owned-wordexp-nocmd-source: PASS\n"),
            ("undef-source-observation", b"154\n", b"owned-wordexp-undef-source-observation: SOURCE-RED\n",
             b"owned-wordexp-undef-source-observation: PASS\n"),
        )
        for case, status, source_stdout, candidate_stdout in cases:
            with self.subTest(case=case):
                source_streams = (status, source_stdout, b"")
                candidate_streams = (b"0\n", candidate_stdout, b"")
                oracle = record("oracle", source_streams)
                candidate = record("candidate", candidate_streams)
                module._assert_case_results(ROOT, case, oracle, candidate, case)
                # A valid source observation cannot waive a changed status,
                # transcript, or diagnostic on either side of the comparison.
                for side in ("oracle", "candidate"):
                    for stream in range(3):
                        changed = list(source_streams if side == "oracle" else candidate_streams)
                        changed[stream] += b"unexpected\n"
                        broken = record("broken", tuple(changed))
                        with self.assertRaises(module.EvidenceError):
                            module._assert_case_results(ROOT, case,
                                broken if side == "oracle" else oracle,
                                broken if side == "candidate" else candidate, case)

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

    def test_posix_source_red_policy_requires_the_pinned_failure_and_candidate_success(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)

        def record(prefix: str, status: bytes, stdout: bytes, stderr: bytes):
            result = {}
            for name, value in (("status", status), ("stdout", stdout), ("stderr", stderr)):
                path = root / f"{prefix}.{name}"
                path.write_bytes(value)
                result[name] = module._checkout_identity(ROOT, path, f"{prefix} {name}")
            return result

        oracle = record("oracle", b"84\n",
                        b"owned-wordexp-posix-quiet: SOURCE-RED diagnostic-present\n", b"")
        candidate = record("candidate", b"0\n", b"owned-wordexp-posix-quiet: PASS\n", b"")
        module._assert_case_results(ROOT, "posix-quiet", oracle, candidate, "synthetic quiet cell")

        broken = record("broken", b"0\n", b"owned-wordexp-posix-quiet: PASS\n", b"")
        with self.assertRaises(module.EvidenceError):
            module._assert_case_results(ROOT, "posix-quiet", broken, candidate, "missing source red")

        comment_oracle = record("comment-oracle", b"244\n",
                                b"owned-wordexp-posix-nocmd-comment-control: SOURCE-RED command-marker-created\n", b"")
        comment_candidate = record("comment-candidate", b"0\n",
                                   b"owned-wordexp-posix-nocmd-comment-control: PASS\n", b"")
        module._assert_case_results(ROOT, "posix-nocmd-comment-control", comment_oracle,
                                    comment_candidate, "synthetic comment cell")

        positional_oracle = record("positional-oracle", b"137\n",
                                   b"owned-wordexp-posix-nocmd-positional: SOURCE-RED positional-parameter-rejected\n", b"")
        positional_candidate = record("positional-candidate", b"0\n",
                                      b"owned-wordexp-posix-nocmd-positional: PASS\n", b"")
        module._assert_case_results(ROOT, "posix-nocmd-positional", positional_oracle,
                                    positional_candidate, "synthetic positional cell")
        shutil.rmtree(root, ignore_errors=True)

    def test_execution_record_defers_a_nonzero_source_red_to_its_exact_policy(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        commands = root / "commands"
        commands.mkdir(parents=True)
        values = {
            "argv": b'["/consumer"]\n', "environment": b'{}\n',
            "stdout": b"source-red\n", "stderr": b"", "status": b"84\n",
        }
        with unittest.mock.patch.object(module, "SOURCE_MOUNT", str(ROOT)):
            record = {}
            for name, content in values.items():
                path = commands / (f"source-red.{name}.json" if name in {"argv", "environment"}
                                   else f"source-red.{name}")
                path.write_bytes(content)
                record[name] = module._checkout_identity(ROOT, path, name)
            with self.assertRaises(module.EvidenceError):
                module._command_record(ROOT, root, "source-red", record, ["/consumer"], {}, "source red")
            self.assertEqual(
                module._command_record(ROOT, root, "source-red", record, ["/consumer"], {}, "source red",
                                       allow_nonzero_status=True),
                record,
            )
        shutil.rmtree(root, ignore_errors=True)


class OwnedWordexpFixtureDeviceTests(unittest.TestCase):
    def test_regular_or_wrong_device_substitutes_are_rejected(self) -> None:
        module = load_module()
        root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        (root / "dev").mkdir(parents=True)
        (root / "dev/null").write_bytes(b"")
        with self.assertRaises(module.EvidenceError):
            module._null_device_identity(root, "dev/null", "regular substitute")
        with self.assertRaises(module.EvidenceError):
            module._null_device_identity(root, "dev/zero", "wrong declared device")
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
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        try:
            self.module._make_private_null(self.work / "external-shell-fixture/dev/null",
                                           "reconstruction private null fixture")
        except self.module.EvidenceError as error:
            self.skipTest(f"requires a private character-device node: {error}")
        (self.product / "lib/ld-musl-x86_64.so.1").symlink_to("keep")
        (self.product / "lib/keep-alias").symlink_to("keep")
        shutil.copytree(self.product, self.execution, symlinks=True)
        (self.execution / "wordexp-tmp").mkdir(mode=0o700)
        (self.execution / "wordexp-tmp").chmod(0o700)
        self._copy(self.work / "candidate", self.execution / "consumer-pie")
        self._copy(self.work / "oracle", self.execution / "oracle")
        # The one allowed external alias replacement is intentionally a regular
        # pinned fixture loader, never an untracked product modification.
        (self.execution / "lib/ld-musl-x86_64.so.1").unlink()
        self._copy(self.work / "external-shell-fixture/bin/sh", self.execution / "bin/sh")
        self._copy(self.work / "external-shell-fixture/lib/ld-musl-x86_64.so.1",
                   self.execution / "lib/ld-musl-x86_64.so.1")
        self.module._copy_private_null(self.work / "external-shell-fixture", "dev/null", self.execution,
                                       "dev/null", "reconstruction execution private null fixture")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def _copy(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    def _fixture(self):
        source = self.work / "external-shell-fixture"
        paths = {"shell": "bin/sh", "dependency:0": "lib/ld-musl-x86_64.so.1"}
        devices = {"null": "dev/null"}
        return source, paths, devices

    def _record(self):
        product_files = {"manifest": "share/crabc/manifest.json", "product:runtime": "runtime", "product:lib/keep": "lib/keep"}
        product_aliases = {"product:lib/keep-alias": "lib/keep-alias"}
        record = self.module.record_execution_root(
            self.execution, product_files=product_files, product_aliases=product_aliases,
            consumers={"candidate": "consumer-pie", "oracle": "oracle"},
            fixture_files={"shell": "bin/sh", "dependency:0": "lib/ld-musl-x86_64.so.1"},
            fixture_devices={"null": "dev/null"},
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


class OwnedWordexpEngineResultTests(unittest.TestCase):
    def test_quiet_source_observation_requires_exact_pinned_diagnostic(self) -> None:
        module = load_module()
        candidate = (b"0\n", b"owned-wordexp: PASS\n", b"")
        diagnostic = b"sh: eval: line 0: syntax error: unterminated quoted string\n"
        oracle = (b"0\n", b"owned-wordexp: PASS\n", diagnostic)
        with unittest.mock.patch.object(module, "_result_streams", side_effect=[oracle, candidate]):
            module._assert_case_results(ROOT, "normal", {}, {}, "normal")
        for changed in (b"unrelated failure\n", diagnostic + b"extra\n", diagnostic[:-1], b""):
            with self.subTest(diagnostic=changed), unittest.mock.patch.object(
                    module, "_result_streams", side_effect=[oracle[:2] + (changed,), candidate]):
                with self.assertRaises(module.EvidenceError):
                    module._assert_case_results(ROOT, "normal", {}, {}, "normal")

    def test_matching_unexpected_diagnostics_cannot_pass_a_source_control(self) -> None:
        module = load_module()
        case = "engine-literals"
        result = (b"0\n", b"owned-wordexp-engine-literals: PASS\n", b"unexpected diagnostic\n")
        with unittest.mock.patch.object(module, "_result_streams", side_effect=[result, result]):
            with self.assertRaises(module.EvidenceError):
                module._assert_case_results(ROOT, case, {}, {}, case)

    def test_engine_cells_require_positive_candidate_and_exact_source_observation(self) -> None:
        module = load_module()
        observations = {
            "undef": "wrde-undef-untyped",
            "append-rollback": "wrde-undef-untyped",
            "parameter-word": "nocmd-parameter-word-badchar",
            "diagnostics": "quiet-shell-diagnostic",
            "sigpipe": "shell-child-no-raw-sigpipe",
        }
        for name, reason in observations.items():
            with self.subTest(name=name):
                case = "engine-" + name
                prefix = "owned-wordexp-" + case + ": "
                oracle = (b"0\n", (prefix + "SOURCE-RED " + reason + "\n").encode(), b"")
                candidate = (b"0\n", (prefix + "PASS\n").encode(), b"")
                with unittest.mock.patch.object(module, "_result_streams", side_effect=[oracle, candidate]):
                    module._assert_case_results(ROOT, case, {}, {}, case)
                for changed_oracle, changed_candidate in (
                    (candidate, candidate),
                    (oracle, oracle),
                    (oracle, (b"1\n", candidate[1], b"")),
                    (oracle, (b"0\n", candidate[1], b"unexpected diagnostic\n")),
                    ((b"0\n", oracle[1] + b"extra\n", b""), candidate),
                ):
                    with unittest.mock.patch.object(module, "_result_streams", side_effect=[changed_oracle, changed_candidate]):
                        with self.assertRaises(module.EvidenceError):
                            module._assert_case_results(ROOT, case, {}, {}, case)


class OwnedWordexpExpectedInputTests(unittest.TestCase):
    def test_external_tool_seal_rejects_matching_report_compiler_mutation(self) -> None:
        module = load_module()
        identity = lambda path, digest: {"path": path, "sha256": digest * 64, "mode": 0o755}
        tools = {
            "compiler": identity("/tool/compiler", "a"),
            "linker": identity("/tool/linker", "b"),
            "oracle-compiler": identity("/usr/local/bin/crabc-x86_64-musl-gcc", "c"),
            "chroot": identity("/tool/chroot", "d"),
            "timeout": identity("/tool/timeout", "e"),
            "ldd": identity("/tool/ldd", "f"),
            "shell": identity("/tool/shell", "0"),
        }
        oracle = {
            "qualification": {
                "version": "musl-1.2.6", "runtime_sha256": "1" * 64,
                "compiler_wrapper_sha256": "2" * 64, "pins_sha256": "3" * 64,
                "files": {name: ("1" if name == "runtime" else "2" if name == "compiler_wrapper" else "4") * 64
                          for name in module.qualification.ORACLE_FILES},
            },
            "loader": {"source_path": "/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1",
                       "identity": identity("/opt/musl-1.2.6/lib/libc.so", "1")},
            "static_libc": {"native": identity("/opt/musl-1.2.6/lib/libc.a", "5"), "retained": {}},
        }
        expected = module.expected_native_input_seal(tools, oracle)
        before, after = copy.deepcopy(tools), copy.deepcopy(tools)
        for recorded in (before, after):
            recorded["compiler"]["sha256"] = "9" * 64
        for recorded in (before, after):
            with self.assertRaises(module.EvidenceError):
                module.validate_expected_native_input(expected, recorded, oracle)


if __name__ == "__main__":
    unittest.main()
