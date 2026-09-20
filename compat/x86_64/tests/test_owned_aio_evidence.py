#!/usr/bin/env python3
"""Focused rejection boundaries for retained owned-AIO receipts."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat/x86_64/owned_aio_evidence.py"
TMP = ROOT / ".work/x86_64/test-owned-aio-evidence"


def module():
    spec = importlib.util.spec_from_file_location("owned_aio_evidence", MODULE_PATH)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class OwnedAioExecutionTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = module()
        self.root = TMP / self.id().replace(".", "-")
        shutil.rmtree(self.root, ignore_errors=True)
        (self.root / "lib").mkdir(parents=True)
        self.source = TMP / (self.id().replace(".", "-") + "-sources")
        self.source.mkdir()
        self._write(self.source / "runtime", b"selected runtime\n", 0o755)
        self._write(self.source / "consumer", b"sealed linked consumer\n", 0o755)
        self._write(self.root / "lib/runtime", b"selected runtime\n", 0o755)
        self._write(self.root / "consumer", b"sealed linked consumer\n", 0o755)
        (self.root / "lib/ld-musl-x86_64.so.1").symlink_to("runtime")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.source, ignore_errors=True)

    @staticmethod
    def _write(path: Path, data: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(mode)

    def _check(self) -> None:
        self.evidence.assert_execution_tree(
            self.root,
            {"lib/runtime": self.source / "runtime", "consumer": self.source / "consumer"},
            {"lib/ld-musl-x86_64.so.1": "runtime"}, None,
        )

    def test_swapped_runtime_or_consumer_and_alias_are_rejected(self) -> None:
        self._check()
        for name, replacement in (("lib/runtime", b"substituted runtime\n"), ("consumer", b"substituted consumer\n")):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(replacement); path.chmod(0o755)
                with self.assertRaises(self.evidence.EvidenceError): self._check()
                source = self.source / ("runtime" if name.endswith("runtime") else "consumer")
                shutil.copy2(source, path)
        alias = self.root / "lib/ld-musl-x86_64.so.1"
        alias.unlink(); alias.symlink_to("../consumer")
        with self.assertRaises(self.evidence.EvidenceError): self._check()


class OwnedAioCommandAndTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = module()
        self.root = TMP / self.id().replace(".", "-")
        shutil.rmtree(self.root, ignore_errors=True)
        self.work = self.root / "work"; self.work.mkdir(parents=True)
        (self.work / "command.stdout").write_bytes(b"ok\n")
        (self.work / "command.stderr").write_bytes(b"")
        (self.work / "command.status").write_bytes(b"0\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_failing_status_or_ambient_environment_cannot_pass_command_receipt(self) -> None:
        with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
            self.evidence.record_command(self.root, self.work, "command", ["/bin/true"], self.root,
                                         self.work / "command.stdout", self.work / "command.stderr", self.work / "command.status")
            self.evidence._command(self.root, self.work, "command", ["/bin/true"], {b"0\n"})
            receipt = self.work / "commands/command.json"
            changed = json.loads(receipt.read_text())
            changed["environment"]["PATH"] = "/foreign/bin"
            receipt.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(self.evidence.EvidenceError):
                self.evidence._command(self.root, self.work, "command", ["/bin/true"], {b"0\n"})
            # Restore the canonical environment and re-sign the changed raw
            # status, so this next rejection reaches the status judge.
            changed["environment"] = self.evidence.command_environment(self.root, self.work)
            (self.work / "command.status").write_bytes(b"1\n")
            changed["status"] = self.evidence._identity(self.root, self.work / "command.status", "changed status")
            receipt.write_text(json.dumps(changed), encoding="utf-8")
        # The mutation above is rejected at the environment boundary; this
        # independent record restores it before exercising raw status.
        with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
            with self.assertRaises(self.evidence.EvidenceError):
                self.evidence._command(self.root, self.work, "command", ["/bin/true"], {b"0\n"})

    def test_external_tool_seal_rejects_matching_report_tool_mutation(self) -> None:
        identity = lambda path, byte: {"path": path, "sha256": byte * 64, "mode": 0o755}
        tools = {
            "dynamic-driver": identity("/workspace/dynamic-driver", "1"),
            "compiler": identity("/tools/compiler", "2"), "linker": identity("/tools/linker", "3"),
            "oracle-compiler": identity("/tools/oracle", "4"), "chroot": identity("/tools/chroot", "5"),
            "timeout": identity("/tools/timeout", "6"),
        }
        oracle = {"qualification": {"version": "musl-1.2.6", "runtime_sha256": "7" * 64,
                  "compiler_wrapper_sha256": "8" * 64, "pins_sha256": "9" * 64,
                  "files": {name: "a" * 64 for name in self.evidence.qualification.ORACLE_FILES}},
                  "static-libc": identity("/opt/musl/libc.a", "b"), "loader": identity("/opt/musl/ld-musl", "c")}
        external = self.evidence.expected_native_input(tools, oracle)
        changed = copy.deepcopy(tools); changed["compiler"]["sha256"] = "d" * 64
        with self.assertRaises(self.evidence.EvidenceError):
            self.evidence._same_expected(external, changed, oracle)


class OwnedAioBehaviorObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = module()
        self.root = TMP / self.id().replace(".", "-")
        shutil.rmtree(self.root, ignore_errors=True)
        self.work = self.root / "work"; self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _record(self, label: str, stdout: bytes, stderr: bytes = b"", status: bytes = b"0\n"):
        (self.work / f"{label}.stdout").write_bytes(stdout)
        (self.work / f"{label}.stderr").write_bytes(stderr)
        (self.work / f"{label}.status").write_bytes(status)
        with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
            self.evidence.record_command(self.root, self.work, label, ["/bin/true"], self.root,
                                         self.work / f"{label}.stdout", self.work / f"{label}.stderr",
                                         self.work / f"{label}.status")
            return self.evidence._command(self.root, self.work, label, ["/bin/true"], {status})

    def test_re_signed_changed_stdout_is_rejected_by_behavior_judge(self) -> None:
        command = self._record("standard", b"owned-aio basic ok\n")
        with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
            self.evidence.assert_success_transcript(self.root, command, b"owned-aio basic ok\n", "standard")
            output = self.work / "standard.stdout"
            output.write_bytes(b"re-signed substituted output\n")
            receipt_path = self.work / "commands/standard.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["stdout"] = self.evidence._identity(self.root, output, "re-signed stdout")
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            command = self.evidence._command(self.root, self.work, "standard", ["/bin/true"], {b"0\n"})
            with self.assertRaises(self.evidence.EvidenceError):
                self.evidence.assert_success_transcript(self.root, command, b"owned-aio basic ok\n", "standard")

    def test_candidate_oracle_mismatch_and_arbitrary_fd_failure_are_rejected(self) -> None:
        oracle = self._record("oracle", b"same pinned transcript\n")
        candidate = self._record("candidate", b"changed candidate transcript\n")
        with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
            with self.assertRaises(self.evidence.EvidenceError):
                self.evidence.assert_matched_transcript(self.root, oracle, candidate, "ordinary workload")
        fd = self._record("oracle-fd", b"", b"arbitrary failure\n", b"1\n")
        with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
            with self.assertRaises(self.evidence.EvidenceError):
                self.evidence.assert_oracle_fd_reuse(self.root, fd)

    @staticmethod
    def _fd_reuse_espipe(*, attempt: int | str, step: str = "wait-pipe-read", regular: int | str = 3,
                         pipe_read: int | str = 3, pipe_write: int | str = 4,
                         positioned_return: int = 1, saved_errno: int | str = 11) -> bytes:
        return (
            f"fd-reuse-failure step={step} attempt={attempt} regular={regular} "
            f"pipe-read={pipe_read} pipe-write={pipe_write} positioned-submit=0 "
            f"positioned-error=0 positioned-return={positioned_return} pipe-submit=0 "
            f"pipe-error=29 pipe-return=-1 byte=0 errno={saved_errno}\n"
        ).encode("ascii")

    def test_fd_reuse_espipe_requires_the_exact_stale_queue_observation(self) -> None:
        for attempt, saved_errno in ((0, 11), (511, 29)):
            with self.subTest(valid_attempt=attempt, saved_errno=saved_errno):
                command = self._record(f"fd-valid-{attempt}", b"", self._fd_reuse_espipe(attempt=attempt, saved_errno=saved_errno), b"1\n")
                with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
                    self.evidence.assert_oracle_fd_reuse(self.root, command)
        invalid = (
            {"attempt": 512},
            {"attempt": 0, "step": "submit-pipe-read"},
            {"attempt": 0, "positioned_return": 0},
            {"attempt": 0, "pipe_write": 3},
            {"attempt": 0, "pipe_read": 4},
            {"attempt": 0, "regular": 0, "pipe_read": 0},
            {"attempt": 0, "pipe_write": 0},
            {"attempt": 0, "saved_errno": "01"},
            {"attempt": 0, "saved_errno": "-0"},
            {"attempt": 0, "saved_errno": "2147483648"},
            {"attempt": 0, "saved_errno": "-2147483649"},
            {"attempt": "00"},
            {"attempt": 0, "regular": "03", "pipe_read": "03"},
            {"attempt": 0, "regular": "2147483648", "pipe_read": "2147483648"},
        )
        for index, kwargs in enumerate(invalid):
            with self.subTest(invalid=kwargs):
                command = self._record(f"fd-invalid-{index}", b"", self._fd_reuse_espipe(**kwargs), b"1\n")
                with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
                    with self.assertRaises(self.evidence.EvidenceError):
                        self.evidence.assert_oracle_fd_reuse(self.root, command)

    def test_suspend_lifetime_observation_keeps_only_the_bounded_return_states(self) -> None:
        for completed in (1, 2):
            with self.subTest(completed=completed):
                command = self._record(
                    f"lifetime-valid-{completed}",
                    f"aio-suspend-lifetime source-shape-completed={completed} "
                    "controlled-second-live=1 drained=2\n".encode("ascii"),
                )
                with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
                    self.evidence.assert_suspend_lifetime_observation(
                        self.root, command, "valid lifetime observation"
                    )
        invalid = (
            b"aio-suspend-lifetime source-shape-completed=0 controlled-second-live=1 drained=2\n",
            b"aio-suspend-lifetime source-shape-completed=3 controlled-second-live=1 drained=2\n",
            b"aio-suspend-lifetime source-shape-completed=1 controlled-second-live=0 drained=2\n",
            b"aio-suspend-lifetime source-shape-completed=1 controlled-second-live=1 drained=1\n",
            b"aio-suspend-lifetime source-shape-completed=1 controlled-second-live=1 drained=2\nextra\n",
        )
        for index, stdout in enumerate(invalid):
            with self.subTest(invalid=stdout):
                command = self._record(f"lifetime-invalid-{index}", stdout)
                with unittest.mock.patch.object(self.evidence, "SOURCE_MOUNT", str(self.root)):
                    with self.assertRaises(self.evidence.EvidenceError):
                        self.evidence.assert_suspend_lifetime_observation(
                            self.root, command, "invalid lifetime observation"
                        )

    def test_prepared_os_test_fixture_requires_exact_source_tree_and_receipt(self) -> None:
        profile = self.evidence.os_test_aio_suspend
        fixture = self.work / self.evidence.PREPARED_OS_TEST_AIO_SUSPEND_ROOT
        receipt = self.work / self.evidence.PREPARED_OS_TEST_AIO_SUSPEND_RECEIPT
        profile.write_prepared_fixture_receipt(fixture, receipt)
        self.assertEqual(
            self.evidence._prepared_os_test_aio_suspend_source(self.work),
            fixture / profile.SOURCE_PATH,
        )
        source = fixture / profile.SOURCE_PATH
        source.write_bytes(source.read_bytes() + b"/* changed */\n")
        with self.assertRaises(self.evidence.EvidenceError):
            self.evidence._prepared_os_test_aio_suspend_source(self.work)
        source.write_bytes(profile.prepared_fixture_files()[profile.SOURCE_PATH])
        receipt.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(self.evidence.EvidenceError):
            self.evidence._prepared_os_test_aio_suspend_source(self.work)


class OwnedAioSuppliedPathTests(unittest.TestCase):
    def test_symlinked_supplied_product_is_rejected_before_product_validation(self) -> None:
        evidence = module()
        root = TMP / self.id().replace(".", "-")
        shutil.rmtree(root, ignore_errors=True)
        (root / ".work").mkdir(parents=True)
        (root / "outside").mkdir()
        (root / ".work/product-link").symlink_to(root / "outside", target_is_directory=True)
        with self.assertRaises(evidence.EvidenceError):
            evidence.supplied_product(root, root / ".work/product-link", "dynamic")
        shutil.rmtree(root, ignore_errors=True)


class OwnedAioCatalogueEvidenceTests(unittest.TestCase):
    def test_catalogue_parser_admits_the_work_directory_not_the_receipt_file(self) -> None:
        evidence = module()
        scratch = TMP / self.id().replace(".", "-")
        shutil.rmtree(scratch, ignore_errors=True)
        leaf = scratch / "owned-aio"
        leaf.mkdir(parents=True)
        receipt = leaf / "owned-aio-receipts.json"
        receipt.write_text("{}\n", encoding="utf-8")
        log = scratch / "runner.log"
        # This is the completed runner line: the receipt is named separately,
        # leaving the catalogue's evidence parser one physical work directory.
        log.write_text(f"owned aio: PASS; receipt: {receipt}; evidence: {leaf}\n", encoding="utf-8")
        self.assertEqual(evidence.qualification.leaf_evidence_directories(log, str(ROOT)), {leaf})
        log.write_text(f"owned aio: PASS; evidence: {receipt}\n", encoding="utf-8")
        with self.assertRaises(evidence.qualification.QualificationError):
            evidence.qualification.leaf_evidence_directories(log, str(ROOT))
        shutil.rmtree(scratch, ignore_errors=True)


class OwnedAioModeAndRouteTests(unittest.TestCase):
    def test_dynamic_only_claims_exactly_four_routes_and_direct_uses_the_loader(self) -> None:
        evidence = module()
        self.assertEqual(evidence._mode_claims(None), [
            "dynamic-pie-kernel", "dynamic-pie-direct",
            "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
        ])
        root = TMP / self.id().replace(".", "-")
        work = root / "work"
        shutil.rmtree(root, ignore_errors=True)
        work.mkdir(parents=True)
        (work / "dynamic-pie-root").mkdir()
        with unittest.mock.patch.object(evidence, "SOURCE_MOUNT", str(root)):
            direct = evidence._execution_argv(root, work, "dynamic-pie", "workload", "direct", "")
            kernel = evidence._execution_argv(root, work, "dynamic-pie", "workload", "kernel", "")
        self.assertEqual(direct[-2:], ["/lib/ld-crabc-x86_64.so.1", "/consumer"])
        self.assertEqual(kernel[-1:], ["/consumer"])
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
