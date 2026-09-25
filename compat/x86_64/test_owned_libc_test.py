#!/usr/bin/env python3
"""Focused source-graph regressions for the owned libc-test aggregate."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("owned_libc_test.py")
SPECIFICATION = importlib.util.spec_from_file_location("owned_libc_test", MODULE_PATH)
assert SPECIFICATION is not None and SPECIFICATION.loader is not None
aggregate = importlib.util.module_from_spec(SPECIFICATION)
SPECIFICATION.loader.exec_module(aggregate)


class OwnedLibcTestGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def translated_common_record(self, name: str) -> tuple[dict, Path]:
        object_path = self.root / f"{name}.o"
        object_path.parent.mkdir(parents=True, exist_ok=True)
        object_path.write_bytes(b"candidate-object")
        return {
            "id": name,
            "kind": "common",
            "candidate_translation": {
                "status": "passed",
                "object": {"path": str(object_path)},
            },
        }, object_path

    def materialized_product(self) -> Path:
        """Create the smallest complete dynamic-product manifest for sealing tests."""

        product = self.root / ".work/product"
        payload = {
            "bin/crabc-cc-dynamic": b"driver\n",
            "share/crabc/crabc_cc_static.py": b"helper\n",
            "usr/lib/libc.so": b"libc\n",
            "usr/lib/crt1.o": b"crt1\n",
            "usr/lib/Scrt1.o": b"scrt1\n",
            "usr/lib/crti.o": b"crti\n",
            "usr/lib/crtn.o": b"crtn\n",
            "usr/lib/crabc-dynamic-attach.o": b"attach\n",
            "usr/lib/libcrabc-builtins.a": b"builtins\n",
            "lib/ld-crabc-x86_64.so.1": b"loader\n",
        }
        for relative, data in payload.items():
            path = product / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (product / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        manifest = {
            "schema": 1,
            "format": aggregate.PRODUCT_FORMAT,
            "target": aggregate.TARGET,
            "files": {relative: aggregate.digest(product / relative) for relative in sorted(payload)},
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        manifest_path = product / "share/crabc/manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return product

    def test_runtest_is_not_linked_into_each_runtime_target(self) -> None:
        """The upstream libtest.a has nine helpers; runtest owns a separate main."""

        records = {}
        paths = {}
        for name in (*aggregate.COMMON_MEMBERS, aggregate.RUNTIME_HELPER):
            record, path = self.translated_common_record(name)
            records[name] = record
            paths[name] = path
        candidate_inputs: list[list[Path]] = []
        oracle_inputs: list[list[Path]] = []

        def candidate_link(**arguments):
            candidate_inputs.append(list(arguments["objects"]))
            return {"status": "passed"}

        def oracle_link(**arguments):
            oracle_inputs.append(list(arguments["objects"]))
            return {"status": "passed"}

        with patch.object(aggregate, "candidate_link", side_effect=candidate_link), patch.object(
            aggregate, "oracle_link", side_effect=oracle_link
        ):
            _, _, common_objects, blocker = aggregate.update_runtest_links(
                records=records, product=self.root, environment={}, work=self.root,
            )

        expected_members = [paths[name] for name in aggregate.COMMON_MEMBERS]
        self.assertIsNone(blocker)
        self.assertEqual(candidate_inputs, [[paths[aggregate.RUNTIME_HELPER], *expected_members]])
        self.assertEqual(oracle_inputs, [[paths[aggregate.RUNTIME_HELPER], *expected_members]])
        self.assertEqual(common_objects, expected_members)
        self.assertNotIn(paths[aggregate.RUNTIME_HELPER], common_objects)

    def test_non_runtest_common_members_have_no_standalone_link_edge(self) -> None:
        record = {
            "id": "common/fdfill",
            "kind": "common",
            "header_translation": {"status": "passed"},
            "candidate_translation": {"status": "passed"},
            "candidate_link": {"status": "not-applicable"},
            "oracle_link": {"status": "not-applicable"},
            "runtime": {"status": "not-applicable"},
        }
        self.assertEqual(aggregate.classify_unit(record), "passed")

    def test_host_control_tool_resolves_a_conventional_symlink(self) -> None:
        target = self.root / "timeout.real"
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o755)
        alias = self.root / "timeout"
        alias.symlink_to(target.name)
        with patch.object(aggregate.shutil, "which", return_value=str(alias)):
            self.assertEqual(aggregate.find_control_tool("timeout"), alias)

    def test_control_loader_is_the_pinned_oracle_runtime(self) -> None:
        loader = self.root / "pinned-libc.so"
        loader.write_bytes(b"pinned musl loader")
        loader.chmod(0o755)

        with patch.object(aggregate, "ORACLE_LIBC", loader):
            self.assertEqual(aggregate.pinned_control_loader(), loader)

    def test_control_launcher_declares_the_exec_environment_abi(self) -> None:
        self.assertIn(b"extern char **environ;", aggregate.CONTROL_SHELL_SOURCE)

    def test_echo_launcher_has_a_separate_pinned_control_closure(self) -> None:
        """`posix_spawnp("echo")` may not resolve through an ambient root."""

        self.assertIn(b"extern char **environ;", aggregate.CONTROL_ECHO_SOURCE)
        self.assertIn(b'command[2] = "echo";', aggregate.CONTROL_ECHO_SOURCE)
        self.assertNotEqual(aggregate.CONTROL_ECHO_SOURCE, aggregate.CONTROL_SHELL_SOURCE)

    def test_source_selected_filesystem_fixtures_are_narrow_and_exact(self) -> None:
        """Only the named upstream units receive their required root topology."""

        shared_memory = [{"path": "/dev/shm", "type": "directory", "mode": "01777"}]
        for unit in (
            "functional/sem_open",
            "regression/sem_close-unmap",
            "functional/pthread_cancel-points",
        ):
            self.assertEqual(aggregate.filesystem_fixture_for_unit(unit), shared_memory)
        self.assertEqual(aggregate.filesystem_fixture_for_unit("regression/tls_get_new-dtv"), [
            {"path": "/proc", "type": "directory", "mode": "0755"},
            {"path": "/proc/self", "type": "directory", "mode": "0755"},
            {"path": "/proc/self/exe", "type": "symlink", "target": "/regression/tls_get_new-dtv"},
        ])
        self.assertEqual(aggregate.filesystem_fixture_for_unit("functional/argv"), [])

    def test_filesystem_fixture_rejects_undeclared_nodes_and_retains_kernel_exe_mapping(self) -> None:
        """The artificial `/proc` tree is only the source-required `$ORIGIN` link."""

        root = self.root / "root"
        (root / "dev").mkdir(parents=True)
        executable = root / "regression/tls_get_new-dtv"
        executable.parent.mkdir()
        executable.write_bytes(b"runtime target")
        executable.chmod(0o755)
        fixture = aggregate.filesystem_fixture_for_unit("regression/tls_get_new-dtv")

        aggregate.materialize_filesystem_fixture(root, fixture)
        self.assertEqual(aggregate.verify_filesystem_fixture(root, fixture), fixture)
        self.assertTrue((root / "proc/self/exe").is_symlink())
        self.assertEqual(os.readlink(root / "proc/self/exe"), "/regression/tls_get_new-dtv")

        shared = aggregate.filesystem_fixture_for_unit("functional/sem_open")
        aggregate.materialize_filesystem_fixture(root, shared)
        (root / "dev/shm/left-behind").write_bytes(b"unexpected")
        with self.assertRaisesRegex(aggregate.EvidenceError, "undeclared child"):
            aggregate.verify_filesystem_fixture(root, shared)

    def test_known_common_linker_failure_blocks_unattempted_candidates(self) -> None:
        stderr = self.root / "candidate-link.stderr"
        stderr.write_text("ld.lld: error: input.o is compressed with ELFCOMPRESS_ZLIB\n")
        failure = {
            "status": "failed",
            "record": {"stderr": {"path": str(stderr)}},
        }

        blocker = aggregate.common_candidate_toolchain_failure("functional/argv", failure)

        self.assertIsNotNone(blocker)
        assert blocker is not None
        self.assertEqual(blocker["kind"], "compressed-debug-information")
        self.assertEqual(blocker["first_unit"], "functional/argv")
        dependent = aggregate.blocked_by_common_candidate_toolchain(blocker)
        self.assertEqual(dependent["status"], "blocked")
        self.assertEqual(dependent["reason"], "unattempted: retained common candidate toolchain failure")
        self.assertEqual(dependent["common_toolchain_failure"], blocker)

    def test_missing_driver_source_edge_records_command_without_compiling(self) -> None:
        prepared = self.root / "prepared"
        source = prepared / "src/functional/example.c"
        source.parent.mkdir(parents=True)
        source.write_text("int main(void) { return 0; }\n")
        common = prepared / "src/common"
        common.mkdir()
        product = self.root / "product"
        helper = product / "share/crabc/crabc_cc_static.py"
        helper.parent.mkdir(parents=True)
        helper.write_text("HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\n")
        generated = self.root / "generated"
        evidence = self.root / "units/example.translation"
        output = self.root / "objects/example.o"

        def header_only(command, *, cwd, environment, stdout, stderr, stdin=None):
            self.assertIn("-H", command)
            stdout.parent.mkdir(parents=True, exist_ok=True)
            stderr.parent.mkdir(parents=True, exist_ok=True)
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            return {"command": command, "environment": environment, "exit_status": 0}

        with patch.object(aggregate, "run_capture", side_effect=header_only) as capture:
            result = aggregate.compile_candidate(
                product=product,
                compiler=Path("/declared/compiler"),
                environment={"LC_ALL": "C"},
                prepared=prepared,
                generated=generated,
                unit={"id": "functional/example", "source": "src/functional/example.c", "kind": "runtime"},
                output=output,
                evidence=evidence,
                driver_ready=False,
            )

        self.assertEqual(capture.call_count, 1)
        self.assertEqual(result["header_translation"]["status"], "passed")
        translation = result["candidate_translation"]
        self.assertEqual(translation["status"], "blocked")
        self.assertEqual(translation["reason"], "installed driver lacks required sealed libc-test source inputs")
        self.assertEqual(translation["record"]["command"][0], str(product / "bin/crabc-cc-dynamic"))
        self.assertFalse(output.exists())

    def test_runtime_status_is_durable_after_private_root_reclaim(self) -> None:
        record = {
            "command": ["controlled-runtime"],
            "environment": {"LC_ALL": "C"},
            "exit_status": 0,
            "stdout": {"path": "/retained/stdout", "sha256": "0" * 64},
            "stderr": {"path": "/retained/stderr", "sha256": "1" * 64},
        }

        def create_root(_product: Path, destination: Path) -> None:
            destination.mkdir()

        before = {"path": str(self.root / "before.json"), "sha256": "2" * 64}
        after = {"path": str(self.root / "after.json"), "sha256": "3" * 64}
        with patch.object(aggregate, "make_candidate_root", side_effect=create_root), patch.object(
            aggregate, "prepare_execution_root"
        ), patch.object(aggregate, "runtime_root_payload_record", return_value={"program": []}), patch.object(
            aggregate, "write_root_payload_phase", side_effect=[before, after]
        ), patch.object(aggregate, "execute_in_root", return_value=record
        ):
            result = aggregate.execute_runtime_side(
                side="candidate",
                work=self.root,
                product=self.root,
                unit_id="functional/example",
                runner=self.root / "runtest",
                executable=self.root / "example",
                support={},
                external_shell=None,
                external_echo=None,
                oracle={},
                candidate_product={"manifest": {"sha256": "4" * 64}, "files": {}, "aliases": {}},
            )

        status_path = self.root / "execution/functional/example/candidate.status.json"
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["root_reclaimed"])
        self.assertFalse((self.root / "execution/functional/example/candidate").exists())
        self.assertEqual(json.loads(status_path.read_text()), record)
        self.assertEqual(result["status_record"]["path"], str(status_path))
        self.assertEqual(result["root_payload"], {"before": before, "after": after, "unchanged": True})

    def test_source_runtest_command_keeps_empty_wrap_and_default_timeout(self) -> None:
        output = self.root / "runtime.stdout"
        timeout = self.root / "timeout"
        chroot = self.root / "chroot"
        captured: list[list[str]] = []

        def capture(command, **_arguments):
            captured.append(list(command))
            return {"exit_status": 0}

        with patch.object(aggregate, "find_control_tool", side_effect=[timeout, chroot]), patch.object(
            aggregate, "run_capture", side_effect=capture
        ):
            aggregate.execute_in_root(self.root / "root", "/functional/argv", output)

        self.assertEqual(aggregate.SOURCE_RUNTEST_TIMEOUT_SECONDS, 5)
        self.assertEqual(captured, [[
            str(timeout), "20", str(chroot), str(self.root / "root"),
            "/runtest", "-w", "", "/functional/argv",
        ]])

    def test_candidate_product_is_sealed_as_full_payload_and_alias_map(self) -> None:
        product = self.materialized_product()
        with patch.object(aggregate, "ROOT", self.root):
            before = aggregate.validate_product(product)
            sealed = aggregate.seal_candidate_product(product, self.root / ".work/sealed", before)
            aggregate.require_same_product_payload(before, sealed, "test seal")

        self.assertEqual(sealed["aliases"], {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"})
        self.assertTrue((self.root / ".work/sealed/lib/ld-musl-x86_64.so.1").is_symlink())
        self.assertEqual(os.readlink(self.root / ".work/sealed/lib/ld-musl-x86_64.so.1"), "ld-crabc-x86_64.so.1")

    def test_control_shell_copy_preserves_candidate_loader_alias(self) -> None:
        root = self.root / "runtime"
        (root / "lib").mkdir(parents=True)
        (root / "lib/ld-crabc-x86_64.so.1").write_bytes(b"candidate-loader")
        (root / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        busybox = self.root / "busybox"
        loader = self.root / "control-loader"
        launcher = self.root / "candidate-launcher"
        for path in (busybox, loader, launcher):
            path.write_bytes(path.name.encode())
            path.chmod(0o755)
        fixture = {
            "status": "passed",
            "control": {
                "busybox": aggregate.artifact(busybox, "BusyBox"),
                "loader": aggregate.artifact(loader, "control loader"),
                "layout": {
                    "busybox": aggregate.CONTROL_BUSYBOX,
                    "loader": aggregate.CONTROL_LOADER,
                    "launcher": "/bin/sh",
                },
            },
            "candidate_launcher": aggregate.artifact(launcher, "launcher"),
        }

        records = aggregate.copy_shell_fixture_record(root, fixture, "candidate")

        self.assertEqual(len(records), 3)
        self.assertTrue((root / "lib/ld-musl-x86_64.so.1").is_symlink())
        self.assertEqual(os.readlink(root / "lib/ld-musl-x86_64.so.1"), "ld-crabc-x86_64.so.1")
        self.assertEqual((root / "bin/sh").read_bytes(), launcher.read_bytes())
        self.assertEqual((root / "control/busybox").read_bytes(), busybox.read_bytes())

    def test_control_echo_copy_preserves_candidate_loader_alias(self) -> None:
        root = self.root / "runtime"
        (root / "lib").mkdir(parents=True)
        (root / "lib/ld-crabc-x86_64.so.1").write_bytes(b"candidate-loader")
        (root / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        busybox = self.root / "busybox"
        loader = self.root / "control-loader"
        launcher = self.root / "candidate-echo-launcher"
        for path in (busybox, loader, launcher):
            path.write_bytes(path.name.encode())
            path.chmod(0o755)
        fixture = {
            "status": "passed",
            "control": {
                "busybox": aggregate.artifact(busybox, "BusyBox"),
                "loader": aggregate.artifact(loader, "control loader"),
                "layout": {
                    "busybox": aggregate.CONTROL_BUSYBOX,
                    "loader": aggregate.CONTROL_LOADER,
                    "launcher": "/bin/echo",
                },
            },
            "candidate_launcher": aggregate.artifact(launcher, "launcher"),
        }

        records = aggregate.copy_echo_fixture_record(root, fixture, "candidate")

        self.assertEqual(len(records), 3)
        self.assertTrue((root / "lib/ld-musl-x86_64.so.1").is_symlink())
        self.assertEqual(os.readlink(root / "lib/ld-musl-x86_64.so.1"), "ld-crabc-x86_64.so.1")
        self.assertEqual((root / "bin/echo").read_bytes(), launcher.read_bytes())
        self.assertEqual((root / "control/busybox").read_bytes(), busybox.read_bytes())

    def test_raw_root_retains_actual_loader_and_libc_copy_hashes(self) -> None:
        runtime = self.root / "pinned-libc.so"
        runtime.write_bytes(b"pinned musl runtime")
        runtime.chmod(0o755)
        oracle = {
            "files": {
                "loader": {"path": "/opt/musl/lib/ld-musl-x86_64.so.1", "sha256": aggregate.digest(runtime)},
                "libc": {"path": "/opt/musl/lib/libc.so", "sha256": aggregate.digest(runtime)},
            },
        }
        root = self.root / "raw-root"

        with patch.object(aggregate, "ORACLE_LIBC", runtime):
            record = aggregate.make_oracle_root(root, oracle)

        self.assertEqual(record["loader"]["destination"], "/lib/ld-musl-x86_64.so.1")
        self.assertEqual(record["libc"]["destination"], "/usr/lib/libc.so")
        self.assertEqual(record["loader"]["copied_sha256"], aggregate.digest(runtime))
        self.assertEqual(record["libc"]["copied_sha256"], aggregate.digest(runtime))
        self.assertEqual((root / "lib/ld-musl-x86_64.so.1").read_bytes(), runtime.read_bytes())

    def test_runtime_observation_keeps_oracle_identity_separate_from_run_result(self) -> None:
        oracle_identity = {"files": {"loader": {"sha256": "a" * 64}}}
        candidate_product = {"manifest": {"sha256": "b" * 64}, "files": {}, "aliases": {}}
        stdout = self.root / "same.stdout"
        stderr = self.root / "same.stderr"
        stdout.write_bytes(b"ok\n")
        stderr.write_bytes(b"")
        calls: list[dict] = []

        def execute(**arguments):
            calls.append(arguments)
            return {
                "status": "passed",
                "record": {
                    "exit_status": 0,
                    "stdout": aggregate.artifact(stdout, "stdout"),
                    "stderr": aggregate.artifact(stderr, "stderr"),
                },
            }

        with patch.object(aggregate, "execute_runtime_side", side_effect=execute):
            result = aggregate.runtime_observation(
                work=self.root,
                product=self.root,
                unit_id="functional/argv",
                candidate_runner=self.root / "candidate-runtest",
                oracle_runner=self.root / "oracle-runtest",
                candidate_executable=self.root / "candidate-argv",
                oracle_executable=self.root / "oracle-argv",
                candidate_support={}, oracle_support={}, external_shell=None,
                external_echo=None,
                oracle_identity=oracle_identity, candidate_product=candidate_product,
            )

        self.assertEqual(result["comparison"]["status"], "passed")
        self.assertEqual([call["oracle"] for call in calls], [oracle_identity, oracle_identity])

    def test_runtime_link_update_preserves_oracle_identity_for_raw_roots(self) -> None:
        object_path = self.root / "example.o"
        object_path.write_bytes(b"candidate object")
        object_path.chmod(0o644)
        records = {
            "functional/example": {
                "id": "functional/example",
                "kind": "runtime",
                "candidate_translation": {
                    "status": "passed",
                    "object": aggregate.artifact(object_path, "candidate object"),
                },
            },
        }
        oracle_identity = {"files": {"loader": {"sha256": "a" * 64}, "libc": {"sha256": "b" * 64}}}
        observed: list[dict] = []

        def observe(**arguments):
            observed.append(arguments)
            return {"oracle": {"status": "passed"}, "candidate": {"status": "passed"},
                    "comparison": {"status": "passed"}}

        with patch.object(aggregate, "candidate_link", return_value={"status": "passed"}), patch.object(
            aggregate, "oracle_link", return_value={"status": "passed", "link": "raw-link"}
        ), patch.object(aggregate, "runtime_observation", side_effect=observe):
            aggregate.update_runtime_links(
                records=records, product=self.root, environment={}, work=self.root,
                common_objects=[], candidate_runner=self.root / "candidate-runtest",
                oracle_runner=self.root / "oracle-runtest", candidate_support={}, oracle_support={}, shell=None,
                echo=None,
                oracle_identity=oracle_identity,
                candidate_product={"manifest": {"sha256": "c" * 64}, "files": {}, "aliases": {}},
            )

        self.assertEqual(observed[0]["oracle_identity"], oracle_identity)
        self.assertEqual(records["functional/example"]["oracle_link"], {"status": "passed", "link": "raw-link"})


if __name__ == "__main__":
    unittest.main()
