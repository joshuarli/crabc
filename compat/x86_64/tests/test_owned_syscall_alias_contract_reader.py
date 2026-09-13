#!/usr/bin/env python3
"""Regression coverage for exact ELF syscall alias identity checks."""

from __future__ import annotations

import sys
import unittest
import json
import os
import shutil
import tempfile
from unittest import mock
import hashlib
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_syscall_alias_contract_reader import (
    ALIASES,
    CURRENT_COMMAND_STEMS,
    GLOBAL_HIDDEN,
    LOCAL_BODIES,
    PUBLIC_ALIAS_SOURCE_CALLERS,
    ReceiptError,
    SymbolRow,
    _validate_command_argv,
    component_projection,
    expected_commands,
    main,
    require_same_probe_object,
    same,
    same_definition,
    validate_report,
)


class OwnedSyscallAliasContractReaderTests(unittest.TestCase):
    def test_oracle_source_recompile_cannot_pass_same_object_evidence(self) -> None:
        object_path = "/workspace/.work/probe/contract.o"
        commands = {
            f"{prefix}-contract-link": ["cc", object_path, "-o", f"/out/{prefix}"]
            for prefix in (
                "oracle", "oracle-dynamic-pie", "oracle-dynamic-non-pie",
                "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
            )
        }
        require_same_probe_object("contract", object_path, commands)
        for replacement in ("/source/contract.c", "/elsewhere/contract.o"):
            with self.subTest(replacement=replacement):
                changed = dict(commands)
                changed["oracle-contract-link"] = ["cc", replacement, "-o", "/out/oracle"]
                with self.assertRaisesRegex(ValueError, "same compiled probe object"):
                    require_same_probe_object("contract", object_path, changed)
        commands.pop("oracle-dynamic-non-pie-contract-link")
        with self.assertRaisesRegex(ValueError, "incomplete or additional probe links"):
            require_same_probe_object("contract", object_path, commands)

    def test_same_member_zero_value_different_sections_is_not_an_alias(self) -> None:
        alias = SymbolRow(
            member="clock_gettime.o",
            value="0000000000000000",
            symbol_type="FUNC",
            binding="WEAK",
            visibility="DEFAULT",
            section="17",
            name="clock_gettime",
        )
        forwarding_body = alias._replace(
            binding="GLOBAL",
            section="18",
            name="__clock_gettime",
        )

        self.assertFalse(same_definition(alias, forwarding_body))

    def test_public_source_caller_roster_includes_both_sigset_branches(self) -> None:
        self.assertEqual(
            PUBLIC_ALIAS_SOURCE_CALLERS,
            (
                ("__fxstat", "fstat"),
                ("__fxstatat", "fstatat"),
                ("ftime", "clock_gettime"),
                ("getloadavg", "sysinfo"),
                ("sigignore", "sigaction"),
                ("siginterrupt", "sigaction"),
                ("sigset", "sigaction"),
            ),
        )

    def test_component_projection_keeps_private_and_source_local_bodies_distinct(self) -> None:
        self.assertEqual(len(ALIASES), 14)
        self.assertEqual(len(GLOBAL_HIDDEN), 13)
        self.assertEqual(LOCAL_BODIES, ("__statfs", "__fstatfs"))
        self.assertIn("__libc_sigaction", GLOBAL_HIDDEN)

    def test_collect_rejects_an_unbound_elf_input_boundary(self) -> None:
        self.assertEqual(main(["collect"]), 2)

    def test_component_projection_survives_json_round_trip(self) -> None:
        projection = component_projection()
        self.assertTrue(same(json.loads(json.dumps(projection)), projection))

    def test_current_runner_envelope_roster_is_fixed_at_forty_seven(self) -> None:
        self.assertEqual(len(CURRENT_COMMAND_STEMS), 47)
        self.assertEqual(len(set(CURRENT_COMMAND_STEMS)), 47)
        self.assertIn("probe-object-link-proof", CURRENT_COMMAND_STEMS)
        self.assertIn("dynamic-non-pie-override-direct", CURRENT_COMMAND_STEMS)

    def test_host_replay_keeps_the_original_container_probe_object_path(self) -> None:
        inputs = {name: {"original": {"path": "/workspace/product/" + name}} for name in (
            "dynamic_driver", "static_driver", "oracle_compiler", "dynamic_linker",
            "dynamic_shared_provenance", "dynamic_producer_tools")}
        root = Path("/workspace")
        work = root / ".work/receipt/runner"
        command = expected_commands(work, inputs, root)["dynamic-pie-contract-link"]
        _validate_command_argv("dynamic-pie-contract-link", command, work, inputs, root)
        with self.assertRaisesRegex(ReceiptError, "exact command argv"):
            _validate_command_argv("dynamic-pie-contract-link", command, Path("/host/receipt/runner"), inputs, root)

    def test_all_forty_seven_commands_reject_each_changed_argument(self) -> None:
        inputs = {name: {"original": {"path": "/workspace/product/" + name}} for name in (
            "dynamic_driver", "static_driver", "oracle_compiler", "dynamic_linker",
            "dynamic_shared_provenance", "dynamic_producer_tools")}
        root, work = Path("/workspace"), Path("/workspace/.work/runner")
        for stem, command in expected_commands(work, inputs, root).items():
            _validate_command_argv(stem, command, work, inputs, root)
            for index in range(len(command)):
                with self.subTest(stem=stem, argument=index):
                    changed = list(command)
                    changed[index] += "-forged"
                    with self.assertRaises(ReceiptError):
                        _validate_command_argv(stem, changed, work, inputs, root)

    def test_review_forged_receipt_is_rejected_after_json_normalization(self) -> None:
        report = SOURCE_DIR.parents[1] / ".work/x86_64/receipt-review/forged-receipt-5ci97ja5/report.json"
        with self.assertRaises(ReceiptError):
            validate_report(report)



class OwnedSyscallAliasRetainedAuthorityTests(unittest.TestCase):
    """Use a real supplied-product receipt; never fabricate a passing ELF seal."""
    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("CRABC_SYSCALL_ALIAS_TEST_RECEIPT")
        if not value:
            raise unittest.SkipTest("set CRABC_SYSCALL_ALIAS_TEST_RECEIPT to a native component receipt")
        cls.receipt = Path(value)
        cls.scratch = SOURCE_DIR.parents[1] / ".work/x86_64/syscall-authority-tests"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=self.scratch)
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "receipt"
        shutil.copytree(self.receipt.parent, self.output, symlinks=True)
        self.path = self.output / "report.json"
        self.report = json.loads(self.path.read_text())
        self.runner = self.output / self.report["runner"]["path"]

    def test_real_receipt_survives_serialized_host_round_trip(self) -> None:
        self.path.write_text(json.dumps(self.report))
        self.assertEqual(validate_report(self.path)["runner"]["command_count"], 47)

    def test_public_alias_relocation_cannot_be_appended_to_raw_stream(self) -> None:
        path = self.runner / "candidate-shared-relocations.txt"
        with path.open("a") as stream:
            stream.write("0000000000 0000000000 R_X86_64_JUMP_SLOT fstat\n")
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_chroot_requires_exact_root_probe_and_regular_input(self) -> None:
        path = self.runner / "dynamic-pie-contract-kernel.argv.json"
        command = json.loads(path.read_text())
        command["argv"] = ["chroot", "/forged-root", "/not-the-probe", "/not-the-regular"]
        path.write_text(json.dumps(command))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_source_modes_are_bound_to_git_tree_not_mutual_seals(self) -> None:
        binding = self.report["source"]["collector"]["compat/x86_64/owned-syscall-alias-contract.md"]
        (self.output / binding["retained"]["path"]).chmod(0o777)
        binding["original"]["mode"] = binding["retained"]["mode"] = 0o777
        self.path.write_text(json.dumps(self.report))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_candidate_symbols_cannot_be_substituted_with_oracle_symbols(self) -> None:
        shutil.copyfile(self.runner / "musl-static-symbols.txt", self.runner / "candidate-static-symbols.txt")
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_host_replay_never_spawns_a_process(self) -> None:
        with mock.patch("subprocess.Popen", side_effect=AssertionError("host replay spawned a process")):
            validate_report(self.path)

    def test_python_stdin_is_bound_to_the_collector_source(self) -> None:
        (self.runner / "probe-object-seal.stdin").write_text("print('forged')\n")
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_tool_bytes_cannot_be_resealed_against_each_other(self) -> None:
        binding = self.report["tools"]["timeout"]
        path = self.output / binding["retained"]["path"]
        path.write_bytes(path.read_bytes() + b"forged")
        for kind in ("retained", "original"):
            binding[kind]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            binding[kind]["size"] = path.stat().st_size
        self.path.write_text(json.dumps(self.report))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_source_epoch_content_cannot_be_self_declared(self) -> None:
        self.report["collector_source"]["before"]["content_sha256"] = "a" * 64
        self.report["collector_source"]["after"]["content_sha256"] = "a" * 64
        self.path.write_text(json.dumps(self.report))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_application_override_weakening_is_not_ignored(self) -> None:
        path = self.runner / "dynamic-pie-override.symbols.txt"
        path.write_text(path.read_text().replace("GLOBAL", "WEAK"))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_final_link_command_is_bound_to_selected_inputs(self) -> None:
        path = self.runner / "dynamic-pie-contract.crabc-link.json"
        record = json.loads(path.read_text())
        record["link_command"][0] = "/foreign/ld"
        path.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_command_environment_cannot_inject_loader_or_python_state(self) -> None:
        path = self.runner / "dynamic-pie-contract-kernel.argv.json"
        record = json.loads(path.read_text())
        record["environment"]["LD_PRELOAD"] = "/foreign/libc.so"
        path.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_runtime_root_cannot_substitute_the_regular_input(self) -> None:
        (self.runner / "dynamic-pie-root/scratch/regular").write_text("forged\n")
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_probe_link_proof_is_replayed(self) -> None:
        path = self.runner / "probe-object-link-proof.json"
        record = json.loads(path.read_text())
        record["contract"]["object_sha256"] = "b" * 64
        path.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_raw_stream_symlink_is_rejected(self) -> None:
        path = self.runner / "candidate-static-symbols.txt"
        data = path.read_bytes()
        path.unlink()
        (self.output / "outside-symbols.txt").write_bytes(data)
        path.symlink_to(self.output / "outside-symbols.txt")
        with self.assertRaises(ReceiptError):
            validate_report(self.path)


if __name__ == "__main__":
    unittest.main()
