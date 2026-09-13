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
import zlib
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))
import owned_syscall_alias_authority as authority

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


    def test_probe_and_staged_copy_modes_cannot_be_resealed_together(self) -> None:
        (self.runner / "dynamic-pie-contract").chmod(0o777)
        (self.runner / "dynamic-pie-root/contract").chmod(0o777)
        with self.assertRaises(ReceiptError):
            validate_report(self.path)


    def test_self_consistent_git_commit_cannot_replace_collector_authority(self) -> None:
        objects = self.output / "source/git-objects"
        def read(oid): return zlib.decompress((objects / oid).read_bytes()).split(b"\0", 1)[1]
        def write(kind, data):
            raw = kind + b" " + str(len(data)).encode() + b"\0" + data
            oid = hashlib.sha1(raw).hexdigest()
            (objects / oid).write_bytes(zlib.compress(raw))
            return oid
        name = "compat/x86_64/owned-syscall-alias-contract.md"
        binding = self.report["source"]["collector"][name]
        retained = self.output / binding["retained"]["path"]
        data = retained.read_bytes() + b"\nforged collector contract\n"
        retained.write_bytes(data)
        for kind in ("retained", "original"):
            binding[kind]["sha256"] = hashlib.sha256(data).hexdigest()
            binding[kind]["size"] = len(data)
        def rewrite_tree(oid, parts):
            tree = read(oid)
            cursor = 0
            while cursor < len(tree):
                end = tree.index(b"\0", cursor)
                filename = tree[cursor:end].split(b" ", 1)[1]
                if filename == parts[0].encode():
                    old = tree[end + 1:end + 21].hex()
                    new = rewrite_tree(old, parts[1:]) if len(parts) > 1 else write(b"blob", data)
                    return write(b"tree", tree[:end + 1] + bytes.fromhex(new) + tree[end + 21:])
                cursor = end + 21
            self.fail("missing test source tree member")
        old_revision = self.report["collector_source"]["before"]["revision"]
        commit = read(old_revision)
        old_tree = commit.split(b"\n", 1)[0][5:].decode()
        tree = rewrite_tree(old_tree, name.split("/"))
        revision = write(b"commit", commit.replace(old_tree.encode(), tree.encode(), 1))
        seal, _files = authority.source_tree(self.output, revision)
        self.report["collector_source"] = {"before": seal, "after": seal}
        self.path.write_text(json.dumps(self.report))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)


    def test_static_endpoints_reject_same_type_provider_substitution(self) -> None:
        for target, replacement in (
            ("static-contract", "oracle-contract"),
            ("static-override", "oracle-override"),
            ("static-pie-contract", "dynamic-pie-contract"),
            ("static-pie-override", "dynamic-pie-override"),
        ):
            with self.subTest(target=target, replacement=replacement):
                path = self.runner / target
                original = path.read_bytes()
                try:
                    path.write_bytes((self.runner / replacement).read_bytes())
                    with self.assertRaises(ReceiptError):
                        validate_report(self.path)
                finally:
                    path.write_bytes(original)


    def test_static_provider_swaps_cannot_be_resealed_with_new_output_hashes(self) -> None:
        for target, replacement in (
            ("static-contract", "oracle-contract"),
            ("static-override", "oracle-override"),
            ("static-pie-contract", "dynamic-pie-contract"),
            ("static-pie-override", "dynamic-pie-override"),
        ):
            with self.subTest(target=target, replacement=replacement):
                path = self.runner / target
                sidecar = self.runner / (target + ".link.json")
                original, original_receipt = path.read_bytes(), sidecar.read_bytes()
                try:
                    path.write_bytes((self.runner / replacement).read_bytes())
                    record = json.loads(original_receipt)
                    record["output"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    sidecar.write_text(json.dumps(record))
                    with self.assertRaises(ReceiptError):
                        validate_report(self.path)
                finally:
                    path.write_bytes(original)
                    sidecar.write_bytes(original_receipt)

    def test_static_selected_probe_object_cannot_be_replaced_in_the_link_receipt(self) -> None:
        for mode in ("static", "static-pie"):
            for probe, other in (("contract", "override"), ("override", "contract")):
                with self.subTest(mode=mode, probe=probe):
                    path = self.runner / f"{mode}-{probe}.link.json"
                    original = path.read_bytes()
                    try:
                        record = json.loads(original)
                        record["input_receipts"][-1] = {
                            "role": "application", "path": self.report["runner"]["original"] + "/" + other + ".o",
                            "sha256": hashlib.sha256((self.runner / (other + ".o")).read_bytes()).hexdigest(),
                        }
                        path.write_text(json.dumps(record))
                        with self.assertRaises(ReceiptError):
                            validate_report(self.path)
                    finally:
                        path.write_bytes(original)

    def test_static_trace_cannot_invent_a_selected_archive_member(self) -> None:
        path = self.runner / "static-contract.link.trace"
        with path.open("a") as stream:
            stream.write(self.report["products"]["static"]["original"] + "/usr/lib/libc.a(invented.o)\n")
        sidecar = self.runner / "static-contract.link.json"
        record = json.loads(sidecar.read_text())
        record["trace"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        sidecar.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_static_function_code_cannot_be_resealed_with_an_output_hash(self) -> None:
        path = self.runner / "static-contract"
        elf = authority.Elf(path)
        main = elf.symbol("main", dynamic=False)
        section = elf.sections[main["section"]]
        offset = section[4] + main["value"] - section[3]
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        path.write_bytes(data)
        sidecar = self.runner / "static-contract.link.json"
        record = json.loads(sidecar.read_text())
        record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
        sidecar.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_static_linker_cannot_be_changed_within_an_otherwise_valid_receipt(self) -> None:
        path = self.runner / "static-pie-override.link.json"
        record = json.loads(path.read_text())
        record["resolved_linker"]["sha256"] = "c" * 64
        path.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)


    def test_static_call_displacement_cannot_be_resealed(self) -> None:
        path = self.runner / "static-contract"
        elf = authority.Elf(path)
        main = elf.symbol("main", dynamic=False)
        section = elf.sections[main["section"]]
        offset = section[4] + main["value"] - section[3] + 72
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        path.write_bytes(data)
        sidecar = self.runner / "static-contract.link.json"
        record = json.loads(sidecar.read_text())
        record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
        sidecar.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def test_static_tls_displacement_cannot_be_resealed(self) -> None:
        path = self.runner / "static-contract"
        elf = authority.Elf(path)
        symbol = elf.symbol("clock_gettime", dynamic=False)
        section = elf.sections[symbol["section"]]
        offset = section[4] + symbol["value"] - section[3] + 23
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        path.write_bytes(data)
        sidecar = self.runner / "static-contract.link.json"
        record = json.loads(sidecar.read_text())
        record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
        sidecar.write_text(json.dumps(record))
        with self.assertRaises(ReceiptError):
            validate_report(self.path)

    def assert_resealed_static_mutation_rejected(self, stem, mutate) -> None:
        path = self.runner / stem
        sidecar = self.runner / (stem + ".link.json")
        original, original_receipt = path.read_bytes(), sidecar.read_bytes()
        try:
            data = bytearray(original)
            mutate(data, authority.Elf(path))
            path.write_bytes(data)
            record = json.loads(original_receipt)
            record["output"]["sha256"] = hashlib.sha256(data).hexdigest()
            sidecar.write_text(json.dumps(record))
            with self.assertRaises(ReceiptError):
                validate_report(self.path)
        finally:
            path.write_bytes(original)
            sidecar.write_bytes(original_receipt)

    def test_each_observed_static_relocation_form_rejects_resealed_displacement(self) -> None:
        for mode in ("static", "static-pie"):
            for probe in ("contract", "override"):
                sites = [(4, "_start", 13 if mode == "static" else 1241)]
                sites += ([(2, "main", 697), (9, "clock_nanosleep", 274), (22, "clock_gettime", 23)]
                          if probe == "contract" else [(2, "clock_gettime", 17), (42, "sigaction", 92)])
                for kind, name, relative in sites:
                    with self.subTest(mode=mode, probe=probe, kind=kind):
                        def mutate(data, elf):
                            symbol = elf.symbol(name, dynamic=False)
                            section = elf.sections[symbol["section"]]
                            offset = section[4] + symbol["value"] - section[3] + relative
                            data[offset] ^= 1
                        self.assert_resealed_static_mutation_rejected(f"{mode}-{probe}", mutate)

    def test_static_relaxation_opcode_is_derived_with_its_displacement(self) -> None:
        for mode in ("static", "static-pie"):
            for probe, name, relative, opcode in (("contract", "clock_gettime", 23, 0x8d),
                                                   ("override", "sigaction", 92, 0x8b)):
                with self.subTest(mode=mode, probe=probe):
                    def mutate(data, elf):
                        symbol = elf.symbol(name, dynamic=False)
                        section = elf.sections[symbol["section"]]
                        offset = section[4] + symbol["value"] - section[3] + relative - 2
                        data[offset] = opcode
                    self.assert_resealed_static_mutation_rejected(f"{mode}-{probe}", mutate)

    def test_static_got_displacement_requires_the_selected_target_value(self) -> None:
        for mode in ("static", "static-pie"):
            with self.subTest(mode=mode):
                def mutate(data, elf):
                    symbol = elf.symbol("clock_nanosleep", dynamic=False)
                    section = elf.sections[symbol["section"]]
                    field = section[4] + symbol["value"] - section[3] + 274
                    slot = symbol["value"] + 274 + 4 + int.from_bytes(data[field:field + 4], "little", signed=True)
                    if mode == "static":
                        got = next(s for s in elf.sections if authority.section_name(elf, s) == ".got")
                        data[got[4] + slot - got[3]] ^= 1
                    else:
                        offsets = [section[4] + offset + 16 for section in elf.sections if section[1] == 4
                                   for offset in range(0, section[5], 24)
                                   if elf.unpack("<Q", section[4] + offset)[0] == slot]
                        self.assertEqual(len(offsets), 1)
                        data[offsets[0]] ^= 1
                self.assert_resealed_static_mutation_rejected(f"{mode}-contract", mutate)

    def test_static_tls_geometry_cannot_be_resealed(self) -> None:
        for mode in ("static", "static-pie"):
            with self.subTest(mode=mode):
                def mutate(data, elf):
                    index = next(i for i, program in enumerate(elf.programs) if program[0] == 7)
                    offset = elf.unpack("<Q", 32)[0] + index * 56 + 40
                    value = elf.unpack("<Q", offset)[0]
                    data[offset:offset + 8] = (value + 8).to_bytes(8, "little")
                self.assert_resealed_static_mutation_rejected(f"{mode}-contract", mutate)


if __name__ == "__main__":
    unittest.main()
