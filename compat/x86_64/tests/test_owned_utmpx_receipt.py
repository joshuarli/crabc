#!/usr/bin/env python3
"""Command-free receipt controls for the owned utmpx ABI component."""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_utmpx_receipt as receipt


class OwnedUtmpxReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/owned-utmpx-receipt-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="receipt-", dir=scratch))
        self.workspace = self.root / "workspace"
        self.commands = self.workspace / ".work/utmpx-receipt/owned-utmpx-receipt/commands"
        self.commands.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def command_fixture(self) -> None:
        runner = (ROOT / "compat/x86_64/run_owned_utmpx.sh").read_text(encoding="utf-8")
        bodies = []
        for match in re.finditer(r"record_stdin_command[ \t]+", runner):
            start = runner.index("<<'PY'\n", match.end()) + len("<<'PY'\n")
            end = runner.index("\nPY\n", start)
            bodies.append(runner[start:end].encode("utf-8") + b"\n")
        self.assertEqual(len(bodies), 7)
        stdin_bodies = {
            "header-oracle-undefined-judge": bodies[0], "header-project-undefined-judge": bodies[0],
            "archive-symbol-judge": bodies[1], "shared-symbol-judge": bodies[2],
            "executable-symbol-judge-static-static": bodies[3], "executable-symbol-judge-static-static-pie": bodies[3],
            "sealed-link-static": bodies[4], "sealed-link-static-pie": bodies[4],
            "sealed-link-pie": bodies[4], "sealed-link-non-pie": bodies[4],
            "link-identities": bodies[5], "dependency-audit": bodies[6],
        }
        for role, (cwd, argv) in receipt.command_plan().items():
            stdin = None
            if role in stdin_bodies:
                stdin_path = self.commands / (role + ".stdin")
                self.write(stdin_path, stdin_bodies[role])
                stdin_path.chmod(0o644)
                stdin = receipt.identity(self.workspace, stdin_path)
            self.write(self.commands / (role + ".json"), {
                "schema": receipt.COMMAND_SCHEMA, "role": role,
                "cwd": cwd,
                "status": 0, "program": receipt.expected_command_program(argv[0]), "argv": argv,
                "env": receipt.expected_command_environment(argv[0]), "stdin": stdin,
            })

    def symbol_fixture(self) -> None:
        raw = self.workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
        addresses = {name: f"{index:016x}" for index, name in enumerate(receipt.STRONG, 1)}
        addresses["utmpname"] = "0000000000000008"
        addresses.update({alias: addresses[target] for alias, target in receipt.ALIASES})
        self.write(raw / "archive-symbols.txt", "".join(
            f"{addresses[name]} {'T' if name in receipt.STRONG else 'W'} {name}\n" for name in (*receipt.STRONG, *receipt.WEAK)
        ).encode())
        self.write(raw / "dynamic-symbols.txt", "".join(
            f"  1: {addresses[name]} 0 FUNC {'GLOBAL' if name in receipt.STRONG else 'WEAK'} DEFAULT 1 {name}\n"
            for name in (*receipt.STRONG, *receipt.WEAK)
        ).encode())
        for _, name in receipt.STATIC_EXECUTABLE_SYMBOLS:
            self.write(raw / name, "".join(
                f"{addresses[symbol]} {'T' if symbol in receipt.STRONG else 'W'} {symbol}\n"
                for symbol in (*receipt.STRONG, *receipt.WEAK)
            ).encode())

    def test_static_symbol_receipt_names_follow_the_existing_runner_modes(self) -> None:
        self.assertEqual(receipt.STATIC_EXECUTABLE_SYMBOLS, (
            ("static", "static-symbols.txt"), ("static-pie", "static-pie-symbols.txt"),
        ))

    def test_retained_runtime_files_follow_the_runner_scenario_rows(self) -> None:
        self.assertEqual(receipt.RUNNER_STREAM_FILES, (
            "static-static-ordinary.stdout", "static-static-ordinary.stderr", "static-static-ordinary.status",
            "static-static-pie-ordinary.stdout", "static-static-pie-ordinary.stderr", "static-static-pie-ordinary.status",
            "dynamic-pie-kernel-ordinary.stdout", "dynamic-pie-kernel-ordinary.stderr", "dynamic-pie-kernel-ordinary.status",
            "dynamic-pie-direct-ordinary.stdout", "dynamic-pie-direct-ordinary.stderr", "dynamic-pie-direct-ordinary.status",
            "dynamic-non-pie-kernel-ordinary.stdout", "dynamic-non-pie-kernel-ordinary.stderr", "dynamic-non-pie-kernel-ordinary.status",
            "dynamic-non-pie-direct-ordinary.stdout", "dynamic-non-pie-direct-ordinary.stderr", "dynamic-non-pie-direct-ordinary.status",
        ))

    def test_source_mounted_command_program_maps_only_to_a_copied_product(self) -> None:
        driver = self.workspace / ".work/utmpx-receipt/inputs/dynamic/bin/crabc-cc-dynamic"
        self.write(driver, b"driver bytes")
        self.assertEqual(
            receipt.collected_program_source(
                "/workspace/.work/utmpx-receipt/inputs/dynamic/bin/crabc-cc-dynamic", self.workspace
            ),
            driver,
        )
        with self.assertRaisesRegex(receipt.ReceiptError, "escapes copied owned products"):
            receipt.collected_program_source("/workspace/compat/x86_64/run_owned_utmpx.sh", self.workspace)

    def test_final_elf_receipt_labels_follow_the_runner_command_roles(self) -> None:
        self.assertEqual(receipt.FINAL_ELF_LABELS, {
            "static": "static-static", "static-pie": "static-static-pie",
            "pie": "dynamic-pie", "non-pie": "dynamic-non-pie",
        })

    def test_rebuilt_link_product_is_projected_to_its_fixed_native_mount(self) -> None:
        product = self.workspace / ".work/utmpx-receipt/inputs/dynamic"
        product.mkdir(parents=True)
        rebuilt = {"product": str(product), "linkage": "pie", "executable_sha256": "a" * 64}
        projected = receipt.project_link_product("pie", product, rebuilt)
        self.assertEqual(projected["product"], "/workspace/.work/utmpx-receipt/inputs/dynamic")
        self.assertEqual(rebuilt["product"], str(product))
        with self.assertRaisesRegex(receipt.ReceiptError, "physical product path"):
            receipt.project_link_product("pie", product, {**rebuilt, "product": "/workspace/forged"})

    def test_nm_provider_rows_cannot_rewrite_an_alias_and_target_together(self) -> None:
        rows = self.root / "archive-symbols.txt"
        rows.write_text(
            "owned.o:\n0000000000000000 W endutent\n0000000000000000 T endutxent\n",
            encoding="utf-8",
        )
        expected = {
            "endutent": (0, "W", "owned.o"),
            "endutxent": (0, "T", "owned.o"),
        }
        receipt.require_nm_provider_rows(rows, expected, "archive")
        rows.write_text(
            "owned.o:\n0000000000000001 W endutent\n0000000000000001 T endutxent\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(receipt.ReceiptError, "provider address differs"):
            receipt.require_nm_provider_rows(rows, expected, "archive")

    def test_contract_has_exact_eight_selected_aliases(self) -> None:
        self.assertEqual(receipt.ALIASES, (
            ("endutent", "endutxent"), ("setutent", "setutxent"), ("getutent", "getutxent"),
            ("getutid", "getutxid"), ("getutline", "getutxline"), ("pututline", "pututxline"),
            ("updwtmp", "updwtmpx"), ("utmpxname", "utmpname"),
        ))

    def test_json_roundtrip_preserves_the_projection_alias_shape(self) -> None:
        projection = {"selected_aliases": [list(pair) for pair in receipt.ALIASES], "component_complete": True,
                      "family_complete": False, "runtime_qualified": False, "public_support": False,
                      "linkages": ["non-pie", "pie", "static", "static-pie"],
                      "runtime_streams": ["non-pie-direct", "non-pie-kernel", "oracle", "pie-direct", "pie-kernel", "static", "static-pie"]}
        decoded = json.loads(json.dumps(projection, sort_keys=True))
        receipt.same(decoded, projection, "JSON projection changed type or value")

    def test_forged_role_roster_or_status_cannot_substitute_for_the_real_command(self) -> None:
        self.command_fixture()
        receipt.command_records(self.workspace)
        forged = self.commands / "oracle-link.json"
        record = json.loads(forged.read_text(encoding="utf-8"))
        record["argv"] = ["/bin/true"]
        self.write(forged, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "command executable"):
            receipt.command_records(self.workspace)
        self.command_fixture()
        forged = self.commands / "runtime-dynamic-pie-direct-ordinary.json"
        record = json.loads(forged.read_text(encoding="utf-8"))
        record["argv"][6] = "/workspace/forged-chroot"
        self.write(forged, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "runtime-dynamic-pie-direct-ordinary command"):
            receipt.command_records(self.workspace)
        self.command_fixture()
        forged = self.commands / "archive-symbols.json"
        record = json.loads(forged.read_text(encoding="utf-8"))
        record["program"] = "/bin/bash"
        self.write(forged, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "program does not match"):
            receipt.command_records(self.workspace)

    def test_oracle_and_runtime_command_tails_cwd_and_path_are_closed(self) -> None:
        self.command_fixture()
        receipt.command_records(self.workspace)
        oracle = self.commands / "oracle-link.json"
        record = json.loads(oracle.read_text(encoding="utf-8"))
        record["cwd"] = "/workspace/forged-oracle-cwd"
        record["argv"][-3] = "/workspace/forged-workload.o"
        record["argv"][-1] = "/workspace/forged-oracle"
        self.write(oracle, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "oracle-link command"):
            receipt.command_records(self.workspace)

        self.command_fixture()
        runtime = self.commands / "runtime-dynamic-pie-direct-ordinary.json"
        record = json.loads(runtime.read_text(encoding="utf-8"))
        record["argv"][4] = "PATH=/workspace/forged-bin"
        self.write(runtime, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "runtime-dynamic-pie-direct-ordinary command"):
            receipt.command_records(self.workspace)

    def test_command_environment_and_inline_judge_are_not_self_sealed(self) -> None:
        self.command_fixture()
        receipt.command_records(self.workspace)
        command = self.commands / "archive-symbols.json"
        record = json.loads(command.read_text(encoding="utf-8"))
        record["env"]["PATH"] = "/workspace/forged-bin"
        self.write(command, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "archive-symbols environment"):
            receipt.command_records(self.workspace)

        self.command_fixture()
        command = self.commands / "archive-symbol-judge.json"
        record = json.loads(command.read_text(encoding="utf-8"))
        stdin = self.commands / "archive-symbol-judge.stdin"
        stdin.write_bytes(stdin.read_bytes() + b"# forged judge source\n")
        stdin.chmod(0o644)
        # Repairing every receipt-owned identity only proves the foreign file
        # matches its report row.  The accepted stdin is fixed reader data.
        record["stdin"] = receipt.identity(self.workspace, stdin)
        self.write(command, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "archive-symbol-judge stdin"):
            receipt.command_records(self.workspace)

    def test_tampered_alias_address_in_raw_symbol_stream_is_rejected(self) -> None:
        self.symbol_fixture()
        receipt.validate_symbol_bytes(self.workspace)
        raw = self.workspace / ".work/utmpx-receipt/owned-utmpx-receipt/archive-symbols.txt"
        raw.write_text(raw.read_text(encoding="utf-8").replace("0000000000000001 W endutent", "00000000000000ff W endutent"), encoding="utf-8")
        with self.assertRaisesRegex(receipt.ReceiptError, "alias address"):
            receipt.validate_symbol_bytes(self.workspace)

    def test_source_bytes_and_modes_cannot_be_reauthorized_by_report_rows(self) -> None:
        for name in receipt.SOURCES:
            receipt.copy_regular(ROOT / name, self.workspace / name)
        records = {name: receipt.identity(self.workspace, self.workspace / name) for name in receipt.SOURCES}
        tree = {"revision": receipt.local_git_head(ROOT), "entries": {
            name: {"git_mode": f"100{(ROOT / name).stat().st_mode & 0o777:03o}",
                   "git_blob": receipt.git_blob_id(self.workspace / name)} for name in receipt.SOURCES
        }}
        receipt.validate_selected_source(self.workspace, records, tree)
        owned = self.workspace / "libc/src/c_abi/x86_64/owned_utmpx.rs"
        owned.write_bytes(owned.read_bytes() + b"// forged source change\n")
        records["libc/src/c_abi/x86_64/owned_utmpx.rs"] = receipt.identity(self.workspace, owned)
        tree["entries"]["libc/src/c_abi/x86_64/owned_utmpx.rs"]["git_blob"] = receipt.git_blob_id(owned)
        with self.assertRaisesRegex(receipt.ReceiptError, "trusted local source"):
            receipt.validate_selected_source(self.workspace, records, tree)
        owned.unlink()
        receipt.copy_regular(ROOT / "libc/src/c_abi/x86_64/owned_utmpx.rs", owned)
        owned.chmod(0o755)
        records["libc/src/c_abi/x86_64/owned_utmpx.rs"] = receipt.identity(self.workspace, owned)
        tree["entries"]["libc/src/c_abi/x86_64/owned_utmpx.rs"].update(git_mode="100755", git_blob=receipt.git_blob_id(owned))
        with self.assertRaisesRegex(receipt.ReceiptError, "trusted local source"):
            receipt.validate_selected_source(self.workspace, records, tree)

    def test_pinned_image_manifest_is_positive_and_forged_tool_bytes_do_not_reauthorize(self) -> None:
        manifest_path = self.workspace / receipt.IMAGE_MANIFEST
        receipt.copy_regular(ROOT / receipt.IMAGE_MANIFEST, manifest_path)
        manifest_record = receipt.identity(self.workspace, manifest_path)
        manifest = receipt.validate_retained_image_manifest(self.workspace, manifest_record)
        program = "/usr/bin/python3"
        self.assertIn(program, manifest["files"])
        forged = self.workspace / "tools/forged-python3"
        self.write(forged, b"forged native tool bytes\n")
        # Re-seal every report-side field for the foreign bytes.  The trusted
        # immutable-image manifest, rather than this repaired self-seal,
        # must still reject the tool.
        with self.assertRaisesRegex(receipt.ReceiptError, "trusted manifest"):
            receipt.validate_image_tool(program, receipt.identity(self.workspace, forged),
                                        self.workspace, {}, manifest)

    def test_selected_product_epoch_is_distinct_from_the_collector_epoch(self) -> None:
        collector = receipt.local_git_head(ROOT)
        selected = {"revision": "f" * 40, "content_sha256": "b" * 64}
        self.assertNotEqual(selected["revision"], collector)
        seals = {}
        for name in receipt.PREPARATION_SOURCE_SEALS:
            path = self.workspace / ".work/utmpx-receipt/inputs/static-preparation" / name
            self.write(path, selected)
            record = receipt.identity(self.workspace, path)
            seals[name] = {key: record[key] for key in ("path", "sha256", "size")}
            seals[name]["path"] = ".work/x86_64/frozen-product/" + name
        preparation = {
            "schema": receipt.STATIC_PREPARATION_SCHEMA, "status": "prepared-unqualified",
            "work": ".work/x86_64/frozen-product", "source": selected, "source_seals": seals,
            "pins": {}, "products": {}, "archives": {}, "steps": {},
        }
        self.assertEqual(receipt.selected_product_epoch(preparation, self.workspace), selected)

    def test_mixed_static_dynamic_source_cohorts_are_rejected(self) -> None:
        source = {"revision": "a" * 40, "content_sha256": "b" * 64}
        state = {
            "schema": receipt.DYNAMIC_STATE_SCHEMA, "status": "materialized-unqualified",
            "source_sha256": source["content_sha256"], "contracts": {}, "payload_files": {},
            "runtime_v1_published": False, "campaign_complete": False, "public_support": False,
            "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
            "runtime_profile": "fixture", "qualification": "fixture",
        }
        receipt._validate_dynamic_source_epoch(state, source)
        state["source_sha256"] = "c" * 64
        with self.assertRaisesRegex(receipt.ReceiptError, "source cohort"):
            receipt._validate_dynamic_source_epoch(state, source)

    def test_raw_elf_symbol_stream_cannot_be_substituted_from_another_binary(self) -> None:
        candidate, foreign = Path("/bin/bash"), Path("/usr/bin/readelf")
        stream = self.root / "candidate-symbols.txt"
        stream.write_bytes(subprocess.check_output(["readelf", "--symbols", "--wide", str(candidate)]))
        receipt.validate_symbol_byte_stream(stream, candidate, "/candidate", frozenset({".dynsym", ".symtab"}))
        # This is a wholesale valid readelf stream from a different executable,
        # not a malformed fixture or a report field mutation.
        stream.write_bytes(subprocess.check_output(["readelf", "--symbols", "--wide", str(foreign)]))
        with self.assertRaisesRegex(receipt.ReceiptError, "raw symbols do not describe"):
            receipt.validate_symbol_byte_stream(stream, candidate, "/candidate", frozenset({".dynsym", ".symtab"}))

    def test_native_runner_failure_keeps_raw_diagnostics_without_a_receipt(self) -> None:
        output = self.root / "failed-native-collection"
        receipt.retain_native_runner_failure(output, b"native stdout\n", b"native stderr\n", 7)
        self.assertEqual((output / "native-runner.stdout").read_bytes(), b"native stdout\n")
        self.assertEqual((output / "native-runner.stderr").read_bytes(), b"native stderr\n")
        self.assertEqual((output / "native-runner.status").read_text(encoding="ascii"), "7\n")
        self.assertEqual(json.loads((output / "native-runner-failure.json").read_text())[
            "schema"], "crabc.x86_64-owned-utmpx-native-runner-failure/v1")

    def test_validate_requires_a_report_file(self) -> None:
        with self.assertRaises(receipt.ReceiptError):
            receipt.validate_report(self.root / "missing-utmpx-receipt.json")


if __name__ == "__main__":
    unittest.main()
