#!/usr/bin/env python3
"""Command-free receipt controls for the owned utmpx ABI component."""
from __future__ import annotations

import json
from pathlib import Path
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
        base = ["/usr/bin/true"]
        for role in receipt.COMMAND_ROLES:
            argv = list(base)
            if role == "dynamic-driver-compile":
                argv = ["/workspace/.work/utmpx-receipt/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-std=c11", "-fno-builtin", "-c",
                        "/workspace/compat/x86_64/owned_utmpx_probe.c", "-o", "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/workload.o"]
            elif role == "oracle-link":
                argv = ["/usr/local/bin/crabc-x86_64-musl-gcc", "-static", "-fno-pie", "-no-pie", "-pthread"]
            elif role.startswith("static-link-"):
                linkage = role.removeprefix("static-link-")
                argv = ["/workspace/.work/utmpx-receipt/inputs/static/bin/crabc-cc", "-" + linkage,
                        "--link-receipt", linkage + ".json", "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/workload.o", "-o",
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/static-" + linkage]
            elif role.startswith("dynamic-link-"):
                linkage = role.removeprefix("dynamic-link-")
                argv = ["/workspace/.work/utmpx-receipt/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-" + linkage,
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/workload.o", "-o",
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/dynamic-" + linkage]
            elif role == "archive-symbols":
                argv = ["nm", "-g", "--defined-only", "/workspace/.work/utmpx-receipt/inputs/static/usr/lib/libc.a"]
            elif role == "archive-symbol-bytes":
                argv = ["readelf", "--symbols", "--wide", "/workspace/.work/utmpx-receipt/inputs/static/usr/lib/libc.a"]
            elif role == "shared-symbols":
                argv = ["readelf", "--dyn-syms", "--wide", "/workspace/.work/utmpx-receipt/inputs/dynamic/usr/lib/libc.so"]
            elif role.startswith("executable-symbol-bytes-"):
                label = role.removeprefix("executable-symbol-bytes-")
                executable = {"static-static": "static-static", "static-static-pie": "static-static-pie",
                              "dynamic-pie": "dynamic-pie", "dynamic-non-pie": "dynamic-non-pie"}[label]
                argv = ["readelf", "--symbols", "--wide", "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/" + executable]
            elif role.startswith("executable-symbols-"):
                label = role.removeprefix("executable-symbols-")
                executable = {"static-static": "static-static", "static-static-pie": "static-static-pie",
                              "dynamic-pie": "dynamic-pie", "dynamic-non-pie": "dynamic-non-pie"}[label]
                argv = ["nm", "-g", "--defined-only", "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/" + executable]
            elif role.startswith("sealed-link-"):
                linkage = role.removeprefix("sealed-link-")
                family = "static" if linkage.startswith("static") else "dynamic"
                executable = ("static-" + linkage if family == "static" else "dynamic-" + linkage)
                suffix = ".receipt.json" if family == "static" else ".crabc-link.json"
                argv = ["python3", "-B", "-", "/workspace", "/workspace/.work/utmpx-receipt/inputs/" + family,
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/workload.o",
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/" + executable,
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/" + executable + suffix, linkage]
            elif role.startswith("runtime-"):
                roots = {"runtime-oracle-ordinary": "oracle-root", "runtime-static-static-ordinary": "static-static-root",
                         "runtime-static-static-pie-ordinary": "static-static-pie-root", "runtime-dynamic-pie-kernel-ordinary": "dynamic-pie-root",
                         "runtime-dynamic-pie-direct-ordinary": "dynamic-pie-root", "runtime-dynamic-non-pie-kernel-ordinary": "dynamic-non-pie-root",
                         "runtime-dynamic-non-pie-direct-ordinary": "dynamic-non-pie-root"}
                direct = ["/lib/ld-crabc-x86_64.so.1"] if "-direct-" in role else []
                argv = ["timeout", "20", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "chroot",
                        "/workspace/.work/utmpx-receipt/owned-utmpx-receipt/" + roots[role], *direct, "/consumer", "ordinary"]
            self.write(self.commands / (role + ".json"), {
                "schema": receipt.COMMAND_SCHEMA, "role": role,
                "cwd": "/workspace/.work/utmpx-receipt/owned-utmpx-receipt" if role.startswith("static-link-") else "/workspace",
                "status": 0, "program": "/usr/bin/true", "argv": argv,
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
        for name in ("static-static-symbols.txt", "static-static-pie-symbols.txt", "dynamic-pie-symbols.txt", "dynamic-non-pie-symbols.txt"):
            self.write(raw / name, "".join(
                f"{addresses[symbol]} {'T' if symbol in receipt.STRONG else 'W'} {symbol}\n"
                for symbol in (*receipt.STRONG, *receipt.WEAK)
            ).encode())

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
        with self.assertRaisesRegex(receipt.ReceiptError, "oracle link command"):
            receipt.command_records(self.workspace)
        self.command_fixture()
        forged = self.commands / "runtime-dynamic-pie-direct-ordinary.json"
        record = json.loads(forged.read_text(encoding="utf-8"))
        record["argv"][6] = "/workspace/forged-chroot"
        self.write(forged, record)
        with self.assertRaisesRegex(receipt.ReceiptError, "runtime-dynamic-pie-direct-ordinary runtime command"):
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

    def test_validate_requires_a_report_file(self) -> None:
        with self.assertRaises(receipt.ReceiptError):
            receipt.validate_report(self.root / "missing-utmpx-receipt.json")


if __name__ == "__main__":
    unittest.main()
