#!/usr/bin/env python3
"""Regression contract for the retained installed-stdio component receipt."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import sys


ROOT = Path(__file__).resolve().parents[3]
READER_PATH = ROOT / "compat/x86_64/owned_stdio_component_receipt.py"
SPEC = importlib.util.spec_from_file_location("owned_stdio_component_receipt_test", READER_PATH)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)
sys.path.insert(0, str(READER_PATH.parent))
import owned_dynamic_qualification as qualification


def identity(root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def undefined_elf_object(*names: str) -> bytes:
    """Minimal physical ELF64 ET_REL bytes for the reader's direct parser."""

    strings = b"\0" + b"".join(name.encode("ascii") + b"\0" for name in names)
    string_offsets: dict[str, int] = {}
    position = 1
    for name in names:
        string_offsets[name] = position
        position += len(name) + 1
    symbols = b"\0" * 24 + b"".join(
        string_offsets[name].to_bytes(4, "little") + b"\x10\0\0\0" + b"\0" * 16
        for name in names
    )
    strings_at = 64
    symbols_at = strings_at + len(strings)
    sections_at = symbols_at + len(symbols)
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (1).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[40:48] = sections_at.to_bytes(8, "little")
    header[52:54] = (64).to_bytes(2, "little")
    header[58:60] = (64).to_bytes(2, "little")
    header[60:62] = (3).to_bytes(2, "little")
    string_section = bytearray(64)
    string_section[4:8] = (3).to_bytes(4, "little")
    string_section[24:32] = strings_at.to_bytes(8, "little")
    string_section[32:40] = len(strings).to_bytes(8, "little")
    symbol_section = bytearray(64)
    symbol_section[4:8] = (2).to_bytes(4, "little")
    symbol_section[24:32] = symbols_at.to_bytes(8, "little")
    symbol_section[32:40] = len(symbols).to_bytes(8, "little")
    symbol_section[40:44] = (1).to_bytes(4, "little")
    symbol_section[56:64] = (24).to_bytes(8, "little")
    return bytes(header) + strings + symbols + b"\0" * 64 + bytes(string_section) + bytes(symbol_section)


def gnu_archive(member: str, unindexed_member: str | None = None) -> bytes:
    names = member.encode("ascii") + b"/\n"
    if unindexed_member is not None:
        names += unindexed_member.encode("ascii") + b"/\n"

    def record(name: bytes, payload: bytes) -> bytes:
        header = (name.ljust(16, b" ") + b"0".ljust(12, b" ")
                  + b"0".ljust(6, b" ") + b"0".ljust(6, b" ")
                  + b"644".ljust(8, b" ") + str(len(payload)).encode().ljust(10, b" ") + b"`\n")
        return header + payload + (b"\n" if len(payload) & 1 else b"")

    index = b"\0\0\0\1" + b"\0" * 4 + b"symbol\0"
    member_offset = 8 + len(record(b"/", index)) + len(record(b"//", names))
    index = index[:4] + member_offset.to_bytes(4, "big") + index[8:]
    archive = b"!<arch>\n" + record(b"/", index) + record(b"//", names) + record(b"/0", b"member")
    if unindexed_member is not None:
        name_offset = len(member.encode("ascii")) + 2
        archive += record(b"/" + str(name_offset).encode(), b"unindexed")
    return archive


class ReceiptFixture:
    """Small physical receipt whose product/link boundaries are mocked alone.

    The reader itself still consumes physical argv, transcript, header, object,
    seal, tool and payload bytes.  The established product readers are patched
    only because a synthetic fixture cannot manufacture an owned ELF product.
    """

    def __init__(self, root: Path, *, static: bool = False) -> None:
        self.root = root
        self.checkout = root / "checkout"
        self.work = self.checkout / ".work" / "stdio"
        self.dynamic = root / "dynamic-product"
        self.static = root / "static-product"
        self.musl_include = root / "musl/include"
        self.checkout.mkdir(parents=True)
        self.work.mkdir(parents=True)
        self.dynamic.mkdir()
        (self.musl_include / "bits").mkdir(parents=True)
        if static:
            self.static.mkdir()
        (self.dynamic / "bin").mkdir()
        (self.dynamic / "share/crabc").mkdir(parents=True)
        (self.dynamic / "usr/include/bits").mkdir(parents=True)
        self.dynamic_driver = self.dynamic / "bin/crabc-cc-dynamic"
        self.dynamic_driver.write_bytes(b"dynamic driver\n")
        self.dynamic_driver.chmod(0o755)
        (self.dynamic / "share/crabc/manifest.json").write_bytes(b"dynamic manifest\n")
        self.dynamic_state = self.dynamic / "share/crabc/dynamic-product-state.json"
        self.dynamic_state.write_text(json.dumps({
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "status": "materialized-unqualified", "source_sha256": "a" * 64,
        }) + "\n")
        if static:
            (self.static / "bin").mkdir()
            (self.static / "share/crabc").mkdir(parents=True)
            (self.static / "usr/lib").mkdir(parents=True)
            (self.static / "usr/lib/libc.a").write_bytes(gnu_archive("c.synthetic_member.o", "c.unindexed_member.o"))
            (self.static / "usr/lib/libcrabc-builtins.a").write_bytes(gnu_archive("crabc-builtins.o"))
            self.static_driver = self.static / "bin/crabc-cc"
            self.static_driver.write_bytes(b"static driver\n")
            self.static_driver.chmod(0o755)
            (self.static / "share/crabc/manifest.json").write_bytes(b"static manifest\n")
        self.probe = self.checkout / "compat/x86_64/owned_stdio_probe.c"
        self.runner = self.checkout / "compat/x86_64/run_owned_stdio.sh"
        self.probe.parent.mkdir(parents=True)
        self.probe.write_bytes(b"int selected_stdio_probe;\n")
        self.runner.write_bytes(b"#!/bin/sh\n")
        self.runner.chmod(0o755)
        self.reader = self.checkout / "compat/x86_64/owned_stdio_component_receipt.py"
        self.reader.write_bytes(b"# retained stdio receipt reader\n")
        self.fopen64_c = self.checkout / "compat/x86_64/fopen64_header_abi_probe.c"
        self.fopen64_c.write_bytes(b"/* fopen64 C profile */\n")
        self.fopen64_cxx = self.checkout / "compat/x86_64/fopen64_header_abi_probe.cpp"
        self.fopen64_cxx.write_bytes(b"/* fopen64 C++ profile */\n")
        self.object = self.work / "workload.o"
        self.object.write_bytes(undefined_elf_object("fopen"))
        self.oracle = self.work / "oracle"
        self.oracle.write_bytes(b"oracle binary\n")
        self.tool = self.work / "tool"
        self.tool.write_bytes(b"tool\n")
        self.tool.chmod(0o755)
        helper = self.dynamic / "share/crabc/crabc_cc_static.py"
        helper.write_text(
            "HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\n"
            "def compiler():\n"
            f"    return {str(self.tool)!r}\n\n"
            "def linker(root):\n"
            f"    return {str(self.tool)!r}\n",
            encoding="utf-8",
        )
        self._write_raw(static)
        self._write_report(static)

    def write(self, name: str, body: bytes) -> Path:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def command(self, stem: str, argv: list[str], stdout: bytes = b"", stderr: bytes = b"", status: bytes = b"0\n") -> None:
        self.write(stem + ".argv.json", json.dumps(argv, separators=(",", ":")).encode() + b"\n")
        self.write(stem + ".stdout", stdout)
        self.write(stem + ".stderr", stderr)
        self.write(stem + ".status", status)

    def _write_fopen64_header_controls(self) -> None:
        for tree, compiler, include in (
            ("reference", str(self.tool), self.musl_include),
            ("installed", str(self.tool), self.dynamic / "usr/include"),
        ):
            trace = b"".join(
                f". {include / header}\n".encode()
                for header in ("stdio.h", "features.h", "bits/alltypes.h")
            )
            for profile, (relative_source, visibility, _) in receipt.FOPEN64_HEADER_PROFILES.items():
                source = self.fopen64_cxx if relative_source.endswith(".cpp") else self.fopen64_c
                object_path = self.work / f"fopen64-{tree}-{profile}.o"
                object_path.write_bytes(undefined_elf_object("fopen"))
                preprocessed = f'# 0 "{source}"\n'.encode()
                if visibility == "fopen":
                    preprocessed += b"fopen64_macro_reference = &fopen;\n"
                else:
                    preprocessed += b"fopen_reference = fopen;\n"
                self.command(
                    f"fopen64-{tree}-{profile}-preprocess",
                    receipt._fopen64_profile_argv(tree, profile, compiler, include, source, object_path, "preprocess"),
                    stdout=preprocessed, stderr=trace,
                )
                self.command(
                    f"fopen64-{tree}-{profile}-compile",
                    receipt._fopen64_profile_argv(tree, profile, compiler, include, source, object_path, "compile"),
                    stderr=trace,
                )

    def _write_raw(self, static: bool) -> None:
        source_seal = {
            "sources": {
                "probe": {"path": "compat/x86_64/owned_stdio_probe.c", "sha256": hashlib.sha256(self.probe.read_bytes()).hexdigest(), "mode": 0o644},
                "runner": {"path": "compat/x86_64/run_owned_stdio.sh", "sha256": hashlib.sha256(self.runner.read_bytes()).hexdigest(), "mode": 0o755},
                "reader": {"path": "compat/x86_64/owned_stdio_component_receipt.py", "sha256": hashlib.sha256(self.reader.read_bytes()).hexdigest(), "mode": 0o644},
                "fopen64_c": {"path": "compat/x86_64/fopen64_header_abi_probe.c", "sha256": hashlib.sha256(self.fopen64_c.read_bytes()).hexdigest(), "mode": 0o644},
                "fopen64_cxx": {"path": "compat/x86_64/fopen64_header_abi_probe.cpp", "sha256": hashlib.sha256(self.fopen64_cxx.read_bytes()).hexdigest(), "mode": 0o644},
            },
            "dynamic": {"path": str(self.dynamic), "manifest": {"path": str(self.dynamic / "share/crabc/manifest.json"), "sha256": hashlib.sha256((self.dynamic / "share/crabc/manifest.json").read_bytes()).hexdigest(), "size": (self.dynamic / "share/crabc/manifest.json").stat().st_size}, "tree": receipt.tree_identity(self.dynamic)},
        }
        if static:
            source_seal["static"] = {"path": str(self.static), "manifest": {"path": str(self.static / "share/crabc/manifest.json"), "sha256": hashlib.sha256((self.static / "share/crabc/manifest.json").read_bytes()).hexdigest(), "size": (self.static / "share/crabc/manifest.json").stat().st_size}, "tree": receipt.tree_identity(self.static)}
        encoded = json.dumps(source_seal, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.write("source-product-before.json", encoded)
        self.write("source-product-after.json", encoded)
        tool_record = lambda path: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size, "mode": stat.S_IMODE(path.stat().st_mode)}
        tools = {"oracle": tool_record(self.tool), "dynamic_driver": tool_record(self.dynamic_driver),
                 "compiler": tool_record(self.tool), "linker": tool_record(self.tool)}
        if static:
            tools["static_driver"] = tool_record(self.static_driver)
        encoded_tools = json.dumps(tools, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.write("tools-before.json", encoded_tools)
        self.write("tools-after.json", encoded_tools)
        header_prefix = str(self.dynamic / "usr/include")
        header_trace = b"".join((f". {header_prefix}/{name}\n".encode() for name in receipt.REQUIRED_HEADERS))
        header_source = (f'# 0 "{self.probe}"\nstatic void *fopen64_macro_entry = fopen;\nint main(int argc, char **argv) {{ return 0; }}\n').encode()
        self.command("header-trace", [str(self.tool), "-nostdinc", "-isystem", header_prefix, "-D_LARGEFILE64_SOURCE=1", "-fstack-protector-strong", "-std=c11", "-fPIE", "-E", "-H", str(self.probe)], stdout=header_source, stderr=header_trace)
        self.command("compile", [str(self.dynamic_driver), "--dynamic-pie", "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-D_LARGEFILE64_SOURCE=1", "-fno-builtin", "-fno-stack-protector", "-c", str(self.probe), "-o", str(self.object)])
        self._write_fopen64_header_controls()
        self.command("oracle-link", [str(self.tool), "-std=c11", "-static", "-fno-pie", "-no-pie", str(self.object), "-o", str(self.oracle)])
        runtime_argv = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(self.oracle), str(self.work / "oracle-first"), str(self.work / "oracle-second"), str(self.work / "oracle-wide")]
        self.command("oracle-run", runtime_argv, b"owned-stdio-products-ok\n")
        for linkage in ("pie", "non-pie"):
            executable = self.work / ("dynamic-" + linkage)
            executable.write_bytes((linkage + " executable\n").encode())
            self.write("dynamic-" + linkage + ".crabc-link.map", (
                "             VMA              LMA     Size Align Out     In      Symbol\n"
                "            1000             1000       10    16 .text\n"
                f"            1000             1000       10     1         {self.object}:(.text)\n"
                "            2000             2000        4     1 .rodata\n"
                f"            2000             2000        4     1         {self.object}:(.rodata)\n"
            ).encode())
            self.command("dynamic-" + linkage + "-link", [str(self.dynamic_driver), "--dynamic-" + linkage, "-std=c11", str(self.object), "-o", str(executable)])
            link = {"linkage": linkage, "product": str(self.dynamic), "product_format": "dynamic", "product_manifest_sha256": "d" * 64,
                    "workload_sha256": hashlib.sha256(self.object.read_bytes()).hexdigest(), "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "receipt_sha256": linkage[0] * 64}
            self.write("dynamic-" + linkage + ".product-link.json", json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            self.command("dynamic-" + linkage + "-validate", ["python3", "-B", "-", str(self.checkout), str(self.dynamic), str(self.object), str(executable), str(executable) + ".crabc-link.json", linkage], json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            payload = {"schema": "payload", "mode": linkage}
            record_path = self.write("dynamic-" + linkage + "-execution-payload.json", json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            root = self.work / ("dynamic-" + linkage + "-root")
            root.mkdir()
            (root / "consumer").write_bytes(executable.read_bytes())
            common = ["--product", str(self.dynamic), "--execution-root", str(root), "--source-consumer", str(executable),
                      "--execution-consumer", str(root / "consumer"), "--record", str(record_path)]
            self.command("dynamic-" + linkage + "-copy-before", ["python3", "-B", str(receipt.COPIES_PATH), "record", *common])
            for phase in ("before", "after"):
                self.command("dynamic-" + linkage + "-copy-audit-" + phase, ["python3", "-B", str(receipt.COPIES_PATH), "audit", *common], json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            for entry in ("kernel", "direct"):
                argv = (["chroot", str(root), "/consumer", "/scratch/first", "/scratch/second", "/scratch/wide"]
                        if entry == "kernel" else
                        ["chroot", str(root), "/lib/ld-crabc-x86_64.so.1", "/consumer", "/scratch/first", "/scratch/second", "/scratch/wide"])
                self.command("dynamic-" + linkage + "-" + entry, argv, b"owned-stdio-products-ok\n")
        if static:
            for linkage in ("static", "static-pie"):
                executable = self.work / linkage
                executable.write_bytes((linkage + " executable\n").encode())
                entry = "rcrt1.o" if linkage == "static-pie" else "crt1.o"
                self.write(linkage + ".crabc-link.map", (
                    "             VMA              LMA     Size Align Out     In      Symbol\n"
                    "            1000             1000       10    16 .text\n"
                    f"            1000             1000        0     1         {self.static / 'usr/lib' / entry}:(.text)\n"
                    f"            1000             1000        0     1         {self.static / 'usr/lib/libc.a'}(c.synthetic_member.o):(.text)\n"
                    f"            1000             1000        0     1         {self.static / 'usr/lib/libcrabc-builtins.a'}(crabc-builtins.o):(.text)\n"
                    f"            1000             1000       10     1         {self.object}:(.text)\n"
                    "            2000             2000        4     1 .rodata\n"
                    f"            2000             2000        4     1         {self.object}:(.rodata)\n"
                ).encode())
                self.command(linkage + "-link", [str(self.static_driver), "-" + linkage, "--link-receipt", linkage + ".crabc-link.json", str(self.object), "-o", str(executable)])
                link = {"linkage": linkage, "product": str(self.static), "product_format": "static", "product_manifest_sha256": "s" * 64,
                        "workload_sha256": hashlib.sha256(self.object.read_bytes()).hexdigest(), "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "receipt_sha256": linkage[0] * 64}
                self.write(linkage + ".product-link.json", json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.command(linkage + "-validate", ["python3", "-B", "-", str(self.checkout), str(self.static), str(self.object), str(executable), str(self.work / (linkage + ".crabc-link.json")), linkage], json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.command(linkage + "-run", ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(executable), str(self.work / (linkage + "-first")), str(self.work / (linkage + "-second")), str(self.work / (linkage + "-wide"))], b"owned-stdio-products-ok\n")

    def _write_report(self, static: bool) -> None:
        commands = {}
        for argv in sorted(self.work.glob("*.argv.json")):
            stem = argv.name.removesuffix(".argv.json")
            commands[stem] = {part: identity(self.work, self.work / (stem + "." + suffix))
                              for part, suffix in (("argv", "argv.json"), ("stdout", "stdout"), ("stderr", "stderr"), ("status", "status"))}
        links = {name: identity(self.work, self.work / (name + ".product-link.json"))
                 for name in ("dynamic-pie", "dynamic-non-pie", "static", "static-pie")
                 if (self.work / (name + ".product-link.json")).exists()}
        payloads = {name: {part: identity(self.work, self.work / ("dynamic-" + name + suffix))
                           for part, suffix in (("record", "-execution-payload.json"), ("before", "-copy-audit-before.stdout"), ("after", "-copy-audit-after.stdout"))}
                    for name in ("pie", "non-pie")}
        self.report = {
            "schema": receipt.SCHEMA,
            "scope": list(receipt.SCOPE),
            "rows": {"stdio.fopen64-alias": receipt.fopen64_row(static=static)},
            "source": identity(self.checkout, self.probe),
            "workload": identity(self.work, self.object),
            "products": {"dynamic": str(self.dynamic), **({"static": str(self.static)} if static else {})},
            "seals": {name: identity(self.work, self.work / (name + ".json"))
                      for name in ("source-product-before", "source-product-after", "tools-before", "tools-after")},
            "object_seals": {},
            "commands": commands,
            "links": links,
            "execution_payloads": payloads,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        self.path = self.work / "owned-stdio-products.json"
        self.refresh_object_seals()
        self.write_report()

    def write_report(self) -> None:
        self.path.write_text(json.dumps(self.report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def refresh_object_seals(self) -> None:
        before = self.work / "source-object-before.sha256"
        after = self.work / "source-object-after.txt"
        sealed = (self.probe, self.fopen64_c, self.fopen64_cxx, self.runner, self.object)
        before.write_bytes(b"".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n".encode() for path in sealed))
        after.write_bytes(b"".join(f"{path}: OK\n".encode() for path in sealed))
        self.report["object_seals"] = {"before": identity(self.work, before), "after": identity(self.work, after)}

    def refresh(self, *names: str) -> None:
        for name in names:
            if name == "commands":
                for argv in sorted(self.work.glob("*.argv.json")):
                    stem = argv.name.removesuffix(".argv.json")
                    self.report["commands"][stem] = {part: identity(self.work, self.work / (stem + "." + suffix))
                                                     for part, suffix in (("argv", "argv.json"), ("stdout", "stdout"), ("stderr", "stderr"), ("status", "status"))}
            elif name == "links":
                for stem in self.report["links"]:
                    self.report["links"][stem] = identity(self.work, self.work / (stem + ".product-link.json"))
            elif name == "payloads":
                for mode, values in self.report["execution_payloads"].items():
                    for part, suffix in (("record", "-execution-payload.json"), ("before", "-copy-audit-before.stdout"), ("after", "-copy-audit-after.stdout")):
                        values[part] = identity(self.work, self.work / ("dynamic-" + mode + suffix))
            elif name == "object_seals":
                self.refresh_object_seals()
            else:
                self.report["seals"][name] = identity(self.work, self.work / (name + ".json"))
        self.write_report()

    def refresh_dynamic_product_seals(self) -> None:
        for phase in ("before", "after"):
            path = self.work / ("source-product-" + phase + ".json")
            value = json.loads(path.read_text())
            value["dynamic"]["tree"] = receipt.tree_identity(self.dynamic)
            path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.refresh("source-product-before", "source-product-after")


class OwnedStdioComponentReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".work")
        self.root = Path(self.temporary.name)
        self.fixture = ReceiptFixture(self.root)
        self.patches = [
            mock.patch.object(receipt, "ORACLE_COMPILER", str(self.fixture.tool)),
            mock.patch.object(receipt, "MUSL_INCLUDE", self.fixture.musl_include),
            mock.patch.object(receipt.products, "_validate_dynamic_product", return_value=(self.fixture.dynamic / "manifest.json", {"bin/crabc-cc-dynamic": "d" * 64})),
            mock.patch.object(receipt.products, "_validate_static_product", return_value=(self.fixture.static / "manifest.json", {"bin/crabc-cc": "s" * 64})),
            mock.patch.object(receipt.products, "validate_link", side_effect=self._link),
            mock.patch.object(receipt.copies, "audit_execution_payload", side_effect=self._payload),
            mock.patch.object(qualification, "source_digest", return_value="a" * 64),
            mock.patch.object(qualification, "ROOT", self.fixture.checkout),
            mock.patch.object(receipt, "elf_section_layout", return_value={".text": (0x1000, 0x10), ".rodata": (0x2000, 0x4)}),
        ]
        for patch in self.patches:
            patch.start()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(lambda: [patch.stop() for patch in reversed(self.patches)])

    def _link(self, product: Path, workload: Path, executable: Path, _link_receipt: Path, linkage: str) -> dict[str, str]:
        stem = "dynamic-" + linkage if linkage in ("pie", "non-pie") else linkage
        return json.loads((self.fixture.work / (stem + ".product-link.json")).read_text())

    def _payload(self, _product: Path, _root: Path, _source: Path, _consumer: Path, record: Path) -> dict[str, object]:
        return json.loads(record.read_text())

    def validate(self, *, require_static: bool = False) -> dict[str, object]:
        return receipt.validate_report(self.fixture.path, self.fixture.checkout, require_static=require_static)

    def static_fixture(self) -> None:
        self.fixture = ReceiptFixture(self.root / "static", static=True)
        for index, (name, value) in enumerate((("ORACLE_COMPILER", str(self.fixture.tool)),
                                               ("MUSL_INCLUDE", self.fixture.musl_include))):
            self.patches[index].stop()
            self.patches[index] = mock.patch.object(receipt, name, value)
            self.patches[index].start()
        qualification.ROOT = self.fixture.checkout

    def test_dynamic_development_receipt_reconstructs_exactly_four_cells(self) -> None:
        report = self.validate()
        self.assertEqual(report["matrix"], "dynamic-development")
        with self.assertRaisesRegex(receipt.ReceiptError, "supplied-static"):
            self.validate(require_static=True)

    def test_rehashed_transplanted_dynamic_product_source_is_rejected(self) -> None:
        state = json.loads(self.fixture.dynamic_state.read_text())
        state["source_sha256"] = "b" * 64
        self.fixture.dynamic_state.write_text(json.dumps(state) + "\n")
        self.fixture.refresh_dynamic_product_seals()
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic product source differs"):
            self.validate()

    def test_checkout_must_be_the_reader_source_checkout(self) -> None:
        qualification.ROOT = self.fixture.root
        with self.assertRaisesRegex(receipt.ReceiptError, "reader source checkout"):
            self.validate()

    def test_fopen64_macro_consumer_row_is_reconstructed(self) -> None:
        row = {
            "feature": "_LARGEFILE64_SOURCE=1",
            "macro": "fopen64",
            "target": "fopen",
            "pointer_equality": True,
            "object_import": "fopen",
            "header_profiles": {
                "c11-base": "hidden",
                "c11-gnu": "hidden",
                "c11-file-offset-bits-64": "hidden",
                "c11-largefile-source": "hidden",
                "c11-largefile64": "fopen",
                "cxx17-base": "hidden",
                "cxx17-gnu": "hidden",
                "cxx17-file-offset-bits-64": "hidden",
                "cxx17-largefile-source": "hidden",
                "cxx17-largefile64": "fopen",
            },
            "runtime_cells": [
                "dynamic-pie-kernel", "dynamic-pie-direct",
                "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
            ],
        }
        report = self.validate()
        self.assertEqual(report["rows"]["stdio.fopen64-alias"], row)
        self.assertEqual(report["products"], self.fixture.report["products"])
        self.assertEqual(report["source"], self.fixture.report["source"])
        self.assertEqual(report["source_product_seal"], self.fixture.report["seals"]["source-product-before"])

    def test_supplied_static_receipt_reconstructs_exactly_six_cells(self) -> None:
        self.static_fixture()
        report = self.validate(require_static=True)
        self.assertEqual(report["matrix"], "supplied-static")

    def test_recomputed_hashes_cannot_substitute_compile_argv(self) -> None:
        path = self.fixture.work / "compile.argv.json"
        path.write_text(json.dumps(["wrong", "-c", str(self.fixture.probe), "-o", str(self.fixture.object)]) + "\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "compile argv"):
            self.validate()

    def test_recomputed_hashes_cannot_remove_fopen64_feature_exposure(self) -> None:
        for stem in ("header-trace", "compile"):
            path = self.fixture.work / (stem + ".argv.json")
            argv = json.loads(path.read_text())
            argv.remove("-D_LARGEFILE64_SOURCE=1")
            path.write_text(json.dumps(argv, separators=(",", ":")) + "\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "header trace argv"):
            self.validate()

    def test_recomputed_hashes_cannot_forge_fopen64_macro_expansion(self) -> None:
        path = self.fixture.work / "fopen64-installed-c11-largefile64-preprocess.stdout"
        path.write_bytes(path.read_bytes().replace(b"= &fopen;", b"= &forged;"))
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "macro expansion"):
            self.validate()

    def test_recomputed_hashes_cannot_import_distinct_fopen64_symbol(self) -> None:
        self.fixture.object.write_bytes(undefined_elf_object("fopen", "fopen64"))
        self.fixture.report["workload"] = identity(self.fixture.work, self.fixture.object)
        self.fixture.refresh_object_seals()
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "fopen64 macro consumer object import"):
            self.validate()

    def test_fopen64_macro_consumer_row_cannot_relabel_pointer_identity(self) -> None:
        self.fixture.report["rows"]["stdio.fopen64-alias"]["pointer_equality"] = False
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "macro-consumer row"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_runtime_output(self) -> None:
        path = self.fixture.work / "dynamic-pie-kernel.stdout"
        path.write_bytes(b"forged success\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic pie kernel stdout"):
            self.validate()

    def test_recomputed_hashes_cannot_omit_a_required_installed_header(self) -> None:
        path = self.fixture.work / "header-trace.stderr"
        path.write_bytes(b". forged/header.h\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "header trace"):
            self.validate()

    def test_recomputed_hashes_cannot_trace_an_ambient_header(self) -> None:
        path = self.fixture.work / "header-trace.stderr"
        path.write_bytes(path.read_bytes() + b". /usr/include/stdio.h\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "header trace escapes installed include tree"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_helper_selected_tools(self) -> None:
        replacement = self.fixture.work / "replacement-tool"
        replacement.write_bytes(b"replacement tool\n")
        replacement.chmod(0o755)
        replacement_record = {
            "path": str(replacement),
            "sha256": hashlib.sha256(replacement.read_bytes()).hexdigest(),
            "size": replacement.stat().st_size,
            "mode": stat.S_IMODE(replacement.stat().st_mode),
        }
        original_tools = {name: (self.fixture.work / name).read_bytes()
                          for name in ("tools-before.json", "tools-after.json")}
        header_argv = self.fixture.work / "header-trace.argv.json"
        original_header_argv = header_argv.read_bytes()
        for role in ("compiler", "linker"):
            for name, body in original_tools.items():
                (self.fixture.work / name).write_bytes(body)
            header_argv.write_bytes(original_header_argv)
            for name in ("tools-before.json", "tools-after.json"):
                path = self.fixture.work / name
                tools = json.loads(path.read_text())
                tools[role] = replacement_record
                path.write_text(json.dumps(tools, sort_keys=True, separators=(",", ":")) + "\n")
            if role == "compiler":
                argv = json.loads(header_argv.read_text())
                argv[0] = str(replacement)
                header_argv.write_text(json.dumps(argv, separators=(",", ":")) + "\n")
                self.fixture.refresh("commands")
            self.fixture.refresh("tools-before", "tools-after")
            with self.subTest(role=role):
                with self.assertRaisesRegex(receipt.ReceiptError, role + " tool path differs from sealed helper"):
                    self.validate()

    def test_recomputed_hashes_cannot_substitute_preprocessed_source(self) -> None:
        path = self.fixture.work / "header-trace.stdout"
        path.write_bytes(b'# 0 "forged.c"\nint main(void) { return 0; }\n')
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "preprocessed source"):
            self.validate()

    def test_recomputed_hashes_cannot_replace_the_shared_object(self) -> None:
        self.fixture.object.write_bytes(undefined_elf_object("fopen", "other"))
        self.fixture.report["workload"] = identity(self.fixture.work, self.fixture.object)
        self.fixture.refresh_object_seals()
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "link workload identity"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_a_link_identity(self) -> None:
        path = self.fixture.work / "dynamic-pie.product-link.json"
        value = json.loads(path.read_text())
        value["product"] = str(self.root / "wrong-product")
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        validate = self.fixture.work / "dynamic-pie-validate.stdout"
        validate.write_bytes(path.read_bytes())
        self.fixture.refresh("links", "commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic pie link identity"):
            self.validate()

    def test_rehashed_dynamic_link_map_cannot_add_a_foreign_record(self) -> None:
        path = self.fixture.work / "dynamic-pie.crabc-link.map"
        path.write_bytes(path.read_bytes() + b"forged-map-record\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic pie link map"):
            self.validate()

    def test_dynamic_link_map_cannot_claim_a_shared_library_output_section(self) -> None:
        path = self.fixture.work / "dynamic-pie.crabc-link.map"
        library = self.fixture.dynamic / "usr/lib/libc.so"
        path.write_text(path.read_text() +
                        f"            1000             1000        1     1         {library}:(.text)\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "shared library output section"):
            self.validate()

    def test_rehashed_dynamic_link_map_cannot_change_output_placement(self) -> None:
        path = self.fixture.work / "dynamic-pie.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(
            b"1000             1000       10    16 .text",
            b"3000             3000       10    16 .text"))
        with self.assertRaisesRegex(receipt.ReceiptError, "link map output sections"):
            self.validate()

    def test_rehashed_static_link_map_cannot_change_output_placement(self) -> None:
        self.static_fixture()
        path = self.fixture.work / "static.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(
            b"1000             1000       10    16 .text",
            b"3000             3000       10    16 .text"))
        with self.assertRaisesRegex(receipt.ReceiptError, "static link map output sections"):
            self.validate(require_static=True)

    def test_rehashed_static_pie_link_map_cannot_name_a_foreign_input(self) -> None:
        self.static_fixture()
        path = self.fixture.work / "static-pie.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(
            (str(self.fixture.object) + ":(.text)").encode(),
            (str(self.fixture.work / "foreign.o") + ":(.text)").encode()))
        with self.assertRaisesRegex(receipt.ReceiptError, "static pie link map contains a foreign input"):
            self.validate(require_static=True)

    def test_rehashed_static_pie_link_map_cannot_name_the_static_crt(self) -> None:
        self.static_fixture()
        path = self.fixture.work / "static-pie.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(b"rcrt1.o:(.text)", b"crt1.o:(.text)"))
        with self.assertRaisesRegex(receipt.ReceiptError, "static pie link map contains a foreign input"):
            self.validate(require_static=True)

    def test_rehashed_static_map_cannot_name_an_absent_libc_member(self) -> None:
        self.static_fixture()
        path = self.fixture.work / "static.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(b"libc.a(c.synthetic_member.o)",
                                                  b"libc.a(nonexistent-member.o)"))
        with self.assertRaisesRegex(receipt.ReceiptError, "static link map archive member is absent"):
            self.validate(require_static=True)

    def test_rehashed_static_pie_map_cannot_name_an_absent_builtins_member(self) -> None:
        self.static_fixture()
        path = self.fixture.work / "static-pie.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(b"libcrabc-builtins.a(crabc-builtins.o)",
                                                  b"libcrabc-builtins.a(nonexistent-member.o)"))
        with self.assertRaisesRegex(receipt.ReceiptError, "static pie link map archive member is absent"):
            self.validate(require_static=True)

    def test_rehashed_static_map_cannot_name_an_unindexed_libc_member(self) -> None:
        self.static_fixture()
        path = self.fixture.work / "static.crabc-link.map"
        path.write_bytes(path.read_bytes().replace(b"libc.a(c.synthetic_member.o)",
                                                  b"libc.a(c.unindexed_member.o)"))
        with self.assertRaisesRegex(receipt.ReceiptError, "static link map archive member is absent"):
            self.validate(require_static=True)

    def test_recomputed_hashes_cannot_replace_payload_audit(self) -> None:
        path = self.fixture.work / "dynamic-non-pie-copy-audit-after.stdout"
        path.write_bytes(b'{"mode":"forged","schema":"payload"}\n')
        self.fixture.refresh("payloads", "commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "payload audit"):
            self.validate()

    def test_reader_rejects_a_symlink_hop_before_opening_the_report(self) -> None:
        alias = self.root / "receipt-link"
        alias.symlink_to(self.fixture.path)
        with self.assertRaisesRegex(receipt.ReceiptError, "symlink"):
            receipt.validate_report(alias, self.fixture.checkout)


if __name__ == "__main__":
    unittest.main()
