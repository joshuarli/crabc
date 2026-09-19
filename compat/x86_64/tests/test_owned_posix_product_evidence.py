#!/usr/bin/env python3
"""Tamper tests for one owned POSIX product link-evidence boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "compat" / "x86_64") not in sys.path:
    sys.path.insert(0, str(ROOT / "compat" / "x86_64"))
MODULE_PATH = ROOT / "compat" / "x86_64" / "owned_posix_product_evidence.py"
SPEC = importlib.util.spec_from_file_location("owned_posix_product_evidence_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)

OS_TEST_MODULE_PATH = ROOT / "compat" / "x86_64" / "owned_os_test.py"
OS_TEST_SPEC = importlib.util.spec_from_file_location("owned_os_test_product_mode_test", OS_TEST_MODULE_PATH)
assert OS_TEST_SPEC is not None and OS_TEST_SPEC.loader is not None
os_test = importlib.util.module_from_spec(OS_TEST_SPEC)
sys.modules[OS_TEST_SPEC.name] = os_test
OS_TEST_SPEC.loader.exec_module(os_test)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sealed_elf(linkage: str) -> bytes:
    """Minimal ELF64 byte fixture for the replay reader, never executable."""
    dynamic = linkage in {"pie", "non-pie"}
    elf_type = 3 if linkage in {"static-pie", "pie"} else 2
    interpreter = b"/lib/ld-crabc-x86_64.so.1\0" if dynamic else b""
    strings = b"\0libc.so\0/usr/lib\0" if dynamic else b""
    dynamic_entries = (
        struct.pack("<qQ", 5, 0x400040)
        + struct.pack("<qQ", 10, len(strings))
        + struct.pack("<qQ", 1, 1)
        + struct.pack("<qQ", 29, len(b"\0libc.so\0"))
        + struct.pack("<qQ", 0, 0)
        if dynamic else b""
    )
    data = bytearray(768)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    data[16:64] = struct.pack(
        "<HHIQQQIHHHHHH", elf_type, 62, 1, 0, 64 if dynamic else 0,
        0, 0, 64, 56, 3 if dynamic else 0, 0, 0, 0,
    )
    if dynamic:
        data[64:120] = struct.pack("<IIQQQQQQ", 3, 4, 256, 0, 0, len(interpreter), len(interpreter), 1)
        data[120:176] = struct.pack("<IIQQQQQQ", 1, 4, 256, 0x400000, 0, 256, 256, 0x1000)
        data[176:232] = struct.pack("<IIQQQQQQ", 2, 4, 384, 0x400080, 0, len(dynamic_entries), len(dynamic_entries), 8)
        data[256:256 + len(interpreter)] = interpreter
        data[320:320 + len(strings)] = strings
        data[384:384 + len(dynamic_entries)] = dynamic_entries
    return bytes(data)


def sealed_shared_elf(soname: str) -> bytes:
    """Add a real DT_SONAME to the bounded dynamic ELF byte fixture."""
    data = bytearray(sealed_elf("pie"))
    strings = b"\0libc.so\0/usr/lib\0" + soname.encode("ascii") + b"\0"
    data[320:320 + len(strings)] = strings
    struct.pack_into("<Q", data, 408, len(strings))
    struct.pack_into("<qQ", data, 448, 14, len(b"\0libc.so\0/usr/lib\0"))
    struct.pack_into("<qQ", data, 464, 0, 0)
    struct.pack_into("<QQ", data, 208, 96, 96)
    return bytes(data)


def loader_dynamic_elf(*, section_headers: bool = True, post_null: bool = False,
                       flags: int = 0, dynamic_segments: int = 1,
                       string_table_address: int | None = None,
                       ambiguous_string_mapping: bool = False,
                       textrel_tag: bool = False, interpreter: bool = False,
                       self_relocation_only: bool = False,
                       elf_type: int = 3) -> bytes:
    """Build a byte-only ELF whose loader and section metadata may disagree.

    The retained reader must follow the loader-visible ``PT_DYNAMIC`` table.
    When present, the section table deliberately advertises benign facts after
    ``DT_NULL`` so it cannot be used as an alternate authority.
    """
    load_offset, strings_offset, dynamic_offset = 256, 320, 448
    load_address = 0x400000
    strings = b"\0" if self_relocation_only else b"\0libforeign.so\0/bad\0"
    owned_interpreter = b"/lib/ld-crabc-x86_64.so.1\0"
    string_address = load_address + strings_offset - load_offset
    if string_table_address is not None:
        string_address = string_table_address
    entries = [
        (5, string_address),  # DT_STRTAB
        (10, len(strings)),   # DT_STRSZ
    ]
    if self_relocation_only:
        entries.extend(((7, load_address + dynamic_offset - load_offset), (8, 24)))  # DT_RELA, DT_RELASZ
    else:
        rpath_offset = len(b"\0libforeign.so\0")
        entries.extend(((1, 1), (15, rpath_offset)))  # DT_NEEDED, DT_RPATH
    entries.extend(((30, flags), (0, 0)))  # DT_FLAGS, DT_NULL
    if textrel_tag:
        entries.insert(-1, (22, 0))  # DT_TEXTREL
    if post_null:
        rpath_offset = len(b"\0libforeign.so\0")
        entries.extend(((1, 1), (29, rpath_offset), (0, 0)))
    load_size = max(320, dynamic_offset + len(entries) * 16 - load_offset)
    programs = [(1, 4, load_offset, load_address, load_size, load_size, 0x1000)]
    programs.extend((2, 4, dynamic_offset, load_address + dynamic_offset - load_offset,
                     len(entries) * 16, len(entries) * 16, 8) for _ in range(dynamic_segments))
    if ambiguous_string_mapping:
        programs.append((1, 4, load_offset + 1, load_address, 100, 100, 0x1000))
    if interpreter:
        programs.append((3, 4, 1120, 0, len(owned_interpreter), len(owned_interpreter), 1))

    data = bytearray(1200)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    section_offset = 928 if section_headers else 0
    data[16:64] = struct.pack(
        "<HHIQQQIHHHHHH", elf_type, 62, 1, 0, 64, section_offset, 0,
        64, 56, len(programs), 64 if section_headers else 0, 2 if section_headers else 0, 0,
    )
    for index, (kind, flags_value, offset, address, size, memory_size, alignment) in enumerate(programs):
        data[64 + index * 56:120 + index * 56] = struct.pack(
            "<IIQQQQQQ", kind, flags_value, offset, address, 0, size, memory_size, alignment
        )
    data[strings_offset:strings_offset + len(strings)] = strings
    for index, entry in enumerate(entries):
        struct.pack_into("<qQ", data, dynamic_offset + index * 16, *entry)
    if interpreter:
        data[1120:1120 + len(owned_interpreter)] = owned_interpreter
    if section_headers:
        fake_strings_offset, fake_dynamic_offset = 672, 736
        fake_strings = b"\0libc.so\0/usr/lib\0"
        data[fake_strings_offset:fake_strings_offset + len(fake_strings)] = fake_strings
        for index, entry in enumerate(((0, 0), (1, 1), (29, len(b"\0libc.so\0")), (0, 0))):
            struct.pack_into("<qQ", data, fake_dynamic_offset + index * 16, *entry)
        data[928:992] = struct.pack(
            "<IIQQQQIIQQ", 0, 3, 0, 0, fake_strings_offset, len(fake_strings), 0, 0, 1, 0
        )
        data[992:1056] = struct.pack(
            "<IIQQQQIIQQ", 0, 6, 0, 0, fake_dynamic_offset, 64, 0, 0, 8, 16
        )
    return bytes(data)


def incongruent_dynamic_elf() -> bytes:
    """Put benign entries at ``p_offset`` and foreign entries at ``p_vaddr``.

    The loader follows the dynamic segment's virtual address through the first
    load segment.  A reader that opens only ``p_offset`` would instead see the
    second, benign table and accept this sectionless artifact.
    """
    data = bytearray(1200)
    load_offset, load_address = 256, 0x400000
    actual_strings = b"\0libforeign.so\0/bad\0"
    benign_offset, benign_address = 640, 0x500000
    benign_strings = b"\0libc.so\0/usr/lib\0"
    actual_dynamic_offset, recorded_dynamic_offset = 448, 736
    dynamic_size = 80
    interpreter = b"/lib/ld-crabc-x86_64.so.1\0"
    programs = (
        (1, 4, load_offset, load_address, 320, 320, 0x1000),
        (1, 4, benign_offset, benign_address, 128, 128, 0x1000),
        (2, 4, recorded_dynamic_offset, load_address + actual_dynamic_offset - load_offset,
         dynamic_size, dynamic_size, 8),
        (3, 4, 1120, 0, len(interpreter), len(interpreter), 1),
    )
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    data[16:64] = struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, len(programs), 0, 0, 0
    )
    for index, program in enumerate(programs):
        kind, flags, offset, address, size, memory_size, alignment = program
        data[64 + index * 56:120 + index * 56] = struct.pack(
            "<IIQQQQQQ", kind, flags, offset, address, 0, size, memory_size, alignment
        )
    data[320:320 + len(actual_strings)] = actual_strings
    data[672:672 + len(benign_strings)] = benign_strings
    actual_entries = (
        (5, load_address + 320 - load_offset), (10, len(actual_strings)),
        (1, 1), (15, len(b"\0libforeign.so\0")), (0, 0),
    )
    benign_entries = (
        (5, benign_address + 672 - benign_offset), (10, len(benign_strings)),
        (1, 1), (29, len(b"\0libc.so\0")), (0, 0),
    )
    for index, entry in enumerate(actual_entries):
        struct.pack_into("<qQ", data, actual_dynamic_offset + index * 16, *entry)
    for index, entry in enumerate(benign_entries):
        struct.pack_into("<qQ", data, recorded_dynamic_offset + index * 16, *entry)
    data[1120:1120 + len(interpreter)] = interpreter
    return bytes(data)


class OwnedPosixProductEvidenceTests(unittest.TestCase):
    """Use files with injected ELF inspections; this is not a native build test."""

    def setUp(self) -> None:
        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="owned-posix-product-evidence.", dir=temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workload = self.put("workload.o", b"one owned workload object\n")
        self.executable = self.put("consumer", sealed_elf("pie"))
        self.linker = self.put("tools/ld.lld", b"sealed linker bytes\n")
        os.chmod(self.linker, 0o755)
        self.static = self.install_static()
        self.dynamic = self.install_dynamic()

    def test_retained_elf_reader_parses_rehashed_dynamic_metadata_without_a_host_tool(self) -> None:
        path = self.put("shared", sealed_shared_elf("libfixture.so"))
        with mock.patch.object(evidence.subprocess, "run", side_effect=AssertionError("host ELF tool ran")):
            facts = evidence.retained_elf_facts(path)
        self.assertEqual(
            facts,
            {"type": 3, "machine": 62, "interpreters": ["/lib/ld-crabc-x86_64.so.1"],
             "dynamic": True, "needed": ["libc.so"], "runpaths": ["/usr/lib"], "rpaths": [],
             "sonames": ["libfixture.so"], "textrel": False},
        )

    def test_retained_elf_reader_uses_pt_dynamic_over_a_forged_dynamic_section(self) -> None:
        path = self.put("forged-section", loader_dynamic_elf(flags=4))
        facts = evidence.retained_elf_facts(path)
        self.assertEqual(facts["needed"], ["libforeign.so"])
        self.assertEqual(facts["rpaths"], ["/bad"])
        self.assertEqual(facts["runpaths"], [])
        self.assertTrue(facts["dynamic"])
        self.assertTrue(facts["textrel"])
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "DT_TEXTREL"):
            evidence._audit_retained_elf(path, "pie")

    def test_retained_elf_reader_uses_pt_dynamic_without_section_headers(self) -> None:
        path = self.put("sectionless", loader_dynamic_elf(section_headers=False, interpreter=True))
        facts = evidence.retained_elf_facts(path)
        self.assertEqual(facts["needed"], ["libforeign.so"])
        self.assertEqual(facts["rpaths"], ["/bad"])
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "foreign DT_NEEDED"):
            evidence._audit_retained_elf(path, "pie")

    def test_retained_elf_reader_detects_dt_textrel_and_dt_flags_textrel(self) -> None:
        for name, payload in (
            ("tag", loader_dynamic_elf(textrel_tag=True)),
            ("flags", loader_dynamic_elf(flags=4)),
        ):
            with self.subTest(name=name):
                self.assertTrue(evidence.retained_elf_facts(self.put(name, payload))["textrel"])

    def test_retained_elf_reader_rejects_nonzero_dynamic_entries_after_dt_null(self) -> None:
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "terminator"):
            evidence.retained_elf_facts(self.put("post-null", loader_dynamic_elf(post_null=True)))

    def test_retained_elf_reader_rejects_missing_or_duplicate_pt_dynamic(self) -> None:
        for name, count in (("missing", 0), ("duplicate", 2)):
            with self.subTest(name=name):
                path = self.put(name, loader_dynamic_elf(dynamic_segments=count))
                if count == 0:
                    with self.assertRaisesRegex(evidence.ProductEvidenceError, "PT_DYNAMIC segment"):
                        evidence._audit_retained_elf(path, "pie")
                else:
                    with self.assertRaisesRegex(evidence.ProductEvidenceError, "PT_DYNAMIC"):
                        evidence.retained_elf_facts(path)

    def test_retained_elf_reader_rejects_dynamic_string_tables_without_one_load_mapping(self) -> None:
        cases = {
            "unmappable": loader_dynamic_elf(string_table_address=0xDEADBEEF),
            "ambiguous": loader_dynamic_elf(ambiguous_string_mapping=True),
        }
        for name, payload in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(evidence.ProductEvidenceError, "string table"):
                evidence.retained_elf_facts(self.put(name, payload))

    def test_retained_elf_reader_rejects_pt_dynamic_offset_not_mapped_from_its_virtual_address(self) -> None:
        path = self.put("incongruent-dynamic", incongruent_dynamic_elf())
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "PT_DYNAMIC.*mapping"):
            evidence.retained_elf_facts(path)

    def test_retained_static_pie_allows_self_relocation_dynamic_metadata(self) -> None:
        path = self.put("static-pie-self-relocation", loader_dynamic_elf(self_relocation_only=True))
        self.assertEqual(
            evidence.retained_elf_facts(path),
            {"type": 3, "machine": 62, "interpreters": [], "dynamic": True,
             "needed": [], "runpaths": [], "rpaths": [], "sonames": [], "textrel": False},
        )
        evidence._audit_retained_elf(path, "static-pie")

    def put(self, relative: str, payload: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def payload_manifest(self, product: Path) -> dict[str, str]:
        return {
            path.relative_to(product).as_posix(): digest(path)
            for path in sorted(product.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def install_static(self) -> Path:
        product = self.root / "static-product"
        for relative in (
            "bin/crabc-cc",
            "usr/include/fixture.h",
            "usr/lib/crt1.o",
            "usr/lib/Scrt1.o",
            "usr/lib/rcrt1.o",
            "usr/lib/crti.o",
            "usr/lib/crtn.o",
            "usr/lib/libc.a",
            "usr/lib/libcrabc-builtins.a",
        ):
            self.put(str(product.relative_to(self.root) / relative), relative.encode())
        os.chmod(product / "bin/crabc-cc", 0o755)
        manifest = {
            "schema": 1,
            "format": "crabc-x86-64-owned-static-sysroot-v1",
            "target": "x86_64-unknown-linux-musl",
            "installed": {
                "headers": "usr/include",
                "crt_objects": [
                    "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/rcrt1.o",
                    "usr/lib/crti.o", "usr/lib/crtn.o",
                ],
                "static_libc": "usr/lib/libc.a",
                "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
                "sealed_static_driver": "bin/crabc-cc",
                "files": self.payload_manifest(product),
            },
            "sealed_static_driver": {
                "format": "crabc-x86-64-sealed-static-driver-v1",
                "path": "bin/crabc-cc",
                "status": "planned-owned-static-product-seed-not-family-completion-not-public-support",
                "modes": [
                    {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"},
                    {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"},
                ],
            },
        }
        self.write_json(product / "share/crabc/manifest.json", manifest)
        return product

    def install_dynamic(self) -> Path:
        product = self.root / "dynamic-product"
        for relative in (
            "bin/crabc-cc-dynamic",
            "share/crabc/crabc_cc_static.py",
            "share/crabc/owned_dynamic_receipt.py",
            "share/crabc/dynamic-product-state.json",
            "usr/include/fixture.h",
            "lib/ld-crabc-x86_64.so.1",
            "usr/lib/crt1.o",
            "usr/lib/Scrt1.o",
            "usr/lib/crti.o",
            "usr/lib/crtn.o",
            "usr/lib/crabc-dynamic-attach.o",
            "usr/lib/libc.so",
            "usr/lib/libcrabc-builtins.a",
        ):
            self.put(str(product.relative_to(self.root) / relative), relative.encode())
        os.chmod(product / "bin/crabc-cc-dynamic", 0o755)
        os.chmod(product / "lib/ld-crabc-x86_64.so.1", 0o755)
        os.chmod(product / "usr/lib/libc.so", 0o755)
        alias = product / "lib/ld-musl-x86_64.so.1"
        alias.symlink_to("ld-crabc-x86_64.so.1")
        manifest = {
            "schema": 1,
            "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "target": "x86_64-unknown-linux-musl",
            "files": self.payload_manifest(product),
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        self.write_json(product / "share/crabc/manifest.json", manifest)
        return product

    def refresh_dynamic_manifest(self) -> None:
        manifest_path = self.dynamic / "share/crabc/manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"] = {
            relative: value
            for relative, value in self.payload_manifest(self.dynamic).items()
            if relative != "share/crabc/manifest.json"
        }
        self.write_json(manifest_path, manifest)

    def static_receipt(self, linkage: str = "static") -> Path:
        self.executable.write_bytes(sealed_elf(linkage))
        mode = {
            "static": ("static-et-exec", "ET_EXEC", "crt1.o"),
            "static-pie": ("static-pie", "ET_DYN", "rcrt1.o"),
        }[linkage]
        receipt = self.root / f"{linkage}.receipt.json"
        map_path = receipt.with_suffix(".map")
        trace_path = receipt.with_suffix(".trace")
        map_path.write_bytes(b"owned link map\n")
        runtime = self.static / "usr/lib"
        trace_path.write_text(
            "\n".join(
                (
                    str(runtime / mode[2]),
                    str(runtime / "crti.o"),
                    str(self.workload),
                    str(runtime / "libc.a") + "(selected.o)",
                    str(runtime / "libcrabc-builtins.a") + "(builtins.o)",
                    str(runtime / "crtn.o"),
                )
            ) + "\n",
            encoding="utf-8",
        )
        records = [
            ("crt-entry", runtime / mode[2]),
            ("crt-prologue", runtime / "crti.o"),
            ("libc", runtime / "libc.a"),
            ("builtins", runtime / "libcrabc-builtins.a"),
            ("crt-epilogue", runtime / "crtn.o"),
            ("application", self.workload),
        ]
        self.write_json(receipt, {
            "schema": 1,
            "format": "crabc-x86-64-sealed-static-driver-v1",
            "target": "x86_64-unknown-linux-musl",
            "mode": {"id": mode[0], "elf_type": mode[1], "crt_object": mode[2], "interpreter": "absent"},
            "resolved_linker": {"path": str(self.linker), "sha256": digest(self.linker)},
            "owned_link_contract": self.static_plan(mode[2], linkage == "static-pie"),
            "input_receipts": [
                {"role": role, "path": path.relative_to(self.static).as_posix() if role != "application" else str(path), "sha256": digest(path)}
                for role, path in records
            ],
            "output": {"path": str(self.executable), "sha256": digest(self.executable)},
            "map": {"path": str(map_path), "sha256": digest(map_path)},
            "trace": {"path": str(trace_path), "sha256": digest(trace_path)},
        })
        return receipt

    def static_plan(self, crt: str, pie: bool) -> list[str]:
        library = self.static / "usr/lib"
        return [
            "ld.lld", "-static", *( ["-pie"] if pie else []), "--no-dynamic-linker",
            "--no-undefined", "--gc-sections", "-z", "relro", "-z", "now", "-e", "_start",
            str(library / crt), str(library / "crti.o"), "<application-objects>",
            str(library / "libc.a"), str(library / "libcrabc-builtins.a"),
            str(library / "crtn.o"), "-o", "<output>",
        ]

    def dynamic_receipt(self, linkage: str = "pie", *, export_dynamic: bool = False) -> Path:
        self.executable.write_bytes(sealed_elf(linkage))
        mode, entry = {"pie": ("pie", "Scrt1.o"), "non-pie": ("exec", "crt1.o")}[linkage]
        receipt = self.root / f"{linkage}.crabc-link.json"
        runtime = self.dynamic / "usr/lib"
        direct = [
            runtime / "crti.o", runtime / "libc.so", runtime / "crtn.o",
            runtime / entry, runtime / "crabc-dynamic-attach.o",
        ]
        inputs = [*direct, self.workload, runtime / "libcrabc-builtins.a"]
        link = [
            str(self.linker), *( ["-pie"] if linkage == "pie" else []), "--hash-style=sysv",
            "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
            "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
            *(["--export-dynamic"] if export_dynamic else []),
            "--dynamic-linker", "/lib/ld-crabc-x86_64.so.1", str(runtime / entry),
            str(runtime / "crabc-dynamic-attach.o"), str(runtime / "crti.o"), str(self.workload),
            str(runtime / "libc.so"), str(runtime / "libcrabc-builtins.a"), str(runtime / "crtn.o"),
            "-o", str(self.executable),
        ]
        manifest = self.dynamic / "share/crabc/manifest.json"
        self.write_json(receipt, {
            "schema": 1,
            "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "mode": mode,
            "binding": "now",
            "runtime_imports": [],
            "application_runpath": "/usr/lib",
            "output_path": str(self.executable),
            "output_sha256": digest(self.executable),
            "manifest_sha256": digest(manifest),
            "application_dsos": {},
            "owned_runtime_inputs": sorted(path.relative_to(self.dynamic).as_posix() for path in [*direct, runtime / "libcrabc-builtins.a"]),
            "input_receipts": [{"path": str(path), "sha256": digest(path)} for path in inputs],
            "resolved_linker": {"path": str(self.linker), "sha256": digest(self.linker)},
            "link_command": link,
            "link_trace": [str(path) for path in [runtime / entry, runtime / "crabc-dynamic-attach.o", runtime / "crti.o", self.workload, runtime / "libc.so", runtime / "crtn.o"]],
            "campaign_complete": False,
        })
        return receipt

    @staticmethod
    def readelf(linkage: str) -> dict[str, str]:
        dynamic = linkage in {"pie", "non-pie"}
        return {
            "header": "  Machine:                           Advanced Micro Devices X86-64\n"
                      + ("  Type:                              DYN (Position-Independent Executable file)\n" if linkage in {"static-pie", "pie"} else "  Type:                              EXEC (Executable file)\n"),
            "program": ("  INTERP         0x000000 0x0000000000000000\n"
                        "      [Requesting program interpreter: /lib/ld-crabc-x86_64.so.1]\n") if dynamic else "",
            "dynamic": " 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n 0x000000000000001d (RUNPATH)            Library runpath: [/usr/lib]\n" if dynamic else "",
        }

    def validate(self, linkage: str, receipt: Path | None = None) -> dict[str, str]:
        product = self.static if linkage in {"static", "static-pie"} else self.dynamic
        if receipt is None:
            receipt = self.static_receipt(linkage) if linkage in {"static", "static-pie"} else self.dynamic_receipt(linkage)
        with mock.patch.object(evidence, "_readelf", return_value=self.readelf(linkage)):
            return evidence.validate_link(product, self.workload, self.executable, receipt, linkage)

    def retained_receipt(self, linkage: str, *, export_dynamic: bool = False) -> tuple[Path, dict[str, str]]:
        """Rewrite a native `/workspace` receipt without materializing its linker."""

        receipt = (self.static_receipt(linkage) if linkage in {"static", "static-pie"}
                   else self.dynamic_receipt(linkage, export_dynamic=export_dynamic))
        record = json.loads(receipt.read_text(encoding="utf-8"))
        host = str(self.root)

        def mounted(value: object) -> object:
            if isinstance(value, str):
                return "/workspace" + value[len(host):] if value.startswith(host + "/") else value
            if isinstance(value, list):
                return [mounted(item) for item in value]
            if isinstance(value, dict):
                return {key: mounted(item) for key, item in value.items()}
            return value

        record = mounted(record)
        assert isinstance(record, dict)
        tools = {"path": "/opt/native-tools/ld.lld", "sha256": digest(self.linker)}
        record["resolved_linker"] = dict(tools)
        if "link_command" in record:
            record["link_command"][0] = tools["path"]
        trace = receipt.with_suffix(".trace")
        if trace.exists():
            trace.write_text(trace.read_text(encoding="utf-8").replace(host + "/", "/workspace/"), encoding="utf-8")
            record["trace"]["sha256"] = digest(trace)
        self.write_json(receipt, record)
        return receipt, tools

    def test_retained_reader_reconstructs_source_mounted_receipt_without_native_linker(self) -> None:
        for linkage in ("static", "static-pie", "pie", "non-pie"):
            with self.subTest(linkage=linkage):
                receipt, linker = self.retained_receipt(linkage)
                product = self.static if linkage in {"static", "static-pie"} else self.dynamic
                with mock.patch.object(
                    evidence.subprocess, "run", side_effect=AssertionError("host replay executed a tool")
                ):
                    identity = evidence.validate_retained_link(
                        self.root, "/workspace", product, self.workload, self.executable,
                        receipt, linkage, linker,
                    )
                self.assertEqual(identity["linkage"], linkage)

    def test_retained_reader_rejects_changed_source_mount_or_linker(self) -> None:
        receipt, linker = self.retained_receipt("pie")
        with mock.patch.object(evidence, "_readelf", return_value=self.readelf("pie")):
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "source mount"):
                evidence.validate_retained_link(
                    self.root, "/not-workspace", self.dynamic, self.workload, self.executable,
                    receipt, "pie", linker,
                )
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "resolved linker"):
                evidence.validate_retained_link(
                    self.root, "/workspace", self.dynamic, self.workload, self.executable,
                    receipt, "pie", {"path": "/opt/native-tools/other-ld.lld", "sha256": linker["sha256"]},
                )

    def test_export_dynamic_requires_the_explicit_dynamic_link_contract(self) -> None:
        receipt = self.dynamic_receipt(export_dynamic=True)
        with mock.patch.object(evidence, "_readelf", return_value=self.readelf("pie")):
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "link command"):
                evidence.validate_link(self.dynamic, self.workload, self.executable, receipt, "pie")
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "export-dynamic"):
                evidence.validate_link(
                    self.dynamic, self.workload, self.executable, receipt, "pie", export_dynamic=1
                )
            identity = evidence.validate_link(
                self.dynamic, self.workload, self.executable, receipt, "pie", export_dynamic=True
            )
        self.assertEqual(identity["linkage"], "pie")

        retained, linker = self.retained_receipt("pie", export_dynamic=True)
        with mock.patch.object(evidence, "_readelf", return_value=self.readelf("pie")):
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "link command"):
                evidence.validate_retained_link(
                    self.root, "/workspace", self.dynamic, self.workload, self.executable,
                    retained, "pie", linker,
                )
            identity = evidence.validate_retained_link(
                self.root, "/workspace", self.dynamic, self.workload, self.executable,
                retained, "pie", linker, export_dynamic=True,
            )
        self.assertEqual(identity["linkage"], "pie")

    def test_accepts_each_sealed_linkage_and_returns_bound_identity(self) -> None:
        for linkage in ("static", "static-pie", "pie", "non-pie"):
            with self.subTest(linkage=linkage):
                identity = self.validate(linkage)
                self.assertEqual(identity["linkage"], linkage)
                self.assertEqual(identity["workload_sha256"], digest(self.workload))
                self.assertEqual(identity["executable_sha256"], digest(self.executable))

    def test_every_link_input_mode_is_derived_from_the_product_owner(self) -> None:
        for product, modes, linkage in (
            (self.static, evidence.STATIC_LINK_INPUT_MODES, "static"),
            (self.dynamic, evidence.DYNAMIC_LINK_INPUT_MODES, "pie"),
        ):
            for relative, expected_mode in modes.items():
                with self.subTest(product=product.name, relative=relative):
                    path = product / relative
                    original_mode = path.stat().st_mode & 0o7777
                    self.assertEqual(original_mode, expected_mode)
                    path.chmod(0o600)
                    try:
                        with self.assertRaisesRegex(evidence.ProductEvidenceError, "source-bound mode"):
                            self.validate(linkage)
                    finally:
                        path.chmod(original_mode)

    def test_os_test_compile_product_preserves_source_bound_dynamic_link_modes(self) -> None:
        """The adapter copy must remain an admissible input to link validation."""
        copied = self.root / "os-test-compiler-product"
        baseline = os_test.tree_roster(self.dynamic)
        source_modes = {
            relative: (self.dynamic / relative).stat().st_mode & 0o7777
            for relative in evidence.DYNAMIC_LINK_INPUT_MODES
        }
        control = os_test.prepare_compile_product(self.dynamic, copied, baseline)

        self.assertEqual(
            {
                relative: (self.dynamic / relative).stat().st_mode & 0o7777
                for relative in evidence.DYNAMIC_LINK_INPUT_MODES
            },
            source_modes,
        )
        original_dynamic = self.dynamic
        self.dynamic = copied
        try:
            receipt = self.dynamic_receipt()
            with mock.patch.object(evidence, "_readelf", return_value=self.readelf("pie")):
                identity = evidence.validate_link(copied, self.workload, self.executable, receipt, "pie")
        finally:
            self.dynamic = original_dynamic

        self.assertEqual(identity["linkage"], "pie")
        self.assertEqual(os_test.tree_roster(copied), baseline)
        self.assertEqual(control["payload"], baseline)

    def test_tampered_workload_object_fails(self) -> None:
        receipt = self.dynamic_receipt()
        self.workload.write_bytes(b"changed object\n")
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "workload|application"):
            self.validate("pie", receipt)

    def test_boolean_schema_is_not_an_integer_version(self) -> None:
        for linkage, product in (("static", self.static), ("pie", self.dynamic)):
            for target in ("manifest", "receipt"):
                with self.subTest(linkage=linkage, target=target):
                    manifest = product / "share/crabc/manifest.json"
                    original = manifest.read_text()
                    if target == "manifest":
                        value = json.loads(original)
                        value["schema"] = True
                        self.write_json(manifest, value)
                    receipt = self.static_receipt(linkage) if linkage == "static" else self.dynamic_receipt(linkage)
                    if target == "receipt":
                        value = json.loads(receipt.read_text())
                        value["schema"] = True
                        self.write_json(receipt, value)
                    try:
                        with self.assertRaisesRegex(evidence.ProductEvidenceError, "schema"):
                            self.validate(linkage, receipt)
                    finally:
                        manifest.write_text(original)

    def test_dynamic_receipt_rejects_unversioned_and_schema_one_hybrid_shapes(self) -> None:
        receipt = self.dynamic_receipt()
        record = json.loads(receipt.read_text())
        for changed in (
            {key: value for key, value in record.items() if key != "schema"},
            {**record, "application_search_kind": "runpath"},
        ):
            with self.subTest(changed=changed):
                self.write_json(receipt, changed)
                with self.assertRaisesRegex(evidence.ProductEvidenceError, "schema|fields"):
                    self.validate("pie", receipt)

    def test_dotdot_workload_path_fails_before_normalization(self) -> None:
        receipt = self.dynamic_receipt()
        redirected = self.root / "redirected-work"
        redirected.symlink_to(self.root, target_is_directory=True)
        lexical_workload = redirected / ".." / self.workload.name
        with mock.patch.object(evidence, "_readelf", return_value=self.readelf("pie")):
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "lexical parent"):
                evidence.validate_link(
                    self.dynamic, lexical_workload, self.executable, receipt, "pie"
                )

    def test_receipt_linker_must_be_an_executable_ld_lld(self) -> None:
        receipt = self.static_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        other = self.put("tools/not-a-linker", b"not lld\n")
        os.chmod(other, 0o755)
        record["resolved_linker"] = {"path": str(other), "sha256": digest(other)}
        self.write_json(receipt, record)
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "ld.lld"):
            self.validate("static", receipt)

        receipt = self.static_receipt("static-pie")
        os.chmod(self.linker, 0o644)
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "executable"):
            self.validate("static-pie", receipt)

    def test_foreign_runtime_roster_fails(self) -> None:
        receipt = self.dynamic_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        foreign = self.dynamic / "usr/lib/libforeign.so"
        foreign.write_bytes(b"foreign runtime\n")
        self.refresh_dynamic_manifest()
        manifest = self.dynamic / "share/crabc/manifest.json"
        record["manifest_sha256"] = digest(manifest)
        record["owned_runtime_inputs"].append("usr/lib/libforeign.so")
        self.write_json(receipt, record)
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "runtime roster"):
            self.validate("pie", receipt)

    def test_dynamic_product_requires_its_sealed_driver(self) -> None:
        receipt = self.dynamic_receipt()
        (self.dynamic / "bin/crabc-cc-dynamic").unlink()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "sealed driver"):
            self.validate("pie", receipt)

    def test_dynamic_product_requires_its_shared_static_helper(self) -> None:
        receipt = self.dynamic_receipt()
        (self.dynamic / "share/crabc/crabc_cc_static.py").unlink()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "shared static helper"):
            self.validate("pie", receipt)

    def test_dynamic_product_requires_its_headers(self) -> None:
        receipt = self.dynamic_receipt()
        headers = self.dynamic / "usr/include"
        (headers / "fixture.h").unlink()
        headers.rmdir()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "headers"):
            self.validate("pie", receipt)

    def test_stale_runtime_and_manifest_fail(self) -> None:
        receipt = self.dynamic_receipt()
        (self.dynamic / "usr/lib/libc.so").write_bytes(b"new owned libc\n")
        self.refresh_dynamic_manifest()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "manifest hash|runtime input"):
            self.validate("pie", receipt)

    def test_tampered_output_fails(self) -> None:
        receipt = self.static_receipt()
        self.executable.write_bytes(b"different executable\n")
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "output"):
            self.validate("static", receipt)

    def test_linkage_mode_mismatch_fails(self) -> None:
        receipt = self.static_receipt()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "mode"):
            self.validate("static-pie", receipt)

    def test_missing_receipt_fails(self) -> None:
        receipt = self.dynamic_receipt()
        receipt.unlink()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "receipt"):
            self.validate("pie", receipt)

    def test_foreign_dynamic_needed_entry_fails(self) -> None:
        receipt = self.dynamic_receipt()
        elf = self.readelf("pie")
        elf["dynamic"] = elf["dynamic"].replace(
            "Shared library: [libc.so]", "Shared library: [libforeign.so]"
        )
        with mock.patch.object(evidence, "_readelf", return_value=elf):
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "DT_NEEDED"):
                evidence.validate_link(self.dynamic, self.workload, self.executable, receipt, "pie")


if __name__ == "__main__":
    unittest.main()
