#!/usr/bin/env python3
"""Focused contract checks for installed x86 errno/h_errno lifecycle evidence."""

from importlib.util import module_from_spec, spec_from_file_location
import hashlib
from pathlib import Path, PurePosixPath
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
TEST_WORK_ROOT = ROOT / ".work" / "x86_64" / "errno-storage-lifecycle" / "tests"
ERRNO = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs"
H_ERRNO = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "h_errno.rs"
PROBE = ROOT / "compat" / "x86_64" / "owned_errno_storage_lifecycle_probe.c"
DSO = ROOT / "compat" / "x86_64" / "owned_errno_storage_lifecycle_dso.c"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_errno_storage_lifecycle.sh"
READER_PATH = ROOT / "compat" / "x86_64" / "owned_errno_storage_lifecycle.py"
PRIVATE_ALIAS_LIST = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_errno_private_aliases.list"

spec = spec_from_file_location("owned_errno_storage_lifecycle", READER_PATH)
assert spec is not None and spec.loader is not None
reader = module_from_spec(spec)
spec.loader.exec_module(reader)


def symbols(rows: str, table: str = ".symtab") -> str:
    return f"Symbol table '{table}' contains 9 entries:\n   Num:    Value          Size Type    Bind   Vis      Ndx Name\n{rows}\n"


STATIC_GOOD = symbols(
    """     1: 0000000000000010    17 FUNC    GLOBAL DEFAULT    1 __errno_location
     2: 0000000000000010    17 FUNC    WEAK   HIDDEN     1 ___errno_location
     3: 0000000000000040     4 OBJECT  GLOBAL DEFAULT    2 h_errno
     4: 0000000000000050    11 FUNC    GLOBAL DEFAULT    1 __h_errno_location"""
)

SHARED_GOOD = (
    symbols(
        """     1: 0000000000001010    17 FUNC    GLOBAL DEFAULT    9 __errno_location
     2: 0000000000001010    17 FUNC    LOCAL  DEFAULT    9 ___errno_location
     3: 0000000000002040     4 OBJECT  GLOBAL DEFAULT   21 h_errno
     4: 0000000000001050    11 FUNC    GLOBAL DEFAULT    9 __h_errno_location"""
    ),
    symbols(
        """     1: 0000000000001010    17 FUNC    GLOBAL DEFAULT    9 __errno_location
     3: 0000000000002040     4 OBJECT  GLOBAL DEFAULT   21 h_errno
     4: 0000000000001050    11 FUNC    GLOBAL DEFAULT    9 __h_errno_location""",
        ".dynsym",
    ),
)


def complete_header(elf_type: str, section_count: int) -> str:
    return f"""\
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 03 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - GNU
  ABI Version:                       0
  Type:                              {elf_type}
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          256 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         {section_count}
  Section header string table index: 4
"""


SECTION_LEGEND = """\
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
"""


def complete_sections(rows: str, count: int) -> str:
    return f"""\
There are {count} section headers, starting at offset 0x100:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
{rows}
{SECTION_LEGEND}"""


def complete_symbols(table: str, value: str) -> str:
    return f"""\
Symbol table '{table}' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: {value}     4 OBJECT  GLOBAL DEFAULT    1 h_errno
     2: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     3: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     4: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     5: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     6: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
"""


STATIC_LAYOUT_HEADER = complete_header("REL (Relocatable file)", 5)
STATIC_LAYOUT_SECTIONS = complete_sections(
    """\
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .bss.h_errno      NOBITS          0000000000000000 000040 000004 00  WA  0   0  4
  [ 2] .text             PROGBITS        0000000000000000 000040 000004 00  AX  0   0 16
  [ 3] .symtab           SYMTAB          0000000000000000 000050 0000a8 18      4   3  8
  [ 4] .strtab           STRTAB          0000000000000000 0000f8 000008 00      0   0  1""",
    5,
)
STATIC_LAYOUT_SYMBOLS = complete_symbols(".symtab", "0000000000000000")

SHARED_LAYOUT_HEADER = complete_header("DYN (Shared object file)", 6)
SHARED_LAYOUT_SECTIONS = complete_sections(
    """\
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .bss              NOBITS          0000000000001000 000040 000080 00  WA  0   0 32
  [ 2] .text             PROGBITS        0000000000002000 000040 000004 00  AX  0   0 16
  [ 3] .dynsym           DYNSYM          0000000000000000 000050 0000a8 18      4   3  8
  [ 4] .dynstr           STRTAB          0000000000000000 0000f8 000008 00      0   0  1
  [ 5] .symtab           SYMTAB          0000000000000000 000100 0000a8 18      4   3  8""",
    6,
)
SHARED_LAYOUT_SYMBOLS = (
    complete_symbols(".dynsym", "0000000000001020")
    + complete_symbols(".symtab", "0000000000001020")
)


def archive_block(payload: str) -> str:
    return f"\nFile: /fixture/static.a(provider.o)\n{payload}"


def archive_member_block(member: str, payload: str) -> str:
    return f"\nFile: /fixture/static.a({member})\n{payload}"


EMPTY_STATIC_HEADER = complete_header("REL (Relocatable file)", 2)
EMPTY_STATIC_SECTIONS = complete_sections(
    """\
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        0000000000000000 000040 000000 00  AX  0   0  1""",
    2,
)


class ErrnoStorageLifecycleTests(unittest.TestCase):
    def test_h_errno_source_and_installed_c_boundary_require_an_x86_int_object(self) -> None:
        source = H_ERRNO.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")

        self.assertIn("use core::ffi::c_int;", source)
        self.assertIn("pub static mut h_errno: c_int = 0;", source)
        self.assertEqual(
            reader.H_ERRNO_METADATA,
            {
                "type": "OBJECT",
                "binding": "GLOBAL",
                "visibility": "DEFAULT",
                "size_bytes": 4,
                "alignment_bytes": 4,
            },
        )
        self.assertIn("_Static_assert(_Alignof(int) == 4", probe)

    def test_allocator_errno_alias_uses_static_hidden_and_shared_link_localization(self) -> None:
        source = ERRNO.read_text(encoding="utf-8")

        self.assertIn(
            '#[cfg(all(crabc_x86_allocator_runtime, not(crabc_x86_dynamic_runtime)))]\n'
            'core::arch::global_asm!(\n'
            '    ".hidden ___errno_location",',
            source,
        )
        self.assertIn(
            '#[cfg(all(crabc_x86_allocator_runtime, crabc_x86_dynamic_runtime))]\n'
            'core::arch::global_asm!(\n'
            '    ".weak ___errno_location",',
            source,
        )
        self.assertEqual(source.count('".weak ___errno_location"'), 2)
        self.assertEqual(source.count('".set ___errno_location, __errno_location"'), 2)
        self.assertNotIn('fn ___errno_location() -> *mut c_int', source)

    def test_static_alias_requires_same_section_and_value(self) -> None:
        reader.validate_static_symbols(STATIC_GOOD, "fixture static")
        forwarded = STATIC_GOOD.replace("WEAK   HIDDEN     1 ___errno_location", "WEAK   HIDDEN     2 ___errno_location")
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "same definition"):
            reader.validate_static_symbols(forwarded, "forwarded static")

    def test_selected_symbol_definitions_require_positive_numeric_sections(self) -> None:
        for section in ("ABS", "COM", "0"):
            reserved = (
                STATIC_GOOD.replace("DEFAULT    1 __errno_location", f"DEFAULT  {section} __errno_location")
                .replace("HIDDEN     1 ___errno_location", f"HIDDEN   {section} ___errno_location")
                .replace("DEFAULT    2 h_errno", f"DEFAULT  {section} h_errno")
                .replace("DEFAULT    1 __h_errno_location", f"DEFAULT  {section} __h_errno_location")
            )
            with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "positive numeric section"):
                reader.validate_static_symbols(reserved, f"reserved-section static {section}")

    def test_shared_alias_is_local_and_not_in_dynsym(self) -> None:
        symtab, dynsym = SHARED_GOOD
        reader.validate_shared_symbols(symtab, dynsym, "fixture shared")
        exposed = dynsym.replace(
            "     3:",
            "     2: 0000000000001010    17 FUNC    GLOBAL DEFAULT    9 ___errno_location\n     3:",
        )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "dynsym"):
            reader.validate_shared_symbols(symtab, exposed, "exposed shared")

    def test_h_errno_layout_requires_its_defining_section_and_offset_to_meet_int_alignment(self) -> None:
        static = reader.validate_static_h_errno_layout(
            archive_block(STATIC_LAYOUT_HEADER),
            archive_block(STATIC_LAYOUT_SECTIONS),
            archive_block(STATIC_LAYOUT_SYMBOLS),
            "provider.o\n",
            "/fixture/static.a",
            "fixture static layout",
        )
        shared = reader.validate_shared_h_errno_layout(
            SHARED_LAYOUT_HEADER,
            SHARED_LAYOUT_SECTIONS,
            SHARED_LAYOUT_SYMBOLS,
            "fixture shared layout",
        )
        self.assertEqual(static["required_alignment_bytes"], 4)
        self.assertEqual(static["defining_section_alignment_bytes"], 4)
        self.assertEqual(static["defining_section_size_bytes"], 4)
        self.assertEqual(static["offset_bytes"], 0)
        self.assertEqual(shared["required_alignment_bytes"], 4)
        self.assertEqual(shared["defining_section_alignment_bytes"], 32)
        self.assertEqual(shared["defining_section_size_bytes"], 0x80)
        self.assertEqual(shared["offset_bytes"], 0x20)

        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "section alignment"):
            reader.validate_static_h_errno_layout(
                archive_block(STATIC_LAYOUT_HEADER),
                archive_block(STATIC_LAYOUT_SECTIONS.replace("0   0  4", "0   0  2")),
                archive_block(STATIC_LAYOUT_SYMBOLS),
                "provider.o\n",
                "/fixture/static.a",
                "under-aligned static layout",
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "offset alignment"):
            reader.validate_static_h_errno_layout(
                archive_block(STATIC_LAYOUT_HEADER),
                archive_block(STATIC_LAYOUT_SECTIONS),
                archive_block(STATIC_LAYOUT_SYMBOLS.replace("0000000000000000     4 OBJECT", "0000000000000002     4 OBJECT")),
                "provider.o\n",
                "/fixture/static.a",
                "misaligned static offset",
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "offset alignment"):
            reader.validate_shared_h_errno_layout(
                SHARED_LAYOUT_HEADER,
                SHARED_LAYOUT_SECTIONS,
                SHARED_LAYOUT_SYMBOLS.replace("0000000000001020", "0000000000001022"),
                "misaligned shared offset",
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "section address"):
            reader.validate_shared_h_errno_layout(
                SHARED_LAYOUT_HEADER,
                SHARED_LAYOUT_SECTIONS.replace("0000000000001000", "0000000000001001"),
                SHARED_LAYOUT_SYMBOLS.replace("0000000000001020", "0000000000001021"),
                "misaligned shared section address",
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "section alignment"):
            reader.validate_shared_h_errno_layout(
                SHARED_LAYOUT_HEADER,
                SHARED_LAYOUT_SECTIONS.replace("  0 32\n  [ 2]", "  0  5\n  [ 2]"),
                SHARED_LAYOUT_SYMBOLS,
                "nonmultiple shared section alignment",
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "exceeds its defining section"):
            reader.validate_shared_h_errno_layout(
                SHARED_LAYOUT_HEADER,
                SHARED_LAYOUT_SECTIONS,
                SHARED_LAYOUT_SYMBOLS.replace("0000000000001020", "0000000000001080"),
                "out-of-range shared h_errno",
            )

    def test_static_h_errno_layout_skips_symbol_free_archive_members(self) -> None:
        layout = reader.validate_static_h_errno_layout(
            archive_member_block("empty.o", EMPTY_STATIC_HEADER)
            + archive_member_block("provider.o", STATIC_LAYOUT_HEADER),
            archive_member_block("empty.o", EMPTY_STATIC_SECTIONS)
            + archive_member_block("provider.o", STATIC_LAYOUT_SECTIONS),
            archive_member_block("empty.o", "")
            + archive_member_block("provider.o", STATIC_LAYOUT_SYMBOLS),
            "empty.o\nprovider.o\n",
            "/fixture/static.a",
            "static archive with a symbol-free member",
        )
        self.assertEqual(layout["archive_member"], {"name": "provider.o", "index": 1, "occurrence": 0})

    def test_static_h_errno_layout_selects_the_defining_member_among_consumers(self) -> None:
        # One member per Rust module: sibling members reference h_errno as UND.
        consumer_symbols = STATIC_LAYOUT_SYMBOLS.replace(
            "0000000000000000     4 OBJECT  GLOBAL DEFAULT    1 h_errno",
            "0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND h_errno",
        )
        self.assertNotEqual(consumer_symbols, STATIC_LAYOUT_SYMBOLS)

        def layout(provider_symbols: str) -> dict[str, object]:
            return reader.validate_static_h_errno_layout(
                archive_member_block("consumer.o", STATIC_LAYOUT_HEADER)
                + archive_member_block("provider.o", STATIC_LAYOUT_HEADER),
                archive_member_block("consumer.o", STATIC_LAYOUT_SECTIONS)
                + archive_member_block("provider.o", STATIC_LAYOUT_SECTIONS),
                archive_member_block("consumer.o", consumer_symbols)
                + archive_member_block("provider.o", provider_symbols),
                "consumer.o\nprovider.o\n",
                "/fixture/static.a",
                "per-module static archive",
            )

        self.assertEqual(layout(STATIC_LAYOUT_SYMBOLS)["archive_member"],
                         {"name": "provider.o", "index": 1, "occurrence": 0})
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "0 static archive h_errno definitions"):
            layout(consumer_symbols)

    def test_h_errno_layout_replay_uses_recorded_archive_spelling_for_host_products(self) -> None:
        """Complete archive facts retain /workspace while replay sees host paths."""

        TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TEST_WORK_ROOT) as temporary:
            work = Path(temporary)
            static_archive = work / "products" / "static" / "usr/lib" / "libc.a"
            dynamic_library = work / "products" / "dynamic" / "usr/lib" / "libc.so"
            static_archive.parent.mkdir(parents=True)
            dynamic_library.parent.mkdir(parents=True)
            static_archive.write_bytes(b"fixture static archive\n")
            dynamic_library.write_bytes(b"fixture shared library\n")
            products = {
                "static": {"libc": reader.identity(static_archive, "fixture static libc")},
                "dynamic": {"libc": reader.identity(dynamic_library, "fixture shared libc")},
            }
            recorded_root = PurePosixPath("/workspace")
            observations = reader._layout_observations(products, ROOT, recorded_root)
            candidate_static_archive = observations["candidate-static-header.txt"][-1]

            def archive_payload(archive: str, member: str, payload: str) -> str:
                return f"\nFile: {archive}({member})\n{payload}"

            payloads = {
                "oracle-static-members.txt": "provider.o\n",
                "oracle-static-header.txt": archive_payload(
                    reader.ORACLE_STATIC_ARCHIVE, "provider.o", STATIC_LAYOUT_HEADER
                ),
                "oracle-static-sections.txt": archive_payload(
                    reader.ORACLE_STATIC_ARCHIVE, "provider.o", STATIC_LAYOUT_SECTIONS
                ),
                "oracle-shared-header.txt": SHARED_LAYOUT_HEADER,
                "oracle-shared-sections.txt": SHARED_LAYOUT_SECTIONS,
                "candidate-static-members.txt": "provider.o\n",
                "candidate-static-header.txt": archive_payload(
                    candidate_static_archive, "provider.o", STATIC_LAYOUT_HEADER
                ),
                "candidate-static-sections.txt": archive_payload(
                    candidate_static_archive, "provider.o", STATIC_LAYOUT_SECTIONS
                ),
                "candidate-shared-header.txt": SHARED_LAYOUT_HEADER,
                "candidate-shared-sections.txt": SHARED_LAYOUT_SECTIONS,
            }
            artifacts = {}
            for name in reader.LAYOUT_INPUTS:
                output = work / name
                output.write_text(payloads[name], encoding="utf-8")
                stem = name.removesuffix(".txt")
                reader.write_json(work / f"{stem}.argv.json", {"argv": observations[name]})
                (work / f"{stem}.status").write_text("0\n", encoding="utf-8")
                (work / f"{stem}.stderr").write_bytes(b"")
                artifacts[name] = reader.observation_artifact(work, name, "fixture layout")

            symbol_payloads = {
                "oracle-static-symbols.txt": archive_payload(
                    reader.ORACLE_STATIC_ARCHIVE, "provider.o", STATIC_LAYOUT_SYMBOLS
                ),
                "candidate-static-symbols.txt": archive_payload(
                    candidate_static_archive, "provider.o", STATIC_LAYOUT_SYMBOLS
                ),
                "oracle-shared-symbols.txt": SHARED_LAYOUT_SYMBOLS,
                "candidate-shared-symbols.txt": SHARED_LAYOUT_SYMBOLS,
                "oracle-dynamic-symbols.txt": SHARED_LAYOUT_SYMBOLS,
                "candidate-dynamic-symbols.txt": SHARED_LAYOUT_SYMBOLS,
            }
            symbols = {}
            for name in reader.SYMBOL_INPUTS:
                path = work / name
                path.write_text(symbol_payloads[name], encoding="utf-8")
                symbols[name] = path

            layout = reader.validate_h_errno_layout_artifacts(
                artifacts, symbols, products, work, ROOT, recorded_root
            )
            self.assertEqual(candidate_static_archive, "/workspace/" + static_archive.relative_to(ROOT).as_posix())
            self.assertEqual(layout["static"]["candidate"]["archive_member"]["name"], "provider.o")
            self.assertEqual(layout["shared"]["candidate"]["required_alignment_bytes"], 4)

    def test_shared_alias_requires_its_exact_local_link_policy(self) -> None:
        self.assertEqual(PRIVATE_ALIAS_LIST.read_text(encoding="utf-8"), "___errno_location\n")
        provenance = {
            "shared_errno_private_aliases": {
                "source": {
                    "path": "libc/src/c_abi/x86_64/owned_errno_private_aliases.list",
                    "sha256": "2e69ec5346002fa183b51dbbbef2f24744bd89093b5cfac6329337c1b3d240dd",
                    "mode": 0o644,
                },
                "member_count": 1,
                "members": ["___errno_location"],
                "linker_policy": "exact-local-symbols",
                "linker_script_sha256": hashlib.sha256(
                    b"{\n  local:\n    ___errno_location;\n};\n"
                ).hexdigest(),
            },
            "libc_shared_link_command": [
                "/pinned/ld.lld",
                "--version-script=$BUILD/libc-errno-private.exports",
            ],
        }
        reader.validate_shared_alias_link_policy(provenance, "fixture shared policy")

        wrong_members = {
            **provenance,
            "shared_errno_private_aliases": {
                **provenance["shared_errno_private_aliases"],
                "members": ["forged_alias"],
            },
        }
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "alias roster"):
            reader.validate_shared_alias_link_policy(wrong_members, "forged shared policy")
        missing_link = {**provenance, "libc_shared_link_command": ["/pinned/ld.lld"]}
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "version script"):
            reader.validate_shared_alias_link_policy(missing_link, "missing shared policy")
        arbitrary_digest = {
            **provenance,
            "shared_errno_private_aliases": {
                **provenance["shared_errno_private_aliases"],
                "linker_script_sha256": "a" * 64,
            },
        }
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "script digest"):
            reader.validate_shared_alias_link_policy(arbitrary_digest, "forged shared policy digest")

    def test_replay_rebases_only_authenticated_container_checkout_paths(self) -> None:
        recorded = {
            "source": {"root": "/workspace"},
            "collection_checkout_root": "/workspace",
            "work": "/workspace/.work/x86_64/errno-storage-lifecycle/receipt",
            "artifact": {"path": "/workspace/.work/x86_64/errno-storage-lifecycle/receipt/raw.txt"},
            "external": {"path": "/opt/musl-1.2.6/lib/libc.so"},
            "source_policy": {"path": "libc/src/c_abi/x86_64/owned_errno_private_aliases.list"},
        }
        rebased = reader.rebase_report_checkout_paths(recorded, ROOT)
        self.assertEqual(rebased["source"]["root"], str(ROOT))
        self.assertEqual(
            rebased["work"],
            str(ROOT / ".work/x86_64/errno-storage-lifecycle/receipt"),
        )
        self.assertEqual(
            rebased["artifact"]["path"],
            str(ROOT / ".work/x86_64/errno-storage-lifecycle/receipt/raw.txt"),
        )
        self.assertEqual(rebased["external"]["path"], "/opt/musl-1.2.6/lib/libc.so")
        self.assertEqual(rebased["source_policy"]["path"], recorded["source_policy"]["path"])
        self.assertEqual(
            reader._recorded_command_path(
                ROOT / ".work" / "x86_64" / "receipt" / "static" / "usr/lib/libc.a",
                ROOT,
                PurePosixPath("/workspace"),
            ),
            "/workspace/.work/x86_64/receipt/static/usr/lib/libc.a",
        )

        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "collection checkout root"):
            reader.rebase_report_checkout_paths(
                {**recorded, "collection_checkout_root": "/forged-workspace"}, ROOT
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "unsafe"):
            reader.rebase_report_checkout_paths(
                {
                    "source": {"root": "/workspace"},
                    "collection_checkout_root": "/workspace",
                    "work": "/workspace/../outside",
                },
                ROOT,
            )

    def test_replay_work_must_stay_in_the_recorded_checkout_evidence_root(self) -> None:
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "escapes recorded checkout"):
            reader.rebase_report_checkout_paths(
                {
                    "source": {"root": "/workspace"},
                    "collection_checkout_root": "/workspace",
                    "work": "/opt/evidence",
                },
                ROOT,
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "below checkout .work"):
            reader.rebase_report_checkout_paths(
                {
                    "source": {"root": "/workspace"},
                    "collection_checkout_root": "/workspace",
                    "work": "/workspace/compat/evidence",
                },
                ROOT,
            )

    def test_replay_work_rejects_an_intermediate_symlink_escape(self) -> None:
        TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TEST_WORK_ROOT) as temporary:
            temporary_path = Path(temporary)
            escape = temporary_path / "escape"
            escape.symlink_to(ROOT / "compat", target_is_directory=True)
            recorded_work = "/workspace/" + (
                temporary_path.relative_to(ROOT) / "escape" / "x86_64"
            ).as_posix()
            with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "resolves outside checkout .work"):
                reader.rebase_report_checkout_paths(
                    {
                        "source": {"root": "/workspace"},
                        "collection_checkout_root": "/workspace",
                        "work": recorded_work,
                    },
                    ROOT,
                )

    def test_independent_link_layouts_do_not_compare_raw_addresses(self) -> None:
        # Alias identity is a relation inside an ELF file.  Pinned-musl and
        # candidate links may legitimately assign unrelated section/value pairs.
        reader.validate_static_symbols(STATIC_GOOD, "oracle fixture")
        candidate = STATIC_GOOD.replace("0000000000000010", "0000000000007010").replace(
            "0000000000000040", "0000000000008040"
        )
        reader.validate_static_symbols(candidate, "candidate fixture")

    def test_workload_keeps_storage_live_and_dso_public(self) -> None:
        probe = PROBE.read_text(encoding="utf-8")
        dso = DSO.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn("pthread_tryjoin_np(worker, 0) != EBUSY || errno != MAIN_ERRNO", probe)
        self.assertIn("Do not read or\n     * dereference state.errno_location/state.h_errno_location after this join.", probe)
        self.assertIn('dlopen("/usr/lib/liberrno-storage-lifecycle-probe.so", RTLD_NOW | RTLD_LOCAL)', probe)
        self.assertIn("errno_storage_lifecycle_snapshot", dso)
        self.assertNotIn("___errno_location", dso)
        self.assertNotIn("crabc_link_visible_h_errno", dso)
        self.assertIn("--dynamic-shared-object", runner)
        self.assertIn("chroot", runner)
        self.assertIn("oracle-static-exec", reader.RUN_LABELS)
        self.assertNotIn("oracle-static-pie", reader.RUN_LABELS)

    def test_live_main_and_worker_accessors_check_int_pointer_alignment(self) -> None:
        probe = PROBE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn("_Static_assert(_Alignof(int) == 4", probe)
        self.assertIn("locations_are_int_aligned", probe)
        self.assertIn("!locations_are_int_aligned(state->errno_location, state->h_errno_location)", probe)
        self.assertIn("!locations_are_int_aligned(main_errno, main_h_errno)", probe)
        self.assertIn('readelf -hW "$MUSL_ARCHIVE"', runner)
        self.assertIn('readelf -SW "$MUSL_ARCHIVE"', runner)
        self.assertIn('ar t "$MUSL_ARCHIVE"', runner)

    def test_workload_symbol_guard_rejects_archive_alias_in_dynamic_object(self) -> None:
        dynamic = symbols(
            """     1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __errno_location
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __h_errno_location
     3: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND h_errno
     4: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND pthread_tryjoin_np
     5: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND dlopen
     6: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND dlsym"""
        )
        dynamic_bad = dynamic.replace(
            "     6:",
            "     7: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND ___errno_location\n     6:",
        )
        static = symbols(
            """     1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __errno_location
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND ___errno_location
     3: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __h_errno_location
     4: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND h_errno
     5: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND pthread_tryjoin_np"""
        )
        plugin = symbols(
            """     1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __errno_location
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __h_errno_location"""
        )
        TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TEST_WORK_ROOT) as temporary:
            work = Path(temporary)
            files = {
                "core-static-symbols.txt": static,
                "core-dynamic-symbols.txt": dynamic_bad,
                "plugin-symbols.txt": plugin,
            }
            values = {}
            for name, payload in files.items():
                path = work / name
                path.write_text(payload, encoding="utf-8")
                values[name] = reader.identity(path, name)
            with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "archive-only"):
                reader.validate_workload_symbols(values, work)


if __name__ == "__main__":
    unittest.main()
