#!/usr/bin/env python3
"""Focused contract checks for installed x86 errno/h_errno lifecycle evidence."""

from importlib.util import module_from_spec, spec_from_file_location
import hashlib
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
TEST_WORK_ROOT = ROOT / ".work" / "x86_64" / "errno-storage-lifecycle" / "tests"
ERRNO = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs"
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


class ErrnoStorageLifecycleTests(unittest.TestCase):
    def test_allocator_errno_alias_uses_static_hidden_and_shared_link_localization(self) -> None:
        source = ERRNO.read_text(encoding="utf-8")

        self.assertIn(
            '#[cfg(all(feature = "x86-allocator-runtime", not(feature = "x86-owned-dynamic-runtime")))]\n'
            'core::arch::global_asm!(\n'
            '    ".hidden ___errno_location",',
            source,
        )
        self.assertIn(
            '#[cfg(all(feature = "x86-allocator-runtime", feature = "x86-owned-dynamic-runtime"))]\n'
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

        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "unsafe"):
            reader.rebase_report_checkout_paths(
                {"source": {"root": "/workspace"}, "work": "/workspace/../outside"}, ROOT
            )

    def test_replay_work_must_stay_in_the_recorded_checkout_evidence_root(self) -> None:
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "escapes recorded checkout"):
            reader.rebase_report_checkout_paths(
                {"source": {"root": "/workspace"}, "work": "/opt/evidence"}, ROOT
            )
        with self.assertRaisesRegex(reader.ErrnoStorageEvidenceError, "below checkout .work"):
            reader.rebase_report_checkout_paths(
                {"source": {"root": "/workspace"}, "work": "/workspace/compat/evidence"}, ROOT
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
