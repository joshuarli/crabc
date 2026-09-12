"""Behavioral integrity of the focused debugger/CRT evidence reader."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('loader_debug_abi_evidence', ROOT / 'compat/x86_64/loader_debug_abi_evidence.py')
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class DebuggerTraceTests(unittest.TestCase):
    def test_complete_transaction_sequence_retains_the_runtime_mapping(self):
        text = ('debug-event=0,maps-added=0\n'
                'debug-event=1,maps-added=0\ndebug-event=0,maps-added=1\n'
                'debug-event=1,maps-added=1\ndebug-event=0,maps-added=1\n')
        self.assertEqual(evidence.trace_events(text), [[0, 0], [1, 0], [0, 1], [1, 1], [0, 1]])

    def test_missing_notifications_and_fabricated_delete_are_rejected(self):
        invalid = [[], [(1, 0)], [(0, 0), (1, 0)],
                   [(0, 0), (1, 0), (0, 1), (1, 1)],
                   [(0, 0), (1, 0), (0, 0), (1, 0), (0, 0)],
                   [(0, 0), (1, 1), (0, 1), (1, 1), (0, 1)],
                   [(0, 0), (1, 0), (0, 1), (1, 1), (0, 0)],
                   [(0, 0), (1, 0), (0, 1), (2, 1), (0, 1)]]
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(evidence.EvidenceError):
                evidence.trace_events(''.join(f'debug-event={state},maps-added={added}\n' for state, added in rows))

    def test_execution_roster_covers_archive_and_all_dynamic_entry_pairs(self):
        cases = evidence.expected_cases()
        self.assertEqual(len(cases), 68)
        for lane in ('oracle', 'candidate'):
            for mode in ('pie', 'non-pie'):
                for entry in ('kernel', 'direct'):
                    self.assertIn(f'{lane}-{mode}-{entry}-copy', cases)
                    self.assertIn(f'{lane}-{mode}-{entry}-trace', cases)
            self.assertIn(f'{lane}-static-pie-archive-override', cases)


class ElfMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / '.work/x86_64/tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'libc.so'
        self.image = bytearray(1024)
        self.image[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<H', self.image, 18, 62)
        struct.pack_into('<Q', self.image, 40, 64)
        struct.pack_into('<HH', self.image, 58, 64, 4)
        struct.pack_into('<IIQQQQIIQQ', self.image, 128, 0, 11, 0, 0, 512, 120, 2, 0, 8, 24)
        names = b'\0_dl_debug_addr\0_dl_debug_state\0_init\0_fini\0'
        struct.pack_into('<IIQQQQIIQQ', self.image, 192, 0, 3, 0, 0, 700, len(names), 0, 0, 1, 0)
        struct.pack_into('<IIQQQQIIQQ', self.image, 256, 0, 0x6fffffff, 0, 0, 800, 10, 1, 0, 2, 2)
        self.image[700:700 + len(names)] = names
        for index, name in enumerate(evidence.PUBLIC, 1):
            kind, binding, size = evidence.PUBLIC[name]
            info = (1 if binding == 'GLOBAL' else 2) << 4 | (1 if kind == 'OBJECT' else 2)
            struct.pack_into('<IBBHQQ', self.image, 512 + 24 * index, names.index(name.encode()), info, 0, 1, 0x1000 + 8 * index, size or 1)
            struct.pack_into('<H', self.image, 800 + 2 * index, 1)
        self.path.write_bytes(self.image)

    def test_exact_pointer_object_and_weak_defaults_are_read_from_elf(self):
        rows = evidence.public_metadata(self.path)
        self.assertEqual(rows['_dl_debug_addr']['size'], 8)
        self.assertEqual(rows['_fini']['binding'], 'WEAK')

    def test_wrong_pointer_layout_binding_visibility_or_version_is_rejected(self):
        for offset, shape, value in [(536 + 16, '<Q', 40), (536 + 4, '<B', 0x12),
                                     (560 + 4, '<B', 0x12), (536 + 5, '<B', 2),
                                     (802, '<H', 2), (536 + 6, '<H', 0)]:
            mutated = bytearray(self.image)
            struct.pack_into(shape, mutated, offset, value)
            self.path.write_bytes(mutated)
            with self.subTest(offset=offset, value=value), self.assertRaises(evidence.EvidenceError):
                evidence.public_metadata(self.path)

    def test_truncated_symbol_table_cannot_be_reported_as_absence(self):
        self.path.write_bytes(self.image[:580])
        with self.assertRaises(evidence.EvidenceError):
            evidence.public_metadata(self.path)

    def test_artifact_cannot_escape_checkout_scratch(self):
        outside = ROOT / 'SCOPE.md'
        item = {'path': 'SCOPE.md', 'sha256': evidence.digest(outside), 'size': outside.stat().st_size}
        with self.assertRaises(evidence.EvidenceError):
            evidence.artifact(item)


if __name__ == '__main__':
    unittest.main()
