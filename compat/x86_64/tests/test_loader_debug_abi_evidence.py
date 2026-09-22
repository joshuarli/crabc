"""Behavioral integrity of the focused debugger/CRT evidence reader."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

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
        outside = ROOT / 'AGENTS.md'
        item = {'path': 'AGENTS.md', 'sha256': evidence.digest(outside), 'size': outside.stat().st_size}
        with self.assertRaises(evidence.EvidenceError):
            evidence.artifact(item)


class SuppliedProductModeTests(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / '.work/x86_64/tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.static = self.root / 'static-product'
        self.dynamic = self.root / 'dynamic-product'
        for path, contents in {
            self.static / 'share/crabc/manifest.json': b'static-manifest',
            self.dynamic / 'share/crabc/manifest.json': b'dynamic-manifest',
            self.dynamic / 'share/crabc/dynamic-product-state.json': b'dynamic-state',
            self.dynamic / 'usr/lib/libc.so': b'candidate-libc',
            self.dynamic / 'lib/ld-crabc-x86_64.so.1': b'candidate-loader',
        }.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)

    def test_supplied_mode_requires_the_complete_static_dynamic_pair_before_creating_output(self):
        output = self.root / 'output'
        with self.assertRaisesRegex(evidence.EvidenceError, 'require both static and dynamic roots'):
            evidence.Collector(output, self.static, None)
        self.assertFalse(output.exists())

    def test_supplied_mode_rejects_a_symlinked_product_before_invoking_a_product_validator(self):
        link = self.root / 'static-link'
        link.symlink_to(self.static.name)
        output = self.root / 'output'
        with self.assertRaisesRegex(evidence.EvidenceError, 'physical checkout .work directory'):
            evidence.Collector(output, link, self.dynamic)
        self.assertFalse(output.exists())

    def test_supplied_mode_rejects_overlapping_product_roots_before_creating_output(self):
        output = self.root / 'output'
        with self.assertRaisesRegex(evidence.EvidenceError, 'product roots overlap'):
            evidence.Collector(output, self.static, self.static)
        self.assertFalse(output.exists())

    def test_product_record_retains_the_dynamic_state_change_between_pre_and_post_checks(self):
        static_driver = types.SimpleNamespace(DriverError=RuntimeError,
                                              validate_installed_runtime=mock.Mock())
        qualification = types.SimpleNamespace(QualificationError=RuntimeError,
                                              product_identity=mock.Mock(return_value='a' * 64))
        with mock.patch.dict(sys.modules, {
            'crabc_cc_static': static_driver,
            'owned_dynamic_qualification': qualification,
        }):
            before = evidence._product_records(self.static, self.dynamic, 'supplied')
            (self.dynamic / 'share/crabc/dynamic-product-state.json').write_bytes(b'changed-dynamic-state')
            after = evidence._product_records(self.static, self.dynamic, 'supplied')
        self.assertNotEqual(before, after)
        self.assertEqual(static_driver.validate_installed_runtime.call_count, 2)
        self.assertEqual(qualification.product_identity.call_count, 2)

    def test_supplied_mode_rejects_the_existing_current_source_product_validator_failure(self):
        static_driver = types.SimpleNamespace(DriverError=RuntimeError,
                                              validate_installed_runtime=mock.Mock())
        qualification = types.SimpleNamespace(
            QualificationError=RuntimeError,
            product_identity=mock.Mock(side_effect=RuntimeError('installed product source is stale')),
        )
        output = self.root / 'output'
        with mock.patch.dict(sys.modules, {
            'crabc_cc_static': static_driver,
            'owned_dynamic_qualification': qualification,
        }), self.assertRaisesRegex(evidence.EvidenceError, 'current supplied product contract differs'):
            evidence.Collector(output, self.static, self.dynamic)
        self.assertFalse(output.exists())
        static_driver.validate_installed_runtime.assert_called_once_with(self.static)
        qualification.product_identity.assert_called_once_with(self.dynamic)

    def test_collect_cli_forwards_the_complete_supplied_pair_to_the_existing_collector(self):
        collector = mock.Mock()
        collector.return_value.collect.return_value = 'report'
        with mock.patch.object(evidence, 'Collector', collector), \
             mock.patch.object(sys, 'argv', [
                 'loader_debug_abi_evidence.py', 'collect', '--output', str(self.root / 'output'),
                 '--static-product', str(self.static), '--dynamic-product', str(self.dynamic),
             ]):
            evidence.main()
        collector.assert_called_once_with(self.root / 'output', self.static, self.dynamic)

    def test_documented_pinned_wrapper_contract_names_both_supplied_roots(self):
        wrapper = (ROOT / 'compat/x86_64/run_loader_debug_abi.sh').read_text(encoding='utf-8')
        document = (ROOT / 'compat/x86_64/loader-debug-crt-abi.md').read_text(encoding='utf-8')
        self.assertIn('"$@"', wrapper)
        self.assertIn('--static-product STATIC_PRODUCT --dynamic-product DYNAMIC_PRODUCT', document)


if __name__ == '__main__':
    unittest.main()
