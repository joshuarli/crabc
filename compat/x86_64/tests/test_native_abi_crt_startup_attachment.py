"""Focused finite joins for the installed CRT startup receipt."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


class NativeCrtStartupAttachmentTests(unittest.TestCase):
    @staticmethod
    def _row(name: str, *, section: str = 'UND', binding: str = 'GLOBAL',
             visibility: str = 'DEFAULT') -> dict[str, object]:
        return {
            'name': name, 'raw_name': name, 'version': None, 'version_default': False,
            'binding': binding, 'visibility': visibility, 'section_index': section,
            'type': 'NOTYPE', 'value': '0000000000000000', 'size_bytes': 0,
            'size': '0', 'row_index': 1, 'raw': name, 'other': None,
            'version_index': None, 'common_alignment': None,
        }

    def test_owner_derives_the_closed_twelve_identity_roster(self) -> None:
        reader = selection._crt_startup_reader()
        names = selection._crt_startup_identity_names(reader)
        self.assertEqual(names, tuple(reader.NAMES))
        self.assertEqual(len(names), 12)
        self.assertNotIn('__init_ssp', names)
        self.assertEqual(reader.contract(ROOT)['record_sizes'], {
            'owned_handoff': 32,
            'conventional_snapshot': 88,
        })

    def test_owner_projection_rejects_an_unowned_ssp_row_and_an_omitted_boundary(self) -> None:
        reader = selection._crt_startup_reader()
        names = selection._crt_startup_identity_names(reader)
        products = {'candidate-static': {}}
        rows = [{
            'member': 'startup.o', 'member_index': 0, 'member_occurrence': 0,
            'table_section_index': index + 1, 'section': None, 'row': self._row(name),
        } for index, name in enumerate(names)]
        selection._crt_startup_observed_rows({'candidate-static': rows}, names, products)
        with self.assertRaisesRegex(selection.SelectionError, 'unowned identity'):
            selection._crt_startup_observed_rows({'candidate-static': [
                *rows, {
                    'member': 'startup.o', 'member_index': 0, 'member_occurrence': 0,
                    'table_section_index': 2, 'section': None, 'row': self._row('__init_ssp'),
                },
            ]}, names, products)
        with self.assertRaisesRegex(selection.SelectionError, 'omits'):
            selection._crt_startup_observed_rows({'candidate-static': rows[:-1]}, names, products)

    def test_attachment_joins_only_the_observed_rows_and_keeps_the_got_boundary_exact(self) -> None:
        reader = selection._crt_startup_reader()
        names = selection._crt_startup_identity_names(reader)
        observed = []
        occurrences = []
        identities = []
        blockers = []
        for index, name in enumerate(names):
            row = self._row(name)
            source = {
                'artifact_key': 'candidate-static', 'member': None, 'member_index': None,
                'member_occurrence': None, 'table_section_index': index + 1,
                'section': None, 'row': row,
            }
            observed.append(source)
            occurrences.append({
                'index': index, 'artifact_key': source['artifact_key'], 'member_name': source['member'],
                'member_index': source['member_index'], 'member_occurrence': source['member_occurrence'],
                'table_section_index': source['table_section_index'], 'definition_section': source['section'],
                'role': 'import', 'row': row,
            })
            reasons = [selection.CRT_STARTUP_RECEIPT_REQUIREMENT, selection.ORDINARY_IMPORT_REASON]
            identities.append({
                'identity': {'name': name, 'version': None, 'version_default': False},
                'selection': {'disposition': 'structural-replacement', 'owner': 'crt-startup-link-boundaries'},
                'unresolved': reasons[:],
            })
            blockers.extend({
                'code': 'identity-unresolved',
                'identity': {'name': name, 'version': None, 'version_default': False},
                'reason': reason,
            } for reason in reasons)
        got = next(row for row in observed if row['row']['name'] == '_GLOBAL_OFFSET_TABLE_')
        got['row'] = self._row('_GLOBAL_OFFSET_TABLE_', binding='GLOBAL', visibility='DEFAULT')
        shared_got = {
            'artifact_key': 'candidate-shared', 'member': None, 'member_index': None,
            'member_occurrence': None, 'table_section_index': 99,
            'section': {'name': '.got.plt'},
            'row': self._row('_GLOBAL_OFFSET_TABLE_', section='18', binding='LOCAL', visibility='HIDDEN'),
        }
        observed.append(shared_got)
        occurrences.append({
            'index': len(occurrences), 'artifact_key': 'candidate-shared', 'member_name': None,
            'member_index': None, 'member_occurrence': None, 'table_section_index': 99,
            'definition_section': {'name': '.got.plt'}, 'role': 'local-definition', 'row': shared_got['row'],
        })
        companion = {
            'status': 'crt-startup-observed-with-boundaries', 'reader': {}, 'contract': {}, 'report': {},
            'source': {}, 'source_inputs': {}, 'products': {'candidate-static': {}, 'candidate-shared': {}},
            'measurement_reports': {},
            'account': {'identity_names': list(names), 'occurrences': observed, 'runtime_labels': []},
            'limits': list(selection.CRT_STARTUP_LIMITS),
        }
        accounting = {'identities': identities, 'placement_joins': [], 'occurrences': occurrences, 'blockers': blockers}
        original_accounting = copy.deepcopy(accounting)
        joins = selection.attach_native_crt_startup(accounting, companion)
        self.assertEqual(len(joins), 12)
        self.assertTrue(all(not row['unresolved'] for row in accounting['identities']))
        self.assertFalse(accounting['blockers'])
        self.assertEqual(
            next(row for row in joins if row['identity']['name'] == '_GLOBAL_OFFSET_TABLE_')['occurrence_indices'],
            [0, 12],
        )

        malformed = copy.deepcopy(companion)
        malformed['account']['occurrences'].pop()
        with self.assertRaisesRegex(selection.SelectionError, 'candidate occurrences differ'):
            selection.attach_native_crt_startup(original_accounting, malformed)

    def test_adapter_rejects_a_historical_collector_before_any_occurrence_join(self) -> None:
        reader = selection._crt_startup_reader()
        parent = selection._common_checkout(selection.ROOT) / '.work/x86_64/crt-startup-selector-tests'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            report_path = Path(temporary) / 'report.json'
            report_path.write_text('{}\n', encoding='utf-8')
            report = {
                'schema': reader.SCHEMA,
                'status': reader.STATUS,
                'image': '',
                'contract': reader.contract(ROOT),
                'collector_source': {'revision': 'historical', 'content_sha256': '0' * 64},
                'collector_files': {},
                'selected_files': {},
                'inputs_before': {},
                'inputs_after': {},
                'oracle': {},
                'oracle_static': {},
                'oracle_crt': {},
                'tools': {},
                'commands': [],
                'observations': {},
                'files': {},
            }
            source = {'revision': 'current', 'content_sha256': '1' * 64, 'clean': True}
            measurement = {
                'candidate_build': {
                    'revision': source['revision'], 'source_content_sha256': source['content_sha256'],
                },
                'reports': {
                    name: {'path': name, 'sha256': '0' * 64, 'size': 0, 'mode': 0}
                    for name in ('elf_report', 'base_inventory', 'static_preparation')
                },
            }
            with mock.patch.object(reader, 'validate_report', return_value=report), \
                 self.assertRaisesRegex(selection.SelectionError, 'collector source differs'):
                selection.native_crt_startup_adapter(
                    report_path, facts={}, measurement=measurement, paths={}, source=source,
                )


if __name__ == '__main__':
    unittest.main()
