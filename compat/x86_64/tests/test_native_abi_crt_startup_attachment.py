"""Focused finite joins for the installed CRT startup receipt."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


class NativeCrtStartupAttachmentTests(unittest.TestCase):
    _FROZEN_0E_ROOT = ROOT.parent / 'native_abi_protocol_integration'
    _FROZEN_0E_RECEIPT = (
        _FROZEN_0E_ROOT / '.work/x86_64/crt-startup-evidence/clean-0e7af481/report.json'
    )
    _E8_RECEIPT = (
        ROOT.parent / 'crt_startup_relocation_contract/.work/x86_64/crt-startup-evidence/'
        'clean-e8b8f385/report.json'
    )
    _B525_FACTS = (
        ROOT.parent / 'crt_startup_relocation_contract/.work/x86_64/crt-startup-inputs-b52538c5/'
        'historical-facts/report.json'
    )

    @staticmethod
    def _projection_cohort_inputs() -> dict[str, dict[str, object]]:
        return {
            name: {'path': name, 'sha256': '0' * 64, 'size': 0, 'mode': 0}
            for name in ('static_manifest', 'dynamic_manifest', 'dynamic_state')
        }

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

    def test_owner_rejects_weakened_descriptor_admission_contract(self) -> None:
        reader = selection._crt_startup_reader()
        contract = reader.contract(ROOT)
        for change in ('omit-admission', 'omit-direct', 'allow-success', 'omit-dso'):
            with self.subTest(change=change):
                altered = copy.deepcopy(contract)
                handoff = altered['descriptor_handoff']
                if change == 'omit-admission':
                    del handoff['admission']
                elif change == 'omit-direct':
                    handoff['admission']['entry_modes'] = ['kernel']
                elif change == 'allow-success':
                    handoff['admission']['rejection']['status'] = 0
                else:
                    del handoff['admission']['dso']
                with mock.patch.object(reader, 'contract', return_value=altered):
                    with self.assertRaisesRegex(selection.SelectionError, 'owner contract differs'):
                        selection._crt_startup_identity_names(reader)

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
            'cohort_inputs': self._projection_cohort_inputs(),
            'measurement_reports': {},
            'account': {'identity_names': list(names), 'occurrences': observed, 'runtime_labels': [],
                        'descriptor_handoff': {}},
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

    def _actual_e8_accounting_and_companion(self):
        """Project retained rows only; this does not admit the historical receipt."""
        if not self._E8_RECEIPT.is_file() or not self._B525_FACTS.is_file():
            self.skipTest('requires retained e8 CRT receipt and b525 complete ELF facts')
        self.assertEqual(
            hashlib.sha256(self._E8_RECEIPT.read_bytes()).hexdigest(),
            '856537c748375a3c8d52f7fe2ab83b5a3347fe316a30153033e1614dd030aa2c',
        )
        self.assertEqual(
            hashlib.sha256(self._B525_FACTS.read_bytes()).hexdigest(),
            'bb51b8d667ffaee89a8b32ae9762e79b198e0b020f26c547b962bbcff8302f6f',
        )
        receipt = json.loads(self._E8_RECEIPT.read_text())
        facts = json.loads(self._B525_FACTS.read_text())
        self.assertEqual(
            receipt['inputs_before']['historical_facts'],
            {
                'path': '.work/x86_64/crt-startup-inputs-b52538c5/historical-facts/report.json',
                'sha256': 'bb51b8d667ffaee89a8b32ae9762e79b198e0b020f26c547b962bbcff8302f6f',
                'size': 40347222,
            },
        )
        reader = selection._crt_startup_reader()
        names = selection._crt_startup_identity_names(reader)
        products = {name: {} for name in receipt['inputs_before']['startup_artifacts']}
        self.assertEqual(len(names), 12)
        self.assertEqual(len(products), 9)
        observed = selection._crt_startup_observed_rows(
            receipt['observations']['product_placements']['all_named_rows'], names, products,
        )
        self.assertEqual(len(observed), 44)
        self.assertEqual(
            len([row for row in observed if row['row']['name'] == '_GLOBAL_OFFSET_TABLE_']), 2,
        )
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        accounting = selection.account_placements(selection.expand_obligations(contract, inputs), facts)
        companion = {
            'status': 'crt-startup-observed-with-boundaries', 'reader': {}, 'contract': {}, 'report': {},
            'source': {},
            'source_inputs': {
                name: selection.file_identity(ROOT / name)
                for name in selection._crt_startup_source_files()
            },
            'products': products,
            'cohort_inputs': self._projection_cohort_inputs(),
            'measurement_reports': {},
            'account': {
                'identity_names': list(names), 'occurrences': observed,
                'runtime_labels': receipt['observations']['runtime_labels'],
                'descriptor_handoff': {},
            },
            'limits': list(selection.CRT_STARTUP_LIMITS),
        }
        return accounting, companion

    def test_retained_e8_projection_joins_all_actual_startup_roles(self) -> None:
        accounting, companion = self._actual_e8_accounting_and_companion()
        joins = selection.attach_native_crt_startup(accounting, companion)
        self.assertEqual(len(joins), 12)
        self.assertEqual(sum(join['owner_observation_count'] for join in joins), 44)
        records = {row['identity']['name']: row for row in accounting['identities']}
        occurrences = {row['index']: row for row in accounting['occurrences']}
        for join in joins:
            name = join['identity']['name']
            record = records[name]
            rows = [occurrences[index] for index in join['occurrence_indices']]
            self.assertNotIn(selection.CRT_STARTUP_RECEIPT_REQUIREMENT, record['unresolved'])
            if any(row['role'] == 'import' for row in rows):
                self.assertNotIn(selection.ORDINARY_IMPORT_REASON, record['unresolved'])
            for artifact_key in {row['artifact_key'] for row in rows if row['role'] == 'definition'}:
                self.assertNotIn(
                    f'candidate definition placement is not selected: {artifact_key}', record['unresolved'],
                )

    def test_actual_0e_projection_binds_only_the_measured_descriptor_transport(self) -> None:
        """Use frozen rows as a shape control, never as a current v2 receipt."""
        if not self._FROZEN_0E_RECEIPT.is_file():
            self.skipTest('requires frozen 0e CRT startup receipt')
        self.assertEqual(hashlib.sha256(self._FROZEN_0E_RECEIPT.read_bytes()).hexdigest(),
                         'e53fe18993303b6ea290773298fcc66ee198477431aaf57da39deb0358195bd6')
        report = json.loads(self._FROZEN_0E_RECEIPT.read_text())
        reader = selection._crt_startup_reader()
        handoff = reader.descriptor_handoff(
            report['observations']['product_relocations'], report['observations']['executables'])
        protocol = next(row for row in selection.load_contract()['private_protocols']
                        if row['id'] == 'loader-libc-tls-descriptor-v1')
        descriptor = selection.identity(reader.DESCRIPTOR)
        row = self._row(reader.DESCRIPTOR, binding='WEAK')
        occurrence = {
            'index': 0, 'artifact_key': 'dynamic-crabc-dynamic-attach.o', 'member_name': None,
            'member_index': None, 'member_occurrence': None, 'table': '.symtab',
            'table_section_index': 4, 'definition_section': None, 'role': 'import', 'row': row,
        }
        requirements = list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_REQUIREMENTS)
        accounting = {
            'identities': [{
                'identity': descriptor,
                'selection': {'disposition': 'private-resolution-operation',
                              'owner': 'loader-libc-tls-descriptor-v1', 'protocol': copy.deepcopy(protocol)},
                'unresolved': requirements[:],
            }],
            'placement_joins': [], 'occurrences': [occurrence],
            'private_protocol_joins': [{
                'identity': copy.deepcopy(descriptor), 'artifact_key': 'dynamic-crabc-dynamic-attach.o',
                'role': 'consumer-import', 'occurrence_indices': [0],
                'endpoint_kind': 'main-image-weak-got-transport',
                'signature_status': 'source-mapped-unverified', 'relocation_lifecycle_proven': False,
            }],
            'blockers': [{
                'code': 'identity-unresolved', 'identity': copy.deepcopy(descriptor), 'reason': requirement,
            } for requirement in requirements],
        }
        companion = {
            'status': 'crt-startup-observed-with-boundaries', 'reader': {}, 'contract': {}, 'report': {},
            'source': {}, 'source_inputs': {}, 'products': {}, 'cohort_inputs': {}, 'measurement_reports': {},
            'account': {'identity_names': list(reader.NAMES), 'occurrences': [], 'runtime_labels': [],
                        'descriptor_handoff': handoff},
            'limits': list(selection.CRT_STARTUP_LIMITS),
        }
        joins = selection.attach_native_crt_descriptor_handoff(accounting, companion)
        self.assertEqual(joins[0]['owned_main_slots'], {
            'owned-pie-normal': 1, 'owned-pie-empty': 1,
            'owned-non-pie-normal': 1, 'owned-non-pie-empty': 1,
        })
        self.assertEqual(joins[0]['requirements_discharged'],
                         list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_MEASURED_REQUIREMENTS))
        self.assertEqual(joins[0]['requirements_remaining'], requirements[2:])
        self.assertEqual(accounting['identities'][0]['unresolved'], requirements[2:])

        for mutate in (
            lambda value: value['executables']['static-normal']['slot'].append(
                copy.deepcopy(value['executables']['owned-pie-normal']['slot'][0])),
            lambda value: value['source_relocation'].update({'kind': 7}),
        ):
            with self.subTest(mutate=mutate):
                malformed = copy.deepcopy(companion)
                mutate(malformed['account']['descriptor_handoff'])
                with self.assertRaises(selection.SelectionError):
                    selection.attach_native_crt_descriptor_handoff(copy.deepcopy(accounting), malformed)

    def test_frozen_0e_v1_owner_is_projection_only_after_the_v2_contract_change(self) -> None:
        """The retained shape informs regressions but cannot admit v2 products."""
        if not self._FROZEN_0E_RECEIPT.is_file():
            self.skipTest('requires frozen 0e CRT startup receipt')
        self.assertEqual(
            hashlib.sha256(self._FROZEN_0E_RECEIPT.read_bytes()).hexdigest(),
            'e53fe18993303b6ea290773298fcc66ee198477431aaf57da39deb0358195bd6',
        )
        report = json.loads(self._FROZEN_0E_RECEIPT.read_text())
        inputs = report['inputs_before']
        paths = {
            'measurement_checkout': self._FROZEN_0E_ROOT,
            'elf_report': self._FROZEN_0E_ROOT / inputs['historical_facts']['path'],
            'base_inventory': self._FROZEN_0E_ROOT / '.work/x86_64/native-abi-inventory/clean-0e7af481/report.json',
            'static_preparation': self._FROZEN_0E_ROOT / inputs['preparation']['path'],
            'static_product': self._FROZEN_0E_ROOT / inputs['static_preparation']['primary']['path'],
            'dynamic_product': self._FROZEN_0E_ROOT / inputs['dynamic_product']['path'],
        }
        self.assertTrue(all(path.is_file() or path.is_dir() for path in paths.values()))
        facts = json.loads(paths['elf_report'].read_text())
        source = {**report['collector_source'], 'clean': True}
        measurement = {
            'candidate_build': {
                'revision': source['revision'], 'source_content_sha256': source['content_sha256'],
            },
            'reports': {
                name: selection.file_identity(paths[key])
                for name, key in (
                    ('elf_report', 'elf_report'), ('base_inventory', 'base_inventory'),
                    ('static_preparation', 'static_preparation'),
                )
            },
        }
        reader = selection._crt_startup_reader()
        # The receipt retains paths below the immutable integration worktree.
        # Redirecting the reader and selector roots is the test fixture's
        # read-only mount analogue; the owner replay itself remains real.
        with mock.patch.object(selection, 'ROOT', self._FROZEN_0E_ROOT), \
             mock.patch.object(reader, 'ROOT', self._FROZEN_0E_ROOT), \
             mock.patch.object(reader.qualification, 'ROOT', self._FROZEN_0E_ROOT), \
             self.assertRaises(reader.StartupEvidenceError):
            selection.native_crt_startup_adapter(
                self._FROZEN_0E_RECEIPT, facts=facts, measurement=measurement,
                paths=paths, source=source,
            )

    def test_adapter_rejects_a_historical_collector_before_any_occurrence_join(self) -> None:
        reader = selection._crt_startup_reader()
        parent = ROOT / '.work/x86_64/crt-startup-selector-tests'
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
            with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
                 mock.patch.object(reader, 'validate_report', return_value=report), \
                 self.assertRaisesRegex(selection.SelectionError, 'collector source differs'):
                selection.native_crt_startup_adapter(
                    report_path, facts={}, measurement=measurement, paths={}, source=source,
                )


class NativeCrtStartupCohortRecheckTests(unittest.TestCase):
    def setUp(self) -> None:
        common_checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
        parent = ROOT / '.work/x86_64/crt-startup-selector-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static = self.work / 'static'
        self.dynamic = self.work / 'dynamic'
        for path, payload in (
            (self.static / 'share/crabc/manifest.json', b'static manifest\n'),
            (self.static / 'bin/crabc-cc', b'static driver\n'),
            (self.static / 'usr/lib/libc.a', b'static libc\n'),
            (self.static / 'usr/lib/crt1.o', b'static crt1\n'),
            (self.static / 'usr/lib/Scrt1.o', b'static Scrt1\n'),
            (self.static / 'usr/lib/rcrt1.o', b'static rcrt1\n'),
            (self.dynamic / 'share/crabc/manifest.json', b'dynamic manifest\n'),
            (self.dynamic / 'share/crabc/dynamic-product-state.json', b'dynamic state\n'),
            (self.dynamic / 'share/crabc/libc-shared.provenance.json', b'dynamic provenance\n'),
            (self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n'),
            (self.dynamic / 'usr/lib/libc.so', b'dynamic libc\n'),
            (self.dynamic / 'usr/lib/crt1.o', b'dynamic crt1\n'),
            (self.dynamic / 'usr/lib/Scrt1.o', b'dynamic Scrt1\n'),
            (self.dynamic / 'usr/lib/crabc-dynamic-attach.o', b'dynamic attach\n'),
            (self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n'),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.base = self._write('base-inventory.json', b'base\n')
        self.elf = self._write('elf-facts.json', b'elf\n')
        self.preparation = self._write('preparation.json', b'preparation\n')
        self.report = self._write('crt-startup-report.json', b'{}\n')
        self.paths = {
            'measurement_checkout': ROOT, 'base_inventory': self.base, 'elf_report': self.elf,
            'static_preparation': self.preparation, 'static_product': self.static,
            'dynamic_product': self.dynamic,
        }
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.measurement = {
            'candidate_build': {
                'revision': self.source['revision'], 'source_content_sha256': self.source['content_sha256'],
            },
            'reports': {
                name: selection.file_identity(self.paths[name])
                for name in ('elf_report', 'base_inventory', 'static_preparation')
            },
        }
        products = selection._crt_startup_product_identities(self.paths)
        self.facts = {'artifacts': {name: {'identity': value} for name, value in products.items()}}

    def _write(self, name: str, payload: bytes) -> Path:
        path = self.work / name
        path.write_bytes(payload)
        return path

    def _companion(self) -> dict[str, object]:
        return {
            'products': selection._crt_startup_product_identities(self.paths),
            'cohort_inputs': selection._crt_startup_cohort_inputs(self.paths),
            'measurement_reports': copy.deepcopy(self.measurement['reports']),
            'report': selection.file_identity(self.report),
        }

    def test_crt_recheck_seals_each_mode_bearing_metadata_input(self) -> None:
        targets = {
            'static_manifest': self.static / 'share/crabc/manifest.json',
            'dynamic_manifest': self.dynamic / 'share/crabc/manifest.json',
            'dynamic_state': self.dynamic / 'share/crabc/dynamic-product-state.json',
        }
        for name, path in targets.items():
            with self.subTest(name=name):
                companion = self._companion()
                original_bytes = path.read_bytes()
                original_mode = path.stat().st_mode
                if name == 'dynamic_manifest':
                    os.chmod(path, original_mode ^ 0o100)
                else:
                    path.write_bytes(original_bytes + b'changed after startup replay\n')
                with mock.patch.object(selection, 'selection_source', return_value=self.source), \
                     self.assertRaisesRegex(selection.SelectionError, f'CRT startup {name} changed'):
                    selection._recheck_runtime_receipt_cohort(
                        paths=self.paths, facts=self.facts, measurement=self.measurement, source=self.source,
                        registry=None, pthread=None, crt_startup=companion,
                    )
                path.write_bytes(original_bytes)
                os.chmod(path, original_mode)


if __name__ == '__main__':
    unittest.main()
