"""Focused selector joins for the finite loader and pthread runtime receipts."""
from __future__ import annotations

import copy
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


class RuntimeReceiptAttachmentTests(unittest.TestCase):
    def setUp(self):
        # The canonical Docker dispatcher mounts a linked worktree at
        # /workspace while preserving its host common Git directory. The
        # adapter admits work paths through this existing seam; make the
        # focused fixture exercise the container-visible checkout root rather
        # than the host-only Git path.
        common_checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
        parent = ROOT / '.work/x86_64/native-abi-runtime-receipt-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static = self.work / 'static'
        self.dynamic = self.work / 'dynamic'
        for directory in (self.static, self.dynamic):
            directory.mkdir()
        self._write(self.static / 'share/crabc/manifest.json', b'static manifest\n')
        self._write(self.static / 'bin/crabc-cc', b'static driver\n')
        self._write(self.static / 'usr/lib/libc.a', b'static libc\n')
        self._write(self.dynamic / 'share/crabc/manifest.json', b'dynamic manifest\n')
        self._write(self.dynamic / 'share/crabc/dynamic-product-state.json', b'dynamic state\n')
        self._write(self.dynamic / 'share/crabc/loader.provenance.json', b'loader provenance\n')
        self._write(self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n')
        self._write(self.dynamic / 'usr/lib/libc.so', b'dynamic libc\n')
        self._write(self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n')
        self.base = self._write(self.work / 'base-inventory.json', b'base\n')
        self.elf = self._write(self.work / 'elf-facts.json', b'elf\n')
        self.preparation = self._write(self.work / 'preparation.json', b'preparation\n')
        self.registry_report_path = self._write(self.work / 'registry-report.json', b'{}\n')
        self.pthread_report_path = self._write(self.work / 'pthread-report.json', b'{}\n')
        self.paths = {
            'measurement_checkout': ROOT,
            'base_inventory': self.base,
            'elf_report': self.elf,
            'static_preparation': self.preparation,
            'static_product': self.static,
            'dynamic_product': self.dynamic,
        }
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.measurement = {
            'candidate_build': {
                'revision': self.source['revision'],
                'source_content_sha256': self.source['content_sha256'],
            },
            'reports': {
                'elf_report': selection.file_identity(self.elf),
                'base_inventory': selection.file_identity(self.base),
                'static_preparation': selection.file_identity(self.preparation),
            },
        }
        self.current = selection._current_product_identities(self.paths)
        self.facts = {
            'artifacts': {
                'candidate-static': {'identity': self.current['static_libc']},
                'candidate-shared': {'identity': self.current['dynamic_libc']},
                'candidate-loader': {'identity': self.current['dynamic_loader']},
            },
        }

    def _write(self, path: Path, contents: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    @staticmethod
    def _runtime_row():
        return {
            'type': 'NOTYPE', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': 'UND',
            'size_bytes': 0, 'value': '0000000000000000', 'version': None, 'version_default': False,
        }

    def registry_report(self):
        imports = {
            name: {table: self._runtime_row() for table in selection.runtime_registry_evidence.SYMBOL_TABLES}
            for name in selection.runtime_registry_evidence.RESOLVERS
        }
        return {
            'schema': selection.runtime_registry_evidence.SCHEMA,
            'target': selection.runtime_registry_evidence.TARGET,
            'status': {'family_completion': False, 'promotion_ready': False},
            'source': copy.deepcopy(self.source),
            'source_files': {},
            'inputs': {
                'contract': {'id': 'x86-loader-runtime-registry-private-resolution', 'status': 'implemented-unqualified'},
                'source': copy.deepcopy(self.source),
                'source_resolution': {}, 'source_files': {}, 'elf_report': selection.file_identity(self.elf),
                'imports': imports,
                'loader': {
                    'loader': self.current['dynamic_loader'],
                    'feature': selection.runtime_registry_evidence.FEATURE,
                    'provenance': selection.file_identity(self.dynamic / 'share/crabc/loader.provenance.json'),
                },
                'products': {
                    'static': self.current['static_libc'],
                    'dynamic_libc': self.current['dynamic_libc'],
                    'dynamic_loader': self.current['dynamic_loader'],
                },
            },
            'dlfcn': {}, 'fork': {}, 'timer_reset': {},
        }

    def pthread_report(self):
        retained = {
            'static_manifest': 'retained/static-manifest',
            'static_driver': 'retained/static-driver',
            'static_libc': 'retained/static-libc',
            'dynamic_manifest': 'retained/dynamic-manifest',
            'dynamic_state': 'retained/dynamic-state',
            'dynamic_driver': 'retained/dynamic-driver',
            'dynamic_libc': 'retained/dynamic-libc',
            'dynamic_loader': 'retained/dynamic-loader',
        }
        artifacts = {retained[name]: copy.deepcopy(self.current[name]) for name in retained}
        aliases = [{'public': public, 'provider': provider}
                   for public, provider in selection.pthread_alias_evidence.ALIASES]
        shapes = {
            placement: {public: ['FUNC', 'WEAK', 'DEFAULT']
                        for public, _ in selection.pthread_alias_evidence.ALIASES}
            for placement in ('dynamic', 'shared', 'static')
        }
        definitions = {
            placement: {
                public: {'alias': {'name': public}, 'provider': {'name': provider}}
                for public, provider in selection.pthread_alias_evidence.ALIASES
            }
            for placement in ('shared', 'static')
        }
        definitions['musl_shared'] = {}
        definitions['musl_static'] = {}
        return {
            'schema': selection.pthread_alias_evidence.SCHEMA,
            'status': selection.pthread_alias_evidence.STATUS,
            'component': selection.pthread_alias_evidence.COMPONENT,
            'public_support': False, 'family_complete': False, 'promotion_ready': False,
            'collection': {}, 'collector': {}, 'inputs': {}, 'oracle': {}, 'historical_evidence': {},
            'commands': {}, 'elf_headers': {}, 'runtime_roots': {},
            'selected_source': {
                'revision': self.source['revision'], 'tree': 'c' * 40,
                'source_sha256': self.source['content_sha256'], 'component_sha256': 'd' * 64, 'files': {},
            },
            'selected_products': {
                'anchor': {},
                'static': {
                    'manifest': retained['static_manifest'], 'driver': retained['static_driver'],
                    'libc': retained['static_libc'], 'original_paths': {},
                },
                'dynamic': {
                    'manifest': retained['dynamic_manifest'], 'state': retained['dynamic_state'],
                    'driver': retained['dynamic_driver'], 'libc': retained['dynamic_libc'],
                    'loader': retained['dynamic_loader'], 'original_paths': {},
                },
            },
            'coverage': selection.pthread_alias_evidence._coverage(),
            'artifacts': artifacts,
            'alias_observations': {
                'aliases': aliases, 'alias_shapes': shapes, 'same_definition': definitions,
                'mq_notify_public_detach': {
                    'musl': {},
                    'candidate': {'member': '/retained/usr/lib/libc.a(mq_notify.o)', 'relocation_section': '.rela.text.notify_start'},
                },
                'application_public_override': {},
            },
        }

    def test_registry_adapter_replays_the_owner_and_binds_current_facts_and_products(self):
        report = self.registry_report()
        with mock.patch.object(selection.runtime_registry_evidence, 'validate_report', return_value=report) as replay:
            result = selection.loader_runtime_registry_adapter(
                self.registry_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        replay.assert_called_once_with(
            self.registry_report_path,
            base_inventory=self.base, elf_report=self.elf, static_preparation=self.preparation,
            static_product=self.static, dynamic_product=self.dynamic,
        )
        self.assertEqual(result['status'], 'private-runtime-registry-observed-with-boundaries')
        self.assertEqual(set(result['inputs']['imports']), set(selection.runtime_registry_evidence.RESOLVERS))

    def test_registry_adapter_rejects_a_substituted_selected_product(self):
        report = self.registry_report()
        report['inputs']['products']['dynamic_libc']['sha256'] = '0' * 64
        with mock.patch.object(selection.runtime_registry_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic libc bytes or mode differ'):
            selection.loader_runtime_registry_adapter(
                self.registry_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def registry_accounting(self):
        protocol = next(row for row in selection.load_contract()['private_protocols']
                        if row['id'] == 'loader-runtime-operations')
        identities, occurrences, joins, blockers = [], [], [], []
        for name in selection.runtime_registry_evidence.RESOLVERS:
            item = {
                'identity': selection.identity(name), 'selection': {
                    'disposition': 'private-resolution-operation', 'owner': 'loader-runtime-operations',
                    'protocol': copy.deepcopy(protocol),
                },
                'unresolved': list(selection.RUNTIME_REGISTRY_REQUIREMENTS),
            }
            identities.append(item)
            indices = []
            for table in selection.runtime_registry_evidence.SYMBOL_TABLES:
                index = len(occurrences)
                indices.append(index)
                occurrences.append({
                    'index': index, 'artifact_key': 'candidate-shared', 'table': table, 'role': 'import',
                    'row': {'name': name, 'version': None, 'version_default': False, **self._runtime_row()},
                    'accounting': {
                        'disposition': 'private-resolution-operation', 'owner': 'loader-runtime-operations',
                        'scope': 'candidate-shared', 'resolution': {
                            'kind': 'source-dispatch-operation', 'operation': {'name': name},
                        }, 'resolution_proven': False,
                    },
                })
            joins.append({
                'identity': selection.identity(name), 'artifact_key': 'candidate-shared', 'role': 'consumer-import',
                'occurrence_indices': indices, 'endpoint_kind': 'source-dispatch-operation',
                'signature_status': protocol['signature_status'], 'relocation_lifecycle_proven': False,
            })
            blockers.extend({
                'code': 'identity-unresolved', 'identity': selection.identity(name), 'reason': reason,
            } for reason in selection.RUNTIME_REGISTRY_REQUIREMENTS)
        return {
            'identities': identities, 'occurrences': occurrences, 'private_protocol_joins': joins,
            'blockers': blockers,
        }

    def test_registry_join_discharges_only_its_nine_exact_protocol_requirements(self):
        report = self.registry_report()
        with mock.patch.object(selection.runtime_registry_evidence, 'validate_report', return_value=report):
            companion = selection.loader_runtime_registry_adapter(
                self.registry_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        accounting = self.registry_accounting()
        joins = selection.attach_loader_runtime_registry(accounting, companion)
        self.assertEqual(len(joins), 9)
        self.assertFalse(accounting['blockers'])
        self.assertTrue(all(not row['unresolved'] for row in accounting['identities']))
        self.assertTrue(all(row['accounting']['resolution_proven'] for row in accounting['occurrences']))
        self.assertTrue(all(row['relocation_lifecycle_proven'] for row in accounting['private_protocol_joins']))

    def test_registry_join_rejects_an_omitted_symtab_occurrence(self):
        report = self.registry_report()
        with mock.patch.object(selection.runtime_registry_evidence, 'validate_report', return_value=report):
            companion = selection.loader_runtime_registry_adapter(
                self.registry_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        accounting = self.registry_accounting()
        accounting['occurrences'].pop(1)
        with self.assertRaisesRegex(selection.SelectionError, 'selected occurrences differ'):
            selection.attach_loader_runtime_registry(accounting, companion)

    def test_pthread_adapter_replays_the_owner_and_binds_each_selected_product_file(self):
        report = self.pthread_report()
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report) as replay:
            result = selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        replay.assert_called_once_with(self.pthread_report_path)
        self.assertEqual(result['status'], 'pthread-alias-contract-observed-with-boundaries')
        self.assertEqual(len(result['coverage']['aliases']), 17)

    def test_pthread_adapter_rejects_a_replaced_dynamic_loader(self):
        report = self.pthread_report()
        retained = report['selected_products']['dynamic']['loader']
        report['artifacts'][retained]['sha256'] = '0' * 64
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic_loader bytes or mode differ'):
            selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def pthread_accounting(self):
        report = self.pthread_report()
        identities, occurrences, placement_joins = [], [], []
        for public, _provider in selection.pthread_alias_evidence.ALIASES:
            identities.append({
                'identity': selection.identity(public),
                'selection': {'disposition': 'public-provider', 'owner': 'checked-header-provider-routing'},
                'unresolved': [selection.ORDINARY_IMPORT_REASON] if public == 'pthread_detach' else [],
            })
            for artifact_key, table in (('candidate-static', '.symtab'), ('candidate-shared', '.dynsym')):
                index = len(occurrences)
                occurrences.append({
                    'index': index, 'artifact_key': artifact_key, 'table': table, 'role': 'definition',
                    'row': {'name': public, 'version': None, 'version_default': False,
                            'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'},
                })
                placement_joins.append({
                    'identity': selection.identity(public), 'artifact_key': artifact_key,
                    'placement_observed': True, 'definition_count': 1, 'occurrence_indices': [index],
                    'metadata_differences': [{'occurrence_index': index, 'fields': []}],
                })
            index = len(occurrences)
            occurrences.append({
                'index': index, 'artifact_key': 'candidate-shared', 'table': '.symtab', 'role': 'definition',
                'row': {'name': public, 'version': None, 'version_default': False,
                        'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'},
            })
        detach_import = len(occurrences)
        occurrences.append({
            'index': detach_import, 'artifact_key': 'candidate-static', 'table': '.symtab', 'role': 'import',
            'member_name': 'mq_notify.o',
            'row': {'name': 'pthread_detach', 'version': None, 'version_default': False,
                    'type': 'NOTYPE', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'},
        })
        return {
            'identities': identities, 'occurrences': occurrences, 'placement_joins': placement_joins,
            'blockers': [{'code': 'identity-unresolved', 'identity': selection.identity('pthread_detach'),
                          'reason': selection.ORDINARY_IMPORT_REASON}],
            'report': report,
        }

    def test_pthread_join_keeps_private_provider_names_out_of_selection_and_clears_only_mq_notify(self):
        report = self.pthread_report()
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report):
            companion = selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        accounting = self.pthread_accounting()
        joins = selection.attach_pthread_alias_contract(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['aliases']), 17)
        self.assertTrue(joins[0]['mq_notify_public_detach']['public_detach_relocation_proven'])
        detach = next(row for row in accounting['identities'] if row['identity']['name'] == 'pthread_detach')
        self.assertNotIn(selection.ORDINARY_IMPORT_REASON, detach['unresolved'])
        self.assertFalse(accounting['blockers'])
        self.assertNotIn('__pthread_detach', {row['identity']['name'] for row in accounting['identities']})

    def test_pthread_join_retains_the_generic_import_reason_for_a_foreign_member(self):
        report = self.pthread_report()
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report):
            companion = selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        accounting = self.pthread_accounting()
        next(row for row in accounting['occurrences'] if row.get('member_name') == 'mq_notify.o')['member_name'] = 'other.o'
        joins = selection.attach_pthread_alias_contract(accounting, companion)
        self.assertFalse(joins[0]['mq_notify_public_detach']['public_detach_relocation_proven'])
        detach = next(row for row in accounting['identities'] if row['identity']['name'] == 'pthread_detach')
        self.assertIn(selection.ORDINARY_IMPORT_REASON, detach['unresolved'])

    def test_runtime_reports_are_independently_optional_at_the_public_cli(self):
        """Each owning reader has its own current-product admission boundary."""
        reconstructed = {
            'identities': [], 'occurrences': [],
            'closure': {'blockers': [], 'complete': False},
        }
        base = [
            'validate-report', str(self.work / 'selection.json'),
            '--measurement-checkout', str(ROOT), '--elf-facts', str(self.elf),
            '--base-inventory', str(self.base), '--static-product', str(self.static),
            '--dynamic-product', str(self.dynamic), '--static-preparation', str(self.preparation),
        ]
        for option, report in (
            ('--loader-runtime-registry-report', self.registry_report_path),
            ('--pthread-alias-contract-report', self.pthread_report_path),
        ):
            with self.subTest(option=option), \
                 mock.patch.object(selection, 'validate_report', return_value=reconstructed) as replay, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(selection.main([*base, option, str(report)]), 0)
            kwargs = replay.call_args.kwargs
            self.assertEqual(kwargs[option[2:].replace('-', '_')], report)
            other = ('pthread_alias_contract_report' if option == '--loader-runtime-registry-report'
                     else 'loader_runtime_registry_report')
            self.assertIsNone(kwargs[other])

    def test_runtime_attachment_rechecks_the_product_cohort_after_component_joins(self):
        registry = self.registry_report()
        pthread = self.pthread_report()
        with (
            mock.patch.object(selection.runtime_registry_evidence, 'validate_report', return_value=registry),
            mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=pthread),
        ):
            registry_companion = selection.loader_runtime_registry_adapter(
                self.registry_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
            pthread_companion = selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        (self.dynamic / 'usr/lib/libc.so').write_bytes(b'replaced after reader\n')
        with mock.patch.object(selection, 'selection_source', return_value=self.source), \
             self.assertRaisesRegex(selection.SelectionError, 'candidate-shared.*bytes or mode differ'):
            selection._recheck_runtime_receipt_cohort(
                paths=self.paths, facts=self.facts, measurement=self.measurement, source=self.source,
                registry=registry_companion, pthread=pthread_companion,
            )


if __name__ == '__main__':
    unittest.main()
