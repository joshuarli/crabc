"""Focused final attachment for the one RuntimeV1 descriptor occurrence."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


class RuntimeV1DescriptorLifecycleAttachmentTests(unittest.TestCase):
    @staticmethod
    def _identity(name: str = '__crabc_x86_64_loader_tls_runtime_v1') -> dict[str, object]:
        return {'name': name, 'version': None, 'version_default': False}

    @staticmethod
    def _row() -> dict[str, object]:
        return {
            'name': '__crabc_x86_64_loader_tls_runtime_v1',
            'type': 'NOTYPE', 'binding': 'WEAK', 'visibility': 'DEFAULT',
            'section_index': 'UND', 'size_bytes': 0, 'value': '0000000000000000',
            'version': None, 'version_default': False,
        }

    def _accounting(self) -> dict[str, object]:
        protocol = next(row for row in selection.load_contract()['private_protocols']
                        if row['id'] == 'loader-libc-tls-descriptor-v1')
        identity = self._identity()
        # 30634 is only the sealed 6bd9-style fixture index. The coordinator
        # locates the descriptor structurally and never relies on this number.
        occurrence = {
            'index': 30634, 'artifact_key': 'dynamic-crabc-dynamic-attach.o',
            'member_name': None, 'member_index': None, 'member_occurrence': None,
            'table': '.symtab', 'definition_section': None, 'role': 'import',
            'row': self._row(),
            'accounting': {
                'disposition': 'private-resolution-operation',
                'owner': 'loader-libc-tls-descriptor-v1',
                'scope': 'dynamic-crabc-dynamic-attach.o',
            },
        }
        remaining = [
            'pointer lifetime, worker mapping generation and fork ownership evidence',
            'release READY ordering and malformed descriptor rejection receipt',
        ]
        return {
            'identities': [{
                'identity': identity,
                'selection': {
                    'disposition': 'private-resolution-operation',
                    'owner': 'loader-libc-tls-descriptor-v1',
                    'protocol': copy.deepcopy(protocol),
                },
                'unresolved': remaining[:],
            }],
            'placement_joins': [], 'occurrences': [occurrence],
            'private_protocol_joins': [{
                'identity': copy.deepcopy(identity),
                'artifact_key': 'dynamic-crabc-dynamic-attach.o',
                'role': 'consumer-import', 'occurrence_indices': [30634],
                'endpoint_kind': 'main-image-weak-got-transport',
                'signature_status': 'source-mapped-unverified',
                'relocation_lifecycle_proven': True,
            }],
            'blockers': [{
                'code': 'identity-unresolved', 'identity': copy.deepcopy(identity), 'reason': reason,
            } for reason in remaining],
        }

    @staticmethod
    def _file(label: str, *, mode: int = 0o644) -> dict[str, object]:
        return {'path': 'retained/' + label, 'sha256': 'a' * 64, 'size': len(label), 'mode': mode}

    def _runtime_admission(self, products: dict[str, dict[str, object]]) -> dict[str, object]:
        reader = selection._crt_startup_reader()
        policy = reader.expected_contract()['descriptor_handoff']['runtime_admission']
        attachment = products['dynamic-crabc-dynamic-attach.o']
        static = products['candidate-static']
        source_order = {
            'scope': 'selected source release/acquire order and CRT attachment route; no compiler or concurrency proof',
            'builder': {'attachment': 'direct PIC object', 'loader_feature': 'x86_64-owned-dynamic-runtime'},
            'publisher': {'state_store': 'Release READY last'},
            'consumer': {
                'state_load': 'Acquire READY before TLS coordinate reads',
                'bodies': copy.deepcopy(policy['consumer_bodies']),
            },
            'crt': {'attachment': 'before __libc_start_main'},
        }
        functions = [
            {
                'name': reader.ATTACH, 'input_owner': '/workspace/retained/attachment',
                'source_binding': 'GLOBAL', 'source_visibility': 'DEFAULT',
                'final_binding': 'GLOBAL', 'final_visibility': 'DEFAULT',
            },
            {
                'name': reader.RECORD, 'input_owner': '/workspace/retained/attachment',
                'source_binding': 'GLOBAL', 'source_visibility': 'HIDDEN',
                'final_binding': 'LOCAL', 'final_visibility': 'HIDDEN',
            },
            *[
                {
                    'name': body['symbol'], 'input_owner': '/workspace/retained/attachment',
                    'source_function': body['source_function'],
                    'source_binding': body['source_binding'], 'source_visibility': body['source_visibility'],
                    'final_binding': body['final_binding'], 'final_visibility': body['final_visibility'],
                }
                for body in policy['consumer_bodies']
            ],
        ]
        cells = []
        for cell in policy['cells']:
            if cell['define'] == '':
                definition = {'descriptor': {
                    'name': reader.DESCRIPTOR, 'type': 'OBJECT', 'binding': 'GLOBAL',
                    'visibility': 'DEFAULT', 'size': 72,
                }}
            elif cell['define'] == 'CRABC_RUNTIME_CASE_ABSENT':
                definition = {'descriptor': None}
            else:
                definition = {
                    'descriptor': {
                        'name': reader.DESCRIPTOR, 'binding': 'GLOBAL', 'visibility': 'DEFAULT',
                        'section': 4, 'value': 1,
                    },
                    'backing': {
                        'name': 'runtime_unaligned_record', 'type': 'OBJECT', 'binding': 'LOCAL',
                        'section': 4, 'value': 0, 'size': 73,
                    },
                }
            cells.append({
                'label': cell['name'], 'define': cell['define'],
                'probe_object': {'path': 'retained/' + cell['name'] + '.o', 'sha256': 'c' * 64, 'size': 1},
                'probe_definition': definition,
                'endpoint': {'path': 'retained/' + cell['name'], 'sha256': 'd' * 64, 'size': 1},
                'map': {'path': 'retained/' + cell['name'] + '.map', 'sha256': 'e' * 64, 'size': 1},
                'relation': {
                    'attachment': '/workspace/retained/attachment',
                    'static_libc': '/workspace/retained/libc.a',
                    'probe_object': '/workspace/retained/' + cell['name'] + '.o',
                    'functions': copy.deepcopy(functions),
                },
                'streams': {'status': 0, 'stdout': '', 'stderr': ''},
            })
        return {
            'scope': 'selected attachment local admission only; source order is lexical and no concurrent publication claim is made',
            'source': {'path': 'retained/runtime-probe.c', 'sha256': 'f' * 64, 'size': 1},
            'inputs': {
                'attachment': {
                    'artifact': 'dynamic-crabc-dynamic-attach.o',
                    'identity': {key: attachment[key] for key in ('path', 'sha256', 'size')},
                    'mode': attachment['mode'],
                },
                'static_libc': {
                    'artifact': 'candidate-static',
                    'identity': {key: static[key] for key in ('path', 'sha256', 'size')},
                    'mode': static['mode'],
                },
            },
            'source_order': source_order,
            'value_cases': copy.deepcopy(policy['value_cases']),
            'cells': cells,
        }

    def _companions(self) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]],
                                    list[dict[str, object]], list[dict[str, object]]]:
        reader = selection._crt_startup_reader()
        source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        products = {
            'candidate-static': self._file('static-libc'),
            'candidate-shared': self._file('shared-libc'),
            'candidate-loader': self._file('loader'),
            'static-crt1.o': self._file('static-crt1'),
            'static-Scrt1.o': self._file('static-scrt1'),
            'static-rcrt1.o': self._file('static-rcrt1'),
            'dynamic-crt1.o': self._file('dynamic-crt1'),
            'dynamic-Scrt1.o': self._file('dynamic-scrt1'),
            'dynamic-crabc-dynamic-attach.o': self._file('dynamic-attach'),
        }
        cohort = {
            'static_manifest': self._file('static-manifest'),
            'dynamic_manifest': self._file('dynamic-manifest'),
            'dynamic_state': self._file('dynamic-state'),
        }
        measurement = {
            'elf_report': self._file('elf-report'),
            'base_inventory': self._file('base-inventory'),
            'static_preparation': self._file('static-preparation'),
        }
        crt = {
            'status': 'crt-startup-observed-with-boundaries', 'reader': {}, 'contract': {},
            'report': self._file('crt-report'), 'source': copy.deepcopy(source),
            'source_inputs': {
                name: selection.file_identity(ROOT / name)
                for name in selection._crt_startup_source_files()
            },
            'products': copy.deepcopy(products), 'cohort_inputs': copy.deepcopy(cohort),
            'measurement_reports': copy.deepcopy(measurement),
            'account': {
                'identity_names': list(reader.NAMES), 'occurrences': [], 'runtime_labels': [],
                'descriptor_handoff': {},
                'descriptor_runtime_admission': self._runtime_admission(products),
            },
            'limits': list(selection.CRT_STARTUP_LIMITS),
        }
        worker_products = {
            'static_manifest': copy.deepcopy(cohort['static_manifest']),
            'static_libc': copy.deepcopy(products['candidate-static']),
            'dynamic_manifest': copy.deepcopy(cohort['dynamic_manifest']),
            'dynamic_state': copy.deepcopy(cohort['dynamic_state']),
            'dynamic_libc': copy.deepcopy(products['candidate-shared']),
            'dynamic_loader': copy.deepcopy(products['candidate-loader']),
        }
        runtime = {
            'application_cells': {row['label']: dict(row) for row in selection.prepared_worker_evidence.runtime_cells()},
            'source_tests': list(selection.prepared_worker_evidence.UNIT_TESTS),
            'source_test_executable': 'loader-tests',
            'source_root': selection.prepared_worker_evidence.UNIT_ROOT,
            'oracle_boundary': 'Common installed C TLS/callback lifecycle only; no musl token/view/unmap-layout claim.',
            'owned_boundary': 'Live TLS and retained views mapped until quiescence; joined/reaped TLS and views unmapped.',
        }
        worker = {
            'status': 'prepared-worker-tls-observed-with-boundaries', 'reader': {}, 'contract': {},
            'report': self._file('worker-report'), 'source': copy.deepcopy(source),
            'products': worker_products, 'measurement_reports': copy.deepcopy(measurement),
            'account': {
                'elf': {
                    'operations': {}, 'descriptor_named_elf_observations': [],
                    'descriptor_installed_import_required': False, 'legacy_named_shared_loader_rows': [],
                },
                'source': copy.deepcopy(selection.prepared_worker_evidence.account_source(ROOT)),
                'worker_relocations': {}, 'runtime': runtime,
            },
            'limits': list(selection.PREPARED_WORKER_TLS_LIMITS),
        }
        identity = self._identity()
        startup_joins = [{
            'identity': {'name': name, 'version': None, 'version_default': False},
            'occurrence_indices': [], 'owner_observation_count': 0, 'current_source_product_cohort': True,
        } for name in reader.NAMES]
        handoff = [{
            'identity': copy.deepcopy(identity), 'source_occurrence_indices': [30634],
            'owned_main_slots': {}, 'non_owned_main_slots_absent': True,
            'requirements_discharged': list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_MEASURED_REQUIREMENTS),
            'requirements_remaining': list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_FINAL_REQUIREMENTS),
        }]
        worker_joins = [{
            'operations': [], 'legacy_replacements': [],
            'descriptor': {
                'identity': copy.deepcopy(identity), 'contract_geometry': {
                    'size_bytes': 72, 'alignment_bytes': 8,
                    'role': 'private-process-lifetime-initial-tls-provenance',
                },
                'source_provenance_verified': True, 'installed_import_required': False,
                'transport_occurrence_indices': [30634], 'provider_occurrence_indices': [],
                'consumer_occurrence_indices': [30634], 'requirements_discharged': [],
                'requirements_remaining': list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_REQUIREMENTS),
            },
        }]
        return crt, worker, startup_joins, handoff, worker_joins

    def test_paired_runtimev1_attachment_is_the_only_descriptor_final_discharge(self) -> None:
        crt, worker, startup, handoff, worker_joins = self._companions()
        for crt_companion, worker_companion in ((None, None), (crt, None), (None, worker)):
            with self.subTest(crt=crt_companion is not None, worker=worker_companion is not None):
                accounting = self._accounting()
                joins = selection.attach_runtimev1_descriptor_lifecycle(
                    accounting, crt_companion=crt_companion, prepared_worker_companion=worker_companion,
                    crt_startup_joins=startup, crt_descriptor_handoff_joins=handoff,
                    prepared_worker_tls_joins=worker_joins,
                )
                self.assertEqual(joins, [])
                self.assertEqual(len(accounting['identities'][0]['unresolved']), 2)
                self.assertEqual(len(accounting['blockers']), 2)

    def test_paired_runtimev1_attachment_binds_one_current_descriptor_occurrence(self) -> None:
        accounting = self._accounting()
        crt, worker, startup, handoff, worker_joins = self._companions()
        joins = selection.attach_runtimev1_descriptor_lifecycle(
            accounting, crt_companion=crt, prepared_worker_companion=worker,
            crt_startup_joins=startup, crt_descriptor_handoff_joins=handoff,
            prepared_worker_tls_joins=worker_joins,
        )
        self.assertEqual(accounting['identities'][0]['unresolved'], [])
        self.assertEqual(accounting['blockers'], [])
        self.assertEqual(len(accounting['identities']), 1)
        self.assertEqual(len(accounting['occurrences']), 1)
        self.assertEqual(len(accounting['private_protocol_joins']), 1)
        self.assertEqual(joins, [{
            'identity': self._identity(), 'source_occurrence_indices': [30634],
            'consumer_occurrence_indices': [30634], 'provider_occurrence_indices': [],
            'requirements_discharged': list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_FINAL_REQUIREMENTS),
            'requirements_remaining': [],
            'crt_runtime_admission': {
                'value_cases': crt['account']['descriptor_runtime_admission']['value_cases'],
                'cells': ['descriptor-runtime-matrix', 'descriptor-runtime-absent',
                          'descriptor-runtime-unaligned-record'],
            },
            'worker_lifecycle': {
                'post_fork_generation': worker['account']['source']['post_fork_generation'],
                'runtime_source_tests': worker['account']['runtime']['source_tests'],
            },
            'current_source_product_cohort': True,
        }])

    def test_paired_runtimev1_attachment_skips_unnamed_null_and_section_rows(self) -> None:
        """Complete ELF accounting retains raw null and section rows."""
        accounting = self._accounting()
        # These rows match the fresh 825 complete-facts shapes: the first
        # candidate-loader .dynsym row is null, and the dynamic attachment
        # keeps its local SECTION row in .symtab.
        null = {
            'index': 30635, 'artifact_key': 'candidate-loader',
            'member_name': None, 'member_index': None, 'member_occurrence': None,
            'table': '.dynsym', 'table_section_index': 3, 'definition_section': None,
            'role': 'unnamed',
            'row': {
                'name': None, 'raw_name': None, 'row_index': 0,
                'type': 'NOTYPE', 'binding': 'LOCAL', 'visibility': 'DEFAULT',
                'section_index': 'UND', 'size': '0', 'size_bytes': 0,
                'value': '0000000000000000', 'version': None, 'version_default': False,
                'version_index': None, 'common_alignment': None, 'other': None,
                'raw': '     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND ',
            },
            'accounting': {'disposition': 'unnamed-observation', 'owner': 'candidate'},
        }
        section = {
            'index': 30636, 'artifact_key': 'dynamic-crabc-dynamic-attach.o',
            'member_name': None, 'member_index': None, 'member_occurrence': None,
            'table': '.symtab', 'table_section_index': 16, 'definition_section': {'name': '.text'},
            'role': 'unsupported',
            'row': {
                'name': '.text._RNvNtCsdlKvXcqhVMX_24crabc_dynamic_attachment21loader_tls_runtime_v122current_thread_pointer',
                'raw_name': '.text._RNvNtCsdlKvXcqhVMX_24crabc_dynamic_attachment21loader_tls_runtime_v122current_thread_pointer',
                'row_index': 2, 'type': 'SECTION', 'binding': 'LOCAL', 'visibility': 'DEFAULT',
                'section_index': '5', 'size': '0', 'size_bytes': 0,
                'value': '0000000000000000', 'version': None, 'version_default': False,
                'version_index': None, 'common_alignment': None, 'other': None,
                'raw': '     2: 0000000000000000     0 SECTION LOCAL  DEFAULT    5 .text._RNvNtCsdlKvXcqhVMX_24crabc_dynamic_attachment21loader_tls_runtime_v122current_thread_pointer',
            },
            'accounting': {'disposition': 'unresolved', 'owner': None},
        }
        accounting['occurrences'].extend((null, section))
        crt, worker, startup, handoff, worker_joins = self._companions()
        joins = selection.attach_runtimev1_descriptor_lifecycle(
            accounting, crt_companion=crt, prepared_worker_companion=worker,
            crt_startup_joins=startup, crt_descriptor_handoff_joins=handoff,
            prepared_worker_tls_joins=worker_joins,
        )
        self.assertEqual(joins[0]['source_occurrence_indices'], [30634])
        self.assertEqual(accounting['identities'][0]['unresolved'], [])

    def test_paired_runtimev1_attachment_rejects_closed_account_and_occurrence_changes(self) -> None:
        for mutation in ('value-cases', 'crt-source-input', 'worker-post-fork', 'worker-geometry',
                         'provider', 'second-occurrence', 'foreign-occurrence', 'provider-definition', 'cohort'):
            with self.subTest(mutation=mutation):
                accounting = self._accounting()
                crt, worker, startup, handoff, worker_joins = self._companions()
                if mutation == 'value-cases':
                    crt['account']['descriptor_runtime_admission']['value_cases'].pop()
                elif mutation == 'crt-source-input':
                    crt['source_inputs']['compat/x86_64/installed_crt_startup_evidence.py']['sha256'] = '0' * 64
                elif mutation == 'worker-post-fork':
                    del worker['account']['source']['post_fork_generation']
                elif mutation == 'worker-geometry':
                    worker_joins[0]['descriptor']['contract_geometry']['size_bytes'] = 71
                elif mutation == 'provider':
                    accounting['identities'][0]['selection']['protocol']['provider_artifacts'] = ['candidate-loader']
                elif mutation == 'second-occurrence':
                    duplicate = copy.deepcopy(accounting['occurrences'][0])
                    duplicate['index'] = 30635
                    accounting['occurrences'].append(duplicate)
                elif mutation == 'foreign-occurrence':
                    duplicate = copy.deepcopy(accounting['occurrences'][0])
                    duplicate['index'] = 30635
                    duplicate['artifact_key'] = 'candidate-shared'
                    accounting['occurrences'].append(duplicate)
                elif mutation == 'provider-definition':
                    duplicate = copy.deepcopy(accounting['occurrences'][0])
                    duplicate['index'] = 30635
                    duplicate['artifact_key'] = 'candidate-loader'
                    duplicate['role'] = 'definition'
                    duplicate['definition_section'] = {'name': '.text'}
                    duplicate['row']['section_index'] = '4'
                    accounting['occurrences'].append(duplicate)
                else:
                    worker['products']['dynamic_libc']['sha256'] = '0' * 64
                with self.assertRaises(selection.SelectionError):
                    selection.attach_runtimev1_descriptor_lifecycle(
                        accounting, crt_companion=crt, prepared_worker_companion=worker,
                        crt_startup_joins=startup, crt_descriptor_handoff_joins=handoff,
                        prepared_worker_tls_joins=worker_joins,
                    )


if __name__ == '__main__':
    unittest.main()
