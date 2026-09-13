"""Focused selector joins for the finite loader and pthread runtime receipts."""
from __future__ import annotations

import copy
import contextlib
import io
import json
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
        self._write(self.dynamic / 'share/crabc/libc-shared.provenance.json', b'dynamic shared provenance\n')
        self._write(self.dynamic / 'share/crabc/loader.provenance.json', b'loader provenance\n')
        self._write(self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n')
        self._write(self.dynamic / 'usr/lib/libc.so', b'dynamic libc\n')
        self._write(self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n')
        self.base = self._write(self.work / 'base-inventory.json', b'base\n')
        self.elf = self._write(self.work / 'elf-facts.json', b'elf\n')
        self.preparation = self._write(self.work / 'preparation.json', b'preparation\n')
        self.registry_report_path = self._write(self.work / 'registry-report.json', b'{}\n')
        self.pthread_report_path = self._write(self.work / 'pthread-report.json', b'{}\n')
        self.prepared_worker_report_path = self._write(self.work / 'prepared-worker-report.json', b'{}\n')
        self.errno_storage_report_path = self._write(self.work / 'errno-storage-report.json', b'{}\n')
        self.stdio_alias_report_path = self._write(self.work / 'stdio-alias-report.json', b'{}\n')
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
        # The public pthread reader preserves its own retained-copy records.
        # They deliberately have path/hash/size, not the selected product
        # file's mode-bearing host identity.
        artifacts = {
            retained[name]: {
                'path': retained[name],
                'sha256': self.current[name]['sha256'],
                'size': self.current[name]['size'],
            }
            for name in retained
        }
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

    @staticmethod
    def _prepared_source_account():
        return {
            'source_files': {},
            'operations': copy.deepcopy(selection.prepared_worker_evidence.OPERATIONS),
            'source_signatures': {},
            'legacy_replacement': copy.deepcopy(selection.prepared_worker_evidence.expected_contract()['legacy_replacement']),
            'worker_token': {
                'producer_fields': list(selection.prepared_worker_evidence.TOKEN_FIELDS),
                'consumer_fields': list(selection.prepared_worker_evidence.TOKEN_FIELDS),
                'size_bytes': 32, 'alignment_bytes': 8,
            },
            'ordering': {},
            'descriptor': {
                'size_bytes': 72, 'alignment_bytes': 8,
                'role': 'private-process-lifetime-initial-tls-provenance',
            },
            'descriptor_source_fields': [],
            'scope': 'Source selection and lexical ordering; native execution/compiled unit receipts remain separate.',
        }

    def prepared_worker_report(self, elf_account, source_account, relocations):
        runtime = {
            'application_cells': {
                row['label']: dict(row) for row in selection.prepared_worker_evidence.runtime_cells()
            },
            'source_tests': list(selection.prepared_worker_evidence.UNIT_TESTS),
            'source_test_executable': 'loader-tests',
            'source_root': selection.prepared_worker_evidence.UNIT_ROOT,
            'oracle_boundary': 'Common installed C TLS/callback lifecycle only; no musl token/view/unmap-layout claim.',
            'owned_boundary': 'Live TLS and retained views mapped until quiescence; joined/reaped TLS and views unmapped.',
        }
        products = {
            'source': {'revision': self.source['revision'], 'content_sha256': self.source['content_sha256']},
            'static_preparation': {
                'receipt': copy.deepcopy(self.measurement['reports']['static_preparation']),
                'source': {'revision': self.source['revision'], 'content_sha256': self.source['content_sha256']},
                'primary': {'path': '.work/static', 'manifest': copy.deepcopy(self.current['static_manifest'])},
            },
            'dynamic_product': {
                'path': '.work/dynamic', 'manifest': copy.deepcopy(self.current['dynamic_manifest']),
                'state': copy.deepcopy(self.current['dynamic_state']), 'manifest_sha256': 'f' * 64,
            },
        }
        return {
            'schema': selection.prepared_worker_evidence.SCHEMA,
            'target': selection.prepared_worker_evidence.inventory.TARGET,
            'image': 'sha256:' + '0' * 64,
            'status': copy.deepcopy(selection.prepared_worker_evidence.STATUS),
            'source_before': copy.deepcopy(self.source), 'source_after': copy.deepcopy(self.source),
            'source_account': copy.deepcopy(source_account),
            'source_copies': {name: {} for name in selection.prepared_worker_evidence.SOURCE_PATHS},
            'inputs_before': {
                'products': products,
                'reports': {
                    'base_inventory': copy.deepcopy(self.measurement['reports']['base_inventory']),
                    'elf_report': copy.deepcopy(self.measurement['reports']['elf_report']),
                },
                'elf': copy.deepcopy(elf_account),
            },
            'inputs_after': {
                'products': copy.deepcopy(products),
                'reports': {
                    'base_inventory': copy.deepcopy(self.measurement['reports']['base_inventory']),
                    'elf_report': copy.deepcopy(self.measurement['reports']['elf_report']),
                },
                'elf': copy.deepcopy(elf_account),
            },
            'tools': {}, 'rust_tools': {}, 'oracle': {}, 'oracle_static_inputs': {}, 'commands': {}, 'links': {},
            'observations': {
                'artifacts': {}, 'worker_relocations': copy.deepcopy(relocations), 'executables': {}, 'dsos': {},
                'runtime': runtime, 'unit_diagnostics': [], 'execution_roots': {},
            },
        }

    @staticmethod
    def _errno_identity(value):
        return {'path': value['path'], 'sha256': value['sha256'], 'size_bytes': value['size']}

    @staticmethod
    def _errno_layout_fact(*, archive=False):
        value = {
            'symbol_value_hex': '0000000000000040',
            'object_size_bytes': 4,
            'required_alignment_bytes': 4,
            'defining_section_index': 7,
            'defining_section_name': '.bss.h_errno',
            'defining_section_address_hex': '0000000000000040',
            'defining_section_size_bytes': 64,
            'defining_section_alignment_bytes': 4,
            'offset_bytes': 0,
            'offset_modulo_required_alignment': 0,
        }
        if archive:
            value['archive_member'] = {'name': 'h_errno.lo', 'index': 0, 'occurrence': 0}
        return value

    def _errno_h_errno_layout(self):
        metadata = copy.deepcopy(selection.errno_storage_evidence.H_ERRNO_METADATA)
        return {
            'static': {
                'metadata': copy.deepcopy(metadata),
                'oracle': self._errno_layout_fact(archive=True),
                'candidate': self._errno_layout_fact(archive=True),
            },
            'shared': {
                'metadata': copy.deepcopy(metadata),
                'oracle': self._errno_layout_fact(),
                'candidate': self._errno_layout_fact(),
            },
        }

    def errno_storage_report(self):
        policy = {
            'source': {
                'path': selection.errno_storage_evidence.SHARED_ALIAS_LIST,
                'sha256': selection.errno_storage_evidence.SHARED_ALIAS_LIST_SHA256,
                'mode': 0o644,
            },
            'member_count': 1,
            'members': [selection.errno_storage_evidence.ALIAS],
            'linker_policy': 'exact-local-symbols',
            'linker_script_sha256': selection.errno_storage_evidence.SHARED_ALIAS_LINKER_SCRIPT_SHA256,
        }
        return {
            'schema': selection.errno_storage_evidence.SCHEMA,
            'target': selection.errno_storage_evidence.TARGET,
            'work': str(self.work),
            'collection_checkout_root': str(ROOT),
            'source': {
                'schema': selection.errno_storage_evidence.SNAPSHOT_SCHEMA,
                'root': str(ROOT), 'commit': self.source['revision'], 'status': '',
                'files': {name: {} for name in selection.errno_storage_evidence.SOURCE_FILES},
            },
            'products': {
                'static': {
                    'root': str(self.static), 'manifest': self._errno_identity(self.current['static_manifest']),
                    'libc': self._errno_identity(self.current['static_libc']),
                },
                'dynamic': {
                    'root': str(self.dynamic), 'manifest': self._errno_identity(self.current['dynamic_manifest']),
                    'libc': self._errno_identity(self.current['dynamic_libc']),
                    'libc_shared_provenance': self._errno_identity(
                        selection._runtime_attachment_identities(self.paths)['dynamic_shared_provenance']
                    ),
                },
            },
            'shared_alias_link_policy': policy,
            'symbols': {name: {} for name in selection.errno_storage_evidence.SYMBOL_INPUTS},
            'layout_artifacts': {name: {} for name in selection.errno_storage_evidence.LAYOUT_INPUTS},
            'h_errno_layout': self._errno_h_errno_layout(),
            'workload_symbols': {name: {} for name in selection.errno_storage_evidence.WORKLOAD_SYMBOL_INPUTS},
            'objects': {name: {} for name in selection.errno_storage_evidence.OBJECTS},
            'execution': {name: {} for name in selection.errno_storage_evidence.RUN_LABELS},
            'dynamic_link_receipts': {name: {} for name in selection.errno_storage_evidence.DYNAMIC_LINKS},
            'summary': {
                'errno_public_accessor': 'GLOBAL DEFAULT FUNC',
                'errno_allocator_alias': 'static WEAK HIDDEN same-address; shared LOCAL DEFAULT absent-dynsym',
                'h_errno': 'GLOBAL DEFAULT OBJECT size=4, source-required alignment=4, and GLOBAL DEFAULT accessor',
                'h_errno_layout': 'static/shared defining section and section-relative offset retain alignment=4; shared section over-alignment is observed separately',
                'execution': 'main/live-worker isolation, aligned live accessor locations, stable live locations, selected pthread EBUSY preserves errno, and loaded DSO access',
                'worker_pointer_lifetime': 'never dereferenced after join',
            },
        }

    def prepared_worker_accounting(self, elf_account):
        contract = selection.load_contract()
        operation_protocol = next(row for row in contract['private_protocols']
                                  if row['id'] == 'loader-worker-tls-operations')
        descriptor_protocol = next(row for row in contract['private_protocols']
                                  if row['id'] == 'loader-libc-tls-descriptor-v1')
        identities, occurrences, protocol_joins, blockers = [], [], [], []
        for name in selection.prepared_worker_evidence.OPERATIONS:
            identity = selection.identity(name)
            identities.append({
                'identity': identity,
                'selection': {
                    'disposition': 'private-resolution-operation', 'owner': 'loader-worker-tls-operations',
                    'protocol': copy.deepcopy(operation_protocol),
                },
                'unresolved': list(selection.PREPARED_WORKER_TLS_REQUIREMENTS),
            })
            indices = []
            for table in ('.dynsym', '.symtab'):
                index = len(occurrences)
                indices.append(index)
                row = {'name': name, 'version': None, 'version_default': False, 'row_index': index,
                       **self._runtime_row()}
                elf_account['operations'][name][table] = {
                    'table_index': 0 if table == '.dynsym' else 1,
                    'row_index': index, 'row': copy.deepcopy(row),
                }
                occurrences.append({
                    'index': index, 'artifact_key': 'candidate-shared', 'table': table, 'role': 'import',
                    'row': row,
                    'accounting': {
                        'disposition': 'private-resolution-operation', 'owner': 'loader-worker-tls-operations',
                        'scope': 'candidate-shared',
                        'resolution': {'kind': 'source-dispatch-operation', 'operation': {'name': name}},
                        'resolution_proven': False,
                    },
                })
            protocol_joins.append({
                'identity': identity, 'artifact_key': 'candidate-shared', 'role': 'consumer-import',
                'occurrence_indices': indices, 'endpoint_kind': 'source-dispatch-operation',
                'signature_status': operation_protocol['signature_status'], 'relocation_lifecycle_proven': False,
            })
            blockers.extend({
                'code': 'identity-unresolved', 'identity': identity, 'reason': requirement,
            } for requirement in selection.PREPARED_WORKER_TLS_REQUIREMENTS)
        structural_requirement = 'current source-bound owning component and consumer semantics receipt'
        for name in selection.prepared_worker_evidence.LEGACY:
            identity = selection.identity(name)
            identities.append({
                'identity': identity,
                'selection': {
                    'disposition': 'structural-replacement', 'owner': 'pthread-prepared-token',
                    'reason': 'Actual pthread consumer uses prepared mapping/thread-pointer/generation token before clone and exact release at exit/reap; raw process clone is not the replacement.',
                },
                'unresolved': [structural_requirement],
            })
            blockers.append({
                'code': 'identity-unresolved', 'identity': identity, 'reason': structural_requirement,
            })
        descriptor_name = '__crabc_x86_64_loader_tls_runtime_v1'
        descriptor_identity = selection.identity(descriptor_name)
        descriptor_requirements = list(selection.PREPARED_WORKER_TLS_DESCRIPTOR_REQUIREMENTS) + [
            'private descriptor exact binding/visibility selection and lifecycle proof remain required',
        ]
        identities.append({
            'identity': descriptor_identity,
            'selection': {
                'disposition': 'private-resolution-operation', 'owner': 'loader-libc-tls-descriptor-v1',
                'protocol': copy.deepcopy(descriptor_protocol),
            },
            'unresolved': descriptor_requirements,
        })
        provider_index = len(occurrences)
        provider_row = {
            'name': descriptor_name, 'version': None, 'version_default': False, 'row_index': provider_index,
            'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': '3',
            'size_bytes': 72, 'value': '0000000000000040',
        }
        occurrences.append({
            'index': provider_index, 'artifact_key': 'candidate-loader', 'table': '.symtab', 'role': 'definition',
            'row': provider_row,
        })
        consumer_indices = []
        for table in ('.dynsym', '.symtab'):
            index = len(occurrences)
            consumer_indices.append(index)
            row = {'name': descriptor_name, 'version': None, 'version_default': False, 'row_index': index,
                   **self._runtime_row()}
            occurrences.append({
                'index': index, 'artifact_key': 'candidate-shared', 'table': table, 'role': 'import', 'row': row,
            })
        elf_account['descriptor_named_elf_observations'] = [
            {'artifact': 'candidate-loader', 'table': '.symtab', 'row': copy.deepcopy(provider_row)},
            *[{'artifact': 'candidate-shared', 'table': occurrences[index]['table'],
               'row': copy.deepcopy(occurrences[index]['row'])} for index in consumer_indices],
        ]
        protocol_joins.extend([
            {
                'identity': descriptor_identity, 'artifact_key': 'candidate-loader',
                'role': 'private-descriptor-definition', 'occurrence_indices': [provider_index],
                'metadata_differences': [{'occurrence_index': provider_index, 'fields': []}],
                'binding_and_visibility_selection_complete': False,
            },
            {
                'identity': descriptor_identity, 'artifact_key': 'candidate-shared', 'role': 'consumer-import',
                'occurrence_indices': consumer_indices, 'endpoint_kind': 'descriptor',
                'signature_status': descriptor_protocol['signature_status'], 'relocation_lifecycle_proven': False,
            },
        ])
        blockers.extend({
            'code': 'identity-unresolved', 'identity': descriptor_identity, 'reason': requirement,
        } for requirement in descriptor_requirements)
        return {
            'identities': identities, 'occurrences': occurrences, 'placement_joins': [],
            'private_protocol_joins': protocol_joins, 'blockers': blockers,
        }

    def errno_storage_accounting(self):
        identities, occurrences, joins, blockers = [], [], [], []

        def add(name, owner, metadata, *, private=False, unresolved=()):
            identity = selection.identity(name)
            selection_record = {'disposition': 'private-provider', 'owner': owner,
                                'group': selection.ERRNO_PRIVATE_ALIAS_GROUP} if private else {
                'disposition': 'public-provider', 'owner': owner,
            }
            identities.append({'identity': identity, 'selection': selection_record, 'unresolved': list(unresolved)})
            blockers.extend({
                'code': 'identity-unresolved', 'identity': identity, 'reason': reason,
            } for reason in unresolved)

            def row(index, *, binding, visibility, value, role, table, artifact, member_index=None,
                    member_occurrence=None):
                return {
                    'index': index, 'artifact_key': artifact, 'table': table, 'role': role,
                    'member_index': member_index, 'member_occurrence': member_occurrence,
                    'table_section_index': '11',
                    'definition_section': {'index': 7, 'alignment': 4},
                    'row': {
                        'name': name, 'version': None, 'version_default': False, 'row_index': index,
                        'type': metadata['type'], 'binding': binding, 'visibility': visibility,
                        'section_index': '7', 'size_bytes': metadata.get('size_bytes', 0), 'value': value,
                    },
                }

            static_index = len(occurrences)
            static_binding = 'WEAK' if private else 'GLOBAL'
            static_visibility = 'HIDDEN' if private else 'DEFAULT'
            static_value = '0000000000000010' if name in {'__errno_location', selection.errno_storage_evidence.ALIAS} else '0000000000000030'
            static = row(static_index, binding=static_binding, visibility=static_visibility, value=static_value,
                         role='definition', table='.symtab', artifact='candidate-static', member_index=3,
                         member_occurrence=1)
            occurrences.append(static)
            joins.append({
                'identity': identity, 'artifact_key': 'candidate-static', 'expected_metadata': copy.deepcopy(metadata),
                'placement_observed': True, 'definition_count': 1, 'occurrence_indices': [static_index],
                'metadata_differences': [{'occurrence_index': static_index, 'fields': []}],
            })
            shared_index = len(occurrences)
            shared_binding = 'LOCAL' if private else 'GLOBAL'
            shared_table = '.symtab' if private else '.dynsym'
            shared_value = '0000000000000020' if name in {'__errno_location', selection.errno_storage_evidence.ALIAS} else '0000000000000040'
            shared = row(shared_index, binding=shared_binding, visibility='DEFAULT', value=shared_value,
                         role='local-definition' if private else 'definition', table=shared_table,
                         artifact='candidate-shared')
            occurrences.append(shared)
            joins.append({
                'identity': identity, 'artifact_key': 'candidate-shared', 'expected_metadata': copy.deepcopy(metadata),
                'placement_observed': True, 'definition_count': 1, 'occurrence_indices': [shared_index],
                'metadata_differences': [{'occurrence_index': shared_index, 'fields': []}],
            })
            return static, shared

        errno_static, _errno_shared_dynsym = add(
            '__errno_location', 'checked-header-provider-routing',
            {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'},
        )
        # The private shared alias joins the full shared symbol table to this
        # ordinary public accessor, rather than treating a dynsym value as an
        # alias domain.
        shared_accessor_index = len(occurrences)
        shared_accessor = copy.deepcopy(errno_static)
        shared_accessor.update({
            'index': shared_accessor_index, 'artifact_key': 'candidate-shared', 'table': '.symtab',
            'member_index': None, 'member_occurrence': None,
        })
        shared_accessor['row'] = copy.deepcopy(shared_accessor['row'])
        shared_accessor['row'].update({'row_index': shared_accessor_index, 'binding': 'GLOBAL',
                                       'visibility': 'DEFAULT', 'value': '0000000000000020'})
        occurrences.append(shared_accessor)
        add('__h_errno_location', 'checked-header-provider-routing',
            {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'})
        add('h_errno', 'object:h_errno', {
            'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size_bytes': 4, 'alignment_bytes': 4,
        })
        alias_static, alias_shared = add(
            selection.errno_storage_evidence.ALIAS, 'x86-errno-storage-lifecycle',
            {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'HIDDEN'}, private=True,
            unresolved=(selection.ERRNO_STORAGE_LIFECYCLE_REQUIREMENT,),
        )
        # The shared placement's expected source metadata is LOCAL DEFAULT;
        # rewrite only that placement and observation from the private group.
        alias_shared['row']['binding'] = 'LOCAL'
        alias_shared['row']['visibility'] = 'DEFAULT'
        alias_shared_join = next(join for join in joins
                                 if join['identity']['name'] == selection.errno_storage_evidence.ALIAS
                                 and join['artifact_key'] == 'candidate-shared')
        alias_shared_join['expected_metadata'] = {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'}
        return {'identities': identities, 'occurrences': occurrences, 'placement_joins': joins,
                'private_protocol_joins': [], 'blockers': blockers}

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

    def test_prepared_worker_and_errno_adapters_reject_incomplete_owner_records(self):
        """A reader result cannot become a selector companion by its path alone."""
        with (
            mock.patch.object(selection.prepared_worker_evidence, 'validate_report', return_value={}),
            self.assertRaises(selection.SelectionError),
        ):
            selection.prepared_worker_tls_adapter(
                self.prepared_worker_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        with (
            mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value={}),
            self.assertRaises(selection.SelectionError),
        ):
            selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_prepared_worker_adapter_replays_the_owner_and_binds_its_finite_product_roster(self):
        elf_account = {
            'operations': {name: {'.dynsym': {}, '.symtab': {}}
                           for name in selection.prepared_worker_evidence.OPERATIONS},
            'descriptor_named_elf_observations': [], 'descriptor_installed_import_required': False,
            'legacy_named_shared_loader_rows': [],
        }
        source_account = self._prepared_source_account()
        relocations = {name: {} for name in selection.prepared_worker_evidence.OPERATIONS}
        report = self.prepared_worker_report(elf_account, source_account, relocations)
        with (
            mock.patch.object(selection.prepared_worker_evidence, 'validate_report', return_value=report) as replay,
            mock.patch.object(selection.prepared_worker_evidence, 'account_elf', return_value=elf_account),
            mock.patch.object(selection.prepared_worker_evidence, 'account_source', return_value=source_account),
            mock.patch.object(selection.prepared_worker_evidence, 'Elf'),
            mock.patch.object(selection.prepared_worker_evidence, 'worker_relocations', return_value=relocations),
        ):
            result = selection.prepared_worker_tls_adapter(
                self.prepared_worker_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        replay.assert_called_once_with(
            ROOT, self.prepared_worker_report_path,
            base_inventory=self.base, elf_report=self.elf, static_preparation=self.preparation,
            static_product=self.static, dynamic_product=self.dynamic,
        )
        self.assertEqual(result['status'], 'prepared-worker-tls-observed-with-boundaries')
        self.assertEqual(
            set(result['products']),
            {'static_manifest', 'static_libc', 'dynamic_manifest', 'dynamic_state', 'dynamic_libc', 'dynamic_loader'},
        )

    def test_errno_adapter_replays_the_owner_and_rejects_a_cross_cohort_library(self):
        report = self.errno_storage_report()
        with mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value=report) as replay:
            result = selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        replay.assert_called_once_with(ROOT, self.errno_storage_report_path)
        self.assertEqual(result['status'], 'errno-storage-lifecycle-observed-with-boundaries')
        report['products']['dynamic']['libc']['sha256'] = '0' * 64
        with mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic_libc bytes differ'):
            selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_errno_adapter_rejects_a_private_alias_policy_from_another_source(self):
        report = self.errno_storage_report()
        report['shared_alias_link_policy']['source']['sha256'] = '0' * 64
        with mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'receipt source differs'):
            selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_errno_adapter_rejects_h_errno_layout_below_the_selected_int_alignment(self):
        report = self.errno_storage_report()
        report['h_errno_layout']['shared']['candidate']['defining_section_alignment_bytes'] = 2
        with mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'h_errno shared candidate alignment fact differs'):
            selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_prepared_worker_join_discharges_only_exact_tls_operations_legacy_names_and_descriptor(self):
        elf_account = {
            'operations': {name: {'.dynsym': {}, '.symtab': {}}
                           for name in selection.prepared_worker_evidence.OPERATIONS},
            'descriptor_named_elf_observations': [], 'descriptor_installed_import_required': False,
            'legacy_named_shared_loader_rows': [],
        }
        source_account = self._prepared_source_account()
        relocations = {name: {} for name in selection.prepared_worker_evidence.OPERATIONS}
        report = self.prepared_worker_report(elf_account, source_account, relocations)
        accounting = self.prepared_worker_accounting(elf_account)
        report['inputs_before']['elf'] = copy.deepcopy(elf_account)
        report['inputs_after']['elf'] = copy.deepcopy(elf_account)
        with (
            mock.patch.object(selection.prepared_worker_evidence, 'validate_report', return_value=report),
            mock.patch.object(selection.prepared_worker_evidence, 'account_elf', return_value=elf_account),
            mock.patch.object(selection.prepared_worker_evidence, 'account_source', return_value=source_account),
            mock.patch.object(selection.prepared_worker_evidence, 'Elf'),
            mock.patch.object(selection.prepared_worker_evidence, 'worker_relocations', return_value=relocations),
        ):
            companion = selection.prepared_worker_tls_adapter(
                self.prepared_worker_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        joins = selection.attach_prepared_worker_tls(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['operations']), 3)
        self.assertEqual(len(joins[0]['legacy_replacements']), 7)
        self.assertFalse(accounting['blockers'])
        self.assertTrue(all(
            occurrence.get('accounting', {}).get('resolution_proven') is True
            for occurrence in accounting['occurrences']
            if occurrence['row']['name'] in selection.prepared_worker_evidence.OPERATIONS
        ))

    def test_errno_join_binds_three_public_rows_and_one_private_same_definition_alias(self):
        report = self.errno_storage_report()
        with mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value=report):
            companion = selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        inputs = {
            'provider_disposition': {
                'default_static': {'members': ['__errno_location']},
                'verified_feature_archives': [{'id': 'x86-h-errno', 'members': ['__h_errno_location']}],
            },
        }
        accounting = self.errno_storage_accounting()
        joins = selection.attach_errno_storage_lifecycle(accounting, companion, inputs)
        self.assertEqual(len(joins), 1)
        self.assertEqual([row['identity']['name'] for row in joins[0]['public_identities']],
                         ['__errno_location', '__h_errno_location', 'h_errno'])
        self.assertEqual(
            next(row for row in joins[0]['public_identities']
                 if row['identity']['name'] == '__h_errno_location')['feature_owner'],
            'x86-h-errno',
        )
        self.assertTrue(joins[0]['private_alias']['shared_dynsym_absent'])
        self.assertEqual(joins[0]['private_alias']['identity']['name'], '___errno_location')
        self.assertFalse(accounting['blockers'])

        leaked = copy.deepcopy(accounting)
        alias = next(row for row in leaked['occurrences']
                     if row['row']['name'] == '___errno_location' and row['artifact_key'] == 'candidate-shared')
        dynsym = copy.deepcopy(alias)
        dynsym['index'] = max(row['index'] for row in leaked['occurrences']) + 1
        dynsym['table'] = '.dynsym'
        dynsym['role'] = 'definition'
        dynsym['row'] = copy.deepcopy(dynsym['row'])
        dynsym['row']['row_index'] = dynsym['index']
        leaked['occurrences'].append(dynsym)
        with self.assertRaisesRegex(selection.SelectionError, 'leaked into shared dynsym'):
            selection.attach_errno_storage_lifecycle(leaked, companion, inputs)

    def test_errno_join_uses_the_actual_633_header_provider_selection(self):
        """The feature roster informs the receipt without changing the real selected owner."""
        lifecycle = ROOT.parent / 'native_abi_lifecycle_integration'
        selection_report_path = lifecycle / '.work/x86_64/native-abi-selection/clean-633bd57f/report.json'
        receipt_path = lifecycle / (
            '.work/x86_64/errno-storage-lifecycle-recipes/633bd57f/tmp/'
            'owned-errno-storage-lifecycle.Yh56V7/report.json'
        )
        if not selection_report_path.is_file() or not receipt_path.is_file():
            self.skipTest('retained 633 errno/cohort control is unavailable')
        selected = json.loads(selection_report_path.read_text())
        receipt = json.loads(receipt_path.read_text())
        inputs = selected['source_inputs']
        accounting = {
            'identities': copy.deepcopy(selected['identities']),
            'occurrences': copy.deepcopy(selected['occurrences']),
            'placement_joins': copy.deepcopy(selected['placement_joins']),
            'private_protocol_joins': copy.deepcopy(selected['private_protocol_joins']),
            'blockers': [],
        }
        companion = {
            'status': 'errno-storage-lifecycle-observed-with-boundaries',
            'reader': {}, 'report': {}, 'source': {}, 'products': {}, 'measurement_reports': {},
            'account': {
                'public_symbols': list(selection.errno_storage_evidence.PUBLIC_SYMBOLS),
                'private_alias': selection.errno_storage_evidence.ALIAS,
                'shared_alias_policy': receipt['shared_alias_link_policy'],
                'h_errno_layout': selection._errno_h_errno_layout(receipt['h_errno_layout']),
                'summary': receipt['summary'],
                'execution_labels': list(selection.errno_storage_evidence.RUN_LABELS),
            },
            'limits': list(selection.ERRNO_STORAGE_LIFECYCLE_LIMITS),
        }
        joins = selection.attach_errno_storage_lifecycle(accounting, companion, inputs)
        rows = {row['identity']['name']: row for row in joins[0]['public_identities']}
        self.assertEqual(rows['__h_errno_location']['owner'], 'checked-header-provider-routing')
        self.assertEqual(rows['__h_errno_location']['feature_owner'], 'x86-h-errno')
        missing_feature = copy.deepcopy(inputs)
        missing_feature['provider_disposition']['verified_feature_archives'] = [
            row for row in missing_feature['provider_disposition']['verified_feature_archives']
            if row.get('id') != 'x86-h-errno'
        ]
        fresh_accounting = {
            'identities': copy.deepcopy(selected['identities']),
            'occurrences': copy.deepcopy(selected['occurrences']),
            'placement_joins': copy.deepcopy(selected['placement_joins']),
            'private_protocol_joins': copy.deepcopy(selected['private_protocol_joins']),
            'blockers': [],
        }
        with self.assertRaisesRegex(selection.SelectionError, 'h_errno accessor feature provider partition differs'):
            selection.attach_errno_storage_lifecycle(fresh_accounting, companion, missing_feature)

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

    def test_pthread_adapter_accepts_the_reader_path_hash_size_artifact_shape(self):
        """The public reader retains copies without inventing their source modes."""
        report = self.pthread_report()
        self.assertTrue(all(set(artifact) == {'path', 'sha256', 'size'}
                            for artifact in report['artifacts'].values()))
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report):
            result = selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        self.assertEqual(result['status'], 'pthread-alias-contract-observed-with-boundaries')

    def test_pthread_adapter_rejects_an_unowned_artifact_mode(self):
        report = self.pthread_report()
        retained = report['selected_products']['static']['manifest']
        report['artifacts'][retained]['mode'] = 0o644
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'static_manifest receipt fields differ'):
            selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_pthread_adapter_rejects_a_replaced_dynamic_loader(self):
        report = self.pthread_report()
        retained = report['selected_products']['dynamic']['loader']
        report['artifacts'][retained]['sha256'] = '0' * 64
        with mock.patch.object(selection.pthread_alias_evidence, 'validate_report', return_value=report), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic_loader bytes differ'):
            selection.pthread_alias_contract_adapter(
                self.pthread_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_pthread_adapter_binds_the_actual_633_receipt_to_selected_accounting(self):
        """The fresh retained receipt uses path/hash/size copies and real rows."""
        lifecycle = ROOT.parent / 'native_abi_lifecycle_integration'
        facts_path = lifecycle / '.work/x86_64/native-abi-elf-facts/clean-633bd57f/report.json'
        selection_report_path = lifecycle / '.work/x86_64/native-abi-selection/clean-633bd57f/report.json'
        pthread_report_path = lifecycle / '.work/x86_64/pthread-alias-contract/clean-633bd57f/report.json'
        static_preparation = lifecycle / '.work/x86_64/public-data-products/static-633bd57f/preparation.json'
        static_product = lifecycle / '.work/x86_64/public-data-products/static-633bd57f/products/primary'
        dynamic_product = lifecycle / '.work/x86_64/loader-debug-abi/clean-633bd57f/component/dynamic-product'
        base_inventory = lifecycle / '.work/x86_64/native-abi-inventory/clean-633bd57f/report.json'
        required = (facts_path, selection_report_path, pthread_report_path, static_preparation,
                    static_product, dynamic_product, base_inventory)
        if not all(path.exists() for path in required):
            self.skipTest('retained 633 pthread/cohort control is unavailable')
        facts = json.loads(facts_path.read_text())
        selected = json.loads(selection_report_path.read_text())
        paths = {
            'measurement_checkout': lifecycle,
            'elf_report': facts_path,
            'base_inventory': base_inventory,
            'static_preparation': static_preparation,
            'static_product': static_product,
            'dynamic_product': dynamic_product,
        }
        measurement = {
            'candidate_build': facts['base_inventory']['candidate_build'],
            'reports': {name: selection.file_identity(paths[name])
                        for name in ('elf_report', 'base_inventory', 'static_preparation')},
        }
        source = {
            'revision': facts['base_inventory']['candidate_build']['revision'],
            'content_sha256': facts['base_inventory']['candidate_build']['source_content_sha256'],
            'clean': True,
        }
        # This retained receipt belongs to the sibling lifecycle worktree in
        # the same physical common checkout; do not weaken production work
        # admission just because the normal fixture uses an isolated root.
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT.parents[2]):
            companion = selection.pthread_alias_contract_adapter(
                pthread_report_path, facts=facts, measurement=measurement, paths=paths, source=source,
            )
        accounting = {
            'identities': copy.deepcopy(selected['identities']),
            'occurrences': copy.deepcopy(selected['occurrences']),
            'placement_joins': copy.deepcopy(selected['placement_joins']),
            'private_protocol_joins': copy.deepcopy(selected['private_protocol_joins']),
            'blockers': [],
        }
        joins = selection.attach_pthread_alias_contract(accounting, companion)
        self.assertEqual(len(joins[0]['aliases']), len(selection.pthread_alias_evidence.ALIASES))
        # The selected archive has both bodies in its monolithic Rust member,
        # so this fresh receipt records no separate UND import to discharge.
        # Preserve that actual limitation rather than manufacturing an
        # ordinary-link success from the component's runtime evidence.
        self.assertFalse(joins[0]['mq_notify_public_detach']['public_detach_relocation_proven'])
        self.assertIsNone(joins[0]['mq_notify_public_detach']['discharged_reason'])

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
            ('--prepared-worker-tls-report', self.prepared_worker_report_path),
            ('--errno-storage-lifecycle-report', self.errno_storage_report_path),
            ('--stdio-alias-contract-report', self.stdio_alias_report_path),
        ):
            with self.subTest(option=option), \
                 mock.patch.object(selection, 'validate_report', return_value=reconstructed) as replay, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(selection.main([*base, option, str(report)]), 0)
            kwargs = replay.call_args.kwargs
            self.assertEqual(kwargs[option[2:].replace('-', '_')], report)
            for other in (
                'loader_runtime_registry_report', 'pthread_alias_contract_report',
                'prepared_worker_tls_report', 'errno_storage_lifecycle_report',
                'stdio_alias_contract_report',
            ):
                if other != option[2:].replace('-', '_'):
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

    def test_existing_runtime_recheck_does_not_require_optional_crt_artifacts(self):
        self.assertFalse((self.static / 'usr/lib/crt1.o').exists())
        registry = self.registry_report()
        with mock.patch.object(selection.runtime_registry_evidence, 'validate_report', return_value=registry):
            companion = selection.loader_runtime_registry_adapter(
                self.registry_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        with mock.patch.object(selection, 'selection_source', return_value=self.source):
            selection._recheck_runtime_receipt_cohort(
                paths=self.paths, facts=self.facts, measurement=self.measurement, source=self.source,
                registry=companion, pthread=None,
            )

    def test_tls_and_errno_attachments_recheck_the_same_product_cohort_after_joins(self):
        elf_account = {
            'operations': {name: {'.dynsym': {}, '.symtab': {}}
                           for name in selection.prepared_worker_evidence.OPERATIONS},
            'descriptor_named_elf_observations': [], 'descriptor_installed_import_required': False,
            'legacy_named_shared_loader_rows': [],
        }
        source_account = self._prepared_source_account()
        relocations = {name: {} for name in selection.prepared_worker_evidence.OPERATIONS}
        prepared = self.prepared_worker_report(elf_account, source_account, relocations)
        errno = self.errno_storage_report()
        with (
            mock.patch.object(selection.prepared_worker_evidence, 'validate_report', return_value=prepared),
            mock.patch.object(selection.prepared_worker_evidence, 'account_elf', return_value=elf_account),
            mock.patch.object(selection.prepared_worker_evidence, 'account_source', return_value=source_account),
            mock.patch.object(selection.prepared_worker_evidence, 'Elf'),
            mock.patch.object(selection.prepared_worker_evidence, 'worker_relocations', return_value=relocations),
            mock.patch.object(selection.errno_storage_evidence, 'validate_report', return_value=errno),
        ):
            prepared_companion = selection.prepared_worker_tls_adapter(
                self.prepared_worker_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
            errno_companion = selection.errno_storage_lifecycle_adapter(
                self.errno_storage_report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        (self.dynamic / 'usr/lib/libc.so').write_bytes(b'replaced after TLS/errno reader\n')
        with mock.patch.object(selection, 'selection_source', return_value=self.source), \
             self.assertRaisesRegex(selection.SelectionError, 'candidate-shared.*bytes or mode differ'):
            selection._recheck_runtime_receipt_cohort(
                paths=self.paths, facts=self.facts, measurement=self.measurement, source=self.source,
                registry=None, pthread=None, prepared_worker=prepared_companion, errno_storage=errno_companion,
            )


if __name__ == '__main__':
    unittest.main()
