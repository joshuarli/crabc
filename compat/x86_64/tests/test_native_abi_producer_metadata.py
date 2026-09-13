"""Select private producer metadata before inspecting candidate ELF rows."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection
import compiler_helper_evidence as helpers


class NativeAbiProducerMetadataTests(unittest.TestCase):
    @staticmethod
    def helper_companion():
        """Minimal already-reader-authenticated helper result for join tests."""
        contract = helpers.load_contract(ROOT)
        archive_metadata = dict(helpers.HELPER_METADATA)
        names = helpers.helper_names(contract)
        return {
            'report': selection.file_identity(ROOT / 'compat/x86_64/compiler_helper_evidence.py'),
            'reader': selection.file_identity(Path(helpers.__file__)),
            'account': {
                'source': helpers.source_binding(ROOT, contract),
                'archive_placements': {
                    placement: {
                        name: {'member': contract['archive']['member'], 'section': '.text.' + name,
                               'metadata': copy.deepcopy(archive_metadata)}
                        for name in names
                    }
                    for placement in helpers.ARCHIVE_PLACEMENTS
                },
                'installed_archive_identities': {
                    placement: {'path': '/products/' + placement + '/libcrabc-builtins.a',
                                'sha256': 'a' * 64, 'size': 1}
                    for placement in helpers.ARCHIVE_PLACEMENTS
                },
                'aggregate_c_abi': {'status': 'joined'},
                'shared_libc_projection': {
                    name: {'table': '.symtab', 'row_index': index, 'section_index': index + 1,
                           'section': '.text.' + name,
                           'metadata': {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'}}
                    for index, name in enumerate(names)
                },
                'shared_placement_selected': False,
                'family_completion': False,
                'public_support': False,
                'ordinary_popcount_import': None,
            },
        }

    @classmethod
    def setUpClass(cls):
        cls.contract = selection.load_contract()
        cls.inputs = selection.load_source_inputs(cls.contract, selection.CONTRACT_PATH)
        cls.companion = selection.fixed_c_producer_metadata_selection(cls.contract, cls.inputs)
        expanded = selection.expand_obligations(cls.contract, cls.inputs)
        cls.pending = selection.attach_fixed_c_producer_metadata(expanded, {
            'status': 'component-pass-not-qualification',
            'selection': {
                'owner_group': selection.FIXED_C_PRODUCER_GROUP,
                'owner': selection.FIXED_C_PRODUCER_OWNER,
                'artifacts': list(selection.FIXED_C_PRODUCER_ARTIFACTS),
                'member_count': len(cls.companion['members']),
                'metadata_placement_count': len(cls.companion['members']) * 2,
                'data_layout_placement_count': 8,
            },
            'source_inputs': cls.companion['source_inputs'],
            'inputs': {},
            'selected_metadata': cls.companion['metadata'],
            'account': {},
        })
        cls.helper_pending = selection.attach_compiler_helper_shared_placement(
            expanded, cls.helper_companion(), cls.contract, cls.inputs,
        )
        cls.records = {row['identity']['name']: row for row in expanded}

    def placements(self, name):
        return {row['artifact_key']: row['metadata']
                for row in self.records[name]['expected_placements']}

    def adapter_fixture(self):
        """Create only the physical product records the adapter must cross-bind.

        The producer implementation is mocked below.  This leaves the test at
        the actual selection adapter boundary: authenticated base-inventory
        roles, ELF artifact identities, and the before/after transaction are
        all real files rather than a duplicated producer reader.
        """
        parent = ROOT / '.work/x86_64/native-abi-producer-metadata-adapter-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)

        def write(relative, value):
            path = work / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode() + b'\n')
            return path

        static = work / 'static'
        dynamic = work / 'dynamic'
        static.mkdir()
        dynamic.mkdir()
        static_manifest = write('static/share/crabc/manifest.json', {})
        static_provenance = write('static/share/crabc/libc-static.provenance.json', {})
        static_libc = write('static/usr/lib/libc.a', b'static-libc\n')
        shared_manifest = write('dynamic/share/crabc/manifest.json', {})
        shared_provenance = write('dynamic/share/crabc/libc-shared.provenance.json', {})
        dynamic_state = write('dynamic/share/crabc/dynamic-product-state.json', {})
        shared_libc = write('dynamic/usr/lib/libc.so', b'shared-libc\n')
        preparation = write('static-preparation.json', {})
        candidate_build = {'revision': 'fixture-revision', 'source_content_sha256': 'f' * 64}
        static_root = selection.inventory.STATIC_PRODUCT_PATH
        dynamic_root = selection.inventory.DYNAMIC_PRODUCT_PATH

        static_manifest_record = selection._producer_product_identity(
            static_manifest, str(static_root / 'share/crabc/manifest.json'), 'fixture static manifest')
        static_provenance_record = selection._producer_product_identity(
            static_provenance, str(static_root / 'share/crabc/libc-static.provenance.json'), 'fixture static provenance')
        shared_manifest_record = selection._producer_product_identity(
            shared_manifest, str(dynamic_root / 'share/crabc/manifest.json'), 'fixture shared manifest')
        shared_provenance_record = selection._producer_product_identity(
            shared_provenance, str(dynamic_root / 'share/crabc/libc-shared.provenance.json'), 'fixture shared provenance')
        static_libc_record = selection._producer_product_identity(
            static_libc, str(static_root / 'usr/lib/libc.a'), 'fixture static libc')
        shared_libc_record = selection._producer_product_identity(
            shared_libc, str(dynamic_root / 'usr/lib/libc.so'), 'fixture shared libc')
        preparation_record = selection._producer_product_identity(
            preparation, str(selection.inventory.STATIC_PREPARATION_PATH), 'fixture static preparation')
        dynamic_state_record = selection._producer_product_identity(
            dynamic_state, str(dynamic_root / selection.inventory.DYNAMIC_STATE_RELATIVE), 'fixture dynamic state')
        dynamic_materialization_state = {
            'logical_path': str(dynamic_root / selection.inventory.DYNAMIC_STATE_RELATIVE),
            'identity': dynamic_state_record, 'manifest_sha256': shared_manifest_record['sha256'], 'state': {},
        }
        base = {
            'inputs': {
                'pinned_musl': {},
                'static_product': {
                    'kind': 'static', 'root': str(static_root), 'manifest': static_manifest_record,
                    'payload_files': {'share/crabc/libc-static.provenance.json': static_provenance_record['sha256']},
                    'selection': {'libc_archive': static_libc_record, 'archive_aliases': []},
                },
                'dynamic_product': {
                    'kind': 'dynamic', 'root': str(dynamic_root), 'manifest': shared_manifest_record,
                    'payload_files': {
                        'share/crabc/libc-shared.provenance.json': shared_provenance_record['sha256'],
                        'share/crabc/dynamic-product-state.json': dynamic_state_record['sha256'],
                    },
                    'selection': {'libc_shared': shared_libc_record, 'loader': {}, 'loader_alias': {}},
                    'materialization_state': copy.deepcopy(dynamic_materialization_state),
                },
            },
            'product_provenance': {
                'candidate_build': candidate_build,
                'static_preparation': {
                    'logical_path': str(selection.inventory.STATIC_PREPARATION_PATH), 'source': {},
                    'product_selector': 'primary', 'manifest_sha256': static_manifest_record['sha256'],
                    'receipt': {'logical_path': str(selection.inventory.STATIC_PREPARATION_PATH),
                                'identity': preparation_record, 'snapshot': {}},
                },
                'dynamic_materialization': {
                    **dynamic_materialization_state, 'state_file': {
                        'logical_path': str(dynamic_root / selection.inventory.DYNAMIC_STATE_RELATIVE),
                        'identity': dynamic_state_record, 'snapshot': {},
                    },
                },
            },
        }
        base_path = write('base-inventory.json', base)
        elf_path = write('elf-facts.json', {})
        base_identity = selection.file_identity(base_path)
        original_base = {
            'path': str(selection.elf_facts.BASE_REPORT),
            **{key: base_identity[key] for key in ('sha256', 'size', 'mode')},
        }
        retained_base = {
            'path': 'inputs/base-inventory-report.json',
            **{key: base_identity[key] for key in ('sha256', 'size', 'mode')},
        }
        artifacts = {
            artifact.key: {'kind': artifact.kind, 'elf_type': 'ET_DYN',
                           'identity': {'path': '/unused/' + artifact.key, 'sha256': 'b' * 64, 'size': 1, 'mode': 0o644},
                           'binding': {}}
            for artifact in selection.elf_facts.ARTIFACTS
        }
        artifacts['candidate-static']['identity'] = static_libc_record
        artifacts['candidate-shared']['identity'] = shared_libc_record
        collector = {'revision': candidate_build['revision'], 'content_sha256': candidate_build['source_content_sha256']}
        facts = {
            'base_inventory': {
                'report': {'original': original_base, 'retained': retained_base},
                'collector_execution_source': collector, 'candidate_build': candidate_build,
            },
            'artifacts': artifacts,
        }
        paths = {'elf_report': elf_path, 'base_inventory': base_path, 'static_preparation': preparation,
                 'static_product': static, 'dynamic_product': dynamic}
        measurement = {
            'inputs': {},
            'reports': {key: selection.file_identity(paths[key])
                        for key in ('elf_report', 'base_inventory', 'static_preparation')},
            'reader': {}, 'python': {}, 'argv': [], 'cwd': str(ROOT), 'environment': {},
            'returncode': 0, 'stdout': '', 'stderr': '', 'collector_source': collector,
            'candidate_build': candidate_build,
        }
        return paths, facts, measurement, shared_provenance

    @staticmethod
    def producer_account():
        return {
            'schema': selection.producer_metadata.SCHEMA,
            'status': 'component-pass-not-qualification',
            'status_flags': {'family_completion': False, 'promotion_ready': False, 'public_support': False},
            'scope': {
                'member_count': 424,
                'metadata_buckets': {
                    'strong-functions': 419, 'weak-null-fallback': 1,
                    'data-objects': 3, 'initial-exec-tls': 1,
                },
                'rust_root_c_imports': 7,
                'shared_dynsym_private_names': 'absent',
            },
        }

    def test_fixed_c_function_ownership_preserves_the_defined_weak_fallback(self):
        names = (ROOT / 'libc/src/c_abi/x86_64/owned_mimalloc_hidden.list').read_text().splitlines()
        objects = {'_mi_cpu_has_popcnt', '_mi_heap_default_key', '_mi_stats_main', 'mi_thread_locals'}
        self.assertEqual(len(names), 424)
        for name in names:
            if name in objects:
                continue
            with self.subTest(name=name):
                self.assertEqual(self.records[name]['selection']['disposition'], 'private-provider')
                self.assertEqual(self.placements(name), {
                    'candidate-static': {'type': 'FUNC', 'binding': 'WEAK' if name == '_ZSt15get_new_handlerv' else 'GLOBAL',
                                         'visibility': 'DEFAULT'},
                    'candidate-shared': {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'},
                })

    def test_fixed_c_object_alignment_uses_the_source_minimum_in_both_placements(self):
        # Generic alignment constrains both a section and its symbol offset.
        # The owning component separately checks the compiler's 32-byte stats
        # section; that does not strengthen the object's C alignment of eight.
        layouts = {
            '_mi_cpu_has_popcnt': ('OBJECT', 1, 64, 64),
            '_mi_heap_default_key': ('OBJECT', 4, 4, 4),
            '_mi_stats_main': ('OBJECT', 4368, 8, 8),
            'mi_thread_locals': ('TLS', 8, 8, 8),
        }
        for name, (kind, size, static_alignment, shared_alignment) in layouts.items():
            with self.subTest(name=name):
                self.assertEqual(self.placements(name), {
                    'candidate-static': {'type': kind, 'binding': 'GLOBAL', 'visibility': 'DEFAULT',
                                         'size_bytes': size, 'alignment_bytes': static_alignment},
                    'candidate-shared': {'type': kind, 'binding': 'LOCAL', 'visibility': 'DEFAULT',
                                         'size_bytes': size, 'alignment_bytes': shared_alignment},
                })

    def test_fixed_c_selection_binds_the_exact_owner_roster_and_source_inputs(self):
        self.assertEqual(self.companion['group']['id'], selection.FIXED_C_PRODUCER_GROUP)
        self.assertEqual(self.companion['group']['owner'], selection.FIXED_C_PRODUCER_OWNER)
        self.assertEqual(self.companion['members'], (ROOT / 'libc/src/c_abi/x86_64/owned_mimalloc_hidden.list').read_text().splitlines())
        self.assertEqual(len(self.pending), 848)
        for name in selection.FIXED_C_PRODUCER_SOURCE_FILES:
            with self.subTest(name=name):
                self.assertEqual(self.companion['source_inputs'][name], selection.file_identity(ROOT / name))

    def test_fixed_c_selection_rejects_another_owner_or_source_identity(self):
        contract = copy.deepcopy(self.contract)
        group = next(row for row in contract['owner_groups'] if row['id'] == selection.FIXED_C_PRODUCER_GROUP)
        group['owner'] = 'prefix-derived-private-owner'
        with self.assertRaisesRegex(selection.SelectionError, 'scope'):
            selection.fixed_c_producer_metadata_selection(contract, self.inputs)
        inputs = copy.deepcopy(self.inputs)
        inputs['bindings']['compat/x86_64/owned_mimalloc_producer_metadata.toml']['sha256'] = '0' * 64
        with self.assertRaisesRegex(selection.SelectionError, 'source input differs'):
            selection.fixed_c_producer_metadata_selection(self.contract, inputs)

    def test_fixed_c_selection_rejects_the_old_static_section_alignment_as_symbol_alignment(self):
        metadata = copy.deepcopy(self.companion['metadata'])
        metadata['_mi_stats_main']['static']['alignment_bytes'] = 32
        with mock.patch.object(selection.producer_metadata, 'selected_metadata', return_value=metadata):
            with self.assertRaisesRegex(selection.SelectionError, 'source alignment differs'):
                selection.fixed_c_producer_metadata_selection(self.contract, self.inputs)

    def test_fixed_c_adapter_binds_the_replayed_product_roles_before_accounting(self):
        paths, facts, measurement, _ = self.adapter_fixture()
        with mock.patch.object(selection.producer_metadata, 'account_producer_metadata',
                               return_value=self.producer_account()) as account:
            result = selection.fixed_c_producer_metadata_adapter(
                facts, measurement, paths, self.contract, self.inputs,
            )
        account.assert_called_once()
        self.assertEqual(result['selection']['member_count'], 424)
        self.assertEqual(result['selection']['metadata_placement_count'], 848)
        self.assertEqual(result['inputs']['before'], result['inputs']['after'])
        self.assertEqual(result['inputs']['public_elf_replay']['candidate_build'], measurement['candidate_build'])

    def test_fixed_c_adapter_rejects_a_product_file_mutated_by_the_account(self):
        paths, facts, measurement, shared_provenance = self.adapter_fixture()

        def mutate(*_):
            shared_provenance.write_text('{"changed":true}\n')
            return self.producer_account()

        with mock.patch.object(selection.producer_metadata, 'account_producer_metadata', side_effect=mutate):
            with self.assertRaisesRegex(selection.SelectionError, 'changed during account'):
                selection.fixed_c_producer_metadata_adapter(
                    facts, measurement, paths, self.contract, self.inputs,
                )

    def test_owned_helpers_keep_both_archive_roles_and_select_the_private_libc_copy(self):
        group = next(row for row in self.contract['owner_groups'] if row['id'] == 'owned-compiler-helper-archive')
        self.assertEqual(len(group['members']), 23)
        for name in group['members']:
            with self.subTest(name=name):
                self.assertEqual(self.records[name]['selection']['owner'], 'builtins')
                self.assertEqual(self.placements(name), {
                    'static-builtins': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'},
                    'dynamic-builtins': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'},
                    'candidate-shared': {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'},
                })

    def test_owned_helpers_reject_a_shared_projection_outside_the_exact_source_scope(self):
        expanded = selection.expand_obligations(self.contract, self.inputs)
        companion = self.helper_companion()
        companion['account']['shared_libc_projection']['__popcountdi2']['metadata']['binding'] = 'GLOBAL'
        with self.assertRaisesRegex(selection.SelectionError, 'private libc projection differs'):
            selection.attach_compiler_helper_shared_placement(expanded, companion, self.contract, self.inputs)

        expanded = selection.expand_obligations(self.contract, self.inputs)
        record = next(row for row in expanded if row['identity']['name'] == '__popcountdi2')
        record['selection']['owner'] = 'another-owner'
        with self.assertRaisesRegex(selection.SelectionError, 'selected owner differs'):
            selection.attach_compiler_helper_shared_placement(
                expanded, self.helper_companion(), self.contract, self.inputs,
            )

        expanded = selection.expand_obligations(self.contract, self.inputs)
        companion = self.helper_companion()
        companion['account']['shared_placement_selected'] = True
        with self.assertRaisesRegex(selection.SelectionError, 'exceeds its producer scope'):
            selection.attach_compiler_helper_shared_placement(expanded, companion, self.contract, self.inputs)

    def test_owned_helpers_preserve_the_reader_projection_for_each_selected_copy(self):
        self.assertEqual(len(self.helper_pending), 23)
        for index, row in enumerate(self.helper_pending):
            with self.subTest(name=row['identity']['name']):
                self.assertEqual(row['artifact_key'], 'candidate-shared')
                self.assertEqual(row['metadata'], {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'})
                self.assertEqual(row['projection']['table'], '.symtab')
                self.assertEqual(row['projection']['row_index'], index)
                self.assertEqual(row['projection']['section'], '.text.' + row['identity']['name'])

    @staticmethod
    def _facts_with_one_definition(*, artifact_key, row, section):
        """Minimal complete physical roster for the generic placement join."""
        facts = {'artifacts': {}, 'facts': {}}
        for artifact in selection.elf_facts.ARTIFACTS:
            facts['artifacts'][artifact.key] = {'identity': {'sha256': 'a' * 64}}
            member = {
                'sections': [{'index': 1, 'name': '.text', 'alignment': 8}],
                'symbol_tables': [{
                    'name': '.dynsym' if artifact.elf_type == 'DYN' else '.symtab',
                    'section_index': 2, 'rows': [],
                }],
            }
            if artifact.kind == 'archive':
                member.update(member_index=0, member_occurrence=0, member='fixture.o')
                facts['facts'][artifact.key] = [member]
            else:
                facts['facts'][artifact.key] = member
        target = facts['facts'][artifact_key]
        member = target[0] if isinstance(target, list) else target
        member['sections'] = [section]
        if artifact_key == 'candidate-shared' and row['binding'] == 'LOCAL':
            member['symbol_tables'][0]['name'] = '.symtab'
        member['symbol_tables'][0]['rows'] = [row]
        return facts

    def test_generic_accounting_empty_difference_rows_reach_both_producer_binders(self):
        """Exercise the real producer -> placement-account -> binder route.

        The original regression was not a hand-authored join shape: generic
        accounting deliberately emits one difference row with an empty field
        list for a matching physical definition.
        """
        fixed = next(row for row in self.pending if row['artifact_key'] == 'candidate-static')
        fixed_metadata = fixed['metadata']
        fixed_row = {
            'name': fixed['identity']['name'], 'raw_name': fixed['identity']['name'],
            'version': None, 'version_default': False, 'binding': fixed_metadata['binding'],
            'visibility': fixed_metadata['visibility'], 'section_index': '1', 'type': fixed_metadata['type'],
            'value': '0000000000000000', 'size_bytes': 0, 'size': '0', 'row_index': 0,
            'raw': 'fixture fixed producer', 'other': None, 'version_index': None, 'common_alignment': None,
        }
        fixed_facts = self._facts_with_one_definition(
            artifact_key='candidate-static', row=fixed_row,
            section={'index': 1, 'name': '.text', 'alignment': 8},
        )
        fixed_accounting = selection.account_placements([copy.deepcopy(self.records[fixed['identity']['name']])], fixed_facts)
        fixed_join = next(row for row in fixed_accounting['placement_joins']
                          if row['artifact_key'] == 'candidate-static')
        self.assertEqual(fixed_join['metadata_differences'][0]['fields'], [])
        self.assertEqual(
            selection.bind_fixed_c_producer_metadata_joins(fixed_accounting, [copy.deepcopy(fixed)])[0]['occurrence_indices'],
            fixed_join['occurrence_indices'],
        )

        helper = self.helper_pending[0]
        projection = helper['projection']
        helper_row = {
            'name': helper['identity']['name'], 'raw_name': helper['identity']['name'],
            'version': None, 'version_default': False, 'binding': 'LOCAL', 'visibility': 'DEFAULT',
            'section_index': str(projection['section_index']), 'type': 'FUNC', 'value': '0000000000000000',
            'size_bytes': 0, 'size': '0', 'row_index': projection['row_index'],
            'raw': 'fixture helper producer', 'other': None, 'version_index': None, 'common_alignment': None,
        }
        helper_facts = self._facts_with_one_definition(
            artifact_key='candidate-shared', row=helper_row,
            section={'index': projection['section_index'], 'name': projection['section'], 'alignment': 8},
        )
        helper_accounting = selection.account_placements([copy.deepcopy(self.records[helper['identity']['name']])], helper_facts)
        helper_join = next(row for row in helper_accounting['placement_joins']
                           if row['artifact_key'] == 'candidate-shared')
        self.assertEqual(helper_join['metadata_differences'][0]['fields'], [])
        self.assertEqual(
            selection.bind_compiler_helper_shared_placement_joins(helper_accounting, [copy.deepcopy(helper)])[0]['occurrence_indices'],
            helper_join['occurrence_indices'],
        )

    def test_metadata_binders_keep_the_generic_empty_field_differences(self):
        """Generic placement accounting records one empty row per exact match.

        ``account_placements`` retains a metadata-difference record for each
        observed candidate definition.  An empty ``fields`` list is its exact
        success representation; neither focused producer binder may mistake
        that retained audit row for a mismatch.
        """
        fixed = copy.deepcopy(self.pending[:1])
        fixed_accounting = {
            'placement_joins': [{
                'identity': fixed[0]['identity'], 'artifact_key': fixed[0]['artifact_key'],
                'expected_metadata': fixed[0]['metadata'], 'placement_observed': True,
                'metadata_differences': [{'occurrence_index': 11, 'fields': []}],
                'definition_count': 1, 'occurrence_indices': [11],
            }],
        }
        self.assertEqual(
            selection.bind_fixed_c_producer_metadata_joins(fixed_accounting, fixed)[0]['occurrence_indices'],
            [11],
        )
        changed_fixed = copy.deepcopy(fixed_accounting)
        changed_fixed['placement_joins'][0]['metadata_differences'][0]['fields'] = ['visibility']
        with self.assertRaisesRegex(selection.SelectionError, 'not exact'):
            selection.bind_fixed_c_producer_metadata_joins(changed_fixed, fixed)

        helper = copy.deepcopy(self.helper_pending[:1])
        row = helper[0]
        observed = {
            'index': 17, 'artifact_key': 'candidate-shared', 'table': '.symtab',
            'member_index': None, 'member_occurrence': None, 'role': 'local-definition',
            'row': {
                'name': row['identity']['name'], 'version': None, 'version_default': False,
                'row_index': row['projection']['row_index'],
                'section_index': str(row['projection']['section_index']),
            },
            'definition_section': {'name': row['projection']['section']},
        }
        helper_accounting = {
            'placement_joins': [{
                'identity': row['identity'], 'artifact_key': 'candidate-shared',
                'expected_metadata': row['metadata'], 'placement_observed': True,
                'metadata_differences': [{'occurrence_index': 17, 'fields': []}],
                'definition_count': 1, 'occurrence_indices': [17],
            }],
            'occurrences': [observed],
        }
        self.assertEqual(
            selection.bind_compiler_helper_shared_placement_joins(helper_accounting, helper)[0]['occurrence_indices'],
            [17],
        )
        changed_helper = copy.deepcopy(helper_accounting)
        changed_helper['placement_joins'][0]['metadata_differences'][0]['fields'] = ['visibility']
        with self.assertRaisesRegex(selection.SelectionError, 'absent, ambiguous or mismatched'):
            selection.bind_compiler_helper_shared_placement_joins(changed_helper, helper)

    def test_owned_helpers_bind_the_selected_symtab_row_and_reject_a_leak_or_row_swap(self):
        pending = copy.deepcopy(self.helper_pending[:1])
        row = pending[0]
        observed = {
            'index': 17, 'artifact_key': 'candidate-shared', 'table': '.symtab',
            'member_index': None, 'member_occurrence': None, 'role': 'local-definition',
            'row': {
                'name': row['identity']['name'], 'version': None, 'version_default': False,
                'row_index': row['projection']['row_index'],
                'section_index': str(row['projection']['section_index']),
            },
            'definition_section': {'name': row['projection']['section']},
        }
        accounting = {
            'placement_joins': [{
                'identity': row['identity'], 'artifact_key': 'candidate-shared',
                'expected_metadata': row['metadata'], 'placement_observed': True,
                'metadata_differences': [{'occurrence_index': 17, 'fields': []}],
                'definition_count': 1, 'occurrence_indices': [17],
            }],
            'occurrences': [observed],
        }
        bound = selection.bind_compiler_helper_shared_placement_joins(accounting, pending)
        self.assertEqual(bound[0]['occurrence_indices'], [17])

        swapped = copy.deepcopy(accounting)
        swapped['occurrences'][0]['row']['row_index'] += 1
        with self.assertRaisesRegex(selection.SelectionError, 'projection does not bind'):
            selection.bind_compiler_helper_shared_placement_joins(swapped, pending)

        leaked = copy.deepcopy(accounting)
        leak = copy.deepcopy(observed)
        leak['index'] = 18
        leak['table'] = '.dynsym'
        leaked['occurrences'].append(leak)
        with self.assertRaisesRegex(selection.SelectionError, 'leaked into dynsym'):
            selection.bind_compiler_helper_shared_placement_joins(leaked, pending)


if __name__ == '__main__':
    unittest.main()
