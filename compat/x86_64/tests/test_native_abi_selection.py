#!/usr/bin/env python3
"""Selection failures must stay visible despite complete ELF observations."""
from __future__ import annotations

import copy
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('native_abi_selection_test', ROOT / 'compat/x86_64/native_abi_selection.py')
assert SPEC is not None and SPEC.loader is not None
selection = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = selection
SPEC.loader.exec_module(selection)


def identity(name, version=None, default=False):
    return {'name': name, 'version': version, 'version_default': default}


def symbol(name, *, binding='GLOBAL', visibility='DEFAULT', section='1', kind='FUNC', value='0000000000000000', size=4):
    return {'name': name, 'raw_name': name, 'version': None, 'version_default': False,
            'binding': binding, 'visibility': visibility, 'section_index': section,
            'type': kind, 'value': value, 'size_bytes': size, 'size': str(size),
            'row_index': 1, 'raw': 'retained fixture row', 'other': None,
            'version_index': None, 'common_alignment': None}


class SelectionContractTests(unittest.TestCase):
    def test_policy_rejects_unknown_selection_rule_instead_of_prefix_expansion(self):
        contract = selection.load_contract()
        contract['owner_groups'][0]['selector'] = 'name-prefix'
        with self.assertRaisesRegex(selection.SelectionError, 'selector'):
            selection.validate_contract(contract)

    def test_policy_rejects_duplicate_owner_ids_and_unknown_root_fields(self):
        contract = selection.load_contract()
        contract['owner_groups'].append(copy.deepcopy(contract['owner_groups'][0]))
        with self.assertRaisesRegex(selection.SelectionError, 'duplicate'):
            selection.validate_contract(contract)
        contract = selection.load_contract()
        contract['public_support'] = False
        with self.assertRaisesRegex(selection.SelectionError, 'fields'):
            selection.validate_contract(contract)

    def test_provider_group_cannot_erase_placements_with_an_empty_roster(self):
        contract = selection.load_contract()
        contract['owner_groups'][0]['artifacts'] = []
        with self.assertRaisesRegex(selection.SelectionError, 'artifacts'):
            selection.validate_contract(contract)

    def test_frozen_tsv_rejects_same_count_substitution_and_wrong_field_roster(self):
        spec = {'columns': ['name', 'version'], 'records': 1, 'unique_names': 1}
        original = b'name\tversion\nopen\t-\n'
        self.assertEqual(selection.parse_frozen_tsv(original, original, spec)[0]['name'], 'open')
        with self.assertRaisesRegex(selection.SelectionError, 'frozen.*bytes'):
            selection.parse_frozen_tsv(b'name\tversion\nclose\t-\n', original, spec)
        with self.assertRaisesRegex(selection.SelectionError, 'columns'):
            selection.parse_frozen_tsv(original, original, {**spec, 'columns': ['version', 'name']})

    def test_json_duplicate_keys_are_not_last_writer_wins(self):
        work = ROOT / '.work/x86_64/native-abi-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            path = Path(temporary) / 'duplicate.json'
            path.write_text('{"schema":"first","schema":"second"}\n')
            with self.assertRaisesRegex(selection.SelectionError, 'duplicate'):
                selection.read_json(path)

    def test_exact_identity_never_collapses_version_or_defaultness(self):
        values = [identity('open'), identity('open', 'VER_1'), identity('open', 'VER_1', True)]
        self.assertEqual(len({selection.identity_key(v) for v in values}), 3)
        with self.assertRaises(selection.SelectionError):
            selection.identity_key(identity('open', None, True))
        with self.assertRaises(selection.SelectionError):
            selection.identity_key(identity('open', None, 0))

    def test_frozen_text_requires_an_explicit_unversioned_form_without_invented_defaultness(self):
        self.assertEqual(selection.frozen_identity({'name': 'open', 'version': '-'}), identity('open'))
        for row in ({'name': 'open', 'version': 'V1'}, {'name': 'open@@V1', 'version': 'V1'}):
            with self.assertRaisesRegex(selection.SelectionError, 'version'):
                selection.frozen_identity(row)

    def test_object_source_mutability_is_boolean_and_not_declaration_constness(self):
        contract = selection.load_contract()
        objects = {r['name']: r for r in contract['object_contracts']}
        self.assertIs(objects['stdin']['source_mutable'], True)
        self.assertIn('const', objects['stdin']['declaration'])
        self.assertIs(objects['in6addr_any']['source_mutable'], False)
        self.assertIs(objects['_ns_flagdata']['source_mutable'], False)
        self.assertIn('c_abi_type', objects['stdin'])
        self.assertIn('meaning', objects['in6addr_any'])
        objects['in6addr_any']['source_mutable'] = 0
        with self.assertRaisesRegex(selection.SelectionError, 'source_mutable'):
            selection.validate_contract(contract)

    def test_declaration_kind_keeps_accessor_and_abi_only_objects_out_of_variable_selection(self):
        objects = {r['name']: r for r in selection.load_contract()['object_contracts']}
        self.assertEqual(objects['stdin']['declaration_kind'], 'installed-variable')
        self.assertEqual(objects['h_errno']['declaration_kind'], 'accessor-macro')
        self.assertEqual(objects['_dl_debug_addr']['declaration_kind'], 'abi-only')
        report = {'occurrences': [{'tree': 'candidate', 'name': 'stdin', 'kind': 'variable', 'linkage_status': 'source-external-declaration'},
                                  {'tree': 'candidate', 'name': 'irrelevant_internal', 'kind': 'variable', 'linkage_status': 'unresolved-from-json'}],
                  'macro_events': [{'tree': 'candidate', 'name': 'h_errno', 'event': 'define', 'replacement': '(*__h_errno_location())'}],
                  'final_active_macros': [{'tree': 'candidate', 'name': 'h_errno', 'replacement': '(*__h_errno_location())'}]}
        account = selection.account_object_declarations(report, [objects[n] for n in ('stdin', 'h_errno', '_dl_debug_addr')])
        self.assertEqual(account['unresolved_selected_occurrences'], [])
        self.assertEqual(len(account['selected_occurrences']), 1)
        self.assertEqual(account['requirements'][1]['variable_occurrence_indices'], [])
        self.assertEqual(account['requirements'][1]['active_macro_indices'], [0])
        self.assertEqual(account['requirements'][2]['remaining'], [])
        report['occurrences'][0]['linkage_status'] = 'unresolved-from-json'
        self.assertEqual(len(selection.account_object_declarations(report, [objects['stdin']])['unresolved_selected_occurrences']), 1)

    def test_selected_alignment_is_a_power_of_two_and_not_a_numeric_boolean(self):
        for bad in (3, True):
            contract = selection.load_contract()
            contract['object_contracts'][0]['alignment_bytes'] = bad
            with self.assertRaisesRegex(selection.SelectionError, 'alignment'):
                selection.validate_contract(contract)

    def test_object_type_and_source_meaning_are_distinct_mandatory_policy_fields(self):
        contract = selection.load_contract()
        del contract['object_contracts'][0]['c_abi_type']
        with self.assertRaisesRegex(selection.SelectionError, 'fields'):
            selection.validate_contract(contract)


class PhysicalAccountingTests(unittest.TestCase):
    def test_hidden_static_definition_is_bindable_and_named_weak_und_is_an_import(self):
        rows = [symbol('__asctime_r', visibility='HIDDEN'),
                symbol('__future_optional', binding='WEAK', section='UND'),
                symbol('opaque', binding='<processor specific>: 13', kind='<OS specific>: 12')]
        self.assertEqual([selection.row_role(r) for r in rows],
                         ['definition', 'import', 'unsupported'])
        local = symbol('private_label', binding='LOCAL', visibility='HIDDEN')
        self.assertEqual(selection.row_role(local), 'local-definition')

    def test_unknown_other_and_reserved_section_metadata_are_retained_as_unsupported(self):
        other = symbol('selected_function'); other['other'] = '0x80'
        reserved = symbol('selected_function', section='PRC[0xff00]')
        self.assertEqual(selection.row_role(other), 'unsupported')
        self.assertEqual(selection.row_role(reserved), 'unsupported')

    def test_unnamed_metadata_does_not_erase_a_named_local_undefined_row(self):
        self.assertEqual(selection.row_role(symbol(None, binding='LOCAL', section='UND', kind='NOTYPE')), 'unnamed')
        self.assertEqual(selection.row_role(symbol('local_import', binding='LOCAL', section='UND', kind='NOTYPE')), 'import')

    def test_alias_equal_zero_values_in_different_archive_members_are_not_storage_proof(self):
        left = {'artifact_key': 'candidate-static', 'member_index': 0, 'member_occurrence': 0,
                'table_section_index': 5, 'row': symbol('environ', kind='OBJECT', size=8)}
        right = copy.deepcopy(left)
        right['row']['name'] = '__environ'
        right['member_index'] = 1
        self.assertFalse(selection.same_definition_domain(left, right))
        right['member_index'] = 0
        right['row']['section_index'] = '2'
        self.assertFalse(selection.same_definition_domain(left, right))
        right['row']['section_index'] = '1'
        self.assertTrue(selection.same_definition_domain(left, right))
        right['table_section_index'] = 6
        self.assertFalse(selection.same_definition_domain(left, right))
        right['table_section_index'] = 5
        right['artifact_key'] = 'candidate-shared'
        self.assertFalse(selection.same_definition_domain(left, right))

    def test_guard_pointer_and_tls_metadata_remain_different_storage_contracts(self):
        contract = {'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT',
                    'size_bytes': 8, 'alignment_bytes': 8}
        row = symbol('_dl_debug_addr', kind='OBJECT', size=40)
        self.assertIn('size_bytes', selection.metadata_differences(contract, row, {'alignment': 8}))
        row = symbol('h_errno', kind='TLS', size=4)
        self.assertIn('type', selection.metadata_differences(contract, row, {'alignment': 4}))
        self.assertIn('alignment_bytes', selection.metadata_differences(contract, symbol('object', kind='OBJECT', size=8), {'alignment': 0}))

    def test_selected_static_metadata_uses_only_unambiguous_oracle_occurrences(self):
        reference = [{'index': 3, 'row': symbol('open', binding='WEAK', visibility='HIDDEN')},
                     {'index': 4, 'row': symbol('open', binding='WEAK', visibility='HIDDEN')}]
        resolved = selection.reference_static_metadata(reference, {'type': 'FUNC'})
        self.assertEqual(resolved['metadata'], {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'HIDDEN'})
        self.assertEqual(resolved['occurrence_indices'], [3, 4])
        self.assertIn('binding', selection.metadata_differences(resolved['metadata'], symbol('open'), None))
        self.assertIn('visibility', selection.metadata_differences(resolved['metadata'], symbol('open'), None))
        reference[1]['row']['binding'] = 'GLOBAL'
        self.assertIsNone(selection.reference_static_metadata(reference, {'type': 'FUNC'})['metadata'])
        self.assertIsNone(selection.reference_static_metadata([], {'type': 'FUNC'})['metadata'])

    def test_private_provider_metadata_is_unknown_until_selected_by_source(self):
        facts = empty_facts()
        facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = [symbol('private_owned', kind='OBJECT', size=8)]
        selected = {'identity': identity('private_owned'), 'origins': [], 'selection': {'disposition': 'private-provider', 'owner': 'fixture'},
                    'expected_placements': [{'artifact_key': 'candidate-static', 'metadata': {}}], 'unresolved': []}
        report = selection.account_placements([selected], facts)
        self.assertTrue(any('metadata selection missing' in row.get('reason', '') for row in report['blockers']))
        self.assertTrue(any('data layout selection missing' in row.get('reason', '') for row in report['blockers']))

    def test_static_oracle_rule_does_not_select_other_reference_names_or_use_candidate_metadata(self):
        facts = empty_facts()
        reference = [symbol('selected', binding='WEAK', visibility='HIDDEN'), symbol('unselected_reference')]
        reference[1]['row_index'] = 2
        facts['facts']['reference-static'][0]['symbol_tables'][0]['rows'] = reference
        facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = [symbol('selected')]
        selected = {'identity': identity('selected'), 'origins': [], 'selection': {'disposition': 'public-provider', 'owner': 'fixture'},
                    'expected_placements': [{'artifact_key': 'candidate-static', 'metadata': {'type': 'FUNC'}, 'metadata_rule': 'selected-native-oracle-function'}], 'unresolved': []}
        report = selection.account_placements([selected], facts)
        self.assertEqual(report['placement_joins'][0]['expected_metadata']['binding'], 'WEAK')
        self.assertFalse(report['placement_joins'][0]['placement_observed'])
        self.assertEqual(next(r for r in report['identities'] if r['identity']['name'] == 'unselected_reference')['selection']['disposition'], 'unselected-observation')
        reference.pop(0)
        report = selection.account_placements([selected], facts)
        self.assertIsNone(report['placement_joins'][0]['metadata_origin']['metadata'])
        self.assertTrue(any('oracle' in r.get('reason', '') for r in report['blockers']))

    def test_complete_join_retains_hidden_local_undefined_and_unsupported_occurrences(self):
        facts = empty_facts()
        rows = [symbol('__native_unowned', visibility='HIDDEN'), symbol('optional', section='UND', binding='WEAK'),
                symbol('private_label', binding='LOCAL'), symbol('opaque', kind='<OS specific>: 12')]
        for index, row in enumerate(rows):
            row['row_index'] = index
        facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = rows
        observed = selection.account_placements([], facts)
        self.assertEqual(len(observed['occurrences']), len(rows))
        self.assertEqual({r['row']['name'] for r in observed['occurrences']}, {r['name'] for r in rows})
        self.assertEqual({r['identity']['name'] for r in observed['identities']}, {'__native_unowned', 'optional', 'opaque'})
        optional = next(r for r in observed['identities'] if r['identity']['name'] == 'optional')
        self.assertTrue(any('import' in reason for reason in optional['unresolved']))
        self.assertTrue(observed['blockers'])

    def test_reference_only_accounting_does_not_assign_a_native_definition_an_owner(self):
        facts = empty_facts()
        for key in ('reference-static', 'candidate-static'):
            facts['facts'][key][0]['symbol_tables'][0]['rows'] = [symbol('same_spelling', visibility='HIDDEN')]
        observed = selection.account_placements([], facts)
        record = next(r for r in observed['identities'] if r['identity']['name'] == 'same_spelling')
        self.assertEqual(record['selection']['disposition'], 'unresolved')
        self.assertIsNone(record['selection']['owner'])

    def test_function_alias_requires_selected_feature_and_same_archive_domain(self):
        facts = empty_facts()
        left = symbol('source_alias', binding='WEAK')
        right = symbol('source_target'); right['row_index'] = 2
        facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = [left, right]
        selected = {'identity': identity('source_alias'), 'origins': [], 'selection': {'disposition': 'public-provider', 'owner': 'fixture'},
                    'expected_placements': [{'artifact_key': 'candidate-static', 'metadata': {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'}}],
                    'unresolved': [], 'function_alias_requirements': [{'name': 'source_alias', 'target': 'source_target', 'binding': 'weak-same-address', 'owner': 'selected-feature', 'sources': ['compat/x86_64/parity.toml']}]}
        report = selection.account_placements([selected], facts)
        self.assertTrue(report['function_alias_observations'][0]['same_domain_pairs'])
        self.assertEqual(report['function_alias_observations'][0]['feature_contract']['owner'], 'selected-feature')
        other = copy.deepcopy(facts['facts']['candidate-static'][0])
        other['member_index'] = 1
        other['member_occurrence'] = 1
        other['symbol_tables'][0]['rows'] = [right]
        facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = [left]
        facts['facts']['candidate-static'].append(other)
        report = selection.account_placements([selected], facts)
        self.assertFalse(report['function_alias_observations'][0]['same_domain_pairs'])
        self.assertTrue(any(r['code'] == 'function-alias-domain-missing' for r in report['blockers']))
        facts['facts']['candidate-static'].pop()
        report = selection.account_placements([selected], facts)
        self.assertFalse(report['function_alias_observations'][0]['same_domain_pairs'])

    def test_join_rejects_omitted_artifact_and_duplicate_occurrence(self):
        facts = empty_facts()
        del facts['facts']['static-crtn.o']
        with self.assertRaisesRegex(selection.SelectionError, 'roster'):
            selection.account_placements([], facts)
        facts = empty_facts()
        row = symbol('repeated')
        facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = [row, copy.deepcopy(row)]
        with self.assertRaisesRegex(selection.SelectionError, 'duplicate physical'):
            selection.account_placements([], facts)


class ClosureTests(unittest.TestCase):
    def test_unresolved_record_blocks_closure_even_if_complete_flag_is_true(self):
        report = {'closure': {'complete': True, 'blockers': [{'code': 'unresolved-owner', 'subject': 'random'}]},
                  'status': {'family_completion': False, 'promotion_ready': False, 'public_support': False}}
        with self.assertRaisesRegex(selection.SelectionError, 'incomplete'):
            selection.require_selection_closure(report)

    def test_public_closure_gate_never_accepts_an_unreplayed_true_flag(self):
        with self.assertRaises(selection.SelectionError):
            selection.require_selection_closure({'closure': {'complete': True, 'blockers': []}})

    def test_missing_declarations_semantics_family_and_source_match_are_independent_blockers(self):
        blockers = selection.evidence_blockers(declaration=None, semantic_receipts=[], family_receipts=[],
                                                source_matches=False)
        self.assertEqual({r['code'] for r in blockers},
                         {'declaration-companion-missing', 'semantic-receipts-missing', 'family-receipts-missing', 'selection-product-source-mismatch'})
        with self.assertRaises(selection.SelectionError):
            selection.evidence_blockers(declaration=None, semantic_receipts=[], family_receipts=[], source_matches=0)


class PathAndCommandTests(unittest.TestCase):
    def test_output_freshness_and_physical_parent_checked_before_mutation(self):
        work = ROOT / '.work/x86_64/native-abi-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            parent = Path(temporary)
            fresh = parent / 'fresh'
            self.assertEqual(selection.physical_work_path(fresh, directory=True, own=True, fresh=True), fresh)
            self.assertFalse(fresh.exists())
            fresh.mkdir()
            with self.assertRaisesRegex(selection.SelectionError, 'fresh'):
                selection.physical_work_path(fresh, directory=True, own=True, fresh=True)
            (parent / 'link').symlink_to(fresh, target_is_directory=True)
            with self.assertRaisesRegex(selection.SelectionError, 'physical'):
                selection.physical_work_path(parent / 'link' / 'output', directory=True, own=True, fresh=True)
            with self.assertRaisesRegex(selection.SelectionError, 'outside'):
                selection.physical_work_path(ROOT / 'outside-evidence', directory=True, own=True, fresh=True)

    def test_duplicate_cli_options_and_abbreviations_are_rejected(self):
        base = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            base += ['--' + flag, str(ROOT / '.work/not-present')]
        for variant in (base + ['--output', 'first', '--output=second'], base + ['--out', 'first']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                selection.main(variant)
            self.assertEqual(result.exception.code, 2)



def empty_facts():
    """Join-only fixture; the production reader separately validates raw ELF."""
    result = {'artifacts': {}, 'facts': {}}
    for artifact in selection.elf_facts.ARTIFACTS:
        result['artifacts'][artifact.key] = {'identity': {'sha256': 'a' * 64}}
        member = {'sections': [{'index': 1, 'alignment': 8}],
                  'symbol_tables': [{'name': '.dynsym' if artifact.elf_type == 'DYN' else '.symtab', 'section_index': 2, 'rows': []}]}
        if artifact.kind == 'archive':
            member.update(member_index=0, member_occurrence=0, member='repeated.o')
            result['facts'][artifact.key] = [member]
        else:
            result['facts'][artifact.key] = member
    return result


if __name__ == '__main__':
    unittest.main()
