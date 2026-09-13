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
from unittest import mock

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


SOURCE_OWNER_NAMES = frozenset('''
_IO_feof_unlocked _IO_ferror_unlocked _IO_getc _IO_getc_unlocked _IO_putc _IO_putc_unlocked
__crypt_blowfish __crypt_md5 __crypt_r __crypt_sha256 __crypt_sha512
__ctype_b_loc __ctype_tolower_loc __ctype_toupper_loc
__cxa_atexit __cxa_finalize __fork_handler __funcs_on_exit
__isalnum_l __isalpha_l __isblank_l __iscntrl_l __isdigit_l __isgraph_l __islower_l __isprint_l __ispunct_l __isspace_l __isupper_l __isxdigit_l __tolower_l __toupper_l __strcasecmp_l __strncasecmp_l __strcoll_l __strxfrm_l
__duplocale __freelocale __newlocale __nl_langinfo __nl_langinfo_l __uselocale __iswalnum_l __iswalpha_l __iswblank_l __iswcntrl_l __iswctype_l __iswdigit_l __iswgraph_l __iswlower_l __iswprint_l __iswpunct_l __iswspace_l __iswupper_l __iswxdigit_l __towctrans_l __towlower_l __towupper_l __wcscoll_l __wcsxfrm_l __wctrans_l __wctype_l
__strerror_l __wcsftime_l __strtod_l __strtof_l __strtold_l
__strtoimax_internal __strtol_internal __strtoll_internal __strtoul_internal __strtoull_internal __strtoumax_internal
__isoc99_fscanf __isoc99_fwscanf __isoc99_scanf __isoc99_sscanf __isoc99_swscanf __isoc99_vfscanf __isoc99_vfwscanf __isoc99_vscanf __isoc99_vsscanf __isoc99_vswscanf __isoc99_vwscanf __isoc99_wscanf
__fgetwc_unlocked __fputwc_unlocked __getdelim __overflow __uflow fpurge
__fxstat __fxstatat __lxstat __xstat __getauxval __libc_start_main __tls_get_addr __setjmp __sigsetjmp __stack_chk_fail __qsort_r __lgammal_r __sysv_signal __xpg_basename __xpg_strerror_r __posix_getopt pivot_root
'''.split())

CRT_OWNER_NAMES = frozenset('''
__crabc_preinit_array_start_address __crabc_preinit_array_end_address
__crabc_init_array_start_address __crabc_init_array_end_address
__crabc_fini_array_start_address __crabc_fini_array_end_address
__crabc_x86_64_dynamic_executable_fini __crabc_x86_64_dynamic_executable_init __crabc_x86_64_dynamic_start
__crabc_x86_64_executable_fini __crabc_x86_64_executable_init
__crabc_x86_64_owned_crt_handoff_value __crabc_x86_64_static_pie_start _start
'''.split())


class SourceOwnerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = selection.load_contract()
        cls.inputs = selection.load_source_inputs(cls.contract, selection.CONTRACT_PATH)
        cls.records = {record['identity']['name']: record
                       for record in selection.expand_obligations(cls.contract, cls.inputs)}
        cls.groups = {group['id']: group for group in cls.contract['owner_groups']}

    def test_exact_frozen_source_set_is_finite_and_keeps_explicit_exclusions_unselected(self):
        source_groups = [group for group in self.groups.values()
                         if group['id'].startswith('source-owned-')]
        selected = {name for group in source_groups for name in group['members']}
        self.assertEqual(selected, SOURCE_OWNER_NAMES)
        self.assertEqual(len(selected), 108)
        for name in ('__crabc_runtime_v1', 'initstate', 'random', 'setstate', 'srandom', 'rust_eh_personality'):
            self.assertNotIn(name, selected)
            self.assertFalse(self.records[name]['selection'].get('group', '').startswith('source-owned-'))

    def test_source_selected_public_static_functions_use_oracle_metadata_only_after_selection(self):
        for group in self.groups.values():
            if not group['id'].startswith('source-owned-') or group['disposition'] != 'public-provider':
                continue
            if 'candidate-static' in group['artifacts'] and group['id'] != 'source-owned-stdio-protected-boundaries':
                self.assertEqual(group['static_metadata_rule'], 'selected-native-oracle-function')
        protected = self.groups['source-owned-stdio-protected-boundaries']
        self.assertEqual(protected['static_metadata_rule'], 'explicit')
        self.assertEqual(protected['placement_metadata']['candidate-static'],
                         {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'PROTECTED'})
        for name in ('__uflow', '__overflow'):
            record = self.records[name]
            self.assertEqual(record['selection']['group'], protected['id'])
            self.assertEqual(record['expected_placements'], [
                {'artifact_key': 'candidate-static', 'metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'PROTECTED'}, 'metadata_rule': 'explicit'},
                {'artifact_key': 'candidate-shared', 'metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'PROTECTED'}, 'metadata_rule': 'explicit'},
            ])

    def test_crypt_direct_bodies_and_tls_startup_boundaries_do_not_collapse(self):
        crypt = self.groups['source-owned-crypt-private-helper-bodies']
        self.assertEqual(crypt['members'], ['__crypt_blowfish', '__crypt_md5', '__crypt_r', '__crypt_sha256', '__crypt_sha512'])
        self.assertEqual(crypt['disposition'], 'private-provider')
        self.assertNotIn('crypt_r', crypt['members'])
        self.assertEqual(self.records['__crypt_r']['selection']['group'], crypt['id'])
        tls = self.records['__tls_get_addr']
        self.assertEqual(tls['selection']['group'], 'source-owned-loader-libc-tls-boundary')
        self.assertEqual([row['artifact_key'] for row in tls['expected_placements']], ['candidate-shared', 'candidate-loader'])
        self.assertNotIn('candidate-static', [row['artifact_key'] for row in tls['expected_placements']])
        qsort = self.records['__qsort_r']
        self.assertEqual(qsort['selection']['group'], 'source-owned-qsort-context-body')
        self.assertIn('Direct __qsort_r context ABI body', qsort['selection']['reason'])
        self.assertNotIn('qsort_r', self.groups['source-owned-qsort-context-body']['members'])
        startup = self.records['__libc_start_main']
        self.assertEqual(startup['selection']['group'], 'source-owned-crt-libc-startup-boundary')
        self.assertEqual([row['artifact_key'] for row in startup['expected_placements']], ['candidate-static', 'candidate-shared'])

    def test_crt_definition_placements_keep_entry_bridges_and_handoff_distinct(self):
        source_groups = [group for group in self.groups.values() if group['id'].startswith('source-crt-')]
        self.assertEqual({name for group in source_groups for name in group['members']}, CRT_OWNER_NAMES)
        self.assertEqual(len(CRT_OWNER_NAMES), 14)
        all_crt = ['static-crt1.o', 'static-Scrt1.o', 'static-rcrt1.o', 'dynamic-crt1.o', 'dynamic-Scrt1.o']
        bridges = self.groups['source-crt-linker-array-address-bridges']
        self.assertEqual(bridges['artifacts'], all_crt)
        self.assertTrue(all(value == {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'}
                            for value in bridges['placement_metadata'].values()))
        entry = self.records['_start']
        self.assertEqual(entry['selection']['disposition'], 'private-provider')
        self.assertEqual([row['artifact_key'] for row in entry['expected_placements']], all_crt)
        self.assertIn('not a C-callable provider', entry['selection']['reason'])
        handoff = self.records['__crabc_x86_64_owned_crt_handoff_value']
        self.assertEqual([row['artifact_key'] for row in handoff['expected_placements']], ['static-Scrt1.o', 'dynamic-crt1.o', 'dynamic-Scrt1.o'])
        self.assertNotIn('__crabc_x86_64_owned_crt_handoff', CRT_OWNER_NAMES)


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

    def test_common_alignment_and_absolute_value_do_not_prove_a_defining_section_alias(self):
        left = {'artifact_key': 'candidate-static', 'member_index': 0, 'member_occurrence': 0,
                'table_section_index': 5, 'row': symbol('left', kind='OBJECT', section='COM', value='0000000000000008', size=8)}
        right = copy.deepcopy(left); right['row']['name'] = 'right'
        self.assertFalse(selection.same_definition_domain(left, right))
        left['row']['section_index'] = right['row']['section_index'] = 'ABS'
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
        for variant in (
            base + ['--output', 'first', '--public-data-ordinary-link-report', '.work/ordinary/report.json'],
            base + ['--output', 'first', '--loader-debug-abi-report', '.work/loader/report.json'],
        ):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                selection.main(variant)
            self.assertEqual(result.exception.code, 2)

    def test_cli_accepts_only_the_complete_linkage_report_pair(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += [
            '--output', '.work/output',
            '--public-data-ordinary-link-report', '.work/ordinary/report.json',
            '--loader-debug-abi-report', '.work/loader/report.json',
        ]
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(build.call_args.kwargs['ordinary_link_report'], Path('.work/ordinary/report.json'))
        self.assertEqual(build.call_args.kwargs['loader_debug_report'], Path('.work/loader/report.json'))



class SelectedDataDeclarationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'compat/x86_64/tests/test_native_data_declarations.py'
        spec = importlib.util.spec_from_file_location('selection_data_declaration_fixture', path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.fixture = module.NativeDataDeclarationsTests()
        cls.objects = selection.load_contract()['object_contracts']

    def setUp(self):
        work = ROOT / '.work/x86_64/native-abi-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(temporary.cleanup)
        self.report = Path(temporary.name) / 'report.json'
        self.report.write_text('{}\n')

    def account(self, envelope):
        # The owning reader's raw replay is tested separately. Exercise the
        # real typed adapter at the selection boundary using its full-roster
        # fixture, and require exactly one public replay for that envelope.
        # Pinned unit fixtures mount this checkout at /workspace while Git's
        # worktree metadata names the host. Path admission has separate tests;
        # make this fixture's checkout its local evidence boundary.
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_inventory, 'validate_report', return_value=envelope) as replay:
            result = selection.declaration_adapter(self.report, selected_objects=self.objects)
        replay.assert_called_once_with(self.report, project_include=ROOT / 'include')
        return result

    def test_typed_data_proof_reuses_public_replay_without_closing_all_declarations(self):
        result = self.account(self.fixture.report_envelope())
        typed = result['selected_data_declarations']
        self.assertEqual(typed['account']['scope']['selected_object_contracts'], 33)
        self.assertEqual(typed['account']['selected_data_declaration_status'], 'proved-with-explicit-boundaries')
        self.assertEqual(typed['contract'], selection.file_identity(ROOT / 'compat/x86_64/native_data_declarations.toml'))
        self.assertEqual(typed['adapter'], selection.file_identity(ROOT / 'compat/x86_64/native_data_declarations.py'))
        self.assertFalse(result['complete'])
        blockers = selection.evidence_blockers(declaration=result, semantic_receipts=[], family_receipts=[], source_matches=True)
        self.assertIn('declaration-companion-incomplete', {item['code'] for item in blockers})
        self.assertTrue(any('layout' in message for item in result['requirements'] for message in item['remaining']))

    def test_typed_declaration_disagreement_is_a_selection_error(self):
        envelope = self.fixture.report_envelope()
        row = next(row for row in envelope['report']['occurrences'] if row['name'] == 'stdin')
        row['type']['qual_type'] = 'FILE *'
        with self.assertRaisesRegex(selection.SelectionError, 'selected data declarations rejected'):
            self.account(envelope)

    def test_historical_source_comparison_survives_nested_data_account(self):
        envelope = self.fixture.report_envelope()
        envelope['current_selecting_source'] = {'matches_retained': False, 'differences': [{'path': 'include/stdio.h', 'kind': 'sha256-differs'}]}
        result = self.account(envelope)
        self.assertEqual(result['current_selecting_source'], envelope['current_selecting_source'])
        typed = result['selected_data_declarations']['account']
        self.assertEqual(typed['selected_data_declaration_status'], 'historical-source-drift-with-explicit-boundaries')
        self.assertFalse(result['complete'])


class PublicDataLinkageAdapterTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/native-abi-selection-linkage-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.work = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.contract = selection.load_contract()
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.paths = {
            'static_preparation': self.work / 'static-preparation.json',
            'static_product': self.work / 'static-product',
            'dynamic_product': self.work / 'dynamic-product',
        }
        self.paths['static_preparation'].write_text('{}\n')
        self.paths['static_product'].mkdir()
        self.paths['dynamic_product'].mkdir()
        self.dynamic_files = {
            'candidate-libc': self.paths['dynamic_product'] / 'usr/lib/libc.so',
            'candidate-loader': self.paths['dynamic_product'] / 'lib/ld-crabc-x86_64.so.1',
            'dynamic-manifest': self.paths['dynamic_product'] / 'share/crabc/manifest.json',
            'dynamic-state': self.paths['dynamic_product'] / 'share/crabc/dynamic-product-state.json',
        }
        for key, path in self.dynamic_files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            content = (json.dumps({'source_sha256': self.source['content_sha256']}) + '\n').encode() \
                if key == 'dynamic-state' else (key + '\n').encode()
            path.write_bytes(content)
        loader_cohort = self.work / 'loader-product'
        self.loader_artifacts = {}
        for key, path in self.dynamic_files.items():
            retained = loader_cohort / path.relative_to(self.paths['dynamic_product'])
            retained.parent.mkdir(parents=True, exist_ok=True)
            retained.write_bytes(path.read_bytes())
            self.loader_artifacts[key] = selection.loader_debug_evidence.record(retained)
        self.admitted_inputs = {
            'source': {key: self.source[key] for key in ('revision', 'content_sha256')},
            'static_preparation': {'receipt': 'exact static receipt'},
            'dynamic_product': {
                'path': self.paths['dynamic_product'].relative_to(ROOT).as_posix(),
                'manifest': selection.ordinary_link_evidence.work_file_identity(
                    ROOT, self.dynamic_files['dynamic-manifest'], 'test dynamic manifest',
                ),
                'state': selection.ordinary_link_evidence.work_file_identity(
                    ROOT, self.dynamic_files['dynamic-state'], 'test dynamic state',
                ),
                'manifest_sha256': 'f' * 64,
            },
        }
        self.ordinary_report = self.work / 'ordinary-report.json'
        self.loader_report = self.work / 'loader-report.json'

    def linkage_companion(self, *, report_inputs=None, admitted_inputs=None, loader_metadata=None, loader_source=None,
                          loader_artifacts=None, ordinary_replay_identity=None, ordinary_selection=None):
        admitted_inputs = copy.deepcopy(self.admitted_inputs) if admitted_inputs is None else admitted_inputs
        report_inputs = admitted_inputs if report_inputs is None else report_inputs
        loader_metadata = {
            'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size': 8,
        } if loader_metadata is None else loader_metadata
        self.ordinary_report.write_text(json.dumps({
            'source_before': report_inputs, 'source_after': report_inputs,
        }) + '\n')
        loader_source = self.source if loader_source is None else loader_source
        loader = {
            'source_commit': loader_source['revision'], 'source_sha256': loader_source['content_sha256'],
            'public_metadata': {'_dl_debug_addr': loader_metadata},
            'artifacts': self.loader_artifacts if loader_artifacts is None else loader_artifacts,
        }
        self.loader_report.write_text(json.dumps(loader) + '\n')
        ordinary_replay = {'report': (
            selection.ordinary_link_evidence.work_file_identity(ROOT, self.ordinary_report, 'test ordinary report')
            if ordinary_replay_identity is None else ordinary_replay_identity
        ), 'links': {}}
        selection_replay = (
            contextlib.nullcontext()
            if ordinary_selection is None
            else mock.patch.object(selection.ordinary_link_evidence, 'selected_objects', return_value=ordinary_selection)
        )
        with (
            mock.patch.object(selection.ordinary_link_evidence, 'validate_report', return_value=ordinary_replay) as ordinary_validate,
            mock.patch.object(selection.ordinary_link_evidence, 'admit_inputs', return_value=admitted_inputs) as ordinary_inputs_replay,
            mock.patch.object(selection.loader_debug_evidence, 'validate_report', return_value=loader) as loader_validate,
            selection_replay,
        ):
            result = selection.public_data_linkage_adapter(
                self.ordinary_report, self.loader_report, contract=self.contract,
                selected_objects=self.contract['object_contracts'], source=self.source, paths=self.paths,
            )
        ordinary_validate.assert_called_once_with(ROOT, self.ordinary_report)
        ordinary_inputs_replay.assert_called_once_with(
            ROOT, self.paths['static_preparation'], self.paths['static_product'], self.paths['dynamic_product'],
        )
        loader_validate.assert_called_once_with(self.loader_report)
        return result

    def test_linkage_reports_are_an_optional_pair(self):
        self.assertIsNone(selection.public_data_linkage_adapter(
            None, None, contract=self.contract, selected_objects=self.contract['object_contracts'],
            source=self.source, paths={},
        ))
        with self.assertRaisesRegex(selection.SelectionError, 'together'):
            selection.public_data_linkage_adapter(
                ROOT / '.work/x86_64/ordinary/report.json',
                None,
                contract=self.contract,
                selected_objects=self.contract['object_contracts'],
                source={'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True},
                paths={},
            )

    def test_linkage_replays_both_owners_and_keeps_the_32_10_one_boundary(self):
        result = self.linkage_companion()
        self.assertEqual(result['status'], 'linkage-addressability-proved-with-boundaries')
        self.assertEqual(len(result['ordinary_link']['objects']), 32)
        self.assertEqual(len(result['ordinary_link']['aliases']), 10)
        self.assertEqual(result['loader_debug_addr']['id'], 'object:_dl_debug_addr')
        self.assertEqual(result['loader_debug_addr']['artifacts'], ['candidate-shared'])
        self.assertEqual(result['loader_debug_addr']['metadata']['size_bytes'], 8)
        bindings = result['loader_debug_addr']['product_bindings']
        self.assertEqual([binding['name'] for binding in bindings], [
            'candidate-libc', 'candidate-loader', 'dynamic-manifest', 'dynamic-state',
        ])
        self.assertTrue(all(binding['loader_receipt']['path'] != binding['selected_dynamic_product']['path']
                            for binding in bindings))

    def test_linkage_accepts_the_real_ordinary_admission_source_projection(self):
        """The ordinary reader owns a two-field product source identity."""
        ordinary_source = {key: self.source[key] for key in ('revision', 'content_sha256')}
        static_manifest = self.paths['static_product'] / 'share/crabc/manifest.json'
        static_manifest.parent.mkdir(parents=True, exist_ok=True)
        static_manifest.write_text(json.dumps({'static': True}) + '\n')
        primary_manifest = selection.ordinary_link_evidence.work_file_identity(
            ROOT, static_manifest, 'test static manifest',
        )
        preparation = {
            'products': {'primary': {
                'path': self.paths['static_product'].relative_to(ROOT).as_posix(),
                'manifest': primary_manifest,
            }},
            'source': ordinary_source,
        }
        loader = {
            'source_commit': self.source['revision'], 'source_sha256': self.source['content_sha256'],
            'public_metadata': {'_dl_debug_addr': {
                'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size': 8,
            }},
            'artifacts': self.loader_artifacts,
        }
        with (
            mock.patch.object(selection.ordinary_link_evidence.static_products, 'validate_receipt', return_value=preparation),
            mock.patch.object(selection.ordinary_link_evidence.static_products, 'source_identity', return_value=ordinary_source),
            mock.patch.object(selection.ordinary_link_evidence.qualification, 'product_identity', return_value='f' * 64),
        ):
            admitted = selection.ordinary_link_evidence.admit_inputs(
                ROOT, self.paths['static_preparation'], self.paths['static_product'], self.paths['dynamic_product'],
            )
            self.assertEqual(admitted['source'], ordinary_source)
            self.ordinary_report.write_text(json.dumps({
                'source_before': admitted, 'source_after': admitted,
            }) + '\n')
            self.loader_report.write_text(json.dumps(loader) + '\n')
            with (
                mock.patch.object(selection.ordinary_link_evidence, 'validate_report', return_value={
                    'report': selection.ordinary_link_evidence.work_file_identity(
                        ROOT, self.ordinary_report, 'test ordinary report',
                    ), 'links': {},
                }),
                mock.patch.object(selection.loader_debug_evidence, 'validate_report', return_value=loader),
            ):
                result = selection.public_data_linkage_adapter(
                    self.ordinary_report, self.loader_report, contract=self.contract,
                    selected_objects=self.contract['object_contracts'], source=self.source, paths=self.paths,
                )
        self.assertEqual(result['selection_source'], self.source)

    def test_linkage_rejects_ordinary_source_missing_or_extra_fields(self):
        two_fields = {key: self.source[key] for key in ('revision', 'content_sha256')}
        for ordinary_source in (
            {'revision': self.source['revision']},
            {**two_fields, 'clean': True},
        ):
            with self.subTest(ordinary_source=ordinary_source), self.assertRaisesRegex(
                    selection.SelectionError, 'ordinary-link receipt source fields'):
                self.linkage_companion(admitted_inputs={
                    'source': ordinary_source,
                    'static_preparation': {'receipt': 'exact static receipt'},
                    'dynamic_product': {'path': 'exact dynamic product'},
                })

    def test_linkage_rejects_a_loader_cohort_with_different_selected_bytes(self):
        artifacts = copy.deepcopy(self.loader_artifacts)
        artifacts['candidate-libc']['sha256'] = '0' * 64
        with self.assertRaisesRegex(selection.SelectionError, 'loader candidate-libc bytes differ'):
            self.linkage_companion(loader_artifacts=artifacts)

    def test_linkage_rejects_a_reader_envelope_with_another_report_identity(self):
        wrong = selection.ordinary_link_evidence.work_file_identity(ROOT, self.ordinary_report, 'unwritten report') \
            if self.ordinary_report.exists() else {'path': self.ordinary_report.relative_to(ROOT).as_posix(),
                                                    'sha256': '0' * 64, 'size': 0}
        wrong['sha256'] = '0' * 64
        with self.assertRaisesRegex(selection.SelectionError, 'ordinary-link reader report identity differs'):
            self.linkage_companion(ordinary_replay_identity=wrong)

    def test_linkage_seals_receipts_after_the_last_ordinary_report_read(self):
        admitted = copy.deepcopy(self.admitted_inputs)
        self.ordinary_report.write_text(json.dumps({
            'source_before': admitted, 'source_after': admitted,
        }) + '\n')
        loader = {
            'source_commit': self.source['revision'], 'source_sha256': self.source['content_sha256'],
            'public_metadata': {'_dl_debug_addr': {
                'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size': 8,
            }},
            'artifacts': self.loader_artifacts,
        }
        self.loader_report.write_text(json.dumps(loader) + '\n')

        def mutate_after_read(*_args):
            self.ordinary_report.write_text('{"tampered":true}\n')
            return admitted

        with (
            mock.patch.object(selection.ordinary_link_evidence, 'validate_report', return_value={
                'report': selection.ordinary_link_evidence.work_file_identity(
                    ROOT, self.ordinary_report, 'test ordinary report',
                ), 'links': {},
            }),
            mock.patch.object(selection.ordinary_link_evidence, 'admit_inputs', side_effect=mutate_after_read),
            mock.patch.object(selection.loader_debug_evidence, 'validate_report', return_value=loader),
            self.assertRaisesRegex(selection.SelectionError, 'companion replay'),
        ):
            selection.public_data_linkage_adapter(
                self.ordinary_report, self.loader_report, contract=self.contract,
                selected_objects=self.contract['object_contracts'], source=self.source, paths=self.paths,
            )

    def test_linkage_rejects_a_report_with_other_supplied_products(self):
        admitted = copy.deepcopy(self.admitted_inputs)
        report = copy.deepcopy(admitted)
        report['dynamic_product']['path'] = 'substituted dynamic product'
        with self.assertRaisesRegex(selection.SelectionError, 'selected static/dynamic products'):
            self.linkage_companion(report_inputs=report, admitted_inputs=admitted)

    def test_linkage_rejects_loader_pointer_or_source_substitution(self):
        for kwargs, message in (
            ({'loader_metadata': {'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size': 40}},
             'pointer metadata'),
            ({'loader_source': {**self.source, 'content_sha256': 'c' * 64}}, 'source differs'),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(selection.SelectionError, message):
                self.linkage_companion(**kwargs)

    def test_linkage_rejects_an_omitted_object_or_changed_alias_projection(self):
        objects, aliases = selection.ordinary_link_evidence.selected_objects(self.contract)
        altered_aliases = copy.deepcopy(aliases)
        altered_aliases[0]['target'] = '__progname'
        for projection in ((objects[:-1], aliases), (objects, altered_aliases)):
            with self.subTest(projection=projection), self.assertRaisesRegex(selection.SelectionError, 'roster'):
                self.linkage_companion(ordinary_selection=projection)

    def test_linkage_clears_only_the_covered_static_object_import(self):
        ordinary_reason = selection.ORDINARY_IMPORT_REASON
        accounting = {
            'identities': [
                {'identity': identity('environ'), 'selection': {'owner': 'object:environ'},
                 'unresolved': [ordinary_reason, 'separate lifecycle receipt remains required']},
                {'identity': identity('stderr'), 'selection': {'owner': 'object:stderr'},
                 'unresolved': [ordinary_reason]},
            ],
            'occurrences': [
                {'index': 7, 'artifact_key': 'candidate-static', 'role': 'import',
                 'row': {'name': 'environ'}, 'accounting': {'disposition': 'public-provider', 'owner': 'object:environ', 'scope': 'candidate-static'}},
                {'index': 8, 'artifact_key': 'candidate-static', 'role': 'import',
                 'row': {'name': 'stderr'}, 'accounting': {'disposition': 'public-provider', 'owner': 'object:stderr', 'scope': 'candidate-static'}},
            ],
            'blockers': [
                {'code': 'identity-unresolved', 'identity': identity('environ'), 'reason': ordinary_reason},
                {'code': 'identity-unresolved', 'identity': identity('environ'), 'reason': 'separate lifecycle receipt remains required'},
                {'code': 'identity-unresolved', 'identity': identity('stderr'), 'reason': ordinary_reason},
            ],
            'data_alias_observations': [
                {'identity': identity('environ'), 'runtime_semantics_proven': False},
            ],
        }
        companion = {
            'ordinary_link': {
                'objects': [
                    {'id': 'object:environ', 'identity': identity('environ'),
                     'artifacts': ['candidate-static', 'candidate-shared']},
                    {'id': 'object:stderr', 'identity': identity('stderr'),
                     'artifacts': ['candidate-static', 'candidate-shared']},
                ],
            },
        }
        joins = selection.attach_public_data_linkage(accounting, companion)
        self.assertEqual([join['occurrence_indices'] for join in joins], [[7], [8]])
        self.assertEqual(accounting['identities'][0]['unresolved'], ['separate lifecycle receipt remains required'])
        self.assertEqual(accounting['identities'][1]['unresolved'], [])
        self.assertEqual(
            accounting['blockers'],
            [{'code': 'identity-unresolved', 'identity': identity('environ'),
              'reason': 'separate lifecycle receipt remains required'}],
        )
        self.assertFalse(accounting['data_alias_observations'][0]['runtime_semantics_proven'])

    def test_linkage_keeps_a_generic_import_blocker_when_another_artifact_imports_it(self):
        ordinary_reason = selection.ORDINARY_IMPORT_REASON
        accounting = {
            'identities': [
                {'identity': identity('environ'), 'selection': {'owner': 'object:environ'},
                 'unresolved': [ordinary_reason]},
            ],
            'occurrences': [
                {'index': 7, 'artifact_key': 'candidate-static', 'role': 'import', 'row': {'name': 'environ'},
                 'accounting': {'disposition': 'public-provider', 'owner': 'object:environ', 'scope': 'candidate-static'}},
                {'index': 8, 'artifact_key': 'candidate-loader', 'role': 'import', 'row': {'name': 'environ'},
                 'accounting': {'disposition': 'public-provider', 'owner': 'object:environ', 'scope': 'candidate-loader'}},
            ],
            'blockers': [{'code': 'identity-unresolved', 'identity': identity('environ'), 'reason': ordinary_reason}],
        }
        companion = {'ordinary_link': {'objects': [
            {'id': 'object:environ', 'identity': identity('environ'),
             'artifacts': ['candidate-static', 'candidate-shared']},
        ]}}
        joins = selection.attach_public_data_linkage(accounting, companion)
        self.assertFalse(joins[0]['ordinary_link_covered'])
        self.assertEqual(joins[0]['artifact_keys'], ['candidate-loader', 'candidate-static'])
        self.assertEqual(accounting['identities'][0]['unresolved'], [ordinary_reason])
        self.assertEqual(accounting['blockers'], [
            {'code': 'identity-unresolved', 'identity': identity('environ'), 'reason': ordinary_reason},
        ])


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
