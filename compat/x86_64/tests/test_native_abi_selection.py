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
if str(ROOT / 'compat/x86_64') not in sys.path:
    sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_data_declarations as data_declarations


def identity(name, version=None, default=False):
    return {'name': name, 'version': version, 'version_default': default}


def symbol(name, *, binding='GLOBAL', visibility='DEFAULT', section='1', kind='FUNC', value='0000000000000000', size=4):
    return {'name': name, 'raw_name': name, 'version': None, 'version_default': False,
            'binding': binding, 'visibility': visibility, 'section_index': section,
            'type': kind, 'value': value, 'size_bytes': size, 'size': str(size),
            'row_index': 1, 'raw': 'retained fixture row', 'other': None,
            'version_index': None, 'common_alignment': None}


class SelectionContractTests(unittest.TestCase):
    def test_public_data_runtime_reader_report_bridges_only_the_fixed_receipt_name(self):
        work = ROOT / '.work/x86_64/native-abi-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            receipt = Path(temporary)
            report = receipt / 'report.json'
            report.write_bytes(b'{"component":"test"}\n')
            physical = selection.file_identity(report)
            reader_identity = {
                'path': 'report.json',
                'sha256': physical['sha256'],
                'size': physical['size'],
                'mode': physical['mode'],
            }
            self.assertNotEqual(reader_identity, physical)
            self.assertEqual(
                selection._public_data_declaration_runtime_reader_report(reader_identity, physical),
                reader_identity,
            )
            for field, wrong in (('path', 'elsewhere.json'), ('sha256', '0' * 64),
                                 ('size', physical['size'] + 1), ('mode', 0o600)):
                with self.subTest(field=field):
                    malformed = copy.deepcopy(reader_identity)
                    malformed[field] = wrong
                    with self.assertRaises(selection.SelectionError):
                        selection._public_data_declaration_runtime_reader_report(malformed, physical)

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

    def test_program_name_selection_names_the_validated_auxv_fallback_owner(self):
        contract = selection.load_contract()
        objects = {row['name']: row for row in contract['object_contracts']}
        for name in (
            '__progname', '__progname_full',
            'program_invocation_name', 'program_invocation_short_name',
        ):
            with self.subTest(name=name):
                row = objects[name]
                self.assertIn('libc/src/c_abi/x86_64/process_globals.rs', row['sources'])
                self.assertIn('libc/src/c_abi/x86_64/auxv_observation.rs', row['sources'])
                self.assertIn('validated AT_EXECFN', row['meaning'])

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


class PublicDataDeclarationRuntimeAttachmentTests(unittest.TestCase):
    """The runtime receipt may finish only the fixed declaration companion."""

    @staticmethod
    def _occurrence(index, name, artifact_key, metadata):
        row = symbol(
            name, kind=metadata['type'], binding=metadata['binding'],
            visibility=metadata['visibility'], size=metadata['size_bytes'],
            value='0000000000000000',
        )
        row['row_index'] = index + 1
        return {
            'index': index, 'artifact_key': artifact_key, 'member_index': None,
            'member_occurrence': None, 'member_name': None, 'table': (
                '.symtab' if artifact_key == 'candidate-static' else '.dynsym'
            ), 'table_section_index': '1', 'row': row,
            'definition_section': {'index': 1, 'name': '.data', 'alignment': metadata['alignment_bytes']},
            'role': 'definition', 'accounting': {'disposition': 'public-provider', 'owner': 'object:' + name},
        }

    def _fixture(self):
        objects = {
            row['name']: row for row in selection.load_contract()['object_contracts']
            if row['name'] in selection.public_data_variable_runtime.OBJECTS
        }
        self.assertEqual(set(objects), set(selection.public_data_variable_runtime.OBJECTS))
        identities, placements, occurrences = [], [], []
        requirements = []
        index = 0
        for name in selection.public_data_variable_runtime.OBJECTS:
            object_contract = objects[name]
            metadata = {
                key: object_contract[key]
                for key in ('type', 'binding', 'visibility', 'size_bytes', 'alignment_bytes')
            }
            identities.append({
                'identity': identity(name), 'selection': {'owner': 'object:' + name},
                'unresolved': [], 'expected_placements': [
                    {'artifact_key': 'candidate-static', 'metadata': copy.deepcopy(metadata)},
                    {'artifact_key': 'candidate-shared', 'metadata': copy.deepcopy(metadata)},
                ],
            })
            requirements.append({
                'identity': identity(name), 'kind': 'installed-variable',
                'remaining': [selection.PUBLIC_DATA_DECLARATION_RUNTIME_VARIABLE_REQUIREMENT],
            })
            for artifact_key in ('candidate-static', 'candidate-shared'):
                occurrence = self._occurrence(index, name, artifact_key, metadata)
                occurrences.append(occurrence)
                placements.append({
                    'identity': identity(name), 'artifact_key': artifact_key,
                    'expected_metadata': copy.deepcopy(metadata), 'placement_observed': True,
                    'definition_count': 1, 'occurrence_indices': [index],
                    'metadata_differences': [{'occurrence_index': index, 'fields': []}],
                })
                index += 1
        h_errno = {
            'identity': identity('h_errno'), 'kind': 'accessor-macro',
            'remaining': [selection.PUBLIC_DATA_DECLARATION_RUNTIME_ACCESSOR_REQUIREMENT],
        }
        requirements.append(h_errno)
        # This physical row is deliberately unrelated to the finite names. It
        # proves the attachment does not reconstruct a logical account from a
        # filtered occurrence roster.
        unnamed = self._occurrence(index, '', 'candidate-static', {
            'type': 'OBJECT', 'binding': 'LOCAL', 'visibility': 'HIDDEN', 'size_bytes': 0, 'alignment_bytes': 1,
        })
        unnamed['row']['name'] = ''
        occurrences.append(unnamed)
        accounting = {
            'identities': identities,
            'placement_joins': placements,
            'occurrences': occurrences,
            'blockers': [{'code': 'identity-unresolved', 'identity': identity('unrelated'), 'reason': 'unchanged'}],
        }
        declaration = {
            'requirements': requirements, 'unresolved_selected_occurrences': [], 'complete': False,
        }
        companion = {
            'status': 'public-data-declaration-runtime-observed-with-boundaries',
            'reader': {'path': 'reader', 'sha256': '0' * 64, 'size': 1, 'mode': 0o644},
            'report': {'path': '.work/runtime/report.json', 'sha256': '1' * 64, 'size': 1, 'mode': 0o644},
            'source': {'revision': 'source', 'content_sha256': '2' * 64, 'clean': True},
            'coverage': {
                'objects': list(selection.public_data_variable_runtime.OBJECTS),
                'groups': [group for group, _members in selection.public_data_variable_runtime.GROUPS],
                'component_complete': True, 'family_completion': False,
                'runtime_qualification': False, 'public_support': False,
            },
            'h_errno': selection.public_data_variable_runtime.h_errno_composition_contract(),
            'companions': {}, 'limits': list(selection.PUBLIC_DATA_DECLARATION_RUNTIME_LIMITS),
        }
        errno_joins = [{
            'public_identities': [{
                'identity': identity('h_errno'), 'static_occurrence_index': 900,
                'shared_occurrence_index': 901,
            }],
        }]
        return declaration, accounting, companion, errno_joins

    def test_exact_19_plus_h_errno_attachment_preserves_raw_rows_and_only_finishes_declaration(self):
        declaration, accounting, companion, errno_joins = self._fixture()
        before_occurrences = copy.deepcopy(accounting['occurrences'])
        before_blockers = copy.deepcopy(accounting['blockers'])
        joins = selection.attach_public_data_declaration_runtime(
            declaration, accounting, companion, errno_joins,
        )
        self.assertTrue(declaration['complete'])
        self.assertTrue(all(row['remaining'] == [] for row in declaration['requirements']))
        self.assertEqual(accounting['occurrences'], before_occurrences)
        self.assertEqual(accounting['blockers'], before_blockers)
        self.assertEqual(len(joins), 1)
        self.assertEqual(joins[0]['requirements_discharged'], ['declaration-companion-incomplete'])
        self.assertEqual([row['identity']['name'] for row in joins[0]['variables']],
                         list(selection.public_data_variable_runtime.OBJECTS))
        self.assertEqual(joins[0]['h_errno']['static_occurrence_index'], 900)
        self.assertEqual(joins[0]['h_errno']['shared_occurrence_index'], 901)

    def test_wrong_shared_visibility_cannot_finish_the_declaration_companion(self):
        declaration, accounting, companion, errno_joins = self._fixture()
        shared = next(row for row in accounting['occurrences']
                      if row['artifact_key'] == 'candidate-shared' and row['row']['name'] == 'timezone')
        shared['row']['visibility'] = 'HIDDEN'
        with self.assertRaisesRegex(selection.SelectionError, 'selected occurrence'):
            selection.attach_public_data_declaration_runtime(
                declaration, accounting, companion, errno_joins,
            )

    def test_incomplete_coverage_cannot_finish_the_declaration_companion(self):
        declaration, accounting, companion, errno_joins = self._fixture()
        companion['coverage']['objects'].pop()
        with self.assertRaisesRegex(selection.SelectionError, 'scope differs'):
            selection.attach_public_data_declaration_runtime(
                declaration, accounting, companion, errno_joins,
            )


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
        for name in ('__crabc_runtime_v1', 'rust_eh_personality'):
            self.assertNotIn(name, selected)
            self.assertFalse(self.records[name]['selection'].get('group', '').startswith('source-owned-'))
        for name in ('initstate', 'random', 'setstate', 'srandom'):
            self.assertEqual(self.records[name]['selection']['group'], 'declared-callable-providers')
            self.assertEqual(self.records[name]['selection']['disposition'], 'public-provider')
            self.assertEqual(self.records[name]['unresolved'], [selection.BSD_RANDOM_REQUIREMENT])
            self.assertEqual({row['artifact_key'] for row in self.records[name]['expected_placements']},
                             {'candidate-static', 'candidate-shared'})

    def test_errno_private_alias_is_a_component_private_provider_not_a_source_owner_or_public_export(self):
        record = self.records['___errno_location']
        self.assertEqual(record['selection']['group'], selection.ERRNO_PRIVATE_ALIAS_GROUP)
        self.assertEqual(record['selection']['disposition'], 'private-provider')
        self.assertEqual(record['selection']['owner'], 'x86-errno-storage-lifecycle')
        self.assertEqual(record['unresolved'], [selection.ERRNO_STORAGE_LIFECYCLE_REQUIREMENT])
        placements = {row['artifact_key']: row['metadata'] for row in record['expected_placements']}
        self.assertEqual(placements['candidate-static'], {
            'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'HIDDEN',
        })
        self.assertEqual(placements['candidate-shared'], {
            'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT',
        })

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
        # Musl hides the helper from libc.so; only the frozen crabc
        # candidate-only dynamic export selects its shared placement.
        self.assertEqual(qsort['expected_placements'], [
            {'artifact_key': 'candidate-static', 'metadata': {'type': 'FUNC'}, 'metadata_rule': 'selected-native-oracle-function'},
            {'artifact_key': 'candidate-shared', 'metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'}, 'metadata_rule': 'explicit'},
        ])
        coverage = selection.tomllib.loads((ROOT / 'compat/crabc-rs/coverage.toml').read_text(encoding='utf-8'))
        self.assertIn('__qsort_r', coverage['dynamic_exports']['candidate_only_symbols'])
        startup = self.records['__libc_start_main']
        self.assertEqual(startup['selection']['group'], 'source-owned-crt-libc-startup-boundary')
        self.assertEqual([row['artifact_key'] for row in startup['expected_placements']], ['candidate-static', 'candidate-shared'])

    def test_x86_only_public_functions_select_explicit_shared_exports(self):
        group = self.groups['x86-only-public-functions']
        self.assertEqual(group['members'], ['arch_prctl', 'ioperm', 'iopl'])
        self.assertIn('arch_prctl', self.groups['feature-abi-only-callables']['delegated_members'])
        self.assertTrue({'ioperm', 'iopl'} <= set(self.groups['declared-callable-providers']['delegated_members']))
        for name in group['members']:
            record = self.records[name]
            self.assertEqual(record['selection']['group'], group['id'])
            self.assertEqual(record['unresolved'], [])
            self.assertEqual(record['expected_placements'], [
                {'artifact_key': 'candidate-static', 'metadata': {'type': 'FUNC'}, 'metadata_rule': 'selected-native-oracle-function'},
                {'artifact_key': 'candidate-shared', 'metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'}, 'metadata_rule': 'explicit'},
            ])

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


PRIVATE_BODY_NAMES = frozenset('''
__pthread_cond_timedwait __pthread_create __pthread_exit __pthread_join __pthread_key_create
__pthread_key_delete __pthread_mutex_lock __pthread_mutex_timedlock __pthread_mutex_trylock
__pthread_mutex_unlock __pthread_once __pthread_rwlock_rdlock __pthread_rwlock_timedrdlock
__pthread_rwlock_timedwrlock __pthread_rwlock_tryrdlock __pthread_rwlock_trywrlock
__pthread_rwlock_unlock __pthread_rwlock_wrlock __pthread_setcancelstate __pthread_testcancel
__pthread_timedjoin_np __pthread_tryjoin_np
__crabc_x86_pthread_clone __crabc_x86_cancel __crabc_x86_syscall_cp_asm __crabc_x86_timer_dispatch
__crabc_x86_timer_invoke __crabc_x86_cp_begin __crabc_x86_cp_cancel __crabc_x86_cp_end
__mkostemps __mremap __ptsname_r __crabc_owned_clone_raw __crabc_owned_vfork_result
__crabc_x86_aio_cabi_free __crabc_x86_aio_cabi_malloc __crabc_x86_scandir_cabi_free
__crabc_x86_scandir_cabi_malloc __crabc_x86_scandir_cabi_realloc crabc_x86_64_signal_restorer
__crabc_owned_printf_float __crabc_owned_printf_promote __crabc_owned_scan __crabc_owned_wide_format
crabc_owned_scan_floatscan crabc_owned_scan_intscan crabc_owned_scan_shgetc crabc_owned_scan_shlim
crabc_owned_scan_vfscanf crabc_owned_vfwprintf crabc_owned_vfwscanf __crabc_x86_stdio_cabi_free
__crabc_x86_stdio_cabi_malloc __crabc_x86_stdio_cabi_realloc __crabc_x86_regex_cabi_calloc
__crabc_x86_regex_cabi_free __crabc_x86_regex_cabi_malloc __crabc_x86_regex_cabi_realloc __fesetround
__stpcpy __stpncpy __strchrnul __memrchr __memcpy_fwd
__dn_expand __inet_aton __crabc_x86_host_cache_cabi_free __crabc_x86_host_cache_cabi_malloc
__tsearch_balance __crabc_x86_passwd_cabi_free __crabc_x86_shadow_cabi_malloc
__stack_chk_fail_local
'''.split())
PRIVATE_NOTYPE_LABELS = frozenset({'__crabc_x86_cp_begin', '__crabc_x86_cp_cancel', '__crabc_x86_cp_end', '__memcpy_fwd'})


class PrivateImplementationBodyPolicyTests(unittest.TestCase):
    """Hidden implementation spellings get exact source owners, never public ABI."""

    @classmethod
    def setUpClass(cls):
        cls.contract = selection.load_contract()
        cls.inputs = selection.load_source_inputs(cls.contract, selection.CONTRACT_PATH)
        cls.records = {record['identity']['name']: record
                       for record in selection.expand_obligations(cls.contract, cls.inputs)}
        cls.groups = [group for group in cls.contract['owner_groups'] if group['id'].startswith('private-')]

    def test_private_body_roster_is_finite_and_outside_public_provider_routes(self):
        members = [name for group in self.groups for name in group['members']]
        self.assertEqual(len(members), len(set(members)))
        self.assertEqual(set(members), PRIVATE_BODY_NAMES)
        self.assertFalse(PRIVATE_BODY_NAMES & set(self.inputs['frozen_names']))
        self.assertFalse(PRIVATE_BODY_NAMES & set(self.inputs['provider_names']))
        for group in self.groups:
            self.assertEqual((group['selector'], group['disposition'], group['static_metadata_rule']),
                             ('explicit', 'private-provider', 'explicit'))
            self.assertTrue(group['sources'] and all(path.startswith('libc/src/c_abi/x86_64/') for path in group['sources']))

    def test_private_bodies_select_hidden_archive_and_local_shared_placements_only(self):
        for name in PRIVATE_BODY_NAMES:
            record = self.records[name]
            kind = 'NOTYPE' if name in PRIVATE_NOTYPE_LABELS else 'FUNC'
            self.assertEqual(record['selection']['disposition'], 'private-provider', name)
            self.assertEqual(record['unresolved'], [], name)
            placements = {row['artifact_key']: row['metadata'] for row in record['expected_placements']}
            binding = 'WEAK' if name == '__stack_chk_fail_local' else 'GLOBAL'
            self.assertEqual(placements['candidate-static'], {'type': kind, 'binding': binding, 'visibility': 'HIDDEN'}, name)
            self.assertEqual(placements['candidate-shared'], {'type': kind, 'binding': 'LOCAL', 'visibility': 'HIDDEN'}, name)

    def test_selected_private_body_cannot_hide_a_shared_dynsym_export(self):
        def facts_with(shared_rows):
            facts = empty_facts()
            facts['facts']['candidate-static'][0]['symbol_tables'][0]['rows'] = [
                symbol('__pthread_once', visibility='HIDDEN')]
            member = facts['facts']['candidate-shared']
            member['symbol_tables'] = [
                {'name': '.dynsym', 'section_index': 2, 'rows': [row for table, row in shared_rows if table == '.dynsym']},
                {'name': '.symtab', 'section_index': 3, 'rows': [row for table, row in shared_rows if table == '.symtab']},
            ]
            return facts

        record = copy.deepcopy(self.records['__pthread_once'])
        local = symbol('__pthread_once', binding='LOCAL', visibility='HIDDEN')
        report = selection.account_placements([copy.deepcopy(record)], facts_with([('.symtab', local)]))
        joined = {row['artifact_key']: row['placement_observed'] for row in report['placement_joins']}
        self.assertEqual(joined, {'candidate-static': True, 'candidate-shared': True})
        self.assertFalse([row for row in report['blockers'] if row['identity']['name'] == '__pthread_once'])

        leaked = symbol('__pthread_once')
        leaked['row_index'] = 2
        report = selection.account_placements([copy.deepcopy(record)], facts_with([('.symtab', local), ('.dynsym', leaked)]))
        self.assertIn({'code': 'identity-unresolved', 'identity': identity('__pthread_once'),
                       'reason': 'missing, ambiguous or mismatched selected provider placement: candidate-shared'},
                      report['blockers'])


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

    def test_semantic_receipt_blocker_names_each_absent_companion(self):
        declaration = None
        partial = selection.evidence_blockers(declaration=declaration, semantic_receipts=['crt_startup_report'],
                                              family_receipts=[{}], source_matches=True,
                                              required_semantic_receipts=['crt_startup_report', 'utmpx_receipt_report'])
        self.assertIn({'code': 'semantic-receipts-missing',
                       'subject': 'owner component extraction, ABI, alias and lifecycle readers',
                       'companions': ['utmpx_receipt_report']}, partial)
        complete = selection.evidence_blockers(declaration=declaration, semantic_receipts=['crt_startup_report'],
                                               family_receipts=[{}], source_matches=True,
                                               required_semantic_receipts=['crt_startup_report'])
        self.assertNotIn('semantic-receipts-missing', {row['code'] for row in complete})
        self.assertNotIn('family-receipts-missing', {row['code'] for row in complete})


class LedgerFamilyAdmissionTests(unittest.TestCase):
    """Foundation-verified families count only through the validated ledger."""

    @classmethod
    def setUpClass(cls):
        cls.contract = selection.load_contract(selection.CONTRACT_PATH)
        cls.families = selection.load_source_inputs(cls.contract, selection.CONTRACT_PATH)['families']

    def test_each_verified_family_discharges_only_its_own_row(self):
        admissions = selection.ledger_family_admissions(self.contract, self.families)
        verified = {row['id'] for row in self.families if row['status'] == 'foundation-verified'}
        self.assertEqual({row['family'] for row in admissions}, verified)
        blockers, evidence = selection.family_semantic_evidence(
            self.families, headers_layouts_companion=None, text_family_companion=None, ledger_admissions=admissions)
        self.assertEqual({row['family'] for row in blockers},
                         {row['id'] for row in self.families} - verified)
        self.assertTrue(all(row['ledger_status'] == 'planned' for row in blockers))
        self.assertEqual(len(evidence), len(verified))

    def test_rejected_ledger_or_differing_roster_rejects_admission(self):
        import validate_parity_ledger
        with mock.patch.object(validate_parity_ledger, 'validate_ledger',
                               side_effect=validate_parity_ledger.LedgerError('receipt replay failed')):
            with self.assertRaisesRegex(selection.SelectionError, 'receipt replay failed'):
                selection.ledger_family_admissions(self.contract, self.families)
        promoted = [dict(row, status='foundation-verified') for row in self.families]
        with self.assertRaisesRegex(selection.SelectionError, 'roster differs'):
            selection.ledger_family_admissions(self.contract, promoted)

    def test_forged_admission_record_is_rejected(self):
        planned = next(row['id'] for row in self.families if row['status'] == 'planned')
        forged = {'family': planned, 'status': selection.LEDGER_FAMILY_ADMISSION_STATUS, 'ledger_status': 'planned'}
        with self.assertRaisesRegex(selection.SelectionError, 'admission record differs'):
            selection.family_semantic_evidence(self.families, headers_layouts_companion=None,
                                               text_family_companion=None, ledger_admissions=[forged])


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
            base + ['--output', 'first', '--ordinary-declaration-abi-report', '.work/ordinary-declaration/report.json'],
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

    def test_cli_threads_pthread_timed_receipt_with_its_product_anchor(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += [
            '--output', '.work/output',
            '--public-data-ordinary-link-report', '.work/ordinary/report.json',
            '--loader-debug-abi-report', '.work/loader/report.json',
            '--pthread-timed-feature-report', '.work/pthread-timed/report.json',
        ]
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(build.call_args.kwargs['pthread_timed_feature_report'], Path('.work/pthread-timed/report.json'))
        self.assertEqual(build.call_args.kwargs['loader_debug_report'], Path('.work/loader/report.json'))

    def test_cli_threads_resolver_alias_receipt_with_its_loader_product_anchor(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += [
            '--output', '.work/output',
            '--public-data-ordinary-link-report', '.work/ordinary/report.json',
            '--loader-debug-abi-report', '.work/loader/report.json',
            '--resolver-alias-receipt-report', '.work/resolver-alias/report.json',
        ]
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(
            build.call_args.kwargs['resolver_alias_receipt_report'],
            Path('.work/resolver-alias/report.json'),
        )
        self.assertEqual(build.call_args.kwargs['ordinary_link_report'], Path('.work/ordinary/report.json'))
        self.assertEqual(build.call_args.kwargs['loader_debug_report'], Path('.work/loader/report.json'))

    def test_cli_threads_headers_layouts_aggregate_report(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += [
            '--output', '.work/output',
            '--headers-layouts-aggregate-report',
            'compat/x86_64/generated/headers_layouts_aggregate/report.json',
        ]
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(
            build.call_args.kwargs['headers_layouts_aggregate_report'],
            Path('compat/x86_64/generated/headers_layouts_aggregate/report.json'),
        )

    def test_cli_threads_loader_structural_owner_receipt(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += ['--output', '.work/output', '--public-data-ordinary-link-report', '.work/ordinary/report.json',
                      '--loader-debug-abi-report', '.work/loader/report.json', '--loader-runtime-registry-report', '.work/registry/report.json',
                      '--loader-structural-owner-receipt-report', '.work/loader-structural/report.json']
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(build.call_args.kwargs['loader_structural_owner_receipt_report'],
                         Path('.work/loader-structural/report.json'))

    def test_cli_threads_public_data_declaration_runtime_report(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += [
            '--output', '.work/output',
            '--public-data-declaration-runtime-report', '.work/public-data-declaration-runtime/report.json',
        ]
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(
            build.call_args.kwargs['public_data_declaration_runtime_report'],
            Path('.work/public-data-declaration-runtime/report.json'),
        )

    def test_cli_threads_the_ordinary_declaration_receipt_only_with_its_header_envelope(self):
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += [
            '--output', '.work/output',
            '--declaration-report', '.work/header/report.json',
            '--ordinary-declaration-abi-report', '.work/ordinary-declaration/report.json',
        ]
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(build.call_args.kwargs['declaration_report'], Path('.work/header/report.json'))
        self.assertEqual(
            build.call_args.kwargs['ordinary_declaration_abi_report'],
            Path('.work/ordinary-declaration/report.json'),
        )



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
        cls.inputs = selection.load_source_inputs(selection.load_contract(), selection.CONTRACT_PATH)

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
             mock.patch.object(selection.declaration_inventory, 'validate_report', return_value=envelope) as replay, \
             mock.patch.object(
                 selection.callable_declarations,
                 'account_declarations',
                 return_value={'selected_callable_declaration_status': 'fixture-not-exercised-here'},
             ):
            result = selection.declaration_adapter(
                self.report,
                selected_objects=self.objects,
                provider_names=self.inputs['provider_names'],
                deferred=self.inputs['deferred'],
                abi_only_callables=self.inputs['abi_only_callables'],
                callable_matrix_projection=self.inputs['callable_declaration_matrix'],
            )
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
        # Pinned fixtures use /workspace while Git's shared worktree metadata
        # retains the host checkout path. Keep this composition fixture inside
        # its mounted checkout; production path admission has separate tests.
        common_checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
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

    def test_linkage_rejects_loader_pointer_float_size(self):
        with self.assertRaisesRegex(selection.SelectionError, 'pointer metadata'):
            self.linkage_companion(loader_metadata={
                'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size': 8.0,
            })

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


class SelectedCallableDeclarationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'compat/x86_64/tests/test_native_callable_declarations.py'
        spec = importlib.util.spec_from_file_location('selection_callable_declaration_fixture', path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.fixture = module.NativeCallableDeclarationsTests()
        cls.objects = selection.load_contract()['object_contracts']

    def setUp(self):
        work = ROOT / '.work/x86_64/native-abi-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(temporary.cleanup)
        self.report = Path(temporary.name) / 'report.json'
        self.report.write_text('{}\n')

    def test_one_public_replay_feeds_data_and_callable_adapters(self):
        envelope = self.fixture.envelope()
        partition = self.fixture.partition()
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_inventory, 'validate_report', return_value=envelope) as replay, \
             mock.patch.object(
                 data_declarations,
                 'account_declarations',
                 return_value={'selected_data_declaration_status': 'fixture-not-exercised-here'},
             ), \
             mock.patch.object(
                 selection.callable_declarations.data_declarations,
                 '_report_envelope',
                 side_effect=self.fixture.authenticated_envelope,
             ):
            result = selection.declaration_adapter(
                self.report,
                selected_objects=self.objects,
                callable_matrix_projection=self.fixture.matrix_projection(),
                **partition,
            )
        replay.assert_called_once_with(self.report, project_include=ROOT / 'include')
        callable_account = result['selected_callable_declarations']
        self.assertEqual(
            callable_account['account']['selected_callable_declaration_status'],
            'proved-with-explicit-boundaries',
        )
        self.assertEqual(
            callable_account['adapter'],
            selection.file_identity(ROOT / 'compat/x86_64/native_callable_declarations.py'),
        )
        self.assertEqual(
            callable_account['contract'],
            selection.file_identity(ROOT / 'compat/x86_64/native_callable_declarations.toml'),
        )
        self.assertEqual(
            callable_account['account']['caller_authenticated_inputs']['selected_partition'],
            'native_abi_selection.load_source_inputs',
        )
        self.assertFalse(result['complete'])

    def test_declaration_adapter_rejects_a_header_report_replaced_after_its_public_replay(self):
        """A reused envelope must retain the exact report bytes it parsed."""
        envelope = self.fixture.envelope()
        partition = self.fixture.partition()

        def replay_then_replace(*_args, **_kwargs):
            self.report.write_text('{"replacement":true}\n')
            return envelope

        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_inventory, 'validate_report', side_effect=replay_then_replace), \
             self.assertRaisesRegex(selection.SelectionError, 'public declaration report changed during replay'):
            selection.declaration_adapter(
                self.report,
                selected_objects=self.objects,
                callable_matrix_projection=self.fixture.matrix_projection(),
                **partition,
            )

    def test_public_composition_rejects_a_selected_projection_without_full_header_envelope(self):
        envelope = self.fixture.envelope()
        partition = self.fixture.partition()
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_inventory, 'validate_report', return_value=envelope), \
             mock.patch.object(
                 data_declarations,
                 'account_declarations',
                 return_value={'selected_data_declaration_status': 'fixture-not-exercised-here'},
             ):
            with self.assertRaisesRegex(selection.SelectionError, 'selected callable declarations rejected'):
                selection.declaration_adapter(
                    self.report,
                    selected_objects=self.objects,
                    callable_matrix_projection=self.fixture.matrix_projection(),
                    **partition,
                )

    def test_source_inputs_bind_the_existing_checked_matrix_before_projection(self):
        contract = selection.load_contract()
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        projection = inputs['callable_declaration_matrix']
        self.assertEqual(projection['schema'], selection.callable_declarations.MATRIX_PROJECTION_SCHEMA)
        self.assertEqual(len(projection['rows']), 1337)
        self.assertEqual(projection['provenance']['report']['path'], 'compat/x86_64/generated/header_abi_matrix/report.json')
        self.assertIn('tgkill', inputs['provider_names'])
        self.assertIn('compat/x86_64/native_data_declarations.py', inputs['bindings'])
        self.assertIn('compat/x86_64/native_declaration_abi.py', inputs['bindings'])
        self.assertIn('compat/x86_64/native_declaration_abi.toml', inputs['bindings'])
        self.assertIn('compat/x86_64/native-declaration-abi.md', inputs['bindings'])
        self.assertIn('compat/x86_64/loader_runtime_registry_evidence.py', inputs['bindings'])
        self.assertIn('compat/x86_64/owned_pthread_alias_contract_reader.py', inputs['bindings'])
        self.assertIn('compat/x86_64/owned-pthread-alias-contract.md', inputs['bindings'])
        self.assertIn('compat/x86_64/prepared_worker_tls_evidence.py', inputs['bindings'])
        self.assertIn('compat/x86_64/prepared-worker-tls.md', inputs['bindings'])
        self.assertIn('compat/x86_64/owned_errno_storage_lifecycle.py', inputs['bindings'])
        self.assertIn('compat/x86_64/owned-errno-storage-lifecycle.md', inputs['bindings'])
        self.assertIn('compat/x86_64/owned_stdio_alias_contract_reader.py', inputs['bindings'])
        self.assertIn('compat/x86_64/owned-stdio-alias-receipt.toml', inputs['bindings'])
        self.assertIn('compat/x86_64/tests/test_native_abi_stdio_alias_attachment.py', inputs['bindings'])

    def test_checked_matrix_failure_cannot_be_projected_as_callable_evidence(self):
        contract = selection.load_contract()
        with mock.patch.object(selection.header_matrix, 'validate_checked_report', side_effect=ValueError('forged checked matrix')):
            with self.assertRaisesRegex(selection.SelectionError, 'checked callable declaration matrix rejected'):
                selection.load_source_inputs(contract, selection.CONTRACT_PATH)


class OrdinaryDeclarationAbiAttachmentTests(unittest.TestCase):
    """The finite object witness must stay below one public header replay."""

    @classmethod
    def setUpClass(cls):
        cls.contract = selection.load_contract()
        cls.objects = {
            row['name']: row for row in cls.contract['object_contracts']
            if row['name'] in {'_ns_flagdata', 'in6addr_any', 'in6addr_loopback'}
        }

    def setUp(self):
        work = ROOT / '.work/x86_64/native-abi-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        self.header_report = directory / 'header-report.json'
        self.ordinary_report = directory / 'ordinary-declaration-report.json'
        self.header_report.write_text('{}\n')
        self.ordinary_report.write_text('{}\n')

    @staticmethod
    def _plan():
        return [{
            'tree': 'candidate', 'header': 'demo.h', 'profile': 'c11-gnu', 'language': 'c',
            'names': ['foo'],
            'references': [{
                'category': 'reference-backed', 'name': 'foo',
                'source_definition_observations': ['extern-declaration-without-initializer'],
                'expected_observation': 'ordinary-undefined-reference',
                'holder': 'crabc_native_declaration_abi_reference_0',
            }],
        }]

    def _replayed(self, plans, *, mismatch=False):
        contract = selection.declaration_abi.load_contract()
        observation = (
            {
                'category': 'reference-backed', 'expected_symbol': 'foo',
                'holder': 'crabc_native_declaration_abi_reference_0',
                'observed_symbol': '_Z3foov', 'relocation_type': 'R_X86_64_64',
                'status': 'ordinary-linkage-identity-mismatch',
            }
            if mismatch else
            {
                'category': 'reference-backed', 'name': 'foo',
                'status': 'ordinary-undefined-reference', 'symbol': 'foo',
            }
        )
        layout = {
            'schema': selection.declaration_abi.RECORD_LAYOUT_PROJECTION_SCHEMA,
            'record_layout_report_schema': selection.declaration_abi.HEADER_RECORD_LAYOUT_REPORT_SCHEMA,
            'records': [
                {
                    'header': fact['header'], 'object_names': list(fact['object_names']),
                    'profiles': [{'profile': profile} for profile in fact['profiles']],
                    'record': fact['record'],
                }
                for fact in contract['record_layout']
            ],
            'limits': copy.deepcopy(contract['limits']),
        }
        statuses = {'ordinary-linkage-identity-mismatch': 1} if mismatch else {'ordinary-undefined-reference': 1}
        report = {
            'schema': selection.declaration_abi.SCHEMA,
            'target': selection.TARGET,
            'oracle': selection.declaration_abi.ORACLE,
            'callable_plan_source': {'selected_partition': 'caller-authenticated-fixture'},
            'status': {
                'callable_declaration_abi_complete': False,
                'family_completion': False,
                'object_linkage_observed': True,
                'promotion_ready': False,
                'public_support': False,
                'record_layout_projection_observed': True,
                'runtime_semantics': False,
            },
            'jobs': [{
                **copy.deepcopy(plans[0]), 'ordinal': 0,
                'observations': [observation],
            }],
        }
        return {
            'callable_plan': copy.deepcopy(plans),
            'execution': {
                'collector_output': '/workspace/.work/x86_64/native-declaration-abi/clean/report.json',
                'collector_source': selection.selection_source(),
                'image_id': 'crabc-core-evidence@sha256:' + 'a' * 64,
                'native_context': 'Linux/x86_64', 'source_mount': '/workspace',
                'timeout_seconds': 30, 'workers': 1,
            },
            'header_declaration_report': {'path': 'header-report.json'},
            'record_layout_projection': layout,
            'report': report,
            'summary': {
                'cxx_job_count': 0, 'job_count': 1, 'language_counts': {'c': 1},
                'observation_count': 1, 'observation_status_counts': statuses,
                'reference_category_counts': {'reference-backed': 1}, 'reference_count': 1,
            },
        }

    def test_attachment_reuses_the_authenticated_header_envelope_and_retains_a_linkage_mismatch(self):
        plans = self._plan()
        replayed = self._replayed(plans, mismatch=True)
        envelope = {'current_selecting_source': {'matches_retained': True, 'differences': []}, 'report': {'fixture': True}}
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_abi, 'linkage_jobs_from_callable_account', return_value=plans), \
             mock.patch.object(selection.declaration_abi, 'validate_report', return_value=replayed) as replay:
            result = selection.ordinary_declaration_abi_adapter(
                self.ordinary_report,
                header_report=self.header_report,
                header_envelope=envelope,
                callable_account={'groups': ['caller-authenticated']},
                selected_objects=list(self.objects.values()),
            )
        replay.assert_called_once_with(
            self.ordinary_report, header_report=self.header_report, header_envelope=envelope,
        )
        self.assertEqual(result['status'], 'ordinary-object-and-record-layout-observed-with-boundaries')
        self.assertEqual(result['linkage_mismatches'][0]['observed_symbol'], '_Z3foov')
        self.assertEqual({row['id'] for row in result['record_layout_joins']}, {
            'object:_ns_flagdata', 'object:in6addr_any', 'object:in6addr_loopback',
        })
        ns = next(row for row in result['record_layout_joins'] if row['id'] == 'object:_ns_flagdata')
        self.assertEqual(ns['remaining_layout_limitations'], ['not-proved-by-record-layout'])

    def test_attachment_rejects_an_object_plan_that_is_not_the_typed_callable_account(self):
        plans = self._plan()
        replayed = self._replayed(plans)
        changed = copy.deepcopy(plans)
        changed[0]['names'] = ['different']
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_abi, 'linkage_jobs_from_callable_account', return_value=changed), \
             mock.patch.object(selection.declaration_abi, 'validate_report', return_value=replayed), \
             self.assertRaisesRegex(selection.SelectionError, 'plan differs'):
            selection.ordinary_declaration_abi_adapter(
                self.ordinary_report,
                header_report=self.header_report,
                header_envelope={'current_selecting_source': {'matches_retained': True, 'differences': []}, 'report': {}},
                callable_account={'groups': ['caller-authenticated']},
                selected_objects=list(self.objects.values()),
            )

    def test_declaration_composition_passes_its_one_header_envelope_to_the_object_reader(self):
        fixture_path = ROOT / 'compat/x86_64/tests/test_native_callable_declarations.py'
        spec = importlib.util.spec_from_file_location('ordinary_declaration_attachment_fixture', fixture_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fixture = module.NativeCallableDeclarationsTests()
        envelope = fixture.envelope()
        partition = fixture.partition()
        ordinary = {'status': 'ordinary-object-and-record-layout-observed-with-boundaries'}
        with mock.patch.object(selection, '_common_checkout', return_value=ROOT), \
             mock.patch.object(selection.declaration_inventory, 'validate_report', return_value=envelope) as header_replay, \
             mock.patch.object(data_declarations, 'account_declarations', return_value={'selected_data_declaration_status': 'fixture'}), \
             mock.patch.object(selection.callable_declarations.data_declarations, '_report_envelope', side_effect=fixture.authenticated_envelope), \
             mock.patch.object(selection, 'ordinary_declaration_abi_adapter', return_value=ordinary) as ordinary_replay:
            result = selection.declaration_adapter(
                self.header_report,
                selected_objects=selection.load_contract()['object_contracts'],
                callable_matrix_projection=fixture.matrix_projection(),
                ordinary_declaration_abi_report=self.ordinary_report,
                **partition,
            )
        header_replay.assert_called_once_with(self.header_report, project_include=ROOT / 'include')
        ordinary_replay.assert_called_once()
        self.assertIs(ordinary_replay.call_args.kwargs['header_envelope'], envelope)
        self.assertEqual(ordinary_replay.call_args.kwargs['header_report'], self.header_report)
        self.assertEqual(result['ordinary_declaration_abi'], ordinary)


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
