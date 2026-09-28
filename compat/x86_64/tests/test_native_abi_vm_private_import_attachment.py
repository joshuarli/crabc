"""Physical occurrence accounting for the C allocator's private VM calls."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection
import native_c_allocator_boundary as boundary


def fixture() -> tuple[dict, dict]:
    names = boundary.VM_PRIVATE_IMPORTS
    c_member = {'name': 'selected-c.o', 'member_index': 11, 'member_occurrence': 0,
                'sha256': 'a' * 64}
    archive = '/workspace/.work/x86_64/current/usr/lib/libc.a'
    accounting = {'identities': [], 'placement_joins': [], 'occurrences': [], 'blockers': []}
    claims = []
    source = {}
    final = {'static': {}, 'static-pie': {}}

    def row(name: str, *, kind: str, binding: str, visibility: str, section: str,
            size: int, value: str) -> dict:
        return {'name': name, 'raw_name': name, 'version': None, 'version_default': False,
                'type': kind, 'binding': binding, 'visibility': visibility,
                'section_index': section, 'size_bytes': size, 'value': value}

    for index, name in enumerate(names):
        identity = selection.identity(name)
        accounting['identities'].append({
            'identity': identity,
            'selection': {'disposition': 'private-provider',
                          'owner': selection.SYSCALL_ALIAS_PRIVATE_OWNER,
                          'group': selection.SYSCALL_ALIAS_PRIVATE_GROUP},
            'unresolved': [selection.ORDINARY_IMPORT_REASON],
        })
        accounting['blockers'].append({'code': 'identity-unresolved', 'identity': identity,
                                       'reason': selection.ORDINARY_IMPORT_REASON})
        member = {'member': f'provider-{index}.o', 'member_index': 21 + index,
                  'member_occurrence': 0}
        imported = row(name, kind='NOTYPE', binding='GLOBAL', visibility='DEFAULT',
                       section='UND', size=0, value='0000000000000000')
        static = row(name, kind='FUNC', binding='GLOBAL', visibility='HIDDEN',
                     section='3', size=8, value='0000000000000000')
        shared = row(name, kind='FUNC', binding='LOCAL', visibility='HIDDEN',
                     section='9', size=8, value=f'{0x3000 + index * 16:016x}')
        claims.append({'name': name, 'static_c_import': imported,
                       'static_provider_member': member, 'static_provider': static,
                       'shared_provider': shared})
        source[name] = [{'section': f'.text.call_{name}', 'offset': 1}]
        for mode in final:
            address = 0x2000 + index * 16 if mode == 'static' else 0x1000 + index * 16
            final[mode][name] = {'provider_member': f"{archive}({member['member']})",
                                 'provider_address': address,
                                 'resolved_calls': [{'section': f'.text.call_{name}', 'offset': 1,
                                                     'call_address': address - 0x100,
                                                     'target_address': address}],
                                 'discarded_calls': []}
        for occurrence_index, artifact, table, role, member_name, member_index, symbol in (
            (index * 3 + 1, 'candidate-static', '.symtab', 'import', c_member['name'],
             c_member['member_index'], imported),
            (index * 3 + 2, 'candidate-static', '.symtab', 'definition', member['member'],
             member['member_index'], static),
            (index * 3 + 3, 'candidate-shared', '.symtab', 'local-definition', None,
             None, shared),
        ):
            occurrence = {'index': occurrence_index, 'artifact_key': artifact,
                          'table': table, 'role': role, 'row': symbol,
                          'member_name': member_name, 'member_index': member_index,
                          'member_occurrence': 0 if member_name else None,
                          'definition_section': {'name': '.text'}}
            accounting['occurrences'].append(occurrence)
            if role != 'import':
                metadata = {key: symbol[key] for key in ('type', 'binding', 'visibility')}
                accounting['placement_joins'].append({
                    'identity': identity, 'artifact_key': artifact,
                    'placement_observed': True, 'definition_count': 1,
                    'occurrence_indices': [occurrence_index],
                    'metadata_differences': [{'occurrence_index': occurrence_index, 'fields': []}],
                    'expected_metadata': metadata,
                })
    companion = {
        'status': 'native-c-allocator-boundary-observed-with-boundaries',
        'reader': {}, 'contract': {}, 'report': {}, 'source': {},
        'source_inputs': {}, 'products': {}, 'measurement_reports': {},
        'account': {
            'c_runtime_imports': {'static_c_member': c_member},
            'c_runtime_static_links': {
                'static': {'selected_members': {'static_c_member': f"{archive}({c_member['name']})"}},
            },
        },
        'private_vm_resolution': {
            'c_member': c_member, 'imports': claims, 'source_relocations': source,
            'static_final_links': final, 'shared_private_import_absent': True,
        },
        'limits': list(selection.C_ALLOCATOR_BOUNDARY_LIMITS),
    }
    return accounting, companion


class PrivateVmImportAttachmentTests(unittest.TestCase):
    def test_exact_c_member_and_hidden_provider_discharge_only_vm_imports(self) -> None:
        accounting, companion = fixture()
        joins = selection.attach_native_c_allocator_private_vm_imports(accounting, companion)
        self.assertEqual([join['identity']['name'] for join in joins], list(boundary.VM_PRIVATE_IMPORTS))
        self.assertEqual(accounting['blockers'], [])
        self.assertTrue(all(record['unresolved'] == [] for record in accounting['identities']))

    def test_foreign_or_duplicate_import_or_provider_rejects_join(self) -> None:
        for mutation in ('foreign-import', 'duplicate-import', 'foreign-provider',
                         'duplicate-provider', 'foreign-final-target'):
            with self.subTest(mutation=mutation):
                accounting, companion = fixture()
                name = boundary.VM_PRIVATE_IMPORTS[0]
                if mutation == 'foreign-import':
                    accounting['occurrences'][0]['member_name'] = 'foreign-c.o'
                elif mutation == 'duplicate-import':
                    extra = copy.deepcopy(accounting['occurrences'][0])
                    extra['index'] = 100
                    extra['member_name'] = 'foreign-c.o'
                    accounting['occurrences'].append(extra)
                elif mutation == 'foreign-provider':
                    accounting['occurrences'][1]['member_name'] = 'foreign-rust.o'
                elif mutation == 'duplicate-provider':
                    extra = copy.deepcopy(accounting['occurrences'][1])
                    extra['index'] = 100
                    extra['member_name'] = 'foreign-rust.o'
                    accounting['occurrences'].append(extra)
                else:
                    companion['private_vm_resolution']['static_final_links']['static'][name][
                        'resolved_calls'][0]['target_address'] += 16
                with self.assertRaises(selection.SelectionError):
                    selection.attach_native_c_allocator_private_vm_imports(accounting, companion)


if __name__ == '__main__':
    unittest.main()
