"""Private dispatchers retain their strong bodies and exact weak archive fallbacks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


def fixture(name):
    anchors = {'__fork_handler': ('pthread_atfork', 'fork', 'pthread_atfork.lo', 'fork.lo'),
               '__funcs_on_exit': ('__cxa_atexit', 'exit', 'atexit.lo', 'exit.lo')}
    provider, fallback, reference_provider, reference_fallback = anchors[name]
    identity = selection.identity(name)
    reason = 'missing, ambiguous or mismatched selected provider placement: candidate-static'
    record = {'identity': identity, 'selection': {
        'disposition': 'private-provider', 'owner': 'x86-process-private-dispatchers',
        'group': 'component-owned-process-private-dispatchers',
    }, 'unresolved': [reason]}
    rows = []
    for artifact, members in (
        ('candidate-static', ('provider.o', 'fallback.o')),
        ('reference-static', (reference_provider, reference_fallback)),
    ):
        for index, (member, anchor) in enumerate(zip(members, (provider, fallback))):
            for symbol, binding, visibility in ((name, 'GLOBAL' if index == 0 else 'WEAK', 'HIDDEN'),
                                                (anchor, 'GLOBAL', 'DEFAULT')):
                rows.append({'index': len(rows), 'artifact_key': artifact, 'table': '.symtab',
                             'role': 'definition', 'member_name': member, 'member_index': index,
                             'member_occurrence': 0, 'table_section_index': 3,
                             'row': {'name': symbol, 'version': None, 'version_default': False,
                                     'binding': binding, 'visibility': visibility,
                                     'type': 'NOTYPE' if artifact == 'candidate-static' and binding == 'WEAK' else 'FUNC',
                                     'section_index': '1', 'size_bytes': 4, 'value': '0'},
                             'definition_section': {'alignment': 8, 'type': 'PROGBITS', 'flags': 'AX'}})
    join = {'identity': identity, 'artifact_key': 'candidate-static',
            'expected_metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'},
            'occurrence_indices': [0, 2], 'definition_count': 2,
            'placement_observed': False, 'metadata_differences': [
                {'occurrence_index': 0, 'fields': []}, {'occurrence_index': 2, 'fields': ['type', 'binding']}],
            'metadata_origin': None}
    unnamed = copy.deepcopy(rows[0])
    unnamed['index'] = len(rows)
    unnamed['role'] = 'unnamed'
    unnamed['row']['name'] = None
    rows.append(unnamed)
    accounting = {'identities': [record], 'occurrences': rows, 'placement_joins': [join],
                  'blockers': [{'code': 'identity-unresolved', 'identity': identity, 'reason': reason}]}
    return accounting, ['provider.o', 'fallback.o']


class ProcessPrivateArchiveRolesTests(unittest.TestCase):
    def test_real_provider_and_fallback_are_both_retained(self):
        for name in ('__fork_handler', '__funcs_on_exit'):
            with self.subTest(name=name):
                accounting, members = fixture(name)
                original = copy.deepcopy(accounting['occurrences'])
                joins = selection.attach_process_private_dispatcher_roles(accounting, members)
                self.assertEqual(len(joins), 1)
                self.assertEqual(accounting['occurrences'], original)
                self.assertEqual(accounting['blockers'], [])
                placement = accounting['placement_joins'][0]
                self.assertTrue(placement['placement_observed'])
                self.assertEqual(placement['definition_count'], 2)
                self.assertEqual(placement['occurrence_indices'], [0, 2])
                self.assertEqual([row['role'] for row in placement['archive_definition_roles']],
                                 ['strong-provider', 'weak-fallback'])
                self.assertTrue(selection.same(accounting, json.loads(json.dumps(accounting))))
                self.assertTrue(selection.same(joins, json.loads(json.dumps(joins))))

    def test_foreign_conflicting_or_malformed_rows_cannot_discharge_the_blocker(self):
        for mutation in ('duplicate-strong', 'duplicate-weak', 'weak-as-strong', 'visible-weak',
                         'visible-strong', 'foreign-member', 'missing-anchor', 'foreign-anchor',
                         'reference-member', 'reference-binding', 'missing-fallback',
                         'member-repeat', 'merged-members', 'fallback-type', 'fallback-data',
                         'unexpected-import', 'unowned-name', 'public-owner'):
            with self.subTest(mutation=mutation):
                accounting, members = fixture('__fork_handler')
                rows = accounting['occurrences']
                if mutation.startswith('duplicate-'):
                    rows.append(copy.deepcopy(rows[0 if mutation == 'duplicate-strong' else 2]))
                    rows[-1]['index'] = 99
                elif mutation == 'weak-as-strong': rows[2]['row']['binding'] = 'GLOBAL'
                elif mutation == 'visible-weak': rows[2]['row']['visibility'] = 'DEFAULT'
                elif mutation == 'visible-strong': rows[0]['row']['visibility'] = 'DEFAULT'
                elif mutation == 'foreign-member': rows[0]['member_name'] = 'foreign.o'
                elif mutation == 'missing-anchor': rows.pop(1)
                elif mutation == 'foreign-anchor': rows[1]['member_index'] = 9
                elif mutation == 'reference-member': rows[4]['member_name'] = 'other.lo'
                elif mutation == 'reference-binding': rows[6]['row']['binding'] = 'GLOBAL'
                elif mutation == 'missing-fallback': rows.pop(2)
                elif mutation == 'member-repeat': rows[2]['member_occurrence'] = 1
                elif mutation == 'merged-members':
                    for row in rows[2:4]:
                        row['member_name'] = rows[0]['member_name']
                        row['member_index'] = rows[0]['member_index']
                elif mutation == 'fallback-type': rows[2]['row']['type'] = 'FUNC'
                elif mutation == 'fallback-data': rows[2]['definition_section']['flags'] = 'WA'
                elif mutation == 'unexpected-import': rows[2]['role'] = 'import'
                elif mutation == 'unowned-name': accounting['identities'][0]['identity']['name'] = '__other'
                elif mutation == 'public-owner': accounting['identities'][0]['selection']['disposition'] = 'public-provider'
                before = copy.deepcopy(accounting)
                self.assertEqual(selection.attach_process_private_dispatcher_roles(accounting, members), [])
                self.assertEqual(accounting, before)

    def test_archive_roles_cannot_discharge_a_shared_visibility_failure(self):
        accounting, members = fixture('__fork_handler')
        reason = 'missing, ambiguous or mismatched selected provider placement: candidate-shared'
        accounting['identities'][0]['unresolved'].append(reason)
        blocker = {'code': 'identity-unresolved', 'identity': selection.identity('__fork_handler'), 'reason': reason}
        accounting['blockers'].append(blocker)
        self.assertEqual(len(selection.attach_process_private_dispatcher_roles(accounting, members)), 1)
        self.assertEqual(accounting['identities'][0]['unresolved'], [reason])
        self.assertEqual(accounting['blockers'], [blocker])


if __name__ == '__main__':
    unittest.main()
