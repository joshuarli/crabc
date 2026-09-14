#!/usr/bin/env python3
"""Finite source-contract guards for installed public-data runtime evidence."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_public_data_variable_runtime as reader


class PublicDataVariableRuntimeContractTests(unittest.TestCase):
    """The receipt has one fixed declaration-completion roster, never a prefix."""

    def test_current_contract_has_exact_seven_groups_nineteen_objects_and_aliases(self) -> None:
        contract = reader.load_contract()
        self.assertEqual(
            [group['id'] for group in contract['groups']],
            [
                'immutable-network-data',
                'environment-global',
                'getdate-global',
                'getopt-and-program-name-globals',
                'math-sign-global',
                'permanent-standard-stream-slots',
                'timezone-globals',
            ],
        )
        self.assertEqual(
            [name for group in contract['groups'] for name in group['objects']],
            [
                '_ns_flagdata', 'in6addr_any', 'in6addr_loopback', 'environ', 'getdate_err',
                'optarg', 'opterr', 'optind', 'optopt', 'optreset',
                'program_invocation_name', 'program_invocation_short_name', 'signgam',
                'stdin', 'stdout', 'stderr', 'timezone', 'daylight', 'tzname',
            ],
        )
        self.assertEqual(
            contract['alias_dependencies'],
            [
                {'dependency': '__environ', 'object': 'environ'},
                {'dependency': '_environ', 'object': 'environ'},
                {'dependency': '___environ', 'object': 'environ'},
                {'dependency': '__optreset', 'object': 'optreset'},
                {'dependency': '__progname', 'object': 'program_invocation_short_name'},
                {'dependency': '__progname_full', 'object': 'program_invocation_name'},
                {'dependency': '__signgam', 'object': 'signgam'},
                {'dependency': '__timezone', 'object': 'timezone'},
                {'dependency': '__daylight', 'object': 'daylight'},
                {'dependency': '__tzname', 'object': 'tzname'},
            ],
        )
        self.assertEqual(contract['candidate_modes'], ['static', 'static-pie', 'dynamic-pie', 'dynamic-non-pie'])
        self.assertEqual(contract['dynamic_execution_routes'], ['kernel', 'direct-interpreter'])

    def test_contract_rejects_a_missing_or_substituted_group_before_collection(self) -> None:
        contract = reader.load_contract()
        missing = copy.deepcopy(contract)
        missing['groups'].pop()
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'group roster'):
            reader.validate_contract(missing)
        substituted = copy.deepcopy(contract)
        substituted['groups'][0]['objects'][0] = 'h_errno'
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'object roster'):
            reader.validate_contract(substituted)

    def test_matrix_rejects_an_omitted_candidate_mode_or_dynamic_execution_route(self) -> None:
        matrix = reader.empty_runtime_matrix()
        reader.validate_runtime_matrix(matrix)
        omitted_mode = copy.deepcopy(matrix)
        omitted_mode[0]['candidate_modes'].remove('static-pie')
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'candidate mode roster'):
            reader.validate_runtime_matrix(omitted_mode)
        omitted_route = copy.deepcopy(matrix)
        omitted_route[0]['dynamic_routes'].pop()
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'dynamic execution route roster'):
            reader.validate_runtime_matrix(omitted_route)

    def test_source_roster_keeps_the_direct_timezone_publication_probe_with_tzif(self) -> None:
        paths = [record['path'] for record in reader.source_inputs()]
        self.assertIn('compat/x86_64/owned_timezone_tzif_probe.c', paths)
        self.assertIn('compat/x86_64/owned_public_data_variable_runtime_probe.c', paths)
        self.assertIn('include/netdb.h', paths)
        self.assertIn('compat/x86_64/owned_errno_storage_lifecycle.py', paths)
        self.assertEqual(len(paths), len(set(paths)))

    def test_h_errno_is_a_fixed_cross_owner_composition_not_a_nineteenth_probe(self) -> None:
        self.assertEqual(reader.h_errno_composition_contract(), {
            'object': 'h_errno',
            'accessor': '__h_errno_location',
            'header': 'include/netdb.h',
            'header_owner': 'native_data_declarations',
            'runtime_owner': 'owned_errno_storage_lifecycle',
            'static_shared_roles': ['static', 'shared'],
            'execution_scope': ['main', 'live-worker', 'loaded-dso'],
        })


if __name__ == '__main__':
    unittest.main()
