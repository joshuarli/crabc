#!/usr/bin/env python3
"""Finite source-contract guards for installed public-data runtime evidence."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import sys
import tempfile
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
        self.assertIn('compat/x86_64/tests/test_owned_public_data_variable_runtime.py', paths)
        self.assertIn('include/netdb.h', paths)
        self.assertIn('compat/x86_64/native-abi-selection.toml', paths)
        self.assertIn('compat/x86_64/native_data_declarations.toml', paths)
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

    def test_every_group_probe_has_all_candidate_modes_and_both_dynamic_routes(self) -> None:
        plan = reader.probe_execution_plan()
        self.assertEqual([entry['group'] for entry in plan], [
            'immutable-network-data', 'immutable-network-data', 'immutable-network-data',
            'environment-global', 'getdate-global', 'getopt-and-program-name-globals',
            'math-sign-global', 'permanent-standard-stream-slots',
            'timezone-globals', 'timezone-globals',
        ])
        for entry in plan:
            self.assertEqual(entry['candidate_modes'], ['static', 'static-pie', 'dynamic-pie', 'dynamic-non-pie'])
            self.assertEqual(entry['dynamic_routes'], ['kernel', 'direct-interpreter'])

    def test_execution_plan_keeps_all_sixty_six_candidate_cells_and_tzif_difference(self) -> None:
        plan = reader.execution_plan()
        self.assertEqual(len(plan), 11)
        self.assertEqual(sum(len(entry['candidate_cells']) for entry in plan), 66)
        self.assertEqual(
            [entry['id'] for entry in plan],
            [
                'ns-flagdata', 'in6addr-any', 'in6addr-loopback',
                'environment-lifecycle-normal', 'environment-lifecycle-allocation-failure',
                'getdate', 'getopt-and-program-names', 'math-sign',
                'standard-stream-slots', 'timezone-tzif-known-difference',
                'timezone-posix-publication',
            ],
        )
        tzif = plan[-2]
        self.assertFalse(tzif['candidate_equals_musl'])
        self.assertEqual(tzif['candidate_argv'], ['/consumer', '/fixture/zone.tzif', 'check'])
        self.assertEqual(tzif['oracle_argv'], ['/consumer', '/fixture/zone.tzif', 'observe'])
        environment = plan[3]
        self.assertEqual(environment['candidate_argv'], ['/consumer'])
        self.assertEqual(environment['expected_stdout'], b'environment-lifecycle-ok\n')
        self.assertEqual(
            {entry['source'] for entry in plan},
            {entry['source'] for entry in reader.probe_execution_plan()},
        )

    def test_new_probe_streams_are_actual_c_byte_sequences_not_escaped_renderings(self) -> None:
        self.assertEqual(reader.EXPECTED_STDOUT['math-sign'], b'math-sign-global-ok\n')
        self.assertEqual(len(reader.EXPECTED_STDOUT['math-sign']), 20)
        self.assertEqual(reader.EXPECTED_STDOUT['timezone-posix-publication'], b'timezone-globals-ok\n')
        self.assertEqual(len(reader.EXPECTED_STDOUT['timezone-posix-publication']), 20)
        self.assertNotIn(b'\\n', reader.EXPECTED_STDOUT['math-sign'])
        self.assertNotIn(b'\\n', reader.TZIF_ORACLE_STDOUT)

    def test_retained_input_policy_rejects_a_symlink_before_resolving_it(self) -> None:
        work = ROOT / '.work' / 'public-data-runtime-source-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            directory = Path(temporary)
            target = directory / 'target'
            target.write_bytes(b'current source')
            alias = directory / 'alias'
            os.symlink(target.name, alias)
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'symlink'):
                reader._physical_file(alias, 'test retained input')


if __name__ == '__main__':
    unittest.main()
