#!/usr/bin/env python3
"""Finite source-contract guards for installed public-data runtime evidence."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

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


class PublicDataVariableRuntimeExecutionRootTests(unittest.TestCase):
    """Execution roots are copies of named payloads, never self-authentication."""

    def setUp(self) -> None:
        self.work = ROOT / '.work' / 'public-data-runtime-execution-root-tests'
        self.work.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=self.work)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.receipt = self.directory / 'receipt'
        self.receipt.mkdir()
        self.scenario = next(item for item in reader.execution_plan() if item['id'] == 'getdate')

    @staticmethod
    def _write(path: Path, payload: bytes, mode: int = 0o755) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, mode)

    def _identity(self, path: Path) -> dict[str, object]:
        return reader._receipt_file_identity(self.receipt, path, 'test retained executable')

    def _root_with_consumer(self, root: Path, executable: Path) -> None:
        root.mkdir(parents=True)
        shutil.copy2(executable, root / 'consumer')
        (root / 'templates').mkdir()
        os.chmod(root / 'templates', 0o755)

    def test_root_projection_binds_static_dynamic_and_oracle_payloads(self) -> None:
        static_executable = self.receipt / 'executables/static'
        dynamic_executable = self.receipt / 'executables/dynamic-pie'
        oracle_executable = self.receipt / 'executables/oracle-static'
        for executable, payload in ((static_executable, b'static'), (dynamic_executable, b'dynamic'),
                                    (oracle_executable, b'oracle')):
            self._write(executable, payload)
        static_root = self.receipt / 'roots/static'
        self._root_with_consumer(static_root, static_executable)
        dynamic_product = self.directory / 'dynamic-product'
        self._write(dynamic_product / 'lib/ld-crabc-x86_64.so.1', b'loader')
        self._write(dynamic_product / 'usr/lib/libc.so', b'libc', 0o644)
        dynamic_root = self.receipt / 'roots/dynamic-pie'
        shutil.copytree(dynamic_product, dynamic_root, symlinks=True)
        shutil.copy2(dynamic_executable, dynamic_root / 'consumer')
        (dynamic_root / 'templates').mkdir()
        os.chmod(dynamic_root / 'templates', 0o755)
        runtime = self.receipt / 'qualification-oracle/runtime'
        self._write(runtime, b'musl-runtime', 0o644)
        oracle_root = self.receipt / 'roots/oracle-static'
        reader._oracle_root_setup(oracle_root, self.receipt, oracle_executable, ('templates',))

        reader._validate_execution_root(
            receipt_root=self.receipt, root=static_root, scenario=self.scenario, mode='static',
            executable=self._identity(static_executable), dynamic_product=None,
        )
        reader._validate_execution_root(
            receipt_root=self.receipt, root=dynamic_root, scenario=self.scenario, mode='dynamic-pie',
            executable=self._identity(dynamic_executable), dynamic_product=dynamic_product,
        )
        reader._validate_execution_root(
            receipt_root=self.receipt, root=oracle_root, scenario=self.scenario, mode='oracle-static',
            executable=self._identity(oracle_executable), dynamic_product=None,
        )

    def test_root_projection_rejects_product_substitution_or_extra_payload(self) -> None:
        executable = self.receipt / 'executables/dynamic-pie'
        self._write(executable, b'dynamic')
        dynamic_product = self.directory / 'dynamic-product'
        self._write(dynamic_product / 'lib/ld-crabc-x86_64.so.1', b'loader')
        dynamic_root = self.receipt / 'roots/dynamic-pie'
        shutil.copytree(dynamic_product, dynamic_root, symlinks=True)
        shutil.copy2(executable, dynamic_root / 'consumer')
        (dynamic_root / 'templates').mkdir()
        os.chmod(dynamic_root / 'templates', 0o755)
        self._write(dynamic_root / 'lib/ld-crabc-x86_64.so.1', b'substituted')
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'product copy'):
            reader._validate_execution_root(
                receipt_root=self.receipt, root=dynamic_root, scenario=self.scenario, mode='dynamic-pie',
                executable=self._identity(executable), dynamic_product=dynamic_product,
            )
        self._write(dynamic_root / 'lib/ld-crabc-x86_64.so.1', b'loader')
        self._write(dynamic_root / 'unexpected', b'extra')
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'payload'):
            reader._validate_execution_root(
                receipt_root=self.receipt, root=dynamic_root, scenario=self.scenario, mode='dynamic-pie',
                executable=self._identity(executable), dynamic_product=dynamic_product,
            )

    def test_oracle_root_setup_normalizes_the_inherited_lib_directory_mode(self) -> None:
        runtime = self.receipt / 'qualification-oracle/runtime'
        consumer = self.receipt / 'executables/oracle-static'
        self._write(runtime, b'musl-runtime', 0o644)
        self._write(consumer, b'oracle')
        roots = self.receipt / 'roots'
        roots.mkdir()
        os.chmod(roots, 0o2755)
        root = roots / 'oracle-static'
        reader._oracle_root_setup(root, self.receipt, consumer, ('templates',))
        self.assertEqual((root / 'lib').stat().st_mode & 0o7777, 0o755)

    def test_retained_link_identity_and_execution_record_are_canonical(self) -> None:
        executable = self.receipt / 'executables/getdate/static'
        self._write(executable, b'static')
        identity = self._identity(executable)
        self.assertEqual(
            reader._validate_retained_file_at(
                self.receipt, identity, 'executables/getdate/static', 'test executable',
            ),
            identity,
        )
        wrong_path = copy.deepcopy(identity)
        wrong_path['path'] = 'executables/getdate/other'
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'identity differs'):
            reader._validate_retained_file_at(
                self.receipt, wrong_path, 'executables/getdate/static', 'test executable',
            )
        valid = {'root': 'roots/getdate/static', 'before': {}, 'after': {}, 'command': 'getdate-static-run'}
        self.assertEqual(
            reader._validate_execution_record(
                valid, root='roots/getdate/static', command='getdate-static-run', description='test execution',
            ),
            valid,
        )
        wrong_root = copy.deepcopy(valid)
        wrong_root['root'] = 'roots/other/static'
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'root differs'):
            reader._validate_execution_record(
                wrong_root, root='roots/getdate/static', command='getdate-static-run', description='test execution',
            )
        wrong_command = copy.deepcopy(valid)
        wrong_command['command'] = 'getdate-dynamic-pie-kernel-run'
        with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'command differs'):
            reader._validate_execution_record(
                wrong_command, root='roots/getdate/static', command='getdate-static-run', description='test execution',
            )

    def test_every_execution_cell_requires_its_own_root_and_command_label(self) -> None:
        records = {}
        links = {}
        commands = []
        for scenario in reader.execution_plan():
            identifier = scenario['id']
            links[identifier] = {
                'oracle-static': {'executable': {}},
                **{
                    mode: {'executable': {}, 'receipt': {}, 'identity': {}}
                    for mode in reader.CANDIDATE_MODES
                },
            }
            for cell in ('oracle-static', *[item['id'] for item in scenario['candidate_cells']]):
                key = identifier + '/' + cell
                root = self.receipt / 'roots' / identifier / cell
                root.mkdir(parents=True)
                command = identifier + '-' + cell + '-run'
                records[key] = {
                    'root': root.relative_to(self.receipt).as_posix(), 'before': {}, 'after': {}, 'command': command,
                }
                commands.append({'label': command})
        with mock.patch.object(reader, '_validate_execution_root', return_value={}) as roots:
            reader._validate_executions(self.receipt, records, commands, links, self.directory / 'dynamic-product')
        self.assertEqual(roots.call_count, 77)
        changed = copy.deepcopy(records)
        changed['ns-flagdata/oracle-static']['command'] = 'math-sign-static-run'
        with mock.patch.object(reader, '_validate_execution_root', return_value={}):
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'command differs'):
                reader._validate_executions(self.receipt, changed, commands, links, self.directory / 'dynamic-product')

    def test_final_recheck_reopens_all_live_boundaries_and_rejects_report_replacement(self) -> None:
        report = self.receipt / 'report.json'
        report.write_text('{}\n', encoding='utf-8')
        report_before = reader._receipt_file_identity(self.receipt, report, 'test report')
        supplied = {}
        originals = {}
        for name in reader.COMPANION_NAMES:
            path = self.directory / (name + '.json')
            self._write(path, name.encode(), 0o644)
            supplied[name] = path
            originals[name] = {
                'original': {
                    'path': str(path), 'sha256': reader.digest(path), 'size': path.stat().st_size, 'mode': 0o644,
                },
            }
        cohort = {'cohort': 'current'}
        sources = {'captured': 'source'}
        projection = {'joined': 'companions'}
        tools = {'tool': 'current'}
        collection = {'source': {'revision': 'current'}}
        companions = {'inputs': {name: {} for name in reader.COMPANION_NAMES}, 'projection': projection}
        with mock.patch.object(reader.ordinary_link, 'admit_inputs', return_value=cohort) as admitted, \
             mock.patch.object(reader, '_validate_source_capture', return_value=sources) as source_capture, \
             mock.patch.object(reader.static_products, 'source_identity', return_value=collection['source']), \
             mock.patch.object(reader, '_validate_copied_input', side_effect=lambda _root, _value, description: originals[description.removeprefix('public-data runtime ')]), \
             mock.patch.object(reader, '_current_companion_projection', return_value=projection) as companion_projection, \
             mock.patch.object(reader.ordinary_link.qualification, 'validate_oracle'), \
             mock.patch.object(reader.ordinary_link, 'validate_oracle_static_inputs'), \
             mock.patch.object(reader.ordinary_link, 'validate_tool_roster', return_value=tools):
            reader._recheck_live_collection_boundary(
                receipt_root=self.receipt, report_path=report, report_before=report_before,
                root=ROOT, static_preparation=self.directory / 'preparation', static_product=self.directory / 'static',
                dynamic_product=self.directory / 'dynamic', actual_inputs=cohort, sources=sources,
                collection=collection, companions=companions, supplied_companions=supplied,
                oracle={}, oracle_static_inputs={}, tools=tools,
            )
        self.assertEqual(admitted.call_count, 1)
        self.assertEqual(source_capture.call_count, 1)
        self.assertEqual(companion_projection.call_count, 1)

        def mutate_report(*_args: object, **_kwargs: object) -> dict[str, str]:
            report.write_text('{"replaced":true}\n', encoding='utf-8')
            return tools

        with mock.patch.object(reader.ordinary_link, 'admit_inputs', return_value=cohort), \
             mock.patch.object(reader, '_validate_source_capture', return_value=sources), \
             mock.patch.object(reader.static_products, 'source_identity', return_value=collection['source']), \
             mock.patch.object(reader, '_validate_copied_input', side_effect=lambda _root, _value, description: originals[description.removeprefix('public-data runtime ')]), \
             mock.patch.object(reader, '_current_companion_projection', return_value=projection), \
             mock.patch.object(reader.ordinary_link.qualification, 'validate_oracle'), \
             mock.patch.object(reader.ordinary_link, 'validate_oracle_static_inputs'), \
             mock.patch.object(reader.ordinary_link, 'validate_tool_roster', side_effect=mutate_report):
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'report changed during replay'):
                reader._recheck_live_collection_boundary(
                    receipt_root=self.receipt, report_path=report, report_before=report_before,
                    root=ROOT, static_preparation=self.directory / 'preparation', static_product=self.directory / 'static',
                    dynamic_product=self.directory / 'dynamic', actual_inputs=cohort, sources=sources,
                    collection=collection, companions=companions, supplied_companions=supplied,
                    oracle={}, oracle_static_inputs={}, tools=tools,
                )


if __name__ == '__main__':
    unittest.main()
