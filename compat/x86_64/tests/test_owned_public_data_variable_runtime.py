#!/usr/bin/env python3
"""Finite source-contract guards for installed public-data runtime evidence."""
from __future__ import annotations

import copy
import contextlib
import json
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
import crabc_cc_owned_dynamic as dynamic_driver
import crabc_cc_static as static_driver
import owned_posix_product_evidence as product_evidence


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
        getopt_group = next(
            group for group in contract['groups']
            if group['id'] == 'getopt-and-program-name-globals'
        )
        self.assertIn('libc/src/c_abi/x86_64/auxv_observation.rs', getopt_group['owner_sources'])
        self.assertIn('validated AT_EXECFN', getopt_group['semantics'])

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

    def test_getopt_runtime_probe_exercises_only_selected_public_state(self) -> None:
        contract = reader.load_contract()
        group = next(item for item in contract['groups']
                     if item['id'] == 'getopt-and-program-name-globals')
        self.assertEqual(group['probe_sources'], ['compat/x86_64/owned_public_data_getopt_probe.c'])
        source = (ROOT / group['probe_sources'][0]).read_text(encoding='utf-8')
        self.assertNotIn('extern int __optpos;', source)
        self.assertNotRegex(source, r'__optpos\s*(?:==|!=|[<>])')
        for required in (
            'optarg', 'opterr', 'optind', 'optopt', 'optreset',
            'program_invocation_name', 'program_invocation_short_name',
            '__optreset = 1', 'optreset = 1', 'getopt_long',
        ):
            self.assertIn(required, source)

    def test_posix_timezone_probe_keeps_the_empty_daylight_name_without_dst_rules(self) -> None:
        """``UTC0`` has a standard abbreviation but no daylight abbreviation.

        Pinned musl 1.2.6 and the selected source both publish the parsed
        daylight-name buffer for POSIX TZ strings.  It is a non-null empty
        string when the input supplies no DST rule; this is separate from the
        source-specific TZif known-difference observation.
        """
        source = (ROOT / 'compat/x86_64/owned_public_data_variable_runtime_probe.c').read_text(
            encoding='utf-8')
        self.assertIn('if (timezone != 0 || daylight != 0 || !tzname[0] || !tzname[1] ||', source)
        self.assertIn('strcmp(tzname[0], "UTC") || strcmp(tzname[1], "")) return 21;', source)
        timezone_group = next(item for item in reader.load_contract()['groups']
                              if item['id'] == 'timezone-globals')
        self.assertEqual(
            timezone_group['semantics'],
            'initial and tzset refresh publication under caller coordination, '
            'including an empty daylight abbreviation for no-DST POSIX forms',
        )

    def test_writable_fixture_sources_leave_their_declared_roots_reversible(self) -> None:
        """The source cleanup and retained-root policy name the same two files.

        The pinned C execution control exercises the cleanup itself.  This
        guard keeps a later source edit from silently moving either mutable
        path away from the reader's exact before/after root predicate.
        """
        getdate = next(entry for entry in reader.execution_plan() if entry['id'] == 'getdate')
        tzif = next(entry for entry in reader.execution_plan()
                    if entry['id'] == 'timezone-tzif-known-difference')
        getdate_source = (ROOT / getdate['source']).read_text(encoding='utf-8')
        tzif_source = (ROOT / tzif['source']).read_text(encoding='utf-8')
        self.assertGreater(getdate_source.index('unlink("/templates/mask")'),
                           getdate_source.index('observe("second-chunk"'))
        self.assertIn('fopen(path,"wb")', tzif_source)
        self.assertIn('CHECK(!unlink(path))', tzif_source)

        for scenario, retained in ((getdate, 'templates/mask'), (tzif, 'fixture/zone.tzif')):
            tree = {
                'consumer': {'kind': 'file', 'mode': 0o755},
                **{directory: {'kind': 'directory', 'mode': 0o755}
                   for directory in scenario['fixture_directories']},
            }
            reader._validate_fixture_tree(tree, scenario, scenario['id'] + ' empty fixture root')
            tree[retained] = {'kind': 'file', 'mode': 0o644}
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'remains after execution'):
                reader._validate_fixture_tree(tree, scenario, scenario['id'] + ' retained fixture file')

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

    def test_all_runtime_probe_compile_commands_are_admitted_by_the_installed_dynamic_driver(self) -> None:
        """The caller supplies no header or code-generation runtime authority.

        The materialized dynamic wrapper parses the compile invocation and
        then adds its own installed-header and selected-PIE flags. This uses
        every source-owned scenario before any one command becomes receipt
        authority.
        """
        work = ROOT / '.work' / 'x86_64' / 'public-data-runtime-compile-command-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            directory = Path(temporary)
            output = directory / 'receipt'
            output.mkdir()
            installed = directory / 'installed-dynamic'
            installed.mkdir()

            class Capture:
                def __init__(self) -> None:
                    self.commands: list[list[str]] = []

                def run(self, _label, argv, **_kwargs):
                    self.commands.append(list(argv))
                    destination = Path(argv[argv.index('-o') + 1])
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(b'compiled probe')
                    return {'label': _label}

            collector = reader.Collector(ROOT, output, directory / 'preparation', directory / 'static',
                                         directory / 'dynamic', {})
            collector.tools = {'dynamic_driver': {'original': {'path': str(installed / 'bin/crabc-cc-dynamic')}}}
            capture = Capture()
            collector.runner = capture
            for scenario in reader.execution_plan():
                collector._compile(scenario)
            self.assertEqual(len(capture.commands), len(reader.execution_plan()))
            for scenario, command in zip(reader.execution_plan(), capture.commands):
                with self.subTest(scenario=scenario['id']), \
                     mock.patch.object(dynamic_driver, 'validate'), \
                     mock.patch.object(dynamic_driver, 'run', return_value='') as run:
                    dynamic_driver.execute(installed, command[1:])
                    self.assertNotIn('-nostdinc', command)
                    self.assertNotIn('-isystem', command)
                    self.assertNotIn('-fPIE', command)
                    self.assertNotIn('-fPIC', command)
                    compiler_command = run.call_args.args[0]
                    self.assertIn('-nostdinc', compiler_command)
                    self.assertIn(str(installed / 'usr/include'), compiler_command)
                    self.assertIn('-fPIE', compiler_command)
                    self.assertNotIn('-fPIC', compiler_command)
                    self.assertNotIn('-fno-pie', compiler_command)

    def test_static_link_receipts_use_their_parent_as_the_driver_working_directory(self) -> None:
        """The static driver serializes relative map paths beside its receipt.

        Its retained product reader resolves those paths from the receipt
        parent.  Passing a receipt path which already names that parent while
        running from a higher directory would duplicate ``executables/<id>``
        on replay.
        """
        output = ROOT / '.work' / 'x86_64' / 'public-data-runtime-static-receipt-command-tests'
        output.mkdir(parents=True, exist_ok=True)
        for mode in ('static', 'static-pie'):
            with self.subTest(mode=mode):
                directory = output / mode / 'executables' / 'ns-flagdata'
                object_path = output / mode / 'objects' / 'ns-flagdata.o'
                executable = directory / mode
                argv, cwd = reader.runtime_probe_static_link_command(
                    '/tools/static', mode, object_path, executable,
                )
                self.assertEqual(cwd, directory)
                self.assertEqual(argv, [
                    '/tools/static', '-' + mode, '--link-receipt', mode + '.crabc-link.json',
                    str(object_path), '-o', str(executable),
                ])

    def test_static_driver_sidecar_record_resolves_from_the_receipt_parent(self) -> None:
        """Exercise the static driver's record against the retained product reader.

        This uses only text stand-ins for the linker's inputs and sidecars. It
        proves the path convention shared by the driver and product reader,
        without compiling, linking, or altering an ELF payload.
        """
        work = ROOT / '.work' / 'x86_64' / 'public-data-runtime-static-receipt-sidecar-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            checkout = Path(temporary) / 'checkout'
            product = checkout / 'product'
            library = product / 'usr/lib'
            for name in ('crt1.o', 'rcrt1.o', 'crti.o', 'crtn.o', 'libc.a', 'libcrabc-builtins.a'):
                path = library / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('product:' + name).encode())
            linker = checkout / '.work/x86_64/receipt/tools/ld.lld'
            linker.parent.mkdir(parents=True)
            linker.write_bytes(b'linker')
            for mode, static_mode in (
                ('static', static_driver.STATIC_ET_EXEC),
                ('static-pie', static_driver.STATIC_PIE),
            ):
                with self.subTest(mode=mode):
                    directory = checkout / '.work/x86_64/receipt/executables/ns-flagdata' / mode
                    directory.mkdir(parents=True)
                    object_path = checkout / '.work/x86_64/receipt/objects' / (mode + '.o')
                    object_path.parent.mkdir(parents=True, exist_ok=True)
                    object_path.write_bytes(b'ordinary source object:' + mode.encode())
                    executable = directory / mode
                    executable.write_bytes(b'ordinary static output:' + mode.encode())
                    argv, cwd = reader.runtime_probe_static_link_command(
                        '/tools/static', mode, object_path, executable,
                    )
                    receipt_argument = Path(argv[argv.index('--link-receipt') + 1])
                    self.assertEqual(cwd, directory)
                    previous = Path.cwd()
                    try:
                        os.chdir(cwd)
                        receipt, map_path, trace_path = static_driver.receipt_sidecars(product, receipt_argument)
                        map_path.write_bytes(b'ordinary link map:' + mode.encode())
                        trace_path.write_bytes(b'ordinary link trace:' + mode.encode())
                        static_driver.write_link_receipt(
                            product, static_mode, [object_path], executable, linker,
                            receipt, map_path, trace_path,
                        )
                    finally:
                        os.chdir(previous)

                    receipt_path = directory / (mode + '.crabc-link.json')
                    record = json.loads(receipt_path.read_text(encoding='utf-8'))
                    self.assertEqual(record['map']['path'], mode + '.crabc-link.map')
                    self.assertEqual(
                        product_evidence._retained_source_path(
                            checkout, '/workspace', record['map']['path'], receipt_path, 'static link map',
                        ),
                        directory / (mode + '.crabc-link.map'),
                    )
                    stale = dict(record['map'])
                    stale['path'] = directory.relative_to(checkout).as_posix() + '/' + mode + '.crabc-link.map'
                    with self.assertRaisesRegex(product_evidence.ProductEvidenceError, 'unreadable'):
                        product_evidence._retained_source_path(
                            checkout, '/workspace', stale['path'], receipt_path, 'static link map',
                        )

    def test_static_links_reach_the_ordinary_command_recorder_at_their_exact_sidecar_cwd(self) -> None:
        """Run the component link path through the real ordinary recorder.

        ``Popen`` is the only mocked external boundary. Its text-only static
        stand-in calls the real static receipt writer, and the retained
        product-reader path resolver validates those resulting sidecars.
        """
        work = ROOT / '.work' / 'x86_64' / 'public-data-runtime-static-cwd-admission-tests'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary) / 'checkout'
            output = root / '.work/receipt'
            output.mkdir(parents=True)
            product = root / '.work/static-product'
            for name in ('crt1.o', 'rcrt1.o', 'crti.o', 'crtn.o', 'libc.a', 'libcrabc-builtins.a'):
                path = product / 'usr/lib' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('product:' + name).encode())
            linker = root / '.work/tools/ld.lld'
            linker.parent.mkdir(parents=True)
            linker.write_bytes(b'linker')
            scenario = next(item for item in reader.execution_plan() if item['id'] == 'ns-flagdata')
            object_path = output / 'objects/ns-flagdata.o'
            object_path.parent.mkdir()
            object_path.write_bytes(b'ordinary source object')
            collector = reader.Collector(root, output, root / '.work/preparation', product,
                                         root / '.work/dynamic-product', {})
            collector.tools = {
                'static_driver': {'original': {'path': '/tools/static'}},
                'dynamic_driver': {'original': {'path': '/tools/dynamic'}},
                'oracle_wrapper': {'original': {'path': '/tools/oracle'}},
            }
            command_cwds = reader.runtime_probe_static_link_cwds(output)
            self.assertEqual(len(command_cwds), 22)
            collector.runner = reader.ordinary_link.Collector(
                root, output, root / '.work/preparation', product, root / '.work/dynamic-product',
                command_cwds=command_cwds,
            )

            def fake_popen(argv, **kwargs):
                command = list(argv)
                executable = Path(command[command.index('-o') + 1])
                if '--link-receipt' in command:
                    mode = 'static-pie' if command[1] == '-static-pie' else 'static'
                    directory = output / 'executables/ns-flagdata'
                    self.assertEqual(kwargs['cwd'], directory)
                    receipt_argument = Path(command[command.index('--link-receipt') + 1])
                    previous = Path.cwd()
                    try:
                        os.chdir(kwargs['cwd'])
                        receipt, map_path, trace_path = static_driver.receipt_sidecars(product, receipt_argument)
                        executable.write_bytes(('static output:' + mode).encode())
                        map_path.write_bytes(('static map:' + mode).encode())
                        trace_path.write_bytes(('static trace:' + mode).encode())
                        static_driver.write_link_receipt(
                            product,
                            static_driver.STATIC_PIE if mode == 'static-pie' else static_driver.STATIC_ET_EXEC,
                            [object_path], executable, linker, receipt, map_path, trace_path,
                        )
                    finally:
                        os.chdir(previous)
                elif command[0] == '/tools/oracle':
                    executable.write_bytes(b'oracle static output')
                else:
                    self.assertEqual(kwargs['cwd'], output)
                    executable.write_bytes(b'dynamic output')
                    Path(str(executable) + '.crabc-link.json').write_bytes(b'dynamic receipt')
                return mock.Mock(wait=mock.Mock(return_value=0))

            def retained_link(_product, _object, executable, receipt, linkage):
                if linkage in {'static', 'static-pie'}:
                    record = json.loads(Path(receipt).read_text(encoding='utf-8'))
                    resolved = product_evidence._retained_source_path(
                        root, '/workspace', record['map']['path'], Path(receipt), 'retained static link map',
                    )
                    self.assertEqual(resolved, Path(receipt).with_suffix('.map'))
                    return {'linkage': linkage, 'map': str(resolved)}
                return {'linkage': linkage, 'dynamic': str(executable)}

            with mock.patch.object(reader.ordinary_link.subprocess, 'Popen', side_effect=fake_popen), \
                 mock.patch.object(reader.product_evidence, 'validate_link', side_effect=retained_link):
                links = collector._link(scenario, object_path)
            self.assertEqual(set(links), {'oracle-static', *reader.CANDIDATE_MODES})
            rows = {row['label']: row for row in collector.runner.commands}
            directory = output / 'executables/ns-flagdata'
            for mode in ('static', 'static-pie'):
                row = rows['ns-flagdata-' + mode + '-link']
                self.assertEqual(row['cwd'], reader.ordinary_link.mounted(root, directory))
                self.assertEqual(row['argv'][row['argv'].index('--link-receipt') + 1],
                                 mode + '.crabc-link.json')
            for mode in ('dynamic-pie', 'dynamic-non-pie'):
                self.assertEqual(rows['ns-flagdata-' + mode + '-link']['cwd'],
                                 reader.ordinary_link.mounted(root, output))


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


class PublicDataVariableRuntimePublicReplayTests(unittest.TestCase):
    """Exercise the public reader's complete retained command/root join.

    The fixture keeps external product, tool, oracle and companion owners as
    typed admissions. It does not replace this reader's object, link, command,
    root, execution, or final-transaction validators: those operate over all
    eleven scenarios and seventy-seven actual plain-text execution roots.
    """

    def setUp(self) -> None:
        work = ROOT / '.work' / 'public-data-runtime-public-replay-tests'
        work.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.receipt = self.directory / 'receipt'
        self.receipt.mkdir()
        self.static_primary = self.directory / 'static-primary'
        self.static_primary.mkdir()
        self.dynamic_product = self.directory / 'dynamic-product'
        self._write(self.dynamic_product / 'lib/ld-crabc-x86_64.so.1', b'loader')
        self._write(self.dynamic_product / 'usr/lib/libc.so', b'libc', 0o644)
        self.companions = {}
        for name in reader.COMPANION_NAMES:
            path = self.directory / 'companions' / name / 'report.json'
            self._write(path, (name + '\n').encode(), 0o644)
            self.companions[name] = path
        self.cohort = {
            'static_preparation': {'primary': {'path': self.static_primary.relative_to(ROOT).as_posix()}},
            'dynamic_product': {'path': self.dynamic_product.relative_to(ROOT).as_posix()},
        }
        self.source = {'revision': 'test-current-source', 'content_sha256': 'a' * 64}
        self.projection = {'typed': 'current companion projection'}
        self.tools = {
            'static_driver': {'original': {'path': '/tools/static'}},
            'dynamic_driver': {'original': {'path': '/tools/dynamic'}},
            'oracle_wrapper': {'original': {'path': '/tools/oracle'}},
            'env': {'original': {'path': '/tools/env'}},
            'chroot': {'original': {'path': '/tools/chroot'}, 'invocation': {}},
            'linker': {'original': {'path': '/tools/linker', 'sha256': 'b' * 64}},
        }

    @staticmethod
    def _write(path: Path, payload: bytes, mode: int = 0o755) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        os.chmod(path, mode)

    def _identity(self, path: Path, description: str) -> dict[str, object]:
        return reader._receipt_file_identity(self.receipt, path, description)

    def _raw_record(self, label: str, argv: list[str], stdout: bytes = b'',
                    cwd: Path | None = None) -> dict[str, object]:
        paths = {}
        for field, suffix, payload in (
            ('command', 'command.json', json.dumps(argv).encode()),
            ('stdout', 'stdout', stdout), ('stderr', 'stderr', b''), ('status', 'status', b'0\n'),
        ):
            path = reader._recorded_command_path(self.receipt, label, suffix)
            self._write(path, payload, 0o644)
            paths[field] = reader.ordinary_link.work_file_identity(ROOT, path, 'synthetic ' + field)
        return {'label': label, 'argv': argv, 'cwd': str(self.receipt if cwd is None else cwd),
                'outcome': 'ok', **paths}

    def _command_rows(self) -> list[dict[str, object]]:
        rows = []
        invocation = '/tools/chroot'
        for scenario in reader.execution_plan():
            identifier = scenario['id']
            source = str(ROOT / scenario['source'])
            object_path = str(self.receipt / 'objects' / (identifier + '.o'))
            executable_dir = self.receipt / 'executables' / identifier
            rows.append(self._raw_record(
                identifier + '-compile',
                reader.runtime_probe_compile_argv('/tools/dynamic', Path(source), Path(object_path)),
            ))
            rows.append(self._raw_record(
                identifier + '-oracle-static-link',
                ['/tools/oracle', '-static', '-fno-pie', '-no-pie', object_path,
                 '-o', str(executable_dir / 'oracle-static')],
            ))
            for mode in reader.CANDIDATE_MODES:
                executable = executable_dir / mode
                if mode in {'static', 'static-pie'}:
                    argv, cwd = reader.runtime_probe_static_link_command(
                        '/tools/static', mode, Path(object_path), executable,
                    )
                else:
                    argv = ['/tools/dynamic', '--dynamic-pie' if mode == 'dynamic-pie' else '--dynamic-non-pie',
                            object_path, '-o', str(executable)]
                    cwd = None
                rows.append(self._raw_record(identifier + '-' + mode + '-link', argv, cwd=cwd))
            oracle_root = self.receipt / 'roots' / identifier / 'oracle-static'
            oracle_stdout = (reader.TZIF_ORACLE_STDOUT if identifier == 'timezone-tzif-known-difference'
                             else scenario['expected_stdout'])
            rows.append(self._raw_record(
                identifier + '-oracle-static-run',
                ['/tools/env', '-i', 'LC_ALL=C', 'TZ=UTC', 'PATH=/usr/bin:/bin', invocation,
                 str(oracle_root), *scenario['oracle_argv']], oracle_stdout,
            ))
            for cell in scenario['candidate_cells']:
                root = self.receipt / 'roots' / identifier / cell['id']
                argv = (['/lib/ld-crabc-x86_64.so.1', *scenario['candidate_argv']]
                        if cell['route'] == 'direct-interpreter' else scenario['candidate_argv'])
                rows.append(self._raw_record(
                    identifier + '-' + cell['id'] + '-run',
                    ['/tools/env', '-i', 'LC_ALL=C', 'TZ=UTC', 'PATH=/usr/bin:/bin', invocation,
                     str(root), *argv], scenario['expected_stdout'],
                ))
        self.assertEqual([row['label'] for row in rows], reader._expected_labels())
        return rows

    def _report(self) -> dict[str, object]:
        sources = reader._source_capture(self.receipt)
        copied_companions = reader._capture_companions(self.receipt, self.companions)
        self._write(self.receipt / 'qualification-oracle/runtime', b'oracle-runtime', 0o644)
        objects, links, executions = {}, {}, {}
        for scenario in reader.execution_plan():
            identifier = scenario['id']
            object_path = self.receipt / 'objects' / (identifier + '.o')
            self._write(object_path, ('object:' + identifier).encode())
            objects[identifier] = self._identity(object_path, identifier + ' object')
            directory = self.receipt / 'executables' / identifier
            oracle = directory / 'oracle-static'
            self._write(oracle, ('oracle:' + identifier).encode())
            links[identifier] = {'oracle-static': {'executable': self._identity(oracle, identifier + ' oracle')}}
            for mode in reader.CANDIDATE_MODES:
                executable = directory / mode
                link_receipt = directory / (mode + '.crabc-link.json')
                self._write(executable, (identifier + ':' + mode).encode())
                self._write(link_receipt, ('receipt:' + identifier + ':' + mode).encode(), 0o644)
                product = ROOT / (
                    self.cohort['static_preparation']['primary']['path']
                    if mode in {'static', 'static-pie'} else self.cohort['dynamic_product']['path']
                )
                links[identifier][mode] = {
                    'executable': self._identity(executable, identifier + ' ' + mode),
                    'receipt': self._identity(link_receipt, identifier + ' ' + mode + ' receipt'),
                    'identity': {'linkage': reader._mode_linkage(mode), 'product': str(product)},
                }
            oracle_root = self.receipt / 'roots' / identifier / 'oracle-static'
            reader._oracle_root_setup(oracle_root, self.receipt, oracle, scenario['fixture_directories'])
            oracle_tree = reader.ordinary_link.execution_tree(ROOT, oracle_root, identifier + ' oracle root')
            executions[identifier + '/oracle-static'] = {
                'root': oracle_root.relative_to(self.receipt).as_posix(),
                'before': oracle_tree, 'after': oracle_tree,
                'command': identifier + '-oracle-static-run',
            }
            for cell in scenario['candidate_cells']:
                root = self.receipt / 'roots' / identifier / cell['id']
                executable = directory / cell['mode']
                if cell['mode'] in {'static', 'static-pie'}:
                    reader._static_root_setup(root, executable, scenario['fixture_directories'])
                else:
                    reader._dynamic_root_setup(root, self.dynamic_product, executable, scenario['fixture_directories'])
                tree = reader.ordinary_link.execution_tree(ROOT, root, identifier + ' ' + cell['id'] + ' root')
                executions[identifier + '/' + cell['id']] = {
                    'root': root.relative_to(self.receipt).as_posix(),
                    'before': tree, 'after': tree,
                    'command': identifier + '-' + cell['id'] + '-run',
                }
        return {
            'schema': reader.SCHEMA, 'status': reader.STATUS, 'component': reader.COMPONENT,
            'collection': {'image': reader.IMAGE, 'source': self.source},
            'contract': reader.load_contract(), 'inputs_before': self.cohort, 'inputs_after': self.cohort,
            'sources': sources, 'companions': {'inputs': copied_companions, 'projection': self.projection},
            'oracle': {}, 'oracle_static_inputs': {}, 'tools': self.tools, 'objects': objects,
            'links': links, 'commands': self._command_rows(), 'executions': executions,
            'runtime_matrix': reader.empty_runtime_matrix(),
            'h_errno': reader.h_errno_composition_contract(),
            'coverage': {
                'objects': list(reader.OBJECTS), 'groups': [name for name, _objects in reader.GROUPS],
                'component_complete': True, 'family_completion': False,
                'runtime_qualification': False, 'public_support': False,
            },
        }

    def _write_report(self, report: dict[str, object]) -> Path:
        path = self.receipt / 'report.json'
        path.write_text(json.dumps(report, sort_keys=True), encoding='utf-8')
        os.chmod(path, 0o644)
        return path

    def _validate(self, path: Path):
        return reader.validate_report(
            path, root=ROOT, static_preparation=self.static_primary,
            static_product=self.static_primary, dynamic_product=self.dynamic_product,
            **self.companions,
        )

    def test_public_replay_binds_all_command_object_link_root_and_final_boundaries(self) -> None:
        report = self._report()
        path = self._write_report(report)

        def retained_link(_root, _mount, _product, _object, _executable, _receipt, linkage, _linker):
            return {'linkage': linkage}

        patches = (
            mock.patch.object(reader.ordinary_link, 'admit_inputs', return_value=self.cohort),
            mock.patch.object(reader.static_products, 'source_identity', return_value=self.source),
            mock.patch.object(reader, '_current_companion_projection', return_value=self.projection),
            mock.patch.object(reader.ordinary_link.qualification, 'validate_oracle'),
            mock.patch.object(reader.ordinary_link, 'validate_oracle_static_inputs'),
            mock.patch.object(reader.ordinary_link, 'validate_tool_roster', return_value=self.tools),
            mock.patch.object(reader.ordinary_link, 'validate_chroot_invocation', return_value='/tools/chroot'),
            mock.patch.object(reader.product_evidence, 'validate_retained_link', side_effect=retained_link),
        )
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            result = self._validate(path)
            self.assertEqual(result['coverage'], report['coverage'])
            self.assertEqual(result['report']['path'], 'report.json')

            changed = copy.deepcopy(report)
            next(row for row in changed['commands']
                 if row['label'] == 'ns-flagdata-static-link')['cwd'] = str(self.receipt)
            self._write_report(changed)
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'working directory differs'):
                self._validate(path)

            self._write_report(report)
            changed = copy.deepcopy(report)
            changed['executions']['ns-flagdata/oracle-static']['command'] = 'math-sign-static-run'
            self._write_report(changed)
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'command differs'):
                self._validate(path)

            self._write_report(report)
            changed = copy.deepcopy(report)
            changed['objects']['ns-flagdata']['sha256'] = '0' * 64
            self._write_report(changed)
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'object identity differs'):
                self._validate(path)

            self._write_report(report)
            changed = copy.deepcopy(report)
            changed['links']['ns-flagdata']['static']['executable']['path'] = 'executables/ns-flagdata/other'
            self._write_report(changed)
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'executable identity differs'):
                self._validate(path)

            self._write_report(report)
            consumer = self.receipt / 'roots' / 'ns-flagdata' / 'static' / 'consumer'
            self._write(consumer, b'resealed consumer')
            with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'payload differs'):
                self._validate(path)
            shutil.copy2(self.receipt / 'executables' / 'ns-flagdata' / 'static', consumer)

            calls = 0

            def mutate_at_final_tool_recheck(*_args: object, **_kwargs: object) -> dict[str, object]:
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.write_text('{"replaced":true}', encoding='utf-8')
                    os.chmod(path, 0o644)
                return self.tools

            with mock.patch.object(reader.ordinary_link, 'validate_tool_roster', side_effect=mutate_at_final_tool_recheck):
                with self.assertRaisesRegex(reader.PublicDataVariableRuntimeError, 'report changed during replay'):
                    self._validate(path)


if __name__ == '__main__':
    unittest.main()
