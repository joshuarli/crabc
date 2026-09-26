"""Finite native component evidence, with independent physical raw fixtures."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import owned_posix_native_observations as native
import owned_math_oracle_defects as math_oracle_defects
import owned_wordexp_upstream_policy as wordexp_policy
import owned_differential_evidence as differential
import owned_signal_process_evidence as signals
import owned_pthread_stress_source as profile
import owned_os_test_aio_suspend_source as aio_suspend_source

MODES = ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct')


class NativeObservationsTests(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / '.work/x86_64/native-observation-tests'
        temporary.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=temporary))
        self.addCleanup(shutil.rmtree, self.root)
        self.leaf = self.root / '.work/leaf'
        self.product = self.root / '.work/product'
        self.leaf.mkdir(parents=True)
        self.product.mkdir()
        self.mount = '/workspace'
        self.put(self.product / 'share/crabc/manifest.json', {'schema': 1,
            'format': 'crabc-x86-64-owned-dynamic-sysroot-v1', 'target': 'x86_64-unknown-linux-musl'})
        self.put(self.product / 'bin/crabc-cc-dynamic', b'driver')
        self.put(self.product / 'share/crabc/crabc_cc_static.py', b"HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\n")

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + '\n').encode())
        return path

    def recorded(self, path):
        return self.mount + '/' + path.relative_to(self.root).as_posix()

    def binding(self, path):
        return {'path': self.recorded(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def identity(self, path):
        return {'sha256': self.binding(path)['sha256'], 'mode': path.stat().st_mode,
                'resolved_path': self.recorded(path)}

    def copy_source(self, relative):
        return self.put(self.root / relative, (ROOT / relative).read_bytes())

    def link(self, mode, object_path, binary):
        receipt = self.put(Path(str(binary) + '.crabc-link.json'), {})
        return {'linkage': mode, 'product': self.recorded(self.product),
                'product_format': 'crabc-x86-64-owned-dynamic-sysroot-v1',
                'product_manifest_sha256': self.binding(self.product / 'share/crabc/manifest.json')['sha256'],
                'workload_sha256': self.binding(object_path)['sha256'],
                'executable_sha256': self.binding(binary)['sha256'], 'receipt_sha256': self.binding(receipt)['sha256']}

    def raw(self, stem, stdout=b'ok\n', status=b'0\n'):
        return {stream: self.put(self.leaf / (stem + '.' + stream), raw)
                for stream, raw in (('status', status), ('stdout', stdout), ('stderr', b''))}

    def collect(self, component):
        return native.collect(component, self.leaf, source_mount=self.mount,
                              dynamic_product=self.product, root=self.root)

    def differential_fixture(self):
        matrix = differential.frozen_matrix(False)
        installed = {'root': self.recorded(self.product), 'manifest': self.binding(self.product / 'share/crabc/manifest.json')}
        compilation = {'schema': differential.COMPILE_SCHEMA, 'pre_compile': {'installed_dynamic': installed, 'sources': {}},
                       'installed_dynamic': installed, 'translation': {}, 'cases': []}
        summary = {'schema': differential.SUMMARY_SCHEMA, 'status': 'pass', 'static_replayed': False,
                   'cases': list(differential.CASES), 'links': {}, 'copies': {}, 'observations': {}}
        for case in differential.CASES:
            source = self.copy_source('compat/differential/tests/' + case + '.c')
            obj = self.put(self.leaf / 'objects' / (case + '.o'), case.encode())
            compilation['cases'].append({'case': case, 'source': self.binding(source), 'object': self.binding(obj)})
            compilation['pre_compile']['sources'][case] = self.binding(source)
            oracle = self.put(self.leaf / 'oracle' / case, b'oracle-executable')
            self.put(self.leaf / 'links' / (case + '-musl.json'), {'schema': differential.ORACLE_LINK_SCHEMA,
                'case': case, 'canonical_object': self.binding(obj), 'executable': self.binding(oracle),
                'command': ['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', self.recorded(obj), '-o', self.recorded(oracle)]})
            reference = self.raw('executions/' + case + '-musl', (case + ': errno=9 result\n').encode())
            for mode in ('pie', 'non-pie'):
                binary = self.put(self.leaf / 'candidates' / f'{case}-dynamic-{mode}', b'executable')
                link = {'schema': differential.LINK_SCHEMA, 'case': case, 'linkage': mode,
                        'canonical_object': self.binding(obj), 'sealed_link': self.link(mode, obj, binary)}
                self.put(self.leaf / 'links' / f'{case}-dynamic-{mode}.json', link)
            for mode in MODES:
                label = 'dynamic-' + mode
                candidate = self.raw('executions/' + case + '-' + label, reference['stdout'].read_bytes())
                record = {'schema': differential.OBSERVATION_SCHEMA, 'case': case, 'passed': True, 'differences': []}
                for role, paths, role_label in (('reference', reference, 'musl'), ('candidate', candidate, label)):
                    record[role] = {'label': role_label, 'status': 0, 'errno': 9}
                    for stream in ('stdout', 'stderr', 'status'):
                        record[role]['raw_status' if stream == 'status' else stream] = {
                            **self.binding(paths[stream]), 'byte_length': paths[stream].stat().st_size}
                self.put(self.leaf / 'observations' / f'{case}-{label}.json', record)
        for directory in ('links', 'copies', 'observations'):
            for item in matrix[directory]:
                path = self.leaf / directory / item['name']
                if not path.exists():
                    self.put(path, {})
                summary[directory][directory + '/' + item['name']] = {'path': item['name'], 'sha256': self.binding(path)['sha256']}
        compile_path = self.put(self.leaf / 'compile.json', compilation)
        summary['compile'] = self.binding(compile_path)
        self.put(self.leaf / 'summary.json', summary)

    def signal_fixture(self):
        source = self.copy_source('compat/signal-process/tests/signal_process.c')
        obj = self.put(self.leaf / 'workload.o', b'signal-object')
        inputs = {'source': self.binding(source), 'product_manifest': self.binding(self.product / 'share/crabc/manifest.json'),
                  'planned_object': self.recorded(obj), 'driver_compile_command': ['driver']}
        self.put(self.leaf / 'compile-inputs.json', inputs)
        audit = {'schema': signals.COMPILE_SCHEMA, 'input_snapshot': self.binding(self.leaf / 'compile-inputs.json'),
                 'object': self.binding(obj), 'driver_compile_command': ['driver']}
        self.put(self.leaf / 'compile.json', audit)
        compile_record = {'schema': signals.COMPILE_SCHEMA, 'compile_audit': self.binding(self.leaf / 'compile.json'),
                          'input_snapshot': audit['input_snapshot'], 'source': self.binding(source), 'object': self.binding(obj),
                          'product_manifest': inputs['product_manifest']}
        report = {'schema': signals.OBSERVATION_SCHEMA, 'subcases': list(signals.SIGNAL_PROCESS_SUBCASES),
                  'compile': compile_record, 'oracle': {'object': self.binding(obj)}, 'links': [], 'execution': {},
                  'observations': [], 'comparison': 'exact raw status/stdout/stderr bytes; no documented source difference',
                  'process_group_isolation': True}
        for mode in ('pie', 'non-pie'):
            binary = self.put(self.leaf / ('dynamic-' + mode), b'executable')
            link = self.link(mode, obj, binary)
            report['links'].append(link)
            self.put(self.leaf / ('dynamic-' + mode + '.link.json'), link)
        for scenario in signals.SIGNAL_PROCESS_SUBCASES:
            self.raw('oracle-' + scenario)
        for mode in MODES:
            for scenario in signals.SIGNAL_PROCESS_SUBCASES:
                candidate = self.raw(mode + '-' + scenario)
                report['observations'].append({'mode': mode, 'subcase': scenario,
                    'reference': {stream: self.binding(self.leaf / f'oracle-{scenario}.{stream}') for stream in candidate},
                    'candidate': {stream: self.binding(path) for stream, path in candidate.items()}})
        self.put(self.leaf / 'signal-process-observations.json', report)

    def stress_fixture(self):
        original = self.copy_source('tests/fixtures/pthread_stress_test.c')
        preparer = self.copy_source('compat/x86_64/owned_pthread_stress_source.py')
        io = self.copy_source('compat/x86_64/owned_io_cancellation_probe.c')
        prepared, replacements = profile.prepare(original.read_bytes(), 'native-v1')
        prepared_path = self.put(self.leaf / 'pthread_stress_test.c', prepared)
        source_map = {'schema': 'crabc.x86_64-pthread-stress-source/v1', 'profile': 'native-v1',
                      'original': self.binding(original), 'prepared': self.binding(prepared_path),
                      'preparer': self.binding(preparer), 'replacements': replacements}
        self.put(self.leaf / 'source-map.json', source_map)
        obj = self.put(self.leaf / 'workload.o', b'stress-object')
        required_inputs = [original, preparer, io, prepared_path, self.leaf / 'source-map.json',
                           self.product / 'share/crabc/manifest.json']
        inputs = {self.recorded(path): self.identity(path) for path in required_inputs}
        compilation = {'inputs': inputs, 'source_map': source_map, 'object_sha256': self.binding(obj)['sha256']}
        self.put(self.leaf / 'compile.json', compilation)
        self.put(self.leaf / 'consumed.json', {**inputs, self.recorded(obj): self.identity(obj),
                 self.recorded(self.leaf / 'compile.json'): self.identity(self.leaf / 'compile.json')})
        report = {'schema': 'crabc.x86_64-owned-pthread-stress/v2', 'campaign_complete': False,
                  'source_profile': 'native-v1', 'source_map': source_map,
                  'source_map_receipt_sha256': self.binding(self.leaf / 'source-map.json')['sha256'],
                  'prepared_source_sha256': self.binding(prepared_path)['sha256'], 'source_sha256': self.binding(original)['sha256'],
                  'workload_object_sha256': self.binding(obj)['sha256'], 'compile_receipt_sha256': self.binding(self.leaf / 'compile.json')['sha256'],
                  'consumed_receipt_sha256': self.binding(self.leaf / 'consumed.json')['sha256'], 'oracle_link_command': ['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', '-pthread', self.recorded(obj), '-o', self.recorded(self.leaf / 'oracle')],
                  'passed': True, 'passed_scope': 'remaining-native-pthread-stress-workload', 'remaining_stress_workload_passed': True,
                  'native_aggregate_complete': False, 'replacement_io_cancellation_required': ['READ_FILE', 'ASYNC_LOOP'],
                  'replacement_io_cancellation_source': {'path': 'compat/x86_64/owned_io_cancellation_probe.c', 'sha256': self.binding(io)['sha256']},
                  'replacement_io_cancellation_receipt': None,
                  'replacement_io_cancellation_binding': 'composite owner must bind the same-product I/O-cancellation family receipt',
                  'cell_roster': ['oracle', *MODES], 'observation_count': 50, 'iterations': [], 'links': [],
                  'timeout_seconds': 10.0, 'raw_artifacts': {}}
        for mode in ('pie', 'non-pie'):
            binary = self.put(self.leaf / ('dynamic-' + mode), b'executable')
            report['links'].append(self.link(mode, obj, binary))
        for iteration in range(1, 11):
            record = {'iteration': iteration, 'observations': {}, 'comparisons': {}}
            for cell in ['oracle', *MODES]:
                prefix = self.leaf / f'iteration-{iteration:03d}-{cell}'
                body = b'pthread stress ok\n'
                command = ['chroot', self.recorded(self.leaf / 'execution-root')]
                command += ['/oracle'] if cell == 'oracle' else (['/lib/ld-crabc-x86_64.so.1'] if cell.endswith('-direct') else []) + ['/dynamic-' + cell.rsplit('-', 1)[0]]
                self.put(Path(str(prefix) + '.status.json'), {'command': command, 'cwd': self.mount, 'timeout_seconds': 10.0,
                         'pid': iteration, 'process_group': iteration, 'status': 0, 'returncode': 0})
                self.put(Path(str(prefix) + '.stdout'), body)
                self.put(Path(str(prefix) + '.stderr'), b'')
                record['observations'][cell] = {'status': 0, 'stdout': {'hex': body.hex(), 'byte_length': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
                    'stderr': {'hex': '', 'byte_length': 0, 'sha256': hashlib.sha256(b'').hexdigest()}}
                record['comparisons'][cell] = dict(passed=True, equal=True, oracle_clean=True, candidate_clean=True)
                for suffix in ('.status.json', '.stdout', '.stderr'):
                    path = Path(str(prefix) + suffix)
                    report['raw_artifacts'][self.recorded(path)] = self.identity(path)
            report['iterations'].append(record)
        self.put(self.leaf / 'pthread-stress.json', report)

    def mutate_json(self, name, mutation):
        path = self.leaf / name
        value = json.loads(path.read_text())
        mutation(value)
        self.put(path, value)

    def test_differential_reconstructs_cross_mount_without_rewriting_receipts(self):
        self.differential_fixture()
        before = (self.leaf / 'summary.json').read_bytes()
        result = self.collect('differential')
        self.assertEqual(len(result['observations']), 20)
        self.assertEqual(result['product']['path'], '.work/product')
        self.assertEqual((self.leaf / 'summary.json').read_bytes(), before)

    def test_differential_missing_extra_and_matched_nonzero_are_rejected(self):
        self.differential_fixture()
        (self.leaf / 'executions/foundational-musl.stderr').unlink()
        with self.assertRaises(native.NativeObservationError): self.collect('differential')
        self.put(self.leaf / 'executions/foundational-musl.stderr', b'')
        self.put(self.leaf / 'executions/foundational-static.status', b'0\n')
        with self.assertRaises(native.NativeObservationError): self.collect('differential')
        (self.leaf / 'executions/foundational-static.status').unlink()
        for path in (self.leaf / 'executions').glob('*.status'): path.write_bytes(b'1\n')
        with self.assertRaises(native.NativeObservationError): self.collect('differential')

    def test_differential_scalar_and_stream_tampering_are_rejected(self):
        self.differential_fixture()
        self.mutate_json('summary.json', lambda value: value.update(static_replayed=0))
        with self.assertRaises(native.NativeObservationError): self.collect('differential')
        self.mutate_json('summary.json', lambda value: value.update(static_replayed=False))
        (self.leaf / 'executions/foundational-dynamic-pie-direct.stdout').write_bytes(b'changed\n')
        with self.assertRaises(native.NativeObservationError): self.collect('differential')

    def test_differential_oracle_must_consume_the_same_canonical_object(self):
        self.differential_fixture()
        self.mutate_json('links/foundational-musl.json', lambda value: value['canonical_object'].update(sha256='0' * 64))
        self.mutate_json('summary.json', lambda value: value['links']['links/foundational-musl.json'].update(
            sha256=self.binding(self.leaf / 'links/foundational-musl.json')['sha256']))
        with self.assertRaises(native.NativeObservationError): self.collect('differential')

    def test_stress_rejects_consistently_changed_aggregate_timeout(self):
        self.stress_fixture()
        report_path = self.leaf / 'pthread-stress.json'
        report = json.loads(report_path.read_text())
        report['timeout_seconds'] = 20.0
        for path in self.leaf.glob('iteration-*.status.json'):
            value = json.loads(path.read_text())
            value['timeout_seconds'] = 20.0
            self.put(path, value)
            report['raw_artifacts'][self.recorded(path)] = self.identity(path)
        self.put(report_path, report)
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')

    def test_stress_oracle_command_must_name_the_canonical_object(self):
        self.stress_fixture()
        self.mutate_json('pthread-stress.json', lambda value: value['oracle_link_command'].__setitem__(5, '/workspace/other.o'))
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')

    def test_duplicate_json_fields_are_rejected(self):
        self.differential_fixture()
        path = self.leaf / 'summary.json'
        path.write_bytes(path.read_bytes().replace(b'{', b'{"static_replayed": false,', 1))
        with self.assertRaises(native.NativeObservationError): self.collect('differential')

    def test_signal_extra_mode_and_stress_extra_iteration_are_rejected(self):
        self.signal_fixture()
        self.raw('static-siginfo')
        with self.assertRaises(native.NativeObservationError): self.collect('signal-process')
        shutil.rmtree(self.leaf)
        self.leaf.mkdir()
        self.stress_fixture()
        self.mutate_json('pthread-stress.json', lambda value: value['iterations'].append(value['iterations'][-1]))
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')

    def test_signal_has_exact_48_comparisons(self):
        self.signal_fixture()
        self.assertEqual(len(self.collect('signal-process')['observations']), 48)
        self.mutate_json('signal-process-observations.json', lambda value: value['observations'].pop())
        with self.assertRaises(native.NativeObservationError): self.collect('signal-process')

    def test_signal_boolean_and_wrong_product_are_rejected(self):
        self.signal_fixture()
        self.mutate_json('signal-process-observations.json', lambda value: value.update(process_group_isolation=1))
        with self.assertRaises(native.NativeObservationError): self.collect('signal-process')
        self.mutate_json('signal-process-observations.json', lambda value: value.update(process_group_isolation=True))
        manifest = json.loads((self.product / 'share/crabc/manifest.json').read_text())
        self.put(self.product / 'share/crabc/manifest.json', {**manifest, 'changed': True})
        with self.assertRaises(native.NativeObservationError): self.collect('signal-process')

    def test_stress_reconstructs_native_source_profile_and_requires_replacement(self):
        self.stress_fixture()
        result = self.collect('pthread-stress')
        self.assertEqual(len(result['observations']), 50)
        self.assertEqual(result['limits'], {'iterations': 10, 'case_timeout_seconds': 10.0})
        self.assertEqual(result['replacement_io_cancellation_required'], ['READ_FILE', 'ASYNC_LOOP'])
        self.mutate_json('pthread-stress.json', lambda value: value.update(replacement_io_cancellation_receipt={}))
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')

    def test_stress_rejects_frozen_profile_prepared_source_tamper_and_bool_status(self):
        self.stress_fixture()
        self.mutate_json('pthread-stress.json', lambda value: value.update(source_profile='frozen'))
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')
        self.mutate_json('pthread-stress.json', lambda value: value.update(source_profile='native-v1'))
        self.mutate_json('iteration-001-oracle.status.json', lambda value: value.update(status=False))
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')
        self.mutate_json('iteration-001-oracle.status.json', lambda value: value.update(status=0))
        path = self.leaf / 'pthread_stress_test.c'
        path.write_bytes(path.read_bytes() + b'/* unauthorized change */\n')
        with self.assertRaises(native.NativeObservationError): self.collect('pthread-stress')

    def test_physical_containment_rejects_symlink_and_recorded_traversal(self):
        self.signal_fixture()
        path = self.leaf / 'oracle-siginfo.stdout'
        path.unlink()
        path.symlink_to(self.leaf / 'oracle-nodefer.stdout')
        with self.assertRaises(native.NativeObservationError): self.collect('signal-process')
        with self.assertRaises(native.NativeObservationError):
            native.collect('signal-process', self.leaf, source_mount='/workspace/../workspace', dynamic_product=self.product, root=self.root)

    def os_test_fixture(self, *, profile=False, aio_cancel_oracle_failure=False):
        import owned_os_test as contract
        stage = self.leaf / 'source-stage'
        for suite in native.OS_TEST_SUITES:
            self.put(stage / suite / 'case.c', ('/* ' + suite + ' */\n').encode())
        for name in ('dlopen', 'dlclose', 'dlsym'):
            self.put(stage / 'basic/dlfcn' / (name + '.c'), ('/* ' + name + ' */\n').encode())
        self.put(stage / aio_suspend_source.SOURCE_PATH, aio_suspend_source.FROZEN_SOURCE)
        if aio_cancel_oracle_failure:
            self.put(stage / 'basic/aio/aio_cancel.c',
                     (HERE / 'tests/fixtures/os-test-aio-cancel.c').read_bytes())
        if profile:
            import owned_posix_native_dispositions as dispositions
            for symbol, content in dispositions.OS_ATOMIC_SOURCES.items():
                self.put(stage / 'include/stdatomic' / (symbol + '.c'), content.encode())
        self.put(stage / 'GNUmakefile', b'pinned Make graph fixture\n')
        self.put(stage / 'misc/suites.list', ('\n'.join(native.OS_TEST_SUITES) + '\n').encode())
        (stage / 'Makefile').symlink_to('GNUmakefile')
        tree, source_files = native.source_tree(stage, allow_symlinks=True)
        tree_patch = patch.object(native, 'OS_TEST_TREE', tree)
        tree_patch.start()
        self.addCleanup(tree_patch.stop)
        self.addCleanup(lambda: contract.thaw_tree(self.leaf))
        def artifact(path, value):
            self.put(path, value)
            return {'path': path.relative_to(self.leaf).as_posix(), 'sha256': self.binding(path)['sha256'], 'byte_length': path.stat().st_size}
        source_roster = artifact(self.leaf / 'records/source-roster.json', {
            'schema': 'crabc.x86_64-owned-os-test-source-roster/v1', 'revision': native.OS_TEST_REVISION, 'tree': tree,
            'entries': [contract.roster_entry(stage, Path(name)) for name in sorted(source_files)]})
        for name in ('crti.o', 'libc.so', 'crtn.o', 'Scrt1.o', 'crabc-dynamic-attach.o', 'libcrabc-builtins.a'):
            self.put(self.product / 'usr/lib' / name, name.encode())
        self.put(self.product / 'usr/include/stdio.h', b'installed header\n')
        self.put(self.product / 'lib/ld-crabc-x86_64.so.1', b'owned loader\n')
        (self.product / 'lib/ld-musl-x86_64.so.1').symlink_to('ld-crabc-x86_64.so.1')
        manifest = self.product / 'share/crabc/manifest.json'
        manifest_value = json.loads(manifest.read_text())
        manifest_value['files'] = {path.relative_to(self.product).as_posix(): self.binding(path)['sha256']
                                  for path in self.product.rglob('*') if path.is_file() and not path.is_symlink() and path != manifest}
        self.put(manifest, manifest_value)
        baseline = contract.tree_roster(self.product)
        def product_identity(root):
            return {'root': self.recorded(root), 'manifest': self.recorded(root / 'share/crabc/manifest.json'),
                    'manifest_sha256': self.binding(manifest)['sha256'], 'driver': self.recorded(root / 'bin/crabc-cc-dynamic'),
                    'driver_sha256': self.binding(self.product / 'bin/crabc-cc-dynamic')['sha256']}
        product_roster = artifact(self.leaf / 'records/supplied-product-roster.json',
                                 {'schema': 'crabc.x86_64-owned-os-test-product-roster/v1', 'entries': baseline})
        preparer = self.put(self.root / 'compat/x86_64/owned_os_test_aio_suspend_source.py',
                            (HERE / 'owned_os_test_aio_suspend_source.py').read_bytes())
        prepared_aio_suspend, aio_suspend_replacements = aio_suspend_source.prepare(
            (stage / aio_suspend_source.SOURCE_PATH).read_bytes()
        )
        aio_suspend_preparation = {
            'schema': aio_suspend_source.SCHEMA,
            'fixture': aio_suspend_source.SOURCE_PATH,
            'source_sha256': aio_suspend_source.ORIGINAL_SHA256,
            'prepared_sha256': aio_suspend_source.PREPARED_SHA256,
            'preparer': {'path': preparer.relative_to(self.root).as_posix(), 'sha256': self.binding(preparer)['sha256']},
            'replacements': aio_suspend_replacements,
            'sides': {},
        }
        report = {'schema': 'crabc.x86_64-owned-os-test/v1', 'passed': True, 'profile': list(native.OS_TEST_SUITES),
                  'timeout_seconds': contract.SUITE_TIMEOUT_SECONDS, 'work': self.recorded(self.leaf),
                  'product': {**product_identity(self.product), 'payload_roster': product_roster},
                  'source': {'revision': native.OS_TEST_REVISION, 'tree': tree,
                             'gnu_makefile_sha256': self.binding(stage / 'GNUmakefile')['sha256'],
                             'suite_list_sha256': self.binding(stage / 'misc/suites.list')['sha256'],
                             'stage': {'stage': 'source-stage', 'revision': native.OS_TEST_REVISION, 'tree': tree,
                                       'tracked_path_count': len(source_files), 'roster': source_roster}},
                  'source_preparation': {'aio_suspend_lifetime': aio_suspend_preparation}, 'suites': []}
        def copied(root):
            shutil.copytree(stage, root, symlinks=True)
        counter = 0
        compiler = {'path': '/usr/bin/gcc', 'sha256': 'b' * 64}
        def event_base(suite, command):
            nonlocal counter
            counter += 1
            identity = f'{counter:032x}'
            product = self.leaf / 'products' / suite
            return identity, {'schema': 'crabc.x86_64-owned-os-test-adapter/v1', 'raw_command': command,
                              'cwd': self.recorded(self.leaf / 'suites' / suite / suite), 'compiler': compiler,
                              'plan': contract.json_safe(contract.target_plan(command, Path(self.recorded(product))))}
        def streams(suite, identity, suffix=''):
            for stream in ('stdout', 'stderr'):
                self.put(self.leaf / 'evidence' / suite / 'events' / (identity + suffix + '.' + stream), b'')
            return {'stdout': contract.stream_snapshot(b''), 'stderr': contract.stream_snapshot(b'')}
        def dependencies(suite, identity, source, plan):
            product = self.leaf / 'products' / suite
            cwd = self.leaf / 'suites' / suite / suite
            raw = ('target.o: ' + source + ' ' + self.recorded(product / 'usr/include/stdio.h') + '\n').encode()
            if plan['kind'] == 'preprocess':
                for stream, data in (('stdout', raw), ('stderr', b'')):
                    self.put(self.leaf / 'evidence' / suite / 'events' / (identity + '.dependencies.' + stream), data)
            return {'command': contract.dependency_command(compiler['path'], Path(self.recorded(product)), Path(source), plan['flags'],
                                                           'pie' if plan['kind'] == 'preprocess' else plan['mode'],
                                                           ('-fstack-protector-strong',)),
                    'status': 0, 'stdout': contract.stream_snapshot(raw), 'stderr': contract.stream_snapshot(b''),
                    'headers': {self.recorded(path): self.binding(path)['sha256'] for path in (cwd / source, product / 'usr/include/stdio.h')}}
        def link(suite, source, object_path, retained, shared, compile_event=None):
            product = self.leaf / 'products' / suite
            cwd = self.leaf / 'suites' / suite / suite
            target = str(Path(source).with_suffix('.so' if shared else ''))
            if shared:
                identity, base = compile_event
            else:
                flags = ['-Wall', '-Wextra'] + (['-Werror', '-Wno-error=deprecated', '-Wno-error=deprecated-declarations']
                                              if suite == 'include' else ['-Werror=implicit-function-declaration'])
                identity, base = event_base(suite, ['-pthread', *flags, '../out/linux/' + suite + '/' + str(Path(source).with_suffix('.o')),
                                                   '-o', target, '-lm', '-lpthread', '-lrt'])
                self.put(self.leaf / 'evidence' / suite / 'events' / (identity + '.json'), {**base, 'state': 'started'})
            output = cwd / target
            binary = self.put(self.leaf / 'evidence' / suite / 'links' / (identity + '.' + output.name), (suite + '/' + target).encode())
            receipt_path = Path(str(binary) + '.crabc-link.json')
            runtime = [product / 'usr/lib' / name for name in ('crti.o', 'libc.so', 'crtn.o')]
            if not shared: runtime += [product / 'usr/lib/Scrt1.o', product / 'usr/lib/crabc-dynamic-attach.o']
            builtins = product / 'usr/lib/libcrabc-builtins.a'
            linker = {'path': '/pinned/ld.lld', 'sha256': 'c' * 64}
            sealed = [linker['path'], '-shared' if shared else '-pie', '--hash-style=sysv', '--eh-frame-hdr', '-z', 'relro', '-z', 'now',
                      '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags', '-rpath', '/usr/lib']
            if shared: sealed += ['-soname', output.name]
            else: sealed += ['--dynamic-linker', '/lib/ld-crabc-x86_64.so.1', self.recorded(product / 'usr/lib/Scrt1.o'), self.recorded(product / 'usr/lib/crabc-dynamic-attach.o')]
            sealed += [self.recorded(product / 'usr/lib/crti.o'), self.recorded(object_path), self.recorded(product / 'usr/lib/libc.so'),
                       self.recorded(builtins), self.recorded(product / 'usr/lib/crtn.o'), '-o', self.recorded(output)]
            self.put(receipt_path, {'schema': 1, 'format': native.PRODUCT_FORMAT, 'mode': 'shared' if shared else 'pie', 'binding': 'now',
                'runtime_imports': [], 'application_runpath': '/usr/lib', 'application_dsos': {}, 'campaign_complete': False,
                'manifest_sha256': self.binding(manifest)['sha256'], 'output_path': self.recorded(output), 'output_sha256': self.binding(binary)['sha256'],
                'resolved_linker': linker, 'link_command': sealed, 'link_trace': [*map(self.recorded, runtime), self.recorded(object_path)],
                'input_receipts': [*(self.binding(path) for path in runtime), {'path': self.recorded(object_path), 'sha256': self.binding(retained)['sha256']}, self.binding(builtins)],
                'owned_runtime_inputs': sorted(path.relative_to(product).as_posix() for path in [*runtime, builtins])})
            linked = {'linkage': 'shared' if shared else 'pie', 'product_manifest_sha256': self.binding(manifest)['sha256'],
                      'workload_sha256': self.binding(retained)['sha256'], 'receipt_sha256': self.binding(receipt_path)['sha256']}
            if shared: linked['output_sha256'] = self.binding(binary)['sha256']
            else: linked.update(product=self.recorded(product), product_format=native.PRODUCT_FORMAT, executable_sha256=self.binding(binary)['sha256'])
            event = {**base, 'event_id': identity, 'state': 'link-finished', 'status': 0, **streams(suite, identity, '.link'),
                     'command': [self.recorded(product / 'bin/crabc-cc-dynamic'), '--dynamic-shared-object' if shared else '--dynamic-pie',
                                 self.recorded(object_path), '-o', target], 'output': self.recorded(output), 'workload': self.recorded(object_path),
                     'retained_output': self.recorded(binary), 'retained_receipt': self.recorded(receipt_path), 'link_identity': linked}
            executed = self.put(self.leaf / 'runtime' / suite / 'work' / suite / target, binary.read_bytes())
            if shared: event['runtime_dso'] = self.recorded(executed)
            else: event['execution_wrapper'] = {'runtime_path': self.recorded(executed), 'runtime_sha256': self.binding(binary)['sha256'],
                                              'host_wrapper': self.recorded(output), 'runtime_cwd': '/work/' + suite}
            self.put(self.leaf / 'evidence' / suite / 'events' / (identity + '.link.json'), event)
        for suite in native.OS_TEST_SUITES:
            product, runtime = self.leaf / 'products' / suite, self.leaf / 'runtime' / suite
            shutil.copytree(self.product, product, symlinks=True)
            shutil.copytree(self.product, runtime, symlinks=True)
            private_proc = None
            if suite == 'basic':
                proc = runtime / 'proc'
                proc.mkdir(mode=0o755)
                proc.chmod(0o755)
                outside = 'pid:[4026533183]'
                private_proc = {
                    'schema': contract.PRIVATE_PROC_SCHEMA,
                    'mountpoint': self.recorded(proc),
                    'reservation': {'empty': True, 'mode': 0o755},
                    'mount': {'command': [contract.PRIVATE_PROC_MOUNT, '-t', 'proc', '-o',
                                          contract.PRIVATE_PROC_MOUNT_OPTIONS, 'proc', self.recorded(proc)],
                              'status': 0, 'stdout': contract.stream_snapshot(b''),
                              'stderr': contract.stream_snapshot(b''), 'target': self.recorded(proc)},
                    'namespace': {'outside': outside,
                                  'inside': {'command': [contract.PRIVATE_PROC_WITNESS_CHROOT, self.recorded(runtime),
                                                         '/control/ld-musl-x86_64.so.1', '/control/busybox',
                                                         'readlink', '/proc/self/ns/pid'], 'status': 0,
                                             'stdout': contract.stream_snapshot((outside + '\n').encode()),
                                             'stderr': contract.stream_snapshot(b'')},
                                  'matched': True},
                    'unmount': {'command': [contract.PRIVATE_PROC_UNMOUNT, self.recorded(proc)], 'status': 0,
                                'stdout': contract.stream_snapshot(b''), 'stderr': contract.stream_snapshot(b'')},
                }
            musl, dynamic = self.leaf / 'musl' / suite, self.leaf / 'suites' / suite
            copied(musl)
            copied(dynamic)
            if suite == 'basic':
                for side, root in (('musl', musl), ('dynamic', dynamic)):
                    self.put(root / aio_suspend_source.SOURCE_PATH, prepared_aio_suspend)
                    aio_suspend_preparation['sides'][side] = artifact(
                        self.leaf / 'records' / f'basic.{side}.aio-suspend-preparation.json',
                        {**{key: value for key, value in aio_suspend_preparation.items() if key != 'sides'}, 'side': side},
                    )
            sources = sorted(path.relative_to(stage / suite).as_posix() for path in (stage / suite).rglob('*.c'))
            expected = [str(Path(name).with_suffix('.out')) for name in sources]
            row = {'suite': suite, 'passed': True, 'differences': [], 'difference_count': 0,
                   'expected_outcomes': artifact(self.leaf / 'records' / (suite + '.expected-outcomes.json'),
                       {'schema': 'crabc.x86_64-owned-os-test-expected-outcomes/v1', 'suite': suite, 'outcomes': expected})}
            for source in sources:
                if suite == 'namespace':
                    for macro in (False, True):
                        target = str(Path(source).with_suffix('.dM' if macro else '.i'))
                        identity, base = event_base(suite, ['-pthread', '-D_POSIX_C_SOURCE=202405L', '-std=c17', '-E', *(['-dM'] if macro else []), source, '-o', target])
                        plan = base['plan']
                        retained = self.put(self.leaf / 'evidence' / suite / 'preprocessed' / (identity + Path(target).suffix), b'preprocessed\n')
                        event = {**base, 'event_id': identity, 'state': 'finished', 'status': 0, **streams(suite, identity),
                                 'command': [*contract.compiler_command(compiler['path'], Path(self.recorded(product)), Path(source), Path('/dev/null'), plan['flags'], 'pie', ('-fstack-protector-strong',))[:-4],
                                             '-E', *(['-dM'] if macro else []), source, '-o', target],
                                 'output': {'source_path': self.recorded(dynamic / suite / target), 'retained': self.recorded(retained), 'sha256': self.binding(retained)['sha256']},
                                 'dependencies': dependencies(suite, identity, source, plan)}
                        self.put(self.leaf / 'evidence' / suite / 'events' / (identity + '.json'), event)
                    continue
                for shared in ([False, True] if suite == 'basic' and source.startswith('dlfcn/') else [False]):
                    if shared:
                        raw = ['-shared', '-fPIC', '-pthread', '-DSHARED', source, '-o', str(Path(source).with_suffix('.so')), '-lm', '-lpthread', '-lrt']
                    else:
                        flags = ['-Wall', '-Wextra'] + (['-Werror', '-Wno-error=deprecated', '-Wno-error=deprecated-declarations'] if suite == 'include' else ['-Werror=implicit-function-declaration'])
                        profiles = ['-D_POSIX_C_SOURCE=202405L'] if suite == 'include' else ['-D_GNU_SOURCE', '-D_BSD_SOURCE', '-D_ALL_SOURCE', '-D_DEFAULT_SOURCE']
                        raw = ['-pthread', *flags, '-c', source, '-o', '../out/linux/' + suite + '/' + str(Path(source).with_suffix('.o')), *profiles]
                    identity, base = event_base(suite, raw)
                    plan = base['plan']
                    object_path = (self.leaf / 'evidence' / suite / 'objects' / (identity + '.o') if shared
                                   else dynamic / 'out/linux' / suite / Path(source).with_suffix('.o'))
                    retained = self.put(self.leaf / 'evidence' / suite / 'objects' / (identity + '.driver.o'), (suite + source + str(shared)).encode())
                    direct = self.put(self.leaf / 'evidence' / suite / 'objects' / (identity + '.direct.o'), retained.read_bytes())
                    event = {**base, 'event_id': identity, 'state': 'finished', 'status': 0, **streams(suite, identity),
                             'command': [self.recorded(product / 'bin/crabc-cc-dynamic'), '--dynamic-shared-object' if shared else '--dynamic-pie', '-c', source,
                                         '-o', self.recorded(object_path) if shared else plan['output'], *plan['flags']],
                             'object': {'path': self.recorded(object_path), 'retained': self.recorded(retained), 'sha256': self.binding(retained)['sha256']},
                             'replay': {'status': 0, 'byte_equal': True, 'object': self.recorded(direct), 'object_sha256': self.binding(direct)['sha256'],
                                        'command': contract.compiler_command(compiler['path'], Path(self.recorded(product)), Path(source), Path(self.recorded(direct)), plan['flags'], plan['mode'], ('-fstack-protector-strong',)),
                                        'stdout': contract.stream_snapshot(b''), 'stderr': contract.stream_snapshot(b'')},
                             'dependencies': dependencies(suite, identity, source, plan)}
                    self.put(self.leaf / 'evidence' / suite / 'events' / (identity + '.json'), event)
                    link(suite, source, object_path, retained, shared, (identity, base) if shared else None)
            for side, root in (('musl', musl), ('dynamic', dynamic)):
                outcomes = {}
                for name in expected:
                    value = b'good\n'
                    if profile and suite == 'include' and name.startswith('stdatomic/'):
                        value = b'undefined\n' if side == 'musl' else b'good\n'
                    if aio_cancel_oracle_failure and suite == 'basic' and name == 'aio/aio_cancel.out':
                        value = b'aio_error: EINPROGRESS\n' if side == 'musl' else b'exit: 0\n'
                    path = self.put(root / 'out/linux' / suite / name, value)
                    outcomes[name] = {'sha256': self.binding(path)['sha256'], 'text': value.decode()}
                command = (contract.musl_make_command(suite, Path(self.recorded(root)), 8) if side == 'musl' else
                           contract.make_command(suite, Path(self.recorded(root)), Path(self.recorded(self.root / 'compat/x86_64/owned_os_test.py')),
                           Path(self.recorded(product)), Path(self.recorded(self.leaf / 'evidence' / suite)), Path(self.recorded(runtime)), 8))
                record = contract.make_record(self.leaf, suite, side, command, contract.SUITE_TIMEOUT_SECONDS, 0, b'make output\n', b'')
                row[side] = {**(record if side == 'musl' else {'make': record}), 'outcomes': outcomes, 'outcome_count': len(expected), 'passed': True}
            integrity = {'passed': True, 'difference': {'missing': [], 'unexpected': [], 'changed': []}}
            for phase in ('before', 'after'):
                integrity[phase] = artifact(self.leaf / 'records' / (suite + '.dynamic-product-payload-' + phase + '.json'),
                    {'schema': 'crabc.x86_64-owned-os-test-product-payload/v1', 'phase': phase + '-execution', 'entries': baseline})
            compiler_payload = artifact(self.leaf / 'records' / (suite + '.compiler-product-payload.json'),
                {'schema': 'crabc.x86_64-owned-os-test-product-payload/v1', 'phase': 'compiler-and-linker', 'entries': baseline})
            control = {'root': self.recorded(runtime), 'compiler_product': {'root': self.recorded(product), 'identity': product_identity(product),
                       'copy_difference': {'missing': [], 'unexpected': [], 'changed': []}, 'payload': compiler_payload}, 'product': product_identity(runtime),
                       'product_copy_difference': {'missing': [], 'unexpected': [], 'changed': []},
                       'product_manifest_sha256': self.binding(manifest)['sha256'], 'candidate_loader_sha256': self.binding(self.product / 'lib/ld-crabc-x86_64.so.1')['sha256'],
                       'product_payload': integrity, 'control_additions': artifact(self.leaf / 'records' / (suite + '.execution-control-additions.json'),
                            {'schema': 'crabc.x86_64-owned-os-test-execution-controls/v1',
                             'entries': [contract.roster_entry(runtime, Path('proc'))] if private_proc is not None else []}),
                       'private_devpts': {'status': 0, 'unmount': {'status': 0}} if suite == 'pty' else None,
                       'private_proc': private_proc}
            control.update(basic_runtime_fixtures=None, shell_launcher=None)
            if suite == 'basic':
                control['private_devpts'] = {'status': 0, 'unmount': {'status': 0}}
                control['basic_runtime_fixtures'] = contract.install_basic_runtime_fixtures(runtime, suite)
                shell_source = self.put(runtime / 'control/candidate-shell-launcher.c', contract.control_shell_launcher_source().encode())
                shell_object = self.put(runtime / 'control/candidate-shell-launcher.o', b'canonical basic shell object')
                for field, name, data in (('busybox', 'busybox', b'controlled busybox'),
                                          ('musl_control_loader', 'ld-musl-x86_64.so.1', b'controlled musl loader')):
                    path = self.put(runtime / 'control' / name, data)
                    control[field] = {'path': '/bin/busybox' if field == 'busybox' else '/lib/ld-musl-x86_64.so.1', 'sha256': self.binding(path)['sha256']}
                events = [json.loads(path.read_bytes()) for path in (self.leaf / 'evidence/basic/events').glob('*.link.json')]
                template = next(event for event in events if event['plan']['output'] == 'case')
                binary_path = self.root / Path(template['retained_output']).relative_to('/workspace')
                binary = self.put(runtime / 'control/candidate-shell-launcher', binary_path.read_bytes())
                receipt_path = self.root / Path(template['retained_receipt']).relative_to('/workspace')
                receipt = json.loads(receipt_path.read_bytes().replace(template['workload'].encode(), self.recorded(shell_object).encode())
                                     .replace(template['output'].encode(), self.recorded(binary).encode()))
                for entry in receipt['input_receipts']:
                    if entry['path'] == self.recorded(shell_object): entry['sha256'] = self.binding(shell_object)['sha256']
                shell_receipt = self.put(Path(str(binary) + '.crabc-link.json'), receipt)
                self.put(runtime / 'bin/sh', binary.read_bytes())
                binary.chmod(0o755)
                (runtime / 'bin/sh').chmod(0o755)
                phase = lambda command: {'command': command, 'status': 0, 'stdout': contract.stream_snapshot(b''), 'stderr': contract.stream_snapshot(b'')}
                driver = self.recorded(product / 'bin/crabc-cc-dynamic')
                control['shell_launcher'] = {'kind': 'candidate-shell-launcher/v1',
                    'source': {'path': '/control/candidate-shell-launcher.c', 'sha256': self.binding(shell_source)['sha256']},
                    'object': {'path': '/control/candidate-shell-launcher.o', 'sha256': self.binding(shell_object)['sha256']},
                    'compile': phase([driver, '--dynamic-pie', '-c', self.recorded(shell_source), '-o', self.recorded(shell_object)]),
                    'link': phase([driver, '--dynamic-pie', self.recorded(shell_object), '-o', self.recorded(binary)]),
                    'link_identity': {**template['link_identity'], 'workload_sha256': self.binding(shell_object)['sha256'],
                                      'receipt_sha256': self.binding(shell_receipt)['sha256']},
                    'launcher': {'path': '/control/candidate-shell-launcher', 'sha256': self.binding(binary)['sha256'],
                        'receipt_sha256': self.binding(shell_receipt)['sha256'], 'candidate_path': '/bin/sh',
                        'candidate_sha256': self.binding(binary)['sha256'],
                        'argv': ['/control/ld-musl-x86_64.so.1', '/control/busybox', 'sh', '<original argv[1..]>']}}
            row['dynamic'].update(execution_control=control, adapter_errors=[],
                                  adapter_event_count=len(list((self.leaf / 'evidence' / suite / 'events').glob('*.json'))))
            if profile and suite == 'include':
                row.update(passed=False, difference_count=6, differences=[
                    {'case': name, 'dynamic': row['dynamic']['outcomes'][name], 'musl': row['musl']['outcomes'][name]}
                    for name in expected if name.startswith('stdatomic/')])
                report['passed'] = False
            if aio_cancel_oracle_failure and suite == 'basic':
                row.update(passed=False, difference_count=1, differences=[
                    {'case': 'aio/aio_cancel.out', 'dynamic': row['dynamic']['outcomes']['aio/aio_cancel.out'],
                     'musl': row['musl']['outcomes']['aio/aio_cancel.out']}])
                report['passed'] = False
            report['suites'].append(row)
        report['musl_oracle'] = {'unchanged': True}
        for phase in ('before', 'after'):
            identity = {'root': '/opt/musl-1.2.6', 'include': {'path': '/opt/musl-1.2.6/include', 'entry_count': 0,
                        'roster': artifact(self.leaf / 'records' / ('musl-oracle-' + phase + '-include-roster.json'),
                                          {'schema': 'crabc.x86_64-owned-os-test-musl-include-roster/v1', 'entries': []})}}
            for field, path in {'wrapper': '/usr/local/bin/crabc-x86_64-musl-gcc', 'marker': '/opt/musl-1.2.6/.crabc-oracle',
                                'specs_digest': '/opt/musl-1.2.6/.crabc-musl-gcc-specs.sha256', 'specs': '/opt/musl-1.2.6/lib/musl-gcc.specs',
                                'libc': '/opt/musl-1.2.6/lib/libc.so'}.items():
                identity[field] = {'path': path, 'sha256': 'd' * 64}
            report['musl_oracle'][phase] = identity
        contract.freeze_tree(stage)
        self.put(self.leaf / 'os-test.json', report)
        return report

    def test_os_test_qualifies_only_the_pinned_aio_cancel_oracle_race(self):
        report = self.os_test_fixture(profile=True, aio_cancel_oracle_failure=True)
        proof = self.profile_companions()
        inputs = self.profile_input_paths()
        def collect():
            with patch.object(native, '_load_profile_companions', return_value=proof):
                return native.collect('os-test', self.leaf, source_mount=self.mount,
                                      dynamic_product=self.product, root=self.root, profile_inputs=inputs)
        result = collect()
        self.assertEqual(result['qualification']['status'], 'profile-qualified')
        self.assertEqual([item['outcome'] for item in result['qualification']['dispositions']
                          if item['suite'] == 'basic'], ['aio/aio_cancel.out'])
        original = (self.leaf / 'os-test.json').read_bytes()
        for failure in (b'aio_error: EINVAL\n',
                        b'aio_error: EINPROGRESS\nexit: 0\n',
                        b'aio_error: EINPROGRESS\nexit: 1\nextra\n'):
            with self.subTest(failure=failure):
                path = self.leaf / 'musl/basic/out/linux/basic/aio/aio_cancel.out'
                self.put(path, failure)
                changed = json.loads(original)
                changed['suites'][2]['musl']['outcomes']['aio/aio_cancel.out'] = {
                    'sha256': self.binding(path)['sha256'], 'text': failure.decode()}
                changed['suites'][2]['differences'][0]['musl'] = changed['suites'][2]['musl']['outcomes']['aio/aio_cancel.out']
                self.put(self.leaf / 'os-test.json', changed)
                with self.assertRaises(native.NativeObservationError):
                    collect()
        oracle = self.leaf / 'musl/basic/out/linux/basic/aio/aio_cancel.out'
        self.put(oracle, b'aio_error: EINPROGRESS\n')
        candidate = self.leaf / 'suites/basic/out/linux/basic/aio/aio_cancel.out'
        self.put(candidate, b'aio_error: EINPROGRESS\n')
        changed = json.loads(original)
        changed['suites'][2]['dynamic']['outcomes']['aio/aio_cancel.out'] = {
            'sha256': self.binding(candidate)['sha256'], 'text': candidate.read_text()}
        changed['suites'][2].update(passed=True, differences=[], difference_count=0)
        self.put(self.leaf / 'os-test.json', changed)
        with self.assertRaises(native.NativeObservationError):
            collect()
        self.put(candidate, b'exit: 0\n')
        self.put(oracle, b'exit: 0\n')
        changed = json.loads(original)
        changed['suites'][2]['musl']['outcomes']['aio/aio_cancel.out'] = {
            'sha256': self.binding(oracle)['sha256'], 'text': oracle.read_text()}
        changed['suites'][2].update(passed=True, differences=[], difference_count=0)
        self.put(self.leaf / 'os-test.json', changed)
        normal = collect()
        self.assertEqual(len(normal['qualification']['dispositions']), 6)
        self.put(self.leaf / 'os-test.json', original)

    def test_os_test_requires_full_attempted_graph_and_sealed_raw_results(self):
        report = self.os_test_fixture()
        with patch('subprocess.run', side_effect=AssertionError('collector executed a tool')), \
             patch('subprocess.Popen', side_effect=AssertionError('collector launched a process')):
            result = self.collect('os-test')
        self.assertEqual(len(result['observations']), 14)
        self.assertEqual(len(result['objects']), 16)
        original = (self.leaf / 'os-test.json').read_bytes()
        for description, mutate in {
            'one omitted suite': lambda r: r['suites'].pop(),
            'different installed product': lambda r: r['product'].update(root='/workspace/.work/other'),
            'missing outcome graph': lambda r: r['suites'][0]['dynamic']['outcomes'].clear(),
            'failed command disguised by summary': lambda r: r['suites'][0]['musl'].update(make_status=1),
            'changed timeout': lambda r: r.update(timeout_seconds=1200.0),
            'failed oracle stability': lambda r: r['musl_oracle'].update(unchanged=False),
            'unbound oracle compiler identity': lambda r: r['musl_oracle']['before']['wrapper'].update(path='/foreign/cc'),
            'missing basic private devpts': lambda r: r['suites'][2]['dynamic']['execution_control'].update(private_devpts=None),
            'missing basic private procfs': lambda r: r['suites'][2]['dynamic']['execution_control'].update(private_proc=None),
            'foreign private procfs mount command': lambda r: r['suites'][2]['dynamic']['execution_control']['private_proc']['mount']['command'].__setitem__(0, '/usr/bin/mount'),
            'different private procfs namespace': lambda r: r['suites'][2]['dynamic']['execution_control']['private_proc']['namespace'].update(outside='pid:[4026533184]'),
            'failed private procfs teardown': lambda r: r['suites'][2]['dynamic']['execution_control']['private_proc']['unmount'].update(status=1),
            'private procfs in a nonbasic suite': lambda r: r['suites'][0]['dynamic']['execution_control'].update(private_proc={'unexpected': True}),
            'foreign basic shell compiler': lambda r: r['suites'][2]['dynamic']['execution_control']['shell_launcher']['compile']['command'].__setitem__(0, '/foreign/compiler'),
            'foreign basic shell source': lambda r: r['suites'][2]['dynamic']['execution_control']['shell_launcher']['source'].update(sha256='0' * 64),
            'replaced basic shell installation': lambda r: r['suites'][2]['dynamic']['execution_control']['shell_launcher']['launcher'].update(candidate_path='/bin/other'),
            'changed aio suspend source attribution': lambda r: r['source_preparation']['aio_suspend_lifetime'].update(prepared_sha256='0' * 64),
            'missing aio suspend candidate preparation receipt': lambda r: r['source_preparation']['aio_suspend_lifetime']['sides'].pop('dynamic'),
        }.items():
            with self.subTest(description=description):
                changed = json.loads(original)
                mutate(changed)
                self.put(self.leaf / 'os-test.json', changed)
                with self.assertRaises(native.NativeObservationError): self.collect('os-test')
        self.put(self.leaf / 'os-test.json', original)
        object_relative = next((self.leaf / 'evidence/include/objects').glob('*.driver.o')).relative_to(self.leaf).as_posix()
        for relative in ('records/malloc.musl.stdout', 'records/malloc.dynamic.status.json', 'products/malloc/usr/lib/libc.so',
                         'runtime/malloc/usr/lib/libc.so', 'suites/malloc/out/linux/malloc/case.out', 'source-stage/GNUmakefile', object_relative,
                         'runtime/basic/bin/sh', 'runtime/basic/control/candidate-shell-launcher.c',
                         'runtime/basic/control/candidate-shell-launcher.o', 'runtime/basic/etc/passwd', 'runtime/basic/control/busybox',
                         'source-stage/basic/aio/aio_suspend.c', 'musl/basic/basic/aio/aio_suspend.c',
                         'suites/basic/basic/aio/aio_suspend.c', 'records/basic.dynamic.aio-suspend-preparation.json'):
            with self.subTest(artifact=relative):
                path = self.leaf / relative
                before, mode = path.read_bytes(), path.stat().st_mode & 0o7777
                path.chmod(mode | 0o200)
                path.write_bytes(before + b'changed')
                path.chmod(mode)
                with self.assertRaises(native.NativeObservationError): self.collect('os-test')
                path.chmod(mode | 0o200)
                path.write_bytes(before)
                path.chmod(mode)
        event = next(path for path in (self.leaf / 'evidence/namespace/events').glob('*.json'))
        before = event.read_bytes()
        event.unlink()
        changed = json.loads(original)
        changed['suites'][1]['dynamic']['adapter_event_count'] -= 1
        self.put(self.leaf / 'os-test.json', changed)
        with self.assertRaises(native.NativeObservationError, msg='complete outcomes cannot hide an omitted preprocessing edge'):
            self.collect('os-test')
        self.put(event, before)
        self.put(self.leaf / 'os-test.json', original)
        extra = self.put(self.leaf / 'runtime/basic/bin/undeclared-tool', b'not a declared basic fixture')
        with self.assertRaises(native.NativeObservationError, msg='the shell exception cannot admit other product-directory additions'):
            self.collect('os-test')
        extra.unlink()
        proc_extra = self.put(self.leaf / 'runtime/basic/proc/undeclared-node', b'not an unmounted empty procfs root')
        with self.assertRaises(native.NativeObservationError, msg='the procfs mountpoint must be empty after teardown'):
            self.collect('os-test')
        proc_extra.unlink()
        launcher = self.leaf / 'runtime/basic/bin/sh'
        launcher.chmod(0o644)
        with self.assertRaises(native.NativeObservationError, msg='the installed shell must retain its executable mode'):
            self.collect('os-test')
        launcher.chmod(0o755)
        compiler_crt = self.leaf / 'products/malloc/usr/lib/Scrt1.o'
        compiler_mode = compiler_crt.stat().st_mode & 0o7777
        compiler_crt.chmod(0o444)
        with self.assertRaises(native.NativeObservationError, msg='the collector must retain source-bound compiler input modes'):
            self.collect('os-test')
        compiler_crt.chmod(compiler_mode)

    def test_os_test_retains_matching_failed_feature_probes_without_inventing_objects(self):
        import owned_os_test as contract
        report = self.os_test_fixture()
        events = self.leaf / 'evidence/include/events'
        original = next(json.loads(path.read_text()) for path in events.glob('*.json')
                        if json.loads(path.read_text()).get('plan', {}).get('kind') == 'compile')
        for path in events.iterdir(): path.unlink()
        shutil.rmtree(self.leaf / 'evidence/include/objects')
        shutil.rmtree(self.leaf / 'evidence/include/links')
        (self.leaf / 'runtime/include/work/include/case').unlink()
        flags = ['-Wall', '-Wextra', '-Werror', '-Wno-error=deprecated', '-Wno-error=deprecated-declarations']
        profiles = [['-D_POSIX_C_SOURCE=202405L'], ['-D_POSIX_C_SOURCE=200809L'],
                    ['-D_GNU_SOURCE', '-D_BSD_SOURCE', '-D_ALL_SOURCE', '-D_DEFAULT_SOURCE']]
        for number, profile in enumerate(profiles, 1):
            identity = f'{1000 + number:032x}'
            raw = ['-pthread', *flags, '-c', 'case.c', '-o', '../out/linux/include/case.o', *profile]
            plan = contract.json_safe(contract.target_plan(raw, Path(self.recorded(self.leaf / 'products/include'))))
            event = {key: original[key] for key in ('schema', 'cwd', 'compiler')}
            event.update(event_id=identity, state='finished', status=1, plan=plan, raw_command=raw,
                         command=[self.recorded(self.leaf / 'products/include/bin/crabc-cc-dynamic'), '--dynamic-pie',
                                  '-c', 'case.c', '-o', '../out/linux/include/case.o', *flags, *profile])
            for stream, data in (('stdout', b''), ('stderr', b'fatal error: missing header\n')):
                self.put(events / (identity + '.' + stream), data)
                event[stream] = contract.stream_snapshot(data)
            self.put(events / (identity + '.json'), event)
        suite = report['suites'][0]
        suite['dynamic']['adapter_event_count'] = 3
        for side, directory in (('musl', 'musl'), ('dynamic', 'suites')):
            path = self.put(self.leaf / directory / 'include/out/linux/include/case.out', b'missing_header\n')
            suite[side]['outcomes']['case.out'] = {'sha256': self.binding(path)['sha256'], 'text': 'missing_header\n'}
        self.put(self.leaf / 'os-test.json', report)
        result = self.collect('os-test')
        self.assertEqual(len(result['observations']), 14)
        self.assertEqual(len(result['objects']), 15)
        self.assertFalse(any(name.startswith('include/') for name in result['objects']))

    def libc_identity_fixture(self, name='regression/pthread_atfork-errno-clobber', side='candidate'):
        fixture = {'kind': 'fixed-unprivileged-identity', 'uid': 65534, 'gid': 65534,
            'supplementary_groups': [],
            'required_zero_capability_sets': ['inheritable', 'permitted', 'effective', 'ambient'],
            'source_requirement': 'RLIMIT_NPROC=0 must reject fork before checking atfork errno preservation'}
        source = self.leaf / 'source-prepared/src' / (name + '.c')
        if not source.exists(): self.put(source, b'unchanged atfork source fixture\n')
        helper = self.put(self.root / 'compat/x86_64/owned_libc_test_identity.py', b'fixed host helper source fixture\n')
        helper_copy = self.put(self.leaf / 'execution-controls/owned_libc_test_identity.py', helper.read_bytes())
        python = self.put(self.leaf / 'execution-controls/python3', b'retained host Python fixture\n')
        python_binding = {'path': '/usr/bin/python3.11', 'sha256': self.binding(python)['sha256']}
        parent = {'resuid': [0, 0, 0], 'resgid': [0, 0, 0], 'groups': [0],
            'proc': {'uids': [0]*4, 'gids': [0]*4, 'groups': [0],
                'capabilities': {key: ('00000000a80425fb' if key in ('permitted', 'effective', 'bounding') else '0000000000000000')
                    for key in ('inheritable', 'permitted', 'effective', 'bounding', 'ambient')}}}
        child = {'resuid': [65534]*3, 'resgid': [65534]*3, 'groups': [],
            'proc': {'uids': [65534]*4, 'gids': [65534]*4, 'groups': [],
                'capabilities': {key: (parent['proc']['capabilities'][key] if key == 'bounding' else '0000000000000000')
                    for key in ('inheritable', 'permitted', 'effective', 'bounding', 'ambient')}}}
        execution_root = self.leaf / 'execution' / name / side
        receipt_path = execution_root.parent / (side + '.identity.json')
        receipt = {'schema': 'crabc.x86_64-owned-libc-test-execution-identity/v1', 'unit': name,
            'root': self.recorded(execution_root), 'fixture': fixture, 'source': self.binding(source),
            'command': ['/runtest', '-w', '', '/' + name], 'before_drop': parent, 'before_exec': child}
        self.put(receipt_path, receipt)
        record = {'fixture': fixture,
            'helper': {'invoked_path': self.recorded(helper), 'source': self.binding(helper),
                'retained': self.binding(helper_copy), 'after': self.binding(helper)},
            'python': {'invoked_path': '/usr/bin/python3', 'source': python_binding,
                'retained': self.binding(python), 'after': python_binding},
            'source': self.binding(source), 'source_after': self.binding(source),
            'receipt': self.binding(receipt_path), 'parent': {'before': parent, 'after': parent, 'unchanged': True}}
        command = ['/usr/bin/timeout', '20', '/usr/bin/python3', '-B', self.recorded(helper),
            '--root', self.recorded(execution_root), '--receipt', self.recorded(receipt_path), '--unit', name]
        return record, command, source, receipt_path

    def test_libc_test_fixed_execution_identity_contract(self):
        record, command, source, receipt_path = self.libc_identity_fixture()
        reader = native.Reader(self.leaf, self.mount, self.product, self.root)
        name = 'regression/pthread_atfork-errno-clobber'
        def validate(value=record, invocation=command, unit=name):
            return native._libc_execution_identity(reader, value, name=unit, side='candidate', source=source, command=invocation)
        with patch('subprocess.run', side_effect=AssertionError('host validation executed helper')), \
             patch('subprocess.Popen', side_effect=AssertionError('host validation executed Python')):
            self.assertIsNotNone(validate())
        for description, change in (
            ('missing fixture', lambda r: r.update(fixture=None)),
            ('wrong fixed uid', lambda r: r['fixture'].update(uid=65533)),
            ('uid scalar type', lambda r: r['fixture'].update(uid=65534.0)),
            ('helper invocation changed', lambda r: r['helper'].update(invoked_path='/workspace/foreign.py')),
            ('foreign Python', lambda r: r['python'].update(invoked_path='/usr/local/bin/python3')),
            ('changed Python after use', lambda r: r['python']['after'].update(sha256='0'*64)),
            ('changed prepared source', lambda r: r['source_after'].update(sha256='0'*64)),
            ('parent identity changed', lambda r: r['parent']['after']['resuid'].__setitem__(0, 1)),
            ('parent unchanged scalar type', lambda r: r['parent'].update(unchanged=1)),
            ('undeclared field', lambda r: r.update(unexpected=True)),
        ):
            with self.subTest(description=description):
                altered = json.loads(json.dumps(record))
                change(altered)
                with self.assertRaises(native.NativeObservationError): validate(altered)
        with self.assertRaises(native.NativeObservationError): validate(None)
        with self.assertRaises(native.NativeObservationError): validate(unit='functional/case_000')
        for position, value in ((1, '1'), (4, '/workspace/foreign.py'), (6, '/workspace/.work/foreign'),
                                (8, '/workspace/.work/other.json'), (10, 'functional/case_000')):
            invocation = list(command)
            invocation[position] = value
            with self.assertRaises(native.NativeObservationError): validate(invocation=invocation)
        before = receipt_path.read_bytes()
        for description, change in (
            ('wrong executed unit', lambda r: r.update(unit='functional/case_000')),
            ('wrong target command', lambda r: r['command'].__setitem__(0, '/bin/true')),
            ('wrong target source', lambda r: r['source'].update(sha256='0'*64)),
            ('wrong actual uid', lambda r: r['before_exec']['resuid'].__setitem__(1, 0)),
            ('wrong actual filesystem gid', lambda r: r['before_exec']['proc']['gids'].__setitem__(3, 0)),
            ('retained supplementary group', lambda r: r['before_exec'].update(groups=[0])),
            ('nonzero permitted capabilities', lambda r: r['before_exec']['proc']['capabilities'].update(permitted='0000000000000001')),
            ('nonzero ambient capabilities', lambda r: r['before_exec']['proc']['capabilities'].update(ambient='0000000000000001')),
            ('missing capability observation', lambda r: r['before_exec']['proc']['capabilities'].pop('inheritable')),
            ('inconsistent before-drop observation', lambda r: r['before_drop']['proc']['uids'].__setitem__(3, 1)),
        ):
            with self.subTest(description=description):
                altered = json.loads(before)
                change(altered)
                self.put(receipt_path, altered)
                evidence = json.loads(json.dumps(record))
                evidence['receipt'] = self.binding(receipt_path)
                with self.assertRaises(native.NativeObservationError): validate(evidence)
        self.put(receipt_path, before)
        for role, filename in (('helper', 'owned_libc_test_identity.py'), ('python', 'python3')):
            path = self.leaf / 'execution-controls' / filename
            original = path.read_bytes()
            path.write_bytes(original + b'changed retained control')
            altered = json.loads(json.dumps(record))
            altered[role]['retained'] = self.binding(path)
            with self.assertRaises(native.NativeObservationError): validate(altered)
            path.write_bytes(original)

    def libc_test_fixture(self, *, profile=False, math_defects=False):
        import owned_libc_test as contract
        stage, prepared = self.leaf / 'source-stage', self.leaf / 'source-prepared'
        source_names = [*contract.COMMON_MEMBERS, contract.RUNTIME_HELPER, *contract.DSO_UNITS]
        for suite, count in (('functional', 74), ('math', 199), ('regression', 68), ('api', 78)):
            source_names += [f'{suite}/case_{number:03d}' for number in range(count)]
        source_names += ['api/unistd']
        for number, name in enumerate(('popen', 'dlopen', 'tls_align', 'tls_align_dlopen', 'tls_init_dlopen', 'sem_open', 'pthread_cancel-points', 'spawn')):
            source_names[source_names.index(f'functional/case_{73-number:03d}')] = 'functional/' + name
        source_names[source_names.index('regression/case_067')] = 'regression/tls_get_new-dtv'
        source_names[source_names.index('regression/case_066')] = 'regression/sem_close-unmap'
        source_names[source_names.index('regression/case_065')] = 'regression/pthread_atfork-errno-clobber'
        if profile:
            source_names[source_names.index('functional/case_065')] = 'functional/crypt'
            source_names[source_names.index('functional/case_064')] = 'functional/strptime'
            source_names[source_names.index('functional/case_063')] = 'functional/wordexp'
        if math_defects:
            for number, name in enumerate(('fmaf', 'fmal', 'powf', 'nextafterl')):
                source_names[source_names.index(f'math/case_{number:03d}')] = 'math/' + name
        for name in source_names:
            self.put(stage / 'src' / (name + '.c'), ('/* ' + name + ' */\n').encode())
        if profile:
            import owned_posix_native_dispositions as dispositions
            self.put(stage / 'src/functional/crypt.c', (ROOT / dispositions.CRYPT_REFERENCE).read_bytes())
            self.put(stage / 'src/functional/strptime.c', (ROOT / dispositions.STRPTIME_REFERENCE).read_bytes())
        if math_defects:
            for definition in math_oracle_defects.ORACLE_DEFECTS.values():
                source = definition['source']
                self.put(stage / source, b'fixture math unit\n')
                for header in definition['headers']:
                    self.put(stage / header, b'fixture diagnostic header\n')
        self.put(stage / 'src/api/unistd.c', b'C(_PC_TIMESTAMP_RESOLUTION)\nC(_SC_XOPEN_UUCP)\n')
        for number in range(29): self.put(stage / f'src/math/gen/g{number:02d}.c', b'generator\n')
        self.put(stage / 'src/musl/pleval.c', b'excluded upstream target\n')
        self.put(stage / 'src/common/options.h.in', b'options template\n')
        self.put(stage / 'Makefile', b'pinned graph fixture\n')
        tree, files = native.source_tree(stage)
        tree_patch = patch.object(native, 'LIBC_TEST_TREE', tree)
        tree_patch.start()
        self.addCleanup(tree_patch.stop)
        shutil.copytree(stage, prepared)
        changes = []
        transformed = (stage / 'src/api/unistd.c').read_text()
        for macro in ('_PC_TIMESTAMP_RESOLUTION', '_SC_XOPEN_UUCP'):
            line = 'C(' + macro + ')'
            replacement = '#ifdef ' + macro + '\n' + line + '\n#endif'
            transformed = transformed.replace(line, replacement)
            changes.append({'line': line, 'macro': macro, 'occurrences': 1, 'replacement': replacement})
        (prepared / 'src/api/unistd.c').write_text(transformed)
        units, inventory = contract.collect_inventory(prepared)
        preparation = {'source': 'src/api/unistd.c', 'original_sha256': files['src/api/unistd.c'],
                       'prepared_sha256': self.binding(prepared / 'src/api/unistd.c')['sha256'],
                       'replacements': changes, 'staged_tracked_files': files}
        for name in ('crti.o', 'libc.so', 'crtn.o', 'Scrt1.o', 'crabc-dynamic-attach.o', 'libcrabc-builtins.a'):
            self.put(self.product / 'usr/lib' / name, name.encode())
        manifest = self.product / 'share/crabc/manifest.json'
        value = json.loads(manifest.read_text())
        value['files'] = {path.relative_to(self.product).as_posix(): self.binding(path)['sha256']
                          for path in self.product.rglob('*') if path.is_file() and path != manifest}
        self.put(manifest, value)
        value['symlinks'] = {'lib/ld-musl-x86_64.so.1': 'ld-crabc-x86_64.so.1'}
        self.put(self.product / 'lib/ld-crabc-x86_64.so.1', b'candidate loader')
        value['files']['lib/ld-crabc-x86_64.so.1'] = self.binding(self.product / 'lib/ld-crabc-x86_64.so.1')['sha256']
        (self.product / 'lib/ld-musl-x86_64.so.1').symlink_to('ld-crabc-x86_64.so.1')
        self.put(manifest, value)
        copied_product = self.leaf / 'candidate-product'
        shutil.copytree(self.product, copied_product, symlinks=True)
        def product_record(root):
            return {'path': self.recorded(root), 'manifest': self.binding(root / 'share/crabc/manifest.json'),
                    'driver': self.binding(root / 'bin/crabc-cc-dynamic'),
                    'compiler_helper': self.binding(root / 'share/crabc/crabc_cc_static.py'),
                    'files': dict(value['files']), 'aliases': dict(value['symlinks'])}
        source_record, copied_record = product_record(self.product), product_record(copied_product)
        for relative in ('compat/upstreams.toml', 'docker/x86_64-musl-oracle-gcc'):
            self.copy_source(relative)
        import run_qualification_manifest as qualification
        oracle_files = {name: {'path': path, 'sha256': 'c' * 64, **({} if name == 'headers' else {'resolved_path': path})}
                        for name, path in qualification.MUSL_RUNTIME_PATHS.items()}
        oracle_files['loader']['resolved_path'] = oracle_files['libc']['path']
        oracle_files['compiler_wrapper']['sha256'] = self.binding(self.root / 'docker/x86_64-musl-oracle-gcc')['sha256']
        import tomllib
        pin = tomllib.loads((self.root / 'compat/upstreams.toml').read_text())['musl']
        manifest_text = ('format=crabc-pinned-musl-oracle-v1\nversion=' + pin['version'] + '\nsource_sha256=' + pin['sha256'] +
                         '\nfallback_revision=' + pin['fallback_revision'] + '\narchitecture=x86_64\n')
        oracle_files['source_manifest']['sha256'] = hashlib.sha256(manifest_text.encode()).hexdigest()
        oracle_files['specs_manifest']['sha256'] = hashlib.sha256((oracle_files['specs']['sha256'] + '  /opt/musl-1.2.6/lib/musl-gcc.specs\n').encode()).hexdigest()
        oracle = {'version': 'musl-1.2.6', 'pins': self.binding(self.root / 'compat/upstreams.toml'), 'files': oracle_files}
        report = {'schema': 'crabc.x86_64-owned-libc-test/v1', 'status': 'passed', 'campaign_complete': False,
                  'public_support': False, 'target': 'x86_64-unknown-linux-musl', 'counts': {'passed': 434},
                  'candidate_link_blocker': None, 'product': {
                  'source': {phase: json.loads(json.dumps(source_record)) for phase in ('before', 'after_copy', 'after_use')},
                  'copied': {phase: json.loads(json.dumps(copied_record)) for phase in ('before', 'after_use')},
                  'driver': copied_record['driver'], 'compiler_helper': copied_record['compiler_helper'],
                  'compiler_environment': {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '1', 'TZ': 'UTC',
                                           'TMPDIR': self.recorded(self.leaf / 'tmp')},
                  'driver_support': {'complete': True}, 'compiler': {'path': '/usr/bin/gcc', 'sha256': 'b' * 64}},
                  'oracle': {phase: json.loads(json.dumps(oracle)) for phase in ('before', 'after')},
                  'upstream': {'revision': native.LIBC_TEST_REVISION, 'tree': tree,
                               'url': 'https://github.com/laputa-systems/libc-test.git'},
                  'source_preparation': {'api_unistd': preparation}, 'inventory': inventory,
                  'source_graph': {'dynamic_runtime_modes': ['dynamic-pie'], 'runtest': {
                      'source': 'src/common/runtest.c', 'child_stack_limit_bytes': 102400,
                      'default_timeout_seconds': 5, 'makefile_invocation': ['runtest.exe', '-w', '', 'TARGET']}}, 'units': []}
        object_paths = {unit['id']: self.put(self.leaf / 'objects/candidate' / (unit['id'] + '.o'), unit['id'].encode()) for unit in units}
        mapped = lambda path: Path(self.recorded(path))
        def command_record(command, stem, stdout=b''):
            streams = {name: self.binding(self.put(self.leaf / (stem + '.' + name), raw))
                       for name, raw in (('stdout', stdout), ('stderr', b''))}
            return {'command': command, 'environment': {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '1', 'TZ': 'UTC',
                    **({'TMPDIR': self.recorded(self.leaf / 'tmp')} if '-c' in command or command[0] == '/usr/bin/gcc' else {})},
                    'exit_status': 0, **streams}
        options = command_record(['/usr/bin/gcc', '-nostdinc', '-isystem', self.recorded(copied_product / 'usr/include'),
            '-fstack-protector-strong', '-std=c99', '-D_POSIX_C_SOURCE=200809L',
            '-D_FILE_OFFSET_BITS=64', '-E', '-H', '-'], 'generated/candidate/options', b'optiongroups_unistd_end\nFIXTURE 1\n')
        generated = self.put(self.leaf / 'generated/candidate/options.h', b'#define FIXTURE 1\n')
        report['source_preparation']['options'] = {'status': 'passed', 'input': self.binding(prepared / 'src/common/options.h.in'),
                                                 'output': self.binding(generated), 'record': options, 'trace': options['stderr']}
        def link(unit, side, inputs, selected_output=None):
            name, shared = unit['id'], unit['kind'] == 'dso'
            output = self.put(selected_output or self.leaf / 'links' / side / (name + ('.so' if shared else '.exe')), (name + side).encode())
            roles = contract.unit_dso_roles(name)
            dsos = [self.leaf / 'links' / side / (dso + '.so') for dso in roles['initial']]
            arguments = {'shared_object': shared, 'application_dsos': list(map(mapped, dsos)), 'runpath': roles['runpath'], 'export_dynamic': roles['export_dynamic']}
            command = (contract.candidate_link_command(mapped(copied_product), list(map(mapped, inputs)), mapped(output), **arguments)
                       if side == 'candidate' else contract.oracle_link_command(list(map(mapped, inputs)), mapped(output), **arguments))
            result = {'status': 'passed', 'output': self.binding(output),
                      'record': command_record(command, 'units/' + name + '.' + side + '-link'),
                      'elf': {'status': 'passed', 'observations': {}}}
            for kind, flag in (('header', '-h'), ('segments', '-l'), ('dynamic', '-d'), ('symbols', '--dyn-syms'), ('relocations', '-r')):
                raw = command_record(['/usr/bin/readelf', flag, '-W', self.recorded(output)], 'units/' + name + '.' + side + '.' + kind)
                result['elf']['observations'][kind] = {'record': raw, 'output': raw['stdout']}
            if side == 'candidate':
                runtime = [copied_product / 'usr/lib' / item for item in ('crti.o', 'libc.so', 'crtn.o')]
                if not shared: runtime += [copied_product / 'usr/lib/Scrt1.o', copied_product / 'usr/lib/crabc-dynamic-attach.o']
                builtins = copied_product / 'usr/lib/libcrabc-builtins.a'
                linker = {'path': '/pinned/ld.lld', 'sha256': 'a' * 64}
                sealed = [linker['path'], '-shared' if shared else '-pie', '--hash-style=sysv', '--eh-frame-hdr', '-z', 'relro', '-z', 'now',
                          '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags', '-rpath', roles['runpath']]
                if roles['export_dynamic']:
                    sealed.append('--export-dynamic')
                if shared:
                    sealed += ['-soname', output.name]
                else:
                    sealed += ['--dynamic-linker', '/lib/ld-crabc-x86_64.so.1', self.recorded(copied_product / 'usr/lib/Scrt1.o'),
                               self.recorded(copied_product / 'usr/lib/crabc-dynamic-attach.o')]
                sealed += list(map(self.recorded, [copied_product / 'usr/lib/crti.o', *inputs, *dsos, copied_product / 'usr/lib/libc.so', builtins, copied_product / 'usr/lib/crtn.o']))
                sealed += ['-o', self.recorded(output)]
                trace = list(map(self.recorded, [*runtime, *inputs, *dsos]))
                receipt = {'schema': 1, 'format': native.PRODUCT_FORMAT, 'mode': 'shared' if shared else 'pie', 'binding': 'now',
                           'runtime_imports': [], 'application_runpath': roles['runpath'], 'campaign_complete': False,
                           'manifest_sha256': self.binding(manifest)['sha256'], 'output_path': self.recorded(output),
                           'output_sha256': self.binding(output)['sha256'], 'application_dsos': {path.name: self.binding(path)['sha256'] for path in dsos},
                           'input_receipts': [self.binding(path) for path in [*runtime, *inputs, *dsos, builtins]],
                           'owned_runtime_inputs': sorted(path.relative_to(copied_product).as_posix() for path in [*runtime, builtins]),
                           'link_command': sealed, 'link_trace': trace, 'resolved_linker': linker}
                path = self.put(Path(str(output) + '.crabc-link.json'), receipt)
                result['receipt'] = {'receipt': self.binding(path), 'link_command': sealed, 'link_trace': trace, 'linker': linker}
            return result
        for definition in units:
            if definition['kind'] == 'dso':
                for side in ('oracle', 'candidate'):
                    link(definition, side, [object_paths[definition['id']]])
        controls_by_fixture = {}
        for name, destination, source_bytes in (('shell', '/bin/sh', contract.CONTROL_SHELL_SOURCE),
                                                  ('echo', '/bin/echo', contract.CONTROL_ECHO_SOURCE)):
            fixture_work = self.leaf / ('external-' + name)
            fixture_source = self.put(fixture_work / (name + '-launcher.c'), source_bytes)
            fixture_object = self.put(fixture_work / (name + '-launcher.o'), (name + ' canonical fixture object').encode())
            fixture_header = command_record(contract.header_command(Path('/usr/bin/gcc'), mapped(copied_product), mapped(fixture_source),
                shared_object=False, quote_dirs=(), kind='runtime', translation=('-fstack-protector-strong',)),
                'external-' + name + '/' + name + '-launcher.headers')
            fixture = {'status': 'passed', 'source': self.binding(fixture_source),
                     'control': {'busybox': {'path': '/bin/busybox', 'sha256': 'd' * 64},
                                 'loader': {'path': '/opt/musl-1.2.6/lib/libc.so', 'sha256': oracle_files['loader']['sha256']},
                                 'layout': {'busybox': '/control/busybox', 'loader': '/control/ld-musl-x86_64.so.1', 'launcher': destination}},
                     'header_translation': {'status': 'passed', 'record': fixture_header, 'trace': fixture_header['stderr'], 'trace_paths': []},
                     'candidate_translation': {'status': 'passed', 'object': self.binding(fixture_object), 'record': command_record(
                        contract.compile_command(mapped(copied_product), mapped(fixture_source), mapped(fixture_object), shared_object=False,
                            quote_dirs=(), kind='runtime'), 'external-' + name + '/' + name + '-launcher.compile')}}
            fixture_controls = {}
            for side in ('oracle', 'candidate'):
                fixture[side + '_link'] = link({'id': 'external-' + name, 'kind': 'runtime'}, side, [fixture_object], fixture_work / (side + '-' + name + '-launcher'))
                fixture[side + '_launcher'] = fixture[side + '_link']['output']
                fixture_controls[side] = [{'source': value, 'destination': destination, 'copied_sha256': value['sha256']}
                    for value, destination in ((fixture['control']['busybox'], '/control/busybox'),
                        (fixture['control']['loader'], '/control/ld-musl-x86_64.so.1'), (fixture[side + '_launcher'], destination))]
            report['external_' + name + '_fixture'] = fixture
            controls_by_fixture[name] = fixture_controls
        shell_controls, echo_controls = controls_by_fixture['shell'], controls_by_fixture['echo']
        for definition in units:
            name, kind = definition['id'], definition['kind']
            source, obj = prepared / definition['source'], object_paths[name]
            quote_dirs = [prepared / 'src/common'] + ([self.leaf / 'generated/candidate'] if kind == 'api' else [])
            command = contract.compile_command(mapped(copied_product), mapped(source), mapped(obj), shared_object=kind == 'dso',
                                               quote_dirs=list(map(mapped, quote_dirs)), kind=kind)
            header_command = contract.header_command(Path('/usr/bin/gcc'), mapped(copied_product), mapped(source),
                shared_object=kind == 'dso', quote_dirs=list(map(mapped, quote_dirs)), kind=kind,
                translation=('-fstack-protector-strong',))
            header = command_record(header_command, 'units/' + name + '.headers')
            unit = {**definition, 'source': self.binding(source), 'status': 'passed', 'quote_include_dirs': list(map(str, map(mapped, quote_dirs))),
                    'candidate_translation': {'status': 'passed', 'object': self.binding(obj), 'record': command_record(command, 'units/' + name + '.compile')},
                    'header_translation': {'status': 'passed', 'foreign_headers': [], 'trace_paths': [], 'record': header, 'trace': header['stderr']}}
            if kind == 'api' or (kind == 'common' and name != contract.RUNTIME_HELPER):
                reason = 'upstream api targets are compilation-only' if kind == 'api' else 'upstream support object has no standalone link edge'
                for field in ('candidate_link', 'oracle_link'): unit[field] = {'status': 'not-applicable', 'reason': reason}
                unit['runtime'] = {'status': 'not-applicable', 'reason': reason if kind == 'api' else 'upstream support object has no direct runtest edge'}
            else:
                inputs = [obj] + ([object_paths[item] for item in contract.COMMON_MEMBERS] if kind != 'dso' else [])
                for side in ('candidate', 'oracle'): unit[side + '_link'] = link(definition, side, inputs)
                if kind != 'runtime':
                    unit['runtime'] = {'status': 'not-applicable', 'reason': 'upstream helper DSO has no direct runtest edge' if kind == 'dso' else 'upstream runtest is the target-side harness executable'}
                else:
                    unit['runtime'] = {'comparison': {'status': 'passed', 'detail': 'passed'}}
                    for side in ('oracle', 'candidate'):
                        command = ['/usr/bin/timeout', '20', '/usr/sbin/chroot', self.recorded(self.leaf / 'execution' / name / side), '/runtest', '-w', '', '/' + name]
                        execution_identity = None
                        if name == 'regression/pthread_atfork-errno-clobber':
                            execution_identity, command, _, _ = self.libc_identity_fixture(name, side)
                        record = command_record(command, 'execution/' + name + '/' + side)
                        if profile and name == 'functional/crypt' and side == 'candidate':
                            rows = dispositions.crypt_vectors(ROOT)
                            output = ''.join(f'{self.recorded(source)}:{r["line"]}: crypt({r["key_literal"]}, "{r["setting"]}") failed: got "*" want "{r["oracle"]}"\n'
                                for r in rows if r['ordinal'] not in (6, 7, 23, 32)).encode() + b'FAIL /functional/crypt [status 1]\n'
                            path = self.leaf / 'execution' / name / (side + '.stdout')
                            self.put(path, output)
                            record.update(exit_status=1, stdout=self.binding(path))
                        if profile and name == 'functional/strptime':
                            output = (
                                f'{self.recorded(source)}:36: "%s": for "683078400" expected 1991-08-25T00:00:00 '
                                'but got 1900-01-00T00:00:00\n'
                                f'{self.recorded(source)}:47: "%z": failed to parse "-06"\n'
                                'FAIL /functional/strptime [status 1]\n'
                            ).encode()
                            path = self.leaf / 'execution' / name / (side + '.stdout')
                            self.put(path, output)
                            record.update(exit_status=1, stdout=self.binding(path))
                        if profile and name == 'functional/wordexp':
                            output = (b'fixture wordexp candidate raw failure\n' if side == 'candidate'
                                      else b'fixture wordexp pinned-musl raw failure\n')
                            path = self.leaf / 'execution' / name / (side + '.stdout')
                            self.put(path, output)
                            record.update(exit_status=1, stdout=self.binding(path))
                        if math_defects and name in math_oracle_defects.ORACLE_DEFECTS and side == 'oracle':
                            output = math_oracle_defects.expected_oracle_stdout(name, self.recorded(prepared))
                            path = self.leaf / 'execution' / name / (side + '.stdout')
                            self.put(path, output)
                            record.update(exit_status=1, stdout=self.binding(path))
                        status = self.put(self.leaf / 'execution' / name / (side + '.status.json'), record)
                        copied_files = [
                            {'destination': '/runtest', 'sha256': self.binding(self.leaf / 'links' / side / 'common/runtest.exe')['sha256']},
                            {'destination': '/' + name, 'sha256': unit[side + '_link']['output']['sha256']}]
                        roles = contract.unit_dso_roles(name)
                        copied_files += [{'destination': destination, 'sha256': self.binding(self.leaf / 'links' / side / (dso + '.so'))['sha256']}
                                         for dso, destination in roles['runtime']]
                        copied_files += [{'destination': '/usr/lib/' + Path(dso).name + '.so', 'sha256': self.binding(self.leaf / 'links' / side / (dso + '.so'))['sha256']}
                                         for dso in roles['initial']]
                        if side == 'candidate':
                            identity = contract.product_payload_identity(copied_record)
                            runtime_payload = {'candidate_product': identity}
                            source_bindings = {'candidate_product_manifest': copied_record['manifest'], 'candidate_product_payload': identity}
                        else:
                            runtime_payload = {'oracle_runtime': {key: {
                                'source': oracle_files[key], 'destination': destination,
                                'copied_sha256': oracle_files[key]['sha256'], 'observed_sha256': oracle_files[key]['sha256']}
                                for key, destination in (('loader', '/lib/ld-musl-x86_64.so.1'), ('libc', '/usr/lib/libc.so'))}}
                            source_bindings = {'oracle': oracle}
                        controls = echo_controls[side] if name == 'functional/spawn' else shell_controls[side] if name in contract.SHELL_RUNTIME_UNITS else []
                        copied_files += [{'destination': entry['destination'], 'sha256': entry['source']['sha256']} for entry in controls]
                        filesystem = []
                        if name in ('functional/sem_open', 'regression/sem_close-unmap', 'functional/pthread_cancel-points'):
                            filesystem = [{'path': '/dev/shm', 'type': 'directory', 'mode': '01777'}]
                        elif name == 'regression/tls_get_new-dtv':
                            filesystem = [{'path': '/proc', 'type': 'directory', 'mode': '0755'},
                                {'path': '/proc/self', 'type': 'directory', 'mode': '0755'},
                                {'path': '/proc/self/exe', 'type': 'symlink', 'target': '/regression/tls_get_new-dtv'}]
                        phases = {}
                        for phase in ('before', 'after'):
                            payload_record = {'schema': 'crabc.x86_64-owned-libc-test-root-payload/v1', 'side': side, 'phase': phase,
                                'runtime': runtime_payload, 'copied_files': copied_files, 'control_fixture': controls,
                                'filesystem_fixture': filesystem,
                                'execution_identity_fixture': execution_identity['fixture'] if execution_identity else None,
                                'topology': contract.unit_dso_roles(name), 'canonical_source_bindings': source_bindings}
                            phases[phase] = self.binding(self.put(self.leaf / 'execution' / name / (side + '.root-payload-' + phase + '.json'), payload_record))
                        unit['runtime'][side] = {'status': 'passed', 'root_reclaimed': True, 'record': record,
                                                'status_record': self.binding(status), 'root_payload': {**phases, 'unchanged': True},
                                                'execution_identity': execution_identity}
            if profile and name == 'functional/crypt':
                unit['status'] = 'runtime-failed'
                unit['runtime']['candidate']['status'] = 'failed'
                unit['runtime']['comparison'] = {'status': 'blocked', 'reason': 'candidate runtime did not pass this prepared root'}
                report.update(status='incomplete', counts={'passed': 432, 'runtime-failed': 2})
            if profile and name == 'functional/strptime':
                unit['status'] = 'runtime-failed'
                unit['runtime']['oracle']['status'] = 'failed'
                unit['runtime']['candidate']['status'] = 'failed'
                unit['runtime']['comparison'] = {'status': 'blocked', 'reason': 'pinned-musl runtime did not pass this prepared root'}
            if profile and name == 'functional/wordexp':
                unit['status'] = 'runtime-failed'
                unit['runtime']['oracle']['status'] = 'failed'
                unit['runtime']['candidate']['status'] = 'failed'
                unit['runtime']['comparison'] = {'status': 'blocked', 'reason': 'pinned-musl runtime did not pass this prepared root'}
            if math_defects and name in math_oracle_defects.ORACLE_DEFECTS:
                unit['status'] = 'runtime-failed'
                unit['runtime']['oracle']['status'] = 'failed'
                unit['runtime']['comparison'] = {'status': 'blocked', 'reason': 'pinned-musl runtime did not pass this prepared root'}
                report.update(status='incomplete', counts={'passed': 429, 'runtime-failed': 5})
            report['units'].append(unit)
        runtime_failed = sum(unit['status'] == 'runtime-failed' for unit in report['units'])
        if runtime_failed:
            report.update(status='incomplete', counts={'passed': 434 - runtime_failed, 'runtime-failed': runtime_failed})
        self.put(self.leaf / 'libc-test.json', report)
        return report

    def profile_companions(self):
        import owned_posix_native_dispositions as dispositions
        for path in (*dispositions.PROFILE_SOURCES, *math_oracle_defects.PROOF_SOURCES):
            self.copy_source(path)
        return {'crypt': {'vectors': dispositions.crypt_vectors(self.root),
                    'receipt': {'path': '.work/crypt/crypt-profile.json', 'sha256': 'c'*64}},
                'atomic': {'receipt': {'path': '.work/atomic/atomic-addressable-profile.json', 'sha256': 'd'*64},
                    'selected_dynamic_entries': {mode: {} for mode in MODES}},
                'wordexp': {'receipt': {'path': '.work/wordexp/owned-wordexp-products.json', 'sha256': 'e'*64},
                    'expected_native_inputs': {'path': '.work/wordexp-inputs/expected-native-inputs.json', 'sha256': 'f'*64},
                    'product': {'path': '.work/product'},
                    'source_policy_probe': {'path': 'compat/x86_64/owned_wordexp_source_policy_probe.c', 'sha256': 'a'*64},
                    'diagnostic_reference': {'path': 'compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json', 'sha256': 'b'*64},
                    'selected_dynamic_entries': {mode: {} for mode in MODES}}}

    def profile_input_paths(self):
        return {'family_execution': '.work/family/execution.json', 'crypt_profile': '.work/crypt/crypt-profile.json',
                'atomic_addressable_profile': '.work/atomic/atomic-addressable-profile.json',
                'wordexp_profile': '.work/wordexp/owned-wordexp-products.json',
                'wordexp_expected_native_inputs': '.work/wordexp-inputs/expected-native-inputs.json'}

    def fixture_wordexp_disposition(self, reader, source, **arguments):
        """Routing seam only; test_owned_wordexp_upstream_policy owns raw qualification."""
        self.assertEqual(source.name, 'wordexp.c')
        self.assertEqual([arguments['candidate_status'], arguments['oracle_status']], [1, 1])
        self.assertEqual(arguments['candidate_stderr'], b'')
        self.assertEqual(arguments['oracle_stderr'], b'')
        self.assertEqual(arguments['candidate_stdout'], b'fixture wordexp candidate raw failure\n')
        self.assertEqual(arguments['oracle_stdout'], b'fixture wordexp pinned-musl raw failure\n')
        self.assertIn('receipt', arguments['companion'])
        return {'unit': 'functional/wordexp', 'status': 'posix-policy-qualified', 'raw_passed': False}

    def test_profile_prerequisites_require_wordexp_report_and_independent_expected_input(self):
        import owned_atomic_addressable_profile as atomic
        import owned_crypt_profile as crypt
        import owned_posix_family_execution as family
        import owned_posix_native_dispositions as dispositions
        import owned_wordexp_upstream_policy as wordexp_policy
        paths = self.profile_input_paths()
        for value in paths.values():
            self.put(self.root / value, {'fixture': value})
        companion = {'product': {'path': '.work/product'}, 'source_policy_probe': {'path': 'probe'},
                     'diagnostic_reference': {'path': 'reference'},
                     'selected_dynamic_entries': {mode: {} for mode in MODES}}
        with patch.object(family, 'validate_receipt', return_value={'fixture': 'complete family matrix'}), \
             patch.object(crypt, 'validate_receipt', return_value={'vectors': [], 'vector_observations': {}}), \
             patch.object(atomic, 'validate_receipt', return_value={'entries': {}}), \
             patch.object(wordexp_policy, 'validate_companion', return_value=companion) as validate_wordexp:
            observed = native._load_profile_companions(self.root, self.product, paths)
        validate_wordexp.assert_called_once_with(self.root, self.root / paths['wordexp_profile'],
                                                 self.root / paths['wordexp_expected_native_inputs'], self.product)
        self.assertEqual(observed['wordexp']['product'], companion['product'])
        self.assertEqual(observed['wordexp']['receipt']['path'], paths['wordexp_profile'])
        self.assertEqual(observed['wordexp']['expected_native_inputs']['path'],
                         paths['wordexp_expected_native_inputs'])
        paths.pop('wordexp_expected_native_inputs')
        with self.assertRaises(native.NativeObservationError):
            native._load_profile_companions(self.root, self.product, paths)

    def fixture_math_oracle_defects(self):
        expected_hashes = {name: {key: hashlib.sha256(value).hexdigest() for key, value in {
            'source': b'fixture math unit\n', 'header': b'fixture diagnostic header\n'}.items()}
            for name in math_oracle_defects.ORACLE_DEFECTS}
        definitions = copy.deepcopy(math_oracle_defects.ORACLE_DEFECTS)
        for name, definition in definitions.items():
            definition['source_sha256'] = expected_hashes[name]['source']
            definition['headers'] = {path: expected_hashes[name]['header'] for path in definition['headers']}
        return definitions

    def test_native_os_profile_preserves_exact_six_raw_failures(self):
        report = self.os_test_fixture(profile=True)
        proof = self.profile_companions()
        inputs = self.profile_input_paths()
        with self.assertRaises(native.NativeObservationError): self.collect('os-test')
        with patch.object(native, '_load_profile_companions', return_value=proof):
            result = native.collect('os-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                                    root=self.root, profile_inputs=inputs)
            self.assertIs(report['passed'], False)
            self.assertEqual(result['qualification']['status'], 'profile-qualified')
            self.assertEqual(len(result['qualification']['dispositions']), 6)
            self.assertIs(result['qualification']['raw_passed'], False)
            include = next(row for row in report['suites'] if row['suite'] == 'include')
            include['differences'].append({'case': 'case.out', 'dynamic': {}, 'musl': {}})
            include['difference_count'] = 7
            self.put(self.leaf / 'os-test.json', report)
            with self.assertRaises(native.NativeObservationError):
                native.collect('os-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                               root=self.root, profile_inputs=inputs)

    def test_native_libc_profile_preserves_crypt_strptime_and_math_oracle_defect_units(self):
        report = self.libc_test_fixture(profile=True, math_defects=True)
        proof = self.profile_companions()
        inputs = self.profile_input_paths()
        with self.assertRaises(native.NativeObservationError): self.collect('libc-test')
        with patch.object(math_oracle_defects, 'ORACLE_DEFECTS', self.fixture_math_oracle_defects()), \
             patch.object(native, '_load_profile_companions', return_value=proof), \
             patch.object(wordexp_policy, 'upstream_disposition', side_effect=self.fixture_wordexp_disposition):
            result = native.collect('libc-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                                    root=self.root, profile_inputs=inputs)
            self.assertEqual(report['counts'], {'passed': 428, 'runtime-failed': 6})
            self.assertEqual(len(result['observations']), 434)
            self.assertEqual(result['qualification']['status'], 'profile-qualified')
            self.assertEqual(len(result['qualification']['dispositions']), 6)
            self.assertEqual(len(result['qualification']['dispositions'][0]['differences']), 28)
            self.assertEqual(result['qualification']['dispositions'][1]['unit'], 'functional/strptime')
            self.assertEqual(result['qualification']['dispositions'][2]['unit'], 'functional/wordexp')
            self.assertEqual(result['qualification']['dispositions'][2]['status'], 'posix-policy-qualified')
            self.assertEqual([entry['unit'] for entry in result['qualification']['dispositions'][3:]],
                             ['math/fmaf', 'math/fmal', 'math/powf'])
            self.assertTrue(all(entry['status'] == 'candidate-passed-oracle-defect'
                                for entry in result['qualification']['dispositions'][3:]))
            count_changed = json.loads(json.dumps(report))
            count_changed['counts']['runtime-failed'] = 5
            self.put(self.leaf / 'libc-test.json', count_changed)
            with self.assertRaises(native.NativeObservationError):
                native.collect('libc-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                               root=self.root, profile_inputs=inputs)
            self.put(self.leaf / 'libc-test.json', report)
            report['units'][0]['status'] = 'runtime-failed'
            self.put(self.leaf / 'libc-test.json', report)
            with self.assertRaises(native.NativeObservationError):
                native.collect('libc-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                               root=self.root, profile_inputs=inputs)

    def test_native_libc_observer_keeps_corrected_math_as_candidate_passed_oracle_defects(self):
        report = self.libc_test_fixture(profile=True, math_defects=True)
        proof = self.profile_companions()
        inputs = self.profile_input_paths()
        with patch.object(math_oracle_defects, 'ORACLE_DEFECTS', self.fixture_math_oracle_defects()):
            with patch.object(native, '_load_profile_companions', return_value=proof), \
                 patch.object(wordexp_policy, 'upstream_disposition', side_effect=self.fixture_wordexp_disposition):
                result = native.collect('libc-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                                        root=self.root, profile_inputs=inputs)
        defects = [entry for entry in result['qualification']['dispositions'] if entry['unit'].startswith('math/')]
        self.assertEqual([entry['unit'] for entry in defects], ['math/fmaf', 'math/fmal', 'math/powf'])
        self.assertTrue(all(entry['status'] == 'candidate-passed-oracle-defect' for entry in defects))
        self.assertTrue(all(entry['candidate']['passed'] and not entry['oracle']['passed'] for entry in defects))
        for name in math_oracle_defects.ORACLE_DEFECTS:
            self.assertEqual((self.leaf / 'execution' / name / 'candidate.stdout').read_bytes(), b'')
            self.assertEqual((self.leaf / 'execution' / name / 'candidate.stderr').read_bytes(), b'')
            self.assertEqual((self.leaf / 'execution' / name / 'oracle.stdout').read_bytes(),
                             math_oracle_defects.expected_oracle_stdout(name, self.recorded(self.leaf / 'source-prepared')))
            self.assertEqual((self.leaf / 'execution' / name / 'oracle.stderr').read_bytes(), b'')
        self.assertEqual(report['counts'], {'passed': 428, 'runtime-failed': 6})

    def test_native_libc_math_oracle_defect_rejects_changed_stream_source_and_unlisted_failures(self):
        report = self.libc_test_fixture(profile=True, math_defects=True)
        proof = self.profile_companions()
        inputs = self.profile_input_paths()
        fixture_defects = self.fixture_math_oracle_defects()
        def collect():
            with patch.object(math_oracle_defects, 'ORACLE_DEFECTS', fixture_defects):
                with patch.object(native, '_load_profile_companions', return_value=proof), \
                     patch.object(wordexp_policy, 'upstream_disposition', side_effect=self.fixture_wordexp_disposition):
                    return native.collect('libc-test', self.leaf, source_mount=self.mount, dynamic_product=self.product,
                                          root=self.root, profile_inputs=inputs)
        original_report = (self.leaf / 'libc-test.json').read_bytes()

        candidate = self.leaf / 'execution/math/fmaf/candidate.stdout'
        candidate_before = candidate.read_bytes()
        status_path = self.leaf / 'execution/math/fmaf/candidate.status.json'
        status_before = status_path.read_bytes()
        changed = json.loads(original_report)
        unit = next(item for item in changed['units'] if item['id'] == 'math/fmaf')
        self.put(candidate, b'unexpected candidate diagnostic\n')
        unit['runtime']['candidate']['record']['stdout'] = self.binding(candidate)
        self.put(status_path, unit['runtime']['candidate']['record'])
        unit['runtime']['candidate']['status_record'] = self.binding(status_path)
        self.put(self.leaf / 'libc-test.json', changed)
        with self.assertRaises(native.NativeObservationError, msg='candidate output is not an oracle-defect waiver'):
            collect()
        self.put(candidate, candidate_before)
        self.put(status_path, status_before)

        oracle = self.leaf / 'execution/math/fmaf/oracle.stdout'
        oracle_before = oracle.read_bytes()
        status_path = self.leaf / 'execution/math/fmaf/oracle.status.json'
        status_before = status_path.read_bytes()
        changed = json.loads(original_report)
        unit = next(item for item in changed['units'] if item['id'] == 'math/fmaf')
        self.put(oracle, oracle_before + b'unexpected oracle diagnostic\n')
        unit['runtime']['oracle']['record']['stdout'] = self.binding(oracle)
        self.put(status_path, unit['runtime']['oracle']['record'])
        unit['runtime']['oracle']['status_record'] = self.binding(status_path)
        self.put(self.leaf / 'libc-test.json', changed)
        with self.assertRaises(native.NativeObservationError, msg='changed pinned-musl diagnostics are rejected'):
            collect()
        self.put(oracle, oracle_before)
        self.put(status_path, status_before)

        header = self.leaf / 'source-prepared/src/math/special/fmaf.h'
        header_before = header.read_bytes()
        header.write_bytes(header_before + b'changed header\n')
        self.put(self.leaf / 'libc-test.json', original_report)
        with self.assertRaises(native.NativeObservationError, msg='prepared diagnostic-header drift is rejected'):
            collect()
        header.write_bytes(header_before)

        for name in ('math/nextafterl', 'functional/case_000'):
            with self.subTest(unit=name):
                output = self.leaf / 'execution' / name / 'oracle.stdout'
                output_before = output.read_bytes()
                status_path = self.leaf / 'execution' / name / 'oracle.status.json'
                status_before = status_path.read_bytes()
                changed = json.loads(original_report)
                unit = next(item for item in changed['units'] if item['id'] == name)
                self.put(output, b'FAIL /' + name.encode() + b' [status 1]\n')
                unit['status'] = 'runtime-failed'
                unit['runtime']['oracle']['status'] = 'failed'
                unit['runtime']['comparison'] = {'status': 'blocked', 'reason': 'pinned-musl runtime did not pass this prepared root'}
                unit['runtime']['oracle']['record'].update(exit_status=1, stdout=self.binding(output))
                self.put(status_path, unit['runtime']['oracle']['record'])
                unit['runtime']['oracle']['status_record'] = self.binding(status_path)
                changed['status'] = 'incomplete'
                changed['counts'] = {'passed': 427, 'runtime-failed': 7}
                self.put(self.leaf / 'libc-test.json', changed)
                with self.assertRaises(native.NativeObservationError, msg='unlisted runtime failure cannot gain a math disposition'):
                    collect()
                self.put(output, output_before)
                self.put(status_path, status_before)

        changed = json.loads(original_report)
        changed['candidate_link_blocker'] = {'unit': 'functional/random'}
        self.put(self.leaf / 'libc-test.json', changed)
        with self.assertRaises(native.NativeObservationError, msg='random link blocker cannot be hidden by math accounting'):
            collect()

    def test_libc_test_preserves_graph_roles_and_rejects_tampered_or_incomplete_evidence(self):
        report = self.libc_test_fixture()
        with patch('subprocess.run', side_effect=AssertionError('collector executed a tool')), \
             patch('subprocess.Popen', side_effect=AssertionError('collector launched a process')):
            result = self.collect('libc-test')
        self.assertEqual(len(result['objects']), 434)
        self.assertEqual(len(result['observations']), 434)
        self.assertEqual(sum(row['kind'] == 'runtime' for row in result['observations'].values()), 341)
        self.assertNotIn('oracle', result['observations']['api/unistd'])
        original = (self.leaf / 'libc-test.json').read_bytes()
        mutations = {
            'omitted graph unit': lambda r: r['units'].pop(),
            'duplicated graph unit': lambda r: r['units'].__setitem__(0, r['units'][1]),
            'invented compile-only run': lambda r: r['units'][0].update(runtime={'status': 'passed'}),
            'different installed product': lambda r: r['product']['source']['before'].update(path='/workspace/.work/other'),
            'changed copied product after use': lambda r: r['product']['copied']['after_use']['files'].update({'usr/lib/libc.so': '0' * 64}),
            'changed source product after copy': lambda r: r['product']['source']['after_copy']['aliases'].clear(),
            'changed oracle after use': lambda r: r['oracle']['after']['files']['loader'].update(sha256='0' * 64),
            'changed upstream default timeout': lambda r: r['source_graph']['runtest'].update(default_timeout_seconds=10),
            'ambient compiler header override': lambda r: r['product']['compiler_environment'].update(CPATH='/foreign'),
            'failed runtime hidden by summary': lambda r: next(u for u in r['units'] if u['kind'] == 'runtime')['runtime']['candidate'].update(status='failed'),
            'boolean exit status': lambda r: r['units'][0]['candidate_translation']['record'].update(exit_status=False),
            'missing execution identity': lambda r: next(u for u in r['units'] if u['id'] == 'regression/pthread_atfork-errno-clobber')['runtime']['candidate'].pop('execution_identity'),
            'omitted fixed execution identity': lambda r: next(u for u in r['units'] if u['id'] == 'regression/pthread_atfork-errno-clobber')['runtime']['candidate'].update(execution_identity=None),
            'identity on unrelated unit': lambda r: next(u for u in r['units'] if u['id'] == 'functional/case_000')['runtime']['candidate'].update(execution_identity={}),
            'incomplete campaign': lambda r: r.update(status='incomplete'),
            'changed generated options': lambda r: r['source_preparation']['options']['output'].update(sha256='changed'),
            'foreign options compiler': lambda r: r['source_preparation']['options']['record']['command'].__setitem__(0, '/foreign/gcc'),
            'foreign shell control loader': lambda r: r['external_shell_fixture']['control']['loader'].update(sha256='0' * 64),
            'foreign shell object': lambda r: r['external_shell_fixture']['candidate_translation']['object'].update(sha256='0' * 64),
            'missing echo fixture': lambda r: r.pop('external_echo_fixture'),
            'unbound echo object': lambda r: r['external_echo_fixture']['candidate_translation']['object'].update(sha256='0' * 64),
            'foreign echo control loader': lambda r: r['external_echo_fixture']['control']['loader'].update(path='/lib/ld-musl-x86_64.so.1'),
            'echo installed as another command': lambda r: r['external_echo_fixture']['control']['layout'].update(launcher='/bin/sh'),
            'foreign header compiler': lambda r: r['units'][0]['header_translation']['record']['command'].__setitem__(0, '/foreign/gcc'),
        }
        for description, mutate in mutations.items():
            with self.subTest(description=description):
                changed = json.loads(original)
                mutate(changed)
                self.put(self.leaf / 'libc-test.json', changed)
                with self.assertRaises(native.NativeObservationError): self.collect('libc-test')
        self.put(self.leaf / 'libc-test.json', original)
        changed = json.loads(original)
        runtime = next(unit for unit in changed['units'] if unit['kind'] == 'runtime')['runtime']['candidate']
        runtime['record']['stdout'] = self.binding(self.leaf / 'execution/functional/case_001/candidate.stdout')
        status_path = self.leaf / 'execution/functional/case_000/candidate.status.json'
        status_before = status_path.read_bytes()
        self.put(status_path, runtime['record'])
        runtime['status_record'] = self.binding(status_path)
        self.put(self.leaf / 'libc-test.json', changed)
        with self.assertRaises(native.NativeObservationError, msg='a consistent report and sidecar cannot reuse another unit raw result'):
            self.collect('libc-test')
        self.put(status_path, status_before)
        self.put(self.leaf / 'libc-test.json', original)
        for unit_name, description, mutate in (
            ('functional/case_000', 'changed copied candidate libc', lambda record: record['runtime']['candidate_product']['files'].update({'usr/lib/libc.so': '0' * 64})),
            ('functional/case_000', 'foreign copied program', lambda record: record['copied_files'][1].update(sha256='0' * 64)),
            ('functional/case_000', 'replaced candidate loader alias', lambda record: record['runtime']['candidate_product']['aliases'].update({'lib/ld-musl-x86_64.so.1': '/control/loader'})),
            ('regression/pthread_atfork-errno-clobber', 'omitted root execution identity', lambda record: record.update(execution_identity_fixture=None)),
            ('functional/case_000', 'undeclared root execution identity', lambda record: record.update(execution_identity_fixture={})),
            ('functional/sem_open', 'missing shared-memory fixture', lambda record: record['filesystem_fixture'].clear()),
            ('regression/sem_close-unmap', 'changed shared-memory permissions', lambda record: record['filesystem_fixture'][0].update(mode='00755')),
            ('functional/pthread_cancel-points', 'changed filesystem mode type', lambda record: record['filesystem_fixture'][0].update(mode=0o1777)),
            ('regression/tls_get_new-dtv', 'foreign executable origin', lambda record: record['filesystem_fixture'][-1].update(target='/unrelated')),
            ('regression/tls_get_new-dtv', 'omitted proc fixture parent', lambda record: record['filesystem_fixture'].pop(0)),
            ('functional/case_000', 'undeclared filesystem fixture', lambda record: record['filesystem_fixture'].append({'path': '/dev/shm', 'type': 'directory', 'mode': '01777'})),
            ('functional/spawn', 'missing copied echo control', lambda record: record['control_fixture'].pop()),
            ('functional/spawn', 'copied echo from another launcher', lambda record: record['control_fixture'][-1]['source'].update(path='/workspace/.work/foreign/echo')),
        ):
            with self.subTest(description=description):
                changed = json.loads(original)
                runtime = next(unit for unit in changed['units'] if unit['id'] == unit_name)['runtime']['candidate']
                phases = []
                for phase in ('before', 'after'):
                    path = self.leaf / 'execution' / unit_name / ('candidate.root-payload-' + phase + '.json')
                    phases.append((path, path.read_bytes()))
                    record = json.loads(path.read_bytes())
                    mutate(record)
                    self.put(path, record)
                    runtime['root_payload'][phase] = self.binding(path)
                self.put(self.leaf / 'libc-test.json', changed)
                with self.assertRaises(native.NativeObservationError, msg='consistent before/after hashes cannot replace the canonical payload'):
                    self.collect('libc-test')
                for path, before in phases:
                    self.put(path, before)
        self.put(self.leaf / 'libc-test.json', original)
        changed = json.loads(original)
        linked = next(unit for unit in changed['units'] if unit['id'] == 'common/runtest')['candidate_link']
        receipt_path = self.leaf / 'links/candidate/common/runtest.exe.crabc-link.json'
        receipt_before = receipt_path.read_bytes()
        receipt = json.loads(receipt_before)
        receipt['link_command'].append('/foreign/runtime.o')
        self.put(receipt_path, receipt)
        linked['receipt']['receipt'] = self.binding(receipt_path)
        linked['receipt']['link_command'] = receipt['link_command']
        self.put(self.leaf / 'libc-test.json', changed)
        with self.assertRaises(native.NativeObservationError, msg='consistent receipt hashes cannot admit a foreign link input'):
            self.collect('libc-test')
        self.put(receipt_path, receipt_before)
        self.put(self.leaf / 'libc-test.json', original)
        for relative in ('source-stage/Makefile', 'source-prepared/src/common/print.c', 'objects/candidate/api/unistd.o',
                         'execution/functional/case_000/candidate.stdout', 'execution/functional/case_000/candidate.status.json'):
            with self.subTest(artifact=relative):
                path = self.leaf / relative
                before = path.read_bytes()
                path.write_bytes(before + b'changed')
                with self.assertRaises(native.NativeObservationError): self.collect('libc-test')
                path.write_bytes(before)

    def test_pinned_tree_binds_nested_files_executable_modes_and_full_roster(self):
        stage = self.leaf / 'source-stage'
        self.put(stage / 'a', b'hello\n')
        self.put(stage / 'nested/run', b'#!/bin/sh\n')
        (stage / 'nested/run').chmod(0o755)
        tree, files = native.source_tree(stage)
        self.assertEqual(set(files), {'a', 'nested/run'})
        (stage / 'nested/run').chmod(0o644)
        self.assertNotEqual(native.source_tree(stage)[0], tree)
        (stage / 'nested/run').chmod(0o755)
        self.assertEqual(native.source_tree(stage)[0], tree)
        self.put(stage / 'extra', b'')
        self.assertNotEqual(native.source_tree(stage)[0], tree)
        (stage / 'extra').unlink()
        (stage / 'a').unlink()
        (stage / 'a').symlink_to(stage / 'nested/run')
        with self.assertRaises(native.NativeObservationError): native.source_tree(stage)
        (stage / 'a').unlink()
        (stage / 'a').symlink_to('missing-target')
        _, files = native.source_tree(stage, allow_symlinks=True)
        self.assertEqual(files['a'], hashlib.sha256(b'missing-target').hexdigest())


if __name__ == '__main__':
    unittest.main()
