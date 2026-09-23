"""Native aggregation uses real fresh steps with explicit external judge seams.

The family matrix and native C collectors have independent product/source
tests. These fixtures replace those two judges, retaining physical products,
all three I/O replays, and five real subprocesses so ordering, failure state,
input identity, and immutable evidence remain observable coordinator behavior.
The wordexp full-receipt validator is an explicit external judge seam here;
these tests cover coordinator wiring, never a real wordexp qualification.
"""
import base64
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_posix_native_execution as execution
import owned_posix_family_execution as family
import owned_posix_family_observations as family_observations
import owned_posix_family_workloads as workloads
import owned_posix_native_observations as native


IO_STDOUT = (''.join(f'blocked-operation {number} canceled cleanup=21\n' for number in range(10)) +
             'initial-thread blocked read canceled cleanup=1\n'
             'fork retains initial/worker pending state type cleanup\n'
             'retired task explicit FILE lock remains orphaned\n'
             'owned-io-cancellation-ok\n').encode()


class NativeExecutionTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/test-posix-native-execution'
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / '.work/aggregate'
        self.source = {'revision': '1' * 40, 'content_sha256': '2' * 64}
        self.matrix_path = self.root / '.work/family/execution.json'
        self.put(self.matrix_path, {'fixture': 'external family judge owns its complete matrix'})
        self.crypt_path = self.put(self.root / '.work/crypt/crypt-profile.json', {'fixture': 'external crypt judge'})
        self.atomic_path = self.put(self.root / '.work/atomic/atomic-addressable-profile.json',
                                    {'fixture': 'external atomic judge'})
        self.wordexp_path = self.put(self.root / '.work/wordexp/owned-wordexp-products.json',
                                     {'fixture': 'external wordexp full receipt judge'})
        self.wordexp_expected_path = self.put(self.root / '.work/wordexp-inputs/expected-native-inputs.json',
                                              {'fixture': 'independently captured wordexp expected inputs'})
        self.products = {}
        for label in ('installed', 'second', 'extracted'):
            product = self.root / '.work/dynamic' / label
            self.put(product / 'share/crabc/manifest.json', {'schema': 1, 'format': native.PRODUCT_FORMAT,
                'target': 'x86_64-unknown-linux-musl', 'fixture_product': label})
            self.put(product / 'bin/crabc-cc-dynamic', b'installed driver bytes')
            self.put(product / 'usr/lib/libc.so', b'installed runtime bytes')
            self.products[label] = product
        self.product = self.products['installed']
        source_paths = set(execution.SHARED_SOURCES)
        for component in execution.COMPONENTS:
            source_paths.update((component.runner, *component.sources))
        for relative in source_paths:
            self.put(self.root / relative, ('source fixture: ' + relative + '\n').encode())
        self.put(self.root / execution.IO_SOURCE, (ROOT / execution.IO_SOURCE).read_bytes())
        for component in execution.COMPONENTS:
            declaration = ("printf '%s\\n' \"$leaf\"" if component.id == 'libc-test' else
                           "printf '" + component.announcement + "%s\\n' \"$leaf\"")
            script = ('#!/usr/bin/env bash\nset -eu\n'
                'root="$(cd "$(dirname "$0")/../.." && pwd)"\n'
                f'printf "{component.id}\\n" >> "$root/.work/order"\n'
                f'leaf="$TMPDIR/{component.leaf_prefix}synthetic"\nmkdir "$leaf"\n' + declaration + '\n' +
                f'printf "{component.id} canonical object\\n" > "$leaf/object.bin"\n'
                f'printf "{component.id} observed\\n" > "$leaf/raw.stdout"\n'
                'printf "0\\n" > "$leaf/raw.status"\n'
                f'printf \'{{"component":"{component.id}"}}\\n\' > "$leaf/report.json"\n')
            self.put(self.root / component.runner, script.encode())
        static = {}
        for label in family.PAIRS:
            path = self.put(self.root / '.work/static' / label / 'manifest.json', {'static': label})
            static[label] = family.file_identity(self.root, path)
        self.matrix = {'schema': family.SCHEMA, 'status': 'workload-matrix-verified',
            'family': 'libc.posix-runtime', 'work': '.work/family', 'family_completion': False,
            'public_support': False, 'native_aggregate_complete': False,
            'inputs': {'source': self.source, 'dynamic_work': '.work/dynamic', 'oracle': {'fixture': 'pinned oracle'},
                'static_preparation': family.file_identity(self.root, self.put(self.root / '.work/static/preparation.json', {})),
                'dynamic_qualification': family.file_identity(self.root, self.put(self.root / '.work/dynamic/qualification.json', {})),
                'static_products': static,
                'dynamic_products': {label: {'path': self.relative(self.products[product]),
                    'manifest_sha256': self.digest(self.products[product] / 'share/crabc/manifest.json')}
                    for label, product in family.PAIRS.items()}}, 'runs': {}}
        for label, product in family.PAIRS.items():
            leaf = self.root / '.work/family/runs' / label / 'io-cancellation/tmp/retained'
            obj = self.put(leaf / 'owned_io_cancellation.o', b'one unchanged I/O object')
            oracle = self.raw(leaf, 'oracle', IO_STDOUT)
            candidates = {mode: self.raw(leaf, mode, IO_STDOUT) for mode in family_observations.MODES}
            receipt = self.put(leaf.parent.parent / 'receipt.json', {'fixture_io_replay': label})
            self.matrix['runs'][label] = {'io-cancellation': {
                'workload': 'io-cancellation', 'dynamic_case': 'io-cancellation', 'static_product': label,
                'dynamic_product': product, 'receipt': family.file_identity(self.root, receipt), 'leaf': self.relative(leaf),
                'objects': {'io-cancellation': {'source': {'path': execution.IO_SOURCE,
                    'sha256': self.digest(self.root / execution.IO_SOURCE)}, 'object': family.file_identity(self.root, obj)}},
                'observations': {'case': 'io-cancellation', 'scenarios': {name: (
                    {'kind': 'differential', 'oracle': oracle, 'candidates': candidates}
                    if name == 'owned_io_cancellation' else {'fixture': 'validated by the complete family judge'})
                    for name in family_observations.IO_SCENARIOS}}}}
        self.patch(family, 'validate_receipt', side_effect=lambda root, path: self.matrix)
        self.patch(execution, 'source_identity', side_effect=self.current_source)
        self.patch(execution, 'require_execution_environment')
        self.patch(execution, 'require_live_oracle')
        self.patch(execution.crypt, 'validate_receipt', side_effect=lambda *args, **kwargs: {'vectors': [], 'vector_observations': {}})
        self.patch(execution.atomic, 'validate_receipt', side_effect=lambda *args, **kwargs: {'entries': {}})
        self.patch(execution.dispositions, 'credentials_companion', return_value={'fixture': 'external credentials judge'})
        self.patch(execution.wordexp_policy, 'validate_companion', side_effect=self.wordexp_companion)
        self.profile_components = set()
        self.native_judge = self.patch(native, 'collect', side_effect=self.native_result)

    def patch(self, target, attribute, **kwargs):
        context = patch.object(target, attribute, **kwargs)
        value = context.start()
        self.addCleanup(context.stop)
        return value

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + '\n').encode())
        return path

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def relative(self, path):
        return path.relative_to(self.root).as_posix()

    def current_source(self, root):
        return {**self.source, 'revision': '3' * 40} if (self.root / '.work/source-changed').exists() else self.source

    def raw(self, leaf, stem, stdout):
        result = {}
        for stream, value in (('stdout', stdout), ('stderr', b''), ('status', b'0\n')):
            path = self.put(leaf / (stem + '.' + stream), value)
            result[stream] = {'path': path.relative_to(leaf).as_posix(), 'size': len(value),
                             'sha256': self.digest(path), 'base64': base64.b64encode(value).decode()}
        return result

    def native_result(self, component, leaf, *, source_mount, dynamic_product, root, profile_inputs=None):
        self.assertEqual(dynamic_product, self.product)
        self.assertEqual(root, self.root)
        self.assertEqual(profile_inputs, {'family_execution': self.relative(self.matrix_path),
            'crypt_profile': self.relative(self.crypt_path),
            'atomic_addressable_profile': self.relative(self.atomic_path),
            'wordexp_profile': self.relative(self.wordexp_path),
            'wordexp_expected_native_inputs': self.relative(self.wordexp_expected_path)})
        if (leaf / 'raw.status').read_bytes() != b'0\n' or (leaf / 'raw.stdout').read_bytes() != (component + ' observed\n').encode():
            raise native.NativeObservationError('synthetic component raw observation failed')
        def identity(path):
            data = path.read_bytes()
            return {'path': path.relative_to(leaf).as_posix(), 'sha256': self.digest(path), 'byte_length': len(data)}
        manifest = self.product / 'share/crabc/manifest.json'
        result = {'component': component, 'report': identity(leaf / 'report.json'),
            'product': {'path': self.relative(self.product), 'manifest': {'path': self.relative(manifest),
                        'sha256': self.digest(manifest), 'byte_length': manifest.stat().st_size}},
            'objects': {'application': {'object': identity(leaf / 'object.bin')}},
            'observations': {'synthetic': identity(leaf / 'raw.stdout')},
            'qualification': {'status': 'profile-qualified' if component in self.profile_components else 'passed',
                'raw_passed': component not in self.profile_components,
                'dispositions': [{'fixture': 'strict external native judge'}] if component in self.profile_components else []}}
        if component == 'pthread-stress':
            source = self.root / execution.IO_SOURCE
            result.update(replacement_io_cancellation_required=['READ_FILE', 'ASYNC_LOOP'],
                replacement_io_cancellation_source={'sha256': self.digest(source), 'mode': source.stat().st_mode,
                    'resolved_path': str(Path(source_mount) / execution.IO_SOURCE)},
                replacement_io_cancellation_receipt=None, native_aggregate_complete=False)
        return result

    def wordexp_companion(self, root, report, expected, product):
        self.assertEqual((root, report, expected, product),
                         (self.root, self.wordexp_path, self.wordexp_expected_path, self.product))
        return {'product': {'path': self.relative(product), 'manifest': {'fixture': 'selected product'}},
                'source_policy_probe': {'path': 'compat/x86_64/owned_wordexp_source_policy_probe.c', 'sha256': 'a' * 64},
                'diagnostic_reference': {'path': 'compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json',
                                         'sha256': 'b' * 64},
                'selected_dynamic_entries': {mode: {} for mode in native.MODES}}

    def execute(self):
        return execution.execute(self.root, self.work, self.matrix_path, self.crypt_path, self.atomic_path,
                                 self.wordexp_path, self.wordexp_expected_path)

    def leaf(self, component):
        item = next(item for item in execution.COMPONENTS if item.id == component)
        return self.work / 'runs' / component / 'tmp' / (item.leaf_prefix + 'synthetic')

    def append_runner(self, component, source):
        item = next(item for item in execution.COMPONENTS if item.id == component)
        path = self.root / item.runner
        path.write_text(path.read_text() + source)

    def test_enumerated_profile_exit_one_retains_raw_status_and_qualifies(self):
        self.profile_components = {'os-test', 'libc-test'}
        for component in self.profile_components:
            self.append_runner(component, 'exit 1\n')
        record = execution.validate_receipt(self.root, self.execute())
        for component in self.profile_components:
            self.assertEqual((self.work / 'runs' / component / 'status').read_bytes(), b'1\n')
            self.assertEqual(record['components'][component]['observations']['qualification']['status'], 'profile-qualified')

    def test_unclassified_exit_one_stops_before_next_component(self):
        self.append_runner('os-test', 'exit 1\n')
        with self.assertRaisesRegex(RuntimeError, 'qualification'):
            self.execute()
        self.assertFalse((self.work / 'runs/signal-process').exists())

    def test_missing_crypt_prerequisite_prevents_execution(self):
        self.crypt_path.unlink()
        with self.assertRaises((RuntimeError, OSError)):
            self.execute()
        self.assertFalse(self.work.exists())

    def test_missing_atomic_prerequisite_prevents_execution(self):
        self.atomic_path.unlink()
        with self.assertRaises((RuntimeError, OSError)):
            self.execute()
        self.assertFalse(self.work.exists())

    def test_missing_wordexp_prerequisite_prevents_execution(self):
        self.wordexp_path.unlink()
        with self.assertRaises((RuntimeError, OSError)):
            self.execute()
        self.assertFalse(self.work.exists())

    def test_missing_wordexp_expected_input_prevents_execution(self):
        self.wordexp_expected_path.unlink()
        with self.assertRaises((RuntimeError, OSError)):
            self.execute()
        self.assertFalse(self.work.exists())

    def test_crypt_artifact_mutation_stops_sequence(self):
        self.put(self.crypt_path.parent / 'raw.stdout', b'physical companion')
        self.append_runner('os-test', 'printf changed > "$root/.work/crypt/raw.stdout"\n')
        with self.assertRaisesRegex(RuntimeError, 'crypt input changed'):
            self.execute()
        self.assertFalse((self.work / 'runs/signal-process').exists())

    def test_atomic_artifact_mutation_stops_sequence(self):
        self.put(self.atomic_path.parent / 'raw.stdout', b'physical companion')
        self.append_runner('os-test', 'printf changed > "$root/.work/atomic/raw.stdout"\n')
        with self.assertRaisesRegex(RuntimeError, 'atomic addressable input changed'):
            self.execute()
        self.assertFalse((self.work / 'runs/signal-process').exists())

    def test_wordexp_report_artifact_mutation_stops_sequence(self):
        self.put(self.wordexp_path.parent / 'retained.raw', b'physical companion')
        self.append_runner('os-test', 'printf changed > "$root/.work/wordexp/retained.raw"\n')
        with self.assertRaisesRegex(RuntimeError, 'wordexp profile input changed'):
            self.execute()
        self.assertFalse((self.work / 'runs/signal-process').exists())

    def test_wordexp_expected_input_mutation_stops_sequence(self):
        self.put(self.wordexp_expected_path.parent / 'retained.raw', b'physical companion')
        self.append_runner('os-test', 'printf changed > "$root/.work/wordexp-inputs/retained.raw"\n')
        with self.assertRaisesRegex(RuntimeError, 'wordexp expected native input changed'):
            self.execute()
        self.assertFalse((self.work / 'runs/signal-process').exists())

    def test_frozen_component_order_and_exact_native_arguments(self):
        self.assertEqual([component.id for component in execution.COMPONENTS],
            ['differential', 'os-test', 'signal-process', 'pthread-stress', 'libc-test'])
        for component in execution.COMPONENTS:
            command = execution.component_command(self.root, component, self.product, '/workspace')
            self.assertEqual(command[:2], ['bash', '/workspace/' + component.runner])
            self.assertEqual(command[-1], '/workspace/.work/dynamic/installed')
            self.assertNotIn('--static-sysroot', command)
            self.assertNotIn('docker', command)
        stress = execution.COMPONENTS[3]
        self.assertEqual(list(stress.arguments), ['--source-profile', 'native-v1', '--iterations', '10', '--timeout', '10'])

    def test_complete_execution_runs_once_in_order_and_stays_nonpromoting(self):
        path = self.execute()
        record = execution.validate_receipt(self.root, path)
        self.assertEqual(path.name, 'native-execution.json')
        self.assertEqual((self.root / '.work/order').read_text().splitlines(), [component.id for component in execution.COMPONENTS])
        self.assertEqual(record['status'], 'native-aggregate-verified')
        self.assertIs(record['native_aggregate_complete'], True)
        for key in ('campaign_complete', 'family_completion', 'public_support'):
            self.assertIs(record[key], False)
        replacement = record['io_cancellation_replacement']
        self.assertEqual(replacement['required_operations'], ['READ_FILE', 'ASYNC_LOOP'])
        self.assertEqual(len(replacement['cells']), 18)
        self.assertEqual(set(replacement['selected_dynamic_entries']), set(family_observations.MODES[2:]))
        self.assertIsNone(record['components']['pthread-stress']['observations']['replacement_io_cancellation_receipt'])
        self.assertTrue(all((self.work / 'runs' / component.id / 'receipt.json').is_file() for component in execution.COMPONENTS))

    def test_component_failure_retains_honest_incomplete_state_and_stops_sequence(self):
        self.append_runner('os-test', 'printf "native failure\\n" >&2\nexit 23\n')
        with self.assertRaisesRegex(RuntimeError, '23'):
            self.execute()
        self.assertFalse((self.work / 'native-execution.json').exists())
        incomplete = json.loads((self.work / 'incomplete.json').read_bytes())
        self.assertEqual(incomplete['status'], 'incomplete')
        self.assertEqual(incomplete['completed_components'], ['differential'])
        self.assertEqual(incomplete['failed_component'], 'os-test')
        self.assertEqual(incomplete['not_run'], ['signal-process', 'pthread-stress', 'libc-test'])
        self.assertEqual((self.work / 'runs/os-test/status').read_bytes(), b'23\n')
        self.assertEqual((self.work / 'runs/os-test/stderr').read_bytes(), b'native failure\n')
        self.assertTrue((self.work / 'runs/differential/receipt.json').is_file())
        self.assertFalse((self.work / 'runs/signal-process').exists())

    def test_successful_outer_status_cannot_hide_a_component_judge_failure(self):
        self.append_runner('signal-process', 'printf "1\\n" > "$leaf/raw.status"\n')
        with self.assertRaisesRegex(RuntimeError, 'raw observation failed'):
            self.execute()
        self.assertEqual((self.work / 'runs/signal-process/status').read_bytes(), b'0\n')
        self.assertFalse((self.work / 'native-execution.json').exists())
        self.assertFalse((self.work / 'runs/pthread-stress').exists())

    def test_missing_matrix_io_entry_or_operation_never_executes_a_component(self):
        row = self.matrix['runs']['primary']['io-cancellation']['observations']['scenarios']['owned_io_cancellation']
        row['candidates'].pop('pie-direct')
        with self.assertRaisesRegex(RuntimeError, 'I/O|entry|mode'):
            self.execute()
        self.assertFalse(self.work.exists())
        self.assertFalse((self.root / '.work/order').exists())

    def test_matched_empty_or_missing_read_file_and_async_loop_transcripts_fail(self):
        for missing in (None, 6, 9):
            with self.subTest(missing=missing):
                value = b'' if missing is None else IO_STDOUT.replace(f'blocked-operation {missing} canceled cleanup=21\n'.encode(), b'')
                for label in family.PAIRS:
                    replay = self.matrix['runs'][label]['io-cancellation']
                    leaf = self.root / replay['leaf']
                    row = replay['observations']['scenarios']['owned_io_cancellation']
                    row['oracle'] = self.raw(leaf, 'oracle', value)
                    row['candidates'] = {mode: self.raw(leaf, mode, value) for mode in family_observations.MODES}
                with self.assertRaisesRegex(RuntimeError, 'I/O|READ_FILE|ASYNC_LOOP|transcript'):
                    self.execute()
                self.assertFalse(self.work.exists())

    def test_installed_selection_cannot_be_replaced_by_another_product(self):
        alternate = self.matrix['inputs']['dynamic_products']['reproduction']
        self.matrix['inputs']['dynamic_products']['primary'] = dict(alternate)
        with self.assertRaisesRegex(RuntimeError, 'installed|product'):
            self.execute()
        self.assertFalse(self.work.exists())

    def test_changed_source_or_product_during_execution_cannot_seal(self):
        self.append_runner('differential', 'touch "$root/.work/source-changed"\n')
        with self.assertRaisesRegex(RuntimeError, 'source'):
            self.execute()
        self.assertFalse((self.work / 'native-execution.json').exists())
        self.assertTrue((self.work / 'source-after.json').exists())
        self.assertTrue((self.work / 'incomplete.json').exists())

    def test_product_mutation_is_bound_before_and_after_the_component(self):
        self.append_runner('differential', 'printf changed >> "${!#}/usr/lib/libc.so"\n')
        with self.assertRaisesRegex(RuntimeError, 'product'):
            self.execute()
        self.assertFalse((self.work / 'native-execution.json').exists())
        self.assertNotEqual(json.loads((self.work / 'product-before.json').read_bytes()),
                            json.loads((self.work / 'product-after.json').read_bytes()))

    def test_component_receipts_reject_missing_cells_and_scalar_substitution(self):
        path = self.execute()
        record = json.loads(path.read_bytes())
        record['native_aggregate_complete'] = 1
        self.put(path, record)
        with self.assertRaisesRegex(RuntimeError, 'receipt'):
            execution.validate_receipt(self.root, path)
        shutil.rmtree(self.work / 'runs/os-test')
        with self.assertRaisesRegex(RuntimeError, 'roster'):
            execution.collect(self.root, self.work)

    def test_invocation_cannot_shrink_stress_or_admit_a_static_replay(self):
        path = self.execute()
        invocation = self.work / 'runs/pthread-stress/invocation.json'
        before = invocation.read_bytes()
        for old, new in (('native-v1', 'frozen'), ('10', '1')):
            record = json.loads(before)
            record['command'][record['command'].index(old)] = new
            self.put(invocation, record)
            with self.assertRaisesRegex(RuntimeError, 'invocation'):
                execution.validate_receipt(self.root, path)
        self.put(invocation, before)
        request = json.loads((self.work / 'request.json').read_bytes())
        request['components'] = ['differential']
        self.put(self.work / 'request.json', request)
        with self.assertRaisesRegex(RuntimeError, 'request'):
            execution.validate_receipt(self.root, path)

    def test_leaf_objects_modes_symlinks_and_extra_nodes_are_immutable(self):
        path = self.execute()
        leaf = self.leaf('differential')
        obj = leaf / 'object.bin'
        before, mode = obj.read_bytes(), obj.stat().st_mode & 0o7777
        obj.write_bytes(b'changed canonical object')
        with self.assertRaisesRegex(RuntimeError, 'receipt'):
            execution.validate_receipt(self.root, path)
        obj.write_bytes(before)
        obj.chmod(mode ^ 0o100)
        with self.assertRaisesRegex(RuntimeError, 'receipt'):
            execution.validate_receipt(self.root, path)
        obj.chmod(mode)
        (leaf / 'extra-symlink').symlink_to('/must-not-be-followed')
        with self.assertRaisesRegex(RuntimeError, 'receipt'):
            execution.validate_receipt(self.root, path)
        (leaf / 'extra-symlink').unlink()
        os.mkfifo(leaf / 'extra-fifo')
        with self.assertRaisesRegex(RuntimeError, 'receipt'):
            execution.validate_receipt(self.root, path)

    def test_outer_scratch_cannot_import_or_hide_another_leaf(self):
        self.append_runner('differential', 'mkdir "$TMPDIR/undeclared"\n')
        with self.assertRaisesRegex(RuntimeError, 'scratch|undeclared'):
            self.execute()
        self.assertFalse((self.work / 'native-execution.json').exists())

    def test_fresh_output_cannot_overlap_an_input_or_be_reused(self):
        with self.assertRaisesRegex(RuntimeError, 'overlap|input|product'):
            execution.execute(self.root, self.product / 'aggregate', self.matrix_path, self.crypt_path, self.atomic_path,
                              self.wordexp_path, self.wordexp_expected_path)
        with self.assertRaisesRegex(RuntimeError, 'overlap|input|matrix'):
            execution.execute(self.root, self.matrix_path.parent / 'aggregate', self.matrix_path, self.crypt_path, self.atomic_path,
                              self.wordexp_path, self.wordexp_expected_path)
        self.execute()
        with self.assertRaisesRegex(RuntimeError, 'fresh'):
            self.execute()

    def test_relative_matrix_input_cannot_overlap_output(self):
        with self.assertRaisesRegex(RuntimeError, 'overlap'):
            execution.execute(self.root, self.matrix_path.parent / 'aggregate',
                              Path(self.relative(self.matrix_path)), Path(self.relative(self.crypt_path)),
                              Path(self.relative(self.atomic_path)), Path(self.relative(self.wordexp_path)),
                              Path(self.relative(self.wordexp_expected_path)))
        self.assertFalse((self.matrix_path.parent / 'aggregate').exists())

    def test_predecessor_binding_rejects_reordered_successful_steps(self):
        path = self.execute()
        start = self.work / 'sequence/01-os-test.json'
        record = json.loads(start.read_bytes())
        record['predecessor'] = family.file_identity(self.root, self.work / 'runs/pthread-stress/receipt.json')
        self.put(start, record)
        with self.assertRaisesRegex(RuntimeError, 'sequence|predecessor'):
            execution.validate_receipt(self.root, path)

    def test_host_validation_reuses_container_paths_without_target_execution(self):
        path = self.execute()
        request = json.loads((self.work / 'request.json').read_bytes())
        request['source_mount'] = '/workspace'
        self.put(self.work / 'request.json', request)
        inputs, product = execution.input_matrix(self.root, request)
        predecessor = inputs['family_execution']
        for index, component in enumerate(execution.COMPONENTS):
            step = self.work / 'runs' / component.id
            for name in ('invocation.json', 'stdout'):
                artifact = step / name
                artifact.write_bytes(artifact.read_bytes().replace(str(self.root).encode(), b'/workspace'))
            start = self.work / 'sequence' / f'{index:02d}-{component.id}.json'
            self.put(start, execution.sequence_record(index, component, predecessor, inputs))
            observed = execution.collect_component(self.root, self.work, index, component, inputs, product, '/workspace', predecessor)
            receipt = self.put(step / 'receipt.json', observed)
            predecessor = family.file_identity(self.root, receipt)
        self.put(path, execution.collect(self.root, self.work))
        with patch.object(family, 'run_step', side_effect=AssertionError('component reexecuted')), \
             patch.object(execution, 'require_live_oracle', side_effect=AssertionError('host consulted live target oracle')):
            record = execution.validate_receipt(self.root, path)
        self.assertEqual(list(record['components']), [component.id for component in execution.COMPONENTS])

    def test_native_receipt_reader_returns_the_single_validated_matrix(self):
        path = self.execute()
        original_validate_matrix = family.validate_receipt
        with patch.object(family, 'validate_receipt', wraps=original_validate_matrix) as validate_matrix:
            record, matrix = execution.validate_receipt_with_matrix(self.root, path)
        self.assertEqual(validate_matrix.call_count, 1)
        self.assertEqual(record, json.loads(path.read_text(encoding='utf-8')))
        self.assertEqual(matrix['schema'], family.SCHEMA)
        self.assertEqual(matrix['status'], 'workload-matrix-verified')


class NativeFamilyAdmissionTests(unittest.TestCase):
    """The admission layer must consume, never synthesize, matrix evidence."""

    def setUp(self):
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64}
        self.matrix = self.matrix_receipt()
        self.native = {
            'schema': execution.SCHEMA,
            'status': 'native-aggregate-verified',
            'inputs': {'source': self.source},
            'components': {component.id: {} for component in execution.COMPONENTS},
            'io_cancellation_replacement': {
                'required_operations': ['READ_FILE', 'ASYNC_LOOP'],
                'cells': {str(index): {} for index in range(18)},
            },
            'native_aggregate_complete': True,
            'campaign_complete': False,
            'family_completion': False,
            'public_support': False,
        }

    def matrix_receipt(self):
        roster = workloads.validate_workloads(root=ROOT)
        by_workload = {workload.id: workload for workload in roster}
        runs = {
            label: {
                workload.id: {'receipt': {
                    'path': f'.work/fixture/{label}/{workload.id}/receipt.json',
                    'sha256': (label[0] + workload.id[0]) * 32,
                    'size': 1,
                }}
                for workload in roster
            }
            for label in family.PAIRS
        }
        catalog = execution.admission_catalog(ROOT)
        owners = workloads.EXPECTED_PRIMARY_OWNERS
        spelling_evidence = {'static': {}, 'dynamic': {}}
        for symbol in owners:
            dynamic_owner = owners[symbol]
            static_owner = workloads.STATIC_SUPPLEMENTAL_OWNERS.get(symbol, dynamic_owner)
            spelling_evidence['static'][symbol] = {
                'workload': static_owner,
                'cells': {
                    f'{label}:{mode}': runs[label][static_owner]['receipt']
                    for label in family.PAIRS for mode in workloads.STATIC_LINKAGES
                },
            }
            spelling_evidence['dynamic'][symbol] = {
                'workload': dynamic_owner,
                'case': by_workload[dynamic_owner].dynamic_case,
                'cells': {
                    f'{family.PAIRS[label]}:{mode}:{entry}': runs[label][dynamic_owner]['receipt']
                    for label in family.PAIRS for mode in workloads.DYNAMIC_LINKAGES
                    for entry in workloads.DYNAMIC_ENTRIES
                },
            }
        self.assertEqual(sum(len(capability.symbols) for capability in catalog.capabilities.values()), 149)
        return {
            'workloads': [dataclasses.asdict(workload) for workload in roster],
            'runs': runs,
            'spelling_evidence': spelling_evidence,
        }

    def test_admission_proves_every_frozen_capability_spelling_and_product_cell(self):
        proof = execution.admission_proof(ROOT, self.native, self.matrix)
        self.assertEqual(proof['capability_count'], 9)
        self.assertEqual(proof['symbol_count'], 149)
        self.assertEqual(proof['static_spelling_cell_count'], 149 * 6)
        self.assertEqual(proof['dynamic_spelling_cell_count'], 149 * 12)
        self.assertEqual(set(proof['capability_symbols']), {
            'filesystem.lchmod-unsupported', 'filesystem.stat-compat', 'filesystem.directory',
            'filesystem.extensions', 'process.control', 'process.credentials',
            'process.environment-mutation', 'process.signal', 'system.kernel-admin',
        })
        self.assertEqual(set(proof['symbol_workloads']),
                         set(workloads.EXPECTED_PRIMARY_OWNERS))
        self.assertEqual(
            proof['ledger_dependencies']['direct_dependencies'],
            [
                {'id': 'oracle.musl-toolchain', 'status': 'foundation-verified'},
                {'id': 'libc.headers-layouts', 'status': 'foundation-verified'},
                {'id': 'libc.raw-syscall', 'status': 'foundation-verified'},
            ],
        )

    def test_admission_inputs_reuses_matrix_from_native_receipt_validation(self):
        matrix = {
            'schema': family.SCHEMA,
            'status': 'workload-matrix-verified',
            'family': 'libc.posix-runtime',
            'native_aggregate_complete': False,
            'family_completion': False,
            'public_support': False,
            'inputs': {'source': self.source},
        }
        native = {
            'inputs': {
                'family_execution': {
                    'path': '.work/test/matrix/execution.json',
                    'sha256': 'a' * 64,
                    'size': 1,
                },
                'source': self.source,
            },
        }
        matrix_path = ROOT / native['inputs']['family_execution']['path']
        with patch.object(execution, 'validate_receipt_with_matrix',
                          return_value=(native, matrix)) as validate, \
             patch.object(execution, 'source_identity', return_value=self.source), \
             patch.object(family, 'file_identity',
                          return_value=native['inputs']['family_execution']) as matrix_identity:
            observed_native, observed_matrix, _, observed_path = execution.admission_inputs(
                ROOT, ROOT / '.work/test/native/native-execution.json')
        validate.assert_called_once()
        matrix_identity.assert_called_once_with(ROOT, matrix_path)
        self.assertIs(observed_native, native)
        self.assertIs(observed_matrix, matrix)
        self.assertEqual(observed_path, matrix_path)

    def test_admission_rejects_one_missing_spelling_or_one_substituted_cell(self):
        self.matrix['spelling_evidence']['dynamic'].pop('fork')
        with self.assertRaisesRegex(RuntimeError, 'spelling'):
            execution.admission_proof(ROOT, self.native, self.matrix)

        self.matrix = self.matrix_receipt()
        self.matrix['spelling_evidence']['static']['fork']['cells']['primary:pie'] = {
            'path': '.work/substituted.json', 'sha256': '0' * 64, 'size': 1,
        }
        with self.assertRaisesRegex(RuntimeError, 'static spelling receipt'):
            execution.admission_proof(ROOT, self.native, self.matrix)

    def test_admission_rejects_a_planned_direct_ledger_dependency(self):
        document = tomllib.loads((ROOT / 'compat/x86_64/parity.toml').read_text(encoding='utf-8'))
        for entry in document['family']:
            if entry['id'] == 'libc.raw-syscall':
                entry['status'] = 'planned'
                break
        else:
            self.fail('fixture ledger lacks libc.raw-syscall')
        with patch.object(execution.tomllib, 'load', return_value=document):
            with self.assertRaisesRegex(RuntimeError, 'depends on unverified ledger family: libc.raw-syscall'):
                execution.admission_dependency_closure(ROOT)

    def test_dependency_closure_allows_a_clean_candidate_transition_revision(self):
        document = tomllib.loads((ROOT / 'compat/x86_64/parity.toml').read_text(encoding='utf-8'))
        for entry in document['family']:
            if entry['id'] == 'libc.posix-runtime':
                entry['status'] = 'foundation-verified'
                break
        else:
            self.fail('fixture ledger lacks libc.posix-runtime')
        with patch.object(execution.tomllib, 'load', return_value=document):
            closure = execution.admission_dependency_closure(ROOT)
        self.assertEqual(closure['direct_dependencies'], [
            {'id': 'oracle.musl-toolchain', 'status': 'foundation-verified'},
            {'id': 'libc.headers-layouts', 'status': 'foundation-verified'},
            {'id': 'libc.raw-syscall', 'status': 'foundation-verified'},
        ])

    def test_physical_admission_revalidates_both_inputs_and_cannot_claim_promotion(self):
        scratch = ROOT / '.work/x86_64/test-posix-family-admission'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            matrix_path = work / 'matrix/execution.json'
            native_path = work / 'native/native-execution.json'
            matrix_path.parent.mkdir(parents=True)
            native_path.parent.mkdir(parents=True)
            matrix = copy.deepcopy(self.matrix)
            matrix.update({
                'schema': family.SCHEMA,
                'status': 'workload-matrix-verified',
                'family': 'libc.posix-runtime',
                'inputs': {'source': self.source},
                'native_aggregate_complete': False,
                'family_completion': False,
                'public_support': False,
            })
            # This is deliberately a disk JSON round trip: dataclass tuples
            # in the workload contract become JSON arrays in the real matrix.
            matrix = json.loads(json.dumps(matrix))
            self.assertIsInstance(matrix['workloads'][0]['source_object_roles'], list)
            matrix_path.write_text(json.dumps(matrix), encoding='utf-8')
            native = copy.deepcopy(self.native)
            native['inputs']['family_execution'] = family.file_identity(ROOT, matrix_path)
            native_path.write_text(json.dumps(native), encoding='utf-8')

            def native_receipt_with_matrix(root, path):
                self.assertEqual(path, native_path)
                observed_native = json.loads(native_path.read_text(encoding='utf-8'))
                observed_matrix = json.loads(matrix_path.read_text(encoding='utf-8'))
                if not execution.same_json(family.file_identity(root, matrix_path),
                                           observed_native['inputs']['family_execution']):
                    raise RuntimeError('family matrix receipt changed')
                return observed_native, observed_matrix

            with patch.object(execution, 'source_identity', return_value=self.source) as current_source, \
                 patch.object(execution, 'validate_receipt_with_matrix',
                              side_effect=native_receipt_with_matrix) as native_receipt:
                original_proof = execution.admission_proof
                proof_calls = 0

                def mutate_matrix_after_first_proof(root, observed_native, observed_matrix):
                    nonlocal proof_calls
                    result = original_proof(root, observed_native, observed_matrix)
                    proof_calls += 1
                    if proof_calls == 1:
                        changed_matrix = json.loads(matrix_path.read_text(encoding='utf-8'))
                        changed_matrix['workloads'][0]['id'] = 'swapped-after-proof'
                        matrix_path.write_text(json.dumps(changed_matrix), encoding='utf-8')
                    return result

                with patch.object(execution, 'admission_proof', side_effect=mutate_matrix_after_first_proof):
                    with self.assertRaisesRegex(RuntimeError, 'family matrix receipt changed'):
                        execution.admit(ROOT, (work / 'mutated').relative_to(ROOT), native_path.relative_to(ROOT))
                self.assertEqual(native_receipt.call_count, 3)

                matrix_path.write_text(json.dumps(matrix), encoding='utf-8')
                output = work / 'admission'
                receipt = execution.admit(ROOT, output.relative_to(ROOT), native_path.relative_to(ROOT))
                record = execution.validate_admission_receipt(ROOT, receipt)
                self.assertTrue(record['family_completion'])
                self.assertTrue(record['native_aggregate_complete'])
                for flag in ('campaign_complete', 'promotion_ready', 'public_support'):
                    self.assertIs(record[flag], False)
                current_source.return_value = {**self.source, 'revision': 'c' * 40}
                with self.assertRaisesRegex(RuntimeError, 'do not share current source'):
                    execution.validate_admission_receipt(ROOT, receipt)
                current_source.return_value = self.source
                changed = json.loads(receipt.read_text())
                changed['proof']['symbol_count'] = 148
                receipt.write_text(json.dumps(changed), encoding='utf-8')
                with self.assertRaisesRegex(RuntimeError, 'admission receipt changed'):
                    execution.validate_admission_receipt(ROOT, receipt)


if __name__ == '__main__':
    unittest.main()
