"""Family execution retains failed commands and seals physical fixture trees."""

import json
from dataclasses import dataclass
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_posix_family_execution as execution


class FamilyExecutionTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/test-posix-family-execution'
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / '.work/run'
        self.work.mkdir(parents=True)

    def test_case_environment_preserves_pinned_rust_and_checkout_git_access(self):
        from generate_qualification_manifest import EXECUTION_CONTRACT
        environment = execution.case_environment(self.root, self.work / 'step', '/workspace')
        self.assertEqual(environment['PATH'].split(':')[0], EXECUTION_CONTRACT['rust_bin_directory'])
        self.assertEqual(environment.get('RUSTUP_HOME'), EXECUTION_CONTRACT['rustup_home'])
        self.assertEqual(environment.get('CARGO_HOME'), '/workspace/.work/x86_64/cargo')
        self.assertEqual(environment.get('GIT_CONFIG_COUNT'), '1')
        self.assertEqual(environment.get('GIT_CONFIG_KEY_0'), 'safe.directory')
        self.assertEqual(environment.get('GIT_CONFIG_VALUE_0'), '/workspace')
        self.assertNotIn('LD_LIBRARY_PATH', environment)
        self.assertNotIn('PYTHONPATH', environment)

    def test_failed_command_keeps_exact_raw_results_and_no_success_receipt(self):
        step = self.work / 'failure'
        command = [sys.executable, '-c',
                   "import sys;sys.stdout.buffer.write(b'out\\x00\\n');"
                   "sys.stderr.buffer.write(b'err\\xff\\n');sys.exit(17)"]
        with self.assertRaisesRegex(execution.ExecutionError, 'exit status 17'):
            execution.run_step(self.root, step, command, {'PATH': os.environ['PATH']})
        self.assertEqual((step / 'stdout').read_bytes(), b'out\x00\n')
        self.assertEqual((step / 'stderr').read_bytes(), b'err\xff\n')
        self.assertEqual((step / 'status').read_bytes(), b'17\n')
        self.assertEqual(json.loads((step / 'invocation.json').read_text())['command'], command)
        self.assertFalse((step / 'receipt.json').exists())

    def test_success_recomputes_invocation_and_requires_fresh_directory(self):
        step = self.work / 'success'
        command = [sys.executable, '-c', 'print("pass")']
        environment = {'PATH': os.environ['PATH']}
        execution.run_step(self.root, step, command, environment)
        execution.check_step(self.root, step, command, environment)
        (step / 'status').write_text('False\n')
        with self.assertRaisesRegex(execution.ExecutionError, 'status'):
            execution.check_step(self.root, step, command, environment)
        with self.assertRaisesRegex(execution.ExecutionError, 'fresh'):
            execution.run_step(self.root, step, command, environment)

    def test_interruption_reaps_the_child_and_records_its_actual_status(self):
        step = self.work / 'interrupted'
        child = [sys.executable, '-c', 'import time; print("ready", flush=True); time.sleep(60)']
        supervisor = subprocess.Popen([sys.executable, '-B', '-c',
            'import json,sys; from pathlib import Path; '
            'sys.path.insert(0,sys.argv[1]); import owned_posix_family_execution as e; '
            'e.run_step(Path(sys.argv[2]),Path(sys.argv[3]),json.loads(sys.argv[4]),{"PATH":sys.argv[5]})',
            str(ROOT / 'compat/x86_64'), str(self.root), str(step), json.dumps(child), os.environ['PATH']],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (step / 'stdout').exists() or (step / 'stdout').read_bytes() != b'ready\n':
                self.assertLess(time.monotonic(), deadline, 'child did not start')
                self.assertIsNone(supervisor.poll(), 'supervisor exited before interruption')
                time.sleep(0.01)
            supervisor.send_signal(signal.SIGINT)
            supervisor.wait(timeout=5)
            self.assertEqual((step / 'status').read_bytes(), b'-15\n')
        finally:
            try:
                os.killpg(supervisor.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            supervisor.wait()

    def test_changed_command_or_missing_stderr_cannot_validate(self):
        step = self.work / 'command'
        command = [sys.executable, '-c', 'pass']
        environment = {'PATH': os.environ['PATH']}
        execution.run_step(self.root, step, command, environment)
        with self.assertRaisesRegex(execution.ExecutionError, 'invocation'):
            execution.check_step(self.root, step, command + ['extra'], environment)
        (step / 'stderr').unlink()
        with self.assertRaises(execution.ExecutionError):
            execution.check_step(self.root, step, command, environment)

    def test_snapshot_preserves_fixture_nodes_without_following_links(self):
        fixture = self.work / 'fixture'
        fixture.mkdir()
        (fixture / 'regular').write_bytes(b'payload')
        (fixture / 'regular').chmod(0o640)
        (fixture / 'outside').symlink_to('/nonexistent/never-follow')
        os.mkfifo(fixture / 'fifo', 0o600)
        local_socket = socket.socket(socket.AF_UNIX)
        self.addCleanup(local_socket.close)
        # Linux sockaddr_un has a short path limit; bind relative to a directory
        # descriptor using /proc rather than moving scratch outside the checkout.
        descriptor = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        local_socket.bind(f'/proc/self/fd/{descriptor}/socket')
        snapshot = execution.snapshot(fixture)
        self.assertEqual(snapshot['regular']['mode'], 0o640)
        self.assertEqual(snapshot['regular']['size'], 7)
        self.assertEqual(snapshot['outside']['target'], '/nonexistent/never-follow')
        self.assertEqual(snapshot['fifo']['kind'], 'fifo')
        self.assertEqual(snapshot['socket']['kind'], 'socket')
        self.assertNotIn('sha256', snapshot['fifo'])
        (fixture / 'regular').write_bytes(b'changed')
        self.assertNotEqual(execution.snapshot(fixture), snapshot)

    def test_declared_leaf_must_be_unique_and_inside_exact_step_scratch(self):
        step = self.work / 'leaf'
        (step / 'tmp/retained').mkdir(parents=True)
        log = step / 'stdout'
        leaf = step / 'tmp/retained'
        log.write_text(f'evidence: {leaf}\nevidence: {leaf}\n')
        self.assertEqual(execution.leaf_directory(self.root, step, str(self.root)), leaf)
        (step / 'tmp/second').mkdir()
        log.write_text(f'evidence: {leaf}\nevidence: {step / "tmp/second"}\n')
        with self.assertRaisesRegex(execution.ExecutionError, 'one retained'):
            execution.leaf_directory(self.root, step, str(self.root))
        outside = self.work / 'unrelated'
        outside.mkdir()
        log.write_text(f'evidence: {outside}\n')
        with self.assertRaisesRegex(execution.ExecutionError, 'scratch'):
            execution.leaf_directory(self.root, step, str(self.root))

    def test_extra_undeclared_scratch_file_is_rejected(self):
        step = self.work / 'extra'
        leaf = step / 'tmp/retained'
        leaf.mkdir(parents=True)
        (step / 'stdout').write_text(f'evidence: {leaf}\n')
        (step / 'tmp/unsealed').write_bytes(b'not included in leaf snapshot')
        with self.assertRaisesRegex(execution.ExecutionError, 'undeclared'):
            execution.leaf_directory(self.root, step, str(self.root))

    def test_object_comparison_requires_all_three_products_and_every_role(self):
        records = {product: {'consumer': 'a' * 64, 'child': 'b' * 64}
                   for product in execution.PAIRS}
        execution.identical_objects(records)
        records['extracted']['child'] = 'c' * 64
        with self.assertRaisesRegex(execution.ExecutionError, 'object'):
            execution.identical_objects(records)
        records['extracted'].pop('child')
        with self.assertRaises(execution.ExecutionError):
            execution.identical_objects(records)
        records.pop('reproduction')
        with self.assertRaisesRegex(execution.ExecutionError, 'product'):
            execution.identical_objects(records)

    def test_frozen_spellings_bind_all_cells_and_keep_static_fork_explicit(self):
        import owned_posix_family_workloads as workloads
        records = {label: {workload.id: {'receipt': f'{label}/{workload.id}/receipt.json'}
                          for workload in workloads.WORKLOADS} for label in execution.PAIRS}
        result = execution.spelling_evidence(workloads.WORKLOADS, records)
        self.assertEqual(len(result['static']), 149)
        self.assertEqual(len(result['dynamic']), 149)
        self.assertEqual(result['static']['fork']['workload'], 'static-fork')
        self.assertEqual(result['dynamic']['fork']['workload'], 'fork')
        for record in result['static'].values():
            self.assertEqual(set(record['cells']), set(workloads.STATIC_CELLS))
        for record in result['dynamic'].values():
            self.assertEqual(set(record['cells']), set(workloads.DYNAMIC_CELLS))
        with self.assertRaisesRegex(execution.ExecutionError, 'static spelling workload is absent'):
            execution.spelling_evidence(tuple(item for item in workloads.WORKLOADS if item.id != 'static-fork'), records)


@dataclass(frozen=True)
class ObjectRole:
    role: str = 'application'
    source: str = 'fixture.c'
    object_path: str = 'workload.o'


@dataclass(frozen=True)
class Workload:
    id: str = 'fixture'
    script: str = 'runner.sh'
    dynamic_case: str = 'fork'
    source_object_roles: tuple = (ObjectRole(),)
    product_scope: str = 'both'
    required_supplementary_sources: tuple = ()
    primary_symbols: tuple = ('fork',)


class FamilyMatrixTests(unittest.TestCase):
    """Run the coordinator's real subprocess/receipt path in an isolated root.

    Product validity and C semantics have their own hard judges. Here those
    boundaries are explicit fixtures so receipt reconstruction, immutable
    objects, product scheduling and failure retention remain independently
    testable without rebuilding six toolchains.
    """
    def setUp(self):
        FamilyExecutionTests.setUp(self)
        self.source = {'revision': '1' * 40, 'content_sha256': '2' * 64}
        (self.root / 'fixture.c').write_text('source-bound workload\n')
        (self.root / 'runner.sh').write_text(
            '#!/bin/bash\nset -eu\n'
            'leaf="$TMPDIR/retained"\nmkdir "$leaf"\n'
            'printf "evidence: %s\\n" "$leaf"\n'
            'printf "one canonical object\\n" > "$leaf/workload.o"\n'
            'printf "observed runtime result\\n" > "$leaf/observation"\n'
        )
        self.products = {}
        for label in execution.PAIRS:
            self.products[label] = {}
            for kind in ('static', 'dynamic'):
                product = self.work / 'products' / label / kind
                product.mkdir(parents=True)
                self.products[label][kind] = product
        for name in ('static.json', 'dynamic.json'):
            (self.work / name).write_text('{}\n')
        self.inputs = {'source': self.source, 'dynamic_work': '.work/oracle', 'oracle': {}}
        self.run = self.work / 'execution'
        self.patch(execution, 'input_products', return_value=(self.inputs, self.products))
        self.patch(execution, 'workload_roster', return_value=(Workload(),))
        self.patch(execution.static_products, 'source_identity', return_value=self.source)
        import owned_dynamic_qualification as dynamic
        self.patch(dynamic, 'require_live_oracle')
        import owned_posix_family_observations as observations
        def collect_observation(case, leaf, *, static_required, root):
            self.assertEqual(case, 'fixture')
            self.assertTrue(static_required)
            return {'observation_sha256': execution.digest(leaf / 'observation')}
        self.patch(observations, 'collect', side_effect=collect_observation)

    def patch(self, target, attribute, **kwargs):
        context = patch.object(target, attribute, **kwargs)
        value = context.start()
        self.addCleanup(context.stop)
        return value

    def execute(self):
        return execution.execute(self.root, self.run, self.work / 'static.json', self.work / 'dynamic.json')

    def test_complete_matrix_reconstructs_from_real_steps_and_stays_nonpromoting(self):
        path = self.execute()
        record = execution.validate_receipt(self.root, path)
        self.assertEqual(set(record['runs']), set(execution.PAIRS))
        self.assertIs(record['family_completion'], False)
        self.assertIs(record['native_aggregate_complete'], False)
        self.assertIs(record['public_support'], False)
        for label, dynamic in execution.PAIRS.items():
            invocation = execution.read(self.run / 'runs' / label / 'fixture/invocation.json')
            self.assertEqual(invocation['command'], ['bash', str(self.root / 'runner.sh'),
                '--static-sysroot', str(self.products[label]['static']), str(self.products[label]['dynamic'])])
            self.assertEqual(record['runs'][label]['fixture']['dynamic_product'], dynamic)

    def test_missing_product_or_changed_scalar_receipt_is_rejected(self):
        path = self.execute()
        record = execution.read(path)
        record['family_completion'] = 0
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(execution.ExecutionError, 'receipt changed'):
            execution.validate_receipt(self.root, path)
        import shutil
        shutil.rmtree(self.run / 'runs/reproduction')
        with self.assertRaisesRegex(execution.ExecutionError, 'product roster'):
            execution.collect(self.root, self.run)

    def test_one_product_recompiles_a_different_object_and_cannot_seal(self):
        runner = self.root / 'runner.sh'
        runner.write_text(runner.read_text() +
            'case "$TMPDIR" in *reproduction*) printf "different object\\n" > "$leaf/workload.o" ;; esac\n')
        with self.assertRaisesRegex(execution.ExecutionError, 'object bytes'):
            self.execute()
        self.assertFalse((self.run / 'execution.json').exists())
        self.assertTrue((self.run / 'source-after.json').exists())

    def test_leaf_failure_preserves_prior_results_without_matrix_receipt(self):
        runner = self.root / 'runner.sh'
        runner.write_text(runner.read_text() +
            'case "$TMPDIR" in *reproduction*) printf "contained failure\\n" >&2; exit 23 ;; esac\n')
        with self.assertRaisesRegex(execution.ExecutionError, 'exit status 23'):
            self.execute()
        self.assertTrue((self.run / 'runs/primary/fixture/receipt.json').exists())
        self.assertEqual((self.run / 'runs/reproduction/fixture/status').read_bytes(), b'23\n')
        self.assertEqual((self.run / 'runs/reproduction/fixture/stderr').read_bytes(), b'contained failure\n')
        self.assertFalse((self.run / 'execution.json').exists())

    def test_object_or_fixture_mutation_invalidates_retained_case_receipt(self):
        path = self.execute()
        leaf = self.run / 'runs/extracted/fixture/tmp/retained'
        (leaf / 'workload.o').write_bytes(b'changed')
        with self.assertRaisesRegex(execution.ExecutionError, 'workload receipt changed'):
            execution.validate_receipt(self.root, path)

    def test_container_mount_records_validate_on_host_without_reexecution(self):
        path = self.execute()
        request = execution.read(self.run / 'request.json')
        request['source_mount'] = '/workspace'
        (self.run / 'request.json').write_text(json.dumps(request))
        for label in execution.PAIRS:
            step = self.run / 'runs' / label / 'fixture'
            # These bytes model the original container-produced invocation and
            # declared leaf path, while files themselves stay in the host tree.
            for name in ('invocation.json', 'stdout'):
                item = step / name
                item.write_text(item.read_text().replace(str(self.root), '/workspace'))
            observed = execution.collect_step(self.root, self.run, label, Workload(),
                                               self.products[label], '/workspace')
            (step / 'receipt.json').write_text(json.dumps(observed))
        path.write_text(json.dumps(execution.collect(self.root, self.run)))
        with patch.object(execution.subprocess, 'Popen', side_effect=AssertionError('workload reexecuted')):
            record = execution.validate_receipt(self.root, path)
        self.assertEqual(set(record['runs']), set(execution.PAIRS))


if __name__ == '__main__':
    unittest.main()
