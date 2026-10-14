"""Retained compiler products for the initial-page commit counter control."""
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m7_statistics_initial_page_commit_fault as producer
import x86_64_foundation_gate_receipts as reader


class InitialPageCommitProducts(unittest.TestCase):
    def test_success_retains_both_executed_compiler_products(self):
        self._produce()

    def test_cold_arena_page_prefix_uses_its_driver_markers_for_both_outputs(self):
        receipt = self._produce(cold_arena_prefix=True)
        self.assertEqual(receipt['c_trace'], {'producer': 'c'})
        self.assertEqual(receipt['rust_trace'], {'producer': 'rust'})

    def test_cold_arena_page_prefix_selector_checks_the_producer_shape(self):
        trace = {
            "profile.level": "2", "profile.on_demand": "1", "profile.eager_arena": "0",
            "profile.show_errors": "1", "before.pages": "0,0,0", "before.arena_count": "0",
            "fault.nonnull": "1", "fault.commit_size": "114688", "fault.failures": "1",
            "fault.warnings": "1", "fault.arena_count": "1", "recovery.nonnull": "1",
            "recovery.client_bytes": "1", "recovery.clients_distinct": "1",
            "recovery.clients_owned": "1", "recovery.failures": "1", "recovery.warnings": "1",
            "recovery.arena_count": "1", "freed.failures": "1", "freed.warnings": "1",
            "freed.arena_count": "1",
        }
        producer.require_commit_failure_shape(
            trace, "complete cold-arena page-prefix trace", cold_arena_prefix=True,
        )
        for key, value in (
            ("fault.commit_size", "131072"),
            ("recovery.clients_owned", "0"),
            ("recovery.arena_count", "2"),
        ):
            with self.subTest(key=key), self.assertRaises(producer.harness.HarnessError):
                producer.require_commit_failure_shape(
                    {**trace, key: value}, key, cold_arena_prefix=True,
                )

    def test_compiler_program_outside_owned_target_preserves_failure_inputs(self):
        self._produce(escaped=True)

    def test_guarded_receiver_requires_live_options_and_surviving_clients(self):
        for profile, (level, debug) in producer.PROFILES.items():
            for faulted in (False, True):
                with self.subTest(profile=profile, faulted=faulted):
                    trace = {"profile.level": str(level), "profile.debug": str(int(debug)),
                             "profile.guarded": "1", "profile.faulted": str(int(faulted)),
                             "profile.sample_rate": "0", "profile.theap_sample_rate": "0",
                             "profile.on_demand": "1", "profile.eager_arena": "0", "profile.show_errors": "1",
                             "fault.nonnull": "1", "fault.commit_size": "114688", "recovery.nonnull": "1",
                             "recovery.client_bytes": "1", "recovery.clients_distinct": "1", "recovery.clients_owned": "1"}
                    for stage in ('fault', 'recovery', 'freed'):
                        trace[stage + '.failures'] = str(int(faulted))
                        trace[stage + '.warnings'] = str(int(faulted))
                        if level == 0:
                            trace[stage + '.normal'] = '0,0,0'
                        if level < 2:
                            trace[stage + '.requested'] = '0,0,0'
                    producer.require_commit_failure_shape(trace, 'current raw control', profile=profile, faulted=faulted)
                    for key, value in [('profile.sample_rate', '4000'), ('profile.theap_sample_rate', '4000'),
                                       ('profile.guarded', '0'), ('profile.level', '3'),
                                       ('recovery.client_bytes', '0'), ('recovery.clients_distinct', '0'),
                                       ('recovery.clients_owned', '0'), ('fault.failures', str(int(not faulted)))]:
                        altered = dict(trace);altered[key] = value
                        with self.assertRaises(producer.harness.HarnessError):
                            producer.require_commit_failure_shape(altered, 'altered raw control', profile=profile, faulted=faulted)

    def _produce(self, *, escaped=False, cold_arena_prefix=False):
        scratch = producer.harness.WORK_ROOT / 'tmp/initial-page-commit-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as name, ExitStack() as stack:
            root = Path(name)
            report = root / 'report.json'
            artifacts = root / 'artifacts'
            selected_driver = (producer.m7.STATISTICS_COLD_ARENA_PAGE_PREFIX_DRIVER
                               if cold_arena_prefix else producer.DRIVER)
            selected_test = ('page::tests::failed_cold_arena_page_prefix_commit_recovers_source_statistics'
                             if cold_arena_prefix else producer.TEST)
            selected_begin = (producer.m7.STATISTICS_COLD_ARENA_PAGE_PREFIX_TRACE_BEGIN
                              if cold_arena_prefix else producer.BEGIN)
            selected_end = (producer.m7.STATISTICS_COLD_ARENA_PAGE_PREFIX_TRACE_END
                            if cold_arena_prefix else producer.END)
            if cold_arena_prefix:
                report = artifacts / 'statistics-cold-arena-page-prefix-fault.json'
            manifest = producer.harness.ROOT / 'crabc-mimalloc/Cargo.toml'
            emitted = root / ('other-target' if escaped else 'target') / 'cargo-emitted-program'
            emitted.parent.mkdir()
            emitted.write_bytes(b'native compiler product')
            (root / 'archive').write_bytes(b'pinned source archive')
            source = root / 'upstream'
            source.mkdir()
            commands = []

            def command(argv, **kwargs):
                commands.append(argv)
                stdout = 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
                if '-o' in argv:
                    Path(argv[argv.index('-o') + 1]).write_bytes(b'C compiler product')
                    stdout = ''
                if '--no-run' in argv:
                    stdout = json.dumps({'reason': 'compiler-artifact',
                        'manifest_path': str(manifest), 'target': {
                            'name': 'crabc_mimalloc', 'src_path': str(manifest.parent / 'src/lib.rs'),
                            'kind': ['lib']}, 'profile': {'test': True},
                        'features': ['mi-stat-1', 'mi-stat-2'], 'executable': str(emitted)})
                elif '-o' not in argv:
                    side = 'rust' if Path(argv[0]) == emitted else 'c'
                    stdout = (f'{selected_begin}\nproducer={side}\n{selected_end}\n'
                              + (stdout if side == 'rust' else ''))
                return {'status': 0, 'stdout': stdout, 'stderr': '', 'command': argv}

            replacements = [(producer, 'REPORT', report), (producer.m7, 'ARTIFACTS', artifacts),
                (sys, 'argv', ['producer'] + (['--cold-arena-page-prefix'] if cold_arena_prefix else [])),
                (producer.harness, 'WORK_ROOT', root),
                (producer.harness, 'require_native_x86_64', lambda **kwargs: dict(execution_mode='native', host_architecture='x86_64', image_id='sha256:' + 'a' * 64)),
                (producer.harness, 'load_pin', lambda: dict(tag='v3.5.0', revision='pin', sha256='hash', archive_root='upstream')),
                (producer.harness, 'fetch_archive', lambda *args: root / 'archive'),
                (producer.harness, 'temporary_directory', lambda *args: tempfile.TemporaryDirectory(dir=root)),
                (producer.harness, 'safe_extract', lambda *args: source),
                (producer.harness, 'require_tool', lambda name: name),
                (producer.harness, 'command_record', command),
                (producer.m7.engine, 'git_provenance', lambda: {}),
                (producer.m7.integrated, 'source_seal', lambda: {}),
                (producer.m7, 'compare_options_traces', lambda *args: None),
                (producer, 'require_commit_failure_shape', lambda *args, **kwargs: None)]
            for owner, name, value in replacements:
                stack.enter_context(mock.patch.object(owner, name, value))
            if escaped:
                with self.assertRaisesRegex(producer.harness.HarnessError, 'escapes its owned Cargo target'):
                    producer.main()
                self.assertFalse(report.exists())
                self.assertEqual(json.loads((report.with_suffix('') / 'c-build.json').read_text())['status'], 0)
                self.assertEqual(json.loads((report.with_suffix('') / 'c-execute.json').read_text())['status'], 0)
                self.assertTrue((report.with_suffix('') / 'rust-build.json').is_file())
                return
            self.assertEqual(producer.main(), 0)
            receipt = json.loads(report.read_text())
            c_program = Path(receipt['c_run']['command'][0])
            rust_program = Path(receipt['rust_test']['command'][0])
            self.assertNotEqual(rust_program.name, 'cargo')
            self.assertEqual(c_program.read_bytes(), b'C compiler product')
            self.assertEqual(rust_program, emitted)
            self.assertEqual(rust_program.read_bytes(), emitted.read_bytes())
            self.assertEqual(receipt['physical_inputs']['unit_program']['artifact'], producer.harness.artifact_record(emitted))
            self.assertEqual((report.with_suffix('') / 'compiled-input.c').read_bytes(), selected_driver.read_bytes())
            artifact = json.loads((report.with_suffix('') / 'compiler-artifact.json').read_text())
            self.assertEqual(artifact['executable'], str(emitted))
            self.assertEqual(artifact['features'], ['mi-stat-1', 'mi-stat-2'])
            reader.authenticate_artifacts(receipt['physical_inputs'], source)
            reader.authenticate_unit_program(receipt['physical_inputs']['unit_program'], features=['mi-stat-1', 'mi-stat-2'])
            self.assertIn('--exact', receipt['rust_test']['command'])
            self.assertIn(selected_test, receipt['rust_test']['command'])
            return receipt


if __name__ == '__main__':
    unittest.main()
