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


class InitialPageCommitProducts(unittest.TestCase):
    def test_success_retains_both_executed_compiler_products(self):
        with tempfile.TemporaryDirectory() as name, ExitStack() as stack:
            root = Path(name)
            report = root / 'report.json'
            manifest = producer.harness.ROOT / 'crabc-mimalloc/Cargo.toml'
            emitted = root / 'cargo-emitted-program'
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
                if '--no-run' in argv:
                    stdout = json.dumps({'reason': 'compiler-artifact',
                        'manifest_path': str(manifest), 'target': {
                            'name': 'crabc_mimalloc', 'src_path': str(manifest.parent / 'src/lib.rs'),
                            'kind': ['lib']}, 'profile': {'test': True},
                        'features': ['mi-stat-1', 'mi-stat-2'], 'executable': str(emitted)})
                return {'status': 0, 'stdout': stdout, 'stderr': '', 'command': argv}

            replacements = [(producer, 'REPORT', report), (sys, 'argv', ['producer']),
                (producer.harness, 'require_native_x86_64', lambda **kwargs: dict(execution_mode='native', host_architecture='x86_64', image_id='sha256:' + 'a' * 64)),
                (producer.harness, 'load_pin', lambda: dict(tag='v3.5.0', revision='pin', sha256='hash', archive_root='upstream')),
                (producer.harness, 'fetch_archive', lambda *args: root / 'archive'),
                (producer.harness, 'temporary_directory', lambda *args: tempfile.TemporaryDirectory(dir=root)),
                (producer.harness, 'safe_extract', lambda *args: source),
                (producer.harness, 'require_tool', lambda name: name),
                (producer.harness, 'command_record', command),
                (producer.m7.engine, 'git_provenance', lambda: {}),
                (producer.m7.integrated, 'source_seal', lambda: {}),
                (producer.m7, 'parse_options_trace', lambda *args: {}),
                (producer.m7, 'compare_options_traces', lambda *args: None),
                (producer, 'require_commit_failure_shape', lambda *args: None)]
            for owner, name, value in replacements:
                stack.enter_context(mock.patch.object(owner, name, value))
            self.assertEqual(producer.main(), 0)
            receipt = json.loads(report.read_text())
            c_program = Path(receipt['c_run']['command'][0])
            rust_program = Path(receipt['rust_test']['command'][0])
            self.assertNotEqual(rust_program.name, 'cargo')
            self.assertEqual(c_program.read_bytes(), b'C compiler product')
            self.assertEqual(rust_program, emitted)
            self.assertEqual(rust_program.read_bytes(), emitted.read_bytes())
            self.assertEqual(receipt['physical_inputs']['unit_program']['artifact'], producer.harness.artifact_record(emitted))
            self.assertEqual((report.with_suffix('') / 'compiled-input.c').read_bytes(), producer.DRIVER.read_bytes())
            artifact = json.loads((report.with_suffix('') / 'compiler-artifact.json').read_text())
            self.assertEqual(artifact['executable'], str(emitted))
            self.assertEqual(artifact['features'], ['mi-stat-1', 'mi-stat-2'])
            self.assertIn('--exact', receipt['rust_test']['command'])
            self.assertIn(producer.TEST, receipt['rust_test']['command'])


if __name__ == '__main__':
    unittest.main()
