"""The malformed-header provider regression keeps its exact fail-closed result."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'unwinder_metadata_bounds', Path(__file__).parents[1] / 'metadata_bounds.py'
)
metadata_bounds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata_bounds)


class MetadataBoundsExecutionContract(unittest.TestCase):
    def test_guarded_header_returns_no_fde_without_a_fault(self):
        metadata_bounds.assert_execution(0, 'truncated EH header rejected\n')
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '')
        with self.assertRaisesRegex(RuntimeError, 'unexpected'):
            metadata_bounds.assert_execution(0, 'truncated metadata accepted\n')

    def test_guarded_eh_frame_metadata_cases_report_phase_errors_without_a_fault(self):
        expected = ('mapped unwind=5\nmapped wait=0\n'
                    'unmapped unwind=3\nunmapped wait=0\n'
                    'unreadable unwind=3\nunreadable wait=0\n'
                    'oversized unwind=3\noversized wait=0\n'
                    'truncated unwind=3\ntruncated wait=0\n'
                    'long-fde unwind=5\nlong-fde wait=0\n'
                    'direct-pointer unwind=0\ndirect-pointer wait=0\n'
                    'indirect-pointer unwind=0\nindirect-pointer wait=0\n'
                    'guarded EH frame metadata rejected\n')
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_guarded_dynamic_table_cases_return_their_exact_results(self):
        expected = 'guarded dynamic table rejected\n'
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_guarded_late_indirect_metadata_returns_fatal_phase_one_without_a_fault(self):
        expected = 'guarded late indirect metadata rejected\n'
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_direct_metadata_targets_return_their_exact_results_without_a_fault(self):
        expected = 'direct metadata targets rejected\n'
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_guarded_register_rule_returns_a_phase_error_without_a_fault(self):
        expected = 'guarded register rule rejected\n'
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_forked_self_read_denial_preserves_raw_child_results(self):
        expected = ('allowed probe=8\nallowed unwind=5\nallowed wait=0\n'
                    'denied probe=-1 errno=1\ndenied unwind=3\ndenied wait=0\n'
                    'forked self-read policy respected\n')
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_provider_provenance_must_name_the_compiled_overlay(self):
        patches = []
        files = []
        for target, path in metadata_bounds.PATCHES.items():
            patch = metadata_bounds.digest(Path(__file__).parents[2] / path)
            patches.append({
                'path': path,
                'target': target,
                'sha256': patch,
                'compiled_sha256': patch,
                'license': 'MIT OR Apache-2.0',
            })
            files.append({'path': target, 'sha256': patch})
        gimli_config = metadata_bounds.GIMLI_READER_PATCH
        gimli_path = gimli_config['path']
        gimli_digest = metadata_bounds.digest(Path(__file__).parents[2] / gimli_path)
        gimli_patch = {
            'path': gimli_path,
            'sha256': gimli_digest,
            'target': gimli_config['target'],
            'upstream_sha256': gimli_config['upstream_sha256'],
            'compiled_sha256': gimli_digest,
            'license': gimli_config['license'],
        }
        provenance = {
            'archive': {'sha256': 'archive'},
            'patched_unwinding': {'patches': patches},
            'patched_gimli': {'patch': gimli_patch},
            'dependencies': [
                {'name': 'unwinding', 'files': files},
                {'name': 'gimli', 'files': [{'path': gimli_config['target'], 'sha256': gimli_digest}]},
            ],
        }
        metadata_bounds.assert_patched_provider(provenance, 'archive')
        provenance['dependencies'][0]['files'][0]['sha256'] = 'unpatched'
        with self.assertRaisesRegex(RuntimeError, 'source audit'):
            metadata_bounds.assert_patched_provider(provenance, 'archive')
        provenance['dependencies'][0]['files'][0]['sha256'] = patches[0]['sha256']
        removed = provenance['patched_unwinding']['patches'].pop()
        with self.assertRaisesRegex(RuntimeError, 'overlay roster'):
            metadata_bounds.assert_patched_provider(provenance, 'archive')
        provenance['patched_unwinding']['patches'].append(removed)
        provenance['dependencies'][1]['files'][0]['sha256'] = 'unpatched'
        with self.assertRaisesRegex(RuntimeError, 'remote-reader prerequisite'):
            metadata_bounds.assert_patched_provider(provenance, 'archive')


if __name__ == '__main__':
    unittest.main()
