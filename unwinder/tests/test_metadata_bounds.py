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

    def test_guarded_eh_frame_pointer_cases_return_no_fde_without_a_fault(self):
        expected = 'guarded EH frame pointers rejected\n'
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_guarded_dynamic_table_cases_return_their_exact_results(self):
        expected = 'guarded dynamic table rejected\n'
        metadata_bounds.assert_execution(0, expected, expected)
        with self.assertRaisesRegex(RuntimeError, 'status'):
            metadata_bounds.assert_execution(-11, '', expected)

    def test_provider_provenance_must_name_the_compiled_overlay(self):
        patch = metadata_bounds.digest(
            Path(__file__).parents[1] / 'patches/unwinding-0.2.10-phdr-bounds.rs'
        )
        provenance = {
            'archive': {'sha256': 'archive'},
            'patched_unwinding': {'patches': [{
                'path': metadata_bounds.PATCH_PATH,
                'target': metadata_bounds.PATCH_TARGET,
                'sha256': patch,
                'compiled_sha256': patch,
                'license': 'MIT OR Apache-2.0',
            }]},
            'dependencies': [{'name': 'unwinding', 'files': [{
                'path': metadata_bounds.PATCH_TARGET,
                'sha256': patch,
            }]}],
        }
        metadata_bounds.assert_patched_provider(provenance, 'archive')
        provenance['dependencies'][0]['files'][0]['sha256'] = 'unpatched'
        with self.assertRaisesRegex(RuntimeError, 'source audit'):
            metadata_bounds.assert_patched_provider(provenance, 'archive')


if __name__ == '__main__':
    unittest.main()
