"""The provider must fail closed when source resolution changes runtime owners."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('unwinder_build', Path(__file__).parents[1] / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class DependencyBoundary(unittest.TestCase):
    def setUp(self):
        self.lock = {'package': [{'name': n, 'version': v, 'checksum': c} for n, (v, c) in builder.PINS.items()]}
        self.metadata = {'packages': [
            {'id': n, 'name': n, 'version': builder.PINS.get(n, ('0.1.0', ''))[0], 'targets': [{'kind': ['lib']}]} for n in builder.FEATURES],
            'resolve': {'nodes': [{'id': n, 'features': sorted(f)} for n, f in builder.FEATURES.items()]}}

    def test_selected_source_and_feature_graph_is_accepted(self):
        self.assertEqual(set(builder.audit_graph(self.metadata, self.lock)), set(builder.FEATURES))

    def test_unwinder_registry_or_personality_cannot_enter_archive(self):
        for feature in ('fde-registry', 'alloc', 'personality', 'panic', 'system-alloc'):
            metadata = copy.deepcopy(self.metadata)
            next(n for n in metadata['resolve']['nodes'] if n['id'] == 'unwinding')['features'].append(feature)
            with self.subTest(feature=feature), self.assertRaisesRegex(ValueError, 'features'):
                builder.audit_graph(metadata, self.lock)

    def test_transitive_source_checksum_cannot_drift(self):
        self.lock['package'][1]['checksum'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source pin'):
            builder.audit_graph(self.metadata, self.lock)

    def test_new_dependency_cannot_enter_normal_graph(self):
        self.metadata['packages'].append({'name': 'cc'})
        with self.assertRaisesRegex(ValueError, 'dependency graph'):
            builder.audit_graph(self.metadata, self.lock)

    def test_only_reviewed_libc_cfg_build_script_is_admitted(self):
        for package in self.metadata['packages']:
            if package['name'] == 'gimli':
                package['targets'].append({'kind': ['custom-build']})
        with self.assertRaisesRegex(ValueError, 'build executable'):
            builder.audit_graph(self.metadata, self.lock)

if __name__ == '__main__':
    unittest.main()
