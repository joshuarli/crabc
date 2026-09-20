"""The provider must fail closed when source resolution changes runtime owners."""
import copy
import importlib.util
from pathlib import Path
import unittest
import unittest.mock
import tempfile

spec = importlib.util.spec_from_file_location('unwinder_build', Path(__file__).parents[1] / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class DependencyBoundary(unittest.TestCase):
    def setUp(self):
        self.lock = {'package': [
            {'name': 'crabc-unwinder', 'version': '0.1.0', 'dependencies': sorted(builder.PINS)},
            *[{'name': n, 'version': v, 'checksum': c} for n, (v, c) in builder.PINS.items()],
        ]}
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
        self.metadata['packages'].append({
            'id': 'cc', 'name': 'cc', 'version': '1.0.0', 'targets': [{'kind': ['lib']}],
        })
        with self.assertRaisesRegex(ValueError, 'dependency graph'):
            builder.audit_graph(self.metadata, self.lock)

    def test_duplicate_package_name_cannot_hide_a_second_graph_member(self):
        duplicate = copy.deepcopy(self.metadata['packages'][0])
        duplicate['id'] = 'unwinding duplicate package'
        self.metadata['packages'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'duplicate package'):
            builder.audit_graph(self.metadata, self.lock)

    def test_missing_resolve_node_cannot_skip_package_features_or_targets(self):
        self.metadata['resolve']['nodes'].pop()
        with self.assertRaisesRegex(ValueError, 'missing resolve node'):
            builder.audit_graph(self.metadata, self.lock)

    def test_duplicate_resolve_node_cannot_repeat_package_audit(self):
        self.metadata['resolve']['nodes'].append(copy.deepcopy(self.metadata['resolve']['nodes'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate resolve node'):
            builder.audit_graph(self.metadata, self.lock)

    def test_unknown_resolve_node_cannot_enter_feature_audit(self):
        self.metadata['resolve']['nodes'].append({'id': 'unknown package', 'features': []})
        with self.assertRaisesRegex(ValueError, 'unknown resolve node'):
            builder.audit_graph(self.metadata, self.lock)

    def test_duplicate_lock_package_cannot_hide_a_second_pin(self):
        self.lock['package'].append(copy.deepcopy(self.lock['package'][1]))
        with self.assertRaisesRegex(ValueError, 'duplicate lock package'):
            builder.audit_graph(self.metadata, self.lock)

    def test_only_reviewed_libc_cfg_build_script_is_admitted(self):
        for package in self.metadata['packages']:
            if package['name'] == 'gimli':
                package['targets'].append({'kind': ['custom-build']})
        with self.assertRaisesRegex(ValueError, 'build executable'):
            builder.audit_graph(self.metadata, self.lock)

    def test_existing_build_evidence_is_rejected_before_any_tool_runs(self):
        scratch = builder.ROOT.parent / '.work/x86_64/unwinder-output-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            receipt = output / 'provenance.json'
            receipt.write_text('historical evidence\n')
            with unittest.mock.patch.object(builder, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'nonempty'):
                    builder.build(output)
                run.assert_not_called()
            self.assertEqual(receipt.read_text(), 'historical evidence\n')

if __name__ == '__main__':
    unittest.main()
