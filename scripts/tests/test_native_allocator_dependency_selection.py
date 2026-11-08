"""The x86 feature closures select an allocator without a Cargo-built C backend."""
import tomllib
import unittest
import sys
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_x86_64_owned_sysroot as builder

MANIFEST = tomllib.loads((ROOT / 'libc/Cargo.toml').read_text())
FEATURES = MANIFEST['features']


def feature_dependencies(selection):
    pending = list(selection)
    visited = set()
    dependencies = set()
    while pending:
        feature = pending.pop()
        if feature in visited:
            continue
        visited.add(feature)
        for child in FEATURES[feature]:
            if child.startswith('dep:'):
                dependencies.add(child[4:])
            elif '/' in child:
                dependencies.add(child.split('/')[0])
            else:
                pending.append(child)
    return dependencies


def feature_closure(selection):
    pending = list(selection)
    visited = set()
    while pending:
        feature = pending.pop()
        if feature in visited:
            continue
        visited.add(feature)
        pending.extend(child for child in FEATURES[feature] if child in FEATURES)
    return visited


def selected_features(selection):
    pending = list(selection)
    visited = set()
    selected = set()
    while pending:
        feature = pending.pop()
        if feature in visited:
            continue
        visited.add(feature)
        for child in FEATURES[feature]:
            if child.startswith('dep:'):
                continue
            if '/' in child:
                selected.add(child)
            elif child in FEATURES:
                pending.append(child)
            else:
                selected.add(child)
    return selected


class NativeAllocatorDependencySelectionTests(unittest.TestCase):
    def test_native_dynamic_production_graph_excludes_c_allocator(self):
        for feature in ('x86-owned-static-native-shadow', 'x86-owned-dynamic-native-shadow'):
            with self.subTest(feature=feature):
                dependencies = feature_dependencies([feature])
                self.assertIn('crabc-mimalloc', dependencies)
                self.assertNotIn('libmimalloc-sys', dependencies)

    def test_c_entrypoints_select_the_c_wrapper_without_a_cargo_allocator(self):
        for feature in ('x86-owned-static-runtime', 'x86-owned-dynamic-runtime',
                        'x86-allocator-runtime', 'x86-allocator-string-duplication',
                        'x86-allocator-observability', 'x86-environment-runtime',
                        'x86-temporary-names', 'x86-scandir',
                        'x86-posix-spawn-file-actions', 'x86-crypt-allocator-composition'):
            with self.subTest(feature=feature):
                self.assertIn('x86-allocator-runtime', feature_closure([feature]))
                dependencies = feature_dependencies([feature])
                self.assertNotIn('libmimalloc-sys', dependencies)
                self.assertNotIn('crabc-mimalloc', dependencies)

    def test_native_and_c_aggregates_keep_identical_nonallocator_leaves(self):
        allocator_clients = {
            'x86-allocator-runtime',
            'x86-allocator-observability',
            'x86-allocator-string-duplication',
        }
        c_leaves = selected_features(['x86-owned-static-runtime']) - allocator_clients - {
            'x86-crypt-allocator-composition',
        }
        native_leaves = selected_features(['x86-owned-static-native-shadow']) - {
            'native-mimalloc-shadow',
        }
        self.assertEqual(native_leaves, c_leaves)

    def test_actual_normal_build_graph_rejects_a_cargo_c_allocator(self):
        native = b'crabc-libc v0.1.0\ncrabc-mimalloc v0.1.0\n'
        accepted = b'crabc-libc v0.1.0\n'
        with patch.object(builder, 'run', return_value=native) as run:
            result = builder.allocator_dependency_graph(['cargo'], 'x86-owned-static-native-shadow', 'native-shadow', {})
            self.assertTrue(result['native_allocator_selected'])
            self.assertIn('normal,build', run.call_args.args[0])
        with patch.object(builder, 'run', return_value=accepted):
            result = builder.allocator_dependency_graph(['cargo'], 'x86-owned-static-runtime', 'accepted-c', {})
            self.assertFalse(result['native_allocator_selected'])
        for backend, packages in (('native-shadow', native + b'libmimalloc-sys v0.1.49\n'),
                                  ('native-shadow', accepted),
                                  ('accepted-c', accepted + b'libmimalloc-sys v0.1.49\n'),
                                  ('accepted-c', native)):
            with self.subTest(backend=backend, packages=packages):
                with patch.object(builder, 'run', return_value=packages):
                    with self.assertRaises(builder.BuildError):
                        builder.allocator_dependency_graph(['cargo'], 'x86-owned-static-runtime', backend, {})

    def test_native_static_manifest_names_only_the_selected_rust_allocator(self):
        manifest = builder.installed_manifest({}, {}, allocator_backend='native-shadow')
        self.assertEqual(manifest['allocator_backend'], 'native-shadow')
        self.assertFalse(any('libmimalloc-sys' in item for item in manifest['purity']['target_runtime_inputs']))
        self.assertTrue(any('Rust mimalloc' in item for item in manifest['purity']['target_runtime_inputs']))

    def test_static_builder_keeps_c_default_and_requires_explicit_native_selection(self):
        self.assertEqual(builder.parse_args([]).allocator_backend, 'accepted-c')
        self.assertEqual(builder.parse_args(['--allocator-backend', 'native-shadow']).allocator_backend, 'native-shadow')

    def test_x86_target_has_no_cargo_c_allocator_dependency(self):
        target = MANIFEST['target']['cfg(all(target_os = "linux", target_arch = "x86_64", target_endian = "little"))']
        self.assertNotIn('libmimalloc-sys', target['dependencies'])

    def test_paused_aarch64_c_dependency_is_unconditional(self):
        target = MANIFEST['target']['cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))']
        dependency = target['dependencies']['libmimalloc-sys']
        self.assertNotIn('optional', dependency)
        self.assertEqual(dependency['version'], '0.1.49')


if __name__ == '__main__':
    unittest.main()
