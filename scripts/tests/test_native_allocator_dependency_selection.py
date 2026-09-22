"""The native production feature closure must not compile the C oracle backend."""
import tomllib
import unittest
import sys
import tempfile
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


class NativeAllocatorDependencySelectionTests(unittest.TestCase):
    def test_native_dynamic_production_graph_excludes_c_allocator(self):
        for feature in ('x86-owned-static-native-shadow', 'x86-owned-dynamic-native-shadow'):
            with self.subTest(feature=feature):
                dependencies = feature_dependencies([feature])
                self.assertIn('crabc-mimalloc', dependencies)
                self.assertNotIn('libmimalloc-sys', dependencies)

    def test_legacy_c_entrypoints_keep_the_accepted_backend(self):
        for feature in ('x86-owned-static-runtime', 'x86-owned-dynamic-runtime',
                        'x86-allocator-runtime', 'x86-allocator-string-duplication',
                        'x86-allocator-observability', 'x86-environment-runtime',
                        'x86-temporary-names', 'x86-scandir',
                        'x86-posix-spawn-file-actions', 'x86-crypt-allocator-composition'):
            with self.subTest(feature=feature):
                dependencies = feature_dependencies([feature])
                self.assertIn('libmimalloc-sys', dependencies)
                self.assertNotIn('crabc-mimalloc', dependencies)

    def test_native_and_c_aggregates_keep_identical_nonallocator_leaves(self):
        clients = {'x86-crypt-allocator-composition', 'x86-allocator-runtime',
                   'x86-allocator-observability', 'x86-allocator-string-duplication',
                   'x86-environment-runtime', 'x86-temporary-names', 'x86-scandir'}
        c_leaves = set(FEATURES['x86-owned-static-runtime']) - clients
        c_leaves.add('x86-crypt')
        native_leaves = set(FEATURES['x86-owned-static-native-shadow']) - {'native-mimalloc-shadow'}
        self.assertEqual(native_leaves, c_leaves)

    def test_actual_normal_build_graph_rejects_c_in_native_selection(self):
        native = b'crabc-libc v0.1.0\ncrabc-mimalloc v0.1.0\n'
        with patch.object(builder, 'run', return_value=native) as run:
            result = builder.allocator_dependency_graph(['cargo'], 'x86-owned-static-native-shadow', 'native-shadow', {})
            self.assertFalse(result['c_allocator_selected'])
            self.assertIn('normal,build', run.call_args.args[0])
        for packages in (native + b'libmimalloc-sys v0.1.49\n', b'crabc-libc v0.1.0\n'):
            with patch.object(builder, 'run', return_value=packages):
                with self.assertRaises(builder.BuildError):
                    builder.allocator_dependency_graph(['cargo'], 'x86-owned-static-native-shadow', 'native-shadow', {})

    def test_native_build_rejects_even_an_orphan_c_archive(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as temporary:
            cargo = Path(temporary)
            self.assertIsNone(builder.selected_allocator_archive(cargo, 'native-shadow'))
            archive = cargo / builder.TARGET / 'release/build/libmimalloc-sys-test/out/libmimalloc.a'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'orphan archive')
            with self.assertRaisesRegex(builder.BuildError, 'C mimalloc archive'):
                builder.selected_allocator_archive(cargo, 'native-shadow')
            self.assertEqual(builder.selected_allocator_archive(cargo, 'accepted-c'), archive)

    def test_native_static_manifest_names_only_the_selected_rust_allocator(self):
        manifest = builder.installed_manifest({}, {}, allocator_backend='native-shadow')
        self.assertEqual(manifest['allocator_backend'], 'native-shadow')
        self.assertFalse(any('libmimalloc-sys' in item for item in manifest['purity']['target_runtime_inputs']))
        self.assertTrue(any('Rust mimalloc' in item for item in manifest['purity']['target_runtime_inputs']))

    def test_static_builder_keeps_c_default_and_requires_explicit_native_selection(self):
        self.assertEqual(builder.parse_args([]).allocator_backend, 'accepted-c')
        self.assertEqual(builder.parse_args(['--allocator-backend', 'native-shadow']).allocator_backend, 'native-shadow')

    def test_paused_aarch64_c_dependency_is_unconditional(self):
        target = MANIFEST['target']['cfg(all(target_os = "linux", target_arch = "aarch64", target_endian = "little"))']
        dependency = target['dependencies']['libmimalloc-sys']
        self.assertNotIn('optional', dependency)
        self.assertEqual(dependency['version'], '0.1.49')


if __name__ == '__main__':
    unittest.main()
