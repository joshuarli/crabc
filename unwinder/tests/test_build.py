"""The provider must fail closed when source resolution changes runtime owners."""
import copy
import importlib.util
from pathlib import Path
import shutil
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

    def test_patched_unwinding_requires_a_local_lock_entry(self):
        with self.assertRaisesRegex(ValueError, 'patched source pin'):
            builder.audit_graph(self.metadata, self.lock, patched_unwinding=True)
        patched_lock = copy.deepcopy(self.lock)
        next(package for package in patched_lock['package'] if package['name'] == 'unwinding').pop('checksum')
        self.assertEqual(
            set(builder.audit_graph(self.metadata, patched_lock, patched_unwinding=True)),
            set(builder.FEATURES),
        )

    def test_tree_digest_requires_declared_overlay_target_and_records_its_content(self):
        scratch = builder.ROOT.parent / '.work/x86_64/unwinder-output-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary) / 'source'
            root.mkdir()
            (root / 'target.rs').write_text('unpatched\n')
            overlay = Path(temporary) / 'overlay.rs'
            overlay.write_text('patched\n')
            baseline = builder.tree_digest(root)
            self.assertNotEqual(
                baseline,
                builder.tree_digest(root, {'target.rs': overlay}),
            )
            with self.assertRaisesRegex(ValueError, 'overlay target'):
                builder.tree_digest(root, {'missing.rs': overlay})

    def test_staged_overlay_drift_is_rejected_before_provenance(self):
        scratch = builder.ROOT.parent / '.work/x86_64/unwinder-output-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            staged_source = Path(temporary) / 'unwinding-0.2.10'
            patches = []
            for relative, configured in builder.PATCHES.items():
                target = staged_source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(configured['overlay'].read_bytes())
                patches.append({
                    'sha256': builder.digest(configured['overlay']),
                    'target': relative,
                    'compiled_sha256': builder.digest(target),
                })
            staged = {
                'staged': staged_source,
                'patched_tree_sha256': builder.tree_digest(staged_source),
                'patches': patches,
            }
            builder.verify_staged_patched_unwinding(staged)
            staged['patches'].append(dict(staged['patches'][0]))
            with self.assertRaisesRegex(ValueError, 'patch roster'):
                builder.verify_staged_patched_unwinding(staged)
            staged['patches'].pop()
            target = staged_source / next(iter(builder.PATCHES))
            target.write_text('source changed while compiling\n')
            with self.assertRaisesRegex(ValueError, 'compiled unwinding source'):
                builder.verify_staged_patched_unwinding(staged)

    def test_staged_overlay_preserves_read_only_private_source_modes(self):
        scratch = builder.ROOT.parent / '.work/x86_64/unwinder-output-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary) / 'crabc-unwinder'
            (root / 'src').mkdir(parents=True)
            (root / 'Cargo.toml').write_text('[package]\nname = "crabc-unwinder"\n')
            (root / 'Cargo.lock').write_text('version = 4\n')
            (root / 'src/lib.rs').write_text('#![no_std]\n')
            upstream = Path(temporary) / 'unwinding-0.2.10'
            target = upstream / 'src/unwinder/find_fde/phdr.rs'
            target.parent.mkdir(parents=True)
            target.write_text('unpatched\n')
            (upstream / 'Cargo.toml').write_text('[package]\nname = "unwinding"\n')
            overlay = Path(temporary) / 'overlay.rs'
            overlay.write_text('patched\n')
            patches = {
                'src/unwinder/find_fde/phdr.rs': {
                    'overlay': overlay,
                    'upstream_sha256': builder.digest(target),
                },
            }
            input_paths = (upstream, upstream / 'src', upstream / 'src/unwinder',
                           upstream / 'src/unwinder/find_fde', target)
            input_bytes = {path: path.read_bytes() for path in input_paths if path.is_file()}
            input_modes = {path: path.stat().st_mode & 0o777 for path in input_paths}
            for path in input_paths:
                path.chmod(0o555 if path.is_dir() else 0o444)
            packages = {
                builder.PATCHED_UNWINDING: {
                    'source': builder.CRATES_IO_REGISTRY,
                    'manifest_path': str(upstream / 'Cargo.toml'),
                },
            }
            try:
                private_stage_root = Path(temporary) / 'private-output/source-inputs'
                private_stage_root.parent.mkdir()
                with unittest.mock.patch.object(builder, 'ROOT', root), \
                     unittest.mock.patch.object(builder, 'PATCHES', patches), \
                     unittest.mock.patch.object(
                         builder, 'PATCHED_UNWINDING_UPSTREAM_TREE_SHA256', builder.tree_digest(upstream),
                     ):
                    staged = builder.stage_patched_unwinding(packages, stage_root=private_stage_root)
                staged_target = Path(staged['staged']) / 'src/unwinder/find_fde/phdr.rs'
                self.assertTrue(Path(staged['source_input']).is_relative_to(private_stage_root))
                self.assertEqual(staged_target.read_bytes(), overlay.read_bytes())
                self.assertEqual(staged_target.stat().st_mode & 0o777, 0o444)
                self.assertEqual({path: path.read_bytes() for path in input_bytes}, input_bytes)
                self.assertEqual({path: path.stat().st_mode & 0o777 for path in input_paths},
                                 {path: 0o555 if path.is_dir() else 0o444 for path in input_paths})
                failed_root = Path(temporary) / 'failed/crabc-unwinder'
                shutil.copytree(root, failed_root)
                failed_stage_root = Path(temporary) / 'failed/private-output/source-inputs'
                failed_stage_root.parent.mkdir(parents=True)
                copyfile = builder.shutil.copyfile

                def fail_overlay_copy(source, destination, *arguments, **keywords):
                    if Path(source) == overlay:
                        raise OSError('overlay copy failed')
                    return copyfile(source, destination, *arguments, **keywords)

                with unittest.mock.patch.object(builder, 'ROOT', failed_root), \
                     unittest.mock.patch.object(builder, 'PATCHES', patches), \
                     unittest.mock.patch.object(
                         builder, 'PATCHED_UNWINDING_UPSTREAM_TREE_SHA256', builder.tree_digest(upstream),
                     ), \
                     unittest.mock.patch.object(builder.shutil, 'copyfile', side_effect=fail_overlay_copy), \
                     self.assertRaisesRegex(OSError, 'overlay copy failed'):
                    builder.stage_patched_unwinding(packages, stage_root=failed_stage_root)
                failed_target = next(failed_stage_root.rglob('phdr.rs'))
                self.assertEqual(failed_target.stat().st_mode & 0o777, 0o444)
            finally:
                for path, mode in input_modes.items():
                    path.chmod(mode)

    def test_private_build_paths_cannot_escape_the_evidence_output(self):
        scratch = builder.ROOT.parent / '.work/x86_64/unwinder-output-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'stage root must remain below'):
                builder.build(root / 'stage-escape', stage_root=root / 'outside')
            cargo_home = root / 'outside' / 'provider-cargo-home'
            cargo_home.parent.mkdir()
            cargo_home.mkdir()
            with self.assertRaisesRegex(ValueError, 'Cargo home must remain beside'):
                builder.build(root / 'cargo-escape', cargo_home=cargo_home)
            output = root / 'not-a-directory-cargo-home'
            output.mkdir()
            with self.assertRaisesRegex(ValueError, 'Cargo home must be a physical directory'):
                builder.build(output, cargo_home=output.parent / 'missing-cargo-home')

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
