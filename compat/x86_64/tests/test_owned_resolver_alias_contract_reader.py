#!/usr/bin/env python3
"""Focused contract tests for the finite resolver alias receipt."""
from __future__ import annotations

import sys
import tempfile
import unittest
import hashlib
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat' / 'x86_64'))

from owned_resolver_alias_contract_reader import (  # noqa: E402
    ALIASES,
    PRIVATE_BODIES,
    PROTECTED_CONTROLS,
    component_projection,
    file_identity,
    _retained_record,
    SOURCE_ALIAS_ROUTES,
    COMMAND_NAMES,
    INPUT_NAMES,
    _expected_command_argvs,
    _git,
    _git_file,
    _copy_input,
    _source_paths,
    _record_in_work,
    _capture_input_identities,
    _validate_captured_input_identities,
    _validate_runtime_roots,
    _validate_runtime,
    capture_runtime_root,
    FIXTURE_FILES,
    RUNTIME_ROOT_SPECS,
    ReceiptError,
    validate_candidate_occurrences,
)


class ResolverAliasReceiptContractTests(unittest.TestCase):
    def test_projection_is_json_safe_and_has_the_exact_five_identity_scope(self) -> None:
        projection = component_projection()
        self.assertEqual(ALIASES, (
            ('res_mkquery', '__res_mkquery'),
            ('res_send', '__res_send'),
            ('res_search', 'res_query'),
        ))
        self.assertEqual(PRIVATE_BODIES, ('__res_mkquery', '__res_send'))
        self.assertEqual(PROTECTED_CONTROLS, ('res_query', 'res_querydomain'))
        self.assertEqual(projection, {
            'aliases': [['res_mkquery', '__res_mkquery'], ['res_send', '__res_send'], ['res_search', 'res_query']],
            'private_bodies': ['__res_mkquery', '__res_send'],
            'protected_controls': ['res_query', 'res_querydomain'],
            'component_complete': True,
            'family_completion': False,
            'runtime_qualification': False,
            'promotion_ready': False,
            'public_support': False,
        })


class ResolverPrivateSourceContractTests(unittest.TestCase):
    def test_mkquery_private_extern_has_the_source_accurate_memory_contract(self) -> None:
        source = (ROOT / 'libc/src/c_abi/x86_64/resolver_runtime.rs').read_text(encoding='utf-8')
        marker = 'pub unsafe extern "C" fn __res_mkquery('
        documentation = source[source.index('/// Encode one selected recursive Internet DNS question'):source.index(marker)]
        for phrase in (
            '# Safety',
            'NUL-terminated',
            '256-byte scratch',
            'may overlap',
            'exclusively writable',
            '`_data` and `_new_record` are ignored',
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, documentation)

    def test_wrapper_transitive_legacy_probe_is_a_retained_source_input(self) -> None:
        paths = _source_paths(ROOT)
        self.assertEqual(paths['probe'], ROOT / 'compat/x86_64/owned_resolver_alias_contract_probe.c')
        self.assertEqual(paths['legacy_probe'], ROOT / 'compat/x86_64/libc_resolver_runtime_probe.c')
        self.assertEqual(paths['override_caller'], ROOT / 'compat/x86_64/owned_resolver_alias_override_caller.c')

def candidate_rows() -> list[dict[str, object]]:
    """A complete seven-name candidate subset with unrelated rows retained."""
    rows: list[dict[str, object]] = []
    index = 100

    def add(artifact: str, table: str, role: str, name: str, binding: str, visibility: str,
            value: str, section: str, member: str | None = None) -> None:
        nonlocal index
        rows.append({
            'index': index, 'artifact_key': artifact, 'table': table, 'role': role,
            'member_name': member,
            'member_index': 0 if member is not None else None,
            'member_occurrence': 0 if member is not None else None,
            'row': {'name': name, 'type': 'FUNC', 'binding': binding, 'visibility': visibility,
                    'value': value, 'size_bytes': int(value, 16), 'section_index': section},
        })
        index += 1

    for body, alias, value in (
        ('__res_mkquery', 'res_mkquery', '01'),
        ('__res_send', 'res_send', '02'),
    ):
        add('candidate-static', '.symtab', 'definition', body, 'GLOBAL', 'HIDDEN', value, value, 'resolver.o')
        add('candidate-static', '.symtab', 'definition', alias, 'WEAK', 'DEFAULT', value, value, 'resolver.o')
    add('candidate-static', '.symtab', 'definition', 'res_search', 'WEAK', 'DEFAULT', '03', '03', 'resolver.o')
    add('candidate-static', '.symtab', 'definition', 'res_query', 'GLOBAL', 'DEFAULT', '03', '03', 'resolver.o')
    add('candidate-static', '.symtab', 'definition', 'res_querydomain', 'GLOBAL', 'DEFAULT', '04', '04', 'resolver.o')
    for name, binding, value in (
        ('res_mkquery', 'WEAK', '11'), ('res_send', 'WEAK', '12'), ('res_search', 'WEAK', '13'),
        ('res_query', 'GLOBAL', '13'), ('res_querydomain', 'GLOBAL', '14'),
    ):
        add('candidate-shared', '.dynsym', 'definition', name, binding, 'DEFAULT', value, value)
    for body, alias, value in (
        ('__res_mkquery', 'res_mkquery', '21'),
        ('__res_send', 'res_send', '22'),
    ):
        add('candidate-shared', '.symtab', 'local-definition', body, 'LOCAL', 'HIDDEN', value, value)
        add('candidate-shared', '.symtab', 'definition', alias, 'WEAK', 'DEFAULT', value, value)
    add('candidate-shared', '.symtab', 'definition', 'res_search', 'WEAK', 'DEFAULT', '23', '23')
    add('candidate-shared', '.symtab', 'definition', 'res_query', 'GLOBAL', 'DEFAULT', '23', '23')
    add('candidate-shared', '.symtab', 'definition', 'res_querydomain', 'GLOBAL', 'DEFAULT', '24', '24')
    rows.append({'index': index, 'artifact_key': 'candidate-shared', 'table': '.symtab', 'role': 'definition',
                 'member_name': None,
                 'member_index': None, 'member_occurrence': None,
                 'row': {'name': 'unrelated_preserved_row', 'type': 'FUNC', 'binding': 'GLOBAL',
                         'visibility': 'DEFAULT', 'value': '99', 'size_bytes': 0x99, 'section_index': '99'}})
    return rows


class ResolverAliasOccurrenceTests(unittest.TestCase):
    def test_actual_role_shape_is_finite_while_unrelated_rows_remain_observations(self) -> None:
        projection = validate_candidate_occurrences(candidate_rows())
        self.assertEqual(projection['candidate_occurrence_count'], 19)
        self.assertEqual(projection['private_dynsym_definitions'], [])
        self.assertEqual([row['alias'] for row in projection['alias_domains']],
                         ['res_mkquery', 'res_send', 'res_search'])

    def test_each_alias_projection_keeps_its_own_target_indices(self) -> None:
        projection = validate_candidate_occurrences(candidate_rows())
        domains = {item['alias']: item for item in projection['alias_domains']}
        self.assertEqual(domains, {
            'res_mkquery': {
                'alias': 'res_mkquery', 'target': '__res_mkquery',
                'static': [101, 100], 'shared_symtab': [113, 112],
            },
            'res_send': {
                'alias': 'res_send', 'target': '__res_send',
                'static': [103, 102], 'shared_symtab': [115, 114],
            },
            'res_search': {
                'alias': 'res_search', 'target': 'res_query',
                'static': [104, 105], 'shared_symtab': [116, 117],
                'shared_dynsym': [109, 110],
            },
        })

    def test_wrong_private_shared_visibility_rejects(self) -> None:
        rows = candidate_rows()
        private = next(row for row in rows if row['row']['name'] == '__res_send'
                       and row['artifact_key'] == 'candidate-shared')
        private['row']['visibility'] = 'DEFAULT'
        with self.assertRaisesRegex(ReceiptError, '__res_send shared private body exact occurrence differs'):
            validate_candidate_occurrences(rows)

    def test_extra_named_candidate_row_rejects(self) -> None:
        rows = candidate_rows()
        duplicate = dict(rows[1])
        duplicate['index'] = 999
        duplicate['row'] = dict(duplicate['row'])
        rows.append(duplicate)
        with self.assertRaisesRegex(ReceiptError, 'res_mkquery static alias exact occurrence differs'):
            validate_candidate_occurrences(rows)

    def test_static_alias_in_another_archive_member_rejects(self) -> None:
        rows = candidate_rows()
        alias = next(row for row in rows if row['row']['name'] == 'res_mkquery'
                     and row['artifact_key'] == 'candidate-static')
        alias['member_index'] = 1
        alias['member_occurrence'] = 1
        with self.assertRaisesRegex(ReceiptError, 'res_mkquery static same-definition domain differs'):
            validate_candidate_occurrences(rows)

    def test_selected_and_legacy_res_send_callers_are_not_conflated(self) -> None:
        self.assertEqual(SOURCE_ALIAS_ROUTES[1], {
            'alias': 'res_send', 'target': '__res_send', 'binding': 'weak-same-address',
            'internal_callers': ['query_response'],
            'legacy_source_callers': ['lookup_dns_records'],
        })

class ResolverAliasRunnerSourceTests(unittest.TestCase):
    def test_component_sources_hold_the_three_normal_override_controls(self) -> None:
        override = (ROOT / 'compat/x86_64/owned_resolver_alias_override_probe.c').read_text(encoding='utf-8')
        caller = (ROOT / 'compat/x86_64/owned_resolver_alias_override_caller.c').read_text(encoding='utf-8')
        for name, sentinel in (('res_mkquery', '71'), ('res_send', '72'), ('res_search', '73')):
            with self.subTest(name=name):
                self.assertIn(name, override)
                self.assertIn(sentinel, override)
                self.assertIn(name, caller)
        self.assertNotIn('int res_query(', override)
        self.assertNotIn('int res_querydomain(', override)
        self.assertNotIn('int main(', override)
        self.assertIn('int main(void)', caller)

    def test_component_document_keeps_legacy_standalone_and_selected_product_boundaries_distinct(self) -> None:
        document = (ROOT / 'compat/x86_64/owned-resolver-alias-contract.md').read_text(encoding='utf-8')
        for phrase in ('custom `_start`', 'no-allocator/no-dynamic-TLS', 'product authority',
                       '`lookup_dns_records`', 'legacy-source observation'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, document)

class ResolverAliasRunnerInterfaceTests(unittest.TestCase):
    def test_runner_uses_only_supplied_products_and_the_four_sealed_driver_modes(self) -> None:
        runner = (ROOT / 'compat/x86_64/run_owned_resolver_alias_contract.sh').read_text(encoding='utf-8')
        for required in (
            '--static-product', '--dynamic-product', '--static-preparation', '--product-report',
            '--elf-facts', '--base-inventory', '--receipt-dir',
            '"$STATIC_DRIVER" -static', '"$STATIC_DRIVER" -static-pie',
            '"$DYNAMIC_DRIVER" --dynamic-pie', '"$DYNAMIC_DRIVER" --dynamic-non-pie',
            'compile-override-mkquery', 'compile-override-send', 'compile-override-search',
            '--link-receipt',
        ):
            with self.subTest(required=required):
                self.assertIn(required, runner)

    def test_selected_driver_compiles_use_installed_headers_and_static_sidecars_are_relative(self) -> None:
        runner = (ROOT / 'compat/x86_64/run_owned_resolver_alias_contract.sh').read_text(encoding='utf-8')
        selected_compile = runner[runner.index('record compile-public-probe'):runner.index('record oracle-symbols')]
        self.assertNotIn('-I "$ROOT/include"', selected_compile)
        self.assertIn('cd "$WORK"', runner)
        self.assertIn('--link-receipt static-contract.link.json', runner)
        self.assertIn('--link-receipt static-pie-contract.link.json', runner)

    def test_command_roster_includes_retained_public_caller_and_dynamic_export_observations(self) -> None:
        self.assertEqual(len(COMMAND_NAMES), 44)
        for name in (
            'public-probe-relocations',
            'override-mkquery-public-relocation', 'override-send-public-relocation',
            'override-search-public-relocation',
            'dynamic-normal-pie-dynsym', 'dynamic-normal-nopie-dynsym',
            'dynamic-override-mkquery-dynsym', 'dynamic-override-send-dynsym',
            'dynamic-override-search-dynsym',
        ):
            with self.subTest(name=name):
                self.assertIn(name, COMMAND_NAMES)

    def test_command_replay_uses_the_retained_source_mount_not_host_paths(self) -> None:
        inputs = {name: {'path': f'/workspace/.work/input/{name}'} for name in INPUT_NAMES}
        inputs.update({
            'dynamic_driver': {'path': '/workspace/.work/dynamic/bin/crabc-cc-dynamic'},
            'static_driver': {'path': '/workspace/.work/static/bin/crabc-cc'},
            'oracle_compiler': {'path': '/usr/local/bin/crabc-x86_64-musl-gcc'},
            'oracle_archive': {'path': '/opt/musl-1.2.6/lib/libc.a'},
            'static_libc': {'path': '/workspace/.work/static/usr/lib/libc.a'},
            'dynamic_libc': {'path': '/workspace/.work/dynamic/usr/lib/libc.so'},
            'probe': {'path': '/workspace/compat/x86_64/owned_resolver_alias_contract_probe.c'},
            'override_probe': {'path': '/workspace/compat/x86_64/owned_resolver_alias_override_probe.c'},
            'override_caller': {'path': '/workspace/compat/x86_64/owned_resolver_alias_override_caller.c'},
            'header_c_probe': {'path': '/workspace/compat/x86_64/resolver_runtime_header_abi_probe.c'},
            'header_cpp_probe': {'path': '/workspace/compat/x86_64/resolver_runtime_header_abi_probe.cpp'},
            'header_compiler': {'path': '/usr/bin/gcc'},
            'readelf': {'path': '/usr/bin/readelf'},
            'timeout': {'path': '/usr/bin/timeout'},
            'chroot': {'path': '/usr/sbin/chroot'},
        })
        expected = _expected_command_argvs(inputs, Path('/workspace'), Path('/workspace/.work/receipt'))
        self.assertEqual(expected['compile-public-probe'][0], '/workspace/.work/dynamic/bin/crabc-cc-dynamic')
        self.assertEqual(expected['static-normal-et-exec-link'][-3:],
                         ['static-contract.link.json', '-o', '/workspace/.work/receipt/outputs/static-contract'])
        self.assertEqual(expected['dynamic-normal-nopie-runtime'],
                         ['/usr/sbin/chroot', '/workspace/.work/receipt/roots/dynamic-non-pie',
                          '/lib/ld-crabc-x86_64.so.1', '/contract', '/fixture'])


class ResolverAliasReceiptFilesystemTests(unittest.TestCase):
    def test_selected_git_regular_mode_is_normalized_to_permission_bits(self) -> None:
        revision = _git(ROOT, 'rev-parse', 'HEAD')
        mode, contents = _git_file(ROOT, revision, Path('libc/Cargo.toml'))
        self.assertEqual(mode, 0o644)
        self.assertIn(b'[package]', contents)

    def test_retained_identity_rejects_a_symlink_even_when_its_target_is_regular(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target'
            target.write_text('resolver receipt', encoding='utf-8')
            retained = root / 'retained'
            retained.symlink_to(target.name)
            with self.assertRaisesRegex(ReceiptError, 'not physical file'):
                file_identity(retained, root=root)

    def test_retained_record_rejects_a_symlink_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target'
            target.write_text('resolver receipt', encoding='utf-8')
            retained = root / 'retained'
            retained.symlink_to(target.name)
            record = {
                'path': 'original/input',
                'retained': 'retained',
                'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                'size': target.stat().st_size,
                'mode': stat.S_IMODE(target.stat().st_mode),
            }
            with self.assertRaisesRegex(ReceiptError, 'retained path is not physical'):
                _retained_record(root, record, 'symlink control')

    def test_collector_refuses_a_symlinked_current_input_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / 'work'
            work.mkdir()
            target = root / 'target'
            target.write_text('resolver receipt', encoding='utf-8')
            input_path = root / 'input'
            input_path.symlink_to(target.name)
            with self.assertRaisesRegex(ReceiptError, 'input is not a physical file'):
                _copy_input(work, 'input', input_path)


class ResolverAliasOrdinaryBoundaryRegressionTests(unittest.TestCase):
    def test_selected_source_requires_getaddrinfo_cfg_attached_to_the_definition(self) -> None:
        from owned_resolver_alias_contract_reader import _validate_selected_source_text

        source = (ROOT / 'libc/src/c_abi/x86_64/resolver_runtime.rs').read_text(encoding='utf-8')
        _validate_selected_source_text(source)
        marker = '#[cfg(not(feature = "x86-owned-static-runtime"))]\n#[no_mangle]\npub unsafe extern "C" fn getaddrinfo('
        self.assertIn(marker, source)
        with self.assertRaisesRegex(ReceiptError, 'legacy getaddrinfo caller is not excluded'):
            _validate_selected_source_text(source.replace(marker, '#[no_mangle]\npub unsafe extern "C" fn getaddrinfo(', 1))

    def test_header_commands_use_pinned_raw_compiler_and_selected_headers(self) -> None:
        from owned_resolver_alias_contract_reader import HEADER_BUILTIN_INCLUDE

        runner = (ROOT / 'compat/x86_64/run_owned_resolver_alias_contract.sh').read_text(encoding='utf-8')
        self.assertIn('readonly RAW_HEADER_COMPILER=/usr/bin/gcc', runner)
        self.assertIn('readonly HEADER_BUILTIN_INCLUDE=', runner)
        header_commands = runner[runner.index('# Header ABI is a source check'):runner.index('record compile-public-probe')]
        self.assertIn('"$RAW_HEADER_COMPILER"', header_commands)
        self.assertIn('-nostdinc -I "$DYNAMIC_PRODUCT/usr/include"', header_commands)
        self.assertIn('-isystem "$HEADER_BUILTIN_INCLUDE"', header_commands)
        self.assertNotIn('"$DYNAMIC_DRIVER" --dynamic-pie -x', header_commands)
        self.assertEqual(HEADER_BUILTIN_INCLUDE,
                         '/usr/lib/gcc/x86_64-alpine-linux-musl/15.2.0/include')




class ResolverAliasRuntimeRootTransitionTests(unittest.TestCase):
    def _write(self, path: Path, content: bytes, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)

    def _fixture(self, root: Path) -> None:
        for relative, content in FIXTURE_FILES.items():
            self._write(root / relative, content)

    def _generated_resolv(self, identity: int = 42) -> bytes:
        return (f'nameserver 127.{128 + (identity >> 16)}.{(identity >> 8) & 0xff}.{identity & 0xff}\n'
                'search fixture.test\noptions ndots:1 timeout:1 attempts:1\n').encode('ascii')

    def test_runtime_roots_retain_exact_before_and_bounded_resolver_after(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            artifacts = {'normal': {}, 'overrides': {}}
            inputs: dict[str, dict[str, object]] = {}
            loader = work / 'inputs/dynamic-loader'
            libc = work / 'inputs/dynamic-libc'
            self._write(loader, b'loader', 0o755)
            self._write(libc, b'libc', 0o755)
            for name, path in (('dynamic_loader', loader), ('dynamic_libc', libc)):
                inputs[name] = {key: value for key, value in _record_in_work(work, path).items()
                                if key in {'sha256', 'size', 'mode'}}
            legacy = ROOT / 'compat/x86_64/libc_resolver_runtime_probe.c'
            retained_legacy = work / 'retained/inputs/legacy_probe'
            self._write(retained_legacy, legacy.read_bytes())
            inputs['legacy_probe'] = _record_in_work(work, retained_legacy)

            for name, (relative, _command, artifact_name) in RUNTIME_ROOT_SPECS.items():
                root = work / relative
                root.mkdir(parents=True)
                root.chmod(0o755)
                if artifact_name == 'fixture':
                    self._fixture(root)
                else:
                    self._write(root / 'lib/ld-crabc-x86_64.so.1', loader.read_bytes(), 0o755)
                    self._write(root / 'usr/lib/libc.so', libc.read_bytes(), 0o755)
                    contract = work / f'outputs/{name}'
                    self._write(contract, name.encode('ascii'), 0o755)
                    record = _record_in_work(work, contract)
                    if artifact_name in {'dynamic_pie', 'dynamic_non_pie'}:
                        artifacts['normal'][artifact_name] = record
                    else:
                        artifacts['overrides'][artifact_name] = record
                    self._write(root / 'contract', contract.read_bytes(), 0o755)
                    self._fixture(root / 'fixture')
                capture_runtime_root(work=work, name=name, root=root, phase='before')

                if artifact_name in {'fixture', 'dynamic_pie', 'dynamic_non_pie'}:
                    resolv = root / ('etc/resolv.conf' if artifact_name == 'fixture' else 'fixture/etc/resolv.conf')
                    self._write(resolv, self._generated_resolv(), 0o600)
                capture_runtime_root(work=work, name=name, root=root, phase='after')

            value = {
                name: {
                    'command': command,
                    'before': _record_in_work(work, work / f'runtime-roots/{name}-before.json'),
                    'after': _record_in_work(work, work / f'runtime-roots/{name}-after.json'),
                }
                for name, (_relative, command, _artifact) in RUNTIME_ROOT_SPECS.items()
            }
            _validate_runtime_roots(value, work, inputs, artifacts)

            dynamic_after = work / 'runtime-roots/dynamic-pie-after.json'
            dynamic_contract = work / 'roots/dynamic-pie/contract'
            dynamic_contract.write_bytes(b'wrong contract')
            dynamic_after.unlink()
            capture_runtime_root(work=work, name='dynamic-pie', root=work / 'roots/dynamic-pie', phase='after')
            value['dynamic-pie']['after'] = _record_in_work(work, dynamic_after)
            with self.assertRaisesRegex(ReceiptError, 'immutable payload differs: dynamic-pie'):
                _validate_runtime_roots(value, work, inputs, artifacts)

            dynamic_contract.write_bytes(b'dynamic-pie')
            dynamic_after.unlink()
            self._write(work / 'roots/dynamic-pie/fixture/etc/resolv.conf', b'nameserver 192.0.2.1\n', 0o600)
            capture_runtime_root(work=work, name='dynamic-pie', root=work / 'roots/dynamic-pie', phase='after')
            value['dynamic-pie']['after'] = _record_in_work(work, dynamic_after)
            with self.assertRaisesRegex(ReceiptError, 'generated resolv.conf differs'):
                _validate_runtime_roots(value, work, inputs, artifacts)



class ResolverAliasPreExecutionCaptureTests(unittest.TestCase):
    def _paths(self, root: Path) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        for name in INPUT_NAMES:
            path = root / 'current' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode('ascii'))
            path.chmod(0o644)
            paths[name] = path
        return paths

    def test_final_seal_rejects_source_and_measurement_bytes_changed_after_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / 'receipt'
            work.mkdir()
            paths = self._paths(root)
            inputs = _capture_input_identities(work, paths, {'files': {}}, image_inputs={})
            _validate_captured_input_identities(work, inputs, paths, {'files': {}}, image_inputs={})

            paths['resolver_source'].write_bytes(b'changed selected source')
            with self.assertRaisesRegex(ReceiptError, 'pre-execution capture: resolver_source'):
                _validate_captured_input_identities(work, inputs, paths, {'files': {}}, image_inputs={})
            paths['resolver_source'].write_bytes(b'resolver_source')
            paths['elf_facts'].write_bytes(b'changed measurement')
            with self.assertRaisesRegex(ReceiptError, 'pre-execution capture: elf_facts'):
                _validate_captured_input_identities(work, inputs, paths, {'files': {}}, image_inputs={})

    def test_image_invocation_path_is_bound_to_the_retained_pinned_program(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / 'receipt'
            work.mkdir()
            paths = self._paths(root)
            image_inputs = {'readelf': '/usr/bin/readelf'}
            record = file_identity(paths['readelf'], root=root)
            manifest = {'files': {'/usr/bin/readelf': {key: record[key] for key in ('sha256', 'size', 'mode')}}}
            inputs = _capture_input_identities(work, paths, manifest, image_inputs=image_inputs)
            _validate_captured_input_identities(work, inputs, paths, manifest, image_inputs=image_inputs)
            inputs['readelf'] = dict(inputs['readelf'], path='/usr/bin/other')
            with self.assertRaisesRegex(ReceiptError, 'pinned image input differs: readelf'):
                _validate_captured_input_identities(work, inputs, paths, manifest, image_inputs=image_inputs)



class ResolverAliasRuntimeStatusTests(unittest.TestCase):
    def test_runtime_status_must_be_the_matching_command_status_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands: dict[str, dict[str, object]] = {}
            expected = {
                'oracle': 'oracle-runtime-run',
                'static-et-exec': 'static-normal-et-exec-runtime',
                'static-pie': 'static-normal-pie-runtime',
                'dynamic-pie': 'dynamic-normal-pie-runtime',
                'dynamic-non-pie': 'dynamic-normal-nopie-runtime',
            }
            for index, command in enumerate(expected.values()):
                status = root / f'{index}.status'
                status.write_text('0\n', encoding='ascii')
                commands[command] = {'status': _record_in_work(root, status)}
            runtime = {name: {'command': command, 'status': commands[command]['status']}
                       for name, command in expected.items()}
            _validate_runtime(runtime, root, commands)
            runtime['oracle'] = dict(runtime['oracle'], status=commands['static-normal-et-exec-runtime']['status'])
            with self.assertRaisesRegex(ReceiptError, 'command status binding differs: oracle'):
                _validate_runtime(runtime, root, commands)


if __name__ == '__main__':
    unittest.main()
