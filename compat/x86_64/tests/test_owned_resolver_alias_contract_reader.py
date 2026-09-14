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
        })
        expected = _expected_command_argvs(inputs, Path('/workspace'), Path('/workspace/.work/receipt'))
        self.assertEqual(expected['compile-public-probe'][0], '/workspace/.work/dynamic/bin/crabc-cc-dynamic')
        self.assertEqual(expected['static-normal-et-exec-link'][-3:],
                         ['static-contract.link.json', '-o', '/workspace/.work/receipt/outputs/static-contract'])
        self.assertEqual(expected['dynamic-normal-nopie-runtime'],
                         ['chroot', '/workspace/.work/receipt/roots/dynamic-non-pie',
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


if __name__ == '__main__':
    unittest.main()
