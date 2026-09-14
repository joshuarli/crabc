#!/usr/bin/env python3
"""Validate the finite current-product x86 resolver alias component receipt.

This is deliberately a resolver-alias receipt reader, not a general ELF evidence
framework. It authenticates exactly three public weak aliases, two private
implementation bodies, and two strong public controls against one supplied
static/dynamic product cohort. It never selects a family or promotes support.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
ROOT = MODULE_DIR.parents[1]
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import owned_posix_product_evidence as product_evidence
import owned_posix_static_products as static_products

SCHEMA = 'crabc.x86_64-owned-resolver-alias-contract/v1'
STATUS = 'component-verified'
COMPONENT = 'resolver-alias-private-bodies'
IMAGE = 'crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d'
IMAGE_MANIFEST = MODULE_DIR / 'owned-resolver-alias-image-inputs.json'
MUSL_SOURCE_COMMIT = '9fa28ece75d8a2191de7c5bb53bed224c5947417'

ALIASES = (
    ('res_mkquery', '__res_mkquery'),
    ('res_send', '__res_send'),
    ('res_search', 'res_query'),
)
PRIVATE_BODIES = ('__res_mkquery', '__res_send')
PROTECTED_CONTROLS = ('res_query', 'res_querydomain')
KNOWN_NAMES = (*PRIVATE_BODIES, *(name for name, _target in ALIASES), *PROTECTED_CONTROLS)

SOURCE_ALIAS_ROUTES = (
    {'alias': 'res_mkquery', 'target': '__res_mkquery', 'binding': 'weak-same-address',
     'internal_callers': ['query_response']},
    {'alias': 'res_send', 'target': '__res_send', 'binding': 'weak-same-address',
     'internal_callers': ['query_response'], 'legacy_source_callers': ['lookup_dns_records']},
    {'alias': 'res_search', 'target': 'res_query', 'binding': 'weak-same-address',
     'internal_callers': []},
)

SOURCE_CONTRACT_PATHS = (
    'libc/Cargo.toml',
    'libc/src/c_abi/x86_64/static_c_abi.rs',
    'libc/src/c_abi/x86_64/resolver_runtime.rs',
    'libc/src/c_abi/x86_64/owned_resolver_batch.rs',
    'include/resolv.h',
    'compat/x86_64/feature_archive_roster.py',
    'compat/x86_64/parity.toml',
    'compat/x86_64/owned-resolver-cancellation.md',
    'compat/x86_64/resolver_runtime_header_abi_probe.c',
    'compat/x86_64/resolver_runtime_header_abi_probe.cpp',
    'compat/x86_64/run_resolver_runtime_header_abi.sh',
    'compat/x86_64/libc_resolver_runtime_probe.c',
    'compat/x86_64/run_libc_resolver_runtime.sh',
)
COLLECTOR_PATHS = (
    'compat/x86_64/owned_resolver_alias_contract_reader.py',
    'compat/x86_64/run_owned_resolver_alias_contract.sh',
    'compat/x86_64/owned_resolver_alias_contract_probe.c',
    'compat/x86_64/owned_resolver_alias_override_probe.c',
    'compat/x86_64/owned_resolver_alias_override_caller.c',
    'compat/x86_64/owned-resolver-alias-contract.md',
    'compat/x86_64/owned-resolver-alias-image-inputs.json',
    'compat/x86_64/owned_static_link_authority.py',
    'compat/x86_64/loader_debug_abi_evidence.py',
    'compat/x86_64/owned_posix_product_evidence.py',
)
# Every retained file is named for its actual role. JSON object order is never
# evidence; the reader compares this exact key set.
INPUT_NAMES = (
    'reader', 'runner', 'probe', 'override_probe', 'override_caller', 'contract',
    'resolver_source', 'static_c_abi_source', 'resolver_batch_source', 'cargo_manifest',
    'resolv_header', 'feature_roster', 'parity_contract', 'cancellation_contract',
    'header_c_probe', 'header_cpp_probe', 'header_runner', 'legacy_probe', 'legacy_runner',
    'static_authority', 'elf_reader', 'product_authority', 'image_manifest',
    'oracle_compiler', 'oracle_archive', 'oracle_shared',
    'static_driver', 'static_manifest', 'static_libc', 'static_crt1', 'static_rcrt1', 'static_crti', 'static_crtn', 'static_builtins',
    'dynamic_driver', 'dynamic_libc', 'dynamic_loader', 'dynamic_crt1', 'dynamic_scrt1',
    'dynamic_crti', 'dynamic_crtn', 'dynamic_attach', 'dynamic_builtins', 'dynamic_manifest', 'dynamic_state',
    'product_report', 'static_preparation', 'elf_facts', 'base_inventory',
)

COMMAND_NAMES = (
    'header-c', 'header-cpp',
    'compile-public-probe', 'public-probe-relocations',
    'compile-override-mkquery', 'compile-override-mkquery-caller', 'override-mkquery-public-relocation',
    'compile-override-send', 'compile-override-send-caller', 'override-send-public-relocation',
    'compile-override-search', 'compile-override-search-caller', 'override-search-public-relocation',
    'oracle-symbols', 'oracle-runtime-link', 'oracle-runtime-run',
    'static-symbols', 'static-private-calls',
    'static-normal-et-exec-link', 'static-normal-et-exec-runtime',
    'static-normal-pie-link', 'static-normal-pie-runtime',
    'dynamic-symbols',
    'dynamic-normal-pie-link', 'dynamic-normal-pie-dynsym', 'dynamic-normal-pie-runtime',
    'dynamic-normal-nopie-link', 'dynamic-normal-nopie-dynsym', 'dynamic-normal-nopie-runtime',
    'static-override-mkquery', 'static-override-mkquery-runtime',
    'static-override-send', 'static-override-send-runtime',
    'static-override-search', 'static-override-search-runtime',
    'dynamic-override-mkquery', 'dynamic-override-mkquery-dynsym', 'dynamic-override-mkquery-runtime',
    'dynamic-override-send', 'dynamic-override-send-dynsym', 'dynamic-override-send-runtime',
    'dynamic-override-search', 'dynamic-override-search-dynsym', 'dynamic-override-search-runtime',
)

LINK_INPUT_MODES = product_evidence.link_input_mode_projection()


class ReceiptError(ValueError):
    """A retained resolver-alias receipt does not satisfy its finite contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def exact(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f'{description} shape differs')
    return value


def same(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read_json(path: Path, description: str) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ReceiptError(f'{description} has invalid JSON constant {value}')))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f'{description} is not JSON: {path}') from error


def file_identity(path: Path, *, root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    require(not path.is_symlink(), f'identity is not physical file: {path}')
    path = path.resolve(strict=True)
    require(path.is_relative_to(root), f'identity escapes root: {path}')
    status = path.stat()
    require(stat.S_ISREG(status.st_mode), f'identity is not physical file: {path}')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'path': path.relative_to(root).as_posix(), 'sha256': digest,
            'size': status.st_size, 'mode': stat.S_IMODE(status.st_mode)}


def retained_file_path(root: Path, relative: str, description: str) -> Path:
    """Return one lexical receipt-relative physical-file path.

    Retained content is only authority if every component from the receipt
    root to the file is a real directory or file. Resolving first would erase
    a symlink before the physical-file policy can reject it.
    """
    require(type(relative) is str, f'{description} retained path differs')
    item = Path(relative)
    require(not item.is_absolute() and all(part not in {'', '.', '..'} for part in item.parts),
            f'{description} retained path escapes receipt')
    root = root.resolve(strict=True)
    current = root
    for part in item.parts:
        current /= part
        require(not current.is_symlink(), f'{description} retained path is not physical: {current}')
    return current


def component_projection() -> dict[str, Any]:
    """JSON-safe finite scope used by both collector and replay."""
    return {
        'aliases': [[alias, target] for alias, target in ALIASES],
        'private_bodies': list(PRIVATE_BODIES),
        'protected_controls': list(PROTECTED_CONTROLS),
        'component_complete': True,
        'family_completion': False,
        'runtime_qualification': False,
        'promotion_ready': False,
        'public_support': False,
    }


def coverage_projection() -> dict[str, Any]:
    return {
        'group': 'component-owned-resolver-private-bodies',
        'owner': 'x86-owned-resolver-private-bodies',
        'private_bodies': list(PRIVATE_BODIES),
        'aliases': [[alias, target] for alias, target in ALIASES],
        'protected_controls': list(PROTECTED_CONTROLS),
    }


def _row_domain(row: Mapping[str, Any]) -> tuple[Any, ...]:
    symbol = row['row']
    return (row.get('member_name'), row.get('member_index'), row.get('member_occurrence'),
            symbol.get('value'), symbol.get('size_bytes'), symbol.get('type'), symbol.get('section_index'))


def _one_row(rows: Sequence[Mapping[str, Any]], *, artifact: str, table: str, role: str,
             name: str, binding: str, visibility: str, description: str) -> Mapping[str, Any]:
    matches = [item for item in rows if item.get('artifact_key') == artifact and item.get('table') == table
               and item.get('role') == role and type(item.get('row')) is dict
               and item['row'].get('name') == name and item['row'].get('type') == 'FUNC'
               and item['row'].get('binding') == binding and item['row'].get('visibility') == visibility]
    require(len(matches) == 1, f'{description} exact occurrence differs')
    return matches[0]


def validate_candidate_occurrences(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate exactly the finite resolver rows without touching other facts."""
    require(type(rows) in {list, tuple}, 'candidate resolver occurrence roster is not a sequence')
    known = [item for item in rows if item.get('artifact_key') in {'candidate-static', 'candidate-shared'}
             and type(item.get('row')) is dict and item['row'].get('name') in KNOWN_NAMES]
    expected: list[Mapping[str, Any]] = []
    static_bodies = {}
    shared_bodies = {}
    static_public = {}
    shared_public = {}
    shared_dyn_public = {}
    for body in PRIVATE_BODIES:
        static_bodies[body] = _one_row(known, artifact='candidate-static', table='.symtab', role='definition',
                                       name=body, binding='GLOBAL', visibility='HIDDEN',
                                       description=f'{body} static private body')
        shared_bodies[body] = _one_row(known, artifact='candidate-shared', table='.symtab', role='local-definition',
                                       name=body, binding='LOCAL', visibility='HIDDEN',
                                       description=f'{body} shared private body')
        expected.extend((static_bodies[body], shared_bodies[body]))
    for alias, _target in ALIASES:
        static_public[alias] = _one_row(known, artifact='candidate-static', table='.symtab', role='definition',
                                        name=alias, binding='WEAK', visibility='DEFAULT', description=f'{alias} static alias')
        shared_dyn_public[alias] = _one_row(known, artifact='candidate-shared', table='.dynsym', role='definition',
                                            name=alias, binding='WEAK', visibility='DEFAULT', description=f'{alias} shared dynsym alias')
        shared_public[alias] = _one_row(known, artifact='candidate-shared', table='.symtab', role='definition',
                                        name=alias, binding='WEAK', visibility='DEFAULT', description=f'{alias} shared symtab alias')
        expected.extend((static_public[alias], shared_dyn_public[alias], shared_public[alias]))
    controls: dict[str, dict[str, Mapping[str, Any]]] = {}
    for control in PROTECTED_CONTROLS:
        controls[control] = {
            'static': _one_row(known, artifact='candidate-static', table='.symtab', role='definition',
                               name=control, binding='GLOBAL', visibility='DEFAULT', description=f'{control} static control'),
            'dynsym': _one_row(known, artifact='candidate-shared', table='.dynsym', role='definition',
                               name=control, binding='GLOBAL', visibility='DEFAULT', description=f'{control} shared dynsym control'),
            'symtab': _one_row(known, artifact='candidate-shared', table='.symtab', role='definition',
                               name=control, binding='GLOBAL', visibility='DEFAULT', description=f'{control} shared symtab control'),
        }
        expected.extend(controls[control].values())
    expected_indices = {item.get('index') for item in expected}
    actual_indices = {item.get('index') for item in known}
    require(None not in expected_indices and len(expected_indices) == 19 and actual_indices == expected_indices,
            'candidate resolver occurrence roster differs')
    for alias, target in ALIASES:
        target_static = (static_public[target] if target in static_public else
                         static_bodies[target] if target in static_bodies else controls[target]['static'])
        target_shared = (shared_public[target] if target in shared_public else
                         shared_bodies[target] if target in shared_bodies else controls[target]['symtab'])
        require(_row_domain(static_public[alias]) == _row_domain(target_static),
                f'{alias} static same-definition domain differs')
        require(_row_domain(shared_public[alias]) == _row_domain(target_shared),
                f'{alias} shared same-definition domain differs')
        if alias == 'res_search':
            require(_row_domain(shared_dyn_public[alias]) == _row_domain(controls['res_query']['dynsym']),
                    'res_search shared dynsym same-definition domain differs')
    alias_domains = []
    for alias, target in ALIASES:
        target_static = (static_public[target] if target in static_public else
                         static_bodies[target] if target in static_bodies else controls[target]['static'])
        target_shared = (shared_public[target] if target in shared_public else
                         shared_bodies[target] if target in shared_bodies else controls[target]['symtab'])
        domain = {
            'alias': alias,
            'target': target,
            'static': [static_public[alias]['index'], target_static['index']],
            'shared_symtab': [shared_public[alias]['index'], target_shared['index']],
        }
        if alias == 'res_search':
            domain['shared_dynsym'] = [shared_dyn_public[alias]['index'], controls['res_query']['dynsym']['index']]
        alias_domains.append(domain)
    return {
        'candidate_occurrence_count': 19,
        'indices': sorted(expected_indices),
        'private_dynsym_definitions': [],
        'alias_domains': alias_domains,
    }


def _validate_identity_record(value: Any, description: str) -> dict[str, Any]:
    record = exact(value, {'path', 'sha256', 'size', 'mode', 'retained'}, description)
    require(type(record['path']) is str and type(record['retained']) is str
            and len(record['sha256']) == 64 and all(char in '0123456789abcdef' for char in record['sha256'])
            and type(record['size']) is int and record['size'] >= 0
            and type(record['mode']) is int and 0 <= record['mode'] <= 0o777,
            f'{description} values differ')
    return record


def _retained_record(root: Path, record: Any, description: str) -> Path:
    record = _validate_identity_record(record, description)
    retained = retained_file_path(root, record['retained'], description)
    observed = file_identity(retained, root=root)
    require(all(observed[key] == record[key] for key in ('sha256', 'size', 'mode')),
            f'{description} retained identity differs')
    return retained


def _identity(path: Path) -> dict[str, Any]:
    require(not path.is_symlink() and path.is_file(), f'input is not a physical file: {path}')
    status = path.stat()
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'size': status.st_size, 'mode': stat.S_IMODE(status.st_mode)}


def _copy_input(work: Path, name: str, source: Path) -> dict[str, Any]:
    require(not source.is_symlink(), f'input is not a physical file: {source}')
    source = source.resolve(strict=True)
    original = _identity(source)
    destination = work / 'retained' / 'inputs' / name
    destination.parent.mkdir(parents=True, exist_ok=False) if not destination.parent.exists() else None
    require(not destination.exists(), f'duplicate retained input: {name}')
    shutil.copyfile(source, destination)
    os.chmod(destination, original['mode'])
    retained = file_identity(destination, root=work)
    require(all(retained[key] == original[key] for key in ('sha256', 'size', 'mode')),
            f'input copy differs: {name}')
    return {**original, 'retained': retained['path']}


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(['git', '-C', str(root), *arguments], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False, text=True)
    require(completed.returncode == 0, 'current resolver source Git object is unavailable')
    return completed.stdout.strip()


def _git_file(root: Path, revision: str, relative: Path) -> tuple[int, bytes]:
    require(not relative.is_absolute() and '..' not in relative.parts, 'source file path escapes checkout')
    completed = subprocess.run(['git', '-C', str(root), 'ls-tree', revision, '--', relative.as_posix()],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    require(completed.returncode == 0 and completed.stdout.count('\n') == 1,
            f'selected source file is unavailable: {relative}')
    fields = completed.stdout.rstrip('\n').split(None, 3)
    require(len(fields) == 4 and fields[1] == 'blob' and fields[3] == relative.as_posix(),
            f'selected source file shape differs: {relative}')
    contents = subprocess.run(['git', '-C', str(root), 'show', f'{revision}:{relative.as_posix()}'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(contents.returncode == 0, f'selected source bytes are unavailable: {relative}')
    require(fields[0] in {'100644', '100755'}, f'selected source file is not a regular blob: {relative}')
    return int(fields[0], 8) & 0o777, contents.stdout


def _source_identity(root: Path, preparation: Path) -> dict[str, str]:
    preparation_value = read_json(preparation, 'static preparation')
    source = exact(preparation_value.get('source'), {'revision', 'content_sha256'}, 'static preparation source')
    current = static_products.source_identity(root)
    revision = current['revision']
    require(source['revision'] == revision and source['content_sha256'] == current['content_sha256'],
            'selected static preparation source is not current collector source')
    tree = _git(root, 'rev-parse', revision + '^{tree}')
    require(type(source['content_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', source['content_sha256']) is not None,
            'selected static preparation source hash differs')
    return {'revision': revision, 'tree': tree, 'source_sha256': current['content_sha256']}


def _source_paths(root: Path) -> dict[str, Path]:
    return {
        'reader': root / 'compat/x86_64/owned_resolver_alias_contract_reader.py',
        'runner': root / 'compat/x86_64/run_owned_resolver_alias_contract.sh',
        'probe': root / 'compat/x86_64/owned_resolver_alias_contract_probe.c',
        'override_probe': root / 'compat/x86_64/owned_resolver_alias_override_probe.c',
        'override_caller': root / 'compat/x86_64/owned_resolver_alias_override_caller.c',
        'contract': root / 'compat/x86_64/owned-resolver-alias-contract.md',
        'resolver_source': root / 'libc/src/c_abi/x86_64/resolver_runtime.rs',
        'static_c_abi_source': root / 'libc/src/c_abi/x86_64/static_c_abi.rs',
        'resolver_batch_source': root / 'libc/src/c_abi/x86_64/owned_resolver_batch.rs',
        'cargo_manifest': root / 'libc/Cargo.toml',
        'resolv_header': root / 'include/resolv.h',
        'feature_roster': root / 'compat/x86_64/feature_archive_roster.py',
        'parity_contract': root / 'compat/x86_64/parity.toml',
        'cancellation_contract': root / 'compat/x86_64/owned-resolver-cancellation.md',
        'header_c_probe': root / 'compat/x86_64/resolver_runtime_header_abi_probe.c',
        'header_cpp_probe': root / 'compat/x86_64/resolver_runtime_header_abi_probe.cpp',
        'header_runner': root / 'compat/x86_64/run_resolver_runtime_header_abi.sh',
        'legacy_probe': root / 'compat/x86_64/libc_resolver_runtime_probe.c',
        'legacy_runner': root / 'compat/x86_64/run_libc_resolver_runtime.sh',
        'static_authority': root / 'compat/x86_64/owned_static_link_authority.py',
        'elf_reader': root / 'compat/x86_64/loader_debug_abi_evidence.py',
        'product_authority': root / 'compat/x86_64/owned_posix_product_evidence.py',
        'image_manifest': root / 'compat/x86_64/owned-resolver-alias-image-inputs.json',
    }


def _product_paths(static_product: Path, dynamic_product: Path, product_report: Path,
                   static_preparation: Path, elf_facts: Path, base_inventory: Path) -> dict[str, Path]:
    return {
        'oracle_compiler': Path('/usr/local/bin/crabc-x86_64-musl-gcc'),
        'oracle_archive': Path('/opt/musl-1.2.6/lib/libc.a'),
        'oracle_shared': Path('/opt/musl-1.2.6/lib/libc.so'),
        'static_driver': static_product / 'bin/crabc-cc',
        'static_manifest': static_product / 'share/crabc/manifest.json',
        'static_libc': static_product / 'usr/lib/libc.a',
        'static_crt1': static_product / 'usr/lib/crt1.o',
        'static_rcrt1': static_product / 'usr/lib/rcrt1.o',
        'static_crti': static_product / 'usr/lib/crti.o',
        'static_crtn': static_product / 'usr/lib/crtn.o',
        'static_builtins': static_product / 'usr/lib/libcrabc-builtins.a',
        'dynamic_driver': dynamic_product / 'bin/crabc-cc-dynamic',
        'dynamic_libc': dynamic_product / 'usr/lib/libc.so',
        'dynamic_loader': dynamic_product / 'lib/ld-crabc-x86_64.so.1',
        'dynamic_crt1': dynamic_product / 'usr/lib/crt1.o',
        'dynamic_scrt1': dynamic_product / 'usr/lib/Scrt1.o',
        'dynamic_crti': dynamic_product / 'usr/lib/crti.o',
        'dynamic_crtn': dynamic_product / 'usr/lib/crtn.o',
        'dynamic_attach': dynamic_product / 'usr/lib/crabc-dynamic-attach.o',
        'dynamic_builtins': dynamic_product / 'usr/lib/libcrabc-builtins.a',
        'dynamic_manifest': dynamic_product / 'share/crabc/manifest.json',
        'dynamic_state': dynamic_product / 'share/crabc/dynamic-product-state.json',
        'product_report': product_report,
        'static_preparation': static_preparation,
        'elf_facts': elf_facts,
        'base_inventory': base_inventory,
    }


def _all_input_paths(root: Path, static_product: Path, dynamic_product: Path, product_report: Path,
                     static_preparation: Path, elf_facts: Path, base_inventory: Path) -> dict[str, Path]:
    values = {**_source_paths(root), **_product_paths(static_product, dynamic_product, product_report,
                                                       static_preparation, elf_facts, base_inventory)}
    require(set(values) == set(INPUT_NAMES), 'resolver current input roster differs')
    return values


def _validate_current_source_inputs(root: Path, revision: str, paths: Mapping[str, Path]) -> None:
    for name, path in _source_paths(root).items():
        require(paths[name] == path, f'resolver source input placement differs: {name}')
        require(not path.is_symlink() and path.is_file(), f'resolver source input is not physical: {name}')
        mode, bytes_at_revision = _git_file(root, revision, path.relative_to(root))
        require(stat.S_IMODE(path.stat().st_mode) == mode and path.read_bytes() == bytes_at_revision,
                f'resolver source input differs from selected source: {name}')


def _fact_occurrences(elf_facts_path: Path) -> list[dict[str, Any]]:
    """Preserve each raw fact row while assigning its canonical physical index."""
    value = read_json(elf_facts_path, 'full ELF facts')
    facts = value.get('facts')
    artifacts = value.get('artifacts')
    require(type(facts) is dict and type(artifacts) is dict, 'full ELF facts shape differs')
    try:
        import native_abi_elf_facts
        descriptors = native_abi_elf_facts.ARTIFACTS
    except (ImportError, AttributeError) as error:
        raise ReceiptError('full ELF fact artifact contract is unavailable') from error
    require(set(facts) == set(artifacts) == {item.key for item in descriptors},
            'full ELF fact artifact roster differs')
    result: list[dict[str, Any]] = []
    for artifact in descriptors:
        observed = facts[artifact.key]
        members = observed if artifact.kind == 'archive' else [observed]
        require(type(members) is list, f'full ELF fact archive shape differs: {artifact.key}')
        for member in members:
            require(type(member) is dict and type(member.get('symbol_tables')) is list,
                    f'full ELF fact member shape differs: {artifact.key}')
            for table in member['symbol_tables']:
                require(type(table) is dict and type(table.get('rows')) is list,
                        f'full ELF fact symbol table shape differs: {artifact.key}')
                for row in table['rows']:
                    require(type(row) is dict, f'full ELF fact symbol row differs: {artifact.key}')
                    name = row.get('name')
                    if not name:
                        role = 'unnamed'
                    elif row.get('section_index') == 'UND':
                        role = 'import'
                    elif row.get('binding') == 'LOCAL':
                        role = 'local-definition'
                    else:
                        role = 'definition'
                    result.append({
                        'index': len(result), 'artifact_key': artifact.key,
                        'member_index': member.get('member_index') if artifact.kind == 'archive' else None,
                        'member_occurrence': member.get('member_occurrence') if artifact.kind == 'archive' else None,
                        'member_name': member.get('member') if artifact.kind == 'archive' else None,
                        'table': table.get('name'), 'role': role, 'row': row,
                    })
    return result


def _record_in_work(work: Path, path: Path) -> dict[str, Any]:
    return {**file_identity(path, root=work), 'retained': path.relative_to(work).as_posix()}


def _command_records(work: Path) -> dict[str, Any]:
    commands: dict[str, Any] = {}
    for name in COMMAND_NAMES:
        argv = work / 'commands' / f'{name}.argv.json'
        status = work / 'commands' / f'{name}.status'
        stdout = work / 'commands' / f'{name}.stdout'
        stderr = work / 'commands' / f'{name}.stderr'
        for path in (argv, status, stdout, stderr):
            require(path.is_file() and not path.is_symlink(), f'missing retained command stream: {name}')
        commands[name] = {field: _record_in_work(work, path) for field, path in
                          (('argv', argv), ('status', status), ('stdout', stdout), ('stderr', stderr))}
    actual = {path.name.removesuffix('.argv.json') for path in (work / 'commands').glob('*.argv.json')}
    require(actual == set(COMMAND_NAMES), 'resolver command envelope roster differs')
    return commands


def _artifact_records(work: Path) -> dict[str, Any]:
    normal = {
        'oracle': work / 'outputs/oracle-contract',
        'static_et_exec': work / 'outputs/static-contract',
        'static_pie': work / 'outputs/static-pie-contract',
        'dynamic_pie': work / 'outputs/dynamic-pie-contract',
        'dynamic_non_pie': work / 'outputs/dynamic-non-pie-contract',
    }
    overrides = {f'{lane}_{alias}': work / f'outputs/{lane}-override-{alias}'
                 for lane in ('static', 'dynamic') for alias in ('mkquery', 'send', 'search')}
    objects = {'header_cpp': work / 'objects/header.cpp.o', 'public_probe': work / 'objects/public-probe.o'}
    for alias in ('mkquery', 'send', 'search'):
        objects[f'{alias}_definition'] = work / f'objects/override-{alias}-definition.o'
        objects[f'{alias}_caller'] = work / f'objects/override-{alias}-caller.o'
    for records in (normal, overrides, objects):
        require(all(path.is_file() and not path.is_symlink() for path in records.values()),
                'resolver artifact is absent or not physical')
    static_links = {
        'static_et_exec': {
            'receipt': work / 'static-contract.link.json',
            'map': work / 'static-contract.link.map',
            'trace': work / 'static-contract.link.trace',
        },
        'static_pie': {
            'receipt': work / 'static-pie-contract.link.json',
            'map': work / 'static-pie-contract.link.map',
            'trace': work / 'static-pie-contract.link.trace',
        },
    }
    require(all(path.is_file() and not path.is_symlink() for values in static_links.values() for path in values.values()),
            'resolver static link sidecar is absent or not physical')
    return {
        **{name: {key: _record_in_work(work, path) for key, path in values.items()}
           for name, values in (('normal', normal), ('overrides', overrides), ('object', objects))},
        'static_links': {mode: {key: _record_in_work(work, path) for key, path in values.items()}
                         for mode, values in static_links.items()},
    }


def _expected_command_argvs(inputs: Mapping[str, Any], origin_root: Path, origin_work: Path) -> dict[str, list[str]]:
    """Reconstruct the finite normal-source command roster without host tools."""
    path = {name: str(inputs[name]['path']) for name in INPUT_NAMES}
    work = str(origin_work)
    objects = f'{work}/objects'
    outputs = f'{work}/outputs'
    runtime = f'{work}/runtime'
    roots = f'{work}/roots'
    dynamic = path['dynamic_driver']
    static = path['static_driver']
    expected = {
        'header-c': [dynamic, '--dynamic-pie', '-x', 'c', '-std=c11', '-D_GNU_SOURCE', '-fno-builtin', '-fsyntax-only', path['header_c_probe']],
        'header-cpp': [dynamic, '--dynamic-pie', '-x', 'c++', '-std=c++17', '-D_GNU_SOURCE', '-fno-builtin', '-c', '-o', f'{objects}/header.cpp.o', path['header_cpp_probe']],
        'compile-public-probe': [dynamic, '--dynamic-pie', '-std=c11', '-D_GNU_SOURCE', '-pthread', '-fno-builtin', '-fno-stack-protector', '-c', path['probe'], '-o', f'{objects}/public-probe.o'],
        'public-probe-relocations': ['readelf', '--relocs', '--wide', f'{objects}/public-probe.o'],
        'oracle-symbols': ['readelf', '--symbols', '--wide', path['oracle_archive']],
        'oracle-runtime-link': [path['oracle_compiler'], '-std=c11', '-D_GNU_SOURCE', '-pthread', '-fno-builtin', '-fno-stack-protector', '-I', str(origin_root / 'include'), f'{objects}/public-probe.o', '-o', f'{outputs}/oracle-contract'],
        'oracle-runtime-run': ['timeout', '15', f'{outputs}/oracle-contract', f'{runtime}/oracle-root'],
        'static-symbols': ['readelf', '--symbols', '--wide', path['static_libc']],
        'static-private-calls': ['readelf', '--relocs', '--wide', path['static_libc']],
        'static-normal-et-exec-link': [static, '-static', '-pthread', f'{objects}/public-probe.o', '--link-receipt', 'static-contract.link.json', '-o', f'{outputs}/static-contract'],
        'static-normal-et-exec-runtime': ['timeout', '15', f'{outputs}/static-contract', f'{runtime}/static-root'],
        'static-normal-pie-link': [static, '-static-pie', '-pthread', f'{objects}/public-probe.o', '--link-receipt', 'static-pie-contract.link.json', '-o', f'{outputs}/static-pie-contract'],
        'static-normal-pie-runtime': ['timeout', '15', f'{outputs}/static-pie-contract', f'{runtime}/static-root'],
        'dynamic-symbols': ['readelf', '--symbols', '--wide', path['dynamic_libc']],
        'dynamic-normal-pie-link': [dynamic, '--dynamic-pie', '-pthread', '-rdynamic', f'{objects}/public-probe.o', '-o', f'{outputs}/dynamic-pie-contract'],
        'dynamic-normal-pie-dynsym': ['readelf', '--dyn-syms', '--wide', f'{outputs}/dynamic-pie-contract'],
        'dynamic-normal-pie-runtime': ['chroot', f'{roots}/dynamic-pie', '/contract', '/fixture'],
        'dynamic-normal-nopie-link': [dynamic, '--dynamic-non-pie', '-pthread', '-rdynamic', f'{objects}/public-probe.o', '-o', f'{outputs}/dynamic-non-pie-contract'],
        'dynamic-normal-nopie-dynsym': ['readelf', '--dyn-syms', '--wide', f'{outputs}/dynamic-non-pie-contract'],
        'dynamic-normal-nopie-runtime': ['chroot', f'{roots}/dynamic-non-pie', '/lib/ld-crabc-x86_64.so.1', '/contract', '/fixture'],
    }
    for alias, number, public in (('mkquery', '1', 'res_mkquery'), ('send', '2', 'res_send'), ('search', '3', 'res_search')):
        definition = f'{objects}/override-{alias}-definition.o'
        caller = f'{objects}/override-{alias}-caller.o'
        expected[f'compile-override-{alias}'] = [dynamic, '--dynamic-pie', '-std=c11', '-D_GNU_SOURCE', '-pthread', '-fno-builtin', '-fno-stack-protector', f'-DCRABC_RESOLVER_ALIAS_OVERRIDE={number}', '-c', path['override_probe'], '-o', definition]
        expected[f'compile-override-{alias}-caller'] = [dynamic, '--dynamic-pie', '-std=c11', '-D_GNU_SOURCE', '-pthread', '-fno-builtin', '-fno-stack-protector', f'-DCRABC_RESOLVER_ALIAS_OVERRIDE={number}', '-c', path['override_caller'], '-o', caller]
        expected[f'override-{alias}-public-relocation'] = ['readelf', '--relocs', '--wide', caller]
        expected[f'static-override-{alias}'] = [static, '-static', '-pthread', caller, definition, '--link-receipt', f'static-override-{alias}.link.json', '-o', f'{outputs}/static-override-{alias}']
        expected[f'static-override-{alias}-runtime'] = [f'{outputs}/static-override-{alias}']
        expected[f'dynamic-override-{alias}'] = [dynamic, '--dynamic-pie', '-pthread', '-rdynamic', caller, definition, '-o', f'{outputs}/dynamic-override-{alias}']
        expected[f'dynamic-override-{alias}-dynsym'] = ['readelf', '--dyn-syms', '--wide', f'{outputs}/dynamic-override-{alias}']
        expected[f'dynamic-override-{alias}-runtime'] = ['chroot', f'{roots}/dynamic-override-{alias}', '/contract']
    require(set(expected) == set(COMMAND_NAMES), 'resolver expected command roster differs')
    return expected


def _validate_commands(commands: Any, receipt_root: Path, inputs: Mapping[str, Any], origin_root: Path,
                       origin_work: Path) -> dict[str, Any]:
    commands = exact(commands, set(COMMAND_NAMES), 'resolver command roster')
    expected_argv = _expected_command_argvs(inputs, origin_root, origin_work)
    for name in COMMAND_NAMES:
        command = exact(commands[name], {'argv', 'status', 'stdout', 'stderr'}, f'resolver command {name}')
        argv_path = _retained_record(receipt_root, command['argv'], f'resolver command {name} argv')
        argv = read_json(argv_path, f'resolver command {name} argv')
        require(exact(argv, {'argv', 'cwd', 'environment', 'stdin'}, f'resolver command {name} envelope')['stdin'] == '/dev/null',
                f'resolver command {name} stdin differs')
        require(type(argv['argv']) is list and argv['argv'] and all(type(item) is str for item in argv['argv'])
                and argv['cwd'] == str(origin_work) and argv['environment'] == {'LC_ALL': 'C', 'PATH': '/opt/cargo/bin:/usr/bin:/bin'},
                f'resolver command {name} envelope differs')
        require(argv['argv'] == expected_argv[name], f'resolver command argv differs: {name}')
        status = _retained_record(receipt_root, command['status'], f'resolver command {name} status')
        require(status.read_text(encoding='ascii') == '0\n', f'resolver command {name} status differs')
        for stream in ('stdout', 'stderr'):
            _retained_record(receipt_root, command[stream], f'resolver command {name} {stream}')
    for alias, public in (('mkquery', 'res_mkquery'), ('send', 'res_send'), ('search', 'res_search')):
        stream = _retained_record(receipt_root, commands[f'override-{alias}-public-relocation']['stdout'],
                                  f'{public} override caller relocation')
        require(public in stream.read_text(encoding='utf-8'), f'{public} override caller has no public relocation')
    public_relocations = _retained_record(receipt_root, commands['public-probe-relocations']['stdout'],
                                         'resolver public caller relocations').read_text(encoding='utf-8')
    require(all(name in public_relocations for name, _target in ALIASES)
            and not any(body in public_relocations for body in PRIVATE_BODIES),
            'resolver normal caller public import boundary differs')
    private_relocations = _retained_record(receipt_root, commands['static-private-calls']['stdout'],
                                           'resolver selected private relocations').read_text(encoding='utf-8')
    require(all(name in private_relocations for name in PRIVATE_BODIES),
            'resolver selected private relocation roster differs')
    for mode in ('dynamic-normal-pie', 'dynamic-normal-nopie'):
        symbols = _retained_record(receipt_root, commands[f'{mode}-dynsym']['stdout'],
                                   f'{mode} dynamic symbols').read_text(encoding='utf-8')
        require(all(re.search(r'UND\s+' + re.escape(name) + r'$', symbols, re.MULTILINE) is not None
                    for name, _target in ALIASES),
                f'{mode} normal public dynamic imports differ')
    for alias, public in (('mkquery', 'res_mkquery'), ('send', 'res_send'), ('search', 'res_search')):
        symbols = _retained_record(receipt_root, commands[f'dynamic-override-{alias}-dynsym']['stdout'],
                                   f'{public} dynamic override symbols').read_text(encoding='utf-8')
        require(re.search(r'FUNC\s+GLOBAL\s+DEFAULT\s+\S+\s+' + re.escape(public) + r'$', symbols, re.MULTILINE) is not None,
                f'{public} dynamic strong override export differs')
    return commands


def _validate_runtime(runtime: Any, receipt_root: Path) -> dict[str, Any]:
    runtime = exact(runtime, {'oracle', 'static-et-exec', 'static-pie', 'dynamic-pie', 'dynamic-non-pie'},
                    'resolver runtime root roster')
    for name, value in runtime.items():
        transcript = _retained_record(receipt_root, value, f'resolver runtime {name}')
        require(transcript.read_text(encoding='ascii') == '0\n', f'resolver runtime {name} differs')
    return runtime


def _validate_artifacts(artifacts: Any, receipt_root: Path) -> dict[str, Any]:
    artifacts = exact(artifacts, {'normal', 'overrides', 'object', 'static_links'}, 'resolver artifact roster')
    expected = {
        'normal': {'oracle', 'static_et_exec', 'static_pie', 'dynamic_pie', 'dynamic_non_pie'},
        'overrides': {f'{lane}_{alias}' for lane in ('static', 'dynamic') for alias in ('mkquery', 'send', 'search')},
        'object': {'header_cpp', 'public_probe', *(f'{alias}_{kind}' for alias in ('mkquery', 'send', 'search')
                                      for kind in ('definition', 'caller'))},
    }
    for category, names in expected.items():
        values = exact(artifacts[category], names, f'resolver {category} artifact roster')
        for name in names:
            _retained_record(receipt_root, values[name], f'resolver {category} artifact {name}')
    static_links = exact(artifacts['static_links'], {'static_et_exec', 'static_pie'}, 'resolver static link roster')
    for mode in ('static_et_exec', 'static_pie'):
        records = exact(static_links[mode], {'receipt', 'map', 'trace'}, f'resolver {mode} static link roster')
        for name, value in records.items():
            _retained_record(receipt_root, value, f'resolver {mode} static link {name}')
    return artifacts


def _elf_symbols(path: Path, *, dynamic: bool) -> list[dict[str, Any]]:
    """Read the one retained ELF symbol-table domain needed by this receipt."""
    from loader_debug_abi_evidence import Elf, EvidenceError
    try:
        elf = Elf(path)
        table_type = 11 if dynamic else 2
        rows: list[dict[str, Any]] = []
        for index, section in enumerate(elf.sections):
            if section[1] != table_type:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, 'retained resolver symbol table differs')
            rows.extend(elf.symbol_row(index, number) for number in range(section[5] // 24))
        require(len(rows) > 0, 'retained resolver symbol table is empty')
        return rows
    except EvidenceError as error:
        raise ReceiptError(f'retained resolver ELF differs: {error}') from error


def _one_elf_symbol(rows: Sequence[Mapping[str, Any]], name: str, description: str) -> Mapping[str, Any]:
    matching = [row for row in rows if row.get('name') == name]
    require(len(matching) == 1, f'{description} symbol differs: {name}')
    return matching[0]


def _validate_linked_public_symbol_domains(receipt_root: Path, artifacts: Mapping[str, Any]) -> None:
    """Cross-check retained streams against the linked ordinary source outputs."""
    public_object = _retained_record(receipt_root, artifacts['object']['public_probe'], 'resolver public probe')
    rows = _elf_symbols(public_object, dynamic=False)
    for name, _target in ALIASES:
        row = _one_elf_symbol(rows, name, 'resolver normal public caller')
        require(row['section'] == 0 and row['binding'] == 'GLOBAL' and row['visibility'] == 'DEFAULT',
                f'resolver normal public caller import differs: {name}')
    require(not any(row.get('name') in PRIVATE_BODIES for row in rows),
            'resolver normal public caller names a private body')
    for mode in ('dynamic_pie', 'dynamic_non_pie'):
        output = _retained_record(receipt_root, artifacts['normal'][mode], f'{mode} resolver output')
        rows = _elf_symbols(output, dynamic=True)
        for name, _target in ALIASES:
            row = _one_elf_symbol(rows, name, f'{mode} resolver public import')
            require(row['section'] == 0 and row['binding'] == 'GLOBAL' and row['visibility'] == 'DEFAULT',
                    f'{mode} resolver public import differs: {name}')
    for alias, public in (('mkquery', 'res_mkquery'), ('send', 'res_send'), ('search', 'res_search')):
        caller = _retained_record(receipt_root, artifacts['object'][f'{alias}_caller'], f'{public} override caller')
        caller_symbol = _one_elf_symbol(_elf_symbols(caller, dynamic=False), public, f'{public} override caller')
        require(caller_symbol['section'] == 0 and caller_symbol['binding'] == 'GLOBAL'
                and caller_symbol['visibility'] == 'DEFAULT', f'{public} override caller import differs')
        output = _retained_record(receipt_root, artifacts['overrides'][f'dynamic_{alias}'],
                                  f'{public} dynamic override output')
        definition = _one_elf_symbol(_elf_symbols(output, dynamic=True), public, f'{public} dynamic override')
        require(definition['section'] != 0 and definition['type'] == 'FUNC'
                and definition['binding'] == 'GLOBAL' and definition['visibility'] == 'DEFAULT',
                f'{public} dynamic strong override definition differs')


def _validate_selected_source_routes(receipt_root: Path, inputs: Mapping[str, Any]) -> None:
    """Derive the finite selected and legacy caller distinction from source bytes."""
    source = _retained_record(receipt_root, inputs['resolver_source'], 'resolver source').read_text(encoding='utf-8')
    assembly = source[source.index('core::arch::global_asm!('):source.index('/// Encode one selected recursive Internet DNS question')]
    for line in ('.hidden __res_mkquery', '.weak res_mkquery', '.set res_mkquery, __res_mkquery',
                 '.hidden __res_send', '.weak res_send', '.set res_send, __res_send',
                 '.weak res_search', '.set res_search, res_query'):
        require(line in assembly, 'resolver source alias assembly route differs')
    query = source[source.index('unsafe fn query_response('):source.index('pub unsafe extern "C" fn res_query(')]
    require('__res_mkquery(' in query and '__res_send(' in query,
            'resolver selected query-response private caller route differs')
    legacy_start = source.index('unsafe fn lookup_dns_records(')
    legacy_end = source.index('pub unsafe extern "C" fn getaddrinfo(', legacy_start)
    require('__res_send(' in source[legacy_start:legacy_end], 'resolver legacy source caller differs')
    cfg_start = source.rfind('#[cfg(not(feature = "x86-owned-static-runtime"))]', 0, legacy_start)
    require(cfg_start >= 0 and cfg_start < legacy_start,
            'resolver legacy source caller is not excluded from the selected runtime')


def _origin_root(inputs: Mapping[str, Any]) -> Path:
    reader = _validate_identity_record(inputs['reader'], 'resolver reader input')
    recorded = Path(reader['path'])
    relative = Path('compat/x86_64/owned_resolver_alias_contract_reader.py')
    require(recorded.is_absolute() and '..' not in recorded.parts
            and recorded.parts[-len(relative.parts):] == relative.parts,
            'resolver receipt source root differs')
    return recorded.parents[len(relative.parts) - 1]


def _validate_inputs(report: Mapping[str, Any], receipt_root: Path, root: Path,
                     static_product: Path, dynamic_product: Path, product_report: Path,
                     static_preparation: Path, elf_facts: Path, base_inventory: Path) -> Path:
    expected_paths = _all_input_paths(root, static_product, dynamic_product, product_report,
                                      static_preparation, elf_facts, base_inventory)
    _validate_current_source_inputs(root, report['selected_source']['revision'], expected_paths)
    inputs = exact(report['inputs'], set(INPUT_NAMES), 'resolver input roster')
    origin_root = _origin_root(inputs)
    image_manifest = read_json(_source_paths(root)['image_manifest'], 'resolver image manifest')
    require(type(image_manifest.get('files')) is dict, 'resolver image manifest file roster differs')
    for name, source in expected_paths.items():
        if name in {'oracle_compiler', 'oracle_archive', 'oracle_shared'}:
            continue
        require(not source.is_symlink(), f'resolver current input is not physical: {name}')
        record = _validate_identity_record(inputs[name], f'resolver input {name}')
        require(record['path'] == str(origin_root / source.resolve(strict=True).relative_to(root)),
                f'resolver input path differs: {name}')
        current = _identity(source.resolve(strict=True))
        require(all(record[key] == current[key] for key in ('sha256', 'size', 'mode')),
                f'resolver current input differs: {name}')
        retained = _retained_record(receipt_root, record, f'resolver input {name}')
        retained_identity = file_identity(retained, root=receipt_root)
        require(all(retained_identity[key] == current[key] for key in ('sha256', 'size', 'mode')),
                f'resolver retained/current input differs: {name}')
    for name, invocation in (('oracle_compiler', '/usr/local/bin/crabc-x86_64-musl-gcc'),
                             ('oracle_archive', '/opt/musl-1.2.6/lib/libc.a'),
                             ('oracle_shared', '/opt/musl-1.2.6/lib/libc.so')):
        record = _validate_identity_record(inputs[name], f'resolver input {name}')
        expected = image_manifest['files'].get(invocation)
        require(type(expected) is dict and all(record[key] == expected.get(key) for key in ('sha256', 'size', 'mode')),
                f'resolver retained pinned image input differs: {name}')
        _retained_record(receipt_root, record, f'resolver input {name}')
    try:
        product_evidence._validate_static_product(static_product)
        product_evidence._validate_dynamic_product(dynamic_product)
    except product_evidence.ProductEvidenceError as error:
        raise ReceiptError(f'supplied product contract differs: {error}') from error
    return origin_root


def _validate_product_cohort_links(root: Path, origin_root: Path, source: Mapping[str, Any], static_product: Path,
                                  dynamic_product: Path, product_report: Path,
                                  static_preparation: Path) -> None:
    """Bind the two supplied product roots to their selected cohort records."""
    preparation = read_json(static_preparation, 'static preparation')
    preparation_source = exact(preparation.get('source'), {'revision', 'content_sha256'},
                               'static preparation source')
    require(preparation_source['revision'] == source['revision']
            and preparation_source['content_sha256'] == source['source_sha256'],
            'static preparation source cohort differs')
    products = exact(preparation.get('products'), {'extracted', 'primary', 'reproduction'},
                     'static preparation products')
    primary = products['primary']
    require(type(primary) is dict and type(primary.get('path')) is str
            and (root / primary['path']).resolve(strict=True) == static_product.resolve(strict=True),
            'static preparation primary product differs')
    anchor = read_json(product_report, 'loader-debug product report')
    require(anchor.get('source_commit') == source['revision'] and anchor.get('source_sha256') == source['source_sha256'],
            'loader-debug product source cohort differs')
    artifacts = anchor.get('artifacts')
    require(type(artifacts) is dict, 'loader-debug product artifacts differ')
    expected = {
        'static-manifest': (static_product / 'share/crabc/manifest.json', False),
        'dynamic-manifest': (dynamic_product / 'share/crabc/manifest.json', True),
        'dynamic-state': (dynamic_product / 'share/crabc/dynamic-product-state.json', True),
        'candidate-libc': (dynamic_product / 'usr/lib/libc.so', True),
        'candidate-loader': (dynamic_product / 'lib/ld-crabc-x86_64.so.1', True),
    }
    for name, (path, exact_path) in expected.items():
        record = artifacts.get(name)
        identity = _identity(path)
        require(type(record) is dict and (not exact_path or record.get('path') == str(origin_root / path.relative_to(root)))
                and record.get('sha256') == identity['sha256'] and record.get('size') == identity['size'],
                f'loader-debug product artifact differs: {name}')


def _validate_measurement_cohort(elf_facts: Path, base_inventory: Path, static_product: Path,
                                 dynamic_product: Path, static_preparation: Path) -> None:
    """Use the existing public inventory/facts replay for this supplied cohort."""
    try:
        import native_abi_elf_facts
        import native_abi_inventory
        native_abi_inventory.validate_report(base_inventory, static_product=static_product,
                                             dynamic_product=dynamic_product, static_preparation=static_preparation)
        native_abi_elf_facts.validate_report(elf_facts, base_inventory=base_inventory,
                                             static_product=static_product, dynamic_product=dynamic_product,
                                             static_preparation=static_preparation)
    except native_abi_inventory.InventoryError as error:
        raise ReceiptError(f'supplied public measurement cohort differs: {error}') from error


def _archive_members(data: bytes) -> list[tuple[str, bytes]]:
    """Decode only the ordinary GNU ar members admitted to the static helper."""
    require(data.startswith(b'!<arch>\n'), 'selected static archive bytes differ')
    cursor, long_names, members = 8, b'', []
    while cursor < len(data):
        header = data[cursor:cursor + 60]
        require(len(header) == 60 and header[58:] == b'`\n', 'selected static archive member differs')
        name, size = header[:16].rstrip(), int(header[48:58])
        start = cursor + 60
        body = data[start:start + size]
        require(len(body) == size, 'selected static archive member is truncated')
        cursor = start + size + size % 2
        if name == b'//':
            long_names = body
        elif name not in (b'/', b'/SYM64/'):
            if name.startswith(b'/'):
                offset = int(name[1:])
                end = long_names.find(b'/\n', offset)
                require(0 <= offset < len(long_names) and end >= 0, 'selected static archive long name differs')
                name = long_names[offset:end]
            else:
                require(name.endswith(b'/'), 'selected static archive member name differs')
                name = name[:-1]
            members.append((name.decode('ascii'), body))
    require(cursor == len(data) and members, 'selected static archive trailing bytes differ')
    return members


def _static_admitted_inputs(receipt_root: Path, origin_work: Path, artifacts: Mapping[str, Any],
                           inputs: Mapping[str, Any], entry: str) -> dict[str, Path | bytes]:
    """Name exact ordinary-link owners for the finite static helper call."""
    public_probe = _retained_record(receipt_root, artifacts['object']['public_probe'], 'resolver public probe')
    admitted: dict[str, Path | bytes] = {
        str(origin_work / 'objects/public-probe.o'): public_probe,
        inputs[entry]['path']: _retained_record(receipt_root, inputs[entry], entry),
        inputs['static_crti']['path']: _retained_record(receipt_root, inputs['static_crti'], 'static crti'),
        inputs['static_crtn']['path']: _retained_record(receipt_root, inputs['static_crtn'], 'static crtn'),
    }
    for name in ('static_libc', 'static_builtins'):
        archive = _retained_record(receipt_root, inputs[name], name)
        for member, data in _archive_members(archive.read_bytes()):
            owner = f"{inputs[name]['path']}({member})"
            require(owner not in admitted, 'selected static archive member is duplicated')
            admitted[owner] = data
    return admitted


def _static_provider_owners(admitted: Mapping[str, Path | bytes], static_archive: str) -> dict[str, str]:
    from owned_static_link_authority import elf_bytes
    wanted = {*PRIVATE_BODIES, *(alias for alias, _target in ALIASES), 'res_query'}
    owners: dict[str, str] = {}
    for owner, value in admitted.items():
        if not owner.startswith(static_archive + '('):
            continue
        require(type(value) is bytes, 'selected static archive member bytes differ')
        elf = elf_bytes(value)
        for table_index, table in enumerate(elf.sections):
            if table[1] != 2:
                continue
            require(table[9] == 24 and table[5] % 24 == 0, 'selected static archive symbol table differs')
            strings = elf.sections[table[6]]
            require(strings[1] == 3 and strings[4] + strings[5] <= len(elf.data),
                    'selected static archive symbol strings differ')
            for number in range(table[5] // 24):
                offset = elf.unpack('<I', table[4] + number * 24)[0]
                require(offset < strings[5], 'selected static archive symbol name differs')
                start = strings[4] + offset
                end = elf.data.find(b'\0', start, strings[4] + strings[5])
                require(end >= 0, 'selected static archive symbol name is unterminated')
                name = elf.data[start:end].decode('ascii')
                if name in wanted and elf.symbol_row(table_index, number)['section']:
                    require(name not in owners, f'selected static archive provider is duplicated: {name}')
                    owners[name] = owner
    require(set(owners) == wanted, 'selected static archive provider roster differs')
    return owners


def _validate_static_link_authority(receipt_root: Path, origin_work: Path, artifacts: Mapping[str, Any],
                                    inputs: Mapping[str, Any]) -> None:
    """Replay the existing finite static byte authority for the two normal links."""
    from owned_static_link_authority import StaticFunctionContract, StaticLinkAuthorityError, require_static_functions
    for mode, entry, binary in (
        ('static_et_exec', 'static_crt1', 'static_et_exec'),
        ('static_pie', 'static_rcrt1', 'static_pie'),
    ):
        sidecars = artifacts['static_links'][mode]
        receipt = read_json(_retained_record(receipt_root, sidecars['receipt'], f'{mode} link receipt'),
                            f'{mode} link receipt')
        require(type(receipt) is dict and receipt.get('schema') == 1
                and receipt.get('format') == 'crabc-x86-64-sealed-static-driver-v1'
                and receipt.get('target') == 'x86_64-unknown-linux-musl',
                f'{mode} static link receipt identity differs')
        expected_mode = {
            'static_et_exec': {'id': 'static-et-exec', 'elf_type': 'ET_EXEC', 'crt_object': 'crt1.o', 'interpreter': 'absent'},
            'static_pie': {'id': 'static-pie', 'elf_type': 'ET_DYN', 'crt_object': 'rcrt1.o', 'interpreter': 'absent'},
        }[mode]
        require(receipt.get('mode') == expected_mode, f'{mode} static link mode differs')
        executable = _retained_record(receipt_root, artifacts['normal'][binary], f'{mode} static executable')
        map_path = _retained_record(receipt_root, sidecars['map'], f'{mode} static map')
        trace_path = _retained_record(receipt_root, sidecars['trace'], f'{mode} static trace')
        require(receipt.get('output') == {
                    'path': str(origin_work / f"outputs/{'static-contract' if mode == 'static_et_exec' else 'static-pie-contract'}"),
                    'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                },
                f'{mode} static link output differs')
        require(receipt.get('map') == {'path': map_path.name, 'sha256': hashlib.sha256(map_path.read_bytes()).hexdigest()}
                and receipt.get('trace') == {'path': trace_path.name, 'sha256': hashlib.sha256(trace_path.read_bytes()).hexdigest()},
                f'{mode} static link sidecar differs')
        admitted = _static_admitted_inputs(receipt_root, origin_work, artifacts, inputs, entry)
        providers = _static_provider_owners(admitted, inputs['static_libc']['path'])
        contracts = [
            StaticFunctionContract('main', str(origin_work / 'objects/public-probe.o'),
                                   'GLOBAL', 'DEFAULT', 'GLOBAL', 'DEFAULT'),
            StaticFunctionContract('_start', inputs[entry]['path'], 'GLOBAL', 'DEFAULT', 'GLOBAL', 'DEFAULT'),
        ]
        for alias, target in ALIASES:
            contracts.append(StaticFunctionContract(alias, providers[alias], 'WEAK', 'DEFAULT', 'WEAK', 'DEFAULT'))
            if target in PRIVATE_BODIES:
                contracts.append(StaticFunctionContract(target, providers[target], 'GLOBAL', 'HIDDEN', 'LOCAL', 'HIDDEN'))
        try:
            require_static_functions(map_path, executable, admitted, contracts)
        except StaticLinkAuthorityError as error:
            raise ReceiptError(f'{mode} selected static function authority differs: {error}') from error


def validate_report(report_path: Path, *, root: Path = ROOT, static_product: Path | None = None,
                    dynamic_product: Path | None = None, product_report: Path | None = None,
                    static_preparation: Path | None = None, elf_facts: Path | None = None,
                    base_inventory: Path | None = None) -> dict[str, Any]:
    """Replay retained bytes against the exact supplied current product cohort.

    Replay never invokes a compiler, linker, readelf, or target product tool.
    It consumes only retained command streams/objects and compares their input
    identities to the caller-supplied current cohort.
    """
    require(all(value is not None for value in (static_product, dynamic_product, product_report,
                                                 static_preparation, elf_facts, base_inventory)),
            'resolver replay requires the complete selected product cohort')
    root = root.resolve(strict=True)
    report_path = report_path.resolve(strict=True)
    receipt_root = report_path.parent
    report = read_json(report_path, 'resolver alias report')
    report = exact(report, {
        'schema', 'status', 'component', 'collection', 'selected_source', 'collector', 'inputs',
        'selected_products', 'static_preparation', 'product_input_modes', 'measurement_reports',
        'source_alias_routes', 'observations', 'artifacts', 'commands', 'execution', 'runtime', 'coverage',
    }, 'resolver alias report')
    require(report['schema'] == SCHEMA and report['status'] == STATUS and report['component'] == COMPONENT,
            'resolver alias report identity differs')
    collection = exact(report['collection'], {'image', 'source_revision'}, 'resolver collection')
    require(collection['image'] == IMAGE, 'resolver collection image differs')
    source = _source_identity(root, Path(static_preparation))
    require(collection['source_revision'] == source['revision'] and same(report['selected_source'], source)
            and same(report['collector'], source), 'resolver selected/collector source differs')
    origin_root = _validate_inputs(report, receipt_root, root, Path(static_product), Path(dynamic_product), Path(product_report),
                                   Path(static_preparation), Path(elf_facts), Path(base_inventory))
    require(receipt_root.is_relative_to(root / '.work'), 'resolver host receipt root differs')
    origin_work = origin_root / receipt_root.relative_to(root)
    _validate_product_cohort_links(root, origin_root, source, Path(static_product), Path(dynamic_product),
                                   Path(product_report), Path(static_preparation))
    _validate_measurement_cohort(Path(elf_facts), Path(base_inventory), Path(static_product),
                                 Path(dynamic_product), Path(static_preparation))
    require(same(report['product_input_modes'], LINK_INPUT_MODES), 'resolver source product mode policy differs')
    require(report['source_alias_routes'] == list(SOURCE_ALIAS_ROUTES), 'resolver source alias routes differ')
    require(report['coverage'] == coverage_projection(), 'resolver coverage differs')
    selected_products = exact(report['selected_products'], {'static', 'dynamic', 'product_report'},
                              'resolver selected product roster')
    require(selected_products == {'static': ['static_driver', 'static_manifest', 'static_libc'],
                                  'dynamic': ['dynamic_driver', 'dynamic_manifest', 'dynamic_state', 'dynamic_libc', 'dynamic_loader'],
                                  'product_report': 'product_report'}, 'resolver selected product projection differs')
    static_projection = exact(report['static_preparation'], {'input', 'products'}, 'resolver static preparation')
    require(static_projection == {'input': 'static_preparation', 'products': 'primary'},
            'resolver static preparation projection differs')
    measurements = exact(report['measurement_reports'], {'elf_facts', 'base_inventory', 'occurrence_count', 'unnamed_count'},
                         'resolver measurement report roster')
    occurrences = _fact_occurrences(Path(elf_facts))
    require(measurements['elf_facts'] == 'elf_facts' and measurements['base_inventory'] == 'base_inventory'
            and measurements['occurrence_count'] == len(occurrences)
            and measurements['unnamed_count'] == sum(row['role'] == 'unnamed' for row in occurrences),
            'resolver full fact accounting differs')
    observations = exact(report['observations'], {'candidate_occurrences', 'candidate_projection', 'public_caller', 'private_calls', 'overrides'},
                         'resolver observations')
    selected_rows = [row for row in occurrences if row['artifact_key'] in {'candidate-static', 'candidate-shared'}
                     and type(row.get('row')) is dict and row['row'].get('name') in KNOWN_NAMES]
    require(same(observations['candidate_occurrences'], selected_rows), 'resolver candidate facts differ')
    projection = validate_candidate_occurrences(selected_rows)
    require(same(observations['candidate_projection'], projection), 'resolver candidate occurrence projection differs')
    require(observations['public_caller'] == {'public_imports': [name for name, _target in ALIASES], 'no_private_imports': True},
            'resolver public caller boundary differs')
    require(observations['private_calls'] == {'__res_mkquery': ['query_response'], '__res_send': ['query_response']},
            'resolver private source call ownership differs')
    require(observations['overrides'] == ['res_mkquery', 'res_send', 'res_search'],
            'resolver strong override roster differs')
    _validate_artifacts(report['artifacts'], receipt_root)
    _validate_linked_public_symbol_domains(receipt_root, report['artifacts'])
    _validate_static_link_authority(receipt_root, origin_work, report['artifacts'], report['inputs'])
    _validate_selected_source_routes(receipt_root, report['inputs'])
    _validate_commands(report['commands'], receipt_root, report['inputs'], origin_root, origin_work)
    execution = exact(report['execution'], {'image', 'stdin', 'environment'}, 'resolver execution')
    require(execution == {'image': IMAGE, 'stdin': '/dev/null', 'environment': {'LC_ALL': 'C', 'PATH': '/opt/cargo/bin:/usr/bin:/bin'}},
            'resolver execution boundary differs')
    _validate_runtime(report['runtime'], receipt_root)
    require(same(report, read_json(report_path, 'resolver alias report final recheck')),
            'resolver alias report changed during replay')
    return {'status': STATUS, 'coverage': coverage_projection(),
            'candidate_occurrence_count': projection['candidate_occurrence_count'],
            'full_occurrence_count': len(occurrences),
            'unnamed_occurrence_count': sum(row['role'] == 'unnamed' for row in occurrences),
            'source_alias_routes': list(SOURCE_ALIAS_ROUTES)}


def collect_report(*, root: Path, work: Path, static_product: Path, dynamic_product: Path,
                   product_report: Path, static_preparation: Path, elf_facts: Path,
                   base_inventory: Path, image: str) -> dict[str, Any]:
    """Seal a completed normal-source runner into a finite replay receipt."""
    root = root.resolve(strict=True)
    work = work.resolve(strict=True)
    require(root == ROOT and work.is_relative_to(root / '.work') and image == IMAGE,
            'resolver collector boundary differs')
    require(not (work / 'report.json').exists(), 'resolver receipt report already exists')
    source = _source_identity(root, static_preparation)
    paths = _all_input_paths(root, static_product, dynamic_product, product_report, static_preparation, elf_facts, base_inventory)
    _validate_current_source_inputs(root, source['revision'], paths)
    try:
        product_evidence._validate_static_product(static_product)
        product_evidence._validate_dynamic_product(dynamic_product)
    except product_evidence.ProductEvidenceError as error:
        raise ReceiptError(f'supplied product contract differs: {error}') from error
    inputs = {name: _copy_input(work, name, path) for name, path in paths.items()}
    occurrences = _fact_occurrences(elf_facts)
    selected_rows = [row for row in occurrences if row['artifact_key'] in {'candidate-static', 'candidate-shared'}
                     and type(row.get('row')) is dict and row['row'].get('name') in KNOWN_NAMES]
    projection = validate_candidate_occurrences(selected_rows)
    commands = _command_records(work)
    report = {
        'schema': SCHEMA, 'status': STATUS, 'component': COMPONENT,
        'collection': {'image': image, 'source_revision': source['revision']},
        'selected_source': source, 'collector': source, 'inputs': inputs,
        'selected_products': {'static': ['static_driver', 'static_manifest', 'static_libc'],
                              'dynamic': ['dynamic_driver', 'dynamic_manifest', 'dynamic_state', 'dynamic_libc', 'dynamic_loader'],
                              'product_report': 'product_report'},
        'static_preparation': {'input': 'static_preparation', 'products': 'primary'},
        'product_input_modes': LINK_INPUT_MODES,
        'measurement_reports': {'elf_facts': 'elf_facts', 'base_inventory': 'base_inventory',
                                'occurrence_count': len(occurrences),
                                'unnamed_count': sum(row['role'] == 'unnamed' for row in occurrences)},
        'source_alias_routes': list(SOURCE_ALIAS_ROUTES),
        'observations': {
            'candidate_occurrences': selected_rows, 'candidate_projection': projection,
            'public_caller': {'public_imports': [name for name, _target in ALIASES], 'no_private_imports': True},
            'private_calls': {'__res_mkquery': ['query_response'], '__res_send': ['query_response']},
            'overrides': ['res_mkquery', 'res_send', 'res_search'],
        },
        'artifacts': _artifact_records(work), 'commands': commands,
        'execution': {'image': IMAGE, 'stdin': '/dev/null', 'environment': {'LC_ALL': 'C', 'PATH': '/opt/cargo/bin:/usr/bin:/bin'}},
        'runtime': {
            'oracle': commands['oracle-runtime-run']['status'],
            'static-et-exec': commands['static-normal-et-exec-runtime']['status'],
            'static-pie': commands['static-normal-pie-runtime']['status'],
            'dynamic-pie': commands['dynamic-normal-pie-runtime']['status'],
            'dynamic-non-pie': commands['dynamic-normal-nopie-runtime']['status'],
        },
        'coverage': coverage_projection(),
    }
    output = work / 'report.json'
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return validate_report(output, root=root, static_product=static_product, dynamic_product=dynamic_product,
                           product_report=product_report, static_preparation=static_preparation,
                           elf_facts=elf_facts, base_inventory=base_inventory)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--collect-report', action='store_true')
    action.add_argument('--validate-report', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--static-product', type=Path)
    parser.add_argument('--dynamic-product', type=Path)
    parser.add_argument('--product-report', type=Path)
    parser.add_argument('--static-preparation', type=Path)
    parser.add_argument('--elf-facts', type=Path)
    parser.add_argument('--base-inventory', type=Path)
    parser.add_argument('--image')
    arguments = parser.parse_args()
    try:
        complete = (arguments.static_product, arguments.dynamic_product, arguments.product_report,
                    arguments.static_preparation, arguments.elf_facts, arguments.base_inventory)
        require(all(value is not None for value in complete),
                'resolver receipt action requires the complete selected product cohort')
        if arguments.collect_report:
            require(arguments.root is not None and arguments.work is not None and arguments.image is not None,
                    '--collect-report requires --root, --work, and --image')
            result = collect_report(root=arguments.root, work=arguments.work,
                                    static_product=arguments.static_product, dynamic_product=arguments.dynamic_product,
                                    product_report=arguments.product_report, static_preparation=arguments.static_preparation,
                                    elf_facts=arguments.elf_facts, base_inventory=arguments.base_inventory,
                                    image=arguments.image)
        else:
            require(arguments.root is not None, '--validate-report requires --root')
            result = validate_report(arguments.validate_report, root=arguments.root,
                                     static_product=arguments.static_product, dynamic_product=arguments.dynamic_product,
                                     product_report=arguments.product_report, static_preparation=arguments.static_preparation,
                                     elf_facts=arguments.elf_facts, base_inventory=arguments.base_inventory)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ReceiptError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
