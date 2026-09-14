#!/usr/bin/env python3
"""Finite declaration-runtime contract for installed public data objects.

This module owns a fixed nineteen-variable semantic receipt.  It deliberately
keeps the `h_errno` runtime evidence in the existing errno lifecycle reader and
will compose that owner only after the public declaration envelope is replayed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import owned_posix_product_evidence as product_evidence
import owned_posix_static_products as static_products
import public_data_ordinary_link_evidence as ordinary_link
import header_declaration_inventory
import native_declaration_abi
import native_data_declarations
import owned_errno_storage_lifecycle
CONTRACT_PATH = MODULE_DIR / 'owned_public_data_variable_runtime.toml'
SCHEMA = 'crabc.x86_64-owned-public-data-variable-runtime/v1'
CONTRACT_SCHEMA = 'crabc.x86_64-owned-public-data-variable-runtime-contract/v1'
COMPONENT = 'public-data-declaration-runtime'
TARGET = 'x86_64-unknown-linux-musl'
PINNED_MUSL_COMMIT = '9fa28ece75d8a2191de7c5bb53bed224c5947417'
STATUS = 'component-verified'
IMAGE_ENV = 'CRABC_PUBLIC_DATA_VARIABLE_RUNTIME_IMAGE_ID'
IMAGE = 'crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d'
COMMAND_TIMEOUT_SECONDS = 45
GROUPS = (
    ('immutable-network-data', ('_ns_flagdata', 'in6addr_any', 'in6addr_loopback')),
    ('environment-global', ('environ',)),
    ('getdate-global', ('getdate_err',)),
    ('getopt-and-program-name-globals', ('optarg', 'opterr', 'optind', 'optopt', 'optreset',
                                          'program_invocation_name', 'program_invocation_short_name')),
    ('math-sign-global', ('signgam',)),
    ('permanent-standard-stream-slots', ('stdin', 'stdout', 'stderr')),
    ('timezone-globals', ('timezone', 'daylight', 'tzname')),
)
OBJECTS = tuple(name for _group, names in GROUPS for name in names)
ALIASES = (
    ('__environ', 'environ'), ('_environ', 'environ'), ('___environ', 'environ'),
    ('__optreset', 'optreset'), ('__progname', 'program_invocation_short_name'),
    ('__progname_full', 'program_invocation_name'), ('__signgam', 'signgam'),
    ('__timezone', 'timezone'), ('__daylight', 'daylight'), ('__tzname', 'tzname'),
)
CANDIDATE_MODES = ('static', 'static-pie', 'dynamic-pie', 'dynamic-non-pie')
DYNAMIC_EXECUTION_ROUTES = ('kernel', 'direct-interpreter')
H_ERRNO = {'object': 'h_errno', 'accessor': '__h_errno_location', 'header': 'include/netdb.h'}

# The runner is intentionally source-owned.  The legacy runners behind five
# of these probes also offer private freestanding starts; this receipt never
# calls them because their private starts bypass the installed product CRT and
# cannot establish all four ordinary installed-product modes.
PROBE_SCENARIOS = (
    ('ns-flagdata', 'immutable-network-data', 'compat/x86_64/libc_ns_flagdata_probe.c', (), (), True),
    ('in6addr-any', 'immutable-network-data', 'compat/x86_64/libc_in6addr_any_probe.c', (), (), True),
    ('in6addr-loopback', 'immutable-network-data', 'compat/x86_64/libc_in6addr_loopback_probe.c', (), (), True),
    ('environment-lifecycle-normal', 'environment-global',
     'compat/x86_64/owned_environment_lifecycle_probe.c', (), (), True),
    ('environment-lifecycle-allocation-failure', 'environment-global',
     'compat/x86_64/owned_environment_lifecycle_probe.c', ('allocation-failure',), (), True),
    ('getdate', 'getdate-global', 'compat/x86_64/owned_getdate_probe.c', (), ('templates',), True),
    ('getopt-and-program-names', 'getopt-and-program-name-globals',
     'compat/x86_64/libc_process_globals_getopt_probe.c', (), (), True),
    ('math-sign', 'math-sign-global', 'compat/x86_64/owned_public_data_variable_runtime_probe.c', (), (), True),
    ('standard-stream-slots', 'permanent-standard-stream-slots',
     'compat/x86_64/libc_stdio_standard_probe.c', (), (), True),
    ('timezone-tzif-known-difference', 'timezone-globals',
     'compat/x86_64/owned_timezone_tzif_probe.c', ('/fixture/zone.tzif', 'check'), ('fixture',), False),
    ('timezone-posix-publication', 'timezone-globals',
     'compat/x86_64/owned_public_data_variable_runtime_probe.c', ('timezone',), (), True),
)

# These bytes are intentionally values, not escaped transcript renderings.
# The historic TZif source has one pinned-musl observation that is retained as
# a known difference; every other row compares the candidate to the same musl
# source run as well as to this finite source-owned expected stream.
EXPECTED_STDOUT = {
    'ns-flagdata': b'',
    'in6addr-any': b'',
    'in6addr-loopback': b'',
    'environment-lifecycle-normal': b'environment-lifecycle-ok\n',
    'environment-lifecycle-allocation-failure': b'environment-allocation-failure-ok\n',
    'getdate': (
        b'unset result=0 getdate_err=1 errno=33\n'
        b'absent result=0 getdate_err=2 errno=2\n'
        b'directory result=0 getdate_err=5 errno=21\n'
        b'full result=1 getdate_err=5 errno=33 same=1 tm=56,34,12,29,1,124,0,0,0,0,1\n'
        b'year result=1 getdate_err=5 errno=33 same=1 tm=56,34,12,29,1,125,0,0,0,0,1\n'
        b'suffix result=0 getdate_err=7 errno=33\n'
        b'retained-partial result=1 getdate_err=7 errno=33 same=1 tm=56,34,12,29,1,126,0,0,0,0,1\n'
        b'second-template result=1 getdate_err=7 errno=33 same=1 tm=56,34,12,29,29,126,0,0,0,0,1\n'
        b'empty result=0 getdate_err=7 errno=33\n'
        b'unterminated-template result=1 getdate_err=7 errno=33 same=1 tm=56,34,12,29,29,130,0,0,0,0,1\n'
        b'second-chunk result=1 getdate_err=7 errno=33 same=1 tm=56,34,12,29,29,131,0,0,0,0,1\n'
    ),
    'getopt-and-program-names': b'',
    'math-sign': b'math-sign-global-ok\n',
    'standard-stream-slots': b'',
    'timezone-tzif-known-difference': (
        b'1 offset=3600 timezone=-3600 dst=0 name=ONE\n'
        b'2 offset=-18000 timezone=18000 dst=0 name=ONE\n'
        b'3 offset=10800 timezone=-10800 dst=0 name=XXX\n'
        b'4 offset=7200 timezone=-3600 dst=1 name=ONE\n'
        b'5 offset=7200 timezone=-3600 dst=1 name=ONE\n'
        b'6 offset=3600 timezone=-3600 dst=0 name=ONE\n'
    ),
    'timezone-posix-publication': b'timezone-globals-ok\n',
}
TZIF_ORACLE_STDOUT = (
    b'1 offset=0 timezone=0 dst=0 name=\n'
    b'2 offset=0 timezone=0 dst=0 name=\n'
    b'3 offset=0 timezone=-10800 dst=0 name=ONE\n'
    b'4 offset=3600 timezone=-3600 dst=0 name=TWO\n'
    b'5 offset=3600 timezone=-3600 dst=0 name=TWO\n'
    b'6 offset=3600 timezone=0 dst=0 name=ONE\n'
)


def _candidate_cells() -> list[dict[str, str]]:
    return [
        {'id': 'static', 'mode': 'static', 'route': 'kernel'},
        {'id': 'static-pie', 'mode': 'static-pie', 'route': 'kernel'},
        {'id': 'dynamic-pie-kernel', 'mode': 'dynamic-pie', 'route': 'kernel'},
        {'id': 'dynamic-pie-direct', 'mode': 'dynamic-pie', 'route': 'direct-interpreter'},
        {'id': 'dynamic-non-pie-kernel', 'mode': 'dynamic-non-pie', 'route': 'kernel'},
        {'id': 'dynamic-non-pie-direct', 'mode': 'dynamic-non-pie', 'route': 'direct-interpreter'},
    ]


class PublicDataVariableRuntimeError(ValueError):
    """A receipt or its finite source contract cannot prove this boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicDataVariableRuntimeError(message)


def exact(value: object, keys: set[str], description: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f'{description} fields differ')
    return value


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f'{path} is not a physical regular file')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def source_identity(path: Path) -> dict[str, Any]:
    path = Path(path)
    require(path.is_file() and not path.is_symlink(),
            'source input is not a physical regular file')
    resolved = path.resolve()
    require(resolved.is_relative_to(ROOT), 'source input escapes the checkout')
    return {
        'path': resolved.relative_to(ROOT).as_posix(),
        'sha256': digest(resolved),
        'size': resolved.stat().st_size,
        'mode': stat.S_IMODE(resolved.stat().st_mode),
    }


def same(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(',', ':'), allow_nan=False
    )


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = tomllib.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PublicDataVariableRuntimeError(f'cannot read public-data runtime contract: {error}') from error
    return validate_contract(value)


def validate_contract(value: object) -> dict[str, Any]:
    contract = exact(value, {
        'schema', 'component', 'target', 'pinned_musl_commit', 'candidate_modes',
        'dynamic_execution_routes', 'groups', 'alias_dependencies', 'h_errno',
    }, 'public-data runtime contract')
    require(contract['schema'] == CONTRACT_SCHEMA and contract['component'] == COMPONENT
            and contract['target'] == TARGET and contract['pinned_musl_commit'] == PINNED_MUSL_COMMIT,
            'public-data runtime contract identity differs')
    require(contract['candidate_modes'] == list(CANDIDATE_MODES), 'public-data runtime candidate mode roster differs')
    require(contract['dynamic_execution_routes'] == list(DYNAMIC_EXECUTION_ROUTES),
            'public-data runtime dynamic execution route roster differs')
    groups = contract['groups']
    require(type(groups) is list and len(groups) == len(GROUPS), 'public-data runtime group roster differs')
    for index, ((identifier, objects), raw) in enumerate(zip(GROUPS, groups)):
        group = exact(raw, {'id', 'objects', 'probe_sources', 'owner_sources', 'semantics'},
                      f'public-data runtime group {index}')
        require(group['id'] == identifier, 'public-data runtime group roster differs')
        require(group['objects'] == list(objects), 'public-data runtime object roster differs')
        for key in ('probe_sources', 'owner_sources'):
            require(type(group[key]) is list and group[key] and all(type(item) is str and item for item in group[key]),
                    f'public-data runtime {identifier} {key} differs')
        require(type(group['semantics']) is str and group['semantics'],
                f'public-data runtime {identifier} semantics differs')
    require([name for group in groups for name in group['objects']] == list(OBJECTS),
            'public-data runtime object roster differs')
    aliases = contract['alias_dependencies']
    require(type(aliases) is list and aliases == [{'dependency': name, 'object': target} for name, target in ALIASES],
            'public-data runtime alias dependency roster differs')
    h_errno = exact(contract['h_errno'], {'object', 'accessor', 'header', 'owner_sources', 'semantics'},
                    'public-data runtime h_errno composition')
    require(all(h_errno[key] == H_ERRNO[key] for key in H_ERRNO)
            and h_errno['owner_sources'] == ['libc/src/c_abi/x86_64/h_errno.rs']
            and type(h_errno['semantics']) is str and h_errno['semantics'],
            'public-data runtime h_errno composition differs')
    return contract


def source_inputs(contract: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return the complete source input roster that a future receipt must retain."""
    contract = load_contract() if contract is None else validate_contract(dict(contract))
    paths = [
        CONTRACT_PATH.relative_to(ROOT).as_posix(),
        'compat/x86_64/owned_public_data_variable_runtime.py',
        'compat/x86_64/run_owned_public_data_variable_runtime.sh',
        'compat/x86_64/owned-public-data-variable-runtime.md',
        'compat/x86_64/tests/test_owned_public_data_variable_runtime.py',
    ]
    for group in contract['groups']:
        paths.extend(group['probe_sources'])
        paths.extend(group['owner_sources'])
    paths.extend(contract['h_errno']['owner_sources'])
    paths.extend((
        contract['h_errno']['header'],
        'compat/x86_64/native-abi-selection.toml',
        'compat/x86_64/native_data_declarations.py',
        'compat/x86_64/native_data_declarations.toml',
        'compat/x86_64/native_declaration_abi.py',
        'compat/x86_64/header_declaration_inventory.py',
        'compat/x86_64/public_data_ordinary_link_evidence.py',
        'compat/x86_64/owned_errno_storage_lifecycle.py',
        'compat/x86_64/owned_posix_static_products.py',
        'compat/x86_64/owned_posix_product_evidence.py',
    ))
    # The narrow signgam and direct timezone branches deliberately share one
    # probe source. Retain it once while group records keep both semantic uses.
    paths = list(dict.fromkeys(paths))
    return [source_identity(ROOT / path) for path in paths]


def empty_runtime_matrix() -> list[dict[str, Any]]:
    """Render the complete mode/route shape before any transcript is admitted.

    The collector fills each cell with raw command artifacts.  Keeping the
    whole shape source-owned prevents a report from claiming coverage while
    silently dropping a hard-to-run product mode.
    """
    return [
        {
            'id': identifier,
            'objects': list(objects),
            'candidate_modes': list(CANDIDATE_MODES),
            'dynamic_routes': list(DYNAMIC_EXECUTION_ROUTES),
        }
        for identifier, objects in GROUPS
    ]


def validate_runtime_matrix(value: object) -> list[dict[str, Any]]:
    require(type(value) is list and len(value) == len(GROUPS), 'public-data runtime matrix group roster differs')
    result = []
    for index, ((identifier, objects), raw) in enumerate(zip(GROUPS, value, strict=True)):
        entry = exact(raw, {'id', 'objects', 'candidate_modes', 'dynamic_routes'},
                      f'public-data runtime matrix group {index}')
        require(entry['id'] == identifier and entry['objects'] == list(objects),
                'public-data runtime matrix object roster differs')
        require(entry['candidate_modes'] == list(CANDIDATE_MODES),
                'public-data runtime matrix candidate mode roster differs')
        require(entry['dynamic_routes'] == list(DYNAMIC_EXECUTION_ROUTES),
                'public-data runtime matrix dynamic execution route roster differs')
        result.append({key: list(item) if type(item) is list else item for key, item in entry.items()})
    return result


def probe_execution_plan(contract: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Expand every retained source probe into the non-optional product matrix."""
    contract = load_contract() if contract is None else validate_contract(dict(contract))
    plan = []
    for group in contract['groups']:
        for source in group['probe_sources']:
            plan.append({
                'group': group['id'],
                'objects': list(group['objects']),
                'source': source,
                'candidate_modes': list(CANDIDATE_MODES),
                'dynamic_routes': list(DYNAMIC_EXECUTION_ROUTES),
            })
    require(len(plan) == 10 and [entry['group'] for entry in plan] == [
        'immutable-network-data', 'immutable-network-data', 'immutable-network-data',
        'environment-global', 'getdate-global', 'getopt-and-program-name-globals',
        'math-sign-global', 'permanent-standard-stream-slots', 'timezone-globals', 'timezone-globals',
    ], 'public-data runtime probe execution roster differs')
    return plan


def execution_plan() -> list[dict[str, Any]]:
    """Return every ordinary executable scenario before a product is touched.

    A group can use more than one source and the environment source has two
    semantic paths.  This plan therefore owns the actual sixty-six candidate
    launches, rather than deriving a partial count from the nineteen names.
    The source fixtures enforce their detailed state transitions.  The reader
    additionally keeps their raw exit/status streams and compares each normal
    scenario to the pinned-musl execution of the same source.
    """
    result = []
    for identifier, group, source, suffix, directories, equals_musl in PROBE_SCENARIOS:
        candidate_argv = ['/consumer', *suffix]
        oracle_argv = list(candidate_argv)
        if identifier == 'timezone-tzif-known-difference':
            oracle_argv[-1] = 'observe'
        result.append({
            'id': identifier,
            'group': group,
            'source': source,
            'candidate_argv': candidate_argv,
            'oracle_argv': oracle_argv,
            'fixture_directories': list(directories),
            'candidate_equals_musl': equals_musl,
            'expected_stdout': EXPECTED_STDOUT[identifier],
            'candidate_cells': _candidate_cells(),
        })
    require([entry['id'] for entry in result] == [item[0] for item in PROBE_SCENARIOS]
            and sum(len(entry['candidate_cells']) for entry in result) == 66,
            'public-data runtime execution roster differs')
    return result


def h_errno_composition_contract() -> dict[str, Any]:
    """Name the existing owners that must meet at the one accessor boundary."""
    return {
        **H_ERRNO,
        'header_owner': 'native_data_declarations',
        'runtime_owner': 'owned_errno_storage_lifecycle',
        'static_shared_roles': ['static', 'shared'],
        'execution_scope': ['main', 'live-worker', 'loaded-dso'],
    }


def _physical_file(path: Path, description: str) -> Path:
    """Reject aliases before resolving one file used by this receipt."""
    path = Path(path)
    require('..' not in path.parts, f'{description} has lexical parent traversal')
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            require(not current.is_symlink(), f'{description} traverses a symlink')
        status = absolute.stat()
    except OSError as error:
        raise PublicDataVariableRuntimeError(f'cannot read {description}: {error}') from error
    require(stat.S_ISREG(status.st_mode), f'{description} is not a physical regular file')
    return absolute


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, 'public-data runtime JSON has a duplicate key: ' + key)
        result[key] = value
    return result


def _receipt_file_identity(receipt_root: Path, path: Path, description: str) -> dict[str, Any]:
    path = _physical_file(path, description)
    receipt_root = receipt_root.resolve(strict=True)
    require(path.is_relative_to(receipt_root), f'{description} escapes retained receipt')
    status = path.stat()
    return {
        'path': path.relative_to(receipt_root).as_posix(),
        'sha256': digest(path), 'size': status.st_size, 'mode': stat.S_IMODE(status.st_mode),
    }


def _copy_input(receipt_root: Path, source: Path, retained: str, description: str) -> dict[str, Any]:
    """Copy one raw source/report/tool input before the first command.

    The copy keeps the live original spelling for collection-only final checks,
    while replay trusts only the receipt-relative physical copy.
    """
    source = _physical_file(source, description)
    destination = receipt_root / retained
    require(not destination.exists() and not destination.is_symlink(), f'duplicate retained input: {retained}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))
    original_status = source.stat()
    original = {'path': str(source), 'sha256': digest(source), 'size': original_status.st_size,
                'mode': stat.S_IMODE(original_status.st_mode)}
    copied = _receipt_file_identity(receipt_root, destination, description + ' retained copy')
    require(all(copied[key] == original[key] for key in ('sha256', 'size', 'mode')),
            f'{description} retained copy differs')
    return {'original': original, 'retained': copied}


def _validate_copied_input(receipt_root: Path, value: object, description: str) -> dict[str, Any]:
    record = exact(value, {'original', 'retained'}, description)
    original = exact(record['original'], {'path', 'sha256', 'size', 'mode'}, description + ' original')
    retained = exact(record['retained'], {'path', 'sha256', 'size', 'mode'}, description + ' retained')
    require(type(original['path']) is str and Path(original['path']).is_absolute()
            and type(original['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', original['sha256']) is not None
            and type(original['size']) is int and original['size'] >= 0
            and type(original['mode']) is int and 0 <= original['mode'] <= 0o777,
            f'{description} original identity differs')
    require(type(retained['path']) is str and not Path(retained['path']).is_absolute(),
            f'{description} retained path differs')
    path = receipt_root / retained['path']
    observed = _receipt_file_identity(receipt_root, path, description + ' retained input')
    require(observed == retained and all(original[key] == retained[key] for key in ('sha256', 'size', 'mode')),
            f'{description} retained input differs')
    return record


def _source_capture(receipt_root: Path) -> dict[str, Any]:
    """Retain the full source contract, collector, and direct probe inputs."""
    result = {}
    for item in source_inputs():
        relative = item['path']
        name = relative.replace('/', '__')
        result[relative] = _copy_input(receipt_root, ROOT / relative, 'retained/sources/' + name,
                                       'source input ' + relative)
    require(set(result) == {item['path'] for item in source_inputs()}, 'source input roster differs')
    return result


def _validate_source_capture(receipt_root: Path, value: object) -> dict[str, Any]:
    require(type(value) is dict and set(value) == {item['path'] for item in source_inputs()},
            'retained source input roster differs')
    result = {}
    for relative in sorted(value):
        record = _validate_copied_input(receipt_root, value[relative], 'source input ' + relative)
        retained = receipt_root / record['retained']['path']
        require(retained.read_bytes() == (ROOT / relative).read_bytes(),
                'retained source input differs from current source: ' + relative)
        now = source_identity(ROOT / relative)
        original = record['original']
        require(all(now[key] == original[key] for key in ('sha256', 'size', 'mode')),
                'current source input differs: ' + relative)
        result[relative] = record
    return result


def _dynamic_root_setup(root: Path, dynamic_product: Path, consumer: Path,
                        directories: Sequence[str]) -> dict[str, Any]:
    """Make one isolated chroot with exactly one normal consumer payload."""
    require(not root.exists() and not root.is_symlink(), 'runtime root already exists')
    shutil.copytree(dynamic_product, root, symlinks=True)
    shutil.copy2(consumer, root / 'consumer')
    for relative in directories:
        target = root / relative
        target.mkdir(mode=0o755, parents=True, exist_ok=False)
        os.chmod(target, 0o755)
    return ordinary_link.execution_tree(ROOT, root, 'candidate execution root')


def _static_root_setup(root: Path, consumer: Path, directories: Sequence[str]) -> dict[str, Any]:
    require(not root.exists() and not root.is_symlink(), 'runtime root already exists')
    root.mkdir(parents=True)
    os.chmod(root, 0o755)
    shutil.copy2(consumer, root / 'consumer')
    for relative in directories:
        target = root / relative
        target.mkdir(mode=0o755, parents=True, exist_ok=False)
        os.chmod(target, 0o755)
    return ordinary_link.execution_tree(ROOT, root, 'static execution root')


def _oracle_root_setup(root: Path, receipt_root: Path, consumer: Path,
                       directories: Sequence[str]) -> dict[str, Any]:
    ordinary_link.prepare_oracle_execution_root(ROOT, receipt_root, root)
    shutil.copy2(consumer, root / 'consumer')
    for relative in directories:
        target = root / relative
        target.mkdir(mode=0o755, parents=True, exist_ok=False)
        os.chmod(target, 0o755)
    return ordinary_link.execution_tree(ROOT, root, 'oracle execution root')


COMPANION_NAMES = ('header_report', 'declaration_abi_report', 'ordinary_link_report', 'errno_report')


def _current_companion_projection(root: Path, paths: Mapping[str, Path]) -> dict[str, Any]:
    """Replay the four existing owners used by the h_errno composition.

    This component does not replace their evidence.  It requires each public
    reader first, then records only the small facts that meet at the installed
    declaration boundary.  Every caller passes these reports again during
    retained replay; a copied report alone never transfers a cohort.
    """
    require(set(paths) == set(COMPANION_NAMES), 'public-data runtime companion roster differs')
    for name, path in paths.items():
        require(_physical_file(path, name + ' report').name == 'report.json',
                name + ' report name differs')
    try:
        header = header_declaration_inventory.validate_report(paths['header_report'])
        current = header.get('current_selecting_source')
        require(isinstance(current, Mapping) and current.get('matches_retained') is True,
                'header declaration report source differs from current selection')
        declaration = native_declaration_abi.validate_report(
            paths['declaration_abi_report'], header_report=paths['header_report'], header_envelope=header,
        )
        declaration_contract = native_data_declarations.load_contract()
        selected_declarations = [{key: item[key] for key in (
            'id', 'name', 'declaration_kind', 'declaration', 'c_abi_type', 'source_mutable',
        )} for item in declaration_contract['objects']]
        header_account = native_data_declarations.account_declarations(
            header, selected_declarations, contract=declaration_contract,
        )
        ordinary = ordinary_link.validate_report(root, paths['ordinary_link_report'])
        errno = owned_errno_storage_lifecycle.validate_report(root, paths['errno_report'])
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise PublicDataVariableRuntimeError(f'public-data runtime companion rejected: {error}') from error
    summary = declaration.get('summary')
    require(isinstance(summary, Mapping) and set(summary) == {
        'cxx_job_count', 'job_count', 'language_counts', 'observation_count',
        'observation_status_counts', 'reference_category_counts', 'reference_count',
    } and type(summary['job_count']) is int and summary['job_count'] > 0,
            'ordinary declaration ABI companion summary differs')
    require(isinstance(ordinary, Mapping) and set(ordinary) == {'report', 'links'},
            'ordinary public-data link companion envelope differs')
    link_projection = {}
    for name, record in ordinary['links'].items():
        require(isinstance(record, Mapping), 'ordinary public-data link projection differs')
        link_projection[name] = {key: value for key, value in record.items() if key != 'product'}
    h_layout = errno.get('h_errno_layout')
    require(isinstance(h_layout, Mapping) and set(h_layout) == {'static', 'shared'},
            'errno storage companion h_errno layout differs')
    require(header_account['scope'] == {
        'selected_object_contracts': 33, 'installed_variables': 19, 'accessor_macros': 1,
        'abi_only_names': 13, 'provider_selection': 'not-evaluated', 'object_layout': 'not-evaluated',
        'runtime': 'not-evaluated', 'family_completion': 'not-claimed', 'public_support': 'not-claimed',
    }, 'header declaration runtime scope differs')
    h_errno_header = next(item for item in header_account['objects'] if item['id'] == 'object:h_errno')
    return {
        'header_current_source': {'matches_retained': True},
        'declaration_summary': dict(summary),
        'ordinary_link': {'report': dict(ordinary['report']), 'links': link_projection},
        'h_errno_header': h_errno_header,
        'h_errno_layout': dict(h_layout),
        'h_errno_execution_labels': list(owned_errno_storage_lifecycle.RUN_LABELS),
    }


def _capture_companions(receipt_root: Path, paths: Mapping[str, Path]) -> dict[str, Any]:
    return {
        name: _copy_input(receipt_root, paths[name], 'retained/companions/' + name + '.json',
                          'public-data runtime ' + name)
        for name in COMPANION_NAMES
    }


def _mode_linkage(mode: str) -> str:
    return {
        'static': 'static', 'static-pie': 'static-pie',
        'dynamic-pie': 'pie', 'dynamic-non-pie': 'non-pie',
    }[mode]


def _validate_fixture_tree(tree: Mapping[str, Mapping[str, Any]], scenario: Mapping[str, Any], description: str) -> None:
    """Keep the two source-owned writable fixtures bounded and reversible."""
    consumer = tree.get('consumer')
    require(isinstance(consumer, Mapping) and consumer.get('kind') == 'file',
            description + ' consumer differs')
    for directory in scenario['fixture_directories']:
        entry = tree.get(directory)
        require(isinstance(entry, Mapping) and entry == {'kind': 'directory', 'mode': 0o755},
                description + ' fixture directory differs')
    if scenario['id'] == 'getdate':
        require('templates/mask' not in tree, description + ' getdate template remains after execution')
    if scenario['id'] == 'timezone-tzif-known-difference':
        require('fixture/zone.tzif' not in tree, description + ' TZif file remains after execution')


def _safe_label(value: str) -> str:
    require(re.fullmatch(r'[a-z0-9-]+', value) is not None, 'runtime command label differs')
    return value


class Collector:
    """Collect exactly the installed-variable runtime matrix once.

    The collector deliberately shares the already reviewed product-admission,
    tool snapshot, oracle snapshot, and command-record primitives with the
    finite public-data ordinary-link owner.  It does not generalize those
    primitives: every source, mode, root, and expected stream is enumerated
    in this component above.
    """

    def __init__(self, root: Path, output: Path, static_preparation: Path,
                 static_product: Path, dynamic_product: Path, companions: Mapping[str, Path]) -> None:
        self.root = root.resolve(strict=True)
        self.output = output
        self.static_preparation = static_preparation
        self.static_product = static_product
        self.dynamic_product = dynamic_product
        self.companions = dict(companions)
        self.runner: ordinary_link.Collector | None = None
        self.tools: dict[str, Any] = {}
        self.executions: dict[str, Any] = {}
        self.links: dict[str, Any] = {}

    def _run(self, label: str, argv: list[str], *, stdout: bytes | None = None,
             stderr: bytes | None = None, cwd: Path | None = None) -> dict[str, Any]:
        require(self.runner is not None, 'runtime collector command runner is unavailable')
        return self.runner.run(_safe_label(label), argv, stdout=stdout, stderr=stderr,
                               cwd=self.output if cwd is None else cwd,
                               timeout_seconds=COMMAND_TIMEOUT_SECONDS)

    def _env_chroot(self, root: Path, argv: Sequence[str]) -> list[str]:
        invocation = ordinary_link.validate_chroot_invocation(self.tools['chroot']['invocation'],
                                                               self.tools['chroot']['original'])
        # Every root has a complete three-descriptor capture at exec.  The
        # fixed strings intentionally avoid inheriting DATEMSK or host TZ.
        return [self.tools['env']['original']['path'], '-i', 'LC_ALL=C', 'TZ=UTC', 'PATH=/usr/bin:/bin',
                invocation, str(root), *argv]

    def _compile(self, scenario: Mapping[str, Any]) -> Path:
        identifier = scenario['id']
        destination = self.output / 'objects' / (identifier + '.o')
        destination.parent.mkdir(exist_ok=True)
        source = self.root / scenario['source']
        include = self.dynamic_product / 'usr/include'
        self._run(identifier + '-compile', [self.tools['dynamic_driver']['original']['path'], '--dynamic-pie',
                                            '-std=c11', '-D_GNU_SOURCE=1', '-fno-builtin',
                                            '-fno-stack-protector', '-nostdinc', '-isystem', str(include),
                                            '-c', str(source), '-o', str(destination)])
        require(destination.is_file() and not destination.is_symlink(),
                'ordinary probe compile did not produce an object: ' + identifier)
        return destination

    def _link(self, scenario: Mapping[str, Any], object_path: Path) -> dict[str, dict[str, Any]]:
        identifier = scenario['id']
        directory = self.output / 'executables' / identifier
        directory.mkdir(parents=True, exist_ok=False)
        result: dict[str, dict[str, Any]] = {}
        oracle = directory / 'oracle-static'
        self._run(identifier + '-oracle-static-link', [self.tools['oracle_wrapper']['original']['path'],
                                                       '-static', '-fno-pie', '-no-pie', str(object_path),
                                                       '-o', str(oracle)])
        result['oracle-static'] = {'executable': _receipt_file_identity(self.output, oracle,
                                                                          identifier + ' oracle static')}
        for mode in CANDIDATE_MODES:
            executable = directory / mode
            if mode in {'static', 'static-pie'}:
                receipt = directory / (mode + '.crabc-link.json')
                argv = [self.tools['static_driver']['original']['path'], '-' + mode, '--link-receipt',
                        receipt.relative_to(self.output).as_posix(), str(object_path), '-o', str(executable)]
                self._run(identifier + '-' + mode + '-link', argv, cwd=self.output)
            else:
                driver_mode = '--dynamic-pie' if mode == 'dynamic-pie' else '--dynamic-non-pie'
                argv = [self.tools['dynamic_driver']['original']['path'], driver_mode, str(object_path),
                        '-o', str(executable)]
                self._run(identifier + '-' + mode + '-link', argv)
                receipt = directory / (mode + '.crabc-link.json')
            require(executable.is_file() and receipt.is_file(),
                    'ordinary probe link did not produce sealed artifacts: ' + identifier + '/' + mode)
            try:
                identity = product_evidence.validate_link(
                    self.static_product if mode in {'static', 'static-pie'} else self.dynamic_product,
                    object_path, executable, receipt, _mode_linkage(mode),
                )
            except product_evidence.ProductEvidenceError as error:
                raise PublicDataVariableRuntimeError(
                    f'ordinary probe link is not sealed: {identifier}/{mode}: {error}'
                ) from error
            result[mode] = {
                'executable': _receipt_file_identity(self.output, executable, identifier + ' ' + mode),
                'receipt': _receipt_file_identity(self.output, receipt, identifier + ' ' + mode + ' receipt'),
                'identity': identity,
            }
        return result

    def _run_one_root(self, label: str, root: Path, argv: Sequence[str], expected: bytes) -> dict[str, Any]:
        before = ordinary_link.execution_tree(self.root, root, label + ' before root')
        scenario = next(item for item in execution_plan() if label.startswith(item['id'] + '-'))
        _validate_fixture_tree(before, scenario, label + ' before root')
        command = self._run(label, self._env_chroot(root, argv), stdout=expected, stderr=b'')
        after = ordinary_link.execution_tree(self.root, root, label + ' after root')
        require(before == after, 'ordinary runtime root changed outside its bounded fixture transition: ' + label)
        _validate_fixture_tree(after, scenario, label + ' after root')
        return {'root': root.relative_to(self.output).as_posix(), 'before': before, 'after': after,
                'command': command['label']}

    def _execute(self, scenario: Mapping[str, Any], linked: Mapping[str, Mapping[str, Any]]) -> None:
        identifier = scenario['id']
        expected = scenario['expected_stdout']
        directory = self.output / 'executables' / identifier
        oracle_root = self.output / 'roots' / identifier / 'oracle-static'
        _oracle_root_setup(oracle_root, self.output, directory / 'oracle-static', scenario['fixture_directories'])
        oracle_expected = TZIF_ORACLE_STDOUT if identifier == 'timezone-tzif-known-difference' else expected
        self.executions[identifier + '/oracle-static'] = self._run_one_root(
            identifier + '-oracle-static-run', oracle_root, scenario['oracle_argv'], oracle_expected,
        )
        for cell in scenario['candidate_cells']:
            root = self.output / 'roots' / identifier / cell['id']
            mode = cell['mode']
            consumer = directory / mode
            if mode in {'static', 'static-pie'}:
                _static_root_setup(root, consumer, scenario['fixture_directories'])
            else:
                _dynamic_root_setup(root, self.dynamic_product, consumer, scenario['fixture_directories'])
            self.executions[identifier + '/' + cell['id']] = self._run_one_root(
                identifier + '-' + cell['id'] + '-run', root,
                ([ '/lib/ld-crabc-x86_64.so.1', *scenario['candidate_argv'] ]
                 if cell['route'] == 'direct-interpreter' else scenario['candidate_argv']), expected,
            )

    def collect(self) -> dict[str, Any]:
        require(os.environ.get(IMAGE_ENV) == IMAGE,
                f'dispatcher must supply exact {IMAGE_ENV} pinned image identity')
        require(not self.output.exists() and self.output.parent.is_dir() and not self.output.parent.is_symlink(),
                'public-data runtime output must be fresh')
        self.output.mkdir()
        before = ordinary_link.admit_inputs(self.root, self.static_preparation, self.static_product, self.dynamic_product)
        source_before = static_products.source_identity(self.root)
        companions_before = _current_companion_projection(self.root, self.companions)
        sources = _source_capture(self.output)
        captured_companions = _capture_companions(self.output, self.companions)
        oracle = ordinary_link.qualification.capture_oracle(self.output)
        ordinary_link.qualification.validate_oracle(self.output, oracle)
        oracle_static = ordinary_link.capture_oracle_static_inputs(self.output)
        self.tools = ordinary_link.capture_tool_roster(self.root, self.output, self.static_product, self.dynamic_product)
        self.runner = ordinary_link.Collector(self.root, self.output, self.static_preparation,
                                              self.static_product, self.dynamic_product)
        objects: dict[str, Any] = {}
        for scenario in execution_plan():
            object_path = self._compile(scenario)
            linked = self._link(scenario, object_path)
            objects[scenario['id']] = _receipt_file_identity(self.output, object_path, scenario['id'] + ' object')
            self.links[scenario['id']] = linked
            self._execute(scenario, linked)
        after = ordinary_link.admit_inputs(self.root, self.static_preparation, self.static_product, self.dynamic_product)
        companions_after = _current_companion_projection(self.root, self.companions)
        require(same(before, after) and same(source_before, static_products.source_identity(self.root))
                and same(companions_before, companions_after),
                'supplied products or collector source changed during public-data runtime collection')
        ordinary_link.require_live_tool_roster(self.tools)
        ordinary_link.require_live_oracle_static_inputs(oracle_static)
        return {
            'schema': SCHEMA, 'status': STATUS, 'component': COMPONENT,
            'collection': {'image': IMAGE, 'source': source_before},
            'contract': load_contract(), 'inputs_before': before, 'inputs_after': after,
            'sources': sources, 'companions': {'inputs': captured_companions, 'projection': companions_before},
            'oracle': oracle, 'oracle_static_inputs': oracle_static,
            'tools': self.tools, 'objects': objects, 'links': self.links,
            'commands': self.runner.commands, 'executions': self.executions,
            'runtime_matrix': empty_runtime_matrix(),
            'h_errno': h_errno_composition_contract(),
            'coverage': {'objects': list(OBJECTS), 'groups': [name for name, _objects in GROUPS],
                         'component_complete': True, 'family_completion': False,
                         'runtime_qualification': False, 'public_support': False},
        }


def _origin_root(receipt_root: Path, sources: Mapping[str, Any]) -> tuple[Path, Path]:
    """Translate the fixed collection mount only for sealed command argv."""
    record = _validate_copied_input(receipt_root,
                                    sources['compat/x86_64/owned_public_data_variable_runtime.py'],
                                    'runtime reader source')
    original = Path(record['original']['path'])
    relative = Path('compat/x86_64/owned_public_data_variable_runtime.py')
    require(original.is_absolute() and original.parts[-len(relative.parts):] == relative.parts,
            'runtime receipt collection root differs')
    origin = original.parents[len(relative.parts) - 1]
    require(receipt_root.is_relative_to(ROOT / '.work'), 'runtime receipt must be in checkout work')
    return origin, origin / receipt_root.relative_to(ROOT)


def _expected_labels() -> list[str]:
    result: list[str] = []
    for scenario in execution_plan():
        identifier = scenario['id']
        result.extend((identifier + '-compile', identifier + '-oracle-static-link'))
        result.extend(identifier + '-' + mode + '-link' for mode in CANDIDATE_MODES)
        result.append(identifier + '-oracle-static-run')
        result.extend(identifier + '-' + cell['id'] + '-run' for cell in scenario['candidate_cells'])
    return result


def _recorded_command_path(receipt_root: Path, label: str, suffix: str) -> Path:
    return ordinary_link.raw_path(receipt_root, label, suffix)


def _validate_commands(receipt_root: Path, records: object, *, origin_output: Path,
                       inputs: Mapping[str, Any], tools: Mapping[str, Any]) -> None:
    require(type(records) is list and [item.get('label') if type(item) is dict else None for item in records]
            == _expected_labels(), 'public-data runtime command roster differs')
    expected_paths = {
        name: tools[name]['original']['path'] for name in ('static_driver', 'dynamic_driver', 'oracle_wrapper', 'env', 'chroot')
    }
    require(all(type(path) is str and Path(path).is_absolute() for path in expected_paths.values()),
            'public-data runtime command tool identity differs')
    invocation = ordinary_link.validate_chroot_invocation(tools['chroot']['invocation'], tools['chroot']['original'])
    # The only collector mount translation is source-root -> origin root.  The
    # supplied product paths are already root-relative in the admitted input.
    origin_root = origin_output
    for _ in receipt_root.relative_to(ROOT).parts:
        origin_root = origin_root.parent
    dynamic_root = origin_root / inputs['dynamic_product']['path']
    for record in records:
        row = exact(record, {'label', 'argv', 'cwd', 'outcome', 'command', 'stdout', 'stderr', 'status'},
                    'public-data runtime command')
        label = row['label']
        require(type(label) is str and type(row['argv']) is list and all(type(item) is str for item in row['argv']),
                'public-data runtime command values differ')
        require(row['cwd'] == str(origin_output) and row['outcome'] == 'ok',
                'public-data runtime command working directory differs')
        for field, suffix in (('command', 'command.json'), ('stdout', 'stdout'), ('stderr', 'stderr'), ('status', 'status')):
            raw = _recorded_command_path(receipt_root, label, suffix)
            observed = ordinary_link.work_file_identity(ROOT, raw, 'runtime command ' + label + ' ' + field)
            require(row[field] == observed, 'public-data runtime command raw identity differs')
        command = json.loads(_recorded_command_path(receipt_root, label, 'command.json').read_text(encoding='utf-8'))
        require(command == row['argv'] and _recorded_command_path(receipt_root, label, 'status').read_bytes() == b'0\n',
                'public-data runtime retained command differs')
        require(_recorded_command_path(receipt_root, label, 'stderr').read_bytes() == b'',
                'public-data runtime command diagnostics differ')
        identifier = next(item['id'] for item in execution_plan() if label.startswith(item['id'] + '-'))
        scenario = next(item for item in execution_plan() if item['id'] == identifier)
        source = str(origin_root / scenario['source'])
        object_path = str(origin_output / 'objects' / (identifier + '.o'))
        executable_dir = origin_output / 'executables' / identifier
        if label == identifier + '-compile':
            require(row['argv'] == [expected_paths['dynamic_driver'], '--dynamic-pie', '-std=c11', '-D_GNU_SOURCE=1',
                                    '-fno-builtin', '-fno-stack-protector', '-nostdinc', '-isystem',
                                    str(dynamic_root / 'usr/include'), '-c', source, '-o', object_path],
                    'public-data runtime compile argv differs')
        elif label == identifier + '-oracle-static-link':
            require(row['argv'] == [expected_paths['oracle_wrapper'], '-static', '-fno-pie', '-no-pie', object_path,
                                    '-o', str(executable_dir / 'oracle-static')],
                    'public-data runtime oracle link argv differs')
        elif label.endswith('-link'):
            mode = label[len(identifier) + 1:-len('-link')]
            executable = executable_dir / mode
            if mode in {'static', 'static-pie'}:
                require(row['argv'] == [expected_paths['static_driver'], '-' + mode, '--link-receipt',
                                        (executable_dir / (mode + '.crabc-link.json')).relative_to(origin_output).as_posix(),
                                        object_path, '-o', str(executable)],
                        'public-data runtime static link argv differs')
            else:
                driver_mode = '--dynamic-pie' if mode == 'dynamic-pie' else '--dynamic-non-pie'
                require(row['argv'] == [expected_paths['dynamic_driver'], driver_mode, object_path, '-o', str(executable)],
                        'public-data runtime dynamic link argv differs')
        else:
            if label == identifier + '-oracle-static-run':
                root = origin_output / 'roots' / identifier / 'oracle-static'
                argv = scenario['oracle_argv']
                expected = TZIF_ORACLE_STDOUT if identifier == 'timezone-tzif-known-difference' else scenario['expected_stdout']
            else:
                cell_name = label[len(identifier) + 1:-len('-run')]
                cell = next(cell for cell in scenario['candidate_cells'] if cell['id'] == cell_name)
                root = origin_output / 'roots' / identifier / cell_name
                argv = ((['/lib/ld-crabc-x86_64.so.1', *scenario['candidate_argv']])
                        if cell['route'] == 'direct-interpreter' else scenario['candidate_argv'])
                expected = scenario['expected_stdout']
            require(row['argv'] == [expected_paths['env'], '-i', 'LC_ALL=C', 'TZ=UTC', 'PATH=/usr/bin:/bin',
                                    invocation, str(root), *argv], 'public-data runtime execution argv differs')
            require(_recorded_command_path(receipt_root, label, 'stdout').read_bytes() == expected,
                    'public-data runtime execution stdout differs')


def _validate_links(receipt_root: Path, value: object, *, origin_root: Path,
                    inputs: Mapping[str, Any], tools: Mapping[str, Any]) -> None:
    require(type(value) is dict and set(value) == {scenario['id'] for scenario in execution_plan()},
            'public-data runtime link scenario roster differs')
    static_product = ROOT / inputs['static_preparation']['primary']['path']
    dynamic_product = ROOT / inputs['dynamic_product']['path']
    linker = {'path': tools['linker']['original']['path'], 'sha256': tools['linker']['original']['sha256']}
    for scenario in execution_plan():
        identifier = scenario['id']
        links = exact(value[identifier], {'oracle-static', *CANDIDATE_MODES}, identifier + ' link roster')
        oracle = exact(links['oracle-static'], {'executable'}, identifier + ' oracle link')
        _receipt_file_identity(receipt_root, receipt_root / oracle['executable']['path'], identifier + ' oracle executable')
        for mode in CANDIDATE_MODES:
            record = exact(links[mode], {'executable', 'receipt', 'identity'}, identifier + ' ' + mode + ' link')
            executable = receipt_root / record['executable']['path']
            receipt = receipt_root / record['receipt']['path']
            _receipt_file_identity(receipt_root, executable, identifier + ' ' + mode + ' executable')
            _receipt_file_identity(receipt_root, receipt, identifier + ' ' + mode + ' receipt')
            object_path = receipt_root / 'objects' / (identifier + '.o')
            try:
                actual = product_evidence.validate_retained_link(
                    ROOT, '/workspace', static_product if mode in {'static', 'static-pie'} else dynamic_product,
                    object_path, executable, receipt, _mode_linkage(mode), linker,
                )
            except product_evidence.ProductEvidenceError as error:
                raise PublicDataVariableRuntimeError(
                    f'public-data runtime retained link rejected: {identifier}/{mode}: {error}'
                ) from error
            expected = dict(actual)
            expected['product'] = str((origin_root / (inputs['static_preparation']['primary']['path']
                                                      if mode in {'static', 'static-pie'}
                                                      else inputs['dynamic_product']['path'])))
            require(record['identity'] == expected, 'public-data runtime retained link identity differs')


def _validate_executions(receipt_root: Path, value: object, commands: Sequence[Mapping[str, Any]]) -> None:
    expected = {scenario['id'] + '/oracle-static' for scenario in execution_plan()}
    expected.update(scenario['id'] + '/' + cell['id']
                    for scenario in execution_plan() for cell in scenario['candidate_cells'])
    require(type(value) is dict and set(value) == expected, 'public-data runtime execution roster differs')
    labels = {item['label'] for item in commands}
    for key in sorted(expected):
        record = exact(value[key], {'root', 'before', 'after', 'command'}, 'public-data runtime execution ' + key)
        root = receipt_root / record['root']
        require(root.is_dir() and not root.is_symlink() and type(record['command']) is str
                and record['command'] in labels, 'public-data runtime execution root differs')
        actual = ordinary_link.execution_tree(ROOT, root, 'retained execution root ' + key)
        require(record['before'] == actual and record['after'] == actual,
                'public-data runtime execution root changed outside its bounded fixture transition')
        identifier = key.rsplit('/', 1)[0]
        scenario = next(item for item in execution_plan() if item['id'] == identifier)
        _validate_fixture_tree(actual, scenario, 'retained execution root ' + key)


def _validate_objects(receipt_root: Path, value: object) -> None:
    require(type(value) is dict and set(value) == {scenario['id'] for scenario in execution_plan()},
            'public-data runtime object roster differs')
    for scenario in execution_plan():
        identifier = scenario['id']
        expected = receipt_root / 'objects' / (identifier + '.o')
        observed = _receipt_file_identity(receipt_root, expected, identifier + ' retained object')
        require(value[identifier] == observed, 'public-data runtime object identity differs')


def validate_report(report_path: Path, *, root: Path = ROOT, static_preparation: Path,
                    static_product: Path, dynamic_product: Path,
                    header_report: Path, declaration_abi_report: Path,
                    ordinary_link_report: Path, errno_report: Path) -> dict[str, Any]:
    """Replay the exact current retained receipt without a compiler or target tool."""
    root = Path(root).resolve(strict=True)
    report_path = _physical_file(report_path, 'public-data runtime report')
    require(report_path.name == 'report.json' and report_path.is_relative_to(root / '.work'),
            'public-data runtime report path differs')
    receipt_root = report_path.parent
    try:
        report = json.loads(report_path.read_text(encoding='utf-8'), object_pairs_hook=_unique_json_object,
                            parse_constant=lambda value: (_ for _ in ()).throw(
                                PublicDataVariableRuntimeError('public-data runtime JSON constant differs: ' + value)))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicDataVariableRuntimeError(f'cannot read public-data runtime report: {error}') from error
    report = exact(report, {
        'schema', 'status', 'component', 'collection', 'contract', 'inputs_before', 'inputs_after',
        'sources', 'companions', 'oracle', 'oracle_static_inputs', 'tools', 'objects', 'links',
        'commands', 'executions', 'runtime_matrix', 'h_errno', 'coverage',
    }, 'public-data runtime report')
    require(report['schema'] == SCHEMA and report['status'] == STATUS and report['component'] == COMPONENT,
            'public-data runtime report identity differs')
    collection = exact(report['collection'], {'image', 'source'}, 'public-data runtime collection')
    require(collection['image'] == IMAGE and collection['source'] == static_products.source_identity(root),
            'public-data runtime collection source differs')
    require(report['contract'] == load_contract() and report['runtime_matrix'] == empty_runtime_matrix()
            and report['h_errno'] == h_errno_composition_contract(),
            'public-data runtime source contract differs')
    actual_inputs = ordinary_link.admit_inputs(root, static_preparation, static_product, dynamic_product)
    require(report['inputs_before'] == actual_inputs and report['inputs_after'] == actual_inputs,
            'public-data runtime supplied product cohort differs')
    sources = _validate_source_capture(receipt_root, report['sources'])
    origin_root, origin_output = _origin_root(receipt_root, sources)
    companions = exact(report['companions'], {'inputs', 'projection'}, 'public-data runtime companions')
    require(type(companions['inputs']) is dict and set(companions['inputs']) == set(COMPANION_NAMES),
            'public-data runtime retained companion roster differs')
    supplied_companions = {
        'header_report': header_report, 'declaration_abi_report': declaration_abi_report,
        'ordinary_link_report': ordinary_link_report, 'errno_report': errno_report,
    }
    for name in COMPANION_NAMES:
        copied = _validate_copied_input(receipt_root, companions['inputs'][name], 'public-data runtime ' + name)
        current = _physical_file(supplied_companions[name], name + ' report')
        original = copied['original']
        require(digest(current) == original['sha256'] and current.stat().st_size == original['size']
                and stat.S_IMODE(current.stat().st_mode) == original['mode'],
                'current public-data runtime companion differs: ' + name)
    require(companions['projection'] == _current_companion_projection(root, supplied_companions),
            'public-data runtime companion projection differs')
    ordinary_link.qualification.validate_oracle(receipt_root, report['oracle'])
    ordinary_link.validate_oracle_static_inputs(receipt_root, report['oracle_static_inputs'])
    tools = ordinary_link.validate_tool_roster(root, receipt_root, actual_inputs, report['tools'])
    _validate_objects(receipt_root, report['objects'])
    _validate_links(receipt_root, report['links'], origin_root=origin_root, inputs=actual_inputs, tools=tools)
    _validate_commands(receipt_root, report['commands'], origin_output=origin_output, inputs=actual_inputs, tools=tools)
    _validate_executions(receipt_root, report['executions'], report['commands'])
    require(report['coverage'] == {
        'objects': list(OBJECTS), 'groups': [name for name, _objects in GROUPS],
        'component_complete': True, 'family_completion': False,
        'runtime_qualification': False, 'public_support': False,
    }, 'public-data runtime scope differs')
    return {
        'report': _receipt_file_identity(receipt_root, report_path, 'public-data runtime report'),
        'coverage': report['coverage'], 'h_errno': report['h_errno'],
    }


def collect(*, root: Path, static_preparation: Path, static_product: Path, dynamic_product: Path,
            header_report: Path, declaration_abi_report: Path, ordinary_link_report: Path,
            errno_report: Path, output: Path) -> Path:
    """Collect and immediately replay one fresh source-matched component receipt."""
    root = Path(root).resolve(strict=True)
    output = Path(output)
    require(output.is_absolute() is False or output.is_relative_to(root / '.work'),
            'public-data runtime output escapes checkout work')
    output = (root / output).resolve() if not output.is_absolute() else output
    require(output.parent.is_dir() and output.is_relative_to(root / '.work'),
            'public-data runtime output parent differs')
    companions = {
        'header_report': Path(header_report), 'declaration_abi_report': Path(declaration_abi_report),
        'ordinary_link_report': Path(ordinary_link_report), 'errno_report': Path(errno_report),
    }
    collector = Collector(root, output, Path(static_preparation), Path(static_product), Path(dynamic_product), companions)
    try:
        report = collector.collect()
        with (output / 'report.json').open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write('\n')
        validate_report(output / 'report.json', root=root, static_preparation=static_preparation,
                        static_product=static_product, dynamic_product=dynamic_product, **companions)
    except BaseException:
        print(f'public-data runtime retained collection: {output}', file=sys.stderr)
        raise
    return output / 'report.json'


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # This source-only preflight was published before collection existed. Keep
    # its one explicit spelling while the new collect/replay boundary uses
    # ordinary subcommands.
    if arguments == ['--check-contract']:
        arguments = ['check-contract']
    parser = argparse.ArgumentParser(description=__doc__)
    parser.allow_abbrev = False
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check-contract', allow_abbrev=False)
    collect_parser = commands.add_parser('collect', allow_abbrev=False)
    replay_parser = commands.add_parser('validate-report', allow_abbrev=False)
    names = ('static-preparation', 'static-product', 'dynamic-product', 'header-report',
             'declaration-abi-report', 'ordinary-link-report', 'errno-report', 'output')
    for target in (collect_parser, replay_parser):
        for name in names:
            if target is replay_parser and name == 'output':
                continue
            target.add_argument('--' + name, type=Path, action='append', required=True)
    replay_parser.add_argument('report', type=Path)
    args = parser.parse_args(arguments)
    for name in names:
        attribute = name.replace('-', '_')
        if not hasattr(args, attribute):
            continue
        values = getattr(args, attribute)
        if len(values) != 1:
            parser.error('--' + name + ' must appear exactly once')
        setattr(args, attribute, values[0])
    if args.command == 'check-contract':
        contract = load_contract()
        print(f'public-data declaration runtime: {len(OBJECTS)} installed variables in {len(contract["groups"])} groups')
    elif args.command == 'collect':
        path = collect(root=ROOT, static_preparation=args.static_preparation, static_product=args.static_product,
                       dynamic_product=args.dynamic_product, header_report=args.header_report,
                       declaration_abi_report=args.declaration_abi_report, ordinary_link_report=args.ordinary_link_report,
                       errno_report=args.errno_report, output=args.output)
        print(json.dumps({'schema': SCHEMA, 'report': str(path), 'sha256': digest(path), 'status': STATUS}, sort_keys=True))
    else:
        replayed = validate_report(args.report, root=ROOT,
                                   static_preparation=args.static_preparation, static_product=args.static_product,
                                   dynamic_product=args.dynamic_product, header_report=args.header_report,
                                   declaration_abi_report=args.declaration_abi_report,
                                   ordinary_link_report=args.ordinary_link_report, errno_report=args.errno_report)
        print(json.dumps({'schema': SCHEMA, 'report': replayed['report']['path'],
                          'sha256': replayed['report']['sha256'], 'status': STATUS}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (PublicDataVariableRuntimeError, product_evidence.ProductEvidenceError,
            static_products.PreparationError, ordinary_link.PublicDataEvidenceError,
            OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'public-data declaration runtime: {error}', file=sys.stderr)
        raise SystemExit(2)
