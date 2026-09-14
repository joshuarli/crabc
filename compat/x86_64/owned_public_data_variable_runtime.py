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
import stat
import sys
import tomllib
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
CONTRACT_PATH = MODULE_DIR / 'owned_public_data_variable_runtime.toml'
SCHEMA = 'crabc.x86_64-owned-public-data-variable-runtime/v1'
CONTRACT_SCHEMA = 'crabc.x86_64-owned-public-data-variable-runtime-contract/v1'
COMPONENT = 'public-data-declaration-runtime'
TARGET = 'x86_64-unknown-linux-musl'
PINNED_MUSL_COMMIT = '9fa28ece75d8a2191de7c5bb53bed224c5947417'
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
    ]
    for group in contract['groups']:
        paths.extend(group['probe_sources'])
        paths.extend(group['owner_sources'])
    paths.extend(contract['h_errno']['owner_sources'])
    paths.extend((
        contract['h_errno']['header'],
        'compat/x86_64/native_data_declarations.py',
        'compat/x86_64/native_declaration_abi.py',
        'compat/x86_64/public_data_ordinary_link_evidence.py',
        'compat/x86_64/owned_errno_storage_lifecycle.py',
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


def h_errno_composition_contract() -> dict[str, Any]:
    """Name the existing owners that must meet at the one accessor boundary."""
    return {
        **H_ERRNO,
        'header_owner': 'native_data_declarations',
        'runtime_owner': 'owned_errno_storage_lifecycle',
        'static_shared_roles': ['static', 'shared'],
        'execution_scope': ['main', 'live-worker', 'loaded-dso'],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-contract', action='store_true')
    args = parser.parse_args(argv)
    if not args.check_contract:
        parser.error('--check-contract is required until collection is implemented')
    contract = load_contract()
    print(f'public-data declaration runtime: {len(OBJECTS)} installed variables in {len(contract["groups"])} groups')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
