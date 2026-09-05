#!/usr/bin/env python3
"""Enter the one libc-test root whose RLIMIT_NPROC assertion requires nonroot.

This host control-plane helper never enters the product. It measures the
credential transition immediately before exec, not the target's identity after
execution. The fixed upstream test and its runtest command remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

UNIT = 'regression/pthread_atfork-errno-clobber'
SCHEMA = 'crabc.x86_64-owned-libc-test-execution-identity/v1'
ROOT = Path(__file__).resolve().parents[2]
CAPABILITY_FIELDS = {
    'CapInh': 'inheritable', 'CapPrm': 'permitted', 'CapEff': 'effective',
    'CapBnd': 'bounding', 'CapAmb': 'ambient',
}


def fixture_for_unit(unit: str) -> dict[str, Any] | None:
    """Select only the source that requires RLIMIT_NPROC to reject fork."""

    if unit != UNIT:
        return None
    return {
        'kind': 'fixed-unprivileged-identity', 'uid': 65534, 'gid': 65534,
        'supplementary_groups': [],
        'required_zero_capability_sets': ['inheritable', 'permitted', 'effective', 'ambient'],
        'source_requirement': 'RLIMIT_NPROC=0 must reject fork before checking atfork errno preservation',
    }


def parse_proc_identity(status: str) -> dict[str, Any]:
    """Read the kernel's real/effective/saved/filesystem IDs and capability sets."""

    expected = {'Uid', 'Gid', 'Groups', *CAPABILITY_FIELDS}
    fields: dict[str, str] = {}
    for line in status.splitlines():
        key, separator, value = line.partition(':')
        if separator and key in expected:
            if key in fields:
                raise ValueError(f'duplicate process identity field: {key}')
            fields[key] = value.strip()
    if set(fields) != expected:
        raise ValueError('process status lacks required identity fields')
    numbers: dict[str, list[int]] = {}
    for key in ('Uid', 'Gid', 'Groups'):
        words = fields[key].split()
        if (key != 'Groups' and len(words) != 4) or any(not word.isdecimal() for word in words):
            raise ValueError(f'invalid process identity field: {key}')
        numbers[key] = [int(word) for word in words]
    capabilities = {}
    for key, name in CAPABILITY_FIELDS.items():
        if re.fullmatch(r'[0-9a-f]{16}', fields[key]) is None:
            raise ValueError(f'invalid process capability field: {key}')
        capabilities[name] = fields[key]
    return {'uids': numbers['Uid'], 'gids': numbers['Gid'], 'groups': numbers['Groups'], 'capabilities': capabilities}


def observe_process_identity(proc_fd: int | None = None) -> dict[str, Any]:
    """Use an already opened proc descriptor when the process has entered chroot."""

    owned_fd = proc_fd is None
    if proc_fd is None:
        proc_fd = os.open('/proc/self/status', os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.lseek(proc_fd, 0, os.SEEK_SET)
        status = os.read(proc_fd, 65536).decode('ascii')
    finally:
        if owned_fd:
            os.close(proc_fd)
    return {
        'resuid': list(os.getresuid()), 'resgid': list(os.getresgid()),
        'groups': os.getgroups(), 'proc': parse_proc_identity(status),
    }


def validate_snapshot(snapshot: dict[str, Any]) -> None:
    """Reject incomplete or contradictory libc/kernel credential observations."""

    if not isinstance(snapshot, dict) or set(snapshot) != {'resuid', 'resgid', 'groups', 'proc'}:
        raise ValueError('invalid process identity snapshot')
    proc = snapshot['proc']
    if not isinstance(proc, dict) or set(proc) != {'uids', 'gids', 'groups', 'capabilities'}:
        raise ValueError('invalid process kernel identity snapshot')
    for owner, name, count in [(snapshot, 'resuid', 3), (snapshot, 'resgid', 3), (proc, 'uids', 4), (proc, 'gids', 4)]:
        values = owner[name]
        if not isinstance(values, list) or len(values) != count or any(type(value) is not int or value < 0 for value in values):
            raise ValueError('invalid process identity numbers')
    for values in (snapshot['groups'], proc['groups']):
        if not isinstance(values, list) or any(type(value) is not int or value < 0 for value in values):
            raise ValueError('invalid supplementary groups')
    if snapshot['resuid'] != proc['uids'][:3] or snapshot['resgid'] != proc['gids'][:3] or sorted(snapshot['groups']) != sorted(proc['groups']):
        raise ValueError('libc and kernel process identities disagree')
    caps = proc['capabilities']
    if not isinstance(caps, dict) or set(caps) != set(CAPABILITY_FIELDS.values()) or any(not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{16}', value) is None for value in caps.values()):
        raise ValueError('invalid capability observation')


def validate_transition(before: dict[str, Any], after: dict[str, Any]) -> None:
    """Prove the source's nonroot/no-capability precondition before target exec."""

    validate_snapshot(before)
    validate_snapshot(after)
    if before['resuid'] != [0] * 3 or before['proc']['uids'] != [0] * 4:
        raise ValueError('identity launcher did not begin with root credentials')
    if after['resuid'] != [65534] * 3 or after['resgid'] != [65534] * 3 or after['proc']['uids'] != [65534] * 4 or after['proc']['gids'] != [65534] * 4:
        raise ValueError('fixed nonroot identity was not installed')
    if after['groups'] or after['proc']['groups']:
        raise ValueError('supplementary groups were not cleared')
    for name in ('inheritable', 'permitted', 'effective', 'ambient'):
        if after['proc']['capabilities'][name] != '0000000000000000':
            raise ValueError(f'nonroot launcher retained {name} capabilities')
    if before['proc']['capabilities']['bounding'] != after['proc']['capabilities']['bounding']:
        raise ValueError('identity transition changed capability bounding set')


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--unit', choices=[UNIT], required=True)
    return parser.parse_args(arguments)


def physical(path: Path) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError(f'identity control path is not physical: {path}')
    return path


def enter_root(arguments: argparse.Namespace) -> None:
    """Drop credentials in this disposable helper process, then replace it."""

    root = physical(arguments.root)
    receipt = arguments.receipt
    if not root.is_dir() or not root.is_relative_to(ROOT / '.work') or root.name not in ('candidate', 'oracle') or root.parts[-4:-1] != ('execution', 'regression', 'pthread_atfork-errno-clobber'):
        raise ValueError('identity root is not the fixed unit execution root')
    if receipt != root.parent / (root.name + '.identity.json') or receipt.exists() or receipt.is_symlink():
        raise ValueError('identity receipt is not a fresh fixed-side sibling')
    source = physical(root.parents[3] / 'source-prepared/src' / (UNIT + '.c'))
    if not source.is_file():
        raise ValueError('identity source binding is not a regular file')
    command = ['/runtest', '-w', '', '/' + UNIT]
    for executable in (root / 'runtest', root / UNIT):
        mode = physical(executable).stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o6000:
            raise ValueError('identity target must be a regular non-setid executable')
    source_record = {'path': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
    proc_fd = os.open('/proc/self/status', os.O_RDONLY | os.O_CLOEXEC)
    receipt_fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    try:
        before = observe_process_identity(proc_fd)
        os.chroot(root)
        os.chdir('/')
        os.setgroups([])
        os.setresgid(65534, 65534, 65534)
        os.setresuid(65534, 65534, 65534)
        after = observe_process_identity(proc_fd)
        validate_transition(before, after)
        data = (json.dumps({
            'schema': SCHEMA, 'unit': UNIT, 'root': str(root), 'fixture': fixture_for_unit(UNIT),
            'source': source_record, 'command': command, 'before_drop': before, 'before_exec': after,
        }, indent=2, sort_keys=True) + '\n').encode('utf-8')
        while data:
            written = os.write(receipt_fd, data)
            if written == 0:
                raise OSError('identity receipt write made no progress')
            data = data[written:]
    finally:
        os.close(receipt_fd)
        os.close(proc_fd)
    os.execve(command[0], command, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': '1'})


def main(arguments: list[str] | None = None) -> int:
    try:
        enter_root(parse_arguments(sys.argv[1:] if arguments is None else arguments))
    except (OSError, ValueError) as error:
        print(f'owned libc-test identity setup failed: {error}', file=sys.stderr)
        return 125
    return 125


if __name__ == '__main__':
    raise SystemExit(main())
