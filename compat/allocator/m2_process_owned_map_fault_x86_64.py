#!/usr/bin/env python3
"""Compare a failed process-owned metadata-sized OS map and exact retry with pinned C."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix('.c')
ARTIFACTS = harness.ARTIFACT_ROOT / 'x86_64/m2-process-owned-map-fault'
TEST = 'os::tests::emit_m2_process_owned_map_fault_c_rust_trace'
FIELDS = (
    'page_size', 'request_size', 'first_failed', 'first_no_owner', 'map_calls',
    'first_null_hint', 'first_length', 'first_protection', 'first_anonymous_private',
    'retry_null_hint', 'retry_length', 'retry_protection', 'retry_anonymous_private',
    'warning_count', 'warning_errno', 'warning_size', 'warning_after_attempt',
    'warning_reserved', 'warning_committed', 'warning_mmap_calls', 'warning_commit_calls',
    'failed_reserved', 'failed_committed', 'failed_mmaps', 'failed_commits',
    'retry_succeeded', 'full_owner', 'writable', 'retry_reserved', 'retry_committed',
    'retry_mmaps', 'retry_commits', 'terminal_reserved', 'terminal_committed',
    'terminal_unmapped',
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f'CRABC_M2_PROCESS_OWNED_MAP_FAULT_{language}_TRACE_BEGIN'
    end = f'CRABC_M2_PROCESS_OWNED_MAP_FAULT_{language}_TRACE_END'
    if output.count(begin) != 1 or output.count(end) != 1:
        raise harness.HarnessError(f'{language} process-owned map markers differ')
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, sep, raw = line.strip().partition('=')
        if not sep or key in values:
            raise harness.HarnessError(f'{language} process-owned map trace malformed')
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise harness.HarnessError(f'{language} process-owned map roster differs: {sorted(values)}')
    return values


def c_oracle(offline: bool) -> tuple[dict[str, int], dict]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix='m2-process-owned-map-fault-') as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin['archive_root'])
        binary = ARTIFACTS / 'pinned-c-oracle'
        command = [harness.require_tool('musl-gcc'), '-std=c11', '-fPIC',
            '-ftls-model=initial-exec', '-DMI_SHARED_LIB', '-DMI_SHARED_LIB_EXPORT',
            '-DMI_LIBC_MUSL=1', '-DMI_PRIM_HAS_PROCESS_ATTACH=1',
            '-I', str(source / 'include'), '-I', str(source / 'src'),
            *harness.CONFIGURATION_PROFILES['release'], str(FIXTURE),
            '-Wl,--wrap=mmap', '-pthread', '-o', str(binary)]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, 'pinned C process-owned map fault build')
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, 'pinned C process-owned map fault')
    (ARTIFACTS / 'pinned-c.stdout').write_text(str(execution['stdout']))
    (ARTIFACTS / 'pinned-c.stderr').write_text(str(execution['stderr']))
    return trace(str(execution['stdout']), 'C'), {'build': build, 'run': execution}


def rust_receiver() -> tuple[dict[str, int], dict]:
    command = ['python3', 'compat/allocator/run_unit_x86_64.py', TEST]
    execution = harness.command_record(command, cwd=ROOT, timeout_seconds=900)
    (ARTIFACTS / 'rust.stdout').write_text(str(execution['stdout']))
    (ARTIFACTS / 'rust.stderr').write_text(str(execution['stderr']))
    harness.require_success(execution, 'Rust process-owned map fault receiver')
    return trace(str(execution['stdout']), 'RUST'), {'run': execution}


def expected_values() -> dict[str, int]:
    page = 4096
    size = 2 * page
    return {
        'page_size': page, 'request_size': size,
        'first_failed': 1, 'first_no_owner': 1, 'map_calls': 2,
        'first_null_hint': 1, 'first_length': size, 'first_protection': 3,
        'first_anonymous_private': 1, 'retry_null_hint': 1,
        'retry_length': size, 'retry_protection': 3, 'retry_anonymous_private': 1,
        'warning_count': 1, 'warning_errno': 1, 'warning_size': 1,
        'warning_after_attempt': 1, 'warning_reserved': 0, 'warning_committed': 0,
        'warning_mmap_calls': 0, 'warning_commit_calls': 0,
        'failed_reserved': 0, 'failed_committed': 0, 'failed_mmaps': 1,
        'failed_commits': 0, 'retry_succeeded': 1, 'full_owner': 1,
        'writable': 1, 'retry_reserved': size, 'retry_committed': size,
        'retry_mmaps': 2, 'retry_commits': 0, 'terminal_reserved': 0,
        'terminal_committed': 0, 'terminal_unmapped': 1,
    }


def run(offline: bool, c_only: bool) -> dict:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    c, c_commands = c_oracle(offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    expected = expected_values()
    mismatches = [f'c.{field}' for field, value in expected.items() if c[field] != value]
    if not c_only:
        mismatches.extend(f'rust.{field}' for field, value in expected.items() if rust[field] != value)
        mismatches.extend(f'differential.{field}' for field in FIELDS if c[field] != rust[field])
    if c_commands['run']['stderr']:
        mismatches.append('c.unrouted_diagnostics')
    if not c_only and rust_commands['run']['stderr']:
        mismatches.append('rust.unrouted_diagnostics')
    report = {'status': 'matched' if not mismatches else 'red', 'c': c, 'rust': rust,
        'mismatches': mismatches, 'c_commands': c_commands,
        'rust_commands': rust_commands,
        'source_seal': {'revision': pin['revision'], 'archive_sha256': pin['sha256'],
            'fixture_sha256': hashlib.sha256(FIXTURE.read_bytes()).hexdigest()},
        'scope': 'metadata-sized committed process OS map; first mmap fault warning before map accounting; no first owner; same-request retry and exact release'}
    (ARTIFACTS / 'evidence.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(f'process-owned map fault {report["status"].upper()} ({len(FIELDS)} fields)')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--c-only', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.offline, args.c_only)['status'] == 'matched' else 1)
