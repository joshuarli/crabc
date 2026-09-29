#!/usr/bin/env python3
"""Compare one failed process-owned commit, exact retry, and release with pinned C."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import run as harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix('.c')
ARTIFACTS = harness.ARTIFACT_ROOT / 'x86_64/m2-process-owned-commit-fault'
TEST = 'os::tests::emit_m2_process_owned_commit_fault_c_rust_trace'
FIELDS = (
    'allocated',
    'full_owner',
    'page_size',
    'mapping_size',
    'request_offset',
    'request_size',
    'first_failed',
    'first_is_zero',
    'mapped_after_failure',
    'retry_succeeded',
    'retry_is_zero',
    'writable_after_retry',
    'third_page_mapped',
    'protection_calls',
    'first_offset',
    'first_length',
    'first_flags',
    'retry_offset',
    'retry_length',
    'retry_flags',
    'warning_count',
    'warning_exact',
    'warning_offset',
    'warning_size',
    'warning_after_attempt',
    'reserved_at_map',
    'committed_at_map',
    'commits_at_map',
    'mmaps_at_map',
    'warning_reserved',
    'warning_committed',
    'warning_commit_calls',
    'warning_mmap_calls',
    'reserved_after_failure',
    'committed_after_failure',
    'commits_after_failure',
    'mmaps_after_failure',
    'reserved_after_retry',
    'committed_after_retry',
    'commits_after_retry',
    'mmaps_after_retry',
    'terminal_reserved',
    'terminal_committed',
    'terminal_unmapped',
)

def trace(output: str, language: str) -> dict[str, int]:
    begin = f'CRABC_M2_PROCESS_OWNED_COMMIT_FAULT_{language}_TRACE_BEGIN'
    end = f'CRABC_M2_PROCESS_OWNED_COMMIT_FAULT_{language}_TRACE_END'
    if output.count(begin) != 1 or output.count(end) != 1:
        raise harness.HarnessError(f'{language} commit fault trace markers differ')
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, sep, raw = line.strip().partition('=')
        if not sep or key in values:
            raise harness.HarnessError(f'{language} commit fault trace malformed')
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise harness.HarnessError(f'{language} commit fault roster differs: {sorted(values)}')
    return values

def c_oracle(offline: bool) -> tuple[dict[str, int], dict]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(prefix='m2-process-owned-commit-fault-') as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin['archive_root'])
        binary = ARTIFACTS / 'pinned-c-oracle'
        command = [harness.require_tool('musl-gcc'), '-std=c11', '-fPIC',
            '-ftls-model=initial-exec', '-DMI_SHARED_LIB', '-DMI_SHARED_LIB_EXPORT',
            '-DMI_LIBC_MUSL=1', '-DMI_PRIM_HAS_PROCESS_ATTACH=1',
            '-I', str(source / 'include'), '-I', str(source / 'src'),
            *harness.CONFIGURATION_PROFILES['release'], str(FIXTURE),
            '-Wl,--wrap=mprotect', '-pthread', '-o', str(binary)]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, 'pinned C process-owned commit fault build')
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, 'pinned C process-owned commit fault')
    (ARTIFACTS / 'pinned-c.stdout').write_text(str(execution['stdout']))
    (ARTIFACTS / 'pinned-c.stderr').write_text(str(execution['stderr']))
    return trace(str(execution['stdout']), 'C'), {
        'build': build, 'run': execution}

def rust_receiver() -> tuple[dict[str, int], dict]:
    command = ['python3', 'compat/allocator/run_unit_x86_64.py', TEST]
    execution = harness.command_record(command, cwd=ROOT, timeout_seconds=900)
    (ARTIFACTS / 'rust.stdout').write_text(str(execution['stdout']))
    (ARTIFACTS / 'rust.stderr').write_text(str(execution['stderr']))
    harness.require_success(execution, 'Rust process-owned commit fault receiver')
    return trace(str(execution['stdout']), 'RUST'), {'run': execution}

def expected_values() -> dict[str, int]:
    return {
        'allocated': 1,
        'full_owner': 1,
        'page_size': 4096,
        'mapping_size': 12288,
        'request_offset': 19,
        'request_size': 4101,
        'first_failed': 1,
        'first_is_zero': 0,
        'mapped_after_failure': 1,
        'retry_succeeded': 1,
        'retry_is_zero': 0,
        'writable_after_retry': 1,
        'third_page_mapped': 1,
        'protection_calls': 2,
        'first_offset': 0,
        'first_length': 8192,
        'first_flags': 3,
        'retry_offset': 0,
        'retry_length': 8192,
        'retry_flags': 3,
        'warning_count': 1,
        'warning_exact': 1,
        'warning_offset': 0,
        'warning_size': 8192,
        'warning_after_attempt': 1,
        'reserved_at_map': 12288,
        'committed_at_map': 0,
        'commits_at_map': 0,
        'mmaps_at_map': 1,
        'warning_reserved': 12288,
        'warning_committed': 0,
        'warning_commit_calls': 1,
        'warning_mmap_calls': 1,
        'reserved_after_failure': 12288,
        'committed_after_failure': 0,
        'commits_after_failure': 1,
        'mmaps_after_failure': 1,
        'reserved_after_retry': 12288,
        'committed_after_retry': 4101,
        'commits_after_retry': 2,
        'mmaps_after_retry': 1,
        'terminal_reserved': 0,
        'terminal_committed': -8187,
        'terminal_unmapped': 1,
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
        'scope': 'regular process-owned reserved OS mapping, failed covering mprotect, exact warning-time VM state, retained owner, successful same-range retry, and terminal release'}
    (ARTIFACTS / 'evidence.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(f'process-owned commit fault {report["status"].upper()} ({len(FIELDS)} fields)')
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--c-only', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.offline, args.c_only)['status'] == 'matched' else 1)
