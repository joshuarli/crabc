#!/usr/bin/env python3
"""Run the exact pinned subprocess stress workload against C and Rust.

The source creates two subprocess owners, starts and joins their workers,
retains transfers between iterations, and destroys the subprocesses only
when their owners have joined. The native adapter supplies the unprefixed
allocator names and natural pthread-key teardown. The source is never
patched, and standard-malloc selection would disable the subprocess test.
"""

from collections import Counter
from pathlib import Path
import shutil
from typing import Mapping, Sequence

import run as harness
import x86_64_m4_gate as m4
import perf_engine_x86_64 as engine


ARTIFACTS = harness.ARTIFACT_ROOT / 'x86_64/m6-test-stress-subprocs'
SOURCE_MEMBERS = ('test/test-stress-subprocs.c', 'test/test-stress.c')
CASES = tuple((workers, scale, iterations)
              for scale, iterations in ((1, 1), (10, 10), (50, 20), (50, 50), (101, 5), (150, 20))
              for workers in (1, 2, 4, 8)) + ((16, 50, 50),)
CASE_TIMEOUT_SECONDS = 300


def expected_stdout(case: tuple[int, int, int]) -> str:
    workers, scale, iterations = case
    large = ' (allow large objects)' if scale > 100 else ''
    progress = ''.join(f'- iterations left: {iterations - completed:3d}\n'
                       for completed in range(10, iterations + 1, 10) for _ in range(2))
    return (f'Using {workers} threads with a {scale}% load-per-thread and {iterations} iterations{large}\n'
            ' (for 2 subprocesses)\n' + progress)


def run_cases(drivers: Mapping[str, Path], artifacts: Path,
              cases: Sequence[tuple[int, int, int]] = CASES) -> int:
    """Retain every observation before judging it; stop at the first failure."""
    for case in cases:
        for side in ('c', 'rust'):
            stem = 'case-' + '-'.join(map(str, case)) + '-' + side
            record = harness.command_record(
                [str(drivers[side]), *map(str, case)], cwd=artifacts, env={},
                timeout_seconds=CASE_TIMEOUT_SECONDS,
            )
            harness.write_json(artifacts / (stem + '.json'), record)
            (artifacts / (stem + '.log')).write_text(str(record['stdout']) + str(record['stderr']))
            harness.require_success(record, f'{side} subprocess stress {case}')
            observed = str(record['stdout']).splitlines()
            expected = expected_stdout(case).splitlines()
            # The owners run concurrently, so their progress lines can interleave.
            if observed[:2] != expected[:2] or Counter(observed[2:]) != Counter(expected[2:]):
                raise harness.HarnessError(f'{side} subprocess stress {case} source mode stdout differs')
            print(f'{side} subprocess stress {case}: passed', flush=True)
    return len(cases)


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    for name in ('source.json', 'native-execution-provenance.json'):
        (ARTIFACTS / name).unlink(missing_ok=True)
    native_before = harness.require_native_x86_64(require_image_identity=True)
    source_before = harness.runtime_ticket_zero_soak_source_state()
    harness.runtime_ticket_zero_soak_source_attestation(source_before, source_before)
    harness.write_json(ARTIFACTS / 'source-before.json', source_before)
    harness.write_json(ARTIFACTS / 'native-before.json', native_before)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    inventory = harness.read_json(harness.UPSTREAM_TEST_CONTRACT)
    hashes = {entry['path']: entry['sha256'] for entry in inventory['tests']}
    with harness.temporary_directory('crabc-mimalloc-subprocess-stress-') as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / 'source', pin['archive_root'])
        selected = ARTIFACTS / 'source'
        selected.mkdir(exist_ok=True)
        for member in SOURCE_MEMBERS:
            path = source / member
            if harness.sha256_file(path) != hashes[member]:
                raise harness.HarnessError(f'pinned subprocess stress source differs: {member}')
            shutil.copy2(path, selected / path.name)
        compiler = harness.require_tool('musl-gcc')
        library = m4.build_adapter_library(ARTIFACTS)
        workload = ARTIFACTS / 'test-stress-subprocs.o'
        oracle = ARTIFACTS / 'pinned-allocator.o'
        # Keep workload assertions and diagnostic calls active. The allocator
        # object still uses the selected release configuration independently.
        translations = {
            'workload': [compiler, '-std=c11', '-O2', '-DMI_DEBUG=0', '-DMI_STAT=0',
                         '-DMI_SECURE=0', '-DMI_GUARDED=0', '-I', str(source / 'include'),
                         '-I', str(source / 'test'), '-c', str(source / SOURCE_MEMBERS[0]),
                         '-o', str(workload)],
            'pinned-allocator': [compiler, '-std=c11', *harness.CONFIGURATION_PROFILES['release'],
                                 '-ftls-model=initial-exec', '-DMI_LIBC_MUSL=1',
                                 '-I', str(source / 'include'), '-c', str(source / 'src/static.c'),
                                 '-o', str(oracle)],
        }
        for label, command in translations.items():
            build = harness.command_record(command, cwd=source, timeout_seconds=300)
            harness.write_json(ARTIFACTS / (label + '-build.json'), build)
            (ARTIFACTS / (label + '-build.log')).write_text(str(build['stdout']) + str(build['stderr']))
            harness.require_success(build, f'authentic subprocess stress {label} build')
        drivers = {side: ARTIFACTS / ('test-stress-subprocs-' + side) for side in ('c', 'rust')}
        for side, binary in drivers.items():
            command = [compiler, str(workload), str(oracle if side == 'c' else library)]
            build = harness.command_record([*command, '-pthread', '-o', str(binary)], cwd=source,
                                           timeout_seconds=300)
            harness.write_json(ARTIFACTS / (side + '-build.json'), build)
            (ARTIFACTS / (side + '-build.log')).write_text(str(build['stdout']) + str(build['stderr']))
            harness.require_success(build, f'{side} authentic subprocess stress build')
        harness.write_json(ARTIFACTS / 'artifacts.json', {
            'archive': engine.file_record(archive), 'adapter': engine.file_record(library),
            'workload': engine.file_record(workload), 'pinned_allocator': engine.file_record(oracle),
            'programs': {side: engine.file_record(binary) for side, binary in drivers.items()},
            'source': {member: engine.file_record(selected / Path(member).name) for member in SOURCE_MEMBERS},
        })
        count = run_cases(drivers, ARTIFACTS)
    source = harness.runtime_ticket_zero_soak_source_attestation(
        source_before, harness.runtime_ticket_zero_soak_source_state())
    native = harness.native_execution_attestation(
        native_before, harness.require_native_x86_64(require_image_identity=True))
    harness.write_json(ARTIFACTS / 'source.json', source)
    harness.write_json(ARTIFACTS / 'native-execution-provenance.json', native)
    print(f'authentic subprocess stress passed: {count} C/Rust cases; {ARTIFACTS}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
