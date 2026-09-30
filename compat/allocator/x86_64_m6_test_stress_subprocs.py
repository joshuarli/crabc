#!/usr/bin/env python3
"""Run the exact pinned subprocess stress workload against C and Rust.

The source creates two subprocess owners, starts and joins their workers,
retains transfers between iterations, and destroys the subprocesses only
when their owners have joined. The native adapter supplies the unprefixed
allocator names and natural pthread-key teardown. The source is never
patched, and standard-malloc selection would disable the subprocess test.
"""

import argparse
from collections import Counter
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Mapping, Sequence

import run as harness
import x86_64_m4_gate as m4
import perf_engine_x86_64 as engine
from x86_64_m6_upstream_heap_stress import receipts


ARTIFACTS = harness.ARTIFACT_ROOT / 'x86_64/m6-test-stress-subprocs'
PROFILES = ('release', 'debug-1', 'stat-1', 'stat-2')
RUNNER = 'allocator-subprocess-stress'
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
              cases: Sequence[tuple[int, int, int]] = CASES, *,
              receipt_cases: list | None = None, profile: str = "release") -> int:
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
            if receipt_cases is not None:
                receipt_cases.append((f'{profile}-{stem}', 0,
                    [artifacts / (stem + '.json'), artifacts / (stem + '.log')]))
            print(f'{profile} {side} subprocess stress {case}: passed', flush=True)
    return len(cases)


def build_translations(compiler: str, source: Path, workload: Path, oracle: Path,
                       profile: str) -> dict[str, list[str]]:
    # Workload assertions and diagnostic calls remain active independently
    # of the allocator mode; only the allocator object receives its profile.
    return {
        'workload': [compiler, '-std=c11', '-O2', '-DMI_DEBUG=0', '-DMI_STAT=0',
                     '-DMI_SECURE=0', '-DMI_GUARDED=0', '-I', str(source / 'include'),
                     '-I', str(source / 'test'), '-c', str(source / SOURCE_MEMBERS[0]),
                     '-o', str(workload)],
        'pinned-allocator': [compiler, '-std=c11', *m4.api_profile_flags(profile),
                             '-ftls-model=initial-exec', '-DMI_LIBC_MUSL=1',
                             '-I', str(source / 'include'), '-c', str(source / 'src/static.c'),
                             '-o', str(oracle)],
    }


def run_profile(profile: str, receipt_cases: list) -> dict[str, Path]:
    artifacts = ARTIFACTS if profile == 'release' else ARTIFACTS / profile
    artifacts.mkdir(parents=True, exist_ok=True)
    for name in ('source.json', 'native-execution-provenance.json'):
        (artifacts / name).unlink(missing_ok=True)
    native_before = harness.require_native_x86_64(require_image_identity=True)
    source_before = harness.runtime_ticket_zero_soak_source_state()
    harness.runtime_ticket_zero_soak_source_attestation(source_before, source_before)
    harness.write_json(artifacts / 'source-before.json', source_before)
    harness.write_json(artifacts / 'native-before.json', native_before)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    inventory = harness.read_json(harness.UPSTREAM_TEST_CONTRACT)
    hashes = {entry['path']: entry['sha256'] for entry in inventory['tests']}
    with harness.temporary_directory('crabc-mimalloc-subprocess-stress-') as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / 'source', pin['archive_root'])
        selected = artifacts / 'source'
        selected.mkdir(exist_ok=True)
        for member in SOURCE_MEMBERS:
            path = source / member
            if harness.sha256_file(path) != hashes[member]:
                raise harness.HarnessError(f'pinned subprocess stress source differs: {member}')
            shutil.copy2(path, selected / path.name)
        compiler = harness.require_tool('musl-gcc')
        library = m4.build_adapter_library(artifacts, profile)
        workload = artifacts / 'test-stress-subprocs.o'
        oracle = artifacts / 'pinned-allocator.o'
        translations = build_translations(compiler, source, workload, oracle, profile)
        for label, command in translations.items():
            build = harness.command_record(command, cwd=source, timeout_seconds=300)
            harness.write_json(artifacts / (label + '-build.json'), build)
            (artifacts / (label + '-build.log')).write_text(str(build['stdout']) + str(build['stderr']))
            harness.require_success(build, f'authentic subprocess stress {label} build')
            receipt_cases.append((f'{profile}-{label}-build', 0,
                [artifacts / (label + '-build.json'), artifacts / (label + '-build.log')]))
        drivers = {side: artifacts / ('test-stress-subprocs-' + side) for side in ('c', 'rust')}
        for side, binary in drivers.items():
            command = [compiler, str(workload), str(oracle if side == 'c' else library)]
            build = harness.command_record([*command, '-pthread', '-o', str(binary)], cwd=source,
                                           timeout_seconds=300)
            harness.write_json(artifacts / (side + '-build.json'), build)
            (artifacts / (side + '-build.log')).write_text(str(build['stdout']) + str(build['stderr']))
            harness.require_success(build, f'{side} authentic subprocess stress build')
            receipt_cases.append((f'{profile}-{side}-build', 0,
                [artifacts / (side + '-build.json'), artifacts / (side + '-build.log')]))
        harness.write_json(artifacts / 'artifacts.json', {
            'profile': profile, 'allocator_flags': list(m4.api_profile_flags(profile)),
            'native_features': [] if profile == 'release' else [f'crabc-mimalloc/mi-{profile}'],
            'workload_assertions': True, 'workload_modified': False,
            'archive': engine.file_record(archive), 'adapter': engine.file_record(library),
            'workload': engine.file_record(workload), 'pinned_allocator': engine.file_record(oracle),
            'programs': {side: engine.file_record(binary) for side, binary in drivers.items()},
            'source': {member: engine.file_record(selected / Path(member).name) for member in SOURCE_MEMBERS},
        })
        count = run_cases(drivers, artifacts, receipt_cases=receipt_cases, profile=profile)
    source = harness.runtime_ticket_zero_soak_source_attestation(
        source_before, harness.runtime_ticket_zero_soak_source_state())
    native = harness.native_execution_attestation(
        native_before, harness.require_native_x86_64(require_image_identity=True))
    harness.write_json(artifacts / 'source.json', source)
    harness.write_json(artifacts / 'native-execution-provenance.json', native)
    print(f'authentic subprocess stress {profile} passed: {count} C/Rust cases; {artifacts}')
    products = {f'{profile}-{side}': binary for side, binary in drivers.items()}
    products.update({f'{profile}-adapter.a': library, f'{profile}-workload.o': workload,
                     f'{profile}-pinned-allocator.o': oracle})
    for path in (artifacts / 'artifacts.json', artifacts / 'source-before.json',
                 artifacts / 'native-before.json', artifacts / 'source.json',
                 artifacts / 'native-execution-provenance.json',
                 *(selected / Path(member).name for member in SOURCE_MEMBERS)):
        products[f'{profile}-{path.name}'] = path
    return products


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--profile', choices=PROFILES, default='release')
    selection.add_argument('--matrix', action='store_true', help='run the unchanged full roster in all four profiles')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--read', action='store_true', help='read the existing exact-source physical receipt')
    action.add_argument('--replay', action='store_true', help='read the receipt and execute its retained drivers')
    args = parser.parse_args(argv)
    profiles = PROFILES if args.matrix else (args.profile,)
    parameters = {'profiles': ','.join(profiles), 'watchdog-seconds': str(CASE_TIMEOUT_SECONDS),
                  'boundary': 'unprefixed-native-mi-adapter', 'workload-assertions': 'active'}
    if args.read or args.replay:
        receipt = receipts.read_receipt(harness.ROOT, RUNNER)
        if dict(receipt.parameters) != parameters:
            raise harness.HarnessError('subprocess stress receipt profile or workload parameters differ')
        for profile in profiles:
            expected = [f'{profile}-case-' + '-'.join(map(str, case)) + '-' + side
                        for case in CASES for side in ('c', 'rust')]
            if receipt.case_ids(f'{profile}-case-') != expected:
                raise harness.HarnessError(f'{profile} subprocess stress receipt lacks the ordered full roster')
        print('authentic subprocess stress exact-source physical receipt: PASS', flush=True)
        if args.replay:
            execution = harness.require_native_x86_64(require_image_identity=True)
            for profile in profiles:
                recorded = harness.read_json(receipt.path.parent / 'products' /
                    f'{profile}-native-execution-provenance.json')
                harness.validate_native_execution_provenance(recorded,
                    expected_image_id=execution['image_id'])
            harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
            scratch = Path(tempfile.mkdtemp(prefix='subprocess-stress-replay-', dir=harness.TEMP_ROOT))
            print(f'subprocess stress reader raw executions: {scratch}', flush=True)
            for profile in profiles:
                directory = scratch / profile
                directory.mkdir()
                drivers = {}
                for side in ('c', 'rust'):
                    binary = directory / side
                    shutil.copyfile(receipt.path.parent / 'products' / f'{profile}-{side}', binary)
                    binary.chmod(0o755)
                    drivers[side] = binary
                run_cases(drivers, directory, profile=profile)
            print('authentic subprocess stress retained full-roster replay: PASS', flush=True)
        return 0
    seal = receipts.source_seal(harness.ROOT)
    cases, products = [], {}
    for profile in profiles:
        products.update(run_profile(profile, cases))
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError('source changed during subprocess stress profile cohort')
    path = receipts.write_receipt(harness.ROOT, RUNNER, ARTIFACTS, products, cases, parameters, True)
    receipts.read_receipt(harness.ROOT, RUNNER)
    print(f'authentic subprocess stress profiles passed: {",".join(profiles)}; {path}', flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (harness.HarnessError, receipts.ReceiptError) as error:
        print(f'subprocess stress failed: {error}', file=sys.stderr)
        raise SystemExit(1)
