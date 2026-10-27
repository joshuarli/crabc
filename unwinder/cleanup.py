#!/usr/bin/env python3
"""Run the full Rust cleanup fixture with the selected standalone unwinder.

This is focused provider evidence only.  It uses the pinned-musl image as a
test harness and neither installs the archive into crabc nor qualifies an
owned runtime product.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent
COMPAT = ROOT.parent / 'compat/x86_64'
if str(COMPAT) not in sys.path:
    sys.path.insert(0, str(COMPAT))
import native_rustc
from loader_debug_abi_evidence import Elf
from owned_static_link_authority import section_name

TARGET = 'x86_64-unknown-linux-musl'
EXPECTED_OUTPUT = 'unwind: backtrace cleanup payload main thread\n'
EXECUTED_UNWIND_ABI = {
    '_Unwind_Backtrace',
    '_Unwind_RaiseException',
    '_Unwind_Resume',
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_logged(command: list[str | Path], environment: dict[str, str], log: Path) -> str:
    if log.exists() or log.is_symlink():
        raise RuntimeError(f'expected fresh evidence log: {log}')
    result = subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f'command failed with status {result.returncode}: {command[0]}')
    return result.stdout


def assert_execution(status: int, output: str) -> None:
    if status:
        raise RuntimeError(f'cleanup fixture exited with status {status}')
    if output != EXPECTED_OUTPUT:
        raise RuntimeError(f'unexpected cleanup fixture output: {output!r}')


def _unwind_symbols(path: Path, defined: str, provider_symbols: set[str]) -> list[str]:
    names = {line.split()[-1] for line in defined.splitlines()
             if len(line.split()) >= 3 and line.split()[-1].startswith('_Unwind_')}
    labels = {name for name in names if name.endswith('$got') and name[:-4] in provider_symbols}
    if not labels:
        return sorted(names)
    image = Elf(path)
    relocations = []
    unsupported = any(section[1] in (9, 19) and section[2] & 2 and section[5] for section in image.sections)
    for section in image.sections:
        if section[1] != 4 or not section[2] & 2:
            continue
        if section[9] != 24 or section[5] % 24:
            raise ValueError('invalid unwind GOT relocations')
        relocations.extend(image.unpack('<QQq', section[4] + offset) for offset in range(0, section[5], 24))
    for name in labels:
        label = image.symbol(name, dynamic=False, required=False)
        target = image.symbol(name[:-4], dynamic=False, required=False)
        if (label is None or target is None or unsupported or not 0 < label['section'] < len(image.sections)
                or not 0 < target['section'] < len(image.sections)):
            continue
        section = image.sections[label['section']]
        target_section = image.sections[target['section']]
        address = label['value']
        nearby = [row for row in relocations if address - 7 <= row[0] < address + 8]
        if (label['type'] == 'OBJECT' and label['binding'] == 'LOCAL' and label['visibility'] == 'DEFAULT'
                and label['size'] == 0 and section_name(image, section) == '.got'
                and section[1] == 1 and section[2] & 3 == 3 and address % 8 == 0
                and section[3] <= address and address + 8 <= section[3] + section[5]
                and target['type'] == 'FUNC' and target['size'] > 0 and target_section[2] & 6 == 6
                and target_section[3] <= target['value']
                and target['value'] + target['size'] <= target_section[3] + target_section[5]
                and nearby == [(address, 8, target['value'])]
                and image.unpack('<Q', section[4] + address - section[3])[0] == target['value']):
            names.remove(name)
    return sorted(names)


def assert_binary_unwind_symbols(symbols: set[str], provider_symbols: set[str]) -> None:
    unexpected = symbols - provider_symbols
    if unexpected:
        raise RuntimeError(f'cleanup binary contains an unselected unwind ABI: {sorted(unexpected)}')
    missing = EXECUTED_UNWIND_ABI - symbols
    if missing:
        raise RuntimeError(f'cleanup binary lacks executed unwind ABI: {sorted(missing)}')


def archive_unwind_symbols(path: Path) -> set[str]:
    return {
        line.split()[-1]
        for line in path.read_text().splitlines()
        if len(line.split()) >= 3 and line.split()[-1].startswith('_Unwind_')
    }


def main() -> None:
    runs = ROOT.parent / '.work/x86_64/unwinder-cleanup-runs'
    runs.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='run-', dir=runs))
    output.chmod(0o755)
    provider = output / 'provider'
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(('CARGO_', 'RUSTFLAGS', 'RUSTUP_TOOLCHAIN'))
    }
    python = sys.executable
    run_logged(
        [python, '-B', ROOT / 'build.py', '--output', provider],
        environment,
        output / 'provider-build.log',
    )
    archive = provider / 'libcrabc-unwind.a'
    provider_symbols = archive_unwind_symbols(provider / 'defined-symbols.txt')
    if len(provider_symbols) != 17 or not archive.is_file():
        raise RuntimeError('provider build did not retain the approved unwind ABI')

    channel = tomllib.loads((ROOT.parent / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    binary = output / 'cleanup'
    link_log = output / 'cleanup-link.log'
    stock_libdir = Path(run_logged(
        ['rustup', 'run', channel, 'rustc', '--target', TARGET, '--print', 'target-libdir'],
        environment,
        output / 'target-libdir.log',
    ).strip())
    fixture_environment = dict(environment)
    fixture_environment.update(
        CRABC_UNWINDER_ARCHIVE=str(archive),
        CRABC_UNWINDER_LINK_LOG=str(link_log),
        CRABC_UNWINDER_STOCK_LIBDIR=str(stock_libdir),
    )
    run_logged(
        [
            *native_rustc.compile_command(), '--edition=2024', '--target', TARGET,
            '-C', 'panic=unwind', '-C', 'force-unwind-tables=yes',
            '-C', f'linker={ROOT / "cleanup_link.py"}',
            '-C', 'link-arg=-Wl,--eh-frame-hdr',
            ROOT / 'fixtures/cleanup.rs', '-o', binary,
        ],
        fixture_environment,
        output / 'cleanup-compile.log',
    )
    link_receipt = json.loads(link_log.read_text())
    if link_receipt['archive'] != {'path': str(archive), 'sha256': digest(archive)}:
        raise RuntimeError('link receipt does not identify the selected unwind archive')
    if link_receipt['command'].count(str(archive)) != 1:
        raise RuntimeError('link command does not select exactly one unwind archive')
    trace = link_receipt['trace']
    if str(archive) not in trace:
        raise RuntimeError('link trace did not extract the selected unwind archive')
    symbols = run_logged(['nm', '--defined-only', binary], fixture_environment, output / 'cleanup-symbols.log')
    binary_symbols = set(_unwind_symbols(binary, symbols, provider_symbols))
    assert_binary_unwind_symbols(binary_symbols, provider_symbols)
    segments = run_logged(['readelf', '-lW', binary], fixture_environment, output / 'cleanup-segments.log')
    if 'GNU_EH_FRAME' not in segments:
        raise RuntimeError('cleanup binary lacks an EH-frame header')
    execution = subprocess.run([binary], env=fixture_environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (output / 'cleanup-execution.log').write_text(execution.stdout)
    assert_execution(execution.returncode, execution.stdout)
    receipt = {
        'schema': 1,
        'scope': 'standalone pinned-musl Rust std cleanup fixture',
        'qualified': False,
        'fixture': {'path': 'unwinder/fixtures/cleanup.rs', 'sha256': digest(ROOT / 'fixtures/cleanup.rs')},
        'provider_archive_sha256': digest(archive),
        'provider_unwind_abi': sorted(provider_symbols),
        'binary_unwind_abi': sorted(binary_symbols),
        'binary_sha256': digest(binary),
        'link_receipt_sha256': digest(link_log),
    }
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
