#!/usr/bin/env python3
"""Exercise one guarded malformed-EH-header boundary through the provider.

This is standalone provider evidence only. It does not select the archive in
an owned runtime or qualify loader callbacks, indirect pointers, or DWARF.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent
TARGET = 'x86_64-unknown-linux-musl'
EXPECTED_OUTPUT = 'truncated EH header rejected\n'
PATCH_PATH = 'unwinder/patches/unwinding-0.2.10-phdr-bounds.rs'
PATCH_TARGET = 'src/unwinder/find_fde/phdr.rs'


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
        raise RuntimeError(f'truncated-metadata fixture exited with status {status}')
    if output != EXPECTED_OUTPUT:
        raise RuntimeError(f'unexpected truncated-metadata fixture output: {output!r}')


def disable_core_dumps() -> None:
    """Keep malformed-metadata probes from creating ambient crash artifacts."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def assert_patched_provider(provenance: dict, archive_sha256: str) -> None:
    if provenance['archive']['sha256'] != archive_sha256:
        raise RuntimeError('provider provenance does not identify the selected archive')
    patches = provenance['patched_unwinding']['patches']
    if len(patches) != 1:
        raise RuntimeError('provider provenance does not identify one bounded-header overlay')
    patch = patches[0]
    patch_digest = digest(ROOT / 'patches/unwinding-0.2.10-phdr-bounds.rs')
    if (
        patch['path'] != PATCH_PATH
        or patch['target'] != PATCH_TARGET
        or patch['sha256'] != patch_digest
        or patch['compiled_sha256'] != patch_digest
        or patch['license'] != 'MIT OR Apache-2.0'
    ):
        raise RuntimeError('provider provenance does not identify the compiled bounded-header overlay')
    dependencies = {dependency['name']: dependency for dependency in provenance['dependencies']}
    compiled = {
        entry['path']: entry['sha256']
        for entry in dependencies['unwinding']['files']
    }
    if compiled.get(PATCH_TARGET) != patch_digest:
        raise RuntimeError('provider source audit does not match the compiled bounded-header overlay')


def main() -> None:
    runs = ROOT.parent / '.work/x86_64/unwinder-metadata-bounds-runs'
    runs.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='run-', dir=runs))
    output.chmod(0o755)
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(('CARGO_', 'RUSTFLAGS', 'RUSTUP_TOOLCHAIN'))
    }
    provider = output / 'provider'
    run_logged([sys.executable, '-B', ROOT / 'build.py', '--output', provider], environment, output / 'provider-build.log')
    archive = provider / 'libcrabc-unwind.a'
    if not archive.is_file():
        raise RuntimeError('provider build did not produce its selected archive')
    assert_patched_provider(
        json.loads((provider / 'provenance.json').read_text()),
        digest(archive),
    )

    channel = tomllib.loads((ROOT.parent / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    stock_libdir = Path(run_logged(
        ['rustup', 'run', channel, 'rustc', '--target', TARGET, '--print', 'target-libdir'],
        environment,
        output / 'target-libdir.log',
    ).strip())
    binary = output / 'truncated-metadata'
    link_log = output / 'truncated-metadata-link.log'
    fixture_environment = dict(environment)
    fixture_environment.update(
        CRABC_UNWINDER_ARCHIVE=str(archive),
        CRABC_UNWINDER_LINK_LOG=str(link_log),
        CRABC_UNWINDER_STOCK_LIBDIR=str(stock_libdir),
    )
    run_logged(
        [
            'rustup', 'run', channel, 'rustc', '--edition=2024', '--target', TARGET,
            '-C', 'panic=unwind', '-C', 'force-unwind-tables=yes',
            '-C', f'linker={ROOT / "cleanup_link.py"}',
            '-C', 'link-arg=-Wl,--eh-frame-hdr',
            ROOT / 'fixtures/truncated_metadata.rs', '-o', binary,
        ],
        fixture_environment,
        output / 'truncated-metadata-compile.log',
    )
    link_receipt = json.loads(link_log.read_text())
    if link_receipt['archive'] != {'path': str(archive), 'sha256': digest(archive)}:
        raise RuntimeError('link receipt does not identify the selected unwind archive')
    if link_receipt['command'].count(str(archive)) != 1 or str(archive) not in link_receipt['trace']:
        raise RuntimeError('link receipt does not demonstrate selected archive extraction')
    execution = subprocess.run(
        [binary], env=fixture_environment, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, preexec_fn=disable_core_dumps,
    )
    (output / 'truncated-metadata-execution.log').write_text(execution.stdout)
    assert_execution(execution.returncode, execution.stdout)
    receipt = {
        'schema': 1,
        'scope': 'standalone guarded PT_GNU_EH_FRAME provider regression',
        'qualified': False,
        'fixture': {'path': 'unwinder/fixtures/truncated_metadata.rs', 'sha256': digest(ROOT / 'fixtures/truncated_metadata.rs')},
        'provider_archive_sha256': digest(archive),
        'binary_sha256': digest(binary),
        'link_receipt_sha256': digest(link_log),
    }
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
