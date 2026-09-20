#!/usr/bin/env python3
"""Replace Rust's ambient unwind-library requests with the selected archive."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


FALLBACK_REQUESTS = frozenset({'-lgcc', '-lgcc_s', '-lunwind'})
PINNED_MUSL_LINKER = '/usr/local/bin/crabc-x86_64-musl-gcc'
STOCK_RUST_UNWIND_ARCHIVE = re.compile(r'libunwind-[0-9a-f]+\.rlib')


class LinkError(RuntimeError):
    pass


def is_foreign_unwind_runtime(argument: str) -> bool:
    if argument.startswith('-l:'):
        name = argument.removeprefix('-l:')
    elif argument.startswith('-l') and len(argument) > 2:
        name = argument.removeprefix('-l')
    else:
        name = Path(argument).name
    return name.startswith(('libgcc', 'libunwind', 'gcc', 'unwind'))


def has_foreign_unwind_linker_option(argument: str) -> bool:
    options = argument.split(',')[1:]
    return any(
        option in FALLBACK_REQUESTS
        or is_foreign_unwind_runtime(option)
        or (option == '-l' and is_foreign_unwind_runtime(next_option))
        for option, next_option in zip(options, [*options[1:], ''])
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_stock_rust_unwind_archive(argument: str, stock_libdir: Path) -> bool:
    candidate = Path(argument)
    return candidate.parent == stock_libdir and STOCK_RUST_UNWIND_ARCHIVE.fullmatch(candidate.name) is not None


def translate_arguments(arguments: list[str], archive: Path, stock_libdir: Path) -> list[str]:
    translated: list[str] = []
    inserted = False
    replaced_stock_archive = 0
    for argument in arguments:
        if argument.startswith('@'):
            raise LinkError(f'response file is not admitted: {argument}')
        if argument in {'-l', '-Xlinker'}:
            raise LinkError(f'alternate linker library spelling is not admitted: {argument}')
        if argument in FALLBACK_REQUESTS:
            if not inserted:
                translated.append(str(archive))
                inserted = True
        elif is_stock_rust_unwind_archive(argument, stock_libdir):
            replaced_stock_archive += 1
        elif is_foreign_unwind_runtime(argument):
            raise LinkError(f'foreign unwind runtime input: {argument}')
        elif argument.startswith('-Wl,') and has_foreign_unwind_linker_option(argument):
            raise LinkError(f'foreign unwind runtime linker option: {argument}')
        else:
            translated.append(argument)
    if not inserted:
        raise LinkError('missing Rust standard unwind request')
    if replaced_stock_archive != 1:
        raise LinkError('expected exactly one stock Rust libunwind archive')
    return translated


def main() -> int:
    archive = Path(os.environ['CRABC_UNWINDER_ARCHIVE'])
    log = Path(os.environ['CRABC_UNWINDER_LINK_LOG'])
    stock_libdir = Path(os.environ['CRABC_UNWINDER_STOCK_LIBDIR'])
    if archive.is_symlink() or not archive.is_file():
        raise LinkError(f'expected selected regular unwind archive: {archive}')
    if stock_libdir.is_symlink() or not stock_libdir.is_dir():
        raise LinkError(f'expected selected regular Rust target library directory: {stock_libdir}')
    if log.exists() or log.is_symlink():
        raise LinkError(f'expected fresh link evidence path: {log}')
    archive = archive.resolve()
    command = [PINNED_MUSL_LINKER, *translate_arguments(sys.argv[1:], archive, stock_libdir), '-Wl,--trace']
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(json.dumps({
        'schema': 1,
        'archive': {'path': str(archive), 'sha256': digest(archive)},
        'command': command,
        'trace': result.stdout,
    }, indent=2) + '\n')
    if result.returncode:
        sys.stderr.write(result.stdout)
        return result.returncode
    if any(is_foreign_unwind_runtime(line) for line in result.stdout.splitlines()):
        raise LinkError('link trace admitted an ambient unwind runtime')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (KeyError, LinkError, OSError) as error:
        print(f'crabc-unwinder-cleanup-link: {error}', file=sys.stderr)
        raise SystemExit(1)
