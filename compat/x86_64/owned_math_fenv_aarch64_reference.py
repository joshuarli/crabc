#!/usr/bin/env python3
"""Extract the independently checked binary128 rounding functions for the musl reference."""
from pathlib import Path
import os
import re
import subprocess
import sys

import owned_posix_product_evidence as products
import source_seal

SYMBOLS = ('acoshl', 'sqrtl', 'rintl', 'nearbyintl')


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def validate_products(root, static, dynamic):
    root = products._physical_directory(root, 'repository root')
    static = products._physical_directory(static, 'static product')
    dynamic = products._physical_directory(dynamic, 'dynamic product')
    source = source_seal.product_source_digest(root)
    manifest, _ = products._validate_static_product(static)
    if products._json_object(manifest, 'static reference manifest').get('source_sha256') != source:
        raise ValueError('static reference product source differs')
    products.validate_dynamic_product_source(dynamic, source)


def create_output(root, output):
    root = products._physical_directory(root, 'repository root')
    try:
        parts = output.relative_to(root / '.work').parts
    except ValueError:
        raise ValueError('reference output must be inside .work') from None
    if not parts or any(part in ('.', '..') for part in parts):
        raise ValueError('invalid reference output path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in ('.work', *parts[:-1]):
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        os.mkdir(parts[-1], 0o700, dir_fd=fd)
        return os.open(parts[-1], flags, dir_fd=fd)
    finally:
        os.close(fd)


def extract(root, static, dynamic, output):
    validate_products(root, static, dynamic)
    archive = static / 'usr/lib/libc.a'
    lines = run('nm', '-A', '-g', '--defined-only', '--format=posix', str(archive)).decode().splitlines()
    output_fd = create_output(root, output)
    try:
      for symbol in SYMBOLS:
        matches = []
        for line in lines:
            match = re.fullmatch(re.escape(str(archive)) + r'\[([^\]/]+)\]: (\S+) (\S+) [0-9a-fA-F]+(?: [0-9a-fA-F]+)?', line)
            if match and match.group(2) == symbol and match.group(3) == 'T':
                matches.append(match.group(1))
        if len(matches) != 1:
            raise ValueError(f'expected exactly one static member defining {symbol}')
        data = run('ar', 'p', str(archive), matches[0])
        fd = os.open(symbol + '.o', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=output_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        path = f'/proc/self/fd/{output_fd}/{symbol}.o'
        definitions = subprocess.run(('nm', '-g', '--defined-only', '--format=posix', path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(output_fd,)).stdout.decode().splitlines()
        names = [line.split()[:2] for line in definitions]
        if names != [[symbol, 'T']]:
            raise ValueError(f'{symbol} member has additional global definitions')
    finally:
        os.close(output_fd)


def validate_trace(trace, workload, objects, builtins):
    fixed = {
        '/opt/musl-1.2.6/lib/Scrt1.o', '/opt/musl-1.2.6/lib/crti.o',
        '/opt/musl-1.2.6/lib/crtn.o',
        '/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0/crtbeginS.o',
        '/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0/crtendS.o',
        str(workload), *(str(objects / (name + '.o')) for name in SYMBOLS),
    }
    observed = []
    archives = set()
    for line in trace.read_text(encoding='utf-8').splitlines():
        if not line.startswith('trace: '):
            raise ValueError(f'unexpected reference linker trace: {line}')
        item = line.removeprefix('trace: ')
        if item in fixed:
            observed.append(item)
        elif item.startswith('/opt/musl-1.2.6/lib/libc.a(') and item.endswith(')'):
            archives.add('musl')
        elif item.startswith(str(builtins) + '(') and item.endswith(')'):
            archives.add('builtins')
        else:
            raise ValueError(f'unowned reference link input: {item}')
    if set(observed) != fixed or len(observed) != len(fixed) or archives != {'musl', 'builtins'}:
        raise ValueError('reference link trace omitted a fixed input')


if __name__ == '__main__':
    try:
        if len(sys.argv) == 6 and sys.argv[1] == 'extract':
            extract(*(Path(value).absolute() for value in sys.argv[2:]))
        elif len(sys.argv) == 5 and sys.argv[1] == 'products':
            validate_products(*(Path(value).absolute() for value in sys.argv[2:]))
        elif len(sys.argv) == 6 and sys.argv[1] == 'trace':
            validate_trace(*(Path(value).absolute() for value in sys.argv[2:]))
        else:
            raise ValueError('usage: reference extract ROOT STATIC DYNAMIC OUTPUT | trace TRACE WORKLOAD OBJECTS BUILTINS')
    except (OSError, ValueError, subprocess.CalledProcessError, products.ProductEvidenceError) as error:
        print(f'aarch64 math reference: {error}', file=sys.stderr)
        raise SystemExit(1)
