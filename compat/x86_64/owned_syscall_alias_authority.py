"""Byte authorities for the finite syscall receipt, independent of its JSON seals.

Git objects bind both source epochs and file modes. ELF objects bind readelf
observations. This module never runs a command while validating retained data.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import stat
import subprocess
import tomllib
import zlib

from loader_debug_abi_evidence import Elf


class AuthorityError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuthorityError(message)


def physical(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'unsafe authority path')
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'authority traverses a symlink')
    require(path.is_file(), 'authority is not a regular file')
    return path


def capture_git_objects(root, output, revisions):
    """Retain only the two commit trees, with deduplicated loose Git objects."""
    objects = set(revisions)
    for revision in revisions:
        tree = subprocess.check_output(['git', 'rev-parse', revision + '^{tree}'], cwd=root).strip().decode()
        objects.add(tree)
        rows = subprocess.check_output(['git', 'ls-tree', '-r', '-t', '-z', revision], cwd=root)
        objects.update(row.split(b'\t', 1)[0].split()[2].decode() for row in rows.split(b'\0') if row)
    payload = subprocess.check_output(['git', 'cat-file', '--batch'], cwd=root,
                                      input=('\n'.join(sorted(objects)) + '\n').encode())
    target = output / 'source/git-objects'
    target.mkdir(parents=True)
    cursor = 0
    for oid in sorted(objects):
        end = payload.index(b'\n', cursor)
        actual, kind, size = payload[cursor:end].split()
        require(actual.decode() == oid, 'Git capture object order differs')
        start = end + 1
        raw = kind + b' ' + size + b'\0' + payload[start:start + int(size)]
        require(hashlib.sha1(raw).hexdigest() == oid, 'Git capture object digest differs')
        (target / oid).write_bytes(zlib.compress(raw))
        cursor = start + int(size) + 1
    require(cursor == len(payload), 'Git capture has trailing output')


def source_tree(output, revision):
    """Derive the product owner's source digest from authenticated Git bytes."""
    def obj(oid, expected):
        require(re.fullmatch('[0-9a-f]{40}', oid) is not None, 'invalid Git object name')
        raw = zlib.decompress(physical(output / 'source/git-objects' / oid).read_bytes())
        require(hashlib.sha1(raw).hexdigest() == oid, 'retained Git object digest differs')
        header, data = raw.split(b'\0', 1)
        require(header == expected + b' ' + str(len(data)).encode(), 'retained Git object type/size differs')
        return data

    commit = obj(revision, b'commit')
    tree_line = commit.split(b'\n', 1)[0]
    require(tree_line.startswith(b'tree '), 'retained commit lacks its tree')
    files = {}

    def walk(tree, prefix):
        data = obj(tree, b'tree')
        cursor = 0
        names = set()
        while cursor < len(data):
            end = data.index(b'\0', cursor)
            mode, name = data[cursor:end].split(b' ', 1)
            require(name not in names and name not in (b'', b'.', b'..') and b'/' not in name,
                    'invalid Git tree member')
            names.add(name)
            oid = data[end + 1:end + 21].hex()
            cursor = end + 21
            path = prefix + name
            if mode == b'40000':
                walk(oid, path + b'/')
            else:
                require(mode in (b'100644', b'100755', b'120000'), 'unsupported Git source node')
                permissions = {b'100644': 0o644, b'100755': 0o755, b'120000': 0o777}[mode]
                files[path.decode()] = (permissions, obj(oid, b'blob'), mode == b'120000')
        require(cursor == len(data), 'truncated Git tree')

    walk(tree_line[5:].decode(), b'')
    content = hashlib.sha256()
    for name, (mode, data, _symlink) in sorted(files.items()):
        content.update(name.encode() + b'\0' + str(mode).encode() + b'\0')
        content.update(hashlib.sha256(data).digest())
    return {'revision': revision, 'content_sha256': content.hexdigest()}, files


def archive_members(data):
    """Decode the ordinary GNU ar format produced by the pinned product tools."""
    require(data.startswith(b'!<arch>\n'), 'expected ordinary archive bytes')
    cursor, names = 8, b''
    while cursor < len(data):
        header = data[cursor:cursor + 60]
        require(len(header) == 60 and header[58:] == b'`\n', 'malformed archive member')
        name = header[:16].rstrip()
        size = int(header[48:58])
        start = cursor + 60
        body = data[start:start + size]
        require(len(body) == size, 'truncated archive member')
        cursor = start + size + size % 2
        if name == b'//':
            names = body
        elif name not in (b'/', b'/SYM64/'):
            if name.startswith(b'/'):
                offset = int(name[1:])
                end = names.find(b'/\n', offset)
                require(0 <= offset < len(names) and end >= 0, 'invalid archive long name')
                name = names[offset:end]
            else:
                require(name.endswith(b'/'), 'unsupported archive name')
                name = name[:-1]
            yield name.decode(), body
    require(cursor == len(data), 'archive trailing bytes differ')


def elf_bytes(data):
    """Initialize the existing ELF reader on a retained archive member's bytes."""
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'expected ELF64 little endian')
    elf = Elf.__new__(Elf)
    elf.data = data
    require(elf.unpack('<H', 18)[0] == 62, 'expected native x86-64 ELF')
    elf.elf_type = elf.unpack('<H', 16)[0]
    offset = elf.unpack('<Q', 40)[0]
    size, count = elf.unpack('<HH', 58)
    require(size == 64 and count > 0, 'missing ELF section table')
    elf.sections = [elf.unpack('<IIQQQQIIQQ', offset + index * size) for index in range(count)]
    return elf


def section_name(elf, section):
    strings = elf.sections[elf.unpack('<H', 62)[0]]
    start = strings[4] + section[0]
    end = elf.data.find(b'\0', start, strings[4] + strings[5])
    require(strings[4] <= start <= end < len(elf.data), 'invalid ELF section name')
    return elf.data[start:end].decode()


def require_symbol_stream(path, artifact, logical_path, tables):
    """Compare every readelf symbol row, including its member/table/index, to ELF."""
    data = physical(artifact).read_bytes()
    members = [(f'{logical_path}({name})', elf_bytes(body)) for name, body in archive_members(data)] if data.startswith(b'!<arch>') else [('', elf_bytes(data))]
    expected = []
    expected_headers = []
    for member, elf in members:
        for index, section in enumerate(elf.sections):
            table = section_name(elf, section)
            if section[1] not in (2, 11) or table not in tables:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, 'invalid ELF symbol table')
            expected_headers.append((member, f"Symbol table '{table}' contains {section[5] // 24} {'entry' if section[5] == 24 else 'entries'}:"))
            for number in range(section[5] // 24):
                row = elf.symbol_row(index, number)
                kind = {'0': 'NOTYPE', '3': 'SECTION', '4': 'FILE', '5': 'COMMON', '6': 'TLS', '10': 'IFUNC'}.get(row['type'], row['type'])
                name = row['name']
                if kind == 'SECTION' and not name:
                    name = section_name(elf, elf.sections[row['section']])
                owner = {0: 'UND', 0xfff1: 'ABS', 0xfff2: 'COM'}.get(row['section'], str(row['section']))
                expected.append((member, table, number, row['value'], row['size'], kind,
                                 row['binding'], row['visibility'], owner, name))
    actual = []
    actual_headers = []
    member, table = '', ''
    for line in physical(path).read_text().splitlines():
        if line.startswith('File: '):
            member = line[6:]
            table = ''
        elif line.startswith("Symbol table '"):
            table = line.split("'", 2)[1]
            actual_headers.append((member, line))
        elif re.match(r'\s*\d+:', line):
            require('@' not in line, 'unexpected versioned syscall symbol')
            fields = line.split(maxsplit=7)
            require(len(fields) >= 7 and table in tables, 'unexpected raw symbol row')
            name = fields[7].split('@', 1)[0] if len(fields) == 8 else ''
            actual.append((member, table, int(fields[0][:-1]), int(fields[1], 16), int(fields[2], 0) if fields[2].startswith('0x') else int(fields[2]), *fields[3:7], name))
        else:
            require(not line.strip() or line.lstrip().startswith('Num:'), 'unexpected raw symbol text')
    require(actual_headers == expected_headers, 'raw symbol table header differs from ELF')
    require(actual == expected, f'raw symbols do not describe retained ELF: {path.name}')


RELOCATION_NAMES = {1: 'R_X86_64_64', 2: 'R_X86_64_PC32', 4: 'R_X86_64_PLT32',
                    5: 'R_X86_64_COPY', 6: 'R_X86_64_GLOB_DAT', 7: 'R_X86_64_JUMP_SLOT',
                    8: 'R_X86_64_RELATIVE', 16: 'R_X86_64_DTPMOD64', 17: 'R_X86_64_DTPOFF64',
                    18: 'R_X86_64_TPOFF64', 37: 'R_X86_64_IRELATIVE'}


def require_relocation_stream(path, artifact):
    elf = Elf(physical(artifact))
    expected = []
    expected_headers = []
    for section in elf.sections:
        if section[1] != 4:
            continue
        require(section[9] == 24 and section[5] % 24 == 0, 'invalid ELF RELA table')
        expected_headers.append(f"Relocation section '{section_name(elf, section)}' at offset 0x{section[4]:x} contains {section[5] // 24} {'entry' if section[5] == 24 else 'entries'}:")
        for offset in range(0, section[5], 24):
            destination, info, addend = elf.unpack('<QQq', section[4] + offset)
            symbol = elf.symbol_row(section[6], info >> 32)
            require(info & 0xffffffff in RELOCATION_NAMES, 'unclassified syscall ELF relocation')
            expected.append((destination, info, RELOCATION_NAMES[info & 0xffffffff], symbol['value'], symbol['name'], addend))
    actual = []
    actual_headers = []
    for line in physical(path).read_text().splitlines():
        if line.startswith('Relocation section '):
            actual_headers.append(line)
        match = re.fullmatch(r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(R_X86_64_\w+)\s*(.*)', line)
        if match:
            destination, info, kind, tail = match.groups()
            fields = tail.split()
            if len(fields) == 1:
                value, name, addend = 0, '', int(fields[0], 16)
            else:
                require(len(fields) == 4 and fields[2] in ('+', '-'), 'malformed raw relocation target')
                value, name = int(fields[0], 16), fields[1].split('@', 1)[0]
                addend = int(fields[3], 16) * (1 if fields[2] == '+' else -1)
            actual.append((int(destination, 16), int(info, 16), kind, value, name, addend))
        else:
            require(not line.strip() or line.startswith('Relocation section ') or line.lstrip().startswith('Offset')
                    or line == 'There are no relocations in this file.', 'unexpected raw relocation text')
    require(actual_headers == expected_headers, 'raw relocation table header differs from ELF')
    require(actual == expected, f'raw relocations do not describe retained ELF: {path.name}')


IMAGE_ID = 'sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d'
IMAGE_COMMANDS = ('bash', 'cat', 'chmod', 'chroot', 'cmp', 'cp', 'dirname', 'env',
                  'grep', 'mkdir', 'mktemp', 'python3', 'readelf', 'realpath',
                  'timeout', 'uname', 'gcc', 'as', 'ld', 'rustup')
_IMAGE_FIXED_PREFIXES = (
    '/usr/local/bin/crabc-x86_64-musl-gcc', '/opt/musl-1.2.6/lib/libc.so',
    '/opt/musl-1.2.6/lib/libc.a',
    '/opt/musl-1.2.6/lib/musl-gcc.specs',
)
_TOOLCHAIN = tomllib.loads((Path(__file__).resolve().parents[2] / 'rust-toolchain.toml').read_text())['toolchain']['channel']
IMAGE_FIXED_PATHS = (
    *_IMAGE_FIXED_PREFIXES,
    f'/opt/rustup/toolchains/{_TOOLCHAIN}-x86_64-unknown-linux-musl/bin/rustc',
    f'/opt/rustup/toolchains/{_TOOLCHAIN}-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld',
)
IMAGE_PATH = '/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def image_input_manifest():
    """Regenerate inside IMAGE_ID; the committed result is replay's image anchor."""
    import shutil
    paths = [shutil.which(name, path=IMAGE_PATH) for name in IMAGE_COMMANDS]
    require(all(paths), 'pinned image lacks a required command')
    paths += list(IMAGE_FIXED_PATHS)
    for name in ('cc1', 'collect2', 'liblto_plugin.so'):
        paths.append(subprocess.check_output(['/usr/bin/gcc', '-print-prog-name=' + name], text=True).strip())
    records = {}
    for invocation in sorted(set(paths)):
        path = Path(invocation).resolve(strict=True)
        records[invocation] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                               'size': path.stat().st_size, 'mode': stat.S_IMODE(path.stat().st_mode)}
    return {'image': IMAGE_ID, 'path': IMAGE_PATH, 'files': records}


if __name__ == '__main__':
    import json
    print(json.dumps(image_input_manifest(), indent=2, sort_keys=True))


def require_static_function_map(map_path, executable, admitted, probe_path, crt_path, archive_path, aliases, override):
    """Supply the syscall component's unchanged owner/binding policy explicitly."""
    from owned_static_link_authority import (
        StaticFunctionContract, StaticLinkAuthorityError, require_static_functions,
    )
    archive_owners = {}
    if not override:
        # Select exact defining members from admitted selected-libc bytes, not
        # from a map claim. The shared reader accepts only these exact owners.
        wanted = set(aliases)
        for owner, value in admitted.items():
            if not owner.startswith(archive_path + '('):
                continue
            source = elf_bytes(value) if isinstance(value, bytes) else Elf(value)
            for index, table in enumerate(source.sections):
                if table[1] != 2:
                    continue
                require(table[9] == 24 and table[5] % 24 == 0, 'invalid syscall input symbol table')
                strings = source.sections[table[6]]
                require(strings[1] == 3 and strings[4] + strings[5] <= len(source.data),
                        'invalid syscall input symbol strings')
                for number in range(table[5] // 24):
                    offset = source.unpack('<I', table[4] + number * 24)[0]
                    require(offset < strings[5], 'invalid syscall input symbol name offset')
                    start = strings[4] + offset
                    end = source.data.find(b'\0', start, strings[4] + strings[5])
                    require(end >= 0, 'unterminated syscall input symbol name')
                    name = source.data[start:end].decode()
                    if name in wanted and source.symbol_row(index, number)['section']:
                        require(name not in archive_owners, 'duplicate selected syscall archive definition')
                        archive_owners[name] = owner
        require(set(archive_owners) == wanted, 'selected archive omits a syscall definition')
    contracts = [
        StaticFunctionContract('main', probe_path, 'GLOBAL', 'DEFAULT', 'GLOBAL', 'DEFAULT'),
        StaticFunctionContract('_start', crt_path, 'GLOBAL', 'DEFAULT', 'GLOBAL', 'DEFAULT'),
    ]
    for name in aliases:
        owner = probe_path if override else archive_owners[name]
        binding = 'GLOBAL' if override else 'WEAK'
        contracts.append(StaticFunctionContract(name, owner, binding, 'DEFAULT', binding, 'DEFAULT'))
    try:
        require_static_functions(map_path, executable, admitted, contracts)
    except StaticLinkAuthorityError as error:
        raise AuthorityError(str(error)) from error
