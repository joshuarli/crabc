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


IMAGE_ID = 'sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d'
IMAGE_COMMANDS = ('bash', 'cat', 'chmod', 'chroot', 'cmp', 'cp', 'dirname', 'env',
                  'grep', 'mkdir', 'mktemp', 'python3', 'readelf', 'realpath',
                  'timeout', 'uname', 'gcc', 'as', 'ld', 'rustup')
IMAGE_FIXED_PATHS = (
    '/usr/local/bin/crabc-x86_64-musl-gcc', '/opt/musl-1.2.6/lib/libc.so',
    '/opt/musl-1.2.6/lib/libc.a',
    '/opt/musl-1.2.6/lib/musl-gcc.specs',
    '/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/bin/rustc',
    '/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld',
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
    """Join ordinary static extraction to the final syscall/probe definitions.

    LLD's map must name an actually traced input member, and each finite
    function keeps its source section, size and fully relocated bytes. The
    finite x86-64 relocations below derive their values from selected input
    definitions and ELF placement; no output instruction field is a mask.
    """
    images = {name: elf_bytes(value) if isinstance(value, bytes) else Elf(value)
              for name, value in admitted.items()}
    final = Elf(executable)
    wanted = set(aliases) | {'main', '_start'}
    mapped = {}
    contributions = {}
    map_symbols = {}
    owner = None
    contribution = None
    lines = physical(map_path).read_text().splitlines()
    require(lines and lines[0].split() == ['VMA', 'LMA', 'Size', 'Align', 'Out', 'In', 'Symbol'],
            'static link map header differs')
    for line in lines[1:]:
        match = re.fullmatch(r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+(.*)', line)
        require(match is not None, 'malformed static link map row')
        address, load, size, _alignment, name = match.groups()
        address, load, size = int(address, 16), int(load, 16), int(size, 16)
        if ':(' in name and name.endswith(')'):
            owner, section = name.rsplit(':(', 1)
            section = section[:-1]
            require(owner == '<internal>' or owner in images, 'static map names an untraced input')
            contribution = (address, size, section)
            key = (owner, section)
            require(key not in contributions, 'duplicate static input section contribution')
            contributions[key] = contribution
        elif name.startswith('.'):
            owner, contribution = None, None
        else:
            if owner in images and contribution is not None:
                map_symbols.setdefault(name, []).append((owner, contribution, address, size))
            if name in wanted:
                require(name not in mapped and owner in images and contribution is not None,
                        'static map duplicates or lacks a function input')
                require(address == load, 'static function load address differs')
                mapped[name] = (owner, contribution, address, size)
    require(set(mapped) == wanted, 'static link map omits a syscall or probe function')
    def selected_symbols(elf, names):
        # Look up the finite names first; Elf.symbol_row then checks their full
        # records and versions. This avoids rescanning every large archive
        # symbol table once per alias during each receipt replay.
        found = {}
        for index, table in enumerate(elf.sections):
            if table[1] != 2:
                continue
            require(table[9] == 24 and table[5] % 24 == 0, 'invalid static symbol table')
            strings = elf.sections[table[6]]
            require(strings[1] == 3 and strings[4] + strings[5] <= len(elf.data), 'invalid static symbol strings')
            for number in range(table[5] // 24):
                offset = elf.unpack('<I', table[4] + number * 24)[0]
                require(offset < strings[5], 'invalid static symbol name offset')
                start = strings[4] + offset
                end = elf.data.find(b'\0', start, strings[4] + strings[5])
                require(end >= 0, 'unterminated static symbol name')
                name = elf.data[start:end].decode()
                if name not in names:
                    continue
                row = elf.symbol_row(index, number)
                if row['section']:
                    require(name not in found, 'duplicate mapped static function')
                    found[name] = row
        return found

    source_symbols = {owner: selected_symbols(images[owner], wanted) for owner in {row[0] for row in mapped.values()}}
    function_relocations = {}
    targets = set(wanted)
    for name, (owner, _contribution, _address, _size) in mapped.items():
        source = images[owner]
        require(name in source_symbols[owner], 'mapped static function lacks a selected definition')
        before = source_symbols[owner][name]
        rows = []
        for relocations in source.sections:
            if relocations[1] != 4 or relocations[7] != before['section']:
                continue
            require(relocations[9] == 24 and relocations[5] % 24 == 0, 'malformed static input relocations')
            for offset in range(0, relocations[5], 24):
                position, info, addend = source.unpack('<QQq', relocations[4] + offset)
                if before['value'] <= position < before['value'] + before['size']:
                    symbol = source.symbol_row(relocations[6], info >> 32)
                    rows.append((position - before['value'], info & 0xffffffff, addend, symbol))
                    if symbol['name']:
                        targets.add(symbol['name'])
        function_relocations[name] = rows
    final_symbols = selected_symbols(final, targets)
    source_targets = {}

    def input_symbol(owner, name):
        if owner not in source_targets:
            source_targets[owner] = selected_symbols(images[owner], targets)
        require(name in source_targets[owner], 'static relocation target lacks its selected definition')
        return source_targets[owner][name]

    def placed_section(owner, index):
        source = images[owner]
        require(0 < index < len(source.sections), 'static relocation target has no input section')
        section = source.sections[index]
        key = (owner, section_name(source, section))
        require(key in contributions, 'static relocation target has no selected section placement')
        base, extent, _name = contributions[key]
        require(extent == section[5] and section[8] > 0 and base % section[8] == 0,
                'static input section placement size/alignment differs')
        return base

    def target_address(owner, symbol):
        # Defined local/hidden symbols resolve in their selected object. An
        # undefined or interposable C name must join the final symbol and its
        # traced map owner to a real selected definition.
        resolved_map = None
        if symbol['binding'] != 'LOCAL' and symbol['visibility'] == 'DEFAULT':
            rows = map_symbols.get(symbol['name'], [])
            require(len(rows) == 1, 'static relocation target has no unique selected definition')
            resolved_map = rows[0]
            owner, _part, _address, extent = resolved_map
            symbol = input_symbol(owner, symbol['name'])
            require(symbol['size'] == extent, 'static relocation target map size differs')
        source = images[owner]
        require(0 < symbol['section'] < len(source.sections), 'unresolved static relocation target')
        section = source.sections[symbol['section']]
        if section[2] & 0x10:  # SHF_MERGE: constant pieces need not keep input order.
            require(section[1] == 1 and not section[2] & 0x21 and section[9] > 0
                    and symbol['binding'] == 'LOCAL' and symbol['type'] == 'OBJECT'
                    and symbol['size'] == section[9] and symbol['value'] % section[9] == 0
                    and symbol['value'] + symbol['size'] <= section[5],
                    'unclassified merged static relocation target')
            key = ('<internal>', section_name(source, section))
            require(key in contributions, 'merged static target lacks its constant pool')
            base, extent, _name = contributions[key]
            outputs = [s for s in final.sections if section_name(final, s) == '.rodata']
            require(len(outputs) == 1, 'merged static target lacks read-only output')
            output = outputs[0]
            require(output[1] == 1 and output[2] & 3 == 2 and base % section[9] == 0
                    and extent % section[9] == 0 and output[3] <= base
                    and base + extent <= output[3] + output[5], 'merged static constant pool placement differs')
            offset = output[4] + base - output[3]
            start = section[4] + symbol['value']
            constant = source.data[start:start + symbol['size']]
            matches = [base + i for i in range(0, extent, section[9])
                       if final.data[offset + i:offset + i + symbol['size']] == constant]
            require(len(matches) == 1, 'merged static target lacks its unique selected constant')
            return matches[0]
        address = placed_section(owner, symbol['section']) + symbol['value']
        require(symbol['value'] + symbol['size'] <= section[5], 'static target exceeds selected section')
        if resolved_map is not None:
            require(resolved_map[2] == address and resolved_map[1][2] == section_name(source, section),
                    'static relocation target map definition placement differs')
        if symbol['name']:
            require(symbol['name'] in final_symbols, 'static target lacks final ELF symbol')
            after = final_symbols[symbol['name']]
            require(after['type'] == symbol['type'] and after['size'] == symbol['size'],
                    'static relocation target type/size differs')
            if symbol['type'] == '6':  # STT_TLS values are relative to PT_TLS.
                require(after['value'] == address - tls[3], 'static TLS symbol placement differs')
            else:
                require(after['value'] == address, 'static relocation target symbol placement differs')
        return address

    # The selected TLS contributions determine the segment geometry, including
    # zero-fill and alignment. This prevents a resealed PT_TLS from changing the
    # thread-pointer displacement without changing the selected input layout.
    tls_rows = [program for program in final.programs if program[0] == 7]
    require(len(tls_rows) == 1, 'static syscall output lacks a unique TLS segment')
    tls = tls_rows[0]
    tls_sections = [section for section in final.sections if section[2] & 0x400]
    require(tls_sections and tls[7] > 0 and tls[7] & (tls[7] - 1) == 0
            and tls[3] % tls[7] == 0, 'unclassified static TLS alignment')
    tls_inputs = []
    for owner, source in images.items():
        for index, section in enumerate(source.sections):
            key = (owner, section_name(source, section))
            if section[2] & 0x400 and key in contributions:
                base, extent, _name = contributions[key]
                require(placed_section(owner, index) == base, 'static TLS placement differs')
                tls_inputs.append((base, extent, section))
    require(tls_inputs and max(s[8] for _b, _e, s in tls_inputs) == tls[7], 'static TLS input alignment differs')
    cursor = tls[3]
    file_end = cursor
    for base, extent, section in sorted(tls_inputs):
        cursor = (cursor + section[8] - 1) // section[8] * section[8]
        require(base == cursor, 'static TLS selected input order/padding differs')
        cursor += extent
        if section[1] != 8:
            file_end = cursor
    require(cursor - tls[3] == tls[6] and file_end - tls[3] == tls[5]
            and min(s[3] for s in tls_sections) == tls[3]
            and max(s[3] + s[5] for s in tls_sections) == cursor, 'static TLS segment geometry differs')
    tls_size = (tls[6] + tls[7] - 1) // tls[7] * tls[7]

    def got_addresses(target):
        sections = [section for section in final.sections if section_name(final, section) == '.got']
        require(len(sections) == 1, 'static output lacks a unique GOT')
        section = sections[0]
        require(section[5] % 8 == 0 and section[3] % 8 == 0, 'invalid static GOT geometry')
        relative = {}
        for relocations in final.sections:
            if relocations[1] != 4 or not relocations[2] & 2:
                continue
            require(relocations[9] == 24 and relocations[5] % 24 == 0, 'invalid static dynamic relocations')
            for offset in range(0, relocations[5], 24):
                address, info, addend = final.unpack('<QQq', relocations[4] + offset)
                if section[3] <= address < section[3] + section[5]:
                    require(info == 8 and address not in relative and address % 8 == 0,
                            'static GOT slot lacks a unique RELATIVE relocation')
                    relative[address] = addend
        matches = []
        for offset in range(0, section[5], 8):
            address = section[3] + offset
            value = final.unpack('<Q', section[4] + offset)[0]
            if final.elf_type == 3:
                require(value == 0, 'static PIE GOT has an unexpected in-place addend')
                value = relative.get(address)
            else:
                require(not relative, 'static executable GOT unexpectedly needs relocation')
            if value == target:
                matches.append(address)
        # Distinct source symbol aliases can produce multiple GOT entries for
        # one resolved address. Each admitted slot must independently contain
        # that exact target (or its static-PIE RELATIVE addend).
        require(matches, 'static target lacks a correctly initialized GOT slot')
        return matches
    for name, (owner, contribution, address, size) in mapped.items():
        expected_owner = probe_path if name == 'main' or override and name in aliases else crt_path if name == '_start' else None
        require(owner == expected_owner if expected_owner else owner.startswith(archive_path + '('),
                'static function came from the wrong selected object/archive')
        source = images[owner]
        require(name in source_symbols[owner] and name in final_symbols, 'mapped static function lacks ELF definition')
        before = source_symbols[owner][name]
        after = final_symbols[name]
        expected_binding = 'WEAK' if name in aliases and not override else 'GLOBAL'
        require(before['type'] == after['type'] == 'FUNC' and before['binding'] == after['binding'] == expected_binding
                and before['visibility'] == after['visibility'] == 'DEFAULT'
                and 0 < before['section'] < len(source.sections) and 0 < after['section'] < len(final.sections),
                'static function definition/binding differs')
        base, extent, section = contribution
        source_section = source.sections[before['section']]
        require(section == section_name(source, source_section)
                and address == base + before['value'] and size == before['size'] == after['size']
                and size > 0 and address == after['value'] and before['value'] + size <= extent,
                'static map/source/final function location differs')
        source_offset = source_section[4] + before['value']
        output_section = final.sections[after['section']]
        output_offset = output_section[4] + after['value'] - output_section[3]
        original = bytearray(source.data[source_offset:source_offset + size])
        linked = bytearray(final.data[output_offset:output_offset + size])
        require(len(original) == len(linked) == size, 'truncated mapped static function')
        for position, kind, addend, symbol in function_relocations[name]:
            require(kind in (2, 4, 9, 22, 42), f'unclassified mapped static relocation {kind} in {name}')
            require(position + 4 <= size, 'static relocation crosses a function boundary')
            target = target_address(owner, symbol)
            value = target + addend - (address + position)
            if kind == 9:
                values = [slot + addend - (address + position) for slot in got_addresses(target)]
                matches = [v for v in values if -(1 << 31) <= v < 1 << 31
                           and v.to_bytes(4, 'little', signed=True) == linked[position:position + 4]]
                require(len(matches) == 1, 'static GOT displacement does not address the selected target')
                value = matches[0]
            elif kind in (22, 42):
                require(position >= 3 and addend == -4, 'unclassified static relaxation addend/instruction')
                rex, opcode, modrm = original[position - 3:position]
                require(rex in (0x48, 0x4c) and opcode == 0x8b and modrm & 0xc7 == 5,
                        'unclassified static relaxed load')
                if kind == 22:
                    require(symbol['type'] == '6', 'GOTTPOFF target is not selected TLS')
                    value = target - tls[3] - tls_size
                    original[position - 3:position] = bytes([0x48 | ((rex >> 2) & 1), 0xc7,
                                                           0xc0 | ((modrm >> 3) & 7)])
                else:
                    require(symbol['binding'] == 'LOCAL' and symbol['type'] == 'FUNC',
                            'unclassified static GOTPCRELX target')
                    original[position - 2] = 0x8d
            require(-(1 << 31) <= value < 1 << 31, 'static relocation overflows signed displacement')
            original[position:position + 4] = value.to_bytes(4, 'little', signed=True)
        require(original == linked, f'linked static function bytes differ from selected input: {name}')
