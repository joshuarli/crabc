#!/usr/bin/env python3
"""Retain complete owned address links and replay physical archive references.

The fixture only takes addresses. Runtime semantics remain the owning family's
obligation. Every admitted operand retains its complete source relocation
roster and final targets in both static modes. Symbol-only imports require an
exact source symbol and complete absence of relocation operands; unsupported
forms stay open.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping

MODULE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import native_c_allocator_boundary as calls
import owned_posix_product_evidence as products
import native_declaration_abi as declaration
import owned_static_link_authority as static_authority

ROOT = inventory.ROOT
MODES = ('static', 'static-pie')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def identity(path: Path) -> dict[str, Any]:
    path = inventory.physical_regular(path.absolute(), str(path))
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size': path.stat().st_size}


def roster(facts: Mapping[str, Any]) -> list[str]:
    return sorted({row['name'] for member in facts['candidate-static']
                   for table in member['symbol_tables'] for row in table['rows']
                   if row['section_index'] != 'UND' and row['type'] in {'FUNC', 'OBJECT'}
                   and row['binding'] in {'GLOBAL', 'WEAK'} and row['size_bytes'] > 0})


def object_roster(facts: Mapping[str, Any]) -> list[str]:
    return sorted({row['name'] for member in facts['candidate-static']
                   for table in member['symbol_tables'] for row in table['rows']
                   if row['section_index'] != 'UND' and row['type'] == 'OBJECT'
                   and row['binding'] in {'GLOBAL', 'WEAK'} and row['size_bytes'] > 0})


def source(names: list[str], *, object_names: list[str] | None = None) -> str:
    require(names and names == sorted(set(names)), 'provider address roster differs')
    objects = set(object_names or [])
    require(objects <= set(names), 'provider object roster leaves the address roster')
    require(all(name and all(character.isalnum() or character in '_.$' for character in name)
                for name in names), 'provider name cannot be emitted as a linker label')
    return (''.join((f'extern unsigned char provider_{index}[] __asm__("{name}");\n' if name in objects
                     else f'extern void provider_{index}(void) __asm__("{name}");\n')
                    for index, name in enumerate(names))
            + 'static const void *volatile providers[] = {\n'
            + ''.join(f'(const void *)provider_{index},\n' for index in range(len(names)))
            + '};\nint main(void) {\n'
            + ' for (unsigned long i = 0; i < sizeof providers / sizeof providers[0]; ++i)\n'
            + '  if (!providers[i]) return 1;\n return 0;\n}\n')


def command(static: Path, work: Path, label: str) -> list[str]:
    if label == 'compile':
        return [str(static / 'bin/crabc-cc'), '-static-pie', '-std=c11', '-fno-builtin',
                '-fno-stack-protector', '-c', str(work / 'providers.c'), '-o', str(work / 'providers.o')]
    if label in MODES:
        return [str(static / 'bin/crabc-cc'), '-' + label, '--link-receipt',
                label + '.receipt.json',
                str(work / 'providers.o'), '-o', str(work / label)]
    return [str(work / label.removesuffix('-run'))]


def capture(argv: list[str], work: Path, label: str) -> dict[str, Any]:
    result = subprocess.run(argv, cwd=work, capture_output=True, check=False, timeout=120)
    for suffix, content in (('stdout', result.stdout), ('stderr', result.stderr),
                            ('status', f'{result.returncode}\n'.encode())):
        (work / (label + '.' + suffix)).write_bytes(content)
    require(result.returncode == 0, f'provider {label} failed: {result.stderr.decode(errors="replace")}')
    return {'argv': argv, 'streams': {suffix: identity(work / (label + '.' + suffix))
                                    for suffix in ('stdout', 'stderr', 'status')}}


def fixture_object(path: Path, names: list[str]) -> dict[str, Any]:
    """Require every forced pointer to name its exact undefined symbol row."""
    tables = inventory.parse_elf_symbol_tables(read_tool('readelf', '-Ws', path))
    require(len(tables) == 1 and tables[0]['name'] == '.symtab', 'provider fixture symbol tables differ')
    rows = tables[0]['rows']
    holders = [row for row in rows if row['name'] == 'providers']
    require(len(holders) == 1 and holders[0]['type'] == 'OBJECT'
            and holders[0]['binding'] == 'LOCAL' and holders[0]['visibility'] == 'DEFAULT'
            and holders[0]['size_bytes'] == 8 * len(names), 'provider forcing table metadata differs')
    holder = holders[0]
    sections = inventory.parse_elf_sections(read_tool('readelf', '-SW', path))['sections']
    selected = [row for row in sections if str(row['index']) == holder['section_index']]
    require(len(selected) == 1 and selected[0]['type'] == 'PROGBITS', 'provider forcing table section differs')
    relocations = declaration.parse_relocations(read_tool('readelf', '-rW', path))
    references = [row for row in relocations if row['section'] == '.rela' + selected[0]['name']]
    require(len(references) == len(names), 'provider forcing reference roster differs')
    for index, (name, relocation) in enumerate(zip(names, references, strict=True)):
        imported = [row for row in rows if row['name'] == name]
        require(len(imported) == 1 and imported[0]['section_index'] == 'UND'
                and imported[0]['binding'] == 'GLOBAL' and imported[0]['visibility'] == 'DEFAULT'
                and relocation['symbol'] == name and relocation['symbol_index'] == imported[0]['row_index']
                and relocation['type'] == 'R_X86_64_64' and relocation['addend'] == 0
                and relocation['offset'] == int(holder['value'], 16) + 8 * index,
                'provider forcing reference names a different symbol or address')
    return {'holder': holder, 'section': selected[0], 'references': references}


def collect(static: Path, elf_report: Path, output: Path) -> dict[str, Any]:
    static = inventory.physical_directory(static.absolute(), 'provider static product')
    output = output.absolute()
    require(output.is_relative_to(ROOT / '.work') and not output.exists()
            and output.parent.resolve() == output.parent, 'provider output must be a fresh physical .work child')
    before = inventory.collector_source_seal()
    require(before['clean'] is True, 'provider links require committed source')
    facts = inventory.read_json(elf_report, 'provider ELF facts')['facts']
    names = roster(facts)
    output.mkdir(mode=0o700)
    (output / 'providers.c').write_text(source(names, object_names=object_roster(facts)), encoding='ascii')
    commands = {'compile': capture(command(static, output, 'compile'), output, 'compile')}
    object_references = fixture_object(output / 'providers.o', names)
    links = {}
    for mode in MODES:
        commands[mode] = capture(command(static, output, mode), output, mode)
        links[mode] = products.validate_link(static, output / 'providers.o', output / mode,
                                            output / (mode + '.receipt.json'), mode)
        links[mode]['product'] = calls.mounted_path(static)
        linked = inventory.read_json(output / (mode + '.receipt.json'), 'provider link receipt')['resolved_linker']
        if mode == MODES[0]:
            linker = linked
            require(identity(Path(linker['path']))['sha256'] == linker['sha256'], 'provider linker changed')
            shutil.copyfile(linker['path'], output / 'linker')
        require(linked == linker and identity(Path(linker['path'])) == identity(output / 'linker'),
                'provider linker changed across links')
        commands[mode + '-run'] = capture(command(static, output, mode + '-run'), output, mode + '-run')
    require(before == inventory.collector_source_seal(), 'provider source changed during collection')
    report = {'source': before, 'static_manifest': identity(static / 'share/crabc/manifest.json'),
              'archive': identity(static / 'usr/lib/libc.a'), 'driver': identity(static / 'bin/crabc-cc'),
              'fixture': identity(output / 'providers.c'), 'object': identity(output / 'providers.o'),
              'commands': commands, 'links': links, 'object_references': object_references, 'linker': linker}
    (output / 'report.json').write_bytes(inventory._stable_json(report))
    output.chmod(0o755)
    for path in output.iterdir():
        path.chmod(path.stat().st_mode | 0o444)
    return report


def validate(work: Path, static: Path, facts: Mapping[str, Any]) -> dict[str, Any]:
    work = inventory.physical_directory(work.absolute(), 'provider retained work')
    static = inventory.physical_directory(static.absolute(), 'provider static product')
    report = inventory.read_json(work / 'report.json', 'provider links')
    require(set(report) == {'source', 'static_manifest', 'archive', 'driver', 'fixture', 'object', 'commands', 'links', 'object_references', 'linker'},
            'provider link report fields differ')
    require(report['source'] == inventory.collector_source_seal() and report['source']['clean'] is True,
            'provider links belong to another source')
    for field, path in (('static_manifest', static / 'share/crabc/manifest.json'),
                        ('archive', static / 'usr/lib/libc.a'), ('driver', static / 'bin/crabc-cc'),
                        ('fixture', work / 'providers.c'), ('object', work / 'providers.o')):
        require(report[field] == identity(path), f'provider {field} changed')
    require((work / 'providers.c').read_text(encoding='ascii') == source(roster(facts), object_names=object_roster(facts)),
            'provider fixture no longer represents the complete physical address roster')
    require(report['object_references'] == fixture_object(work / 'providers.o', roster(facts)),
            'provider forcing object references changed')
    labels = ('compile', *MODES, *(mode + '-run' for mode in MODES))
    require(set(report['commands']) == set(labels) and set(report['links']) == set(MODES),
            'provider command/link roster differs')
    require(set(report['linker']) == {'path', 'sha256'}
            and identity(work / 'linker')['sha256'] == report['linker']['sha256'], 'provider retained linker changed')
    for label in labels:
        retained = report['commands'][label]
        require(set(retained) == {'argv', 'streams'} and retained['argv'] == [calls.mounted_path(Path(arg)) if arg.startswith(str(ROOT) + '/') else arg
                                              for arg in command(static, work, label)]
                and retained['streams'] == {suffix: identity(work / (label + '.' + suffix))
                                           for suffix in ('stdout', 'stderr', 'status')}
                and (work / (label + '.status')).read_bytes() == b'0\n',
                f'provider {label} execution changed')
    for mode in MODES:
        link = products.validate_retained_link(ROOT, '/workspace', static, work / 'providers.o', work / mode,
                                      work / (mode + '.receipt.json'), mode, report['linker'])
        link['product'] = calls.mounted_path(static)
        require(report['links'][mode] == link, f'provider {mode} link changed')
    return report


def read_tool(tool: str, flag: str, path: Path) -> str:
    result = subprocess.run(['/usr/bin/' + tool, flag, str(path)], capture_output=True, text=True, check=False)
    require(result.returncode == 0, f'provider {tool} cannot read {path}')
    return result.stdout


def _indexed_view(work: Path, mode: str, elf_type: int) -> dict[str, Any]:
    """Index physical transcripts once for the complete archive workload."""
    view = {'image': (work / mode).read_bytes(), 'type': elf_type,
            'symbols': read_tool('readelf', '-Ws', work / mode),
            'relocations': read_tool('readelf', '-rW', work / mode),
            'map': (work / (mode + '.receipt.map')).read_text(),
            'trace': (work / (mode + '.receipt.trace')).read_text()}
    view['symbol_rows'] = {}
    for line in view['symbols'].splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].endswith(':'):
            view['symbol_rows'].setdefault(parts[-1], []).append(parts)
    view['map_rows'] = {}
    for line in view['map'].splitlines():
        if ':(' in line and line.rstrip().endswith(')'):
            suffix = line.split()[-1]
            view['map_rows'].setdefault(suffix, []).append(line)
    view['trace_counts'] = {}
    for line in view['trace'].splitlines():
        view['trace_counts'][line] = view['trace_counts'].get(line, 0) + 1
    view['relocation_rows'] = {}
    for line in view['relocations'].splitlines():
        address = re.match(r'^\s*([0-9a-f]+)\s+', line)
        if address:
            view['relocation_rows'].setdefault(int(address.group(1), 16), []).append(line)
    if (work / 'providers.o').is_file():
        view['forcing_image'] = (work / 'providers.o').read_bytes()
    return view


def _call_transcripts(view: Mapping[str, Any], member: str,
                      source_calls: list[dict[str, Any]]) -> tuple[str, str]:
    """Keep each physical call's full map domain and exact GOT relocation rows.

    The existing branch reader still checks source opcodes, virtual segment
    permissions, slot values, relocation type and provider targets. Indexing
    only avoids rescanning unrelated map and relocation lines for every call.
    """
    maps, relocations = {}, {}
    for call in source_calls:
        section = call['section']
        rows = view['map_rows'].get(member + ':(' + section + ')', [])
        maps[section] = rows
        if call['kind'] != 'R_X86_64_GOTPCREL' or len(rows) != 1:
            continue
        base = int(rows[0].split()[0], 16)
        address = base + call['offset'] - 2
        opcode = calls._public_weak_virtual_bytes(view['image'], address, 7, view['type'], executable=True)
        if opcode[:2] in (b'\xff\x15', b'\xff\x25'):
            slot = address + 6 + struct.unpack_from('<i', opcode, 2)[0]
        else:
            address -= 1
            opcode = calls._public_weak_virtual_bytes(view['image'], address, 7, view['type'], executable=True)
            slot = address + 7 + struct.unpack_from('<i', opcode, 3)[0]
        relocations[slot] = view['relocation_rows'].get(slot, [])
    return ('\n'.join(line for rows in maps.values() for line in rows),
            '\n'.join(line for rows in relocations.values() for line in rows))


def scalar_read_prefix(source: bytes, offset: int) -> bytes:
    """Recognize eight-byte RIP-relative scalar double reads, never stores.

    The optional REX.R bit only extends the XMM destination register. Other
    prefixes, opcodes, addressing modes and operand widths stay unsupported.
    """
    for size in (5, 4):
        prefix = source[offset - size:offset] if offset >= size else b''
        if size == 5 and prefix[:2] == b'\xf2\x44':
            operation = prefix[2:]
        elif size == 4 and prefix[:1] == b'\xf2':
            operation = prefix[1:]
        else:
            continue
        if (len(operation) == 3 and operation[0] == 0x0f
                and operation[1] in {0x10, 0x58, 0x59} and operation[2] & 0xc7 == 0x05):
            return prefix
    return b''


def locked_cmpxchg_prefix(source: bytes, offset: int) -> bytes:
    """Decode only a locked, 64-bit CMPXCHG with a RIP-relative operand."""
    prefix = source[offset - 5:offset] if offset >= 5 else b''
    if (len(prefix) == 5 and prefix[0] == 0xf0 and prefix[1] in {0x48, 0x4c}
            and prefix[2:4] == b'\x0f\xb1' and prefix[4] & 0xc7 == 0x05):
        return prefix
    return b''


def integer_memory_operand(source: bytes, offset: int, *,
                           instruction_span: tuple[int, int] | None = None) -> tuple[bytes, int, bytes, str] | None:
    """Decode the supported RIP-relative integer operand and trailing immediate."""
    legacy_prefixes = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3}
    if instruction_span is not None:
        start, end = instruction_span
        require(0 <= start < offset and offset + 4 <= end <= len(source),
                'integer operand instruction span differs')
        prefix = source[start:offset] if end == offset + 4 else b''
        operation = prefix[1:] if len(prefix) == 4 and prefix[0] == 0x44 else prefix
        if (len(operation) == 3 and operation[:2] == b'\x0f\xb6' and operation[2] & 0xc7 == 0x05):
            return prefix, 1, b'', 'integer-zero-extend-load'
        # Decode within the authenticated instruction, then require the entire
        # prefix and immediate. Bytes belonging to adjacent instructions cannot
        # change this operand's width or supply an ignored extra prefix.
        decoded = integer_memory_operand(source[start:end], offset - start)
        if decoded is not None:
            prefix, _, immediate, _ = decoded
            if offset - start == len(prefix) and end == offset + 4 + len(immediate):
                return decoded
        return None
    locked = locked_cmpxchg_prefix(source, offset)
    if locked and (offset == len(locked) or source[offset - len(locked) - 1] not in legacy_prefixes):
        return locked, 8, b'', 'locked-cmpxchg'
    prefix = source[offset - 3:offset] if offset >= 3 else b''
    if (prefix == b'\xf0\x81\x2d' and offset + 8 <= len(source)
            and (offset == 3 or source[offset - 4] not in legacy_prefixes)):
        return prefix, 4, source[offset + 4:offset + 8], 'locked-subtract'
    if (len(prefix) == 3 and prefix[0] in {0x48, 0x4c}
            and prefix[1] in {0x8b, 0x89} and prefix[2] & 0xc7 == 0x05
            and (offset == 3 or source[offset - 4] not in legacy_prefixes)):
        return prefix, 8, b'', 'integer-data-load' if prefix[1] == 0x8b else 'integer-data-store'
    prefix = source[offset - 2:offset] if offset >= 2 else b''
    if len(prefix) == 2 and prefix[0] in {0x8b, 0x89, 0x0b} and prefix[1] & 0xc7 == 0x05:
        # Operand-size and register-extension prefixes are not part of these
        # observed 32-bit forms; do not mistake a wider or narrower access.
        if offset >= 3 and (source[offset - 3] in legacy_prefixes or 0x40 <= source[offset - 3] <= 0x4f):
            return None
        operation = {0x8b: 'integer-data-load', 0x89: 'integer-data-store', 0x0b: 'integer-data-or'}[prefix[0]]
        return prefix, 4, b'', operation
    if prefix == b'\xc7\x05' and offset + 8 <= len(source):
        if offset >= 3 and (source[offset - 3] in legacy_prefixes or 0x40 <= source[offset - 3] <= 0x4f):
            return None
        return prefix, 4, source[offset + 4:offset + 8], 'integer-immediate-store'
    return None


def import_relocations(transcript: str, name: str, *, image: bytes,
                       disassembly: str | None = None) -> list[dict[str, Any]]:
    """Retain the complete executable relocation roster for a symbol import.

    A function reference may load its address without calling it at that site.
    Only the exact PC-relative instruction forms decoded below are accepted.
    Non-executable relocations remain outside this proof. Interior LEA addends
    require a separately authenticated object extent during final projection.
    Disassembly boundaries are checked against raw section bytes so a preceding
    instruction displacement cannot be mistaken for an operand-size prefix.
    """
    sections = calls._ordinary_relocation_sections(image)
    instruction_spans = {}
    if disassembly is not None:
        source_sections = calls._ordinary_source_sections(image, set(sections.values()))
        current = None
        for line in disassembly.splitlines():
            heading = re.match(r'^Disassembly of section (.+):$', line)
            if heading:
                current = heading.group(1) if heading.group(1) in source_sections else None
                continue
            decoded = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
            if current is None or decoded is None:
                continue
            start = int(decoded.group(1), 16)
            encoded = bytes.fromhex(decoded.group(2))
            end = start + len(encoded)
            require(end <= len(source_sections[current]) and source_sections[current][start:end] == encoded,
                    'provider source disassembly bytes differ')
            spans = instruction_spans.setdefault(current, {})
            require(start not in spans, 'provider source instruction start is ambiguous')
            spans[start] = end
    section, references = None, []
    for line in transcript.splitlines():
        header = re.match(r"^Relocation section '(\.rela\.text(?:\.[^']+)?)' at offset 0x([0-9a-f]+)", line)
        if header:
            section = sections.get(int(header.group(2), 16))
            require(section is not None and ('.rela' + section).startswith(header.group(1)),
                    'provider import relocation heading differs from ELF target')
            continue
        if line.startswith('Relocation section '):
            section = None
            continue
        row = re.match(r'^\s*([0-9a-f]{16})\s+\S+\s+(R_X86_64_\w+)\s+\S+\s+(\S+)\s+([+-])\s+([0-9a-f]+)\s*$', line)
        if row is None or row.group(3) != name:
            continue
        addend = int(row.group(5), 16) * (-1 if row.group(4) == '-' else 1)
        offset, kind = int(row.group(1), 16), row.group(2)
        source = calls._ordinary_source_sections(image, {section})[section] if section is not None else b''
        scalar = section is not None and kind == 'R_X86_64_PC32' and scalar_read_prefix(source, offset)
        prefix = source[offset - 3:offset] if offset >= 3 else b''
        address = (kind == 'R_X86_64_PC32' and len(prefix) == 3 and prefix[0] in {0x48, 0x4c}
                   and prefix[1] == 0x8d and prefix[2] & 0xc7 == 0x05)
        instruction_span = None
        if kind == 'R_X86_64_PC32' and disassembly is not None:
            containing = [(start, end) for start, end in instruction_spans.get(section, {}).items()
                          if start <= offset and offset + 4 <= end]
            require(len(containing) == 1, f'provider import {name} instruction span is absent or ambiguous')
            instruction_span = containing[0]
        elif (kind == 'R_X86_64_PC32' and offset >= 3
                and source[offset - 3:offset - 1] == b'\x0f\xb6'):
            require(False, f'provider import {name} instruction boundaries are required')
        integer = integer_memory_operand(source, offset, instruction_span=instruction_span) if kind == 'R_X86_64_PC32' else None
        require(section is not None and kind in {'R_X86_64_PLT32', 'R_X86_64_GOTPCREL', 'R_X86_64_PC32'}
                and (addend == -4 or scalar or address or integer is not None),
                f'provider import {name} relocation is not a supported reference')
        references.append({'section': section, 'offset': offset, 'kind': kind,
                           **({'addend': addend} if scalar else {}),
                           **({'address_addend': addend} if address and addend != -4 else {}),
                           **({'operand_addend': addend} if integer is not None else {}),
                           **({'instruction_start': instruction_span[0], 'instruction_end': instruction_span[1]}
                              if instruction_span is not None else {})})
    require(len({(row['section'], row['offset']) for row in references}) == len(references),
            f'provider import {name} relocation roster differs')
    return references


def symbol_only_import(tables: list[dict[str, Any]], imported: Mapping[str, Any], transcript: str) -> bool:
    """Prove one strong undefined symbol has no relocation operand anywhere.

    A linker can extract an archive provider for a strong undefined symbol
    even when the importer emits no operand referring to it. The exact source
    symbol row and complete relocation tables distinguish that class from an
    unsupported or discarded reference. It proves no machine-code call.
    """
    require(len(tables) == 1 and tables[0]['name'] == '.symtab'
            and imported in tables[0]['rows'] and imported['section_index'] == 'UND'
            and imported['binding'] == 'GLOBAL' and imported['visibility'] in {'DEFAULT', 'HIDDEN'}
            and imported['type'] in {'NOTYPE', 'FUNC', 'OBJECT'}
            and imported['size_bytes'] == 0 and int(imported['value'], 16) == 0,
            'provider symbol-only import source symbol differs')
    normalized = declaration.NO_RELOCATIONS + '\n' if transcript.strip() == declaration.NO_RELOCATIONS else transcript
    try:
        relocations = declaration.parse_relocations(normalized)
    except declaration.NativeDeclarationAbiError as error:
        raise ValueError(f'provider symbol-only import relocation tables differ: {error}') from error
    require(not any(row['symbol_index'] == imported['row_index'] for row in relocations),
            'provider symbol-only import has an actual source relocation')
    return True


def final_member_references(image: bytes, *, archive_member: str, source_calls: list[dict[str, Any]],
                            map_text: str, relocation_text: str, provider_address: int,
                            elf_type: int, name: str, source_sections: Mapping[str, bytes],
                            provider_data: bytes | None = None,
                            provider_object: tuple[bytes, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Bind exact source instruction operands to their final provider address.

    Register address loads and GOT comparisons prove address binding only.
    They do not assert a later call, register lifetime, comparison outcome,
    reachability or runtime semantics.
    Direct calls retain the existing branch proof and all sites must survive.
    Scalar reads require the exact unrelocated bytes and full extent of the
    selected read-only OBJECT; the caller authenticates its source definition.
    They prove initial operand bytes, not execution or later memory contents.
    Integer memory operands bind the selected object and full access extent.
    Ordinary immutable objects also require the complete unrelocated source
    payload in one final read-only mapping; only loads may reference them.
    Trailing immediate bytes are part of the instruction, not payload
    bytes at a NOBITS target. No execution or subsequent values are asserted.
    Source instruction spans must come from disassembly checked against the
    complete original section bytes; adjacent instructions are not prefixes.
    """
    resolved, discarded = [], []
    for reference in source_calls:
        section, offset, kind = reference['section'], reference['offset'], reference['kind']
        rows = [line for line in map_text.splitlines() if line.rstrip().endswith(f'{archive_member}:({section})')]
        require(len(rows) <= 1, f'provider {name} source section map is ambiguous')
        if not rows:
            discarded.append(dict(reference))
            continue
        source = source_sections[section]
        parts = rows[0].split()
        require(len(parts) >= 5 and type(offset) is int and offset >= 1
                and offset + 4 <= len(source) and offset + 4 <= int(parts[2], 16),
                f'provider {name} reference leaves selected section')
        instruction_span = ((reference['instruction_start'], reference['instruction_end'])
                            if 'instruction_start' in reference else None)
        integer = integer_memory_operand(source, offset, instruction_span=instruction_span) if kind == 'R_X86_64_PC32' else None
        if integer is not None:
            prefix, operand_size, immediate, operation = integer
            provider_offset = reference.get('operand_addend', -4) + 4 + len(immediate)
            require(provider_object is not None,
                    f'provider {name} integer operand lacks its source object')
            source_image, definition = provider_object
            original = static_authority.elf_bytes(source_image)
            symbol = original.symbol(name, dynamic=False)
            row, observed = definition['row'], definition['definition_section']
            require(original.elf_type == 1 and symbol is not None
                    and symbol['type'] == row['type'] == 'OBJECT'
                    and symbol['binding'] == row['binding'] == 'GLOBAL'
                    and symbol['visibility'] == row['visibility'] == 'HIDDEN'
                    and symbol['section'] == int(row['section_index']) == observed['index']
                    and symbol['value'] == int(row['value'], 16)
                    and symbol['size'] == row['size_bytes'] > 0
                    and 0 < symbol['section'] < len(original.sections),
                    f'provider {name} integer source symbol differs')
            header = original.sections[symbol['section']]
            readonly = header[1] == 1 and header[2] == 2
            require(header[1] in {1, 8} and observed['type'] == ('PROGBITS' if header[1] == 1 else 'NOBITS')
                    and (header[2], observed['flags']) == ((2, 'A') if readonly else (3, 'WA'))
                    and header[3] == int(observed['address'], 16)
                    and header[4] == int(observed['offset'], 16)
                    and header[5] == int(observed['size'], 16)
                    and header[6] == observed['link'] and header[7] == observed['info']
                    and header[8] == observed['alignment'] and header[8] > 0
                    and header[9] == int(observed['entry_size'], 16) == 0
                    and symbol['value'] + symbol['size'] <= header[5]
                    and (header[1] == 8 or header[4] + header[5] <= len(source_image))
                    and static_authority.section_name(original, header) == observed['name'],
                    f'provider {name} integer source extent differs')
            if readonly:
                require(operation in {'integer-data-load', 'integer-zero-extend-load'},
                        f'provider {name} immutable object reference is not a load')
                # No relocation table may target this ordinary source section.
                # Its complete payload, including bytes outside the operand,
                # must retain an immutable interpretation after linking.
                require(not any(section[1] in {4, 9, 19} and section[7] == symbol['section']
                                for section in original.sections),
                        f'provider {name} immutable source relocation footprint differs')
            require(0 <= provider_offset and provider_offset + operand_size <= symbol['size'],
                    f'provider {name} integer operand leaves provider object')
            require(not operation.startswith('locked-')
                    or (header[8] >= operand_size and (symbol['value'] + provider_offset) % operand_size == 0),
                    f'provider {name} locked source alignment differs')
            require(offset + 4 + len(immediate) <= int(parts[2], 16),
                    f'provider {name} immediate leaves selected section')
            call_address = int(parts[0], 16) + offset - len(prefix)
            opcode = calls._public_weak_virtual_bytes(image, call_address, len(prefix) + 4 + len(immediate),
                                                     elf_type, executable=True)
            require(opcode[:len(prefix)] == prefix and opcode[len(prefix) + 4:] == immediate, f'provider {name} reference opcode differs')
            target = call_address + len(prefix) + 4 + len(immediate) + struct.unpack_from('<i', opcode, len(prefix))[0]
            require(target == provider_address + provider_offset
                    and (not operation.startswith('locked-') or target % operand_size == 0),
                    f'provider {name} integer operand resolves to a foreign provider')
            final = static_authority.elf_bytes(image)
            final_symbol = final.symbol(name, dynamic=False)
            require(final_symbol is not None and final_symbol['type'] == 'OBJECT'
                    and final_symbol['binding'] == 'LOCAL' and final_symbol['visibility'] == 'HIDDEN'
                    and final_symbol['value'] == provider_address and final_symbol['size'] == symbol['size']
                    and 0 < final_symbol['section'] < len(final.sections),
                    f'provider {name} integer final symbol differs')
            output = final.sections[final_symbol['section']]
            require(output[1] == header[1] and output[2] == (2 if readonly else 3)
                    and output[3] <= provider_address
                    and provider_address + symbol['size'] <= output[3] + output[5]
                    and (output[1] == 8 or output[4] + output[5] <= len(image)),
                    f'provider {name} integer final extent differs')
            table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
            programs = [struct.unpack_from('<IIQQQQQQ', image, table + width * index) for index in range(count)]
            if readonly:
                start = output[4] + provider_address - output[3]
                extent = symbol['size']
                mappings = [program for program in programs if program[0] == 1
                            and program[3] < provider_address + extent and provider_address < program[3] + program[6]]
                require(len(mappings) == 1 and mappings[0][1] == 4
                            and mappings[0][3] <= provider_address and provider_address + extent <= mappings[0][3] + mappings[0][5]
                            and mappings[0][2] + provider_address - mappings[0][3] == start
                            and mappings[0][2] + mappings[0][5] <= len(image),
                        f'provider {name} immutable object lacks a read-only load extent')
                for relocation in final.sections:
                    if relocation[1] not in {4, 9, 19}:
                        continue
                    require(relocation[1] == 4 and relocation[9] == 24 and relocation[5] % 24 == 0
                            and relocation[4] + relocation[5] <= len(image),
                            f'provider {name} immutable final relocation encoding is unsupported')
                    for position in range(relocation[4], relocation[4] + relocation[5], 24):
                        address, info, _ = final.unpack('<QQq', position)
                        require(info == 8 and not (address < provider_address + extent and provider_address < address + 8),
                                f'provider {name} immutable final relocation footprint differs')
                source_start = header[4] + symbol['value']
                require(image[start:start + extent] == source_image[source_start:source_start + extent],
                        f'provider {name} immutable payload differs')
            else:
                # NOBITS has memory extent but no source or final file payload.
                # Writable operands must lie in one non-executable load image.
                require(sum(program[0] == 1 and program[1] == 6
                            and program[3] <= target and target + operand_size <= program[3] + program[6 if output[1] == 8 else 5]
                            for program in programs) == 1,
                        f'provider {name} integer operand lacks a writable load extent')
            resolved.append({'section': section, 'offset': offset, 'call_address': call_address,
                             'target_address': target, 'operand_size': operand_size, 'branch_kind': operation,
                             **({'provider_offset': provider_offset} if provider_offset else {})})
            continue
        scalar = scalar_read_prefix(source, offset) if kind == 'R_X86_64_PC32' else b''
        if scalar:
            # S + A - P encodes a displacement relative to the relocation word;
            # the instruction reads relative to its end, four bytes after P.
            provider_offset = reference.get('addend', -4) + 4
            require(provider_data is not None and 0 <= provider_offset
                    and provider_offset + 8 <= len(provider_data),
                    f'provider {name} scalar read leaves provider object')
            call_address = int(parts[0], 16) + offset - len(scalar)
            opcode = calls._public_weak_virtual_bytes(image, call_address, len(scalar) + 4,
                                                     elf_type, executable=True)
            require(opcode[:len(scalar)] == scalar, f'provider {name} reference opcode differs')
            target = call_address + len(scalar) + 4 + struct.unpack_from('<i', opcode, len(scalar))[0]
            require(target == provider_address + provider_offset,
                    f'provider {name} scalar read resolves to a foreign provider')
            data = calls._public_weak_virtual_bytes(image, target, 8, elf_type, executable=False)
            table, entry_size, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
            readable = [struct.unpack_from('<IIQQQQQQ', image, table + entry_size * index)
                        for index in range(count)]
            require(sum(header[0] == 1 and header[1] & 4 != 0 and header[1] & 3 == 0
                        and header[3] <= target and target + 8 <= header[3] + header[5]
                        for header in readable) == 1,
                    f'provider {name} scalar data lacks a read-only load segment')
            require(data == provider_data[provider_offset:provider_offset + 8],
                    f'provider {name} scalar data bytes differ')
            resolved.append({'section': section, 'offset': offset, 'call_address': call_address,
                             'target_address': target, 'provider_offset': provider_offset,
                             'read_size': 8, 'branch_kind': 'scalar-data-read'})
            continue
        prefix = source[offset - 3:offset] if offset >= 3 else b''
        address_compare = (len(prefix) == 3 and kind == 'R_X86_64_GOTPCREL'
                           and prefix[0] in {0x48, 0x4c} and prefix[1] == 0x3b
                           and prefix[2] & 0xc7 == 0x05)
        address_load = (len(prefix) == 3 and prefix[0] in {0x48, 0x4c} and prefix[2] & 0xc7 == 0x05
                        and ((kind == 'R_X86_64_GOTPCREL' and prefix[1] == 0x8b)
                             or (kind == 'R_X86_64_PC32' and prefix[1] == 0x8d)))
        conditional = (kind == 'R_X86_64_PLT32' and offset >= 2
                       and source[offset - 2] == 0x0f and 0x80 <= source[offset - 1] <= 0x8f)
        if not address_load and not address_compare and not conditional:
            prefix_size = 1 if kind == 'R_X86_64_PLT32' else 2
            prefix = source[offset - prefix_size:offset]
            require((kind == 'R_X86_64_PLT32' and prefix in {b'\xe8', b'\xe9'})
                    or (kind == 'R_X86_64_GOTPCREL' and prefix in {b'\xff\x15', b'\xff\x25'}),
                    f'provider {name} reference opcode differs')
            require(calls._public_weak_virtual_bytes(image, int(parts[0], 16) + offset - prefix_size,
                                                     prefix_size, elf_type, executable=True) == prefix,
                    f'provider {name} final reference opcode differs')
            result = calls._ordinary_final_member_calls(image, archive_member=archive_member,
                source_calls=[reference], map_text=map_text, relocation_text=relocation_text,
                provider_address=provider_address, elf_type=elf_type, name=name, source_sections=source_sections)
            resolved.extend(result['resolved_calls'])
            discarded.extend(result['discarded_calls'])
            continue
        prefix_size = 3 if address_load or address_compare else 2
        call_address = int(parts[0], 16) + offset - prefix_size
        opcode = calls._public_weak_virtual_bytes(image, call_address, prefix_size + 4, elf_type, executable=True)
        require(opcode[:prefix_size] == source[offset - prefix_size:offset],
                f'provider {name} reference opcode differs')
        target = call_address + prefix_size + 4 + struct.unpack_from('<i', opcode, prefix_size)[0]
        record = {'section': section, 'offset': offset, 'call_address': call_address,
                  'target_address': provider_address}
        if kind == 'R_X86_64_GOTPCREL':
            slot = target
            target = struct.unpack('<Q', calls._public_weak_virtual_bytes(image, slot, 8, elf_type, executable=False))[0]
            relative = re.findall(rf'^0*{slot:x}\s+\S+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)\s*$', relocation_text, re.MULTILINE)
            relr = re.findall(rf'^\s*0*{slot:x}\s+\.got\b', relocation_text, re.MULTILINE)
            relocations = re.findall(rf'^\s*0*{slot:x}\s+\S+\s+(R_X86_64_\w+)', relocation_text, re.MULTILINE)
            require((elf_type == 2 and target == provider_address and not relocations and not relr)
                    or (elf_type == 3 and ((len(relative) == 1 and int(relative[0], 16) == provider_address
                                           and target == 0 and relocations == ['R_X86_64_RELATIVE'] and not relr)
                                          or (len(relr) == 1 and target == provider_address and not relocations))),
                    f'provider {name} GOT resolves to a foreign provider')
            record.update(got_slot=slot, branch_kind='got-address-compare' if address_compare else 'got-address-load')
        else:
            provider_offset = 0
            if 'address_addend' in reference:
                require(address_load and provider_object is not None,
                        f'provider {name} interior address lacks its source object')
                source_image, definition = provider_object
                original = static_authority.elf_bytes(source_image)
                symbol = original.symbol(name, dynamic=False)
                row, observed = definition['row'], definition['definition_section']
                require(original.elf_type == 1 and symbol is not None
                        and symbol['type'] == row['type'] == 'OBJECT'
                        and symbol['binding'] == row['binding'] == 'GLOBAL'
                        and symbol['visibility'] == row['visibility'] == 'HIDDEN'
                        and symbol['section'] == int(row['section_index']) == observed['index']
                        and symbol['value'] == int(row['value'], 16)
                        and symbol['size'] == row['size_bytes'] > 0
                        and 0 < symbol['section'] < len(original.sections),
                        f'provider {name} interior source symbol differs')
                header = original.sections[symbol['section']]
                require(header[1] == 1 and observed['type'] == 'PROGBITS'
                        and header[2] == 3 and observed['flags'] == 'WA'
                        and header[3] == int(observed['address'], 16)
                        and header[4] == int(observed['offset'], 16)
                        and header[5] == int(observed['size'], 16)
                        and header[6] == observed['link'] and header[7] == observed['info']
                        and header[8] == observed['alignment'] and header[8] > 0
                        and header[9] == int(observed['entry_size'], 16) == 0
                        and header[4] + header[5] <= len(source_image)
                        and symbol['value'] + symbol['size'] <= header[5]
                        and static_authority.section_name(original, header) == observed['name'],
                        f'provider {name} interior source extent differs')
                # PC32 is S + A - P; RIP is four bytes beyond P. LEA forms
                # an address inside the selected object without reading it.
                provider_offset = reference['address_addend'] + 4
                require(0 <= provider_offset < symbol['size'],
                        f'provider {name} interior address leaves provider object')
                final = static_authority.elf_bytes(image)
                final_symbol = final.symbol(name, dynamic=False)
                require(final_symbol is not None and final_symbol['type'] == 'OBJECT'
                        and final_symbol['binding'] == 'LOCAL' and final_symbol['visibility'] == 'HIDDEN'
                        and final_symbol['value'] == provider_address and final_symbol['size'] == symbol['size']
                        and 0 < final_symbol['section'] < len(final.sections),
                        f'provider {name} interior final symbol differs')
                output = final.sections[final_symbol['section']]
                require(output[1] == 1 and output[2] == 3
                        and output[3] <= provider_address
                        and provider_address + symbol['size'] <= output[3] + output[5],
                        f'provider {name} interior final extent differs')
                table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
                require(sum(program[0] == 1 and program[1] == 6
                            and program[3] <= provider_address
                            and provider_address + symbol['size'] <= program[3] + program[5]
                            for program in (struct.unpack_from('<IIQQQQQQ', image, table + width * index)
                                            for index in range(count))) == 1,
                        f'provider {name} interior object lacks a writable load extent')
                record['provider_offset'] = provider_offset
                record['target_address'] = provider_address + provider_offset
            require(target == provider_address + provider_offset,
                    f'provider {name} reference resolves to a foreign provider')
            record['branch_kind'] = 'rip-relative-address' if address_load else 'conditional-jump'
        resolved.append(record)
    return {'resolved_calls': resolved, 'discarded_calls': discarded}


def definition_address(view: Mapping[str, Any], archive_member: str, definition: Mapping[str, Any],
                       *, source_image: bytes | None = None) -> int:
    """Bind a final symbol to its exact selected archive section and offset."""
    name = definition['row']['name']
    symbol_rows = view['symbol_rows'].get(name, [])
    require(all(row[3] == definition['row']['type'] and row[6] != 'UND' for row in symbol_rows),
            'provider final symbol metadata differs')
    symbols = [(int(row[1], 16), int(row[2])) for row in symbol_rows]
    require(len(symbols) == 1 and symbols[0][1] == definition['row']['size_bytes'],
            'provider final symbol is absent, ambiguous or mismatched')
    address = symbols[0][0]
    section = definition['definition_section']['name']
    maps = view['map_rows'].get(archive_member + ':(' + section + ')', [])
    if not maps and definition['row']['type'] in {'FUNC', 'OBJECT'} and source_image is not None:
        source = static_authority.elf_bytes(source_image)
        require(source.elf_type == 1, 'provider source is not a relocatable ELF')
        symbol = source.symbol(name, dynamic=False)
        row, observed = definition['row'], definition['definition_section']
        require(symbol is not None and symbol['type'] == row['type']
                and symbol['binding'] == row['binding'] and symbol['visibility'] == row['visibility']
                and symbol['section'] == int(row['section_index'])
                and symbol['value'] == int(row['value'], 16) and symbol['size'] == row['size_bytes'],
                'provider source symbol metadata differs')
        index = symbol['section']
        require(0 < index < len(source.sections) and observed['index'] == index,
                'provider source section index differs')
        header = source.sections[index]
        flag_bits = {'W': 1, 'A': 2, 'X': 4, 'M': 16, 'S': 32, 'I': 64, 'L': 128,
                     'O': 256, 'G': 512, 'T': 1024, 'C': 2048, 'R': 0x200000,
                     'D': 0x1000000, 'E': 0x80000000}
        require(len(observed['flags']) == len(set(observed['flags']))
                and set(observed['flags']) <= set(flag_bits)
                and sum(flag_bits[flag] for flag in observed['flags']) == header[2]
                and header[2] & 6 == (6 if row['type'] == 'FUNC' else 2),
                'provider source section flags differ')
        require(header[1] == 1 and observed['type'] == 'PROGBITS'
                and header[3] == int(observed['address'], 16)
                and header[4] == int(observed['offset'], 16)
                and header[5] == int(observed['size'], 16)
                and header[9] == int(observed['entry_size'], 16)
                and header[6] == observed['link'] and header[7] == observed['info']
                and header[8] == observed['alignment']
                and header[4] + header[5] <= len(source_image)
                and symbol['value'] + symbol['size'] <= header[5],
                'provider source section geometry differs')
        actual_name = static_authority.section_name(source, header)
        # The pinned GNU renderer caps section names at 256 bytes even in wide
        # output. The indexed ELF string defines ownership; a display prefix
        # alone never identifies a section or permits a different member.
        require(section == actual_name or (len(section) == 256 and len(actual_name) > 256
                                           and section == actual_name[:256]),
                'provider source section display name differs')
        maps = view['map_rows'].get(archive_member + ':(' + actual_name + ')', [])
        if row['type'] == 'OBJECT' and not maps:
            require(row['binding'] == 'GLOBAL' and row['visibility'] == 'HIDDEN'
                    and header[2] in {18, 50} and header[8] > 0
                    and header[9] > 0 and header[5] % header[9] == 0
                    and symbol['value'] % header[9] == 0
                    and symbol['size'] > 0 and symbol['size'] % header[9] == 0,
                    'provider merged object metadata differs')
            start = header[4] + symbol['value']
            data = source_image[start:start + symbol['size']]
            strings = bool(header[2] & 32)
            require((strings and header[9] == 1 and data[-1:] == b'\0'
                     and data.count(b'\0') == 1
                     and (symbol['value'] == 0 or source_image[start - 1] == 0))
                    or (not strings and header[9] in {4, 8, 16} and symbol['size'] == header[9]),
                    'provider merged object element differs')
            require(symbol_rows[0][4:6] == ['LOCAL', 'HIDDEN'],
                    'provider merged final symbol metadata differs')
            pools = view['map_rows'].get('<internal>:(' + actual_name + ')', [])
            require(view['trace_counts'].get(archive_member) == 1 and len(pools) == 1,
                    'provider merged object lacks selected member or pool')
            parts = pools[0].split()
            base, load, extent, alignment = int(parts[0], 16), int(parts[1], 16), int(parts[2], 16), int(parts[3])
            final = static_authority.elf_bytes(view['image'])
            final_index = int(symbol_rows[0][6])
            require(0 < final_index < len(final.sections), 'provider merged final section differs')
            output = final.sections[final_index]
            require(output[1] == 1 and output[2] & 7 == 2 and base == load
                    and alignment >= header[8] and base % alignment == 0
                    and extent > 0 and extent % header[9] == 0
                    and output[3] <= base and base + extent <= output[3] + output[5]
                    and base <= address and address + len(data) <= base + extent
                    and (address - base) % header[9] == 0,
                    'provider merged pool geometry differs')
            table, width, count = struct.unpack_from('<Q', view['image'], 32)[0], *struct.unpack_from('<HH', view['image'], 54)
            require(sum(program[0] == 1 and program[1] == 4
                        and program[3] <= base and base + extent <= program[3] + program[5]
                        for program in (struct.unpack_from('<IIQQQQQQ', view['image'], table + width * index)
                                        for index in range(count))) == 1,
                    'provider merged pool lacks a read-only load segment')
            require(calls._public_weak_virtual_bytes(view['image'], address, len(data), view['type'],
                                                   executable=False) == data,
                    'provider merged object bytes differ')
            # A merge pool has no winning input member. Ownership comes from
            # the selected hidden definition and its exact forcing relocation,
            # not another constant with equal bytes or the same pooled address.
            forcing = static_authority.elf_bytes(view.get('forcing_image', b''))
            holder = forcing.symbol('providers', dynamic=False)
            require(forcing.elf_type == 1 and holder is not None and holder['type'] == 'OBJECT'
                    and holder['binding'] == 'LOCAL' and holder['visibility'] == 'DEFAULT'
                    and holder['size'] > 0 and holder['size'] % 8 == 0
                    and 0 < holder['section'] < len(forcing.sections),
                    'provider forcing holder differs')
            holder_section = forcing.sections[holder['section']]
            require(holder_section[1] == 1 and holder_section[2] == 3
                    and holder['value'] + holder['size'] <= holder_section[5],
                    'provider forcing section differs')
            references = []
            for relocation in forcing.sections:
                if relocation[1] != 4 or relocation[7] != holder['section']:
                    continue
                require(relocation[9] == 24 and relocation[5] % 24 == 0,
                        'provider forcing relocation table differs')
                for offset in range(0, relocation[5], 24):
                    position, info, addend = forcing.unpack('<QQq', relocation[4] + offset)
                    imported = forcing.symbol_row(relocation[6], info >> 32)
                    if imported['name'] != name:
                        continue
                    require(info & 0xffffffff == 1 and addend == 0
                            and imported['binding'] == 'GLOBAL' and imported['visibility'] == 'DEFAULT'
                            and imported['section'] == imported['value'] == imported['size'] == 0
                            and holder['value'] <= position and position + 8 <= holder['value'] + holder['size']
                            and (position - holder['value']) % 8 == 0,
                            'provider forcing reference differs')
                    references.append(position)
            owner = view.get('forcing_owner')
            forcing_maps = view['map_rows'].get(str(owner) + ':(' + static_authority.section_name(forcing, holder_section) + ')', [])
            require(len(references) == 1 and view['trace_counts'].get(owner) == 1 and len(forcing_maps) == 1,
                    'provider merged object lacks its exact forcing reference')
            placement = forcing_maps[0].split()
            forcing_base = int(placement[0], 16)
            require(forcing_base == int(placement[1], 16) and int(placement[2], 16) == holder_section[5]
                    and holder_section[8] > 0 and forcing_base % holder_section[8] == 0,
                    'provider forcing placement differs')
            slot = forcing_base + references[0]
            value = struct.unpack('<Q', calls._public_weak_virtual_bytes(view['image'], slot, 8,
                                                                      view['type'], executable=False))[0]
            targets = []
            for relocation in final.sections:
                require(not (relocation[1] in {9, 19} and relocation[2] & 2),
                        'provider forcing relocation encoding is unsupported')
                if relocation[1] != 4:
                    continue
                require(relocation[9] == 24 and relocation[5] % 24 == 0,
                        'provider final relocation table differs')
                for offset in range(0, relocation[5], 24):
                    position, info, addend = final.unpack('<QQq', relocation[4] + offset)
                    if position == slot:
                        targets.append((info, addend))
            require((view['type'] == 2 and value == address and not targets)
                    or (view['type'] == 3 and value == 0 and targets == [(8, address)]),
                    'provider forcing target differs')
            return address
    require(view['trace_counts'].get(archive_member) == 1 and len(maps) == 1
            and int(maps[0].split()[0], 16) + int(definition['row']['value'], 16) == address,
            'provider final symbol does not belong to the exact archive definition')
    return address


def project(work: Path, static: Path, accounting: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    retained = validate(work, static, facts)
    proof = project_references(work, static, accounting,
        mapped_archive=calls.mounted_path(static / 'usr/lib/libc.a'),
        forcing_owner=calls.mounted_path(work / 'providers.o'), temporary_parent=ROOT / '.work/x86_64')
    require(retained == validate(work, static, facts), 'provider work changed during physical projection')
    return {'retained': retained, **proof}


def project_references(work: Path, static: Path, accounting: Mapping[str, Any], *,
                       mapped_archive: str, forcing_owner: str, temporary_parent: Path) -> dict[str, Any]:
    """Replay the complete reference roster after independent input admission.

    The caller authenticates the accounting/facts, archive, forcing object,
    maps, executables and exact original trace names as one immutable tuple.
    This stage does not admit that tuple or qualify a different receiver source.
    Tool input copies belong to the caller's private temporary directory.
    """
    archive = static / 'usr/lib/libc.a'
    final = {}
    for mode, elf_type in (('static', 2), ('static-pie', 3)):
        final[mode] = _indexed_view(work, mode, elf_type)
        final[mode]['forcing_owner'] = forcing_owner
    source_members = {}
    definition_images = {}
    by_name = {}
    for row in accounting['occurrences']:
        if row['artifact_key'] == 'candidate-static' and row['role'] in {'definition', 'import'}:
            by_name.setdefault(row['row']['name'], []).append(row)
    admitted, failures = [], []
    for record in accounting['identities']:
        name = record['identity']['name']
        if (record['selection']['disposition'] != 'unresolved'
                and 'exact ordinary import/provider or optional weak/null resolution proof is missing'
                    not in record['unresolved']):
            continue
        rows = by_name.get(name, [])
        definitions = [row for row in rows if row['role'] == 'definition']
        imports = [row for row in rows if row['role'] == 'import']
        if (len(definitions) != 1 or definitions[0]['row']['type'] not in {'FUNC', 'OBJECT'}
                or definitions[0]['row']['size_bytes'] <= 0):
            continue
        definition = definitions[0]
        proof = {'identity': record['identity'], 'definition_index': definition['index'],
                 'import_indices': sorted(row['index'] for row in imports), 'static_modes': list(MODES),
                 'physical_provider_and_calls': True, 'links': {}}
        try:
            source_imports = []
            for row in imports:
                member = row['member_name']
                require(row['member_occurrence'] == 0, 'provider archive member is ambiguous')
                if member not in source_members:
                    result = subprocess.run(['/usr/bin/ar', 'p', str(archive), member], capture_output=True, check=False)
                    require(result.returncode == 0 and result.stdout, 'provider archive member is unreadable')
                    with tempfile.TemporaryDirectory(dir=temporary_parent) as temporary:
                        path = Path(temporary) / 'member.o'
                        path.write_bytes(result.stdout)
                        relocations = read_tool('readelf', '-rW', path)
                        symbols = inventory.parse_elf_symbol_tables(read_tool('readelf', '-Ws', path))
                        disassembly = read_tool('objdump', '-dw', path)
                    source_members[member] = (result.stdout, relocations, symbols, disassembly)
                image, relocations, symbols, disassembly = source_members[member]
                require(len(symbols) == 1 and symbols[0]['name'] == '.symtab'
                        and row['row'] in symbols[0]['rows'], 'provider source import symbol changed')
                source_calls = import_relocations(relocations, name, image=image, disassembly=disassembly)
                if not source_calls:
                    symbol_only_import(symbols, row['row'], relocations)
                source_imports.append((row, source_calls, calls._ordinary_source_sections(
                    image, {item['section'] for item in source_calls})))
            provider_data = None
            integer_object = any('operand_addend' in reference
                                 for _, references, _ in source_imports for reference in references)
            interior_object = any('address_addend' in reference
                                  for _, references, _ in source_imports for reference in references)
            if any('addend' in reference for _, references, _ in source_imports for reference in references):
                section = definition['definition_section']
                require(definition['row']['type'] == 'OBJECT' and section['type'] == 'PROGBITS'
                        and 'A' in section['flags'] and 'W' not in section['flags'] and 'X' not in section['flags'],
                        'scalar provider is not a read-only source object')
                result = subprocess.run(['/usr/bin/ar', 'p', str(archive), definition['member_name']],
                                        capture_output=True, check=False)
                require(result.returncode == 0 and result.stdout, 'scalar provider source member is unreadable')
                source_data = calls._ordinary_source_sections(result.stdout, {section['name']})[section['name']]
                start, size = int(definition['row']['value'], 16), definition['row']['size_bytes']
                require(start + size <= len(source_data), 'scalar provider leaves its source section')
                provider_data = source_data[start:start + size]
            for mode, view in final.items():
                selected = mapped_archive + '(' + definition['member_name'] + ')'
                source_image = None
                if (definition['row']['type'] in {'FUNC', 'OBJECT'}
                        and (integer_object or interior_object or not view['map_rows'].get(selected + ':(' + definition['definition_section']['name'] + ')'))):
                    member = definition['member_name']
                    require(definition['member_occurrence'] == 0, 'provider definition member is ambiguous')
                    if member not in definition_images:
                        result = subprocess.run(['/usr/bin/ar', 'p', str(archive), member], capture_output=True, check=False)
                        require(result.returncode == 0 and result.stdout, 'provider definition member is unreadable')
                        definition_images[member] = result.stdout
                    source_image = definition_images[member]
                address = definition_address(view, selected, definition, source_image=source_image)
                linked = []
                for imported, source_calls, sections in source_imports:
                    member = mapped_archive + '(' + imported['member_name'] + ')'
                    require(view['trace_counts'].get(member) == 1,
                            'provider importer was not extracted exactly once')
                    map_text, relocation_text = _call_transcripts(view, member, source_calls)
                    result = final_member_references(view['image'], archive_member=member,
                        source_calls=source_calls, map_text=map_text, relocation_text=relocation_text,
                        provider_address=address, elf_type=view['type'], name=name, source_sections=sections, provider_data=provider_data,
                        provider_object=(source_image, definition) if integer_object or interior_object else None)
                    require((result['resolved_calls'] or not source_calls) and not result['discarded_calls'],
                            'provider witness does not retain every source call')
                    linked.append({'occurrence_index': imported['index'], 'member_sha256':
                                   hashlib.sha256(source_members[imported['member_name']][0]).hexdigest(), **result,
                                   **({'symbol_only_reference': True} if not source_calls else {})})
                proof['links'][mode] = {'provider_address': address, 'importers': linked}
            admitted.append(proof)
        except (ValueError, KeyError, calls.AllocatorBoundaryError) as error:
            failures.append({'identity': record['identity'], 'reason': str(error)})
    return {'identities': admitted, 'failures': failures}


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('mode', choices=('collect',))
    parser.add_argument('--static-product', type=Path, required=True)
    parser.add_argument('--elf-facts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    collect(args.static_product, args.elf_facts, args.output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
