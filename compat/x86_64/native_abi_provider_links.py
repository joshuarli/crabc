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
        if call['kind'] not in {'R_X86_64_GOTPCREL', 'R_X86_64_REX_GOTPCRELX'} or len(rows) != 1:
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


def integer_memory_operand(source: bytes, offset: int, *,
                           instruction_span: tuple[int, int] | None = None) -> tuple[bytes, int, bytes, str] | None:
    """Decode supported RIP-relative integer or packed-vector memory operands."""
    legacy_prefixes = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3}
    if instruction_span is not None:
        start, end = instruction_span
        require(0 <= start < offset and offset + 4 <= end <= len(source),
                'integer operand instruction span differs')
        # A byte immediate follows the displacement and changes its PC bias.
        # Its complete span owns that immediate; neighboring bytes cannot
        # supply it or turn a wider store into this one-byte operation.
        if (end == offset + 5 and source[start:offset] == b'\xc6\x05'):
            return b'\xc6\x05', 1, source[offset + 4:end], 'integer-immediate-store'
        # Operand-size 66 makes this C7 store two bytes, including imm16.
        # No REX, address-size or segment prefix shares this instruction form.
        if end == offset + 6 and source[start:offset] == b'\x66\xc7\x05':
            return b'\x66\xc7\x05', 2, source[offset + 4:end], 'integer-immediate-store'
        # Sign-extended imm32 stores still access eight bytes. Compare imm8
        # changes the PC bias but retains the encoded four/eight-byte access.
        # Require the complete instruction before interpreting either suffix.
        complete_prefix = source[start:offset]
        if end == offset + 8 and complete_prefix == b'\x48\xc7\x05':
            return complete_prefix, 8, source[offset + 4:end], 'integer-immediate-store'
        if (end == offset + 5 and complete_prefix in {b'\x83\x3d', b'\x48\x83\x3d'}):
            return complete_prefix, 8 if complete_prefix[0] == 0x48 else 4, source[offset + 4:end], 'integer-immediate-compare'
        prefix = source[start:offset] if end == offset + 4 else b''
        if (len(prefix) == 3 and prefix[:2] in {b'\x0f\xb7', b'\x66\x89'}
                and prefix[2] & 0xc7 == 0x05):
            return prefix, 2, b'', ('integer-zero-extend-load' if prefix[:2] == b'\x0f\xb7'
                                   else 'integer-data-store')
        operation = prefix[1:] if len(prefix) == 4 and prefix[0] == 0x44 else prefix
        if (len(operation) == 3 and operation[:2] == b'\x0f\xb6' and operation[2] & 0xc7 == 0x05):
            return prefix, 1, b'', 'integer-zero-extend-load'
        # REX.R extends the destination register without widening this load.
        # The unprefixed byte store has no REX or operand-size interpretation.
        if len(prefix) == 3 and prefix[:2] == b'\x44\x8b' and prefix[2] & 0xc7 == 0x05:
            return prefix, 4, b'', 'integer-data-load'
        if len(prefix) == 2 and prefix[0] == 0x88 and prefix[1] & 0xc7 == 0x05:
            return prefix, 1, b'', 'integer-data-store'
        # These REX forms extend a byte source or dword register without
        # changing the memory width; MOVSXD reads a dword into a qword register.
        if len(prefix) == 3 and prefix[:2] == b'\x40\x88' and prefix[2] & 0xc7 == 0x05:
            return prefix, 1, b'', 'integer-data-store'
        if len(prefix) == 3 and prefix[:2] == b'\x44\x89' and prefix[2] & 0xc7 == 0x05:
            return prefix, 4, b'', 'integer-data-store'
        if len(prefix) == 3 and prefix[:2] == b'\x48\x63' and prefix[2] & 0xc7 == 0x05:
            return prefix, 4, b'', 'integer-sign-extend-load'
        # Unaligned packed-single moves access sixteen bytes. Their complete
        # legacy encoding has no mandatory prefix, REX, VEX or segment override.
        if len(prefix) == 3 and prefix[:2] in {b'\x0f\x10', b'\x0f\x11'} and prefix[2] & 0xc7 == 0x05:
            return prefix, 16, b'', 'vector-data-load' if prefix[1] == 0x10 else 'vector-data-store'
        # MOVDQU uses its mandatory F3 prefix and a 16-byte operand. Only
        # these complete legacy encodings are admitted; REX/VEX, additional
        # prefixes and aligned or narrower vector moves are separate forms.
        if (len(prefix) == 4 and prefix[:2] == b'\xf3\x0f'
                and prefix[2] in {0x6f, 0x7f} and prefix[3] & 0xc7 == 0x05):
            return prefix, 16, b'', 'vector-data-load' if prefix[2] == 0x6f else 'vector-data-store'
        # Atomic operands are decoded only from a complete authenticated span.
        # LOCK is explicit for compare/exchange and increments; memory XCHG
        # supplies its own lock. Only these observed widths and REX bits belong
        # to the admitted forms; segment/address/operand-size prefixes do not.
        # Byte CMPXCHG admits only the observed low-byte register encodings.
        # REX 40 selects SIL/DIL instead of high-byte registers; REX 44
        # extends the register field. Neither changes the memory width.
        byte_atomic = prefix[1:] if prefix.startswith(b'\xf0') else b''
        if byte_atomic[:1] in {b'\x40', b'\x44'}:
            byte_atomic = byte_atomic[1:]
        if (len(byte_atomic) == 3 and byte_atomic[:2] == b'\x0f\xb0'
                and byte_atomic[2] & 0xc7 == 0x05):
            return prefix, 1, b'', 'locked-cmpxchg'
        atomic = prefix
        locked = atomic.startswith(b'\xf0')
        if locked:
            atomic = atomic[1:]
        rex = atomic[0] if atomic and atomic[0] in {0x44, 0x48, 0x4c} else None
        if rex is not None:
            atomic = atomic[1:]
        if len(atomic) == 3 and atomic[:2] == b'\x0f\xb1' and atomic[2] & 0xc7 == 0x05 and locked:
            return prefix, 8 if rex in {0x48, 0x4c} else 4, b'', 'locked-cmpxchg'
        if len(atomic) == 2 and atomic[1] & 0xc7 == 0x05 and not locked:
            if atomic[0] == 0x86 and rex is None:
                return prefix, 1, b'', 'atomic-exchange'
            if atomic[0] == 0x87:
                return prefix, 8 if rex in {0x48, 0x4c} else 4, b'', 'atomic-exchange'
        if locked and rex is None and atomic in {b'\xff\x05', b'\xff\x0d'}:
            return prefix, 4, b'', 'locked-increment' if atomic[1] == 0x05 else 'locked-decrement'
        # Decode within the authenticated instruction, then require the entire
        # prefix and immediate. Bytes belonging to adjacent instructions cannot
        # change this operand's width or supply an ignored extra prefix.
        decoded = integer_memory_operand(source[start:end], offset - start)
        if decoded is not None:
            prefix, _, immediate, _ = decoded
            if offset - start == len(prefix) and end == offset + 4 + len(immediate):
                return decoded
        return None
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


def data_pointer_relocations(image: bytes, name: str) -> list[dict[str, Any]]:
    """Read named slots from complete ordinary data.rel.ro pointer tables.

    The source holder can be a section without an OBJECT symbol. Its complete
    file extent must consist of aligned, zero-filled RELA pointer slots, each
    naming a strong hidden undefined symbol. Mixed data, section-local targets,
    merge pools, TLS, constructor arrays and partial relocation coverage do not
    acquire pointer-table ownership through a similar name or equal bytes.
    """
    original = static_authority.elf_bytes(image)
    require(original.elf_type == 1, 'data pointer source is not relocatable ELF')
    result = []
    for relocation in original.sections:
        if relocation[1] != 4:
            continue
        require(relocation[9] == 24 and relocation[5] % 24 == 0
                and relocation[4] + relocation[5] <= len(image)
                and 0 < relocation[7] < len(original.sections), 'data pointer relocation table differs')
        entries = [original.unpack('<QQq', position)
                   for position in range(relocation[4], relocation[4] + relocation[5], 24)]
        if not any(info & 0xffffffff == 1 and original.symbol_row(relocation[6], info >> 32)['name'] == name
                   for _, info, _ in entries):
            continue
        section = original.sections[relocation[7]]
        if section[1] != 1 or section[2] != 3:
            continue
        section_name = static_authority.section_name(original, section)
        # Explicit relocation-ready data tables are this source class. GOT and
        # constructor storage require their own ABI ownership authority even
        # when their file bytes resemble ordinary pointer slots.
        if section_name != '.data.rel.ro' and not section_name.startswith('.data.rel.ro.'):
            continue
        require(section[3] == 0 and section[5] > 0 and section[5] % 8 == 0
                and section[8] >= 8 and section[8] % 8 == 0 and section[9] == 0
                and section[6] == section[7] == 0 and section[4] + section[5] <= len(image)
                and image[section[4]:section[4] + section[5]] == bytes(section[5])
                and static_authority.section_name(original, relocation) == '.rela' + section_name
                and original.sections[relocation[6]][1] == 2
                and len([other for other in original.sections if other[1] in {4, 9, 19}
                         and other[7] == relocation[7]]) == 1,
                'data pointer holder extent or payload differs')
        positions = []
        for offset, info, addend in entries:
            imported = original.symbol_row(relocation[6], info >> 32)
            require(info & 0xffffffff == 1 and imported['name']
                    and imported['binding'] == 'GLOBAL' and imported['visibility'] == 'HIDDEN'
                    and imported['type'] in {'0', 'OBJECT'}
                    and imported['section'] == imported['value'] == imported['size'] == 0
                    and imported['version_index'] == 1
                    and offset % 8 == 0 and 0 <= offset and offset + 8 <= section[5],
                    'data pointer holder relocation footprint differs')
            positions.append(offset)
            if imported['name'] == name:
                result.append({'section': section_name, 'offset': offset, 'kind': 'R_X86_64_64',
                               'pointer_addend': addend})
        require(len(positions) == len(set(positions)) and set(positions) == set(range(0, section[5], 8)),
                'data pointer holder relocation coverage differs')
    return result


def import_relocations(transcript: str, name: str, *, image: bytes,
                       disassembly: str | None = None) -> list[dict[str, Any]]:
    """Retain the complete executable relocation roster for a symbol import.

    A function reference may load its address without calling it at that site.
    Only the exact PC-relative instruction forms decoded below are accepted.
    Ordinary complete data-pointer tables have a separate raw relocation proof.
    Other non-executable forms stay unsupported. Interior LEA addends
    require a separately authenticated object extent during final projection.
    Disassembly boundaries are checked against raw section bytes so a preceding
    instruction displacement cannot be mistaken for an operand-size prefix.
    """
    sections = calls._ordinary_relocation_sections(image)
    pointers = data_pointer_relocations(image, name) if 'R_X86_64_64' in transcript else []
    if pointers:
        original = static_authority.elf_bytes(image)
        pointer_sections = {reference['section'] for reference in pointers}
        for relocation in original.sections:
            if relocation[1] == 4 and static_authority.section_name(original, original.sections[relocation[7]]) in pointer_sections:
                sections[relocation[4]] = static_authority.section_name(original, original.sections[relocation[7]])
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
        header = re.match(r"^Relocation section '(\.rela[^']*)' at offset 0x([0-9a-f]+)", line)
        if header:
            section = sections.get(int(header.group(2), 16))
            require((section is not None or not header.group(1).startswith('.rela.text'))
                    and (section is None or ('.rela' + section).startswith(header.group(1))),
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
        if kind == 'R_X86_64_64':
            reference = {'section': section, 'offset': offset, 'kind': kind, 'pointer_addend': addend}
            require(reference in pointers, f'provider import {name} data pointer relocation differs')
            references.append(reference)
            continue
        source = calls._ordinary_source_sections(image, {section})[section] if section is not None else b''
        scalar = section is not None and kind == 'R_X86_64_PC32' and scalar_read_prefix(source, offset)
        prefix = source[offset - 3:offset] if offset >= 3 else b''
        address = (kind == 'R_X86_64_PC32' and len(prefix) == 3 and prefix[0] in {0x48, 0x4c}
                   and prefix[1] == 0x8d and prefix[2] & 0xc7 == 0x05)
        instruction_span = None
        if kind in {'R_X86_64_PC32', 'R_X86_64_REX_GOTPCRELX'} and disassembly is not None:
            containing = [(start, end) for start, end in instruction_spans.get(section, {}).items()
                          if start <= offset and offset + 4 <= end]
            require(len(containing) == 1, f'provider import {name} instruction span is absent or ambiguous')
            instruction_span = containing[0]
        elif (kind == 'R_X86_64_PC32' and offset >= 3
                and (source[offset - 3:offset - 1] in {b'\x0f\xb6', b'\x0f\xb7'}
                     or source[offset - 3:offset] == b'\x66\xc7\x05'
                     or (source[offset - 3:offset - 1] == b'\x66\x89'
                         and source[offset - 1] & 0xc7 == 0x05))):
            require(False, f'provider import {name} instruction boundaries are required')
        if kind == 'R_X86_64_REX_GOTPCRELX':
            # A relaxable address load retains its exact seven-byte source
            # instruction. Relaxation can change MOV to LEA, never the REX
            # register bits, addressing mode, operand boundary or symbol bias.
            require(instruction_span == (offset - 3, offset + 4) and addend == -4
                    and len(prefix) == 3 and prefix[0] in {0x48, 0x4c}
                    and prefix[1] == 0x8b and prefix[2] & 0xc7 == 0x05,
                    f'provider import {name} relaxable GOT instruction differs')
        integer = integer_memory_operand(source, offset, instruction_span=instruction_span) if kind == 'R_X86_64_PC32' else None
        require(section is not None and kind in {'R_X86_64_PLT32', 'R_X86_64_GOTPCREL', 'R_X86_64_REX_GOTPCRELX', 'R_X86_64_PC32'}
                and (addend == -4 or scalar or address or integer is not None),
                f'provider import {name} relocation is not a supported reference')
        references.append({'section': section, 'offset': offset, 'kind': kind,
                           **({'addend': addend} if scalar else {}),
                           **({'address_addend': addend} if address and addend != -4 else {}),
                           **({'operand_addend': addend} if integer is not None else {}),
                           **({'instruction_start': instruction_span[0], 'instruction_end': instruction_span[1]}
                              if instruction_span is not None else {})})
    require([reference for reference in references if reference['kind'] == 'R_X86_64_64'] == pointers,
            f'provider import {name} data pointer transcript roster differs')
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


def merged_string_translation(image: bytes, elf_type: int, source_image: bytes,
                              definition: Mapping[str, Any], address: int,
                              pool: tuple[Mapping[str, Any], str] | None) -> None:
    """Bind a pooled string to its selected definition and exact forcing slot.

    Equal payloads and shared suffix addresses do not identify an archive owner.
    The complete raw final view authenticates the selected member, pool map,
    source element, final symbol, and relocation naming that specific definition.
    """
    require(pool is not None, 'merged string lacks its owned pool translation')
    view, member = pool
    require(view['image'] == image and view['type'] == elf_type
            and definition['definition_section']['flags'] == 'AMS'
            and not view['map_rows'].get(member + ':(' + definition['definition_section']['name'] + ')'),
            'merged string pool translation differs')
    require(definition_address(view, member, definition, source_image=source_image) == address,
            'merged string pool resolves to a foreign provider')


def immutable_object_payload(image: bytes, source_image: bytes, *, symbol: Mapping[str, Any],
                             header: tuple[int, ...], output: tuple[int, ...],
                             address: int, name: str) -> None:
    """Authenticate the complete payload after source/final ownership admission."""
    original, final = static_authority.elf_bytes(source_image), static_authority.elf_bytes(image)
    require(not any(section[1] in {4, 9, 19} and section[7] == symbol['section']
                    for section in original.sections),
            f'provider {name} immutable source relocation footprint differs')
    table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
    programs = [struct.unpack_from('<IIQQQQQQ', image, table + width * index) for index in range(count)]
    start, extent = output[4] + address - output[3], symbol['size']
    mappings = [program for program in programs if program[0] == 1
                and program[3] < address + extent and address < program[3] + program[6]]
    require(len(mappings) == 1 and mappings[0][1] == 4
            and mappings[0][3] <= address and address + extent <= mappings[0][3] + mappings[0][5]
            and mappings[0][2] + address - mappings[0][3] == start
            and mappings[0][2] + mappings[0][5] <= len(image),
            f'provider {name} immutable object lacks a read-only load extent')
    for relocation in final.sections:
        if relocation[1] not in {4, 9, 19}:
            continue
        require(relocation[1] == 4 and relocation[9] == 24 and relocation[5] % 24 == 0
                and relocation[4] + relocation[5] <= len(image),
                f'provider {name} immutable final relocation encoding is unsupported')
        for position in range(relocation[4], relocation[4] + relocation[5], 24):
            target, info, _ = final.unpack('<QQq', position)
            require(info == 8 and not (target < address + extent and address < target + 8),
                    f'provider {name} immutable final relocation footprint differs')
    source_start = header[4] + symbol['value']
    require(image[start:start + extent] == source_image[source_start:source_start + extent],
            f'provider {name} immutable payload differs')


def writable_object_mapping(image: bytes, *, address: int, extent: int,
                            output: tuple[int, ...], label: str) -> None:
    """Prove the full object's exclusive non-executable writable mapping."""
    table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
    programs = [struct.unpack_from('<IIQQQQQQ', image, table + width * index) for index in range(count)]
    mappings = [program for program in programs if program[0] == 1
                and program[3] < address + extent and address < program[3] + program[6]]
    require(len(mappings) == 1 and mappings[0][1] == 6 and mappings[0][3] <= address
            and address + extent <= mappings[0][3] + mappings[0][6]
            and mappings[0][2] + mappings[0][5] <= len(image)
            and (output[1] == 8 or
                 (address + extent <= mappings[0][3] + mappings[0][5]
                  and mappings[0][2] + address - mappings[0][3] == output[4] + address - output[3])),
            f'{label} lacks an exclusive writable load extent')


def final_data_pointer(image: bytes, *, reference: Mapping[str, Any], placement: list[str],
                       importer_image: bytes | None, source_payload: bytes,
                       provider_object: tuple[bytes, Mapping[str, Any]] | None,
                       provider_address: int, elf_type: int, name: str) -> dict[str, Any]:
    """Bind a named source table slot to the exact selected ordinary OBJECT.

    This proves an initial address representation or its RELATIVE fixup, not a
    later dereference or the active contents of a relocatable target object.
    Neighbor slots must retain the table's complete pointer footprint; their
    target ownership is proved independently when their names are selected.
    """
    require(importer_image is not None and provider_object is not None,
            'data pointer lacks its owned source table or target object')
    require(reference in data_pointer_relocations(importer_image, name),
            'data pointer source reference differs')
    original = static_authority.elf_bytes(importer_image)
    headers = [header for header in original.sections
               if static_authority.section_name(original, header) == reference['section']]
    require(len(headers) == 1, 'data pointer source holder is ambiguous')
    holder = headers[0]
    require(source_payload == importer_image[holder[4]:holder[4] + holder[5]],
            'data pointer source holder payload differs')
    require(len(placement) >= 5 and int(placement[0], 16) == int(placement[1], 16)
            and int(placement[2], 16) == holder[5] and int(placement[3]) == holder[8],
            'data pointer source holder placement differs')
    base, offset = int(placement[0], 16), reference['offset']
    require(base % holder[8] == 0 and offset % 8 == 0 and offset + 8 <= holder[5],
            'data pointer source slot extent differs')
    final = static_authority.elf_bytes(image)
    require(final.elf_type == elf_type, 'data pointer final ELF type differs')
    # The linker can pool an ordinary input with retained writable data.
    # GNU retain changes collection policy, not its read/write permissions.
    outputs = [section for section in final.sections if section[1] == 1 and section[2] in {3, 0x200003}
               and section[3] <= base and base + holder[5] <= section[3] + section[5]
               and section[4] + section[5] <= len(image)]
    require(len(outputs) == 1, 'data pointer final holder extent differs')
    writable_object_mapping(image, address=base, extent=holder[5], output=outputs[0], label='data pointer holder')
    source_image, definition = provider_object
    provider = static_authority.elf_bytes(source_image)
    symbol = provider.symbol(name, dynamic=False)
    row, observed = definition['row'], definition['definition_section']
    require(provider.elf_type == 1 and symbol is not None
            and symbol['type'] == row['type'] == 'OBJECT'
            and symbol['binding'] == row['binding'] == 'GLOBAL'
            and symbol['visibility'] == row['visibility'] == 'HIDDEN'
            and symbol['section'] == int(row['section_index']) == observed['index']
            and symbol['value'] == int(row['value'], 16) and symbol['size'] == row['size_bytes'] > 0
            and 0 < symbol['section'] < len(provider.sections), 'data pointer target source symbol differs')
    header = provider.sections[symbol['section']]
    readonly = header[2] == 2
    require(header[1] == 1 and observed['type'] == 'PROGBITS'
            and (header[2], observed['flags']) == ((2, 'A') if readonly else (3, 'WA'))
            and header[3] == int(observed['address'], 16) and header[4] == int(observed['offset'], 16)
            and header[5] == int(observed['size'], 16) and header[6] == observed['link']
            and header[7] == observed['info'] and header[8] == observed['alignment'] > 0
            and header[9] == int(observed['entry_size'], 16) == 0
            and header[4] + header[5] <= len(source_image) and symbol['value'] + symbol['size'] <= header[5]
            and static_authority.section_name(provider, header) == observed['name'],
            'data pointer target source extent differs')
    addend = reference['pointer_addend']
    require(type(addend) is int and 0 <= addend < symbol['size'], 'data pointer addend leaves target object')
    target = final.symbol(name, dynamic=False)
    require(target is not None and target['type'] == 'OBJECT' and target['binding'] == 'LOCAL'
            and target['visibility'] == 'HIDDEN' and target['value'] == provider_address
            and target['size'] == symbol['size'] and 0 < target['section'] < len(final.sections),
            'data pointer target final symbol differs')
    output = final.sections[target['section']]
    require(output[1] == 1 and (output[2] in {2, 18, 50} if readonly else output[2] in {3, 0x200003})
            and output[3] <= provider_address and provider_address + symbol['size'] <= output[3] + output[5]
            and output[4] + output[5] <= len(image), 'data pointer target final extent differs')
    if readonly:
        immutable_object_payload(image, source_image, symbol=symbol, header=header, output=output,
                                 address=provider_address, name=name)
    else:
        writable_object_mapping(image, address=provider_address, extent=symbol['size'], output=output,
                                label='data pointer target')
    footprint = []
    for relocation in final.sections:
        if relocation[1] not in {4, 9, 19}:
            continue
        require(relocation[1] == 4 and relocation[9] == 24 and relocation[5] % 24 == 0
                and relocation[4] + relocation[5] <= len(image), 'data pointer final relocation encoding differs')
        for position in range(relocation[4], relocation[4] + relocation[5], 24):
            address, info, value = final.unpack('<QQq', position)
            require(info == 8, 'data pointer final relocation type differs')
            if address < base + holder[5] and base < address + 8:
                footprint.append((address, info, value))
    slot = base + offset
    value = struct.unpack('<Q', calls._public_weak_virtual_bytes(image, slot, 8, elf_type, executable=False))[0]
    expected = provider_address + addend
    positions = [position for position, _, _ in footprint]
    require((elf_type == 2 and not footprint and value == expected)
            or (elf_type == 3 and len(positions) == len(set(positions))
                and set(positions) == set(range(base, base + holder[5], 8))
                and (slot, 8, expected) in footprint and value == 0),
            'data pointer final slot or relocation footprint differs')
    return {'section': reference['section'], 'offset': offset, 'slot_address': slot,
            'target_address': expected, 'provider_offset': addend, 'operand_size': 8,
            'branch_kind': 'data-object-pointer'}


def final_member_references(image: bytes, *, archive_member: str, source_calls: list[dict[str, Any]],
                            map_text: str, relocation_text: str, provider_address: int,
                            elf_type: int, name: str, source_sections: Mapping[str, bytes],
                            provider_data: bytes | None = None,
                            provider_object: tuple[bytes, Mapping[str, Any]] | None = None,
                            provider_pool: tuple[Mapping[str, Any], str] | None = None,
                            importer_image: bytes | None = None) -> dict[str, Any]:
    """Bind source instruction operands and data pointer slots to provider owners.

    Register address loads and GOT comparisons prove address binding only.
    They do not assert a later call, register lifetime, comparison outcome,
    reachability or runtime semantics.
    Direct calls retain the existing branch proof and all sites must survive.
    Ordinary data tables require raw named R64 slots and complete source/final
    pointer footprints; an address representation grants no dereference scope.
    Scalar reads require the exact unrelocated bytes and full extent of the
    selected read-only OBJECT; the caller authenticates its source definition.
    They prove initial operand bytes, not execution or later memory contents.
    Integer and packed-vector operands bind the selected object and full
    access extent.
    Ordinary immutable objects also require the complete unrelocated source
    payload in one final read-only mapping; only loads may reference them.
    Pooled byte strings require the selected definition's pool and forcing
    relocation authority before a bounded load or address is admitted. A formed
    one-past address is recorded separately and supplies no memory-read extent.
    Trailing immediate bytes are part of the instruction, not payload
    bytes at a NOBITS target. No execution or subsequent values are asserted.
    Source instruction spans must come from disassembly checked against the
    complete original section bytes; adjacent instructions are not prefixes.
    """
    pooled_string = provider_object is not None and provider_object[1]['definition_section']['flags'] == 'AMS'
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
        if kind == 'R_X86_64_64':
            resolved.append(final_data_pointer(image, reference=reference, placement=parts,
                importer_image=importer_image, source_payload=source, provider_object=provider_object,
                provider_address=provider_address, elf_type=elf_type, name=name))
            continue
        require(len(parts) >= 5 and type(offset) is int and offset >= 1
                and offset + 4 <= len(source) and offset + 4 <= int(parts[2], 16),
                f'provider {name} reference leaves selected section')
        instruction_span = ((reference['instruction_start'], reference['instruction_end'])
                            if 'instruction_start' in reference else None)
        integer = integer_memory_operand(source, offset, instruction_span=instruction_span) if kind == 'R_X86_64_PC32' else None
        if provider_pool is not None or pooled_string:
            require(provider_pool is not None, 'merged string lacks its owned pool translation')
            require(kind == 'R_X86_64_PC32' and instruction_span is not None,
                    f'provider {name} merged string reference lacks its instruction span')
            if integer is None:
                start, end = instruction_span
                prefix = source[start:offset]
                require(start == offset - 3 and end == offset + 4 and prefix[0] in {0x48, 0x4c}
                        and prefix[1] == 0x8d and prefix[2] & 0xc7 == 0x05,
                        f'provider {name} merged string reference is not a supported load or address')
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
            merged = header[1] == 1 and header[2] == 50
            readonly = header[1] == 1 and header[2] in {2, 50}
            require(header[1] in {1, 8} and observed['type'] == ('PROGBITS' if header[1] == 1 else 'NOBITS')
                    and (header[2], observed['flags']) == ((50, 'AMS') if merged else (2, 'A') if readonly else (3, 'WA'))
                    and header[3] == int(observed['address'], 16)
                    and header[4] == int(observed['offset'], 16)
                    and header[5] == int(observed['size'], 16)
                    and header[6] == observed['link'] and header[7] == observed['info']
                    and header[8] == observed['alignment'] and header[8] > 0
                    and header[9] == int(observed['entry_size'], 16) == (1 if merged else 0)
                    and symbol['value'] + symbol['size'] <= header[5]
                    and (header[1] == 8 or header[4] + header[5] <= len(source_image))
                    and static_authority.section_name(original, header) == observed['name'],
                    f'provider {name} integer source extent differs')
            if readonly:
                # Packed-vector loads cover ordinary constants. Pooled string
                # ownership retains its separately bounded scalar-load scope.
                require(operation in {'integer-data-load', 'integer-zero-extend-load', 'vector-data-load'}
                        and (not merged or operation != 'vector-data-load'),
                        f'provider {name} immutable object reference is not a supported load')
                if merged:
                    merged_string_translation(image, elf_type, source_image, definition, provider_address, provider_pool)
                # No relocation table may target this ordinary source section.
                # Its complete payload, including bytes outside the operand,
                # must retain an immutable interpretation after linking.
                require(not any(section[1] in {4, 9, 19} and section[7] == symbol['section']
                                for section in original.sections),
                        f'provider {name} immutable source relocation footprint differs')
            require(0 <= provider_offset and provider_offset + operand_size <= symbol['size'],
                    f'provider {name} integer operand leaves provider object')
            atomic = operation.startswith('locked-') or operation == 'atomic-exchange'
            require(not atomic
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
                    and (not atomic or target % operand_size == 0),
                    f'provider {name} integer operand resolves to a foreign provider')
            final = static_authority.elf_bytes(image)
            final_symbol = final.symbol(name, dynamic=False)
            require(final_symbol is not None and final_symbol['type'] == 'OBJECT'
                    and final_symbol['binding'] == 'LOCAL' and final_symbol['visibility'] == 'HIDDEN'
                    and final_symbol['value'] == provider_address and final_symbol['size'] == symbol['size']
                    and 0 < final_symbol['section'] < len(final.sections),
                    f'provider {name} integer final symbol differs')
            output = final.sections[final_symbol['section']]
            # A linker may combine ordinary constants and mergeable constants
            # in one immutable output section. The source object remains
            # ordinary and its selected member map supplies ownership.
            require(output[1] == header[1] and (output[2] in {2, 18, 50} if readonly else output[2] == 3)
                    and output[3] <= provider_address
                    and provider_address + symbol['size'] <= output[3] + output[5]
                    and (output[1] == 8 or output[4] + output[5] <= len(image)),
                    f'provider {name} integer final extent differs')
            table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
            programs = [struct.unpack_from('<IIQQQQQQ', image, table + width * index) for index in range(count)]
            if readonly:
                immutable_object_payload(image, source_image, symbol=symbol, header=header,
                                         output=output, address=provider_address, name=name)
            else:
                # NOBITS has memory extent but no source or final file payload.
                # Writable operands must lie in one non-executable load image.
                require(sum(program[0] == 1 and program[1] == 6
                            and program[3] <= target and target + operand_size <= program[3] + program[6 if output[1] == 8 else 5]
                            for program in programs) == 1,
                        f'provider {name} integer operand lacks a writable load extent')
                # The complete selected object belongs to one writable,
                # non-executable mapping. An overlapping LOAD cannot offer
                # different permissions or a second interpretation of it.
                writable_object_mapping(image, address=provider_address, extent=symbol['size'], output=output,
                                        label=f'provider {name} integer object')
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
        got_reference = kind in {'R_X86_64_GOTPCREL', 'R_X86_64_REX_GOTPCRELX'}
        if kind == 'R_X86_64_REX_GOTPCRELX':
            require(instruction_span == (offset - 3, offset + 4) and len(prefix) == 3
                    and prefix[0] in {0x48, 0x4c} and prefix[1] == 0x8b
                    and prefix[2] & 0xc7 == 0x05,
                    f'provider {name} relaxable GOT instruction differs')
        address_compare = (len(prefix) == 3 and kind == 'R_X86_64_GOTPCREL'
                           and prefix[0] in {0x48, 0x4c} and prefix[1] == 0x3b
                           and prefix[2] & 0xc7 == 0x05)
        address_load = (len(prefix) == 3 and prefix[0] in {0x48, 0x4c} and prefix[2] & 0xc7 == 0x05
                        and ((got_reference and prefix[1] == 0x8b)
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
        relaxed = (kind == 'R_X86_64_REX_GOTPCRELX'
                   and opcode[:prefix_size] == prefix[:1] + b'\x8d' + prefix[2:])
        require(opcode[:prefix_size] == source[offset - prefix_size:offset] or relaxed,
                f'provider {name} reference opcode differs')
        target = call_address + prefix_size + 4 + struct.unpack_from('<i', opcode, prefix_size)[0]
        record = {'section': section, 'offset': offset, 'call_address': call_address,
                  'target_address': provider_address}
        if got_reference and not relaxed:
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
            object_end = False
            if 'address_addend' in reference or pooled_string and address_load:
                require(address_load and provider_object is not None,
                        f'provider {name} interior address lacks its source object')
                require(instruction_span is not None
                        and instruction_span == (offset - 3, offset + 4),
                        f'provider {name} interior address instruction span differs')
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
                merged = header[1] == 1 and header[2] == 50
                require(header[1] in {1, 8} and observed['type'] == ('PROGBITS' if header[1] == 1 else 'NOBITS')
                        and (header[2], observed['flags']) == ((50, 'AMS') if merged else (3, 'WA'))
                        and header[3] == int(observed['address'], 16)
                        and header[4] == int(observed['offset'], 16)
                        and header[5] == int(observed['size'], 16)
                        and header[6] == observed['link'] and header[7] == observed['info']
                        and header[8] == observed['alignment'] and header[8] > 0
                        and header[9] == int(observed['entry_size'], 16) == (1 if merged else 0)
                        and (header[1] == 8 or header[4] + header[5] <= len(source_image))
                        and symbol['value'] + symbol['size'] <= header[5]
                        and static_authority.section_name(original, header) == observed['name'],
                        f'provider {name} interior source extent differs')
                if merged:
                    merged_string_translation(image, elf_type, source_image, definition, provider_address, provider_pool)
                # PC32 is S + A - P; RIP is four bytes beyond P. LEA forms
                # a bounded address without reading it. A pooled string's exact
                # one-past address is a formed pointer, never a load permission.
                provider_offset = reference.get('address_addend', -4) + 4
                object_end = merged and provider_offset == symbol['size']
                require(0 <= provider_offset and (provider_offset < symbol['size'] or object_end),
                        f'provider {name} interior address leaves provider object')
                final = static_authority.elf_bytes(image)
                final_symbol = final.symbol(name, dynamic=False)
                require(final_symbol is not None and final_symbol['type'] == 'OBJECT'
                        and final_symbol['binding'] == 'LOCAL' and final_symbol['visibility'] == 'HIDDEN'
                        and final_symbol['value'] == provider_address and final_symbol['size'] == symbol['size']
                        and 0 < final_symbol['section'] < len(final.sections),
                        f'provider {name} interior final symbol differs')
                output = final.sections[final_symbol['section']]
                require(output[1] == header[1] and (output[2] in {2, 18, 50} if merged else output[2] == 3)
                        and output[3] <= provider_address
                        and provider_address + symbol['size'] <= output[3] + output[5]
                        and (output[1] == 8 or output[4] + output[5] <= len(image)),
                        f'provider {name} interior final extent differs')
                if merged:
                    immutable_object_payload(image, source_image, symbol=symbol, header=header,
                                             output=output, address=provider_address, name=name)
                if not merged:
                    # NOBITS owns memory extent, never a file payload. Forming
                    # an interior address proves the whole writable object's
                    # placement without granting a read or one-past extent.
                    writable_object_mapping(image, address=provider_address, extent=symbol['size'], output=output,
                                            label=f'provider {name} interior object')
                record['provider_offset'] = provider_offset
                record['target_address'] = provider_address + provider_offset
            require(target == provider_address + provider_offset,
                    f'provider {name} reference resolves to a foreign provider')
            record['branch_kind'] = ('relaxed-got-address-load' if relaxed else
                                     'rip-relative-object-end-address' if object_end else
                                     'rip-relative-address' if address_load else 'conditional-jump')
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
            pointer_object = any(reference['kind'] == 'R_X86_64_64'
                                 for _, references, _ in source_imports for reference in references)
            interior_object = any('address_addend' in reference
                                  for _, references, _ in source_imports for reference in references)
            merged_string = definition['row']['type'] == 'OBJECT' and definition['definition_section']['flags'] == 'AMS'
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
                        and (integer_object or interior_object or pointer_object or merged_string or not view['map_rows'].get(selected + ':(' + definition['definition_section']['name'] + ')'))):
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
                        provider_object=(source_image, definition) if integer_object or interior_object or pointer_object or merged_string else None,
                        provider_pool=(view, selected) if merged_string else None,
                        importer_image=source_members[imported['member_name']][0] if pointer_object else None)
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
