"""Prove finite selected static input functions against retained x86-64 ELF.

Components own the function roster, exact admitted owners, source/final metadata,
link-mode audit, and all source/tool/product admission. This reader only joins
those admitted inputs through the LLD map to their fully relocated final bytes.
It supports the reviewed PC32, PLT32, GOTPCREL, GOTTPOFF and REX_GOTPCRELX forms;
an unclassified input form fails instead of widening the byte relation.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import re

from loader_debug_abi_evidence import Elf


class StaticLinkAuthorityError(ValueError):
    pass


@dataclass(frozen=True)
class StaticFunctionContract:
    """One FUNC's exact traced input owner and required ELF metadata.

    The same name is required in the input and final ELF. A component must
    enumerate aliases and implementation bodies separately when it claims both.
    No owner prefixes, inferred provider policy, or optional rows are admitted.
    """
    name: str
    input_owner: str
    source_binding: str
    source_visibility: str
    final_binding: str
    final_visibility: str


def require(condition, message):
    if not condition:
        raise StaticLinkAuthorityError(message)


def physical(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'unsafe authority path')
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'authority traverses a symlink')
    require(path.is_file(), 'authority is not a regular file')
    return path


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


def _require_static_functions(map_path, executable, admitted, functions):
    """Join ordinary static extraction to the explicitly contracted definitions.

    LLD's map must name an actually traced input member, and each finite
    function keeps its source section, size and fully relocated bytes. The
    finite x86-64 relocations below derive their values from selected input
    definitions and ELF placement; no output instruction field is a mask.
    """
    images = {name: elf_bytes(value) if isinstance(value, bytes) else Elf(value)
              for name, value in admitted.items()}
    final = Elf(executable)
    contracts = {row.name: row for row in functions}
    wanted = set(contracts)
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
    require(set(mapped) == wanted, 'static link map omits a contracted function')
    def selected_symbols(elf, names):
        # Look up the finite names first; Elf.symbol_row then checks their full
        # records and versions. This avoids rescanning every large archive
        # symbol table once per contracted name during each receipt replay.
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
        require(owner == contracts[name].input_owner, 'static function came from the wrong selected object/archive')
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
    require(len(tls_rows) == 1, 'static output lacks a unique TLS segment')
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
        contract = contracts[name]
        require(owner == contract.input_owner, 'static function came from the wrong selected object/archive')
        source = images[owner]
        require(name in source_symbols[owner] and name in final_symbols, 'mapped static function lacks ELF definition')
        before = source_symbols[owner][name]
        after = final_symbols[name]
        require(before['type'] == after['type'] == 'FUNC'
                and before['binding'] == contract.source_binding and after['binding'] == contract.final_binding
                and before['visibility'] == contract.source_visibility and after['visibility'] == contract.final_visibility
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


def require_static_functions(
    map_path: Path,
    executable: Path,
    admitted: Mapping[str, Path | bytes],
    functions: Sequence[StaticFunctionContract],
) -> None:
    """Require every explicit function's admitted input-to-final byte relation.

    ``admitted`` uses exact original trace identities as keys; values are retained
    physical object paths or archive-member bytes already authenticated by the
    component. This function executes no commands and selects no extra inputs.
    Components must independently bind the map/trace, audit the executable's
    static/static-PIE mode, and authenticate source, product and tool identities.
    """
    require(functions and all(isinstance(row, StaticFunctionContract) for row in functions),
            'static function contract roster is empty or invalid')
    require(all(isinstance(row.name, str) and row.name for row in functions), 'invalid static function contract name')
    require(len({row.name for row in functions}) == len(functions), 'duplicate static function contract')
    for row in functions:
        require(isinstance(row.input_owner, str)
                and row.input_owner in admitted, 'static function contract lacks an exact admitted owner')
        require(row.source_binding in ('LOCAL', 'GLOBAL', 'WEAK')
                and row.final_binding in ('LOCAL', 'GLOBAL', 'WEAK')
                and row.source_visibility in ('DEFAULT', 'HIDDEN', 'PROTECTED')
                and row.final_visibility in ('DEFAULT', 'HIDDEN', 'PROTECTED'),
                'invalid static function contract metadata')
    try:
        _require_static_functions(map_path, executable, admitted, functions)
    except (ValueError, OSError, IndexError, KeyError) as error:
        if isinstance(error, StaticLinkAuthorityError):
            raise
        raise StaticLinkAuthorityError(str(error)) from error
