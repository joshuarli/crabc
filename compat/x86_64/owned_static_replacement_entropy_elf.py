#!/usr/bin/env python3
"""Bind getentropy's archived getrandom import to the application in each final ELF."""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
from pathlib import Path


def command(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise SystemExit(f'entropy replacement ELF: {detail}')


def file_offset(elf: bytes, address: int) -> int:
    # The final static products are ELF64 little-endian; consult PT_LOAD so
    # both fixed and PIE virtual addresses map to their exact file bytes.
    require(elf[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little-endian')
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', elf, 54)
    for index in range(phnum):
        header = phoff + index * phentsize
        kind = struct.unpack_from('<I', elf, header)[0]
        offset, virtual = struct.unpack_from('<QQ', elf, header + 8)
        # In ELF64 the file size is at byte 32, after p_paddr.
        size = struct.unpack_from('<Q', elf, header + 32)[0]
        if kind == 1 and virtual <= address and address + 8 <= virtual + size:
            return offset + address - virtual
    raise SystemExit(f'entropy replacement ELF: 0x{address:x} is outside file-backed PT_LOAD')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--application', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--map', required=True, type=Path)
    parser.add_argument('--mode', required=True, choices=('static', 'static-pie'))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()

    definitions = command('nm', '-A', '--defined-only', '-g', str(args.archive))
    members = re.findall(r'^.+:([^:]+):[0-9a-fA-F]+ T getentropy$', definitions, re.M)
    require(len(members) == 1, 'expected one archived getentropy definition')
    member = members[0]
    member_bytes = subprocess.run(['ar', 'p', str(args.archive), member],
                                  check=True, capture_output=True).stdout
    member_file = args.report.with_suffix('.member.o')
    member_file.write_bytes(member_bytes)
    relocations = command('readelf', '-rW', str(member_file))
    args.report.with_suffix('.member.relocations').write_text(relocations)
    imports = re.findall(r'^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+'
                         r'(R_X86_64_GOTPCREL(?:X|X_REX)?)\s+.*\bgetrandom\s*-\s*4\s*$',
                         relocations, re.M)
    require(len(imports) == 1, 'getentropy must retain one GOT relocation to getrandom')
    site_offset, relocation_kind = imports[0]

    owner = ''
    getrandom = getentropy = None
    for line in args.map.read_text().splitlines():
        if ':(.' in line:
            owner = line
        symbol = re.search(r'^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s*$', line)
        if symbol and symbol.group(2) == 'getrandom' and f'{args.application}:(.text)' in owner:
            getrandom = int(symbol.group(1), 16)
        if symbol and symbol.group(2) == 'getentropy' and f'libc.a({member}):(.text.getentropy)' in owner:
            getentropy = int(symbol.group(1), 16)
    require(getrandom is not None, 'link map does not attribute getrandom to application')
    require(getentropy is not None, 'link map does not attribute getentropy to archived member')

    symbols = command('readelf', '-sW', str(args.binary))
    strong = re.findall(r'^\s*\d+:\s*([0-9a-fA-F]+)\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+getrandom$', symbols, re.M)
    require(len(strong) == 1 and int(strong[0], 16) == getrandom,
            'final strong getrandom must have the application map address')

    elf = args.binary.read_bytes()
    expected_type = 2 if args.mode == 'static' else 3
    require(struct.unpack_from('<H', elf, 16)[0] == expected_type, 'unexpected final ELF type')
    site = getentropy + int(site_offset, 16)
    displacement = struct.unpack_from('<i', elf, file_offset(elf, site))[0]
    got = site + 4 + displacement
    slot = struct.unpack_from('<Q', elf, file_offset(elf, got))[0]
    disassembly = command('objdump', '-d', '--disassemble=getentropy', str(args.binary))
    args.report.with_suffix('.getentropy.disassembly').write_text(disassembly)
    load = re.search(r'^\s*[0-9a-f]+:.*\bmov\s+.*\(%rip\),%([a-z0-9]+)\s+#\s*' +
                     f'{got:x}' + r'\b', disassembly, re.M)
    require(load is not None and re.search(r'\bcall\s+\*%' + load.group(1) + r'\b', disassembly),
            'getentropy must call through the relocated getrandom GOT load')

    dynamic = command('readelf', '-rW', str(args.binary))
    args.report.with_suffix('.final.relocations').write_text(dynamic)
    relative = re.findall(r'^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+R_X86_64_RELATIVE\s+([0-9a-fA-F]+)\s*$',
                          dynamic, re.M)
    binding = [(int(offset, 16), int(addend, 16)) for offset, addend in relative if int(offset, 16) == got]
    if args.mode == 'static':
        require(slot == getrandom and not binding, 'ET_EXEC GOT must contain the application address')
    else:
        require(slot == 0 and binding == [(got, getrandom)],
                'static PIE GOT must have one RELATIVE relocation to the application address')

    result = {'mode': args.mode, 'archived_member': member, 'source_relocation': {
        'offset': int(site_offset, 16), 'type': relocation_kind, 'symbol': 'getrandom',
    }, 'final_getentropy': getentropy, 'final_getrandom': getrandom,
        'final_relocation_site': site, 'got_slot': got, 'file_slot_value': slot,
        'relative_addend': binding[0][1] if binding else None}
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(f'entropy replacement ELF {args.mode}: application getrandom=0x{getrandom:x}, '
          f'getentropy GOT=0x{got:x}; report: {args.report}')


if __name__ == '__main__':
    main()
