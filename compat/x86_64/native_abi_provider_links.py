#!/usr/bin/env python3
"""Retain complete-function owned links and replay physical archive call targets.

The fixture only takes addresses. Function semantics remain the owning family's
obligation. Every admitted import requires its own complete source relocation
roster and final targets in both static modes; unsupported forms stay open.
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
                   if row['section_index'] != 'UND' and row['type'] == 'FUNC'
                   and row['binding'] in {'GLOBAL', 'WEAK'} and row['size_bytes'] > 0})


def source(names: list[str]) -> str:
    require(names and names == sorted(set(names)), 'provider function roster differs')
    require(all(name and all(character.isalnum() or character in '_.$' for character in name)
                for name in names), 'provider name cannot be emitted as a linker label')
    return (''.join(f'extern void provider_{index}(void) __asm__("{name}");\n'
                    for index, name in enumerate(names))
            + 'static void (*volatile providers[])(void) = {\n'
            + ''.join(f'provider_{index},\n' for index in range(len(names)))
            + '};\nint main(void) {\n'
            + ' for (unsigned long i = 0; i < sizeof providers / sizeof providers[0]; ++i)\n'
            + '  if (!providers[i]) return 1;\n return 0;\n}\n')


def command(static: Path, work: Path, label: str) -> list[str]:
    if label == 'compile':
        return [str(static / 'bin/crabc-cc'), '-static-pie', '-std=c11', '-fno-builtin',
                '-fno-stack-protector', '-c', str(work / 'providers.c'), '-o', str(work / 'providers.o')]
    if label in MODES:
        return [str(static / 'bin/crabc-cc'), '-' + label, '--link-receipt',
                str((work / (label + '.receipt.json')).relative_to(ROOT)),
                str(work / 'providers.o'), '-o', str(work / label)]
    return [str(work / label.removesuffix('-run'))]


def capture(argv: list[str], work: Path, label: str) -> dict[str, Any]:
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False, timeout=120)
    for suffix, content in (('stdout', result.stdout), ('stderr', result.stderr),
                            ('status', f'{result.returncode}\n'.encode())):
        (work / (label + '.' + suffix)).write_bytes(content)
    require(result.returncode == 0, f'provider {label} failed: {result.stderr.decode(errors="replace")}')
    return {'argv': argv, 'streams': {suffix: identity(work / (label + '.' + suffix))
                                    for suffix in ('stdout', 'stderr', 'status')}}


def fixture_object(path: Path, names: list[str]) -> dict[str, Any]:
    """Require every forced pointer to name its exact undefined function row."""
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
    (output / 'providers.c').write_text(source(names), encoding='ascii')
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
    require((work / 'providers.c').read_text(encoding='ascii') == source(roster(facts)),
            'provider fixture no longer represents the complete physical function roster')
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


def project(work: Path, static: Path, accounting: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    retained = validate(work, static, facts)
    archive = static / 'usr/lib/libc.a'
    final = {}
    for mode, elf_type in (('static', 2), ('static-pie', 3)):
        final[mode] = _indexed_view(work, mode, elf_type)
    source_members = {}
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
        if (len(definitions) != 1 or definitions[0]['row']['type'] != 'FUNC'
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
                    with tempfile.TemporaryDirectory(dir=ROOT / '.work/x86_64') as temporary:
                        path = Path(temporary) / 'member.o'
                        path.write_bytes(result.stdout)
                        relocations = read_tool('readelf', '-rW', path)
                    source_members[member] = (result.stdout, relocations)
                image, relocations = source_members[member]
                source_calls = calls._ordinary_import_relocations(relocations, name, image=image)
                source_imports.append((row, source_calls, calls._ordinary_source_sections(
                    image, {item['section'] for item in source_calls})))
            for mode, view in final.items():
                symbol_rows = view['symbol_rows'].get(name, [])
                require(all(row[3] == 'FUNC' and row[6] != 'UND' for row in symbol_rows),
                        'provider final symbol metadata differs')
                symbols = [(int(row[1], 16), int(row[2])) for row in symbol_rows]
                require(len(symbols) == 1 and symbols[0][1] == definition['row']['size_bytes'],
                        'provider final symbol is absent, ambiguous or mismatched')
                address = symbols[0][0]
                selected = calls.mounted_path(archive) + '(' + definition['member_name'] + ')'
                section = definition['definition_section']['name']
                maps = view['map_rows'].get(selected + ':(' + section + ')', [])
                require(view['trace_counts'].get(selected) == 1 and len(maps) == 1
                        and int(maps[0].split()[0], 16) + int(definition['row']['value'], 16) == address,
                        'provider final symbol does not belong to the exact archive definition')
                linked = []
                for imported, source_calls, sections in source_imports:
                    member = calls.mounted_path(archive) + '(' + imported['member_name'] + ')'
                    require(view['trace_counts'].get(member) == 1,
                            'provider importer was not extracted exactly once')
                    map_text, relocation_text = _call_transcripts(view, member, source_calls)
                    result = calls._ordinary_final_member_calls(view['image'], archive_member=member,
                        source_calls=source_calls, map_text=map_text, relocation_text=relocation_text,
                        provider_address=address, elf_type=view['type'], name=name, source_sections=sections)
                    require(result['resolved_calls'] and not result['discarded_calls'],
                            'provider witness does not retain every source call')
                    linked.append({'occurrence_index': imported['index'], 'member_sha256':
                                   hashlib.sha256(source_members[imported['member_name']][0]).hexdigest(), **result})
                proof['links'][mode] = {'provider_address': address, 'importers': linked}
            admitted.append(proof)
        except (ValueError, KeyError, calls.AllocatorBoundaryError) as error:
            failures.append({'identity': record['identity'], 'reason': str(error)})
    require(retained == validate(work, static, facts), 'provider work changed during physical projection')
    return {'retained': retained, 'identities': admitted, 'failures': failures}


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
