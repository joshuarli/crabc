"""Complete-function links bind archive imports without spelling heuristics."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import sys
import shutil
import subprocess
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


class ProviderLinkAttachmentTests(unittest.TestCase):
    def accounting(self, *, private=False):
        name = 'ordinary_domain_function'
        def row(index, role, member, section, visibility='DEFAULT'):
            return {'index': index, 'artifact_key': 'candidate-static', 'table': '.symtab',
                    'member_name': member, 'member_index': index, 'member_occurrence': 0,
                    'role': role, 'row': {'name': name, 'version': None, 'version_default': False,
                    'type': 'FUNC' if role == 'definition' else 'NOTYPE', 'binding': 'GLOBAL',
                    'visibility': visibility, 'section_index': section, 'size_bytes': 6 if role == 'definition' else 0}}
        ident = selection.identity(name)
        reasons = list(selection.MODULE_PRIVATE_REASONS) if private else [selection.ORDINARY_IMPORT_REASON]
        record = {'identity': ident, 'selection': {'disposition': 'unresolved', 'owner': None} if private else
                  {'disposition': 'public-provider', 'owner': 'reviewed-domain'},
                  'unresolved': reasons, 'expected_placements': []}
        return {'identities': [record], 'occurrences': [row(0, 'definition', 'provider.o', '3'),
                row(1, 'import', 'caller.o', 'UND')], 'placement_joins': [{'identity': ident, 'artifact_key': 'candidate-static',
                'placement_observed': True, 'definition_count': 1, 'occurrence_indices': [0]}],
                'blockers': [{'code': 'identity-unresolved', 'identity': ident, 'reason': reason} for reason in reasons]}

    def proof(self, accounting):
        return {'identities': [{'identity': copy.deepcopy(accounting['identities'][0]['identity']),
            'definition_index': 0, 'import_indices': [1], 'static_modes': ['static', 'static-pie'],
            'physical_provider_and_calls': True}], 'failures': []}

    def attach(self, accounting, proof):
        return selection.attach_provider_links(accounting, proof,
            selection.load_contract(selection.CONTRACT_PATH)['module_private_symbols'], ['provider.o', 'caller.o'])

    def test_default_archive_private_class_needs_physical_both_mode_proof(self):
        accounting = self.accounting(private=True)
        self.assertTrue(self.attach(accounting, self.proof(accounting)))
        self.assertEqual(accounting['identities'][0]['selection']['disposition'], 'private-provider')
        self.assertEqual(accounting['blockers'], [])

    def test_proof_cannot_erase_unrelated_semantics_or_foreign_import(self):
        accounting = self.accounting()
        record = accounting['identities'][0]
        record['unresolved'].append('component runtime semantics')
        self.attach(accounting, self.proof(accounting))
        self.assertEqual(record['unresolved'], ['component runtime semantics'])
        for change in ('foreign importer', 'missing mode', 'missing import', 'missing physical proof'):
            with self.subTest(change=change):
                accounting = self.accounting(private=True)
                proof = self.proof(accounting)
                if change == 'foreign importer': accounting['occurrences'][1]['member_name'] = 'foreign.o'
                elif change == 'missing mode': proof['identities'][0]['static_modes'] = ['static']
                elif change == 'missing import': proof['identities'][0]['import_indices'] = []
                else: proof['identities'][0]['physical_provider_and_calls'] = False
                self.assertEqual(self.attach(accounting, proof), [])
                self.assertTrue(accounting['blockers'])

    def test_shared_public_exposure_does_not_acquire_private_owner(self):
        for symbol_type in ('FUNC', 'OBJECT'):
            with self.subTest(symbol_type=symbol_type):
                accounting = self.accounting(private=True)
                accounting['occurrences'][0]['row']['type'] = symbol_type
                leaked = copy.deepcopy(accounting['occurrences'][0])
                leaked.update(index=2, artifact_key='candidate-shared', table='.dynsym', member_name=None)
                accounting['occurrences'].append(leaked)
                self.assertEqual(self.attach(accounting, self.proof(accounting)), [])
                self.assertTrue(accounting['blockers'])


class ProviderFixtureObjectTests(unittest.TestCase):
    def test_whole_projection_replays_real_definitions_importers_and_unclassified_reads(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            static = work / 'product'
            (static / 'usr/lib').mkdir(parents=True)
            private = work / 'private'
            private.mkdir()
            names = ['domain_body', 'domain_caller', 'domain_scalar']
            (work / 'providers.c').write_text(links.source(names, object_names=['domain_scalar']))
            (work / 'provider.S').write_text(
                '.section .text.domain_body,"ax",@progbits\n.globl domain_body\n.hidden domain_body\n'
                '.type domain_body,@function\ndomain_body: mov $7,%eax; ret\n.size domain_body,.-domain_body\n'
                '.section .rodata.cst8,"aM",@progbits,8\n.balign 8\n'
                '.globl domain_scalar\n.hidden domain_scalar\n.type domain_scalar,@object\n'
                'domain_scalar: .quad 0x123456789abcdef0\n.size domain_scalar,.-domain_scalar\n'
                '.section .note.GNU-stack,"",@progbits\n')
            for read in ('movsd domain_scalar(%rip),%xmm0', 'movq domain_scalar(%rip),%rax'):
                with self.subTest(read=read):
                    (work / 'caller.S').write_text(
                        '.section .text.domain_caller,"ax",@progbits\n.globl domain_caller\n.hidden domain_caller\n'
                        '.hidden domain_body\n.hidden domain_scalar\n.type domain_caller,@function\n'
                        'domain_caller: call domain_body\n' + read + '\nret\n.size domain_caller,.-domain_caller\n'
                        '.section .note.GNU-stack,"",@progbits\n')
                    for source, target in [('provider.S', 'provider.o'), ('caller.S', 'caller.o'),
                                           ('providers.c', 'providers.o')]:
                        subprocess.run([compiler, '-fPIC', '-c', str(work / source), '-o', str(work / target)],
                                       check=True, capture_output=True)
                    archive = static / 'usr/lib/libc.a'
                    subprocess.run(['ar', 'rcs', str(archive), str(work / 'caller.o'), str(work / 'provider.o')],
                                   check=True, capture_output=True)
                    occurrences = []
                    for member in ('caller.o', 'provider.o'):
                        symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / member))
                        sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / member))['sections']
                        for row in symbols[0]['rows']:
                            if row['name'] not in names:
                                continue
                            role = 'import' if row['section_index'] == 'UND' else 'definition'
                            occurrence = {'index': len(occurrences), 'artifact_key': 'candidate-static',
                                          'member_name': member, 'member_occurrence': 0, 'role': role, 'row': row}
                            if role == 'definition':
                                occurrence['definition_section'] = next(
                                    section for section in sections if str(section['index']) == row['section_index'])
                            occurrences.append(occurrence)
                    accounting = {'occurrences': occurrences, 'identities': [
                        {'identity': selection.identity(name), 'selection': {'disposition': 'unresolved'},
                         'unresolved': []} for name in names]}
                    for mode, flag in [('static', '-static'), ('static-pie', '-pie')]:
                        result = subprocess.run([linker, flag, '--no-relax', '-e', 'main', '--trace',
                                                 '-Map=' + str(work / (mode + '.receipt.map')),
                                                 str(work / 'providers.o'), str(archive), '-o', str(work / mode)],
                                                check=True, capture_output=True)
                        (work / (mode + '.receipt.trace')).write_bytes(result.stdout)
                    arguments = dict(mapped_archive=str(archive), forcing_owner=str(work / 'providers.o'),
                                     temporary_parent=private)
                    proof = links.project_references(work, static, accounting, **arguments)
                    admitted = {row['identity']['name']: row for row in proof['identities']}
                    if read.startswith('movsd'):
                        self.assertEqual(set(admitted), set(names))
                        self.assertEqual(proof['failures'], [])
                        for mode in links.MODES:
                            self.assertEqual({site['branch_kind'] for row in proof['identities']
                                for importer in row['links'][mode]['importers'] for site in importer['resolved_calls']},
                                {'call', 'scalar-data-read'})
                            self.assertFalse(any(importer['discarded_calls'] for row in proof['identities']
                                                 for importer in row['links'][mode]['importers']))
                    else:
                        self.assertEqual(set(admitted), {'domain_body', 'domain_caller'})
                        self.assertEqual([row['identity']['name'] for row in proof['failures']], ['domain_scalar'])
                        self.assertIn('source extent differs', proof['failures'][0]['reason'])
                    wrong_owner = links.project_references(work, static, accounting,
                        **{**arguments, 'mapped_archive': str(work / 'unselected.a')})
                    self.assertEqual(wrong_owner['identities'], [])
                    self.assertEqual({row['identity']['name'] for row in wrong_owner['failures']}, set(names))
                    self.assertEqual(list(private.iterdir()), [])

    def test_whole_projection_binds_data_pointer_tables_to_selected_object_addresses(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            static = work / 'product'
            (static / 'usr/lib').mkdir(parents=True)
            private = work / 'private'
            private.mkdir()
            names = ['domain_body', 'domain_caller', 'domain_target']
            (work / 'providers.c').write_text(links.source(names, object_names=['domain_target']))
            for storage, addend, supported in [('data', 0, True), ('data', 8, True),
                    ('rodata', 0, True), ('rodata', 8, True), ('retained-output', 0, True), ('data', 16, False), ('data', -1, False),
                    ('function', 0, False), ('table-gap', 0, False), ('got-table', 0, False)]:
                with self.subTest(storage=storage, addend=addend):
                    (work / 'provider.S').write_text(
                        '.section .text.domain_body,"ax",@progbits\n.globl domain_body\n.hidden domain_body\n'
                        '.type domain_body,@function\ndomain_body: ret\n.size domain_body,.-domain_body\n'
                        + '.section .' + ('text' if storage == 'function' else 'data.rel.ro' if storage == 'retained-output' else 'data' if storage in {'table-gap', 'got-table'} else storage)
                        + '.domain_target,"' + ('ax' if storage == 'function' else 'a' if storage == 'rodata' else 'aw')
                        + '",@progbits\n.balign 8\n.globl domain_target\n.hidden domain_target\n'
                        + '.type domain_target,@' + ('function' if storage == 'function' else 'object') + '\ndomain_target:\n'
                        + ('ret\n' if storage == 'function' else '.quad .Lbytes; .quad 8\n'
                           if storage in {'data', 'table-gap', 'got-table', 'retained-output'} else '.quad 0x1234; .quad 0x5678\n')
                        + '.size domain_target,.-domain_target\n.section .rodata.bytes,"a",@progbits\n.Lbytes: .quad 7\n'
                        + ('.section .data.rel.ro.retained_companion,"awR",@progbits\n.quad 0\n'
                           if storage == 'retained-output' else '')
                        + '.section .note.GNU-stack,"",@progbits\n')
                    (work / 'caller.S').write_text(
                        '.section .text.domain_caller,"ax",@progbits\n.globl domain_caller\n.hidden domain_caller\n'
                        '.hidden domain_body\n.hidden domain_target\n.type domain_caller,@function\n'
                        'domain_caller: call domain_body; ret\n.size domain_caller,.-domain_caller\n'
                        + '.section ' + ('.got' if storage == 'got-table' else '.data.rel.ro.pointer_table') + ',"aw",@progbits\n.balign 8\n'
                        + f'.quad domain_target+({addend}); ' + ('.quad 0\n' if storage == 'table-gap'
                                                                  else f'.quad domain_target+({addend})\n')
                        + '.section .note.GNU-stack,"",@progbits\n')
                    for source, target in [('provider.S', 'provider.o'), ('caller.S', 'caller.o'), ('providers.c', 'providers.o')]:
                        subprocess.run([compiler, '-fPIC', '-c', str(work / source), '-o', str(work / target)],
                                       check=True, capture_output=True)
                    archive = static / 'usr/lib/libc.a'
                    subprocess.run(['ar', 'rcs', str(archive), str(work / 'caller.o'), str(work / 'provider.o')],
                                   check=True, capture_output=True)
                    occurrences = []
                    for member in ('caller.o', 'provider.o'):
                        symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / member))
                        sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / member))['sections']
                        for row in symbols[0]['rows']:
                            if row['name'] not in names:
                                continue
                            role = 'import' if row['section_index'] == 'UND' else 'definition'
                            occurrence = {'index': len(occurrences), 'artifact_key': 'candidate-static',
                                          'member_name': member, 'member_occurrence': 0, 'role': role, 'row': row}
                            if role == 'definition':
                                occurrence['definition_section'] = next(section for section in sections
                                    if str(section['index']) == row['section_index'])
                            occurrences.append(occurrence)
                    accounting = {'occurrences': occurrences, 'identities': [
                        {'identity': selection.identity(name), 'selection': {'disposition': 'unresolved'},
                         'unresolved': []} for name in names]}
                    for mode, flag in [('static', '-static'), ('static-pie', '-pie')]:
                        linked = subprocess.run([linker, flag, '--no-relax', '-e', 'main', '--trace',
                            '-Map=' + str(work / (mode + '.receipt.map')), str(work / 'providers.o'), str(archive),
                            '-o', str(work / mode)], check=True, capture_output=True)
                        (work / (mode + '.receipt.trace')).write_bytes(linked.stdout)
                    if storage == 'retained-output':
                        original = links.static_authority.elf_bytes((work / 'caller.o').read_bytes())
                        self.assertEqual(next(header[2] for header in original.sections
                            if links.static_authority.section_name(original, header) == '.data.rel.ro.pointer_table'), 3)
                        for mode in ['static', 'static-pie']:
                            retained = links.static_authority.elf_bytes((work / mode).read_bytes())
                            self.assertEqual(next(header[2] for header in retained.sections
                                if links.static_authority.section_name(retained, header) == '.data.rel.ro'), 0x200003)
                    arguments = dict(mapped_archive=str(archive), forcing_owner=str(work / 'providers.o'), temporary_parent=private)
                    proof = links.project_references(work, static, accounting, **arguments)
                    admitted = {row['identity']['name']: row for row in proof['identities']}
                    if not supported:
                        self.assertEqual(set(admitted), {'domain_body', 'domain_caller'}, proof['failures'])
                        self.assertEqual([row['identity']['name'] for row in proof['failures']], ['domain_target'])
                        continue
                    self.assertEqual(set(admitted), set(names), proof['failures'])
                    self.assertEqual(proof['failures'], [])
                    definition = next(row for row in occurrences
                        if row['role'] == 'definition' and row['row']['name'] == 'domain_target')
                    caller = (work / 'caller.o').read_bytes()
                    references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                        'domain_target', image=caller, disassembly=links.read_tool('objdump', '-dw', work / 'caller.o'))
                    sections = links.calls._ordinary_source_sections(caller, {row['section'] for row in references})
                    source_object = (work / 'provider.o').read_bytes()
                    for mode, elf_type in [('static', 2), ('static-pie', 3)]:
                        image = (work / mode).read_bytes()
                        address = admitted['domain_target']['links'][mode]['provider_address']
                        reference_arguments = dict(archive_member=str(archive) + '(caller.o)', source_calls=references,
                            map_text=(work / (mode + '.receipt.map')).read_text(),
                            relocation_text=links.read_tool('readelf', '-rW', work / mode), provider_address=address,
                            elf_type=elf_type, name='domain_target', source_sections=sections,
                            provider_object=(source_object, definition), importer_image=caller)
                        bound = links.final_member_references(image, **reference_arguments)
                        self.assertEqual(len(bound['resolved_calls']), 2)
                        self.assertEqual({row['branch_kind'] for row in bound['resolved_calls']}, {'data-object-pointer'})
                        self.assertEqual({row['operand_size'] for row in bound['resolved_calls']}, {8})
                        self.assertEqual({row['target_address'] for row in bound['resolved_calls']}, {address + addend})
                        wrong = copy.deepcopy(definition)
                        wrong['row']['size_bytes'] += 1
                        wrong_reference = copy.deepcopy(references)
                        wrong_reference[0]['pointer_addend'] += 1
                        for altered in [{'provider_object': None}, {'importer_image': None},
                                {'provider_object': (source_object, wrong)}, {'provider_address': address + 1},
                                {'source_calls': wrong_reference}]:
                            with self.assertRaises(ValueError):
                                links.final_member_references(image, **{**reference_arguments, **altered})
                        source = links.static_authority.elf_bytes(caller)
                        table_index, table_header = next((index, header) for index, header in enumerate(source.sections)
                            if links.static_authority.section_name(source, header) == references[0]['section'])
                        relocation = next(header for header in source.sections if header[1] == 4 and header[7] == table_index)
                        changed_source = bytearray(caller)
                        changed_source[table_header[4]] = 1
                        changed_addend = bytearray(caller)
                        struct.pack_into('<q', changed_addend, relocation[4] + 16, addend + 1)
                        body_index = next(index for index in range(source.sections[relocation[6]][5] // 24)
                            if source.symbol_row(relocation[6], index)['name'] == 'domain_body')
                        changed_symbol = bytearray(caller)
                        struct.pack_into('<Q', changed_symbol, relocation[4] + 8, (body_index << 32) | 1)
                        section_table, section_width = struct.unpack_from('<Q', caller, 40)[0], struct.unpack_from('<H', caller, 58)[0]
                        changed_extent = bytearray(caller)
                        struct.pack_into('<Q', changed_extent, section_table + section_width * table_index + 32, 15)
                        for altered_source in [changed_source, changed_addend, changed_symbol, changed_extent]:
                            with self.assertRaises(ValueError):
                                links.final_member_references(image, **{**reference_arguments, 'importer_image': bytes(altered_source)})
                        changed_references = links.data_pointer_relocations(bytes(changed_addend), 'domain_target')
                        with self.assertRaisesRegex(ValueError, 'slot or relocation footprint differs'):
                            links.final_member_references(image, **{**reference_arguments,
                                'importer_image': bytes(changed_addend), 'source_calls': changed_references})
                        target_source = links.static_authority.elf_bytes(source_object)
                        target_symbol = target_source.symbol('domain_target', dynamic=False)
                        target_table, target_width = struct.unpack_from('<Q', source_object, 40)[0], struct.unpack_from('<H', source_object, 58)[0]
                        target_header = target_table + target_width * target_symbol['section']
                        for field, value, encoding in [(4, 8, '<I'), (8, 7, '<Q'), (32, 15, '<Q')]:
                            changed = bytearray(source_object)
                            struct.pack_into(encoding, changed, target_header + field, value)
                            with self.assertRaisesRegex(ValueError, 'target source extent differs'):
                                links.final_member_references(image, **{**reference_arguments, 'provider_object': (bytes(changed), definition)})
                        final = links.static_authority.elf_bytes(image)
                        symbol = final.symbol('domain_target', dynamic=False)
                        final_table, final_width = struct.unpack_from('<Q', image, 40)[0], struct.unpack_from('<H', image, 58)[0]
                        for flags in [7, 19, 0x200007, 0x200403]:
                            changed = bytearray(image)
                            struct.pack_into('<Q', changed, final_table + final_width * symbol['section'] + 8, flags)
                            with self.assertRaises(ValueError):
                                links.final_member_references(bytes(changed), **reference_arguments)
                        changed = bytearray(image)
                        struct.pack_into('<Q', changed, final_table + final_width * symbol['section'] + 32,
                                         address + 15 - final.sections[symbol['section']][3])
                        with self.assertRaisesRegex(ValueError, 'target final extent differs'):
                            links.final_member_references(bytes(changed), **reference_arguments)
                        slot = bound['resolved_calls'][0]['slot_address']
                        program_table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
                        programs = [(program_table + width * index, struct.unpack_from('<IIQQQQQQ', image, program_table + width * index))
                                    for index in range(count)]
                        holder_location, holder_load = next((location, program) for location, program in programs
                            if program[0] == 1 and program[3] <= slot < program[3] + program[5])
                        for flags in [4, 7]:
                            changed = bytearray(image)
                            struct.pack_into('<I', changed, holder_location + 4, flags)
                            with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                links.final_member_references(bytes(changed), **reference_arguments)
                        changed = bytearray(image)
                        struct.pack_into('<Q', changed, holder_location + 32, slot + 7 - holder_load[3])
                        with self.assertRaisesRegex(ValueError, 'writable load extent'):
                            links.final_member_references(bytes(changed), **reference_arguments)
                        readonly_location, _ = next((location, program) for location, program in programs if program[:2] == (1, 4))
                        changed = bytearray(image)
                        struct.pack_into('<Q', changed, readonly_location + 16, slot)
                        with self.assertRaisesRegex(ValueError, 'writable load extent'):
                            links.final_member_references(bytes(changed), **reference_arguments)
                        changed = bytearray(image)
                        struct.pack_into('<Q', changed, holder_location + 8, holder_load[2] + 1)
                        with self.assertRaisesRegex(ValueError, 'writable load extent'):
                            links.final_member_references(bytes(changed), **reference_arguments)
                        changed = bytearray(image)
                        changed[holder_load[2] + slot - holder_load[3]] ^= 1
                        with self.assertRaisesRegex(ValueError, 'slot or relocation footprint differs'):
                            links.final_member_references(bytes(changed), **reference_arguments)
                        if elf_type == 3:
                            relative = next(header for header in final.sections if header[1] == 4
                                and any(final.unpack('<Q', position)[0] == slot
                                        for position in range(header[4], header[4] + header[5], 24)))
                            position = next(position for position in range(relative[4], relative[4] + relative[5], 24)
                                            if final.unpack('<Q', position)[0] == slot)
                            for field, value, encoding in [(0, slot + 4, '<Q'), (8, 1, '<Q'), (16, address + addend + 1, '<q')]:
                                changed = bytearray(image)
                                struct.pack_into(encoding, changed, position + field, value)
                                with self.assertRaises(ValueError):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                    self.assertEqual(list(private.iterdir()), [])

    def test_whole_projection_binds_observed_integer_memory_operands(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            static = work / 'product'
            (static / 'usr/lib').mkdir(parents=True)
            private = work / 'private'
            private.mkdir()
            names = ['domain_body', 'domain_caller', 'domain_scalar']
            (work / 'providers.c').write_text(links.source(names, object_names=['domain_scalar']))
            cases = [('bss', 17, 'movdqu domain_scalar(%rip),%xmm0; movdqu %xmm0,domain_scalar(%rip)', True),
                     ('data', 16, 'movdqu domain_scalar(%rip),%xmm7; movdqu %xmm7,domain_scalar(%rip)', True),
                     ('bss', 17, 'movdqu domain_scalar+1(%rip),%xmm1', True),
                     ('data', 17, 'mov $0x66000000,%eax; movdqu %xmm1,domain_scalar(%rip)', True),
                     ('bss', 16, 'mov $0xf3000000,%eax; movdqu domain_scalar(%rip),%xmm0', True),
                     ('rodata', 17, 'movdqu domain_scalar(%rip),%xmm0', True),
                     ('rodata', 17, 'movdqu domain_scalar+1(%rip),%xmm7', True),
                     ('rodata', 16, 'movdqu %xmm0,domain_scalar(%rip)', False),
                     ('bss', 15, 'movdqu domain_scalar(%rip),%xmm0', False),
                     ('bss', 17, 'movdqu domain_scalar+2(%rip),%xmm0', False),
                     ('bss', 16, 'movdqa domain_scalar(%rip),%xmm0', False),
                     ('bss', 16, 'movdqu %fs:domain_scalar(%rip),%xmm0', False),
                     ('bss', 16, 'addr32 movdqu domain_scalar(%eip),%xmm0', False),
                     ('bss', 16, 'movdqu domain_scalar(%rip),%xmm8', False),
                     ('bss', 16, 'vmovdqu domain_scalar(%rip),%xmm0', False),
                     ('bss', 32, 'vmovdqu domain_scalar(%rip),%ymm0', False),
                     ('bss', 8, 'movq domain_scalar(%rip),%xmm0', False),
                     ('rodata-reloc', 16, 'movdqu domain_scalar(%rip),%xmm0', False),
                     ('rodata-merge', 16, 'movdqu domain_scalar(%rip),%xmm0', False),
                     ('rodata-string', 16, 'movdqu domain_scalar(%rip),%xmm0', False),
                     ('bss', 1, 'mov %al,domain_scalar(%rip)', True),
                     ('bss', 8, 'mov %al,domain_scalar(%rip)', True),
                     ('data', 1, 'mov %cl,domain_scalar(%rip)', True),
                     ('bss', 1, 'mov $0x66000000,%eax; mov %al,domain_scalar(%rip)', True),
                     ('bss', 1, 'mov %al,domain_scalar+1(%rip)', False),
                     ('rodata', 1, 'mov %al,domain_scalar(%rip)', False),
                     ('bss', 1, 'mov %al,%fs:domain_scalar(%rip)', False),
                     ('bss', 1, 'addr32 mov %al,domain_scalar(%eip)', False),
                     ('bss', 1, 'mov %r8b,domain_scalar(%rip)', False),
                     ('bss', 4, 'mov domain_scalar(%rip),%r8d; mov domain_scalar(%rip),%r9d; '
                                 'mov domain_scalar(%rip),%r12d', True),
                     ('data', 4, 'mov $0xf3000000,%eax; mov domain_scalar(%rip),%r12d', True),
                     ('bss', 8, 'mov domain_scalar+4(%rip),%r9d', True),
                     ('bss', 8, 'mov domain_scalar+5(%rip),%r9d', False),
                     ('rodata', 4, 'mov domain_scalar(%rip),%r9d', True),
                     ('bss', 4, 'mov %r9d,domain_scalar(%rip)', True),
                     ('bss', 4, 'mov %fs:domain_scalar(%rip),%r9d', False),
                     ('bss', 4, 'addr32 mov domain_scalar(%eip),%r9d', False),
                     ('bss', 1, 'movzbl domain_scalar(%rip),%eax; movzbl domain_scalar(%rip),%r9d', True),
                     ('data', 1, 'movzbl domain_scalar(%rip),%ecx', True),
                     ('bss', 1, 'test %eax,%eax; jz 1f; movzbl domain_scalar(%rip),%ecx; '
                                  '.space 39,0x90; 1:', True),
                     ('bss', 1, 'test %eax,%eax; jz 1f; movzbl domain_scalar(%rip),%r9d; '
                                  '.space 92,0x90; 1:', True),
                     ('bss', 56, 'movzbl domain_scalar+55(%rip),%r9d', True),
                     ('bss', 1, 'movzbl domain_scalar+1(%rip),%eax', False),
                     ('bss', 2, 'movzwl domain_scalar(%rip),%eax', True),
                     ('bss', 1, 'movzbw domain_scalar(%rip),%ax', False),
                     ('bss', 1, 'movzbq domain_scalar(%rip),%rax', False),
                     ('bss', 1, 'test %eax,%eax; jo 1f; movzbl %fs:domain_scalar(%rip),%eax; '
                                  '.space 108,0x90; 1:', False),
                     ('bss', 1, 'addr32 movzbl domain_scalar(%eip),%eax', False),
                     ('bss', 4, 'mov domain_scalar(%rip),%ecx; mov %edx,domain_scalar(%rip); '
                                 'or domain_scalar(%rip),%eax; movl $0,domain_scalar(%rip); '
                                 'lock subl $0x80000001,domain_scalar(%rip)', True),
                     ('data', 4, 'mov domain_scalar(%rip),%ecx; mov %edx,domain_scalar(%rip); '
                                  'or domain_scalar(%rip),%eax; movl $0,domain_scalar(%rip); '
                                  'lock subl $0x80000001,domain_scalar(%rip)', True),
                     ('bss', 4, 'mov $0x66000000,%eax; mov domain_scalar(%rip),%ecx; '
                                  'mov $0x40000000,%eax; mov %edx,domain_scalar(%rip); '
                                  'or domain_scalar(%rip),%eax; '
                                  'mov $0xf2000000,%eax; movl $0,domain_scalar(%rip); '
                                  'mov $0x66000000,%eax; lock subl $0x80000001,domain_scalar(%rip)', True),
                     ('bss', 8, 'mov $0x66000000,%eax; mov domain_scalar(%rip),%rcx; '
                                  'mov $0xf3000000,%eax; mov %r9,domain_scalar(%rip)', True),
                     ('bss', 8, 'mov domain_scalar(%rip),%rcx; mov %r9,domain_scalar(%rip)', True),
                     ('data', 8, 'mov domain_scalar(%rip),%r9; mov %rdx,domain_scalar(%rip)', True),
                     ('bss', 56, 'mov domain_scalar+48(%rip),%r9', True),
                     ('bss', 56, 'mov domain_scalar+49(%rip),%r9', False),
                     ('rodata', 1, 'movzbl domain_scalar(%rip),%eax', True),
                     ('rodata', 8, 'mov domain_scalar(%rip),%rax', True),
                     ('rodata', 9, 'movzbl domain_scalar+8(%rip),%eax', True),
                     ('rodata', 12, 'mov domain_scalar+8(%rip),%ecx', True),
                     ('rodata', 14, 'mov domain_scalar+6(%rip),%rax', True),
                     ('rodata', 8, 'mov %rax,domain_scalar(%rip)', False),
                     ('rodata', 4, 'movl $0,domain_scalar(%rip)', False),
                     ('rodata-reloc', 8, 'mov domain_scalar(%rip),%rax', False),
                     ('rodata-merge', 8, 'mov domain_scalar(%rip),%rax', False),
                     ('bss', 4, 'add domain_scalar(%rip),%eax', False),
                     ('bss', 4, 'movw domain_scalar(%rip),%cx', False),
                     ('bss', 8, 'addr32 mov domain_scalar(%eip),%rcx', False),
                     ('bss', 4, 'subl $0x80000001,domain_scalar(%rip)', False)]
            for storage, size, read, supported in cases:
                with self.subTest(storage=storage, size=size, read=read):
                    (work / 'provider.S').write_text(
                        '.section .text.domain_body,"ax",@progbits\n.globl domain_body\n.hidden domain_body\n'
                        '.type domain_body,@function\ndomain_body: mov $7,%eax; ret\n.size domain_body,.-domain_body\n'
                        + '.section .' + storage + '.domain_scalar,"'
                        + ('aMS' if storage == 'rodata-string' else 'aM' if storage == 'rodata-merge' else 'a' if storage.startswith('rodata') else 'aw')
                        + '",@' + ('nobits' if storage == 'bss' else 'progbits')
                        + (',1' if storage == 'rodata-string' else ',8' if storage == 'rodata-merge' else '')
                        + '\n.balign ' + str(min(size, 8))
                        + '\n.globl domain_scalar\n.hidden domain_scalar\n.type domain_scalar,@object\n'
                        + 'domain_scalar: ' + ('.fill ' + str(size - 1) + ',1,0x5a; .byte 0' if storage == 'rodata-string' else '.fill ' + str(size) + ',1,0x5a' if storage.startswith('rodata') else '.zero ' + str(size))
                        + '\n.size domain_scalar,.-domain_scalar\n'
                        + ('.reloc domain_scalar,R_X86_64_NONE,0\n' if storage == 'rodata-reloc' else '')
                        + ('.section .rodata.str1.1,"aMS",@progbits,1\n.asciz "merged companion"\n'
                           if storage == 'rodata' else '')
                        + '.section .note.GNU-stack,"",@progbits\n')
                    (work / 'caller.S').write_text(
                        '.section .text.domain_caller,"ax",@progbits\n.globl domain_caller\n.hidden domain_caller\n'
                        '.hidden domain_body\n.hidden domain_scalar\n.type domain_caller,@function\n'
                        'domain_caller: call domain_body\n' + read + '\nret\n.size domain_caller,.-domain_caller\n'
                        '.section .note.GNU-stack,"",@progbits\n')
                    for source, target in [('provider.S', 'provider.o'), ('caller.S', 'caller.o'),
                                           ('providers.c', 'providers.o')]:
                        subprocess.run([compiler, '-fPIC', '-c', str(work / source), '-o', str(work / target)],
                                       check=True, capture_output=True)
                    archive = static / 'usr/lib/libc.a'
                    subprocess.run(['ar', 'rcs', str(archive), str(work / 'caller.o'), str(work / 'provider.o')],
                                   check=True, capture_output=True)
                    occurrences = []
                    for member in ('caller.o', 'provider.o'):
                        symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / member))
                        sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / member))['sections']
                        for row in symbols[0]['rows']:
                            if row['name'] not in names:
                                continue
                            role = 'import' if row['section_index'] == 'UND' else 'definition'
                            occurrence = {'index': len(occurrences), 'artifact_key': 'candidate-static',
                                          'member_name': member, 'member_occurrence': 0, 'role': role, 'row': row}
                            if role == 'definition':
                                occurrence['definition_section'] = next(
                                    section for section in sections if str(section['index']) == row['section_index'])
                            occurrences.append(occurrence)
                    accounting = {'occurrences': occurrences, 'identities': [
                        {'identity': selection.identity(name), 'selection': {'disposition': 'unresolved'},
                         'unresolved': []} for name in names]}
                    for mode, flag in [('static', '-static'), ('static-pie', '-pie')]:
                        result = subprocess.run([linker, flag, '--no-relax', '-e', 'main', '--trace',
                                                 '-Map=' + str(work / (mode + '.receipt.map')),
                                                 str(work / 'providers.o'), str(archive), '-o', str(work / mode)],
                                                check=True, capture_output=True)
                        (work / (mode + '.receipt.trace')).write_bytes(result.stdout)
                    arguments = dict(mapped_archive=str(archive), forcing_owner=str(work / 'providers.o'),
                                     temporary_parent=private)
                    proof = links.project_references(work, static, accounting, **arguments)
                    admitted = {row['identity']['name']: row for row in proof['identities']}
                    if supported:
                        vector = 'movdqu' in read
                        byte_store = 'mov %al,' in read or 'mov %cl,' in read
                        rex_load = any(register in read for register in ('%r8d', '%r9d', '%r12d'))
                        self.assertEqual(set(admitted), set(names), proof['failures'])
                        self.assertEqual(proof['failures'], [])
                        for mode in links.MODES:
                            self.assertTrue(all(site['operand_size'] == (16 if vector else 2 if 'movzwl' in read else 1 if 'movzbl' in read or byte_store else 4 if rex_load or size == 4 or storage == 'rodata' and size == 12 else 8)
                                for importer in admitted['domain_scalar']['links'][mode]['importers']
                                for site in importer['resolved_calls']))
                            self.assertFalse(any(importer['discarded_calls'] for row in proof['identities']
                                                 for importer in row['links'][mode]['importers']))
                        definition = next(row for row in occurrences
                                          if row['role'] == 'definition' and row['row']['name'] == 'domain_scalar')
                        caller = (work / 'caller.o').read_bytes()
                        references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                              'domain_scalar', image=caller, disassembly=links.read_tool('objdump', '-dw', work / 'caller.o'))
                        self.assertTrue(all(row['instruction_start'] < row['offset']
                            and row['offset'] + 4 <= row['instruction_end'] for row in references))
                        if 'movzbl' in read:
                            with self.assertRaisesRegex(ValueError, 'instruction boundaries are required'):
                                links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                    'domain_scalar', image=caller)
                            disassembly = links.read_tool('objdump', '-dw', work / 'caller.o')
                            for corrupted in [disassembly.replace('0f b6', '0f b7', 1),
                                    '\n'.join(line for line in disassembly.splitlines()
                                              if 'movzbl' not in line)]:
                                with self.assertRaisesRegex(ValueError, 'disassembly bytes differ|instruction span is absent'):
                                    links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                        'domain_scalar', image=caller, disassembly=corrupted)
                        sections = links.calls._ordinary_source_sections(caller, {row['section'] for row in references})
                        source_object = (work / 'provider.o').read_bytes()
                        for mode, elf_type in [('static', 2), ('static-pie', 3)]:
                            image = (work / mode).read_bytes()
                            address = admitted['domain_scalar']['links'][mode]['provider_address']
                            reference_arguments = dict(archive_member=str(archive) + '(caller.o)', source_calls=references,
                                map_text=(work / (mode + '.receipt.map')).read_text(),
                                relocation_text=links.read_tool('readelf', '-rW', work / mode), provider_address=address,
                                elf_type=elf_type, name='domain_scalar', source_sections=sections,
                                provider_object=(source_object, definition))
                            bound = links.final_member_references(image, **reference_arguments)
                            expected_operations = ({'vector-data-load', 'vector-data-store'} if vector and 'movdqu domain' in read and 'movdqu %' in read else {'vector-data-store'} if vector and 'movdqu %' in read else {'vector-data-load'} if vector else {'integer-data-store'} if byte_store else {'integer-data-store'} if 'mov %r9d,' in read else {'integer-data-load'} if rex_load and 'movzbl' not in read else {'integer-zero-extend-load'} if 'movzbl' in read or 'movzwl' in read else {'integer-data-load'} if storage == 'rodata' else {'integer-data-load', 'integer-data-store', 'integer-data-or',
                                'integer-immediate-store', 'locked-subtract'} if size == 4 else
                                {'integer-data-load', 'integer-data-store'} if size == 8 else {'integer-data-load'})
                            self.assertEqual({row['branch_kind'] for row in bound['resolved_calls']}, expected_operations)
                            self.assertEqual({row['target_address'] for row in bound['resolved_calls']},
                                             {address + (1 if vector and 'domain_scalar+1(' in read else 4 if 'domain_scalar+4(' in read else 8 if storage == 'rodata' and size in {9, 12} else 6 if storage == 'rodata' and size == 14 else 55 if size == 56 and 'movzbl' in read else 48 if size == 56 else 0)})
                            if vector or byte_store or rex_load and 'movzbl' not in read:
                                missing_spans = [{key: value for key, value in reference.items()
                                                  if key not in {'instruction_start', 'instruction_end'}}
                                                 for reference in references]
                                with self.assertRaises(ValueError):
                                    links.final_member_references(image, **{**reference_arguments,
                                        'source_calls': missing_spans})
                            wrong = copy.deepcopy(definition)
                            wrong['row']['size_bytes'] += 1
                            wrong_references = copy.deepcopy(references)
                            wrong_references[0]['operand_addend'] += 1
                            wrong_spans = copy.deepcopy(references)
                            wrong_spans[0]['instruction_end'] += 1
                            for altered, message in [({'provider_object': None}, 'lacks its source object'),
                                    ({'provider_object': (source_object, wrong)}, 'source symbol differs'),
                                    ({'provider_address': address + 1}, 'foreign provider'),
                                    ({'source_calls': wrong_spans}, 'reference opcode differs'),
                                    ({'source_calls': wrong_references}, 'leaves provider object|foreign provider')]:
                                with self.assertRaisesRegex(ValueError, message):
                                    links.final_member_references(image, **{**reference_arguments, **altered})
                            program_table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
                            headers = [struct.unpack_from('<IIQQQQQQ', image, program_table + width * index)
                                       for index in range(count)]
                            if storage != 'rodata' and (vector or byte_store or rex_load and 'movzbl' not in read):
                                writable_index = next(index for index, segment in enumerate(headers)
                                    if segment[0] == 1 and segment[1] == 6
                                    and segment[3] <= address < segment[3] + segment[6])
                                writable = headers[writable_index]
                                for flags in [4, 7]:
                                    changed = bytearray(image)
                                    struct.pack_into('<I', changed, program_table + width * writable_index + 4, flags)
                                    with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                                readonly_index = next(index for index, segment in enumerate(headers)
                                                      if segment[0] == 1 and segment[1] == 4)
                                changed = bytearray(image)
                                struct.pack_into('<Q', changed, program_table + width * readonly_index + 16, address)
                                with self.assertRaisesRegex(ValueError, 'exclusive writable load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                                if byte_store and size == 8 or vector and size == 17 and 'domain_scalar+1(' not in read:
                                    changed = bytearray(image)
                                    struct.pack_into('<Q', changed, program_table + width * writable_index + 40,
                                                     address + (16 if vector else 1) - writable[3])
                                    with self.assertRaisesRegex(ValueError, 'exclusive writable load extent'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                                if storage == 'data':
                                    changed = bytearray(image)
                                    struct.pack_into('<Q', changed, program_table + width * writable_index + 8,
                                                     writable[2] + 1)
                                    with self.assertRaisesRegex(ValueError, 'exclusive writable load extent'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                            if storage == 'rodata':
                                immutable_index = next(index for index, segment in enumerate(headers)
                                    if segment[0] == 1 and segment[1] == 4
                                    and segment[3] <= address and address + size <= segment[3] + segment[5])
                                segment = headers[immutable_index]
                                changed = bytearray(image)
                                changed[segment[2] + address - segment[3] + (16 if vector and size == 17 and 'domain_scalar+1(' not in read else 0)] ^= 1
                                with self.assertRaisesRegex(ValueError, 'immutable payload differs'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                                changed = bytearray(image)
                                struct.pack_into('<I', changed, program_table + width * immutable_index + 4, 6)
                                with self.assertRaisesRegex(ValueError, 'read-only load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                                writable_index = next(index for index, segment in enumerate(headers)
                                    if segment[0] == 1 and segment[1] == 6)
                                changed = bytearray(image)
                                struct.pack_into('<Q', changed, program_table + width * writable_index + 16, address)
                                with self.assertRaisesRegex(ValueError, 'read-only load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                                final = links.static_authority.elf_bytes(image)
                                for relocation in final.sections:
                                    if relocation[1] != 4 or not relocation[2] & 2 or not relocation[5]:
                                        continue
                                    changed = bytearray(image)
                                    struct.pack_into('<Q', changed, relocation[4], address)
                                    with self.assertRaisesRegex(ValueError, 'immutable final relocation footprint differs'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                                    section_table = struct.unpack_from('<Q', image, 40)[0]
                                    section_width = struct.unpack_from('<H', image, 58)[0]
                                    struct.pack_into('<Q', changed,
                                        section_table + section_width * final.sections.index(relocation) + 8, 0)
                                    with self.assertRaisesRegex(ValueError, 'immutable final relocation footprint differs'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                            for site in bound['resolved_calls']:
                                code = site['call_address']
                                executable = next(segment for segment in headers
                                                  if segment[0] == 1 and segment[3] <= code < segment[3] + segment[5])
                                location = executable[2] + code - executable[3]
                                reference = next(reference for reference in references if reference['offset'] == site['offset'])
                                for opcode_byte in range(reference['offset'] - reference['instruction_start']):
                                    changed = bytearray(image)
                                    changed[location + opcode_byte] ^= 1
                                    with self.assertRaisesRegex(ValueError, 'opcode differs'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                                if site['branch_kind'] in {'integer-immediate-store', 'locked-subtract'}:
                                    changed = bytearray(image)
                                    changed[location + (10 if site['branch_kind'] == 'locked-subtract' else 9)] ^= 1
                                    with self.assertRaisesRegex(ValueError, 'opcode differs'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                    else:
                        self.assertEqual(set(admitted), {'domain_body', 'domain_caller'})
                        self.assertEqual([row['identity']['name'] for row in proof['failures']], ['domain_scalar'])
                        self.assertTrue(proof['failures'][0]['reason'])
                        if storage == 'rodata-string':
                            self.assertIn('immutable object reference is not a supported load', proof['failures'][0]['reason'])
                        if storage == 'rodata-reloc':
                            self.assertIn('immutable source relocation footprint differs', proof['failures'][0]['reason'])
                    wrong_owner = links.project_references(work, static, accounting,
                        **{**arguments, 'mapped_archive': str(work / 'unselected.a')})
                    self.assertEqual(wrong_owner['identities'], [])
                    self.assertEqual({row['identity']['name'] for row in wrong_owner['failures']}, set(names))
                    self.assertEqual(list(private.iterdir()), [])

    def test_whole_projection_binds_interior_lea_to_selected_writable_object(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            static = work / 'product'
            (static / 'usr/lib').mkdir(parents=True)
            private = work / 'private'
            private.mkdir()
            names = ['domain_body', 'domain_caller', 'domain_scalar']
            (work / 'providers.c').write_text(links.source(names, object_names=['domain_scalar']))
            for storage, read in ((storage, read) for storage in ('data', 'bss') for read in ('lea domain_scalar+4(%rip),%rax', 'lea domain_scalar+127(%rip),%r9',
                         'lea domain_scalar+128(%rip),%rax', 'lea domain_scalar-1(%rip),%rax',
                         'add domain_scalar+4(%rip),%rax', 'addr32 lea domain_scalar+4(%eip),%rax')):
                with self.subTest(storage=storage, read=read):
                    (work / 'provider.S').write_text(
                        '.section .text.domain_body,"ax",@progbits\n.globl domain_body\n.hidden domain_body\n'
                        '.type domain_body,@function\ndomain_body: mov $7,%eax; ret\n.size domain_body,.-domain_body\n'
                        f'.section .{storage}.domain_scalar,"aw",@{"nobits" if storage == "bss" else "progbits"}\n.balign 4\n'
                        '.globl domain_scalar\n.hidden domain_scalar\n.type domain_scalar,@object\n'
                        'domain_scalar: .zero 128\n.size domain_scalar,.-domain_scalar\n'
                        '.section .note.GNU-stack,"",@progbits\n')

                    (work / 'caller.S').write_text(
                        '.section .text.domain_caller,"ax",@progbits\n.globl domain_caller\n.hidden domain_caller\n'
                        '.hidden domain_body\n.hidden domain_scalar\n.type domain_caller,@function\n'
                        'domain_caller: call domain_body\n' + read + '\nret\n.size domain_caller,.-domain_caller\n'
                        '.section .note.GNU-stack,"",@progbits\n')
                    for source, target in [('provider.S', 'provider.o'), ('caller.S', 'caller.o'),
                                           ('providers.c', 'providers.o')]:
                        subprocess.run([compiler, '-fPIC', '-c', str(work / source), '-o', str(work / target)],
                                       check=True, capture_output=True)
                    archive = static / 'usr/lib/libc.a'
                    subprocess.run(['ar', 'rcs', str(archive), str(work / 'caller.o'), str(work / 'provider.o')],
                                   check=True, capture_output=True)
                    occurrences = []
                    for member in ('caller.o', 'provider.o'):
                        symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / member))
                        sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / member))['sections']
                        for row in symbols[0]['rows']:
                            if row['name'] not in names:
                                continue
                            role = 'import' if row['section_index'] == 'UND' else 'definition'
                            occurrence = {'index': len(occurrences), 'artifact_key': 'candidate-static',
                                          'member_name': member, 'member_occurrence': 0, 'role': role, 'row': row}
                            if role == 'definition':
                                occurrence['definition_section'] = next(
                                    section for section in sections if str(section['index']) == row['section_index'])
                            occurrences.append(occurrence)
                    accounting = {'occurrences': occurrences, 'identities': [
                        {'identity': selection.identity(name), 'selection': {'disposition': 'unresolved'},
                         'unresolved': []} for name in names]}
                    for mode, flag in [('static', '-static'), ('static-pie', '-pie')]:
                        result = subprocess.run([linker, flag, '--no-relax', '-e', 'main', '--trace',
                                                 '-Map=' + str(work / (mode + '.receipt.map')),
                                                 str(work / 'providers.o'), str(archive), '-o', str(work / mode)],
                                                check=True, capture_output=True)
                        (work / (mode + '.receipt.trace')).write_bytes(result.stdout)
                    arguments = dict(mapped_archive=str(archive), forcing_owner=str(work / 'providers.o'),
                                     temporary_parent=private)
                    proof = links.project_references(work, static, accounting, **arguments)
                    admitted = {row['identity']['name']: row for row in proof['identities']}
                    if read in {'lea domain_scalar+4(%rip),%rax', 'lea domain_scalar+127(%rip),%r9'}:
                        self.assertEqual(set(admitted), set(names), proof['failures'])
                        self.assertEqual(proof['failures'], [])
                        for mode in links.MODES:
                            self.assertEqual({site['branch_kind'] for row in proof['identities']
                                for importer in row['links'][mode]['importers'] for site in importer['resolved_calls']},
                                {'call', 'rip-relative-address'})
                            self.assertFalse(any(importer['discarded_calls'] for row in proof['identities']
                                                 for importer in row['links'][mode]['importers']))
                        definition = next(row for row in occurrences
                                          if row['role'] == 'definition' and row['row']['name'] == 'domain_scalar')
                        caller = (work / 'caller.o').read_bytes()
                        references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                              'domain_scalar', image=caller, disassembly=links.read_tool('objdump', '-dw', work / 'caller.o'))
                        sections = links.calls._ordinary_source_sections(caller, {row['section'] for row in references})
                        source_object = (work / 'provider.o').read_bytes()
                        for mode, elf_type in [('static', 2), ('static-pie', 3)]:
                            image = (work / mode).read_bytes()
                            address = admitted['domain_scalar']['links'][mode]['provider_address']
                            reference_arguments = dict(archive_member=str(archive) + '(caller.o)', source_calls=references,
                                map_text=(work / (mode + '.receipt.map')).read_text(),
                                relocation_text=links.read_tool('readelf', '-rW', work / mode), provider_address=address,
                                elf_type=elf_type, name='domain_scalar', source_sections=sections,
                                provider_object=(source_object, definition))
                            bound = links.final_member_references(image, **reference_arguments)
                            expected_offset = 4 if '%rax' in read else 127
                            self.assertEqual(bound['resolved_calls'][0]['provider_offset'], expected_offset)
                            self.assertEqual(bound['resolved_calls'][0]['target_address'], address + expected_offset)
                            missing_spans = [{key: value for key, value in reference.items()
                                              if key not in {'instruction_start', 'instruction_end'}}
                                             for reference in references]
                            for reference_set in [missing_spans,
                                    [{**references[0], 'instruction_start': references[0]['instruction_start'] - 1}]]:
                                with self.assertRaisesRegex(ValueError, 'instruction span differs'):
                                    links.final_member_references(image, **{**reference_arguments, 'source_calls': reference_set})
                            wrong = copy.deepcopy(definition)
                            wrong['row']['size_bytes'] = 4
                            wrong_references = copy.deepcopy(references)
                            wrong_references[0]['address_addend'] += 1
                            for altered, message in [({'provider_object': None}, 'lacks its source object'),
                                    ({'provider_object': (source_object, wrong)}, 'source symbol differs'),
                                    ({'provider_address': address + 1}, 'final symbol differs'),
                                    ({'source_calls': wrong_references}, 'leaves provider object|foreign provider')]:
                                with self.assertRaisesRegex(ValueError, message):
                                    links.final_member_references(image, **{**reference_arguments, **altered})
                            original = links.static_authority.elf_bytes(source_object)
                            source_symbol = original.symbol('domain_scalar', dynamic=False)
                            section_table, section_width = struct.unpack_from('<Q', source_object, 40)[0], struct.unpack_from('<H', source_object, 58)[0]
                            source_header = section_table + section_width * source_symbol['section']
                            for field, value, encoding in [(4, 1 if storage == 'bss' else 8, '<I'), (8, 2, '<Q'), (32, 127, '<Q')]:
                                changed_source = bytearray(source_object)
                                struct.pack_into(encoding, changed_source, source_header + field, value)
                                with self.assertRaisesRegex(ValueError, 'source extent differs'):
                                    links.final_member_references(image, **{**reference_arguments,
                                        'provider_object': (bytes(changed_source), definition)})
                            program_table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
                            load_location, load = next((program_table + width * index, program)
                                for index in range(count)
                                for program in [struct.unpack_from('<IIQQQQQQ', image, program_table + width * index)]
                                if program[0] == 1 and program[3] <= address < program[3] + program[6])
                            for flags, file_size in [(4, load[6] if storage == 'bss' else load[5]), (7, load[6] if storage == 'bss' else load[5]), (6, address + 127 - load[3])]:
                                changed = bytearray(image)
                                struct.pack_into('<I', changed, load_location + 4, flags)
                                struct.pack_into('<Q', changed, load_location + (40 if storage == 'bss' else 32), file_size)
                                with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                            readonly_location = next(program_table + width * index for index in range(count)
                                if struct.unpack_from('<II', image, program_table + width * index) == (1, 4))
                            changed = bytearray(image)
                            struct.pack_into('<Q', changed, readonly_location + 16, address)
                            with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                links.final_member_references(bytes(changed), **reference_arguments)
                            if storage == 'data':
                                changed = bytearray(image)
                                struct.pack_into('<Q', changed, load_location + 8, load[2] + 1)
                                with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                            code = bound['resolved_calls'][0]['call_address']
                            executable = next(program for index in range(count)
                                for program in [struct.unpack_from('<IIQQQQQQ', image, program_table + width * index)]
                                if program[0] == 1 and program[1] == 5 and program[3] <= code < program[3] + program[5])
                            for opcode_byte in range(3):
                                changed = bytearray(image)
                                changed[executable[2] + code - executable[3] + opcode_byte] ^= 1
                                with self.assertRaisesRegex(ValueError, 'opcode differs'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                    else:
                        self.assertEqual(set(admitted), {'domain_body', 'domain_caller'})
                        self.assertEqual([row['identity']['name'] for row in proof['failures']], ['domain_scalar'])
                        self.assertTrue(proof['failures'][0]['reason'])
                    wrong_owner = links.project_references(work, static, accounting,
                        **{**arguments, 'mapped_archive': str(work / 'unselected.a')})
                    self.assertEqual(wrong_owner['identities'], [])
                    self.assertEqual({row['identity']['name'] for row in wrong_owner['failures']}, set(names))
                    self.assertEqual(list(private.iterdir()), [])

    def test_whole_projection_binds_integer_state_operands_to_owned_writable_objects(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            static = work / 'product'
            (static / 'usr/lib').mkdir(parents=True)
            private = work / 'private'
            private.mkdir()
            names = ['domain_body', 'domain_caller', 'domain_scalar']
            (work / 'providers.c').write_text(links.source(names, object_names=['domain_scalar']))
            cases = [
                ('bss', 8, 'lock cmpxchg %rcx,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 8, 'lock cmpxchg %rdx,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 8, 'mov $0x66000000,%eax; lock cmpxchg %r9,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('data', 8, 'lock cmpxchg %r9,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 4, 'lock cmpxchg %ecx,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('data', 4, 'lock cmpxchg %r9d,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 4, 'mov $0xf0000000,%eax; xchg %eax,domain_scalar(%rip)', 'atomic-exchange'),
                ('data', 4, 'xchg %r9d,domain_scalar(%rip)', 'atomic-exchange'),
                ('bss', 8, 'xchg %rdi,domain_scalar(%rip)', 'atomic-exchange'),
                ('data', 8, 'xchg %r9,domain_scalar(%rip)', 'atomic-exchange'),
                ('bss', 1, 'xchg %al,domain_scalar(%rip)', 'atomic-exchange'),
                ('data', 1, 'xchg %cl,domain_scalar(%rip)', 'atomic-exchange'),
                ('bss', 4, 'lock incl domain_scalar(%rip)', 'locked-increment'),
                ('data', 4, 'lock decl domain_scalar(%rip)', 'locked-decrement'),
                ('bss', 4, 'mov $0x66000000,%eax; lock incl domain_scalar(%rip)', 'locked-increment'),
                ('bss', 8, 'cmpxchg %rcx,domain_scalar(%rip)', None),
                ('bss', 4, 'cmpxchg %ecx,domain_scalar(%rip)', None),
                ('bss', 2, 'lock cmpxchg %cx,domain_scalar(%rip)', None),
                ('bss', 1, 'lock cmpxchg %cl,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('data', 1, 'lock cmpxchg %dl,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 1, 'lock cmpxchg %sil,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('data', 1, 'lock cmpxchg %r8b,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 1, 'mov $0x40000000,%eax; lock cmpxchg %cl,domain_scalar(%rip)', 'locked-cmpxchg'),
                ('bss', 1, 'movb $0,domain_scalar(%rip)', 'integer-immediate-store'),
                ('data', 1, 'movb $1,domain_scalar(%rip)', 'integer-immediate-store'),
                ('bss', 1, 'mov $0x66000000,%eax; movb $0xff,domain_scalar(%rip)', 'integer-immediate-store'),
                ('bss', 1, 'cmpxchg %cl,domain_scalar(%rip)', None),
                ('bss', 1, 'lock cmpxchg %cl,domain_scalar+8(%rip)', None),
                ('rodata', 1, 'lock cmpxchg %cl,domain_scalar(%rip)', None),
                ('rodata', 1, 'movb $0,domain_scalar(%rip)', None),
                ('bss', 1, 'movb $0,domain_scalar+8(%rip)', None),
                ('bss', 1, 'movb $0,%fs:domain_scalar(%rip)', None),
                ('bss', 1, 'lock cmpxchg %sil,%fs:domain_scalar(%rip)', None),
                ('bss', 4, 'lock cmpxchg %ecx,%fs:domain_scalar(%rip)', None),
                ('bss', 4, 'addr32 lock cmpxchg %ecx,domain_scalar(%eip)', None),
                ('bss', 2, 'xchg %cx,domain_scalar(%rip)', None),
                ('bss', 4, 'lock xchg %ecx,domain_scalar(%rip)', None),
                ('bss', 4, 'lock xadd %ecx,domain_scalar(%rip)', None),
                ('bss', 4, 'incl domain_scalar(%rip)', None),
                ('bss', 8, 'lock incq domain_scalar(%rip)', None),
                ('bss', 2, 'lock incw domain_scalar(%rip)', None),
                ('bss', 4, 'lock cmpxchg %ecx,domain_scalar+1(%rip)', None),
                ('bss', 8, 'lock cmpxchg %rcx,domain_scalar+1(%rip)', None),
                ('bss', 4, 'xchg %ecx,domain_scalar+6(%rip)', None),
                ('bss', 8, 'xchg %rdi,domain_scalar+1(%rip)', None),
                ('bss', 1, 'xchg %cl,domain_scalar+8(%rip)', None),
                ('bss', 4, 'lock incl domain_scalar+1(%rip)', None),
                ('bss', 4, 'lock decl domain_scalar+5(%rip)', None),
                ('rodata', 4, 'lock cmpxchg %ecx,domain_scalar(%rip)', None),
                ('rodata', 1, 'xchg %al,domain_scalar(%rip)', None),
                ('rodata', 4, 'lock incl domain_scalar(%rip)', None),
            ]
            cases = [(*case, 1 if case[1] == 1 else 8) for case in cases] + [
                ('data', 2, 'movzwl domain_scalar(%rip),%eax', 'integer-zero-extend-load', 14),
                ('bss', 2, 'movzwl domain_scalar+4(%rip),%ecx', 'integer-zero-extend-load', 6),
                ('bss', 2, 'mov $0x66000000,%eax; movzwl domain_scalar(%rip),%edx', 'integer-zero-extend-load', 2),
                ('data', 2, 'mov %cx,domain_scalar(%rip)', 'integer-data-store', 14),
                ('bss', 2, 'mov %ax,domain_scalar+4(%rip)', 'integer-data-store', 6),
                ('bss', 2, 'mov $0x66000000,%eax; mov %ax,domain_scalar(%rip)', 'integer-data-store', 2),
                ('data', 2, 'movw $0x330e,domain_scalar(%rip)', 'integer-immediate-store', 14),
                ('bss', 2, 'movw $0x2a,domain_scalar(%rip)', 'integer-immediate-store', 260),
                ('bss', 2, 'mov $0x66000000,%eax; movw $0xffff,domain_scalar(%rip)', 'integer-immediate-store', 2),
                ('bss', 2, 'movzwl domain_scalar(%rip),%eax', None, 1),
                ('bss', 2, 'mov %ax,domain_scalar+5(%rip)', None, 6),
                ('bss', 2, 'movw $0x2a,domain_scalar+259(%rip)', None, 260),
                ('rodata', 2, 'mov %ax,domain_scalar(%rip)', None, 6),
                ('rodata', 2, 'movw $0x2a,domain_scalar(%rip)', None, 6),
                ('bss', 2, 'movswl domain_scalar(%rip),%eax', None, 6),
                ('bss', 2, 'movzwq domain_scalar(%rip),%rax', None, 6),
                ('bss', 2, 'movzwl domain_scalar(%rip),%r8d', None, 6),
                ('bss', 2, 'mov %r8w,domain_scalar(%rip)', None, 6),
                ('bss', 2, 'movw $0x2a,%fs:domain_scalar(%rip)', None, 6),
                ('bss', 2, 'mov %ax,%fs:domain_scalar(%rip)', None, 6),
                ('bss', 2, 'movzwl %fs:domain_scalar(%rip),%eax', None, 6),
                ('bss', 2, 'addr32 movw $0x2a,domain_scalar(%eip)', None, 6),
            ]
            cases += [
                ('bss', 8, 'movq $0,domain_scalar(%rip)', 'integer-immediate-store', 24),
                ('data', 8, 'movq $-1,domain_scalar+8(%rip)', 'integer-immediate-store', 24),
                ('bss', 8, 'mov $0x48000000,%eax; movq $0,domain_scalar(%rip)', 'integer-immediate-store', 24),
                ('bss', 4, 'movslq domain_scalar(%rip),%rbx', 'integer-sign-extend-load', 8),
                ('data', 4, 'mov %r9d,domain_scalar+4(%rip)', 'integer-data-store', 8),
                ('bss', 1, 'mov %sil,domain_scalar+7(%rip)', 'integer-data-store', 8),
                ('data', 4, 'cmpl $0,domain_scalar(%rip)', 'integer-immediate-compare', 8),
                ('bss', 8, 'cmpq $-1,domain_scalar+8(%rip)', 'integer-immediate-compare', 24),
                ('bss', 16, 'movups %xmm1,domain_scalar+16(%rip)', 'vector-data-store', 48),
                ('data', 16, 'movups domain_scalar+16(%rip),%xmm2', 'vector-data-load', 48),
                ('bss', 8, 'movq $0,domain_scalar+17(%rip)', None, 24),
                ('bss', 16, 'movups %xmm1,domain_scalar+33(%rip)', None, 48),
                ('rodata', 8, 'movq $0,domain_scalar(%rip)', None, 24),
                ('rodata', 16, 'movups %xmm1,domain_scalar(%rip)', None, 48),
                ('bss', 4, 'movslq %fs:domain_scalar(%rip),%rbx', None, 8),
                ('bss', 8, 'cmpq $0,%fs:domain_scalar(%rip)', None, 24),
                ('bss', 8, 'addr32 movq $0,domain_scalar(%eip)', None, 24),
                ('bss', 16, 'movups %xmm1,%fs:domain_scalar(%rip)', None, 48),
                ('bss', 4, 'addl $1,domain_scalar(%rip)', None, 8),
            ]
            for storage, operand_size, read, operation, object_size in cases:
                with self.subTest(storage=storage, read=read):
                    (work / 'provider.S').write_text(
                        '.section .text.domain_body,"ax",@progbits\n.globl domain_body\n.hidden domain_body\n'
                        '.type domain_body,@function\ndomain_body: mov $7,%eax; ret\n.size domain_body,.-domain_body\n'
                        + '.section .' + storage + '.domain_scalar,"' + ('a' if storage == 'rodata' else 'aw')
                        + '",@' + ('nobits' if storage == 'bss' else 'progbits') + '\n.balign 8\n'
                        '.globl domain_scalar\n.hidden domain_scalar\n.type domain_scalar,@object\n'
                        + 'domain_scalar: .zero ' + str(object_size)
                        + '\n.size domain_scalar,.-domain_scalar\n'
                        '.section .note.GNU-stack,"",@progbits\n')
                    (work / 'caller.S').write_text(
                        '.section .text.domain_caller,"ax",@progbits\n.globl domain_caller\n.hidden domain_caller\n'
                        '.hidden domain_body\n.hidden domain_scalar\n.type domain_caller,@function\n'
                        'domain_caller: call domain_body\n' + read + '\nret\n.size domain_caller,.-domain_caller\n'
                        '.section .note.GNU-stack,"",@progbits\n')
                    for source, target in [('provider.S', 'provider.o'), ('caller.S', 'caller.o'),
                                           ('providers.c', 'providers.o')]:
                        subprocess.run([compiler, '-fPIC', '-c', str(work / source), '-o', str(work / target)],
                                       check=True, capture_output=True)
                    archive = static / 'usr/lib/libc.a'
                    subprocess.run(['ar', 'rcs', str(archive), str(work / 'caller.o'), str(work / 'provider.o')],
                                   check=True, capture_output=True)
                    occurrences = []
                    for member in ('caller.o', 'provider.o'):
                        symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / member))
                        sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / member))['sections']
                        for row in symbols[0]['rows']:
                            if row['name'] not in names:
                                continue
                            role = 'import' if row['section_index'] == 'UND' else 'definition'
                            occurrence = {'index': len(occurrences), 'artifact_key': 'candidate-static',
                                          'member_name': member, 'member_occurrence': 0, 'role': role, 'row': row}
                            if role == 'definition':
                                occurrence['definition_section'] = next(
                                    section for section in sections if str(section['index']) == row['section_index'])
                            occurrences.append(occurrence)
                    accounting = {'occurrences': occurrences, 'identities': [
                        {'identity': selection.identity(name), 'selection': {'disposition': 'unresolved'},
                         'unresolved': []} for name in names]}
                    for mode, flag in [('static', '-static'), ('static-pie', '-pie')]:
                        result = subprocess.run([linker, flag, '--no-relax', '-e', 'main', '--trace',
                                                 '-Map=' + str(work / (mode + '.receipt.map')),
                                                 str(work / 'providers.o'), str(archive), '-o', str(work / mode)],
                                                check=True, capture_output=True)
                        (work / (mode + '.receipt.trace')).write_bytes(result.stdout)
                    arguments = dict(mapped_archive=str(archive), forcing_owner=str(work / 'providers.o'),
                                     temporary_parent=private)
                    proof = links.project_references(work, static, accounting, **arguments)
                    admitted = {row['identity']['name']: row for row in proof['identities']}
                    if operation is not None:
                        self.assertEqual(set(admitted), set(names), proof['failures'])
                        self.assertEqual(proof['failures'], [])
                        for mode in links.MODES:
                            self.assertEqual({site['branch_kind'] for row in proof['identities']
                                for importer in row['links'][mode]['importers'] for site in importer['resolved_calls']},
                                {'call', operation})
                            self.assertFalse(any(importer['discarded_calls'] for row in proof['identities']
                                                 for importer in row['links'][mode]['importers']))
                        definition = next(row for row in occurrences
                                          if row['role'] == 'definition' and row['row']['name'] == 'domain_scalar')
                        caller = (work / 'caller.o').read_bytes()
                        references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                              'domain_scalar', image=caller,
                                                              disassembly=links.read_tool('objdump', '-dw', work / 'caller.o'))
                        if operand_size == 2:
                            with self.assertRaisesRegex(ValueError, 'instruction boundaries are required'):
                                links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                         'domain_scalar', image=caller)
                        disassembly = links.read_tool('objdump', '-dw', work / 'caller.o')
                        corrupted = '\n'.join(line for line in disassembly.splitlines()
                                              if '(%rip)' not in line)
                        with self.assertRaisesRegex(ValueError, 'instruction span is absent'):
                            links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                     'domain_scalar', image=caller, disassembly=corrupted)
                        sections = links.calls._ordinary_source_sections(caller, {row['section'] for row in references})
                        source_object = (work / 'provider.o').read_bytes()
                        for mode, elf_type in [('static', 2), ('static-pie', 3)]:
                            image = (work / mode).read_bytes()
                            address = admitted['domain_scalar']['links'][mode]['provider_address']
                            reference_arguments = dict(archive_member=str(archive) + '(caller.o)', source_calls=references,
                                map_text=(work / (mode + '.receipt.map')).read_text(),
                                relocation_text=links.read_tool('readelf', '-rW', work / mode), provider_address=address,
                                elf_type=elf_type, name='domain_scalar', source_sections=sections,
                                provider_object=(source_object, definition))
                            bound = links.final_member_references(image, **reference_arguments)
                            self.assertEqual(bound['resolved_calls'][0]['operand_size'], operand_size)
                            missing_spans = [{key: value for key, value in reference.items()
                                              if key not in {'instruction_start', 'instruction_end'}}
                                             for reference in references]
                            extra_byte = copy.deepcopy(references)
                            extra_byte[0]['instruction_end'] += 1
                            extended_prefix = copy.deepcopy(references)
                            extended_prefix[0]['instruction_start'] -= 1
                            if operand_size == 2:
                                wrong_bias = copy.deepcopy(references)
                                wrong_bias[0]['operand_addend'] += 1
                                with self.assertRaisesRegex(ValueError, 'foreign provider|leaves provider object'):
                                    links.final_member_references(image, **{**reference_arguments, 'source_calls': wrong_bias})
                            for altered in [missing_spans, extra_byte, extended_prefix]:
                                with self.assertRaises(ValueError):
                                    links.final_member_references(image, **{**reference_arguments, 'source_calls': altered})
                            wrong = copy.deepcopy(definition)
                            wrong['row']['size_bytes'] = 4
                            for altered, message in [({'provider_object': None}, 'lacks its source object'),
                                    ({'provider_object': (source_object, wrong)}, 'source symbol differs'),
                                    ({'provider_address': address + 1}, 'foreign provider')]:
                                with self.assertRaisesRegex(ValueError, message):
                                    links.final_member_references(image, **{**reference_arguments, **altered})
                            original = links.static_authority.elf_bytes(source_object)
                            source_symbol = original.symbol('domain_scalar', dynamic=False)
                            section_table, section_width = struct.unpack_from('<Q', source_object, 40)[0], struct.unpack_from('<H', source_object, 58)[0]
                            source_header = section_table + section_width * source_symbol['section']
                            for field, value, encoding in [(4, 1 if storage == 'bss' else 8, '<I'), (8, 2, '<Q'), (32, 7, '<Q')]:
                                changed_source = bytearray(source_object)
                                struct.pack_into(encoding, changed_source, source_header + field, value)
                                with self.assertRaisesRegex(ValueError, 'source extent differs'):
                                    links.final_member_references(image, **{**reference_arguments,
                                        'provider_object': (bytes(changed_source), definition)})
                            elf = links.static_authority.elf_bytes(image)
                            symbol = elf.symbol('domain_scalar', dynamic=False)
                            output = elf.sections[symbol['section']]
                            self.assertEqual(output[1], 8 if storage == 'bss' else 1)
                            program_table, width, count = struct.unpack_from('<Q', image, 32)[0], *struct.unpack_from('<HH', image, 54)
                            load_location, load = next((program_table + width * index, program)
                                for index in range(count)
                                for program in [struct.unpack_from('<IIQQQQQQ', image, program_table + width * index)]
                                if program[0] == 1 and program[3] <= address < program[3] + program[6])
                            if storage == 'bss':
                                self.assertGreater(address + operand_size, load[3] + load[5])
                            for flags, memory_size in [(4, load[6]), (7, load[6]), (6, address + operand_size - 1 - load[3])]:
                                changed = bytearray(image)
                                struct.pack_into('<I', changed, load_location + 4, flags)
                                struct.pack_into('<Q', changed, load_location + (40 if storage == 'bss' else 32), memory_size)
                                with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                            headers = [(program_table + width * index,
                                        struct.unpack_from('<IIQQQQQQ', image, program_table + width * index))
                                       for index in range(count)]
                            readonly_location, _ = next((location, program) for location, program in headers
                                                        if program[0] == 1 and program[1] == 4)
                            changed = bytearray(image)
                            struct.pack_into('<Q', changed, readonly_location + 16, address)
                            with self.assertRaisesRegex(ValueError, 'exclusive writable load extent'):
                                links.final_member_references(bytes(changed), **reference_arguments)
                            if operand_size < definition['row']['size_bytes']:
                                changed = bytearray(image)
                                struct.pack_into('<Q', changed, load_location + 40, address + operand_size - load[3])
                                with self.assertRaisesRegex(ValueError, 'writable load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                            if storage == 'data':
                                changed = bytearray(image)
                                struct.pack_into('<Q', changed, load_location + 8, load[2] + 1)
                                with self.assertRaisesRegex(ValueError, 'exclusive writable load extent'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                            code = bound['resolved_calls'][0]['call_address']
                            executable = next(segment for index in range(count)
                                for segment in [struct.unpack_from('<IIQQQQQQ', image, program_table + width * index)]
                                if segment[0] == 1 and segment[3] <= code < segment[3] + segment[5])
                            prefix_size = references[0]['offset'] - references[0]['instruction_start']
                            if operation == 'integer-immediate-store':
                                for immediate_byte in range(references[0]['instruction_end'] - references[0]['offset'] - 4):
                                    changed = bytearray(image)
                                    changed[executable[2] + code - executable[3] + prefix_size + 4 + immediate_byte] ^= 1
                                    with self.assertRaisesRegex(ValueError, 'opcode differs'):
                                        links.final_member_references(bytes(changed), **reference_arguments)
                            for byte in range(prefix_size):
                                changed = bytearray(image)
                                changed[executable[2] + code - executable[3] + byte] ^= 1
                                with self.assertRaisesRegex(ValueError, 'opcode differs'):
                                    links.final_member_references(bytes(changed), **reference_arguments)
                    else:
                        self.assertEqual(set(admitted), {'domain_body', 'domain_caller'})
                        self.assertEqual([row['identity']['name'] for row in proof['failures']], ['domain_scalar'])
                        self.assertTrue(proof['failures'][0]['reason'])
                    wrong_owner = links.project_references(work, static, accounting,
                        **{**arguments, 'mapped_archive': str(work / 'unselected.a')})
                    self.assertEqual(wrong_owner['identities'], [])
                    self.assertEqual({row['identity']['name'] for row in wrong_owner['failures']}, set(names))
                    self.assertEqual(list(private.iterdir()), [])

    def test_real_archive_references_keep_all_register_loads_address_expressions_and_conditional_branches(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('clang') or shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            source = ['.section .text.caller,"ax",@progbits', '.globl caller', '.type caller,@function', 'caller:',
                      'call domain_body', 'jmp domain_body']
            for register in range(16):
                source += [f'.byte {0x48 if register < 8 else 0x4c}, 0x8b, {0x05 + ((register % 8) << 3)}',
                           '.long 0', '.reloc .-4, R_X86_64_GOTPCREL, domain_body-4']
            source += ['.byte 0x48, 0x8d, 0x05', '.long 0', '.reloc .-4, R_X86_64_PC32, domain_body-4',
                       '.byte 0x0f, 0x84', '.long 0', '.reloc .-4, R_X86_64_PLT32, domain_body-4', 'ret',
                       '.size caller,.-caller', '.section .text.provider,"ax",@progbits',
                       '.globl domain_body', '.type domain_body,@function', 'domain_body:', 'ret',
                       '.size domain_body,.-domain_body', '.section .note.GNU-stack,"",@progbits']
            (work / 'caller.S').write_text('\n'.join(source) + '\n')
            subprocess.run([compiler, '-c', str(work / 'caller.S'), '-o', str(work / 'caller.o')],
                           check=True, capture_output=True)
            subprocess.run(['ar', 'rcs', str(work / 'libdomain.a'), str(work / 'caller.o')],
                           check=True, capture_output=True)
            image = (work / 'caller.o').read_bytes()
            references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                  'domain_body', image=image)
            self.assertEqual(len(references), 20)
            sections = links.calls._ordinary_source_sections(image, {row['section'] for row in references})
            member = str(work / 'libdomain.a') + '(caller.o)'
            for mode, elf_type, flag in [('static', 2, '-static'), ('static-pie', 3, '-pie')]:
                output, map_path = work / mode, work / (mode + '.map')
                subprocess.run([linker, flag, '--no-relax', '-e', 'caller', '--undefined=caller',
                                         '-Map=' + str(map_path), str(work / 'libdomain.a'), '-o', str(output)],
                                        check=True, capture_output=True)
                symbol_text = links.read_tool('readelf', '-sW', output)
                address = int(next(row.split()[1] for row in symbol_text.splitlines()
                                   if row.split() and row.split()[-1] == 'domain_body'), 16)
                arguments = dict(archive_member=member, source_calls=references, map_text=map_path.read_text(),
                                 relocation_text=links.read_tool('readelf', '-rW', output),
                                 provider_address=address, elf_type=elf_type, name='domain_body', source_sections=sections)
                proof = links.final_member_references(output.read_bytes(), **arguments)
                self.assertEqual(len(proof['resolved_calls']), 20)
                self.assertEqual(proof['discarded_calls'], [])
                self.assertEqual({row['branch_kind'] for row in proof['resolved_calls']},
                                 {'call', 'tail-jump', 'got-address-load', 'rip-relative-address', 'conditional-jump'})
                for reference in references:
                    with self.assertRaisesRegex((ValueError, links.calls.AllocatorBoundaryError), 'foreign provider'):
                        links.final_member_references(output.read_bytes(), **{
                            **arguments, 'source_calls': [reference], 'provider_address': address + 1})
                changed = bytearray(output.read_bytes())
                table, count = struct.unpack_from('<Q', changed, 32)[0], struct.unpack_from('<H', changed, 56)[0]
                call_address = proof['resolved_calls'][0]['call_address']
                for index in range(count):
                    header = struct.unpack_from('<IIQQQQQQ', changed, table + 56 * index)
                    if header[0] == 1 and header[3] <= call_address < header[3] + header[5]:
                        changed[header[2] + call_address - header[3]] ^= 1
                with self.assertRaisesRegex(ValueError, 'opcode differs'):
                    links.final_member_references(bytes(changed), **arguments)

    def test_merged_objects_keep_selected_owner_and_exact_forcing_relocations(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            names = ['domain_duplicate', 'domain_scalar', 'domain_string', 'domain_suffix']
            (work / 'provider.S').write_text(
                '.section .rodata.cst8,"aM",@progbits,8\n.balign 8\n'
                '.globl domain_scalar\n.hidden domain_scalar\n.type domain_scalar,@object\n'
                'domain_scalar: .quad 0x123456789abcdef0\n.size domain_scalar,.-domain_scalar\n'
                '.section .rodata.str1.1,"aMS",@progbits,1\n'
                '.globl domain_string\n.hidden domain_string\n.type domain_string,@object\n'
                'domain_string: .asciz "prefixsuffix"\n.size domain_string,.-domain_string\n'
                '.globl domain_suffix\n.hidden domain_suffix\n.type domain_suffix,@object\n'
                'domain_suffix: .asciz "suffix"\n.size domain_suffix,.-domain_suffix\n'
                '.globl domain_duplicate\n.hidden domain_duplicate\n.type domain_duplicate,@object\n'
                'domain_duplicate: .asciz "suffix"\n.size domain_duplicate,.-domain_duplicate\n'
                '.section .note.GNU-stack,"",@progbits\n')
            (work / 'caller.S').write_text(
                '.section .text.domain_caller,"ax",@progbits\n.globl domain_caller\n.hidden domain_caller\n'
                '.type domain_caller,@function\ndomain_caller:\n'
                'lea domain_string+2(%rip),%rax\nmov domain_string+4(%rip),%ecx\n'
                'lea domain_string+13(%rip),%rax\n'
                'lea domain_suffix+1(%rip),%rcx\nmovzbl domain_suffix+6(%rip),%eax\n'
                'lea domain_suffix(%rip),%rax\n'
                'lea domain_suffix+7(%rip),%rcx\n'
                'lea domain_duplicate+2(%rip),%rax\nmov domain_duplicate(%rip),%ecx\n'
                'lea domain_duplicate+7(%rip),%rax\n'
                'ret\n.size domain_caller,.-domain_caller\n.section .note.GNU-stack,"",@progbits\n')
            (work / 'providers.c').write_text(links.source(names, object_names=names))
            for source, target in [('provider.S', 'provider.o'), ('providers.c', 'providers.o'), ('caller.S', 'caller.o')]:
                subprocess.run([compiler, '-fPIC', '-c', str(work / source), '-o', str(work / target)],
                               check=True, capture_output=True)
            subprocess.run(['ar', 'rcs', str(work / 'libdomain.a'), str(work / 'provider.o'), str(work / 'caller.o')],
                           check=True, capture_output=True)
            image = (work / 'provider.o').read_bytes()
            tables = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / 'provider.o'))
            sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / 'provider.o'))['sections']
            forcing = links.fixture_object(work / 'providers.o', names)
            member = str(work / 'libdomain.a') + '(provider.o)'
            for mode, elf_type, flag in [('static', 2, '-static'), ('static-pie', 3, '-pie')]:
                linked = subprocess.run([linker, flag, '-O2', '--no-relax', '-e', 'main', '--trace',
                                         '--undefined=domain_caller',
                                         '-Map=' + str(work / (mode + '.receipt.map')),
                                         str(work / 'providers.o'), str(work / 'libdomain.a'),
                                         '-o', str(work / mode)], check=True, capture_output=True)
                (work / (mode + '.receipt.trace')).write_bytes(linked.stdout)
                view = links._indexed_view(work, mode, elf_type)
                view.update(forcing_owner=str(work / 'providers.o'),
                            forcing_image=(work / 'providers.o').read_bytes())
                addresses = {}
                for name in names:
                    row = next(row for row in tables[0]['rows'] if row['name'] == name)
                    section = next(section for section in sections if str(section['index']) == row['section_index'])
                    definition = {'row': row, 'definition_section': section}
                    address = int(view['symbol_rows'][name][0][1], 16)
                    for altered in ({'trace_counts': {**view['trace_counts'], member: 0}},
                                    {'forcing_owner': member}, {'forcing_image': image},
                                    {'map_rows': {}}, {'forcing_image': b''}):
                        with self.assertRaises(ValueError):
                            links.definition_address({**view, **altered}, member, definition, source_image=image)
                    for field, value in [('flags', 'A'), ('entry_size', '0'), ('size', '0'),
                                         ('alignment', section['alignment'] + 1)]:
                        with self.assertRaises(ValueError):
                            links.definition_address(view, member, {**definition,
                                'definition_section': {**section, field: value}}, source_image=image)
                    changed = bytearray(view['image'])
                    address_offset = links.static_authority.elf_bytes(bytes(changed)).sections[
                        int(view['symbol_rows'][name][0][6])]
                    changed[address_offset[4] + address - address_offset[3]] ^= 1
                    with self.assertRaises(ValueError):
                        links.definition_address({**view, 'image': bytes(changed)}, member,
                                                 definition, source_image=image)
                    source_forcing = links.static_authority.elf_bytes(view['forcing_image'])
                    holder = source_forcing.symbol('providers', dynamic=False)
                    reference = next(r for r in forcing['references'] if r['symbol'] == name)
                    forcing_section = links.static_authority.section_name(source_forcing,
                        source_forcing.sections[holder['section']])
                    placement = view['map_rows'][view['forcing_owner'] + ':(' + forcing_section + ')'][0].split()
                    slot = int(placement[0], 16) + reference['offset']
                    changed = bytearray(view['image'])
                    final = links.static_authority.elf_bytes(bytes(changed))
                    if elf_type == 2:
                        data_section = next(s for s in final.sections if s[1] == 1
                                            and s[3] <= slot and slot + 8 <= s[3] + s[5])
                        struct.pack_into('<Q', changed, data_section[4] + slot - data_section[3], address + 1)
                    else:
                        for rela in final.sections:
                            if rela[1] == 4:
                                for offset in range(0, rela[5], 24):
                                    if final.unpack('<Q', rela[4] + offset)[0] == slot:
                                        struct.pack_into('<q', changed, rela[4] + offset + 16, address + 1)
                    with self.assertRaisesRegex(ValueError, 'forcing target differs'):
                        links.definition_address({**view, 'image': bytes(changed)}, member,
                                                 definition, source_image=image)
                    changed = bytearray(view['forcing_image'])
                    for rela in source_forcing.sections:
                        if rela[1] == 4 and rela[7] == holder['section']:
                            for offset in range(0, rela[5], 24):
                                if source_forcing.unpack('<Q', rela[4] + offset)[0] == reference['offset']:
                                    struct.pack_into('<q', changed, rela[4] + offset + 16, 1)
                    with self.assertRaisesRegex(ValueError, 'forcing reference differs'):
                        links.definition_address({**view, 'forcing_image': bytes(changed)}, member,
                                                 definition, source_image=image)
                    pool_key = '<internal>:(' + section['name'] + ')'
                    pool = view['map_rows'][pool_key][0].split()
                    pool[2] = '0'
                    with self.assertRaisesRegex(ValueError, 'pool geometry differs'):
                        links.definition_address({**view, 'map_rows': {**view['map_rows'],
                            pool_key: [' '.join(pool)]}}, member, definition, source_image=image)
                    addresses[name] = links.definition_address(view, member, definition, source_image=image)
                    self.assertEqual(addresses[name], address)
                    if name != 'domain_scalar':
                        caller = (work / 'caller.o').read_bytes()
                        references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                            name, image=caller, disassembly=links.read_tool('objdump', '-dw', work / 'caller.o'))
                        reference_arguments = dict(archive_member=str(work / 'libdomain.a') + '(caller.o)',
                            source_calls=references, map_text=(work / (mode + '.receipt.map')).read_text(),
                            relocation_text=links.read_tool('readelf', '-rW', work / mode), provider_address=address,
                            elf_type=elf_type, name=name,
                            source_sections=links.calls._ordinary_source_sections(caller, {row['section'] for row in references}),
                            provider_object=(image, definition), provider_pool=(view, member))
                        bound = links.final_member_references(view['image'], **reference_arguments)
                        self.assertEqual(len(bound['resolved_calls']), 4 if name == 'domain_suffix' else 3)
                        self.assertEqual(bound['discarded_calls'], [])
                        self.assertEqual({row['branch_kind'] for row in bound['resolved_calls']},
                            {'rip-relative-address', 'rip-relative-object-end-address',
                             'integer-zero-extend-load' if name == 'domain_suffix' else 'integer-data-load'})
                        wrong = copy.deepcopy(references)
                        wrong[0]['address_addend'] += row['size_bytes']
                        wrong_span = copy.deepcopy(references)
                        wrong_span[0]['instruction_end'] += 1
                        end_load = copy.deepcopy(next(reference for reference in references if 'operand_addend' in reference))
                        end_load['operand_addend'] = row['size_bytes'] - 4
                        ambiguous = {**view, 'map_rows': {**view['map_rows'],
                            pool_key: [*view['map_rows'][pool_key], *view['map_rows'][pool_key]]}}
                        for altered, message in [({'provider_pool': None}, 'owned pool translation'),
                                ({'provider_pool': (ambiguous, member)}, 'selected member or pool'),
                                ({'provider_pool': ({**view, 'forcing_image': b''}, member)}, 'ELF'),
                                ({'source_calls': wrong}, 'leaves provider object'),
                                ({'source_calls': [end_load]}, 'leaves provider object'),
                                ({'source_calls': wrong_span}, 'supported load or address')]:
                            with self.assertRaisesRegex(ValueError, message):
                                links.final_member_references(view['image'], **{**reference_arguments, **altered})
                        if name == 'domain_suffix':
                            base = next(reference for reference in references
                                        if 'address_addend' not in reference and 'operand_addend' not in reference)
                            with self.assertRaisesRegex(ValueError, 'owned pool translation'):
                                links.final_member_references(view['image'], **{**reference_arguments,
                                    'source_calls': [base], 'provider_pool': None})
                        if name in {'domain_suffix', 'domain_duplicate'}:
                            other = 'domain_duplicate' if name == 'domain_suffix' else 'domain_suffix'
                            other_reference = next(r for r in forcing['references'] if r['symbol'] == other)
                            changed = bytearray(view['forcing_image'])
                            for rela in source_forcing.sections:
                                if rela[1] == 4 and rela[7] == holder['section']:
                                    for offset in range(0, rela[5], 24):
                                        if source_forcing.unpack('<Q', rela[4] + offset)[0] == reference['offset']:
                                            struct.pack_into('<Q', changed, rela[4] + offset + 8,
                                                other_reference['symbol_index'] << 32 | 1)
                            # The alternative string has the same final address
                            # and bytes, but cannot supply this definition's slot.
                            with self.assertRaisesRegex(ValueError, 'exact forcing reference'):
                                links.final_member_references(view['image'], **{**reference_arguments,
                                    'provider_pool': ({**view, 'forcing_image': bytes(changed)}, member)})
                self.assertEqual(addresses['domain_suffix'], addresses['domain_string'] + 6)
                self.assertEqual(addresses['domain_duplicate'], addresses['domain_suffix'])
            static = work / 'product'
            (static / 'usr/lib').mkdir(parents=True)
            shutil.copyfile(work / 'libdomain.a', static / 'usr/lib/libc.a')
            occurrences = []
            for source_member in ('provider.o', 'caller.o'):
                symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / source_member))
                source_sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / source_member))['sections']
                for row in symbols[0]['rows']:
                    if row['name'] not in names:
                        continue
                    role = 'import' if row['section_index'] == 'UND' else 'definition'
                    occurrence = {'index': len(occurrences), 'artifact_key': 'candidate-static',
                        'member_name': source_member, 'member_occurrence': 0, 'role': role, 'row': row}
                    if role == 'definition':
                        occurrence['definition_section'] = next(section for section in source_sections
                            if str(section['index']) == row['section_index'])
                    occurrences.append(occurrence)
            accounting = {'occurrences': occurrences, 'identities': [
                {'identity': selection.identity(name), 'selection': {'disposition': 'unresolved'},
                 'unresolved': []} for name in names]}
            private = work / 'private'
            private.mkdir()
            proof = links.project_references(work, static, accounting,
                mapped_archive=str(work / 'libdomain.a'), forcing_owner=str(work / 'providers.o'), temporary_parent=private)
            self.assertEqual({row['identity']['name'] for row in proof['identities']}, set(names), proof['failures'])
            self.assertEqual(proof['failures'], [])
            (work / 'ambiguous.S').write_text(
                '.section .rodata.str1.1,"aMS",@progbits,1\n.globl domain_suffix\n.hidden domain_suffix\n'
                '.type domain_suffix,@object\ndomain_suffix: .asciz "suffix"\n.size domain_suffix,.-domain_suffix\n'
                '.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([compiler, '-c', str(work / 'ambiguous.S'), '-o', str(work / 'ambiguous.o')],
                           check=True, capture_output=True)
            subprocess.run(['ar', 'r', str(static / 'usr/lib/libc.a'), str(work / 'ambiguous.o')],
                           check=True, capture_output=True)
            ambiguous_symbols = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / 'ambiguous.o'))
            ambiguous_row = next(row for row in ambiguous_symbols[0]['rows'] if row['name'] == 'domain_suffix')
            ambiguous_sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / 'ambiguous.o'))['sections']
            ambiguous_section = next(section for section in ambiguous_sections
                                     if str(section['index']) == ambiguous_row['section_index'])
            ambiguous_accounting = copy.deepcopy(accounting)
            ambiguous_accounting['occurrences'].append({'index': len(occurrences), 'artifact_key': 'candidate-static',
                'member_name': 'ambiguous.o', 'member_occurrence': 0, 'role': 'definition',
                'row': ambiguous_row, 'definition_section': ambiguous_section})
            refused = links.project_references(work, static, ambiguous_accounting,
                mapped_archive=str(work / 'libdomain.a'), forcing_owner=str(work / 'providers.o'), temporary_parent=private)
            self.assertNotIn('domain_suffix', {row['identity']['name'] for row in refused['identities']})

    def test_long_function_section_display_keeps_exact_indexed_archive_owner(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            common = '.text.' + 'indexed_provider_' * 20
            (work / 'provider.S').write_text(''.join(
                f'.section {common + suffix},"ax",@progbits\n.globl {name}\n.hidden {name}\n'
                f'.type {name},@function\n{name}: mov ${value},%eax; ret\n.size {name},.-{name}\n'
                for suffix, name, value in [('first', 'domain_function', 42), ('second', 'other_function', 43)])
                + '.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([compiler, '-c', str(work / 'provider.S'), '-o', str(work / 'provider.o')],
                           check=True, capture_output=True)
            subprocess.run(['ar', 'rcs', str(work / 'libdomain.a'), str(work / 'provider.o')],
                           check=True, capture_output=True)
            tables = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / 'provider.o'))
            row = next(row for row in tables[0]['rows'] if row['name'] == 'domain_function')
            sections = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / 'provider.o'))['sections']
            section = next(section for section in sections if str(section['index']) == row['section_index'])
            self.assertEqual(section['name'], (common + 'first')[:256])
            definition = {'row': row, 'definition_section': section}
            image = (work / 'provider.o').read_bytes()
            for mode, elf_type, flag in [('static', 2, '-static'), ('static-pie', 3, '-pie')]:
                output, map_path, trace_path = work / mode, work / (mode + '.receipt.map'), work / (mode + '.receipt.trace')
                linked = subprocess.run([linker, flag, '-e', 'domain_function', '--undefined=domain_function',
                                         '--undefined=other_function', '--trace', '-Map=' + str(map_path),
                                         str(work / 'libdomain.a'), '-o', str(output)], check=True, capture_output=True)
                trace_path.write_bytes(linked.stdout)
                view = links._indexed_view(work, mode, elf_type)
                address = links.definition_address(view, str(work / 'libdomain.a') + '(provider.o)',
                                                   definition, source_image=image)
                self.assertEqual(address, int(view['symbol_rows']['domain_function'][0][1], 16))
                self.assertEqual(links.calls._public_weak_virtual_bytes(output.read_bytes(), address,
                                 row['size_bytes'], elf_type, executable=True),
                                 image[int(section['offset'], 16):int(section['offset'], 16) + row['size_bytes']])
                member = str(work / 'libdomain.a') + '(provider.o)'
                other = next(row for row in tables[0]['rows'] if row['name'] == 'other_function')
                changes = [({'row': {**row, 'section_index': other['section_index']}}, 'symbol metadata differs'),
                           ({'definition_section': {**section, 'index': int(other['section_index'])}}, 'section index differs'),
                           ({'definition_section': {**section, 'name': 'wrong' + section['name'][5:]}}, 'display name differs'),
                           ({'definition_section': {**section, 'flags': 'A'}}, 'section flags differ'),
                           ({'definition_section': {**section, 'flags': 'WWX'}}, 'section flags differ'),
                           ({'definition_section': {**section, 'type': 'NOBITS'}}, 'section geometry differs'),
                           ({'row': {**row, 'binding': 'WEAK'}}, 'symbol metadata differs'),
                           ({'row': {**row, 'visibility': 'DEFAULT'}}, 'symbol metadata differs'),
                           ({'row': {**row, 'value': '0000000000000001'}}, 'symbol metadata differs')]
                for field in ('address', 'offset', 'size', 'entry_size'):
                    changes.append(({'definition_section': {**section, field: format(int(section[field], 16) + 1, 'x')}},
                                    'section geometry differs'))
                for field in ('alignment', 'link', 'info'):
                    changes.append(({'definition_section': {**section, field: section[field] + 1}},
                                    'section geometry differs'))
                for altered, message in changes:
                    with self.assertRaisesRegex(ValueError, message):
                        links.definition_address(view, member, {**definition, **altered}, source_image=image)
                for altered in ({'trace_counts': {}}, {'map_rows': {}},
                                {'symbol_rows': {'domain_function': [*view['symbol_rows']['domain_function'],
                                                                     *view['symbol_rows']['domain_function']]}}):
                    with self.assertRaises(ValueError):
                        links.definition_address({**view, **altered}, member, definition, source_image=image)

    def test_real_scalar_table_reads_bind_interior_object_bytes_in_both_static_modes(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            (work / 'caller.S').write_text('.section .text.caller,"ax",@progbits\n'
                '.globl caller\n.type caller,@function\ncaller:\n'
                'movsd domain_table+48(%rip),%xmm0\n'
                'mulsd domain_table+8(%rip),%xmm1\n'
                'addsd domain_table+40(%rip),%xmm2\n'
                'movsd domain_table+56(%rip),%xmm9\n'
                'ret\n.size caller,.-caller\n.section .note.GNU-stack,"",@progbits\n')
            data = bytes(range(64))
            (work / 'table.S').write_text('.section .rodata.table,"a",@progbits\n'
                '.globl domain_table\n.type domain_table,@object\ndomain_table:\n.byte '
                + ','.join(str(value) for value in data)
                + '\n.size domain_table,.-domain_table\n.section .note.GNU-stack,"",@progbits\n')
            for name in ('caller', 'table'):
                subprocess.run([compiler, '-c', str(work / (name + '.S')), '-o', str(work / (name + '.o'))],
                               check=True, capture_output=True)
            subprocess.run(['ar', 'rcs', str(work / 'libdomain.a'), str(work / 'caller.o'),
                            str(work / 'table.o')], check=True, capture_output=True)
            image = (work / 'caller.o').read_bytes()
            references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                  'domain_table', image=image)
            self.assertEqual(len(references), 4)
            sections = links.calls._ordinary_source_sections(image, {row['section'] for row in references})
            for mode, elf_type, flag in [('static', 2, '-static'), ('static-pie', 3, '-pie')]:
                output, map_path = work / mode, work / (mode + '.map')
                subprocess.run([linker, flag, '-e', 'caller', '--undefined=caller',
                                '-Map=' + str(map_path), str(work / 'libdomain.a'), '-o', str(output)],
                               check=True, capture_output=True)
                address = int(next(row.split()[1] for row in links.read_tool('readelf', '-sW', output).splitlines()
                                   if row.split() and row.split()[-1] == 'domain_table'), 16)
                arguments = dict(archive_member=str(work / 'libdomain.a') + '(caller.o)', source_calls=references,
                                 map_text=map_path.read_text(), relocation_text=links.read_tool('readelf', '-rW', output),
                                 provider_address=address, elf_type=elf_type, name='domain_table',
                                 source_sections=sections, provider_data=data)
                proof = links.final_member_references(output.read_bytes(), **arguments)
                self.assertEqual([row['provider_offset'] for row in proof['resolved_calls']], [48, 8, 40, 56])
                self.assertEqual({row['branch_kind'] for row in proof['resolved_calls']}, {'scalar-data-read'})
                self.assertEqual(proof['discarded_calls'], [])
                for altered, message in [({'provider_data': None}, 'leaves provider object'),
                                         ({'provider_data': data[:56]}, 'leaves provider object'),
                                         ({'provider_address': address + 1}, 'foreign provider'),
                                         ({'provider_data': data[:48] + b'\xff' + data[49:]}, 'bytes differ')]:
                    with self.assertRaisesRegex(ValueError, message):
                        links.final_member_references(output.read_bytes(), **{**arguments, **altered})
                table, count = struct.unpack_from('<Q', output.read_bytes(), 32)[0], struct.unpack_from('<H', output.read_bytes(), 56)[0]
                headers = [(table + 56 * index, struct.unpack_from('<IIQQQQQQ', output.read_bytes(), table + 56 * index))
                           for index in range(count)]
                for label, virtual, message in [('opcode', proof['resolved_calls'][0]['call_address'], 'opcode differs'),
                                                 ('data', address + 48, 'bytes differ')]:
                    changed = bytearray(output.read_bytes())
                    header = next(row for _, row in headers if row[0] == 1 and row[3] <= virtual < row[3] + row[5])
                    changed[header[2] + virtual - header[3]] ^= 1
                    with self.assertRaisesRegex(ValueError, message):
                        links.final_member_references(bytes(changed), **arguments)
                changed = bytearray(output.read_bytes())
                location, header = next((location, row) for location, row in headers
                                        if row[0] == 1 and row[3] <= address < row[3] + row[5])
                struct.pack_into('<I', changed, location + 4, header[1] & ~4)
                with self.assertRaisesRegex(ValueError, 'read-only load segment'):
                    links.final_member_references(bytes(changed), **arguments)
            section_headers = links.inventory.parse_elf_sections(links.read_tool('readelf', '-SW', work / 'caller.o'))['sections']
            section = next(row for row in section_headers if row['name'] == references[0]['section'])
            for prefix_offset, opcode in [(-2, 0x11), (-4, 0xf3)]:
                changed = bytearray(image)
                changed[int(section['offset'], 16) + references[0]['offset'] + prefix_offset] = opcode
                with self.assertRaisesRegex(ValueError, 'not a supported reference'):
                    links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                             'domain_table', image=bytes(changed))

    def test_real_object_addresses_cover_complete_data_roster_and_got_comparison_operands(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('clang') or shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        facts = {'candidate-static': [{'symbol_tables': [{'rows': [
            {'name': name, 'type': kind, 'binding': 'GLOBAL', 'section_index': '3', 'size_bytes': size}
            for name, kind, size in [('domain_data', 'OBJECT', 4), ('domain_body', 'FUNC', 1),
                                     ('tls_data', 'TLS', 4), ('empty_data', 'OBJECT', 0)]
        ]}]}]}
        self.assertEqual(links.roster(facts), ['domain_body', 'domain_data'])
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            (work / 'forcing.c').write_text(links.source(links.roster(facts), object_names=['domain_data']))
            subprocess.run([compiler, '-fPIE', '-c', str(work / 'forcing.c'), '-o', str(work / 'forcing.o')],
                           check=True, capture_output=True)
            forcing = links.fixture_object(work / 'forcing.o', links.roster(facts))
            self.assertEqual([row['symbol'] for row in forcing['references']], ['domain_body', 'domain_data'])
            source = ['.section .text.caller,"ax",@progbits', '.globl caller', '.type caller,@function', 'caller:']
            for register in range(16):
                source += [f'.byte {0x48 if register < 8 else 0x4c}, 0x3b, {0x05 + ((register % 8) << 3)}',
                           '.long 0', '.reloc .-4, R_X86_64_GOTPCREL, domain_data-4']
            source += ['.byte 0x48, 0x8b, 0x05', '.long 0',
                       '.reloc .-4, R_X86_64_GOTPCREL, domain_data-4', 'ret', '.size caller,.-caller',
                       '.section .data.provider,"aw",@progbits', '.globl domain_data', '.type domain_data,@object',
                       'domain_data:', '.long 42', '.size domain_data,.-domain_data',
                       '.section .note.GNU-stack,"",@progbits']
            (work / 'caller.S').write_text('\n'.join(source) + '\n')
            subprocess.run([compiler, '-c', str(work / 'caller.S'), '-o', str(work / 'caller.o')],
                           check=True, capture_output=True)
            subprocess.run(['ar', 'rcs', str(work / 'libdomain.a'), str(work / 'caller.o')],
                           check=True, capture_output=True)
            image = (work / 'caller.o').read_bytes()
            references = links.import_relocations(links.read_tool('readelf', '-rW', work / 'caller.o'),
                                                  'domain_data', image=image)
            self.assertEqual(len(references), 17)
            sections = links.calls._ordinary_source_sections(image, {row['section'] for row in references})
            for mode, elf_type, flag in [('static', 2, '-static'), ('static-pie', 3, '-pie')]:
                output, map_path = work / mode, work / (mode + '.map')
                subprocess.run([linker, flag, '--no-relax', '-e', 'caller', '--undefined=caller',
                                '-Map=' + str(map_path), str(work / 'libdomain.a'), '-o', str(output)],
                               check=True, capture_output=True)
                address = int(next(row.split()[1] for row in links.read_tool('readelf', '-sW', output).splitlines()
                                   if row.split() and row.split()[-1] == 'domain_data'), 16)
                arguments = dict(archive_member=str(work / 'libdomain.a') + '(caller.o)', source_calls=references,
                                 map_text=map_path.read_text(), relocation_text=links.read_tool('readelf', '-rW', output),
                                 provider_address=address, elf_type=elf_type, name='domain_data', source_sections=sections)
                proof = links.final_member_references(output.read_bytes(), **arguments)
                self.assertEqual(len(proof['resolved_calls']), 17)
                self.assertEqual(proof['discarded_calls'], [])
                self.assertEqual({row['branch_kind'] for row in proof['resolved_calls']},
                                 {'got-address-compare', 'got-address-load'})
                for reference in references:
                    with self.assertRaisesRegex((ValueError, links.calls.AllocatorBoundaryError), 'foreign provider'):
                        links.final_member_references(output.read_bytes(), **{
                            **arguments, 'source_calls': [reference], 'provider_address': address + 1})

    def test_strong_symbol_only_import_extracts_provider_without_claiming_a_call(self):
        import native_abi_provider_links as links
        compiler, linker = shutil.which('clang') or shutil.which('gcc'), shutil.which('ld.lld')
        if compiler is None or linker is None:
            self.skipTest('native compiler and linker are required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            (work / 'importer.S').write_text('.text\n.globl importer\n.type importer,@function\n'
                'importer: ret\n.size importer,.-importer\n.globl domain_body\n'
                '.section .note.GNU-stack,"",@progbits\n')
            (work / 'provider.S').write_text('.text\n.globl domain_body\n.type domain_body,@function\n'
                'domain_body: ret\n.size domain_body,.-domain_body\n.section .note.GNU-stack,"",@progbits\n')
            for name in ('importer', 'provider'):
                subprocess.run([compiler, '-c', str(work / (name + '.S')), '-o', str(work / (name + '.o'))],
                               check=True, capture_output=True)
            subprocess.run(['ar', 'rcs', str(work / 'libdomain.a'), str(work / 'importer.o'), str(work / 'provider.o')],
                           check=True, capture_output=True)
            image = (work / 'importer.o').read_bytes()
            relocations = links.read_tool('readelf', '-rW', work / 'importer.o')
            tables = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / 'importer.o'))
            imported = next(row for row in tables[0]['rows'] if row['name'] == 'domain_body')
            self.assertEqual(links.import_relocations(relocations, 'domain_body', image=image), [])
            self.assertTrue(links.symbol_only_import(tables, imported, relocations))
            for malformed in (relocations + 'unparsed relocation\n', '', 'relocation table truncated\n'):
                with self.subTest(malformed=malformed):
                    with self.assertRaisesRegex(ValueError, 'symbol-only import relocation tables differ'):
                        links.symbol_only_import(tables, imported, malformed)
            for mutation in ('wrong name', 'wrong ordinal', 'weak import', 'missing table'):
                with self.subTest(mutation=mutation):
                    changed, changed_tables = copy.deepcopy(imported), copy.deepcopy(tables)
                    if mutation == 'wrong name': changed['name'] = 'another_body'
                    elif mutation == 'wrong ordinal': changed['row_index'] += 1
                    elif mutation == 'weak import': changed['binding'] = 'WEAK'
                    else: changed_tables = []
                    with self.assertRaisesRegex(ValueError, 'symbol-only import'):
                        links.symbol_only_import(changed_tables, changed, relocations)
            (work / 'pointer.S').write_text('.data\n.quad domain_body\n.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([compiler, '-c', str(work / 'pointer.S'), '-o', str(work / 'pointer.o')],
                           check=True, capture_output=True)
            pointer_tables = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / 'pointer.o'))
            pointer_import = next(row for row in pointer_tables[0]['rows'] if row['name'] == 'domain_body')
            with self.assertRaisesRegex(ValueError, 'symbol-only import.*relocation'):
                links.symbol_only_import(pointer_tables, pointer_import, links.read_tool('readelf', '-rW', work / 'pointer.o'))
            for mode, flag in [('static', '-static'), ('static-pie', '-pie')]:
                result = subprocess.run([linker, flag, '-e', 'importer', '--trace', '--undefined=importer',
                    '-Map=' + str(work / (mode + '.map')), str(work / 'libdomain.a'), '-o', str(work / mode)],
                    check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.splitlines(), [str(work / 'libdomain.a') + '(importer.o)',
                                                              str(work / 'libdomain.a') + '(provider.o)'])
                final = links.inventory.parse_elf_symbol_tables(links.read_tool('readelf', '-Ws', work / mode))
                provider = next(row for table in final if table['name'] == '.symtab'
                                for row in table['rows'] if row['name'] == 'domain_body')
                self.assertEqual((provider['type'], provider['binding'], provider['size_bytes']), ('FUNC', 'GLOBAL', 1))
                self.assertNotEqual(provider['section_index'], 'UND')

    def test_link_commands_reserve_owned_driver_relative_sidecars(self):
        import crabc_cc_static as driver
        import native_abi_provider_links as links
        import owned_posix_product_evidence as products
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        previous = Path.cwd()
        try:
            os.chdir(ROOT)
            with tempfile.TemporaryDirectory(dir=scratch) as temporary:
                work = Path(temporary)
                os.chdir(work)
                installed = scratch / 'installed'
                for mode in links.MODES:
                    argv = links.command(installed, work, mode)
                    receipt = Path(argv[argv.index('--link-receipt') + 1])
                    paths = driver.receipt_sidecars(installed, receipt)
                    self.assertEqual(paths[0].absolute(), work / (mode + '.receipt.json'))
                    paths[1].write_text('retained map')
                    self.assertEqual(products._recorded_file(str(paths[1]), paths[0].absolute(), 'map'),
                                     work / (mode + '.receipt.map'))
        finally:
            os.chdir(previous)

    def test_real_object_forces_exact_complete_function_addresses(self):
        import native_abi_provider_links as links
        compiler = shutil.which('clang') or shutil.which('gcc')
        if compiler is None:
            self.skipTest('native compiler is required')
        scratch = ROOT / '.work/x86_64/provider-links-object-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            names = ['domain_body', 'sibling_body']
            source = work / 'forcing.c'
            source.write_text(links.source(names))
            subprocess.run([compiler, '-fPIE', '-fno-stack-protector', '-c', str(source),
                            '-o', str(work / 'forcing.o')], check=True, capture_output=True)
            proof = links.fixture_object(work / 'forcing.o', names)
            self.assertEqual([row['symbol'] for row in proof['references']], names)
            with self.assertRaisesRegex(ValueError, 'different symbol'):
                links.fixture_object(work / 'forcing.o', ['different_body', 'sibling_body'])
            with self.assertRaisesRegex(ValueError, 'metadata differs'):
                links.fixture_object(work / 'forcing.o', ['domain_body'])
