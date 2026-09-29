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
        accounting = self.accounting(private=True)
        leaked = copy.deepcopy(accounting['occurrences'][0])
        leaked.update(index=2, artifact_key='candidate-shared', table='.dynsym', member_name=None)
        accounting['occurrences'].append(leaked)
        self.assertEqual(self.attach(accounting, self.proof(accounting)), [])
        self.assertTrue(accounting['blockers'])


class ProviderFixtureObjectTests(unittest.TestCase):
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
