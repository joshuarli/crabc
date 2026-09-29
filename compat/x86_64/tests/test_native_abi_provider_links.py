"""Complete-function links bind archive imports without spelling heuristics."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import sys
import shutil
import subprocess
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
        compiler = shutil.which('gcc')
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
