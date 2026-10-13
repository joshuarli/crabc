#!/usr/bin/env python3
"""Physical ordered-receipt and installed-ownership composition boundaries.

The existing case fixture executes real subprocesses and retains their logs.
Product publication readers are isolated at their already-tested owning API;
packaging, extraction, dependency records and ELF symbol checks run physically.
The tiny symbol objects are inspection fixtures, never allocator implementations.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "compat/x86_64"))

import test_qualification_prefix as prefix
manifest, runner = prefix.manifest, prefix.runner
import test_owned_static_sysroot_package as package_tests
package = package_tests.package
import campaign_promotion_closure as closure
from scripts import build_x86_64_owned_sysroot as static_builder
from scripts import build_x86_64_owned_dynamic_sysroot as dynamic_builder


class PromotionClosureTests(unittest.TestCase):
    def setUp(self):
        data = copy.deepcopy(closure.ledger.load_toml(closure.ledger.LEDGER_PATH))
        capabilities = copy.deepcopy(closure.inventory.build_inventory())
        prefix.ChainReceiptRoundTripTests.setUp(self)
        data['completion'] = {'qualification_profile': 'correctness', 'deferred_families': ['performance.release']}
        for family in data['family']:
            if family['id'] != 'performance.release':
                family['status'] = 'foundation-verified'
        for capability in capabilities['capabilities']:
            capability['contract_state'] = 'implemented-foundation'
        self.data = data
        self.capabilities = capabilities
        for target, name, value in ((closure, 'ROOT', self.root), (closure, 'qualification', runner),
                                    (closure, 'manifest', manifest), (closure, 'package', package),
                                    (closure.static, 'ROOT', self.root), (closure.dynamic, 'ROOT', self.root)):
            self.start(patch.object(target, name, value))
        self.start(patch.object(closure.ledger, 'load_toml', return_value=data))
        self.ledger_validation = self.start(
            patch.object(closure.ledger, 'validate_ledger', return_value={})
        )
        self.start(patch.object(closure.inventory, 'validate_inventory', return_value=capabilities))
        self.start(patch.object(closure.static, 'source_digest', return_value=self.source['content_sha256']))
        self.start(patch.object(closure.dynamic, 'source_digest', return_value=self.source['content_sha256']))
        self.start(patch.object(package.static_product_contract, 'source_digest', return_value=self.source['content_sha256']))
        self.start(patch.object(static_builder, 'DEFAULT_ALLOCATOR_BACKEND', 'accepted-c'))
        self.start(patch.dict(static_builder.build.__kwdefaults__, allocator_backend='accepted-c'))
        self.start(patch.dict(dynamic_builder.build.__kwdefaults__, allocator_backend='accepted-c'))
        self.start(patch.object(runner, 'tool_identity', return_value={'path': shutil.which('nm')}))
        allocator_hash = 'a' * 64
        graph = {'edges': ['normal', 'build'], 'packages': ['libmimalloc-sys v0.1.49'],
                 'c_allocator_selected': True, 'native_allocator_selected': False}
        object_path = self.root / 'symbols.o'
        source = self.root / 'symbols.S'
        source.write_text('.text\n.globl malloc,free,mi_malloc,mi_free\n.hidden mi_malloc,mi_free\n'
                          'malloc:\nfree:\nmi_malloc:\nmi_free:\nret\n.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['gcc', '-c', str(source), '-o', str(object_path)], check=True)
        tree = self.root / '.work/static-tree'
        package_tests.OwnedStaticSysrootPackageTests.populate_tree(self, tree)
        subprocess.run(['ar', 'rcs', str(tree / 'usr/lib/native.a'), str(object_path)], check=True)
        (tree / 'usr/lib/libc.a').write_bytes((tree / 'usr/lib/native.a').read_bytes())
        (tree / 'usr/lib/native.a').unlink()
        allocator_sources = {'libmimalloc-sys/c_src/mimalloc/v3/src/static.c': allocator_hash,
                             'include/crabc/stdlib.h': allocator_hash}
        self.static_provenance = {'dependency_graph': graph, 'allocator_lifecycle_test_audit': False,
                                  'allocator_backend': {
                                      'crate': static_builder.C_ALLOCATOR_PIN,
                                      'archive_sha256': allocator_hash,
                                      'member': 'a' * 16 + '-static.o',
                                      'member_sha256': allocator_hash,
                                      'implementation': 'accepted C backend; native Rust promotion remains separate',
                                      'compiler': {'path': '/usr/bin/gcc', 'resolved_path': '/usr/bin/gcc',
                                                  'sha256': allocator_hash},
                                      'source_and_header_sha256': allocator_sources,
                                  }}
        (tree / 'share/crabc/libc-static.provenance.json').write_text(json.dumps(self.static_provenance))
        document = json.loads((tree / 'share/crabc/manifest.json').read_text())
        document['allocator_backend'] = 'accepted-c'
        document['installed']['files'] = {p.relative_to(tree).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in tree.rglob('*') if p.is_file() and p.name != 'manifest.json'}
        (tree / 'share/crabc/manifest.json').write_text(json.dumps(document))
        self.archive = self.root / '.work/static-report/archives/primary.tar.xz'
        self.archive.parent.mkdir(parents=True)
        package.create_archive(tree, self.archive)
        self.static_receipt = {'report': '.work/static-report', 'source_sha256': self.source['content_sha256']}
        self.dynamic_receipt = {'work': '.work/dynamic', 'source_sha256': self.source['content_sha256']}
        self.static_reader = self.start(patch.object(closure.static, 'load_publication', return_value=self.static_receipt))
        self.dynamic_reader = self.start(patch.object(closure.dynamic, 'load_publication', return_value=self.dynamic_receipt))
        loader = self.root / 'loader.S'
        loader.write_text('.text\n.globl loader_anchor\nloader_anchor: ret\n.section .note.GNU-stack,"",@progbits\n')
        self.provenance_paths = []
        for name in ('installed', 'second', 'extracted'):
            tree = self.root / '.work/dynamic' / name
            (tree / 'share/crabc').mkdir(parents=True)
            (tree / 'usr/lib').mkdir(parents=True)
            (tree / 'lib').mkdir()
            state = {'allocator_backend': 'accepted-c', 'allocator_lifecycle_test_audit': False}
            provenance = {**state, 'dependency_graph': graph,
                          'accepted_allocator': dynamic_builder.common.C_ALLOCATOR_PIN,
                          'allocator_headers': allocator_sources,
                          'allocator_compiler': {'path': '/usr/bin/gcc', 'resolved_path': '/usr/bin/gcc',
                                                 'sha256': allocator_hash},
                          'shared_mimalloc_hidden_exports': {
                              'source': {'path': 'libc/src/c_abi/x86_64/owned_mimalloc_hidden.list',
                                         'sha256': dynamic_builder.MIMALLOC_V3_HIDDEN_LIST_SHA256},
                              'member_count': 2, 'members': ['mi_free', 'mi_malloc'],
                              'linker_policy': 'exact-local-symbols',
                          }}
            (tree / 'share/crabc/dynamic-product-state.json').write_text(json.dumps(state))
            path = tree / 'share/crabc/libc-shared.provenance.json'
            path.write_text(json.dumps(provenance))
            self.provenance_paths.append(path)
            subprocess.run(['gcc', '-shared', '-nostdlib', str(object_path), '-o', str(tree / 'usr/lib/libc.so')], check=True)
            subprocess.run(['gcc', '-shared', '-nostdlib', str(loader), '-o', str(tree / 'lib/ld-crabc-x86_64.so.1')], check=True)

    def start(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def complete(self, profile='correctness'):
        report = manifest.load_contract()
        return runner.run_chain(report, manifest.active_chain(profile)[-1], profile=profile)[0]

    def test_current_complete_profile_and_accepted_c_physical_ownership_pass_before_public_policy(self):
        result = closure.validate_promotion_closure(self.complete())
        self.assertTrue(result['functional_readiness'])
        self.assertFalse(result['public_support'])
        self.ledger_validation.assert_called_once_with(self.data, require_receipts=True)
        self.assertEqual(self.static_reader.call_count, 2)
        self.assertEqual(self.dynamic_reader.call_count, 2)

    def test_missing_partial_stale_and_tampered_receipts_never_establish_readiness(self):
        with self.assertRaises(closure.PromotionClosureError):
            closure.validate_promotion_closure(None)
        partial = runner.run_chain(manifest.load_contract(), manifest.CHAIN[1])[0]
        with self.assertRaisesRegex(closure.PromotionClosureError, 'complete selected profile'):
            closure.validate_promotion_closure(partial)
        path = self.complete()
        old = self.source
        self.source = {'revision': 'c' * 40, 'content_sha256': 'd' * 64}
        with self.assertRaisesRegex(runner.QualificationRunError, 'source is stale'):
            closure.validate_promotion_closure(path)
        self.source = old
        document = json.loads(path.read_text())
        log = path.parent / document['cases'][0]['stdout']['path']
        log.chmod(0o644)
        log.write_bytes(b'forged PASS\n')
        with self.assertRaises(runner.QualificationRunError):
            closure.validate_promotion_closure(path)

    def test_native_default_c_dependency_and_missing_reviewed_product_are_rejected(self):
        path = self.complete()
        with patch.object(static_builder, 'DEFAULT_ALLOCATOR_BACKEND', 'native'):
            with self.assertRaisesRegex(closure.PromotionClosureError, 'accepted-C allocator default'):
                closure.validate_promotion_closure(path)
        with patch.object(closure.static, 'load_publication', return_value=None):
            with self.assertRaisesRegex(closure.PromotionClosureError, 'publications are required'):
                closure.validate_promotion_closure(path)
        target = self.provenance_paths[-1]
        document = json.loads(target.read_text())
        document['dependency_graph']['packages'].append('crabc-mimalloc v0.1.0')
        document['dependency_graph']['c_allocator_selected'] = False
        document['dependency_graph']['native_allocator_selected'] = True
        target.write_text(json.dumps(document))
        with self.assertRaisesRegex(closure.PromotionClosureError, 'dependency ownership differs'):
            closure.validate_promotion_closure(path)

    def test_foreign_product_source_and_unowned_allocator_symbol_are_rejected(self):
        path = self.complete()
        self.dynamic_receipt['source_sha256'] = 'd' * 64
        with self.assertRaisesRegex(closure.PromotionClosureError, 'product source differs'):
            closure.validate_promotion_closure(path)
        self.dynamic_receipt['source_sha256'] = self.source['content_sha256']
        foreign = self.root / 'foreign.S'
        foreign.write_text('.text\n.globl _mi_foreign\n_mi_foreign: ret\n.section .note.GNU-stack,"",@progbits\n')
        product = self.provenance_paths[-1].parents[2]
        subprocess.run(['gcc', '-shared', '-nostdlib', str(self.root / 'symbols.o'), str(foreign),
                        '-o', str(product / 'usr/lib/libc.so')], check=True)
        with self.assertRaisesRegex(closure.PromotionClosureError, 'accepted-C allocator symbol ownership'):
            closure.validate_promotion_closure(path)

    def test_unowned_static_c_allocator_import_is_rejected(self):
        path = self.complete()
        tree = self.root / '.work/static-tree'
        assembly = self.root / 'dormant.S'
        object_path = self.root / 'dormant.o'
        symbol = 'mi_foreign'
        assembly.write_text('.text\n.globl dormant_c_member\n'
                            f'dormant_c_member: call {symbol}; ret\n'
                            '.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['gcc', '-c', str(assembly), '-o', str(object_path)], check=True)
        archive = tree / 'usr/lib/libc.a'
        subprocess.run(['ar', 'rcs', str(archive), str(object_path)], check=True)
        imports = subprocess.check_output(['nm', '--undefined-only', str(archive)]).decode()
        self.assertIn(symbol, imports)
        manifest_path = tree / 'share/crabc/manifest.json'
        document = json.loads(manifest_path.read_text())
        document['installed']['files']['usr/lib/libc.a'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(document))
        self.archive.unlink()
        package.create_archive(tree, self.archive)
        with self.assertRaisesRegex(closure.PromotionClosureError, 'static accepted-C allocator symbol ownership'):
            closure.validate_promotion_closure(path)

    def test_functional_family_failure_is_not_hidden_by_complete_receipt(self):
        next(row for row in self.data['family'] if row['id'] == 'libc.resolver')['status'] = 'planned'
        with self.assertRaisesRegex(closure.PromotionClosureError, 'prerequisite families'):
            closure.validate_promotion_closure(self.complete())

    def test_selected_capability_and_product_change_during_read_are_rejected(self):
        path = self.complete()
        self.capabilities['capabilities'][0]['contract_state'] = 'selected-partial'
        with self.assertRaisesRegex(closure.PromotionClosureError, 'capability implementation'):
            closure.validate_promotion_closure(path)
        self.capabilities['capabilities'][0]['contract_state'] = 'implemented-foundation'
        with patch.object(closure.dynamic, 'load_publication', side_effect=[self.dynamic_receipt, None]):
            with self.assertRaisesRegex(closure.PromotionClosureError, 'changed during promotion'):
                closure.validate_promotion_closure(path)

    def test_full_profile_requires_terminal_performance_case(self):
        document = json.loads(self.contract.read_text())
        document['qualification_profile'] = 'full'
        self.contract.write_text(json.dumps(document))
        self.data['completion'] = {'qualification_profile': 'full', 'deferred_families': []}
        next(row for row in self.data['family'] if row['id'] == 'performance.release')['status'] = 'foundation-verified'
        partial = runner.run_chain(manifest.load_contract(), 'capability.accounting', profile='full')[0]
        with self.assertRaisesRegex(closure.PromotionClosureError, 'complete selected profile'):
            closure.validate_promotion_closure(partial)
        self.assertTrue(closure.validate_promotion_closure(self.complete('full'))['functional_readiness'])
