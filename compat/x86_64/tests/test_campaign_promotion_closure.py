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
        upstream = (closure.ROOT / 'crabc-mimalloc/UPSTREAM.md').read_bytes()
        prefix.ChainReceiptRoundTripTests.setUp(self)
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
        self.start(patch.object(closure.ledger, 'validate_ledger', return_value={}))
        self.start(patch.object(closure.inventory, 'validate_inventory', return_value=capabilities))
        self.start(patch.object(closure.static, 'source_digest', return_value=self.source['content_sha256']))
        self.start(patch.object(closure.dynamic, 'source_digest', return_value=self.source['content_sha256']))
        self.start(patch.object(package.static_product_contract, 'source_digest', return_value=self.source['content_sha256']))
        self.start(patch.object(static_builder, 'DEFAULT_ALLOCATOR_BACKEND', 'native'))
        self.start(patch.dict(static_builder.build.__kwdefaults__, allocator_backend='native'))
        self.start(patch.dict(dynamic_builder.build.__kwdefaults__, allocator_backend='native'))
        self.start(patch.object(runner, 'tool_identity', return_value={'path': shutil.which('nm')}))
        path = self.root / 'crabc-mimalloc/UPSTREAM.md'
        path.parent.mkdir(parents=True)
        path.write_bytes(upstream)
        native_hash = hashlib.sha256(upstream).hexdigest()
        graph = {'edges': ['normal', 'build'], 'packages': ['crabc-mimalloc v0.1.0 ($SOURCE/crabc-mimalloc)'],
                 'c_allocator_selected': False, 'native_allocator_selected': True}
        object_path = self.root / 'symbols.o'
        source = self.root / 'symbols.S'
        source.write_text('.text\n.globl malloc,free,__crabc_x86_native_mimalloc_process_finalizer\nmalloc:\nfree:\n__crabc_x86_native_mimalloc_process_finalizer:\nret\n.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['gcc', '-c', str(source), '-o', str(object_path)], check=True)
        tree = self.root / '.work/static-tree'
        package_tests.OwnedStaticSysrootPackageTests.populate_tree(self, tree)
        subprocess.run(['ar', 'rcs', str(tree / 'usr/lib/native.a'), str(object_path)], check=True)
        (tree / 'usr/lib/libc.a').write_bytes((tree / 'usr/lib/native.a').read_bytes())
        (tree / 'usr/lib/native.a').unlink()
        self.static_provenance = {'dependency_graph': graph, 'allocator_lifecycle_test_audit': False,
                                  'allocator_backend': {'upstream_sha256': native_hash}}
        (tree / 'share/crabc/libc-static.provenance.json').write_text(json.dumps(self.static_provenance))
        document = json.loads((tree / 'share/crabc/manifest.json').read_text())
        document['allocator_backend'] = 'native'
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
            state = {'allocator_backend': 'native', 'allocator_lifecycle_test_audit': False}
            provenance = {**state, 'dependency_graph': graph,
                          'native_allocator': {'path': 'crabc-mimalloc/UPSTREAM.md', 'sha256': native_hash}}
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

    def test_current_complete_profile_and_native_physical_ownership_pass_before_public_policy(self):
        result = closure.validate_promotion_closure(self.complete())
        self.assertTrue(result['functional_readiness'])
        self.assertFalse(result['public_support'])
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

    def test_c_default_c_dependency_and_missing_reviewed_product_are_rejected(self):
        path = self.complete()
        with patch.object(static_builder, 'DEFAULT_ALLOCATOR_BACKEND', 'accepted-c'):
            with self.assertRaisesRegex(closure.PromotionClosureError, 'source still selects'):
                closure.validate_promotion_closure(path)
        with patch.object(closure.static, 'load_publication', return_value=None):
            with self.assertRaisesRegex(closure.PromotionClosureError, 'publications are required'):
                closure.validate_promotion_closure(path)
        target = self.provenance_paths[-1]
        document = json.loads(target.read_text())
        document['dependency_graph']['packages'].append('libmimalloc-sys v0.1.0')
        target.write_text(json.dumps(document))
        with self.assertRaisesRegex(closure.PromotionClosureError, 'dependency ownership differs'):
            closure.validate_promotion_closure(path)

    def test_foreign_product_source_and_actual_c_allocator_symbol_are_rejected(self):
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
        with self.assertRaisesRegex(dynamic_builder.common.BuildError, 'native allocator ownership violated'):
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
