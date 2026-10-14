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
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'compat/allocator/tests'))
from test_perf_engine_x86_64 import fixture_elf
import campaign_promotion_closure as closure
from scripts import build_x86_64_owned_sysroot as static_builder
from scripts import build_x86_64_owned_dynamic_sysroot as dynamic_builder


def symbol_archive(definitions, *, undefined=()):
    """Physical inspection fixture; no compiler or native execution."""
    body = fixture_elf(definitions, executable=False, undefined=undefined)
    header = f"{'symbols.o/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
    return b'!<arch>\n' + header + body + (b'\n' if len(body) % 2 else b'')


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
        self.accepted_symbols = {'malloc', 'free', 'mi_malloc', 'mi_free'}
        object_path.write_bytes(fixture_elf(self.accepted_symbols, executable=False))
        tree = self.root / '.work/static-tree'
        package_tests.OwnedStaticSysrootPackageTests.populate_tree(self, tree)
        (tree / 'usr/lib/libc.a').write_bytes(symbol_archive(self.accepted_symbols))
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
            (tree / 'usr/lib/libc.so').write_bytes(fixture_elf(self.accepted_symbols))
            (tree / 'lib/ld-crabc-x86_64.so.1').write_bytes(fixture_elf({'loader_anchor'}))

    def start(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def complete(self, profile='correctness'):
        report = manifest.load_contract()
        return runner.run_chain(report, manifest.active_chain(profile)[-1], profile=profile)[0]

    def native_product(self, kind):
        tree = self.root / '.work' / f'native-{kind}'
        (tree / 'usr/lib').mkdir(parents=True)
        (tree / 'share/crabc').mkdir(parents=True)
        (tree / 'lib').mkdir()
        upstream = Path(closure.__file__).resolve().parents[2] / 'crabc-mimalloc/UPSTREAM.md'
        target = self.root / 'crabc-mimalloc/UPSTREAM.md'
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(upstream.read_bytes())
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        graph = {'target': static_builder.TARGET, 'features': [f'x86-owned-{kind}-native-shadow'],
                 'edges': ['normal', 'build'], 'packages': ['crabc-mimalloc v0.3.0'],
                 'c_allocator_selected': False, 'native_allocator_selected': True}
        symbols = {'malloc', 'calloc', 'realloc', 'free', 'aligned_alloc', 'posix_memalign', 'malloc_usable_size'}
        provenance = {'dependency_graph': graph, 'allocator_lifecycle_test_audit': False}
        if kind == 'static':
            provenance['allocator_backend'] = {'implementation': 'native Rust; production-shaped selection',
                                               'upstream_sha256': digest, 'crate': None, 'compiler': None,
                                               'source_and_header_sha256': None}
            (tree / 'usr/lib/libc.a').write_bytes(symbol_archive(symbols))
        else:
            provenance.update(allocator_backend='native',
                              native_allocator={'path': 'crabc-mimalloc/UPSTREAM.md', 'sha256': digest},
                              accepted_allocator=None, allocator_headers=None, allocator_compiler=None,
                              excluded_c_allocator=None)
            (tree / 'usr/lib/libc.so').write_bytes(fixture_elf(
                symbols | {'__crabc_x86_native_mimalloc_process_finalizer'}))
            (tree / 'lib/ld-crabc-x86_64.so.1').write_bytes(fixture_elf({'loader_anchor'}))
        (tree / 'share/crabc/manifest.json').write_text(json.dumps({'allocator_backend': 'native'}))
        name = 'libc-static.provenance.json' if kind == 'static' else 'libc-shared.provenance.json'
        (tree / 'share/crabc' / name).write_text(json.dumps(provenance))
        return tree, provenance

    def test_native_physical_products_require_owned_graphs_provenance_and_symbols(self):
        for kind in ('static', 'dynamic'):
            with self.subTest(kind=kind):
                tree, provenance = self.native_product(kind)
                closure.validate_native_product(tree, kind, provenance, ar=shutil.which('ar'), nm=shutil.which('nm'))
                foreign = copy.deepcopy(provenance)
                foreign['dependency_graph']['packages'].append('libmimalloc-sys v0.1.49')
                with self.assertRaisesRegex(closure.PromotionClosureError, 'native dependency ownership'):
                    closure.validate_native_product(tree, kind, foreign, ar=shutil.which('ar'), nm=shutil.which('nm'))
                if kind == 'static':
                    (tree / 'usr/lib/libc.a').write_bytes(symbol_archive(
                        {'malloc', 'free'}, undefined={'mi_foreign'}))
                else:
                    (tree / 'lib/ld-crabc-x86_64.so.1').write_bytes(fixture_elf({'malloc'}))
                with self.assertRaisesRegex(dynamic_builder.common.BuildError, 'native allocator ownership'):
                    closure.validate_native_product(tree, kind, provenance, ar=shutil.which('ar'), nm=shutil.which('nm'))

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
            with self.assertRaisesRegex(closure.PromotionClosureError, 'mixed or unqualified allocator defaults'):
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
        product = self.provenance_paths[-1].parents[2]
        (product / 'usr/lib/libc.so').write_bytes(fixture_elf(self.accepted_symbols | {'_mi_foreign'}))
        with self.assertRaisesRegex(closure.PromotionClosureError, 'accepted-C allocator symbol ownership'):
            closure.validate_promotion_closure(path)

    def test_unowned_static_c_allocator_import_is_rejected(self):
        path = self.complete()
        tree = self.root / '.work/static-tree'
        symbol = 'mi_foreign'
        archive = tree / 'usr/lib/libc.a'
        archive.write_bytes(symbol_archive(self.accepted_symbols | {'dormant_c_member'}, undefined={symbol}))
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
