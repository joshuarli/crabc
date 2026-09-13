"""Focused selector boundary tests for the four pthread timed aliases."""
from __future__ import annotations

import copy
import functools
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


ALIASES = (
    ('pthread_cond_timedwait', '__pthread_cond_timedwait'),
    ('pthread_mutex_timedlock', '__pthread_mutex_timedlock'),
    ('pthread_timedjoin_np', '__pthread_timedjoin_np'),
    ('pthread_tryjoin_np', '__pthread_tryjoin_np'),
)
SOURCE_CONTRACT_PATHS = (
    'libc/Cargo.toml',
    'libc/src/c_abi/x86_64/static_c_abi.rs',
    'libc/src/c_abi/x86_64/owned_pthread_cond.rs',
    'libc/src/c_abi/x86_64/pthread_cond.rs',
    'libc/src/c_abi/x86_64/pthread_create_join.rs',
    'libc/src/c_abi/x86_64/pthread_mutex.rs',
    'compat/x86_64/parity.toml',
    'scripts/build_x86_64_owned_sysroot.py',
)
COLLECTOR_PATHS = {
    'probe': 'compat/x86_64/owned_pthread_timed_feature_contract_probe.c',
    'reader': 'compat/x86_64/owned_pthread_timed_feature_contract_reader.py',
    'runner': 'compat/x86_64/run_owned_pthread_timed_feature_contract.sh',
    'syscall_authority': 'compat/x86_64/owned_syscall_alias_authority.py',
    'static_authority': 'compat/x86_64/owned_static_link_authority.py',
    'elf_authority': 'compat/x86_64/loader_debug_abi_evidence.py',
    'static_preparation_owner': 'compat/x86_64/owned_posix_static_products.py',
    'static_package_owner': 'compat/x86_64/owned_static_sysroot_package.py',
    'product_validator': 'compat/x86_64/owned_posix_product_evidence.py',
    'dynamic_probe_authority': 'compat/x86_64/owned_pthread_timed_dynamic_authority.py',
    'image_manifest': 'compat/x86_64/owned_pthread_timed_feature_image_inputs.json',
}
STATIC_LINK_INPUTS = {
    'static_crt1': 'usr/lib/crt1.o', 'static_rcrt1': 'usr/lib/rcrt1.o',
    'static_crti': 'usr/lib/crti.o', 'static_crtn': 'usr/lib/crtn.o',
    'static_libc': 'usr/lib/libc.a', 'static_builtins': 'usr/lib/libcrabc-builtins.a',
}
DYNAMIC_LINK_INPUTS = {
    'dynamic_crt1': 'usr/lib/crt1.o', 'dynamic_scrt1': 'usr/lib/Scrt1.o',
    'dynamic_crti': 'usr/lib/crti.o', 'dynamic_crtn': 'usr/lib/crtn.o',
    'dynamic_attach': 'usr/lib/crabc-dynamic-attach.o',
    'dynamic_builtins': 'usr/lib/libcrabc-builtins.a', 'dynamic_libc': 'usr/lib/libc.so',
}
INPUT_NAMES = (
    'probe', 'reader', 'runner', 'oracle_compiler', 'musl_shared', 'musl_archive',
    'static_driver', 'static_libc', 'static_crt1', 'static_rcrt1', 'static_crti', 'static_crtn', 'static_builtins',
    'dynamic_driver', 'dynamic_crt1', 'dynamic_scrt1', 'dynamic_crti', 'dynamic_crtn',
    'dynamic_attach', 'dynamic_builtins', 'dynamic_libc', 'dynamic_loader',
    'product_report', 'static_preparation',
)


class FakeReader:
    ROOT = ROOT
    __file__ = str(ROOT / 'compat/x86_64/owned_pthread_timed_feature_contract_reader.py')
    SCHEMA = 'crabc.x86_64-owned-pthread-timed-feature-contract/v1'
    STATUS = 'component-verified'
    COMPONENT = 'pthread-timed-feature-alias-linkage'
    FEATURE = 'x86-owned-static-runtime'
    ALIASES = ALIASES
    FEATURE_ALIASES = ALIASES
    ARCHIVE_HIDDEN = tuple(provider for _public, provider in ALIASES)
    ARCHIVE_LOCAL = ()
    INPUT_NAMES = INPUT_NAMES
    SOURCE_CONTRACT_PATHS = SOURCE_CONTRACT_PATHS
    COLLECTOR_PATHS = COLLECTOR_PATHS
    ReceiptError = ValueError

    def __init__(self, report: dict[str, object]):
        self.report = report

    @staticmethod
    def _coverage() -> dict[str, object]:
        return {'aliases': [list(pair) for pair in ALIASES], 'limits': ['finite']}

    @staticmethod
    def evaluate_feature_source(_root: Path) -> dict[str, object]:
        return {'feature': 'x86-owned-static-runtime',
                'aliases': [{'public': public, 'provider': provider} for public, provider in ALIASES]}

    def validate_report(self, report_path: Path) -> dict[str, object]:
        for relative, artifact in self.report['artifacts'].items():
            if Path(relative).is_absolute():
                continue
            path = report_path.parent / relative
            if path.exists() and selection._identity_payload(artifact, 'fake retained artifact') != selection._identity_payload(
                    selection.file_identity(path), 'fake retained artifact current'):
                raise self.ReceiptError('retained artifact changed')
        return copy.deepcopy(self.report)


def _symbol(name: str, binding: str, visibility: str, value: str) -> dict[str, object]:
    return {
        'name': name, 'raw_name': name, 'version': None, 'version_default': False,
        'binding': binding, 'visibility': visibility, 'section_index': '1',
        'type': 'FUNC', 'value': value, 'size_bytes': 4, 'size': '4',
        'row_index': 1, 'raw': name, 'other': None, 'version_index': None,
        'common_alignment': None,
    }


def _occurrence(index: int, name: str, artifact: str, table: str, binding: str,
                visibility: str, value: str) -> dict[str, object]:
    return {
        'index': index, 'artifact_key': artifact, 'member_name': None,
        'member_index': None, 'member_occurrence': None, 'table': table,
        'table_section_index': 1, 'definition_section': {'name': '.text'},
        'role': 'definition', 'row': _symbol(name, binding, visibility, value),
    }


class NativePthreadTimedAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        checkout.start()
        self.addCleanup(checkout.stop)
        parent = ROOT / '.work/x86_64/native-abi-pthread-timed-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static, self.dynamic = self.work / 'static', self.work / 'dynamic'
        self._write_products()
        self.base = self._write('base.json', b'base\n')
        self.elf = self._write('elf.json', b'elf\n')
        self.preparation = self._write('preparation.json', b'preparation\n')
        self.anchor = self._write('loader-debug.json', b'loader debug\n')
        self.report_path = self._write('receipt.json', b'{}\n')
        self.paths = {
            'measurement_checkout': ROOT, 'base_inventory': self.base, 'elf_report': self.elf,
            'static_preparation': self.preparation, 'static_product': self.static,
            'dynamic_product': self.dynamic,
        }
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.measurement = {
            'candidate_build': {'revision': self.source['revision'], 'source_content_sha256': self.source['content_sha256']},
            'reports': {
                'elf_report': selection.file_identity(self.elf),
                'base_inventory': selection.file_identity(self.base),
                'static_preparation': selection.file_identity(self.preparation),
            },
        }
        self.facts = {'artifacts': {
            'candidate-static': {'identity': selection.file_identity(self.static / 'usr/lib/libc.a')},
            'candidate-shared': {'identity': selection.file_identity(self.dynamic / 'usr/lib/libc.so')},
            'candidate-loader': {'identity': selection.file_identity(self.dynamic / 'lib/ld-crabc-x86_64.so.1')},
        }}

    def _write(self, name: str, data: bytes) -> Path:
        path = self.work / name
        path.write_bytes(data)
        return path

    def _write_products(self) -> None:
        files = (
            (self.static / 'bin/crabc-cc', b'static driver\n'),
            (self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n'),
            (self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n'),
            (self.dynamic / 'share/crabc/dynamic-product-state.json', b'dynamic state\n'),
            (self.dynamic / 'share/crabc/libc-shared.provenance.json', b'dynamic provenance\n'),
        )
        for path, data in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name, relative in STATIC_LINK_INPUTS.items():
            path = self.static / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes((name + '\n').encode())
        for name, relative in DYNAMIC_LINK_INPUTS.items():
            path = self.dynamic / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes((name + '\n').encode())
        (self.dynamic / 'usr/lib/libc.so').chmod(0o755)
        self._write_manifests()

    def _write_manifests(self) -> None:
        static = self.static / 'share/crabc/manifest.json'
        static.parent.mkdir(parents=True, exist_ok=True)
        static.write_text(json.dumps({'installed': {'files': {
            relative: hashlib.sha256((self.static / relative).read_bytes()).hexdigest()
            for relative in (*STATIC_LINK_INPUTS.values(), 'bin/crabc-cc')
        }}}, sort_keys=True))
        dynamic = self.dynamic / 'share/crabc/manifest.json'
        dynamic.parent.mkdir(parents=True, exist_ok=True)
        dynamic.write_text(json.dumps({'files': {
            relative: hashlib.sha256((self.dynamic / relative).read_bytes()).hexdigest()
            for relative in (*DYNAMIC_LINK_INPUTS.values(), 'bin/crabc-cc-dynamic',
                             'lib/ld-crabc-x86_64.so.1', 'share/crabc/dynamic-product-state.json')
        }}, sort_keys=True))

    @staticmethod
    def _identity(path: Path) -> dict[str, object]:
        return selection.file_identity(path)

    def _retain(self, source: Path, name: str, artifacts: dict[str, object]) -> str:
        relative = 'retained/' + name
        target = self.report_path.parent / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(source.stat().st_mode & 0o777)
        identity = self._identity(target)
        identity['path'] = relative
        artifacts[relative] = identity
        return relative

    def _receipt(self) -> dict[str, object]:
        artifacts: dict[str, object] = {}
        selected_files = {}
        for name in SOURCE_CONTRACT_PATHS:
            retained = self._retain(ROOT / name, 'source/' + name, artifacts)
            selected_files[name] = artifacts[retained]
        collector_files = {}
        for name, relative in COLLECTOR_PATHS.items():
            retained = self._retain(ROOT / relative, 'collector/' + name, artifacts)
            collector_files[name] = artifacts[retained]
        inputs: dict[str, object] = {}
        sources: dict[str, Path] = {
            'probe': ROOT / COLLECTOR_PATHS['probe'],
            'reader': ROOT / COLLECTOR_PATHS['reader'],
            'runner': ROOT / COLLECTOR_PATHS['runner'],
            'static_driver': self.static / 'bin/crabc-cc',
            'static_libc': self.static / 'usr/lib/libc.a',
            'static_crt1': self.static / 'usr/lib/crt1.o',
            'static_rcrt1': self.static / 'usr/lib/rcrt1.o',
            'static_crti': self.static / 'usr/lib/crti.o',
            'static_crtn': self.static / 'usr/lib/crtn.o',
            'static_builtins': self.static / 'usr/lib/libcrabc-builtins.a',
            'dynamic_driver': self.dynamic / 'bin/crabc-cc-dynamic',
            'dynamic_crt1': self.dynamic / 'usr/lib/crt1.o',
            'dynamic_scrt1': self.dynamic / 'usr/lib/Scrt1.o',
            'dynamic_crti': self.dynamic / 'usr/lib/crti.o',
            'dynamic_crtn': self.dynamic / 'usr/lib/crtn.o',
            'dynamic_attach': self.dynamic / 'usr/lib/crabc-dynamic-attach.o',
            'dynamic_builtins': self.dynamic / 'usr/lib/libcrabc-builtins.a',
            'dynamic_libc': self.dynamic / 'usr/lib/libc.so',
            'dynamic_loader': self.dynamic / 'lib/ld-crabc-x86_64.so.1',
            'product_report': self.anchor,
            'static_preparation': self.preparation,
        }
        for name in ('oracle_compiler', 'musl_shared', 'musl_archive'):
            sources[name] = self._write(name, (name + '\n').encode())
        for name in INPUT_NAMES:
            retained = self._retain(sources[name], 'inputs/' + name, artifacts)
            inputs[name] = {'original_path': str(sources[name]), 'retained': retained}
        static_manifest = self._retain(self.static / 'share/crabc/manifest.json', 'products/static-manifest.json', artifacts)
        dynamic_manifest = self._retain(self.dynamic / 'share/crabc/manifest.json', 'products/dynamic-manifest.json', artifacts)
        dynamic_state = self._retain(self.dynamic / 'share/crabc/dynamic-product-state.json', 'products/dynamic-state.json', artifacts)
        anchor = self._retain(self.anchor, 'products/anchor-report.json', artifacts)
        static_driver = self._retain(self.static / 'bin/crabc-cc', 'products/static-driver', artifacts)
        static_libc = self._retain(self.static / 'usr/lib/libc.a', 'products/static-libc.a', artifacts)
        dynamic_driver = self._retain(self.dynamic / 'bin/crabc-cc-dynamic', 'products/dynamic-driver', artifacts)
        dynamic_libc = self._retain(self.dynamic / 'usr/lib/libc.so', 'products/dynamic-libc.so', artifacts)
        dynamic_loader = self._retain(self.dynamic / 'lib/ld-crabc-x86_64.so.1', 'products/dynamic-loader', artifacts)
        observations = {
            'aliases': [{'public': public, 'provider': provider} for public, provider in ALIASES],
            'archive_hidden_providers': [provider for _public, provider in ALIASES],
            'archive_local_providers': [],
            'alias_shapes': {mode: {public: ['FUNC', 'WEAK', 'DEFAULT'] for public, _provider in ALIASES}
                             for mode in ('dynamic', 'shared', 'static')},
            'same_definition': {mode: {
                public: {'alias': {'name': public}, 'provider': {'name': provider}}
                for public, provider in ALIASES
            } for mode in ('musl_shared', 'musl_static', 'shared', 'static')},
        }
        return {
            'schema': FakeReader.SCHEMA, 'status': FakeReader.STATUS, 'component': FakeReader.COMPONENT,
            'public_support': False, 'family_complete': False, 'promotion_ready': False,
            'selected_source': {'revision': self.source['revision'], 'source_sha256': self.source['content_sha256'],
                                'files': selected_files},
            'collector': {'source_before': {'revision': self.source['revision'], 'content_sha256': self.source['content_sha256']},
                          'source_after': {'revision': self.source['revision'], 'content_sha256': self.source['content_sha256']},
                          'files': collector_files},
            'inputs': inputs, 'artifacts': artifacts,
            'selected_products': {
                'anchor': {'report': anchor, 'schema': 'crabc.x86_64-loader-debug-crt-abi/v1',
                           'source_commit': self.source['revision'], 'source_sha256': self.source['content_sha256']},
                'static': {'manifest': static_manifest, 'driver': static_driver, 'libc': static_libc,
                           'original_paths': {}},
                'dynamic': {'manifest': dynamic_manifest, 'state': dynamic_state, 'driver': dynamic_driver,
                            'libc': dynamic_libc, 'loader': dynamic_loader, 'original_paths': {}},
            },
            'product_input_modes': selection._pthread_timed_source_link_input_modes(),
            'coverage': FakeReader._coverage(), 'feature_source': FakeReader.evaluate_feature_source(ROOT),
            'alias_observations': observations,
        }

    def _adapter(self, receipt: dict[str, object] | None = None) -> dict[str, object] | None:
        with mock.patch.object(selection, '_pthread_timed_feature_reader', return_value=FakeReader(receipt or self._receipt())):
            return selection.native_pthread_timed_feature_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement, paths=self.paths,
                source=self.source, product_anchor=self.anchor,
            )

    def _feature(self, public: str, provider: str) -> dict[str, object]:
        actual = self._actual_feature(public)
        if actual.get('target') != provider:
            raise AssertionError(f'feature target differs: {public}')
        return copy.deepcopy(actual)

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _actual_feature(public: str) -> dict[str, object]:
        contract_path = ROOT / 'compat/x86_64/native-abi-selection.toml'
        contract = selection.load_contract(contract_path)
        inputs = selection.load_source_inputs(contract, contract_path)
        records = selection.expand_obligations(contract, inputs)
        record = next(record for record in records if record['identity']['name'] == public)
        requirements = record.get('function_alias_requirements')
        if type(requirements) is not list or len(requirements) != 1:
            raise AssertionError(f'missing exact feature requirement: {public}')
        return copy.deepcopy(requirements[0])

    def test_feature_fixture_uses_the_complete_current_source_record(self) -> None:
        for public, provider in ALIASES:
            with self.subTest(public=public):
                self.assertEqual(self._feature(public, provider), self._actual_feature(public))

    def _accounting(self, extra_named: bool = False) -> dict[str, object]:
        occurrences, index = [], 0
        function_observations = []
        for number, (public, provider) in enumerate(ALIASES, start=1):
            value = f'{number:016x}'
            static_alias = index
            occurrences.append(_occurrence(index, public, 'candidate-static', '.symtab', 'WEAK', 'DEFAULT', value)); index += 1
            occurrences.append(_occurrence(index, public, 'candidate-shared', '.dynsym', 'WEAK', 'DEFAULT', value)); index += 1
            occurrences.append(_occurrence(index, public, 'candidate-shared', '.symtab', 'WEAK', 'DEFAULT', value)); index += 1
            static_provider = index
            occurrences.append(_occurrence(index, provider, 'candidate-static', '.symtab', 'GLOBAL', 'HIDDEN', value)); index += 1
            occurrences.append(_occurrence(index, provider, 'candidate-shared', '.symtab', 'LOCAL', 'HIDDEN', value)); index += 1
            feature = self._feature(public, provider)
            function_observations.append({
                'identity': {'name': public, 'version': None, 'version_default': False},
                'target': {'name': provider, 'version': None, 'version_default': False},
                'artifact_key': 'candidate-static', 'same_domain_pairs': [[static_alias, static_provider]],
                'feature_contract': feature, 'feature_archive_receipt_proven': False,
                'runtime_semantics_proven': False,
            })
        if extra_named:
            occurrences.append(_occurrence(index, ALIASES[0][0], 'candidate-static', '.dynsym', 'WEAK', 'DEFAULT', '1')); index += 1
        occurrences.append(_occurrence(index, 'unowned_pthread_fact', 'candidate-static', '.symtab', 'GLOBAL', 'DEFAULT', '9')); index += 1
        occurrences.append(_occurrence(index, '', 'candidate-shared', '.symtab', 'LOCAL', 'DEFAULT', 'a')); index += 1
        identities, blockers = [], []
        for public, provider in ALIASES:
            item = {'name': public, 'version': None, 'version_default': False}
            identities.append({'identity': item, 'selection': {'disposition': 'public-provider'},
                               'function_alias_requirements': [self._feature(public, provider)],
                               'unresolved': [selection.PTHREAD_TIMED_FEATURE_RECEIPT_REQUIREMENT]})
            blockers.append({'code': 'identity-unresolved', 'identity': copy.deepcopy(item),
                             'reason': selection.PTHREAD_TIMED_FEATURE_RECEIPT_REQUIREMENT})
        untouched = {'name': 'unrelated_pthread', 'version': None, 'version_default': False}
        identities.append({'identity': untouched, 'selection': {'disposition': 'public-provider'},
                           'unresolved': [selection.ORDINARY_IMPORT_REASON]})
        blockers.append({'code': 'identity-unresolved', 'identity': copy.deepcopy(untouched),
                         'reason': selection.ORDINARY_IMPORT_REASON})
        return {'identities': identities, 'placement_joins': [], 'occurrences': occurrences,
                'function_alias_observations': function_observations, 'blockers': blockers}

    def test_adapter_is_absent_without_receipt(self) -> None:
        self.assertIsNone(selection.native_pthread_timed_feature_adapter(
            None, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            product_anchor=None,
        ))

    def test_valid_receipt_discharges_only_the_four_existing_reasons(self) -> None:
        companion = self._adapter()
        self.assertEqual(companion['status'], 'pthread-timed-observed-with-boundaries')
        accounting = self._accounting()
        joins = selection.attach_native_pthread_timed_feature(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['aliases']), 4)
        self.assertEqual(joins[0]['complete_elf_occurrence_count'], 22)
        for record in accounting['identities'][:4]:
            self.assertEqual(record['unresolved'], [])
        self.assertEqual(accounting['identities'][-1]['unresolved'], [selection.ORDINARY_IMPORT_REASON])
        self.assertTrue(any(row['row']['name'] == '' for row in accounting['occurrences']))
        self.assertTrue(any(row['row']['name'] == 'unowned_pthread_fact' for row in accounting['occurrences']))

    def test_feature_requirement_metadata_must_match_the_current_source_record(self) -> None:
        companion = self._adapter()
        accounting = self._accounting()
        forged = copy.deepcopy(accounting['identities'][0]['function_alias_requirements'][0])
        forged['baseline_features'] = ['forged-feature-baseline']
        accounting['identities'][0]['function_alias_requirements'] = [forged]
        accounting['function_alias_observations'][0]['feature_contract'] = copy.deepcopy(forged)
        with self.assertRaises(selection.SelectionError):
            selection.attach_native_pthread_timed_feature(accounting, companion)

    def test_wrong_selected_source_is_rejected(self) -> None:
        receipt = self._receipt()
        record = receipt['selected_source']['files'][SOURCE_CONTRACT_PATHS[0]]
        record['sha256'] = '0' * 64
        with self.assertRaises(selection.SelectionError):
            self._adapter(receipt)

    def test_wrong_product_anchor_and_retained_product_are_rejected(self) -> None:
        receipt = self._receipt()
        receipt['inputs']['product_report']['retained'] = receipt['inputs']['static_libc']['retained']
        with self.assertRaises(selection.SelectionError):
            self._adapter(receipt)
        receipt = self._receipt()
        retained = self.report_path.parent / receipt['inputs']['static_libc']['retained']
        retained.write_bytes(b'forged static libc\n')
        with self.assertRaises(selection.SelectionError):
            self._adapter(receipt)

    def test_current_dynamic_state_must_match_the_retained_manifest_sidecar(self) -> None:
        receipt = self._receipt()
        state = self.dynamic / 'share/crabc/dynamic-product-state.json'
        state.write_bytes(b'mutated current dynamic state\n')
        with self.assertRaises(selection.SelectionError):
            self._adapter(receipt)

    def test_current_static_crt_dynamic_attach_and_builtins_modes_are_source_bound(self) -> None:
        for path in (self.static / 'usr/lib/crti.o', self.dynamic / 'usr/lib/crabc-dynamic-attach.o',
                     self.dynamic / 'usr/lib/libcrabc-builtins.a'):
            original = path.stat().st_mode & 0o777
            self.addCleanup(path.chmod, original)
            path.chmod(0o600)
            with self.assertRaises(selection.SelectionError, msg=str(path)):
                self._adapter()
            path.chmod(original)

    def test_alias_domain_extra_named_row_is_rejected_and_unknown_rows_remain(self) -> None:
        companion = self._adapter()
        with self.assertRaises(selection.SelectionError):
            selection.attach_native_pthread_timed_feature(self._accounting(extra_named=True), companion)
        accounting = self._accounting()
        before = copy.deepcopy(accounting['occurrences'])
        selection.attach_native_pthread_timed_feature(accounting, companion)
        self.assertEqual(accounting['occurrences'], before)

    def test_final_recheck_rejects_retained_mutation(self) -> None:
        companion = self._adapter()
        receipt = self._receipt()
        retained = self.report_path.parent / receipt['inputs']['dynamic_attach']['retained']
        retained.write_bytes(b'mutated after attachment\n')
        with (mock.patch.object(selection, '_pthread_timed_feature_reader', return_value=FakeReader(receipt)),
              mock.patch.object(selection, 'selection_source', return_value=self.source)):
            with self.assertRaises(selection.SelectionError):
                selection._recheck_runtime_receipt_cohort(
                    paths=self.paths, facts=self.facts, measurement=self.measurement, source=self.source,
                    registry=None, pthread=None, pthread_timed=companion,
                )


if __name__ == '__main__':
    unittest.main()
