"""Focused selector attachment tests for the finite syscall alias receipt."""
from __future__ import annotations

import copy
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
import owned_syscall_alias_contract_reader as syscall_reader


ALIASES = (
    ('clock_gettime', '__clock_gettime'), ('clock_nanosleep', '__clock_nanosleep'),
    ('dup3', '__dup3'), ('fstat', '__fstat'), ('fstatat', '__fstatat'),
    ('fstatfs', '__fstatfs'), ('lseek', '__lseek'), ('madvise', '__madvise'),
    ('mmap', '__mmap'), ('mprotect', '__mprotect'), ('munmap', '__munmap'),
    ('statfs', '__statfs'), ('sysinfo', '__lsysinfo'), ('sigaction', '__sigaction'),
)
ALIAS_GLOBAL_HIDDEN = tuple(body for _alias, body in ALIASES if body not in {'__statfs', '__fstatfs'})
GLOBAL_HIDDEN = (*ALIAS_GLOBAL_HIDDEN, '__libc_sigaction')
LOCAL_BODIES = ('__statfs', '__fstatfs')
PRIVATE_SOURCES = (
    'libc/src/c_abi/x86_64/clock_gettime.rs',
    'libc/src/c_abi/x86_64/clock_nanosleep.rs',
    'libc/src/c_abi/x86_64/descriptor_io.rs',
    'libc/src/c_abi/x86_64/stat_compat.rs',
    'libc/src/c_abi/x86_64/memory_mapping.rs',
    'libc/src/c_abi/x86_64/system_observation.rs',
    'libc/src/c_abi/x86_64/signal_control.rs',
    'compat/x86_64/owned-syscall-alias-contract.md',
)
STATIC_LINK_INPUTS = {
    'static_crt1': 'usr/lib/crt1.o',
    'static_rcrt1': 'usr/lib/rcrt1.o',
    'static_crti': 'usr/lib/crti.o',
    'static_crtn': 'usr/lib/crtn.o',
    'static_libc': 'usr/lib/libc.a',
    'static_builtins': 'usr/lib/libcrabc-builtins.a',
}
DYNAMIC_LINK_INPUTS = {
    'dynamic_crt1': 'usr/lib/crt1.o',
    'dynamic_Scrt1': 'usr/lib/Scrt1.o',
    'dynamic_crti': 'usr/lib/crti.o',
    'dynamic_crtn': 'usr/lib/crtn.o',
    'dynamic_libc': 'usr/lib/libc.so',
    'dynamic_builtins': 'usr/lib/libcrabc-builtins.a',
    'dynamic_attach': 'usr/lib/crabc-dynamic-attach.o',
}
RECEIPT_PRODUCT_INPUTS = (
    'selected_dynamic_list', 'static_libc', 'static_driver', 'static_manifest',
    'dynamic_libc', 'dynamic_driver', 'dynamic_loader', 'dynamic_manifest',
    'dynamic_producer_tools', 'dynamic_shared_provenance',
)


class FakeSyscallReader:
    """A process-free v2 reader fixture; native replay is owned by the reader."""

    ROOT = ROOT
    __file__ = str(ROOT / 'compat/x86_64/owned_syscall_alias_contract_reader.py')
    SCHEMA = 'crabc.x86_64-owned-syscall-alias-contract/v2'
    STATUS = {
        'component_complete': True, 'family_completion': False,
        'runtime_qualification': False, 'promotion_ready': False, 'public_support': False,
    }
    IMAGE = 'crabc-core-evidence@sha256:' + '5' * 64
    MUSL_SOURCE_COMMIT = '9' * 40
    ALIASES = ALIASES
    ALIAS_GLOBAL_HIDDEN = ALIAS_GLOBAL_HIDDEN
    GLOBAL_HIDDEN = GLOBAL_HIDDEN
    LOCAL_BODIES = LOCAL_BODIES
    COLLECTOR_SOURCES = syscall_reader.COLLECTOR_SOURCES
    RUNTIME_SOURCES = syscall_reader.RUNTIME_SOURCES
    ReceiptError = ValueError

    def __init__(self, report: dict[str, object]):
        self.report = report

    @staticmethod
    def component_projection() -> dict[str, object]:
        return {
            'aliases': [[alias, body] for alias, body in ALIASES],
            'alias_global_hidden': list(ALIAS_GLOBAL_HIDDEN),
            'global_hidden': list(GLOBAL_HIDDEN),
            'source_local': list(LOCAL_BODIES),
            'raw_private_body': '__libc_sigaction',
            'component_complete': True,
            'family_completion': False,
            'public_support': False,
        }

    def validate_report(self, report_path: Path) -> dict[str, object]:
        return copy.deepcopy(self.report)


def _symbol(name: str, *, binding: str, visibility: str) -> dict[str, object]:
    return {
        'name': name, 'raw_name': name, 'version': None, 'version_default': False,
        'binding': binding, 'visibility': visibility, 'section_index': '1',
        'type': 'FUNC', 'value': '0000000000000010', 'size_bytes': 4, 'size': '4',
        'row_index': 1, 'raw': name, 'other': None, 'version_index': None,
        'common_alignment': None,
    }


def _occurrence(index: int, name: str, *, artifact: str, table: str, role: str,
                binding: str, visibility: str) -> dict[str, object]:
    return {
        'index': index, 'artifact_key': artifact, 'member_name': None,
        'member_index': None, 'member_occurrence': None, 'table': table,
        'table_section_index': 1, 'definition_section': {'name': '.text'}, 'role': role,
        'row': _symbol(name, binding=binding, visibility=visibility),
    }


class SyscallAliasOwnerPolicyTests(unittest.TestCase):
    def test_thirteen_global_hidden_bodies_have_only_the_finite_private_provider_route(self) -> None:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        records = {row['identity']['name']: row for row in selection.expand_obligations(contract, inputs)}
        self.assertEqual(len(GLOBAL_HIDDEN), 13)
        for name in GLOBAL_HIDDEN:
            with self.subTest(name=name):
                record = records[name]
                self.assertEqual(record['selection']['disposition'], 'private-provider')
                self.assertEqual(record['selection']['owner'], selection.SYSCALL_ALIAS_PRIVATE_OWNER)
                self.assertEqual(record['selection']['group'], selection.SYSCALL_ALIAS_PRIVATE_GROUP)
                self.assertEqual(record['selection']['sources'], list(PRIVATE_SOURCES))
                self.assertEqual(record['unresolved'], [selection.SYSCALL_ALIAS_RECEIPT_REQUIREMENT])
                self.assertEqual(record['expected_placements'], [
                    {
                        'artifact_key': 'candidate-static',
                        'metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'},
                        'metadata_rule': 'explicit',
                    },
                    {
                        'artifact_key': 'candidate-shared',
                        'metadata': {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'HIDDEN'},
                        'metadata_rule': 'explicit',
                    },
                ])
        for name in LOCAL_BODIES:
            self.assertNotIn(name, records)


class NativeSyscallAliasAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        common_checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
        parent = ROOT / '.work/x86_64/native-abi-syscall-alias-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static = self.work / 'static'
        self.dynamic = self.work / 'dynamic'
        for path, payload in (
            (self.static / 'bin/crabc-cc', b'static driver\n'),
            (self.static / 'usr/lib/libc.a', b'static archive\n'),
            (self.dynamic / 'share/crabc/dynamic-product-state.json', b'dynamic state\n'),
            (self.dynamic / 'share/crabc/libc-shared.provenance.json', b'dynamic provenance\n'),
            (self.dynamic / 'share/crabc/producer-tools.json', b'dynamic tools\n'),
            (self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n'),
            (self.dynamic / 'usr/lib/libc.so', b'dynamic shared\n'),
            (self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n'),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        for key, relative in STATIC_LINK_INPUTS.items():
            path = self.static / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes((key + '\n').encode())
        for key, relative in DYNAMIC_LINK_INPUTS.items():
            path = self.dynamic / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes((key + '\n').encode())
        static_manifest = self.static / 'share/crabc/manifest.json'
        static_manifest.parent.mkdir(parents=True, exist_ok=True)
        static_manifest.write_text(json.dumps({
            'installed': {'files': {
                relative: hashlib.sha256((self.static / relative).read_bytes()).hexdigest()
                for relative in STATIC_LINK_INPUTS.values()
            }},
        }, sort_keys=True))
        state_path = self.dynamic / 'share/crabc/dynamic-product-state.json'
        manifest_path = self.dynamic / 'share/crabc/manifest.json'
        manifest_path.write_text(json.dumps({
            'files': {
                'share/crabc/dynamic-product-state.json': hashlib.sha256(state_path.read_bytes()).hexdigest(),
                **{
                    relative: hashlib.sha256((self.dynamic / relative).read_bytes()).hexdigest()
                    for relative in DYNAMIC_LINK_INPUTS.values()
                },
            },
        }, sort_keys=True))
        self.base = self._write('base-inventory.json', b'base\n')
        self.elf = self._write('elf-facts.json', b'elf\n')
        self.preparation = self._write('preparation.json', b'preparation\n')
        self.dynamic_linker = self._write('dynamic-linker', b'linker\n')
        self.oracle_compiler = self._write('oracle-compiler', b'compiler\n')
        self.oracle_shared = self._write('oracle-shared', b'oracle shared\n')
        self.oracle_archive = self._write('oracle-archive', b'oracle archive\n')
        self.report_path = self._write('receipt.json', b'{}\n')
        self.paths = {
            'measurement_checkout': ROOT,
            'base_inventory': self.base,
            'elf_report': self.elf,
            'static_preparation': self.preparation,
            'static_product': self.static,
            'dynamic_product': self.dynamic,
        }
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.measurement = {
            'candidate_build': {
                'revision': self.source['revision'],
                'source_content_sha256': self.source['content_sha256'],
            },
            'reports': {
                key: selection.file_identity(self.paths[key])
                for key in ('base_inventory', 'elf_report', 'static_preparation')
            },
        }
        self.products = selection._syscall_alias_product_identities(self.paths)
        self.facts = {
            'artifacts': {
                'candidate-static': {'identity': self.products['static_libc']},
                'candidate-shared': {'identity': self.products['dynamic_libc']},
                'candidate-loader': {'identity': self.products['dynamic_loader']},
            },
        }

    def _write(self, name: str, payload: bytes) -> Path:
        path = self.work / name
        path.write_bytes(payload)
        return path

    @staticmethod
    def _receipt_pair(value: dict[str, object]) -> dict[str, object]:
        return {'original': copy.deepcopy(value), 'retained': copy.deepcopy(value)}

    def _receipt(self) -> dict[str, object]:
        source_pair = {'revision': self.source['revision'], 'content_sha256': self.source['content_sha256']}
        inputs = {
            'static_preparation': self._receipt_pair(selection.file_identity(self.preparation)),
            'elf_facts': self._receipt_pair(selection.file_identity(self.elf)),
            'base_inventory': self._receipt_pair(selection.file_identity(self.base)),
            **{name: self._receipt_pair(self.products[name]) for name in RECEIPT_PRODUCT_INPUTS},
            'dynamic_linker': self._receipt_pair(selection.file_identity(self.dynamic_linker)),
            'oracle_compiler': self._receipt_pair(selection.file_identity(self.oracle_compiler)),
            'oracle_shared': self._receipt_pair(selection.file_identity(self.oracle_shared)),
            'oracle_archive': self._receipt_pair(selection.file_identity(self.oracle_archive)),
        }
        self.assertEqual(set(inputs), {
            'static_preparation', 'elf_facts', 'base_inventory', 'selected_dynamic_list',
            'static_libc', 'static_driver', 'static_manifest', 'dynamic_libc', 'dynamic_driver',
            'dynamic_loader', 'dynamic_manifest', 'dynamic_producer_tools', 'dynamic_shared_provenance',
            'dynamic_linker', 'oracle_compiler', 'oracle_shared', 'oracle_archive',
        })
        retained_dynamic = self.work / 'products/dynamic'
        retained_static = self.work / 'products/static'
        for root, retained_root, relatives in (
            (self.static, retained_static, ('share/crabc/manifest.json', *STATIC_LINK_INPUTS.values())),
            (self.dynamic, retained_dynamic, (
                'share/crabc/manifest.json', 'share/crabc/dynamic-product-state.json', *DYNAMIC_LINK_INPUTS.values(),
            )),
        ):
            for relative in relatives:
                source = root / relative
                retained = retained_root / relative
                retained.parent.mkdir(parents=True, exist_ok=True)
                retained.write_bytes(source.read_bytes())
                retained.chmod(source.stat().st_mode & 0o7777)

        reader = FakeSyscallReader({})
        return {
            'schema': reader.SCHEMA, 'status': copy.deepcopy(reader.STATUS),
            'image': reader.IMAGE, 'musl_source_commit': reader.MUSL_SOURCE_COMMIT,
            'collector_source': {'before': source_pair, 'after': copy.deepcopy(source_pair)},
            'selected_product_source': copy.deepcopy(source_pair),
            'image_inputs': {}, 'inputs': inputs,
            'products': {
                'static': {'original': str(self.static), 'retained': 'products/static'},
                'dynamic': {'original': str(self.dynamic), 'retained': 'products/dynamic'},
            },
            'source': {
                kind: {
                    name: self._receipt_pair(selection.file_identity(ROOT / name))
                    for name in names
                }
                for kind, names in (
                    ('collector', FakeSyscallReader.COLLECTOR_SOURCES),
                    ('selected_runtime', FakeSyscallReader.RUNTIME_SOURCES),
                )
            },
            'tools': {}, 'runner': {}, 'historical_epochs': {},
            'selection_projection': FakeSyscallReader.component_projection(),
        }

    def _companion(self) -> dict[str, object]:
        reader = FakeSyscallReader({})
        return {
            'status': 'syscall-alias-observed-with-boundaries', 'reader': {}, 'report': {},
            'source': {},
            'source_inputs': {
                name: selection.file_identity(ROOT / name)
                for name in selection._syscall_alias_source_files()
            },
            'products': {}, 'measurement_reports': {},
            'projection': reader.component_projection(), 'limits': list(selection.SYSCALL_ALIAS_LIMITS),
        }

    def _accounting(self, *, include_unowned: bool = False) -> dict[str, object]:
        occurrences = []
        index = 0
        for alias, body in ALIASES:
            for artifact, table, role, binding, visibility in (
                ('candidate-static', '.symtab', 'definition', 'WEAK', 'DEFAULT'),
                ('candidate-shared', '.dynsym', 'definition', 'WEAK', 'DEFAULT'),
                ('candidate-shared', '.symtab', 'definition', 'WEAK', 'DEFAULT'),
                ('candidate-static', '.symtab', 'local-definition' if body in LOCAL_BODIES else 'definition',
                 'LOCAL' if body in LOCAL_BODIES else 'GLOBAL', 'DEFAULT' if body in LOCAL_BODIES else 'HIDDEN'),
                ('candidate-shared', '.symtab', 'local-definition', 'LOCAL', 'HIDDEN'),
            ):
                occurrences.append(_occurrence(index, alias if binding == 'WEAK' else body,
                                               artifact=artifact, table=table, role=role,
                                               binding=binding, visibility=visibility))
                index += 1
        occurrences.extend([
            _occurrence(index, '__libc_sigaction', artifact='candidate-static', table='.symtab',
                        role='definition', binding='GLOBAL', visibility='HIDDEN'),
            _occurrence(index + 1, '__libc_sigaction', artifact='candidate-shared', table='.symtab',
                        role='local-definition', binding='LOCAL', visibility='HIDDEN'),
        ])
        index += 2
        if include_unowned:
            occurrences.extend([
                _occurrence(index, '__unowned_syscall_body', artifact='candidate-static', table='.symtab',
                            role='definition', binding='GLOBAL', visibility='HIDDEN'),
                _occurrence(index + 1, '', artifact='candidate-shared', table='.symtab',
                            role='local-definition', binding='LOCAL', visibility='HIDDEN'),
            ])
        identities = []
        placement_joins = []
        blockers = []
        for name in GLOBAL_HIDDEN:
            identity = {'name': name, 'version': None, 'version_default': False}
            identities.append({
                'identity': identity,
                'selection': {
                    'disposition': 'private-provider', 'owner': selection.SYSCALL_ALIAS_PRIVATE_OWNER,
                    'group': selection.SYSCALL_ALIAS_PRIVATE_GROUP,
                },
                'unresolved': [selection.SYSCALL_ALIAS_RECEIPT_REQUIREMENT],
            })
            blockers.append({
                'code': 'identity-unresolved', 'identity': copy.deepcopy(identity),
                'reason': selection.SYSCALL_ALIAS_RECEIPT_REQUIREMENT,
            })
            for artifact, role, binding, visibility in (
                ('candidate-static', 'definition', 'GLOBAL', 'HIDDEN'),
                ('candidate-shared', 'local-definition', 'LOCAL', 'HIDDEN'),
            ):
                matching = [row['index'] for row in occurrences if row['artifact_key'] == artifact
                            and row['row']['name'] == name and row['role'] == role]
                placement_joins.append({
                    'identity': copy.deepcopy(identity), 'artifact_key': artifact,
                    'expected_metadata': {'type': 'FUNC', 'binding': binding, 'visibility': visibility},
                    'definition_count': 1, 'placement_observed': True,
                    'metadata_differences': [{'occurrence_index': matching[0], 'fields': []}],
                    'occurrence_indices': matching,
                })
        return {
            'identities': identities, 'placement_joins': placement_joins,
            'occurrences': occurrences, 'blockers': blockers,
        }

    def test_adapter_is_absent_without_a_receipt(self) -> None:
        self.assertIsNone(selection.native_syscall_alias_adapter(
            None, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
        ))

    def test_adapter_binds_the_current_source_product_and_reader_projection(self) -> None:
        receipt = self._receipt()
        reader = FakeSyscallReader(receipt)
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=reader):
            companion = selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        assert companion is not None
        self.assertEqual(companion['status'], 'syscall-alias-observed-with-boundaries')
        self.assertEqual(set(companion['products']), {
            'static_manifest', 'static_driver', 'static_libc', 'dynamic_manifest', 'dynamic_state',
            'dynamic_driver', 'dynamic_libc', 'dynamic_loader', 'dynamic_shared_provenance',
            'dynamic_producer_tools', 'selected_dynamic_list',
            'static_crt1', 'static_rcrt1', 'static_crti', 'static_crtn', 'static_builtins',
            'dynamic_crt1', 'dynamic_Scrt1', 'dynamic_crti', 'dynamic_crtn', 'dynamic_builtins', 'dynamic_attach',
        })
        self.assertEqual(companion['projection']['aliases'], [list(pair) for pair in ALIASES])

        wrong_source = copy.deepcopy(receipt)
        wrong_source['collector_source']['before']['revision'] = 'c' * 40
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(wrong_source)), \
             self.assertRaisesRegex(selection.SelectionError, 'collector or selected product source'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

        wrong_collector_file = copy.deepcopy(receipt)
        collector_file = FakeSyscallReader.COLLECTOR_SOURCES[0]
        wrong_collector_file['source']['collector'][collector_file]['original']['sha256'] = '0' * 64
        wrong_collector_file['source']['collector'][collector_file]['retained']['sha256'] = '0' * 64
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(wrong_collector_file)), \
             self.assertRaisesRegex(selection.SelectionError, 'collector source differs'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

        wrong_product = copy.deepcopy(receipt)
        wrong_product['inputs']['dynamic_shared_provenance']['original']['sha256'] = '0' * 64
        wrong_product['inputs']['dynamic_shared_provenance']['retained']['sha256'] = '0' * 64
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(wrong_product)), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic_shared_provenance differs'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

        wrong_oracle_tool = copy.deepcopy(receipt)
        wrong_oracle_tool['inputs']['oracle_compiler']['retained']['mode'] = 0o700
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(wrong_oracle_tool)), \
             self.assertRaisesRegex(selection.SelectionError, 'retained oracle_compiler retained bytes differ'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

        wrong_image = copy.deepcopy(receipt)
        wrong_image['image'] = 'crabc-core-evidence@sha256:' + '0' * 64
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(wrong_image)), \
             self.assertRaisesRegex(selection.SelectionError, 'status, image, source commit or projection differs'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

        wrong_projection = copy.deepcopy(receipt)
        wrong_projection['selection_projection']['aliases'].pop()
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(wrong_projection)), \
             self.assertRaisesRegex(selection.SelectionError, 'status, image, source commit or projection differs'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_adapter_rejects_a_current_dynamic_state_not_sealed_by_the_retained_dynamic_tree(self) -> None:
        receipt = self._receipt()
        current_state = self.dynamic / 'share/crabc/dynamic-product-state.json'
        original_state = current_state.read_bytes()
        current_state.write_bytes(b'changed dynamic materialization state\n')
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic state'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        current_state.write_bytes(original_state)
        original_mode = current_state.stat().st_mode & 0o7777
        current_state.chmod(0o777)
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic state'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        current_state.chmod(original_mode)

        receipt = self._receipt()
        retained_state = self.work / 'products/dynamic/share/crabc/dynamic-product-state.json'
        changed_state = b'changed dynamic materialization state\n'
        current_state.write_bytes(changed_state)
        retained_state.write_bytes(changed_state)
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
             self.assertRaisesRegex(selection.SelectionError, 'retained dynamic state is not sealed by its manifest'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        current_state.write_bytes(original_state)

        receipt = self._receipt()
        current_manifest = self.dynamic / 'share/crabc/manifest.json'
        current_manifest.write_bytes(b'changed dynamic manifest\n')
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic_manifest differs'):
            selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def test_adapter_rejects_current_link_inputs_outside_the_retained_product_manifests(self) -> None:
        """Every exact CRT, builtins, and dynamic-attach byte is receipt-bound."""
        for product, records in ((self.static, STATIC_LINK_INPUTS), (self.dynamic, DYNAMIC_LINK_INPUTS)):
            for name, relative in records.items():
                with self.subTest(name=name):
                    receipt = self._receipt()
                    current = product / relative
                    original = current.read_bytes()
                    current.write_bytes(b'changed current link input: ' + name.encode() + b'\n')
                    with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
                         self.assertRaisesRegex(selection.SelectionError, name):
                        selection.native_syscall_alias_adapter(
                            self.report_path, facts=self.facts, measurement=self.measurement,
                            paths=self.paths, source=self.source,
                        )
                    current.write_bytes(original)

    def test_adapter_rejects_current_link_input_mode_substitutions(self) -> None:
        for product, name, relative in (
            (self.static, 'static_crt1', STATIC_LINK_INPUTS['static_crt1']),
            (self.static, 'static_builtins', STATIC_LINK_INPUTS['static_builtins']),
            (self.dynamic, 'dynamic_Scrt1', DYNAMIC_LINK_INPUTS['dynamic_Scrt1']),
            (self.dynamic, 'dynamic_attach', DYNAMIC_LINK_INPUTS['dynamic_attach']),
            (self.dynamic, 'dynamic_builtins', DYNAMIC_LINK_INPUTS['dynamic_builtins']),
        ):
            with self.subTest(name=name):
                receipt = self._receipt()
                current = product / relative
                original_mode = current.stat().st_mode & 0o7777
                current.chmod(0o600)
                with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
                     self.assertRaisesRegex(selection.SelectionError, name):
                    selection.native_syscall_alias_adapter(
                        self.report_path, facts=self.facts, measurement=self.measurement,
                        paths=self.paths, source=self.source,
                    )
                current.chmod(original_mode)

    def test_adapter_rejects_retained_link_inputs_unsealed_by_the_product_manifests(self) -> None:
        for product, retained_root, records in (
            (self.static, self.work / 'products/static', STATIC_LINK_INPUTS),
            (self.dynamic, self.work / 'products/dynamic', DYNAMIC_LINK_INPUTS),
        ):
            for name, relative in records.items():
                with self.subTest(name=name):
                    receipt = self._receipt()
                    retained = retained_root / relative
                    changed = b'changed retained link input: ' + name.encode() + b'\n'
                    retained.write_bytes(changed)
                    with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)), \
                         self.assertRaisesRegex(selection.SelectionError, 'sealed by its manifest'):
                        selection.native_syscall_alias_adapter(
                            self.report_path, facts=self.facts, measurement=self.measurement,
                            paths=self.paths, source=self.source,
                        )

    def test_runtime_recheck_rejects_link_input_changed_after_receipt_attachment(self) -> None:
        receipt = self._receipt()
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader(receipt)):
            companion = selection.native_syscall_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        assert companion is not None
        changed = self.static / STATIC_LINK_INPUTS['static_crti']
        changed.write_bytes(b'changed after syscall receipt attachment\n')
        with mock.patch.object(selection, 'selection_source', return_value=copy.deepcopy(self.source)), \
             self.assertRaisesRegex(selection.SelectionError, 'syscall alias static_crti changed'):
            selection._recheck_runtime_receipt_cohort(
                paths=self.paths, facts=self.facts, measurement=self.measurement, source=self.source,
                registry=None, pthread=None, syscall_alias=companion,
            )

    def test_attachment_selects_and_discharges_only_the_thirteen_global_hidden_bodies(self) -> None:
        accounting = self._accounting()
        companion = self._companion()
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader({})):
            joins = selection.attach_native_syscall_alias(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['aliases']), 14)
        self.assertEqual(len(joins[0]['private_bodies']), 15)
        private = {row['body']: row for row in joins[0]['private_bodies']}
        self.assertEqual(set(private), set((*GLOBAL_HIDDEN, *LOCAL_BODIES)))
        self.assertEqual({row['scope'] for row in private.values()}, {'global-hidden', 'source-local'})
        self.assertEqual(
            {row['body'] for row in private.values() if row['scope'] == 'global-hidden'}, set(GLOBAL_HIDDEN),
        )
        self.assertTrue(all(row['requirements_discharged'] == [selection.SYSCALL_ALIAS_RECEIPT_REQUIREMENT]
                            for row in joins[0]['private_bodies'] if row['scope'] == 'global-hidden'))
        self.assertTrue(all(not record['unresolved'] for record in accounting['identities']))
        self.assertFalse(accounting['blockers'])

    def test_attachment_rejects_wrong_public_or_private_scope(self) -> None:
        companion = self._companion()
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader({})):
            wrong_alias = self._accounting()
            next(row for row in wrong_alias['occurrences']
                 if row['artifact_key'] == 'candidate-shared' and row['table'] == '.dynsym'
                 and row['row']['name'] == 'fstat')['row']['binding'] = 'GLOBAL'
            with self.assertRaisesRegex(selection.SelectionError, 'alias fstat shared dynsym'):
                selection.attach_native_syscall_alias(wrong_alias, companion)

            wrong_private = self._accounting()
            next(row for row in wrong_private['occurrences']
                 if row['artifact_key'] == 'candidate-static' and row['row']['name'] == '__libc_sigaction'
                 )['row']['visibility'] = 'DEFAULT'
            with self.assertRaisesRegex(selection.SelectionError, 'private body __libc_sigaction static'):
                selection.attach_native_syscall_alias(wrong_private, companion)

            wrong_local = self._accounting()
            next(row for row in wrong_local['occurrences']
                 if row['artifact_key'] == 'candidate-static' and row['row']['name'] == '__statfs'
                 )['row']['binding'] = 'GLOBAL'
            with self.assertRaisesRegex(selection.SelectionError, 'body __statfs static'):
                selection.attach_native_syscall_alias(wrong_local, companion)

    def test_attachment_keeps_unowned_and_unnamed_rows_and_public_import_reasons(self) -> None:
        accounting = self._accounting(include_unowned=True)
        public_identity = {'name': 'clock_gettime', 'version': None, 'version_default': False}
        accounting['identities'].append({
            'identity': public_identity,
            'selection': {'disposition': 'public-provider'},
            'unresolved': [selection.ORDINARY_IMPORT_REASON],
        })
        accounting['blockers'].append({
            'code': 'identity-unresolved', 'identity': copy.deepcopy(public_identity),
            'reason': selection.ORDINARY_IMPORT_REASON,
        })
        companion = self._companion()
        original_count = len(accounting['occurrences'])
        with mock.patch.object(selection, '_syscall_alias_reader', return_value=FakeSyscallReader({})):
            joins = selection.attach_native_syscall_alias(accounting, companion)
        self.assertEqual(joins[0]['complete_elf_occurrence_count'], original_count)
        self.assertEqual(len(accounting['occurrences']), original_count)
        self.assertTrue(any(row['row']['name'] == '__unowned_syscall_body' for row in accounting['occurrences']))
        self.assertTrue(any(row['row']['name'] == '' for row in accounting['occurrences']))
        public = next(row for row in accounting['identities'] if row['identity']['name'] == 'clock_gettime')
        self.assertEqual(public['unresolved'], [selection.ORDINARY_IMPORT_REASON])
        self.assertTrue(any(row['reason'] == selection.ORDINARY_IMPORT_REASON for row in accounting['blockers']))

    def test_public_cli_and_report_roundtrip_thread_the_receipt_path(self) -> None:
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += ['--output', '.work/output', '--syscall-alias-contract-report', '.work/syscall/report.json']
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(build.call_args.kwargs['syscall_alias_contract_report'], Path('.work/syscall/report.json'))

        output = self.work / 'roundtrip'
        expected = {'roundtrip': 'receipt path reaches both public operations'}
        with mock.patch.object(selection, 'validate_measurement_paths', return_value=self.paths), \
             mock.patch.object(selection, '_build_report', return_value=expected) as build_internal:
            self.assertEqual(
                selection.build_report(
                    output=output, syscall_alias_contract_report=self.report_path,
                    elf_report=self.elf, base_inventory=self.base, static_preparation=self.preparation,
                    static_product=self.static, dynamic_product=self.dynamic, measurement_checkout=ROOT,
                ), expected,
            )
            self.assertEqual(
                selection.validate_report(
                    output / 'report.json', syscall_alias_contract_report=self.report_path,
                    elf_report=self.elf, base_inventory=self.base, static_preparation=self.preparation,
                    static_product=self.static, dynamic_product=self.dynamic, measurement_checkout=ROOT,
                ), expected,
            )
        self.assertEqual(build_internal.call_count, 2)
        self.assertTrue(all(
            call.kwargs['syscall_alias_contract_report'] == self.report_path
            for call in build_internal.call_args_list
        ))


if __name__ == '__main__':
    unittest.main()
