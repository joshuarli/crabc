#!/usr/bin/env python3
"""Account native ABI obligations separately from complete physical ELF facts.

An accepted report can be incomplete. Unknown ownership, absent declaration or
behavioral receipts, and older measured products remain explicit blockers.
The existing ELF reader runs in its own clean measurement checkout; this module
does not relax that reader's same-current-collector contract.
"""
from __future__ import annotations

import argparse
import copy
import csv
import fnmatch
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import native_abi_elf_facts as elf_facts
import header_abi_matrix as header_matrix
import header_callable_disposition as callable_disposition
import feature_archive_roster as feature_roster
import header_declaration_inventory as declaration_inventory
import loader_debug_abi_evidence as loader_debug_evidence
import public_data_ordinary_link_evidence as ordinary_link_evidence
import native_callable_declarations as callable_declarations
import native_declaration_abi as declaration_abi
import compiler_helper_evidence as compiler_helpers
import owned_mimalloc_producer_metadata as producer_metadata
import loader_runtime_registry_evidence as runtime_registry_evidence
import owned_pthread_alias_contract_reader as pthread_alias_evidence
import prepared_worker_tls_evidence as prepared_worker_evidence
import owned_errno_storage_lifecycle as errno_storage_evidence
import native_c_allocator_boundary
import owned_posix_product_evidence as product_evidence

SCHEMA = 'crabc.x86_64-native-abi-selection-report/v1'
CONTRACT_SCHEMA = 'crabc.x86_64-native-abi-selection/v1'
TARGET = inventory.TARGET
CONTRACT_PATH = MODULE_DIR / 'native-abi-selection.toml'
INPUT_PATHS = {
    'frozen_baseline': 'compat/x86_64/aarch64_frozen_baseline.json',
    'coverage': 'compat/crabc-rs/coverage.toml',
    'frozen_dynamic': 'compat/abi/musl-1.2.6/aarch64/libc.so.dynamic.tsv',
    'frozen_static': 'compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv',
    'callable_inventory': 'compat/x86_64/header_callable_inventory.json',
    'callable_disposition': 'compat/x86_64/header_callable_disposition.json',
    'header_abi_matrix': 'compat/x86_64/generated/header_abi_matrix/report.json',
    'parity': 'compat/x86_64/parity.toml',
}
STATUS = {'family_completion': False, 'promotion_ready': False, 'public_support': False}
SELECTORS = {'header-providers', 'feature-abi-only', 'exact-file-members', 'explicit'}
DISPOSITIONS = {'public-provider', 'private-provider', 'unresolved'}
SUPPORTED_TYPES = {'NOTYPE', 'OBJECT', 'FUNC', 'SECTION', 'FILE', 'COMMON', 'TLS', 'IFUNC'}
SUPPORTED_BINDINGS = {'LOCAL', 'GLOBAL', 'WEAK', 'UNIQUE'}
SUPPORTED_VISIBILITIES = {'DEFAULT', 'INTERNAL', 'HIDDEN', 'PROTECTED'}
ORDINARY_IMPORT_REASON = 'exact ordinary import/provider or optional weak/null resolution proof is missing'
PUBLIC_DATA_LINKAGE_LIMITS = [
    'No lifecycle, strong-override, interposition, COPY-relocation, or header-feature-profile proof.',
    'Shared-only _dl_debug_addr remains owned by the loader debugger component.',
    'Linkage evidence is not runtime qualification, family completion, or public support.',
]
FIXED_C_PRODUCER_GROUP = 'allocator-shared-local'
FIXED_C_PRODUCER_OWNER = 'fixed-C-mimalloc-producer'
FIXED_C_PRODUCER_ARTIFACTS = ('candidate-static', 'candidate-shared')
FIXED_C_PRODUCER_SOURCE_FILES = (
    'libc/src/c_abi/x86_64/owned_mimalloc_hidden.list',
    'compat/x86_64/owned_mimalloc_producer_metadata.py',
    'compat/x86_64/owned_mimalloc_producer_metadata.toml',
    'compat/x86_64/owned-mimalloc-producer-metadata.md',
    'compat/x86_64/owned-mimalloc-export-visibility.md',
    'compat/x86_64/tests/test_owned_mimalloc_producer_metadata.py',
    'compat/x86_64/tests/test_native_abi_producer_metadata.py',
)
FIXED_C_PRODUCER_PRODUCT_FILES = {
    'static_provenance': ('static_product', 'share/crabc/libc-static.provenance.json', inventory.STATIC_PRODUCT_PATH),
    'shared_provenance': ('dynamic_product', 'share/crabc/libc-shared.provenance.json', inventory.DYNAMIC_PRODUCT_PATH),
    'shared_manifest': ('dynamic_product', 'share/crabc/manifest.json', inventory.DYNAMIC_PRODUCT_PATH),
    'dynamic_state': ('dynamic_product', inventory.DYNAMIC_STATE_RELATIVE, inventory.DYNAMIC_PRODUCT_PATH),
    'static_manifest': ('static_product', 'share/crabc/manifest.json', inventory.STATIC_PRODUCT_PATH),
    'candidate_static_libc': ('static_product', 'usr/lib/libc.a', inventory.STATIC_PRODUCT_PATH),
    'candidate_shared_libc': ('dynamic_product', 'usr/lib/libc.so', inventory.DYNAMIC_PRODUCT_PATH),
}
COMPILER_HELPER_GROUP = 'owned-compiler-helper-archive'
COMPILER_HELPER_SHARED_ARTIFACT = 'candidate-shared'
COMPILER_HELPER_SHARED_METADATA_RULE = 'validated-compiler-helper-shared-local'
DECLARATION_ABI_LIMITS = [
    'The object witness records emitted ordinary references; it does not select an archive/shared provider.',
    'The four retained C++ membarrier spelling mismatches remain observations, not a language-linkage pass.',
    'Only _ns_flagdata element and in6_addr record facts are projected; FILE, table extent and h_errno storage semantics remain open.',
    'Runtime semantics, family completion, promotion and public support remain false.',
]
RUNTIME_REGISTRY_LIMITS = [
    'Only the selected nine shared-libc source-dispatch imports are attached; no loader symbol is selected as an installed provider.',
    'RuntimeV1 worker protocol, CRT structure, general loader qualification, family completion and promotion remain open.',
]
PTHREAD_ALIAS_LIMITS = [
    'The receipt binds named public weak aliases and the mq_notify public pthread_detach relocation; it does not select private provider spellings as new ABI identities.',
    'No general pthread family, cancellation, scheduling, lifecycle, promotion or public-support closure follows from this component receipt.',
]
PREPARED_WORKER_TLS_LIMITS = [
    'Only three private shared-libc TLS dispatch imports and seven retired prepared-token replacements are attached. The 72-byte loader descriptor source contract is authenticated without discharging its unobserved protocol obligations.',
    'The owned CRT handoff carrier, a main-thread descriptor import, descriptor provider/import/lifecycle proof, RuntimeV1 facade parity, general pthread qualification, family completion, promotion and public support remain open.',
]
ERRNO_STORAGE_LIFECYCLE_LIMITS = [
    'Only __errno_location, __h_errno_location, h_errno and the private ___errno_location alias receive this storage/lifecycle account.',
    'h_errno declaration/macro and accessor-to-storage agreement, broad TLS/TCB semantics, loader evidence, family completion, promotion and public support remain open.',
]
C_ALLOCATOR_BOUNDARY_LIMITS = [
    'Only the seven authenticated candidate-static Rust-root imports are joined to the fixed-C mimalloc provider account.',
    'The C v3.3.2 wrapper/lifecycle receipt does not select other imports or complete allocator behavior, family, promotion or public support.',
]
C_ALLOCATOR_BOUNDARY_SOURCE_FILES = (
    *native_c_allocator_boundary.COMPONENT_SOURCES,
    *native_c_allocator_boundary.RUNTIME_SOURCES,
    'compat/x86_64/owned_posix_static_products.py',
    'compat/x86_64/tests/test_native_c_allocator_boundary.py',
    'compat/x86_64/tests/test_native_abi_c_allocator_boundary_attachment.py',
)
STDIO_ALIAS_PRIVATE_GROUP = 'component-owned-stdio-private-bodies'
STDIO_ALIAS_PRIVATE_OWNER = 'x86-owned-stdio-private-bodies'
STDIO_ALIAS_RECEIPT_REQUIREMENT = 'current source-bound FILE alias/private-body receipt'
SYSCALL_ALIAS_PRIVATE_GROUP = 'component-owned-syscall-private-bodies'
SYSCALL_ALIAS_PRIVATE_OWNER = 'x86-owned-syscall-private-bodies'
STDIO_ALIAS_LIMITS = [
    'The receipt observes 42 named FILE weak aliases; selection joins 39 pending aliases, three private bodies and two protected controls. The three already-accounted aliases acquire no receipt obligation or discharge.',
    'The receipt does not close general stdio behavior, declaration/profile agreement, runtime qualification, family completion, promotion or public support.',
]
CRT_STARTUP_RECEIPT_REQUIREMENT = 'current source-bound installed CRT startup receipt'
CRT_STARTUP_LIMITS = [
    'Only the twelve owner-declared CRT startup identities and their retained exact occurrences are joined.',
    'The 32-byte owned handoff and 88-byte conventional snapshot stay distinct from the prepared-worker 72-byte descriptor.',
    'This receipt does not qualify first-bootstrap failures, descriptor lifetime, general CRT lifecycle, runtime qualification, family completion, promotion or public support.',
]
SYSCALL_ALIAS_RECEIPT_REQUIREMENT = 'current source-bound syscall alias/private-body receipt'
SYSCALL_ALIAS_LIMITS = [
    'Only the fourteen named public aliases, thirteen explicitly selected private global-hidden bodies, and two local statfs bodies are attached to complete candidate ELF observations.',
    'The receipt discharges only the thirteen private-body receipt requirements. Public alias import reasons, unowned observations, local bodies, syscall behavior generally, family completion, promotion and public support remain separate.',
]
SYSCALL_ALIAS_STATIC_LINK_INPUTS = (
    ('static_crt1', 'usr/lib/crt1.o'),
    ('static_rcrt1', 'usr/lib/rcrt1.o'),
    ('static_crti', 'usr/lib/crti.o'),
    ('static_crtn', 'usr/lib/crtn.o'),
    ('static_libc', 'usr/lib/libc.a'),
    ('static_builtins', 'usr/lib/libcrabc-builtins.a'),
)
SYSCALL_ALIAS_DYNAMIC_LINK_INPUTS = (
    ('dynamic_crt1', 'usr/lib/crt1.o'),
    ('dynamic_Scrt1', 'usr/lib/Scrt1.o'),
    ('dynamic_crti', 'usr/lib/crti.o'),
    ('dynamic_crtn', 'usr/lib/crtn.o'),
    ('dynamic_libc', 'usr/lib/libc.so'),
    ('dynamic_builtins', 'usr/lib/libcrabc-builtins.a'),
    ('dynamic_attach', 'usr/lib/crabc-dynamic-attach.o'),
)

UTMPX_ALIAS_RECEIPT_REQUIREMENT = 'source-selected alias requires exact feature archive selection and component receipt'
UTMPX_LIMITS = [
    'Only the eight source-selected utmpx aliases are joined to their existing feature-alias receipt requirements.',
    'The retained sixteen-provider envelope, static function proof, dynamic imports, source/product cohort and runtime controls do not select private providers, qualify utmpx semantics, complete a family, promote support or erase unrelated imports.',
]
UTMPX_STATIC_LINK_INPUTS = (
    ('static_crt1', 'usr/lib/crt1.o'),
    ('static_rcrt1', 'usr/lib/rcrt1.o'),
    ('static_crti', 'usr/lib/crti.o'),
    ('static_crtn', 'usr/lib/crtn.o'),
    ('static_libc', 'usr/lib/libc.a'),
    ('static_builtins', 'usr/lib/libcrabc-builtins.a'),
)
UTMPX_DYNAMIC_LINK_INPUTS = (
    ('dynamic_crt1', 'usr/lib/crt1.o'),
    ('dynamic_Scrt1', 'usr/lib/Scrt1.o'),
    ('dynamic_crti', 'usr/lib/crti.o'),
    ('dynamic_crtn', 'usr/lib/crtn.o'),
    ('dynamic_libc', 'usr/lib/libc.so'),
    ('dynamic_builtins', 'usr/lib/libcrabc-builtins.a'),
    ('dynamic_attach', 'usr/lib/crabc-dynamic-attach.o'),
)


def _stdio_alias_reader():
    """Load the FILE reader after this selection module has initialized.

    The FILE reader reuses the ordinary-data reader, which imports this
    selector for its checked product boundary. Importing it at module load
    would create a partial-module cycle when the FILE reader is used directly.
    The attachment still loads its exact source-owned reader before accepting
    a report; this delayed import only preserves that public reader entry
    point.
    """
    try:
        return importlib.import_module('owned_stdio_alias_contract_reader')
    except (ImportError, OSError, ValueError) as error:
        raise SelectionError(f'cannot load FILE alias reader: {error}') from error


def _stdio_alias_source_files() -> tuple[str, ...]:
    reader = _stdio_alias_reader()
    return (
        *reader.COLLECTOR_SOURCES,
        *reader.RUNTIME_SOURCES,
        'compat/x86_64/tests/test_owned_stdio_alias_contract_reader.py',
        'compat/x86_64/tests/test_native_abi_stdio_alias_attachment.py',
    )


def _crt_startup_reader():
    """Load the CRT receipt reader after this selector has initialized.

    The CRT reader reuses the FILE receipt substrate, whose public reader
    imports this selector for its selected-product boundary.  Keep this
    import lazy for the same reason as the FILE attachment: direct CRT-reader
    use must never observe a partially initialized selector module.
    """
    try:
        return importlib.import_module('installed_crt_startup_evidence')
    except (ImportError, OSError, ValueError) as error:
        raise SelectionError(f'cannot load CRT startup reader: {error}') from error


def _crt_startup_source_files() -> tuple[str, ...]:
    """Return the owner-derived provenance roster for the CRT attachment."""
    reader = _crt_startup_reader()
    return (
        *reader.COLLECTOR_SOURCES,
        'compat/x86_64/installed-crt-startup.md',
        'compat/x86_64/tests/test_installed_crt_startup_evidence.py',
        'compat/x86_64/tests/test_native_abi_crt_startup_attachment.py',
    )


def _utmpx_reader():
    """Load the finite utmpx reader only after selector initialization."""
    try:
        return importlib.import_module('owned_utmpx_receipt')
    except (ImportError, OSError, ValueError) as error:
        raise SelectionError(f'cannot load utmpx receipt reader: {error}') from error


def _utmpx_source_files() -> tuple[str, ...]:
    reader = _utmpx_reader()
    return (
        *reader.SOURCES,
        'compat/x86_64/tests/test_native_abi_utmpx_attachment.py',
        'compat/x86_64/native-abi-selection.md',
    )


def _syscall_alias_reader():
    """Load the finite syscall alias receipt reader after selector startup.

    The reader imports product evidence that may in turn inspect the selector.
    Keep this owner import lazy, as with FILE and CRT, so direct replay cannot
    observe a partially initialized selection module.
    """
    try:
        return importlib.import_module('owned_syscall_alias_contract_reader')
    except (ImportError, OSError, ValueError) as error:
        raise SelectionError(f'cannot load syscall alias reader: {error}') from error


def _syscall_alias_source_files() -> tuple[str, ...]:
    reader = _syscall_alias_reader()
    return (
        *reader.COLLECTOR_SOURCES,
        *reader.RUNTIME_SOURCES,
        'compat/x86_64/tests/test_native_abi_syscall_alias_attachment.py',
        'compat/x86_64/native-abi-selection.md',
    )
RUNTIME_REGISTRY_REQUIREMENTS = (
    'current signature and exact relocation-admission evidence',
    'graph rollback/reentry/fork and thread-local diagnostic component evidence',
)
PREPARED_WORKER_TLS_REQUIREMENTS = (
    'prepared token layout, allocation-before-clone and exit/reap release receipt',
)
PREPARED_WORKER_TLS_DESCRIPTOR_REQUIREMENTS = (
    'exact main-image weak-GOT transport and static no-slot receipt',
    'current owned main descriptor geometry and acquire READY/TP-DTV receipt',
    'release READY ordering and malformed descriptor rejection receipt',
    'pointer lifetime, worker mapping generation and fork ownership evidence',
)
PREPARED_WORKER_TLS_DESCRIPTOR_MEASURED_REQUIREMENTS = (
    'exact main-image weak-GOT transport and static no-slot receipt',
    'current owned main descriptor geometry and acquire READY/TP-DTV receipt',
)
PREPARED_WORKER_TLS_DESCRIPTOR_SOURCE_FIELDS = (
    'magic:u64', 'version:u32', 'abi_size:u32', 'process_mode:u32', 'owner:u32', 'state:AtomicU8',
    'reserved:[u8; 7]', 'thread_pointer:*const u8', 'dtv:*const usize', 'dtv_words:usize',
    'module_count:usize', 'generation:u64',
)
ERRNO_PRIVATE_ALIAS_GROUP = 'component-owned-errno-private-alias'
ERRNO_STORAGE_LIFECYCLE_REQUIREMENT = 'current source-bound errno storage/lifecycle and private alias receipt'


class SelectionError(ValueError):
    """An input is malformed, substituted, or cannot satisfy required closure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SelectionError(message)


def same(left: Any, right: Any) -> bool:
    return elf_facts._same(left, right)


def exact(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f'{description} fields differ')
    return value


def string(value: Any, description: str, *, empty: bool = False) -> str:
    require(type(value) is str and (empty or bool(value)), f'{description} is not a string')
    return value


def strings(value: Any, description: str, *, empty: bool = True) -> list[str]:
    require(type(value) is list and (empty or bool(value)), f'{description} is not a list')
    for item in value:
        string(item, description)
    require(len(value) == len(set(value)), f'{description} has duplicate members')
    return value


def read_json(path: Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f'{path}: duplicate JSON key {key}')
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(SelectionError(f'invalid JSON constant {value}')))
    except (OSError, json.JSONDecodeError) as error:
        raise SelectionError(f'cannot read JSON {path}: {error}') from error


def identity_key(value: Mapping[str, Any]) -> tuple[str, str | None, bool]:
    exact(dict(value), {'name', 'version', 'version_default'}, 'identity')
    name = string(value['name'], 'identity name')
    version = value['version']
    require(version is None or type(version) is str and bool(version), 'identity version is invalid')
    require(type(value['version_default']) is bool, 'identity defaultness is not Boolean')
    require(version is not None or value['version_default'] is False, 'unversioned identity cannot be default-versioned')
    return name, version, value['version_default']


def identity(name: str, version: str | None = None, default: bool = False) -> dict[str, Any]:
    result = {'name': name, 'version': version, 'version_default': default}
    identity_key(result)
    return result


def frozen_identity(row: Mapping[str, str]) -> dict[str, Any]:
    # The frozen TSV encodes no default-version bit. Only its explicit current
    # unversioned spelling is supported; never invent a defaultness assertion.
    require(row.get('version') == '-' and '@' not in row['name'], 'unsupported frozen version/defaultness representation')
    return identity(row['name'])


def parse_frozen_tsv(content: bytes, frozen_content: bytes, manifest: Mapping[str, Any]) -> list[dict[str, str]]:
    require(content == frozen_content, 'frozen TSV bytes differ from frozen source commit')
    reader = csv.DictReader(io.StringIO(content.decode('utf-8')), delimiter='\t')
    require(reader.fieldnames == manifest['columns'], 'frozen TSV columns differ')
    rows = list(reader)
    require(all(set(row) == set(manifest['columns']) and all(type(v) is str and v for v in row.values()) for row in rows), 'frozen TSV row fields differ')
    require(len(rows) == manifest['records'] and len({r['name'] for r in rows}) == manifest['unique_names'], 'frozen TSV cardinality differs')
    return rows


def row_identity(row: Mapping[str, Any]) -> dict[str, Any]:
    return identity(row['name'], row['version'], row['version_default'])


def identity_order(value):
    name, version, default = value
    return name, version or '', default


def source_path(value: str) -> Path:
    relative = Path(string(value, 'source path'))
    require(not relative.is_absolute() and '..' not in relative.parts, 'source path escapes checkout')
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink() and path.resolve() == path, f'nonphysical source input {value}')
    return path


def validate_contract(value: Any) -> dict[str, Any]:
    result = exact(value, {'schema', 'target', 'inputs', 'profiles', 'owner_groups', 'structural_groups',
                           'object_contracts', 'private_protocols', 'requirements'}, 'selection contract')
    require(result['schema'] == CONTRACT_SCHEMA and result['target'] == TARGET, 'selection schema/target changed')
    require(same(result['inputs'], INPUT_PATHS), 'selection input roster differs')
    for path in result['inputs'].values():
        source_path(path)
    artifact_keys = {item.key for item in elf_facts.ARTIFACTS}
    require(type(result['profiles']) is list and bool(result['profiles']), 'profiles missing')
    profile_ids = set()
    covered_artifacts = []
    for profile in result['profiles']:
        exact(profile, {'id', 'artifacts', 'feature_root'}, 'profile')
        identifier = string(profile['id'], 'profile id')
        require(identifier not in profile_ids, 'duplicate profile id')
        profile_ids.add(identifier)
        covered_artifacts.extend(strings(profile['artifacts'], 'profile artifacts', empty=False))
        string(profile['feature_root'], 'feature root')
    require(len(covered_artifacts) == len(set(covered_artifacts)) and set(covered_artifacts) == artifact_keys,
            'profiles do not exactly partition ELF artifact placements')
    for field in ('owner_groups', 'structural_groups', 'object_contracts', 'private_protocols'):
        require(type(result[field]) is list, f'{field} is not a list')
        seen = set()
        for record in result[field]:
            require(type(record) is dict, f'{field} record invalid')
            identifier = string(record.get('id'), f'{field} id')
            require(identifier not in seen, f'duplicate {field} id')
            seen.add(identifier)
            for path in strings(record.get('sources'), f'{identifier} sources', empty=False):
                source_path(path)
            if field == 'owner_groups':
                exact(record, {'id', 'selector', 'disposition', 'owner', 'family', 'artifacts', 'sources',
                               'members', 'members_file', 'delegated_members', 'expected_type', 'placement_metadata', 'static_metadata_rule', 'reason'}, 'owner group')
                require(record['selector'] in SELECTORS, f'{identifier} selector invalid')
                require(record['disposition'] in DISPOSITIONS, f'{identifier} disposition invalid')
                require(set(strings(record['artifacts'], 'owner artifacts', empty=False)) <= artifact_keys, 'unknown owner artifact')
                strings(record['members'], 'owner members')
                strings(record['delegated_members'], 'delegated members')
                require(not record['delegated_members'] or record['selector'] in {'header-providers', 'feature-abi-only'}, 'only source roster routes can delegate members')
                string(record['members_file'], 'members file', empty=True)
                require(bool(record['members_file']) == (record['selector'] == 'exact-file-members'), 'members file selector mismatch')
                require(bool(record['members']) == (record['selector'] == 'explicit'), 'explicit members selector mismatch')
                if record['members_file']:
                    source_path(record['members_file'])
                for key in ('owner', 'family', 'reason'):
                    string(record[key], key)
                require(record['expected_type'] in ('', 'FUNC', 'OBJECT', 'TLS'), 'owner expected type invalid')
                require(record['static_metadata_rule'] in {'explicit', 'selected-native-oracle-function'}, 'static metadata rule invalid')
                if record['static_metadata_rule'] == 'selected-native-oracle-function':
                    require(record['disposition'] == 'public-provider' and record['expected_type'] == 'FUNC' and 'candidate-static' in record['artifacts'], 'oracle metadata requires an already selected public static function')
                require(type(record['placement_metadata']) is dict and set(record['placement_metadata']) <= set(record['artifacts']), 'placement metadata artifact differs')
                for metadata in record['placement_metadata'].values():
                    require(type(metadata) is dict and set(metadata) <= {'type', 'binding', 'visibility'}, 'placement metadata fields differ')
                    for key, values in (('type', SUPPORTED_TYPES), ('binding', SUPPORTED_BINDINGS), ('visibility', SUPPORTED_VISIBILITIES)):
                        require(key not in metadata or metadata[key] in values, f'placement {key} invalid')
            elif field == 'structural_groups':
                exact(record, {'id', 'members', 'sources', 'disposition', 'reason', 'requirements'}, 'structural group')
                strings(record['members'], 'structural members', empty=False)
                require(record['disposition'] in {'structural-replacement', 'unresolved'}, 'structural disposition invalid')
                string(record['reason'], 'structural reason')
                strings(record['requirements'], 'structural requirements', empty=False)
            elif field == 'object_contracts':
                exact(record, {'id', 'name', 'sources', 'artifacts', 'type', 'binding', 'visibility', 'size_bytes',
                               'alignment_bytes', 'alias_target', 'declaration', 'declaration_kind', 'c_abi_type', 'source_mutable', 'meaning'}, 'object contract')
                string(record['name'], 'object name')
                require(record['type'] in {'OBJECT', 'TLS'}, 'object type invalid')
                require(record['binding'] in {'GLOBAL', 'WEAK', 'UNIQUE'}, 'object binding invalid')
                require(record['visibility'] in SUPPORTED_VISIBILITIES, 'object visibility invalid')
                require(set(strings(record['artifacts'], 'object artifacts', empty=False)) <= artifact_keys, 'unknown object artifact')
                for key in ('size_bytes', 'alignment_bytes'):
                    require(type(record[key]) is int and record[key] > 0, f'object {key} invalid')
                require(record['alignment_bytes'] & (record['alignment_bytes'] - 1) == 0, 'object alignment must be a power of two')
                string(record['alias_target'], 'alias target', empty=True)
                string(record['declaration'], 'object declaration')
                require(record['declaration_kind'] in {'installed-variable', 'accessor-macro', 'abi-only'}, 'object declaration kind invalid')
                string(record['c_abi_type'], 'object c_abi_type')
                require(type(record['source_mutable']) is bool, 'object source_mutable is not Boolean')
                string(record['meaning'], 'object meaning')
            else:
                exact(record, {'id', 'members', 'sources', 'consumer_artifacts', 'provider_artifacts', 'provider_metadata', 'endpoint_kind',
                               'endpoint', 'signature', 'signature_status', 'operations', 'requirements', 'reason'}, 'private protocol')
                strings(record['members'], 'private protocol members', empty=False)
                require(set(strings(record['consumer_artifacts'], 'consumer artifacts', empty=False)) <= artifact_keys, 'unknown consumer artifact')
                require(set(strings(record['provider_artifacts'], 'provider artifacts')) <= artifact_keys, 'unknown private provider artifact')
                require(type(record['provider_metadata']) is dict and set(record['provider_metadata']) <= {'type', 'size_bytes', 'alignment_bytes'}, 'private provider metadata fields differ')
                for key in ('size_bytes', 'alignment_bytes'):
                    require(key not in record['provider_metadata'] or type(record['provider_metadata'][key]) is int and record['provider_metadata'][key] > 0, f'private provider {key} invalid')
                alignment = record['provider_metadata'].get('alignment_bytes', 1)
                require(alignment & (alignment - 1) == 0, 'private provider alignment must be a power of two')
                require('type' not in record['provider_metadata'] or record['provider_metadata']['type'] in {'OBJECT', 'TLS'}, 'private provider type invalid')
                require(record['endpoint_kind'] in {'source-dispatch-operation', 'descriptor', 'lifecycle',
                                                     'main-image-weak-got-transport'}, 'private endpoint invalid')
                require(bool(record['provider_artifacts'])
                        == (record['endpoint_kind'] not in {'source-dispatch-operation', 'main-image-weak-got-transport'}),
                        'private provider artifacts differ from endpoint role')
                for key in ('endpoint', 'signature', 'reason'):
                    string(record[key], key)
                require(record['signature_status'] == 'source-mapped-unverified', 'private signature proof status is not supported')
                require(type(record['operations']) is list, 'private operations are not a list')
                operation_names = []
                for operation in record['operations']:
                    exact(operation, {'name', 'producer', 'consumer'}, 'private operation')
                    operation_names.append(string(operation['name'], 'operation name'))
                    for endpoint in ('producer', 'consumer'):
                        entry = exact(operation[endpoint], {'source', 'function', 'parameters', 'result', 'abi', 'unsafe'}, 'operation endpoint')
                        require(entry['source'] in record['sources'], 'operation endpoint source missing from owner roster')
                        string(entry['function'], 'operation function')
                        require(type(entry['parameters']) is list and all(type(v) is str and v for v in entry['parameters']), 'operation parameters invalid')
                        string(entry['result'], 'operation result')
                        require(entry['abi'] == 'C' and entry['unsafe'] is True, 'operation ABI/unsafe source observation invalid')
                require(len(operation_names) == len(set(operation_names)), 'duplicate private operation')
                require(set(operation_names) == (set(record['members']) if record['endpoint_kind'] == 'source-dispatch-operation' else set()), 'private operation/member coverage differs')
                strings(record['requirements'], 'private requirements', empty=False)
    exact(result['requirements'], {'declaration_companion', 'semantic_receipts', 'family_receipts', 'same_source_products'}, 'requirements')
    require(all(value is True for value in result['requirements'].values()), 'selection requirements cannot be disabled')
    explicit_members = [name for row in result['owner_groups'] if row['selector'] == 'explicit' for name in row['members']]
    require(len(explicit_members) == len(set(explicit_members)), 'duplicate explicit owner membership')
    for row in result['owner_groups']:
        require(set(row['delegated_members']) <= set(explicit_members), 'delegated member lacks an exact explicit owner')
    return copy.deepcopy(result)


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        return validate_contract(tomllib.loads(path.read_text()))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SelectionError(f'cannot read selection contract: {error}') from error


def row_role(row: Mapping[str, Any]) -> str:
    if not row['name']:
        return 'unnamed'
    if row['binding'] not in SUPPORTED_BINDINGS or row['type'] not in SUPPORTED_TYPES or row['visibility'] not in SUPPORTED_VISIBILITIES:
        return 'unsupported'
    # Raw projection accepts future processor/OS metadata. Selection must keep
    # it visible without assigning supported binding or section semantics.
    if row.get('other') is not None or not (row['section_index'] in {'UND', 'ABS', 'COM'} or re.fullmatch(r'[0-9]+', row['section_index'])):
        return 'unsupported'
    if row['section_index'] == 'UND':
        return 'import'
    if row['binding'] == 'LOCAL':
        return 'local-definition'
    return 'definition'


def same_definition_domain(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    # Table rows in dynsym and symtab may observe the same linked definition;
    # archive member and defining section equality are never inferred from nm.
    # COMMON st_value is alignment; ABS has no defining section. Neither can
    # establish this storage/code placement relationship from equal row values.
    keys = ('artifact_key', 'member_index', 'member_occurrence')
    return (all(left.get(key) == right.get(key) for key in keys)
            and (left.get('member_index') is None or left['table_section_index'] == right['table_section_index'])
            and re.fullmatch(r'[1-9][0-9]*', left['row']['section_index']) is not None
            and all(left['row'][key] == right['row'][key] for key in ('section_index', 'value', 'type', 'size_bytes')))


def metadata_differences(expected: Mapping[str, Any], row: Mapping[str, Any], section: Mapping[str, Any] | None) -> list[str]:
    differences = [key for key in ('type', 'binding', 'visibility', 'size_bytes') if key in expected and not same(expected[key], row[key])]
    alignment = expected.get('alignment_bytes')
    if alignment is not None:
        if row['section_index'] == 'COM':
            observed = row.get('common_alignment')
            if type(observed) is not int or observed < alignment or observed % alignment:
                differences.append('alignment_bytes')
        elif section is None:
            differences.append('alignment-unproven')
        else:
            observed = section.get('alignment')
            if type(observed) is not int or observed < alignment or observed % alignment or int(row['value'], 16) % alignment:
                differences.append('alignment_bytes')
    return differences


def _metadata_difference_rows_are_empty(value: object, description: str) -> bool:
    """Validate generic placement-difference rows without erasing matches.

    ``account_placements`` retains one row for each observed definition, even
    when that row has no differing fields.  Focused source-owner binders need
    that physical occurrence record; only a nonempty ``fields`` list means the
    generic metadata comparison found a mismatch.
    """
    require(isinstance(value, list), f'{description} metadata differences are invalid')
    occurrences: set[int] = set()
    for index, raw in enumerate(value):
        item = exact(raw, {'occurrence_index', 'fields'}, f'{description} metadata difference {index}')
        occurrence = item['occurrence_index']
        require(type(occurrence) is int and occurrence >= 0 and occurrence not in occurrences,
                f'{description} metadata difference occurrence differs')
        occurrences.add(occurrence)
        fields = item['fields']
        require(isinstance(fields, list) and all(type(field) is str and field for field in fields)
                and len(fields) == len(set(fields)),
                f'{description} metadata difference fields differ')
        if fields:
            return False
    return True


def reference_static_metadata(occurrences: Sequence[Mapping[str, Any]], explicit: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve metadata only after a separate source contract selected a name.

    Caller supplies exact reference-static definition occurrences for that exact
    identity. Sizes and addresses do not become callable compatibility policy.
    Conflicting oracle tuples or an incompatible explicit source constraint keep
    the obligation unresolved; candidate observations never feed this selector.
    """
    tuples = {(r['row']['type'], r['row']['binding'], r['row']['visibility']) for r in occurrences}
    metadata = dict(zip(('type', 'binding', 'visibility'), next(iter(tuples)))) if len(tuples) == 1 else None
    if metadata is not None and (metadata['type'] != 'FUNC' or any(key in metadata and value != metadata[key] for key, value in explicit.items())):
        metadata = None
    return {'rule': 'selected-native-oracle-function', 'metadata': metadata,
            'occurrence_indices': [r['index'] for r in occurrences],
            'reason': None if metadata is not None else 'absent, conflicting or source-incompatible oracle static definition metadata'}


def evidence_blockers(*, declaration: Any, semantic_receipts: Sequence[Any], family_receipts: Sequence[Any], source_matches: bool) -> list[dict[str, str]]:
    require(type(source_matches) is bool, 'source match is not Boolean')
    blockers = []
    if declaration is None:
        blockers.append({'code': 'declaration-companion-missing', 'subject': 'enumerable compiler declaration/profile facts'})
    elif declaration['complete'] is not True:
        blockers.append({'code': 'declaration-companion-incomplete', 'subject': 'unresolved compiler declaration occurrences'})
    if declaration is not None and declaration['current_selecting_source']['matches_retained'] is not True:
        blockers.append({'code': 'declaration-source-mismatch', 'subject': 'retained declaration source differs from current selected source'})
    if not semantic_receipts:
        blockers.append({'code': 'semantic-receipts-missing', 'subject': 'owner component extraction, ABI, alias and lifecycle readers'})
    if not family_receipts:
        blockers.append({'code': 'family-receipts-missing', 'subject': 'complete selected native family evidence'})
    if not source_matches:
        blockers.append({'code': 'selection-product-source-mismatch', 'subject': 'selected source and measured product build'})
    return blockers


def _require_closed_report(report: Mapping[str, Any]) -> None:
    closure = exact(report.get('closure'), {'complete', 'blockers'}, 'closure')
    require(type(closure['complete']) is bool and type(closure['blockers']) is list, 'closure field types invalid')
    require(closure['complete'] is True and not closure['blockers'], 'native ABI selection is incomplete')


def require_selection_closure(report_path: Path, **inputs: Any) -> dict[str, Any]:
    """Replay all public inputs before applying the closure gate.

    A caller-provided mapping or completion flag is not a validation receipt.
    """
    require(isinstance(report_path, Path), 'selection is incomplete without a physical report path and public replay')
    report = validate_report(report_path, **inputs)
    _require_closed_report(report)
    return report


def file_identity(path: Path) -> dict[str, Any]:
    return inventory.file_record(path, logical_path=str(path))


def selecting_source_file_identity(path: Path) -> dict[str, Any]:
    """Record a current selecting-source file under its canonical repo path."""
    supplied = Path(path)
    require(supplied.is_file() and not supplied.is_symlink(), 'selecting source identity is not a physical checkout file')
    physical = supplied.resolve()
    require(physical.is_relative_to(ROOT), 'selecting source identity escapes the checkout')
    return inventory.file_record(physical, logical_path=str(physical.relative_to(ROOT)))


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(['git', '-c', f'safe.directory={root}', *args], cwd=root, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        raise SelectionError(f'cannot read checkout identity: {root}') from error


def selection_source() -> dict[str, Any]:
    """Use the inventory seal for clean source; mark development source dirty.

    The same tracked-tree digest framing is retained in development. Explicit
    source-input records additionally bind the not-yet-tracked new component.
    A dirty selection can be measured but can never satisfy source closure.
    """
    clean = not _git(ROOT, 'status', '--porcelain', '--untracked-files=all').strip()
    if clean:
        return inventory.collector_source_seal()
    digest = hashlib.sha256()
    for name in sorted(n for n in _git(ROOT, 'ls-files', '-z', '--cached').split(b'\0') if n):
        path = ROOT / os.fsdecode(name)
        mode = path.lstat().st_mode
        payload = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        digest.update(name + b'\0' + str(stat.S_IMODE(mode)).encode() + b'\0')
        digest.update(hashlib.sha256(payload).digest())
    return {'revision': _git(ROOT, 'rev-parse', 'HEAD').decode().strip(), 'content_sha256': digest.hexdigest(), 'clean': False}


def load_source_inputs(contract: Mapping[str, Any], contract_path: Path) -> dict[str, Any]:
    paths = {key: source_path(value) for key, value in contract['inputs'].items()}
    coverage = tomllib.loads(paths['coverage'].read_text())
    frozen = read_json(paths['frozen_baseline'])
    for record in frozen['aarch64_inputs'].values():
        require(inventory.sha256(source_path(record['path'])) == record['sha256'], 'frozen source input changed')
    candidate_names = strings(coverage['dynamic_exports']['candidate_symbols'], 'frozen candidate symbols', empty=False)
    require(len(candidate_names) == coverage['dynamic_exports']['candidate_count'], 'frozen candidate roster count changed')
    header = read_json(paths['callable_inventory'])
    disposition = read_json(paths['callable_disposition'])
    disposition_contract = callable_disposition.load_contract()
    expected_disposition = callable_disposition.build_report(disposition_contract)
    require(same(disposition, expected_disposition), 'current callable/provider disposition does not reconstruct')
    try:
        matrix_contract = header_matrix.load_contract()
        matrix_report = read_json(paths['header_abi_matrix'])
        header_matrix.validate_checked_report(matrix_report, matrix_contract)
        callable_matrix = callable_declarations.matrix_projection_from_checked_report(
            matrix_report,
            provenance={
                'report': selecting_source_file_identity(paths['header_abi_matrix']),
                'reader': selecting_source_file_identity(Path(header_matrix.__file__)),
                'contract': selecting_source_file_identity(header_matrix.CONTRACT_PATH),
                'extension_contract': selecting_source_file_identity(header_matrix.callable_extension_contract.CONTRACT_PATH),
            },
        )
    except (ValueError, OSError) as error:
        raise SelectionError(f'checked callable declaration matrix rejected: {error}') from error
    feature_rows = feature_roster.load_feature_archive_roster()
    capabilities = []
    owners = {}
    for capability in coverage['capability']:
        names = list(capability.get('symbols', []))
        for pattern in capability.get('symbol_patterns', []):
            matches = [name for name in candidate_names if fnmatch.fnmatchcase(name, pattern)]
            require(bool(matches), f'frozen capability selector has no members: {pattern}')
            names.extend(matches)
        require(len(names) == len(set(names)), f'duplicate frozen capability members: {capability["id"]}')
        for name in names:
            require(name in candidate_names and name not in owners, f'frozen capability ownership differs: {name}')
            owners[name] = {'id': capability['id'], 'classification': capability['classification']}
        capabilities.append({'id': capability['id'], 'classification': capability['classification'], 'members': sorted(names)})
    require(set(owners) == set(candidate_names), 'frozen capability ownership is incomplete')
    manifest = read_json(source_path(frozen['aarch64_inputs']['abi_manifest']['path']))
    frozen_rows = {}
    for kind in ('dynamic', 'static'):
        path = paths['frozen_' + kind]
        original = _git(ROOT, 'show', frozen['source_commit'] + ':' + str(path.relative_to(ROOT)))
        frozen_rows[kind] = parse_frozen_tsv(path.read_bytes(), original, manifest[kind])
    dynamic, static = frozen_rows['dynamic'], frozen_rows['static']
    names = {identity_key(frozen_identity(r)) for r in dynamic}
    require(len(names) == len(dynamic), 'duplicate frozen dynamic identity')
    rows = [r for r in header['callables'] if r['tree'] == 'candidate' and r['classification'] == 'external']
    provider_names = set()
    primary = disposition['primary_disposition']
    provider_names.update(primary['default_static']['members'])
    for key in ('verified_feature_archives', 'declared_unverified_feature_archives'):
        for row in primary[key]:
            provider_names.update(row['members'])
    deferred = {name: row for row in primary['deferred_owner_groups'] for name in row['members']}
    require(provider_names.isdisjoint(deferred) and provider_names | set(deferred) == {r['name'] for r in rows}, 'header provider partition differs')
    abi_only = [{'name': name, 'owner': row.identifier, 'state': row.state, 'runner': row.runner}
                for row in feature_rows for name in row.abi_only_callables]
    feature_aliases = [{'name': alias.name, 'target': alias.target, 'binding': alias.binding, 'owner': row.identifier,
                        'state': row.state, 'evidence_record': row.evidence_record, 'runner': row.runner,
                        'baseline_features': list(row.baseline_features), 'enabled_features': list(row.enabled_features),
                        'feature_selection_source': row.feature_selection_source,
                        'sources': ['compat/x86_64/feature_archive_roster.py', 'compat/x86_64/parity.toml']}
                       for row in feature_rows for alias in row.aliases]
    files = set(contract['inputs'].values()) | {
        'compat/x86_64/native_abi_selection.py', 'compat/x86_64/tests/test_native_abi_selection.py',
        'compat/x86_64/native_abi_inventory.py', 'compat/x86_64/native_abi_elf_facts.py',
        'compat/x86_64/header_callable_disposition.py', 'compat/x86_64/header_callable_disposition.toml',
        'compat/x86_64/header_callable_linkage_audit.py', 'compat/x86_64/header_callable_inventory.py',
        'compat/x86_64/header_declaration_inventory.py',
        'compat/x86_64/feature_archive_roster.py', 'compat/x86_64/static_c_abi_exports.txt',
        'compat/x86_64/header_callable_extension_contract.py', 'compat/x86_64/header_callable_extension_contract.toml',
        'compat/x86_64/header_abi_matrix.py', 'compat/x86_64/header_abi_matrix.toml',
        'compat/x86_64/native_data_declarations.py', 'compat/x86_64/native_data_declarations.toml',
        'compat/x86_64/tests/test_native_data_declarations.py', 'compat/x86_64/native-data-declarations.md',
        'compat/x86_64/native_callable_declarations.py', 'compat/x86_64/native_callable_declarations.toml',
        'compat/x86_64/tests/test_native_callable_declarations.py', 'compat/x86_64/native-callable-declarations.md',
        *FIXED_C_PRODUCER_SOURCE_FILES,
        'libc/Cargo.toml', 'compat/x86_64/native-abi-selection.md',
        'compat/x86_64/compiler_helper_evidence.py',
        'compat/x86_64/tests/test_compiler_helper_evidence.py',
        'compat/x86_64/tests/test_native_abi_compiler_helpers.py',
        'builtins/x86_64-helper-contract.md',
    }
    files.update(path.as_posix() for path in compiler_helpers.SOURCE_FILES)
    # The ordinary declaration companion replays its own finite source
    # snapshots.  The selector also binds its reader, contract, explanatory
    # boundary, and focused behavior source before it is allowed to attach the
    # resulting object observations to this report.
    files.update(declaration_abi.SOURCE_FILES)
    files.update({
        'compat/x86_64/native-declaration-abi.md',
        'compat/x86_64/tests/test_native_declaration_abi.py',
        *runtime_registry_evidence.SOURCE_FILES,
        'compat/x86_64/loader-runtime-registry-private-resolution.md',
        'compat/x86_64/tests/test_loader_runtime_registry_evidence.py',
        'compat/x86_64/tests/test_native_abi_runtime_receipts.py',
        'compat/x86_64/owned_pthread_alias_contract_reader.py',
        'compat/x86_64/owned_pthread_alias_contract_probe.c',
        'compat/x86_64/run_owned_pthread_alias_contract.sh',
        'compat/x86_64/tests/test_owned_pthread_alias_contract_reader.py',
        'compat/x86_64/owned-pthread-alias-contract.md',
        *prepared_worker_evidence.SOURCE_PATHS,
        'compat/x86_64/prepared-worker-tls.md',
        'compat/x86_64/tests/test_prepared_worker_tls_evidence.py',
        *errno_storage_evidence.SOURCE_FILES,
        *C_ALLOCATOR_BOUNDARY_SOURCE_FILES,
        *_stdio_alias_source_files(),
        *_crt_startup_source_files(),
        *_syscall_alias_source_files(),
    })
    files.update(pthread_alias_evidence.SOURCE_CONTRACT_PATHS)
    for field in ('owner_groups', 'structural_groups', 'object_contracts', 'private_protocols'):
        for row in contract[field]:
            files.update(row['sources'])
            if row.get('members_file'):
                files.add(row['members_file'])
    files.update(str(path.relative_to(ROOT)) for path in (ROOT / 'include').rglob('*') if path.is_file())
    bindings = {name: file_identity(source_path(name)) for name in sorted(files)}
    bindings['selection-contract'] = file_identity(contract_path)
    parity = tomllib.loads(paths['parity'].read_text())
    return {'bindings': bindings, 'frozen_names': candidate_names, 'frozen_owners': owners,
            'frozen_dynamic': dynamic, 'frozen_static': static, 'capabilities': capabilities,
            'header_occurrences': rows, 'header_profiles': header['profiles'], 'provider_names': sorted(provider_names),
            'deferred': deferred, 'provider_disposition': primary, 'abi_only_callables': abi_only,
            'callable_declaration_matrix': callable_matrix,
            'feature_aliases': feature_aliases,
            'families': [{'id': r['id'], 'status': r['status']} for r in parity['family']]}


def group_members(group: Mapping[str, Any], inputs: Mapping[str, Any]) -> list[str]:
    selector = group['selector']
    if selector == 'header-providers':
        values = set(inputs['provider_names'])
        require(set(group['delegated_members']) <= values, 'delegated member absent from header provider roster')
        return sorted(values - set(group['delegated_members']))
    if selector == 'feature-abi-only':
        values = {r['name'] for r in inputs['abi_only_callables']}
        require(set(group['delegated_members']) <= values, 'delegated member absent from ABI-only provider roster')
        return sorted(values - set(group['delegated_members']))
    if selector == 'explicit':
        return group['members']
    lines = source_path(group['members_file']).read_text().splitlines()
    require(lines and lines == sorted(set(lines)) and all(lines), 'exact member file is not sorted unique names')
    return lines


def expand_obligations(contract: Mapping[str, Any], inputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = {}
    def obtain(name):
        key = identity_key(identity(name))
        if key not in records:
            records[key] = {'identity': identity(name), 'origins': [], 'selection': None,
                            'expected_placements': [], 'unresolved': []}
        return records[key]
    for name in inputs['frozen_names']:
        obtain(name)['origins'].append({'kind': 'frozen-project-dynamic', 'capability': inputs['frozen_owners'][name]})
    for row in inputs['frozen_dynamic']:
        obtain(frozen_identity(row)['name'])['origins'].append({'kind': 'frozen-musl-dynamic', 'row': row})
    for index, row in enumerate(inputs['frozen_static']):
        obtain(row['name'])['origins'].append({'kind': 'frozen-musl-archive', 'row_index': index, 'row': row})
    for index, row in enumerate(inputs['header_occurrences']):
        obtain(row['name'])['origins'].append({'kind': 'native-header-external', 'occurrence_index': index})
    for row in inputs['abi_only_callables']:
        obtain(row['name'])['origins'].append({'kind': 'feature-abi-only', 'provider': row})
    for group in contract['owner_groups']:
        for name in group_members(group, inputs):
            record = obtain(name)
            require(record['selection'] is None, f'conflicting owner groups for {name}')
            record['selection'] = {'disposition': group['disposition'], 'owner': group['owner'], 'group': group['id'],
                                   'family': group['family'], 'reason': group['reason'], 'sources': group['sources']}
            record['origins'].append({'kind': 'source-owner-group', 'group': group['id']})
            for artifact in group['artifacts']:
                metadata = {'type': group['expected_type']} if group['expected_type'] else {}
                # Frozen metadata is an explicit inherited shared requirement;
                # function byte sizes and static binding are separate domains.
                frozen_row = next((r for r in inputs['frozen_dynamic'] if r['name'] == name), None)
                if artifact == 'candidate-shared' and frozen_row:
                    metadata.update({key: frozen_row[key] for key in ('type', 'binding', 'visibility')})
                    if frozen_row['type'] in {'OBJECT', 'TLS'}:
                        metadata['size_bytes'] = int(frozen_row['size'])
                metadata.update(group['placement_metadata'].get(artifact, {}))
                record['expected_placements'].append({'artifact_key': artifact, 'metadata': metadata, 'metadata_rule': group['static_metadata_rule'] if artifact == 'candidate-static' else 'explicit'})
            if group['id'] == ERRNO_PRIVATE_ALIAS_GROUP:
                # Metadata selects this deliberately non-public provider, but
                # cannot stand in for its source-bound alias/lifecycle receipt.
                record['unresolved'].append(ERRNO_STORAGE_LIFECYCLE_REQUIREMENT)
            if group['id'] == STDIO_ALIAS_PRIVATE_GROUP:
                # The three named FILE bodies are deliberately private. Their
                # exact static/shared placement and public weak alias domains
                # require the finite owner receipt below; metadata alone is
                # never a replacement for those runtime and ELF observations.
                record['unresolved'].append(STDIO_ALIAS_RECEIPT_REQUIREMENT)
            if group['id'] == SYSCALL_ALIAS_PRIVATE_GROUP:
                # This bounded private-provider route needs its own retained
                # source, alias, override and interposition evidence. Metadata
                # alone cannot make the 13 syscall bodies an owner discharge.
                record['unresolved'].append(SYSCALL_ALIAS_RECEIPT_REQUIREMENT)
    for name, owner in inputs['deferred'].items():
        record = obtain(name)
        require(record['selection'] is None, f'deferred/provider overlap: {name}')
        resolution = owner['resolution']
        disposition = {'compiler-builtin': 'compiler-builtin', 'consumer-supplied': 'consumer-supplied',
                       'oracle-declared-no-provider': 'oracle-no-provider'}.get(resolution, 'unresolved')
        record['selection'] = {'disposition': disposition, 'owner': owner['id'], 'family': owner['semantic_family'],
                               'reason': owner['provider_target'], 'sources': ['compat/x86_64/header_callable_disposition.toml']}
        if disposition == 'unresolved':
            record['unresolved'].append('BSD random policy is unresolved; planned provider routing is not closure')
        else:
            record['unresolved'].append('selected boundary requires its declaration/consumer/compiler/oracle receipt')
    for group in contract['structural_groups']:
        for name in group['members']:
            record = obtain(name)
            require(record['selection'] is None, f'structural/provider overlap: {name}')
            record['selection'] = {'disposition': group['disposition'], 'owner': group['id'], 'sources': group['sources'], 'reason': group['reason']}
            record['origins'].append({'kind': 'native-structural-contract', 'group': group['id']})
            record['unresolved'].extend(group['requirements'])
    for obj in contract['object_contracts']:
        record = obtain(obj['name'])
        require(record['selection'] is None, f'object/provider overlap: {obj["name"]}')
        record['selection'] = {'disposition': 'public-provider', 'owner': obj['id'], 'sources': obj['sources'],
                               'reason': obj['meaning'], 'c_abi_type': obj['c_abi_type'], 'source_mutable': obj['source_mutable'],
                               'declaration': obj['declaration'], 'declaration_kind': obj['declaration_kind'], 'alias_target': obj['alias_target']}
        metadata = {key: obj[key] for key in ('type', 'binding', 'visibility', 'size_bytes', 'alignment_bytes')}
        record['expected_placements'] = [{'artifact_key': artifact, 'metadata': metadata} for artifact in obj['artifacts']]
        record['origins'].append({'kind': 'native-object-contract', 'group': obj['id']})
    for protocol in contract['private_protocols']:
        for name in protocol['members']:
            record = obtain(name)
            require(record['selection'] is None, f'private/provider overlap: {name}')
            record['selection'] = {'disposition': 'private-resolution-operation', 'owner': protocol['id'],
                                   'sources': protocol['sources'], 'reason': protocol['reason'], 'protocol': protocol}
            record['origins'].append({'kind': 'native-private-protocol', 'group': protocol['id']})
            record['unresolved'].extend(protocol['requirements'])
    for alias in inputs['feature_aliases']:
        record = obtain(alias['name'])
        record.setdefault('function_alias_requirements', []).append(copy.deepcopy(alias))
        record['origins'].append({'kind': 'selected-feature-function-alias', 'feature': alias['owner']})
        record['unresolved'].append('source-selected alias requires exact feature archive selection and component receipt')
    for record in records.values():
        if record['selection'] is None:
            kinds = {r['kind'] for r in record['origins']}
            if kinds == {'frozen-musl-archive'}:
                record['selection'] = {'disposition': 'unselected-observation', 'owner': 'pinned-musl',
                                       'scope': 'frozen-oracle-archive-only', 'physical_exposure': 'frozen reference archive observation; no native placement selected',
                                       'reason': 'frozen archive occurrence alone does not select an application ABI'}
            else:
                record['selection'] = {'disposition': 'unresolved', 'owner': None,
                                       'reason': 'selecting inputs need an explicit native owner/disposition'}
                record['unresolved'].append('native selection or structural ownership is unresolved')
    return [records[key] for key in sorted(records, key=identity_order)]


def account_placements(expanded: Sequence[Mapping[str, Any]], facts: Mapping[str, Any]) -> dict[str, Any]:
    """Retain every physical row and join selected providers by definition domain.

    The caller supplies publicly replayed facts. This pure join does not replace
    the complete ELF parser or infer source ownership from symbol spelling.
    """
    expected_keys = {item.key for item in elf_facts.ARTIFACTS}
    require(set(facts['facts']) == set(facts['artifacts']) == expected_keys, 'physical artifact roster differs')
    records = {identity_key(r['identity']): copy.deepcopy(r) for r in expanded}
    require(len(records) == len(expanded), 'duplicate expanded identity')
    occurrences, artifacts, keys = [], {}, set()
    by_identity = {}
    for artifact in elf_facts.ARTIFACTS:
        observed = facts['facts'][artifact.key]
        members = observed if artifact.kind == 'archive' else [observed]
        artifact_refs = []
        for member in members:
            member_index = member['member_index'] if artifact.kind == 'archive' else None
            member_occurrence = member['member_occurrence'] if artifact.kind == 'archive' else None
            sections = {str(section['index']): section for section in member['sections']}
            for table in member['symbol_tables']:
                for row in table['rows']:
                    key = (artifact.key, member_index, member_occurrence, table['section_index'], row['row_index'])
                    require(key not in keys, 'duplicate physical symbol occurrence')
                    keys.add(key)
                    role = row_role(row)
                    index = len(occurrences)
                    occurrence = {'index': index, 'artifact_key': artifact.key,
                                  'artifact_sha256': facts['artifacts'][artifact.key]['identity']['sha256'],
                                  'member_index': member_index, 'member_occurrence': member_occurrence,
                                  'member_name': member['member'] if artifact.kind == 'archive' else None,
                                  'table': table['name'], 'table_section_index': table['section_index'],
                                  'row': copy.deepcopy(row), 'definition_section': copy.deepcopy(sections.get(row['section_index'])),
                                  'role': role, 'accounting': None}
                    artifact_refs.append(index)
                    occurrences.append(occurrence)
                    if role == 'unnamed':
                        occurrence['accounting'] = {'disposition': 'unnamed-observation', 'owner': artifact.owner}
                        continue
                    identity_value = row_identity(row)
                    logical_key = identity_key(identity_value)
                    by_identity.setdefault(logical_key, []).append(occurrence)
                    record = records.get(logical_key)
                    if artifact.owner == 'reference':
                        occurrence['accounting'] = {'disposition': 'unselected-observation', 'owner': 'pinned-musl',
                                                    'scope': 'native-reference-ELF', 'physical_exposure': role,
                                                    'reason': 'reference placement is an oracle observation, not a native provider selection'}
                        if role in {'definition', 'import', 'unsupported'}:
                            if record is None:
                                record = {'identity': identity_value, 'origins': [], 'selection': occurrence['accounting'],
                                          'expected_placements': [], 'unresolved': []}
                                records[logical_key] = record
                            record['origins'].append({'kind': 'native-reference-occurrence', 'index': index})
                        continue
                    selected_private_definition = record is not None and (
                        record['selection']['disposition'] == 'private-provider'
                        or artifact.key in record['selection'].get('protocol', {}).get('provider_artifacts', []))
                    if role == 'local-definition' and not selected_private_definition:
                        occurrence['accounting'] = {'disposition': 'local-observation', 'owner': artifact.owner,
                                                    'reason': 'retained implementation-local definition; no public selection inferred'}
                        continue
                    if record is None:
                        record = {'identity': identity_value, 'origins': [],
                                  'selection': {'disposition': 'unresolved', 'owner': None,
                                                'reason': 'candidate occurrence has no reviewed native owner/disposition'},
                                  'expected_placements': [], 'unresolved': ['candidate binding ownership is unresolved']}
                        records[logical_key] = record
                    elif record['selection']['disposition'] == 'unselected-observation':
                        record['selection'] = {'disposition': 'unresolved', 'owner': None,
                                                'reason': 'oracle-only accounting does not assign this candidate occurrence a native owner'}
                        record['unresolved'].append('candidate binding ownership is unresolved')
                    record['origins'].append({'kind': 'native-candidate-occurrence', 'index': index})
                    occurrence['accounting'] = {'disposition': record['selection']['disposition'],
                                                'owner': record['selection'].get('owner'), 'scope': artifact.key}
                    if role == 'unsupported':
                        record['unresolved'].append('unsupported candidate ELF binding/type/visibility semantics')
                    elif role == 'import':
                        protocol = record['selection'].get('protocol')
                        if protocol and artifact.key in protocol['consumer_artifacts']:
                            occurrence['accounting']['resolution'] = {'kind': protocol['endpoint_kind'], 'endpoint': protocol['endpoint']}
                            if protocol['endpoint_kind'] == 'source-dispatch-operation':
                                occurrence['accounting']['resolution']['operation'] = next(r for r in protocol['operations'] if r['name'] == row['name'])
                                if row['binding'] != 'GLOBAL' or row['visibility'] != 'DEFAULT' or row['type'] not in {'NOTYPE', 'FUNC'}:
                                    record['unresolved'].append('private operation import metadata violates source admission')
                            occurrence['accounting']['resolution_proven'] = False
                        else:
                            record['unresolved'].append('exact ordinary import/provider or optional weak/null resolution proof is missing')
                    elif artifact.key not in {r['artifact_key'] for r in record['expected_placements']} | set(record['selection'].get('protocol', {}).get('provider_artifacts', [])):
                        record['unresolved'].append(f'candidate definition placement is not selected: {artifact.key}')
        artifacts[artifact.key] = {'artifact': copy.deepcopy(facts['artifacts'][artifact.key]), 'occurrence_indices': artifact_refs,
                                   'member_count': len(members),
                                   'complete_facts_sha256': hashlib.sha256(inventory._stable_json(observed)).hexdigest()}

    joins, blockers, protocol_joins = [], [], []
    for key in sorted(records, key=identity_order):
        record = records[key]
        relevant = by_identity.get(key, [])
        protocol = record['selection'].get('protocol')
        if protocol:
            for artifact_key in protocol['consumer_artifacts']:
                imported = [r for r in relevant if r['artifact_key'] == artifact_key and r['role'] == 'import']
                protocol_joins.append({'identity': record['identity'], 'artifact_key': artifact_key, 'role': 'consumer-import',
                                       'occurrence_indices': [r['index'] for r in imported], 'endpoint_kind': protocol['endpoint_kind'],
                                       'signature_status': protocol['signature_status'], 'relocation_lifecycle_proven': False})
                if not imported:
                    record['unresolved'].append(f'selected private consumer import is absent: {artifact_key}')
            for artifact_key in protocol['provider_artifacts']:
                definitions = [r for r in relevant if r['artifact_key'] == artifact_key and r['row']['section_index'] != 'UND']
                differences = [{'occurrence_index': r['index'], 'fields': metadata_differences(protocol['provider_metadata'], r['row'], r['definition_section'])} for r in definitions]
                protocol_joins.append({'identity': record['identity'], 'artifact_key': artifact_key, 'role': 'private-descriptor-definition',
                                       'occurrence_indices': [r['index'] for r in definitions], 'metadata_differences': differences,
                                       'binding_and_visibility_selection_complete': False})
                if not definitions or any(r['fields'] for r in differences):
                    record['unresolved'].append(f'selected private descriptor definition is absent or mismatched: {artifact_key}')
                record['unresolved'].append('private descriptor exact binding/visibility selection and lifecycle proof remain required')
        for expected in record['expected_placements']:
            artifact_key = expected['artifact_key']
            candidates = [r for r in relevant if r['artifact_key'] == artifact_key and r['row']['section_index'] != 'UND']
            public = record['selection']['disposition'] == 'public-provider'
            if artifact_key in {'candidate-shared', 'candidate-loader'} and public:
                candidates = [r for r in candidates if r['table'] == '.dynsym' and r['row']['binding'] in {'GLOBAL', 'WEAK', 'UNIQUE'}
                              and r['row']['visibility'] in {'DEFAULT', 'PROTECTED'}]
            elif record['selection'].get('group') == FIXED_C_PRODUCER_GROUP and artifact_key == 'candidate-shared':
                candidates = [r for r in candidates if r['table'] == '.symtab']
                if any(r['table'] == '.dynsym' and r['row']['section_index'] != 'UND' for r in relevant if r['artifact_key'] == artifact_key):
                    record['unresolved'].append('private allocator owner unexpectedly appears in shared dynsym')
            elif (record['selection'].get('group') == COMPILER_HELPER_GROUP
                  and artifact_key == COMPILER_HELPER_SHARED_ARTIFACT
                  and expected.get('metadata_rule') == COMPILER_HELPER_SHARED_METADATA_RULE):
                # The owning helper reader has already proved that the exact
                # private libc copy is local in .symtab and absent from
                # .dynsym.  Archive GLOBAL definitions are a separate
                # selected placement and cannot stand in for this copy.
                candidates = [r for r in candidates if r['table'] == '.symtab']
                if any(r['table'] == '.dynsym' and r['row']['section_index'] != 'UND'
                       for r in relevant if r['artifact_key'] == artifact_key):
                    record['unresolved'].append('private compiler-helper owner unexpectedly appears in shared dynsym')
            elif record['selection']['disposition'] == 'private-provider':
                # A reviewed private provider may intentionally be a LOCAL
                # shared ``.symtab`` definition.  It still satisfies normal
                # archive linking, but must never be promoted through the
                # public ``.dynsym`` branch above.
                candidates = [r for r in candidates if r['role'] in {'definition', 'local-definition'}]
            else:
                candidates = [r for r in candidates if r['role'] == 'definition']
            definitions = []
            for candidate in candidates:
                if not any(same_definition_domain(candidate, previous) for previous in definitions):
                    definitions.append(candidate)
            metadata_origin = None
            if expected.get('metadata_rule') == 'selected-native-oracle-function':
                oracle = [r for r in relevant if r['artifact_key'] == 'reference-static' and r['role'] == 'definition']
                metadata_origin = reference_static_metadata(oracle, expected['metadata'])
                if metadata_origin['metadata'] is None:
                    record['unresolved'].append(metadata_origin['reason'])
                else:
                    expected['metadata'] = {**metadata_origin['metadata'], **expected['metadata']}
            differences = [{'occurrence_index': r['index'], 'fields': metadata_differences(expected['metadata'], r['row'], r['definition_section'])}
                           for r in candidates]
            missing_metadata = [field for field in ('type', 'binding', 'visibility') if field not in expected['metadata']]
            if missing_metadata:
                record['unresolved'].append(f'exact metadata selection missing for {artifact_key}: {", ".join(missing_metadata)}')
            if expected['metadata'].get('type') in {'OBJECT', 'TLS'} or any(r['row']['type'] in {'OBJECT', 'TLS'} for r in candidates):
                missing_layout = [field for field in ('size_bytes', 'alignment_bytes') if field not in expected['metadata']]
                if missing_layout:
                    record['unresolved'].append(f'exact data layout selection missing for {artifact_key}: {", ".join(missing_layout)}')
            join = {'identity': record['identity'], 'artifact_key': artifact_key, 'expected_metadata': expected['metadata'], 'metadata_origin': metadata_origin,
                    'occurrence_indices': [r['index'] for r in candidates], 'definition_count': len(definitions),
                    'metadata_differences': differences, 'placement_observed': len(definitions) == 1 and not any(r['fields'] for r in differences)}
            joins.append(join)
            if not join['placement_observed']:
                record['unresolved'].append(f'missing, ambiguous or mismatched selected provider placement: {artifact_key}')
        record['unresolved'] = sorted(set(record['unresolved']))
        for reason in record['unresolved']:
            blockers.append({'code': 'identity-unresolved', 'identity': record['identity'], 'reason': reason})
        if record['selection']['disposition'] == 'unresolved' and not record['unresolved']:
            blockers.append({'code': 'identity-unresolved', 'identity': record['identity'], 'reason': record['selection']['reason']})

    aliases = []
    for record in records.values():
        target = record['selection'].get('alias_target')
        if not target:
            continue
        for expected in record['expected_placements']:
            artifact_key = expected['artifact_key']
            left = [r for r in by_identity.get(identity_key(record['identity']), []) if r['artifact_key'] == artifact_key and r['row']['section_index'] != 'UND']
            right = [r for r in by_identity.get(identity_key(identity(target)), []) if r['artifact_key'] == artifact_key and r['row']['section_index'] != 'UND']
            matches = [[a['index'], b['index']] for a in left for b in right if same_definition_domain(a, b)]
            aliases.append({'kind': 'source-defined-data-alias', 'identity': record['identity'], 'target': identity(target),
                            'artifact_key': artifact_key, 'same_domain_pairs': matches,
                            'source_owner': record['selection']['owner'], 'runtime_semantics_proven': False})
            if not matches:
                blockers.append({'code': 'alias-domain-missing', 'identity': record['identity'], 'artifact_key': artifact_key})
    function_aliases = []
    for record in records.values():
        for alias in record.get('function_alias_requirements', []):
            # This is the selected aggregate archive observation. The exact
            # feature-profile archive receipt remains a distinct open domain.
            expected = [row for row in record['expected_placements'] if row['artifact_key'] == 'candidate-static']
            if not expected:
                blockers.append({'code': 'function-alias-placement-unselected', 'identity': record['identity'], 'feature': alias['owner']})
            for placement in expected:
                artifact_key = placement['artifact_key']
                left = [r for r in by_identity.get(identity_key(record['identity']), []) if r['artifact_key'] == artifact_key and r['role'] == 'definition']
                right = [r for r in by_identity.get(identity_key(identity(alias['target'])), []) if r['artifact_key'] == artifact_key and r['role'] == 'definition']
                matches = [[a['index'], b['index']] for a in left for b in right
                           if a['row']['type'] == 'FUNC' and a['row']['binding'] == 'WEAK' and same_definition_domain(a, b)]
                function_aliases.append({'identity': record['identity'], 'target': identity(alias['target']),
                                         'artifact_key': artifact_key, 'same_domain_pairs': matches,
                                         'feature_contract': copy.deepcopy(alias), 'feature_archive_receipt_proven': False,
                                         'runtime_semantics_proven': False})
                if not matches:
                    blockers.append({'code': 'function-alias-domain-missing', 'identity': record['identity'], 'artifact_key': artifact_key})
    return {'identities': [records[key] for key in sorted(records, key=identity_order)], 'artifacts': artifacts,
            'occurrences': occurrences, 'placement_joins': joins, 'private_protocol_joins': protocol_joins,
            'data_alias_observations': aliases, 'function_alias_observations': function_aliases, 'blockers': blockers}


def _common_checkout(root: Path) -> Path:
    path = Path(_git(root, 'rev-parse', '--git-common-dir').decode().strip())
    if not path.is_absolute():
        path = root / path
    return path.resolve().parent


def physical_work_path(path: Path, *, directory: bool, own: bool = False, fresh: bool = False) -> Path:
    value = Path(os.path.abspath(path))
    base = ROOT / '.work' if own else _common_checkout(ROOT) / '.work'
    require(value.is_relative_to(base) and value != base, f'path is outside checkout-local .work: {value}')
    if fresh:
        require(not value.exists() and not value.is_symlink(), 'output must be fresh')
        require(value.parent.is_dir() and value.parent.resolve() == value.parent, 'output parent must be an existing physical directory')
    else:
        require(value.exists() and value.resolve() == value and not value.is_symlink(), f'nonphysical input path: {value}')
        require(value.is_dir() if directory else value.is_file(), f'input path kind differs: {value}')
    return value


def validate_measurement_paths(*, measurement_checkout: Path, elf_report: Path, base_inventory: Path,
                               static_product: Path, dynamic_product: Path, static_preparation: Path) -> dict[str, Path]:
    checkout = physical_work_path(measurement_checkout, directory=True)
    require(_common_checkout(checkout) == _common_checkout(ROOT), 'measurement checkout belongs to another repository')
    require(not _git(checkout, 'status', '--porcelain', '--untracked-files=all').strip(), 'measurement checkout must be clean')
    values = {'measurement_checkout': checkout}
    for name, path, directory in [('elf_report', elf_report, False), ('base_inventory', base_inventory, False),
                                   ('static_product', static_product, True), ('dynamic_product', dynamic_product, True),
                                   ('static_preparation', static_preparation, False)]:
        values[name] = physical_work_path(path, directory=directory)
    return values


def replay_measurement(paths: Mapping[str, Path]) -> tuple[dict[str, Any], dict[str, Any]]:
    checkout = paths['measurement_checkout']
    reader = checkout / 'compat/x86_64/native_abi_elf_facts.py'
    before = {key: file_identity(paths[key]) for key in ('elf_report', 'base_inventory', 'static_preparation')}
    reader_before = file_identity(reader)
    revision_before = _git(checkout, 'rev-parse', 'HEAD').decode().strip()
    argv = [sys.executable, '-B', '-I', str(reader), '--validate-report', str(paths['elf_report'])]
    argv += [word for option, key in [('--base-inventory', 'base_inventory'), ('--static-product', 'static_product'),
                                     ('--dynamic-product', 'dynamic_product'), ('--static-preparation', 'static_preparation')]
             for word in (option, str(paths[key]))]
    environment = {'LANG': 'C', 'LC_ALL': 'C', 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONDONTWRITEBYTECODE': '1'}
    completed = subprocess.run(argv, cwd=checkout, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(completed.returncode == 0 and not completed.stderr,
            f'existing public ELF reader rejected measurement: {completed.stderr.decode(errors="replace")}')
    require(same(before, {key: file_identity(paths[key]) for key in before}) and same(reader_before, file_identity(reader)), 'measurement input changed during public replay')
    require(revision_before == _git(checkout, 'rev-parse', 'HEAD').decode().strip()
            and not _git(checkout, 'status', '--porcelain', '--untracked-files=all').strip(), 'measurement source changed during replay')
    facts = read_json(paths['elf_report'])
    require(facts['collector_execution_source']['revision'] == revision_before, 'measurement collector is not the replay checkout')
    binding = {'inputs': {key: str(value) for key, value in paths.items()}, 'reports': before,
               'reader': reader_before, 'python': file_identity(Path(sys.executable).resolve()),
               'argv': argv, 'cwd': str(checkout), 'environment': environment,
               'returncode': completed.returncode, 'stdout': completed.stdout.decode(), 'stderr': completed.stderr.decode(),
               'collector_source': facts['collector_execution_source'], 'candidate_build': facts['base_inventory']['candidate_build']}
    return facts, binding


def fixed_c_producer_metadata_selection(contract: Mapping[str, Any], inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Load the one exact fixed-C metadata projection before ELF placement joins.

    The allocator's shared-localization list is a finite source-owned set.  It
    is not a spelling prefix or a default rule for another private provider.
    The owning account supplies source minimum alignment for both symbol
    placements; its separate static-section observation remains in that
    account rather than becoming a generic selection alignment rule.
    """
    groups = [row for row in contract['owner_groups'] if row['id'] == FIXED_C_PRODUCER_GROUP]
    require(len(groups) == 1, 'fixed-C producer owner group is absent or duplicated')
    group = groups[0]
    require(group['selector'] == 'exact-file-members'
            and group['disposition'] == 'private-provider'
            and group['owner'] == FIXED_C_PRODUCER_OWNER
            and group['family'] == 'libc.c-abi-compat'
            and tuple(group['artifacts']) == FIXED_C_PRODUCER_ARTIFACTS
            and group['sources'] == list(FIXED_C_PRODUCER_SOURCE_FILES[:5])
            and group['members'] == []
            and group['members_file'] == 'libc/src/c_abi/x86_64/owned_mimalloc_hidden.list'
            and group['delegated_members'] == []
            and group['expected_type'] == ''
            and group['placement_metadata'] == {}
            and group['static_metadata_rule'] == 'explicit',
            'fixed-C producer owner scope differs')
    source_bindings = {}
    for name in FIXED_C_PRODUCER_SOURCE_FILES:
        binding = inputs['bindings'].get(name)
        require(binding is not None and same(binding, file_identity(ROOT / name)),
                f'fixed-C producer source input differs: {name}')
        source_bindings[name] = copy.deepcopy(binding)
    members = group_members(group, inputs)
    try:
        owner_contract = producer_metadata.load_contract()
        owner_members = producer_metadata.contract_members(owner_contract)
        metadata = producer_metadata.selected_metadata()
    except (ValueError, OSError) as error:
        raise SelectionError(f'fixed-C producer metadata contract rejected: {error}') from error
    require(members == owner_members and len(members) == 424, 'fixed-C producer member roster differs')
    require(set(metadata) == set(members) and len(metadata) == len(members),
            'fixed-C producer metadata roster differs')
    data_layouts = {row['name']: row for row in owner_contract['metadata']['data_objects']}
    data_layouts[owner_contract['metadata']['tls_object']['name']] = owner_contract['metadata']['tls_object']
    for name in members:
        roles = exact(metadata[name], {'static', 'shared'}, f'fixed-C producer metadata {name}')
        fields = {'type', 'binding', 'visibility'}
        if name in data_layouts:
            fields |= {'size_bytes', 'alignment_bytes'}
        for role in ('static', 'shared'):
            row = exact(roles[role], fields, f'fixed-C producer {role} metadata {name}')
            require(row['type'] in {'FUNC', 'OBJECT', 'TLS'}
                    and row['binding'] in {'GLOBAL', 'WEAK', 'LOCAL'}
                    and row['visibility'] == 'DEFAULT',
                    f'fixed-C producer {role} metadata is unsupported: {name}')
            if name in data_layouts:
                require(type(row['size_bytes']) is int and row['size_bytes'] > 0
                        and type(row['alignment_bytes']) is int and row['alignment_bytes'] > 0
                        and row['alignment_bytes'] & (row['alignment_bytes'] - 1) == 0,
                        f'fixed-C producer {role} layout is invalid: {name}')
        if name in data_layouts:
            required_alignment = data_layouts[name]['source']['source_required_alignment']
            require(roles['static']['alignment_bytes'] == required_alignment
                    and roles['shared']['alignment_bytes'] == required_alignment,
                    f'fixed-C producer source alignment differs: {name}')
    return {
        'group': copy.deepcopy(group),
        'members': list(members),
        'metadata': copy.deepcopy(metadata),
        'source_inputs': source_bindings,
    }


def _producer_product_identity(path: Path, logical_path: str, description: str) -> dict[str, Any]:
    try:
        return inventory.file_record(path, logical_path=logical_path)
    except inventory.InventoryError as error:
        raise SelectionError(f'fixed-C producer {description} is not a physical regular file') from error


def _require_logical_identity(observed: Mapping[str, Any], retained: object, logical_path: str, description: str) -> None:
    retained = exact(retained, {'path', 'sha256', 'size', 'mode'}, description)
    require(retained['path'] == logical_path, f'{description} logical path differs')
    require(same(dict(observed), retained), f'{description} physical identity differs')


def _require_identity_payload(observed: Mapping[str, Any], retained: object, logical_path: str, description: str) -> None:
    """Compare a host-path record with a retained canonical-path record."""
    retained = exact(retained, {'path', 'sha256', 'size', 'mode'}, description)
    require(retained['path'] == logical_path, f'{description} logical path differs')
    require(same({key: observed[key] for key in ('sha256', 'size', 'mode')},
                 {key: retained[key] for key in ('sha256', 'size', 'mode')}),
            f'{description} physical identity differs')


def fixed_c_producer_metadata_adapter(facts: Mapping[str, Any], measurement: Mapping[str, Any],
                                      paths: Mapping[str, Path], contract: Mapping[str, Any],
                                      inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Bind the fixed C account to the product cohort already replayed by ELF facts.

    This deliberately does not invoke either product reader again.  The public
    ELF replay has already authenticated the base inventory and both products.
    Here the retained base report, exact manifest payload entries, and
    before/after physical identities keep the focused C account from accepting
    a different file after that replay.
    """
    selection = fixed_c_producer_metadata_selection(contract, inputs)
    expected_measurement = {
        'inputs', 'reports', 'reader', 'python', 'argv', 'cwd', 'environment',
        'returncode', 'stdout', 'stderr', 'collector_source', 'candidate_build',
    }
    measurement = exact(measurement, expected_measurement, 'public ELF replay binding')
    reports = exact(measurement['reports'], {'elf_report', 'base_inventory', 'static_preparation'},
                    'public ELF replay report identities')
    facts_binding = exact(facts.get('base_inventory'), {'report', 'collector_execution_source', 'candidate_build'},
                          'ELF facts base inventory binding')
    facts_report = exact(facts_binding['report'], {'original', 'retained'}, 'ELF facts base inventory snapshot')
    actual_base = file_identity(paths['base_inventory'])
    actual_elf = file_identity(paths['elf_report'])
    actual_preparation = _producer_product_identity(
        paths['static_preparation'], str(inventory.STATIC_PREPARATION_PATH), 'static preparation')
    before = {'elf_facts': actual_elf, 'base_inventory': actual_base, 'static_preparation': actual_preparation}
    for name, (path_key, relative, logical_root) in FIXED_C_PRODUCER_PRODUCT_FILES.items():
        before[name] = _producer_product_identity(
            paths[path_key] / relative, str(logical_root / relative), name.replace('_', ' '))
    require(same(actual_elf, reports['elf_report']) and same(actual_base, reports['base_inventory'])
            and same(file_identity(paths['static_preparation']), reports['static_preparation']),
            'public ELF replay input changed before fixed-C producer account')
    _require_identity_payload(actual_base, facts_report['original'], str(elf_facts.BASE_REPORT),
                              'ELF facts base inventory snapshot')
    _require_identity_payload(actual_base, facts_report['retained'], 'inputs/base-inventory-report.json',
                              'retained ELF facts base inventory snapshot')
    require(same(facts_binding['candidate_build'], measurement['candidate_build']),
            'ELF facts candidate build differs from public replay')
    require(same(facts_binding['collector_execution_source'], measurement['collector_source']),
            'ELF facts collector source differs from public replay')

    base = read_json(paths['base_inventory'])
    base_inputs = exact(base.get('inputs'), {'pinned_musl', 'static_product', 'dynamic_product'},
                        'replayed base inventory inputs')
    static_product = exact(base_inputs['static_product'], {'kind', 'root', 'manifest', 'payload_files', 'selection'},
                           'replayed static product')
    dynamic_product = exact(base_inputs['dynamic_product'],
                            {'kind', 'root', 'manifest', 'payload_files', 'selection', 'materialization_state'},
                            'replayed dynamic product')
    require(static_product['kind'] == 'static' and static_product['root'] == str(inventory.STATIC_PRODUCT_PATH),
            'replayed static product role differs')
    require(dynamic_product['kind'] == 'dynamic' and dynamic_product['root'] == str(inventory.DYNAMIC_PRODUCT_PATH),
            'replayed dynamic product role differs')
    _require_logical_identity(before['static_manifest'], static_product['manifest'],
                              str(inventory.STATIC_PRODUCT_PATH / 'share/crabc/manifest.json'),
                              'replayed static manifest')
    _require_logical_identity(before['shared_manifest'], dynamic_product['manifest'],
                              str(inventory.DYNAMIC_PRODUCT_PATH / 'share/crabc/manifest.json'),
                              'replayed dynamic manifest')
    for product, name in ((static_product, 'static_provenance'), (dynamic_product, 'shared_provenance'),
                          (dynamic_product, 'dynamic_state')):
        payloads = product['payload_files']
        require(type(payloads) is dict and type(payloads.get(FIXED_C_PRODUCER_PRODUCT_FILES[name][1])) is str
                and payloads[FIXED_C_PRODUCER_PRODUCT_FILES[name][1]] == before[name]['sha256'],
                f'replayed product payload differs: {name}')
    static_selection = exact(static_product['selection'], {'libc_archive', 'archive_aliases'},
                             'replayed static product selection')
    dynamic_selection = exact(dynamic_product['selection'], {'libc_shared', 'loader', 'loader_alias'},
                              'replayed dynamic product selection')
    _require_logical_identity(before['candidate_static_libc'], static_selection['libc_archive'],
                              str(inventory.STATIC_PRODUCT_PATH / 'usr/lib/libc.a'), 'replayed static libc archive')
    _require_logical_identity(before['candidate_shared_libc'], dynamic_selection['libc_shared'],
                              str(inventory.DYNAMIC_PRODUCT_PATH / 'usr/lib/libc.so'), 'replayed dynamic libc')
    facts_artifacts = exact(facts.get('artifacts'), {item.key for item in elf_facts.ARTIFACTS},
                            'ELF facts artifact roster')
    _require_logical_identity(before['candidate_static_libc'],
                              exact(facts_artifacts['candidate-static'], {'kind', 'elf_type', 'identity', 'binding'},
                                    'ELF facts static artifact')['identity'],
                              str(inventory.STATIC_PRODUCT_PATH / 'usr/lib/libc.a'), 'ELF facts static libc')
    _require_logical_identity(before['candidate_shared_libc'],
                              exact(facts_artifacts['candidate-shared'], {'kind', 'elf_type', 'identity', 'binding'},
                                    'ELF facts shared artifact')['identity'],
                              str(inventory.DYNAMIC_PRODUCT_PATH / 'usr/lib/libc.so'), 'ELF facts shared libc')

    provenance = exact(base.get('product_provenance'),
                       {'candidate_build', 'static_preparation', 'dynamic_materialization'},
                       'replayed product provenance')
    require(same(provenance['candidate_build'], facts_binding['candidate_build']),
            'replayed product build differs from ELF facts')
    static_provenance = exact(provenance['static_preparation'],
                              {'logical_path', 'source', 'product_selector', 'manifest_sha256', 'receipt'},
                              'replayed static preparation provenance')
    require(static_provenance['logical_path'] == str(inventory.STATIC_PREPARATION_PATH)
            and static_provenance['product_selector'] == 'primary'
            and static_provenance['manifest_sha256'] == static_product['manifest']['sha256'],
            'replayed static preparation selection differs')
    static_receipt = exact(static_provenance['receipt'], {'logical_path', 'identity', 'snapshot'},
                           'replayed static preparation receipt')
    _require_logical_identity(before['static_preparation'], static_receipt['identity'],
                              str(inventory.STATIC_PREPARATION_PATH), 'replayed static preparation receipt')
    dynamic_provenance = exact(provenance['dynamic_materialization'],
                               {'logical_path', 'identity', 'manifest_sha256', 'state', 'state_file'},
                               'replayed dynamic materialization provenance')
    require(dynamic_provenance['logical_path'] == str(inventory.DYNAMIC_PRODUCT_PATH / inventory.DYNAMIC_STATE_RELATIVE)
            and dynamic_provenance['manifest_sha256'] == dynamic_product['manifest']['sha256'],
            'replayed dynamic materialization selection differs')
    dynamic_state = exact(dynamic_provenance['state_file'], {'logical_path', 'identity', 'snapshot'},
                          'replayed dynamic state receipt')
    _require_logical_identity(before['dynamic_state'], dynamic_state['identity'],
                              str(inventory.DYNAMIC_PRODUCT_PATH / inventory.DYNAMIC_STATE_RELATIVE),
                              'replayed dynamic state receipt')
    require(same(dynamic_product['materialization_state'], {
        key: dynamic_provenance[key] for key in ('logical_path', 'identity', 'manifest_sha256', 'state')
    }), 'replayed dynamic materialization state differs')

    try:
        account = producer_metadata.account_producer_metadata(
            facts,
            read_json(paths['static_product'] / 'share/crabc/libc-static.provenance.json'),
            read_json(paths['dynamic_product'] / 'share/crabc/libc-shared.provenance.json'),
            read_json(paths['dynamic_product'] / 'share/crabc/manifest.json'),
        )
    except (ValueError, OSError) as error:
        raise SelectionError(f'fixed-C producer account rejected: {error}') from error
    require(type(account) is dict and account.get('schema') == producer_metadata.SCHEMA
            and account.get('status') == 'component-pass-not-qualification',
            'fixed-C producer account status differs')
    flags = exact(account.get('status_flags'), {'family_completion', 'promotion_ready', 'public_support'},
                  'fixed-C producer account flags')
    require(all(flags[field] is False for field in flags), 'fixed-C producer account changes qualification flags')
    scope = exact(account.get('scope'), {'member_count', 'metadata_buckets', 'rust_root_c_imports', 'shared_dynsym_private_names'},
                  'fixed-C producer account scope')
    require(same(scope, {
                'member_count': len(selection['members']),
                'metadata_buckets': {
                    'strong-functions': 419, 'weak-null-fallback': 1, 'data-objects': 3, 'initial-exec-tls': 1,
                },
                'rust_root_c_imports': 7,
                'shared_dynsym_private_names': 'absent',
            }),
            'fixed-C producer account scope differs')

    after = {'elf_facts': file_identity(paths['elf_report']), 'base_inventory': file_identity(paths['base_inventory']),
             'static_preparation': _producer_product_identity(paths['static_preparation'], str(inventory.STATIC_PREPARATION_PATH),
                                                               'static preparation')}
    for name, (path_key, relative, logical_root) in FIXED_C_PRODUCER_PRODUCT_FILES.items():
        after[name] = _producer_product_identity(paths[path_key] / relative, str(logical_root / relative),
                                                 name.replace('_', ' '))
    require(same(before, after), 'fixed-C producer product input changed during account')
    return {
        'status': 'component-pass-not-qualification',
        'selection': {
            'owner_group': FIXED_C_PRODUCER_GROUP,
            'owner': FIXED_C_PRODUCER_OWNER,
            'artifacts': list(FIXED_C_PRODUCER_ARTIFACTS),
            'member_count': len(selection['members']),
            'metadata_placement_count': len(selection['members']) * len(FIXED_C_PRODUCER_ARTIFACTS),
            'data_layout_placement_count': 8,
        },
        'source_inputs': selection['source_inputs'],
        'inputs': {
            'before': before,
            'after': after,
            'public_elf_replay': {
                'base_inventory': copy.deepcopy(facts_binding['report']),
                'candidate_build': copy.deepcopy(facts_binding['candidate_build']),
                'collector_source': copy.deepcopy(facts_binding['collector_execution_source']),
            },
        },
        'selected_metadata': selection['metadata'],
        'account': account,
    }


def attach_fixed_c_producer_metadata(expanded: Sequence[Mapping[str, Any]], companion: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Apply only the fixed-C account's exact metadata before ELF observation."""
    companion = exact(companion, {'status', 'selection', 'source_inputs', 'inputs', 'selected_metadata', 'account'},
                      'fixed-C producer companion')
    selection = exact(companion['selection'], {
        'owner_group', 'owner', 'artifacts', 'member_count', 'metadata_placement_count', 'data_layout_placement_count',
    }, 'fixed-C producer companion selection')
    require(companion['status'] == 'component-pass-not-qualification'
            and selection['owner_group'] == FIXED_C_PRODUCER_GROUP
            and selection['owner'] == FIXED_C_PRODUCER_OWNER
            and selection['artifacts'] == list(FIXED_C_PRODUCER_ARTIFACTS),
            'fixed-C producer companion selection differs')
    metadata = companion['selected_metadata']
    require(type(metadata) is dict and len(metadata) == selection['member_count'] == 424,
            'fixed-C producer companion metadata roster differs')
    records = {}
    for record in expanded:
        key = identity_key(record['identity'])
        require(key not in records, 'expanded identity is duplicated before fixed-C metadata attachment')
        records[key] = record
    selected_records = [record for record in records.values()
                        if record['selection'].get('group') == FIXED_C_PRODUCER_GROUP]
    selected_names = set()
    for record in selected_records:
        key = identity_key(record['identity'])
        require(key[1:] == (None, False), 'fixed-C producer identity is unexpectedly versioned')
        selected_names.add(key[0])
        selection_record = record['selection']
        require(selection_record.get('disposition') == 'private-provider'
                and selection_record.get('owner') == FIXED_C_PRODUCER_OWNER,
                'fixed-C producer identity has another owner')
    require(selected_names == set(metadata), 'fixed-C producer selection scope differs from exact metadata roster')
    joins = []
    for name in sorted(selected_names):
        record = records[identity_key(identity(name))]
        placements = {item['artifact_key']: item for item in record['expected_placements']}
        require(set(placements) == set(FIXED_C_PRODUCER_ARTIFACTS)
                and len(placements) == len(record['expected_placements']),
                f'fixed-C producer placement scope differs: {name}')
        roles = exact(metadata[name], {'static', 'shared'}, f'fixed-C companion metadata {name}')
        for artifact_key, role in zip(FIXED_C_PRODUCER_ARTIFACTS, ('static', 'shared')):
            placements[artifact_key]['metadata'] = copy.deepcopy(roles[role])
            placements[artifact_key]['metadata_rule'] = 'explicit'
            joins.append({
                'identity': copy.deepcopy(record['identity']),
                'artifact_key': artifact_key,
                'metadata': copy.deepcopy(roles[role]),
                'owner_group': FIXED_C_PRODUCER_GROUP,
                'owner': FIXED_C_PRODUCER_OWNER,
            })
    require(len(joins) == selection['metadata_placement_count'], 'fixed-C producer placement count differs')
    return joins


def bind_fixed_c_producer_metadata_joins(accounting: Mapping[str, Any], pending: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Retain the physical joins after the generic placement reader observes them."""
    placement_joins = accounting['placement_joins']
    index = {}
    for row in placement_joins:
        key = (identity_key(row['identity']), row['artifact_key'])
        require(key not in index, 'duplicate placement join while binding fixed-C producer metadata')
        index[key] = row
    result = []
    for pending_row in pending:
        key = (identity_key(pending_row['identity']), pending_row['artifact_key'])
        joined = index.get(key)
        require(joined is not None and same(joined['expected_metadata'], pending_row['metadata']),
                'fixed-C producer metadata placement join is absent or differs')
        require(joined['placement_observed'] is True and _metadata_difference_rows_are_empty(
                    joined.get('metadata_differences'), 'fixed-C producer metadata placement'),
                'fixed-C producer metadata placement is not exact')
        result.append({
            **copy.deepcopy(pending_row),
            'occurrence_indices': list(joined['occurrence_indices']),
            'definition_count': joined['definition_count'],
            'placement_observed': joined['placement_observed'],
        })
    return result


def account_object_declarations(report: Mapping[str, Any], selected_objects: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Join replayed compiler observations without promoting raw type strings.

    Variable declarations, accessor macros and ABI-only storage are separate
    source obligations. Unknown unselected internals do not select new names.
    """
    names = {row['name'] for row in selected_objects}
    occurrences = [row for row in report['occurrences'] if row['tree'] == 'candidate' and row['name'] in names]
    events = [row for row in report['macro_events'] if row['tree'] == 'candidate' and row['name'] in names]
    active = [row for row in report['final_active_macros'] if row['tree'] == 'candidate' and row['name'] in names]
    requirements, unresolved = [], []
    for obj in selected_objects:
        variable_indices = [i for i, row in enumerate(occurrences) if row['name'] == obj['name'] and row['kind'] == 'variable']
        macro_indices = [i for i, row in enumerate(active) if row['name'] == obj['name']]
        remaining = []
        if obj['declaration_kind'] == 'installed-variable':
            if not variable_indices:
                remaining.append('selected installed variable declaration is absent')
            unresolved.extend(occurrences[i] for i in variable_indices if occurrences[i]['linkage_status'] == 'unresolved-from-json')
            remaining.append('selected declaration profile, linkage, type, qualifier and layout agreement remains unverified')
        elif obj['declaration_kind'] == 'accessor-macro':
            if not macro_indices:
                remaining.append('selected accessor macro is absent')
            remaining.append('selected accessor expansion, profiles and callable-to-storage semantics remain unverified')
        elif variable_indices:
            remaining.append('ABI-only storage has an unexpected installed variable observation requiring review')
        requirements.append({'identity': identity(obj['name']), 'kind': obj['declaration_kind'],
                             'variable_occurrence_indices': variable_indices, 'active_macro_indices': macro_indices,
                             'remaining': remaining})
    return {'selected_occurrences': occurrences, 'selected_macro_events': events, 'selected_active_macros': active,
            'requirements': requirements, 'unresolved_selected_occurrences': unresolved,
            'complete': not unresolved and not any(row['remaining'] for row in requirements)}


def _ordinary_declaration_plan_joins(
    replayed: Mapping[str, Any],
    callable_account: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Join validated object observations to the selected declaration account.

    The callable adapter owns raw AST type/linker-spelling pairs and their
    header-job provenance.  This finite join only confirms that every emitted
    object reference came from that same typed account; it does not infer a
    provider or turn a C++ spelling mismatch into a success.
    """
    expected_plans = declaration_abi.linkage_jobs_from_callable_account(callable_account)
    plans = replayed['callable_plan']
    require(same(plans, expected_plans), 'ordinary declaration object plan differs from selected callable account')
    report = replayed['report']
    require(type(report) is dict and type(report.get('jobs')) is list, 'ordinary declaration report jobs differ')
    jobs = report['jobs']
    require(len(jobs) == len(plans), 'ordinary declaration job count differs from validated plan')
    joins: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    for ordinal, (plan, job) in enumerate(zip(plans, jobs, strict=True)):
        require(type(plan) is dict and type(job) is dict and job.get('ordinal') == ordinal,
                f'ordinary declaration job {ordinal} identity differs')
        fields = {'tree', 'header', 'profile', 'language', 'names', 'references'}
        require(same({field: job.get(field) for field in fields}, plan),
                f'ordinary declaration job {ordinal} does not join the selected plan')
        observations = job.get('observations')
        references = plan['references']
        require(type(observations) is list and len(observations) == len(references),
                f'ordinary declaration job {ordinal} observation roster differs')
        mismatch_indices: list[int] = []
        for index, (reference, observation) in enumerate(zip(references, observations, strict=True)):
            reference = exact(reference, {'category', 'expected_observation', 'holder', 'name', 'source_definition_observations'},
                              f'ordinary declaration plan {ordinal}:{index}')
            require(type(observation) is dict and observation.get('category') == reference['category'],
                    f'ordinary declaration observation category differs: {ordinal}:{index}')
            expected = reference['expected_observation']
            if expected == 'ordinary-undefined-reference':
                status = observation.get('status')
                if status == 'ordinary-undefined-reference':
                    exact(observation, {'category', 'name', 'status', 'symbol'}, f'ordinary declaration observation {ordinal}:{index}')
                    require(observation['name'] == reference['name'] and observation['symbol'] == reference['name'],
                            f'ordinary declaration symbol identity differs: {ordinal}:{index}')
                elif status == 'ordinary-linkage-identity-mismatch':
                    exact(observation, {'category', 'expected_symbol', 'holder', 'observed_symbol', 'relocation_type', 'status'},
                          f'ordinary declaration mismatch {ordinal}:{index}')
                    require(observation['expected_symbol'] == reference['name']
                            and observation['holder'] == reference['holder']
                            and observation['relocation_type'] == 'R_X86_64_64'
                            and type(observation['observed_symbol']) is str
                            and observation['observed_symbol'] != reference['name'],
                            f'ordinary declaration linkage mismatch differs: {ordinal}:{index}')
                    mismatch_indices.append(index)
                    mismatches.append({
                        'ordinal': ordinal,
                        'tree': plan['tree'],
                        'header': plan['header'],
                        'profile': plan['profile'],
                        **copy.deepcopy(observation),
                    })
                else:
                    raise SelectionError(f'ordinary declaration observation status differs: {ordinal}:{index}')
            elif expected == 'header-defined-or-inline':
                exact(observation, {'category', 'name', 'source_definition_observation', 'status'},
                      f'ordinary declaration inline observation {ordinal}:{index}')
                require(observation['name'] == reference['name']
                        and observation['status'] == 'header-defined-or-inline'
                        and observation['source_definition_observation'] == 'function-body-present',
                        f'ordinary declaration inline observation differs: {ordinal}:{index}')
            else:
                raise SelectionError(f'ordinary declaration expected observation differs: {ordinal}:{index}')
        joins.append({
            'ordinal': ordinal,
            'tree': plan['tree'],
            'header': plan['header'],
            'profile': plan['profile'],
            'language': plan['language'],
            'names': copy.deepcopy(plan['names']),
            'observation_count': len(observations),
            'linkage_mismatch_indices': mismatch_indices,
        })
    return joins, mismatches


def _ordinary_declaration_layout_joins(
    projection: Mapping[str, Any],
    selected_objects: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Attach only the component's two named layout facts to object contracts."""
    component_contract = declaration_abi.load_contract()
    exact(dict(projection), {'schema', 'record_layout_report_schema', 'records', 'limits'},
          'ordinary declaration record-layout projection')
    require(projection['schema'] == declaration_abi.RECORD_LAYOUT_PROJECTION_SCHEMA
            and projection['record_layout_report_schema'] == declaration_abi.HEADER_RECORD_LAYOUT_REPORT_SCHEMA
            and same(projection['limits'], component_contract['limits']),
            'ordinary declaration record-layout projection identity differs')
    records = projection['records']
    require(type(records) is list and len(records) == len(component_contract['record_layout']),
            'ordinary declaration record-layout roster differs')
    objects = {row['name']: row for row in selected_objects}
    require(len(objects) == len(selected_objects), 'selected object contracts repeat before layout attachment')
    joins: list[dict[str, Any]] = []
    for ordinal, (raw, fact) in enumerate(zip(records, component_contract['record_layout'], strict=True)):
        raw = exact(raw, {'header', 'object_names', 'profiles', 'record'}, f'ordinary declaration layout record {ordinal}')
        require(raw['header'] == fact['header'] and raw['record'] == fact['record']
                and raw['object_names'] == fact['object_names'] and type(raw['profiles']) is list
                and [row.get('profile') for row in raw['profiles']] == fact['profiles'],
                f'ordinary declaration layout record {ordinal} differs from its reviewed scope')
        for name in raw['object_names']:
            object_contract = objects.get(name)
            require(object_contract is not None
                    and object_contract.get('id') == 'object:' + name
                    and object_contract.get('declaration_kind') == 'installed-variable'
                    and object_contract.get('type') == 'OBJECT'
                    and 'include/' + raw['header'] in object_contract.get('sources', []),
                    f'ordinary declaration layout object scope differs: {name}')
            remaining = []
            if name == '_ns_flagdata':
                remaining.append(projection['limits']['_ns_flagdata_array_extent'])
            joins.append({
                'id': object_contract['id'],
                'identity': identity(name),
                'header': raw['header'],
                'record': raw['record'],
                'profile_count': len(raw['profiles']),
                'remaining_layout_limitations': remaining,
            })
    return joins


def ordinary_declaration_abi_adapter(
    report_path: Path | None,
    *,
    header_report: Path,
    header_envelope: Mapping[str, Any],
    callable_account: Mapping[str, Any],
    selected_objects: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Attach ordinary declaration objects to one authenticated header replay.

    This is intentionally a narrow companion.  It validates the component's
    retained object report and joins it to the same typed callable account that
    came from the one public header replay.  It never replays that 616MB header
    report, chooses an ELF provider, or claims runtime/family closure.
    """
    if report_path is None:
        return None
    require(Path(declaration_abi.ROOT) == ROOT, 'ordinary declaration reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    header_report = physical_work_path(header_report, directory=False)
    before = {'ordinary_declaration_report': file_identity(report_path), 'header_report': file_identity(header_report)}
    try:
        replayed = declaration_abi.validate_report(
            report_path,
            header_report=header_report,
            header_envelope=header_envelope,
        )
    except (ValueError, OSError) as error:
        raise SelectionError(f'ordinary declaration ABI companion rejected: {error}') from error
    after = {'ordinary_declaration_report': file_identity(report_path), 'header_report': file_identity(header_report)}
    require(same(before, after), 'ordinary declaration ABI input changed during companion replay')
    exact(replayed, {'callable_plan', 'execution', 'header_declaration_report', 'record_layout_projection', 'report', 'summary'},
          'ordinary declaration ABI reader envelope')
    execution = exact(replayed['execution'], {'collector_output', 'collector_source', 'image_id', 'native_context', 'source_mount', 'timeout_seconds', 'workers'},
                      'ordinary declaration ABI execution')
    require(same(execution['collector_source'], selection_source()),
            'ordinary declaration ABI collector source differs from the selecting source')
    report = replayed['report']
    require(type(report) is dict and report.get('schema') == declaration_abi.SCHEMA
            and report.get('target') == TARGET and report.get('oracle') == declaration_abi.ORACLE,
            'ordinary declaration ABI report identity differs')
    status = exact(report.get('status'), {
        'callable_declaration_abi_complete', 'family_completion', 'object_linkage_observed', 'promotion_ready',
        'public_support', 'record_layout_projection_observed', 'runtime_semantics',
    }, 'ordinary declaration ABI status')
    require(status == {
        'callable_declaration_abi_complete': False,
        'family_completion': False,
        'object_linkage_observed': True,
        'promotion_ready': False,
        'public_support': False,
        'record_layout_projection_observed': True,
        'runtime_semantics': False,
    }, 'ordinary declaration ABI status exceeds component scope')
    joins, mismatches = _ordinary_declaration_plan_joins(replayed, callable_account)
    summary = exact(replayed['summary'], {
        'cxx_job_count', 'job_count', 'language_counts', 'observation_count', 'observation_status_counts',
        'reference_category_counts', 'reference_count',
    }, 'ordinary declaration ABI summary')
    counts = summary['observation_status_counts']
    require(type(counts) is dict and counts.get('ordinary-linkage-identity-mismatch', 0) == len(mismatches),
            'ordinary declaration ABI mismatch summary differs')
    layouts = _ordinary_declaration_layout_joins(replayed['record_layout_projection'], selected_objects)
    callable_plan_source = report.get('callable_plan_source')
    require(type(callable_plan_source) is dict, 'ordinary declaration ABI callable plan source differs')
    return {
        'status': 'ordinary-object-and-record-layout-observed-with-boundaries',
        'reader': file_identity(Path(declaration_abi.__file__)),
        'contract': file_identity(declaration_abi.CONTRACT_PATH),
        'report': before['ordinary_declaration_report'],
        'header_report': before['header_report'],
        'header_collector_identity': copy.deepcopy(replayed['header_declaration_report']),
        'execution': copy.deepcopy(execution),
        'callable_plan_source': copy.deepcopy(callable_plan_source),
        'status_flags': copy.deepcopy(status),
        'summary': copy.deepcopy(summary),
        'callable_joins': joins,
        'linkage_mismatches': mismatches,
        'record_layout_joins': layouts,
        'limits': list(DECLARATION_ABI_LIMITS),
    }


def declaration_adapter(report_path: Path | None, *, selected_objects: Sequence[Mapping[str, Any]],
                        provider_names: Sequence[str], deferred: Mapping[str, Any],
                        abi_only_callables: Sequence[Mapping[str, Any]],
                        callable_matrix_projection: Mapping[str, Any],
                        ordinary_declaration_abi_report: Path | None = None) -> dict[str, Any] | None:
    if report_path is None:
        require(ordinary_declaration_abi_report is None,
                'ordinary declaration ABI report requires the public declaration report')
        return None
    module_path = Path(declaration_inventory.__file__)
    report_path = physical_work_path(report_path, directory=False)
    # The public header reader returns a parsed envelope.  Bind the physical
    # report before invoking it, then prove the same bytes remain present
    # through every downstream attachment that reuses that envelope.  Without
    # this interval, a replacement after the reader returns could inherit the
    # old authenticated data while the selection record named new bytes.
    report_before = file_identity(report_path)
    try:
        envelope = declaration_inventory.validate_report(report_path, project_include=ROOT / 'include')
    except (ValueError, OSError) as error:
        raise SelectionError(f'declaration companion rejected: {error}') from error
    require(same(report_before, file_identity(report_path)),
            'public declaration report changed during replay')
    exact(envelope, {'report', 'current_selecting_source'}, 'declaration reader envelope')
    source = exact(envelope['current_selecting_source'], {'matches_retained', 'differences'}, 'declaration source comparison')
    require(type(source['matches_retained']) is bool and type(source['differences']) is list, 'declaration source comparison types differ')
    if ordinary_declaration_abi_report is not None:
        require(source['matches_retained'] is True and not source['differences'],
                'ordinary declaration ABI report requires a current public declaration envelope')
    report = envelope['report']
    account = account_object_declarations(report, selected_objects)
    # Reuse this one public replay for the finite data contract. Its type and
    # profile checks do not establish callable declarations, record layout or
    # accessor-to-storage behavior for the complete selected ABI.
    import native_data_declarations as data_declarations
    try:
        typed_data = data_declarations.account_declarations(envelope, selected_objects)
    except (ValueError, OSError) as error:
        raise SelectionError(f'selected data declarations rejected: {error}') from error
    for requirement in account['requirements']:
        if requirement['kind'] == 'installed-variable':
            requirement['remaining'] = ['selected object layout and runtime semantics remain unverified']
        elif requirement['kind'] == 'accessor-macro':
            requirement['remaining'] = ['selected accessor callable linkage and runtime-to-storage semantics remain unverified']
    account['complete'] = False
    account['selected_data_declarations'] = {
        'adapter': file_identity(Path(data_declarations.__file__)),
        'contract': file_identity(data_declarations.CONTRACT_PATH),
        'account': typed_data,
    }
    try:
        typed_callables = callable_declarations.account_declarations(
            envelope,
            provider_names=provider_names,
            deferred=deferred,
            abi_only_callables=abi_only_callables,
            matrix_projection=callable_matrix_projection,
        )
    except (ValueError, OSError) as error:
        raise SelectionError(f'selected callable declarations rejected: {error}') from error
    account['selected_callable_declarations'] = {
        'adapter': file_identity(Path(callable_declarations.__file__)),
        'contract': file_identity(callable_declarations.CONTRACT_PATH),
        'account': typed_callables,
    }
    account['ordinary_declaration_abi'] = ordinary_declaration_abi_adapter(
        ordinary_declaration_abi_report,
        header_report=report_path,
        header_envelope=envelope,
        callable_account=typed_callables,
        selected_objects=selected_objects,
    )
    account['complete'] = False
    require(same(report_before, file_identity(report_path)),
            'public declaration report changed during companion attachment')
    return {'report': report_before, 'reader': file_identity(module_path),
            'current_selecting_source': source, 'physical_status': report['status'], **account}


def public_data_linkage_adapter(ordinary_report_path: Path | None, loader_report_path: Path | None, *,
                                contract: Mapping[str, Any], selected_objects: Sequence[Mapping[str, Any]], source: Mapping[str, Any],
                                paths: Mapping[str, Path]) -> dict[str, Any] | None:
    """Replay the two fixed public-data linkage receipts, if both are supplied.

    This is deliberately a finite attachment for the selected data objects. It
    does not turn receipt presence into the repository-wide semantic-receipt
    gate, and it does not claim each object's lifecycle semantics.
    """
    if ordinary_report_path is None and loader_report_path is None:
        return None
    require(ordinary_report_path is not None and loader_report_path is not None,
            'public-data ordinary-link and loader-debug reports must be supplied together')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    require(source['clean'] is True and type(source['revision']) is str and type(source['content_sha256']) is str,
            'public-data linkage requires a clean selected source')
    require(Path(ordinary_link_evidence.ROOT) == ROOT and Path(loader_debug_evidence.ROOT) == ROOT,
            'public-data linkage readers belong to a different checkout')
    ordinary_report_path = physical_work_path(ordinary_report_path, directory=False)
    loader_report_path = physical_work_path(loader_report_path, directory=False)
    require(ordinary_report_path.is_relative_to(ROOT / '.work') and loader_report_path.is_relative_to(ROOT / '.work'),
            'public-data linkage reports must belong to the selecting checkout')
    ordinary_before = file_identity(ordinary_report_path)
    loader_before = file_identity(loader_report_path)
    try:
        ordinary_replay = ordinary_link_evidence.validate_report(ROOT, ordinary_report_path)
        loader_replay = loader_debug_evidence.validate_report(loader_report_path)
    except (ValueError, OSError) as error:
        raise SelectionError(f'public-data linkage companion rejected: {error}') from error
    require(file_identity(ordinary_report_path) == ordinary_before and file_identity(loader_report_path) == loader_before,
            'public-data linkage report changed during reader replay')
    require(type(ordinary_replay) is dict and set(ordinary_replay) == {'report', 'links'},
            'ordinary-link reader envelope differs')
    require(type(loader_replay) is dict, 'loader-debug reader envelope differs')
    ordinary_reader_report = exact(ordinary_replay['report'], {'path', 'sha256', 'size'},
                                   'ordinary-link reader report identity')
    ordinary_expected_report = {
        'path': ordinary_report_path.relative_to(ROOT).as_posix(),
        'sha256': ordinary_before['sha256'],
        'size': ordinary_before['size'],
    }
    require(ordinary_reader_report == ordinary_expected_report,
            'ordinary-link reader report identity differs')

    ordinary_report = read_json(ordinary_report_path)
    expected_inputs = ordinary_link_evidence.admit_inputs(
        ROOT, paths['static_preparation'], paths['static_product'], paths['dynamic_product'],
    )
    require(ordinary_report.get('source_before') == expected_inputs
            and ordinary_report.get('source_after') == expected_inputs,
            'ordinary-link receipt does not use the selected static/dynamic products')
    ordinary_source = exact(expected_inputs['source'], {'revision', 'content_sha256'},
                            'ordinary-link receipt source')
    require(ordinary_source == {key: source[key] for key in ('revision', 'content_sha256')},
            'ordinary-link receipt source differs from selection')
    ordinary_dynamic = exact(expected_inputs['dynamic_product'],
                             {'path', 'manifest', 'state', 'manifest_sha256'},
                             'ordinary-link dynamic product')
    selected_dynamic = {
        'candidate-libc': paths['dynamic_product'] / 'usr/lib/libc.so',
        'candidate-loader': paths['dynamic_product'] / 'lib/ld-crabc-x86_64.so.1',
        'dynamic-manifest': paths['dynamic_product'] / 'share/crabc/manifest.json',
        'dynamic-state': paths['dynamic_product'] / 'share/crabc/dynamic-product-state.json',
    }
    selected_dynamic_records = {name: file_identity(path) for name, path in selected_dynamic.items()}
    for name, ordinary_key in (('dynamic-manifest', 'manifest'), ('dynamic-state', 'state')):
        ordinary_record = exact(ordinary_dynamic[ordinary_key], {'path', 'sha256', 'size'},
                                f'ordinary-link {ordinary_key} identity')
        selected_record = selected_dynamic_records[name]
        require(ordinary_record == {
            'path': selected_dynamic[name].relative_to(ROOT).as_posix(),
            'sha256': selected_record['sha256'], 'size': selected_record['size'],
        }, f'ordinary-link {ordinary_key} differs from selected dynamic product')

    loader_artifacts = loader_replay.get('artifacts')
    require(type(loader_artifacts) is dict, 'loader-debug receipt artifact roster differs')
    loader_product_bindings = []
    for name, selected_record in selected_dynamic_records.items():
        loader_record = exact(loader_artifacts.get(name), {'path', 'sha256', 'size'},
                              f'loader {name} identity')
        require(type(loader_record['path']) is str and loader_record['path']
                and not Path(loader_record['path']).is_absolute() and '..' not in Path(loader_record['path']).parts
                and type(loader_record['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', loader_record['sha256']) is not None
                and type(loader_record['size']) is int and loader_record['size'] >= 0,
                f'loader {name} identity values differ')
        require(loader_record['sha256'] == selected_record['sha256'] and loader_record['size'] == selected_record['size'],
                f'loader {name} bytes differ from selected dynamic product')
        loader_product_bindings.append({
            'name': name,
            'loader_receipt': copy.deepcopy(loader_record),
            'selected_dynamic_product': selected_record,
        })

    common = [dict(row) for row in selected_objects
              if set(row.get('artifacts', ())) == {'candidate-static', 'candidate-shared'}]
    loader_objects = [dict(row) for row in selected_objects if row.get('name') == '_dl_debug_addr']
    try:
        ordinary_objects, aliases = ordinary_link_evidence.selected_objects(contract)
    except (ValueError, OSError) as error:
        raise SelectionError(f'public-data linkage selected-object contract rejected: {error}') from error
    require(common == ordinary_objects, 'ordinary-link object roster differs from selected object contracts')
    expected_aliases = [
        {'name': row['name'], 'target': row['alias_target']}
        for row in common if row['alias_target']
    ]
    require(aliases == expected_aliases, 'ordinary-link alias roster differs from selected object contracts')
    require(len(loader_objects) == 1 and loader_objects[0]['id'] == 'object:_dl_debug_addr'
            and loader_objects[0]['artifacts'] == ['candidate-shared'] and not loader_objects[0]['alias_target'],
            'loader debugger pointer selection differs')
    loader_object = loader_objects[0]
    require({key: loader_object[key] for key in ('type', 'binding', 'visibility', 'size_bytes', 'alignment_bytes')}
            == {'type': 'OBJECT', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'size_bytes': 8, 'alignment_bytes': 8},
            'loader debugger pointer contract differs')
    require(loader_replay.get('source_commit') == source['revision']
            and loader_replay.get('source_sha256') == source['content_sha256'],
            'loader-debug receipt source differs from selection')
    metadata = loader_replay.get('public_metadata', {}).get('_dl_debug_addr')
    require(type(metadata) is dict
            and metadata.get('type') == 'OBJECT' and metadata.get('binding') == 'GLOBAL'
            and metadata.get('visibility') == 'DEFAULT' and type(metadata.get('size')) is int
            and metadata['size'] == 8,
            'loader-debug receipt pointer metadata differs')
    require(file_identity(ordinary_report_path) == ordinary_before and file_identity(loader_report_path) == loader_before,
            'public-data linkage report changed during companion replay')
    return {
        'status': 'linkage-addressability-proved-with-boundaries',
        'selection_source': copy.deepcopy(source),
        'ordinary_link': {
            'reader': file_identity(Path(ordinary_link_evidence.__file__)),
            'report': ordinary_before,
            'source_and_products': expected_inputs,
            'objects': [{'id': row['id'], 'identity': identity(row['name']), 'artifacts': row['artifacts']} for row in common],
            'aliases': [{'identity': identity(row['name']), 'target': identity(row['target'])} for row in aliases],
        },
        'loader_debug_addr': {
            'reader': file_identity(Path(loader_debug_evidence.__file__)),
            'report': loader_before,
            'id': loader_object['id'], 'identity': identity(loader_object['name']),
            'artifacts': copy.deepcopy(loader_object['artifacts']),
            'metadata': {'type': metadata['type'], 'binding': metadata['binding'],
                         'visibility': metadata['visibility'], 'size_bytes': metadata['size']},
            'product_bindings': loader_product_bindings,
        },
        'limits': list(PUBLIC_DATA_LINKAGE_LIMITS),
    }


def attach_public_data_linkage(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Attach ordinary-addressability evidence to the exact imported objects.

    The ordinary-link receipt covers the supplied static product, not every
    future candidate artifact that may happen to import a selected spelling.
    An uncovered feature/private import therefore keeps the original generic
    import reason instead of being cleared by an object-name match.
    """
    if companion is None:
        return []
    require(type(companion) is dict and type(companion.get('ordinary_link')) is dict,
            'public-data linkage companion differs')
    raw_objects = companion['ordinary_link'].get('objects')
    require(type(raw_objects) is list, 'public-data linkage object roster differs')
    objects: dict[str, Mapping[str, Any]] = {}
    for raw in raw_objects:
        require(type(raw) is dict and set(raw) == {'id', 'identity', 'artifacts'},
                'public-data linkage object fields differ')
        name = identity_key(raw['identity'])[0]
        require(type(raw['id']) is str and raw['id'] == 'object:' + name
                and raw['artifacts'] == ['candidate-static', 'candidate-shared'],
                'public-data linkage object placement differs')
        require(name not in objects, 'public-data linkage object is duplicated')
        objects[name] = raw
    candidate_artifacts = {artifact.key for artifact in elf_facts.ARTIFACTS if artifact.owner != 'reference'}
    joins: list[dict[str, Any]] = []
    discharged: set[tuple[str, str | None, bool]] = set()
    for record in accounting['identities']:
        if ORDINARY_IMPORT_REASON not in record['unresolved']:
            continue
        name, version, default = identity_key(record['identity'])
        object_record = objects.get(name)
        if object_record is None:
            continue
        require(version is None and default is False and record['selection'].get('owner') == object_record['id'],
                'public-data linkage identity ownership differs')
        imports = [occurrence for occurrence in accounting['occurrences']
                   if occurrence['role'] == 'import' and occurrence['row']['name'] == name
                   and occurrence['artifact_key'] in candidate_artifacts]
        covered = bool(imports) and all(
            occurrence['artifact_key'] == 'candidate-static'
            and occurrence['accounting'] == {
                'disposition': 'public-provider', 'owner': object_record['id'], 'scope': 'candidate-static',
            }
            for occurrence in imports
        )
        joins.append({
            'identity': copy.deepcopy(record['identity']),
            'owner': object_record['id'],
            'artifact_keys': sorted({occurrence['artifact_key'] for occurrence in imports}),
            'occurrence_indices': [occurrence['index'] for occurrence in imports],
            'ordinary_link_covered': covered,
            'discharged_reason': ORDINARY_IMPORT_REASON if covered else None,
        })
        if covered:
            record['unresolved'].remove(ORDINARY_IMPORT_REASON)
            discharged.add((name, version, default))
    if discharged:
        accounting['blockers'][:] = [
            blocker for blocker in accounting['blockers']
            if not (blocker['code'] == 'identity-unresolved'
                    and identity_key(blocker['identity']) in discharged
                    and blocker['reason'] == ORDINARY_IMPORT_REASON)
        ]
    return joins


def compiler_helper_adapter(report_path: Path | None, *, ordinary_report_path: Path | None,
                            paths: Mapping[str, Path]) -> dict[str, Any] | None:
    """Attach the owning helper reader's aggregate-to-installed archive proof.

    The component validates its own supplied products and optional ordinary
    link maps. Its result keeps shared helper visibility and runtime/family
    completion separate from the two installed archive roles.
    """
    if report_path is None:
        return None
    require(paths['measurement_checkout'] == ROOT and Path(compiler_helpers.ROOT) == ROOT,
            'compiler-helper evidence requires the selecting checkout product cohort')
    report_path = physical_work_path(report_path, directory=False)
    require(report_path.is_relative_to(ROOT / '.work'), 'compiler-helper aggregate must belong to the selecting checkout')
    before = file_identity(report_path)
    try:
        account = compiler_helpers.validate_supplied_product_evidence(
            root=ROOT, **{key: paths[key] for key in
                         ('base_inventory', 'elf_report', 'static_preparation', 'static_product', 'dynamic_product')},
            ordinary_link_report=ordinary_report_path, aggregate_report=report_path,
        )
    except (ValueError, OSError) as error:
        raise SelectionError(f'compiler-helper component rejected: {error}') from error
    require(file_identity(report_path) == before, 'compiler-helper aggregate report changed during replay')
    require(type(account) is dict and type(account.get('aggregate_c_abi')) is dict
            and account['aggregate_c_abi'].get('status') == 'joined', 'compiler-helper aggregate is not joined to both archives')
    require(all(account.get(key) is False for key in ('shared_placement_selected', 'family_completion', 'public_support')),
            'compiler-helper component exceeds archive evidence scope')
    return {'report': before, 'reader': file_identity(Path(compiler_helpers.__file__)), 'account': account}


def _identity_payload(record: object, description: str) -> dict[str, Any]:
    """Return a physical-file identity without treating its logical path as portable.

    Component receipts commonly retain their own `/workspace` or copied-input
    paths.  The selector's product cohort has distinct host paths.  The path
    remains in each receipt for that reader to validate, while this join binds
    the immutable bytes, mode, and size to the already selected product.
    """
    row = exact(record, {'path', 'sha256', 'size', 'mode'}, description)
    require(type(row['path']) is str and row['path']
            and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
            and type(row['size']) is int and row['size'] >= 0
            and type(row['mode']) is int and not isinstance(row['mode'], bool) and row['mode'] >= 0,
            f'{description} identity values differ')
    return {key: row[key] for key in ('sha256', 'size', 'mode')}


def _require_same_identity_payload(left: object, right: object, description: str) -> None:
    require(same(_identity_payload(left, description + ' left'), _identity_payload(right, description + ' right')),
            f'{description} bytes or mode differ')


def _current_product_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Name the finite selected-product files shared by runtime attachments."""
    records = {
        'static_manifest': paths['static_product'] / 'share/crabc/manifest.json',
        'static_driver': paths['static_product'] / 'bin/crabc-cc',
        'static_libc': paths['static_product'] / 'usr/lib/libc.a',
        'dynamic_manifest': paths['dynamic_product'] / 'share/crabc/manifest.json',
        'dynamic_state': paths['dynamic_product'] / inventory.DYNAMIC_STATE_RELATIVE,
        'dynamic_driver': paths['dynamic_product'] / 'bin/crabc-cc-dynamic',
        'dynamic_libc': paths['dynamic_product'] / 'usr/lib/libc.so',
        'dynamic_loader': paths['dynamic_product'] / 'lib/ld-crabc-x86_64.so.1',
    }
    return {name: file_identity(path) for name, path in records.items()}


def _runtime_attachment_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Return the finite file roster that runtime companions may authenticate.

    Most existing companions bind the complete installed-product identity
    roster.  The errno receipt additionally owns the shared-libc provenance
    file, while the prepared-worker receipt intentionally has no claim over
    either installed driver.  Keeping this wider roster separate prevents a
    narrow component from accidentally inheriting unrelated product authority.
    """
    current = _current_product_identities(paths)
    current['dynamic_shared_provenance'] = file_identity(
        paths['dynamic_product'] / 'share/crabc/libc-shared.provenance.json'
    )
    return current


def _c_allocator_boundary_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Return only the installed files owned by the C allocator receipt.

    The C boundary consumes the static provenance record as well as the
    installed archive and final DSO.  It does not acquire driver or loader
    authority merely because other runtime companions use those files.
    """
    current = _runtime_attachment_identities(paths)
    current['static_provenance'] = file_identity(
        paths['static_product'] / 'share/crabc/libc-static.provenance.json'
    )
    return current


def _errno_identity_payload(value: object, description: str) -> dict[str, Any]:
    """Normalize the errno reader's path/hash/size identity for a byte join.

    Its public schema deliberately does not assign a product-file mode.  The
    selector separately seals current product modes before and after every
    attachment, so this conversion never invents a mode assertion for the
    owning reader.
    """
    row = exact(value, {'path', 'sha256', 'size_bytes'}, description)
    require(type(row['path']) is str and row['path']
            and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
            and type(row['size_bytes']) is int and not isinstance(row['size_bytes'], bool) and row['size_bytes'] >= 0,
            f'{description} identity values differ')
    return {'sha256': row['sha256'], 'size': row['size_bytes']}


def _require_same_errno_identity(value: object, current: object, description: str) -> None:
    observed = _errno_identity_payload(value, description + ' receipt')
    selected = _identity_payload(current, description + ' selected')
    require(observed == {key: selected[key] for key in ('sha256', 'size')},
            f'{description} bytes differ')


def _measurement_source_matches(source: Mapping[str, Any], measurement: Mapping[str, Any], description: str) -> None:
    candidate = measurement.get('candidate_build')
    require(type(candidate) is dict
            and type(candidate.get('revision')) is str and type(candidate.get('source_content_sha256')) is str,
            f'{description} public ELF candidate-build binding differs')
    require(source.get('clean') is True
            and source.get('revision') == candidate['revision']
            and source.get('content_sha256') == candidate['source_content_sha256'],
            f'{description} source differs from the selected product cohort')


def _measurement_report_bindings(measurement: Mapping[str, Any], description: str) -> dict[str, dict[str, Any]]:
    reports = exact(measurement.get('reports'), {'elf_report', 'base_inventory', 'static_preparation'},
                    f'{description} public ELF replay report identities')
    for name, row in reports.items():
        _identity_payload(row, f'{description} public ELF replay {name}')
    return copy.deepcopy(reports)


def _recheck_runtime_receipt_cohort(*, paths: Mapping[str, Path], facts: Mapping[str, Any],
                                    measurement: Mapping[str, Any], source: Mapping[str, Any],
                                    registry: Mapping[str, Any] | None,
                                    pthread: Mapping[str, Any] | None,
                                    prepared_worker: Mapping[str, Any] | None = None,
                                    errno_storage: Mapping[str, Any] | None = None,
                                    c_allocator_boundary: Mapping[str, Any] | None = None,
                                    stdio_alias_contract: Mapping[str, Any] | None = None,
                                    crt_startup: Mapping[str, Any] | None = None,
                                    syscall_alias: Mapping[str, Any] | None = None,
                                    utmpx: Mapping[str, Any] | None = None) -> None:
    """Keep runtime attachments within the same source/product transaction.

    Both owning readers validate their receipts before the selector's placement
    joins.  Recheck the exact supplied files after those joins so a mutable
    product or raw report cannot change in the interval before `report.json`
    is sealed.
    """
    if (registry is None and pthread is None and prepared_worker is None
            and errno_storage is None and c_allocator_boundary is None
            and stdio_alias_contract is None and crt_startup is None and syscall_alias is None and utmpx is None):
        return
    require(same(source, selection_source()), 'selection source changed during runtime receipt attachment')
    reports = _measurement_report_bindings(measurement, 'runtime receipt')
    for name, path_key in (
        ('elf_report', 'elf_report'), ('base_inventory', 'base_inventory'), ('static_preparation', 'static_preparation'),
    ):
        require(same(reports[name], file_identity(paths[path_key])),
                f'public ELF replay {name} changed during runtime receipt attachment')
    base_products = _current_product_identities(paths)
    current = {
        **base_products,
        'dynamic_shared_provenance': file_identity(
            paths['dynamic_product'] / 'share/crabc/libc-shared.provenance.json'
        ),
    }
    facts_artifacts = facts.get('artifacts')
    require(type(facts_artifacts) is dict, 'public ELF facts artifact roster changed during runtime receipt attachment')
    for current_name, artifact_key in (
        ('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared'), ('dynamic_loader', 'candidate-loader'),
    ):
        artifact = facts_artifacts.get(artifact_key)
        require(type(artifact) is dict and 'identity' in artifact,
                f'public ELF facts omit {artifact_key} during runtime receipt attachment')
        _require_same_identity_payload(artifact['identity'], current[current_name],
                                       f'public ELF {artifact_key} during runtime receipt attachment')
    companion_rosters: list[tuple[str, Mapping[str, Any] | None, Mapping[str, Mapping[str, Any]], bool]] = [
        ('runtime registry', registry, base_products, True),
        ('pthread alias', pthread, base_products, True),
        ('prepared worker TLS', prepared_worker, {
            name: current[name] for name in (
                'static_manifest', 'static_libc', 'dynamic_manifest', 'dynamic_state', 'dynamic_libc', 'dynamic_loader',
            )
        }, True),
        ('errno storage lifecycle', errno_storage, {
            name: current[name] for name in (
                'static_manifest', 'static_libc', 'dynamic_manifest', 'dynamic_libc', 'dynamic_shared_provenance',
            )
        }, True),
    ]
    if c_allocator_boundary is not None or stdio_alias_contract is not None:
        current['static_provenance'] = file_identity(
            paths['static_product'] / 'share/crabc/libc-static.provenance.json'
        )
    if c_allocator_boundary is not None:
        companion_rosters.append(('native C allocator boundary', c_allocator_boundary, {
            name: current[name] for name in (
                'static_manifest', 'static_libc', 'static_provenance', 'dynamic_manifest',
                'dynamic_state', 'dynamic_libc', 'dynamic_shared_provenance',
            )
        }, True))
    if stdio_alias_contract is not None:
        companion_rosters.append(('FILE alias', stdio_alias_contract, {
            name: current[name] for name in (
                'static_manifest', 'static_driver', 'static_libc', 'static_provenance',
                'dynamic_manifest', 'dynamic_state', 'dynamic_driver', 'dynamic_libc',
                'dynamic_loader', 'dynamic_shared_provenance',
            )
        }, True))
    if crt_startup is not None:
        startup_products = _crt_startup_product_identities(paths)
        for artifact_key, identity_value in startup_products.items():
            artifact = facts_artifacts.get(artifact_key)
            require(type(artifact) is dict and 'identity' in artifact,
                f'public ELF facts omit CRT startup {artifact_key} during attachment')
            _require_same_identity_payload(artifact['identity'], identity_value,
                                           f'public ELF CRT startup {artifact_key} during attachment')
        companion_rosters.append(('CRT startup', crt_startup, startup_products, True))
    for label, companion, expected_products, needs_measurement_reports in companion_rosters:
        if companion is None:
            continue
        records = companion.get('products')
        require(type(records) is dict and set(records) == set(expected_products),
                f'{label} product roster differs during attachment')
        for name in expected_products:
            _require_same_identity_payload(records[name], expected_products[name],
                                           f'{label} {name} changed during attachment')
        if needs_measurement_reports:
            require(same(companion.get('measurement_reports'), reports),
                    f'{label} public replay binding changed during attachment')
        report = companion.get('report')
        require(type(report) is dict and type(report.get('path')) is str,
                f'{label} report identity differs during attachment')
        report_path = Path(report['path'])
        require(report_path.is_file() and report_path.resolve() == report_path,
                f'{label} report disappeared during attachment')
        require(same(report, file_identity(report_path)),
                f'{label} report changed during attachment')
    if crt_startup is not None:
        cohort_inputs = _crt_startup_cohort_inputs(paths)
        retained_inputs = crt_startup.get('cohort_inputs')
        require(type(retained_inputs) is dict and set(retained_inputs) == set(cohort_inputs),
                'CRT startup metadata cohort differs during attachment')
        for name in cohort_inputs:
            _require_same_identity_payload(retained_inputs[name], cohort_inputs[name],
                                           f'CRT startup {name} changed during attachment')
    if syscall_alias is not None:
        expected_products = _syscall_alias_product_identities(paths)
        records = syscall_alias.get('products')
        require(type(records) is dict and set(records) == set(expected_products),
                'syscall alias product roster differs during attachment')
        for name in expected_products:
            _require_same_identity_payload(records[name], expected_products[name],
                                           f'syscall alias {name} changed during attachment')
        require(same(syscall_alias.get('measurement_reports'), reports),
                'syscall alias public replay binding changed during attachment')
        report = syscall_alias.get('report')
        require(type(report) is dict and type(report.get('path')) is str,
                'syscall alias report identity differs during attachment')
        report_path = Path(report['path'])
        require(report_path.is_file() and report_path.resolve() == report_path
                and same(report, file_identity(report_path)),
                'syscall alias report changed during attachment')
    if utmpx is not None:
        expected_products = _utmpx_product_identities(paths)
        records = utmpx.get('products')
        require(type(records) is dict and set(records) == set(expected_products),
                'utmpx product roster differs during attachment')
        for name in expected_products:
            _require_same_identity_payload(records[name], expected_products[name],
                                           f'utmpx {name} changed during attachment')
        require(same(utmpx.get('measurement_reports'), reports),
                'utmpx public replay binding changed during attachment')
        report = utmpx.get('report')
        require(type(report) is dict and type(report.get('path')) is str,
                'utmpx report identity differs during attachment')
        report_path = Path(report['path'])
        require(report_path.is_file() and report_path.resolve() == report_path
                and same(report, file_identity(report_path)),
                'utmpx report changed during attachment')


def loader_runtime_registry_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                                    measurement: Mapping[str, Any], paths: Mapping[str, Path],
                                    source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay the finite loader registry receipt against this selected cohort.

    The owning reader keeps its standalone public reconstruction: it replays
    the retained runtime commands and supplied-product admission.  This
    selector attachment then cross-binds its exact input identities to the
    public ELF product cohort before it can discharge only the matching
    private-operation requirements below.
    """
    if report_path is None:
        return None
    require(Path(runtime_registry_evidence.ROOT) == ROOT,
            'runtime registry reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = runtime_registry_evidence.validate_report(
            report_path,
            **{key: paths[key] for key in
               ('base_inventory', 'elf_report', 'static_preparation', 'static_product', 'dynamic_product')},
        )
    except (KeyError, TypeError, ValueError, OSError, runtime_registry_evidence.RuntimeRegistryEvidenceError) as error:
        raise SelectionError(f'loader runtime registry component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'runtime registry report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'runtime registry')
    measurement_reports = _measurement_report_bindings(measurement, 'runtime registry')
    report = exact(report, {'schema', 'target', 'status', 'source', 'source_files', 'inputs', 'replay_inputs',
                            'dlfcn', 'fork', 'timer_reset'},
                   'runtime registry reader report')
    require(report['schema'] == runtime_registry_evidence.SCHEMA and report['target'] == runtime_registry_evidence.TARGET,
            'runtime registry reader report identity differs')
    require(same(report['source'], source), 'runtime registry report source differs from selection')
    inputs = exact(report['inputs'], {
        'contract', 'source', 'source_resolution', 'source_files', 'elf_report', 'imports', 'loader', 'products',
    }, 'runtime registry supplied-product account')
    require(same(inputs['source'], source), 'runtime registry supplied-product source differs from selection')
    # The owning v2 reader preserves the executed /workspace spelling. Bind
    # that exact mount projection while independently sealing the host replay
    # input; never rewrite the retained report or discard its path or mode.
    require(same(measurement_reports['elf_report'], file_identity(paths['elf_report']))
            and same(inputs['elf_report'], runtime_registry_evidence.checkout_identity(ROOT, paths['elf_report'])),
            'runtime registry ELF report differs from public replay input')
    current = _current_product_identities(paths)
    products = exact(inputs['products'], {'static', 'dynamic_libc', 'dynamic_loader'},
                     'runtime registry product identity roster')
    _require_same_identity_payload(products['static'], current['static_libc'], 'runtime registry static libc')
    _require_same_identity_payload(products['dynamic_libc'], current['dynamic_libc'], 'runtime registry dynamic libc')
    _require_same_identity_payload(products['dynamic_loader'], current['dynamic_loader'], 'runtime registry dynamic loader')
    loader = exact(inputs['loader'], {'loader', 'feature', 'provenance'}, 'runtime registry loader account')
    require(loader['feature'] == runtime_registry_evidence.FEATURE,
            'runtime registry loader feature differs')
    _require_same_identity_payload(loader['loader'], current['dynamic_loader'], 'runtime registry loader provenance')
    _require_same_identity_payload(loader['provenance'], file_identity(
        paths['dynamic_product'] / 'share/crabc/loader.provenance.json'
    ), 'runtime registry loader provenance file')
    facts_artifacts = facts.get('artifacts')
    require(type(facts_artifacts) is dict, 'public ELF facts artifact roster differs for runtime registry')
    for current_name, artifact_key in (
        ('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared'), ('dynamic_loader', 'candidate-loader'),
    ):
        artifact = facts_artifacts.get(artifact_key)
        require(type(artifact) is dict and 'identity' in artifact,
                f'public ELF facts omit runtime registry {artifact_key}')
        _require_same_identity_payload(artifact['identity'], current[current_name],
                                       f'public ELF/runtime registry {artifact_key}')
    imports = inputs['imports']
    require(type(imports) is dict and set(imports) == set(runtime_registry_evidence.RESOLVERS),
            'runtime registry import roster differs')
    for name in runtime_registry_evidence.RESOLVERS:
        tables = exact(imports[name], set(runtime_registry_evidence.SYMBOL_TABLES),
                       f'runtime registry import {name}')
        for table in runtime_registry_evidence.SYMBOL_TABLES:
            exact(tables[table], {
                'type', 'binding', 'visibility', 'section_index', 'size_bytes', 'value', 'version', 'version_default',
            }, f'runtime registry import {name} {table}')
    return {
        'status': 'private-runtime-registry-observed-with-boundaries',
        'reader': file_identity(Path(runtime_registry_evidence.__file__)),
        'contract': file_identity(runtime_registry_evidence.CONTRACT_PATH),
        'report': before,
        'source': copy.deepcopy(source),
        'products': {name: copy.deepcopy(current[name]) for name in sorted(current)},
        'measurement_reports': measurement_reports,
        'inputs': copy.deepcopy(inputs),
        'limits': list(RUNTIME_REGISTRY_LIMITS),
    }


def _runtime_registry_row_projection(occurrence: Mapping[str, Any]) -> dict[str, Any]:
    row = occurrence.get('row')
    require(type(row) is dict, 'runtime registry occurrence row differs')
    return {key: row.get(key) for key in (
        'type', 'binding', 'visibility', 'section_index', 'size_bytes', 'value', 'version', 'version_default',
    )}


def attach_loader_runtime_registry(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Discharge only the exact selected loader registry import requirements."""
    if companion is None:
        return []
    companion = exact(companion, {'status', 'reader', 'contract', 'report', 'source', 'products', 'measurement_reports', 'inputs', 'limits'},
                      'runtime registry companion')
    require(companion['status'] == 'private-runtime-registry-observed-with-boundaries'
            and companion['limits'] == RUNTIME_REGISTRY_LIMITS,
            'runtime registry companion boundary differs')
    inputs = exact(companion['inputs'], {
        'contract', 'source', 'source_resolution', 'source_files', 'elf_report', 'imports', 'loader', 'products',
    }, 'runtime registry companion inputs')
    imports = inputs['imports']
    require(type(imports) is dict and set(imports) == set(runtime_registry_evidence.RESOLVERS),
            'runtime registry companion import roster differs')
    records = {identity_key(record['identity']): record for record in accounting['identities']}
    require(len(records) == len(accounting['identities']), 'duplicate identities before runtime registry attachment')
    protocol_joins = accounting['private_protocol_joins']
    require(type(protocol_joins) is list, 'runtime registry private protocol joins differ')
    discharged: set[tuple[str, str | None, bool]] = set()
    result: list[dict[str, Any]] = []
    for name, resolver in sorted(runtime_registry_evidence.RESOLVERS.items()):
        key = (name, None, False)
        record = records.get(key)
        require(record is not None, f'runtime registry selected identity is absent: {name}')
        selection_record = record.get('selection')
        require(type(selection_record) is dict
                and selection_record.get('disposition') == 'private-resolution-operation'
                and selection_record.get('owner') == 'loader-runtime-operations',
                f'runtime registry selected owner differs: {name}')
        protocol = selection_record.get('protocol')
        require(type(protocol) is dict and protocol.get('id') == 'loader-runtime-operations'
                and type(protocol.get('members')) is list
                and len(protocol['members']) == len(runtime_registry_evidence.RESOLVERS)
                and set(protocol['members']) == set(runtime_registry_evidence.RESOLVERS)
                and protocol.get('consumer_artifacts') == ['candidate-shared']
                and protocol.get('endpoint_kind') == 'source-dispatch-operation'
                and protocol.get('provider_artifacts') == [],
                f'runtime registry protocol scope differs: {name}')
        operations = protocol.get('operations')
        require(type(operations) is list and len(operations) == len(runtime_registry_evidence.RESOLVERS)
                and next((row for row in operations if isinstance(row, dict) and row.get('name') == name), None) is not None,
                f'runtime registry protocol operation differs: {name}')
        expected_tables = exact(imports[name], set(runtime_registry_evidence.SYMBOL_TABLES),
                                f'runtime registry attachment import {name}')
        occurrences = [row for row in accounting['occurrences']
                       if row['artifact_key'] == 'candidate-shared' and row['role'] == 'import'
                       and identity_key(row_identity(row['row'])) == key]
        by_table = {row['table']: row for row in occurrences}
        require(len(by_table) == len(occurrences) == len(runtime_registry_evidence.SYMBOL_TABLES)
                and set(by_table) == set(runtime_registry_evidence.SYMBOL_TABLES),
                f'runtime registry selected occurrences differ: {name}')
        indices: list[int] = []
        for table in runtime_registry_evidence.SYMBOL_TABLES:
            occurrence = by_table[table]
            require(same(_runtime_registry_row_projection(occurrence), expected_tables[table]),
                    f'runtime registry selected metadata differs: {name} {table}')
            observed_account = occurrence.get('accounting')
            require(type(observed_account) is dict
                    and observed_account.get('disposition') == 'private-resolution-operation'
                    and observed_account.get('owner') == 'loader-runtime-operations'
                    and observed_account.get('scope') == 'candidate-shared',
                    f'runtime registry selected occurrence ownership differs: {name} {table}')
            resolution = observed_account.get('resolution')
            require(type(resolution) is dict
                    and resolution.get('kind') == 'source-dispatch-operation'
                    and type(resolution.get('operation')) is dict
                    and resolution['operation'].get('name') == name
                    and observed_account.get('resolution_proven') is False,
                    f'runtime registry selected occurrence resolution differs: {name} {table}')
            observed_account['resolution_proven'] = True
            indices.append(occurrence['index'])
        join = next((row for row in protocol_joins
                     if row.get('identity') == record['identity'] and row.get('artifact_key') == 'candidate-shared'
                     and row.get('role') == 'consumer-import'), None)
        require(join is not None and join.get('occurrence_indices') == indices
                and join.get('endpoint_kind') == 'source-dispatch-operation'
                and join.get('relocation_lifecycle_proven') is False,
                f'runtime registry private protocol join differs: {name}')
        join['relocation_lifecycle_proven'] = True
        require(all(reason in record['unresolved'] for reason in RUNTIME_REGISTRY_REQUIREMENTS),
                f'runtime registry requirements are absent before attachment: {name}')
        record['unresolved'] = [reason for reason in record['unresolved'] if reason not in RUNTIME_REGISTRY_REQUIREMENTS]
        discharged.add(key)
        result.append({
            'identity': copy.deepcopy(record['identity']), 'resolver': resolver,
            'artifact_key': 'candidate-shared', 'occurrence_indices': indices,
            'requirements_discharged': list(RUNTIME_REGISTRY_REQUIREMENTS),
            'source_dispatch_proven': True,
        })
    accounting['blockers'][:] = [
        blocker for blocker in accounting['blockers']
        if not (blocker.get('code') == 'identity-unresolved'
                and identity_key(blocker.get('identity', {})) in discharged
                and blocker.get('reason') in RUNTIME_REGISTRY_REQUIREMENTS)
    ]
    require(len(result) == len(runtime_registry_evidence.RESOLVERS),
            'runtime registry attachment count differs')
    return result


def _pthread_receipt_artifact(report: Mapping[str, Any], relative: str, description: str) -> dict[str, Any]:
    """Read the pthread reader's retained-copy identity without inventing a mode.

    The owner records the copied artifact path, bytes, and size.  Its receipt
    intentionally does not represent the source file mode, so selection binds
    those two immutable byte fields to the selected installed product while
    the public ELF/product transaction continues to seal the actual mode.
    """
    artifacts = report.get('artifacts')
    require(type(artifacts) is dict, 'pthread alias receipt artifact roster differs')
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and '..' not in Path(relative).parts,
            f'{description} retained path differs')
    row = exact(artifacts.get(relative), {'path', 'sha256', 'size'}, description)
    require(row['path'] == relative
            and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
            and type(row['size']) is int and not isinstance(row['size'], bool) and row['size'] >= 0,
            f'{description} identity differs')
    return row


def _require_same_pthread_receipt_identity(value: object, current: object, description: str) -> None:
    """Compare a pthread retained copy to the selected file's byte identity."""
    observed = exact(value, {'path', 'sha256', 'size'}, description + ' receipt')
    selected = _identity_payload(current, description + ' selected')
    require(observed['sha256'] == selected['sha256'] and observed['size'] == selected['size'],
            f'{description} bytes differ')


def pthread_alias_contract_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                                  measurement: Mapping[str, Any], paths: Mapping[str, Path],
                                  source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay and bind the fixed pthread alias receipt to this product cohort."""
    if report_path is None:
        return None
    require(Path(pthread_alias_evidence.__file__).resolve().parent == MODULE_DIR,
            'pthread alias reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = pthread_alias_evidence.validate_report(report_path)
    except (KeyError, TypeError, ValueError, OSError, pthread_alias_evidence.ReceiptError) as error:
        raise SelectionError(f'pthread alias component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'pthread alias report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'pthread alias')
    measurement_reports = _measurement_report_bindings(measurement, 'pthread alias')
    report = exact(report, {
        'schema', 'status', 'component', 'public_support', 'family_complete', 'promotion_ready',
        'collection', 'selected_source', 'collector', 'inputs', 'selected_products', 'oracle',
        'historical_evidence', 'coverage', 'artifacts', 'commands', 'elf_headers', 'alias_observations', 'runtime_roots',
    }, 'pthread alias reader report')
    require(report['schema'] == pthread_alias_evidence.SCHEMA
            and report['status'] == pthread_alias_evidence.STATUS
            and report['component'] == pthread_alias_evidence.COMPONENT
            and report['public_support'] is False and report['family_complete'] is False and report['promotion_ready'] is False,
            'pthread alias reader report identity or boundary differs')
    selected_source = exact(report['selected_source'], {'revision', 'tree', 'source_sha256', 'component_sha256', 'files'},
                            'pthread alias selected source')
    require(selected_source['revision'] == source['revision']
            and selected_source['source_sha256'] == source['content_sha256'],
            'pthread alias selected source differs from selection')
    current = _current_product_identities(paths)
    selected = exact(report['selected_products'], {'anchor', 'static', 'dynamic'}, 'pthread alias selected products')
    static = exact(selected['static'], {'manifest', 'driver', 'libc', 'original_paths'}, 'pthread alias static product')
    dynamic = exact(selected['dynamic'], {'manifest', 'state', 'driver', 'libc', 'loader', 'original_paths'},
                    'pthread alias dynamic product')
    for retained, current_name in (
        (static['manifest'], 'static_manifest'), (static['driver'], 'static_driver'), (static['libc'], 'static_libc'),
        (dynamic['manifest'], 'dynamic_manifest'), (dynamic['state'], 'dynamic_state'),
        (dynamic['driver'], 'dynamic_driver'), (dynamic['libc'], 'dynamic_libc'), (dynamic['loader'], 'dynamic_loader'),
    ):
        _require_same_pthread_receipt_identity(
            _pthread_receipt_artifact(report, retained, f'pthread alias {current_name} receipt'),
            current[current_name], f'pthread alias {current_name}',
        )
    facts_artifacts = facts.get('artifacts')
    require(type(facts_artifacts) is dict, 'public ELF facts artifact roster differs for pthread aliases')
    for current_name, artifact_key in (
        ('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared'), ('dynamic_loader', 'candidate-loader'),
    ):
        artifact = facts_artifacts.get(artifact_key)
        require(type(artifact) is dict and 'identity' in artifact,
                f'public ELF facts omit pthread alias {artifact_key}')
        _require_same_identity_payload(artifact['identity'], current[current_name],
                                       f'public ELF/pthread alias {artifact_key}')
    require(same(report['coverage'], pthread_alias_evidence._coverage()), 'pthread alias coverage differs')
    alias_observations = report['alias_observations']
    require(type(alias_observations) is dict and alias_observations.get('aliases') == [
        {'public': public, 'provider': provider} for public, provider in pthread_alias_evidence.ALIASES
    ], 'pthread alias observation roster differs')
    return {
        'status': 'pthread-alias-contract-observed-with-boundaries',
        'reader': file_identity(Path(pthread_alias_evidence.__file__)),
        'report': before,
        'source': copy.deepcopy(selected_source),
        'products': {name: copy.deepcopy(current[name]) for name in sorted(current)},
        'measurement_reports': measurement_reports,
        'coverage': copy.deepcopy(report['coverage']),
        'alias_observations': copy.deepcopy(alias_observations),
        'limits': list(PTHREAD_ALIAS_LIMITS),
    }


def _pthread_alias_shape(value: object, placement: str, name: str) -> None:
    require(value == ['FUNC', 'WEAK', 'DEFAULT'],
            f'pthread alias {name} {placement} shape differs')


def _archive_member_from_reader(value: object) -> str:
    require(type(value) is str and value.endswith(')') and '(' in value,
            'pthread alias mq_notify archive member differs')
    member = value.rsplit('(', 1)[1][:-1]
    require(member and '/' not in member and '\\' not in member and '\x00' not in member,
            'pthread alias mq_notify archive member is unsafe')
    return member


def attach_pthread_alias_contract(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Attach public pthread alias facts without selecting private spellings."""
    if companion is None:
        return []
    companion = exact(companion, {'status', 'reader', 'report', 'source', 'products', 'measurement_reports', 'coverage', 'alias_observations', 'limits'},
                      'pthread alias companion')
    require(companion['status'] == 'pthread-alias-contract-observed-with-boundaries'
            and companion['limits'] == PTHREAD_ALIAS_LIMITS,
            'pthread alias companion boundary differs')
    coverage = exact(companion['coverage'], {'aliases', 'mq_notify_source_policy', 'behavior'},
                     'pthread alias companion coverage')
    require(coverage == pthread_alias_evidence._coverage(), 'pthread alias companion coverage differs')
    observations = companion['alias_observations']
    require(type(observations) is dict, 'pthread alias companion observations differ')
    aliases = observations.get('aliases')
    expected_aliases = [{'public': public, 'provider': provider} for public, provider in pthread_alias_evidence.ALIASES]
    require(aliases == expected_aliases, 'pthread alias companion alias roster differs')
    shapes = observations.get('alias_shapes')
    same_definitions = observations.get('same_definition')
    require(type(shapes) is dict and set(shapes) == {'dynamic', 'shared', 'static'}
            and type(same_definitions) is dict and set(same_definitions) == {'musl_shared', 'musl_static', 'shared', 'static'},
            'pthread alias companion definition observations differ')
    records = {identity_key(record['identity']): record for record in accounting['identities']}
    require(len(records) == len(accounting['identities']), 'duplicate identities before pthread alias attachment')
    joins_by_key = {(identity_key(row['identity']), row['artifact_key']): row for row in accounting['placement_joins']}
    require(len(joins_by_key) == len(accounting['placement_joins']), 'duplicate placement joins before pthread alias attachment')
    occurrences = {row['index']: row for row in accounting['occurrences']}
    require(len(occurrences) == len(accounting['occurrences']), 'duplicate occurrences before pthread alias attachment')
    alias_joins: list[dict[str, Any]] = []
    for public, provider in pthread_alias_evidence.ALIASES:
        key = (public, None, False)
        record = records.get(key)
        require(record is not None and record.get('selection', {}).get('disposition') == 'public-provider',
                f'pthread alias selected public identity differs: {public}')
        for placement in ('dynamic', 'shared', 'static'):
            _pthread_alias_shape(shapes[placement].get(public), placement, public)
        for placement in ('shared', 'static'):
            definition = same_definitions[placement].get(public)
            require(type(definition) is dict and set(definition) == {'alias', 'provider'}
                    and definition['alias'].get('name') == public and definition['provider'].get('name') == provider,
                    f'pthread alias same-definition evidence differs: {public} {placement}')
        placement_rows: dict[str, dict[str, Any]] = {}
        for artifact_key, placement in (('candidate-static', 'static'), ('candidate-shared', 'shared')):
            expected_table = '.symtab' if artifact_key == 'candidate-static' else '.dynsym'
            join = joins_by_key.get((key, artifact_key))
            require(join is not None and join.get('placement_observed') is True
                    and join.get('definition_count') == 1 and len(join.get('occurrence_indices', [])) == 1
                    and _metadata_difference_rows_are_empty(join.get('metadata_differences'),
                                                             f'pthread alias {public} {artifact_key}'),
                    f'pthread alias selected placement differs: {public} {artifact_key}')
            occurrence = occurrences.get(join['occurrence_indices'][0])
            require(occurrence is not None and occurrence.get('artifact_key') == artifact_key
                    and occurrence.get('role') == 'definition' and occurrence.get('table') == expected_table
                    and same(row_identity(occurrence['row']), record['identity'])
                    and occurrence['row'].get('type') == 'FUNC'
                    and occurrence['row'].get('binding') == 'WEAK'
                    and occurrence['row'].get('visibility') == 'DEFAULT',
                    f'pthread alias selected occurrence differs: {public} {artifact_key}')
            placement_rows[placement] = {'artifact_key': artifact_key, 'occurrence_index': occurrence['index']}
        shared_symtab = [row for row in occurrences.values()
                         if row.get('artifact_key') == 'candidate-shared' and row.get('table') == '.symtab'
                         and row.get('role') == 'definition' and same(row_identity(row['row']), record['identity'])]
        require(len(shared_symtab) == 1
                and shared_symtab[0]['row'].get('type') == 'FUNC'
                and shared_symtab[0]['row'].get('binding') == 'WEAK'
                and shared_symtab[0]['row'].get('visibility') == 'DEFAULT',
                f'pthread alias shared symtab occurrence differs: {public}')
        alias_joins.append({
            'identity': copy.deepcopy(record['identity']), 'provider': provider,
            'placements': placement_rows, 'shared_symtab_occurrence_index': shared_symtab[0]['index'],
            'same_definition_observed': True,
        })
    require(len(alias_joins) == len(pthread_alias_evidence.ALIASES)
            and len({row['provider'] for row in alias_joins}) == 15,
            'pthread alias/provider cardinality differs')
    mq = observations.get('mq_notify_public_detach')
    require(type(mq) is dict and set(mq) == {'musl', 'candidate'}
            and type(mq['candidate']) is dict and set(mq['candidate']) == {'member', 'relocation_section'},
            'pthread alias mq_notify evidence differs')
    member = _archive_member_from_reader(mq['candidate']['member'])
    require(type(mq['candidate']['relocation_section']) is str and mq['candidate']['relocation_section'].startswith('.rela'),
            'pthread alias mq_notify relocation section differs')
    detach_key = ('pthread_detach', None, False)
    detach = records.get(detach_key)
    require(detach is not None and detach.get('selection', {}).get('disposition') == 'public-provider',
            'pthread alias public pthread_detach selection differs')
    imports = [row for row in occurrences.values()
               if row.get('artifact_key') == 'candidate-static' and row.get('role') == 'import'
               and same(row_identity(row['row']), detach['identity'])]
    matched = [row for row in imports
               if row.get('table') == '.symtab' and row.get('member_name') == member
               and row['row'].get('type') == 'NOTYPE' and row['row'].get('binding') == 'GLOBAL'
               and row['row'].get('visibility') == 'DEFAULT']
    covered = len(imports) == len(matched) == 1
    if covered:
        require(ORDINARY_IMPORT_REASON in detach['unresolved'],
                'pthread alias mq_notify import reason is absent before attachment')
        detach['unresolved'].remove(ORDINARY_IMPORT_REASON)
        accounting['blockers'][:] = [
            blocker for blocker in accounting['blockers']
            if not (blocker.get('code') == 'identity-unresolved'
                    and identity_key(blocker.get('identity', {})) == detach_key
                    and blocker.get('reason') == ORDINARY_IMPORT_REASON)
        ]
    mq_join = {
        'identity': copy.deepcopy(detach['identity']), 'artifact_key': 'candidate-static',
        'member_name': member, 'occurrence_indices': [row['index'] for row in matched],
        'relocation_section': mq['candidate']['relocation_section'],
        'public_detach_relocation_proven': covered,
        'discharged_reason': ORDINARY_IMPORT_REASON if covered else None,
    }
    return [{
        'aliases': alias_joins,
        'mq_notify_public_detach': mq_join,
        'application_public_override': copy.deepcopy(observations.get('application_public_override')),
    }]


def _runtime_facts_match_selected_products(facts: Mapping[str, Any], current: Mapping[str, Any], *,
                                           label: str, artifacts: Sequence[tuple[str, str]]) -> None:
    """Bind a component's named ELF observations to the selected raw facts."""
    facts_artifacts = facts.get('artifacts')
    require(type(facts_artifacts) is dict, f'public ELF facts artifact roster differs for {label}')
    for current_name, artifact_key in artifacts:
        artifact = facts_artifacts.get(artifact_key)
        require(type(artifact) is dict and 'identity' in artifact,
                f'public ELF facts omit {label} {artifact_key}')
        _require_same_identity_payload(artifact['identity'], current[current_name],
                                       f'public ELF/{label} {artifact_key}')


def _prepared_runtime_projection(value: object) -> dict[str, Any]:
    expected = {
        'application_cells': {row['label']: dict(row) for row in prepared_worker_evidence.runtime_cells()},
        'source_tests': list(prepared_worker_evidence.UNIT_TESTS),
        'source_test_executable': 'loader-tests',
        'source_root': prepared_worker_evidence.UNIT_ROOT,
        'oracle_boundary': 'Common installed C TLS/callback lifecycle only; no musl token/view/unmap-layout claim.',
        'owned_boundary': 'Live TLS and retained views mapped until quiescence; joined/reaped TLS and views unmapped.',
    }
    require(same(value, expected), 'prepared worker runtime observation roster differs')
    return copy.deepcopy(expected)


def _prepared_worker_work_identity(value: object, expected_path: Path, description: str) -> dict[str, Any]:
    """Join the owner's root-relative work record to one supplied input.

    The prepared-worker reader deliberately records only its portable
    path/hash/size work identity.  Selection binds all three fields to the
    supplied path, while its returned product cohort retains mode-bearing
    records for the post-attachment transaction recheck.
    """
    observed = exact(value, {'path', 'sha256', 'size'}, description)
    expected_path = physical_work_path(expected_path, directory=False)
    require(expected_path.is_relative_to(ROOT), f'{description} selected input is outside selector checkout')
    current = file_identity(expected_path)
    expected = {
        'path': expected_path.relative_to(ROOT).as_posix(),
        'sha256': current['sha256'],
        'size': current['size'],
    }
    require(same(observed, expected), f'{description} differs from selected input')
    return copy.deepcopy(expected)


def _require_prepared_worker_product_root(value: object, expected_path: Path, description: str) -> None:
    """Require the owner's exact root-relative spelling of a supplied product."""
    expected_path = physical_work_path(expected_path, directory=True)
    require(expected_path.is_relative_to(ROOT), f'{description} selected product is outside selector checkout')
    require(value == expected_path.relative_to(ROOT).as_posix(),
            f'{description} differs from selected product')


def prepared_worker_tls_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                                measurement: Mapping[str, Any], paths: Mapping[str, Path],
                                source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay and bind the finite prepared-worker TLS receipt once.

    The owning reader already validates its source copies, tool commands and
    runtime cells.  This adapter only joins its exact source/product/ELF facts
    to the selection transaction; it does not manufacture a main-thread TLS
    import or treat the owned CRT handoff carrier as this descriptor.
    """
    if report_path is None:
        return None
    require(Path(prepared_worker_evidence.__file__).resolve().parent == MODULE_DIR,
            'prepared worker reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = prepared_worker_evidence.validate_report(
            ROOT, report_path,
            **{key: paths[key] for key in
               ('base_inventory', 'elf_report', 'static_preparation', 'static_product', 'dynamic_product')},
        )
    except (KeyError, TypeError, ValueError, OSError, prepared_worker_evidence.PreparedWorkerTlsError) as error:
        raise SelectionError(f'prepared worker TLS component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'prepared worker TLS report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'prepared worker TLS')
    measurement_reports = _measurement_report_bindings(measurement, 'prepared worker TLS')
    report = exact(report, {
        'schema', 'target', 'image', 'status', 'source_before', 'source_after', 'source_account', 'source_copies',
        'inputs_before', 'inputs_after', 'tools', 'rust_tools', 'oracle', 'oracle_static_inputs', 'commands', 'links',
        'observations',
    }, 'prepared worker TLS reader report')
    require(report['schema'] == prepared_worker_evidence.SCHEMA and report['target'] == prepared_worker_evidence.inventory.TARGET
            and same(report['status'], prepared_worker_evidence.STATUS),
            'prepared worker TLS reader report identity or status differs')
    require(same(report['source_before'], source) and same(report['source_after'], source),
            'prepared worker TLS source differs from selection')
    require(type(report['image']) is str and bool(report['image']), 'prepared worker TLS image identity differs')
    inputs = exact(report['inputs_before'], {'products', 'reports', 'elf'}, 'prepared worker TLS input binding')
    require(same(report['inputs_after'], inputs), 'prepared worker TLS input binding changed')
    products = exact(inputs['products'], {'source', 'static_preparation', 'dynamic_product'},
                     'prepared worker TLS product binding')
    expected_source = {'revision': source['revision'], 'content_sha256': source['content_sha256']}
    require(same(products['source'], expected_source), 'prepared worker TLS product source differs')
    static_preparation = exact(products['static_preparation'], {'receipt', 'source', 'primary'},
                               'prepared worker TLS static preparation binding')
    require(same(static_preparation['source'], expected_source),
            'prepared worker TLS static preparation source differs from selection')
    _prepared_worker_work_identity(static_preparation['receipt'], paths['static_preparation'],
                                   'prepared worker TLS static preparation receipt')
    primary = exact(static_preparation['primary'], {'path', 'manifest'}, 'prepared worker TLS static primary')
    dynamic_product = exact(products['dynamic_product'], {'path', 'manifest', 'state', 'manifest_sha256'},
                            'prepared worker TLS dynamic product binding')
    reports = exact(inputs['reports'], {'base_inventory', 'elf_report'}, 'prepared worker TLS report binding')
    current = _runtime_attachment_identities(paths)
    for name, path_key in (
        ('base_inventory', 'base_inventory'), ('elf_report', 'elf_report'),
        ('static_preparation', 'static_preparation'),
    ):
        require(same(measurement_reports[name], file_identity(paths[path_key])),
                f'prepared worker TLS selected {name} differs from public replay')
    _prepared_worker_work_identity(reports['base_inventory'], paths['base_inventory'],
                                   'prepared worker TLS base inventory report')
    _prepared_worker_work_identity(reports['elf_report'], paths['elf_report'],
                                   'prepared worker TLS ELF report')
    _require_prepared_worker_product_root(primary['path'], paths['static_product'],
                                          'prepared worker TLS static primary root')
    _prepared_worker_work_identity(primary['manifest'],
                                   paths['static_product'] / 'share/crabc/manifest.json',
                                   'prepared worker TLS static manifest')
    _require_prepared_worker_product_root(dynamic_product['path'], paths['dynamic_product'],
                                          'prepared worker TLS dynamic product root')
    dynamic_manifest = _prepared_worker_work_identity(
        dynamic_product['manifest'], paths['dynamic_product'] / 'share/crabc/manifest.json',
        'prepared worker TLS dynamic manifest',
    )
    _prepared_worker_work_identity(dynamic_product['state'],
                                   paths['dynamic_product'] / 'share/crabc/dynamic-product-state.json',
                                   'prepared worker TLS dynamic state')
    require(dynamic_product['manifest_sha256'] == dynamic_manifest['sha256'],
            'prepared worker TLS dynamic manifest digest differs')
    _runtime_facts_match_selected_products(
        facts, current, label='prepared worker TLS',
        artifacts=(('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared'),
                   ('dynamic_loader', 'candidate-loader')),
    )
    expected_elf = prepared_worker_evidence.account_elf(facts)
    require(same(inputs['elf'], expected_elf), 'prepared worker TLS selected ELF account differs')
    expected_source_account = prepared_worker_evidence.account_source(ROOT)
    require(same(report['source_account'], expected_source_account), 'prepared worker TLS source account differs')
    require(type(report['source_copies']) is dict and set(report['source_copies']) == set(prepared_worker_evidence.SOURCE_PATHS),
            'prepared worker TLS retained source roster differs')
    observations = exact(report['observations'], {
        'artifacts', 'worker_relocations', 'executables', 'dsos', 'runtime', 'unit_diagnostics', 'execution_roots',
    }, 'prepared worker TLS observations')
    try:
        expected_relocations = prepared_worker_evidence.worker_relocations(
            prepared_worker_evidence.Elf(paths['dynamic_product'] / 'usr/lib/libc.so')
        )
    except (ValueError, OSError, prepared_worker_evidence.PreparedWorkerTlsError) as error:
        raise SelectionError(f'prepared worker TLS relocation account rejected: {error}') from error
    require(same(observations['worker_relocations'], expected_relocations),
            'prepared worker TLS relocation account differs')
    runtime = _prepared_runtime_projection(observations['runtime'])
    selected_products = {
        name: copy.deepcopy(current[name]) for name in (
            'static_manifest', 'static_libc', 'dynamic_manifest', 'dynamic_state', 'dynamic_libc', 'dynamic_loader',
        )
    }
    return {
        'status': 'prepared-worker-tls-observed-with-boundaries',
        'reader': file_identity(Path(prepared_worker_evidence.__file__)),
        'contract': file_identity(prepared_worker_evidence.CONTRACT),
        'report': before,
        'source': copy.deepcopy(source),
        'products': selected_products,
        'measurement_reports': measurement_reports,
        'account': {
            'elf': copy.deepcopy(expected_elf),
            'source': copy.deepcopy(expected_source_account),
            'worker_relocations': copy.deepcopy(expected_relocations),
            'runtime': runtime,
        },
        'limits': list(PREPARED_WORKER_TLS_LIMITS),
    }


def _errno_summary(value: object) -> dict[str, str]:
    expected = {
        'errno_public_accessor': 'GLOBAL DEFAULT FUNC',
        'errno_allocator_alias': 'static WEAK HIDDEN same-address; shared LOCAL DEFAULT absent-dynsym',
        'h_errno': 'GLOBAL DEFAULT OBJECT size=4, source-required alignment=4, and GLOBAL DEFAULT accessor',
        'h_errno_layout': 'static/shared defining section and section-relative offset retain alignment=4; shared section over-alignment is observed separately',
        'execution': 'main/live-worker isolation, aligned live accessor locations, stable live locations, selected pthread EBUSY preserves errno, and loaded DSO access',
        'worker_pointer_lifetime': 'never dereferenced after join',
    }
    require(same(value, expected), 'errno storage lifecycle summary differs')
    return copy.deepcopy(expected)


def _errno_h_errno_layout(value: object) -> dict[str, dict[str, Any]]:
    """Keep the errno reader's finite object-layout projection exact.

    The owning reader reconstructs the complete raw section/member facts.  The
    selector consumes only the source-required object metadata after requiring
    both retained role records, so a section's incidental shared over-alignment
    never becomes a generic native ABI rule.
    """
    roles = exact(value, {'static', 'shared'}, 'errno h_errno layout roster')
    metadata = errno_storage_evidence.H_ERRNO_METADATA
    fact_keys = {
        'symbol_value_hex', 'object_size_bytes', 'required_alignment_bytes',
        'defining_section_index', 'defining_section_name', 'defining_section_address_hex',
        'defining_section_size_bytes', 'defining_section_alignment_bytes',
        'offset_bytes', 'offset_modulo_required_alignment',
    }
    result: dict[str, dict[str, Any]] = {}
    for role in ('static', 'shared'):
        record = exact(roles[role], {'metadata', 'oracle', 'candidate'}, f'errno h_errno {role} layout')
        observed_metadata = exact(record['metadata'], set(metadata), f'errno h_errno {role} metadata')
        require(same(observed_metadata, metadata), f'errno h_errno {role} metadata differs')
        expected_fact_keys = set(fact_keys)
        if role == 'static':
            expected_fact_keys.add('archive_member')
        for owner in ('oracle', 'candidate'):
            fact = exact(record[owner], expected_fact_keys, f'errno h_errno {role} {owner} fact')
            require(fact['object_size_bytes'] == metadata['size_bytes']
                    and fact['required_alignment_bytes'] == metadata['alignment_bytes']
                    and fact['offset_modulo_required_alignment'] == 0
                    and type(fact['defining_section_index']) is int and fact['defining_section_index'] > 0
                    and type(fact['defining_section_alignment_bytes']) is int
                    and fact['defining_section_alignment_bytes'] >= metadata['alignment_bytes']
                    and fact['defining_section_alignment_bytes'] % metadata['alignment_bytes'] == 0
                    and type(fact['offset_bytes']) is int and fact['offset_bytes'] >= 0
                    and fact['offset_bytes'] % metadata['alignment_bytes'] == 0
                    and all(type(fact[field]) is str and fact[field]
                            for field in ('symbol_value_hex', 'defining_section_name', 'defining_section_address_hex'))
                    and type(fact['defining_section_size_bytes']) is int and fact['defining_section_size_bytes'] >= metadata['size_bytes'],
                    f'errno h_errno {role} {owner} alignment fact differs')
            if role == 'static':
                archive_member = exact(fact['archive_member'], {'name', 'index', 'occurrence'},
                                       f'errno h_errno {role} {owner} member')
                require(type(archive_member['name']) is str and archive_member['name']
                        and type(archive_member['index']) is int and archive_member['index'] >= 0
                        and type(archive_member['occurrence']) is int and archive_member['occurrence'] >= 0,
                        f'errno h_errno {role} {owner} member differs')
        result[role] = copy.deepcopy(observed_metadata)
    return result


def _errno_alias_policy(value: object, description: str) -> dict[str, Any]:
    """Validate the receipt's fixed one-name policy projection.

    The owning reader validates the retained full shared-libc link command.
    This join keeps only its deliberately compact policy projection, so it
    checks the reviewed source/list/script constants directly instead of
    synthesizing a partial command merely to reuse that reader's helper.
    """
    aliases = exact(value, {'source', 'member_count', 'members', 'linker_policy', 'linker_script_sha256'}, description)
    source = exact(aliases['source'], {'path', 'sha256', 'mode'}, f'{description} source')
    require(same(source, {
        'path': errno_storage_evidence.SHARED_ALIAS_LIST,
        'sha256': errno_storage_evidence.SHARED_ALIAS_LIST_SHA256,
        'mode': 0o644,
    }), f'{description} source differs')
    require(type(aliases['member_count']) is int
            and aliases['member_count'] == len(errno_storage_evidence.SHARED_ALIAS_MEMBERS)
            and aliases['members'] == list(errno_storage_evidence.SHARED_ALIAS_MEMBERS)
            and aliases['linker_policy'] == 'exact-local-symbols'
            and aliases['linker_script_sha256'] == errno_storage_evidence.SHARED_ALIAS_LINKER_SCRIPT_SHA256,
            f'{description} policy differs')
    return copy.deepcopy(aliases)


def errno_storage_lifecycle_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                                    measurement: Mapping[str, Any], paths: Mapping[str, Path],
                                    source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay and bind the finite errno storage/lifecycle receipt once.

    The receipt owns public accessor behavior, the private local alias policy,
    and live-worker observations.  It deliberately does not stand in for the
    selected loader report, the h_errno header/declaration account, or the
    generic object-layout proof.
    """
    if report_path is None:
        return None
    require(Path(errno_storage_evidence.__file__).resolve().parent == MODULE_DIR,
            'errno storage reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = errno_storage_evidence.validate_report(ROOT, report_path)
    except (KeyError, TypeError, ValueError, OSError, errno_storage_evidence.ErrnoStorageEvidenceError) as error:
        raise SelectionError(f'errno storage lifecycle component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'errno storage lifecycle report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'errno storage lifecycle')
    measurement_reports = _measurement_report_bindings(measurement, 'errno storage lifecycle')
    report = exact(report, {
        'schema', 'target', 'work', 'source', 'collection_checkout_root', 'products', 'shared_alias_link_policy',
        'symbols', 'layout_artifacts', 'h_errno_layout', 'workload_symbols', 'objects', 'execution',
        'dynamic_link_receipts', 'summary',
    }, 'errno storage lifecycle reader report')
    require(report['schema'] == errno_storage_evidence.SCHEMA and report['target'] == errno_storage_evidence.TARGET,
            'errno storage lifecycle reader report identity differs')
    receipt_source = exact(report['source'], {'schema', 'root', 'commit', 'status', 'files'},
                           'errno storage lifecycle source snapshot')
    require(receipt_source['schema'] == errno_storage_evidence.SNAPSHOT_SCHEMA
            and receipt_source['root'] == str(ROOT)
            and receipt_source['commit'] == source['revision'] and receipt_source['status'] == ''
            and type(receipt_source['files']) is dict and set(receipt_source['files']) == set(errno_storage_evidence.SOURCE_FILES),
            'errno storage lifecycle source differs from selection')
    products = exact(report['products'], {'static', 'dynamic'}, 'errno storage lifecycle product record')
    static_product = exact(products['static'], {'root', 'manifest', 'libc'}, 'errno storage lifecycle static product')
    dynamic_product = exact(products['dynamic'], {'root', 'manifest', 'libc', 'libc_shared_provenance'},
                            'errno storage lifecycle dynamic product')
    current = _runtime_attachment_identities(paths)
    for receipt, name in (
        (static_product['manifest'], 'static_manifest'), (static_product['libc'], 'static_libc'),
        (dynamic_product['manifest'], 'dynamic_manifest'), (dynamic_product['libc'], 'dynamic_libc'),
        (dynamic_product['libc_shared_provenance'], 'dynamic_shared_provenance'),
    ):
        _require_same_errno_identity(receipt, current[name], f'errno storage lifecycle {name}')
    _runtime_facts_match_selected_products(
        facts, current, label='errno storage lifecycle',
        artifacts=(('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared')),
    )
    alias_policy = _errno_alias_policy(report['shared_alias_link_policy'], 'errno storage lifecycle receipt')
    h_errno_layout = _errno_h_errno_layout(report['h_errno_layout'])
    require(type(report['symbols']) is dict and set(report['symbols']) == set(errno_storage_evidence.SYMBOL_INPUTS)
            and type(report['layout_artifacts']) is dict
            and set(report['layout_artifacts']) == set(errno_storage_evidence.LAYOUT_INPUTS)
            and type(report['workload_symbols']) is dict and set(report['workload_symbols']) == set(errno_storage_evidence.WORKLOAD_SYMBOL_INPUTS)
            and type(report['objects']) is dict and set(report['objects']) == set(errno_storage_evidence.OBJECTS)
            and type(report['execution']) is dict and set(report['execution']) == set(errno_storage_evidence.RUN_LABELS)
            and type(report['dynamic_link_receipts']) is dict and set(report['dynamic_link_receipts']) == set(errno_storage_evidence.DYNAMIC_LINKS),
            'errno storage lifecycle retained evidence roster differs')
    summary = _errno_summary(report['summary'])
    selected_products = {
        name: copy.deepcopy(current[name]) for name in (
            'static_manifest', 'static_libc', 'dynamic_manifest', 'dynamic_libc', 'dynamic_shared_provenance',
        )
    }
    return {
        'status': 'errno-storage-lifecycle-observed-with-boundaries',
        'reader': file_identity(Path(errno_storage_evidence.__file__)),
        'report': before,
        'source': copy.deepcopy(source),
        'products': selected_products,
        'measurement_reports': measurement_reports,
        'account': {
            'public_symbols': list(errno_storage_evidence.PUBLIC_SYMBOLS),
            'private_alias': errno_storage_evidence.ALIAS,
            'shared_alias_policy': copy.deepcopy(alias_policy),
            'h_errno_layout': h_errno_layout,
            'summary': summary,
            'execution_labels': list(errno_storage_evidence.RUN_LABELS),
        },
        'limits': list(ERRNO_STORAGE_LIFECYCLE_LIMITS),
    }


def _c_allocator_boundary_contract() -> tuple[dict[str, Any], list[str]]:
    """Load the one source-owned seven-import boundary without a name rule.

    The C component's TOML is the authority for this finite list.  This
    selector deliberately consumes it as an exact contract rather than
    extending the fixed-C metadata group's 424-name private-provider roster.
    """
    try:
        contract = native_c_allocator_boundary.load_contract(ROOT)
    except (OSError, ValueError, native_c_allocator_boundary.AllocatorBoundaryError) as error:
        raise SelectionError(f'native C allocator boundary contract rejected: {error}') from error
    scope = exact(contract.get('scope'), {
        'weak_entries', 'global_entries', 'rust_c_imports', 'lifecycle_entries',
        'interposition_scenarios', 'dynamic_modes', 'dynamic_entries', 'static_modes',
    }, 'native C allocator boundary scope')
    imports = scope['rust_c_imports']
    require(type(imports) is list and all(type(name) is str and name for name in imports)
            and len(imports) == 7 and len(set(imports)) == len(imports),
            'native C allocator boundary Rust import roster differs')
    return contract, list(imports)


def native_c_allocator_boundary_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                                        measurement: Mapping[str, Any], paths: Mapping[str, Path],
                                        source: Mapping[str, Any],
                                        fixed_c_companion: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay the finite C wrapper/lifecycle receipt against this ELF cohort.

    The public component reader owns its product validation and runtime
    transcripts.  This adapter seals the report before and after that replay,
    joins its exact product identities to the already replayed ELF cohort, and
    exposes only the seven Rust-root C import claims for later placement
    accounting.  It does not turn the C backend into allocator-family proof.
    """
    if report_path is None:
        return None
    require(Path(native_c_allocator_boundary.ROOT) == ROOT
            and Path(native_c_allocator_boundary.__file__).resolve().parent == MODULE_DIR,
            'native C allocator boundary reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = native_c_allocator_boundary.validate_report(
            report_path,
            static_preparation=paths['static_preparation'],
            static_product=paths['static_product'],
            dynamic_product=paths['dynamic_product'],
            elf_facts_report=paths['elf_report'],
        )
    except (KeyError, TypeError, ValueError, OSError, native_c_allocator_boundary.AllocatorBoundaryError) as error:
        raise SelectionError(f'native C allocator boundary component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'native C allocator boundary report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'native C allocator boundary')
    measurement_reports = _measurement_report_bindings(measurement, 'native C allocator boundary')
    contract, import_names = _c_allocator_boundary_contract()
    report = exact(report, {
        'schema', 'target', 'status', 'collector_source', 'component_sources', 'inputs', 'startup', 'interposition',
    }, 'native C allocator boundary reader report')
    require(report['schema'] == native_c_allocator_boundary.SCHEMA
            and report['target'] == native_c_allocator_boundary.TARGET
            and same(report['status'], {
                'family_completion': False, 'promotion': False, 'public_support': False,
            }), 'native C allocator boundary reader status differs')
    require(same(report['collector_source'], source),
            'native C allocator boundary collector source differs from selection')
    require(same(report['component_sources'], native_c_allocator_boundary.source_records(ROOT)),
            'native C allocator boundary component source roster differs')
    inputs = exact(report['inputs'], {
        'product_source', 'source_resolution', 'static_preparation', 'static', 'dynamic', 'elf_facts',
        'producer_account', 'wrapper_product_bindings',
    }, 'native C allocator boundary input account')
    product_source = exact(inputs['product_source'], {'revision', 'content_sha256'},
                           'native C allocator boundary product source')
    require(same(product_source, {
        'revision': source['revision'], 'content_sha256': source['content_sha256'],
    }), 'native C allocator boundary product source differs from selection')
    try:
        expected_source_resolution = native_c_allocator_boundary.source_resolution(ROOT, source['revision'])
    except (OSError, ValueError, native_c_allocator_boundary.AllocatorBoundaryError) as error:
        raise SelectionError(f'native C allocator boundary source resolution rejected: {error}') from error
    require(same(inputs['source_resolution'], expected_source_resolution),
            'native C allocator boundary source resolution differs')
    current = _c_allocator_boundary_identities(paths)
    _require_same_identity_payload(inputs['static_preparation'], measurement_reports['static_preparation'],
                                   'native C allocator boundary static preparation')
    static_product = exact(inputs['static'], {'product', 'manifest', 'libc', 'provenance'},
                           'native C allocator boundary static product')
    dynamic_product = exact(inputs['dynamic'], {'product', 'manifest', 'state', 'libc', 'provenance'},
                            'native C allocator boundary dynamic product')
    require(static_product['product'] == '/inputs/static-product'
            and dynamic_product['product'] == '/inputs/dynamic-product',
            'native C allocator boundary product path roles differ')
    for receipt, name in (
        (static_product['manifest'], 'static_manifest'),
        (static_product['libc'], 'static_libc'),
        (static_product['provenance'], 'static_provenance'),
        (dynamic_product['manifest'], 'dynamic_manifest'),
        (dynamic_product['state'], 'dynamic_state'),
        (dynamic_product['libc'], 'dynamic_libc'),
        (dynamic_product['provenance'], 'dynamic_shared_provenance'),
    ):
        _require_same_identity_payload(receipt, current[name],
                                       f'native C allocator boundary {name}')
    _require_same_identity_payload(inputs['elf_facts'], measurement_reports['elf_report'],
                                   'native C allocator boundary ELF facts')
    _runtime_facts_match_selected_products(
        facts, current, label='native C allocator boundary',
        artifacts=(('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared')),
    )
    fixed_account = fixed_c_companion.get('account') if isinstance(fixed_c_companion, Mapping) else None
    require(type(fixed_account) is dict and same(inputs['producer_account'], fixed_account),
            'native C allocator boundary fixed-C producer account differs')
    producer_account = inputs['producer_account']
    archive_map = producer_account.get('archive_map') if isinstance(producer_account, dict) else None
    require(type(archive_map) is dict and type(archive_map.get('static_rust_root_member')) is str
            and archive_map['static_rust_root_member'],
            'native C allocator boundary static Rust root differs')
    claims = producer_account.get('rust_root_c_import_joins') if isinstance(producer_account, dict) else None
    require(type(claims) is list and [claim.get('name') for claim in claims if isinstance(claim, dict)] == import_names
            and len(claims) == len(import_names),
            'native C allocator boundary producer import claims differ')
    for claim in claims:
        require(type(claim) is dict and set(claim) == {
            'name', 'static_rust_import', 'static_c_provider', 'shared_c_final_provider',
        }, 'native C allocator boundary producer import claim fields differ')
        static_import = exact(claim['static_rust_import'], {
            'type', 'binding', 'visibility', 'section_index',
        }, 'native C allocator boundary static Rust import')
        require(static_import == {
            'type': 'NOTYPE', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': 'UND',
        }, 'native C allocator boundary static Rust import metadata differs')
    wrappers = exact(inputs['wrapper_product_bindings'], {'static_member', 'static', 'shared'},
                     'native C allocator boundary wrapper product bindings')
    roles = native_c_allocator_boundary.wrapper_roles(contract)
    require(wrappers['static_member'] == archive_map['static_rust_root_member']
            and type(wrappers['static']) is dict and set(wrappers['static']) == set(roles)
            and type(wrappers['shared']) is dict and set(wrappers['shared']) == {'.dynsym', '.symtab'}
            and all(type(rows) is dict and set(rows) == set(roles) for rows in wrappers['shared'].values()),
            'native C allocator boundary wrapper product binding roster differs')
    require(type(report['startup']) is dict and set(report['startup']) == {'command', 'work', 'observation'}
            and type(report['interposition']) is dict and set(report['interposition']) == {'command', 'work', 'observation'},
            'native C allocator boundary runtime observation shape differs')
    selected_products = {
        name: copy.deepcopy(current[name]) for name in (
            'static_manifest', 'static_libc', 'static_provenance', 'dynamic_manifest',
            'dynamic_state', 'dynamic_libc', 'dynamic_shared_provenance',
        )
    }
    source_inputs = {name: file_identity(ROOT / name) for name in C_ALLOCATOR_BOUNDARY_SOURCE_FILES}
    return {
        'status': 'native-c-allocator-boundary-observed-with-boundaries',
        'reader': file_identity(Path(native_c_allocator_boundary.__file__)),
        'contract': file_identity(native_c_allocator_boundary.CONTRACT_PATH),
        'report': before,
        'source': copy.deepcopy(source),
        'source_inputs': source_inputs,
        'products': selected_products,
        'measurement_reports': measurement_reports,
        'account': {
            'imports': list(import_names),
            'claims': copy.deepcopy(claims),
            'static_rust_root_member': archive_map['static_rust_root_member'],
        },
        'limits': list(C_ALLOCATOR_BOUNDARY_LIMITS),
    }


def _stdio_alias_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Return the installed product files sealed by the FILE alias receipt.

    The FILE reader validates complete static and dynamic trees.  Selection
    retains this finite file roster as the transaction join, rather than
    letting a matching alias row authorize an unrelated installed product.
    """
    return _c_allocator_boundary_identities(paths)


def _stdio_receipt_identity(value: object, description: str) -> dict[str, Any]:
    """Validate the FILE reader's path/hash/size form without inventing mode."""
    row = exact(value, {'path', 'sha256', 'size'}, description)
    relative = Path(row['path']) if type(row['path']) is str else None
    require(relative is not None and str(relative) and not relative.is_absolute()
            and '..' not in relative.parts
            and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
            and type(row['size']) is int and not isinstance(row['size'], bool) and row['size'] >= 0,
            f'{description} identity differs')
    return {'path': relative.as_posix(), 'sha256': row['sha256'], 'size': row['size']}


def _require_stdio_receipt_identity(value: object, current: object, description: str) -> None:
    observed = _stdio_receipt_identity(value, description + ' receipt')
    selected = _identity_payload(current, description + ' selected')
    require(observed['sha256'] == selected['sha256'] and observed['size'] == selected['size'],
            f'{description} bytes differ')


def _require_stdio_receipt_path(value: object, expected: Path, description: str) -> None:
    """Bind a reader-resolved input path to the selection's physical input."""
    observed = _stdio_receipt_identity(value, description)
    retained = (ROOT / observed['path']).resolve()
    require(retained == expected.resolve(), f'{description} path differs from selected input')


def _require_stdio_product_root(value: object, expected: Path, description: str) -> None:
    require(type(value) is str and value and not Path(value).is_absolute()
            and '..' not in Path(value).parts,
            f'{description} root path differs')
    require((ROOT / value).resolve() == expected.resolve(),
            f'{description} root differs from selected product')


def _require_stdio_tree_file(tree: object, relative: str, current: object, description: str) -> None:
    require(type(tree) is dict, f'{description} tree differs')
    row = exact(tree.get(relative), {'kind', 'mode', 'sha256', 'size'}, f'{description} tree file')
    selected = _identity_payload(current, f'{description} selected')
    require(row['kind'] == 'file' and row['mode'] == selected['mode']
            and row['sha256'] == selected['sha256'] and row['size'] == selected['size'],
            f'{description} tree file differs')


def _stdio_source_snapshot(value: object, names: Sequence[str], description: str) -> dict[str, dict[str, Any]]:
    require(type(value) is dict and set(value) == set(names), f'{description} source roster differs')
    result = {}
    for name in names:
        row = _stdio_receipt_identity(value[name], f'{description} source {name}')
        live = _identity_payload(file_identity(ROOT / name), f'{description} live source {name}')
        require(row['sha256'] == live['sha256'] and row['size'] == live['size'],
                f'{description} source differs: {name}')
        result[name] = row
    return result


def _normalized_stdio_complete_facts(value: object, artifact_key: str) -> object:
    """Normalize only retained archive path spelling before raw-row equality.

    The public full-facts reader records its container input spelling while the
    FILE receipt records the supplied product spelling.  Neither spelling is
    ABI metadata.  Every member, table, section and raw row remains exact.
    """
    result = copy.deepcopy(value)
    if artifact_key.endswith('static'):
        require(type(result) is list, f'FILE {artifact_key} archive facts differ')
        for member in result:
            require(type(member) is dict and type(member.get('archive')) is str and member['archive'],
                    f'FILE {artifact_key} archive path differs')
            member['archive'] = '<receipt-archive-path>'
    else:
        require(type(result) is dict, f'FILE {artifact_key} shared facts differ')
    return result


def _stdio_complete_facts_match(value: object, facts: Mapping[str, Any]) -> None:
    """Join the four raw FILE views to the public complete ELF facts once."""
    keys = {'candidate-static', 'reference-static', 'candidate-shared', 'reference-shared'}
    require(type(value) is dict and set(value) == keys
            and type(facts.get('facts')) is dict and keys <= set(facts['facts']),
            'FILE complete ELF facts roster differs')
    for key in sorted(keys):
        require(same(_normalized_stdio_complete_facts(value[key], key),
                     _normalized_stdio_complete_facts(facts['facts'][key], key)),
                f'FILE complete ELF facts differ: {key}')


def native_stdio_alias_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                               measurement: Mapping[str, Any], paths: Mapping[str, Path],
                               source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay and bind the finite current-source FILE alias receipt once.

    The owner reader retains raw archive/shared observations and runtime
    transcripts.  Selection consumes that public replay only for the fixed
    alias/body domains and protected-body controls; it neither infers another
    stdio provider nor treats this component as general stdio qualification.
    """
    if report_path is None:
        return None
    stdio_alias_evidence = _stdio_alias_reader()
    require(Path(stdio_alias_evidence.ROOT) == ROOT
            and Path(stdio_alias_evidence.__file__).resolve().parent == MODULE_DIR,
            'FILE alias reader belongs to a different checkout')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = stdio_alias_evidence.validate_report(ROOT, report_path)
    except (KeyError, TypeError, ValueError, OSError, stdio_alias_evidence.StdioAliasEvidenceError) as error:
        raise SelectionError(f'FILE alias component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'FILE alias report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'FILE alias')
    measurement_reports = _measurement_report_bindings(measurement, 'FILE alias')
    report = exact(report, {
        'schema', 'status', 'image', 'contract', 'collector_source', 'collector_files', 'selected_files',
        'inputs_before', 'inputs_after', 'oracle', 'oracle_static', 'tools', 'commands', 'observations', 'files',
    }, 'FILE alias reader report')
    require(report['schema'] == stdio_alias_evidence.SCHEMA
            and same(report['status'], stdio_alias_evidence.STATUS)
            and same(report['contract'], stdio_alias_evidence.contract(ROOT)),
            'FILE alias reader contract or status differs')
    require(same(report['collector_source'], {
        'revision': source['revision'], 'content_sha256': source['content_sha256'],
    }), 'FILE alias collector source differs from selection')
    collector_files = _stdio_source_snapshot(
        report['collector_files'], stdio_alias_evidence.COLLECTOR_SOURCES, 'FILE collector',
    )
    selected_files = _stdio_source_snapshot(
        report['selected_files'], stdio_alias_evidence.RUNTIME_SOURCES, 'FILE selected runtime',
    )
    inputs = exact(report['inputs_before'], {
        'selected_source', 'producer_commands', 'preparation', 'historical_facts', 'static_preparation',
        'dynamic_product', 'static_tree', 'dynamic_tree', 'state',
    }, 'FILE alias input account')
    require(same(report['inputs_after'], inputs), 'FILE alias input account changed')
    require(same(inputs['selected_source'], {
        'revision': source['revision'], 'content_sha256': source['content_sha256'],
    }), 'FILE alias product source differs from selection')
    current = _stdio_alias_identities(paths)
    _require_stdio_receipt_path(inputs['preparation'], paths['static_preparation'], 'FILE static preparation')
    _require_stdio_receipt_identity(inputs['preparation'], measurement_reports['static_preparation'],
                                    'FILE static preparation')
    _require_stdio_receipt_path(inputs['historical_facts'], paths['elf_report'], 'FILE complete ELF facts')
    _require_stdio_receipt_identity(inputs['historical_facts'], measurement_reports['elf_report'],
                                    'FILE complete ELF facts')
    static_product = exact(inputs['static_preparation'], {'primary'}, 'FILE static product')
    static_primary = exact(static_product['primary'], {'path', 'manifest'}, 'FILE static product primary')
    _require_stdio_product_root(static_primary['path'], paths['static_product'], 'FILE static product')
    _require_stdio_receipt_identity(static_primary['manifest'], current['static_manifest'], 'FILE static manifest')
    dynamic_product = exact(inputs['dynamic_product'], {'path', 'manifest'}, 'FILE dynamic product')
    _require_stdio_product_root(dynamic_product['path'], paths['dynamic_product'], 'FILE dynamic product')
    _require_stdio_receipt_identity(dynamic_product['manifest'], current['dynamic_manifest'], 'FILE dynamic manifest')
    _require_stdio_receipt_identity(inputs['state'], current['dynamic_state'], 'FILE dynamic state')
    for tree, relative, name in (
        (inputs['static_tree'], 'share/crabc/manifest.json', 'static_manifest'),
        (inputs['static_tree'], 'share/crabc/libc-static.provenance.json', 'static_provenance'),
        (inputs['static_tree'], 'bin/crabc-cc', 'static_driver'),
        (inputs['static_tree'], 'usr/lib/libc.a', 'static_libc'),
        (inputs['dynamic_tree'], 'share/crabc/manifest.json', 'dynamic_manifest'),
        (inputs['dynamic_tree'], 'share/crabc/dynamic-product-state.json', 'dynamic_state'),
        (inputs['dynamic_tree'], 'share/crabc/libc-shared.provenance.json', 'dynamic_shared_provenance'),
        (inputs['dynamic_tree'], 'bin/crabc-cc-dynamic', 'dynamic_driver'),
        (inputs['dynamic_tree'], 'usr/lib/libc.so', 'dynamic_libc'),
        (inputs['dynamic_tree'], 'lib/ld-crabc-x86_64.so.1', 'dynamic_loader'),
    ):
        _require_stdio_tree_file(tree, relative, current[name], f'FILE {name}')
    _runtime_facts_match_selected_products(
        facts, current, label='FILE alias',
        artifacts=(('static_libc', 'candidate-static'), ('dynamic_libc', 'candidate-shared')),
    )
    observations = exact(report['observations'], {
        'complete_elf_facts', 'aliases', 'objects', 'executables', 'candidate_links', 'execution_roots', 'runtime_labels',
    }, 'FILE alias observations')
    _stdio_complete_facts_match(observations['complete_elf_facts'], facts)
    aliases = observations['aliases']
    artifact_keys = {'candidate-static', 'reference-static', 'candidate-shared', 'reference-shared'}
    require(type(aliases) is dict and set(aliases) == artifact_keys
            and all(type(value) is dict and set(value) == {'aliases', 'protected'} for value in aliases.values()),
            'FILE alias observation roster differs')
    require(type(observations['candidate_links']) is dict
            and set(observations['candidate_links']) == {
                name for name in stdio_alias_evidence.binaries() if name.startswith('candidate-')
            }
            and observations['runtime_labels'] == [row['label'] for row in stdio_alias_evidence.runtime_cells()],
            'FILE alias runtime/link roster differs')
    selected_products = {
        name: copy.deepcopy(current[name]) for name in (
            'static_manifest', 'static_driver', 'static_libc', 'static_provenance', 'dynamic_manifest',
            'dynamic_state', 'dynamic_driver', 'dynamic_libc', 'dynamic_loader', 'dynamic_shared_provenance',
        )
    }
    source_inputs = {name: file_identity(ROOT / name) for name in _stdio_alias_source_files()}
    return {
        'status': 'stdio-alias-observed-with-boundaries',
        'reader': file_identity(Path(stdio_alias_evidence.__file__)),
        'contract': file_identity(ROOT / 'compat/x86_64/owned-stdio-alias-receipt.toml'),
        'report': before,
        'source': copy.deepcopy(source),
        'source_inputs': source_inputs,
        'products': selected_products,
        'measurement_reports': measurement_reports,
        'account': {
            'aliases': copy.deepcopy(aliases),
            'runtime_labels': list(observations['runtime_labels']),
            'candidate_link_labels': sorted(observations['candidate_links']),
        },
        'limits': list(STDIO_ALIAS_LIMITS),
    }


def _crt_startup_identity_names(reader: Any) -> tuple[str, ...]:
    """Derive, rather than repeat, the closed startup spelling roster."""
    names = tuple(reader.NAMES)
    contract = reader.contract(ROOT)
    require(len(names) == 12 and len(names) == len(set(names))
            and same(list(names), contract['identities'])
            and contract['record_sizes'] == {
                'owned_handoff': 32,
                'conventional_snapshot': 88,
            }
            and contract['descriptor_import_required'] is False
            and contract['descriptor_handoff'] == {
                'name': '__crabc_x86_64_loader_tls_runtime_v1',
                'source_artifact': 'dynamic-crabc-dynamic-attach.o',
                'source_relocation': {'kind': 9, 'addend': -4, 'symbol_type': '0', 'binding': 'WEAK',
                                      'visibility': 'DEFAULT', 'symbol_section': 0, 'symbol_value': 0},
                'main_slot_relocation': {'kind': 6, 'addend': 0, 'symbol_type': '0', 'binding': 'WEAK',
                                         'visibility': 'DEFAULT', 'symbol_section': 0, 'symbol_value': 0},
                'owned_modes': ['owned-pie', 'owned-non-pie'],
                'geometry': {'size_bytes': 72, 'alignment_bytes': 8, 'magic': '43524142435f5451',
                             'version': 1, 'process_mode': 2, 'owner': 1, 'ready_state': 2, 'generation': 1},
            },
            'CRT startup owner contract differs')
    return names


def _crt_startup_product_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Return only the installed bytes which the CRT receipt actually owns."""
    static = paths['static_product'] / 'usr/lib'
    dynamic = paths['dynamic_product']
    records = {
        'candidate-static': static / 'libc.a',
        'candidate-shared': dynamic / 'usr/lib/libc.so',
        'candidate-loader': dynamic / 'lib/ld-crabc-x86_64.so.1',
        'static-crt1.o': static / 'crt1.o',
        'static-Scrt1.o': static / 'Scrt1.o',
        'static-rcrt1.o': static / 'rcrt1.o',
        'dynamic-crt1.o': dynamic / 'usr/lib/crt1.o',
        'dynamic-Scrt1.o': dynamic / 'usr/lib/Scrt1.o',
        'dynamic-crabc-dynamic-attach.o': dynamic / 'usr/lib/crabc-dynamic-attach.o',
    }
    return {name: file_identity(path) for name, path in records.items()}


def _crt_startup_relocation_artifacts(products: Mapping[str, Any]) -> set[str]:
    """Keep the owner's executable/DSO/object relocation boundary finite.

    The startup owner parses relocation tables for each exact startup product
    except the selected static archive. Its archive members remain in the
    complete placement and named-row proof, where their member locations are
    meaningful, but an archive itself has no single relocation table.
    """
    artifact_kinds = {artifact.key: artifact.kind for artifact in elf_facts.ARTIFACTS}
    require(set(products) <= set(artifact_kinds)
            and {key for key in products if artifact_kinds[key] == 'archive'} == {'candidate-static'},
            'CRT startup product archive boundary differs')
    return {key for key in products if artifact_kinds[key] != 'archive'}


def _crt_startup_cohort_inputs(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Retain the three mode-bearing metadata inputs beside CRT ELF ownership.

    The startup receipt consumes these product descriptors to admit its nine
    installed ELF artifacts. They remain a separate cohort seal: they are not
    extra startup symbols or CRT product authority.
    """
    records = {
        'static_manifest': paths['static_product'] / 'share/crabc/manifest.json',
        'dynamic_manifest': paths['dynamic_product'] / 'share/crabc/manifest.json',
        'dynamic_state': paths['dynamic_product'] / inventory.DYNAMIC_STATE_RELATIVE,
    }
    return {name: file_identity(path) for name, path in records.items()}


def _crt_startup_complete_facts_match(value: object, facts: Mapping[str, Any],
                                      products: Mapping[str, Any]) -> None:
    """Bind all component-owned raw ELF views to the public replay once."""
    require(type(value) is dict and set(products) <= set(value)
            and type(facts.get('facts')) is dict and set(products) <= set(facts['facts']),
            'CRT startup complete ELF facts roster differs')
    for artifact_key in sorted(products):
        require(same(_normalized_stdio_complete_facts(value[artifact_key], artifact_key),
                     _normalized_stdio_complete_facts(facts['facts'][artifact_key], artifact_key)),
                f'CRT startup complete ELF facts differ: {artifact_key}')


def _crt_startup_observed_rows(value: object, names: Sequence[str],
                               products: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize the owner reader's finite named-row projection for joining."""
    require(type(value) is dict and set(value) == set(products),
            'CRT startup named product roster differs')
    result: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for artifact_key in sorted(products):
        rows = value[artifact_key]
        require(type(rows) is list, f'CRT startup named rows differ: {artifact_key}')
        for observed in rows:
            row = exact(observed, {
                'member', 'member_index', 'member_occurrence', 'row', 'section', 'table_section_index',
            }, f'CRT startup named row {artifact_key}')
            symbol = row['row']
            require(type(symbol) is dict and symbol.get('name') in names,
                    f'CRT startup observation names an unowned identity: {symbol.get("name")}')
            require(type(row['table_section_index']) is int
                    and (row['member_index'] is None or type(row['member_index']) is int)
                    and (row['member_occurrence'] is None or type(row['member_occurrence']) is int)
                    and (row['member'] is None or type(row['member']) is str),
                    'CRT startup named-row location differs')
            key = (artifact_key, row['member_index'], row['member_occurrence'],
                   row['table_section_index'], symbol.get('row_index'))
            require(key not in seen, 'duplicate CRT startup named-row observation')
            seen.add(key)
            result.append({'artifact_key': artifact_key, **copy.deepcopy(row)})
    require({row['row']['name'] for row in result} == set(names),
            'CRT startup observation omits an owner-declared identity')
    return result


def native_crt_startup_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                               measurement: Mapping[str, Any], paths: Mapping[str, Path],
                               source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay the CRT owner before joining its twelve exact selected rows.

    The receipt is a component-level native execution proof.  This adapter
    requires its replay to bind the current selected source and product cohort,
    then passes only its finite ELF occurrence projection to accounting.  A
    historical receipt with byte-identical runtime files but an earlier source
    revision therefore cannot waive a fresh product collection.
    """
    if report_path is None:
        return None
    reader = _crt_startup_reader()
    require(Path(reader.ROOT) == ROOT and Path(reader.__file__).resolve().parent == MODULE_DIR,
            'CRT startup reader belongs to a different checkout')
    names = _crt_startup_identity_names(reader)
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = reader.validate_report(ROOT, report_path)
    except (KeyError, TypeError, ValueError, OSError, reader.StartupEvidenceError) as error:
        raise SelectionError(f'CRT startup component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'CRT startup report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    _measurement_source_matches(source, measurement, 'CRT startup')
    measurement_reports = _measurement_report_bindings(measurement, 'CRT startup')
    report = exact(report, {
        'schema', 'status', 'image', 'contract', 'collector_source', 'collector_files', 'selected_files',
        'inputs_before', 'inputs_after', 'oracle', 'oracle_static', 'oracle_crt', 'tools', 'commands',
        'observations', 'files',
    }, 'CRT startup reader report')
    require(report['schema'] == reader.SCHEMA and same(report['status'], reader.STATUS)
            and same(report['contract'], reader.contract(ROOT)),
            'CRT startup reader contract or status differs')
    source_pair = {'revision': source['revision'], 'content_sha256': source['content_sha256']}
    require(same(report['collector_source'], source_pair),
            'CRT startup collector source differs from selection')
    _stdio_source_snapshot(report['collector_files'], reader.COLLECTOR_SOURCES, 'CRT startup collector')
    _stdio_source_snapshot(report['selected_files'], reader.RUNTIME_SOURCES, 'CRT startup selected runtime')
    inputs = exact(report['inputs_before'], {
        'selected_source', 'producer_commands', 'preparation', 'historical_facts', 'static_preparation',
        'dynamic_product', 'static_tree', 'dynamic_tree', 'state', 'startup_artifacts',
    }, 'CRT startup input account')
    require(same(report['inputs_after'], inputs) and same(inputs['selected_source'], source_pair),
            'CRT startup source/product input account changed')
    products = _crt_startup_product_identities(paths)
    cohort_inputs = _crt_startup_cohort_inputs(paths)
    startup_artifacts = inputs['startup_artifacts']
    require(type(startup_artifacts) is dict and set(startup_artifacts) == set(products),
            'CRT startup installed artifact roster differs')
    for name in sorted(products):
        _require_stdio_receipt_identity(startup_artifacts[name], products[name],
                                        f'CRT startup {name}')
    _require_stdio_receipt_path(inputs['preparation'], paths['static_preparation'],
                                'CRT startup static preparation')
    _require_stdio_receipt_identity(inputs['preparation'], measurement_reports['static_preparation'],
                                    'CRT startup static preparation')
    _require_stdio_receipt_path(inputs['historical_facts'], paths['elf_report'],
                                'CRT startup complete ELF facts')
    _require_stdio_receipt_identity(inputs['historical_facts'], measurement_reports['elf_report'],
                                    'CRT startup complete ELF facts')
    static_product = exact(inputs['static_preparation'], {'primary'}, 'CRT startup static product')
    static_primary = exact(static_product['primary'], {'path', 'manifest'}, 'CRT startup static product primary')
    _require_stdio_product_root(static_primary['path'], paths['static_product'], 'CRT startup static product')
    _require_stdio_receipt_identity(static_primary['manifest'], cohort_inputs['static_manifest'],
                                    'CRT startup static manifest')
    dynamic_product = exact(inputs['dynamic_product'], {'path', 'manifest'}, 'CRT startup dynamic product')
    _require_stdio_product_root(dynamic_product['path'], paths['dynamic_product'], 'CRT startup dynamic product')
    _require_stdio_receipt_identity(dynamic_product['manifest'], cohort_inputs['dynamic_manifest'],
                                    'CRT startup dynamic manifest')
    _require_stdio_receipt_identity(inputs['state'], cohort_inputs['dynamic_state'],
                                    'CRT startup dynamic state')
    _runtime_facts_match_selected_products(
        facts, products, label='CRT startup',
        artifacts=tuple((name, name) for name in products),
    )
    observations = exact(report['observations'], {
        'complete_elf_facts', 'product_placements', 'product_relocations', 'executables', 'roots',
        'runtime_labels', 'limits', 'descriptor_handoff',
    }, 'CRT startup observations')
    _crt_startup_complete_facts_match(observations['complete_elf_facts'], facts, products)
    placements = observations['product_placements']
    require(type(placements) is dict and 'all_named_rows' in placements,
            'CRT startup named placement observations differ')
    observed_rows = _crt_startup_observed_rows(placements['all_named_rows'], names, products)
    relocations = observations['product_relocations']
    require(type(relocations) is dict
            and set(relocations) == _crt_startup_relocation_artifacts(products)
            and all(type(rows) is list for rows in relocations.values()),
            'CRT startup relocation observation roster differs')
    descriptor_handoff = reader.descriptor_handoff(relocations, observations['executables'])
    require(same(observations['descriptor_handoff'], descriptor_handoff),
            'CRT startup descriptor handoff observation differs')
    source_inputs = {name: file_identity(ROOT / name) for name in _crt_startup_source_files()}
    return {
        'status': 'crt-startup-observed-with-boundaries',
        'reader': file_identity(Path(reader.__file__)),
        'contract': file_identity(ROOT / 'compat/x86_64/installed-crt-startup.toml'),
        'report': before,
        'source': copy.deepcopy(source),
        'source_inputs': source_inputs,
        'products': {name: copy.deepcopy(products[name]) for name in sorted(products)},
        'cohort_inputs': {name: copy.deepcopy(cohort_inputs[name]) for name in sorted(cohort_inputs)},
        'measurement_reports': measurement_reports,
        'account': {
            'identity_names': list(names),
            'occurrences': observed_rows,
            'runtime_labels': list(observations['runtime_labels']),
            'descriptor_handoff': copy.deepcopy(descriptor_handoff),
        },
        'limits': list(CRT_STARTUP_LIMITS),
    }


def _utmpx_product_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Return the finite current inputs sealed by the utmpx receipt.

    This is the runner's actual static/dynamic link surface, not a product-tree
    prefix.  The owning reader validates its retained complete trees; this
    selector roster makes each concrete current byte and mode available both to
    direct attachment and to the transaction-final recheck.
    """
    records = {
        **_runtime_attachment_identities(paths),
        'static_preparation': file_identity(paths['static_preparation']),
        'dynamic_producer_tools': file_identity(paths['dynamic_product'] / 'share/crabc/producer-tools.json'),
    }
    for name, relative in UTMPX_STATIC_LINK_INPUTS:
        records.setdefault(name, file_identity(paths['static_product'] / relative))
    for name, relative in UTMPX_DYNAMIC_LINK_INPUTS:
        records.setdefault(name, file_identity(paths['dynamic_product'] / relative))
    return records


def _utmpx_retained_inputs(report_path: Path, report: Mapping[str, Any],
                           products: Mapping[str, Any],
                           link_input_modes: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Bind every selected link input to the reader-validated retained product.

    ``owned_utmpx_receipt.validate_report`` owns the complete retained-tree,
    provenance, command and runtime replay.  This join follows its finite
    manifests to prevent a current CRT, builtins, attach object, state, or
    driver byte from being accepted only because a copied tree was valid once.
    """
    roots = exact(report['products'], {'static', 'dynamic'}, 'utmpx retained product roots')
    workspace = physical_work_path(report_path.parent / 'workspace', directory=True)
    expected = {
        'static': {
            'root': '.work/utmpx-receipt/inputs/static',
            'manifest_files': lambda manifest: manifest.get('installed', {}).get('files')
                if type(manifest.get('installed')) is dict else None,
            'records': (
                ('static_manifest', 'share/crabc/manifest.json'),
                ('static_driver', 'bin/crabc-cc'),
                *UTMPX_STATIC_LINK_INPUTS,
            ),
        },
        'dynamic': {
            'root': '.work/utmpx-receipt/inputs/dynamic',
            'manifest_files': lambda manifest: manifest.get('files'),
            'records': (
                ('dynamic_manifest', 'share/crabc/manifest.json'),
                ('dynamic_state', 'share/crabc/dynamic-product-state.json'),
                ('dynamic_driver', 'bin/crabc-cc-dynamic'),
                ('dynamic_loader', 'lib/ld-crabc-x86_64.so.1'),
                ('dynamic_shared_provenance', 'share/crabc/libc-shared.provenance.json'),
                ('dynamic_producer_tools', 'share/crabc/producer-tools.json'),
                *UTMPX_DYNAMIC_LINK_INPUTS,
            ),
        },
    }
    retained: dict[str, dict[str, Any]] = {}
    snapshots: list[tuple[Path, dict[str, Any]]] = []
    for family, contract in expected.items():
        root = exact(roots[family], {'workspace_path', 'retained_tree'}, f'utmpx {family} product')
        require(root['workspace_path'] == contract['root'] and type(root['retained_tree']) is dict,
                f'utmpx {family} retained product root differs')
        retained_root = physical_work_path(workspace / contract['root'], directory=True)
        manifest_path = retained_root / 'share/crabc/manifest.json'
        require(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.resolve() == manifest_path,
                f'utmpx retained {family} manifest is not physical')
        manifest_identity = file_identity(manifest_path)
        files = contract['manifest_files'](read_json(manifest_path))
        require(type(files) is dict, f'utmpx retained {family} manifest file roster differs')
        link_records = UTMPX_STATIC_LINK_INPUTS if family == 'static' else UTMPX_DYNAMIC_LINK_INPUTS
        modes = exact(link_input_modes.get(family), {relative for _name, relative in link_records},
                      f'utmpx retained {family} source mode roster')
        for name, relative in contract['records']:
            path = retained_root / relative
            require(path.is_file() and not path.is_symlink() and path.resolve() == path,
                    f'utmpx retained {name} is not physical')
            value = file_identity(path)
            entry = root['retained_tree'].get(relative)
            require(type(entry) is dict and entry.get('kind') == 'file'
                    and entry.get('sha256') == value['sha256'] and entry.get('size') == value['size']
                    and entry.get('mode') == value['mode'],
                    f'utmpx retained {name} differs from reader-sealed tree')
            if name != 'static_manifest' and name != 'dynamic_manifest':
                require(files.get(relative) == value['sha256'],
                        f'utmpx {name} is not sealed by retained {family} manifest')
            if relative in modes:
                require(value['mode'] == modes[relative],
                        f'utmpx retained {name} source-bound mode differs')
            retained[name] = value
            snapshots.append((path, value))
        require(same(manifest_identity, retained['static_manifest' if family == 'static' else 'dynamic_manifest']),
                f'utmpx retained {family} manifest identity differs')
    expected_names = set(products) - {'static_preparation'}
    require(set(retained) == expected_names, 'utmpx retained product input roster differs')
    require(all(same(value, file_identity(path)) for path, value in snapshots),
            'utmpx retained product bytes changed during selector binding')
    return retained


def _utmpx_projection(reader: Any, value: object) -> dict[str, Any]:
    projection = exact(value, {
        'selected_aliases', 'component_complete', 'family_complete', 'runtime_qualified', 'public_support',
        'linkages', 'runtime_streams',
    }, 'utmpx receipt projection')
    aliases = [[alias, target] for alias, target in reader.ALIASES]
    require(projection['selected_aliases'] == aliases and projection['component_complete'] is True
            and projection['family_complete'] is False and projection['runtime_qualified'] is False
            and projection['public_support'] is False
            and projection['linkages'] == ['non-pie', 'pie', 'static', 'static-pie']
            and projection['runtime_streams'] == [
                'non-pie-direct', 'non-pie-kernel', 'oracle', 'pie-direct', 'pie-kernel', 'static', 'static-pie',
            ], 'utmpx receipt projection differs')
    require(len(aliases) == 8 and len({name for pair in aliases for name in pair}) == 16,
            'utmpx finite alias/provider cardinality differs')
    return copy.deepcopy(projection)


def _utmpx_symbol_summary(reader: Any, value: object) -> dict[str, Any]:
    symbols = exact(value, {'headers', 'archive', 'shared', 'executables', 'dynamic_imports'}, 'utmpx symbol summary')
    names = {*reader.STRONG, *reader.WEAK}
    require(len(names) == 16 and set(reader.STRONG).isdisjoint(reader.WEAK),
            'utmpx reader provider roster differs')
    expected_archive = {name: ('T' if name in reader.STRONG else 'W') for name in names}
    expected_shared = {name: ('GLOBAL' if name in reader.STRONG else 'WEAK') for name in names}
    require(symbols['archive'] == expected_archive and symbols['shared'] == expected_shared,
            'utmpx provider binding summary differs')
    require(type(symbols['executables']) is dict and set(symbols['executables']) == {'static', 'static-pie'}
            and all(symbols['executables'][mode] == expected_archive for mode in symbols['executables']),
            'utmpx static function proof differs')
    expected_imports = {name: 'GLOBAL DEFAULT UND' for name in names}
    require(type(symbols['dynamic_imports']) is dict and set(symbols['dynamic_imports']) == {'pie', 'non-pie'}
            and all(symbols['dynamic_imports'][mode] == expected_imports for mode in symbols['dynamic_imports']),
            'utmpx dynamic import proof differs')
    return copy.deepcopy(symbols)


def native_utmpx_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                         measurement: Mapping[str, Any], paths: Mapping[str, Path],
                         source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Bind the owner-replayed finite utmpx receipt to this selected cohort."""
    if report_path is None:
        return None
    reader = _utmpx_reader()
    require(Path(reader.ROOT) == ROOT and Path(reader.__file__).resolve().parent == MODULE_DIR,
            'utmpx reader belongs to a different checkout')
    require(reader.SCHEMA == 'crabc.x86_64-owned-utmpx-receipt/v3',
            'utmpx reader is not the current v3 receipt boundary')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = reader.validate_report(report_path)
    except (KeyError, TypeError, ValueError, OSError, reader.ReceiptError) as error:
        raise SelectionError(f'utmpx component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'utmpx report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'utmpx selection source')
    require(source['clean'] is True, 'utmpx selection source is not clean')
    _measurement_source_matches(source, measurement, 'utmpx')
    measurement_reports = _measurement_report_bindings(measurement, 'utmpx')
    report = exact(report, {
        'schema', 'image', 'source_tree', 'sources', 'products', 'product_cohort', 'link_input_modes', 'tools', 'commands',
        'symbols', 'runtime', 'links', 'projection',
    }, 'utmpx reader report')
    require(report['schema'] == reader.SCHEMA and type(report['image']) is dict
            and report['image'].get('id') == reader.PINNED_IMAGE,
            'utmpx reader schema or pinned image differs')
    source_tree = exact(report['source_tree'], {'revision', 'entries'}, 'utmpx receipt source Git tree')
    require(source_tree['revision'] == source['revision'] and type(source_tree['entries']) is dict
            and set(source_tree['entries']) == set(reader.SOURCES),
            'utmpx receipt source Git tree differs from selection')
    sources = report['sources']
    require(type(sources) is dict and set(sources) == set(reader.SOURCES), 'utmpx receipt source roster differs')
    for name in reader.SOURCES:
        _require_same_identity_payload(sources[name], file_identity(ROOT / name), f'utmpx source {name}')
    cohort = exact(report['product_cohort'], {
        'source', 'static_preparation', 'static_source_before', 'static_source_after', 'static_manifest',
        'dynamic_manifest', 'dynamic_state',
    }, 'utmpx receipt product cohort')
    require(same(cohort['source'], {'revision': source['revision'], 'content_sha256': source['content_sha256']}),
            'utmpx receipt selected product source differs')
    source_link_input_modes = getattr(reader, 'LINK_INPUT_MODES', None)
    expected_link_input_modes = product_evidence.link_input_mode_projection()
    require(type(source_link_input_modes) is dict and same(source_link_input_modes, expected_link_input_modes)
            and same(report['link_input_modes'], expected_link_input_modes),
            'utmpx source-bound link-input mode policy differs')
    link_input_modes = exact(report['link_input_modes'], {'static', 'dynamic'},
                             'utmpx source-bound link-input modes')
    products = _utmpx_product_identities(paths)
    for family, records in (('static', UTMPX_STATIC_LINK_INPUTS), ('dynamic', UTMPX_DYNAMIC_LINK_INPUTS)):
        modes = exact(link_input_modes[family], {relative for _name, relative in records},
                      f'utmpx {family} source mode roster')
        for name, relative in records:
            require(products[name]['mode'] == modes[relative],
                    f'utmpx {name} source-bound mode differs')
    _require_same_identity_payload(cohort['static_preparation'], products['static_preparation'],
                                   'utmpx static preparation')
    for name in ('static_manifest', 'dynamic_manifest', 'dynamic_state'):
        _require_same_identity_payload(cohort[name], products[name], f'utmpx {name.replace("_", " ")}')
    retained = _utmpx_retained_inputs(report_path, report, products, link_input_modes)
    for name, value in retained.items():
        _require_same_identity_payload(value, products[name], f'utmpx {name}')
    facts_artifacts = facts.get('artifacts')
    require(type(facts_artifacts) is dict, 'utmpx public ELF artifact roster differs')
    for artifact, name in (('candidate-static', 'static_libc'), ('candidate-shared', 'dynamic_libc'),
                           ('candidate-loader', 'dynamic_loader')):
        value = facts_artifacts.get(artifact)
        require(type(value) is dict and 'identity' in value, f'utmpx public ELF artifact differs: {artifact}')
        _require_same_identity_payload(value['identity'], products[name], f'utmpx public ELF {artifact}')
    projection = _utmpx_projection(reader, report['projection'])
    symbols = _utmpx_symbol_summary(reader, report['symbols'])
    require(type(report['links']) is dict and set(report['links']) == {'static', 'static-pie', 'pie', 'non-pie'}
            and type(report['runtime']) is dict
            and set(report['runtime']) == set(projection['runtime_streams']),
            'utmpx reader link/runtime roster differs')
    source_inputs = {name: file_identity(ROOT / name) for name in _utmpx_source_files()}
    return {
        'status': 'utmpx-observed-with-boundaries', 'reader': file_identity(Path(reader.__file__)),
        'report': before, 'source': copy.deepcopy(source), 'source_inputs': source_inputs,
        'products': {name: copy.deepcopy(products[name]) for name in sorted(products)},
        'measurement_reports': measurement_reports, 'projection': projection, 'symbols': symbols,
        'limits': list(UTMPX_LIMITS),
    }


def _utmpx_named_rows(occurrences: Mapping[int, Mapping[str, Any]], name: str) -> list[dict[str, Any]]:
    """Restrict logical joins to a finite named scope without dropping raw rows."""
    return [dict(value) for value in occurrences.values()
            if type(value.get('row')) is dict and value['row'].get('name') == name]


def _utmpx_one_row(rows: Sequence[Mapping[str, Any]], *, artifact: str, table: str,
                   binding: str, description: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get('artifact_key') == artifact and row.get('table') == table
               and row.get('role') == 'definition' and row.get('row', {}).get('type') == 'FUNC'
               and row['row'].get('binding') == binding and row['row'].get('visibility') == 'DEFAULT']
    require(len(matches) == 1, f'{description} exact candidate occurrence differs')
    return dict(matches[0])


def attach_native_utmpx(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Discharge only the eight already-selected utmpx feature-alias reasons."""
    if companion is None:
        return []
    reader = _utmpx_reader()
    companion = exact(companion, {
        'status', 'reader', 'report', 'source', 'source_inputs', 'products', 'measurement_reports',
        'projection', 'symbols', 'limits',
    }, 'utmpx companion')
    require(companion['status'] == 'utmpx-observed-with-boundaries' and companion['limits'] == UTMPX_LIMITS
            and same(companion['projection'], _utmpx_projection(reader, companion['projection']))
            and same(companion['symbols'], _utmpx_symbol_summary(reader, companion['symbols']))
            and same(companion['source_inputs'], {name: file_identity(ROOT / name) for name in _utmpx_source_files()}),
            'utmpx companion boundary differs')
    records, _placements, occurrences = _accounting_indexes(accounting, description='utmpx attachment')
    occurrence_count = len(occurrences)
    aliases = tuple((str(alias), str(target)) for alias, target in reader.ALIASES)
    providers = {*reader.STRONG, *reader.WEAK}
    expected_indices: set[int] = set()
    joins: list[dict[str, Any]] = []
    for name in sorted(providers):
        binding = 'GLOBAL' if name in reader.STRONG else 'WEAK'
        rows = _utmpx_named_rows(occurrences, name)
        static = _utmpx_one_row(rows, artifact='candidate-static', table='.symtab', binding=binding,
                                 description=f'utmpx provider {name} static')
        shared_dyn = _utmpx_one_row(rows, artifact='candidate-shared', table='.dynsym', binding=binding,
                                     description=f'utmpx provider {name} shared dynsym')
        shared = _utmpx_one_row(rows, artifact='candidate-shared', table='.symtab', binding=binding,
                                 description=f'utmpx provider {name} shared symtab')
        expected_indices.update((static['index'], shared_dyn['index'], shared['index']))
    actual_indices = {row['index'] for row in occurrences.values()
                      if row.get('artifact_key') in {'candidate-static', 'candidate-shared'}
                      and type(row.get('row')) is dict and row['row'].get('name') in providers}
    require(actual_indices == expected_indices, 'utmpx candidate provider occurrence roster differs')
    observations = accounting.get('function_alias_observations')
    require(type(observations) is list, 'utmpx source-selected alias observations differ')
    for alias, target in aliases:
        record = records.get((alias, None, False))
        require(record is not None and record.get('selection', {}).get('disposition') == 'public-provider',
                f'utmpx selected public alias differs: {alias}')
        feature = record.get('function_alias_requirements')
        require(type(feature) is list and len(feature) == 1
                and feature[0] == {'name': alias, 'target': target, 'binding': 'weak-same-address',
                                   'owner': 'x86-owned-static-runtime'},
                f'utmpx selected feature alias differs: {alias}')
        alias_static = _utmpx_one_row(_utmpx_named_rows(occurrences, alias), artifact='candidate-static',
                                       table='.symtab', binding='WEAK', description=f'utmpx alias {alias} static')
        alias_shared = _utmpx_one_row(_utmpx_named_rows(occurrences, alias), artifact='candidate-shared',
                                       table='.symtab', binding='WEAK', description=f'utmpx alias {alias} shared')
        target_binding = 'GLOBAL' if target in reader.STRONG else 'WEAK'
        target_static = _utmpx_one_row(_utmpx_named_rows(occurrences, target), artifact='candidate-static',
                                        table='.symtab', binding=target_binding,
                                        description=f'utmpx target {target} static')
        target_shared = _utmpx_one_row(_utmpx_named_rows(occurrences, target), artifact='candidate-shared',
                                        table='.symtab', binding=target_binding,
                                        description=f'utmpx target {target} shared')
        require(same_definition_domain(alias_static, target_static)
                and same_definition_domain(alias_shared, target_shared),
                f'utmpx alias definition domain differs: {alias}')
        expected_observation = next((row for row in observations
                                     if row.get('identity') == record['identity'] and row.get('artifact_key') == 'candidate-static'
                                     and row.get('target') == identity(target) and row.get('feature_contract') == feature[0]), None)
        require(type(expected_observation) is dict
                and expected_observation.get('same_domain_pairs') == [[alias_static['index'], target_static['index']]],
                f'utmpx selected feature archive observation differs: {alias}')
        _remove_identity_requirements(accounting, record, (UTMPX_ALIAS_RECEIPT_REQUIREMENT,),
                                      description=f'utmpx alias {alias}')
        joins.append({
            'alias': alias, 'target': target,
            'static_alias_occurrence_index': alias_static['index'],
            'shared_alias_occurrence_index': alias_shared['index'],
            'static_target_occurrence_index': target_static['index'],
            'shared_target_occurrence_index': target_shared['index'],
            'requirements_discharged': [UTMPX_ALIAS_RECEIPT_REQUIREMENT],
        })
    require(len(joins) == 8 and len(occurrences) == occurrence_count,
            'utmpx finite attachment cardinality differs')
    return [{'aliases': joins, 'requirements_discharged': [UTMPX_ALIAS_RECEIPT_REQUIREMENT],
             'complete_elf_occurrence_count': occurrence_count}]


def _syscall_receipt_input(value: object, description: str) -> dict[str, Any]:
    """Read one syscall receipt input without accepting its container path as ours."""
    record = exact(value, {'original', 'retained'}, description)
    original = _identity_payload(record['original'], description + ' original')
    retained = _identity_payload(record['retained'], description + ' retained')
    require(original == retained, f'{description} retained bytes differ from original')
    return original


def _require_syscall_receipt_input(value: object, current: object, description: str) -> None:
    require(_syscall_receipt_input(value, description) == _identity_payload(current, description + ' selected'),
            f'{description} differs from selected cohort')


def _syscall_source_snapshot(value: object, names: Sequence[str], description: str) -> dict[str, dict[str, Any]]:
    require(type(value) is dict and set(value) == set(names), f'{description} source roster differs')
    result: dict[str, dict[str, Any]] = {}
    for name in names:
        observed = _syscall_receipt_input(value[name], f'{description} {name}')
        current = _identity_payload(file_identity(ROOT / name), f'{description} current {name}')
        require(observed == current, f'{description} source differs: {name}')
        result[name] = observed
    return result


def _syscall_alias_projection(reader: Any) -> dict[str, Any]:
    projection = reader.component_projection()
    require(type(projection) is dict and set(projection) == {
        'aliases', 'alias_global_hidden', 'global_hidden', 'source_local', 'raw_private_body',
        'component_complete', 'family_completion', 'public_support',
    }, 'syscall alias selection projection fields differ')
    require(projection['aliases'] == [[name, body] for name, body in reader.ALIASES]
            and projection['alias_global_hidden'] == list(reader.ALIAS_GLOBAL_HIDDEN)
            and projection['global_hidden'] == list(reader.GLOBAL_HIDDEN)
            and projection['source_local'] == list(reader.LOCAL_BODIES)
            and projection['raw_private_body'] == '__libc_sigaction'
            and projection['component_complete'] is True
            and projection['family_completion'] is False
            and projection['public_support'] is False,
            'syscall alias selection projection differs')
    require(len(projection['aliases']) == 14 and len(projection['global_hidden']) == 13
            and len(projection['source_local']) == 2,
            'syscall alias finite projection cardinality differs')
    return copy.deepcopy(projection)


def _syscall_alias_product_identities(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    """Return the selected files consumed by the finite alias runner.

    The regular runtime records retain the receipts' direct inputs.  The
    static and dynamic driver receipts also consume the exact CRT, libc,
    builtins, and dynamic-attachment files below.  Keep that finite link
    roster here so direct attachment and the transaction recheck cannot omit
    an installed driver input merely because it was sealed through a retained
    product manifest rather than copied as a top-level reader input.
    """
    records = {
        **_runtime_attachment_identities(paths),
        'dynamic_producer_tools': file_identity(paths['dynamic_product'] / 'share/crabc/producer-tools.json'),
        'selected_dynamic_list': file_identity(ROOT / 'libc/src/c_abi/x86_64/owned_dynamic.list'),
    }
    for product_key, relative in SYSCALL_ALIAS_STATIC_LINK_INPUTS:
        records.setdefault(product_key, file_identity(paths['static_product'] / relative))
    for product_key, relative in SYSCALL_ALIAS_DYNAMIC_LINK_INPUTS:
        records.setdefault(product_key, file_identity(paths['dynamic_product'] / relative))
    return records


def _syscall_retained_link_inputs(report_path: Path, roots: Mapping[str, Any],
                                  inputs: Mapping[str, Any],
                                  link_input_modes: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Bind the exact static and dynamic driver inputs to retained manifests.

    The owning v2 reader validates complete retained product trees, including
    the static preparation/tree relationship and dynamic materialization
    state.  The selector still needs byte-and-mode identities for every
    concrete installed input consumed by the four static and four dynamic
    final-link receipts.  This closed roster retains no broad product-tree or
    prefix authority: it is the union of those driver input records, reusing
    the existing libc identities, plus the existing dynamic state recheck.
    """
    expected = {
        'static': {
            'manifest_input': 'static_manifest',
            'manifest_path': 'share/crabc/manifest.json',
            'manifest_files': lambda manifest: manifest.get('installed', {}).get('files')
            if type(manifest.get('installed')) is dict else None,
            'records': SYSCALL_ALIAS_STATIC_LINK_INPUTS,
            'extra_records': (),
        },
        'dynamic': {
            'manifest_input': 'dynamic_manifest',
            'manifest_path': 'share/crabc/manifest.json',
            'manifest_files': lambda manifest: manifest.get('files'),
            'records': SYSCALL_ALIAS_DYNAMIC_LINK_INPUTS,
            'extra_records': (('dynamic_state', 'share/crabc/dynamic-product-state.json'),),
        },
    }
    retained: dict[str, dict[str, Any]] = {}
    snapshots: list[tuple[Path, dict[str, Any]]] = []
    for product, contract in expected.items():
        root = exact(roots.get(product), {'original', 'retained'}, f'syscall alias {product} retained product')
        require(root['retained'] == 'products/' + product,
                f'syscall alias {product} retained tree path differs')
        retained_root = physical_work_path(report_path.parent / root['retained'], directory=True)

        def retained_file(relative: str, description: str) -> tuple[Path, dict[str, Any]]:
            value = retained_root / relative
            require(value.is_file() and not value.is_symlink() and value.resolve() == value,
                    f'{description} is not a physical retained product file')
            identity_value = file_identity(value)
            snapshots.append((value, identity_value))
            return value, identity_value

        manifest_path, retained_manifest = retained_file(
            contract['manifest_path'], f'syscall alias retained {product} manifest',
        )
        require(_syscall_receipt_input(inputs[contract['manifest_input']], f'syscall alias {product} manifest')
                == _identity_payload(retained_manifest, f'syscall alias retained {product} manifest'),
                f'syscall alias retained {product} manifest differs from its receipt input')
        manifest = read_json(manifest_path)
        files = contract['manifest_files'](manifest) if type(manifest) is dict else None
        require(type(files) is dict, f'syscall alias retained {product} manifest file roster differs')
        modes = exact(link_input_modes.get(product),
                      {relative for _name, relative in contract['records']},
                      f'syscall alias retained {product} source mode roster')
        for product_key, relative in (*contract['records'], *contract['extra_records']):
            display_name = 'dynamic state' if product_key == 'dynamic_state' else product_key
            _path, identity_value = retained_file(relative, f'syscall alias retained {display_name}')
            require(files.get(relative) == identity_value['sha256'],
                    f'syscall alias retained {display_name} is not sealed by its manifest')
            if product_key != 'dynamic_state':
                require(identity_value['mode'] == modes[relative],
                        f'syscall alias retained {display_name} source-bound mode differs')
            retained[product_key] = identity_value
    require(set(retained) == {
        *(name for name, _relative in SYSCALL_ALIAS_STATIC_LINK_INPUTS),
        *(name for name, _relative in SYSCALL_ALIAS_DYNAMIC_LINK_INPUTS),
        'dynamic_state',
    }, 'syscall alias retained link input roster differs')
    require(all(same(identity_value, file_identity(path)) for path, identity_value in snapshots),
            'syscall alias retained product tree changed during selector binding')
    return retained


def native_syscall_alias_adapter(report_path: Path | None, *, facts: Mapping[str, Any],
                                 measurement: Mapping[str, Any], paths: Mapping[str, Path],
                                 source: Mapping[str, Any]) -> dict[str, Any] | None:
    """Replay and bind the finite v3 syscall alias receipt to one selected cohort.

    This attachment has no provider-selection authority.  The owning reader
    proves the alias and runtime boundary; the selector only binds that proof
    to its current product, source, and complete public ELF observations.
    """
    if report_path is None:
        return None
    reader = _syscall_alias_reader()
    require(Path(reader.ROOT) == ROOT and Path(reader.__file__).resolve().parent == MODULE_DIR,
            'syscall alias reader belongs to a different checkout')
    require(reader.SCHEMA == 'crabc.x86_64-owned-syscall-alias-contract/v3',
            'syscall alias reader is not the current v3 boundary')
    report_path = physical_work_path(report_path, directory=False)
    before = file_identity(report_path)
    try:
        report = reader.validate_report(report_path)
    except (KeyError, TypeError, ValueError, OSError, reader.ReceiptError) as error:
        raise SelectionError(f'syscall alias component rejected: {error}') from error
    require(same(before, file_identity(report_path)), 'syscall alias report changed during replay')
    source = exact(dict(source), {'revision', 'content_sha256', 'clean'}, 'selection source')
    require(source['clean'] is True, 'syscall alias selection source is not clean')
    _measurement_source_matches(source, measurement, 'syscall alias')
    measurement_reports = _measurement_report_bindings(measurement, 'syscall alias')
    report = exact(report, {
        'schema', 'status', 'image', 'musl_source_commit', 'collector_source', 'selected_product_source',
        'image_inputs', 'inputs', 'products', 'link_input_modes', 'source', 'tools', 'runner', 'historical_epochs',
        'selection_projection',
    }, 'syscall alias reader report')
    projection = _syscall_alias_projection(reader)
    require(report['schema'] == reader.SCHEMA and same(report['status'], reader.STATUS)
            and report['image'] == reader.IMAGE and report['musl_source_commit'] == reader.MUSL_SOURCE_COMMIT
            and same(report['selection_projection'], projection),
            'syscall alias reader status, image, source commit or projection differs')
    source_pair = {'revision': source['revision'], 'content_sha256': source['content_sha256']}
    collector = exact(report['collector_source'], {'before', 'after'}, 'syscall alias collector source')
    require(same(collector['before'], source_pair) and same(collector['after'], source_pair)
            and same(report['selected_product_source'], source_pair),
            'syscall alias collector or selected product source differs from selection')
    source_records = exact(report['source'], {'collector', 'selected_runtime'}, 'syscall alias source records')
    _syscall_source_snapshot(source_records['collector'], reader.COLLECTOR_SOURCES, 'syscall alias collector')
    _syscall_source_snapshot(source_records['selected_runtime'], reader.RUNTIME_SOURCES, 'syscall alias selected runtime')
    source_link_input_modes = getattr(reader, 'LINK_INPUT_MODES', None)
    require(type(source_link_input_modes) is dict
            and same(report['link_input_modes'], source_link_input_modes),
            'syscall alias source-bound link-input mode policy differs')
    link_input_modes = exact(report['link_input_modes'], {'static', 'dynamic'},
                             'syscall alias source-bound link-input modes')
    inputs = report['inputs']
    expected_inputs = {
        'static_preparation', 'elf_facts', 'base_inventory', 'selected_dynamic_list',
        'static_libc', 'static_driver', 'static_manifest', 'dynamic_libc', 'dynamic_driver',
        'dynamic_loader', 'dynamic_manifest', 'dynamic_producer_tools', 'dynamic_shared_provenance',
        'dynamic_linker', 'oracle_compiler', 'oracle_shared', 'oracle_archive',
    }
    require(type(inputs) is dict and set(inputs) == expected_inputs, 'syscall alias input roster differs')
    for name in sorted(expected_inputs):
        _syscall_receipt_input(inputs[name], f'syscall alias retained {name}')
    _require_syscall_receipt_input(inputs['static_preparation'], measurement_reports['static_preparation'],
                                   'syscall alias static preparation')
    _require_syscall_receipt_input(inputs['elf_facts'], measurement_reports['elf_report'],
                                   'syscall alias complete ELF facts')
    _require_syscall_receipt_input(inputs['base_inventory'], measurement_reports['base_inventory'],
                                   'syscall alias base inventory')
    products = _syscall_alias_product_identities(paths)
    for name in ('selected_dynamic_list', 'static_libc', 'static_driver', 'static_manifest',
                 'dynamic_libc', 'dynamic_driver', 'dynamic_loader', 'dynamic_manifest',
                 'dynamic_producer_tools', 'dynamic_shared_provenance'):
        _require_syscall_receipt_input(inputs[name], products[name], f'syscall alias {name}')
    for product, records in (('static', SYSCALL_ALIAS_STATIC_LINK_INPUTS),
                             ('dynamic', SYSCALL_ALIAS_DYNAMIC_LINK_INPUTS)):
        modes = exact(link_input_modes[product], {relative for _name, relative in records},
                      f'syscall alias {product} source mode roster')
        for name, relative in records:
            require(products[name]['mode'] == modes[relative],
                    f'syscall alias {name} source-bound mode differs')
    roots = report['products']
    require(type(roots) is dict and set(roots) == {'static', 'dynamic'}
            and all(type(roots[name]) is dict and set(roots[name]) == {'original', 'retained'}
                    and type(roots[name]['original']) is str and Path(roots[name]['original']).is_absolute()
                    and roots[name]['retained'] == 'products/' + name for name in roots),
            'syscall alias retained product roots differ')
    retained_link_inputs = _syscall_retained_link_inputs(report_path, roots, inputs, link_input_modes)
    for name, retained_identity in retained_link_inputs.items():
        display_name = 'dynamic state' if name == 'dynamic_state' else name
        _require_same_identity_payload(retained_identity, products[name], f'syscall alias {display_name}')
    facts_artifacts = facts.get('artifacts')
    require(type(facts_artifacts) is dict, 'syscall alias public ELF artifact roster differs')
    for artifact_key, name in (('candidate-static', 'static_libc'), ('candidate-shared', 'dynamic_libc'),
                               ('candidate-loader', 'dynamic_loader')):
        artifact = facts_artifacts.get(artifact_key)
        require(type(artifact) is dict and 'identity' in artifact, f'syscall alias ELF artifact differs: {artifact_key}')
        _require_same_identity_payload(artifact['identity'], products[name],
                                       f'syscall alias ELF artifact {artifact_key}')
    source_inputs = {name: file_identity(ROOT / name) for name in _syscall_alias_source_files()}
    return {
        'status': 'syscall-alias-observed-with-boundaries',
        'reader': file_identity(Path(reader.__file__)),
        'report': before,
        'source': copy.deepcopy(source),
        'source_inputs': source_inputs,
        'products': {name: copy.deepcopy(products[name]) for name in sorted(products)},
        'measurement_reports': measurement_reports,
        'projection': projection,
        'limits': list(SYSCALL_ALIAS_LIMITS),
    }


def _crt_startup_accounting_occurrence(occurrences: Mapping[int, Mapping[str, Any]],
                                       observed: Mapping[str, Any]) -> dict[str, Any]:
    """Join one owner-retained physical row to one public full-facts row."""
    matches = [candidate for candidate in occurrences.values()
               if candidate.get('artifact_key') == observed['artifact_key']
               and candidate.get('member_index') == observed['member_index']
               and candidate.get('member_occurrence') == observed['member_occurrence']
               and candidate.get('member_name') == observed['member']
               and candidate.get('table_section_index') == observed['table_section_index']
               and same(candidate.get('row'), observed['row'])
               and same(candidate.get('definition_section'), observed['section'])]
    require(len(matches) == 1, 'CRT startup observation does not bind one selected occurrence')
    return dict(matches[0])


def _validate_crt_startup_got(rows: Sequence[Mapping[str, Any]]) -> None:
    """Keep the GOT spelling as its link-time identity, never an import rule."""
    require(len(rows) == 2
            and {(row['artifact_key'], row['role']) for row in rows} == {
                ('candidate-static', 'import'), ('candidate-shared', 'local-definition'),
            }, 'CRT startup GOT ownership boundary differs')
    static = next(row for row in rows if row['artifact_key'] == 'candidate-static')
    shared = next(row for row in rows if row['artifact_key'] == 'candidate-shared')
    require({key: static['row'].get(key) for key in ('type', 'binding', 'visibility', 'section_index', 'size_bytes')} == {
                'type': 'NOTYPE', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': 'UND', 'size_bytes': 0,
            }
            and {key: shared['row'].get(key) for key in ('type', 'binding', 'visibility', 'size_bytes')} == {
                'type': 'NOTYPE', 'binding': 'LOCAL', 'visibility': 'HIDDEN', 'size_bytes': 0,
            }
            and shared['row'].get('section_index') != 'UND'
            and type(shared.get('definition_section')) is dict
            and shared['definition_section'].get('name') == '.got.plt',
            'CRT startup GOT source metadata differs')


def attach_native_crt_startup(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Discharge only the current receipt's finite CRT/link-time boundaries."""
    if companion is None:
        return []
    companion = exact(companion, {
        'status', 'reader', 'contract', 'report', 'source', 'source_inputs', 'products', 'cohort_inputs',
        'measurement_reports', 'account', 'limits',
    }, 'CRT startup companion')
    require(companion['status'] == 'crt-startup-observed-with-boundaries'
            and companion['limits'] == CRT_STARTUP_LIMITS,
            'CRT startup companion boundary differs')
    reader = _crt_startup_reader()
    names = _crt_startup_identity_names(reader)
    account = exact(companion['account'], {'identity_names', 'occurrences', 'runtime_labels', 'descriptor_handoff'},
                    'CRT startup companion account')
    require(account['identity_names'] == list(names) and type(account['occurrences']) is list,
            'CRT startup companion identity roster differs')
    cohort_inputs = companion['cohort_inputs']
    require(type(cohort_inputs) is dict and set(cohort_inputs) == {
        'static_manifest', 'dynamic_manifest', 'dynamic_state',
    }, 'CRT startup companion metadata cohort differs')
    for name, value in cohort_inputs.items():
        _identity_payload(value, f'CRT startup companion {name}')
    records, _placements, occurrences = _accounting_indexes(accounting, description='CRT startup attachment')
    observed_by_name = {name: [] for name in names}
    selected_indices: set[int] = set()
    for observed in account['occurrences']:
        require(type(observed) is dict and observed.get('row', {}).get('name') in observed_by_name,
                'CRT startup companion occurrence differs')
        occurrence = _crt_startup_accounting_occurrence(occurrences, observed)
        name = occurrence['row']['name']
        observed_by_name[name].append(occurrence)
        require(occurrence['index'] not in selected_indices,
                'CRT startup companion occurrence is duplicated')
        selected_indices.add(occurrence['index'])
    require(all(observed_by_name[name] for name in names),
            'CRT startup companion has an unjoined owner identity')
    product_keys = set(companion['products'])
    actual = {row['index'] for row in occurrences.values()
              if row.get('artifact_key') in product_keys and row.get('row', {}).get('name') in observed_by_name}
    require(actual == selected_indices,
            'CRT startup candidate occurrences differ from the finite owner receipt')
    _validate_crt_startup_got(observed_by_name['_GLOBAL_OFFSET_TABLE_'])
    joins: list[dict[str, Any]] = []
    for name in names:
        record = records.get((name, None, False))
        require(record is not None
                and record.get('selection', {}).get('disposition') == 'structural-replacement'
                and record['selection'].get('owner') == 'crt-startup-link-boundaries',
                f'CRT startup selection differs: {name}')
        rows = observed_by_name[name]
        reasons = [CRT_STARTUP_RECEIPT_REQUIREMENT]
        if any(row['role'] == 'import' for row in rows):
            reasons.append(ORDINARY_IMPORT_REASON)
        for artifact_key in sorted({row['artifact_key'] for row in rows if row['role'] == 'definition'}):
            reasons.append(f'candidate definition placement is not selected: {artifact_key}')
        _remove_identity_requirements(accounting, record, reasons, description=f'CRT startup {name}')
        joins.append({
            'identity': copy.deepcopy(record['identity']),
            'occurrence_indices': sorted(row['index'] for row in rows),
            'owner_observation_count': len(rows),
            'current_source_product_cohort': True,
        })
    require(len(joins) == len(names), 'CRT startup finite accounting differs')
    return joins


def attach_native_crt_descriptor_handoff(accounting: Mapping[str, Any],
                                         companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Discharge only the current main-image descriptor transport evidence.

    The 72-byte descriptor has no selected loader ELF definition and no
    selected shared-libc consumer. Its source object import, four owned final
    main-image weak slots, static/non-owned absence, and successful owned
    probe form one bounded private transport account. Worker lifetime, READY
    publication ordering, and malformed-record rejection remain open.
    """
    if companion is None:
        return []
    companion = exact(companion, {
        'status', 'reader', 'contract', 'report', 'source', 'source_inputs', 'products', 'cohort_inputs',
        'measurement_reports', 'account', 'limits',
    }, 'CRT descriptor handoff companion')
    require(companion['status'] == 'crt-startup-observed-with-boundaries'
            and companion['limits'] == CRT_STARTUP_LIMITS,
            'CRT descriptor handoff companion boundary differs')
    account = exact(companion['account'], {'identity_names', 'occurrences', 'runtime_labels', 'descriptor_handoff'},
                    'CRT descriptor handoff companion account')
    reader = _crt_startup_reader()
    policy = reader.expected_contract()['descriptor_handoff']
    handoff = exact(account['descriptor_handoff'], {
        'source_artifact', 'source_relocation', 'executables', 'probe_owned_modes', 'static_slot_absent',
    }, 'CRT descriptor handoff account')
    require(handoff['source_artifact'] == policy['source_artifact']
            and handoff['probe_owned_modes'] == policy['owned_modes']
            and handoff['static_slot_absent'] is True,
            'CRT descriptor handoff scope differs')
    try:
        reader.require_descriptor_relocation(handoff['source_relocation'], policy['source_relocation'],
                                             'CRT descriptor source relocation')
    except reader.StartupEvidenceError as error:
        raise SelectionError(str(error)) from error
    expected_cases = {case['name']: case for case in reader.cases()}
    require(type(handoff['executables']) is dict and set(handoff['executables']) == set(expected_cases),
            'CRT descriptor final executable roster differs')
    slot_counts: dict[str, int] = {}
    for name, case in expected_cases.items():
        row = exact(handoff['executables'][name], {'mode', 'variant', 'slot'},
                    f'CRT descriptor executable {name}')
        require(row['mode'] == case['mode'] and row['variant'] == case['variant'] and type(row['slot']) is list,
                f'CRT descriptor executable case differs: {name}')
        owned = case['mode'] in policy['owned_modes']
        require(len(row['slot']) == (1 if owned else 0),
                f'CRT descriptor main-image slot count differs: {name}')
        for relocation in row['slot']:
            try:
                reader.require_descriptor_relocation(relocation, policy['main_slot_relocation'],
                                                     f'CRT descriptor main-image slot {name}')
            except reader.StartupEvidenceError as error:
                raise SelectionError(str(error)) from error
        slot_counts[name] = len(row['slot'])
    records, _placements, occurrences = _accounting_indexes(accounting, description='CRT descriptor handoff')
    descriptor_name = policy['name']
    record = records.get((descriptor_name, None, False))
    require(record is not None
            and record.get('selection', {}).get('disposition') == 'private-resolution-operation'
            and record['selection'].get('owner') == 'loader-libc-tls-descriptor-v1',
            'CRT descriptor selection differs')
    protocol = record['selection'].get('protocol')
    require(type(protocol) is dict
            and protocol.get('consumer_artifacts') == [policy['source_artifact']]
            and protocol.get('provider_artifacts') == []
            and protocol.get('provider_metadata') == {}
            and protocol.get('endpoint_kind') == 'main-image-weak-got-transport'
            and protocol.get('requirements') == list(PREPARED_WORKER_TLS_DESCRIPTOR_REQUIREMENTS),
            'CRT descriptor protocol differs')
    candidates = [row for row in occurrences.values()
                  if row.get('artifact_key') == policy['source_artifact']
                  and row.get('member_name') is None and row.get('member_index') is None
                  and row.get('member_occurrence') is None and row.get('table') == '.symtab'
                  and row.get('role') == 'import'
                  and row.get('definition_section') is None
                  and row.get('row', {}).get('name') == descriptor_name
                  and same(row_identity(row.get('row')), identity(descriptor_name))]
    require(len(candidates) == 1, 'CRT descriptor source occurrence differs')
    occurrence = candidates[0]
    require(same({field: occurrence['row'].get(field) for field in (
        'type', 'binding', 'visibility', 'section_index', 'size_bytes', 'value', 'version', 'version_default',
    )}, {
        'type': 'NOTYPE', 'binding': 'WEAK', 'visibility': 'DEFAULT', 'section_index': 'UND',
        'size_bytes': 0, 'value': '0000000000000000', 'version': None, 'version_default': False,
    }), 'CRT descriptor source metadata differs')
    joins = [row for row in accounting['private_protocol_joins']
             if row.get('identity') == record['identity']]
    require(len(joins) == 1, 'CRT descriptor private transport join roster differs')
    join = joins[0]
    require(join.get('artifact_key') == policy['source_artifact'] and join.get('role') == 'consumer-import'
            and join.get('occurrence_indices') == [occurrence['index']]
            and join.get('endpoint_kind') == 'main-image-weak-got-transport'
            and join.get('relocation_lifecycle_proven') is False,
            'CRT descriptor private transport join differs')
    _remove_identity_requirements(accounting, record, PREPARED_WORKER_TLS_DESCRIPTOR_MEASURED_REQUIREMENTS,
                                  description='CRT descriptor handoff')
    join['relocation_lifecycle_proven'] = True
    return [{
        'identity': copy.deepcopy(record['identity']),
        'source_occurrence_indices': [occurrence['index']],
        'owned_main_slots': {name: count for name, count in slot_counts.items() if count},
        'non_owned_main_slots_absent': all(not count for name, count in slot_counts.items() if not name.startswith('owned-')),
        'requirements_discharged': list(PREPARED_WORKER_TLS_DESCRIPTOR_MEASURED_REQUIREMENTS),
        'requirements_remaining': copy.deepcopy(record['unresolved']),
    }]


def _accounting_indexes(accounting: Mapping[str, Any], *, description: str) -> tuple[dict[tuple[str, str | None, bool], dict[str, Any]],
                                                                                      dict[tuple[tuple[str, str | None, bool], str], dict[str, Any]],
                                                                                      dict[int, dict[str, Any]]]:
    records = {identity_key(record['identity']): record for record in accounting['identities']}
    require(len(records) == len(accounting['identities']), f'duplicate identities before {description}')
    placements = {(identity_key(row['identity']), row['artifact_key']): row for row in accounting['placement_joins']}
    require(len(placements) == len(accounting['placement_joins']), f'duplicate placement joins before {description}')
    occurrences = {row['index']: row for row in accounting['occurrences']}
    require(len(occurrences) == len(accounting['occurrences']), f'duplicate occurrences before {description}')
    return records, placements, occurrences


def _selected_placement(placements: Mapping[tuple[tuple[str, str | None, bool], str], Mapping[str, Any]],
                        occurrences: Mapping[int, Mapping[str, Any]], *, name: str, artifact_key: str,
                        table: str, role: str, metadata: Mapping[str, Any], description: str) -> tuple[dict[str, Any], dict[str, Any]]:
    key = (name, None, False)
    join = placements.get((key, artifact_key))
    require(join is not None and join.get('placement_observed') is True
            and join.get('definition_count') == 1 and len(join.get('occurrence_indices', [])) == 1
            and _metadata_difference_rows_are_empty(join.get('metadata_differences'), description),
            f'{description} selected placement differs')
    expected = join.get('expected_metadata')
    require(type(expected) is dict and all(expected.get(field) == value for field, value in metadata.items()),
            f'{description} selected metadata differs')
    occurrence = occurrences.get(join['occurrence_indices'][0])
    require(occurrence is not None and occurrence.get('artifact_key') == artifact_key
            and occurrence.get('table') == table and occurrence.get('role') == role
            and same(row_identity(occurrence['row']), identity(name))
            and not metadata_differences(metadata, occurrence['row'], occurrence.get('definition_section')),
            f'{description} selected occurrence differs')
    return dict(join), dict(occurrence)


def _remove_identity_requirements(accounting: Mapping[str, Any], record: Mapping[str, Any],
                                  requirements: Sequence[str], *, description: str) -> None:
    require(all(reason in record['unresolved'] for reason in requirements),
            f'{description} requirements are absent before attachment')
    record['unresolved'] = [reason for reason in record['unresolved'] if reason not in requirements]
    key = identity_key(record['identity'])
    accounting['blockers'][:] = [
        blocker for blocker in accounting['blockers']
        if not (blocker.get('code') == 'identity-unresolved'
                and identity_key(blocker.get('identity', {})) == key
                and blocker.get('reason') in requirements)
    ]


def _prepared_observation_occurrence(occurrences: Mapping[int, Mapping[str, Any]], *, artifact_key: str,
                                     table: str, observation: Mapping[str, Any], description: str) -> dict[str, Any]:
    observed = exact(observation, {'table_index', 'row_index', 'row'}, description)
    row = observed['row']
    require(type(row) is dict and type(row.get('name')) is str and row['name'], f'{description} raw row differs')
    matches = [candidate for candidate in occurrences.values()
               if candidate.get('artifact_key') == artifact_key and candidate.get('table') == table
               and candidate.get('row', {}).get('row_index') == observed['row_index']
               and same(candidate.get('row'), row)]
    require(len(matches) == 1, f'{description} does not bind one selected occurrence')
    return dict(matches[0])


def attach_prepared_worker_tls(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Attach worker dispatch and retired-token evidence without inventing descriptor proof."""
    if companion is None:
        return []
    companion = exact(companion, {
        'status', 'reader', 'contract', 'report', 'source', 'products', 'measurement_reports', 'account', 'limits',
    }, 'prepared worker TLS companion')
    require(companion['status'] == 'prepared-worker-tls-observed-with-boundaries'
            and companion['limits'] == PREPARED_WORKER_TLS_LIMITS,
            'prepared worker TLS companion boundary differs')
    account = exact(companion['account'], {'elf', 'source', 'worker_relocations', 'runtime'},
                    'prepared worker TLS companion account')
    elf_account = exact(account['elf'], {
        'operations', 'descriptor_named_elf_observations', 'descriptor_installed_import_required',
        'legacy_named_shared_loader_rows',
    }, 'prepared worker TLS ELF account')
    require(elf_account['descriptor_installed_import_required'] is False
            and elf_account['legacy_named_shared_loader_rows'] == [],
            'prepared worker TLS imported legacy/descriptor policy differs')
    source_account = exact(account['source'], {
        'source_files', 'operations', 'source_signatures', 'legacy_replacement', 'worker_token', 'ordering',
        'descriptor', 'descriptor_source_fields', 'scope',
    }, 'prepared worker TLS source account')
    require(source_account['operations'] == prepared_worker_evidence.OPERATIONS
            and source_account['legacy_replacement'] == prepared_worker_evidence.expected_contract()['legacy_replacement']
            and source_account['worker_token'] == {
                'producer_fields': prepared_worker_evidence.TOKEN_FIELDS,
                'consumer_fields': prepared_worker_evidence.TOKEN_FIELDS,
                'size_bytes': 32, 'alignment_bytes': 8,
            }
            and source_account['scope'] == 'Source selection and lexical ordering; native execution/compiled unit receipts remain separate.',
            'prepared worker TLS source account scope differs')
    _prepared_runtime_projection(account['runtime'])
    require(type(account['worker_relocations']) is dict and set(account['worker_relocations']) == set(prepared_worker_evidence.OPERATIONS),
            'prepared worker TLS relocation roster differs')
    records, placements, occurrences = _accounting_indexes(accounting, description='prepared worker TLS attachment')
    protocol_joins = accounting['private_protocol_joins']
    require(type(protocol_joins) is list, 'prepared worker TLS private protocol joins differ')
    operation_joins: list[dict[str, Any]] = []
    for name, operation in sorted(prepared_worker_evidence.OPERATIONS.items()):
        key = (name, None, False)
        record = records.get(key)
        require(record is not None and record.get('selection', {}).get('disposition') == 'private-resolution-operation'
                and record['selection'].get('owner') == 'loader-worker-tls-operations',
                f'prepared worker TLS selected operation differs: {name}')
        protocol = record['selection'].get('protocol')
        require(type(protocol) is dict and protocol.get('id') == 'loader-worker-tls-operations'
                and protocol.get('members') == list(prepared_worker_evidence.OPERATIONS)
                and protocol.get('consumer_artifacts') == ['candidate-shared']
                and protocol.get('provider_artifacts') == []
                and protocol.get('requirements') == list(PREPARED_WORKER_TLS_REQUIREMENTS),
                f'prepared worker TLS protocol differs: {name}')
        source_operation = source_account['operations'].get(name)
        require(source_operation == operation, f'prepared worker TLS source operation differs: {name}')
        observed_tables = elf_account['operations'].get(name)
        require(type(observed_tables) is dict and set(observed_tables) == {'.dynsym', '.symtab'},
                f'prepared worker TLS selected operation table roster differs: {name}')
        bound_indices: list[int] = []
        for table in ('.dynsym', '.symtab'):
            occurrence = _prepared_observation_occurrence(
                occurrences, artifact_key='candidate-shared', table=table, observation=observed_tables[table],
                description=f'prepared worker TLS {name} {table}',
            )
            require(occurrence['role'] == 'import' and same(row_identity(occurrence['row']), identity(name))
                    and occurrence.get('accounting', {}).get('disposition') == 'private-resolution-operation'
                    and occurrence['accounting'].get('owner') == 'loader-worker-tls-operations'
                    and occurrence['accounting'].get('scope') == 'candidate-shared'
                    and occurrence['accounting'].get('resolution_proven') is False,
                    f'prepared worker TLS selected operation occurrence differs: {name} {table}')
            resolution = occurrence['accounting'].get('resolution')
            require(type(resolution) is dict and resolution.get('kind') == 'source-dispatch-operation'
                    and type(resolution.get('operation')) is dict and resolution['operation'].get('name') == name,
                    f'prepared worker TLS source-dispatch operation differs: {name} {table}')
            occurrence['accounting']['resolution_proven'] = True
            bound_indices.append(occurrence['index'])
        join = next((row for row in protocol_joins
                     if row.get('identity') == record['identity'] and row.get('artifact_key') == 'candidate-shared'
                     and row.get('role') == 'consumer-import'), None)
        require(join is not None and join.get('occurrence_indices') == bound_indices
                and join.get('endpoint_kind') == 'source-dispatch-operation'
                and join.get('relocation_lifecycle_proven') is False,
                f'prepared worker TLS private operation join differs: {name}')
        join['relocation_lifecycle_proven'] = True
        _remove_identity_requirements(accounting, record, PREPARED_WORKER_TLS_REQUIREMENTS,
                                      description=f'prepared worker TLS {name}')
        operation_joins.append({
            'identity': copy.deepcopy(record['identity']), 'role': operation['role'],
            'artifact_key': 'candidate-shared', 'occurrence_indices': bound_indices,
            'source_dispatch_proven': True,
            'requirements_discharged': list(PREPARED_WORKER_TLS_REQUIREMENTS),
        })
    legacy_joins: list[dict[str, Any]] = []
    structural_requirement = 'current source-bound owning component and consumer semantics receipt'
    for legacy in source_account['legacy_replacement']:
        legacy = exact(legacy, {'name', 'owner', 'role'}, 'prepared worker TLS legacy replacement')
        name = legacy['name']
        record = records.get((name, None, False))
        require(record is not None and record.get('selection', {}).get('disposition') == 'structural-replacement'
                and record['selection'].get('owner') == 'pthread-prepared-token'
                and record['selection'].get('reason') == 'Actual pthread consumer uses prepared mapping/thread-pointer/generation token before clone and exact release at exit/reap; raw process clone is not the replacement.',
                f'prepared worker TLS legacy replacement selection differs: {name}')
        _remove_identity_requirements(accounting, record, (structural_requirement,),
                                      description=f'prepared worker TLS legacy replacement {name}')
        legacy_joins.append({
            'identity': copy.deepcopy(record['identity']), 'owner': legacy['owner'], 'role': legacy['role'],
            'requirements_discharged': [structural_requirement],
        })
    require(len(legacy_joins) == len(prepared_worker_evidence.LEGACY),
            'prepared worker TLS legacy replacement count differs')
    descriptor_name = '__crabc_x86_64_loader_tls_runtime_v1'
    descriptor = records.get((descriptor_name, None, False))
    require(descriptor is not None and descriptor.get('selection', {}).get('disposition') == 'private-resolution-operation'
            and descriptor['selection'].get('owner') == 'loader-libc-tls-descriptor-v1',
            'prepared worker TLS descriptor selection differs')
    descriptor_protocol = descriptor['selection'].get('protocol')
    require(type(descriptor_protocol) is dict and descriptor_protocol.get('id') == 'loader-libc-tls-descriptor-v1'
            and descriptor_protocol.get('members') == [descriptor_name]
            and descriptor_protocol.get('consumer_artifacts') == ['dynamic-crabc-dynamic-attach.o']
            and descriptor_protocol.get('provider_artifacts') == []
            and descriptor_protocol.get('provider_metadata') == {}
            and descriptor_protocol.get('endpoint_kind') == 'main-image-weak-got-transport'
            and descriptor_protocol.get('requirements') == list(PREPARED_WORKER_TLS_DESCRIPTOR_REQUIREMENTS),
            'prepared worker TLS descriptor protocol differs')
    descriptor_contract = exact(prepared_worker_evidence.expected_contract()['descriptor'], {
        'owner', 'size_bytes', 'alignment_bytes', 'initial_generation', 'role', 'current_view',
        'current_view_tcb_offset', 'require_installed_import',
    }, 'prepared worker TLS descriptor source contract')
    require(descriptor_contract == {
        'owner': 'ldso/src/x86_64_general_initial_tls_state.rs:GeneralLoaderLibcTlsRuntimeV1',
        'size_bytes': 72, 'alignment_bytes': 8, 'initial_generation': 1,
        'role': 'private-process-lifetime-initial-tls-provenance',
        'current_view': 'ldso/src/x86_64_runtime_tls_view.rs:RuntimeTlsView',
        'current_view_tcb_offset': 24, 'require_installed_import': False,
    }, 'prepared worker TLS descriptor source contract differs')
    source_descriptor = source_account['descriptor']
    current_source_account = prepared_worker_evidence.account_source(ROOT)
    require(same(source_descriptor, current_source_account['descriptor'])
            and source_account['descriptor_source_fields'] == list(PREPARED_WORKER_TLS_DESCRIPTOR_SOURCE_FIELDS)
            and same(source_account['descriptor_source_fields'], current_source_account['descriptor_source_fields']),
            'prepared worker TLS descriptor source provenance differs')
    observed_descriptor = elf_account['descriptor_named_elf_observations']
    require(observed_descriptor == [], 'prepared worker TLS installed descriptor observation differs')
    # The complete current facts retain one weak undefined reference in the
    # dynamic CRT attachment object. It is the source-side GOTPCREL endpoint;
    # the CRT owner separately proves its final main-image slots. This worker
    # receipt only preserves the occurrence and discharges no descriptor
    # behavior, lifetime, ordering, or rejection obligation.
    descriptor_occurrences = [
        row for row in occurrences.values()
        # Complete ELF accounts also retain unnamed null and section rows.
        # Only the named descriptor can enter logical identity validation.
        if row['row']['name'] == descriptor_name
        and same(row_identity(row['row']), identity(descriptor_name))
    ]
    require(len(descriptor_occurrences) == 1, 'prepared worker TLS descriptor transport occurrence differs')
    descriptor_occurrence = descriptor_occurrences[0]
    require(
        descriptor_occurrence.get('artifact_key') == 'dynamic-crabc-dynamic-attach.o'
        and descriptor_occurrence.get('member_name') is None
        and descriptor_occurrence.get('member_index') is None
        and descriptor_occurrence.get('member_occurrence') is None
        and descriptor_occurrence.get('table') == '.symtab'
        and descriptor_occurrence.get('role') == 'import'
        and descriptor_occurrence.get('definition_section') is None
        and same({
            field: descriptor_occurrence.get('row', {}).get(field)
            for field in (
                'type', 'binding', 'visibility', 'section_index', 'size_bytes', 'value',
                'version', 'version_default',
            )
        }, {
            'type': 'NOTYPE', 'binding': 'WEAK', 'visibility': 'DEFAULT', 'section_index': 'UND',
            'size_bytes': 0, 'value': '0000000000000000', 'version': None, 'version_default': False,
        })
        and descriptor_occurrence.get('accounting', {}).get('disposition') == 'private-resolution-operation'
        and descriptor_occurrence['accounting'].get('owner') == 'loader-libc-tls-descriptor-v1'
        and descriptor_occurrence['accounting'].get('scope') == 'dynamic-crabc-dynamic-attach.o',
        'prepared worker TLS descriptor transport occurrence differs',
    )
    consumer_join = next((row for row in protocol_joins
                          if row.get('identity') == descriptor['identity'] and row.get('artifact_key') == 'dynamic-crabc-dynamic-attach.o'
                          and row.get('role') == 'consumer-import'), None)
    require(consumer_join is not None and consumer_join.get('endpoint_kind') == 'main-image-weak-got-transport'
            and consumer_join.get('relocation_lifecycle_proven') is False
            and consumer_join.get('occurrence_indices') == [descriptor_occurrence['index']],
            'prepared worker TLS descriptor consumer join differs')
    return [{
        'operations': operation_joins,
        'legacy_replacements': legacy_joins,
        'descriptor': {
            'identity': copy.deepcopy(descriptor['identity']),
            'contract_geometry': {
                'size_bytes': descriptor_contract['size_bytes'],
                'alignment_bytes': descriptor_contract['alignment_bytes'],
                'role': descriptor_contract['role'],
            },
            'source_provenance_verified': True,
            'installed_import_required': descriptor_contract['require_installed_import'],
            'transport_occurrence_indices': [row['index'] for row in descriptor_occurrences],
            'provider_occurrence_indices': [],
            'consumer_occurrence_indices': [descriptor_occurrence['index']],
            'requirements_discharged': [],
            'requirements_remaining': copy.deepcopy(descriptor['unresolved']),
        },
    }]


def _errno_provider_partition(inputs: Mapping[str, Any]) -> None:
    """Use the already authenticated callable partition without rebuilding it."""
    disposition = inputs.get('provider_disposition')
    require(type(disposition) is dict, 'errno storage callable provider disposition differs')
    default_static = disposition.get('default_static')
    require(type(default_static) is dict and '__errno_location' in default_static.get('members', []),
            'errno public accessor is absent from the default-static provider partition')
    verified = disposition.get('verified_feature_archives')
    h_errno = [row for row in verified if type(row) is dict and row.get('id') == 'x86-h-errno'] if type(verified) is list else []
    require(len(h_errno) == 1 and h_errno[0].get('members') == ['__h_errno_location'],
            'h_errno accessor feature provider partition differs')


def attach_errno_storage_lifecycle(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None,
                                   inputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Join the finite errno storage evidence without expanding its scope."""
    if companion is None:
        return []
    companion = exact(companion, {
        'status', 'reader', 'report', 'source', 'products', 'measurement_reports', 'account', 'limits',
    }, 'errno storage lifecycle companion')
    require(companion['status'] == 'errno-storage-lifecycle-observed-with-boundaries'
            and companion['limits'] == ERRNO_STORAGE_LIFECYCLE_LIMITS,
            'errno storage lifecycle companion boundary differs')
    account = exact(companion['account'], {
        'public_symbols', 'private_alias', 'shared_alias_policy', 'h_errno_layout', 'summary', 'execution_labels',
    }, 'errno storage lifecycle companion account')
    require(account['public_symbols'] == list(errno_storage_evidence.PUBLIC_SYMBOLS)
            and account['private_alias'] == errno_storage_evidence.ALIAS
            and account['execution_labels'] == list(errno_storage_evidence.RUN_LABELS),
            'errno storage lifecycle finite identity roster differs')
    _errno_summary(account['summary'])
    _errno_alias_policy(account['shared_alias_policy'], 'errno storage lifecycle companion')
    # The adapter already reconstructed the complete role facts through the
    # public errno reader. The compact companion intentionally carries only
    # the selected metadata for these generic placement joins.
    h_errno_layout = account['h_errno_layout']
    require(type(h_errno_layout) is dict and set(h_errno_layout) == {'static', 'shared'}
            and all(same(h_errno_layout[role], errno_storage_evidence.H_ERRNO_METADATA)
                    for role in ('static', 'shared')),
            'errno storage lifecycle h_errno metadata differs')
    _errno_provider_partition(inputs)
    records, placements, occurrences = _accounting_indexes(accounting, description='errno storage lifecycle attachment')
    public_rows = []
    # ``__h_errno_location`` is routed through the checked installed-header
    # provider group in the assembled selection.  The separate exact
    # ``x86-h-errno`` feature roster remains an authenticated prerequisite for
    # this lifecycle receipt; it does not rewrite the selected owner field.
    for name, owner, feature_owner, static_metadata, shared_metadata in (
        ('__errno_location', 'checked-header-provider-routing',
         None,
         {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'},
         {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'}),
        ('__h_errno_location', 'checked-header-provider-routing', 'x86-h-errno',
         {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'},
         {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT'}),
        ('h_errno', 'object:h_errno', None, h_errno_layout['static'], h_errno_layout['shared']),
    ):
        record = records.get((name, None, False))
        require(record is not None and record.get('selection', {}).get('disposition') == 'public-provider'
                and record['selection'].get('owner') == owner,
                f'errno storage lifecycle selected owner differs: {name}')
        static_join, static_occurrence = _selected_placement(
            placements, occurrences, name=name, artifact_key='candidate-static', table='.symtab', role='definition',
            metadata=static_metadata, description=f'errno storage lifecycle {name} static',
        )
        shared_join, shared_occurrence = _selected_placement(
            placements, occurrences, name=name, artifact_key='candidate-shared', table='.dynsym', role='definition',
            metadata=shared_metadata, description=f'errno storage lifecycle {name} shared',
        )
        public_rows.append({
            'identity': copy.deepcopy(record['identity']), 'owner': owner,
            'feature_owner': feature_owner,
            'static_occurrence_index': static_occurrence['index'], 'shared_occurrence_index': shared_occurrence['index'],
            'static_placement_observed': static_join['placement_observed'],
            'shared_placement_observed': shared_join['placement_observed'],
        })
    alias_record = records.get((errno_storage_evidence.ALIAS, None, False))
    require(alias_record is not None and alias_record.get('selection', {}).get('disposition') == 'private-provider'
            and alias_record['selection'].get('group') == ERRNO_PRIVATE_ALIAS_GROUP
            and alias_record['selection'].get('owner') == 'x86-errno-storage-lifecycle',
            'errno storage lifecycle private alias selection differs')
    _static_alias_join, static_alias = _selected_placement(
        placements, occurrences, name=errno_storage_evidence.ALIAS, artifact_key='candidate-static', table='.symtab',
        role='definition', metadata={'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'HIDDEN'},
        description='errno storage lifecycle private alias static',
    )
    _shared_alias_join, shared_alias = _selected_placement(
        placements, occurrences, name=errno_storage_evidence.ALIAS, artifact_key='candidate-shared', table='.symtab',
        role='local-definition', metadata={'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'},
        description='errno storage lifecycle private alias shared',
    )
    errno_static = next(row for row in public_rows if row['identity']['name'] == '__errno_location')
    static_accessor = occurrences[errno_static['static_occurrence_index']]
    shared_accessor = [row for row in occurrences.values()
                       if row.get('artifact_key') == 'candidate-shared' and row.get('table') == '.symtab'
                       and row.get('role') == 'definition' and row.get('row', {}).get('name') == '__errno_location'
                       and row['row'].get('version') is None and row['row'].get('version_default') is False]
    require(len(shared_accessor) == 1 and same_definition_domain(static_alias, static_accessor)
            and same_definition_domain(shared_alias, shared_accessor[0]),
            'errno storage lifecycle private alias no longer shares its selected definition')
    leaks = [row for row in occurrences.values()
             if row.get('artifact_key') == 'candidate-shared' and row.get('table') == '.dynsym'
             and row.get('row', {}).get('section_index') != 'UND'
             and row.get('row', {}).get('name') == errno_storage_evidence.ALIAS
             and row['row'].get('version') is None and row['row'].get('version_default') is False]
    require(not leaks, 'errno storage lifecycle private alias leaked into shared dynsym')
    _remove_identity_requirements(
        accounting, alias_record, (ERRNO_STORAGE_LIFECYCLE_REQUIREMENT,),
        description='errno storage lifecycle private alias',
    )
    return [{
        'public_identities': public_rows,
        'private_alias': {
            'identity': copy.deepcopy(alias_record['identity']),
            'static_occurrence_index': static_alias['index'], 'shared_occurrence_index': shared_alias['index'],
            'static_same_definition_target': static_accessor['index'],
            'shared_same_definition_target': shared_accessor[0]['index'],
            'shared_dynsym_absent': True,
            'one_name_local_script_policy': copy.deepcopy(account['shared_alias_policy']),
            'requirements_discharged': [ERRNO_STORAGE_LIFECYCLE_REQUIREMENT],
        },
        'runtime_summary': copy.deepcopy(account['summary']),
        'h_errno_layout': copy.deepcopy(h_errno_layout),
        'limits': list(ERRNO_STORAGE_LIFECYCLE_LIMITS),
    }]


def _c_allocator_provider_metadata(value: object, description: str) -> dict[str, Any]:
    """Keep the producer's observed function row distinct from selection policy.

    The fixed-C metadata attachment has already selected type/binding/
    visibility.  This helper preserves the C receipt's defining-row facts for
    its consumer join without turning code size or section index into a new
    compatibility ratchet.
    """
    row = exact(value, {
        'type', 'binding', 'visibility', 'definition', 'section_index', 'size_bytes',
    }, description)
    require(row['type'] == 'FUNC' and row['binding'] in {'GLOBAL', 'LOCAL'}
            and row['visibility'] == 'DEFAULT' and row['definition'] == 'defined'
            and type(row['section_index']) is str and row['section_index'].isdigit()
            and int(row['section_index']) > 0
            and type(row['size_bytes']) is int and row['size_bytes'] > 0,
            f'{description} differs')
    return copy.deepcopy(row)


def attach_native_c_allocator_boundary(accounting: Mapping[str, Any],
                                       companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Discharge only the seven exact static Rust-root C imports.

    A spelling match is deliberately insufficient.  Each import must remain a
    single unversioned NOTYPE GLOBAL DEFAULT ``.symtab`` undefined row in the
    one authenticated static Rust root archive member.  An import of the same
    name from another member or candidate artifact retains the generic reason.
    """
    if companion is None:
        return []
    companion = exact(companion, {
        'status', 'reader', 'contract', 'report', 'source', 'source_inputs', 'products',
        'measurement_reports', 'account', 'limits',
    }, 'native C allocator boundary companion')
    require(companion['status'] == 'native-c-allocator-boundary-observed-with-boundaries'
            and companion['limits'] == C_ALLOCATOR_BOUNDARY_LIMITS,
            'native C allocator boundary companion scope differs')
    require(same(companion['source_inputs'], {
        name: file_identity(ROOT / name) for name in C_ALLOCATOR_BOUNDARY_SOURCE_FILES
    }), 'native C allocator boundary source inputs changed')
    _contract, import_names = _c_allocator_boundary_contract()
    account = exact(companion['account'], {'imports', 'claims', 'static_rust_root_member'},
                    'native C allocator boundary companion account')
    require(account['imports'] == import_names
            and type(account['static_rust_root_member']) is str and account['static_rust_root_member']
            and type(account['claims']) is list and len(account['claims']) == len(import_names)
            and [claim.get('name') for claim in account['claims'] if isinstance(claim, dict)] == import_names,
            'native C allocator boundary companion import roster differs')
    records, placements, occurrences = _accounting_indexes(
        accounting, description='native C allocator boundary attachment',
    )
    candidate_artifacts = {artifact.key for artifact in elf_facts.ARTIFACTS if artifact.owner != 'reference'}
    result: list[dict[str, Any]] = []
    discharged: set[tuple[str, str | None, bool]] = set()
    for claim in account['claims']:
        claim = exact(claim, {
            'name', 'static_rust_import', 'static_c_provider', 'shared_c_final_provider',
        }, 'native C allocator boundary import claim')
        name = claim['name']
        require(type(name) is str and name in import_names, 'native C allocator boundary import name differs')
        static_import = exact(claim['static_rust_import'], {
            'type', 'binding', 'visibility', 'section_index',
        }, f'native C allocator boundary {name} static Rust import')
        require(static_import == {
            'type': 'NOTYPE', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': 'UND',
        }, f'native C allocator boundary {name} static Rust import differs')
        static_provider = _c_allocator_provider_metadata(
            claim['static_c_provider'], f'native C allocator boundary {name} static provider',
        )
        shared_provider = _c_allocator_provider_metadata(
            claim['shared_c_final_provider'], f'native C allocator boundary {name} shared provider',
        )
        key = (name, None, False)
        record = records.get(key)
        require(record is not None and record.get('selection', {}).get('disposition') == 'private-provider'
                and record['selection'].get('group') == FIXED_C_PRODUCER_GROUP
                and record['selection'].get('owner') == FIXED_C_PRODUCER_OWNER,
                f'native C allocator boundary selected owner differs: {name}')
        static_placement = placements.get((key, 'candidate-static'))
        shared_placement = placements.get((key, 'candidate-shared'))
        for placement, provider, label in (
            (static_placement, static_provider, 'static'),
            (shared_placement, shared_provider, 'shared'),
        ):
            require(placement is not None and placement.get('placement_observed') is True
                    and placement.get('definition_count') == 1
                    and _metadata_difference_rows_are_empty(
                        placement.get('metadata_differences'),
                        f'native C allocator boundary {name} {label} placement',
                    )
                    and same(placement.get('expected_metadata'), {
                        field: provider[field] for field in ('type', 'binding', 'visibility')
                    }), f'native C allocator boundary {name} {label} provider placement differs')
        imports = [
            occurrence for occurrence in occurrences.values()
            if occurrence.get('role') == 'import'
            and occurrence.get('artifact_key') in candidate_artifacts
            and occurrence.get('row', {}).get('name') == name
            and occurrence['row'].get('version') is None
            and occurrence['row'].get('version_default') is False
        ]
        covered = len(imports) == 1 and all(
            occurrence.get('artifact_key') == 'candidate-static'
            and occurrence.get('table') == '.symtab'
            and occurrence.get('member_name') == account['static_rust_root_member']
            and occurrence.get('member_index') is not None
            and occurrence.get('member_occurrence') == 0
            and occurrence.get('accounting') == {
                'disposition': 'private-provider',
                'owner': FIXED_C_PRODUCER_OWNER,
                'scope': 'candidate-static',
            }
            and occurrence.get('row', {}).get('raw_name') == name
            and all(occurrence['row'].get(field) == value for field, value in static_import.items())
            and occurrence['row'].get('size_bytes') == 0
            and occurrence['row'].get('value') == '0000000000000000'
            for occurrence in imports
        )
        result.append({
            'identity': copy.deepcopy(record['identity']),
            'owner': FIXED_C_PRODUCER_OWNER,
            'artifact_key': 'candidate-static',
            'static_rust_root_member': account['static_rust_root_member'],
            'occurrence_indices': [occurrence['index'] for occurrence in imports],
            'producer_static_metadata': static_provider,
            'producer_shared_metadata': shared_provider,
            'ordinary_import_covered': covered,
            'discharged_reason': ORDINARY_IMPORT_REASON if covered else None,
        })
        if covered:
            require(ORDINARY_IMPORT_REASON in record['unresolved'],
                    f'native C allocator boundary import reason is absent before attachment: {name}')
            record['unresolved'].remove(ORDINARY_IMPORT_REASON)
            discharged.add(key)
    require([row['identity']['name'] for row in result] == import_names,
            'native C allocator boundary join cardinality differs')
    if discharged:
        accounting['blockers'][:] = [
            blocker for blocker in accounting['blockers']
            if not (blocker.get('code') == 'identity-unresolved'
                    and identity_key(blocker.get('identity', {})) in discharged
                    and blocker.get('reason') == ORDINARY_IMPORT_REASON)
        ]
    return result


def _stdio_alias_occurrence(occurrences: Mapping[int, Mapping[str, Any]], *, artifact_key: str,
                            observation: Mapping[str, Any], description: str) -> dict[str, Any]:
    """Bind one retained FILE ``.symtab`` definition to a full-facts row."""
    observed = exact(dict(observation), {
        'member', 'member_index', 'member_occurrence', 'table_section_index', 'row', 'section',
    }, description)
    row = observed['row']
    require(type(row) is dict and type(row.get('name')) is str and row['name']
            and row.get('section_index') != 'UND' and type(observed['section']) is dict,
            f'{description} raw definition differs')
    matches = [candidate for candidate in occurrences.values()
               if candidate.get('artifact_key') == artifact_key and candidate.get('table') == '.symtab'
               and candidate.get('member_name') == observed['member']
               and candidate.get('member_index') == observed['member_index']
               and candidate.get('member_occurrence') == observed['member_occurrence']
               and candidate.get('table_section_index') == observed['table_section_index']
               and same(candidate.get('row'), row)
               and same(candidate.get('definition_section'), observed['section'])]
    require(len(matches) == 1, f'{description} does not bind one complete ELF occurrence')
    return dict(matches[0])


def _stdio_selected_alias_placement(placements: Mapping[tuple[tuple[str, str | None, bool], str], Mapping[str, Any]],
                                    occurrences: Mapping[int, Mapping[str, Any]], *, name: str,
                                    description: str) -> tuple[dict[str, Any], dict[str, Any]]:
    static = _selected_placement(
        placements, occurrences, name=name, artifact_key='candidate-static', table='.symtab', role='definition',
        metadata={'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'},
        description=f'{description} static alias',
    )
    shared = _selected_placement(
        placements, occurrences, name=name, artifact_key='candidate-shared', table='.dynsym', role='definition',
        metadata={'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'},
        description=f'{description} shared alias',
    )
    return static, shared


# These three members complete the owner's source groups but have no pending
# feature-alias receipt obligation. Keep them observed without inventing a
# requirement to discharge. The other 39 aliases retain their exact feature
# ownership, including the separately selected narrow scanning feature.
STDIO_ALREADY_ACCOUNTED_ALIASES = {
    '__getdelim': 'getdelim', '__isoc99_sscanf': 'sscanf', '__isoc99_vsscanf': 'vsscanf',
}


def _stdio_alias_feature_owners() -> dict[str, str]:
    reader = _stdio_alias_reader()
    source_owners = {
        'owned_static_stdio': 'x86-owned-static-runtime',
        'owned_wide_stdio': 'x86-owned-static-runtime',
        'owned_stdio_extensions': 'x86-owned-static-runtime',
        'stdio_format_scan': 'x86-stdio-permanent-format-scan',
        'owned_wide_format': 'x86-owned-static-runtime',
    }
    require({owner for owner, _source, _pairs in reader.ALIAS_GROUPS} == set(source_owners)
            and len(reader.ALIASES) == 42
            and all(reader.ALIASES.get(name) == target
                    for name, target in STDIO_ALREADY_ACCOUNTED_ALIASES.items()),
            'FILE source alias group contract differs')
    result = {
        alias: source_owners[owner]
        for owner, _source, pairs in reader.ALIAS_GROUPS for alias, _target in pairs
        if alias not in STDIO_ALREADY_ACCOUNTED_ALIASES
    }
    require(len(result) == 39, 'FILE feature alias roster differs')
    return result


def attach_native_stdio_alias(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Attach only the finite FILE alias/body and protected-boundary receipt.

    The raw receipt covers four artifact views.  This join maps every retained
    alias/body definition back to the single public complete-facts occurrence,
    clears only the pre-existing feature-alias receipt requirement, and keeps
    the three named hidden bodies private providers.  It does not make a
    spelling-prefix rule for other stdio internals.
    """
    if companion is None:
        return []
    stdio_alias_evidence = _stdio_alias_reader()
    companion = exact(companion, {
        'status', 'reader', 'contract', 'report', 'source', 'source_inputs', 'products',
        'measurement_reports', 'account', 'limits',
    }, 'FILE alias companion')
    require(companion['status'] == 'stdio-alias-observed-with-boundaries'
            and companion['limits'] == STDIO_ALIAS_LIMITS,
            'FILE alias companion boundary differs')
    require(same(companion['source_inputs'], {
        name: file_identity(ROOT / name) for name in _stdio_alias_source_files()
    }), 'FILE alias source inputs changed')
    account = exact(companion['account'], {'aliases', 'runtime_labels', 'candidate_link_labels'},
                    'FILE alias companion account')
    require(account['runtime_labels'] == [row['label'] for row in stdio_alias_evidence.runtime_cells()]
            and account['candidate_link_labels'] == sorted(
                name for name in stdio_alias_evidence.binaries() if name.startswith('candidate-')
            ), 'FILE alias runtime/link account differs')
    aliases = account['aliases']
    artifact_keys = ('candidate-static', 'reference-static', 'candidate-shared', 'reference-shared')
    require(type(aliases) is dict and set(aliases) == set(artifact_keys), 'FILE alias artifact roster differs')
    records, placements, occurrences = _accounting_indexes(accounting, description='FILE alias attachment')
    function_observations = accounting.get('function_alias_observations')
    require(type(function_observations) is list, 'FILE function alias observation roster differs')
    alias_joins: list[dict[str, Any]] = []
    private_pairs: dict[str, dict[str, Any]] = {}
    feature_owners = _stdio_alias_feature_owners()
    for name in STDIO_ALREADY_ACCOUNTED_ALIASES:
        record = records.get((name, None, False))
        require(record is not None and record.get('selection', {}).get('disposition') == 'public-provider'
                and not record.get('function_alias_requirements')
                and 'source-selected alias requires exact feature archive selection and component receipt'
                    not in record['unresolved'],
                f'FILE already-accounted alias acquired a receipt obligation: {name}')
    for alias_name, expected_feature_owner in feature_owners.items():
        target_name = stdio_alias_evidence.ALIASES[alias_name]
        key = (alias_name, None, False)
        record = records.get(key)
        require(record is not None and record.get('selection', {}).get('disposition') == 'public-provider',
                f'FILE public alias selection differs: {alias_name}')
        feature = record.get('function_alias_requirements')
        require(type(feature) is list and len(feature) == 1
                and feature[0].get('name') == alias_name and feature[0].get('target') == target_name
                and feature[0].get('binding') == 'weak-same-address'
                and feature[0].get('owner') == expected_feature_owner,
                f'FILE feature alias contract differs: {alias_name}')
        matching_observations = [row for row in function_observations
                                 if type(row) is dict and same(row.get('identity'), identity(alias_name))
                                 and same(row.get('target'), identity(target_name))]
        require(len(matching_observations) == 1,
                f'FILE function alias observation differs: {alias_name}')
        function_observation = matching_observations[0]
        require(function_observation.get('feature_contract') == feature[0]
                and function_observation.get('feature_archive_receipt_proven') is False
                and function_observation.get('runtime_semantics_proven') is False,
                f'FILE function alias observation differs: {alias_name}')
        static_placement, shared_placement = _stdio_selected_alias_placement(
            placements, occurrences, name=alias_name, description=f'FILE {alias_name}',
        )
        artifact_pairs = {}
        for artifact_key in artifact_keys:
            artifact = exact(aliases[artifact_key], {'aliases', 'protected'},
                             f'FILE {artifact_key} alias account')
            pairs = artifact['aliases']
            require(type(pairs) is dict and set(pairs) == set(stdio_alias_evidence.ALIASES),
                    f'FILE {artifact_key} alias roster differs')
            pair = exact(pairs[alias_name], {'target', 'alias_occurrence', 'target_occurrence'},
                         f'FILE {artifact_key} {alias_name} pair')
            require(pair['target'] == target_name, f'FILE {artifact_key} alias target differs: {alias_name}')
            alias_occurrence = _stdio_alias_occurrence(
                occurrences, artifact_key=artifact_key, observation=pair['alias_occurrence'],
                description=f'FILE {artifact_key} alias {alias_name}',
            )
            target_occurrence = _stdio_alias_occurrence(
                occurrences, artifact_key=artifact_key, observation=pair['target_occurrence'],
                description=f'FILE {artifact_key} target {target_name}',
            )
            require(alias_occurrence['row'].get('type') == 'FUNC'
                    and alias_occurrence['row'].get('binding') == 'WEAK'
                    and alias_occurrence['row'].get('visibility') == 'DEFAULT'
                    and same_definition_domain(alias_occurrence, target_occurrence),
                    f'FILE {artifact_key} alias domain differs: {alias_name}')
            artifact_pairs[artifact_key] = {
                'alias_occurrence_index': alias_occurrence['index'],
                'target_occurrence_index': target_occurrence['index'],
            }
        static_pair = artifact_pairs['candidate-static']
        require(static_pair['alias_occurrence_index'] in static_placement[0]['occurrence_indices']
                and [static_pair['alias_occurrence_index'], static_pair['target_occurrence_index']]
                in function_observation.get('same_domain_pairs', []),
                f'FILE static feature alias domain differs: {alias_name}')
        function_observation['feature_archive_receipt_proven'] = True
        function_observation['runtime_semantics_proven'] = True
        _remove_identity_requirements(
            accounting, record,
            ('source-selected alias requires exact feature archive selection and component receipt',),
            description=f'FILE alias {alias_name}',
        )
        alias_joins.append({
            'identity': copy.deepcopy(record['identity']), 'target': identity(target_name),
            'static_alias_occurrence_index': static_placement[1]['index'],
            'shared_alias_occurrence_index': shared_placement[1]['index'],
            'artifact_pairs': artifact_pairs,
            'feature_archive_receipt_proven': True,
            'runtime_semantics_proven': True,
        })
        if target_name in stdio_alias_evidence.HIDDEN:
            private_pairs[target_name] = artifact_pairs
    require([row['identity']['name'] for row in alias_joins] == list(feature_owners),
            'FILE alias join cardinality differs')

    private_joins: list[dict[str, Any]] = []
    for name in stdio_alias_evidence.HIDDEN:
        record = records.get((name, None, False))
        require(record is not None and record.get('selection', {}).get('disposition') == 'private-provider'
                and record['selection'].get('owner') == STDIO_ALIAS_PRIVATE_OWNER
                and record['selection'].get('group') == STDIO_ALIAS_PRIVATE_GROUP,
                f'FILE private body selection differs: {name}')
        static_placement, static_occurrence = _selected_placement(
            placements, occurrences, name=name, artifact_key='candidate-static', table='.symtab', role='definition',
            metadata={'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'},
            description=f'FILE private body {name} static',
        )
        shared_placement, shared_occurrence = _selected_placement(
            placements, occurrences, name=name, artifact_key='candidate-shared', table='.symtab', role='local-definition',
            metadata={'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'HIDDEN'},
            description=f'FILE private body {name} shared',
        )
        require(not [row for row in occurrences.values()
                     if row.get('artifact_key') == 'candidate-shared' and row.get('table') == '.dynsym'
                     and row.get('row', {}).get('name') == name and row['row'].get('section_index') != 'UND'],
                f'FILE private body leaked to candidate dynsym: {name}')
        pairs = private_pairs.get(name)
        require(type(pairs) is dict and set(pairs) == set(artifact_keys)
                and pairs['candidate-static']['target_occurrence_index'] == static_occurrence['index']
                and pairs['candidate-shared']['target_occurrence_index'] == shared_occurrence['index'],
                f'FILE private body receipt domain differs: {name}')
        _remove_identity_requirements(
            accounting, record, (STDIO_ALIAS_RECEIPT_REQUIREMENT,),
            description=f'FILE private body {name}',
        )
        private_joins.append({
            'identity': copy.deepcopy(record['identity']),
            'static_occurrence_index': static_occurrence['index'],
            'shared_occurrence_index': shared_occurrence['index'],
            'static_metadata': copy.deepcopy(static_placement['expected_metadata']),
            'shared_metadata': copy.deepcopy(shared_placement['expected_metadata']),
            'candidate_dynsym_definition_absent': True,
            'requirements_discharged': [STDIO_ALIAS_RECEIPT_REQUIREMENT],
        })

    protected_joins: list[dict[str, Any]] = []
    for name in stdio_alias_evidence.PROTECTED:
        record = records.get((name, None, False))
        require(record is not None and record.get('selection', {}).get('disposition') == 'public-provider'
                and record['selection'].get('group') == 'source-owned-stdio-protected-boundaries',
                f'FILE protected body selection differs: {name}')
        static_placement, static_occurrence = _selected_placement(
            placements, occurrences, name=name, artifact_key='candidate-static', table='.symtab', role='definition',
            metadata={'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'PROTECTED'},
            description=f'FILE protected body {name} static',
        )
        shared_placement, shared_occurrence = _selected_placement(
            placements, occurrences, name=name, artifact_key='candidate-shared', table='.dynsym', role='definition',
            metadata={'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'PROTECTED'},
            description=f'FILE protected body {name} shared',
        )
        retained = []
        for artifact_key in artifact_keys:
            artifact = exact(aliases[artifact_key], {'aliases', 'protected'},
                             f'FILE {artifact_key} protected account')
            protected = artifact['protected']
            require(type(protected) is dict and set(protected) == set(stdio_alias_evidence.PROTECTED),
                    f'FILE {artifact_key} protected roster differs')
            occurrence = _stdio_alias_occurrence(
                occurrences, artifact_key=artifact_key, observation=protected[name],
                description=f'FILE {artifact_key} protected body {name}',
            )
            require(occurrence['row'].get('type') == 'FUNC'
                    and occurrence['row'].get('binding') == 'GLOBAL'
                    and occurrence['row'].get('visibility') == 'PROTECTED',
                    f'FILE {artifact_key} protected metadata differs: {name}')
            retained.append(occurrence['index'])
        require(static_occurrence['index'] in retained and shared_occurrence['index'] not in retained,
                f'FILE protected candidate table domain differs: {name}')
        protected_joins.append({
            'identity': copy.deepcopy(record['identity']),
            'static_occurrence_index': static_occurrence['index'],
            'shared_dynsym_occurrence_index': shared_occurrence['index'],
            'retained_symtab_occurrence_indices': retained,
            'runtime_control_observed': True,
        })
    return [{'aliases': alias_joins, 'private_bodies': private_joins, 'protected_controls': protected_joins}]


def _syscall_named_rows(occurrences: Mapping[int, Mapping[str, Any]], name: str) -> list[dict[str, Any]]:
    """Filter the already-accounted roster before converting a named identity.

    ``account_placements`` retains unnamed rows as physical observations.  This
    finite component must never feed those rows into identity conversion or
    reduce the overall occurrence roster while looking up its named scope.
    """
    return [dict(occurrence) for occurrence in occurrences.values()
            if type(occurrence.get('row')) is dict and occurrence['row'].get('name') == name]


def _syscall_one_row(rows: Sequence[Mapping[str, Any]], *, artifact_key: str, table: str,
                     role: str, metadata: Mapping[str, str], description: str) -> dict[str, Any]:
    matches = [row for row in rows
               if row.get('artifact_key') == artifact_key and row.get('table') == table
               and row.get('role') == role
               and all(row.get('row', {}).get(field) == value for field, value in metadata.items())]
    require(len(matches) == 1, f'{description} exact candidate occurrence differs')
    return dict(matches[0])


def attach_native_syscall_alias(accounting: Mapping[str, Any],
                                companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Attach the finite alias/body observations without selecting new owners.

    Public aliases and private bodies remain distinct identities.  The receipt
    authenticates their shape and same-definition domains, but no unresolved
    owner or unrelated physical occurrence is removed from selection.
    """
    if companion is None:
        return []
    companion = exact(companion, {
        'status', 'reader', 'report', 'source', 'source_inputs', 'products', 'measurement_reports',
        'projection', 'limits',
    }, 'syscall alias companion')
    require(companion['status'] == 'syscall-alias-observed-with-boundaries'
            and companion['limits'] == SYSCALL_ALIAS_LIMITS,
            'syscall alias companion boundary differs')
    reader = _syscall_alias_reader()
    projection = _syscall_alias_projection(reader)
    require(same(companion['projection'], projection)
            and same(companion['source_inputs'], {
                name: file_identity(ROOT / name) for name in _syscall_alias_source_files()
            }), 'syscall alias companion source differs')
    records, placements, occurrences = _accounting_indexes(
        accounting, description='syscall alias attachment',
    )
    occurrence_count = len(occurrences)
    aliases = tuple((str(name), str(body)) for name, body in projection['aliases'])
    global_hidden = tuple(str(name) for name in projection['global_hidden'])
    local_bodies = tuple(str(name) for name in projection['source_local'])
    known_names = {name for name, _body in aliases} | set(global_hidden) | set(local_bodies)
    joins: list[dict[str, Any]] = []
    expected_indices: set[int] = set()
    public_metadata = {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'}
    for public, body in aliases:
        alias_rows = _syscall_named_rows(occurrences, public)
        target_rows = _syscall_named_rows(occurrences, body)
        static_alias = _syscall_one_row(alias_rows, artifact_key='candidate-static', table='.symtab',
                                        role='definition', metadata=public_metadata,
                                        description=f'syscall alias {public} static')
        shared_dyn = _syscall_one_row(alias_rows, artifact_key='candidate-shared', table='.dynsym',
                                      role='definition', metadata=public_metadata,
                                      description=f'syscall alias {public} shared dynsym')
        shared_alias = _syscall_one_row(alias_rows, artifact_key='candidate-shared', table='.symtab',
                                        role='definition', metadata=public_metadata,
                                        description=f'syscall alias {public} shared symtab')
        target_metadata = ({'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'}
                           if body in local_bodies else {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'})
        static_role = 'local-definition' if body in local_bodies else 'definition'
        static_target = _syscall_one_row(target_rows, artifact_key='candidate-static', table='.symtab',
                                         role=static_role, metadata=target_metadata,
                                         description=f'syscall body {body} static')
        shared_target = _syscall_one_row(target_rows, artifact_key='candidate-shared', table='.symtab',
                                         role='local-definition', metadata={'type': 'FUNC', 'binding': 'LOCAL'},
                                         description=f'syscall body {body} shared')
        require(shared_target['row'].get('visibility') in {'DEFAULT', 'HIDDEN'},
                f'syscall body {body} shared visibility differs')
        require(not [row for row in target_rows if row.get('artifact_key') == 'candidate-shared'
                     and row.get('table') == '.dynsym' and row.get('role') in {'definition', 'local-definition'}],
                f'syscall private body leaked to candidate dynsym: {body}')
        require(same_definition_domain(static_alias, static_target)
                and same_definition_domain(shared_alias, shared_target),
                f'syscall alias/body definition domain differs: {public}')
        indices = {row['index'] for row in (static_alias, shared_dyn, shared_alias, static_target, shared_target)}
        expected_indices.update(indices)
        joins.append({
            'public_alias': public,
            'private_body': body,
            'static_alias_occurrence_index': static_alias['index'],
            'shared_dynsym_alias_occurrence_index': shared_dyn['index'],
            'shared_symtab_alias_occurrence_index': shared_alias['index'],
            'static_body_occurrence_index': static_target['index'],
            'shared_body_occurrence_index': shared_target['index'],
            'requirements_discharged': [],
        })
    private_joins: list[dict[str, Any]] = []
    for body in global_hidden:
        key = (body, None, False)
        record = records.get(key)
        require(record is not None and record.get('selection', {}).get('disposition') == 'private-provider'
                and record['selection'].get('owner') == SYSCALL_ALIAS_PRIVATE_OWNER
                and record['selection'].get('group') == SYSCALL_ALIAS_PRIVATE_GROUP,
                f'syscall private body selection differs: {body}')
        rows = _syscall_named_rows(occurrences, body)
        static_body = _syscall_one_row(rows, artifact_key='candidate-static', table='.symtab', role='definition',
                                       metadata={'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'},
                                       description=f'syscall private body {body} static')
        shared_body = _syscall_one_row(rows, artifact_key='candidate-shared', table='.symtab', role='local-definition',
                                       metadata={'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'HIDDEN'},
                                       description=f'syscall private body {body} shared')
        static_placement, static_selected = _selected_placement(
            placements, occurrences, name=body, artifact_key='candidate-static', table='.symtab', role='definition',
            metadata={'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'},
            description=f'syscall private body {body} selected static',
        )
        shared_placement, shared_selected = _selected_placement(
            placements, occurrences, name=body, artifact_key='candidate-shared', table='.symtab', role='local-definition',
            metadata={'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'HIDDEN'},
            description=f'syscall private body {body} selected shared',
        )
        require(static_selected['index'] == static_body['index']
                and shared_selected['index'] == shared_body['index'],
                f'syscall private body selected occurrence differs: {body}')
        require(not [row for row in rows if row.get('artifact_key') == 'candidate-shared'
                     and row.get('table') == '.dynsym' and row.get('role') in {'definition', 'local-definition'}],
                f'syscall private body leaked to candidate dynsym: {body}')
        _remove_identity_requirements(
            accounting, record, (SYSCALL_ALIAS_RECEIPT_REQUIREMENT,),
            description=f'syscall private body {body}',
        )
        expected_indices.update({static_body['index'], shared_body['index']})
        private_joins.append({
            'identity': copy.deepcopy(record['identity']), 'body': body, 'scope': 'global-hidden',
            'static_occurrence_index': static_body['index'],
            'shared_occurrence_index': shared_body['index'],
            'static_metadata': copy.deepcopy(static_placement['expected_metadata']),
            'shared_metadata': copy.deepcopy(shared_placement['expected_metadata']),
            'candidate_dynsym_definition_absent': True,
            'requirements_discharged': [SYSCALL_ALIAS_RECEIPT_REQUIREMENT],
        })
    for body in local_bodies:
        rows = _syscall_named_rows(occurrences, body)
        static_body = _syscall_one_row(rows, artifact_key='candidate-static', table='.symtab', role='local-definition',
                                       metadata={'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'},
                                       description=f'syscall local body {body} static')
        shared_body = _syscall_one_row(rows, artifact_key='candidate-shared', table='.symtab', role='local-definition',
                                       metadata={'type': 'FUNC', 'binding': 'LOCAL'},
                                       description=f'syscall local body {body} shared')
        require(shared_body['row'].get('visibility') in {'DEFAULT', 'HIDDEN'},
                f'syscall local body {body} shared visibility differs')
        expected_indices.update({static_body['index'], shared_body['index']})
        private_joins.append({'body': body, 'scope': 'source-local',
                              'static_occurrence_index': static_body['index'],
                              'shared_occurrence_index': shared_body['index'],
                              'requirements_discharged': []})
    actual_indices = {row['index'] for row in occurrences.values()
                      if row.get('artifact_key') in {'candidate-static', 'candidate-shared'}
                      and type(row.get('row')) is dict and row['row'].get('name') in known_names}
    require(actual_indices == expected_indices, 'syscall alias candidate occurrence roster differs')
    require(len(occurrences) == occurrence_count, 'syscall alias attachment changed complete ELF occurrence roster')
    require(len(joins) == 14 and len(private_joins) == 15
            and [row['body'] for row in private_joins] == [*global_hidden, *local_bodies],
            'syscall alias finite attachment cardinality differs')
    return [{'aliases': joins, 'private_bodies': private_joins,
             'requirements_discharged': [SYSCALL_ALIAS_RECEIPT_REQUIREMENT],
             'complete_elf_occurrence_count': occurrence_count}]


def _compiler_helper_shared_contract(contract: Mapping[str, Any], inputs: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Authenticate the finite helper source selection before using its DSO view.

    The producer reader owns the archive and private-libc observations.  This
    adapter only consumes that already validated projection for the exact
    source-selected group; it cannot use an archive spelling or an arbitrary
    LOCAL symbol as a new helper provider.
    """
    helper_contract = compiler_helpers.load_contract(ROOT)
    names = list(compiler_helpers.helper_names(helper_contract))
    groups = [row for row in contract['owner_groups'] if row['id'] == COMPILER_HELPER_GROUP]
    require(len(groups) == 1, 'compiler-helper owner group is absent or duplicated')
    group = groups[0]
    archive_metadata = {key: compiler_helpers.HELPER_METADATA[key]
                        for key in ('type', 'binding', 'visibility')}
    require(group['selector'] == 'explicit'
            and group['disposition'] == 'private-provider'
            and group['owner'] == 'builtins'
            and group['family'] == 'crt.static-pie'
            and group['artifacts'] == list(compiler_helpers.ARCHIVE_PLACEMENTS)
            and group['sources'] == [helper_contract['source'], helper_contract['builder'], compiler_helpers.CONTRACT.as_posix()]
            and group['members'] == names
            and group['members_file'] == ''
            and group['expected_type'] == 'FUNC'
            and group['delegated_members'] == []
            and group['placement_metadata'] == {
                placement: {'binding': 'GLOBAL', 'visibility': 'DEFAULT'}
                for placement in compiler_helpers.ARCHIVE_PLACEMENTS
            }
            and group['static_metadata_rule'] == 'explicit',
            'compiler-helper owner scope differs')
    source_inputs = {}
    for path in compiler_helpers.SOURCE_FILES:
        name = path.as_posix()
        binding = inputs['bindings'].get(name)
        require(binding is not None and same(binding, file_identity(ROOT / name)),
                f'compiler-helper source input differs: {name}')
        source_inputs[name] = copy.deepcopy(binding)
    shared = exact(helper_contract['shared_libc'], set(compiler_helpers.SHARED_LIBC_METADATA),
                   'compiler-helper source shared-libc contract')
    require(same(shared, compiler_helpers.SHARED_LIBC_METADATA),
            'compiler-helper source shared-libc contract differs')
    shared_metadata = {key: shared[key] for key in ('type', 'binding', 'visibility')}
    require(shared_metadata == {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'DEFAULT'},
            'compiler-helper source shared-libc metadata differs')
    return helper_contract, source_inputs, shared_metadata


def _validated_compiler_helper_shared_projection(companion: Mapping[str, Any], helper_contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return the reader-authenticated local libc rows without selecting them yet."""
    companion = exact(companion, {'report', 'reader', 'account'}, 'compiler-helper companion')
    exact(companion['report'], {'path', 'sha256', 'size', 'mode'}, 'compiler-helper aggregate report identity')
    exact(companion['reader'], {'path', 'sha256', 'size', 'mode'}, 'compiler-helper reader identity')
    account = exact(companion['account'], {
        'source', 'archive_placements', 'installed_archive_identities', 'aggregate_c_abi',
        'shared_libc_projection', 'shared_placement_selected', 'family_completion',
        'public_support', 'ordinary_popcount_import',
    }, 'compiler-helper account')
    require(same(account['source'], compiler_helpers.source_binding(ROOT, helper_contract)),
            'compiler-helper account source differs from the selecting checkout')
    require(type(account['aggregate_c_abi']) is dict and account['aggregate_c_abi'].get('status') == 'joined',
            'compiler-helper aggregate is not joined to both archive roles')
    require(account['shared_placement_selected'] is False
            and account['family_completion'] is False and account['public_support'] is False,
            'compiler-helper account exceeds its producer scope')
    names = list(compiler_helpers.helper_names(helper_contract))
    archive_metadata = dict(compiler_helpers.HELPER_METADATA)
    archive_placements = exact(account['archive_placements'], set(compiler_helpers.ARCHIVE_PLACEMENTS),
                               'compiler-helper archive placement roster')
    for placement in compiler_helpers.ARCHIVE_PLACEMENTS:
        placement_rows = archive_placements[placement]
        require(type(placement_rows) is dict and set(placement_rows) == set(names),
                f'compiler-helper {placement} projection roster differs')
        for name in names:
            row = exact(placement_rows[name], {'member', 'section', 'metadata'},
                        f'compiler-helper {placement} projection {name}')
            require(row['member'] == helper_contract['archive']['member']
                    and row['section'] == '.text.' + name and same(row['metadata'], archive_metadata),
                    f'compiler-helper {placement} projection differs: {name}')
    identities = exact(account['installed_archive_identities'], set(compiler_helpers.ARCHIVE_PLACEMENTS),
                       'compiler-helper installed archive roster')
    for placement in compiler_helpers.ARCHIVE_PLACEMENTS:
        row = exact(identities[placement], {'path', 'sha256', 'size'},
                    f'compiler-helper installed archive identity {placement}')
        require(type(row['path']) is str and row['path']
                and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
                and type(row['size']) is int and row['size'] > 0,
                f'compiler-helper installed archive identity differs: {placement}')
    projection = account['shared_libc_projection']
    require(type(projection) is dict and set(projection) == set(names),
            'compiler-helper private libc projection roster differs')
    metadata = {key: helper_contract['shared_libc'][key] for key in ('type', 'binding', 'visibility')}
    result = {}
    for name in names:
        row = exact(projection[name], {'table', 'row_index', 'section_index', 'section', 'metadata'},
                    f'compiler-helper private libc projection {name}')
        require(row['table'] == '.symtab' and type(row['row_index']) is int and row['row_index'] >= 0
                and type(row['section_index']) is int and row['section_index'] > 0
                and type(row['section']) is str and row['section']
                and same(row['metadata'], metadata),
                f'compiler-helper private libc projection differs: {name}')
        result[name] = copy.deepcopy(row)
    return result


def attach_compiler_helper_shared_placement(expanded: Sequence[Mapping[str, Any]], companion: Mapping[str, Any] | None,
                                            contract: Mapping[str, Any], inputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Select the exact private shared-libc helper copies from their own reader.

    Archive provider selection stays in the TOML group.  The third placement is
    attached only after the helper reader has authenticated the selected
    product's private ``.symtab`` projection and exact archive policy.
    """
    if companion is None:
        return []
    helper_contract, _source_inputs, shared_metadata = _compiler_helper_shared_contract(contract, inputs)
    projection = _validated_compiler_helper_shared_projection(companion, helper_contract)
    records = {}
    for record in expanded:
        key = identity_key(record['identity'])
        require(key not in records, 'expanded identity is duplicated before compiler-helper shared attachment')
        records[key] = record
    names = set(projection)
    selected = []
    for name in names:
        record = records.get(identity_key(identity(name)))
        require(record is not None and identity_key(record['identity']) == (name, None, False),
                f'compiler-helper identity differs: {name}')
        selection_record = record['selection']
        require(selection_record.get('group') == COMPILER_HELPER_GROUP
                and selection_record.get('disposition') == 'private-provider'
                and selection_record.get('owner') == 'builtins',
                f'compiler-helper selected owner differs: {name}')
        selected.append(record)
    require({identity_key(record['identity'])[0] for record in selected} == names,
            'compiler-helper selected owner roster differs')
    archive_metadata = {key: compiler_helpers.HELPER_METADATA[key]
                        for key in ('type', 'binding', 'visibility')}
    pending = []
    for record in sorted(selected, key=lambda row: identity_key(row['identity'])):
        name = record['identity']['name']
        placements = {row['artifact_key']: row for row in record['expected_placements']}
        require(len(placements) == len(record['expected_placements'])
                and set(placements) == set(compiler_helpers.ARCHIVE_PLACEMENTS),
                f'compiler-helper existing placement scope differs: {name}')
        for placement in compiler_helpers.ARCHIVE_PLACEMENTS:
            row = placements[placement]
            require(row.get('metadata_rule') == 'explicit' and same(row.get('metadata'), archive_metadata),
                    f'compiler-helper archive placement differs: {name}')
        record['expected_placements'].append({
            'artifact_key': COMPILER_HELPER_SHARED_ARTIFACT,
            'metadata': copy.deepcopy(shared_metadata),
            'metadata_rule': COMPILER_HELPER_SHARED_METADATA_RULE,
        })
        pending.append({
            'identity': copy.deepcopy(record['identity']),
            'artifact_key': COMPILER_HELPER_SHARED_ARTIFACT,
            'metadata': copy.deepcopy(shared_metadata),
            'projection': copy.deepcopy(projection[name]),
            'owner_group': COMPILER_HELPER_GROUP,
            'owner': 'builtins',
        })
    require(len(pending) == len(names) == 23, 'compiler-helper private shared placement count differs')
    return pending


def bind_compiler_helper_shared_placement_joins(accounting: Mapping[str, Any], pending: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Bind the selected rows back to the producer reader's raw ``.symtab`` view."""
    if not pending:
        return []
    placement_index = {}
    for row in accounting['placement_joins']:
        key = (identity_key(row['identity']), row['artifact_key'])
        require(key not in placement_index, 'duplicate placement join while binding compiler-helper shared rows')
        placement_index[key] = row
    occurrences = {row['index']: row for row in accounting['occurrences']}
    require(len(occurrences) == len(accounting['occurrences']), 'duplicate occurrence while binding compiler-helper shared rows')
    result = []
    for pending_row in pending:
        pending_row = exact(pending_row, {'identity', 'artifact_key', 'metadata', 'projection', 'owner_group', 'owner'},
                            'compiler-helper pending shared placement')
        identity_value = pending_row['identity']
        require(identity_key(identity_value)[1:] == (None, False)
                and pending_row['artifact_key'] == COMPILER_HELPER_SHARED_ARTIFACT
                and pending_row['owner_group'] == COMPILER_HELPER_GROUP and pending_row['owner'] == 'builtins',
                'compiler-helper pending shared identity differs')
        projection = exact(pending_row['projection'], {'table', 'row_index', 'section_index', 'section', 'metadata'},
                           'compiler-helper pending shared projection')
        joined = placement_index.get((identity_key(identity_value), COMPILER_HELPER_SHARED_ARTIFACT))
        require(joined is not None and same(joined['expected_metadata'], pending_row['metadata'])
                and joined['placement_observed'] is True and _metadata_difference_rows_are_empty(
                    joined.get('metadata_differences'), 'compiler-helper private shared placement')
                and joined['definition_count'] == 1 and len(joined['occurrence_indices']) == 1,
                'compiler-helper private shared placement is absent, ambiguous or mismatched')
        occurrence = occurrences.get(joined['occurrence_indices'][0])
        require(occurrence is not None and occurrence['artifact_key'] == COMPILER_HELPER_SHARED_ARTIFACT
                and occurrence['table'] == projection['table'] == '.symtab'
                and occurrence['member_index'] is None and occurrence['member_occurrence'] is None
                and occurrence['role'] == 'local-definition'
                and same(row_identity(occurrence['row']), identity_value)
                and occurrence['row']['row_index'] == projection['row_index']
                and occurrence['row']['section_index'] == str(projection['section_index'])
                and type(occurrence['definition_section']) is dict
                and occurrence['definition_section'].get('name') == projection['section'],
                'compiler-helper private shared projection does not bind the selected ELF row')
        # Complete facts retain the ELF null rows in both symbol tables.  Do
        # not construct a logical identity until this is a named defining
        # ``.dynsym`` row; an unrelated unnamed ``.symtab``/``.dynsym`` row
        # is still retained in the report but cannot be compared as a helper
        # export.
        leaked = [row for row in accounting['occurrences']
                  if row['artifact_key'] == COMPILER_HELPER_SHARED_ARTIFACT
                  and row['table'] == '.dynsym' and row['row'].get('section_index') != 'UND'
                  and row['row'].get('name') == identity_value['name']
                  and row['row'].get('version') == identity_value['version']
                  and row['row'].get('version_default') == identity_value['version_default']
                  and same(row_identity(row['row']), identity_value)]
        require(not leaked, 'compiler-helper private shared definition leaked into dynsym')
        result.append({
            **copy.deepcopy(pending_row),
            'occurrence_indices': list(joined['occurrence_indices']),
            'definition_count': joined['definition_count'],
            'placement_observed': joined['placement_observed'],
        })
    return result


def attach_compiler_helper_import(accounting: Mapping[str, Any], companion: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Discharge only the exact ordinary static import covered by both maps.

    Other candidate imports of the same spelling retain the generic unresolved
    reason. Member occurrence and symbol-table row distinguish the actual
    consumer from a same-name import in another archive member.
    """
    if companion is None or companion['account']['ordinary_popcount_import'] is None:
        return []
    claim = companion['account']['ordinary_popcount_import']
    require(claim['identity'] == '__popcountdi2' and claim['consumer_artifact'] == 'candidate-static'
            and claim['provider_placement'] == 'static-builtins' and claim['provider_member'] == 'crabc-builtins.o'
            and claim['provider_section'] == '.text.__popcountdi2', 'compiler-helper ordinary import boundary differs')
    candidate_artifacts = {artifact.key for artifact in elf_facts.ARTIFACTS if artifact.owner != 'reference'}
    joins = []
    for record in accounting['identities']:
        if not same(record['identity'], identity('__popcountdi2')) or ORDINARY_IMPORT_REASON not in record['unresolved']:
            continue
        require(record['selection'].get('owner') == 'builtins', 'compiler-helper import owner differs')
        imports = [row for row in accounting['occurrences'] if row['role'] == 'import'
                   and row['row']['name'] == '__popcountdi2' and row['artifact_key'] in candidate_artifacts]
        covered = len(imports) == 1 and all(
            row['artifact_key'] == 'candidate-static' and row['table'] == '.symtab'
            and row['member_name'] == claim['consumer_member']
            and row['member_index'] == claim['consumer_member_index']
            and row['member_occurrence'] == claim['consumer_member_occurrence']
            and row['row']['row_index'] == claim['consumer_symtab_row']
            and row['accounting'] == {'disposition': 'private-provider', 'owner': 'builtins', 'scope': 'candidate-static'}
            for row in imports
        )
        joins.append({'identity': copy.deepcopy(record['identity']), 'owner': 'builtins',
                      'occurrence_indices': [row['index'] for row in imports],
                      'ordinary_link_covered': covered, 'discharged_reason': ORDINARY_IMPORT_REASON if covered else None})
        if covered:
            record['unresolved'].remove(ORDINARY_IMPORT_REASON)
            accounting['blockers'][:] = [row for row in accounting['blockers']
                                        if not (row['code'] == 'identity-unresolved'
                                                and same(row['identity'], record['identity']) and row['reason'] == ORDINARY_IMPORT_REASON)]
    return joins


def _build_report(*, contract_path: Path, paths: Mapping[str, Path], declaration_report: Path | None,
                  ordinary_declaration_abi_report: Path | None = None,
                  ordinary_link_report: Path | None = None, loader_debug_report: Path | None = None,
                  compiler_helper_aggregate_report: Path | None = None,
                  loader_runtime_registry_report: Path | None = None,
                  pthread_alias_contract_report: Path | None = None,
                  prepared_worker_tls_report: Path | None = None,
                  errno_storage_lifecycle_report: Path | None = None,
                  native_c_allocator_boundary_report: Path | None = None,
                  stdio_alias_contract_report: Path | None = None,
                  crt_startup_report: Path | None = None,
                  syscall_alias_contract_report: Path | None = None,
                  utmpx_receipt_report: Path | None = None) -> dict[str, Any]:
    source_before = selection_source()
    contract = load_contract(contract_path)
    inputs = load_source_inputs(contract, contract_path)
    facts, measurement = replay_measurement(paths)
    fixed_c_producer_metadata_companion = fixed_c_producer_metadata_adapter(
        facts, measurement, paths, contract, inputs,
    )
    # These finite supplied-product readers do not consume header facts. Admit
    # them before the expensive declaration envelope so malformed runtime
    # evidence fails without paying for a second long compiler-report replay.
    # They are still attached only after the common placement accounting below.
    loader_runtime_registry_companion = loader_runtime_registry_adapter(
        loader_runtime_registry_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    pthread_alias_contract_companion = pthread_alias_contract_adapter(
        pthread_alias_contract_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    prepared_worker_tls_companion = prepared_worker_tls_adapter(
        prepared_worker_tls_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    errno_storage_lifecycle_companion = errno_storage_lifecycle_adapter(
        errno_storage_lifecycle_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    native_c_allocator_boundary_companion = native_c_allocator_boundary_adapter(
        native_c_allocator_boundary_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
        fixed_c_companion=fixed_c_producer_metadata_companion,
    )
    stdio_alias_contract_companion = native_stdio_alias_adapter(
        stdio_alias_contract_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    crt_startup_companion = native_crt_startup_adapter(
        crt_startup_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    syscall_alias_contract_companion = native_syscall_alias_adapter(
        syscall_alias_contract_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    utmpx_receipt_companion = native_utmpx_adapter(
        utmpx_receipt_report, facts=facts, measurement=measurement, paths=paths, source=source_before,
    )
    declaration = declaration_adapter(
        declaration_report,
        selected_objects=contract['object_contracts'],
        provider_names=inputs['provider_names'],
        deferred=inputs['deferred'],
        abi_only_callables=inputs['abi_only_callables'],
        callable_matrix_projection=inputs['callable_declaration_matrix'],
        ordinary_declaration_abi_report=ordinary_declaration_abi_report,
    )
    public_data_linkage_companion = public_data_linkage_adapter(
        ordinary_link_report, loader_debug_report, contract=contract,
        selected_objects=contract['object_contracts'], source=source_before, paths=paths,
    )
    compiler_helper_companion = compiler_helper_adapter(
        compiler_helper_aggregate_report, ordinary_report_path=ordinary_link_report, paths=paths,
    )
    expanded = expand_obligations(contract, inputs)
    fixed_c_producer_metadata_pending = attach_fixed_c_producer_metadata(
        expanded, fixed_c_producer_metadata_companion,
    )
    compiler_helper_shared_placement_pending = attach_compiler_helper_shared_placement(
        expanded, compiler_helper_companion, contract, inputs,
    )
    accounting = account_placements(expanded, facts)
    fixed_c_producer_metadata_joins = bind_fixed_c_producer_metadata_joins(
        accounting, fixed_c_producer_metadata_pending,
    )
    compiler_helper_shared_placement_joins = bind_compiler_helper_shared_placement_joins(
        accounting, compiler_helper_shared_placement_pending,
    )
    public_data_linkage_joins = attach_public_data_linkage(accounting, public_data_linkage_companion)
    compiler_helper_import_joins = attach_compiler_helper_import(accounting, compiler_helper_companion)
    loader_runtime_registry_joins = attach_loader_runtime_registry(accounting, loader_runtime_registry_companion)
    pthread_alias_contract_joins = attach_pthread_alias_contract(accounting, pthread_alias_contract_companion)
    prepared_worker_tls_joins = attach_prepared_worker_tls(accounting, prepared_worker_tls_companion)
    errno_storage_lifecycle_joins = attach_errno_storage_lifecycle(
        accounting, errno_storage_lifecycle_companion, inputs,
    )
    native_c_allocator_boundary_joins = attach_native_c_allocator_boundary(
        accounting, native_c_allocator_boundary_companion,
    )
    stdio_alias_contract_joins = attach_native_stdio_alias(
        accounting, stdio_alias_contract_companion,
    )
    crt_startup_joins = attach_native_crt_startup(accounting, crt_startup_companion)
    crt_descriptor_handoff_joins = attach_native_crt_descriptor_handoff(accounting, crt_startup_companion)
    syscall_alias_contract_joins = attach_native_syscall_alias(accounting, syscall_alias_contract_companion)
    utmpx_receipt_joins = attach_native_utmpx(accounting, utmpx_receipt_companion)
    _recheck_runtime_receipt_cohort(
        paths=paths, facts=facts, measurement=measurement, source=source_before,
        registry=loader_runtime_registry_companion, pthread=pthread_alias_contract_companion,
        prepared_worker=prepared_worker_tls_companion, errno_storage=errno_storage_lifecycle_companion,
        c_allocator_boundary=native_c_allocator_boundary_companion,
        stdio_alias_contract=stdio_alias_contract_companion,
        crt_startup=crt_startup_companion, syscall_alias=syscall_alias_contract_companion,
        utmpx=utmpx_receipt_companion,
    )
    candidate = measurement['candidate_build']
    source_matches = source_before['clean'] is True and source_before['revision'] == candidate['revision'] and source_before['content_sha256'] == candidate['source_content_sha256']
    blockers = accounting.pop('blockers')
    blockers.extend(evidence_blockers(declaration=declaration, semantic_receipts=[], family_receipts=[], source_matches=source_matches))
    for family in inputs['families']:
        blockers.append({'code': 'family-semantic-evidence-unavailable', 'family': family['id'], 'ledger_status': family['status']})
    require(same(source_before, selection_source()), 'selection source changed while building report')
    require(same(inputs['bindings'], load_source_inputs(contract, contract_path)['bindings']), 'selection input bytes changed during report')
    blockers = sorted(blockers, key=lambda item: json.dumps(item, sort_keys=True))
    return {'schema': SCHEMA, 'target': TARGET, 'selection_source': source_before, 'source_inputs': inputs,
            'contract': contract, 'measurement': measurement, 'declaration_companion': declaration,
            'fixed_c_producer_metadata_companion': fixed_c_producer_metadata_companion,
            'fixed_c_producer_metadata_joins': fixed_c_producer_metadata_joins,
            'public_data_linkage_companion': public_data_linkage_companion,
            'public_data_linkage_joins': public_data_linkage_joins,
            'compiler_helper_companion': compiler_helper_companion,
            'compiler_helper_shared_placement_joins': compiler_helper_shared_placement_joins,
            'compiler_helper_import_joins': compiler_helper_import_joins,
            'loader_runtime_registry_companion': loader_runtime_registry_companion,
            'loader_runtime_registry_joins': loader_runtime_registry_joins,
            'pthread_alias_contract_companion': pthread_alias_contract_companion,
            'pthread_alias_contract_joins': pthread_alias_contract_joins,
            'prepared_worker_tls_companion': prepared_worker_tls_companion,
            'prepared_worker_tls_joins': prepared_worker_tls_joins,
            'errno_storage_lifecycle_companion': errno_storage_lifecycle_companion,
            'errno_storage_lifecycle_joins': errno_storage_lifecycle_joins,
            'native_c_allocator_boundary_companion': native_c_allocator_boundary_companion,
            'native_c_allocator_boundary_joins': native_c_allocator_boundary_joins,
            'stdio_alias_contract_companion': stdio_alias_contract_companion,
            'stdio_alias_contract_joins': stdio_alias_contract_joins,
            'crt_startup_companion': crt_startup_companion,
            'crt_startup_joins': crt_startup_joins,
            'crt_descriptor_handoff_joins': crt_descriptor_handoff_joins,
            'syscall_alias_contract_companion': syscall_alias_contract_companion,
            'syscall_alias_contract_joins': syscall_alias_contract_joins,
            'utmpx_receipt_companion': utmpx_receipt_companion,
            'utmpx_receipt_joins': utmpx_receipt_joins,
            **accounting, 'closure': {'complete': not blockers, 'blockers': blockers}, 'status': dict(STATUS),
            'limits': ['selection audit is not qualification', 'complete raw ELF observations stay with the publicly replayed supplement',
                       'no allocator metadata or unwinder investigation', 'no imported AArch64 execution proof',
                       'public-data linkage is scoped evidence; aggregate semantic and family receipt adapters remain unavailable']}


def build_report(*, output: Path, contract_path: Path = CONTRACT_PATH, declaration_report: Path | None = None,
                 ordinary_declaration_abi_report: Path | None = None,
                 ordinary_link_report: Path | None = None, loader_debug_report: Path | None = None,
                 compiler_helper_aggregate_report: Path | None = None,
                 loader_runtime_registry_report: Path | None = None,
                 pthread_alias_contract_report: Path | None = None,
                 prepared_worker_tls_report: Path | None = None,
                 errno_storage_lifecycle_report: Path | None = None,
                 native_c_allocator_boundary_report: Path | None = None,
                 stdio_alias_contract_report: Path | None = None,
                 crt_startup_report: Path | None = None,
                 syscall_alias_contract_report: Path | None = None,
                 utmpx_receipt_report: Path | None = None,
                 **measurement_inputs: Path) -> dict[str, Any]:
    output = physical_work_path(output, directory=True, own=True, fresh=True)
    paths = validate_measurement_paths(**measurement_inputs)
    contract_path = Path(os.path.abspath(contract_path))
    require(contract_path.is_relative_to(ROOT) and contract_path.resolve() == contract_path and contract_path.is_file(), 'contract must be a physical read-only checkout source')
    report = _build_report(contract_path=contract_path, paths=paths, declaration_report=declaration_report,
                           ordinary_declaration_abi_report=ordinary_declaration_abi_report,
                           ordinary_link_report=ordinary_link_report, loader_debug_report=loader_debug_report,
                           compiler_helper_aggregate_report=compiler_helper_aggregate_report,
                           loader_runtime_registry_report=loader_runtime_registry_report,
                           pthread_alias_contract_report=pthread_alias_contract_report,
                           prepared_worker_tls_report=prepared_worker_tls_report,
                           errno_storage_lifecycle_report=errno_storage_lifecycle_report,
                           native_c_allocator_boundary_report=native_c_allocator_boundary_report,
                           stdio_alias_contract_report=stdio_alias_contract_report,
                           crt_startup_report=crt_startup_report,
                           syscall_alias_contract_report=syscall_alias_contract_report,
                           utmpx_receipt_report=utmpx_receipt_report)
    output.mkdir()
    (output / 'report.json').write_bytes(inventory._stable_json(report))
    return report


def validate_report(report_path: Path, *, contract_path: Path = CONTRACT_PATH, declaration_report: Path | None = None,
                    ordinary_declaration_abi_report: Path | None = None,
                    ordinary_link_report: Path | None = None, loader_debug_report: Path | None = None,
                    compiler_helper_aggregate_report: Path | None = None,
                    loader_runtime_registry_report: Path | None = None,
                    pthread_alias_contract_report: Path | None = None,
                    prepared_worker_tls_report: Path | None = None,
                    errno_storage_lifecycle_report: Path | None = None,
                    native_c_allocator_boundary_report: Path | None = None,
                    stdio_alias_contract_report: Path | None = None,
                    crt_startup_report: Path | None = None,
                    syscall_alias_contract_report: Path | None = None,
                    utmpx_receipt_report: Path | None = None,
                    **measurement_inputs: Path) -> dict[str, Any]:
    report_path = physical_work_path(report_path, directory=False, own=True)
    require(report_path.name == 'report.json', 'selection report has the wrong name')
    paths = validate_measurement_paths(**measurement_inputs)
    report = read_json(report_path)
    contract_path = Path(os.path.abspath(contract_path))
    require(contract_path.is_relative_to(ROOT) and contract_path.resolve() == contract_path and contract_path.is_file(), 'contract must be a physical read-only checkout source')
    expected = _build_report(contract_path=contract_path, paths=paths, declaration_report=declaration_report,
                             ordinary_declaration_abi_report=ordinary_declaration_abi_report,
                             ordinary_link_report=ordinary_link_report, loader_debug_report=loader_debug_report,
                             compiler_helper_aggregate_report=compiler_helper_aggregate_report,
                             loader_runtime_registry_report=loader_runtime_registry_report,
                             pthread_alias_contract_report=pthread_alias_contract_report,
                             prepared_worker_tls_report=prepared_worker_tls_report,
                             errno_storage_lifecycle_report=errno_storage_lifecycle_report,
                             native_c_allocator_boundary_report=native_c_allocator_boundary_report,
                             stdio_alias_contract_report=stdio_alias_contract_report,
                             crt_startup_report=crt_startup_report,
                             syscall_alias_contract_report=syscall_alias_contract_report,
                             utmpx_receipt_report=utmpx_receipt_report)
    require(same(report, expected), 'selection report does not reconstruct exactly from source inputs and public measurement replay')
    return report


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument('mode', choices=('build-report', 'validate-report', 'require-closure'))
    parser.add_argument('report', nargs='?', type=Path)
    for option in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
        parser.add_argument('--' + option, required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--contract', type=Path, default=CONTRACT_PATH)
    parser.add_argument('--declaration-report', type=Path)
    parser.add_argument('--ordinary-declaration-abi-report', type=Path)
    parser.add_argument('--public-data-ordinary-link-report', type=Path)
    parser.add_argument('--loader-debug-abi-report', type=Path)
    parser.add_argument('--compiler-helper-aggregate-report', type=Path)
    parser.add_argument('--loader-runtime-registry-report', type=Path)
    parser.add_argument('--pthread-alias-contract-report', type=Path)
    parser.add_argument('--prepared-worker-tls-report', type=Path)
    parser.add_argument('--errno-storage-lifecycle-report', type=Path)
    parser.add_argument('--native-c-allocator-boundary-report', type=Path)
    parser.add_argument('--stdio-alias-contract-report', type=Path)
    parser.add_argument('--crt-startup-report', type=Path)
    parser.add_argument('--syscall-alias-contract-report', type=Path)
    parser.add_argument('--utmpx-receipt-report', type=Path)
    options = [arg.split('=', 1)[0] for arg in argv if arg.startswith('--')]
    if len(options) != len(set(options)):
        parser.error('duplicate options are not accepted')
    args = parser.parse_args(argv)
    if (args.public_data_ordinary_link_report is None) != (args.loader_debug_abi_report is None):
        parser.error('--public-data-ordinary-link-report and --loader-debug-abi-report must be supplied together')
    if args.ordinary_declaration_abi_report is not None and args.declaration_report is None:
        parser.error('--ordinary-declaration-abi-report requires --declaration-report')
    kwargs = {key: getattr(args, key) for key in ('measurement_checkout', 'base_inventory', 'static_product', 'dynamic_product',
                                                'static_preparation', 'declaration_report', 'public_data_ordinary_link_report',
                                                'loader_debug_abi_report', 'compiler_helper_aggregate_report',
                                                'ordinary_declaration_abi_report', 'loader_runtime_registry_report',
                                                'pthread_alias_contract_report', 'prepared_worker_tls_report',
                                                'errno_storage_lifecycle_report', 'native_c_allocator_boundary_report',
                                                'stdio_alias_contract_report', 'crt_startup_report',
                                                'syscall_alias_contract_report', 'utmpx_receipt_report')}
    kwargs['ordinary_link_report'] = kwargs.pop('public_data_ordinary_link_report')
    kwargs['loader_debug_report'] = kwargs.pop('loader_debug_abi_report')
    kwargs.update(contract_path=args.contract, elf_report=args.elf_facts)
    try:
        if args.mode == 'build-report':
            if args.report is not None or args.output is None:
                parser.error('build-report requires --output and no report positional argument')
            report = build_report(output=args.output, **kwargs)
        else:
            if args.report is None or args.output is not None:
                parser.error('replay requires report and does not accept --output')
            report = require_selection_closure(args.report, **kwargs) if args.mode == 'require-closure' else validate_report(args.report, **kwargs)
        print(f'native ABI selection: {len(report["identities"])} identities, {len(report["occurrences"])} complete occurrences, '
              f'{len(report["closure"]["blockers"])} blockers; complete={report["closure"]["complete"]}; public support=false')
        return 0
    except (SelectionError, inventory.InventoryError, OSError, ValueError) as error:
        print(f'ERROR: native ABI selection: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
