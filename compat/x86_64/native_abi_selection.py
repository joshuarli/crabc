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
                require(record['endpoint_kind'] in {'source-dispatch-operation', 'descriptor', 'lifecycle'}, 'private endpoint invalid')
                require(bool(record['provider_artifacts']) == (record['endpoint_kind'] != 'source-dispatch-operation'), 'private provider artifacts differ from endpoint role')
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
    })
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
    try:
        envelope = declaration_inventory.validate_report(report_path, project_include=ROOT / 'include')
    except (ValueError, OSError) as error:
        raise SelectionError(f'declaration companion rejected: {error}') from error
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
    return {'report': file_identity(report_path), 'reader': file_identity(module_path),
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
        leaked = [row for row in accounting['occurrences']
                  if row['artifact_key'] == COMPILER_HELPER_SHARED_ARTIFACT
                  and same(row_identity(row['row']), identity_value)
                  and row['table'] == '.dynsym' and row['row']['section_index'] != 'UND']
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
                  compiler_helper_aggregate_report: Path | None = None) -> dict[str, Any]:
    source_before = selection_source()
    contract = load_contract(contract_path)
    inputs = load_source_inputs(contract, contract_path)
    facts, measurement = replay_measurement(paths)
    fixed_c_producer_metadata_companion = fixed_c_producer_metadata_adapter(
        facts, measurement, paths, contract, inputs,
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
            **accounting, 'closure': {'complete': not blockers, 'blockers': blockers}, 'status': dict(STATUS),
            'limits': ['selection audit is not qualification', 'complete raw ELF observations stay with the publicly replayed supplement',
                       'no allocator metadata or unwinder investigation', 'no imported AArch64 execution proof',
                       'public-data linkage is scoped evidence; aggregate semantic and family receipt adapters remain unavailable']}


def build_report(*, output: Path, contract_path: Path = CONTRACT_PATH, declaration_report: Path | None = None,
                 ordinary_declaration_abi_report: Path | None = None,
                 ordinary_link_report: Path | None = None, loader_debug_report: Path | None = None,
                 compiler_helper_aggregate_report: Path | None = None,
                 **measurement_inputs: Path) -> dict[str, Any]:
    output = physical_work_path(output, directory=True, own=True, fresh=True)
    paths = validate_measurement_paths(**measurement_inputs)
    contract_path = Path(os.path.abspath(contract_path))
    require(contract_path.is_relative_to(ROOT) and contract_path.resolve() == contract_path and contract_path.is_file(), 'contract must be a physical read-only checkout source')
    report = _build_report(contract_path=contract_path, paths=paths, declaration_report=declaration_report,
                           ordinary_declaration_abi_report=ordinary_declaration_abi_report,
                           ordinary_link_report=ordinary_link_report, loader_debug_report=loader_debug_report,
                           compiler_helper_aggregate_report=compiler_helper_aggregate_report)
    output.mkdir()
    (output / 'report.json').write_bytes(inventory._stable_json(report))
    return report


def validate_report(report_path: Path, *, contract_path: Path = CONTRACT_PATH, declaration_report: Path | None = None,
                    ordinary_declaration_abi_report: Path | None = None,
                    ordinary_link_report: Path | None = None, loader_debug_report: Path | None = None,
                    compiler_helper_aggregate_report: Path | None = None,
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
                             compiler_helper_aggregate_report=compiler_helper_aggregate_report)
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
                                                'ordinary_declaration_abi_report')}
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
