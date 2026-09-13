#!/usr/bin/env python3
"""Source-bound complete ELF observations supplementing a current v1 inventory.

This reader selects artifact placements from the owned product contracts, not
public ABI names or aliases. A fresh same-collector v1 inventory validates the
supplied products and their independently recorded build provenance first.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory

ROOT = inventory.ROOT
SCHEMA = 'crabc.x86_64-native-abi-elf-facts/v1'
BASE_REPORT = Path('/inputs/base-inventory/report.json')
SOURCE_FILES = (*inventory.SOURCE_FILES, 'compat/x86_64/native_abi_elf_facts.py')
TOOL_NAMES = ('ar', 'readelf')
STATUS = {
    'classification': 'measurement-only-no-abi-selection-or-promotion',
    'family_completion': False, 'promotion_ready': False, 'public_support': False,
}
require = inventory.require


def _same(left: object, right: object) -> bool:
    """JSON numbers and booleans are distinct contract values (unlike Python ==)."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _validate_snapshot(output: Path, record: object, description: str, **paths: str) -> None:
    inventory._validate_snapshot(output, record, description, **paths)
    retained = record['retained']
    observed = inventory.file_record(output / retained['path'], logical_path=retained['path'])
    require(_same(retained, observed), f'{description} retained identity types or bytes drifted')


@dataclass(frozen=True)
class Artifact:
    """One manifest placement, even when another placement has identical bytes."""
    key: str
    owner: str
    relative: str
    kind: str
    elf_type: str


ARTIFACTS = (
    Artifact('reference-static', 'reference', 'lib/libc.a', 'archive', 'REL'),
    Artifact('reference-shared', 'reference', 'lib/libc.so', 'elf', 'DYN'),
    Artifact('candidate-static', 'candidate-static', 'usr/lib/libc.a', 'archive', 'REL'),
    Artifact('candidate-shared', 'candidate-dynamic', 'usr/lib/libc.so', 'elf', 'DYN'),
    Artifact('candidate-loader', 'candidate-dynamic', 'lib/ld-crabc-x86_64.so.1', 'elf', 'DYN'),
    *(Artifact('static-' + name, 'candidate-static', 'usr/lib/' + name, 'elf', 'REL')
      for name in ('crt1.o', 'Scrt1.o', 'rcrt1.o', 'crti.o', 'crtn.o')),
    Artifact('static-builtins', 'candidate-static', 'usr/lib/libcrabc-builtins.a', 'archive', 'REL'),
    *(Artifact('dynamic-' + name, 'candidate-dynamic', 'usr/lib/' + name, 'elf', 'REL')
      for name in ('crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'crabc-dynamic-attach.o')),
    Artifact('dynamic-builtins', 'candidate-dynamic', 'usr/lib/libcrabc-builtins.a', 'archive', 'REL'),
)

# Every non-ELF product placement is explicit too. REQUIRED names are the
# drivers/helpers in the imported product contracts; metadata names are the
# remaining regular payloads installed by their builders/materializer. An
# unknown name cannot be ignored because it lacks a familiar ELF suffix.
NON_ELF_REQUIRED = {
    'candidate-static': ('bin/crabc-cc',),
    'candidate-dynamic': ('bin/crabc-cc-dynamic', 'share/crabc/crabc_cc_static.py',
                          'share/crabc/owned_dynamic_receipt.py'),
}
NON_ELF_METADATA = {
    'candidate-static': (
        'share/crabc/build.commands.json', 'share/crabc/crt.commands.json',
        'share/crabc/crt.provenance.json', 'share/crabc/headers.provenance.json',
        'share/crabc/libc-static.provenance.json', 'share/crabc/libcrabc-builtins.provenance.json',
    ),
    'candidate-dynamic': (
        'share/crabc/builtins.provenance.json', 'share/crabc/crt.commands.json',
        'share/crabc/crt.provenance.json', 'share/crabc/dynamic-product-state.json',
        'share/crabc/libc-shared.elf.json', 'share/crabc/libc-shared.provenance.json',
        'share/crabc/loader.elf.json', 'share/crabc/loader.provenance.json',
        'share/crabc/producer-tools.json',
    ),
}


def _installed_header_placements() -> set[str]:
    """Both product builders install exactly the current include/ file roster.

    This reuses the physical regular-file tree reader, including its rejection
    of symlinks. Source header *names* classify placements; v1 still binds each
    product's actual header bytes and distinct product build provenance.
    """
    tree = inventory._header_tree_identity(ROOT / 'include')
    return {'usr/' + row['path'] for row in tree['files']}


def _command_specs(artifact: Artifact) -> tuple[tuple[str, str, str], ...]:
    prefix = (('members', 'ar', 't'),) if artifact.kind == 'archive' else ()
    return (*prefix, ('header', 'readelf', '-hW'), ('sections', 'readelf', '-SW'), ('symbols', 'readelf', '-sW'))


def _require_product_artifact_rosters(base: Mapping[str, Any]) -> None:
    # Review required contract changes before examining manifest membership.
    # ELF additions require explicit observation and v1 correlation decisions;
    # neither a suffix nor product-manifest presence makes that decision.
    for owner, contract in (
        ('candidate-static', inventory.product_evidence.STATIC_REQUIRED),
        ('candidate-dynamic', inventory.product_evidence.DYNAMIC_REQUIRED),
    ):
        elf = [item.relative for item in ARTIFACTS if item.owner == owner]
        expected = [*elf, *NON_ELF_REQUIRED[owner]]
        require(len(expected) == len(set(expected)) and len(contract) == len(set(contract))
                and set(contract) == set(expected), f'{owner} placement roster differs from product contract')
    headers = _installed_header_placements()
    for owner in ('candidate-static', 'candidate-dynamic'):
        expected = [*(item.relative for item in ARTIFACTS if item.owner == owner),
                    *NON_ELF_REQUIRED[owner], *NON_ELF_METADATA[owner], *headers]
        require(len(expected) == len(set(expected)), f'{owner} placement classifications overlap')
        product = base['inputs']['static_product' if owner == 'candidate-static' else 'dynamic_product']
        require(set(product['payload_files']) == set(expected),
                f'{owner} classified placement roster differs from manifest')


def _artifact_records(base: Mapping[str, Any], static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    _require_product_artifact_rosters(base)
    records = {}
    for item in ARTIFACTS:
        if item.owner == 'reference':
            identity = base['inputs']['pinned_musl']['regular_files'][item.relative]['original']
            binding = {'owner': 'reference', 'relative': item.relative, 'base_input': 'pinned_musl.regular_files'}
        else:
            static = item.owner == 'candidate-static'
            product = base['inputs']['static_product' if static else 'dynamic_product']
            physical_root = static_product if static else dynamic_product
            logical_root = inventory.STATIC_PRODUCT_PATH if static else inventory.DYNAMIC_PRODUCT_PATH
            identity = inventory.file_record(physical_root / item.relative, logical_path=str(logical_root / item.relative))
            require(identity['sha256'] == product['payload_files'][item.relative], f'{item.key} payload identity drifted')
            binding = {'owner': item.owner, 'relative': item.relative, 'manifest': product['manifest']}
        records[item.key] = {'kind': item.kind, 'elf_type': item.elf_type, 'identity': identity, 'binding': binding}
    return records


def _snapshot_sources(output: Path) -> dict[str, Any]:
    return {name: inventory._snapshot_regular(output, ROOT / name, f'inputs/source/{name}', name)
            for name in SOURCE_FILES}


def _validate_sources(output: Path, records: object) -> None:
    require(isinstance(records, dict) and set(records) == set(SOURCE_FILES), 'ELF fact collector source roster drifted')
    for name in SOURCE_FILES:
        record = records[name]
        _validate_snapshot(output, record, f'collector source {name}',
                                     expected_original_path=name, expected_retained_path=f'inputs/source/{name}')
        require(_same(record['original'], inventory.file_record(ROOT / name, logical_path=name)),
                f'current ELF fact collector source differs: {name}')


def _capture_tools(output: Path, base: Mapping[str, Any]) -> dict[str, Any]:
    tools = {}
    for name in TOOL_NAMES:
        tool = inventory.physical_executable(inventory.TOOL_PATHS[name], f'{name} tool')
        tools[name] = inventory._snapshot_regular(output, tool, f'inputs/tools/{name}', str(tool))
        require(_same(tools[name]['original'], base['tools'][name]['original']), f'{name} differs from base inventory tool')
    return tools


def _validate_tools(output: Path, tools: object, base: Mapping[str, Any]) -> None:
    require(isinstance(tools, dict) and set(tools) == set(TOOL_NAMES), 'ELF fact tool roster drifted')
    for name in TOOL_NAMES:
        _validate_snapshot(output, tools[name], f'{name} tool',
                                     expected_original_path=str(inventory.TOOL_PATHS[name]),
                                     expected_retained_path=f'inputs/tools/{name}')
        require(_same(tools[name]['original'], base['tools'][name]['original']), f'{name} differs from base inventory tool')


def _capture_command(output: Path, *, key: str, tool: str, flag: str, artifact_key: str,
                     artifact: Mapping[str, Any], tool_record: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(artifact['identity']['path'])
    before = inventory.file_record(path)
    require(before == artifact['identity'], f'{key} input artifact changed before inspection')
    argv = [str(inventory.TOOL_PATHS[tool]), flag, str(path)]
    try:
        result = subprocess.run(argv, cwd=ROOT, env=inventory.TOOL_ENVIRONMENT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=inventory.TOOL_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise inventory.InventoryError(f'{key} inspection could not finish') from error
    streams = {}
    for suffix, payload in (('stdout', result.stdout), ('stderr', result.stderr)):
        relative = f'raw/{key}.{suffix}'
        inventory._write_private(output / relative, payload)
        streams[suffix] = inventory.file_record(output / relative, logical_path=relative)
    return {'key': key, 'tool': tool, 'tool_identity': tool_record, 'argv': argv, 'cwd': '/workspace',
            'artifact_key': artifact_key, 'artifact_before': before, 'artifact_after': inventory.file_record(path),
            'collector_execution_source': source, 'environment': dict(inventory.TOOL_ENVIRONMENT),
            'returncode': result.returncode, **streams}


def _replay_command(output: Path, record: object, *, key: str, tool: str, flag: str, artifact_key: str,
                    artifact: Mapping[str, Any], tool_record: Mapping[str, Any], source: Mapping[str, Any]) -> str:
    record = inventory.require_exact_keys(record, {
        'key', 'tool', 'tool_identity', 'argv', 'cwd', 'artifact_key', 'artifact_before', 'artifact_after',
        'collector_execution_source', 'environment', 'returncode', 'stdout', 'stderr',
    }, f'ELF fact command {key}')
    require(record['key'] == key and record['tool'] == tool and record['artifact_key'] == artifact_key,
            f'{key} command/artifact identity drifted')
    require(record['argv'] == [str(inventory.TOOL_PATHS[tool]), flag, artifact['identity']['path']], f'{key} argv drifted')
    require(record['cwd'] == '/workspace' and record['environment'] == inventory.TOOL_ENVIRONMENT, f'{key} execution context drifted')
    require(_same(record['collector_execution_source'], source), f'{key} collector source drifted')
    require(_same(record['tool_identity'], tool_record), f'{key} tool identity drifted')
    require(_same(record['artifact_before'], artifact['identity']) and _same(record['artifact_after'], artifact['identity']),
            f'{key} artifact bytes or placement drifted')
    require(type(record['returncode']) is int and record['returncode'] == 0, f'{key} did not finish successfully')
    for suffix in ('stdout', 'stderr'):
        stream = inventory.require_exact_keys(record[suffix], {'path', 'sha256', 'size', 'mode'}, f'{key} {suffix}')
        require(stream['path'] == f'raw/{key}.{suffix}', f'{key} raw path drifted')
        observed = inventory.file_record(output / stream['path'], logical_path=stream['path'])
        require(_same(stream, observed), f'{key} raw identity types or bytes drifted')
    stdout = inventory._read_raw(output, record['stdout'], f'{key} stdout')
    stderr = inventory._read_raw(output, record['stderr'], f'{key} stderr')
    inventory.require_empty_diagnostics(tool, stderr)
    return stdout


def _project(item: Artifact, raw: Mapping[str, str], artifact: Mapping[str, Any], base: Mapping[str, Any]) -> Any:
    if item.kind == 'archive':
        members = inventory.parse_archive_members(raw['members'])
        return inventory.parse_archive_elf_facts(raw['header'], raw['sections'], raw['symbols'], members,
                                                 expected_archive=artifact['identity']['path'])
    facts = inventory.parse_elf_facts(raw['header'], raw['sections'], raw['symbols'], expected_type=item.elf_type)
    if item.elf_type == 'DYN':
        # A complete -sW display must also reproduce the separately validated
        # v1 public view. This is correlation, not an ABI selection decision.
        tables = [table for table in facts['symbol_tables'] if table['name'] == '.dynsym'
                  and facts['sections'][table['section_index']]['type'] == 'DYNSYM']
        require(len(tables) == 1, f'{item.key} lacks exactly one independently bound .dynsym table')
        public = [{column: row[column] for column in inventory.DYNAMIC_COLUMNS} for row in tables[0]['rows']
                  if row['section_index'] != 'UND' and row['binding'] in {'GLOBAL', 'WEAK', 'UNIQUE'}
                  and row['visibility'] in {'DEFAULT', 'PROTECTED'}]
        side, product = {'reference-shared': ('reference', 'shared'), 'candidate-shared': ('candidate', 'shared'),
                         'candidate-loader': ('candidate', 'loader')}[item.key]
        require(_same(public, base['inventories'][side][product]['dynamic_symbols']), f'{item.key} full tables differ from v1 public view')
    return facts


def _validate_base(base_inventory: Path, static_product: Path, dynamic_product: Path, static_preparation: Path) -> dict[str, Any]:
    base = inventory.validate_report(base_inventory, static_product=static_product, dynamic_product=dynamic_product,
                                     static_preparation=static_preparation)
    require(base['collector_execution_source'] == inventory.collector_source_seal(),
            'ELF facts require a same-current-collector v1 inventory')
    return base


def _base_binding(output: Path, snapshot: object, base_inventory: Path, base: Mapping[str, Any]) -> dict[str, Any]:
    _validate_snapshot(output, snapshot, 'base inventory report', expected_original_path=str(BASE_REPORT),
                                 expected_retained_path='inputs/base-inventory-report.json')
    require(_same(snapshot['original'], inventory.file_record(base_inventory, logical_path=str(BASE_REPORT))),
            'supplied base inventory report changed')
    return {'report': snapshot, 'collector_execution_source': base['collector_execution_source'],
            'candidate_build': base['product_provenance']['candidate_build']}


def _require_collection_context(base_inventory: Path, static_product: Path, dynamic_product: Path, static_preparation: Path) -> None:
    inventory._require_native_collection_context()
    inventory._ensure_collection_paths(static_product=static_product, dynamic_product=dynamic_product,
                                      static_preparation=static_preparation)
    require(base_inventory == BASE_REPORT, 'collection requires /inputs/base-inventory/report.json')


def collect_facts(*, base_inventory: Path, static_product: Path, dynamic_product: Path, static_preparation: Path,
                  output: Path, work_root: Path) -> dict[str, Any]:
    """Inspect the finite native artifact roster; never build or select an ABI."""
    _require_collection_context(base_inventory, static_product, dynamic_product, static_preparation)
    source = inventory.collector_source_seal()
    base = _validate_base(base_inventory, static_product, dynamic_product, static_preparation)
    image = os.environ.get('CRABC_X86_ABI_IMAGE_ID')
    require(image == base['image'], 'ELF fact image differs from base inventory')
    output = inventory._fresh_output_root(output, work_root)
    source_records = _snapshot_sources(output)
    base_snapshot = inventory._snapshot_regular(output, base_inventory, 'inputs/base-inventory-report.json', str(BASE_REPORT))
    base_binding = _base_binding(output, base_snapshot, base_inventory, base)
    artifacts = _artifact_records(base, static_product, dynamic_product)
    tools = _capture_tools(output, base)
    commands, facts = {}, {}
    for item in ARTIFACTS:
        raw = {}
        for suffix, tool, flag in _command_specs(item):
            key = f'{item.key}-{suffix}'
            commands[key] = _capture_command(output, key=key, tool=tool, flag=flag, artifact_key=item.key,
                                              artifact=artifacts[item.key], tool_record=tools[tool], source=source)
            # Keep failed inspection bytes/commands reviewable, but never emit a
            # successful report after a diagnostic, unsupported member or error.
            inventory._write_private(output / 'commands.json', inventory._stable_json(commands))
            raw[suffix] = _replay_command(output, commands[key], key=key, tool=tool, flag=flag, artifact_key=item.key,
                                          artifact=artifacts[item.key], tool_record=tools[tool], source=source)
        facts[item.key] = _project(item, raw, artifacts[item.key], base)
    require(source == inventory.collector_source_seal(), 'ELF fact collector source changed during collection')
    require(base == _validate_base(base_inventory, static_product, dynamic_product, static_preparation), 'base inventory changed during collection')
    require(artifacts == _artifact_records(base, static_product, dynamic_product), 'artifact placements changed during collection')
    for artifact in artifacts.values():
        require(_same(inventory.file_record(Path(artifact['identity']['path'])), artifact['identity']),
                'artifact bytes changed during collection')
    _validate_sources(output, source_records)
    _validate_tools(output, tools, base)
    require(_same(base_binding, _base_binding(output, base_snapshot, base_inventory, base)),
            'retained base inventory changed during collection')
    for name in TOOL_NAMES:
        require(inventory.file_record(inventory.TOOL_PATHS[name]) == tools[name]['original'], f'{name} bytes changed during collection')
    report = {'schema': SCHEMA, 'target': inventory.TARGET, 'image': image, 'status': dict(STATUS),
              'collector_execution_source': source, 'collector_sources': source_records, 'base_inventory': base_binding,
              'artifacts': artifacts, 'tools': tools, 'commands': commands, 'facts': facts}
    inventory._write_private(output / inventory.REPORT_NAME, inventory._stable_json(report))
    return report


def validate_report(report_path: Path, *, base_inventory: Path, static_product: Path, dynamic_product: Path,
                    static_preparation: Path) -> dict[str, Any]:
    """Replay current-source evidence and supplied products without native tools."""
    report_path = inventory.physical_regular(report_path, 'ELF fact report')
    require(report_path.name == inventory.REPORT_NAME, 'ELF fact report has the wrong name')
    output = inventory.physical_directory(report_path.parent, 'ELF fact report root')
    report = inventory.require_exact_keys(inventory.read_json(report_path, 'ELF fact report'), {
        'schema', 'target', 'image', 'status', 'collector_execution_source', 'collector_sources',
        'base_inventory', 'artifacts', 'tools', 'commands', 'facts',
    }, 'ELF fact report')
    require(report['schema'] == SCHEMA and report['target'] == inventory.TARGET and _same(report['status'], STATUS),
            'ELF fact schema/target/measurement status drifted')
    inventory._validate_collector_source_seal(report['collector_execution_source'])
    _validate_sources(output, report['collector_sources'])
    base = _validate_base(base_inventory, static_product, dynamic_product, static_preparation)
    require(report['image'] == base['image'], 'ELF fact image differs from base inventory')
    binding = inventory.require_exact_keys(report['base_inventory'], {'report', 'collector_execution_source', 'candidate_build'}, 'base inventory binding')
    require(_same(binding, _base_binding(output, binding['report'], base_inventory, base)), 'base inventory provenance drifted')
    artifacts = _artifact_records(base, static_product, dynamic_product)
    require(_same(report['artifacts'], artifacts), 'ELF fact artifact roster or ownership drifted')
    _validate_tools(output, report['tools'], base)
    commands = report['commands']
    expected_keys = {f'{item.key}-{suffix}' for item in ARTIFACTS for suffix, _tool, _flag in _command_specs(item)}
    require(isinstance(commands, dict) and set(commands) == expected_keys, 'ELF fact command roster drifted')
    replayed = {}
    for item in ARTIFACTS:
        raw = {}
        for suffix, tool, flag in _command_specs(item):
            key = f'{item.key}-{suffix}'
            raw[suffix] = _replay_command(output, commands[key], key=key, tool=tool, flag=flag, artifact_key=item.key,
                                          artifact=artifacts[item.key], tool_record=report['tools'][tool],
                                          source=report['collector_execution_source'])
        replayed[item.key] = _project(item, raw, artifacts[item.key], base)
    require(_same(report['facts'], replayed), 'retained ELF facts do not reconstruct from complete raw observations')
    return report


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--collect', action='store_true')
    modes.add_argument('--validate-report', type=Path)
    parser.add_argument('--base-inventory', required=True, type=Path)
    parser.add_argument('--static-product', required=True, type=Path)
    parser.add_argument('--dynamic-product', required=True, type=Path)
    parser.add_argument('--static-preparation', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--work-root', type=Path)
    args = parser.parse_args(argv)
    inputs = {name: getattr(args, name) for name in ('base_inventory', 'static_product', 'dynamic_product', 'static_preparation')}
    try:
        if args.collect:
            if args.output is None or args.work_root is None:
                parser.error('--collect requires --output and --work-root')
            report = collect_facts(**inputs, output=args.output, work_root=args.work_root)
        else:
            if args.output is not None or args.work_root is not None:
                parser.error('--validate-report does not accept --output or --work-root')
            report = validate_report(args.validate_report, **inputs)
        print(f"native ABI ELF facts validated: {len(report['artifacts'])} placements, {len(report['commands'])} commands; measurement only")
        return 0
    except (inventory.InventoryError, OSError) as error:
        print(f'ERROR: native ABI ELF facts: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
