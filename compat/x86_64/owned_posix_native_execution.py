#!/usr/bin/env python3
"""Retain the fixed five-component native POSIX aggregate on one installed product.

The complete three-product family matrix is a prerequisite. Its source-bound
I/O cancellation replays supply READ_FILE and ASYNC_LOOP, which the native
pthread stress profile deliberately delegates. Completion here never promotes
family closure, the campaign, or public architecture support.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import dataclasses
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tomllib

import owned_posix_family_execution as family
import owned_posix_family_observations as family_observations
import owned_posix_native_observations as native
import owned_crypt_profile as crypt
import owned_atomic_addressable_profile as atomic
import owned_math_oracle_defects as math_oracle
import owned_wordexp_upstream_policy as wordexp_policy

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'crabc.x86_64-owned-posix-native-execution/v2'
ADMISSION_SCHEMA = 'crabc.x86_64-owned-posix-runtime-admission/v1'
IO_SOURCE = 'compat/x86_64/owned_io_cancellation_probe.c'


@dataclass(frozen=True)
class Component:
    id: str
    runner: str
    sources: tuple[str, ...]
    arguments: tuple[str, ...]
    announcement: str
    leaf_prefix: str


# This is a qualification contract, not a selectable runner menu. Keep the
# order, full stress bounds, and dynamic-only invocation source-bound.
COMPONENTS = (
    Component('differential', 'compat/x86_64/run_owned_differential.sh',
        ('compat/x86_64/owned_differential_evidence.py', 'compat/differential/README.md',
         *('compat/differential/tests/' + name + '.c' for name in
           ('allocator', 'fd-filesystem', 'foundational', 'stdio-fdopen', 'string-memory'))),
        (), 'owned differential evidence: ', 'owned-differential.'),
    Component('os-test', 'compat/x86_64/run_owned_os_test.sh',
        ('compat/x86_64/owned_os_test.py',), (), 'owned os-test evidence: ', 'owned-os-test.'),
    Component('signal-process', 'compat/x86_64/run_owned_signal_process.sh',
        ('compat/x86_64/owned_signal_process_evidence.py', 'compat/signal-process/tests/signal_process.c'),
        (), 'owned signal-process evidence: ', 'owned-signal-process.'),
    Component('pthread-stress', 'compat/x86_64/run_owned_pthread_stress.sh',
        ('compat/x86_64/owned_pthread_stress.py', 'compat/x86_64/owned_pthread_stress_source.py',
         'compat/pthread-stress/README.md', IO_SOURCE),
        ('--source-profile', 'native-v1', '--iterations', '10', '--timeout', '10'),
        'pthread-stress evidence: ', 'owned-pthread-stress.'),
    Component('libc-test', 'compat/x86_64/run_owned_libc_test.sh',
        ('compat/x86_64/owned_libc_test.py',), (), '', 'owned-libc-test.'),
)
SHARED_SOURCES = (*crypt.SOURCES, *atomic.SOURCES, *wordexp_policy.wordexp.SOURCES, *wordexp_policy.SOURCES,
    'compat/x86_64/owned_math_oracle_defects.py', *math_oracle.PROOF_SOURCES,
    'compat/x86_64/owned_posix_native_dispositions.py',
    'compat/x86_64/owned-posix-native-dispositions.md',
    'compat/x86_64/owned_posix_native_execution.py',
    'compat/x86_64/owned-posix-native-execution.md',
    'compat/x86_64/owned_posix_native_observations.py',
    'compat/x86_64/README.md',
    'compat/x86_64/owned_posix_family_execution.py',
    'compat/x86_64/owned_posix_family_observations.py',
    'compat/x86_64/owned_posix_static_products.py',
    'compat/x86_64/owned_dynamic_qualification.py',
    'compat/upstreams.toml', 'rust-toolchain.toml', 'docker/Dockerfile.x86_64',
)
# Family admission is deliberately a consuming phase over the two existing
# execution receipts. It does not rerun either producer and cannot turn a
# catalog proposal into evidence: both receipts are reconstructed first.
ADMISSION_SOURCES = (
    'compat/x86_64/owned_posix_native_execution.py',
    'compat/x86_64/owned_posix_family_execution.py',
    'compat/x86_64/owned_posix_family_workloads.py',
    'compat/x86_64/owned_posix_runtime_catalog.py',
    'compat/x86_64/owned-posix-runtime-catalog.toml',
    'compat/x86_64/owned-posix-runtime.md',
    'compat/x86_64/owned-posix-native-execution.md',
    'compat/x86_64/validate_parity_ledger.py',
    'compat/x86_64/parity.toml',
)
require = family.require
read = family.read
same_json = family.same_json
write_new = family.static_products.write_new


def source_identity(root):
    return family.static_products.source_identity(root)


def require_execution_environment():
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and sys.byteorder == 'little' and os.geteuid() == 0,
            'native execution requires the pinned Linux/x86-64 root environment')


def require_live_oracle(work, oracle):
    import owned_dynamic_qualification as dynamic
    dynamic.require_live_oracle(work, oracle)


def source_files(root):
    paths = set(SHARED_SOURCES)
    for component in COMPONENTS:
        paths.update((component.runner, *component.sources))
    return {path: family.source_file(root, path) for path in sorted(paths)}


def tree_binding(root, path):
    path = family.physical(root, path)
    metadata = path.stat()
    return {'path': path.relative_to(root).as_posix(),
            'root': {'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid,
                     'gid': metadata.st_gid, 'links': metadata.st_nlink},
            'nodes': family.snapshot(path)}


def product_binding(root, product):
    return {'manifest': family.file_identity(root, product / 'share/crabc/manifest.json'),
            'tree': tree_binding(root, product)}


def io_replacement(root, matrix):
    source = family.source_file(root, IO_SOURCE)
    content = (root / IO_SOURCE).read_text()
    declaration = re.search(r'enum operation\s*\{([^}]+)\}', content)
    require(declaration is not None, 'I/O operation declaration missing')
    operations = [part.strip() for part in declaration[1].split(',')]
    require(operations == ['READ_BYTE', 'READ_VECTOR', 'WRITE_BYTE', 'WRITE_VECTOR',
        'READ_DISABLED', 'READ_MASKED', 'READ_FILE', 'READ_FILE_LOCKED', 'READ_PENDING', 'ASYNC_LOOP']
        and 'for (int operation=READ_BYTE;operation<=ASYNC_LOOP;operation++) CHECK(!exercise(operation));' in content,
        'I/O READ_FILE/ASYNC_LOOP operation contract changed')
    expected = (''.join(f'blocked-operation {number} canceled cleanup=21\n' for number in range(10)) +
        'initial-thread blocked read canceled cleanup=1\n'
        'fork retains initial/worker pending state type cleanup\n'
        'retired task explicit FILE lock remains orphaned\nowned-io-cancellation-ok\n').encode()
    def raw(leaf, record):
        require(isinstance(record, dict) and set(record) == {'stdout', 'stderr', 'status'}, 'I/O raw stream roster differs')
        for stream, value in (('stdout', expected), ('stderr', b''), ('status', b'0\n')):
            item = record[stream]
            path = family.physical(root, leaf / item['path'])
            require(path.is_relative_to(leaf), 'I/O raw stream escapes replay')
            data = path.read_bytes()
            require(data == value and family.digest(path) == item['sha256'] and
                    type(item['size']) is int and len(data) == item['size'] and
                    base64.b64decode(item['base64'], validate=True) == data,
                    'I/O READ_FILE/ASYNC_LOOP transcript or raw identity differs')
        return record
    cells, replays = {}, {}
    object_hashes = set()
    for label, dynamic_label in family.PAIRS.items():
        replay = matrix['runs'][label]['io-cancellation']
        require(replay['static_product'] == label and replay['dynamic_product'] == dynamic_label,
                'I/O replay product labels differ')
        scenarios = replay['observations']['scenarios']
        require(set(scenarios) == set(family_observations.IO_SCENARIOS), 'I/O scenario roster differs')
        scenario = scenarios['owned_io_cancellation']
        require(scenario['kind'] == 'differential' and set(scenario['candidates']) == set(family_observations.MODES),
                'I/O candidate mode roster differs')
        leaf = family.physical(root, root / replay['leaf'])
        obj = replay['objects']['io-cancellation']
        require(same_json(obj['source'], source), 'I/O canonical source differs')
        require(same_json(obj['object'], family.file_identity(root, root / obj['object']['path'])),
                'I/O canonical object identity differs')
        object_hashes.add(obj['object']['sha256'])
        raw(leaf, scenario['oracle'])
        receipt = family.file_identity(root, root / replay['receipt']['path'])
        require(same_json(receipt, replay['receipt']), 'I/O replay receipt identity differs')
        replays[label] = {'receipt': receipt, 'leaf': replay['leaf'], 'objects': replay['objects'],
                         'oracle': scenario['oracle'], 'static_product': label, 'dynamic_product': dynamic_label}
        for mode in family_observations.MODES:
            cells[label + ':' + mode] = {'replay': label, 'mode': mode,
                'product': label if mode in family_observations.MODES[:2] else dynamic_label,
                'raw': raw(leaf, scenario['candidates'][mode])}
    require(len(object_hashes) == 1, 'I/O canonical object differs across three products')
    return {'source': source, 'required_operations': ['READ_FILE', 'ASYNC_LOOP'],
            'replays': replays, 'cells': cells,
            'selected_dynamic_entries': {mode: 'primary:' + mode for mode in family_observations.MODES[2:]}}


def _input_matrix(root, request):
    require(isinstance(request, dict) and set(request) == {'schema', 'source_mount', 'family_execution', 'crypt_profile',
            'atomic_addressable_profile', 'wordexp_profile', 'wordexp_expected_native_inputs'}
            and request['schema'] == SCHEMA, 'native execution request fields differ')
    mount = request['source_mount']
    require(isinstance(mount, str) and Path(mount).is_absolute() and '..' not in Path(mount).parts
            and str(Path(mount)) == mount, 'invalid request source mount')
    value = request['family_execution']
    require(isinstance(value, str) and not Path(value).is_absolute(), 'matrix input must be checkout-relative')
    path = family.physical(root, root / value)
    matrix = family.validate_receipt(root, path)
    require(matrix['schema'] == family.SCHEMA and matrix['status'] == 'workload-matrix-verified'
            and matrix['family'] == 'libc.posix-runtime', 'complete POSIX family matrix required')
    require(all(matrix[key] is False for key in ('family_completion', 'public_support', 'native_aggregate_complete')),
            'matrix promotion flags differ')
    source = source_identity(root)
    require(same_json(matrix['inputs']['source'], source), 'matrix source differs')
    products = matrix['inputs']['dynamic_products']
    require(set(products) == set(family.PAIRS), 'matrix product roster differs')
    dynamic_work = family.physical(root, root / matrix['inputs']['dynamic_work'])
    for label, name in family.PAIRS.items():
        selected = family.physical(root, root / products[label]['path'])
        require(selected == dynamic_work / name, 'matrix installed product selection differs')
        require(family.digest(selected / 'share/crabc/manifest.json') == products[label]['manifest_sha256'],
                'matrix product manifest differs')
    product = dynamic_work / 'installed'
    crypt_value = request['crypt_profile']
    require(isinstance(crypt_value, str) and not Path(crypt_value).is_absolute(), 'crypt input must be checkout-relative')
    crypt_path = family.physical(root, root / crypt_value)
    crypt_record = crypt.validate_receipt(root, crypt_path, product=product)
    atomic_value = request['atomic_addressable_profile']
    require(isinstance(atomic_value, str) and not Path(atomic_value).is_absolute(),
            'atomic input must be checkout-relative')
    atomic_path = family.physical(root, root / atomic_value)
    atomic_record = atomic.validate_receipt(root, atomic_path, product=product)
    wordexp_value = request['wordexp_profile']
    require(isinstance(wordexp_value, str) and not Path(wordexp_value).is_absolute(),
            'wordexp profile input must be checkout-relative')
    wordexp_path = family.physical(root, root / wordexp_value)
    wordexp_expected_value = request['wordexp_expected_native_inputs']
    require(isinstance(wordexp_expected_value, str) and not Path(wordexp_expected_value).is_absolute(),
            'wordexp expected native input must be checkout-relative')
    wordexp_expected_path = family.physical(root, root / wordexp_expected_value)
    wordexp_record = wordexp_policy.validate_companion(root, wordexp_path, wordexp_expected_path, product)
    inputs = {'crypt_profile': family.file_identity(root, crypt_path),
              'crypt_tree': tree_binding(root, crypt_path.parent),
              'atomic_addressable_profile': family.file_identity(root, atomic_path),
              'atomic_addressable_tree': tree_binding(root, atomic_path.parent),
              'wordexp_profile': family.file_identity(root, wordexp_path),
              'wordexp_profile_tree': tree_binding(root, wordexp_path.parent),
              'wordexp_expected_native_inputs': family.file_identity(root, wordexp_expected_path),
              'wordexp_expected_native_inputs_tree': tree_binding(root, wordexp_expected_path.parent),
              'profile_companions': {'crypt': crypt_record, 'atomic': atomic_record,
                                     'wordexp': wordexp_record},
              'family_execution': family.file_identity(root, path), 'source': source,
              'source_files': source_files(root), 'product': product_binding(root, product),
              'matrix_inputs': matrix['inputs'], 'io_cancellation_replacement': io_replacement(root, matrix)}
    return inputs, product, matrix


def input_matrix(root, request):
    """Return the native input bindings while keeping the matrix internal."""
    inputs, product, _ = _input_matrix(root, request)
    return inputs, product


def admission_catalog(root):
    """Load the frozen POSIX spelling contract from this receipt's checkout."""
    import owned_posix_runtime_catalog as catalog

    require(root == ROOT, 'POSIX family admission must use the coordinator checkout')
    require(catalog.CATALOG_PATH == root / 'compat/x86_64/owned-posix-runtime-catalog.toml',
            'POSIX family catalog path differs')
    with catalog.CATALOG_PATH.open('rb') as source:
        document = tomllib.load(source)
    try:
        return catalog.validate_catalog(document, catalog.frozen_family_symbols(), root=root)
    except (catalog.CatalogError, OSError, ValueError) as error:
        raise family.ExecutionError(f'POSIX family catalog rejected: {error}') from error


def admission_dependency_closure(root):
    """Require the current ledger prerequisites before consuming evidence.

    The catalog freezes spelling scope, but it is not an alternate promotion
    ledger.  Read the same current ledger here and retain the concrete direct
    prerequisite statuses in the receipt so a complete matrix cannot bypass a
    planned header, syscall, or musl-oracle foundation.
    """
    ledger_path = root / 'compat/x86_64/parity.toml'
    try:
        with ledger_path.open('rb') as source:
            document = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise family.ExecutionError(f'cannot read POSIX admission ledger: {error}') from error
    families = document.get('family') if isinstance(document, dict) else None
    require(isinstance(families, list), 'POSIX admission ledger family roster differs')
    by_id = {}
    for entry in families:
        require(isinstance(entry, dict) and isinstance(entry.get('id'), str),
                'POSIX admission ledger family entry differs')
        require(entry['id'] not in by_id, 'POSIX admission ledger family identifier duplicates')
        by_id[entry['id']] = entry
    selected = by_id.get('libc.posix-runtime')
    require(isinstance(selected, dict), 'POSIX admission ledger family is missing')
    dependencies = selected.get('depends_on')
    require(dependencies == ['oracle.musl-toolchain', 'libc.headers-layouts', 'libc.raw-syscall'],
            'POSIX admission ledger dependency closure differs')
    closure = []
    for identifier in dependencies:
        dependency = by_id.get(identifier)
        require(isinstance(dependency, dict) and dependency.get('status') == 'foundation-verified',
                f'POSIX admission depends on unverified ledger family: {identifier}')
        closure.append({'id': identifier, 'status': dependency['status']})
    return {
        'ledger': family.source_file(root, 'compat/x86_64/parity.toml'),
        'direct_dependencies': closure,
    }


def admission_proof(root, native_execution, matrix):
    """Bind every frozen spelling to its exact reconstructed matrix cells.

    ``owned_posix_family_execution`` owns product execution and raw receipts;
    this function intentionally verifies references to those receipts instead
    of copying or normalizing their observations. The native aggregate then
    proves the required five component sequence against the matrix's installed
    dynamic product. Together those two independent validators are the only
    inputs a family admission may consume.
    """
    import owned_posix_family_workloads as workloads

    catalog = admission_catalog(root)
    roster = workloads.validate_workloads(root=root)
    by_workload = {workload.id: workload for workload in roster}
    require(len(by_workload) == len(roster), 'POSIX admission workload roster duplicates an identifier')
    # The family matrix is decoded from JSON, while ``Workload`` retains its
    # immutable tuple fields.  Compare canonical JSON values, not Python's
    # tuple/list representation, so this validates the physical receipt.
    expected_workloads = json.loads(json.dumps([dataclasses.asdict(workload) for workload in roster]))
    require(same_json(matrix['workloads'], expected_workloads),
            'POSIX family matrix workload map differs from admission contract')
    require(set(matrix['runs']) == set(family.PAIRS), 'POSIX family matrix product labels differ')
    for label in family.PAIRS:
        require(set(matrix['runs'][label]) == set(by_workload),
                f'POSIX family matrix workload runs differ: {label}')

    evidence = matrix['spelling_evidence']
    require(isinstance(evidence, dict) and set(evidence) == {'static', 'dynamic'},
            'POSIX family matrix spelling evidence sections differ')
    owners = workloads.EXPECTED_PRIMARY_OWNERS
    expected_symbols = [symbol for capability in catalog.capabilities.values() for symbol in capability.symbols]
    require(set(expected_symbols) == set(owners) and len(expected_symbols) == len(owners),
            'POSIX admission primary spelling roster differs')
    require(set(evidence['static']) == set(expected_symbols)
            and set(evidence['dynamic']) == set(expected_symbols),
            'POSIX family matrix omits or adds a frozen spelling')

    capability_symbols = {}
    symbol_workloads = {}
    for capability_id, capability in catalog.capabilities.items():
        capability_symbols[capability_id] = list(capability.symbols)
        for symbol in capability.symbols:
            dynamic_owner = owners[symbol]
            dynamic_workload = by_workload[dynamic_owner]
            static_owner = workloads.STATIC_SUPPLEMENTAL_OWNERS.get(symbol, dynamic_owner)
            static_workload = by_workload[static_owner]
            require(static_workload.product_scope in ('static', 'both')
                    and dynamic_workload.product_scope in ('dynamic', 'both'),
                    f'POSIX admission spelling has no required product owner: {symbol}')
            expected_static_cells = {
                f'{label}:{mode}': matrix['runs'][label][static_owner]['receipt']
                for label in family.PAIRS for mode in workloads.STATIC_LINKAGES
            }
            expected_dynamic_cells = {
                f'{family.PAIRS[label]}:{mode}:{entry}': matrix['runs'][label][dynamic_owner]['receipt']
                for label in family.PAIRS for mode in workloads.DYNAMIC_LINKAGES
                for entry in workloads.DYNAMIC_ENTRIES
            }
            observed_static = evidence['static'][symbol]
            observed_dynamic = evidence['dynamic'][symbol]
            require(observed_static == {'workload': static_owner, 'cells': expected_static_cells},
                    f'POSIX family static spelling receipt differs: {symbol}')
            require(observed_dynamic == {
                'workload': dynamic_owner, 'case': dynamic_workload.dynamic_case,
                'cells': expected_dynamic_cells,
            }, f'POSIX family dynamic spelling receipt differs: {symbol}')
            symbol_workloads[symbol] = {
                'static': static_owner,
                'dynamic': dynamic_owner,
                'dynamic_case': dynamic_workload.dynamic_case,
            }

    required_workloads = set()
    for capability in catalog.capabilities.values():
        required_workloads.update(capability.closure_workloads)
    import owned_posix_runtime_catalog as catalog_module
    require(required_workloads == set(catalog_module.WORKLOADS),
            'POSIX catalog closure workload set differs')
    for workload in required_workloads:
        require(workload in by_workload and all(workload in matrix['runs'][label] for label in family.PAIRS),
                f'POSIX family matrix omits closure workload: {workload}')

    require(native_execution['schema'] == SCHEMA
            and native_execution['status'] == 'native-aggregate-verified'
            and native_execution['native_aggregate_complete'] is True
            and native_execution['campaign_complete'] is False
            and native_execution['family_completion'] is False
            and native_execution['public_support'] is False,
            'native aggregate does not retain its non-promoting completion boundary')
    require(set(native_execution['components']) == {component.id for component in COMPONENTS},
            'native aggregate component roster differs')
    replacement = native_execution['io_cancellation_replacement']
    require(replacement['required_operations'] == ['READ_FILE', 'ASYNC_LOOP']
            and len(replacement['cells']) == 18,
            'native aggregate I/O replacement proof differs')

    return {
        'catalog': family.source_file(root, 'compat/x86_64/owned-posix-runtime-catalog.toml'),
        'catalog_schema': 'crabc.x86_64-owned-posix-runtime-catalog/v1',
        'ledger_dependencies': admission_dependency_closure(root),
        'capability_count': len(catalog.capabilities),
        'symbol_count': len(expected_symbols),
        'capability_symbols': capability_symbols,
        'symbol_workloads': symbol_workloads,
        'closure_workloads': sorted(required_workloads),
        'static_cells': list(catalog.static_cells),
        'dynamic_cells': list(catalog.dynamic_cells),
        'static_spelling_cell_count': len(expected_symbols) * len(catalog.static_cells),
        'dynamic_spelling_cell_count': len(expected_symbols) * len(catalog.dynamic_cells),
        'native_components': [component.id for component in COMPONENTS],
        'native_io_cancellation_cells': len(replacement['cells']),
    }


def admission_inputs(root, native_path):
    """Reconstruct the two current receipts and their common selected source."""
    native_path = family.physical(root, native_path)
    require(native_path.name == 'native-execution.json', 'expected native-execution.json for family admission')
    native_execution, matrix = validate_receipt_with_matrix(root, native_path)
    matrix_identity = native_execution['inputs']['family_execution']
    require(isinstance(matrix_identity, dict) and set(matrix_identity) == {'path', 'sha256', 'size'},
            'native aggregate family matrix identity differs')
    matrix_path = family.physical(root, root / matrix_identity['path'])
    # Keep the final byte identity seal after native replay, but reuse the full
    # matrix validation already performed while rebuilding the native receipt.
    require(same_json(family.file_identity(root, matrix_path), matrix_identity),
            'native aggregate family matrix receipt changed')
    require(matrix['schema'] == family.SCHEMA and matrix['status'] == 'workload-matrix-verified'
            and matrix['family'] == 'libc.posix-runtime'
            and matrix['native_aggregate_complete'] is False
            and matrix['family_completion'] is False
            and matrix['public_support'] is False,
            'POSIX family matrix completion boundary differs')
    source = source_identity(root)
    require(same_json(native_execution['inputs']['source'], source)
            and same_json(matrix['inputs']['source'], source),
            'native aggregate and POSIX matrix do not share current source')
    return native_execution, matrix, source, matrix_path


def collect_admission(root, work):
    """Rebuild one physical family-admission receipt without target execution."""
    work = family.physical(root, work)
    request = read(work / 'request.json')
    require(isinstance(request, dict) and set(request) == {'schema', 'native_execution'}
            and request['schema'] == ADMISSION_SCHEMA,
            'POSIX family admission request fields differ')
    value = request['native_execution']
    require(isinstance(value, str) and value and not Path(value).is_absolute(),
            'POSIX family admission native receipt must be checkout-relative')
    native_execution, matrix, source, matrix_path = admission_inputs(root, root / value)
    expected = {'request.json', 'source-before.json', 'source-after.json', 'family-admission.json'}
    require({path.name for path in work.iterdir()} in (expected - {'family-admission.json'}, expected),
            'POSIX family admission output roster differs')
    for phase in ('before', 'after'):
        require(same_json(read(work / f'source-{phase}.json'), source),
                f'POSIX family admission source seal differs: {phase}')
    proof = admission_proof(root, native_execution, matrix)
    # Reconstruct both receipts after traversing every spelling/cell.  Their
    # validators recheck the selected installed products and all retained
    # product snapshots; exact receipt equality prevents a mutable input from
    # being swapped between collection and admission.
    native_after, matrix_after, source_after, matrix_path_after = admission_inputs(root, root / value)
    require(matrix_path_after == matrix_path
            and same_json(native_after, native_execution)
            and same_json(matrix_after, matrix)
            and same_json(source_after, source),
            'POSIX family admission input or product snapshot changed during proof collection')
    proof_after = admission_proof(root, native_after, matrix_after)
    require(same_json(proof_after, proof),
            'POSIX family admission proof inputs changed during collection')
    require(same_json(read(work / 'source-after.json'), source_identity(root)),
            'POSIX family admission final source seal differs')
    return {
        'schema': ADMISSION_SCHEMA,
        'status': 'family-admission-verified',
        'family': 'libc.posix-runtime',
        'inputs': {
            'native_execution': family.file_identity(root, root / value),
            'family_execution': family.file_identity(root, matrix_path),
            'source': source,
            'source_files': {path: family.source_file(root, path) for path in ADMISSION_SOURCES},
        },
        'request': family.file_identity(root, work / 'request.json'),
        'source_seals': {phase: family.file_identity(root, work / f'source-{phase}.json')
                         for phase in ('before', 'after')},
        'proof': proof,
        # This is a complete family evidence receipt. It deliberately does
        # not claim campaign/promotion/public-support completion.
        'family_completion': True,
        'native_aggregate_complete': True,
        'campaign_complete': False,
        'promotion_ready': False,
        'public_support': False,
    }


def admit(root, work, native_path):
    """Seal a fresh admission from already validated native family evidence."""
    root = root.resolve(strict=True)
    work = family.physical(root, root / work)
    native_path = family.physical(root, root / native_path)
    require(not work.exists(), 'POSIX family admission requires fresh output')
    require(work.is_relative_to(root / '.work'), 'POSIX family admission output must stay under checkout .work')
    require(not work.is_relative_to(native_path.parent) and not native_path.parent.is_relative_to(work),
            'POSIX family admission output overlaps native aggregate input')
    # Validate inputs before creating output, so a bad matrix/native receipt
    # cannot leave a plausible-looking family admission directory behind.
    _, _, source, _ = admission_inputs(root, native_path)
    work.mkdir(parents=True)
    try:
        request = {'schema': ADMISSION_SCHEMA,
                   'native_execution': native_path.relative_to(root).as_posix()}
        write_new(work / 'request.json', request)
        write_new(work / 'source-before.json', source)
        write_new(work / 'source-after.json', source_identity(root))
        result = collect_admission(root, work)
        path = work / 'family-admission.json'
        write_new(path, result)
        return path
    finally:
        family.static_products.make_retained_evidence_readable(work)


def validate_admission_receipt(root, path):
    path = family.physical(root, path)
    require(path.name == 'family-admission.json', 'expected family-admission.json receipt')
    observed = collect_admission(root, path.parent)
    require(same_json(read(path), observed), 'POSIX family admission receipt changed')
    return observed


def component_command(root, component, product, source_mount):
    return ['bash', str(Path(source_mount) / component.runner), *component.arguments,
            family.mounted(root, product, source_mount)]


def sequence_record(index, component, predecessor, inputs):
    return {'schema': SCHEMA, 'index': index, 'component': component.id,
            'predecessor': predecessor, 'inputs': inputs}


def collect_component(root, work, index, component, inputs, product, source_mount, predecessor):
    step = family.physical(root, work / 'runs' / component.id)
    require({p.name for p in step.iterdir()} in (
        {'invocation.json', 'stdout', 'stderr', 'status', 'tmp'},
        {'invocation.json', 'stdout', 'stderr', 'status', 'tmp', 'receipt.json'}), 'component step roster differs')
    start = work / 'sequence' / f'{index:02d}-{component.id}.json'
    require(same_json(read(start), sequence_record(index, component, predecessor, inputs)),
            'component sequence predecessor or inputs changed')
    expected_invocation = family.invocation(Path(source_mount),
        component_command(root, component, product, source_mount), family.case_environment(root, step, source_mount))
    require(same_json(read(step / 'invocation.json'), expected_invocation), 'workload invocation changed')
    status = (step / 'status').read_bytes()
    require(status == b'0\n' or (component.id in ('os-test', 'libc-test') and status == b'1\n'),
            'native component outer status differs')
    execution = {name: family.file_identity(root, step / name)
                 for name in ('invocation.json', 'stdout', 'stderr', 'status')}
    prefix = source_mount.rstrip('/') + '/'
    candidates = set()
    for line in (step / 'stdout').read_text().splitlines():
        if component.announcement:
            if not line.startswith(component.announcement):
                continue
            value = line[len(component.announcement):]
        else:
            if not line.startswith(prefix) or not Path(line).name.startswith(component.leaf_prefix):
                continue
            value = line
        require(value.startswith(prefix), 'native evidence escapes source mount')
        leaf = family.physical(root, root / value[len(prefix):])
        require(leaf.parent == step / 'tmp' and leaf.name.startswith(component.leaf_prefix),
                'native evidence escapes exact component scratch')
        candidates.add(leaf)
    require(len(candidates) == 1, 'native component needs one declared scratch leaf')
    leaf = candidates.pop()
    require(set((step / 'tmp').iterdir()) == {leaf}, 'undeclared component scratch child')
    try:
        observed = native.collect(component.id, leaf, source_mount=source_mount, dynamic_product=product, root=root,
            profile_inputs={key: inputs[key]['path'] for key in
                            ('family_execution', 'crypt_profile', 'atomic_addressable_profile', 'wordexp_profile',
                             'wordexp_expected_native_inputs')})
    except native.NativeObservationError as error:
        raise family.ExecutionError(str(error)) from error
    require(observed['component'] == component.id and observed['product']['path'] == product.relative_to(root).as_posix()
            and observed['product']['manifest']['sha256'] == inputs['product']['manifest']['sha256'],
            'native component product binding differs')
    qualification = observed['qualification']
    require(qualification['status'] == ('profile-qualified' if status == b'1\n' else 'passed')
            and qualification['raw_passed'] is (status == b'0\n')
            and bool(qualification['dispositions']) == (status == b'1\n'),
            'native outer status and strict profile qualification disagree')
    if component.id == 'pthread-stress':
        require(observed['replacement_io_cancellation_required'] == ['READ_FILE', 'ASYNC_LOOP']
                and observed['replacement_io_cancellation_receipt'] is None
                and observed['native_aggregate_complete'] is False
                and observed['replacement_io_cancellation_source']['sha256'] ==
                    inputs['io_cancellation_replacement']['source']['sha256'], 'stress I/O replacement contract differs')
    return {'schema': SCHEMA, 'component': component.id, 'index': index,
            'sequence': family.file_identity(root, start), 'predecessor': predecessor,
            'execution': execution, 'leaf': leaf.relative_to(root).as_posix(),
            'snapshot': tree_binding(root, leaf), 'observations': observed}


def guard(root, inputs, product):
    require(same_json(source_identity(root), inputs['source']) and
            same_json(source_files(root), inputs['source_files']), 'source changed during native execution')
    require(same_json(product_binding(root, product), inputs['product']), 'product changed during native execution')
    require(same_json(family.file_identity(root, root / inputs['family_execution']['path']), inputs['family_execution']),
            'matrix input changed during native execution')
    require(same_json(family.file_identity(root, root / inputs['crypt_profile']['path']), inputs['crypt_profile'])
            and same_json(tree_binding(root, (root / inputs['crypt_profile']['path']).parent), inputs['crypt_tree']),
            'crypt input changed during native execution')
    require(same_json(family.file_identity(root, root / inputs['atomic_addressable_profile']['path']),
                      inputs['atomic_addressable_profile']) and
            same_json(tree_binding(root, (root / inputs['atomic_addressable_profile']['path']).parent),
                      inputs['atomic_addressable_tree']), 'atomic addressable input changed during native execution')
    require(same_json(family.file_identity(root, root / inputs['wordexp_profile']['path']), inputs['wordexp_profile']) and
            same_json(tree_binding(root, (root / inputs['wordexp_profile']['path']).parent),
                      inputs['wordexp_profile_tree']), 'wordexp profile input changed during native execution')
    require(same_json(family.file_identity(root, root / inputs['wordexp_expected_native_inputs']['path']),
                      inputs['wordexp_expected_native_inputs']) and
            same_json(tree_binding(root, (root / inputs['wordexp_expected_native_inputs']['path']).parent),
                      inputs['wordexp_expected_native_inputs_tree']),
            'wordexp expected native input changed during native execution')


def _collect(root, work):
    work = family.physical(root, work)
    request = read(work / 'request.json')
    inputs, product, matrix = _input_matrix(root, request)
    expected = {'request.json', 'source-before.json', 'source-after.json',
                'product-before.json', 'product-after.json', 'runs', 'sequence'}
    require({p.name for p in work.iterdir()} in (expected, expected | {'native-execution.json'}),
            'native output roster includes incomplete or undeclared evidence')
    require(set(p.name for p in (work / 'runs').iterdir()) == {c.id for c in COMPONENTS}, 'native component roster differs')
    require(set(p.name for p in (work / 'sequence').iterdir()) ==
            {f'{i:02d}-{c.id}.json' for i, c in enumerate(COMPONENTS)}, 'native sequence roster differs')
    for phase in ('before', 'after'):
        require(same_json(read(work / f'source-{phase}.json'), inputs['source']), 'native source seal changed')
        require(same_json(read(work / f'product-{phase}.json'), inputs['product']), 'native product seal changed')
    components = {}
    predecessor = inputs['family_execution']
    for index, component in enumerate(COMPONENTS):
        observed = collect_component(root, work, index, component, inputs, product, request['source_mount'], predecessor)
        path = work / 'runs' / component.id / 'receipt.json'
        require(same_json(read(path), observed), 'native component receipt changed: ' + component.id)
        components[component.id] = observed
        predecessor = family.file_identity(root, path)
    guard(root, inputs, product)
    result = {'schema': SCHEMA, 'status': 'native-aggregate-verified', 'inputs': inputs,
            'request': family.file_identity(root, work / 'request.json'),
            'seals': {f'{kind}-{phase}': family.file_identity(root, work / f'{kind}-{phase}.json')
                      for kind in ('source', 'product') for phase in ('before', 'after')},
            'components': components, 'io_cancellation_replacement': inputs['io_cancellation_replacement'],
            'native_aggregate_complete': True, 'campaign_complete': False, 'family_completion': False, 'public_support': False}

    return result, matrix


def collect(root, work):
    """Reconstruct the serialized native receipt, discarding internal inputs."""
    result, _ = _collect(root, work)
    return result


def execute(root, work, matrixpath, cryptpath, atomicpath, wordexppath, wordexp_expected_path):
    root = root.resolve(strict=True)
    work = family.physical(root, root / work)
    matrixpath = family.physical(root, root / matrixpath)
    cryptpath = family.physical(root, root / cryptpath)
    atomicpath = family.physical(root, root / atomicpath)
    wordexppath = family.physical(root, root / wordexppath)
    wordexp_expected_path = family.physical(root, root / wordexp_expected_path)
    require(not work.exists(), 'native execution requires fresh output')
    request = {'schema': SCHEMA, 'source_mount': str(root),
               'family_execution': family.physical(root, matrixpath).relative_to(root).as_posix(),
               'crypt_profile': family.physical(root, cryptpath).relative_to(root).as_posix(),
               'atomic_addressable_profile': family.physical(root, atomicpath).relative_to(root).as_posix(),
               'wordexp_profile': family.physical(root, wordexppath).relative_to(root).as_posix(),
               'wordexp_expected_native_inputs': family.physical(root, wordexp_expected_path).relative_to(root).as_posix()}
    inputs, product = input_matrix(root, request)
    matrix_inputs = inputs['matrix_inputs']
    input_roots = [family.physical(root, cryptpath).parent, family.physical(root, atomicpath).parent,
                   family.physical(root, wordexppath).parent, family.physical(root, wordexp_expected_path).parent,
                   matrixpath.parent, root / matrix_inputs['dynamic_work']]
    input_roots.extend((root / matrix_inputs[name]['path']).parent
                       for name in ('static_preparation', 'dynamic_qualification'))
    require(work.is_relative_to(root / '.work'), 'native output must stay under checkout .work')
    require(all(not work.is_relative_to(path) and not path.is_relative_to(work) for path in input_roots),
            'native output overlaps matrix or product input')
    require_execution_environment()
    require_live_oracle(root / matrix_inputs['dynamic_work'], matrix_inputs['oracle'])
    work.mkdir(parents=True)
    write_new(work / 'request.json', request)
    write_new(work / 'source-before.json', inputs['source'])
    write_new(work / 'product-before.json', inputs['product'])
    completed = []
    current = None
    predecessor = inputs['family_execution']
    try:
        try:
            for index, component in enumerate(COMPONENTS):
                current = component.id
                guard(root, inputs, product)
                require_live_oracle(root / matrix_inputs['dynamic_work'], matrix_inputs['oracle'])
                start = work / 'sequence' / f'{index:02d}-{component.id}.json'
                start.parent.mkdir(exist_ok=True)
                write_new(start, sequence_record(index, component, predecessor, inputs))
                step = work / 'runs' / component.id
                print(f'POSIX native {component.id}: running', flush=True)
                try:
                    family.run_step(root, step, component_command(root, component, product, str(root)),
                                    family.case_environment(root, step, str(root)))
                except family.ExecutionError:
                    # Only these producers may retain an honest raw failure. The
                    # immediate strict collector must independently qualify it.
                    if component.id not in ('os-test', 'libc-test') or not (step / 'status').is_file() or (step / 'status').read_bytes() != b'1\n':
                        raise
                finally:
                    if step.exists():
                        family.static_products.make_retained_evidence_readable(step)
                require_live_oracle(root / matrix_inputs['dynamic_work'], matrix_inputs['oracle'])
                guard(root, inputs, product)
                observed = collect_component(root, work, index, component, inputs, product, str(root), predecessor)
                write_new(step / 'receipt.json', observed)
                predecessor = family.file_identity(root, step / 'receipt.json')
                completed.append(component.id)
                current = None
                print(f'POSIX native {component.id}: PASS', flush=True)
        finally:
            for kind, capture in (('source', lambda: source_identity(root)),
                                  ('product', lambda: product_binding(root, product))):
                try:
                    write_new(work / f'{kind}-after.json', capture())
                except Exception as error:
                    write_new(work / f'{kind}-after-error.json', {'error': str(error)})
            family.static_products.make_retained_evidence_readable(work)
        result = collect(root, work)
        path = work / 'native-execution.json'
        write_new(path, result)
        return path
    except BaseException as error:
        write_new(work / 'incomplete.json', {'schema': SCHEMA, 'status': 'incomplete',
            'completed_components': completed, 'failed_component': current,
            'not_run': [c.id for c in COMPONENTS if c.id not in completed and c.id != current],
            'error': str(error), 'native_aggregate_complete': False, 'campaign_complete': False,
            'family_completion': False, 'public_support': False})
        raise
    finally:
        family.static_products.make_retained_evidence_readable(work)


def validate_receipt(root, path):
    path = family.physical(root, path)
    require(path.name == 'native-execution.json', 'expected native-execution.json receipt')
    observed = collect(root, path.parent)
    require(same_json(read(path), observed), 'native aggregate receipt changed')
    return observed


def validate_receipt_with_matrix(root, path):
    """Validate a native receipt and return its already validated matrix."""
    path = family.physical(root, path)
    require(path.name == 'native-execution.json', 'expected native-execution.json receipt')
    observed, matrix = _collect(root, path.parent)
    require(same_json(read(path), observed), 'native aggregate receipt changed')
    return observed, matrix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    run = sub.add_parser('run')
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--family-execution', type=Path, required=True)
    run.add_argument('--crypt-profile', type=Path, required=True)
    run.add_argument('--atomic-addressable-profile', type=Path, required=True)
    run.add_argument('--wordexp-profile', type=Path, required=True)
    run.add_argument('--wordexp-expected-native-inputs', type=Path, required=True)
    admission = sub.add_parser('admit')
    admission.add_argument('--native-execution', type=Path, required=True)
    admission.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('validate')
    check.add_argument('receipt', type=Path)
    check_admission = sub.add_parser('validate-admission')
    check_admission.add_argument('receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'run':
            print(execute(ROOT, args.output, args.family_execution, args.crypt_profile,
                          args.atomic_addressable_profile, args.wordexp_profile,
                          args.wordexp_expected_native_inputs))
        elif args.action == 'admit':
            print(admit(ROOT, args.output, args.native_execution))
        elif args.action == 'validate':
            validate_receipt(ROOT, args.receipt)
            print('native POSIX aggregate receipt: PASS')
        else:
            validate_admission_receipt(ROOT, args.receipt)
            print('native POSIX family admission receipt: PASS')
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
