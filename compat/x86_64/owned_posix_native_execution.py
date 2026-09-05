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
import os
from pathlib import Path
import platform
import re
import stat
import sys

import owned_posix_family_execution as family
import owned_posix_family_observations as family_observations
import owned_posix_native_observations as native
import owned_crypt_profile as crypt
import owned_posix_native_dispositions as dispositions

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'crabc.x86_64-owned-posix-native-execution/v1'
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
SHARED_SOURCES = (*crypt.SOURCES,
    'compat/x86_64/owned_posix_native_dispositions.py',
    'compat/x86_64/owned-posix-native-dispositions.md',
    'compat/x86_64/owned_posix_native_execution.py',
    'compat/x86_64/owned-posix-native-execution.md',
    'compat/x86_64/owned_posix_native_observations.py',
    'compat/x86_64/owned_posix_family_execution.py',
    'compat/x86_64/owned_posix_family_observations.py',
    'compat/x86_64/owned_posix_static_products.py',
    'compat/x86_64/owned_dynamic_qualification.py',
    'compat/upstreams.toml', 'rust-toolchain.toml', 'docker/Dockerfile.x86_64',
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


def input_matrix(root, request):
    require(isinstance(request, dict) and set(request) == {'schema', 'source_mount', 'family_execution', 'crypt_profile'}
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
    credentials = dispositions.credentials_companion(root, matrix, family.file_identity(root, path), product)
    inputs = {'crypt_profile': family.file_identity(root, crypt_path),
              'crypt_tree': tree_binding(root, crypt_path.parent),
              'profile_companions': {'credentials': credentials, 'crypt': crypt_record},
              'family_execution': family.file_identity(root, path), 'source': source,
              'source_files': source_files(root), 'product': product_binding(root, product),
              'matrix_inputs': matrix['inputs'], 'io_cancellation_replacement': io_replacement(root, matrix)}
    return inputs, product


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
            profile_inputs={key: inputs[key]['path'] for key in ('family_execution', 'crypt_profile')})
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


def collect(root, work):
    work = family.physical(root, work)
    request = read(work / 'request.json')
    inputs, product = input_matrix(root, request)
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
    return {'schema': SCHEMA, 'status': 'native-aggregate-verified', 'inputs': inputs,
            'request': family.file_identity(root, work / 'request.json'),
            'seals': {f'{kind}-{phase}': family.file_identity(root, work / f'{kind}-{phase}.json')
                      for kind in ('source', 'product') for phase in ('before', 'after')},
            'components': components, 'io_cancellation_replacement': inputs['io_cancellation_replacement'],
            'native_aggregate_complete': True, 'campaign_complete': False, 'family_completion': False, 'public_support': False}


def execute(root, work, matrixpath, cryptpath):
    root = root.resolve(strict=True)
    work = family.physical(root, root / work)
    matrixpath = family.physical(root, root / matrixpath)
    cryptpath = family.physical(root, root / cryptpath)
    require(not work.exists(), 'native execution requires fresh output')
    request = {'schema': SCHEMA, 'source_mount': str(root),
               'family_execution': family.physical(root, matrixpath).relative_to(root).as_posix(),
               'crypt_profile': family.physical(root, cryptpath).relative_to(root).as_posix()}
    inputs, product = input_matrix(root, request)
    matrix_inputs = inputs['matrix_inputs']
    input_roots = [family.physical(root, cryptpath).parent, matrixpath.parent, root / matrix_inputs['dynamic_work']]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    run = sub.add_parser('run')
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--family-execution', type=Path, required=True)
    run.add_argument('--crypt-profile', type=Path, required=True)
    check = sub.add_parser('validate')
    check.add_argument('receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'run':
            print(execute(ROOT, args.output, args.family_execution, args.crypt_profile))
        else:
            validate_receipt(ROOT, args.receipt)
            print('native POSIX aggregate receipt: PASS')
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
