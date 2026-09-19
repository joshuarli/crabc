"""Read the five finite native POSIX component results without executing tools.

The source-bound component runner owns compiler, header, ELF and sealed-link
validation. This reader independently checks its canonical source/object/product
bindings and every required raw observation. The aggregate owner additionally
seals the complete immutable leaf tree and validates the supplied product.
Recorded absolute paths are compared through one explicit checkout mount; no
receipt is rewritten and no compiler or target executable is launched.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import tomllib

import owned_dynamic_receipt as receipt_contract
import owned_differential_evidence as differential
import owned_signal_process_evidence as signals
import owned_pthread_stress_source as stress_source

ROOT = Path(__file__).resolve().parents[2]
MODES = ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct')
PRODUCT_FORMAT = 'crabc-x86-64-owned-dynamic-sysroot-v1'
COMPONENTS = ('differential', 'signal-process', 'pthread-stress', 'os-test', 'libc-test')
LIBC_TEST_REVISION = '68edb8bd73dab8147ee54c8bec638f4d2b3cff37'
LIBC_TEST_TREE = '4f7a5373652c6534b0fbafb58fe3fed1489f3b3b'
OS_TEST_REVISION = '5e9456d510612f83b6ec8b1a0c06d6b1303a2512'
OS_TEST_TREE = '68fd4eef88d0e52b55c7cc2a73659b1e439d33fe'
OS_TEST_SUITES = ('include', 'namespace', 'basic', 'io', 'limits', 'malloc', 'process', 'pty', 'signal', 'stdio')


class NativeObservationError(ValueError):
    """A finite component roster, binding or raw result is absent or changed."""


def require(condition, message):
    if not condition:
        raise NativeObservationError(message)


def same(actual, expected, description):
    # JSON's scalar types matter: false, 0 and 0.0 are different receipt facts.
    require(json.dumps(actual, sort_keys=True, allow_nan=False) ==
            json.dumps(expected, sort_keys=True, allow_nan=False), description + ' differs')


def keys(value, expected, description):
    require(isinstance(value, dict) and set(value) == set(expected), description + ' fields differ')
    return value


def physical(path, *, directory=False):
    path = Path(path)
    require('..' not in path.parts, 'physical path has parent traversal')
    path = path.absolute()
    try:
        require(path.resolve(strict=True) == path, 'artifact traverses a symlink: ' + str(path))
        require(path.is_dir() if directory else path.is_file(), 'artifact has wrong node type: ' + str(path))
    except OSError as error:
        raise NativeObservationError('missing or unreadable artifact: ' + str(path)) from error
    return path


def read_bytes(path):
    try:
        return physical(path).read_bytes()
    except OSError as error:
        raise NativeObservationError('unreadable artifact: ' + str(path)) from error


def digest(path):
    return hashlib.sha256(read_bytes(path)).hexdigest()


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise NativeObservationError('nonfinite JSON constant: ' + value)
    try:
        return json.loads(read_bytes(path), object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeObservationError('invalid JSON: ' + str(path)) from error


class Reader:
    def __init__(self, leaf, mount, product, root):
        self.root = physical(root, directory=True)
        require(isinstance(mount, str) and Path(mount).is_absolute() and '..' not in Path(mount).parts
                and str(Path(mount)) == mount, 'invalid source mount')
        self.mount = Path(mount)
        self.leaf = physical(leaf, directory=True)
        self.product = physical(product, directory=True)
        for path in (self.leaf, self.product):
            require(path.is_relative_to(self.root / '.work') and path != self.root / '.work',
                    'component evidence and products must be physical checkout .work children')
        require(not self.product.is_relative_to(self.leaf), 'supplied product cannot be a leaf execution copy')
        self.manifest = self.product / 'share/crabc/manifest.json'
        manifest = read_json(self.manifest)
        require(isinstance(manifest, dict), 'dynamic manifest is not an object')
        same({key: manifest.get(key) for key in ('schema', 'format', 'target')},
             {'schema': 1, 'format': PRODUCT_FORMAT, 'target': 'x86_64-unknown-linux-musl'}, 'dynamic product identity')

    def recorded(self, path):
        path = Path(path).absolute()
        require(path.is_relative_to(self.root) and '..' not in path.parts, 'recorded artifact escapes checkout')
        return str(self.mount / path.relative_to(self.root))

    def local(self, value, *, within=None):
        require(isinstance(value, str) and str(Path(value)) == value and '..' not in Path(value).parts,
                'invalid recorded artifact path')
        path = Path(value)
        require(path.is_relative_to(self.mount), 'recorded artifact is outside source mount')
        result = self.root / path.relative_to(self.mount)
        require(result.is_relative_to(within or self.leaf), 'recorded artifact escapes its evidence owner')
        return physical(result)

    def artifact(self, value, *, within=None, raw=False):
        path = self.local(value['path'], within=within)
        self.bind(value, path, 'retained artifact')
        return self.identity(path, source=not path.is_relative_to(self.leaf), raw=raw)

    def relative_artifact(self, value, path, *, raw=False):
        same(value, self.identity(path), 'leaf-relative artifact binding')
        return self.identity(path, raw=raw)

    def binding(self, path):
        return {'path': self.recorded(path), 'sha256': digest(path)}

    def bind(self, value, path, description):
        same(value, self.binding(path), description)

    def identity(self, path, *, source=False, raw=False):
        data = read_bytes(path)
        result = {'path': Path(path).relative_to(self.root if source else self.leaf).as_posix(),
                  'sha256': hashlib.sha256(data).hexdigest(), 'byte_length': len(data)}
        if raw:
            result['base64'] = base64.b64encode(data).decode('ascii')
        return result

    def mode_identity(self, value, path, description):
        same(value, {'sha256': digest(path), 'mode': physical(path).stat().st_mode,
                     'resolved_path': self.recorded(path)}, description)

    def raw(self, stem, *, status_suffix='.status'):
        paths = {stream: self.leaf / (stem + (status_suffix if stream == 'status' else '.' + stream))
                 for stream in ('status', 'stdout', 'stderr')}
        data = {stream: read_bytes(path) for stream, path in paths.items()}
        if status_suffix == '.status':
            require(data['status'] == b'0\n', 'raw process status must be exactly zero: ' + stem)
        return data, {stream: self.identity(path, raw=True) for stream, path in paths.items()}

    def object(self, source, obj):
        return {'source': self.identity(source, source=True), 'object': self.identity(obj)}

    def link(self, value, mode, obj, binary):
        same(value, {'linkage': mode, 'product': self.recorded(self.product),
            'product_format': PRODUCT_FORMAT, 'product_manifest_sha256': digest(self.manifest),
            'workload_sha256': digest(obj), 'executable_sha256': digest(binary),
            'receipt_sha256': digest(Path(str(binary) + '.crabc-link.json'))}, 'canonical dynamic link identity')

    def finish(self, component, report, observations, objects, **extra):
        return {'component': component, 'report': self.identity(self.leaf / report),
                'product': {'path': self.product.relative_to(self.root).as_posix(),
                            'manifest': self.identity(self.manifest, source=True)},
                'objects': objects, 'observations': observations, **extra}


def exact_files(directory, expected, description):
    directory = physical(directory, directory=True)
    require({path.name for path in directory.iterdir()} == set(expected), description + ' roster differs')
    for name in expected:
        physical(directory / name)


def raw_roster(leaf, stems, *, status_suffix='.status', auxiliary=()):
    expected = {stem + suffix for stem in stems for suffix in ('.stdout', '.stderr', status_suffix)}
    actual = {p.name for p in leaf.iterdir() if p.name.endswith(('.stdout', '.stderr', '.status', '.status.json'))}
    require(actual - set(auxiliary) == expected, 'raw observation file roster differs')
    return expected


def source_tree(directory, *, ignore_git_metadata=False, allow_symlinks=False):
    """Reconstruct Git's tracked tree identity from retained source entries.

    A report's own path/hash list cannot establish completeness. Comparing this
    tree against the pinned revision's fixed tree ID binds every filename,
    executable bit and byte, including headers and Makefiles outside the direct
    C target roster. The OS profile also hashes its pinned Makefile symlinks as
    literal Git blobs; it never follows their targets. SHA-1 here is Git's
    existing object identity, not a security primitive or a new algorithm.
    """
    directory = physical(directory, directory=True)
    files = {}
    def git_object(kind, data):
        return hashlib.sha1(kind + b' ' + str(len(data)).encode() + b'\0' + data).digest()
    def walk(parent):
        entries = []
        for path in parent.iterdir():
            if ignore_git_metadata and parent == directory and path.name == '.git':
                physical(path, directory=True)
                continue
            if path.is_symlink():
                require(allow_symlinks, 'pinned source tree contains a symlink')
                data = os.fsencode(os.readlink(path))
                files[path.relative_to(directory).as_posix()] = hashlib.sha256(data).hexdigest()
                entries.append((path.name.encode(), b'120000', path.name.encode(), git_object(b'blob', data)))
            elif path.is_dir():
                physical(path, directory=True)
                entries.append((path.name.encode() + b'/', b'40000', path.name.encode(), walk(path)))
            else:
                data = read_bytes(path)
                files[path.relative_to(directory).as_posix()] = hashlib.sha256(data).hexdigest()
                mode = b'100755' if path.stat().st_mode & 0o111 else b'100644'
                entries.append((path.name.encode(), mode, path.name.encode(), git_object(b'blob', data)))
        return git_object(b'tree', b''.join(mode + b' ' + name + b'\0' + oid
                          for _, mode, name, oid in sorted(entries)))
    return walk(directory).hex(), dict(sorted(files.items()))


def _load_profile_companions(root, product, inputs):
    """Only physical prerequisite paths are accepted, never caller waivers."""
    import owned_posix_family_execution as family
    import owned_crypt_profile as crypt
    import owned_atomic_addressable_profile as atomic
    import owned_posix_native_dispositions as dispositions
    import owned_wordexp_upstream_policy as wordexp_policy
    keys(inputs, ('family_execution', 'crypt_profile', 'atomic_addressable_profile', 'wordexp_profile',
                  'wordexp_expected_native_inputs'),
         'native profile prerequisite paths')
    paths = {}
    for key, value in inputs.items():
        require(isinstance(value, str) and not Path(value).is_absolute(), 'native profile input must be checkout-relative')
        paths[key] = family.physical(root, root / value)
    matrix = family.validate_receipt(root, paths['family_execution'])
    credential = dispositions.credentials_companion(root, matrix, family.file_identity(root, paths['family_execution']), product)
    crypt_record = crypt.validate_receipt(root, paths['crypt_profile'], product=product)
    atomic_record = atomic.validate_receipt(root, paths['atomic_addressable_profile'], product=product)
    wordexp_record = wordexp_policy.validate_companion(root, paths['wordexp_profile'],
                                                        paths['wordexp_expected_native_inputs'], product)
    return {'credentials': credential, 'crypt': {'receipt': family.file_identity(root, paths['crypt_profile']),
            'vectors': crypt_record['vectors'], 'observations': crypt_record['vector_observations']},
            'atomic': {'receipt': family.file_identity(root, paths['atomic_addressable_profile']),
                       'selected_dynamic_entries': atomic_record['entries']},
            'wordexp': {'receipt': family.file_identity(root, paths['wordexp_profile']),
                        'expected_native_inputs': family.file_identity(root, paths['wordexp_expected_native_inputs']),
                        **wordexp_record}}


def collect(component, leaf_root, *, source_mount, dynamic_product, root=ROOT, profile_inputs=None):
    """Reconstruct one dynamic-only component; never compile, link or execute.

    ``source_mount`` is the original absolute checkout path in retained JSON.
    ``root`` and ``dynamic_product`` are their actual physical host locations.
    The returned observations use leaf-relative paths and preserve raw bytes.
    """
    require(component in COMPONENTS, 'unknown native POSIX component')
    reader = Reader(leaf_root, source_mount, dynamic_product, root)
    reader.profile_companions = None
    try:
        if profile_inputs is not None and component in ('os-test', 'libc-test'):
            reader.profile_companions = _load_profile_companions(root, dynamic_product, profile_inputs)
        result = {'differential': _differential, 'signal-process': _signal_process,
                'pthread-stress': _pthread_stress, 'os-test': _os_test, 'libc-test': _libc_test}[component](reader)
        result.setdefault('qualification', {'status': 'passed', 'raw_passed': True, 'dispositions': []})
        return result
    except (KeyError, TypeError, IndexError, OSError, RuntimeError, ImportError) as error:
        raise NativeObservationError('incomplete or malformed ' + component + ' evidence: ' + str(error)) from error


def _differential(reader):
    leaf = reader.leaf
    report = read_json(leaf / 'summary.json')
    keys(report, ('schema', 'status', 'static_replayed', 'cases', 'compile', 'links', 'observations', 'copies'), 'differential summary')
    same({key: report[key] for key in ('schema', 'status', 'static_replayed', 'cases')},
         {'schema': differential.SUMMARY_SCHEMA, 'status': 'pass', 'static_replayed': False,
          'cases': list(differential.CASES)}, 'dynamic-only differential summary')
    reader.bind(report['compile'], leaf / 'compile.json', 'compile receipt')
    compilation = read_json(leaf / 'compile.json')
    require(compilation['schema'] == differential.COMPILE_SCHEMA, 'differential compile schema differs')
    installed = compilation['installed_dynamic']
    require(installed['root'] == reader.recorded(reader.product), 'differential compile product differs')
    reader.bind(installed['manifest'], reader.manifest, 'differential compile manifest')
    same(compilation['pre_compile']['installed_dynamic'], installed, 'pre/post compile product')
    records = compilation['cases']
    require(isinstance(records, list) and [item['case'] for item in records] == list(differential.CASES),
            'differential object roster differs')
    matrix = differential.frozen_matrix(False)
    for directory in ('links', 'copies', 'observations'):
        names = [item['name'] for item in matrix[directory]]
        exact_files(leaf / directory, names, 'differential ' + directory)
        same(report[directory], {directory + '/' + name: {'path': name, 'sha256': digest(leaf / directory / name)}
                                for name in names}, 'differential ' + directory + ' index')
    raw_names = {f'{case}-{label}.{stream}' for case in differential.CASES
                 for label in ('musl', *('dynamic-' + mode for mode in MODES))
                 for stream in ('status', 'stdout', 'stderr')}
    exact_files(leaf / 'executions', raw_names, 'differential raw executions')
    objects, observations, sources = {}, {}, {}
    for record in records:
        case = record['case']
        source = reader.root / 'compat/differential/tests' / (case + '.c')
        obj = leaf / 'objects' / (case + '.o')
        reader.bind(record['source'], source, 'differential source')
        reader.bind(record['object'], obj, 'differential object')
        sources[case] = reader.binding(source)
        objects[case] = reader.object(source, obj)
        oracle_link = read_json(leaf / 'links' / (case + '-musl.json'))
        same([oracle_link['schema'], oracle_link['case']], [differential.ORACLE_LINK_SCHEMA, case], 'differential oracle role')
        reader.bind(oracle_link['canonical_object'], obj, 'differential oracle canonical object')
        reader.bind(oracle_link['executable'], leaf / 'oracle' / case, 'differential oracle executable')
        same(oracle_link['command'], ['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie',
             reader.recorded(obj), '-o', reader.recorded(leaf / 'oracle' / case)], 'differential oracle object command')
        for mode in ('pie', 'non-pie'):
            link = read_json(leaf / 'links' / f'{case}-dynamic-{mode}.json')
            keys(link, ('schema', 'case', 'linkage', 'canonical_object', 'sealed_link'), 'differential link record')
            same([link['schema'], link['case'], link['linkage']], [differential.LINK_SCHEMA, case, mode], 'differential link role')
            reader.bind(link['canonical_object'], obj, 'differential canonical link object')
            reader.link(link['sealed_link'], mode, obj, leaf / 'candidates' / f'{case}-dynamic-{mode}')
        for mode in MODES:
            label = 'dynamic-' + mode
            reference, reference_identity = reader.raw(f'executions/{case}-musl')
            candidate, candidate_identity = reader.raw(f'executions/{case}-{label}')
            require(reference == candidate, 'differential raw streams differ: ' + case + '/' + mode)
            markers = differential.errno_values(case, leaf / f'executions/{case}-musl.stdout')
            require(len(markers) == 1, 'differential requires exactly one errno marker')
            expected = {'schema': differential.OBSERVATION_SCHEMA, 'case': case, 'passed': True, 'differences': []}
            for role, role_label, raw in (('reference', 'musl', reference), ('candidate', label, candidate)):
                expected[role] = {'label': role_label, 'status': 0, 'errno': markers[0]}
                for stream in ('stdout', 'stderr', 'status'):
                    path = leaf / f'executions/{case}-{role_label}.{stream}'
                    expected[role]['raw_status' if stream == 'status' else stream] = {
                        **reader.binding(path), 'byte_length': len(raw[stream])}
            same(read_json(leaf / 'observations' / f'{case}-{label}.json'), expected, 'differential raw comparison')
            observations[case + '/' + mode] = {'reference': reference_identity, 'candidate': candidate_identity,
                                              'errno': markers[0]}
    same(compilation['pre_compile']['sources'], sources, 'differential precompile sources')
    exact_files(leaf / 'objects', [case + '.o' for case in differential.CASES], 'differential canonical objects')
    return reader.finish('differential', 'summary.json', observations, objects,
                         compile_receipt=reader.identity(leaf / 'compile.json'))


def _signal_process(reader):
    leaf = reader.leaf
    report = read_json(leaf / 'signal-process-observations.json')
    keys(report, ('schema', 'subcases', 'compile', 'oracle', 'links', 'execution', 'observations',
                  'comparison', 'process_group_isolation'), 'signal process report')
    same([report['schema'], report['subcases'], report['comparison'], report['process_group_isolation']],
         [signals.OBSERVATION_SCHEMA, list(signals.SIGNAL_PROCESS_SUBCASES),
          'exact raw status/stdout/stderr bytes; no documented source difference', True], 'signal process contract')
    compilation = report['compile']
    require(compilation['schema'] == signals.COMPILE_SCHEMA, 'signal compile schema differs')
    source = reader.root / 'compat/signal-process/tests/signal_process.c'
    obj = leaf / 'workload.o'
    for field, path in (('source', source), ('object', obj), ('product_manifest', reader.manifest),
                        ('compile_audit', leaf / 'compile.json'), ('input_snapshot', leaf / 'compile-inputs.json')):
        reader.bind(compilation[field], path, 'signal compile ' + field)
    inputs, audit = read_json(leaf / 'compile-inputs.json'), read_json(leaf / 'compile.json')
    reader.bind(inputs['source'], source, 'signal input source')
    reader.bind(inputs['product_manifest'], reader.manifest, 'signal input manifest')
    require(inputs['planned_object'] == reader.recorded(obj), 'signal planned object differs')
    reader.bind(audit['object'], obj, 'signal emitted object')
    reader.bind(audit['input_snapshot'], leaf / 'compile-inputs.json', 'signal input snapshot')
    same(audit['driver_compile_command'], inputs['driver_compile_command'], 'signal compile command')
    reader.bind(report['oracle']['object'], obj, 'signal oracle object')
    require(isinstance(report['links'], list) and len(report['links']) == 2, 'signal dynamic link roster differs')
    for mode, link in zip(('pie', 'non-pie'), report['links']):
        reader.link(link, mode, obj, leaf / ('dynamic-' + mode))
        same(read_json(leaf / ('dynamic-' + mode + '.link.json')), link, 'signal retained link identity')
    stems = ['oracle-' + scenario for scenario in signals.SIGNAL_PROCESS_SUBCASES]
    stems += [mode + '-' + scenario for mode in MODES for scenario in signals.SIGNAL_PROCESS_SUBCASES]
    raw_roster(leaf, stems, auxiliary=('driver-compile.stdout', 'driver-compile.stderr'))
    expected_rows, observations = [], {}
    for mode in MODES:
        for scenario in signals.SIGNAL_PROCESS_SUBCASES:
            reference, reference_identity = reader.raw('oracle-' + scenario)
            candidate, candidate_identity = reader.raw(mode + '-' + scenario)
            require(reference == candidate, 'signal process raw streams differ: ' + scenario + '/' + mode)
            expected_rows.append({'mode': mode, 'subcase': scenario,
                'reference': {stream: reader.binding(leaf / f'oracle-{scenario}.{stream}') for stream in reference},
                'candidate': {stream: reader.binding(leaf / f'{mode}-{scenario}.{stream}') for stream in candidate}})
            observations[scenario + '/' + mode] = {'reference': reference_identity, 'candidate': candidate_identity}
    same(report['observations'], expected_rows, 'signal process observation roster and bindings')
    return reader.finish('signal-process', 'signal-process-observations.json', observations,
                         {'application': reader.object(source, obj)}, compile_receipt=reader.identity(leaf / 'compile.json'))


def _pthread_stress(reader):
    leaf = reader.leaf
    report = read_json(leaf / 'pthread-stress.json')
    expected_fields = ('schema', 'campaign_complete', 'source_profile', 'source_map', 'source_map_receipt_sha256',
        'prepared_source_sha256', 'source_sha256', 'workload_object_sha256', 'compile_receipt_sha256',
        'consumed_receipt_sha256', 'oracle_link_command', 'links', 'raw_artifacts', 'timeout_seconds',
        'passed', 'observation_count', 'cell_roster', 'iterations', 'passed_scope', 'remaining_stress_workload_passed',
        'native_aggregate_complete', 'replacement_io_cancellation_required', 'replacement_io_cancellation_source',
        'replacement_io_cancellation_receipt', 'replacement_io_cancellation_binding')
    keys(report, expected_fields, 'pthread stress report')
    contract = {'schema': 'crabc.x86_64-owned-pthread-stress/v2', 'campaign_complete': False,
        'source_profile': 'native-v1', 'passed': True, 'passed_scope': 'remaining-native-pthread-stress-workload',
        'remaining_stress_workload_passed': True, 'native_aggregate_complete': False,
        'replacement_io_cancellation_required': ['READ_FILE', 'ASYNC_LOOP'], 'replacement_io_cancellation_receipt': None,
        'replacement_io_cancellation_binding': 'composite owner must bind the same-product I/O-cancellation family receipt',
        'observation_count': 50, 'cell_roster': ['oracle', *MODES]}
    same({key: report[key] for key in contract}, contract, 'native stress profile and dynamic-only matrix')
    timeout = report['timeout_seconds']
    # The standalone runner supports other limits, but this aggregate invokes
    # exactly --iterations 10 --timeout 10. Do not admit a different campaign
    # merely because its report and per-process metadata agree with each other.
    same(timeout, 10.0, 'aggregate pthread stress ten-second timeout')
    original = reader.root / 'tests/fixtures/pthread_stress_test.c'
    preparer = reader.root / 'compat/x86_64/owned_pthread_stress_source.py'
    prepared_path = leaf / 'pthread_stress_test.c'
    io = reader.root / 'compat/x86_64/owned_io_cancellation_probe.c'
    try:
        prepared, replacements = stress_source.prepare(read_bytes(original), 'native-v1')
    except stress_source.SourceProfileError as error:
        raise NativeObservationError(str(error)) from error
    require(read_bytes(prepared_path) == prepared, 'prepared pthread source differs from the exact two-call derivative')
    source_map = {'schema': 'crabc.x86_64-pthread-stress-source/v1', 'profile': 'native-v1',
                  'original': reader.binding(original), 'prepared': reader.binding(prepared_path),
                  'preparer': reader.binding(preparer), 'replacements': replacements}
    same(report['source_map'], source_map, 'stress source map')
    same(read_json(leaf / 'source-map.json'), source_map, 'retained stress source map')
    same(report['replacement_io_cancellation_source'],
         {'path': io.relative_to(reader.root).as_posix(), 'sha256': digest(io)}, 'replacement I/O source requirement')
    obj = leaf / 'workload.o'
    same(report['oracle_link_command'], ['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie',
         '-pthread', reader.recorded(obj), '-o', reader.recorded(leaf / 'oracle')], 'stress oracle object command')
    for key, path in (('source_map_receipt_sha256', leaf / 'source-map.json'), ('source_sha256', original),
                      ('prepared_source_sha256', prepared_path), ('workload_object_sha256', obj),
                      ('compile_receipt_sha256', leaf / 'compile.json'), ('consumed_receipt_sha256', leaf / 'consumed.json')):
        same(report[key], digest(path), 'stress ' + key)
    compilation, consumed = read_json(leaf / 'compile.json'), read_json(leaf / 'consumed.json')
    same(compilation['source_map'], source_map, 'compiled stress source map')
    same(compilation['object_sha256'], digest(obj), 'compiled stress object')
    for path in (original, preparer, io, prepared_path, leaf / 'source-map.json', reader.manifest):
        reader.mode_identity(compilation['inputs'][reader.recorded(path)], path, 'stress compile input')
        reader.mode_identity(consumed[reader.recorded(path)], path, 'stress consumed input')
    for path in (obj, leaf / 'compile.json'):
        reader.mode_identity(consumed[reader.recorded(path)], path, 'stress consumed object/compile receipt')
    require(isinstance(report['links'], list) and len(report['links']) == 2, 'stress dynamic link roster differs')
    for mode, link in zip(('pie', 'non-pie'), report['links']):
        reader.link(link, mode, obj, leaf / ('dynamic-' + mode))
    stems = [f'iteration-{iteration:03d}-{cell}' for iteration in range(1, 11) for cell in ('oracle', *MODES)]
    expected_raw = raw_roster(leaf, stems, status_suffix='.status.json', auxiliary=(
        'compile.stdout', 'compile.stderr', 'oracle-link.stdout', 'oracle-link.stderr',
        'link-pie.stdout', 'link-pie.stderr', 'link-non-pie.stdout', 'link-non-pie.stderr'))
    same(set(report['raw_artifacts']) == {reader.recorded(leaf / name) for name in expected_raw}, True, 'stress raw artifact roster')
    expected_iterations, observations = [], {}
    for iteration in range(1, 11):
        row = {'iteration': iteration, 'observations': {}, 'comparisons': {}}
        for cell in ('oracle', *MODES):
            stem = f'iteration-{iteration:03d}-{cell}'
            raw, identity = reader.raw(stem, status_suffix='.status.json')
            status_path = leaf / (stem + '.status.json')
            status = read_json(status_path)
            keys(status, ('command', 'cwd', 'timeout_seconds', 'pid', 'process_group', 'status', 'returncode'), 'stress status')
            require(type(status['pid']) is int and status['pid'] > 0, 'stress child PID must be a positive integer')
            same([status['status'], status['returncode'], status['process_group']], [0, 0, status['pid']], 'stress raw child termination')
            command = ['chroot', reader.recorded(leaf / 'execution-root')]
            command += ['/oracle'] if cell == 'oracle' else (
                (['/lib/ld-crabc-x86_64.so.1'] if cell.endswith('-direct') else []) + ['/dynamic-' + cell.rsplit('-', 1)[0]])
            same([status['command'], status['cwd'], status['timeout_seconds']], [command, str(reader.mount), timeout], 'stress execution invocation')
            require(raw['stdout'] == b'pthread stress ok\n' and raw['stderr'] == b'', 'stress observation is not exact clean success')
            for stream, suffix in (('stdout', '.stdout'), ('stderr', '.stderr'), ('status', '.status.json')):
                path = leaf / (stem + suffix)
                reader.mode_identity(report['raw_artifacts'][reader.recorded(path)], path, 'stress raw artifact identity')
            row['observations'][cell] = {'status': 0, **{stream: {'hex': raw[stream].hex(),
                'byte_length': len(raw[stream]), 'sha256': hashlib.sha256(raw[stream]).hexdigest()} for stream in ('stdout', 'stderr')}}
            row['comparisons'][cell] = {'passed': True, 'equal': True, 'oracle_clean': True, 'candidate_clean': True}
            observations[f'{iteration:03d}/{cell}'] = identity
        expected_iterations.append(row)
    same(report['iterations'], expected_iterations, 'stress iterations and comparisons')
    return reader.finish('pthread-stress', 'pthread-stress.json', observations,
        {'application': reader.object(original, obj)}, source_map=reader.identity(leaf / 'source-map.json'),
        prepared_source=reader.identity(prepared_path), preparer=reader.identity(preparer, source=True),
        replacement_io_cancellation_required=['READ_FILE', 'ASYNC_LOOP'],
        replacement_io_cancellation_source=report['replacement_io_cancellation_source'],
        replacement_io_cancellation_receipt=None, native_aggregate_complete=False,
        limits={'iterations': 10, 'case_timeout_seconds': 10.0})


def _command_streams(reader, record, *, command=None, expected_status=0):
    same(record['exit_status'], expected_status, 'retained command exit status')
    require('start_error' not in record, 'retained command did not start')
    if command is not None:
        same(record['command'], command, 'retained command invocation')
    return {stream: reader.artifact(record[stream], raw=True) for stream in ('stdout', 'stderr')}


def _libc_test_source(reader, report, contract):
    stage, prepared = reader.leaf / 'source-stage', reader.leaf / 'source-prepared'
    tree, files = source_tree(stage)
    same(tree, LIBC_TEST_TREE, 'complete pinned libc-test Git tree')
    same([report['upstream']['revision'], report['upstream']['tree'], report['upstream']['url']],
         [LIBC_TEST_REVISION, LIBC_TEST_TREE, 'https://github.com/laputa-systems/libc-test.git'], 'libc-test upstream pin')
    preparation = report['source_preparation']['api_unistd']
    same(preparation['staged_tracked_files'], files, 'libc-test tracked source graph')
    relative = 'src/api/unistd.c'
    original = read_bytes(stage / relative)
    transformed, replacements = original, []
    for macro in ('_PC_TIMESTAMP_RESOLUTION', '_SC_XOPEN_UUCP'):
        line = 'C(' + macro + ')'
        replacement = '#ifdef ' + macro + '\n' + line + '\n#endif'
        require(transformed.count(line.encode()) == 1, 'libc-test guarded source occurrence differs')
        transformed = transformed.replace(line.encode(), replacement.encode())
        replacements.append({'line': line, 'macro': macro, 'occurrences': 1, 'replacement': replacement})
    same({key: preparation[key] for key in ('source', 'original_sha256', 'prepared_sha256', 'replacements')},
         {'source': relative, 'original_sha256': hashlib.sha256(original).hexdigest(),
          'prepared_sha256': hashlib.sha256(transformed).hexdigest(), 'replacements': replacements}, 'libc-test source derivative')
    _, prepared_files = source_tree(prepared)
    expected_prepared = {**files, relative: hashlib.sha256(transformed).hexdigest()}
    same(prepared_files, expected_prepared, 'libc-test complete prepared source graph')
    try:
        units, inventory = contract.collect_inventory(prepared)
    except (RuntimeError, ValueError) as error:
        raise NativeObservationError('libc-test source inventory differs: ' + str(error)) from error
    same(report['inventory'], inventory, 'libc-test upstream target inventory')
    require([unit['id'] for unit in report['units']] == [unit['id'] for unit in units],
            'libc-test complete unit roster differs')
    return units, files


def _libc_test_link(reader, phase, *, unit, side, objects, contract, product, output=None):
    leaf = reader.leaf
    shared = unit['kind'] == 'dso'
    output = output or leaf / 'links' / side / (unit['id'] + ('.so' if shared else '.exe'))
    roles = contract.unit_dso_roles(unit['id'])
    dsos = [leaf / 'links' / side / (name + '.so') for name in roles['initial']]
    same(phase['status'], 'passed', 'libc-test required link phase')
    reader.bind(phase['output'], output, 'libc-test linked executable')
    mapped = lambda path: Path(reader.recorded(path))
    arguments = {'shared_object': shared, 'application_dsos': list(map(mapped, dsos)),
                 'runpath': roles['runpath'], 'export_dynamic': roles['export_dynamic']}
    if side == 'candidate':
        command = contract.candidate_link_command(mapped(product), list(map(mapped, objects)), mapped(output), **arguments)
        receipt_path = Path(str(output) + '.crabc-link.json')
        reader.bind(phase['receipt']['receipt'], receipt_path, 'libc-test sealed receipt')
        receipt = read_json(receipt_path)
        search = receipt_contract.validate(
            receipt, format=PRODUCT_FORMAT, label='libc-test sealed receipt',
            fail=lambda message: require(False, message),
        )
        same([receipt['format'], receipt['mode'], receipt['binding'], receipt['runtime_imports'],
              receipt['application_runpath'], receipt['campaign_complete'], receipt['manifest_sha256']],
             [PRODUCT_FORMAT, 'shared' if shared else 'pie', 'now', [], roles['runpath'], False, digest(reader.manifest)],
             'libc-test sealed receipt contract')
        receipt_contract.require_runpath(
            search, roles['runpath'], label='libc-test sealed receipt', fail=lambda message: require(False, message)
        )
        same([receipt['output_path'], receipt['output_sha256']], [reader.recorded(output), digest(output)], 'libc-test receipt output')
        same(receipt['application_dsos'], {path.name: digest(path) for path in dsos}, 'libc-test initial DSO bindings')
        library = product / 'usr/lib'
        runtime = [library / name for name in ('crti.o', 'libc.so', 'crtn.o')]
        if not shared:
            runtime += [library / 'Scrt1.o', library / 'crabc-dynamic-attach.o']
        builtins = library / 'libcrabc-builtins.a'
        same(receipt['input_receipts'], [reader.binding(path) for path in [*runtime, *objects, *dsos, builtins]],
             'libc-test canonical object and product link graph')
        same(receipt['owned_runtime_inputs'], sorted(path.relative_to(product).as_posix() for path in [*runtime, builtins]),
             'libc-test owned runtime input roster')
        same(phase['receipt']['link_command'], receipt['link_command'], 'libc-test retained sealed command')
        same(phase['receipt']['link_trace'], receipt['link_trace'], 'libc-test retained sealed trace')
        linker = receipt['resolved_linker']
        keys(linker, ('path', 'sha256'), 'libc-test sealed linker identity')
        require(isinstance(linker['path'], str) and Path(linker['path']).is_absolute() and
                re.fullmatch('[0-9a-f]{64}', linker['sha256']) is not None, 'libc-test sealed linker identity is malformed')
        same(phase['receipt']['linker'], linker, 'libc-test retained linker identity')
        sealed = [linker['path'], '-shared' if shared else '-pie', '--hash-style=sysv', '-z', 'relro', '-z', 'now',
                  '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags',
                  '-rpath', roles['runpath']]
        if roles['export_dynamic']:
            sealed.append('--export-dynamic')
        if shared:
            sealed += ['-soname', output.name]
        else:
            sealed += ['--dynamic-linker', '/lib/ld-crabc-x86_64.so.1', reader.recorded(library / 'Scrt1.o'),
                       reader.recorded(library / 'crabc-dynamic-attach.o')]
        sealed += [reader.recorded(path) for path in [library / 'crti.o', *objects, *dsos, library / 'libc.so', builtins, library / 'crtn.o']]
        sealed += ['-o', reader.recorded(output)]
        same(receipt['link_command'], sealed, 'libc-test canonical sealed link command')
        direct = {reader.recorded(path) for path in [*runtime, *objects, *dsos]}
        archive = reader.recorded(builtins)
        trace = receipt['link_trace']
        require(isinstance(trace, list) and all(isinstance(item, str) for item in trace), 'libc-test sealed trace is malformed')
        require(all(item in direct or item == archive or (item.startswith(archive + '(') and item.endswith(')')) for item in trace),
                'libc-test sealed trace has a foreign input')
        require(direct <= set(trace), 'libc-test sealed trace omits a direct input')
    else:
        command = contract.oracle_link_command(list(map(mapped, objects)), mapped(output), **arguments)
    _command_streams(reader, phase['record'], command=command)
    same(phase['elf']['status'], 'passed', 'libc-test ELF audit')
    keys(phase['elf']['observations'], ('header', 'segments', 'dynamic', 'symbols', 'relocations'), 'libc-test retained ELF roster')
    for observation in phase['elf']['observations'].values():
        reader.artifact(observation['output'])
        _command_streams(reader, observation['record'])
        same(observation['output'], observation['record']['stdout'], 'libc-test ELF raw output binding')
        require(observation['record']['command'][-1] == reader.recorded(output), 'libc-test ELF command names another unit')
    return output


def _libc_product(reader, report):
    """Join the supplied product, immutable compilation copy, and both phases."""
    product = report['product']
    copied = reader.leaf / 'candidate-product'
    manifest = read_json(reader.manifest)
    identity = {'manifest_sha256': digest(reader.manifest), 'files': manifest['files'], 'aliases': manifest['symlinks']}
    for role, path, phases in (('source', reader.product, ('before', 'after_copy', 'after_use')),
                               ('copied', copied, ('before', 'after_use'))):
        keys(product[role], phases, 'libc-test product phase roster')
        for phase in phases:
            value = product[role][phase]
            same(value['path'], reader.recorded(path), 'libc-test ' + role + ' product path')
            for field, relative in (('manifest', 'share/crabc/manifest.json'), ('driver', 'bin/crabc-cc-dynamic'),
                                     ('compiler_helper', 'share/crabc/crabc_cc_static.py')):
                reader.bind(value[field], path / relative, 'libc-test product ' + field)
            same({'manifest_sha256': value['manifest']['sha256'], 'files': value['files'], 'aliases': value['aliases']},
                 identity, 'libc-test complete product identity across copies and use')
        observed_files, observed_aliases = {}, {}
        for item in path.rglob('*'):
            relative = item.relative_to(path).as_posix()
            if item.is_symlink():
                observed_aliases[relative] = os.readlink(item)
            elif item.is_file() and relative != 'share/crabc/manifest.json':
                observed_files[relative] = digest(item)
            else:
                require(item.is_dir() or relative == 'share/crabc/manifest.json', 'libc-test special product entry')
        same([observed_files, observed_aliases], [identity['files'], identity['aliases']], 'libc-test physical product copy')
    for field, relative in (('driver', 'bin/crabc-cc-dynamic'), ('compiler_helper', 'share/crabc/crabc_cc_static.py')):
        reader.bind(product[field], copied / relative, 'libc-test selected installed ' + field)
    keys(product['compiler'], ('path', 'sha256'), 'libc-test selected compiler identity')
    require(Path(product['compiler']['path']).is_absolute() and re.fullmatch('[0-9a-f]{64}', product['compiler']['sha256']) is not None,
            'libc-test selected compiler identity is malformed')
    environment = product['compiler_environment']
    same(environment, {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '1', 'TZ': 'UTC',
                       'TMPDIR': reader.recorded(reader.leaf / 'tmp')}, 'libc-test clean installed compiler environment')
    same(product['driver_support']['complete'], True, 'libc-test installed driver feature contract')
    return copied, identity


def _libc_oracle(reader, report):
    # The source runner checks the physical pinned /opt inputs. Retain that
    # complete identity and require its independent before/after agreement;
    # this reader may run outside the original evidence image.
    import run_qualification_manifest as qualification
    oracle = report['oracle']
    keys(oracle, ('before', 'after'), 'libc-test oracle phase roster')
    same(oracle['before'], oracle['after'], 'libc-test pinned oracle across execution')
    value = oracle['before']
    same(value['version'], 'musl-1.2.6', 'libc-test pinned oracle version')
    reader.bind(value['pins'], reader.root / 'compat/upstreams.toml', 'libc-test source oracle pins')
    keys(value['files'], qualification.MUSL_RUNTIME_PATHS, 'libc-test complete pinned oracle roster')
    for name, path in qualification.MUSL_RUNTIME_PATHS.items():
        record = value['files'][name]
        keys(record, ('path', 'sha256') if name == 'headers' else ('path', 'resolved_path', 'sha256'), 'libc-test oracle ' + name)
        same(record['path'], path, 'libc-test pinned oracle path')
        require(re.fullmatch('[0-9a-f]{64}', record['sha256']) is not None, 'libc-test malformed oracle hash')
        if name != 'headers':
            same(record['resolved_path'], qualification.MUSL_RUNTIME_PATHS['libc'] if name == 'loader' else path,
                 'libc-test pinned physical oracle path')
    same(value['files']['loader']['sha256'], value['files']['libc']['sha256'], 'libc-test pinned loader and libc bytes')
    same(value['files']['compiler_wrapper']['sha256'], digest(reader.root / 'docker/x86_64-musl-oracle-gcc'),
         'libc-test pinned compiler wrapper source')
    pin = tomllib.loads(read_bytes(reader.root / 'compat/upstreams.toml').decode())['musl']
    source_manifest = ('format=crabc-pinned-musl-oracle-v1\nversion=' + pin['version'] + '\nsource_sha256=' + pin['sha256'] +
                       '\nfallback_revision=' + pin['fallback_revision'] + '\narchitecture=x86_64\n').encode()
    specs_manifest = (value['files']['specs']['sha256'] + '  /opt/musl-1.2.6/lib/musl-gcc.specs\n').encode()
    for name, raw in (('source_manifest', source_manifest), ('specs_manifest', specs_manifest)):
        same(value['files'][name]['sha256'], hashlib.sha256(raw).hexdigest(), 'libc-test pinned oracle manifest semantics')
    return value


def _libc_filesystem_fixture(name):
    """Reconstruct only the pinned source's declared disposable-root inputs.

    Named semaphores/shared memory require /dev/shm. Musl's main-executable
    $ORIGIN lookup requires /proc/self/exe for the one source-selected TLS
    test; its literal target is that unit's separately bound executable.
    These records describe fixtures, not extra runtime providers.
    """
    if name in ('functional/sem_open', 'regression/sem_close-unmap', 'functional/pthread_cancel-points'):
        return [{'path': '/dev/shm', 'type': 'directory', 'mode': '01777'}]
    if name == 'regression/tls_get_new-dtv':
        return [{'path': '/proc', 'type': 'directory', 'mode': '0755'},
                {'path': '/proc/self', 'type': 'directory', 'mode': '0755'},
                {'path': '/proc/self/exe', 'type': 'symlink', 'target': '/regression/tls_get_new-dtv'}]
    return []


def _libc_execution_identity_fixture(name):
    """Only this unchanged source requires fork to honor RLIMIT_NPROC=0.

    Root bypasses that Linux precondition. The fixed child identity supplies
    the source's environment; it cannot waive a failing candidate or oracle.
    Keep this selector independent of the producer's declaration function.
    """
    if name != 'regression/pthread_atfork-errno-clobber':
        return None
    return {'kind': 'fixed-unprivileged-identity', 'uid': 65534, 'gid': 65534,
            'supplementary_groups': [],
            'required_zero_capability_sets': ['inheritable', 'permitted', 'effective', 'ambient'],
            'source_requirement': 'RLIMIT_NPROC=0 must reject fork before checking atfork errno preservation'}


def _libc_identity_snapshot(value, *, before_exec=False):
    keys(value, ('resuid', 'resgid', 'groups', 'proc'), 'libc-test identity snapshot')
    proc = keys(value['proc'], ('uids', 'gids', 'groups', 'capabilities'), 'libc-test proc identity')
    for field, count in (('resuid', 3), ('resgid', 3), ('groups', None)):
        values = value[field]
        require(isinstance(values, list) and (count is None or len(values) == count)
                and all(type(item) is int and 0 <= item < 2**32 for item in values),
                'libc-test malformed actual identity ' + field)
    for field in ('uids', 'gids'):
        require(isinstance(proc[field], list) and len(proc[field]) == 4
                and all(type(item) is int and 0 <= item < 2**32 for item in proc[field]),
                'libc-test malformed proc identity ' + field)
    same(proc['uids'][:3], value['resuid'], 'libc-test proc/getresuid agreement')
    same(proc['gids'][:3], value['resgid'], 'libc-test proc/getresgid agreement')
    require(isinstance(proc['groups'], list) and all(type(item) is int and 0 <= item < 2**32
            for item in proc['groups']), 'libc-test malformed proc supplementary groups')
    same(sorted(proc['groups']), sorted(value['groups']), 'libc-test proc/getgroups agreement')
    capabilities = keys(proc['capabilities'], ('inheritable', 'permitted', 'effective', 'bounding', 'ambient'),
                        'libc-test observed capability sets')
    require(all(isinstance(item, str) and re.fullmatch('[0-9a-f]{16}', item) for item in capabilities.values()),
            'libc-test capability observation is not sixteen lowercase hex digits')
    if before_exec:
        same([value['resuid'], value['resgid'], value['groups'], proc['uids'], proc['gids']],
             [[65534]*3, [65534]*3, [], [65534]*4, [65534]*4], 'libc-test actual fixed execution identity')
        same({key: capabilities[key] for key in ('inheritable', 'permitted', 'effective', 'ambient')},
             {key: '0000000000000000' for key in ('inheritable', 'permitted', 'effective', 'ambient')},
             'libc-test zero execution capabilities')
    else:
        same(proc['uids'], [0]*4, 'libc-test root parent user identity')


def _libc_execution_identity(reader, value, *, name, side, source, command):
    """Validate retained host control bytes and actual pre-exec observations.

    No host Python or helper is executed during collection. Its retained Python
    bytes bind the historical resolved executable, while the helper must also
    match this checkout's tracked source. The observation ends before exec;
    runtime success still comes from the separately retained target streams.
    """
    fixture = _libc_execution_identity_fixture(name)
    if fixture is None:
        same(value, None, 'libc-test undeclared execution identity fixture')
        require(command[0] in ('/usr/bin/timeout', '/bin/timeout') and
                command[2] in ('/usr/sbin/chroot', '/usr/bin/chroot', '/bin/chroot'),
                'libc-test runtime control command differs')
        same(command[1:], ['20', command[2], reader.recorded(reader.leaf / 'execution' / name / side),
                          '/runtest', '-w', '', '/' + name], 'libc-test bounded runtime invocation')
        return None
    keys(value, ('fixture', 'helper', 'python', 'source', 'source_after', 'receipt', 'parent'),
         'libc-test execution identity fixture record')
    same(value['fixture'], fixture, 'libc-test fixed execution identity declaration')
    helper = reader.root / 'compat/x86_64/owned_libc_test_identity.py'
    receipt_path = reader.leaf / 'execution' / name / (side + '.identity.json')
    execution_root = reader.leaf / 'execution' / name / side
    for role, retained in (('helper', 'owned_libc_test_identity.py'), ('python', 'python3')):
        artifact = keys(value[role], ('invoked_path', 'source', 'retained', 'after'), 'libc-test identity ' + role)
        copy = reader.leaf / 'execution-controls' / retained
        reader.bind(artifact['retained'], copy, 'libc-test retained identity ' + role)
        same(artifact['after'], artifact['source'], 'libc-test identity control unchanged ' + role)
        if role == 'helper':
            same(artifact['invoked_path'], reader.recorded(helper), 'libc-test tracked identity helper invocation')
            reader.bind(artifact['source'], helper, 'libc-test tracked identity helper source')
        else:
            same(artifact['invoked_path'], '/usr/bin/python3', 'libc-test identity Python invocation')
            keys(artifact['source'], ('path', 'sha256'), 'libc-test identity Python source')
            require(isinstance(artifact['source']['path'], str) and
                    re.fullmatch(r'/usr/bin/python3\.[0-9]+', artifact['source']['path']),
                    'libc-test identity Python resolved path')
        same(artifact['retained']['sha256'], artifact['source']['sha256'], 'libc-test retained control bytes ' + role)
    reader.bind(value['source'], source, 'libc-test identity prepared source')
    reader.bind(value['source_after'], source, 'libc-test identity prepared source after execution')
    reader.bind(value['receipt'], receipt_path, 'libc-test identity child receipt')
    same(command, ['/usr/bin/timeout', '20', '/usr/bin/python3', '-B', reader.recorded(helper),
                   '--root', reader.recorded(execution_root), '--receipt', reader.recorded(receipt_path),
                   '--unit', name], 'libc-test fixed identity invocation')
    receipt = keys(read_json(receipt_path), ('schema', 'unit', 'root', 'fixture', 'source', 'command', 'before_drop', 'before_exec'),
                   'libc-test identity child receipt')
    same({key: receipt[key] for key in ('schema', 'unit', 'root', 'fixture', 'source', 'command')},
         {'schema': 'crabc.x86_64-owned-libc-test-execution-identity/v1', 'unit': name,
          'root': reader.recorded(execution_root), 'fixture': fixture, 'source': reader.binding(source),
          'command': ['/runtest', '-w', '', '/' + name]}, 'libc-test source-bound identity execution')
    parent = keys(value['parent'], ('before', 'after', 'unchanged'), 'libc-test parent identity phases')
    same(parent['unchanged'], True, 'libc-test parent identity stability')
    same(parent['before'], parent['after'], 'libc-test unchanged parent identity')
    same(receipt['before_drop'], parent['before'], 'libc-test child inherited identity')
    _libc_identity_snapshot(parent['before'])
    _libc_identity_snapshot(receipt['before_exec'], before_exec=True)
    same(receipt['before_exec']['proc']['capabilities']['bounding'],
         parent['before']['proc']['capabilities']['bounding'], 'libc-test capability bounding set unchanged')
    return {'fixture': fixture, 'receipt': reader.identity(receipt_path, raw=True),
            'helper': reader.identity(helper, source=True),
            'python': reader.identity(reader.leaf / 'execution-controls/python3'),
            'parent': parent}


def _libc_root_phases(reader, run, *, name, side, payload, controls, topology, product_identity, oracle, product):
    phases = run['root_payload']
    keys(phases, ('before', 'after', 'unchanged'), 'libc-test private-root phase roster')
    same(phases['unchanged'], True, 'libc-test private-root payload unchanged')
    if side == 'candidate':
        runtime = {'candidate_product': product_identity}
        sources = {'candidate_product_manifest': reader.binding(product / 'share/crabc/manifest.json'),
                   'candidate_product_payload': product_identity}
    else:
        runtime = {'oracle_runtime': {key: {'source': oracle['files'][key], 'destination': destination,
                    'copied_sha256': oracle['files'][key]['sha256'], 'observed_sha256': oracle['files'][key]['sha256']}
                    for key, destination in (('loader', '/lib/ld-musl-x86_64.so.1'), ('libc', '/usr/lib/libc.so'))}}
        sources = {'oracle': oracle}
    copied = [{'destination': item['destination'], 'sha256': item['source']['sha256']} for item in [*payload, *controls]]
    for phase in ('before', 'after'):
        path = reader.leaf / 'execution' / name / (side + '.root-payload-' + phase + '.json')
        reader.bind(phases[phase], path, 'libc-test retained private-root phase')
        same(read_json(path), {'schema': 'crabc.x86_64-owned-libc-test-root-payload/v1', 'side': side, 'phase': phase,
             'runtime': runtime, 'copied_files': copied, 'control_fixture': controls, 'topology': topology,
             'filesystem_fixture': _libc_filesystem_fixture(name),
             'execution_identity_fixture': _libc_execution_identity_fixture(name),
             'canonical_source_bindings': sources}, 'libc-test copied runtime, programs, and controls')


def _libc_control_launcher(reader, fixture, *, contract, product, compiler, environment, oracle, launcher):
    """Bind either declared launcher to one installed-driver source object.

    The helper is a control fixture outside the pinned 434-unit source graph.
    Each runtime side links that same object, preserving the product loader
    alias while explicitly entering the separately copied musl/BusyBox shell or echo applet.
    """
    require(launcher in ('shell', 'echo'), 'libc-test unknown control launcher')
    destination = '/bin/sh' if launcher == 'shell' else '/bin/echo'
    expected_source = contract.CONTROL_SHELL_SOURCE if launcher == 'shell' else contract.CONTROL_ECHO_SOURCE
    work = reader.leaf / ('external-' + launcher)
    source, obj = work / (launcher + '-launcher.c'), work / (launcher + '-launcher.o')
    same(fixture['status'], 'passed', 'libc-test control fixture status')
    reader.bind(fixture['source'], source, 'libc-test declared control launcher source')
    require(read_bytes(source) == expected_source, 'libc-test control fixture source differs')
    translation, header = fixture['candidate_translation'], fixture['header_translation']
    same([translation['status'], header['status']], ['passed', 'passed'], 'libc-test control fixture translation')
    reader.bind(translation['object'], obj, 'libc-test control fixture canonical object')
    mapped = lambda path: Path(reader.recorded(path))
    _command_streams(reader, translation['record'], command=contract.compile_command(
        mapped(product), mapped(source), mapped(obj), shared_object=False, quote_dirs=(), kind='runtime'))
    _command_streams(reader, header['record'], command=contract.header_command(
        Path(compiler['path']), mapped(product), mapped(source), shared_object=False, quote_dirs=(), kind='runtime'))
    for value in (translation, header):
        same(value['record']['environment'], environment, 'libc-test control fixture compiler environment')
    reader.bind(header['trace'], reader.local(header['record']['stderr']['path']), 'libc-test control fixture header trace')
    trace = read_bytes(reader.local(header['trace']['path'])).decode('utf-8', errors='replace')
    paths = [match.group(1) for line in trace.splitlines() if (match := re.match(r'^\.+\s+(.*)$', line))]
    same(header['trace_paths'], paths, 'libc-test control fixture header closure')
    require(all(reader.local(path, within=reader.root).is_relative_to(product / 'usr/include') for path in paths),
            'libc-test control fixture has foreign headers')
    control = fixture['control']
    same(control['layout'], {'busybox': '/control/busybox', 'loader': '/control/ld-musl-x86_64.so.1', 'launcher': destination},
         'libc-test explicit launcher control layout')
    for name in ('busybox', 'loader'):
        value = control[name]
        keys(value, ('path', 'sha256'), 'libc-test launcher control identity')
        require(Path(value['path']).is_absolute() and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None,
                'libc-test malformed shell control identity')
    same(control['loader']['sha256'], oracle['files']['loader']['sha256'], 'libc-test launcher control pinned loader')
    same(control['loader']['path'], '/opt/musl-1.2.6/lib/libc.so', 'libc-test launcher control pinned source')
    controls = {}
    for side in ('candidate', 'oracle'):
        output = work / (side + '-' + launcher + '-launcher')
        _libc_test_link(reader, fixture[side + '_link'], unit={'id': 'external-' + launcher, 'kind': 'runtime'},
                        side=side, objects=[obj], contract=contract, product=product, output=output)
        reader.bind(fixture[side + '_launcher'], output, 'libc-test side-specific control launcher')
        controls[side] = [{'source': value, 'destination': destination, 'copied_sha256': value['sha256']}
                         for value, destination in ((control['busybox'], control['layout']['busybox']),
                                                    (control['loader'], control['layout']['loader']),
                                                    (reader.binding(output), destination))]
    return controls


def _libc_test(reader):
    # Only pure source-graph and command constructors are called. The runner's
    # execution/ELF validators remain its responsibility; no compiler is loaded.
    import owned_libc_test as contract
    import owned_math_oracle_defects as math_oracle
    import owned_wordexp_upstream_policy as wordexp_policy
    leaf = reader.leaf
    report = read_json(leaf / 'libc-test.json')
    profiled = reader.profile_companions is not None
    dispositions = []
    same({key: report[key] for key in ('schema', 'status', 'campaign_complete', 'public_support', 'target')},
         {'schema': 'crabc.x86_64-owned-libc-test/v1', 'status': 'incomplete' if profiled else 'passed', 'campaign_complete': False,
          'public_support': False, 'target': 'x86_64-unknown-linux-musl'}, 'complete libc-test campaign')
    require('fatal_error' not in report and report['candidate_link_blocker'] is None, 'libc-test campaign has a retained blocker')
    product = report['product']
    copied_product, product_identity = _libc_product(reader, report)
    oracle = _libc_oracle(reader, report)
    units, source_files = _libc_test_source(reader, report, contract)
    raw_counts = {}
    for unit in report['units']:
        status = unit.get('status')
        require(isinstance(status, str), 'libc-test unit status is malformed')
        raw_counts[status] = raw_counts.get(status, 0) + 1
    same(report['counts'], raw_counts, 'libc-test retained raw status counts')
    shell_controls = None
    if any(unit['id'] in contract.SHELL_RUNTIME_UNITS for unit in units):
        shell_controls = _libc_control_launcher(reader, report['external_shell_fixture'], contract=contract,
            product=copied_product, compiler=product['compiler'], environment=product['compiler_environment'], oracle=oracle, launcher='shell')
    echo_controls = None
    if any(unit['id'] == 'functional/spawn' for unit in units):
        echo_controls = _libc_control_launcher(reader, report['external_echo_fixture'], contract=contract,
            product=copied_product, compiler=product['compiler'], environment=product['compiler_environment'], oracle=oracle, launcher='echo')
    options = report['source_preparation']['options']
    same(options['status'], 'passed', 'libc-test generated API options')
    reader.bind(options['input'], leaf / 'source-prepared/src/common/options.h.in', 'libc-test generated options template')
    reader.bind(options['output'], leaf / 'generated/candidate/options.h', 'libc-test generated options header')
    _command_streams(reader, options['record'], command=[product['compiler']['path'], '-nostdinc', '-isystem',
        reader.recorded(copied_product / 'usr/include'), '-ffreestanding', '-fno-builtin', '-fstack-protector-strong',
        '-std=c99', '-D_POSIX_C_SOURCE=200809L', '-D_FILE_OFFSET_BITS=64', '-E', '-H', '-'])
    same(options['record']['environment'], product['compiler_environment'], 'libc-test options compiler environment')
    reader.bind(options['trace'], reader.local(options['record']['stderr']['path']), 'libc-test generated options trace')
    # This is the pinned Makefile's options-header text transform. Its input is
    # retained preprocessor stdout; never invoke a preprocessor while reading.
    active, pending, definitions = False, None, []
    for line in read_bytes(reader.local(options['record']['stdout']['path'])).decode('utf-8', errors='replace').splitlines():
        if 'optiongroups_unistd_end' in line:
            active = True
            continue
        if not active or not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        if pending is None:
            pending = fields[0]
            if len(fields) == 1:
                continue
        definitions.append('#define ' + pending + ' ' + fields[-1])
        pending = None
    generated = ('\n'.join(definitions) + ('\n' if definitions else '')).encode()
    require(read_bytes(leaf / 'generated/candidate/options.h') == generated, 'libc-test generated options differ from raw preprocessing')
    same(report['source_graph']['dynamic_runtime_modes'], ['dynamic-pie'], 'libc-test runtime mode')
    runtest = report['source_graph']['runtest']
    same({key: runtest[key] for key in ('source', 'child_stack_limit_bytes', 'default_timeout_seconds', 'makefile_invocation')},
         {'source': 'src/common/runtest.c', 'child_stack_limit_bytes': 102400, 'default_timeout_seconds': 5,
          'makefile_invocation': ['runtest.exe', '-w', '', 'TARGET']}, 'libc-test upstream harness contract')
    objects, observations = {}, {}
    object_paths = {unit['id']: leaf / 'objects/candidate' / (unit['id'] + '.o') for unit in units}
    actual_objects = {path.relative_to(leaf / 'objects/candidate').as_posix() for path in (leaf / 'objects/candidate').rglob('*') if path.is_file()}
    same(actual_objects == {name + '.o' for name in object_paths}, True, 'libc-test canonical object roster')
    for definition, unit in zip(units, report['units']):
        name, kind = definition['id'], definition['kind']
        crypt_profile = profiled and name == 'functional/crypt'
        strptime_profile = profiled and name == 'functional/strptime'
        wordexp_profile = profiled and name == 'functional/wordexp'
        math_oracle_defect = profiled and name in math_oracle.ORACLE_DEFECTS
        profiled_runtime = crypt_profile or strptime_profile or wordexp_profile or math_oracle_defect
        same([unit['id'], unit['kind'], unit['suite'], unit['status']],
             [name, kind, definition['suite'], 'runtime-failed' if profiled_runtime else 'passed'], 'libc-test unit role and status')
        source, obj = leaf / 'source-prepared' / definition['source'], object_paths[name]
        reader.bind(unit['source'], source, 'libc-test prepared compilation source')
        translation, header = unit['candidate_translation'], unit['header_translation']
        same([translation['status'], header['status'], header['foreign_headers']], ['passed', 'passed', []], 'libc-test translation phases')
        reader.bind(translation['object'], obj, 'libc-test canonical source object')
        quote_dirs = [leaf / 'source-prepared/src/common'] + ([leaf / 'generated/candidate'] if kind == 'api' else [])
        mapped = lambda path: Path(reader.recorded(path))
        same(unit['quote_include_dirs'], list(map(str, map(mapped, quote_dirs))), 'libc-test quote include closure')
        command = contract.compile_command(mapped(copied_product), mapped(source), mapped(obj), shared_object=kind == 'dso',
                                           quote_dirs=list(map(mapped, quote_dirs)), kind=kind)
        compile_streams = _command_streams(reader, translation['record'], command=command)
        same(translation['record']['environment'], product['compiler_environment'], 'libc-test installed compiler environment')
        header_command = contract.header_command(Path(product['compiler']['path']), mapped(copied_product), mapped(source),
            shared_object=kind == 'dso', quote_dirs=list(map(mapped, quote_dirs)), kind=kind)
        _command_streams(reader, header['record'], command=header_command)
        same(header['record']['environment'], product['compiler_environment'], 'libc-test installed header compiler environment')
        reader.bind(header['trace'], reader.local(header['record']['stderr']['path']), 'libc-test header trace')
        trace = read_bytes(reader.local(header['trace']['path'])).decode('utf-8', errors='replace')
        paths = [match.group(1) for line in trace.splitlines() if (match := re.match(r'^\.+\s+(.*)$', line))]
        same(header['trace_paths'], paths, 'libc-test retained header closure')
        for path in paths:
            local = reader.local(path, within=reader.root)
            require(any(local.is_relative_to(parent) for parent in
                        (copied_product / 'usr/include', leaf / 'source-prepared/src', leaf / 'generated')),
                    'libc-test header escapes installed and prepared inputs')
        objects[name] = {'source': reader.identity(source), 'object': reader.identity(obj)}
        if kind == 'api' or (kind == 'common' and name != contract.RUNTIME_HELPER):
            reason = 'upstream api targets are compilation-only' if kind == 'api' else 'upstream support object has no standalone link edge'
            for field in ('candidate_link', 'oracle_link'):
                same(unit[field], {'status': 'not-applicable', 'reason': reason}, 'libc-test absent source link edge')
            runtime_reason = reason if kind == 'api' else 'upstream support object has no direct runtest edge'
            same(unit['runtime'], {'status': 'not-applicable', 'reason': runtime_reason}, 'libc-test absent source runtime edge')
            observations[name] = {'kind': kind, 'translation': compile_streams}
            continue
        inputs = [obj] + ([object_paths[item] for item in contract.COMMON_MEMBERS] if kind != 'dso' else [])
        linked = {side: _libc_test_link(reader, unit[side + '_link'], unit=definition, side=side, objects=inputs, contract=contract, product=copied_product)
                  for side in ('candidate', 'oracle')}
        if kind != 'runtime':
            reason = ('upstream helper DSO has no direct runtest edge' if kind == 'dso'
                      else 'upstream runtest is the target-side harness executable')
            same(unit['runtime'], {'status': 'not-applicable', 'reason': reason}, 'libc-test support runtime edge')
            observations[name] = {'kind': kind, 'translation': compile_streams}
            continue
        runtime = unit['runtime']
        same(runtime['comparison'], {'status': 'blocked', 'reason': 'candidate runtime did not pass this prepared root'}
             if crypt_profile else {'status': 'blocked', 'reason': 'pinned-musl runtime did not pass this prepared root'}
             if strptime_profile or wordexp_profile or math_oracle_defect else {'status': 'passed', 'detail': 'passed'},
             'libc-test runtime comparison')
        results, raw = {}, {}
        for side in ('oracle', 'candidate'):
            run = runtime[side]
            failed = wordexp_profile or (side == 'candidate' and (crypt_profile or strptime_profile)) or (
                side == 'oracle' and (strptime_profile or math_oracle_defect))
            same([run['status'], run['root_reclaimed']], ['failed' if failed else 'passed', True],
                 'libc-test private-root raw result')
            record = run['record']
            status_path = leaf / 'execution' / name / (side + '.status.json')
            reader.bind(run['status_record'], status_path, 'libc-test durable runtime status')
            same(read_json(status_path), record, 'libc-test independent runtime command result')
            for stream in ('stdout', 'stderr'):
                reader.bind(record[stream], leaf / 'execution' / name / (side + '.' + stream), 'libc-test per-unit raw ' + stream)
            same(record['environment'], {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '1', 'TZ': 'UTC'},
                 'libc-test private-root execution environment')
            command = record['command']
            identity = _libc_execution_identity(reader, run['execution_identity'], name=name, side=side,
                                                source=source, command=command)
            results[side] = {**_command_streams(reader, record, expected_status=1 if failed else 0),
                             'status': reader.identity(status_path, raw=True),
                             'execution_identity': identity}
            raw[side] = [read_bytes(reader.local(record[stream]['path'])) for stream in ('stdout', 'stderr')]
            roles = contract.unit_dso_roles(name)
            payload = [{'source': reader.binding(leaf / 'links' / side / 'common/runtest.exe'), 'destination': '/runtest'},
                       {'source': reader.binding(linked[side]), 'destination': '/' + name}]
            payload += [{'source': reader.binding(leaf / 'links' / side / (dso + '.so')), 'destination': destination}
                        for dso, destination in roles['runtime']]
            payload += [{'source': reader.binding(leaf / 'links' / side / (dso + '.so')), 'destination': '/usr/lib/' + Path(dso).name + '.so'}
                        for dso in roles['initial']]
            controls = []
            if name == 'functional/spawn':
                controls = echo_controls[side]
            elif name in contract.SHELL_RUNTIME_UNITS:
                controls = shell_controls[side]
            _libc_root_phases(reader, run, name=name, side=side, payload=payload, controls=controls, topology=roles,
                              product_identity=product_identity, oracle=oracle, product=copied_product)
        if crypt_profile:
            import owned_posix_native_dispositions as profile_contract
            dispositions.append(profile_contract.crypt_disposition(reader, source,
                candidate_status=runtime['candidate']['record']['exit_status'], candidate_stdout=raw['candidate'][0], candidate_stderr=raw['candidate'][1],
                oracle_status=runtime['oracle']['record']['exit_status'], oracle_stdout=raw['oracle'][0], oracle_stderr=raw['oracle'][1],
                companion=reader.profile_companions['crypt']))
        elif strptime_profile:
            import owned_posix_native_dispositions as profile_contract
            dispositions.append(profile_contract.strptime_disposition(reader, source,
                candidate_status=runtime['candidate']['record']['exit_status'], candidate_stdout=raw['candidate'][0], candidate_stderr=raw['candidate'][1],
                oracle_status=runtime['oracle']['record']['exit_status'], oracle_stdout=raw['oracle'][0], oracle_stderr=raw['oracle'][1]))
        elif wordexp_profile:
            import owned_posix_native_dispositions as profile_contract
            disposition = wordexp_policy.upstream_disposition(reader, source,
                candidate_status=runtime['candidate']['record']['exit_status'], candidate_stdout=raw['candidate'][0], candidate_stderr=raw['candidate'][1],
                oracle_status=runtime['oracle']['record']['exit_status'], oracle_stdout=raw['oracle'][0], oracle_stderr=raw['oracle'][1],
                companion=reader.profile_companions['wordexp'])
            disposition['profiles'] = profile_contract.profile_sources(reader.root)
            dispositions.append(disposition)
        elif math_oracle_defect:
            dispositions.append(math_oracle.oracle_defect_disposition(reader, source, unit=name,
                candidate_status=runtime['candidate']['record']['exit_status'], candidate_stdout=raw['candidate'][0], candidate_stderr=raw['candidate'][1],
                oracle_status=runtime['oracle']['record']['exit_status'], oracle_stdout=raw['oracle'][0], oracle_stderr=raw['oracle'][1]))
        else:
            require(raw['oracle'] == raw['candidate'], 'libc-test raw runtime streams differ: ' + name)
        observations[name] = {'kind': kind, **results}
    expected_dispositions = ['functional/crypt', 'functional/strptime', 'functional/wordexp', *math_oracle.ORACLE_DEFECTS]
    require(not profiled or [entry['unit'] for entry in dispositions] == expected_dispositions,
            'libc-test fixed profile and math oracle-defect dispositions are missing')
    return reader.finish('libc-test', 'libc-test.json', observations, objects,
                         qualification={'status': 'profile-qualified' if profiled else 'passed',
                                        'raw_passed': not profiled, 'dispositions': dispositions},
                         source_tree={'revision': LIBC_TEST_REVISION, 'tree': LIBC_TEST_TREE, 'files': source_files},
                         limits={'runtime_case_seconds': 5, 'outer_timeout_seconds': 20})


def _os_snapshot(value, data=None):
    keys(value, ('text', 'sha256', 'byte_length'), 'os-test stream snapshot')
    require(isinstance(value['text'], str), 'os-test stream text is malformed')
    if data is None:
        data = value['text'].encode()
    same(value, {'text': data.decode('utf-8', errors='replace'), 'sha256': hashlib.sha256(data).hexdigest(),
                 'byte_length': len(data)}, 'os-test retained stream bytes')
    return data


def _os_sealed_link(reader, *, binary, receipt_path, shared, output, workload_path, link_identity, retained_object, product):
    receipt = read_json(receipt_path)
    search = receipt_contract.validate(
        receipt, format=PRODUCT_FORMAT, label='os-test sealed receipt', fail=lambda message: require(False, message)
    )
    same([receipt['format'], receipt['mode'], receipt['binding'], receipt['runtime_imports'],
          receipt['application_runpath'], receipt['application_dsos'], receipt['campaign_complete'], receipt['manifest_sha256']],
         [PRODUCT_FORMAT, 'shared' if shared else 'pie', 'now', [], '/usr/lib', {}, False, digest(reader.manifest)],
         'os-test sealed link contract')
    receipt_contract.require_runpath(
        search, '/usr/lib', label='os-test sealed receipt', fail=lambda message: require(False, message)
    )
    same([receipt['output_path'], receipt['output_sha256']], [output, digest(binary)], 'os-test retained link output')
    library = product / 'usr/lib'
    runtime = [library / name for name in ('crti.o', 'libc.so', 'crtn.o')]
    if not shared:
        runtime += [library / 'Scrt1.o', library / 'crabc-dynamic-attach.o']
    builtins = library / 'libcrabc-builtins.a'
    workload = {'path': workload_path, 'sha256': digest(retained_object)}
    same(receipt['input_receipts'], [*(reader.binding(path) for path in runtime), workload, reader.binding(builtins)],
         'os-test canonical object and product input graph')
    same(receipt['owned_runtime_inputs'], sorted(path.relative_to(product).as_posix() for path in [*runtime, builtins]),
         'os-test runtime input roster')
    linker = receipt['resolved_linker']
    keys(linker, ('path', 'sha256'), 'os-test sealed linker identity')
    require(isinstance(linker['path'], str) and Path(linker['path']).is_absolute() and
            re.fullmatch('[0-9a-f]{64}', linker['sha256']) is not None, 'os-test sealed linker identity is malformed')
    command = [linker['path'], '-shared' if shared else '-pie', '--hash-style=sysv', '-z', 'relro', '-z', 'now',
               '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags', '-rpath', '/usr/lib']
    if shared:
        command += ['-soname', Path(output).name]
    else:
        command += ['--dynamic-linker', '/lib/ld-crabc-x86_64.so.1', reader.recorded(library / 'Scrt1.o'),
                    reader.recorded(library / 'crabc-dynamic-attach.o')]
    command += [reader.recorded(library / 'crti.o'), workload_path, reader.recorded(library / 'libc.so'),
                reader.recorded(builtins), reader.recorded(library / 'crtn.o'), '-o', output]
    same(receipt['link_command'], command, 'os-test canonical sealed link command')
    direct, archive = {reader.recorded(path) for path in runtime} | {workload_path}, reader.recorded(builtins)
    trace = receipt['link_trace']
    require(isinstance(trace, list) and all(isinstance(item, str) for item in trace), 'os-test malformed sealed trace')
    require(all(item in direct or item == archive or (item.startswith(archive + '(') and item.endswith(')')) for item in trace),
            'os-test sealed trace has a foreign input')
    require(direct <= set(trace), 'os-test sealed trace omits a direct input')
    identity = {'linkage': 'shared' if shared else 'pie', 'product_manifest_sha256': digest(reader.manifest),
                'workload_sha256': digest(retained_object), 'receipt_sha256': digest(receipt_path)}
    if shared:
        identity['output_sha256'] = digest(binary)
    else:
        identity.update(product=reader.recorded(product), product_format=PRODUCT_FORMAT, executable_sha256=digest(binary))
    same(link_identity, identity, 'os-test canonical link identity')



def _os_link_receipt(reader, event, retained_object, product):
    _os_sealed_link(reader, binary=reader.local(event['retained_output']), receipt_path=reader.local(event['retained_receipt']),
                    shared=event['plan']['mode'] == 'shared', output=event['output'], workload_path=event['workload'],
                    link_identity=event['link_identity'], retained_object=retained_object, product=product)


def _os_event_graph(reader, suite, expected, result, source_files, contract):
    """Reconstruct the Make scripts' attempted C graph, including failed probes.

    `include` retries three feature profiles and may retry a failed link;
    `namespace` preprocesses twice per source; the ordinary suites compile
    once, and basic's three dlfcn cases also build the same C source as a DSO.
    A matching upstream `undefined` or `missing_header` outcome is not turned
    into an invented successful object or runtime execution.
    """
    leaf = reader.leaf
    source_root, product = leaf / 'suites' / suite, leaf / 'products' / suite
    cwd = source_root / suite
    events_root = leaf / 'evidence' / suite / 'events'
    paths = sorted(physical(events_root, directory=True).glob('*.json'))
    same(result['adapter_event_count'], len(paths), 'os-test adapter event count')
    same(result['adapter_errors'], [], 'os-test adapter error roster')
    events = {path.name: read_json(path) for path in paths}
    expected_sources = {str(Path(path).with_suffix('.c')) for path in expected}
    attempts = {name: [] for name in expected_sources}
    objects, original_objects, links = {}, {}, {}
    base_flags = ['-Wall', '-Wextra'] + (['-Werror', '-Wno-error=deprecated', '-Wno-error=deprecated-declarations']
                                      if suite == 'include' else ['-Werror=implicit-function-declaration'])
    extensions = ['-D_GNU_SOURCE', '-D_BSD_SOURCE', '-D_ALL_SOURCE', '-D_DEFAULT_SOURCE']
    include_profiles = [['-D_POSIX_C_SOURCE=202405L'], ['-D_POSIX_C_SOURCE=200809L'], extensions]
    dso_sources = {'dlfcn/dlclose.c', 'dlfcn/dlopen.c', 'dlfcn/dlsym.c'} if suite == 'basic' else set()
    for filename, event in events.items():
        event_id = filename.split('.', 1)[0]
        require(re.fullmatch('[0-9a-f]{32}', event_id) is not None, 'os-test malformed adapter event identity')
        same(event['schema'], 'crabc.x86_64-owned-os-test-adapter/v1', 'os-test adapter schema')
        same(event['cwd'], reader.recorded(cwd), 'os-test adapter working directory')
        require('adapter_error' not in event and event['state'] in ('started', 'finished', 'link-finished'),
                'os-test adapter did not finish its source graph')
        same(filename, event_id + ('.link.json' if event['state'] == 'link-finished' else '.json'), 'os-test canonical event filename')
        plan = event['plan']
        same(plan, contract.json_safe(contract.target_plan(event['raw_command'], Path(reader.recorded(product)))),
             'os-test raw invocation and admitted plan')
        if event['state'] == 'started':
            require(plan['kind'] == 'link' and event_id + '.link.json' in events, 'os-test unfinished link attempt')
            continue
        same(event['event_id'], event_id, 'os-test final adapter event identity')
        require(type(event['status']) is int, 'os-test adapter status is not an integer')
        suffix = '.link' if event['state'] == 'link-finished' else ''
        for stream in ('stdout', 'stderr'):
            _os_snapshot(event[stream], read_bytes(events_root / (event_id + suffix + '.' + stream)))
        if event['state'] == 'link-finished':
            require(event_id + '.json' in events, 'os-test link has no source attempt')
            parent = events[event_id + '.json']
            for field in ('cwd', 'raw_command', 'compiler', 'plan'):
                same(event[field], parent[field], 'os-test compile/link event association')
            links.setdefault(event['workload'], []).append(event)
            continue
        kind, source = plan['kind'], plan['source']
        require(source in expected_sources and kind in ('compile', 'source-link', 'preprocess'), 'os-test foreign source attempt')
        same(digest(cwd / source), source_files[suite + '/' + source], 'os-test compiled source bytes')
        attempts[source].append(event)
        if kind == 'preprocess':
            require(suite == 'namespace' and type(plan['macro_dump']) is bool, 'os-test unexpected preprocessing edge')
            same(plan['flags'], ['-D_POSIX_C_SOURCE=202405L', '-std=c17'], 'os-test namespace feature profile')
            expected_output = str(Path(source).with_suffix('.dM' if plan['macro_dump'] else '.i'))
            same(plan['output'], expected_output, 'os-test namespace output role')
            command = [*contract.compiler_command(event['compiler']['path'], Path(reader.recorded(product)), Path(source),
                       Path('/dev/null'), plan['flags'], 'pie')[:-4], '-E', *(['-dM'] if plan['macro_dump'] else []), source, '-o', expected_output]
            same(event['command'], command, 'os-test namespace compiler invocation')
            if event['status'] == 0:
                output = leaf / 'evidence' / suite / 'preprocessed' / (event_id + Path(expected_output).suffix)
                same(event['output'], {'source_path': reader.recorded(cwd / expected_output), 'retained': reader.recorded(output),
                                       'sha256': digest(output)}, 'os-test retained preprocessing output')
            else:
                require('output' not in event, 'os-test failed preprocessing invented an output')
        else:
            if kind == 'source-link':
                require(source in dso_sources, 'os-test undeclared helper DSO source')
                same([plan['mode'], plan['flags'], plan['output']], ['shared', ['-DSHARED'], str(Path(source).with_suffix('.so'))],
                     'os-test helper DSO compilation profile')
                object_path = leaf / 'evidence' / suite / 'objects' / (event_id + '.o')
                command_object = reader.recorded(object_path)
            else:
                require(suite != 'namespace' and plan['mode'] == 'pie', 'os-test unexpected canonical compilation mode')
                allowed = [base_flags + profile for profile in include_profiles] if suite == 'include' else [base_flags + extensions]
                require(plan['flags'] in allowed, 'os-test source feature profile differs')
                expected_output = '../out/linux/' + suite + '/' + str(Path(source).with_suffix('.o'))
                same(plan['output'], expected_output, 'os-test canonical source object output')
                object_path = source_root / 'out/linux' / suite / Path(source).with_suffix('.o')
                command_object = expected_output
            same(event['command'], [reader.recorded(product / 'bin/crabc-cc-dynamic'),
                 '--dynamic-shared-object' if kind == 'source-link' else '--dynamic-pie', '-c', source, '-o', command_object, *plan['flags']],
                 'os-test installed-driver compilation')
            if event['status'] == 0:
                retained = leaf / 'evidence' / suite / 'objects' / (event_id + '.driver.o')
                direct = leaf / 'evidence' / suite / 'objects' / (event_id + '.direct.o')
                same(event['object'], {'path': reader.recorded(object_path), 'retained': reader.recorded(retained), 'sha256': digest(retained)},
                     'os-test canonical retained object')
                replay = event['replay']
                same([replay['status'], replay['byte_equal'], replay['object'], replay['object_sha256']],
                     [0, True, reader.recorded(direct), digest(direct)], 'os-test independent object replay')
                require(read_bytes(retained) == read_bytes(direct), 'os-test driver/replay object bytes differ')
                same(replay['command'], contract.compiler_command(event['compiler']['path'], Path(reader.recorded(product)), Path(source),
                     Path(reader.recorded(direct)), plan['flags'], plan['mode']), 'os-test direct object compiler invocation')
                for stream in ('stdout', 'stderr'):
                    _os_snapshot(replay[stream])
                key = reader.recorded(object_path)
                require(key not in original_objects, 'os-test canonical object overwritten by another successful attempt')
                original_objects[key] = (retained, event)
                objects[suite + '/' + event_id] = {'source': reader.identity(leaf / 'source-stage' / suite / source),
                                                  'object': reader.identity(retained), 'replay': reader.identity(direct)}
            else:
                require('object' not in event and 'replay' not in event, 'os-test failed compile invented an object')
        if 'dependencies' in event:
            dependencies = event['dependencies']
            require(type(dependencies['status']) is int, 'os-test dependency status is not an integer')
            if event['status'] == 0:
                same(dependencies['status'], 0, 'os-test successful source header closure')
            same(dependencies['command'], contract.dependency_command(event['compiler']['path'], Path(reader.recorded(product)),
                 Path(source), plan['flags'], 'pie' if kind == 'preprocess' else plan['mode']), 'os-test header dependency invocation')
            raw = _os_snapshot(dependencies['stdout'])
            _os_snapshot(dependencies['stderr'])
            if kind == 'preprocess':
                for stream in ('stdout', 'stderr'):
                    _os_snapshot(dependencies[stream], read_bytes(events_root / (event_id + '.dependencies.' + stream)))
            if dependencies['status'] == 0:
                require(b':' in raw, 'os-test malformed dependency output')
                names = raw.decode().replace('\\\n', ' ').split(':', 1)[1].split()
                headers = {}
                for name in names:
                    recorded = posixpath.normpath(posixpath.join(reader.recorded(cwd), name))
                    path = reader.local(recorded)
                    require(path.is_relative_to(source_root) or path.is_relative_to(product / 'usr/include'), 'os-test foreign header dependency')
                    headers[recorded] = digest(path)
                same(dependencies['headers'], headers, 'os-test complete retained header closure')
            else:
                same(dependencies['headers'], {}, 'os-test failed dependency probe has no closure')
        else:
            require(event['status'] != 0 and kind != 'preprocess', 'os-test successful source omits its header closure')
    for source, rows in attempts.items():
        if suite == 'namespace':
            require(len(rows) == 2 and {row['plan']['macro_dump'] for row in rows} == {False, True}, 'os-test namespace preprocessing graph differs')
            continue
        compiled = [row for row in rows if row['plan']['kind'] == 'compile']
        helpers = [row for row in rows if row['plan']['kind'] == 'source-link']
        require(len(helpers) == (1 if source in dso_sources else 0), 'os-test source-defined DSO graph differs')
        require(all(row['status'] == 0 for row in helpers), 'os-test mandatory helper DSO compilation failed')
        if suite == 'include':
            by_flags = {tuple(row['plan']['flags']): row for row in compiled}
            require(len(by_flags) == len(compiled), 'os-test duplicate include feature attempt')
            required = []
            for profile in include_profiles:
                flags = tuple(base_flags + profile)
                require(flags in by_flags, 'os-test omitted include feature attempt')
                required.append(flags)
                if by_flags[flags]['status'] == 0:
                    break
            require(set(by_flags) == set(required), 'os-test include retry graph differs')
        else:
            require(len(compiled) == 1, 'os-test ordinary source compile graph differs')
        if not any(row['status'] == 0 for row in compiled):
            require(result['outcomes'][str(Path(source).with_suffix('.out'))]['text'] in
                    ('missing_optional\n', 'missing_header\n', 'incompatible\n', 'undeclared\n', 'unknown_type\n', 'compile_error\n'),
                    'os-test failed source claimed an executable observation')
    require(set(links) == set(original_objects), 'os-test successful objects and attempted links differ')
    for workload, rows in links.items():
        retained, compiled = original_objects[workload]
        shared = compiled['plan']['kind'] == 'source-link'
        if suite == 'include':
            require(len(rows) in (1, 2) and (len(rows) == 2 or rows[0]['status'] == 0), 'os-test include link retry graph differs')
            require(sum(row['status'] == 0 for row in rows) <= 1, 'os-test include link succeeded twice')
        else:
            require(len(rows) == 1, 'os-test source link graph differs')
        if shared:
            require(rows[0]['status'] == 0, 'os-test mandatory helper DSO link failed')
        elif suite == 'include':
            profile = compiled['plan']['flags'][len(base_flags):]
            label = ('good', 'previous_posix', 'extension')[include_profiles.index(profile)]
            if len(rows) == 2:
                label = 'outside_libc' if any(row['status'] == 0 for row in rows) else 'undefined'
            same(result['outcomes'][str(Path(compiled['plan']['source']).with_suffix('.out'))]['text'], label + '\n',
                 'os-test include outcome follows its actual retry graph')
        elif rows[0]['status'] != 0:
            same(result['outcomes'][str(Path(compiled['plan']['source']).with_suffix('.out'))]['text'], 'undefined\n',
                 'os-test failed link outcome')
        for event in rows:
            same([event['plan']['kind'], event['plan']['output'], event['plan']['flags']],
                 ['source-link' if shared else 'link', str(Path(compiled['plan']['source']).with_suffix('.so' if shared else '')),
                  ['-DSHARED'] if shared else base_flags], 'os-test source-defined link target')
            same(event['command'], [reader.recorded(product / 'bin/crabc-cc-dynamic'),
                 '--dynamic-shared-object' if shared else '--dynamic-pie', workload, '-o', event['plan']['output']], 'os-test canonical object link invocation')
            output = cwd / event['plan']['output']
            same(event['output'], reader.recorded(output), 'os-test source-derived linked output')
            if event['status'] == 0:
                _os_link_receipt(reader, event, retained, product)
                binary = reader.local(event['retained_output'])
                if shared:
                    target = leaf / 'runtime' / suite / 'work' / suite / event['plan']['output']
                    same(event['runtime_dso'], reader.recorded(target), 'os-test executed helper DSO')
                    same(digest(target), digest(binary), 'os-test runtime DSO bytes')
                else:
                    wrapper = event['execution_wrapper']
                    target = leaf / 'runtime' / suite / 'work' / suite / event['plan']['output']
                    same(wrapper, {'runtime_path': reader.recorded(target), 'runtime_sha256': digest(binary),
                                   'host_wrapper': reader.recorded(output), 'runtime_cwd': '/work/' + suite}, 'os-test execution payload binding')
                    same(digest(target), digest(binary), 'os-test actual runtime payload')
            else:
                require('retained_output' not in event and 'link_identity' not in event, 'os-test failed link invented a sealed output')
    return objects


def _os_make(reader, suite, side, record, timeout, contract):
    prefix = reader.leaf / 'records' / (suite + '.' + side)
    status_path = Path(str(prefix) + '.status.json')
    reader.relative_artifact(record['status_record'], status_path)
    status = read_json(status_path)
    expected = {'schema': 'crabc.x86_64-owned-os-test-make-status/v1', 'suite': suite, 'side': side,
                'command': record['command'], 'timeout_seconds': timeout, 'make_status': 0,
                'environment': {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': '1'},
                'stdout': record['stdout'], 'stderr': record['stderr']}
    same(status, expected, 'os-test canonical Make result')
    same([record['make_status'], record['timeout_seconds']], [0, timeout], 'os-test Make report result')
    raw = {'status': reader.identity(status_path, raw=True)}
    for stream in ('stdout', 'stderr'):
        raw[stream] = reader.relative_artifact(record[stream], Path(str(prefix) + '.' + stream), raw=True)
    command = record['command']
    root = reader.leaf / ('musl' if side == 'musl' else 'suites') / suite
    if side == 'musl':
        same(command, contract.musl_make_command(suite, Path(reader.recorded(root)), 8), 'os-test pinned-musl Make invocation')
    else:
        expected = contract.make_command(suite, Path(reader.recorded(root)),
            Path(reader.recorded(reader.root / 'compat/x86_64/owned_os_test.py')),
            Path(reader.recorded(reader.leaf / 'products' / suite)),
            Path(reader.recorded(reader.leaf / 'evidence' / suite)), Path(reader.recorded(reader.leaf / 'runtime' / suite)), 8)
        # The exact Python executable belongs to the pinned image, not to the
        # host running this read-only collector. Every remaining CC word is fixed.
        require(isinstance(command, list) and len(command) == len(expected), 'os-test Make command roster differs')
        actual_cc, expected_cc = shlex.split(command[5][3:]), shlex.split(expected[5][3:])
        require(command[5].startswith('CC=') and actual_cc[0] in ('/usr/bin/python3', '/usr/local/bin/python3'),
                'os-test adapter is not the pinned Python control plane')
        same(actual_cc[1:], expected_cc[1:], 'os-test source-bound adapter invocation')
        same(command[:5] + command[6:], expected[:5] + expected[6:], 'os-test frozen Make invocation')
    return raw


def _os_source(reader, report):
    stage = reader.leaf / 'source-stage'
    tree, files = source_tree(stage, ignore_git_metadata=True, allow_symlinks=True)
    same(tree, OS_TEST_TREE, 'complete pinned os-test Git tree')
    source = report['source']
    same([source['revision'], source['tree']], [OS_TEST_REVISION, OS_TEST_TREE], 'os-test upstream pin')
    same([source['gnu_makefile_sha256'], source['suite_list_sha256']],
         [digest(stage / 'GNUmakefile'), digest(stage / 'misc/suites.list')], 'os-test Make source bindings')
    staged = source['stage']
    same({key: staged[key] for key in ('stage', 'revision', 'tree', 'tracked_path_count')},
         {'stage': 'source-stage', 'revision': OS_TEST_REVISION, 'tree': OS_TEST_TREE, 'tracked_path_count': len(files)},
         'os-test pristine source stage')
    path = reader.leaf / 'records/source-roster.json'
    reader.relative_artifact(staged['roster'], path)
    roster = read_json(path)
    same([roster['schema'], roster['revision'], roster['tree']],
         ['crabc.x86_64-owned-os-test-source-roster/v1', OS_TEST_REVISION, OS_TEST_TREE], 'os-test source roster pin')
    require(sorted(entry['path'] for entry in roster['entries']) == sorted(files), 'os-test tracked source roster differs')
    for entry in roster['entries']:
        source_path = stage / entry['path']
        if source_path.is_symlink():
            target = os.readlink(source_path)
            same(entry, {'path': entry['path'], 'type': 'symlink', 'mode': source_path.lstat().st_mode & 0o7777,
                         'target': target, 'target_sha256': files[entry['path']], 'target_byte_length': len(os.fsencode(target))},
                 'os-test pristine source symlink')
            continue
        same({key: entry[key] for key in ('path', 'type', 'sha256', 'byte_length')},
             {'path': entry['path'], 'type': 'regular', 'sha256': files[entry['path']], 'byte_length': len(read_bytes(source_path))},
             'os-test pristine source file')
        require(type(entry['mode']) is int and entry['mode'] & ~0o222 == source_path.stat().st_mode & 0o7777,
                'os-test frozen source mode differs')
    return stage, files


def _os_basic_fixtures(reader, control, product, runtime, contract):
    """Admit basic's source-selected system files and explicit shell control."""
    files = {}
    for name, raw in contract.BASIC_SYSTEM_FILES.items():
        path = runtime / 'etc' / name
        require(read_bytes(path) == raw and path.stat().st_mode & 0o7777 == 0o644, 'os-test basic system file differs')
        files['/etc/' + name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'byte_length': len(raw)}
    require(physical(runtime / 'dev/shm', directory=True).stat().st_mode & 0o7777 == 0o1777, 'os-test basic shared-memory directory mode differs')
    same(control['basic_runtime_fixtures'], {'kind': 'basic-system-files', '/dev/shm': {'mode': 0o1777}, 'files': files},
         'os-test basic conventional system inputs')
    shell = control['shell_launcher']
    same(shell['kind'], 'candidate-shell-launcher/v1', 'os-test candidate-visible shell fixture')
    source, obj, binary = (runtime / 'control' / ('candidate-shell-launcher' + suffix) for suffix in ('.c', '.o', ''))
    receipt_path = Path(str(binary) + '.crabc-link.json')
    require(read_bytes(source) == contract.control_shell_launcher_source().encode(), 'os-test shell control source differs')
    for field, path in (('source', source), ('object', obj)):
        same(shell[field], {'path': '/control/' + path.name, 'sha256': digest(path)}, 'os-test shell fixture ' + field)
    driver = reader.recorded(product / 'bin/crabc-cc-dynamic')
    for phase, command in (('compile', [driver, '--dynamic-pie', '-c', reader.recorded(source), '-o', reader.recorded(obj)]),
                            ('link', [driver, '--dynamic-pie', reader.recorded(obj), '-o', reader.recorded(binary)])):
        same([shell[phase]['command'], shell[phase]['status']], [command, 0], 'os-test canonical shell fixture ' + phase)
        for stream in ('stdout', 'stderr'):
            _os_snapshot(shell[phase][stream])
    _os_sealed_link(reader, binary=binary, receipt_path=receipt_path, shared=False, output=reader.recorded(binary),
                    workload_path=reader.recorded(obj), link_identity=shell['link_identity'], retained_object=obj, product=product)
    same(shell['launcher'], {'path': '/control/candidate-shell-launcher', 'sha256': digest(binary),
         'receipt_sha256': digest(receipt_path), 'candidate_path': '/bin/sh', 'candidate_sha256': digest(runtime / 'bin/sh'),
         'argv': ['/control/ld-musl-x86_64.so.1', '/control/busybox', 'sh', '<original argv[1..]>']},
         'os-test installed candidate shell fixture')
    same(digest(runtime / 'bin/sh'), digest(binary), 'os-test executed shell launcher bytes')
    require(binary.stat().st_mode & 0o111 != 0 and (runtime / 'bin/sh').stat().st_mode & 0o7777 == binary.stat().st_mode & 0o7777,
            'os-test shell launcher executable modes differ')
    for field, path in (('busybox', 'control/busybox'), ('musl_control_loader', 'control/ld-musl-x86_64.so.1')):
        same(control[field]['sha256'], digest(runtime / path), 'os-test actual external shell control bytes')


def _os_private_proc(reader, suite, private, runtime, controls, contract):
    """Require basic's bounded procfs lifecycle before reading its runtime tree.

    A failed teardown can leave a live kernel filesystem below the retained
    execution root.  Validate the receipt first and refuse it before any
    roster or payload walk; after the successful unmount, the ordinary empty
    mountpoint is the only filesystem node that may be inspected.
    """
    if suite != 'basic':
        same(private, None, 'os-test unexpected private procfs fixture')
        return
    require(isinstance(private, dict), 'os-test basic suite lacks its private procfs fixture')
    keys(private, ('schema', 'mountpoint', 'reservation', 'mount', 'namespace', 'unmount'),
         'os-test private procfs receipt')
    target = runtime / 'proc'
    target_recorded = reader.recorded(target)
    same([private['schema'], private['mountpoint']], [contract.PRIVATE_PROC_SCHEMA, target_recorded],
         'os-test private procfs root binding')
    same(private['reservation'], {'empty': True, 'mode': 0o755}, 'os-test private procfs pre-snapshot reservation')

    mount = private['mount']
    keys(mount, ('command', 'status', 'stdout', 'stderr', 'target'), 'os-test private procfs mount')
    same([mount['command'], mount['target'], mount['status']],
         [[contract.PRIVATE_PROC_MOUNT, '-t', 'proc', '-o', contract.PRIVATE_PROC_MOUNT_OPTIONS,
           'proc', target_recorded], target_recorded, 0], 'os-test private procfs mount command')
    _os_snapshot(mount['stdout'], b'')
    _os_snapshot(mount['stderr'], b'')

    namespace = private['namespace']
    keys(namespace, ('outside', 'inside', 'matched'), 'os-test private procfs namespace witness')
    outside = namespace['outside']
    require(type(outside) is str and re.fullmatch(r'pid:\[[0-9]+\]', outside) is not None,
            'os-test private procfs outside PID namespace is malformed')
    inside = namespace['inside']
    keys(inside, ('command', 'status', 'stdout', 'stderr'), 'os-test private procfs inside PID namespace witness')
    same([inside['command'], inside['status'], namespace['matched']],
         [[contract.PRIVATE_PROC_WITNESS_CHROOT, reader.recorded(runtime),
           '/control/ld-musl-x86_64.so.1', '/control/busybox', 'readlink', '/proc/self/ns/pid'], 0, True],
         'os-test private procfs same-container PID namespace witness')
    _os_snapshot(inside['stdout'], (outside + '\n').encode())
    _os_snapshot(inside['stderr'], b'')

    unmount = private['unmount']
    keys(unmount, ('command', 'status', 'stdout', 'stderr'), 'os-test private procfs unmount')
    same([unmount['command'], unmount['status']], [[contract.PRIVATE_PROC_UNMOUNT, target_recorded], 0],
         'os-test private procfs unmount command')
    _os_snapshot(unmount['stdout'], b'')
    _os_snapshot(unmount['stderr'], b'')

    additions = read_json(controls)
    keys(additions, ('schema', 'entries'), 'os-test execution control additions')
    same(additions['schema'], 'crabc.x86_64-owned-os-test-execution-controls/v1',
         'os-test execution control additions schema')
    require(isinstance(additions['entries'], list), 'os-test execution control additions are malformed')
    proc_entries = [entry for entry in additions['entries'] if isinstance(entry, dict) and entry.get('path') == 'proc']
    same(proc_entries, [{'path': 'proc', 'type': 'directory', 'mode': 0o755}],
         'os-test private procfs pre-mount control roster')
    require(not any(isinstance(entry, dict) and isinstance(entry.get('path'), str) and entry['path'].startswith('proc/')
                    for entry in additions['entries']), 'os-test private procfs control roster includes mounted content')
    mounted = physical(target, directory=True)
    same(mounted.stat().st_mode & 0o7777, 0o755, 'os-test private procfs mountpoint mode after unmount')
    exact_files(mounted, (), 'os-test private procfs mountpoint after unmount')


def _os_product_copy(reader, suite, control, baseline, contract):
    empty = {'missing': [], 'unexpected': [], 'changed': []}
    compile_product = reader.leaf / 'products' / suite
    runtime = reader.leaf / 'runtime' / suite
    same(control['compiler_product']['root'], reader.recorded(compile_product), 'os-test compiler product copy root')
    same(control['compiler_product']['copy_difference'], empty, 'os-test compiler product copy equality')
    compiler_payload = reader.leaf / 'records' / (suite + '.compiler-product-payload.json')
    reader.relative_artifact(control['compiler_product']['payload'], compiler_payload)
    same(read_json(compiler_payload), {'schema': 'crabc.x86_64-owned-os-test-product-payload/v1',
                                       'phase': 'compiler-and-linker', 'entries': baseline},
         'os-test recorded compiler product payload')
    same(contract.tree_roster(compile_product), baseline, 'os-test source-bound compiler product payload')
    for root, identity in ((compile_product, control['compiler_product']['identity']), (runtime, control['product'])):
        same(identity, {'root': reader.recorded(root), 'manifest': reader.recorded(root / 'share/crabc/manifest.json'),
                        'manifest_sha256': digest(reader.manifest), 'driver': reader.recorded(root / 'bin/crabc-cc-dynamic'),
                        'driver_sha256': digest(reader.product / 'bin/crabc-cc-dynamic')}, 'os-test copied product identity')
    same(control['root'], reader.recorded(runtime), 'os-test runtime root')
    same(control['product_copy_difference'], empty, 'os-test runtime product copy equality')
    same(control['product_manifest_sha256'], digest(reader.manifest), 'os-test runtime product manifest')
    same(control['candidate_loader_sha256'], digest(reader.product / 'lib/ld-crabc-x86_64.so.1'), 'os-test runtime loader binding')
    controls = reader.leaf / 'records' / (suite + '.execution-control-additions.json')
    reader.relative_artifact(control['control_additions'], controls)
    _os_private_proc(reader, suite, control['private_proc'], runtime, controls, contract)
    require('setup_error' not in control and control.get('setup_status') != 'ERROR', 'os-test execution fixture failed')
    integrity = control['product_payload']
    same([integrity['passed'], integrity['difference']], [True, empty], 'os-test product integrity result')
    for phase in ('before', 'after'):
        path = reader.leaf / 'records' / (suite + '.dynamic-product-payload-' + phase + '.json')
        reader.relative_artifact(integrity[phase], path)
        same(read_json(path), {'schema': 'crabc.x86_64-owned-os-test-product-payload/v1',
                              'phase': phase + '-execution', 'entries': baseline}, 'os-test retained product payload')
    # Project product directories without following aliases or reading the
    # fixture character devices. Basic adds one proven /bin/sh within bin;
    # no other extra product-directory entry is admitted.
    if suite == 'basic':
        require(all(entry['path'] != 'bin/sh' for entry in baseline), 'os-test shell fixture collides with supplied product')
        _os_basic_fixtures(reader, control, compile_product, runtime, contract)
    else:
        same([control['basic_runtime_fixtures'], control['shell_launcher']], [None, None], 'os-test unexpected basic fixture')
    projected = [contract.roster_entry(runtime, Path('.'))] if any(entry['path'] == '.' for entry in baseline) else []
    for top in sorted({Path(entry['path']).parts[0] for entry in baseline if Path(entry['path']).parts}):
        projected.append(contract.roster_entry(runtime, Path(top)))
        projected += [{**entry, 'path': top + '/' + entry['path']} for entry in contract.tree_roster(runtime / top) if entry['path'] != '.']
    if suite == 'basic':
        projected = [entry for entry in projected if entry['path'] != 'bin/sh']
    same(sorted(projected, key=lambda entry: entry['path']), baseline, 'os-test actual runtime product payload')
    private = control['private_devpts']
    if suite in ('basic', 'pty'):
        require(isinstance(private, dict), 'os-test suite lacks its private devpts fixture')
        same([private['status'], private['unmount']['status']], [0, 0], 'os-test private devpts lifecycle')
    else:
        same(private, None, 'os-test unexpected devpts fixture')


def _os_test(reader):
    import owned_os_test as contract
    leaf = reader.leaf
    report = read_json(leaf / 'os-test.json')
    profiled = reader.profile_companions is not None
    dispositions = []
    same([report['schema'], report['passed'], report['profile'], report['timeout_seconds'], report['work']],
         ['crabc.x86_64-owned-os-test/v1', not profiled, list(OS_TEST_SUITES), 600.0, reader.recorded(leaf)], 'complete os-test campaign')
    require([suite['suite'] for suite in report['suites']] == list(OS_TEST_SUITES), 'os-test full suite roster differs')
    stage, files = _os_source(reader, report)
    product = report['product']
    same({key: product[key] for key in ('root', 'manifest', 'manifest_sha256', 'driver', 'driver_sha256')},
         {'root': reader.recorded(reader.product), 'manifest': reader.recorded(reader.manifest), 'manifest_sha256': digest(reader.manifest),
          'driver': reader.recorded(reader.product / 'bin/crabc-cc-dynamic'), 'driver_sha256': digest(reader.product / 'bin/crabc-cc-dynamic')},
         'os-test supplied product identity')
    product_roster_path = leaf / 'records/supplied-product-roster.json'
    reader.relative_artifact(product['payload_roster'], product_roster_path)
    product_roster = read_json(product_roster_path)
    same(product_roster, {'schema': 'crabc.x86_64-owned-os-test-product-roster/v1', 'entries': contract.tree_roster(reader.product)},
         'os-test full supplied product payload')
    observations, objects, commands = {}, {}, {}
    for suite in report['suites']:
        name = suite['suite']
        profiled_suite = profiled and name in ('basic', 'include')
        expected_differences = []
        if not profiled_suite:
            same([suite['passed'], suite['differences'], suite['difference_count']], [True, [], 0], 'os-test suite comparison')
        expected = sorted(Path(path).relative_to(name).with_suffix('.out').as_posix() for path in files
                          if Path(path).is_relative_to(name) and path.endswith('.c'))
        require(expected, 'os-test pinned suite has no source outcomes')
        expected_path = leaf / 'records' / (name + '.expected-outcomes.json')
        reader.relative_artifact(suite['expected_outcomes'], expected_path)
        same(read_json(expected_path), {'schema': 'crabc.x86_64-owned-os-test-expected-outcomes/v1', 'suite': name, 'outcomes': expected},
             'os-test complete source-derived outcome roster')
        commands[name] = {}
        for side in ('musl', 'dynamic'):
            result = suite[side]
            same([result['passed'], result['outcome_count']], [True, len(expected)], 'os-test side result')
            require(set(result['outcomes']) == set(expected), 'os-test side omitted or added a source outcome')
            commands[name][side] = _os_make(reader, name, side, result if side == 'musl' else result['make'], 600.0, contract)
            root = leaf / ('musl' if side == 'musl' else 'suites') / name
            outcomes = root / 'out/linux' / name
            actual = {path.relative_to(outcomes).as_posix() for path in outcomes.rglob('*.out')}
            same(actual == set(expected), True, 'os-test physical outcome roster')
            # Make creates binaries and reports beside the tracked C inputs;
            # every tracked source byte must still equal its pristine stage.
            for relative, expected_hash in files.items():
                if (stage / relative).is_symlink():
                    require((root / relative).is_symlink(), 'os-test copied source symlink changed type')
                    same(hashlib.sha256(os.fsencode(os.readlink(root / relative))).hexdigest(), expected_hash, 'os-test copied source symlink')
                else:
                    same(digest(root / relative), expected_hash, 'os-test copied source graph')
            for relative in expected:
                path = outcomes / relative
                raw = read_bytes(path)
                same(result['outcomes'][relative], {'sha256': hashlib.sha256(raw).hexdigest(), 'text': raw.decode('utf-8', errors='replace')},
                     'os-test raw outcome binding')
                observations.setdefault(name + '/' + relative, {})[side] = reader.identity(path, raw=True)
        for relative in expected:
            row = observations[name + '/' + relative]
            if profiled and ((name == 'basic' and relative in ('unistd/seteuid.out', 'unistd/setegid.out',
                'unistd/setreuid.out', 'unistd/setregid.out')) or (name == 'include' and relative in
                ('stdatomic/atomic_flag_clear.out', 'stdatomic/atomic_flag_clear_explicit.out',
                 'stdatomic/atomic_flag_test_and_set.out', 'stdatomic/atomic_flag_test_and_set_explicit.out',
                 'stdatomic/atomic_signal_fence.out', 'stdatomic/atomic_thread_fence.out'))):
                import owned_posix_native_dispositions as profile_contract
                source = stage / name / Path(relative).with_suffix('.c')
                dispositions.append(profile_contract.os_disposition(reader, name, relative, source,
                    base64.b64decode(row['dynamic']['base64']), base64.b64decode(row['musl']['base64']),
                    {'credentials': reader.profile_companions['credentials'],
                     'atomic': reader.profile_companions['atomic']}))
                expected_differences.append({'case': relative, 'dynamic': suite['dynamic']['outcomes'][relative],
                                             'musl': suite['musl']['outcomes'][relative]})
            else:
                same(row['musl']['base64'], row['dynamic']['base64'], 'os-test exact raw outcome comparison')
        if profiled_suite:
            same([suite['passed'], suite['differences'], suite['difference_count']],
                 [False, expected_differences, 4 if name == 'basic' else 6],
                 'os-test exact selected profile differences')
        objects.update(_os_event_graph(reader, name, expected, suite['dynamic'], files, contract))
        _os_product_copy(reader, name, suite['dynamic']['execution_control'], product_roster['entries'], contract)
    oracle = report['musl_oracle']
    same(oracle['unchanged'], True, 'os-test pinned musl oracle stability')
    same(contract.same_musl_oracle(oracle['before'], oracle['after']), True, 'os-test before/after musl oracle')
    for phase in ('before', 'after'):
        identity = oracle[phase]
        same(identity['root'], '/opt/musl-1.2.6', 'os-test pinned musl root')
        for field, path in {'wrapper': '/usr/local/bin/crabc-x86_64-musl-gcc', 'marker': '/opt/musl-1.2.6/.crabc-oracle',
                            'specs_digest': '/opt/musl-1.2.6/.crabc-musl-gcc-specs.sha256', 'specs': '/opt/musl-1.2.6/lib/musl-gcc.specs',
                            'libc': '/opt/musl-1.2.6/lib/libc.so'}.items():
            keys(identity[field], ('path', 'sha256'), 'os-test pinned musl input')
            same(identity[field]['path'], path, 'os-test pinned musl input path')
            require(isinstance(identity[field]['sha256'], str) and re.fullmatch('[0-9a-f]{64}', identity[field]['sha256']) is not None,
                    'os-test pinned musl input digest is malformed')
        artifact = identity['include']['roster']
        path = leaf / 'records' / ('musl-oracle-' + phase + '-include-roster.json')
        reader.relative_artifact(artifact, path)
        roster = read_json(path)
        same([roster['schema'], identity['include']['path'], identity['include']['entry_count']],
             ['crabc.x86_64-owned-os-test-musl-include-roster/v1', '/opt/musl-1.2.6/include', len(roster['entries'])],
             'os-test pinned musl header roster')
    require(not profiled or len(dispositions) == 10, 'os-test fixed profile dispositions are missing')
    return reader.finish('os-test', 'os-test.json', observations, objects, suite_commands=commands,
        qualification={'status': 'profile-qualified' if profiled else 'passed', 'raw_passed': not profiled,
                       'dispositions': dispositions},
        source_tree={'revision': OS_TEST_REVISION, 'tree': OS_TEST_TREE, 'files': files},
        oracle_inputs=oracle, limits={'suite_timeout_seconds': 600.0, 'header_jobs': 8})
