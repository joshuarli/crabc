"""Finite accounting for reviewed upstream functional/wordexp diagnostics.

The pinned libc-test unit remains a raw failure for both the selected product
and pinned musl. This module names the twenty reviewed candidate diagnostics,
the complete pinned-musl diagnostic trace, and the independently validated
same-product public-C companion. It never turns either raw failure into an
upstream pass or a generic matched-failure rule.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import owned_posix_native_observations as native
import owned_wordexp_evidence as wordexp


SCHEMA = 'crabc.x86_64-owned-wordexp-upstream-policy/v1'
UPSTREAM_SOURCE = 'source-prepared/src/functional/wordexp.c'
UPSTREAM_SOURCE_SHA256 = 'e3e310de1a73bc30273ac5f4711492817a2f26a5750795c9a3f0be42645871c9'
REFERENCE = 'compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json'
REFERENCE_SHA256 = '4a18984a01a412185a2e605f1b8964312dd07edefd5522273a0522c89ffb9372'
REFERENCE_SCHEMA = 'crabc.x86_64-wordexp-upstream-diagnostics/v1'
REFERENCE_MEASUREMENT = '96a4a847'
SOURCE_POLICY_PROBE = 'compat/x86_64/owned_wordexp_source_policy_probe.c'
SOURCE_POLICY_CASE = 'source-policy'
SOURCES = ('compat/x86_64/owned_wordexp_upstream_policy.py', REFERENCE)
DYNAMIC_MODES = (
    'dynamic-pie-kernel',
    'dynamic-pie-direct',
    'dynamic-non-pie-kernel',
    'dynamic-non-pie-direct',
)


# This is the public-C candidate policy, independently fixed here rather than
# reconstructed from a retained report. stderrhex describes the captured
# wordexp diagnostic; process stderr remains empty for both sides.
_CANDIDATE_ROWS = (
    (0, 0, '-'), (2, 0, '-'), (2, 0, '-'), (2, 0, '-'), (2, 0, '-'),
    (5, 0, '-'), (5, 0, '-'), (5, 0, '-'), (2, 0, '-'),
    (0, 1, '9:230a6563686f20785c'), (5, 0, '-'), (2, 0, '-'),
    (0, 1, '0:'), (4, 0, '-'), (4, 0, '-'), (0, 2, '1:31,1:31'),
    (2, 0, '-'), (2, 0, '-'), (2, 0, '-'), (2, 0, '-'),
)

# The fixed musl C-companion transcript is retained as an observation. It
# demonstrates why matching or alternate shell behavior cannot waive the
# twenty candidate obligations.
_ORACLE_ROWS = (
    (0, 1, '1:32', '-', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520303a2073796e746178206572726f723a20756e6578706563746564202229220a', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520303a2073796e746178206572726f723a20756e6578706563746564202228220a', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520303a2073796e746178206572726f723a20756e6578706563746564202229220a', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520303a2073796e746178206572726f723a20756e6578706563746564202228220a', 0),
    (4, 0, '-', '-', 0), (4, 0, '-', '-', 0), (4, 0, '-', '-', 0),
    (2, 0, '-', '-', 0), (0, 1, '3:78270a', '-', 0), (4, 0, '-', '-', 0),
    (0, 1, '5:247b41427d', '-', 0), (2, 0, '-', '-', 0), (4, 0, '-', '-', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520303a2061726974686d657469632073796e746178206572726f720a', 1),
    (2, 0, '-', '-', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520313a2073796e746178206572726f723a206d697373696e6720272929270a', 0),
    (5, 0, '-', '73683a206576616c3a206c696e6520323a2073796e746178206572726f723a206d697373696e6720272929270a', 0),
    (2, 0, '-', '-', 0), (2, 0, '-', '-', 0),
)


def _render_rows(rows):
    return ''.join(
        f'owned-wordexp-source-policy: case={index:02d} status={status} count={count} '
        f'wordhex={wordhex} stderrhex={stderrhex} effect={effect} env=0\n'
        for index, (status, count, wordhex, stderrhex, effect) in enumerate(rows, 1)
    ).encode()


def candidate_trace():
    """The fixed selected-product trace for the twenty reviewed records."""
    return _render_rows(tuple((*row, '-', 0) for row in _CANDIDATE_ROWS))


def oracle_trace():
    """The fixed musl observation for the same public-C companion."""
    return _render_rows(_ORACLE_ROWS)


def _reference(root):
    path = native.physical(root / REFERENCE)
    native.require(native.digest(path) == REFERENCE_SHA256, 'wordexp diagnostic reference bytes differ')
    value = native.read_json(path)
    native.keys(value, ('measurement_source_revision', 'schema', 'sides', 'source_sha256', 'terminal'),
                'wordexp diagnostic reference')
    native.same([value['measurement_source_revision'], value['schema'], value['source_sha256'], value['terminal']],
                [REFERENCE_MEASUREMENT, REFERENCE_SCHEMA, UPSTREAM_SOURCE_SHA256,
                 'FAIL /functional/wordexp [status 1]\n'], 'wordexp diagnostic reference contract')
    native.keys(value['sides'], ('candidate', 'oracle'), 'wordexp diagnostic reference sides')
    for side, count in (('candidate', 20), ('oracle', 104)):
        item = value['sides'][side]
        native.keys(item, ('diagnostics', 'status', 'stderr'), 'wordexp diagnostic reference side')
        native.require(isinstance(item['diagnostics'], list) and len(item['diagnostics']) == count,
                       'wordexp diagnostic reference count differs')
        native.same([item['status'], item['stderr']], [1, ''], 'wordexp diagnostic reference raw status')
        for row in item['diagnostics']:
            native.keys(row, ('diagnostic', 'line'), 'wordexp diagnostic record')
            native.require(type(row['line']) is int and row['line'] > 0 and isinstance(row['diagnostic'], str),
                           'wordexp diagnostic record fields differ')
    return value


def _upstream_trace(reader, source, reference, side):
    item = reference['sides'][side]
    prefix = (reader.recorded(source) + ':').encode()
    rows = b''.join(
        prefix + str(row['line']).encode() + b': ' + row['diagnostic'].encode()
        for row in item['diagnostics']
    )
    return rows + reference['terminal'].encode()


def upstream_disposition(reader, source, *, candidate_status, candidate_stdout, candidate_stderr,
                         oracle_status, oracle_stdout, oracle_stderr, companion):
    """Qualify exactly the selected raw failures after a full companion proof."""
    expected_source = reader.leaf / UPSTREAM_SOURCE
    native.require(source == expected_source, 'wordexp disposition source path differs')
    native.require(hashlib.sha256(native.read_bytes(source)).hexdigest() == UPSTREAM_SOURCE_SHA256,
                   'wordexp upstream source differs')
    reference = _reference(reader.root)
    native.keys(companion, ('receipt', 'expected_native_inputs', 'product', 'selected_dynamic_entries',
                            'source_policy_probe', 'diagnostic_reference'), 'wordexp companion proof')
    native.require(set(companion['selected_dynamic_entries']) == set(DYNAMIC_MODES),
                   'wordexp companion dynamic mode roster differs')
    native.same([candidate_status, oracle_status],
                [reference['sides']['candidate']['status'], reference['sides']['oracle']['status']],
                'wordexp original raw exit statuses')
    native.require(candidate_stderr == b'' and oracle_stderr == b'',
                   'wordexp original raw stderr differs')
    native.require(candidate_stdout == _upstream_trace(reader, source, reference, 'candidate') and
                   oracle_stdout == _upstream_trace(reader, source, reference, 'oracle'),
                   'wordexp original diagnostics differ from the fixed source policy')
    return {
        'schema': SCHEMA,
        'unit': 'functional/wordexp',
        'status': 'posix-policy-qualified',
        'basis': 'pinned-source-posix-policy',
        'raw_passed': False,
        'source': reader.identity(source),
        'diagnostic_reference': reader.identity(reader.root / REFERENCE, source=True),
        'candidate_diagnostic_count': len(reference['sides']['candidate']['diagnostics']),
        'oracle_diagnostic_count': len(reference['sides']['oracle']['diagnostics']),
        'companion': companion['receipt'],
        'expected_native_inputs': companion['expected_native_inputs'],
        'product': companion['product'],
        'source_policy_probe': companion['source_policy_probe'],
        'selected_dynamic_entries': companion['selected_dynamic_entries'],
    }


def _mounted_identity(root, mount, value, description):
    native.keys(value, ('path', 'sha256', 'mode'), description)
    native.require(isinstance(value['path'], str) and value['path'].startswith(mount + '/'),
                   description + ' path differs')
    relative = Path(value['path']).relative_to(mount)
    native.require(relative.parts and '..' not in relative.parts, description + ' path is unsafe')
    path = native.physical(root / relative)
    native.same(value, {'path': value['path'], 'sha256': native.digest(path), 'mode': path.stat().st_mode & 0o7777},
                description + ' identity')
    return path


def _same_product(root, report, product):
    mount = report.get('source_mount')
    native.require(isinstance(mount, str) and Path(mount).is_absolute() and '..' not in Path(mount).parts,
                   'wordexp report source mount differs')
    native.require(mount == wordexp.SOURCE_MOUNT, 'wordexp report source mount differs')
    inputs = report.get('inputs')
    native.require(isinstance(inputs, dict) and set(inputs) == {'before', 'after', 'built_products'},
                   'wordexp report input seals differ')
    before, after = inputs['before'], inputs['after']
    native.require(isinstance(before, dict) and isinstance(after, dict), 'wordexp report input seals are malformed')
    products = before.get('products')
    native.require(isinstance(products, dict) and set(products) == {'dynamic', 'static'},
                   'wordexp report product seal differs')
    dynamic = products['dynamic']
    native.require(isinstance(dynamic, dict) and set(dynamic) == {'root', 'manifest', 'files'},
                   'wordexp report dynamic product differs')
    try:
        product_relative = product.relative_to(root)
    except ValueError as error:
        raise native.NativeObservationError('wordexp companion product escapes checkout') from error
    expected_root = mount + '/' + product_relative.as_posix()
    native.same(dynamic['root'], expected_root, 'wordexp companion selected product')
    manifest = _mounted_identity(root, mount, dynamic['manifest'], 'wordexp companion selected manifest')
    native.require(manifest == product / 'share/crabc/manifest.json', 'wordexp companion manifest path differs')
    native.same(after.get('products', {}).get('dynamic'), dynamic, 'wordexp companion product seals differ')
    return {'path': product_relative.as_posix(), 'manifest': {'path': dynamic['manifest']['path'],
            'sha256': dynamic['manifest']['sha256'], 'mode': dynamic['manifest']['mode']}}


def _source_policy_probe(root, report):
    mount = report['source_mount']
    sources = report['inputs']['before'].get('sources')
    native.require(isinstance(sources, dict) and SOURCE_POLICY_PROBE in sources,
                   'wordexp full receipt omits the source-policy probe')
    path = _mounted_identity(root, mount, sources[SOURCE_POLICY_PROBE], 'wordexp source-policy probe')
    native.require(path == root / SOURCE_POLICY_PROBE, 'wordexp source-policy probe path differs')
    return {'path': SOURCE_POLICY_PROBE, 'sha256': native.digest(path), 'mode': path.stat().st_mode & 0o7777}


def _cell_streams(root, mount, cell, side, mode):
    native.require(isinstance(cell, dict) and cell.get('mode') == mode and cell.get('case') == SOURCE_POLICY_CASE,
                   'wordexp source-policy cell role differs')
    command = cell.get(side)
    native.require(isinstance(command, dict), 'wordexp source-policy cell lacks ' + side)
    return {stream: _mounted_identity(root, mount, command.get(stream), f'wordexp {mode} {side} {stream}')
            for stream in ('status', 'stdout', 'stderr')}


def _source_policy_cells(root, report):
    mount = report['source_mount']
    cells = report.get('cells')
    native.require(isinstance(cells, dict), 'wordexp report cell map differs')
    result = {}
    for mode in DYNAMIC_MODES:
        label = mode + '-' + SOURCE_POLICY_CASE
        native.require(label in cells, 'wordexp source-policy dynamic cell is missing')
        candidate = _cell_streams(root, mount, cells[label], 'candidate', mode)
        oracle = _cell_streams(root, mount, cells[label], 'oracle', mode)
        native.require([native.read_bytes(candidate['status']), native.read_bytes(candidate['stdout']),
                        native.read_bytes(candidate['stderr'])] == [b'0\n', candidate_trace(), b''],
                       'wordexp source-policy candidate trace differs')
        native.require([native.read_bytes(oracle['status']), native.read_bytes(oracle['stdout']),
                        native.read_bytes(oracle['stderr'])] == [b'0\n', oracle_trace(), b''],
                       'wordexp source-policy pinned-musl trace differs')
        result[mode] = {
            'candidate': {name: {'path': path.relative_to(root).as_posix(), 'sha256': native.digest(path)}
                          for name, path in candidate.items()},
            'oracle': {name: {'path': path.relative_to(root).as_posix(), 'sha256': native.digest(path)}
                       for name, path in oracle.items()},
        }
    return result


def validate_companion(root, report_path, expected_native_inputs, product):
    """Validate the whole wordexp receipt before exposing its finite companion."""
    root = native.physical(root, directory=True)
    report_path = native.physical(report_path)
    expected_native_inputs = native.physical(expected_native_inputs)
    product = native.physical(product, directory=True)
    expected = native.read_json(expected_native_inputs)
    try:
        report = wordexp.validate_report(root, report_path, expected)
    except wordexp.EvidenceError as error:
        raise native.NativeObservationError('wordexp full receipt rejected: ' + str(error)) from error
    product_identity = _same_product(root, report, product)
    probe = _source_policy_probe(root, report)
    cells = _source_policy_cells(root, report)
    reference = root / REFERENCE
    _reference(root)
    return {
        'product': product_identity,
        'source_policy_probe': probe,
        'diagnostic_reference': {'path': REFERENCE, 'sha256': native.digest(reference)},
        'selected_dynamic_entries': cells,
    }
