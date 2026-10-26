"""Finite source-bound pinned-musl defects corrected by the native candidate.

The complete pinned libc-test graph, exact test sources and diagnostic
headers, and checked production correction sources must agree. Candidate
success and the finite pow raw discrepancy retain distinct dispositions.
Every other mismatched libc-test unit remains a raw failure.
"""
from __future__ import annotations

from pathlib import Path
import tomllib

import verify_math_scalar_corrections as exact

import owned_posix_native_observations as native

SCHEMA = 'crabc.x86_64-math-oracle-defects/v1'
MUSL_REVISION = '7813e9119eb5fe681b6750b8a033a0490bca0941'
MUSL_ARCHIVE_SHA256 = '8c16adf94bfd61358cf884353a4c0b71837ed792e7b7f056c86354436cf05bdb'
MUSL_TREE_SHA256 = '25147f955c696eba8881eb347e5a44ff47e7f91ccc30f9e6dada0188a28600cf'

PROOF_SOURCES = (
    'compat/upstreams.toml',
    'compat/x86_64/math-scalar-corrections.md',
    'compat/x86_64/math_scalar_corrections.py',
    'compat/x86_64/math_pow_identity110_probe.c',
    'compat/x86_64/math_pow_identity110_boundary.rs',
    'compat/x86_64/math_pow_identity110_start.S',
    'compat/x86_64/run_math_pow_identity110.sh',
    'compat/x86_64/run_math_scalar_corrections_libc_test.py',
    'compat/x86_64/math_scalar_corrections_probe.c',
    'compat/x86_64/generate_libc_math_scalar_completion.py',
    'compat/x86_64/generate_libc_math_elementary_long_double.py',
    'compat/x86_64/generate_libc_math_pow.py',
    'compat/x86_64/generate_libc_math_special.py',
    'compat/x86_64/run_math_scalar_corrections.sh',
    'compat/x86_64/run_musl_oracle.sh',
    'compat/x86_64/musl_oracle.py',
    'compat/x86_64/verify_math_scalar_corrections.py',
    'compat/x86_64/verify_math_pow_records.py',
    'compat/x86_64/math_scalar_corrections_boundary.rs',
    'compat/x86_64/math_scalar_corrections_stream.c',
    'compat/x86_64/math_scalar_corrections_start.S',
    'compat/x86_64/owned_static_math_scalar_consumer.c',
    'compat/x86_64/owned_static_math_scalar_consumer_start.S',
    'compat/x86_64/owned_static_math_binary80_consumer.c',
    'compat/x86_64/owned_static_math_binary80_consumer_start.S',
    'compat/x86_64/libc_math_pow_probe.c',
    'compat/x86_64/libc_math_pow_start.S',
    'compat/x86_64/libc_math_elementary_long_double_probe.c',
    'compat/x86_64/libc_math_elementary_long_double_start.S',
    'compat/x86_64/libc_math_special_probe.c',
    'compat/x86_64/libc_math_special_start.S',
    'libc/src/c_abi/x86_64/math_scalar_completion.rs',
    'libc/src/c_abi/x86_64/math_elementary_long_double.rs',
    'libc/src/c_abi/x86_64/math_pow.rs',
    'libc/src/c_abi/x86_64/math_special.rs',
    'libc/src/c_abi/x86_64/math_complex.rs',
    'libc/src/c_abi/x86_64/math_x87_extended.rs',
    'libc/src/c_abi/x86_64/fenv.rs',
    'libc/src/c_abi/x86_64/elementary_sqrt.rs',
    'libc/src/c_abi/x86_64/fenv_rounding.rs',
    'libc/src/c_abi/x86_64/math_scalar_completion_musl_x86_64.S',
    'libc/src/c_abi/x86_64/math_elementary_long_double_musl_x86_64.S',
    'libc/src/c_abi/x86_64/math_pow_musl_x86_64.S',
    'libc/src/c_abi/x86_64/math_special_musl_x86_64.S',
)

ORACLE_DEFECTS = {
    'math/fmal': {
        'source': 'src/math/fmal.c',
        'source_sha256': 'd061e49f12822c9adba55a05dcc14bae235258f6584d9251c0f673b719c96a7d',
        'headers': {'src/math/special/fmal.h': 'c18845e8a5b5e79dd721ef2b91b496b521afa74131feadf40524774034f80c00'},
        'algorithm': 'binary80-unbounded-precision-tininess',
        'diagnostics': (
            ('src/math/special/fmal.h', 46, '',
             'bad fp exception: RN fmal(-0x1p-10000,0x1.0000000000001p-6445,0x1p-16382)=0x1.fffffffffffffffcp-16383, want INEXACT|UNDERFLOW got INEXACT'),
        ),
    },
    'math/powf': {
        'source': 'src/math/powf.c',
        'source_sha256': 'bc1d46abbe248da44373bba8d88e0f8075d722ac8ec2a4ce394712cbd7f61183',
        'headers': {'src/math/ucb/powf.h': '8a5efb4f1a074125b0b9a651663db136221e224f9254a2cb9f9400db9e83b4c8'},
        'algorithm': 'finite-binary32-identity',
        'diagnostics': (
            ('src/math/ucb/powf.h', 103, '',
             'bad fp exception: RU powf(0x1.fffffep+127,0x1p+0)=0x1.fffffep+127, want 0 got INEXACT|OVERFLOW'),
            ('src/math/ucb/powf.h', 530, 'X ',
             'bad fp exception: RN powf(0x1.fffff8p-127,0x1p+0)=0x1.fffff8p-127, want 0 got INEXACT|UNDERFLOW'),
            ('src/math/ucb/powf.h', 533, 'X ',
             'bad fp exception: RN powf(0x1.fffffcp-127,0x1p+0)=0x1.fffffcp-127, want 0 got INEXACT|UNDERFLOW'),
            ('src/math/ucb/powf.h', 719, 'X ',
             'bad fp exception: RN powf(-0x1.fffff8p-127,0x1p+0)=-0x1.fffff8p-127, want 0 got INEXACT|UNDERFLOW'),
            ('src/math/ucb/powf.h', 722, 'X ',
             'bad fp exception: RN powf(-0x1.fffffcp-127,0x1p+0)=-0x1.fffffcp-127, want 0 got INEXACT|UNDERFLOW'),
        ),
    },
}


def _require_bytes(value, expected, description):
    native.require(type(value) is bytes and value == expected, description)


def expected_oracle_stdout(unit, prepared_root):
    """Construct the exact pinned-libc-test stream for one named defect."""
    definition = ORACLE_DEFECTS[unit]
    root = Path(prepared_root)
    lines = []
    for header, line, prefix, message in definition['diagnostics']:
        lines.append(f'{prefix}{root / header}:{line}: {message}\n')
    lines.append(f'FAIL /{unit} [status 1]\n')
    return ''.join(lines).encode('ascii')


def proof_sources(root):
    """Bind the provenance and correction algorithm before admitting a defect."""
    root = Path(root)
    sources = {}
    for relative in PROOF_SOURCES:
        sources[relative] = {'path': relative, 'sha256': native.digest(root / relative)}
    pins = tomllib.loads(native.read_bytes(root / 'compat/upstreams.toml').decode('utf-8'))['musl_native']
    native.same({key: pins.get(key) for key in ('version', 'sha256', 'fallback_revision')},
                {'version': '1.2.6', 'sha256': MUSL_ARCHIVE_SHA256, 'fallback_revision': MUSL_REVISION},
                'math oracle-defect musl provenance')
    return sources


def oracle_defect_disposition(reader, source, *, unit, candidate_status, candidate_stdout, candidate_stderr,
                              oracle_status, oracle_stdout, oracle_stderr):
    """Record one candidate pass against a fixed pinned-musl oracle defect.

    This is not a waiver: source drift, another unit, candidate output, an
    oracle pass, changed diagnostics, failed links, or a failed runtime all
    remain invalid in the calling observer.
    """
    native.require(unit in ORACLE_DEFECTS, 'libc-test unit has no math oracle-defect disposition')
    definition = ORACLE_DEFECTS[unit]
    expected_source = reader.leaf / 'source-prepared' / definition['source']
    native.require(source == expected_source, 'math oracle-defect source path differs')
    native.require(native.digest(source) == definition['source_sha256'], 'math oracle-defect source differs')
    headers = {}
    prepared = reader.leaf / 'source-prepared'
    for relative, expected in definition['headers'].items():
        header = prepared / relative
        native.require(native.digest(header) == expected, 'math oracle-defect diagnostic header differs: ' + relative)
        headers[relative] = reader.identity(header)
    proofs = proof_sources(reader.root)
    native.require(type(candidate_status) is int and candidate_status == 0, 'math oracle-defect candidate exit status differs')
    _require_bytes(candidate_stdout, b'', 'math oracle-defect candidate stdout differs')
    _require_bytes(candidate_stderr, b'', 'math oracle-defect candidate stderr differs')
    native.require(type(oracle_status) is int and oracle_status == 1, 'math oracle-defect oracle exit status differs')
    _require_bytes(oracle_stdout, expected_oracle_stdout(unit, reader.recorded(prepared)),
                   'math oracle-defect exact oracle diagnostics differ')
    _require_bytes(oracle_stderr, b'', 'math oracle-defect oracle stderr differs')
    return {
        'schema': SCHEMA,
        'unit': unit,
        'status': 'candidate-passed-oracle-defect',
        'basis': 'pinned-musl-1.2.6-source-bound-defect',
        'raw_passed': False,
        'candidate': {'exit_status': 0, 'passed': True, 'stdout_empty': True, 'stderr_empty': True},
        'oracle': {'exit_status': 1, 'passed': False, 'stderr_empty': True,
                   'diagnostic_count': len(definition['diagnostics'])},
        'source': reader.identity(source),
        'headers': headers,
        'algorithm': definition['algorithm'],
        'libc_test': {'revision': native.LIBC_TEST_REVISION, 'tree': native.LIBC_TEST_TREE},
        'musl': {'revision': MUSL_REVISION, 'archive_sha256': MUSL_ARCHIVE_SHA256,
                 'normalized_source_tree_sha256': MUSL_TREE_SHA256},
        'proof_sources': proofs,
        'diagnostics': [
            {'header': header, 'line': line, 'prefix': prefix, 'message': message}
            for header, line, prefix, message in definition['diagnostics']
        ],
    }


POW_DEFECT = {
    'source': 'src/math/pow.c',
    'source_sha256': '6c4dc2812c42592cb8030532ded21908d685baa97df9967ef3c52cc3d12a68ab',
    'headers': {
        'src/math/crlibm/pow.h': '16172044a961cbc04cf59e34495955f9fd226036311edba52b422253e14fa3a7',
        'src/math/ucb/pow.h': '9fc49fb91af37ce0409b4e00bf9148218c905bc68f75cff8ff0aa62dd0fb130f',
        'src/math/sanity/pow.h': '5e05d64d8d5f462c5c25f5cd68ad14240854133cd38e02e64cbb28efc9ab1920',
        'src/math/special/pow.h': '2e2559d5d8dba0e7598989196e739041107497af4e7a91da95a3645748993044',
    },
}

POW_IDENTITIES = (
    (72, '0x1p-1074'),
    (73, '0x1p-1042'),
    (75, '-0x1p-1074'),
    (76, '-0x1p-1042'),
    (284, '0x1p-1073'),
    (300, '0x1p-1024'),
    (304, '0x1p-1023'),
    (310, '0x1.ffffffffffffcp-1023'),
    (313, '0x1.ffffffffffffep-1023'),
    (544, '-0x1p-1073'),
    (548, '-0x1p-1024'),
    (551, '-0x1p-1023'),
    (557, '-0x1.ffffffffffffcp-1023'),
    (560, '-0x1.ffffffffffffep-1023'),
)

POW_DIAGNOSTICS = (
    ('src/math/crlibm/pow.h', 13, 'bad fp exception: RN pow(0x1p+1,-0x1.0c8p+10)=0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 72, 'bad fp exception: RN pow(0x1p-1074,0x1p+0)=0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 73, 'bad fp exception: RN pow(0x1p-1042,0x1p+0)=0x1p-1042, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 75, 'bad fp exception: RN pow(-0x1p-1074,0x1p+0)=-0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 76, 'bad fp exception: RN pow(-0x1p-1042,0x1p+0)=-0x1p-1042, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 284, 'bad fp exception: RN pow(0x1p-1073,0x1p+0)=0x1p-1073, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 300, 'bad fp exception: RN pow(0x1p-1024,0x1p+0)=0x1p-1024, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 304, 'bad fp exception: RN pow(0x1p-1023,0x1p+0)=0x1p-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 310, 'bad fp exception: RN pow(0x1.ffffffffffffcp-1023,0x1p+0)=0x1.ffffffffffffcp-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 313, 'bad fp exception: RN pow(0x1.ffffffffffffep-1023,0x1p+0)=0x1.ffffffffffffep-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 338, 'bad fp exception: RN pow(0x1p-537,0x1p+1)=0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 437, 'bad fp exception: RN pow(0x1p+1,-0x1.0c8p+10)=0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 498, 'bad fp exception: RN pow(0x1p+350,-0x1.8p+1)=0x1p-1050, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 499, 'bad fp exception: RN pow(0x1p+700,-0x1.8p+0)=0x1p-1050, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 516, 'bad fp exception: RN pow(0x1p+1023,-0x1p+0)=0x1p-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 544, 'bad fp exception: RN pow(-0x1p-1073,0x1p+0)=-0x1p-1073, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 548, 'bad fp exception: RN pow(-0x1p-1024,0x1p+0)=-0x1p-1024, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 551, 'bad fp exception: RN pow(-0x1p-1023,0x1p+0)=-0x1p-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 557, 'bad fp exception: RN pow(-0x1.ffffffffffffcp-1023,0x1p+0)=-0x1.ffffffffffffcp-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 560, 'bad fp exception: RN pow(-0x1.ffffffffffffep-1023,0x1p+0)=-0x1.ffffffffffffep-1023, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 581, 'bad fp exception: RN pow(-0x1p-537,0x1p+1)=0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 655, 'bad fp exception: RN pow(-0x1p+1,-0x1.0c8p+10)=0x1p-1074, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 695, 'bad fp exception: RN pow(-0x1p+350,-0x1.8p+1)=-0x1p-1050, want 0 got INEXACT|UNDERFLOW'),
    ('src/math/ucb/pow.h', 708, 'bad fp exception: RN pow(-0x1p+1023,-0x1p+0)=-0x1p-1023, want 0 got INEXACT|UNDERFLOW'),
)


def expected_pow_stdout(prepared_root, *, candidate):
    root = Path(prepared_root)
    corrected = {line for line, _ in POW_IDENTITIES}
    return ''.join(f'X {root / header}:{line}: {message}\n'
                   for header, line, message in POW_DIAGNOSTICS
                   if not candidate or header != 'src/math/ucb/pow.h' or line not in corrected).encode('ascii')


def pow_disposition(reader, source, *, unit, candidate_status, candidate_stdout, candidate_stderr,
                    oracle_status, oracle_stdout, oracle_stderr):
    native.same(unit, 'math/pow', 'finite pow discrepancy unit')
    prepared = reader.leaf / 'source-prepared'
    native.require(source == prepared / POW_DEFECT['source'], 'finite pow discrepancy source path')
    native.same(native.digest(source), POW_DEFECT['source_sha256'], 'finite pow discrepancy source')
    headers = {}
    for relative, digest in POW_DEFECT['headers'].items():
        path = prepared / relative
        native.same(native.digest(path), digest, 'finite pow discrepancy header: ' + relative)
        headers[relative] = reader.identity(path)
    proofs = proof_sources(reader.root)
    identities = []
    rows = native.read_bytes(prepared / 'src/math/ucb/pow.h').decode('ascii').splitlines()
    for line, base in POW_IDENTITIES:
        row = rows[line - 1].strip()
        native.require(row.startswith('T(') and row.endswith(')'), 'finite pow identity row syntax')
        fields = tuple(field.strip() for field in row[2:-1].split(','))
        native.same(fields, ('RN', base, '0x1p+0', base, '0x0p+0', '0'), 'finite pow identity source vector')
        integer, exponent = exact.decode(exact.literal(base, 64), 64)
        shift = exponent + 1074
        denominator = 1 << max(-shift, 0)
        units, remainder = divmod(abs(integer) << max(shift, 0), denominator)
        native.require(remainder == 0 and 0 < units < 1 << 52, 'finite pow identity is not exact binary64 subnormal')
        identities.append({'header': 'src/math/ucb/pow.h', 'line': line, 'base': base,
                           'exponent': '0x1p+0', 'result': base, 'required_exceptions': 0,
                           'binary64_subnormal_units': -units if integer < 0 else units})
    for side, status, stdout, stderr in (
            ('candidate', candidate_status, candidate_stdout, candidate_stderr),
            ('oracle', oracle_status, oracle_stdout, oracle_stderr)):
        native.require(type(status) is int and status == 0, 'finite pow discrepancy ' + side + ' exit status')
        _require_bytes(stdout, expected_pow_stdout(reader.recorded(prepared), candidate=side == 'candidate'),
                       'finite pow discrepancy exact ' + side + ' diagnostics')
        _require_bytes(stderr, b'', 'finite pow discrepancy ' + side + ' stderr')
    return {
        'schema': SCHEMA,
        'unit': unit,
        'status': 'candidate-corrected-oracle-discrepancy',
        'basis': 'pinned-musl-source-bound-finite-binary64-identity',
        'raw_passed': False,
        'candidate': {'exit_status': 0, 'harness_passed': True, 'stdout_empty': False,
                      'stderr_empty': True, 'diagnostic_count': 10},
        'oracle': {'exit_status': 0, 'harness_passed': True, 'stdout_empty': False,
                   'stderr_empty': True, 'diagnostic_count': 24},
        'source': reader.identity(source),
        'headers': headers,
        'algorithm': 'finite-binary64-exact-identity',
        'exact_identities': identities,
        'libc_test': {'revision': native.LIBC_TEST_REVISION, 'tree': native.LIBC_TEST_TREE},
        'musl': {'revision': MUSL_REVISION, 'archive_sha256': MUSL_ARCHIVE_SHA256,
                 'normalized_source_tree_sha256': MUSL_TREE_SHA256},
        'proof_sources': proofs,
        'diagnostics': [{'header': header, 'line': line, 'prefix': 'X ', 'message': message}
                        for header, line, message in POW_DIAGNOSTICS],
    }
