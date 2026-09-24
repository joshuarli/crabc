"""Finite source-bound pinned-musl defects corrected by the native candidate.

This is deliberately narrower than profile accounting.  It admits a candidate
success only when the complete pinned libc-test graph, the exact test source
and diagnostic header, and the checked production correction sources agree.
Every other mismatched libc-test unit remains a raw failure.
"""
from __future__ import annotations

from pathlib import Path
import tomllib

import owned_posix_native_observations as native

SCHEMA = 'crabc.x86_64-math-oracle-defects/v1'
MUSL_REVISION = '9fa28ece75d8a2191de7c5bb53bed224c5947417'
MUSL_ARCHIVE_SHA256 = 'd585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a'
MUSL_TREE_SHA256 = '2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88'

# These are the correction source-to-assembly chain and its independent proof
# closure.  The four checked assembly inputs include fmal's nextafterl support;
# the runner, exact-dyadic judge, stream transport and Rust boundary prove the
# correction against an actual product rather than a prose claim. The
# disposition records the digest of each source that actually ran; the
# qualification cohort binds them to its clean revision.
PROOF_SOURCES = (
    'compat/upstreams.toml',
    'compat/x86_64/math-scalar-corrections.md',
    'compat/x86_64/math_scalar_corrections.py',
    'compat/x86_64/run_math_scalar_corrections_libc_test.py',
    'compat/x86_64/math_scalar_corrections_probe.c',
    'compat/x86_64/generate_libc_math_scalar_completion.py',
    'compat/x86_64/generate_libc_math_elementary_long_double.py',
    'compat/x86_64/generate_libc_math_pow.py',
    'compat/x86_64/generate_libc_math_special.py',
    'compat/x86_64/run_math_scalar_corrections.sh',
    'compat/x86_64/run_musl_oracle.sh',
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

# The source and headers are pinned libc-test inputs, not rewritten expected
# output.  Each message is the entire observed pinned-musl discrepancy after
# the source path and the harness's terminal FAIL marker are added.
ORACLE_DEFECTS = {
    'math/fmaf': {
        'source': 'src/math/fmaf.c',
        'source_sha256': 'a9986572cc7a8fcf6a56a88ca10a57867be22fad2442b9b484489badb21498d3',
        'headers': {'src/math/special/fmaf.h': 'd358f3f778693b518ffe93bbda6ab76043355613aafe5a9a7fe50ee13211e8fa'},
        'algorithm': 'subnormal-binary32-midpoint-spacing',
        'diagnostics': (
            ('src/math/special/fmaf.h', 78, '',
             'RN fmaf(-0x1.001p-81,0x1.ffe002p-70,0x1.0002p-133) want 0x1.0001p-133 got 0x1.0002p-133 ulperr 0.500 = 0x1p+0 + -0x1p-1'),
            ('src/math/special/fmaf.h', 82, '',
             'RN fmaf(0x1.01008p-75,0x1.fe01p-76,0x1p-128) want 0x1.000008p-128 got 0x1p-128 ulperr -0.500 = -0x1p+0 + 0x1p-1'),
            ('src/math/special/fmaf.h', 83, '',
             'RN fmaf(0x1.01008p-75,0x1.fe01p-76,-0x1p-128) want -0x1.fffffp-129 got -0x1p-128 ulperr -0.500 = -0x1p+0 + 0x1p-1'),
            ('src/math/special/fmaf.h', 84, '',
             'RN fmaf(-0x1.002002p-75,-0x1.ffc004p-76,0x1p-142) want 0x1.02p-142 got 0x1p-142 ulperr -0.500 = -0x1p+0 + 0x1p-1'),
            ('src/math/special/fmaf.h', 85, '',
             'RN fmaf(-0x1.002002p-75,0x1.ffc004p-76,0x1p-142) want 0x1.fcp-143 got 0x1p-142 ulperr 0.500 = 0x1p+0 + -0x1p-1'),
            ('src/math/special/fmaf.h', 86, '',
             'RN fmaf(0x1.43cb1ep-75,0x1.94cd22p-76,0x1.f8p-144) want 0x1.f8p-144 got 0x1p-143 ulperr 0.500 = 0x1p+0 + -0x1p-1'),
            ('src/math/special/fmaf.h', 87, '',
             'RN fmaf(0x1.43cb1ep-75,0x1.94cd22p-76,-0x1.f8p-144) want -0x1.f8p-144 got -0x1.fp-144 ulperr 0.500 = 0x1p+0 + -0x1p-1'),
        ),
    },
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
    pins = tomllib.loads(native.read_bytes(root / 'compat/upstreams.toml').decode('utf-8'))['musl']
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
