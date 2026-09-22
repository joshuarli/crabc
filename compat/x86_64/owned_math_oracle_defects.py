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
# correction against an actual product rather than a prose claim. Their fixed
# digests mean a later edit cannot reuse these observed pinned-musl diagnostics
# by name alone.
PROOF_SOURCES = {
    'compat/upstreams.toml': '21f2ac05168af11b667bd8e068499acfc484924176ee2fadd0ef11f20b86fdad',
    'compat/x86_64/math-scalar-corrections.md': '7496c2882edc73f579cd02e56760cdf9e469b359b8d97e01a3bd135450d31f99',
    'compat/x86_64/math_scalar_corrections.py': '3df692cfaa4ce0a66288d6939aa4ba7ff4d1186543e644b1241b972fe23837d6',
    'compat/x86_64/run_math_scalar_corrections_libc_test.py': '898d6b45311a5126d2975020515e10f3f40015166c09775b3494f6a1cf60bea4',
    'compat/x86_64/math_scalar_corrections_probe.c': '9e5e3f8f407bfe383558bb939d9f2c824a6d791c9e6e0b6d0cc534c446779559',
    'compat/x86_64/generate_libc_math_scalar_completion.py': 'b627a4322fb7243ab2d7dbc03eaaf61f5512ac37384bb261db8c074e5e113973',
    'compat/x86_64/generate_libc_math_elementary_long_double.py': '4b08aa69558f42d023e5971565b1b3eef68a1ece9d9b4b84cc1e19fd4708798c',
    'compat/x86_64/generate_libc_math_pow.py': '13d4ba9c0e69d3c3416804d08443353516cb591646bf33bfe59c271ea6d4bdc4',
    'compat/x86_64/generate_libc_math_special.py': 'a73830ba507bb030336d348d1b173aaf121dad3894ea31bffa843526a5cbc4c6',
    'compat/x86_64/run_math_scalar_corrections.sh': 'c77f82afc760ecf195cd3e5a2d6ccf13c0b7c5fef299606fa840474f30bf2772',
    'compat/x86_64/run_musl_oracle.sh': '4f37688ab2b16c36aee03a666d336bbadf11f79645019effb35c4cbebcc58c2a',
    'compat/x86_64/verify_math_scalar_corrections.py': 'f171001ac9321e82d7af8d1fd3f5dcab18387d8fbb22cc92ecc19c4cc241f50f',
    'compat/x86_64/verify_math_pow_records.py': '377c45675a7bb503b2f2148783db2c5b952686148b4ce0164965349ab7b4fe12',
    'compat/x86_64/math_scalar_corrections_boundary.rs': '4783309a2d509a9df4aa17f82c9ef8f98a8a65f08fbf72147b769fb22443509f',
    'compat/x86_64/math_scalar_corrections_stream.c': '5835882d1fa52127f7355b2047e62d161fe990acf28aac2df367c8a2bd8f3865',
    'compat/x86_64/math_scalar_corrections_start.S': '40897bbe7de7f35bcf865618c25ae6caf224a596b85a0b7db88c49a49bc4dae2',
    'compat/x86_64/owned_static_math_scalar_consumer.c': '83e7651532c54b0ba993b9e8bdbce094d106b2d3a72fde7328d8d9924c4b35b3',
    'compat/x86_64/owned_static_math_scalar_consumer_start.S': '0b668474e400fdb90250a36427e15e5c1b760281635445fe1df564936676eedd',
    'compat/x86_64/owned_static_math_binary80_consumer.c': '471842055aa3476f2039cfc8262cad547657d766b4bf3ca86756aef91f180532',
    'compat/x86_64/owned_static_math_binary80_consumer_start.S': '0b668474e400fdb90250a36427e15e5c1b760281635445fe1df564936676eedd',
    'compat/x86_64/libc_math_pow_probe.c': '873146c872ba1a5fee4c7661a0a4de6cfe019cc926f338862a91363c486ed30f',
    'compat/x86_64/libc_math_pow_start.S': '23401f3b543cfe9928c27b71d8a61a57b07ad1d0a4bae8e3964d6551b202a96b',
    'compat/x86_64/libc_math_elementary_long_double_probe.c': '6449e7be9dd0978da20206f385dac20f3cbf48ff0c09ee00a7a311496d495e00',
    'compat/x86_64/libc_math_elementary_long_double_start.S': '8801bb7960a563910822a09be72d75ffd9c2175ae7b7d9311dee7755682b7878',
    'compat/x86_64/libc_math_special_probe.c': 'ea404cb6517a65070cb5bca883a494d246eb757400125fc2b0e4f31dd4e7b8e0',
    'compat/x86_64/libc_math_special_start.S': 'c4eef41eafceb833b14215170d922d00bb20cde2905bbd637391ed8a73f06f15',
    'libc/src/c_abi/x86_64/math_scalar_completion.rs': '563c23418d91a30e23fc82f159db38580174afcc5f4114e6840b2e14bceb97b6',
    'libc/src/c_abi/x86_64/math_elementary_long_double.rs': 'ee732b5bfca1482641c21c238673fddd43c06ccf7b6b927b44977f988108308d',
    'libc/src/c_abi/x86_64/math_pow.rs': '05111f83e80c72145138519c425cd6cb24c5cf3263f5a2b4e39f54a323176fc4',
    'libc/src/c_abi/x86_64/math_special.rs': 'df74a349ab13e09b761566b2bdcf0009e82e4ad5dfee9efacf98a48da4ddb1e5',
    'libc/src/c_abi/x86_64/math_complex.rs': '03481dd4635d1ead4ac35baa81aeaeefeea944414448d6799fb866a62f621d26',
    'libc/src/c_abi/x86_64/math_x87_extended.rs': '377e95408f3481be0bd79e86e6b79fd86b974b073e44aa2f0ee4e49b5a4d9f94',
    'libc/src/c_abi/x86_64/fenv.rs': '84656ed5d80b52b3adb056d443c73b072d0f4a869c1250d8328a1473c3a2dbeb',
    'libc/src/c_abi/x86_64/elementary_sqrt.rs': 'f6387d34780aba68ee36a1dc4822a549fc7990ad96583303468a8b2d3007356c',
    'libc/src/c_abi/x86_64/fenv_rounding.rs': '7c55a23f461250745247a3565b1bb27763d179ec4b24b8642238fa988748e89b',
    'libc/src/c_abi/x86_64/math_scalar_completion_musl_x86_64.S': '540fbee35c6e9da21beb1e0035449cd40676ed9bbdbba20294fb352ba7d8b9bf',
    'libc/src/c_abi/x86_64/math_elementary_long_double_musl_x86_64.S': 'c92059813c80d5725f7345022734d4e9c7d3d24b1d46fb58c5dcdcc8d84f4c97',
    'libc/src/c_abi/x86_64/math_pow_musl_x86_64.S': '2c0a801e05e24538832d7cb6d49de1b771943164da1b6cb4ae905bb2043f8aac',
    'libc/src/c_abi/x86_64/math_special_musl_x86_64.S': '4a3ec2513d3db50ce340d41b52e5574d7a32cdab864ebda34952ff205a5f0359',
}

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
    for relative, expected in PROOF_SOURCES.items():
        path = root / relative
        actual = native.digest(path)
        native.require(actual == expected, 'math oracle-defect proof source differs: ' + relative)
        sources[relative] = {'path': relative, 'sha256': actual}
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
