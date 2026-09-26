"""Finite source/profile boundaries and pinned oracle exceptions.

This owner does not execute or waive a test. It retains exact upstream raw
failures and requires the source-specific companion or source contract that
each finite boundary names.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

import owned_posix_native_observations as native

SCHEMA = 'crabc.x86_64-owned-posix-native-dispositions/v1'
CRYPT_REFERENCE = 'compat/x86_64/native-crypt-reference/crypt.c'
CRYPT_REFERENCE_SHA256 = 'd25b9d533b304f9bbae0c8eae8212196e431fdbeb18e805aebf667741235aafe'
STRPTIME_REFERENCE = 'compat/x86_64/native-strptime-reference/strptime.c'
STRPTIME_REFERENCE_SHA256 = 'af24cbeb224b18937c7396ce38710df72f7e35ba896dc5603de2119d16cffe8c'
DYNAMIC_MODES = ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct')
PROFILE_SOURCES = ('COMPATIBILITY-PROFILE.md', 'compat/crabc-rs/crypt-profile.md',
    'compat/x86_64/owned-posix-native-dispositions.md', 'compat/x86_64/owned_posix_native_dispositions.py',
    'compat/x86_64/owned_wordexp_upstream_policy.py',
    'compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json',
    'compat/x86_64/atomic_addressable_abi_probe.c', 'compat/x86_64/atomic_addressable_abi_probe.cpp',
    'compat/x86_64/atomic_addressable_abi_dynamic_main.c', 'compat/x86_64/run_atomic_addressable_abi.sh',
    'compat/x86_64/run_owned_atomic_addressable_profile.sh',
    'compat/x86_64/owned_atomic_addressable_profile.py',
    'compat/x86_64/owned-atomic-addressable-profile.md',
    CRYPT_REFERENCE, 'compat/x86_64/native-crypt-reference/COPYRIGHT',
    'compat/x86_64/native-crypt-reference/README.md',
    STRPTIME_REFERENCE, 'compat/x86_64/native-strptime-reference/COPYRIGHT',
    'compat/x86_64/native-strptime-reference/README.md')

# These are the complete address-taken C11 atomic failures in the pinned OS
# include suite. The unusual space in one declaration is upstream source data.
OS_ATOMIC_SOURCES = {
    'atomic_flag_clear': '#include <stdatomic.h>\n#ifdef atomic_flag_clear\n#undef atomic_flag_clear\n#endif\nvoid (*foo)(volatile atomic_flag *) = atomic_flag_clear;\nint main(void) { return 0; }\n',
    'atomic_flag_clear_explicit': '#include <stdatomic.h>\n#ifdef atomic_flag_clear_explicit\n#undef atomic_flag_clear_explicit\n#endif\nvoid (*foo)(volatile atomic_flag *, memory_order) = atomic_flag_clear_explicit;\nint main(void) { return 0; }\n',
    'atomic_flag_test_and_set': '#include <stdatomic.h>\n#ifdef atomic_flag_test_and_set\n#undef atomic_flag_test_and_set\n#endif\n_Bool (*foo)(volatile atomic_flag *) = atomic_flag_test_and_set;\nint main(void) { return 0; }\n',
    'atomic_flag_test_and_set_explicit': '#include <stdatomic.h>\n#ifdef atomic_flag_test_and_set_explicit\n#undef atomic_flag_test_and_set_explicit\n#endif\n_Bool (*foo)( volatile atomic_flag *, memory_order) = atomic_flag_test_and_set_explicit;\nint main(void) { return 0; }\n',
    'atomic_signal_fence': '#include <stdatomic.h>\n#ifdef atomic_signal_fence\n#undef atomic_signal_fence\n#endif\nvoid (*foo)(memory_order) = atomic_signal_fence;\nint main(void) { return 0; }\n',
    'atomic_thread_fence': '#include <stdatomic.h>\n#ifdef atomic_thread_fence\n#undef atomic_thread_fence\n#endif\nvoid (*foo)(memory_order) = atomic_thread_fence;\nint main(void) { return 0; }\n',
}

OS_AIO_CANCEL_SOURCE_SHA256 = '72ec1f0c1c1245c07a68f96c8b434c6e72a448781c8d6722fed3644586954acd'
OS_AIO_CANCEL_ORACLE_FAILURE = b'aio_error: EINPROGRESS\n'
OS_AIO_CANCEL_CANDIDATE_SUCCESS = b'exit: 0\n'


def profile_sources(root):
    return {path: {'path': path, 'sha256': native.digest(root / path)} for path in PROFILE_SOURCES}


def crypt_vectors(root):
    source = native.read_bytes(root / CRYPT_REFERENCE)
    native.require(hashlib.sha256(source).hexdigest() == CRYPT_REFERENCE_SHA256, 'crypt reference source differs')
    text = source.decode('ascii')
    # Keep newlines while removing comments. The source hash fixes the grammar:
    # all active calls contain exactly three single C string literals, without
    # concatenation, macros, trigraphs, or expression-valued arguments.
    token = r'"(?:[^"\\]|\\.)*"'
    comments = re.compile(r'/\*.*?\*/|//[^\n]*', re.DOTALL)
    uncommented = comments.sub(lambda m: '\n' * m[0].count('\n'), text)
    pattern = re.compile(r'\bT\(\s*(' + token + r')\s*,\s*(' + token + r')\s*,\s*(' + token + r')\s*\)')
    rows = []
    for ordinal, match in enumerate(pattern.finditer(uncommented), 1):
        expected_literal, setting_literal, key_literal = match.groups()
        # Settings and results in this fixed source are plain ASCII. Preserve
        # the key token verbatim for C generation and upstream #k diagnostics.
        native.require('\\' not in expected_literal and '\\' not in setting_literal, 'crypt reference setting grammar differs')
        setting, expected = setting_literal[1:-1], expected_literal[1:-1]
        # __LINE__ in the nested t_error macro names the T invocation's
        # first token, including calls whose arguments span several lines.
        line = uncommented.count('\n', 0, match.start()) + 1
        if ordinal in (6, 7, 23, 32):
            disposition, candidate = 'upstream-match', expected
        elif ordinal <= 14:
            disposition, candidate = 'unsupported-legacy-format', '*'
        else:
            local = (ordinal - 15) % 9
            reason = {0: 'empty-salt', 1: 'additional-field', 2: 'additional-field',
                      3: 'empty-salt', 4: 'empty-salt', 5: 'noncanonical-salt',
                      6: 'overlong-salt', 7: 'overlong-salt'}[local]
            disposition, candidate = 'unsupported-sha-' + reason, '*'
        rows.append({'ordinal': ordinal, 'line': line, 'key_literal': key_literal, 'setting': setting,
                     'oracle': expected, 'candidate': candidate, 'disposition': disposition})
    native.require(len(rows) == 32, 'crypt active vector roster differs')
    native.same([row['setting'] for row in rows if row['disposition'] == 'upstream-match'],
                ['$2a$00$0123456789012345678901', '$2a$08$01234567890123456789',
                 '$5$rounds=10$roundstoolow', '$6$rounds=10$roundstoolow'], 'crypt genuine upstream matches')
    return rows


def crypt_vector_observations(root, raw, side):
    native.require(side in ('candidate', 'oracle'), 'crypt observer role differs')
    rows = crypt_vectors(root)
    expected = ''.join(f'vector {row["ordinal"]:02d} line={row["line"]} nonnull=1 output={row[side].encode().hex()}\n'
                       for row in rows).encode()
    native.require(raw == expected, 'crypt per-vector nonnull output or complete roster differs')
    return [{'ordinal': row['ordinal'], 'line': row['line'], 'nonnull': True,
             'output': row[side], 'disposition': row['disposition']} for row in rows]


def crypt_disposition(reader, source, *, candidate_status, candidate_stdout, candidate_stderr,
                      oracle_status, oracle_stdout, oracle_stderr, companion):
    native.require(isinstance(companion, dict) and 'receipt' in companion, 'crypt companion proof required')
    rows = crypt_vectors(reader.root)
    native.same(companion['vectors'], rows, 'crypt companion source-vector roster')
    native.require(native.read_bytes(source) == native.read_bytes(reader.root / CRYPT_REFERENCE),
                   'crypt prepared source differs from fixed reference')
    native.same([candidate_status, oracle_status], [1, 0], 'crypt original raw exit statuses')
    native.require(candidate_stderr == b'' and oracle_stdout == b'' and oracle_stderr == b'',
                   'crypt unexpected original diagnostic or oracle failure')
    differences = [row for row in rows if row['disposition'] != 'upstream-match']
    expected = ''.join(f'{reader.recorded(source)}:{row["line"]}: crypt({row["key_literal"]}, "{row["setting"]}") '
                       f'failed: got "{row["candidate"]}" want "{row["oracle"]}"\n' for row in differences).encode()
    expected += b'FAIL /functional/crypt [status 1]\n'
    native.require(candidate_stdout == expected, 'crypt original diagnostics do not match all 28 observed vector differences')
    return {'schema': SCHEMA, 'unit': 'functional/crypt', 'status': 'profile-qualified', 'raw_passed': False,
            'source': reader.identity(source), 'profiles': profile_sources(reader.root),
            'differences': differences, 'matches': [row for row in rows if row['disposition'] == 'upstream-match'],
            'companion': companion['receipt']}


def strptime_disposition(reader, source, *, candidate_status, candidate_stdout, candidate_stderr,
                         oracle_status, oracle_stdout, oracle_stderr):
    """Qualify only the exact pinned libc-test Glibc-only strptime block.

    The original unit remains failed for both candidate and pinned musl. The
    fixed source, exact two diagnostics and empty stderr make this a finite
    source-and-standard contract rather than a generic matched-failure rule.

    POSIX.1-2017 does not specify ``%s`` or ``%z`` for strptime:
    https://pubs.opengroup.org/onlinepubs/9699919799.2018edition/functions/strptime.html
    POSIX.1-2024 specifies ``%s`` but leaves its tm effect unspecified, and
    specifies ``%z`` as ``+hhmm`` or ``-hhmm`` only:
    https://pubs.opengroup.org/onlinepubs/9799919799/functions/strptime.html
    The fixed source's ``-06`` is outside the latter syntax. The pinned musl
    source parses ``%s`` without changing tm and requires all four %z digits.
    """
    expected_source = reader.leaf / 'source-prepared/src/functional/strptime.c'
    native.require(source == expected_source, 'strptime disposition source path differs')
    reference = reader.root / STRPTIME_REFERENCE
    reference_bytes = native.read_bytes(reference)
    native.require(hashlib.sha256(reference_bytes).hexdigest() == STRPTIME_REFERENCE_SHA256,
                   'strptime reference source differs')
    native.require(native.read_bytes(source) == reference_bytes,
                   'strptime prepared source differs from fixed reference')
    native.same([candidate_status, oracle_status], [1, 1], 'strptime original raw exit statuses')
    native.require(candidate_stderr == b'' and oracle_stderr == b'',
                   'strptime unexpected original stderr')
    expected = (
        f'{reader.recorded(source)}:36: "%s": for "683078400" expected 1991-08-25T00:00:00 '
        'but got 1900-01-00T00:00:00\n'
        f'{reader.recorded(source)}:47: "%z": failed to parse "-06"\n'
        'FAIL /functional/strptime [status 1]\n'
    ).encode()
    native.require(candidate_stdout == expected and oracle_stdout == expected,
                   'strptime original diagnostics differ from the fixed two-line source contract')
    return {
        'schema': SCHEMA,
        'unit': 'functional/strptime',
        'status': 'profile-qualified',
        'basis': 'pinned-source-musl-posix',
        'raw_passed': False,
        'source': reader.identity(source),
        'reference': reader.identity(reference, source=True),
        'profiles': profile_sources(reader.root),
        'diagnostics': [
            {'line': 36, 'conversion': '%s', 'input': '683078400',
             'raw': 'expected 1991-08-25T00:00:00 but got 1900-01-00T00:00:00'},
            {'line': 47, 'conversion': '%z', 'input': '-06', 'raw': 'failed to parse'},
        ],
    }


def os_atomic_disposition(reader, suite, outcome, source, candidate, oracle, companion):
    symbol = Path(outcome).stem
    native.require(suite == 'include' and outcome == 'stdatomic/' + symbol + '.out'
                   and symbol in OS_ATOMIC_SOURCES, 'OS outcome has no selected atomic profile disposition')
    native.require(isinstance(companion, dict) and 'receipt' in companion
                   and set(companion['selected_dynamic_entries']) == set(DYNAMIC_MODES),
                   'OS atomic companion proof required')
    native.require(native.read_bytes(source) == OS_ATOMIC_SOURCES[symbol].encode(),
                   'OS atomic source differs')
    native.require(candidate == b'good\n' and oracle == b'undefined\n',
                   'OS atomic exact raw outcomes differ')
    return {'schema': SCHEMA, 'suite': suite, 'outcome': outcome, 'symbol': symbol,
            'status': 'profile-qualified', 'raw_passed': False, 'source': reader.identity(source),
            'profiles': profile_sources(reader.root), 'companion': companion['receipt'],
            'selected_dynamic_entries': companion['selected_dynamic_entries']}


def os_aio_cancel_disposition(reader, suite, outcome, source, candidate, oracle):
    """Qualify the completion-publication race in pinned musl AIO cancellation.

    The worker clears its running flag before publishing the aiocb error.
    ``aio_cancel`` can finish its wait in that interval and return ALLDONE;
    the unchanged test then observes EINPROGRESS. A candidate must complete
    the request before returning, and every other upstream outcome fails.
    """
    native.same([suite, outcome], ['basic', 'aio/aio_cancel.out'], 'OS AIO cancellation outcome')
    native.require(source == reader.leaf / 'source-stage/basic/aio/aio_cancel.c',
                   'OS AIO cancellation source path differs')
    native.same(native.digest(source), OS_AIO_CANCEL_SOURCE_SHA256,
                'OS AIO cancellation pinned source')
    native.require(candidate == OS_AIO_CANCEL_CANDIDATE_SUCCESS and oracle == OS_AIO_CANCEL_ORACLE_FAILURE,
                   'OS AIO cancellation exact raw outcomes differ')
    return {'schema': SCHEMA, 'suite': suite, 'outcome': outcome,
            'status': 'candidate-passed-oracle-defect', 'raw_passed': False,
            'basis': 'pinned-musl-completion-publication-race',
            'source': reader.identity(source), 'profiles': profile_sources(reader.root),
            'candidate': {'passed': True, 'outcome': 'exit: 0'},
            'oracle': {'passed': False, 'outcome': 'aio_error: EINPROGRESS'}}


def os_disposition(reader, suite, outcome, source, candidate, oracle, companions):
    """Admit only the atomic profile and the pinned AIO oracle defect."""
    native.require(isinstance(companions, dict) and set(companions) == {'atomic'},
                   'complete OS companion proofs required')
    if suite == 'include' and outcome in {'stdatomic/' + name + '.out' for name in OS_ATOMIC_SOURCES}:
        return os_atomic_disposition(reader, suite, outcome, source, candidate, oracle, companions['atomic'])
    if suite == 'basic' and outcome == 'aio/aio_cancel.out':
        return os_aio_cancel_disposition(reader, suite, outcome, source, candidate, oracle)
    raise native.NativeObservationError('OS outcome has no selected profile disposition')
