"""Finite source/profile reconciliation for four aliases, six atomics and crypt.

This owner does not execute or waive a test. It retains exact upstream raw
failures and requires separately qualified same-product companion evidence.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re

import owned_posix_native_observations as native

SCHEMA = 'crabc.x86_64-owned-posix-native-dispositions/v1'
CRYPT_REFERENCE = 'compat/x86_64/native-crypt-reference/crypt.c'
CRYPT_REFERENCE_SHA256 = 'd25b9d533b304f9bbae0c8eae8212196e431fdbeb18e805aebf667741235aafe'
DYNAMIC_MODES = ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct')
PROFILE_SOURCES = ('COMPATIBILITY-PROFILE.md', 'compat/crabc-rs/crypt-profile.md',
    'compat/x86_64/owned-posix-native-dispositions.md', 'compat/x86_64/owned_posix_native_dispositions.py',
    'compat/x86_64/atomic_addressable_abi_probe.c', 'compat/x86_64/atomic_addressable_abi_probe.cpp',
    'compat/x86_64/atomic_addressable_abi_dynamic_main.c', 'compat/x86_64/run_atomic_addressable_abi.sh',
    'compat/x86_64/run_owned_atomic_addressable_profile.sh',
    'compat/x86_64/owned_atomic_addressable_profile.py',
    'compat/x86_64/owned-atomic-addressable-profile.md',
    CRYPT_REFERENCE, 'compat/x86_64/native-crypt-reference/COPYRIGHT',
    'compat/x86_64/native-crypt-reference/README.md')

# Exact tiny source inputs from the pinned OS-test tree. The complete native
# collector also proves their upstream tree/revision and untouched source copies.
OS_ALIAS_SOURCES = {}
for _alias, _getter in (('seteuid', 'geteuid'), ('setegid', 'getegid')):
    OS_ALIAS_SOURCES[_alias] = (f'/* Test whether a basic {_alias} invocation works. */\n\n'
        '#include <unistd.h>\n\n#include "../basic.h"\n\nint main(void)\n{\n'
        f'\tif ( {_alias}({_getter}()) < 0 )\n\t\terr(1, "{_alias}");\n\treturn 0;\n}}\n')
for _alias, _kind in (('setreuid', 'uid'), ('setregid', 'gid')):
    OS_ALIAS_SOURCES[_alias] = (f'/*[XSI]*/\n/* Test whether a basic {_alias} invocation works. */\n\n'
        '#include <unistd.h>\n\n#include "../basic.h"\n\nint main(void)\n{\n'
        f'\t{_kind}_t r{_kind} = get{_kind}();\n\t{_kind}_t e{_kind} = gete{_kind}();\n'
        f'\tif ( {_alias}(r{_kind}, e{_kind}) < 0 )\n\t\terr(1, "{_alias}");\n\treturn 0;\n}}\n')


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


def os_alias_disposition(reader, suite, outcome, source, candidate, oracle, companion):
    alias = Path(outcome).stem
    native.require(suite == 'basic' and outcome == 'unistd/' + alias + '.out' and alias in OS_ALIAS_SOURCES,
                   'OS outcome has no selected profile disposition')
    native.require(isinstance(companion, dict) and 'receipt' in companion
                   and set(companion['selected_dynamic_entries']) == set(DYNAMIC_MODES),
                   'OS credential companion proof required')
    native.require(native.read_bytes(source) == OS_ALIAS_SOURCES[alias].encode(), 'OS credential alias source differs')
    native.require(candidate == (alias + ': ENOTSUP\n').encode() and oracle == b'exit: 0\n',
                   'OS credential alias exact raw outcomes differ')
    return {'schema': SCHEMA, 'suite': suite, 'outcome': outcome, 'alias': alias,
            'status': 'profile-qualified', 'raw_passed': False, 'source': reader.identity(source),
            'profiles': profile_sources(reader.root), 'companion': companion['receipt'],
            'selected_dynamic_entries': companion['selected_dynamic_entries']}


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


def os_disposition(reader, suite, outcome, source, candidate, oracle, companions):
    """Admit only the two fixed OS rosters; every other raw mismatch rejects."""
    native.require(isinstance(companions, dict) and set(companions) == {'credentials', 'atomic'},
                   'complete OS companion proofs required')
    if suite == 'basic' and outcome in {'unistd/' + name + '.out' for name in OS_ALIAS_SOURCES}:
        return os_alias_disposition(reader, suite, outcome, source, candidate, oracle, companions['credentials'])
    if suite == 'include' and outcome in {'stdatomic/' + name + '.out' for name in OS_ATOMIC_SOURCES}:
        return os_atomic_disposition(reader, suite, outcome, source, candidate, oracle, companions['atomic'])
    raise native.NativeObservationError('OS outcome has no selected profile disposition')


def _retained_raw(root, leaf, record):
    from owned_posix_family_execution import physical
    native.keys(record, ('stdout', 'stderr', 'status'), 'profile companion raw streams')
    values = {}
    for stream, item in record.items():
        native.keys(item, ('path', 'sha256', 'size', 'base64'), 'profile companion stream')
        path = physical(root, leaf / item['path'])
        native.require(path.is_relative_to(leaf), 'profile companion raw path escapes replay')
        data = native.read_bytes(path)
        native.same([item['sha256'], item['size'], item['base64']],
                    [hashlib.sha256(data).hexdigest(), len(data), base64.b64encode(data).decode()],
                    'profile companion physical raw identity')
        values[stream] = data
    native.require(values['status'] == b'0\n' and values['stderr'] == b'', 'profile companion execution failed')
    return values


def credentials_companion(root, matrix, matrix_receipt, product):
    """The caller supplies the already fully validated family matrix.

    Rebind all three physical source/object/receipt/raw replays here, including
    direct setters. The composite independently validates the complete matrix
    first; this function cannot manufacture a partial-matrix qualification.
    """
    import owned_posix_family_execution as family
    import owned_posix_family_observations as observations
    from owned_posix_family_observations import _credentials_helper
    source = root / 'compat/x86_64/owned_credentials_profile_probe.c'
    expected_source = family.source_file(root, str(source.relative_to(root)))
    native.same(matrix['inputs']['dynamic_products']['primary']['path'], product.relative_to(root).as_posix(),
                'credentials companion selected installed product')
    native.same(matrix['inputs']['dynamic_products']['primary']['manifest_sha256'],
                native.digest(product / 'share/crabc/manifest.json'), 'credentials companion installed manifest')
    replays, hashes = {}, set()
    for label, dynamic_label in family.PAIRS.items():
        row = matrix['runs'][label]['credentials-profile']
        native.same([row['static_product'], row['dynamic_product']], [label, dynamic_label], 'credentials replay products')
        leaf = family.physical(root, root / row['leaf'])
        native.same(row['receipt'], family.file_identity(root, root / row['receipt']['path']), 'credentials replay receipt')
        objects = row['objects']
        native.require(len(objects) == 1, 'credentials canonical object roster differs')
        obj = next(iter(objects.values()))
        native.same(obj['source'], expected_source, 'credentials canonical source')
        native.same(obj['object'], family.file_identity(root, root / obj['object']['path']), 'credentials canonical object')
        hashes.add(obj['object']['sha256'])
        scenarios = row['observations']['scenarios']
        native.keys(scenarios, ('direct', 'aliases'), 'credentials companion scenarios')
        for scenario in ('direct', 'aliases'):
            record = scenarios[scenario]
            native.same(record['kind'], 'differential' if scenario == 'direct' else 'credentials-profile-difference',
                        'credentials scenario semantic kind')
            native.keys(record['candidates'], observations.MODES, 'credentials complete product entries')
            oracle = _retained_raw(root, leaf, record['oracle'])
            _credentials_helper(root, 'direct' if scenario == 'direct' else 'aliases-musl', leaf / record['oracle']['stdout']['path'])
            for mode in observations.MODES:
                candidate = _retained_raw(root, leaf, record['candidates'][mode])
                _credentials_helper(root, 'direct' if scenario == 'direct' else 'aliases-profile', leaf / record['candidates'][mode]['stdout']['path'])
                if scenario == 'direct':
                    native.require(candidate == oracle, 'credentials direct-setter raw difference')
        replays[label] = {'receipt': row['receipt'], 'objects': objects, 'scenarios': scenarios}
    native.require(len(hashes) == 1, 'credentials replay object differs across products')
    return {'receipt': matrix_receipt, 'replays': replays,
            'selected_dynamic_entries': {mode: {'direct': replays['primary']['scenarios']['direct']['candidates'][mode],
                'aliases': replays['primary']['scenarios']['aliases']['candidates'][mode]} for mode in DYNAMIC_MODES}}
