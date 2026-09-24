#!/usr/bin/env python3
"""Link-result differential for application definitions of libc functions.

For one public function F, pinned musl's static link succeeds exactly when no
libc.a member that defines F strongly is extracted. The witness object for F
defines F itself and references every public symbol that musl's libc.a and
the candidate archive both define, except the symbols of F's own musl member.
Musl links it unless its libc objects themselves need F's member; the
candidate must link wherever musl does, in static ET_EXEC and static-PIE mode.

Every function both archives define is linked and recorded in the report, so
the report measures the whole surface. The exit status gates only the
`--require` roster: each roster function must link with musl, and then with
the candidate in both modes.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# nm symbol classes that define a symbol in an archive member.
DEFINED = set('TDBRVWiu')
STRONG_FUNCTION = 'T'
FUNCTION = set('TW')


def archive_definitions(archive: Path) -> dict[str, dict[str, str]]:
    """Map each archive member to its global definitions and their nm class."""
    completed = subprocess.run(
        ['nm', '-A', '--defined-only', '-g', str(archive)],
        check=False, capture_output=True, text=True,
    )
    members: dict[str, dict[str, str]] = {}
    for line in completed.stdout.splitlines():
        match = re.match(r'^[^:]+:([^:]+):\s*[0-9a-fA-F]*\s+(\S)\s+(\S+)$', line)
        if match and match.group(2) in DEFINED:
            members.setdefault(match.group(1), {})[match.group(3)] = match.group(2)
    if not members:
        raise SystemExit(f'{archive}: no global definitions')
    return members


def owners(members: dict[str, dict[str, str]]) -> dict[str, list[tuple[str, str]]]:
    result: dict[str, list[tuple[str, str]]] = {}
    for member, symbols in members.items():
        for symbol, kind in symbols.items():
            result.setdefault(symbol, []).append((member, kind))
    return result


def witness(function: str, references: list[str]) -> str:
    lines = [
        '.text',
        f'.globl {function}',
        f'.type {function},@function',
        f'{function}:',
        '    ret',
        f'.size {function},1',
        '.globl main',
        '.type main,@function',
        'main:',
        '    xorl %eax, %eax',
        '    ret',
        '.section .data.rel.replacement_references,"aw"',
        '.balign 8',
    ]
    lines.extend(f'    .quad {symbol}' for symbol in references)
    return '\n'.join(lines) + '\n'


def link(command: list[str], log: Path) -> bool:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    log.write_text(completed.stdout + completed.stderr)
    return completed.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--oracle-cc', required=True)
    parser.add_argument('--oracle-archive', required=True, type=Path)
    parser.add_argument('--product', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--require', action='append', default=[])
    arguments = parser.parse_args()

    musl = archive_definitions(arguments.oracle_archive)
    candidate = archive_definitions(arguments.product / 'usr/lib/libc.a')
    musl_owners, candidate_owners = owners(musl), owners(candidate)
    public = sorted(symbol for symbol in musl_owners
                    if symbol in candidate_owners and not symbol.startswith('_'))
    functions = [symbol for symbol in public
                 if any(kind in FUNCTION for _, kind in musl_owners[symbol])
                 and any(kind in FUNCTION for _, kind in candidate_owners[symbol])]
    missing = sorted(set(arguments.require) - set(functions))
    if missing:
        raise SystemExit('replacement roster names functions outside both archives: ' + ' '.join(missing))

    work = arguments.work
    work.mkdir(parents=True, exist_ok=False)
    driver = str(arguments.product / 'bin/crabc-cc')

    def sweep(function: str) -> dict[str, object]:
        strong = [member for member, kind in musl_owners[function] if kind == STRONG_FUNCTION]
        excluded = set(musl[strong[0]]) if strong else set()
        references = [symbol for symbol in public if symbol != function and symbol not in excluded]
        source = work / f'{function}.s'
        source.write_text(witness(function, references))
        obj = work / f'{function}.o'
        subprocess.run([arguments.oracle_cc, '-c', str(source), '-o', str(obj)], check=True)
        result: dict[str, object] = {'musl_member': strong[0] if strong else None}
        result['musl'] = link([arguments.oracle_cc, '-static', '-fno-pie', '-no-pie', str(obj),
                               '-o', str(work / f'{function}.musl')], work / f'{function}.musl.log')
        for mode in ('static', 'static-pie'):
            result[mode] = link([driver, f'-{mode}', str(obj), '-o', str(work / f'{function}.{mode}')],
                                work / f'{function}.{mode}.log')
        for name in (f'{function}.musl', f'{function}.static', f'{function}.static-pie', f'{function}.s'):
            (work / name).unlink(missing_ok=True)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        results = dict(zip(functions, pool.map(sweep, functions)))

    divergent = sorted(f for f, r in results.items()
                       if r['musl'] and not (r['static'] and r['static-pie']))
    report = {
        'schema': 1,
        'functions': results,
        'musl_replaceable': sorted(f for f, r in results.items() if r['musl']),
        'candidate_divergent': divergent,
        'required': sorted(arguments.require),
    }
    (work / 'report.json').write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')

    failed = False
    for function in sorted(arguments.require):
        result = results[function]
        if not result['musl']:
            print(f'replacement roster: musl does not link a program defining {function}', file=sys.stderr)
            failed = True
        elif not (result['static'] and result['static-pie']):
            print(f'replacement roster: candidate does not link a program defining {function}; '
                  f'see {work}/{function}.static.log', file=sys.stderr)
            failed = True
    print(f'owned static replacement sweep: {len(functions)} functions, '
          f'{len(report["musl_replaceable"])} musl-replaceable, {len(divergent)} candidate-divergent, '
          f'{len(arguments.require)} required; report: {work}/report.json')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
