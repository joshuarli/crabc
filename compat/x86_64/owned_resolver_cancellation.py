#!/usr/bin/env python3
"""Same installed-header object through owned DNS cancellation entry modes."""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys

from owned_classic_netdb import checked, fixture_module, physical
from owned_dynamic_qualification import source_digest

ROOT = Path(__file__).resolve().parents[2]
APIS = ('query', 'send', 'classic', 'modern', 'reverse')
SCENARIOS = ('udp', 'tcp', 'pending', 'disabled', 'masked',
             'masked-udp', 'masked-tcp', 'disabled-udp', 'disabled-tcp',
             'masked-udp-to-tcp', 'setup-pending', 'kernel-canceled',
             'masked-tcp-socket-failure', 'normal-udp', 'normal-tcp',
             'retry-udp', 'retry-cancel-udp', 'reuse-cancel-udp')
# Preserve raw observations. Only these ordinary, non-consumed-cancellation
# errno differences are outside this slice; lifecycle and success still match.
ORDINARY_ERRNO_DIFFERENCES = frozenset(('disabled', 'disabled-udp', 'disabled-tcp',
                                      'kernel-canceled', 'normal-tcp'))
PROVIDERS = frozenset(('res_query', 'res_send', 'gethostbyname_r', 'getaddrinfo', 'getnameinfo'))


def prepare(work: Path) -> None:
    for kind, builder in (('static', 'build_x86_64_owned_sysroot.py'), ('dynamic', 'build_x86_64_owned_dynamic_sysroot.py')):
        checked([sys.executable, '-B', ROOT / 'scripts' / builder, '--output', work / f'{kind}-sysroot'], work / f'{kind}-build.log')


def providers(binary: Path, dynamic: bool, output: Path) -> None:
    checked(['readelf', '--wide', '--dyn-syms' if dynamic else '--syms', binary], output)
    found = {}
    for line in output.read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in PROVIDERS:
            found[fields[7]] = fields
    if set(found) != PROVIDERS:
        raise RuntimeError(f'missing DNS cancellation providers: {sorted(PROVIDERS-set(found))}')
    for name, fields in found.items():
        if fields[3] != 'FUNC' or fields[4] not in ('GLOBAL', 'WEAK') or fields[5] != 'DEFAULT' or fields[6] == 'UND':
            raise RuntimeError(f'incorrect DNS cancellation provider: {name}: {fields}')


def observation(stdout: bytes) -> dict[str, int]:
    fields = dict(field.split('=', 1) for field in stdout.decode('ascii').split())
    expected = {'canceled', 'returned', 'cleanup', 'cleanup_fds', 'leaked', 'state', 'transmitted', 'success', 'errno'}
    if set(fields) != expected:
        raise RuntimeError(f'incomplete DNS cancellation observation: {fields}')
    return {key: int(value) for key, value in fields.items()}


def run(work: Path, static: Path | None, dynamic: Path | None) -> None:
    fixture = fixture_module()
    fixture.require_native_loopback_container()
    source_sha256 = source_digest()
    products = {kind: fixture.tree_identity(path) for kind, path in (('static', static), ('dynamic', dynamic)) if path is not None}
    proof = {'interfaces': sorted(line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:] if ':' in line),
             'network_namespace': os.readlink('/proc/self/ns/net'), 'user_namespace': os.readlink('/proc/self/ns/user')}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        flags = fcntl.ioctl(control, 0x8913, struct.pack('16sH22x', b'lo', 0))
        proof['loopback_up'] = bool(struct.unpack_from('H', flags, 16)[0] & 1)
    if not proof['loopback_up']:
        raise RuntimeError('DNS cancellation loopback is down')
    proof['isolation'] = os.environ.get('CRABC_RESOLVER_CANCELLATION_ISOLATION', 'docker-network-none')
    proof['parent_network_namespace'] = os.environ.get('CRABC_RESOLVER_CANCELLATION_PARENT_NETNS')
    (work / 'network-isolation.json').write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n')
    source = ROOT / 'compat/x86_64/owned_resolver_cancellation_probe.c'
    obj = work / 'workload.o'
    compiler = static / 'bin/crabc-cc' if static is not None else dynamic / 'bin/crabc-cc-dynamic'
    compile_mode = '--static-pie' if static is not None else '--dynamic-pie'
    checked([compiler, compile_mode, '-std=c11', '-fno-builtin', '-c', source, '-o', obj], work / 'compile.log')
    object_record = fixture.artifact_record(obj)
    checked(['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', '-pthread', obj, '-o', work / 'oracle'], work / 'oracle-link.log')
    providers(work / 'oracle', False, work / 'oracle-symbols.txt')
    execution = work / 'execution-root'
    (execution / 'etc').mkdir(parents=True)
    shutil.copy2(work / 'oracle', execution / 'oracle')
    witness = ROOT / 'compat/x86_64/run_pthread_wait_witness.py'
    outcomes = []
    oracle = {}
    differences = []
    audits = {'source_sha256': source_sha256, 'source': fixture.artifact_record(source),
              'object': object_record, 'products': products, 'artifacts': {}}

    def execute(label: str, entry: list[str]) -> None:
        for api in APIS:
            for scenario in SCENARIOS:
                name = f'{label}-{api}-{scenario}'
                command = [sys.executable, '-B', str(witness), str(execution), *entry, scenario, api]
                try:
                    result = subprocess.run(command, capture_output=True, timeout=10)
                    status, stdout, stderr = result.returncode, result.stdout, result.stderr
                except subprocess.TimeoutExpired as error:
                    status, stdout, stderr = 124, error.stdout or b'', error.stderr or b''
                (work / (name+'.stdout')).write_bytes(stdout)
                (work / (name+'.stderr')).write_bytes(stderr)
                outcomes.append({'entry': label, 'api': api, 'scenario': scenario, 'exit_status': status})
                (work / 'execution-status.json').write_text(json.dumps(outcomes, indent=2)+'\n')
                if status:
                    raise RuntimeError(f'{name} exited {status}: {stderr.decode(errors="replace")}')
                current = observation(stdout)
                if label == 'oracle':
                    oracle[(api, scenario)] = (current, stderr)
                else:
                    expected, oracle_stderr = oracle[(api, scenario)]
                    excluded = {'errno'} if scenario in ORDINARY_ERRNO_DIFFERENCES else set()
                    if stderr != oracle_stderr or any(current[key] != expected[key] for key in expected.keys()-excluded):
                        raise RuntimeError(f'DNS cancellation observation differs: {name}: {current} != {expected}')
                    if current != expected:
                        differences.append({'entry': label, 'api': api, 'scenario': scenario,
                                            'oracle_errno': expected['errno'], 'owned_errno': current['errno']})
                print(f'{name}: PASS', flush=True)

    # Separate oracle-only wrappers observe the real disabled fast-open and
    # fallback-connect phases. No owned consumer links these wrapper objects.
    transition_source = ROOT / 'compat/x86_64/owned_resolver_tcp_transition_probe.c'
    transition_obj = work / 'tcp-transition.o'
    checked([compiler, compile_mode, '-std=c11', '-fno-builtin', '-c', transition_source, '-o', transition_obj], work / 'tcp-transition-compile.log')
    checked(['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', '-pthread', obj, transition_obj,
             '-Wl,--wrap=setsockopt,--wrap=connect,--wrap=sendmsg', '-o', execution / 'oracle-tcp-transition'], work / 'tcp-transition-link.log')
    for fallback in (False, True):
        label = 'oracle-connect-transition' if fallback else 'oracle-fastopen-transition'
        environment = os.environ.copy()
        if fallback: environment['CRABC_TEST_NO_FASTOPEN'] = '1'
        else: environment.pop('CRABC_TEST_NO_FASTOPEN', None)
        result = subprocess.run([sys.executable, '-B', str(witness), str(execution), '/oracle-tcp-transition', 'tcp', 'query'],
                                capture_output=True, timeout=10, env=environment)
        (work / (label+'.stdout')).write_bytes(result.stdout)
        (work / (label+'.stderr')).write_bytes(result.stderr)
        lines = result.stderr.decode().splitlines()
        expected = ['tcp-fastopen-option state=1', 'tcp-connect state=1', 'tcp-sendmsg fastopen=0 state=0'] if fallback else ['tcp-fastopen-option state=1', 'tcp-sendmsg fastopen=1 state=1']
        if result.returncode or lines[:len(expected)] != expected or any(line != 'tcp-sendmsg fastopen=0 state=0' for line in lines[len(expected):]):
            raise RuntimeError(f'TCP source transition differs: {label}: {result.returncode}: {lines}')
    execute('oracle', ['/oracle'])
    if static is not None:
        for mode in ('static-et-exec', 'static-pie'):
            binary = work / mode
            receipt = work / (mode+'.receipt.json')
            checked([static / 'bin/crabc-cc', '--'+mode, '--link-receipt', receipt.name, obj, '-o', binary], work / (mode+'-link.log'), cwd=work)
            audits['artifacts'][mode] = {'receipt': fixture.static_receipt_audit(static, '--'+mode, obj, binary, receipt),
                                         'elf': fixture.elf_audit(binary, mode='static' if mode == 'static-et-exec' else mode, dynamic=False)}
            providers(binary, False, work / (mode+'-symbols.txt'))
            shutil.copy2(binary, execution / mode)
            execute(mode, ['/'+mode])
    if dynamic is not None:
        providers(dynamic / 'usr/lib/libc.so', True, work / 'dynamic-provider-symbols.txt')
        shutil.copytree(dynamic, execution, dirs_exist_ok=True, symlinks=True)
        for mode in ('pie', 'non-pie'):
            binary = work / ('dynamic-'+mode)
            checked([dynamic / 'bin/crabc-cc-dynamic', '--dynamic-'+mode, obj, '-o', binary], work / (mode+'-link.log'))
            audits['artifacts']['dynamic-'+mode] = {
                'receipt': fixture.dynamic_receipt_audit(dynamic, '--dynamic-'+mode, obj, binary, Path(str(binary)+'.crabc-link.json')),
                'elf': fixture.elf_audit(binary, mode='dynamic-'+mode, dynamic=True)}
            shutil.copy2(binary, execution / binary.name)
            execute(mode+'-kernel', ['/'+binary.name])
            execute(mode+'-direct', ['/lib/ld-crabc-x86_64.so.1', '/'+binary.name])
    if source_digest() != source_sha256 or fixture.artifact_record(obj) != object_record:
        raise RuntimeError('DNS cancellation source or same application object changed during execution')
    for kind, path in (('static', static), ('dynamic', dynamic)):
        if path is not None and fixture.tree_identity(path) != products[kind]:
            raise RuntimeError(f'supplied {kind} product changed during execution')
    expected_count = len(APIS)*len(SCENARIOS)*(1+(2 if static is not None else 0)+(4 if dynamic is not None else 0))
    if len(outcomes) != expected_count:
        raise RuntimeError('incomplete DNS cancellation entry matrix')
    (work / 'ordinary-errno-differences.json').write_text(json.dumps(differences, indent=2)+'\n')
    (work / 'artifact-audits.json').write_text(json.dumps(audits, indent=2, sort_keys=True)+'\n')
    print(f'owned resolver cancellation: PASS ({len(outcomes)} same-object cases); evidence: {work}', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--static-sysroot', type=Path)
    parser.add_argument('--dynamic-sysroot', type=Path)
    args = parser.parse_args()
    work = physical(args.work, 'resolver cancellation evidence')
    print(f'resolver cancellation evidence: {work}', flush=True)
    if args.action == 'prepare': prepare(work)
    else:
        if args.static_sysroot is None and args.dynamic_sysroot is None:
            raise RuntimeError('at least one supplied static or dynamic product is required')
        static = physical(args.static_sysroot, 'static product') if args.static_sysroot else None
        dynamic = physical(args.dynamic_sysroot, 'dynamic product') if args.dynamic_sysroot else None
        run(work, static, dynamic)


if __name__ == '__main__':
    try: main()
    except (RuntimeError, OSError, ValueError) as error:
        raise SystemExit(f'owned resolver cancellation: ERROR: {error}')
