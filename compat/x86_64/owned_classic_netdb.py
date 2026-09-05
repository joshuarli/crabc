#!/usr/bin/env python3
"""One installed-header object through the contained classic netdb matrix."""
from __future__ import annotations
import argparse
import importlib.util
import fcntl
import socket
import struct
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CASES = ('host-numeric', 'host-local', 'host-buffers', 'host-many', 'host-dns',
         'search-precedence', 'mixed-family', 'reverse-local', 'reverse-dns', 'services',
         'service-buffers', 'open-errors', 'read-errors', 'access-errors',
         'socket-error', 'fcntl-error', 'empty-reporting', 'addrinfo', 'threads-fork', 'allocation')
PROVIDERS = {'gethostbyaddr', 'gethostbyaddr_r', 'gethostbyname', 'gethostbyname2',
             'gethostbyname2_r', 'gethostbyname_r', 'gethostent', 'getnetbyaddr',
             'getnetbyname', 'getnetent', 'getservbyname', 'getservbyname_r',
             'getservbyport', 'getservbyport_r', 'herror'}


def physical(path: Path, label: str) -> Path:
    result = path.resolve(strict=True)
    if path.is_symlink() or not result.is_dir() or not result.is_relative_to(ROOT / '.work'):
        raise RuntimeError(f'{label} must be a physical checkout .work directory')
    return result


def checked(arguments: list[str | Path], log: Path, *, cwd: Path = ROOT) -> None:
    with log.open('wb') as output:
        result = subprocess.run(list(map(str, arguments)), cwd=cwd, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        print(log.read_text(errors='replace'), end='', flush=True)
        raise RuntimeError(f'command failed ({result.returncode}): {log}')


def prepare(work: Path) -> None:
    for kind, builder in (('static', 'build_x86_64_owned_sysroot.py'), ('dynamic', 'build_x86_64_owned_dynamic_sysroot.py')):
        checked([sys.executable, '-B', ROOT / 'scripts' / builder, '--output', work / f'{kind}-sysroot'], work / f'{kind}-build.log')


def fixture_module():
    spec = importlib.util.spec_from_file_location('classic_netdb_existing_fixture', ROOT / 'compat/resolver-network/run_x86_64.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def symbols(binary: Path, dynamic: bool, destination: Path) -> None:
    checked(['readelf', '--wide', '--dyn-syms' if dynamic else '--syms', binary], destination)
    found = {}
    for line in destination.read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in PROVIDERS:
            found[fields[7]] = fields
    if set(found) != PROVIDERS:
        raise RuntimeError(f'missing classic netdb providers: {sorted(PROVIDERS - set(found))}')
    for name, fields in found.items():
        if fields[3:6] != ['FUNC', 'GLOBAL', 'DEFAULT'] or fields[6] == 'UND':
            raise RuntimeError(f'incorrect classic netdb provider binding: {name}: {fields}')


def run(work: Path, static: Path | None, dynamic: Path) -> None:
    fixture = fixture_module()
    from owned_dynamic_qualification import source_digest
    source_sha256 = source_digest()
    fixture.require_native_loopback_container()
    proof = {'interfaces': sorted(line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:] if ':' in line),
             'network_namespace': os.readlink('/proc/self/ns/net'),
             'user_namespace': os.readlink('/proc/self/ns/user')}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        flags = fcntl.ioctl(control, 0x8913, struct.pack('16sH22x', b'lo', 0))
        proof['loopback_up'] = bool(struct.unpack_from('H', flags, 16)[0] & 1)
    if not proof['loopback_up']:
        raise RuntimeError('classic netdb loopback interface is down')
    proof['isolation'] = os.environ.get('CRABC_CLASSIC_NETDB_ISOLATION', 'docker-network-none')
    proof['parent_network_namespace'] = os.environ.get('CRABC_CLASSIC_NETDB_PARENT_NETNS')
    (work / 'network-isolation.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    source = ROOT / 'compat/x86_64/owned_classic_netdb_probe.c'
    obj = work / 'workload.o'
    if static is not None:
        compiler = static / 'bin/crabc-cc'
        flags = ['-static-pie']
    else:
        compiler = dynamic / 'bin/crabc-cc-dynamic'
        flags = ['--dynamic-pie']
    checked([compiler, *flags, '-std=c11', '-fno-builtin', '-c', source, '-o', obj], work / 'compile.log')
    checked(['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', '-pthread', obj, '-o', work / 'oracle'], work / 'oracle-link.log')
    symbols(work / 'oracle', False, work / 'oracle-symbols.txt')
    root = work / 'execution-root'
    root.mkdir()
    (root / 'etc').mkdir()
    shutil.copy2(work / 'oracle', root / 'oracle')
    observations = {}
    outcomes = []
    audits = {"source_sha256": source_sha256, "workload": fixture.artifact_record(source),
              "object": fixture.artifact_record(obj), "artifacts": {}}
    server, ready = fixture.start_server(work / 'dns-events.json')
    (work / 'dns-ready.json').write_text(json.dumps(ready, indent=2, sort_keys=True) + '\n')
    def execute(label: str, arguments: list[str]) -> None:
        for case in CASES:
            status, stdout, stderr = fixture.run_chroot_raw(root, [*arguments, case], 45)
            (work / f'{label}-{case}.stdout').write_bytes(stdout)
            (work / f'{label}-{case}.stderr').write_bytes(stderr)
            outcomes.append({'entry': label, 'case': case, 'exit_status': status})
            (work / 'execution-status.json').write_text(json.dumps(outcomes, indent=2) + '\n')
            if status != 0:
                raise RuntimeError(f'{label}/{case} exited {status}: {stderr.decode(errors="replace")}')
            if label == 'oracle': observations[case] = (stdout, stderr)
            elif observations[case] != (stdout, stderr):
                raise RuntimeError(f'raw musl comparison differs: {label}/{case}')
    try:
        execute('oracle', ['/oracle'])
        if static is not None:
            for mode in ('static', 'static-pie'):
                binary = work / mode
                option = '--static-et-exec' if mode == 'static' else '--static-pie'
                receipt = work / f'{mode}.receipt.json'
                checked([static / 'bin/crabc-cc', option, '--link-receipt', receipt.name,
                         obj, '-o', binary], work / f'{mode}-link.log', cwd=work)
                audits['artifacts'][mode] = {
                    'receipt': fixture.static_receipt_audit(static, option, obj, binary, receipt),
                    'elf': fixture.elf_audit(binary, mode=mode, dynamic=False)}
                symbols(binary, False, work / f'{mode}-symbols.txt')
                shutil.copy2(binary, root / mode)
                execute(mode, ['/' + mode])
        symbols(dynamic / 'usr/lib/libc.so', True, work / 'dynamic-provider-symbols.txt')
        shutil.copytree(dynamic, root, dirs_exist_ok=True, symlinks=True)
        for mode in ('pie', 'non-pie'):
            binary = work / f'dynamic-{mode}'
            checked([dynamic / 'bin/crabc-cc-dynamic', '--dynamic-' + mode, obj, '-o', binary], work / f'{mode}-link.log')
            audits['artifacts']['dynamic-' + mode] = {
                'receipt': fixture.dynamic_receipt_audit(dynamic, '--dynamic-' + mode,
                                                        obj, binary, Path(str(binary) + '.crabc-link.json')),
                'elf': fixture.elf_audit(binary, mode='dynamic-' + mode, dynamic=True)}
            shutil.copy2(binary, root / f'dynamic-{mode}')
            execute(mode + '-kernel', ['/dynamic-' + mode])
            execute(mode + '-direct', ['/lib/ld-crabc-x86_64.so.1', '/dynamic-' + mode])
    finally:
        fixture.stop_server(server)
    events, error = fixture.load_events(work / 'dns-events.json')
    if error: raise RuntimeError(error)
    # Every successful arm must have exercised both DNS transport paths and PTR.
    arms = 7 if static is not None else 5
    for name, qtype, transport in (('a.example.test.', 1, 'udp'),
                                   ('tc.example.test.', 1, 'tcp'),
                                   ('42.100.51.198.in-addr.arpa.', 12, 'udp')):
        count = sum(event.get('name') == name and event.get('qtype') == qtype and event.get('transport') == transport for event in events)
        if count < arms: raise RuntimeError(f'incomplete DNS event evidence: {name}/{transport}: {count} < {arms}')
    expected = arms * len(CASES)
    if len(outcomes) != expected or any(row['exit_status'] != 0 for row in outcomes):
        raise RuntimeError('incomplete classic netdb execution matrix')
    if source_digest() != source_sha256 or fixture.artifact_record(obj) != audits['object']:
        raise RuntimeError('classic netdb source or shared application object changed during execution')
    (work / 'artifact-audits.json').write_text(json.dumps(audits, indent=2, sort_keys=True) + '\n')
    print(f'owned classic netdb: PASS ({len(CASES)} scenarios, same installed object, {arms} musl/owned entry arms); evidence: {work}', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--static-sysroot', type=Path)
    parser.add_argument('--dynamic-sysroot', type=Path)
    args = parser.parse_args()
    work = physical(args.work, 'evidence')
    print(f'classic netdb evidence: {work}', flush=True)
    if args.action == 'prepare': prepare(work)
    else:
        static = physical(args.static_sysroot, 'static product') if args.static_sysroot else None
        dynamic = physical(args.dynamic_sysroot, 'dynamic product')
        run(work, static, dynamic)

if __name__ == '__main__':
    try: main()
    except (RuntimeError, OSError, ValueError) as error:
        raise SystemExit(f'owned classic netdb: ERROR: {error}')
