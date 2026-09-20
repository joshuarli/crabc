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

import owned_classic_netdb_component_receipt as receipt

ROOT = Path(__file__).resolve().parents[2]
# The receipt owns this closed roster.  Keeping the producer on the same
# tuple prevents prose or a second list from silently dropping a scenario.
CASES = receipt.CASES
PROVIDERS = set(receipt.PROVIDERS)


def physical(path: Path, label: str) -> Path:
    result = path.resolve(strict=True)
    if path.is_symlink() or not result.is_dir() or not result.is_relative_to(ROOT / '.work'):
        raise RuntimeError(f'{label} must be a physical checkout .work directory')
    return result


class CommandJournal:
    """Keep each fixed producer command's argv and raw streams separately."""

    def __init__(self, work: Path):
        self.work = work
        self.records: dict[str, dict[str, object]] = {}

    def record(self, label: str, arguments: list[str | Path], stdout: bytes, stderr: bytes, status: int) -> None:
        if label in self.records:
            raise RuntimeError(f'duplicate classic netdb command label: {label}')
        argv = [str(argument) for argument in arguments]
        paths = {
            'argv': self.work / f'{label}.argv.json',
            'stdout': self.work / f'{label}.stdout',
            'stderr': self.work / f'{label}.stderr',
            'status': self.work / f'{label}.status',
        }
        paths['argv'].write_bytes(json.dumps(argv, separators=(',', ':')).encode() + b'\n')
        paths['stdout'].write_bytes(stdout)
        paths['stderr'].write_bytes(stderr)
        paths['status'].write_bytes(f'{status}\n'.encode())
        self.records[label] = {name: receipt.identity(ROOT, path) for name, path in paths.items()}


def checked(arguments: list[str | Path], log: Path, *, cwd: Path = ROOT, journal: CommandJournal | None = None,
            label: str | None = None) -> None:
    result = subprocess.run(list(map(str, arguments)), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log.write_bytes(result.stdout + result.stderr)
    if journal is not None:
        if label is None:
            raise RuntimeError('classic netdb journal entry has no label')
        journal.record(label, arguments, result.stdout, result.stderr, result.returncode)
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


def symbols(binary: Path, dynamic: bool, destination: Path, journal: CommandJournal, label: str) -> None:
    checked(['/usr/bin/readelf', '--wide', '--dyn-syms' if dynamic else '--syms', binary], destination,
            journal=journal, label=label)
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
    execution_mode = receipt.FULL_MODE if static is not None else receipt.DYNAMIC_MODE
    source_product_before = receipt.source_product_seal(ROOT, static, dynamic)
    tools_before = receipt.tool_roster(ROOT, dynamic, static)
    (work / 'source-product-before.json').write_bytes(receipt.canonical(source_product_before))
    (work / 'tools-before.json').write_bytes(receipt.canonical(tools_before))
    journal = CommandJournal(work)
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
    header_root = (static or dynamic) / 'usr/include'
    checked(['/usr/bin/gcc', '-nostdinc', '-isystem', header_root,
             '-std=c11', '-fno-builtin', '-E', '-H', source], work / 'header-trace.log',
            journal=journal, label='header-trace')
    checked([compiler, *flags, '-std=c11', '-fno-builtin', '-c', source, '-o', obj], work / 'compile.log',
            journal=journal, label='compile')
    checked(['/usr/local/bin/crabc-x86_64-musl-gcc', '-static', '-fno-pie', '-no-pie', '-pthread', obj, '-o', work / 'oracle'],
            work / 'oracle-link.log', journal=journal, label='oracle-link')
    symbols(work / 'oracle', False, work / 'oracle-symbols.txt', journal, 'oracle-symbols')
    root = work / 'execution-root'
    root.mkdir()
    (root / 'etc').mkdir()
    shutil.copy2(work / 'oracle', root / 'oracle')
    observations = {}
    association_differences = []
    outcomes = []
    executions = []
    audits = {"source_sha256": source_sha256, "workload": fixture.artifact_record(source),
              "object": fixture.artifact_record(obj), "artifacts": {}}
    server, ready = fixture.start_server(work / 'dns-events.json')
    (work / 'dns-ready.json').write_text(json.dumps(ready, indent=2, sort_keys=True) + '\n')
    def execute(root: Path, label: str, arguments: list[str]) -> None:
        for case in CASES:
            status, stdout, stderr = fixture.run_chroot_raw(root, [*arguments, case], 45)
            stdout_path = work / f'{label}-{case}.stdout'
            stderr_path = work / f'{label}-{case}.stderr'
            argv_path = work / f'{label}-{case}.argv.json'
            status_path = work / f'{label}-{case}.status'
            stdout_path.write_bytes(stdout)
            stderr_path.write_bytes(stderr)
            argv_path.write_bytes(json.dumps([*arguments, case], separators=(',', ':')).encode() + b'\n')
            status_path.write_bytes(f'{status}\n'.encode())
            executions.append({'entry': label, 'case': case, 'argv': receipt.identity(ROOT, argv_path),
                               'stdout': receipt.identity(ROOT, stdout_path), 'stderr': receipt.identity(ROOT, stderr_path),
                               'status': receipt.identity(ROOT, status_path)})
            outcomes.append({'entry': label, 'case': case, 'exit_status': status})
            (work / 'execution-status.json').write_text(json.dumps(outcomes, indent=2) + '\n')
            if status != 0:
                raise RuntimeError(f'{label}/{case} exited {status}: {stderr.decode(errors="replace")}')
            if label == 'oracle': observations[case] = (stdout, stderr)
            elif observations[case] != (stdout, stderr):
                # musl associates this selected C reply by ID alone.  The
                # source-bounded batch deliberately also requires an exact
                # echoed question, so its correct follow-up answer is a
                # recorded project boundary rather than a false equivalence.
                if case == 'dns-batch' and stderr == observations[case][1] and stdout == b'wrong-association=198.51.100.50\nclassic netdb scenario passed\n':
                    association_differences.append({'entry': label, 'case': case,
                                                    'musl_stdout': receipt.ASSOCIATION_MUSL,
                                                    'owned_stdout': receipt.ASSOCIATION_OWNED, 'stderr': ''})
                else:
                    raise RuntimeError(f'raw musl comparison differs: {label}/{case}')
    try:
        execute(root, 'oracle', ['/oracle'])
        if static is not None:
            for static_mode in ('static', 'static-pie'):
                binary = work / static_mode
                option = '--static-et-exec' if static_mode == 'static' else '--static-pie'
                link_receipt = work / f'{static_mode}.crabc-link.json'
                checked([static / 'bin/crabc-cc', option, '--link-receipt', link_receipt.name,
                         obj, '-o', binary], work / f'{static_mode}-link.log', cwd=work, journal=journal, label=f'{static_mode}-link')
                audits['artifacts'][static_mode] = {
                    'receipt': fixture.static_receipt_audit(static, option, obj, binary, link_receipt),
                    'elf': fixture.elf_audit(binary, mode=static_mode, dynamic=False)}
                symbols(binary, False, work / f'{static_mode}-symbols.txt', journal, f'{static_mode}-symbols')
                shutil.copy2(binary, root / static_mode)
                execute(root, static_mode, ['/' + static_mode])
        symbols(dynamic / 'usr/lib/libc.so', True, work / 'dynamic-provider-symbols.txt', journal, 'dynamic-provider-symbols')
        payloads = {}
        for dynamic_mode in ('pie', 'non-pie'):
            binary = work / f'dynamic-{dynamic_mode}'
            checked([dynamic / 'bin/crabc-cc-dynamic', '--dynamic-' + dynamic_mode, obj, '-o', binary], work / f'{dynamic_mode}-link.log',
                    journal=journal, label=f'dynamic-{dynamic_mode}-link')
            audits['artifacts']['dynamic-' + dynamic_mode] = {
                'receipt': fixture.dynamic_receipt_audit(dynamic, '--dynamic-' + dynamic_mode,
                                                        obj, binary, Path(str(binary) + '.crabc-link.json')),
                'elf': fixture.elf_audit(binary, mode='dynamic-' + dynamic_mode, dynamic=True)}
            dynamic_root = work / f'dynamic-{dynamic_mode}-root'
            dynamic_root.mkdir()
            (dynamic_root / 'etc').mkdir()
            shutil.copytree(dynamic, dynamic_root, dirs_exist_ok=True, symlinks=True)
            consumer = dynamic_root / 'consumer'
            shutil.copy2(binary, consumer)
            payload = receipt.payload_record(dynamic, dynamic_root, binary, consumer)
            payload_record = work / f'dynamic-{dynamic_mode}-execution-payload.json'
            payload_before = work / f'dynamic-{dynamic_mode}-execution-payload-before.json'
            payload_record.write_bytes(receipt.canonical(payload))
            payload_before.write_bytes(receipt.canonical(payload))
            execute(dynamic_root, 'dynamic-' + dynamic_mode + '-kernel', ['/consumer'])
            execute(dynamic_root, 'dynamic-' + dynamic_mode + '-direct', ['/lib/ld-crabc-x86_64.so.1', '/consumer'])
            payload_after = work / f'dynamic-{dynamic_mode}-execution-payload-after.json'
            payload_after.write_bytes(receipt.canonical(receipt.payload_record(dynamic, dynamic_root, binary, consumer)))
            payloads[dynamic_mode] = {'record': receipt.identity(ROOT, payload_record),
                              'before': receipt.identity(ROOT, payload_before), 'after': receipt.identity(ROOT, payload_after)}
    finally:
        fixture.stop_server(server)
    events, error = fixture.load_events(work / 'dns-events.json')
    if error: raise RuntimeError(error)
    # Every successful arm must have exercised both DNS transport paths and PTR.
    arms = 7 if static is not None else 5
    for name, qtype, transport in (('a.example.test.', 1, 'udp'),
                                   ('tc.example.test.', 1, 'tcp'),
                                   ('42.100.51.198.in-addr.arpa.', 12, 'udp'),
                                   ('order-after.example.test.', 1, 'udp'),
                                   ('order-before.example.test.', 1, 'udp'),
                                   ('order-empty.example.test.', 1, 'udp'),
                                   ('order-cap.example.test.', 1, 'udp'),
                                   ('order-aaaa.example.test.', 28, 'udp'),
                                   ('prefix-a.example.test.', 1, 'udp'),
                                   ('prefix-aaaa.example.test.', 28, 'udp'),
                                   ('prefix-authority.example.test.', 1, 'udp'),
                                   ('prefix-rdata.example.test.', 1, 'udp'),
                                   ('prefix-additional.example.test.', 1, 'udp'),
                                   ('prefix-empty.example.test.', 1, 'udp'),
                                   ('prefix-tcp.example.test.', 1, 'tcp'),
                                   ('batch.example.test.', 1, 'udp'),
                                   ('batch.example.test.', 28, 'udp'),
                                   ('batch-mixed.example.test.', 1, 'udp'),
                                   ('batch-mixed.example.test.', 1, 'tcp'),
                                   ('batch-mixed.example.test.', 28, 'udp'),
                                   ('wrong-association.example.test.', 1, 'udp'),
                                   ('refused.example.test.', 1, 'udp'),
                                   ('47.100.51.198.in-addr.arpa.', 12, 'udp')):
        count = sum(event.get('name') == name and event.get('qtype') == qtype and event.get('transport') == transport for event in events)
        if count < arms: raise RuntimeError(f'incomplete DNS event evidence: {name}/{transport}: {count} < {arms}')
    for role in ('valid', 'drop', 'fallback'):
        for qtype in (1, 28):
            count = sum(event.get('role') == role and event.get('name') == 'batch.example.test.'
                        and event.get('qtype') == qtype and event.get('transport') == 'udp' for event in events)
            if count < arms:
                raise RuntimeError(f'incomplete DNS batch fanout evidence: {role}/{qtype}: {count} < {arms}')
        for qtype in (1, 28):
            count = sum(event.get('role') == role and event.get('name') == 'batch-retry.example.test.'
                        and event.get('qtype') == qtype and event.get('transport') == 'udp' for event in events)
            if count < arms * 2:
                raise RuntimeError(f'incomplete DNS batch retry evidence: {role}/{qtype}: {count} < {arms * 2}')
    servfail = sum(event.get('name') == 'servfail.example.test.' and event.get('transport') == 'udp'
                   and event.get('action') == 'servfail' for event in events)
    # The recorded musl source schedule sends the three configured endpoints,
    # then consumes one immediate SERVFAIL resend before the next poll; the
    # bounded `2*nqueries` counter prevents another retry round here.
    if servfail != arms * 4:
        raise RuntimeError(f'unbounded or incomplete SERVFAIL retry evidence: {servfail} != {arms * 4}')
    expected = arms * len(CASES)
    if len(outcomes) != expected or any(row['exit_status'] != 0 for row in outcomes):
        raise RuntimeError('incomplete classic netdb execution matrix')
    if source_digest() != source_sha256 or fixture.artifact_record(obj) != audits['object']:
        raise RuntimeError('classic netdb source or shared application object changed during execution')
    (work / 'artifact-audits.json').write_text(json.dumps(audits, indent=2, sort_keys=True) + '\n')
    (work / 'exact-question-association-differences.json').write_text(
        json.dumps(association_differences, indent=2, sort_keys=True) + '\n')
    source_product_after = receipt.source_product_seal(ROOT, static, dynamic)
    tools_after = receipt.tool_roster(ROOT, dynamic, static)
    if source_product_before != source_product_after or tools_before != tools_after:
        raise RuntimeError('classic netdb source, product, or tool changed during execution')
    (work / 'source-product-after.json').write_bytes(receipt.canonical(source_product_after))
    (work / 'tools-after.json').write_bytes(receipt.canonical(tools_after))
    links = {'dynamic-pie': receipt.identity(ROOT, work / 'dynamic-pie.crabc-link.json'),
             'dynamic-non-pie': receipt.identity(ROOT, work / 'dynamic-non-pie.crabc-link.json')}
    if static is not None:
        links.update({'static': receipt.identity(ROOT, work / 'static.crabc-link.json'),
                      'static-pie': receipt.identity(ROOT, work / 'static-pie.crabc-link.json')})
    report = {
        'schema': receipt.SCHEMA, 'component': receipt.COMPONENT, 'source_mount': receipt.SOURCE_MOUNT,
        'execution_mode': execution_mode, 'scope': list(receipt.SCOPE), 'cases': list(receipt.CASES),
        'behavior_roster': receipt.BEHAVIOR_ROSTER, 'sources': source_product_before['sources'],
        'products': {'dynamic': dynamic.relative_to(ROOT).as_posix(),
                     **({'static': static.relative_to(ROOT).as_posix()} if static is not None else {})},
        'seals': {name: receipt.identity(ROOT, work / f'{name}.json') for name in
                  ('source-product-before', 'source-product-after', 'tools-before', 'tools-after')},
        'image': {'id': receipt.PINNED_IMAGE, 'manifest': receipt.identity(ROOT, ROOT / receipt.IMAGE_MANIFEST)},
        'workload': receipt.identity(ROOT, obj), 'commands': journal.records, 'links': links, 'payloads': payloads,
        'executions': executions, 'network': receipt.identity(ROOT, work / 'network-isolation.json'),
        'dns': {'ready': receipt.identity(ROOT, work / 'dns-ready.json'), 'events': receipt.identity(ROOT, work / 'dns-events.json')},
        'audits': receipt.identity(ROOT, work / 'artifact-audits.json'), 'association_differences': association_differences,
        'family_completion': False, 'promotion_ready': False, 'public_support': False,
    }
    (work / 'classic-netdb-products.json').write_bytes(receipt.canonical(report))
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
