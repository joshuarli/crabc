#!/usr/bin/env python3
"""Installed nondefault dynamic allocator ownership and lifecycle comparison.

Products must be explicitly built with the scalar lifecycle audit. The C
baseline remains the accepted backend; this compares transport/ownership, not
full mimalloc algorithm parity or promotion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_x86_64_owned_dynamic_sysroot as producer


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, log):
    result = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {log}')
    return result.stdout.decode()


def execute(argv, work, name, final_worker):
    stdout_path, stderr_path = work / (name + '.stdout'), work / (name + '.stderr')
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        child = subprocess.Popen(list(map(str, argv)), stdin=subprocess.PIPE,
                                 stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            if final_worker:
                # The worker blocks on stdin. Release it only after Linux
                # marks the initial task dead, proving the final-task path.
                deadline = time.monotonic() + 20
                while True:
                    if child.poll() is not None:
                        raise RuntimeError(f'{name} exited before main pthread_exit')
                    status = Path(f'/proc/{child.pid}/task/{child.pid}/stat').read_text()
                    if status[status.rfind(')') + 2:].split()[0] == 'Z':
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f'{name} never completed main pthread_exit')
                    time.sleep(0.01)
                child.stdin.write(b'R')
                child.stdin.flush()
            child.stdin.close()
            status = child.wait(timeout=20)
            if status != 0 or stderr_path.stat().st_size:
                raise RuntimeError(f'{name} failed: status={status}; see {stderr_path}')
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    return stdout_path.read_text()


def validate_product(path, backend):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / '.work'):
        raise RuntimeError('allocator product must be checkout-local')
    producer.installed_driver.validate(path)
    provenance = json.loads((path / 'share/crabc/libc-shared.provenance.json').read_text())
    if (provenance.get('allocator_backend') != backend
            or provenance.get('allocator_lifecycle_test_audit') is not True):
        raise RuntimeError(f'{backend} product lacks explicit allocator/audit selection')
    return path


def run(c_product, native_product, work):
    producer.common.assert_native_target()
    if work.exists() or not work.resolve().is_relative_to(ROOT / '.work'):
        raise RuntimeError('choose a fresh checkout-local work directory')
    work.mkdir(parents=True)
    products = {'accepted-c': validate_product(c_product, 'accepted-c'),
                'native-shadow': validate_product(native_product, 'native-shadow')}
    manifests = {backend: digest(product / 'share/crabc/manifest.json') for backend, product in products.items()}
    c_driver = products['accepted-c'] / 'bin/crabc-cc-dynamic'
    # Both products consume identical application and dependency objects.
    for name in ('probe', 'dso'):
        command([c_driver, '--dynamic-pie', '-std=c11', '-fno-builtin', '-fPIC', '-pthread',
                 '-c', ROOT / f'compat/x86_64/dynamic_native_allocator_{name}.c',
                 '-o', work / f'{name}.o'], work / f'compile-{name}.log')
    tools = producer.common.resolve_pinned_producer_tools()
    rustup = Path(tools['rustup']['path'])
    lld = producer.common.pinned_rustc_sysroot(rustup) / 'lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld'
    outcomes = {}
    for backend, product in products.items():
        driver = product / 'bin/crabc-cc-dynamic'
        backend_work = work / backend
        backend_work.mkdir()
        for graph in ('dependent', 'independent'):
            graph_work = backend_work / graph
            graph_work.mkdir()
            dso = graph_work / 'liballocator-probe.so'
            if graph == 'dependent':
                command([driver, '--dynamic-shared-object', work / 'dso.o', '-o', dso], graph_work / 'dso-link.log')
            else:
                # Deliberately no libc dependency: its unresolved public C
                # imports still bind to the main graph's sole libc. The sealed
                # main driver validates their complete provider closure.
                command([lld, '-shared', '--hash-style=sysv', '-soname', dso.name,
                         work / 'dso.o', '-o', dso], graph_work / 'dso-link.log')
            dynamic = command(['readelf', '-dW', dso], graph_work / 'dso.dynamic')
            if ('(NEEDED)' in dynamic) != (graph == 'dependent'):
                raise RuntimeError('DSO graph prerequisite differs')
            expected = ('DSO_INIT\nMAIN_INIT\nMAIN\nATEXIT\nMAIN_FINI\n'
                        + ('DSO_FINI=1\n' if graph == 'dependent' else 'DSO_FINI=2\n')
                        + 'FLUSH=2\n')
            for mode in ('pie', 'non-pie'):
                executable = graph_work / f'consumer-{mode}'
                command([driver, f'--dynamic-{mode}', '--application-dso', dso,
                         work / 'probe.o', '-o', executable], graph_work / f'{mode}-link.log')
                execution_root = graph_work / f'{mode}-root'
                shutil.copytree(product, execution_root, symlinks=True)
                shutil.copy2(dso, execution_root / 'usr/lib' / dso.name)
                shutil.copy2(executable, execution_root / 'consumer')
                for entry in ('kernel', 'direct'):
                    invocation = ['chroot', execution_root]
                    if entry == 'direct':
                        invocation.append('/lib/ld-crabc-x86_64.so.1')
                    invocation.append('/consumer')
                    for final_worker in (False, True):
                        name = f'{mode}-{entry}-' + ('final-worker' if final_worker else 'main-return')
                        actual = execute([*invocation, *(['final-worker'] if final_worker else [])], graph_work, name, final_worker)
                        if actual != expected:
                            raise RuntimeError(f'{backend}/{graph}/{name}: lifecycle order differs: {actual!r}')
                        outcomes[f'{backend}/{graph}/{name}'] = {'stdout_sha256': digest(graph_work / (name + '.stdout'))}
        producer.installed_driver.validate(product)
        if digest(product / 'share/crabc/manifest.json') != manifests[backend]:
            raise RuntimeError('supplied allocator product changed')
    receipt = {'schema': 'crabc.dynamic-native-allocator-development/v1',
               'qualified': False, 'allocator_promoted': False, 'public_support': False,
               'products': {name: {'path': str(path), 'manifest_sha256': manifests[name]} for name, path in products.items()},
               'objects': {name: digest(work / (name + '.o')) for name in ('probe', 'dso')},
               'cases': outcomes}
    (work / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(work / 'receipt.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-product', type=Path, required=True)
    parser.add_argument('--native-product', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    run(args.c_product, args.native_product, args.work)


if __name__ == '__main__':
    main()
