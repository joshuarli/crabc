#!/usr/bin/env python3
"""Exercise guarded decoded EH metadata through standalone or installed products."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import resource
import subprocess
import sys
import tomllib

from metadata_bounds import assert_patched_provider, digest, run_fixture


EXPECTED_OUTPUT = (
    'mapped unwind=5\nmapped wait=0\n'
    'unmapped unwind=3\nunmapped wait=0\n'
    'unreadable unwind=3\nunreadable wait=0\n'
    'oversized unwind=3\noversized wait=0\n'
    'truncated unwind=3\ntruncated wait=0\n'
    'long-fde unwind=5\nlong-fde wait=0\n'
    'direct-pointer unwind=0\ndirect-pointer wait=0\n'
    'indirect-pointer unwind=0\nindirect-pointer wait=0\n'
    'guarded EH frame metadata rejected\n'
)

CASES = {
    'mapped': 5,
    'unmapped': 3,
    'unreadable': 3,
    'oversized': 3,
    'truncated': 3,
    'long-fde': 5,
    'direct-pointer': 0,
    'indirect-pointer': 0,
}


def assert_case_result(label: str, status: int, stdout: str, stderr: str) -> None:
    expected = f'{label} unwind={CASES[label]}\n{label} wait=0\n'
    if status != 0 or stdout != expected or stderr:
        raise RuntimeError(f'{label} failed guarded metadata execution: status={status}')


def run_installed(static_preparation: Path, dynamic_qualification: Path,
                  provider_root: Path, output: Path, image_id: str) -> Path:
    import owned_cleanup as owned

    compat = owned.CHECKOUT / 'compat/x86_64'
    if str(compat) not in sys.path:
        sys.path.insert(0, str(compat))
    import owned_dynamic_qualification as qualification
    import owned_posix_static_products as static_products

    output = owned.work_child(output, 'guarded installed metadata output')
    if not image_id.startswith('sha256:') or len(image_id) != 71:
        raise RuntimeError('installed metadata requires an immutable image digest')
    source = qualification.source_digest()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=owned.CHECKOUT, text=True).strip()
    static_preparation = owned.physical(static_preparation, 'static preparation')
    dynamic_qualification = owned.physical(dynamic_qualification, 'dynamic qualification')
    static_receipt = static_products.validate_receipt(owned.CHECKOUT, static_preparation)
    dynamic_receipt = qualification.validate_receipt(dynamic_qualification)
    if static_receipt['source'] != {'revision': revision, 'content_sha256': source}:
        raise RuntimeError('static preparation differs from the current source')
    if dynamic_receipt['source_sha256'] != source:
        raise RuntimeError('dynamic qualification differs from the current source')
    if dynamic_receipt['status'] != 'qualified-pending-review':
        raise RuntimeError('dynamic qualification has not passed its product matrix')
    static_root = owned.CHECKOUT / static_receipt['products']['primary']['path']
    dynamic_root = dynamic_qualification.parent / 'installed'
    static_product = owned.product_snapshot(static_root, 'static')
    dynamic_product = owned.product_snapshot(dynamic_root, 'dynamic')
    output.mkdir(mode=0o755)
    output = owned.physical(output, 'guarded installed metadata output', directory=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    channel = tomllib.loads((owned.CHECKOUT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    environment = owned.clean_environment()
    toolchain = owned.run_logged(['rustup', 'run', channel, 'rustc', '-Vv'], environment,
                                 output / 'toolchain.log', 'guarded metadata compiler identity')
    provider = owned.provider_snapshot(owned.physical(provider_root, 'selected provider', directory=True), toolchain)
    assert_patched_provider(provider['record'], provider['archive']['sha256'])
    fixture = owned.physical(owned.ROOT / 'fixtures/guarded_eh_frame.rs', 'guarded metadata fixture')
    receipt = {
        'schema': 1, 'scope': 'source-bound installed guarded EH metadata development proof',
        'qualified': False, 'source': {'revision': revision, 'content_sha256': source},
        'image_id': image_id,
        'static_preparation': owned.record_file(static_preparation, 'static preparation'),
        'dynamic_qualification': owned.record_file(dynamic_qualification, 'dynamic qualification'),
        'products': {'static': static_product, 'dynamic': dynamic_product},
        'provider': {'archive': provider['archive'], 'provenance': provider['provenance']},
        'fixture': owned.record_file(fixture, 'guarded metadata fixture'),
        'cases': {},
    }
    for mode, product in (('static', static_product), ('dynamic', dynamic_product)):
        application = output / mode
        application.mkdir(mode=0o755)
        binary = application / 'guarded-eh-frame'
        libdir = Path(owned.run_logged(
            ['rustup', 'run', channel, 'rustc', '--target', owned.TARGET, '--print', 'target-libdir'],
            environment, application / 'target-libdir.log', f'{mode} target library discovery',
        ).strip())
        libdir = owned.physical(libdir, f'{mode} stock target library directory', directory=True)
        link_env = dict(environment)
        link_env.update({
            'CRABC_OWNED_RUST_LINK_MODE': mode,
            'CRABC_OWNED_RUST_PRODUCT': product['root'],
            'CRABC_OWNED_RUST_PROVIDER': provider['archive']['path'],
            'CRABC_OWNED_RUST_STOCK_LIBDIR': str(libdir),
            'CRABC_OWNED_RUST_APPLICATION_ROOT': str(application),
            'CRABC_OWNED_RUST_CHANNEL': channel,
        })
        command = ['rustup', 'run', channel, 'rustc', '--edition=2024', '--target', owned.TARGET,
                   '-C', 'panic=unwind', '-C', 'force-unwind-tables=yes',
                   '-C', 'link-self-contained=no', '-C', 'target-feature=-crt-static',
                   '-C', f'linker={owned.ROOT / "owned_rust_link.py"}',
                   '-C', 'link-arg=-Wl,--eh-frame-hdr']
        if mode == 'static':
            command.extend(('-C', 'relocation-model=static'))
        command.extend((str(fixture), '-o', str(binary)))
        owned.run_logged(command, link_env, application / 'compile.log', f'{mode} guarded metadata compile')
        binary = owned.physical(binary, f'{mode} guarded metadata executable', executable=True)
        link_path = owned.physical(Path(str(binary) + '.crabc-owned-rust-link.json'), f'{mode} link receipt')
        link = owned.json_object(link_path, f'{mode} link receipt')
        if (link.get('mode') != mode or link.get('output') != owned.record_file(binary, f'{mode} binary')
                or link.get('provider_archive') != provider['archive']):
            raise RuntimeError(f'{mode} linker did not select the authenticated product and provider')
        owned.assert_nonpromoting(link, f'{mode} link receipt')
        trace = link.get('resolved_input_trace', '')
        if ('libcrabc-unwind.a' not in trace or any(token in trace for token in ('libgcc', 'libunwind'))):
            raise RuntimeError(f'{mode} link trace admits an ambient unwind provider')
        mode_record = {'binary': owned.record_file(binary, f'{mode} binary'),
                       'link_receipt': owned.record_file(link_path, f'{mode} link receipt'),
                       'compile_log': owned.record_file(application / 'compile.log', f'{mode} compile log'),
                       'cases': {}}
        loader = owned.physical(dynamic_root / 'lib/ld-crabc-x86_64.so.1', 'owned dynamic loader', executable=True)
        for label in CASES:
            execution = ([str(binary)] if mode == 'static' else
                         [str(loader), '--library-path', str(dynamic_root / 'usr/lib'), str(binary)])
            execution.extend(('--case', label))
            try:
                result = subprocess.run(execution, env=environment, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
                status, stdout, stderr = result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired as error:
                status = 124
                stdout = error.stdout.decode(errors='replace') if isinstance(error.stdout, bytes) else error.stdout or ''
                stderr = error.stderr.decode(errors='replace') if isinstance(error.stderr, bytes) else error.stderr or ''
            stdout_path = application / f'{label}.stdout'
            stderr_path = application / f'{label}.stderr'
            status_path = application / f'{label}.status'
            stdout_path.write_text(stdout)
            stderr_path.write_text(stderr)
            status_path.write_text(f'{status}\n')
            mode_record['cases'][label] = {
                'command': execution, 'status': status,
                'stdout': owned.record_file(stdout_path, f'{mode} {label} stdout'),
                'stderr': owned.record_file(stderr_path, f'{mode} {label} stderr'),
                'status_file': owned.record_file(status_path, f'{mode} {label} status'),
            }
            assert_case_result(label, status, stdout, stderr)
        receipt['cases'][mode] = mode_record
    if qualification.source_digest() != source:
        raise RuntimeError('source changed during installed guarded metadata execution')
    owned.assert_same_product(static_product, 'static')
    owned.assert_same_product(dynamic_product, 'dynamic')
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed-static-preparation', type=Path)
    parser.add_argument('--installed-dynamic-qualification', type=Path)
    parser.add_argument('--provider-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--image-id')
    options = parser.parse_args()
    installed = [options.installed_static_preparation, options.installed_dynamic_qualification,
                 options.provider_root, options.output, options.image_id]
    if any(installed):
        if not all(installed):
            parser.error('installed execution requires both product receipts, provider root, output and image ID')
        print(run_installed(*installed))
        return
    print(run_fixture(
        'unwinder-eh-frame-bounds-runs',
        'guarded_eh_frame.rs',
        EXPECTED_OUTPUT,
        'standalone guarded decoded EH metadata provider regression',
        'guarded-eh-frame-execution.log',
        'guarded-eh-frame',
    ))


if __name__ == '__main__':
    main()
