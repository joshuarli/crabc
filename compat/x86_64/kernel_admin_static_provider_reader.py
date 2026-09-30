#!/usr/bin/env python3
"""Validate owned static kernel-administration provider ELF metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

import core_image
import native_shadow_receipt as shadow
from owned_posix_product_evidence import validate_link

RUNNER = 'owned-kernel-admin'
EXECUTIONS = ('static', 'static-pie', 'dynamic-pie-kernel', 'dynamic-pie-direct',
              'dynamic-non-pie-kernel', 'dynamic-non-pie-direct')
SUCCESS = b'kernel-admin-observations-ok\n'

PROVIDERS = ("arch_prctl", "iopl", "ioperm")
REQUIRED_METADATA = ("FUNC", "GLOBAL", "DEFAULT")


def validate_table(table: str) -> None:
    """Require one strong default-visible function definition per provider."""

    rows: dict[str, list[list[str]]] = {provider: [] for provider in PROVIDERS}
    for line in table.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in rows:
            rows[fields[7]].append(fields)

    for provider, definitions in rows.items():
        if len(definitions) != 1:
            raise ValueError(
                f"static provider {provider} has {len(definitions)} symbol rows, expected one"
            )
        fields = definitions[0]
        if tuple(fields[3:6]) != REQUIRED_METADATA or fields[6] == "UND":
            actual = " ".join(fields[3:7])
            expected = " ".join(REQUIRED_METADATA)
            raise ValueError(
                f"static provider {provider} must be {expected}, got {actual}"
            )


def validate_component(root: Path = ROOT) -> shadow.Receipt:
    """Reread original comparisons, providers and four physical owned links."""
    receipt = shadow.read_receipt(root, RUNNER)
    if receipt.case_ids() != ['providers', *('compare-' + label for label in EXECUTIONS)]:
        raise ValueError('kernel-admin comparison roster differs')
    if set(receipt.parameters) != {'CORE_IMAGE', 'STATIC_PRODUCT', 'DYNAMIC_PRODUCT'}:
        raise ValueError('kernel-admin product parameters differ')
    if receipt.parameters['CORE_IMAGE'] != core_image.CORE_IMAGE_ID:
        raise ValueError('kernel-admin core image differs')
    document = json.loads(receipt.path.read_text())
    paths = [document['work'], receipt.parameters['STATIC_PRODUCT'], receipt.parameters['DYNAMIC_PRODUCT']]
    directories = []
    for relative in paths:
        if not isinstance(relative, str) or not relative.startswith('.work/') or '..' in Path(relative).parts:
            raise ValueError('kernel-admin input escapes checkout scratch')
        path = root / relative
        if not path.is_dir() or path.resolve() != path:
            raise ValueError('kernel-admin input is not a retained physical directory')
        directories.append(path)
    work, static, dynamic = directories
    products = {
        'probe': root / 'compat/x86_64/libc_kernel_admin_probe.c',
        'workload': work / 'workload.o', 'oracle': work / 'root/oracle',
        'static': work / 'root/static', 'static-pie': work / 'root/static-pie',
        'dynamic-pie': work / 'root/dynamic-pie', 'dynamic-non-pie': work / 'root/dynamic-non-pie',
        'static-libc': static / 'usr/lib/libc.a', 'dynamic-libc': dynamic / 'usr/lib/libc.so',
        'dynamic-loader': dynamic / 'lib/ld-crabc-x86_64.so.1',
        'static-provenance': static / 'share/crabc/libc-static.provenance.json',
        'dynamic-provenance': dynamic / 'share/crabc/libc-shared.provenance.json',
    }
    if set(receipt.products) != set(products):
        raise ValueError('kernel-admin retained product roster differs')
    for name, path in products.items():
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise ValueError(f'kernel-admin physical product is missing: {name}')
        content = path.read_bytes()
        if receipt.products[name] != {'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}:
            raise ValueError(f'kernel-admin current product differs: {name}')
    for name, relative in (('dynamic-libc', 'usr/lib/libc.so'), ('dynamic-loader', 'lib/ld-crabc-x86_64.so.1')):
        loaded = work / 'root' / relative
        if (not loaded.is_file() or loaded.is_symlink() or loaded.resolve() != loaded
                or loaded.read_bytes() != products[name].read_bytes()):
            raise ValueError('kernel-admin executed runtime differs from the linked product')
    for case in receipt.cases:
        for relative, record in case['logs'].items():
            path = work / relative
            if not path.is_file() or path.is_symlink() or path.resolve() != path:
                raise ValueError('kernel-admin original raw log is missing')
            content = path.read_bytes()
            if record != {'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}:
                raise ValueError('kernel-admin original raw log differs')
    logs = receipt.path.parent / 'logs'
    required_logs = {'input.sha256', 'input-verified.txt', 'header-trace', 'static-symbols', 'dynamic-symbols'}
    required_logs.update(f'{label}-{provider}.disassembly'
                         for label in ('static-archive', 'shared-libc') for provider in PROVIDERS)
    if not required_logs <= set(receipt.cases[0]['logs']):
        raise ValueError('kernel-admin provider/source evidence is incomplete')
    checksum = ''.join(f"{receipt.products[name]['sha256']}  {products[name]}\n"
                       for name in ('probe', 'workload')).encode()
    verified = ''.join(f'{products[name]}: OK\n' for name in ('probe', 'workload')).encode()
    if (logs / 'input.sha256').read_bytes() != checksum or (logs / 'input-verified.txt').read_bytes() != verified:
        raise ValueError('kernel-admin original source/object verification differs')
    header_trace = (logs / 'header-trace').read_text()
    include = str(dynamic / 'usr/include') + '/'
    header_paths = re.findall(r'^\.+ (.+)$', header_trace, re.MULTILINE)
    if (not header_paths or any(not path.startswith(include) for path in header_paths)
            or any(include + header not in header_paths
                   for header in ('errno.h', 'stdint.h', 'stdio.h', 'sys/io.h', 'sys/syscall.h', 'bits/syscall.h'))):
        raise ValueError('kernel-admin header trace has missing or ambient inputs')
    for label in ('static-archive', 'shared-libc'):
        for provider, number, helper in (('arch_prctl', '9e', 'syscall2'), ('iopl', 'ac', 'syscall1'),
                                        ('ioperm', 'ad', 'syscall3')):
            body = (logs / f'{label}-{provider}.disassembly').read_text()
            if not re.search(r'\$0x' + number + r'(,|\s|$)', body):
                raise ValueError('kernel-admin provider syscall number differs')
            if not re.search(r'\s+syscall(?:\s|$)', body):
                helper_body = (logs / f'{label}-{provider}-{helper}.disassembly').read_text()
                names = re.findall(r'^[0-9a-f]+ <([^>]+)>:', helper_body, re.MULTILINE)
                if (not re.search(r'\s+syscall(?:\s|$)', helper_body)
                        or not any('raw_syscall' in name and helper in name and name in body for name in names)):
                    raise ValueError('kernel-admin raw syscall transfer differs')
            if provider != 'arch_prctl' and re.search(r'(^|\s)(in|out)([bwl])?(\s|$)|(^|\s)(ins|outs)[bwl](\s|$)', body):
                raise ValueError('kernel-admin provider contains a port-I/O instruction')
    original = (logs / 'oracle.status').read_bytes()
    try:
        status = int(original)
    except ValueError as error:
        raise ValueError('kernel-admin oracle status is malformed') from error
    if original != f'{status}\n'.encode() or not 0 <= status <= 85 or status & ~85:
        raise ValueError('kernel-admin oracle is not an I/O errno fingerprint')
    for label in ('oracle', *EXECUTIONS):
        if ((logs / (label + '.status')).read_bytes() != original
                or (logs / (label + '.stdout')).read_bytes() != SUCCESS
                or (logs / (label + '.stderr')).read_bytes() != b''):
            raise ValueError('kernel-admin observations did not complete or differ from oracle')
    validate_table((logs / 'static-symbols').read_text())
    validate_table((logs / 'dynamic-symbols').read_text())
    for product, command in ((static / 'usr/lib/libc.a', ['--wide', '--symbols']),
                             (dynamic / 'usr/lib/libc.so', ['--dyn-syms', '--wide'])):
        table = subprocess.run(['readelf', *command, str(product)], check=True, capture_output=True, text=True)
        validate_table(table.stdout)
    for mode in ('static', 'static-pie', 'pie', 'non-pie'):
        static_mode = mode in ('static', 'static-pie')
        label = mode if static_mode else 'dynamic-' + mode
        executable = products[label]
        link = work / (mode + '.link.json') if static_mode else Path(str(executable) + '.crabc-link.json')
        validate_link(static if static_mode else dynamic, products['workload'], executable, link, mode)
    if shadow.read_receipt(root, RUNNER) != receipt or json.loads(receipt.path.read_text()) != document:
        raise ValueError('kernel-admin receipt changed during validation')
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("table", nargs="?", type=Path, help="raw readelf --symbols output")
    parser.add_argument("--read", action="store_true", help="reread the complete retained installed component")
    args = parser.parse_args()
    if args.read == (args.table is not None):
        parser.error('select TABLE or --read')
    try:
        if args.read:
            validate_component()
            print('kernel-admin installed component: PASS (bounded inputs; no family or public admission)')
        else:
            validate_table(args.table.read_text(encoding="utf-8"))
    except (OSError, ValueError, RuntimeError, shadow.ReceiptError, subprocess.SubprocessError) as error:
        raise SystemExit(f"kernel-admin static provider metadata: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
