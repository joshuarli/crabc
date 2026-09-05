#!/usr/bin/env python3
"""Activate private loopback for the finite owned DNS qualification leaves."""
from __future__ import annotations
import fcntl
import os
from pathlib import Path
import socket
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
LEAVES = {
    ROOT / 'compat/x86_64/run_owned_classic_netdb.sh': 'CRABC_CLASSIC_NETDB',
    ROOT / 'compat/x86_64/run_owned_resolver_cancellation.sh': 'CRABC_RESOLVER_CANCELLATION',
}


def activate_loopback(prefix: str) -> None:
    interfaces = {line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:] if ':' in line}
    if interfaces != {'lo'}:
        raise RuntimeError('DNS namespace must contain only lo')
    parent = os.environ.get(prefix + '_PARENT_NETNS')
    if not parent or os.readlink('/proc/self/ns/net') == parent:
        raise RuntimeError('DNS helper requires a newly created network namespace')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        result = fcntl.ioctl(control, 0x8913, struct.pack('16sH22x', b'lo', 0))
        flags = struct.unpack_from('H', result, 16)[0]
        fcntl.ioctl(control, 0x8914, struct.pack('16sH22x', b'lo', flags | 1))


def run_leaf(fixed_leaf: Path | None = None) -> None:
    if len(sys.argv) != 3:
        raise RuntimeError('DNS helper requires one fixed leaf and one installed product')
    leaf = Path(sys.argv[1])
    if leaf not in LEAVES or fixed_leaf is not None and leaf != fixed_leaf:
        raise RuntimeError('DNS helper accepts only its fixed qualification leaves')
    product = Path(sys.argv[2])
    if product.is_symlink() or not product.is_dir() or product.resolve(strict=True) != product or not product.is_relative_to(ROOT / '.work'):
        raise RuntimeError('DNS product must be a physical checkout .work directory')
    prefix = LEAVES[leaf]
    activate_loopback(prefix)
    os.environ[prefix + '_ISOLATION'] = 'user-net-namespace'
    os.execvp('bash', ['bash', str(leaf), str(product)])


if __name__ == '__main__':
    run_leaf()
