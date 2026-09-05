#!/usr/bin/env python3
"""Activate lo in the classic netdb case's explicitly created user/net namespace."""
from __future__ import annotations
import fcntl
import os
from pathlib import Path
import socket
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
LEAF = ROOT / 'compat/x86_64/run_owned_classic_netdb.sh'


def activate_loopback() -> None:
    interfaces = {line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:] if ':' in line}
    if interfaces != {'lo'}:
        raise RuntimeError('classic netdb namespace must contain only lo')
    parent = os.environ.get('CRABC_CLASSIC_NETDB_PARENT_NETNS')
    if not parent or os.readlink('/proc/self/ns/net') == parent:
        raise RuntimeError('classic netdb helper requires a newly created network namespace')
    request = struct.pack('16sH22x', b'lo', 0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        result = fcntl.ioctl(control, 0x8913, request)  # SIOCGIFFLAGS
        flags = struct.unpack_from('H', result, 16)[0]
        fcntl.ioctl(control, 0x8914, struct.pack('16sH22x', b'lo', flags | 1))  # SIOCSIFFLAGS/IFF_UP


def main() -> None:
    if len(sys.argv) != 3 or Path(sys.argv[1]) != LEAF:
        raise RuntimeError('classic netdb helper accepts only its fixed leaf and one installed product')
    product = Path(sys.argv[2])
    if product.is_symlink() or product.resolve(strict=True) != product or not product.is_relative_to(ROOT / '.work'):
        raise RuntimeError('classic netdb product must be a physical checkout .work directory')
    activate_loopback()
    os.environ['CRABC_CLASSIC_NETDB_ISOLATION'] = 'user-net-namespace'
    os.execvp('bash', ['bash', str(LEAF), str(product)])


if __name__ == '__main__':
    main()
