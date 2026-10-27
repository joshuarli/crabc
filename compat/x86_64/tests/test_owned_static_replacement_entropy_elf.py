"""Entropy replacement ownership regressions on linked native ELF."""
from __future__ import annotations

import importlib.util
import re
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
spec = importlib.util.spec_from_file_location('entropy_elf', ROOT / 'compat/x86_64/owned_static_replacement_entropy_elf.py')
assert spec is not None and spec.loader is not None
entropy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entropy)


class EntropyOwnerTests(unittest.TestCase):
    def test_mold_owners_and_mutations(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            root = Path(directory)
            app, source, archive, binary, link_map = (root / name for name in ('app.o', 'entropy.s', 'libc.a', 'binary', 'binary.map'))
            (root / 'app.s').write_text('.text\n.globl getrandom\n.type getrandom,@function\ngetrandom: ret\n.size getrandom,.-getrandom\n.globl _start\n_start: call getentropy\nret\n')
            source.write_text('.text\n.globl getentropy\n.type getentropy,@function\ngetentropy: mov getrandom@GOTPCREL(%rip),%rax\ncall *%rax\nret\n.size getentropy,.-getentropy\n')
            subprocess.run(['cc', '-c', str(root / 'app.s'), '-o', str(app)], check=True)
            member = root / 'entropy.o'
            subprocess.run(['cc', '-Wa,-mrelax-relocations=no', '-c', str(source), '-o', str(member)], check=True)
            subprocess.run(['ar', 'rcs', str(archive), str(member)], check=True)
            subprocess.run(['mold', '-static', '-e', '_start', '-Map=' + str(link_map), str(app), str(archive), '-o', str(binary)], check=True)
            admitted = {str(app): app, str(archive) + '(entropy.o)': member.read_bytes()}
            entropy.validate_owners(link_map, binary, admitted, str(app), str(archive) + '(entropy.o)')
            original = link_map.read_text()
            link_map.write_text(original.replace(str(app) + ':(.text)', '/foreign.o:(.text)'))
            with self.assertRaises(SystemExit):
                entropy.validate_owners(link_map, binary, admitted, str(app), str(archive) + '(entropy.o)')
            link_map.write_text(original)
            altered = bytearray(binary.read_bytes())
            address = entropy.final_address(binary, 'getrandom')
            offset = entropy.file_offset(altered, address)
            altered[offset] ^= 1
            binary.write_bytes(altered)
            with self.assertRaises(SystemExit):
                entropy.validate_owners(link_map, binary, admitted, str(app), str(archive) + '(entropy.o)')

    def test_static_pie_keeps_unrelocated_tls_got(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            root = Path(directory)
            app, member, archive, binary, link_map = (root / name for name in ('app.o', 'entropy.o', 'libc.a', 'binary', 'binary.map'))
            (root / 'app.s').write_text('.text\n.globl getrandom\n.type getrandom,@function\ngetrandom: ret\n.size getrandom,.-getrandom\n.globl _start\n_start: call getentropy\nret\n')
            (root / 'entropy.s').write_text('.section .tdata,"awT",@progbits\n.globl errno_slot\n.type errno_slot,@tls_object\nerrno_slot: .quad 1\n.size errno_slot,8\n.text\n.globl getentropy\n.type getentropy,@function\ngetentropy: mov getrandom@GOTPCREL(%rip),%rax\nmov errno_slot@gottpoff(%rip),%rcx\ncall *%rax\nret\n.size getentropy,.-getentropy\n')
            subprocess.run(['cc', '-c', str(root / 'app.s'), '-o', str(app)], check=True)
            subprocess.run(['cc', '-Wa,-mrelax-relocations=no', '-c', str(root / 'entropy.s'), '-o', str(member)], check=True)
            subprocess.run(['ar', 'rcs', str(archive), str(member)], check=True)
            subprocess.run(['mold', '-pie', '--no-dynamic-linker', '--no-relax', '-e', '_start', '-Map=' + str(link_map), str(app), str(archive), '-o', str(binary)], check=True)
            admitted = {str(app): app, str(archive) + '(entropy.o)': member.read_bytes()}
            entropy.validate_owners(link_map, binary, admitted, str(app), str(archive) + '(entropy.o)')
            disassembly = subprocess.check_output(['objdump', '-d', '--disassemble=getentropy', str(binary)], text=True)
            got = re.search(r'mov\s+.*\(%rip\),%rax\s+#\s*([0-9a-f]+)', disassembly)
            self.assertIsNotNone(got)
            body = bytearray(binary.read_bytes())
            offset = entropy.file_offset(body, int(got.group(1), 16))
            struct.pack_into('<Q', body, offset, entropy.final_address(binary, 'getrandom') + 1)
            binary.write_bytes(body)
            with self.assertRaises(SystemExit):
                entropy.validate_owners(link_map, binary, admitted, str(app), str(archive) + '(entropy.o)')
