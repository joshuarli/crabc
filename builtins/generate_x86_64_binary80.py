#!/usr/bin/env python3
"""Translate pinned binary80 kernels to checked Rust global-assembly input.

The runtime build consumes assembly only. This development tool compiles the
unchanged LLVM kernels and their small private musl math closure; it never
installs a C object, target CRT, or external compiler runtime.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
LLVM = ROOT/'fixtures/llvm22_binary80'
HEADERS = ROOT/'fixtures/llvm22_divdc3'
KERNELS = ('floattixf.c', 'floatuntixf.c', 'fixxfti.c', 'fixunsxfti.c', 'mulxc3.c', 'divxc3.c')
SUPPORT = ('fmaxl', 'logbl', 'ilogbl', 'scalbnl', '__fpclassifyl', '__signbitl')
MUSL_DIGEST = '2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88'
FLAGS = ('-std=c11', '-O2', '-ffreestanding', '-frounding-math', '-ffp-contract=off', '-fwrapv',
         '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
         '-ffunction-sections', '-fdata-sections', '-fPIC', '-fno-ident')

def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        name = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(name).to_bytes(4, 'big')); digest.update(name)
        digest.update(len(data).to_bytes(8, 'big')); digest.update(data)
    return digest.hexdigest()

def transform(name, text, private):
    tag = Path(name).stem
    for symbol in SUPPORT:
        text = re.sub(r'(?<![A-Za-z0-9_.$])'+symbol+r'(?![A-Za-z0-9_.$])',
                      '__crabc_binary80_'+symbol, text)
    if private:
        text = re.sub(r'^\s*\.globl\s+(__crabc_binary80_\w+)\s*$', r'.local \1', text, flags=re.M)
    text = re.sub(r'(?<![A-Za-z0-9_.$])\.L([A-Za-z0-9_.$]+)', '.Lbinary80_'+tag+r'_\1', text)
    text = re.sub(r'^\s*\.(?:file|ident)\s+.*\n', '', text, flags=re.M)
    text = re.sub(r'^\s*\.section\s+\.note\.GNU-stack[^\n]*\n', '', text, flags=re.M)
    return text.rstrip()+'\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--musl-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default='/usr/local/bin/crabc-x86_64-musl-gcc')
    args = parser.parse_args()
    if tree_digest(args.musl_source) != MUSL_DIGEST:
        raise SystemExit('pinned musl source tree differs')
    version = subprocess.check_output([args.cc, '--version'], text=True).splitlines()[0]
    if '15.2.0' not in version:
        raise SystemExit('requires pinned GCC 15.2.0')
    for directory in (LLVM, HEADERS):
        for line in (directory/'SHA256SUMS').read_text().splitlines():
            digest, name = line.split()
            if hashlib.sha256((directory/name).read_bytes()).hexdigest() != digest:
                raise SystemExit('pinned LLVM source differs: '+name)
    for name in SUPPORT:
        if (ROOT/'fixtures/musl126_binary80'/(name+'.c')).read_bytes() != (args.musl_source/'src/math'/(name+'.c')).read_bytes():
            raise SystemExit('retained musl kernel differs: '+name)
    includes = ['-I'+str(HEADERS)]
    includes += ['-I'+str(args.musl_source/p) for p in ('src/math', 'src/internal', 'src/include', 'arch/x86_64', 'arch/generic', 'include')]
    blocks = ['/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception AND MIT\n * Faithful binary80 compiler kernels with a local musl math closure.\n * The six public entries use the System V AMD64 x87 calling convention.\n */']
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        for name in (*KERNELS, *(n+'.c' for n in SUPPORT)):
            private = name not in KERNELS
            source = args.musl_source/'src/math'/name if private else LLVM/name
            assembly = Path(temporary)/(name+'.s')
            subprocess.run([args.cc, *FLAGS, *includes, '-S', str(source), '-o', str(assembly)], check=True)
            blocks += ['/* '+('musl 1.2.6' if private else 'LLVM 22.1.3')+' '+name+' */', transform(name, assembly.read_text(), private)]
    blocks.append('.section .note.GNU-stack,"",@progbits\n')
    args.output.write_text('\n'.join(blocks))

if __name__ == '__main__':
    main()
