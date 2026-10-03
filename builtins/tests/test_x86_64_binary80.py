"""Ordinary compiler-emitted binary80 calls through the owned helper archive."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PINNED = Path('/opt/rustup/toolchains/nightly-2026-09-15-x86_64-unknown-linux-musl')
HELPERS = {'__floattixf', '__floatuntixf', '__fixxfti', '__fixunsxfti', '__mulxc3', '__divxc3'}

@unittest.skipUnless((PINNED/'bin/rustc').is_file(), 'requires pinned native x86 environment')
class Binary80CompilerCalls(unittest.TestCase):
    def test_defined_conversions_and_complex_arithmetic_link_without_foreign_providers(self):
        parent = ROOT/'.work/x86_64/binary80-test'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory)
            archive = work/'libcrabc-builtins.a'
            subprocess.run(['python3', '-B', str(ROOT/'builtins/build_x86_64.py'), '--output', str(archive)],
                           check=True, capture_output=True)
            cc = '/usr/local/bin/crabc-x86_64-musl-gcc'
            obj = work/'consumer.o'
            subprocess.run([cc, '-O0', '-ffreestanding', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
                            '-c', str(ROOT/'builtins/fixtures/x86_64_binary80_probe.c'), '-o', str(obj)],
                           check=True, capture_output=True)
            imports = subprocess.check_output(['nm', '--undefined-only', str(obj)], text=True)
            self.assertEqual({line.split()[-1] for line in imports.splitlines()}, HELPERS)
            start = work/'start.S'
            start.write_text('.text\n.globl _start\n_start:\nandq $-16,%rsp\ncall main\nmovl %eax,%edi\nmovl $60,%eax\nsyscall\n.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([cc, '-c', str(start), '-o', str(work/'start.o')], check=True, capture_output=True)
            lld = PINNED/'lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld'
            for mode in ('static', 'pie'):
                output = work/mode
                result = subprocess.run([str(lld), '-static', *(['-pie'] if mode=='pie' else []),
                                         '--no-dynamic-linker', '--no-undefined', '--gc-sections',
                                         str(work/'start.o'), str(obj), str(archive), '-o', str(output)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                subprocess.run([str(output)], check=True, capture_output=True)

    def test_pinned_kernels_match_defined_conversions_complex_results_and_fenv(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('binary80_codegen', ROOT/'builtins/generate_x86_64_binary80.py')
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        parent = ROOT/'.work/x86_64/binary80-differential-test'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory)
            archive = work/'libcrabc-builtins.a'
            subprocess.run(['python3', '-B', str(ROOT/'builtins/build_x86_64.py'), '--output', str(archive)],
                           check=True, capture_output=True)
            cc = '/usr/local/bin/crabc-x86_64-musl-gcc'
            renames = ['-D'+name+'=reference_'+name[2:] for name in sorted(HELPERS)]
            oracles = []
            for source in generator.KERNELS:
                obj = work/(source+'.o')
                subprocess.run([cc, *generator.FLAGS, '-I'+str(generator.HEADERS), *renames,
                                '-c', str(generator.LLVM/source), '-o', str(obj)], check=True, capture_output=True)
                oracles.append(str(obj))
            output = work/'differential'
            # Pinned musl hosts this numerical comparison only. The ordinary
            # compiler consumer above links without any target runtime input.
            subprocess.run([cc, *generator.FLAGS, str(ROOT/'builtins/fixtures/x86_64_binary80_differential.c'),
                            *oracles, str(archive), '-lm', '-o', str(output)], check=True, capture_output=True)
            result = subprocess.run([str(output)], check=True, capture_output=True)
            self.assertEqual(result.stdout, b'binary80 differential: PASS (524288 complex cases; four rounding modes; defined conversions)\n')
            self.assertEqual(result.stderr, b'')
