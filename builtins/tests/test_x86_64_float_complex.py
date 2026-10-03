"""Ordinary compiler-emitted float-complex calls through the owned helper archive."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PINNED = Path('/opt/rustup/toolchains/nightly-2026-09-15-x86_64-unknown-linux-musl')
HELPERS = {'__mulsc3', '__divsc3'}

@unittest.skipUnless((PINNED/'bin/rustc').is_file(), 'requires pinned native x86 environment')
class FloatComplexCompilerCalls(unittest.TestCase):
    def test_ordinary_float_complex_arithmetic_link_without_foreign_providers(self):
        parent = ROOT/'.work/x86_64/float_complex-test'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory)
            archive = work/'libcrabc-builtins.a'
            subprocess.run(['python3', '-B', str(ROOT/'builtins/build_x86_64.py'), '--output', str(archive)],
                           check=True, capture_output=True)
            cc = '/usr/local/bin/crabc-x86_64-musl-gcc'
            obj = work/'consumer.o'
            subprocess.run([cc, '-O0', '-ffreestanding', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
                            '-c', str(ROOT/'builtins/fixtures/x86_64_float_complex_probe.c'), '-o', str(obj)],
                           check=True, capture_output=True)
            imports = subprocess.check_output(['nm', '--undefined-only', str(obj)], text=True)
            self.assertEqual({line.split()[-1] for line in imports.splitlines()}, HELPERS)
            start = work/'start.S'
            start.write_text('.text\n.globl _start\n_start:\nandq $-16,%rsp\ncall main\nmovl %eax,%edi\nmovl $60,%eax\nsyscall\n.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([cc, '-c', str(start), '-o', str(work/'start.o')], check=True, capture_output=True)
            lld = PINNED/'lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld'
            for mode in ('static', 'pie'):
                output = work/mode
                map_path = work/(mode+'.map')
                trace_path = work/(mode+'.trace')
                result = subprocess.run([str(lld), '-static', *(['-pie'] if mode=='pie' else []),
                                         '--no-dynamic-linker', '--no-undefined', '--gc-sections', '-Map', str(map_path), '-t',
                                         str(work/'start.o'), str(obj), str(archive), '-o', str(output)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                subprocess.run([str(output)], check=True, capture_output=True)
                trace_path.write_bytes(result.stdout)
                import sys
                sys.path.insert(0, str(ROOT/'compat/x86_64'))
                import compiler_helper_evidence as evidence
                observed = evidence._compiler_helper_transfers(root=ROOT, archive=archive, workload=obj,
                    executable=output, map_path=map_path, trace_path=trace_path, names=sorted(HELPERS))
                self.assertEqual(set(observed['transfers']), HELPERS)


    def test_pinned_kernels_match_complex_results_and_fenv_in_all_rounding_modes(self):
        parent = ROOT/'.work/x86_64/float-complex-differential-test'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory)
            archive = work/'libcrabc-builtins.a'
            subprocess.run(['python3', '-B', str(ROOT/'builtins/build_x86_64.py'), '--output', str(archive)],
                           check=True, capture_output=True)
            cc = '/usr/local/bin/crabc-x86_64-musl-gcc'
            flags = ['-O2', '-frounding-math', '-ffp-contract=off', '-fno-stack-protector']
            oracles = []
            for name in ('mulsc3', 'divsc3'):
                obj = work/(name+'.o')
                subprocess.run([cc, *flags, '-I'+str(ROOT/'builtins/fixtures/llvm22_divdc3'),
                                '-D__'+name+'=crabc_reference_'+name, '-c',
                                str(ROOT/'builtins/fixtures/llvm22_float_complex'/(name+'.c')), '-o', str(obj)],
                               check=True, capture_output=True)
                oracles.append(str(obj))
            output = work/'differential'
            # The pinned musl program is a numerical oracle host. The ordinary
            # consumer separately proves linkage with only the owned archive.
            subprocess.run([cc, *flags, str(ROOT/'builtins/fixtures/x86_64_float_complex_differential.c'),
                            *oracles, str(archive), '-lm', '-o', str(output)], check=True, capture_output=True)
            result = subprocess.run([str(output)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b'float complex differential: PASS (2814208 cases; four rounding modes)\n')
            self.assertEqual(result.stderr, b'')
