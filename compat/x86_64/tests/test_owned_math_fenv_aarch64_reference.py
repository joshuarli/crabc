import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import owned_math_fenv_aarch64_reference as reference


class ReferenceTraceTests(unittest.TestCase):
    def test_requires_owned_inputs_and_rejects_ambient_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / 'trace'
            workload = root / 'workload.o'
            objects = root / 'objects'
            builtins = root / 'libcrabc-builtins.a'
            fixed = ['/opt/musl-1.2.6/lib/Scrt1.o', '/opt/musl-1.2.6/lib/crti.o',
                     '/opt/musl-1.2.6/lib/crtn.o',
                     '/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0/crtbeginS.o',
                     '/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0/crtendS.o',
                     str(workload), *(str(objects / (name + '.o')) for name in reference.SYMBOLS),
                     '/opt/musl-1.2.6/lib/libc.a(math.o)', str(builtins) + '(builtins.o)']
            trace.write_text(''.join('trace: ' + item + '\n' for item in fixed))
            reference.validate_trace(trace, workload, objects, builtins)
            trace.write_text(trace.read_text() + 'trace: /usr/lib/libgcc.a(soft.o)\n')
            with self.assertRaisesRegex(ValueError, 'unowned reference link input'):
                reference.validate_trace(trace, workload, objects, builtins)
            trace.write_text(''.join('trace: ' + item + '\n' for item in fixed[1:]))
            with self.assertRaisesRegex(ValueError, 'omitted a fixed input'):
                reference.validate_trace(trace, workload, objects, builtins)


if __name__ == '__main__':
    unittest.main()
