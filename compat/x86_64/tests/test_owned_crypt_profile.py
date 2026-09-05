"""The crypt companion retains observations and independently binds ELF inputs."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_crypt_profile as crypt
import owned_posix_native_dispositions as dispositions
import owned_posix_native_observations as native


def elf(elf_type=3, interpreter='/lib/ld-crabc-x86_64.so.1', needed='libc.so', runpath='/usr/lib'):
    """Minimal physical ELF metadata fixture, never an executable test double."""
    strings = b'\0' + (needed.encode() + b'\0' if needed else b'') + runpath.encode() + b'\0'
    dynamic = (struct.pack('<qQ', 1, 1) if needed else b'') + struct.pack('<qQ', 29, len(needed)+2 if needed else 1) + struct.pack('<qQ', 0, 0)
    data = bytearray(512)
    data[:16] = b'\x7fELF\x02\x01\x01' + b'\0'*9
    data[16:64] = struct.pack('<HHIQQQIHHHHHH', elf_type, 62, 1, 0, 64, 256, 0, 64, 56, 1 if interpreter else 0, 64, 3, 0)
    if interpreter:
        blob = interpreter.encode()+b'\0'
        data[64:120] = struct.pack('<IIQQQQQQ', 3, 4, 128, 0, 0, len(blob), len(blob), 1)
        data[128:128+len(blob)] = blob
    data[160:160+len(strings)] = strings
    data[192:192+len(dynamic)] = dynamic
    data[320:384] = struct.pack('<IIQQQQIIQQ', 0, 3, 0, 0, 160, len(strings), 0, 0, 1, 0)
    data[384:448] = struct.pack('<IIQQQQIIQQ', 0, 6, 0, 0, 192, len(dynamic), 1, 0, 8, 16)
    return bytes(data)


class CryptProfileTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/crypt-profile-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.root)
        self.leaf = self.root / '.work/crypt'
        self.leaf.mkdir(parents=True)
        self.product = self.root / '.work/product'
        self.product.mkdir()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value)+'\n').encode())
        return path

    def test_generated_observer_keeps_32_original_calls_and_actual_pointer_check(self):
        source = crypt.generated_observer(ROOT)
        self.assertEqual(source.count(b'/* upstream vector '), 32)
        self.assertIn(b'nonnull=%d output=', source)
        self.assertIn(b'crypt(vectors[i].key, vectors[i].setting)', source)
        self.assertIn(b'if (result == NULL)', source)
        self.assertIn(b'"$5$rounds=10$roundstoolow"', source)
        self.assertIn(b'"$6$rounds=10$roundstoolow"', source)
        self.assertNotIn(b'#define crypt', source)

    def test_physical_elf_metadata_rejects_foreign_loader_needed_and_wrong_architecture(self):
        path = self.put(self.leaf / 'consumer', elf())
        crypt.require_elf(path, 'pie')
        for data in (elf(interpreter='/lib64/ld-linux-x86-64.so.2'), elf(needed='libc.so.6'),
                     elf(runpath='/foreign'), elf(elf_type=2), elf()[:25],
                     elf()[:18]+struct.pack('<H', 183)+elf()[20:]):
            self.put(path, data)
            with self.assertRaises((native.NativeObservationError, crypt.CryptProfileError)):
                crypt.require_elf(path, 'pie')

    def test_command_record_binds_raw_status_and_exact_invocation(self):
        command = ['bash', '-c', 'printf retained; printf diagnostic >&2; exit 7']
        with self.assertRaisesRegex(RuntimeError, '7'):
            crypt.run_command(self.root, self.leaf, 'failed', command, {'PATH': '/usr/bin:/bin'})
        self.assertEqual((self.leaf / 'failed.stdout').read_bytes(), b'retained')
        self.assertEqual((self.leaf / 'failed.stderr').read_bytes(), b'diagnostic')
        record = json.loads((self.leaf / 'failed.command.json').read_bytes())
        self.assertEqual(record['status'], 7)
        self.assertEqual(record['command'], command)

    def test_existing_command_evidence_is_not_overwritten_or_executed_again(self):
        marker = self.leaf / 'marker'
        self.put(self.leaf / 'reused.status', b'23\n')
        with self.assertRaisesRegex(native.NativeObservationError, 'fresh'):
            crypt.run_command(self.root, self.leaf, 'reused', ['touch', str(marker)], crypt.ENVIRONMENT)
        self.assertFalse(marker.exists())
        self.assertEqual((self.leaf / 'reused.status').read_bytes(), b'23\n')
        self.assertFalse((self.leaf / 'reused.stdout').exists())

    def test_retained_command_rejects_missing_streams_status_and_invocation_changes(self):
        command = ['/bin/true']
        crypt.run_command(self.root, self.leaf, 'retained', command, crypt.ENVIRONMENT)
        self.put(self.product / 'share/crabc/manifest.json', {'schema': 1, 'format': native.PRODUCT_FORMAT,
            'target': 'x86_64-unknown-linux-musl'})
        reader = native.Reader(self.leaf, str(self.root), self.product, self.root)
        crypt.collect_command(reader, 'retained', command, raw_stdout=b'')
        for suffix, changed in (('.status', b'1\n'), ('.stderr', b'noise'), ('.stdout', b'noise'),
                                ('.command.json', b'{}')):
            path = self.leaf / ('retained'+suffix)
            original = path.read_bytes()
            path.write_bytes(changed)
            with self.assertRaises(native.NativeObservationError):
                crypt.collect_command(reader, 'retained', command, raw_stdout=b'')
            path.unlink()
            with self.assertRaises(native.NativeObservationError):
                crypt.collect_command(reader, 'retained', command, raw_stdout=b'')
            path.write_bytes(original)

    def test_runtime_invocations_bind_each_dynamic_copy_and_observer_role(self):
        for mode in ('pie', 'non-pie'):
            for entry in ('kernel', 'direct'):
                for role in ('dynamic', 'vector'):
                    command = crypt.runtime_command(self.leaf, role+'-'+mode+'-'+entry)
                    start = command.index('/usr/sbin/chroot')
                    directory = self.leaf / ('vectors' if role == 'vector' else '') / ('dynamic-'+mode+'-root')
                    self.assertEqual(command[start:], ['/usr/sbin/chroot', str(directory),
                        *([crypt.INTERPRETER] if entry == 'direct' else []), '/consumer',
                        *(['candidate'] if role == 'vector' else [])])
        self.assertEqual(crypt.runtime_command(self.leaf, 'vector-oracle')[-2:],
                         [str(self.leaf / 'vectors/oracle'), 'oracle'])

    def test_link_receipt_cannot_rebind_another_object_or_product(self):
        product = self.product
        for name in ('crti.o','libc.so','crtn.o','Scrt1.o','crabc-dynamic-attach.o','libcrabc-builtins.a'):
            self.put(product / 'usr/lib' / name, name.encode())
        manifest = self.put(product / 'share/crabc/manifest.json', {'schema': 1, 'format': native.PRODUCT_FORMAT,
            'target': 'x86_64-unknown-linux-musl'})
        reader = native.Reader(self.leaf, '/workspace', product, self.root)
        obj = self.put(self.leaf / 'workload.o', b'canonical source object')
        binary = self.put(self.leaf / 'consumer', elf())
        receipt_path = Path(str(binary)+'.crabc-link.json')
        runtime = [product / 'usr/lib' / name for name in ('crti.o','libc.so','crtn.o','Scrt1.o','crabc-dynamic-attach.o')]
        builtins = product / 'usr/lib/libcrabc-builtins.a'
        linker = {'path': '/pinned/ld.lld', 'sha256': 'a'*64}
        receipt = {'schema': 1, 'format': native.PRODUCT_FORMAT, 'mode': 'pie', 'binding': 'now',
            'runtime_imports': [], 'application_runpath': '/usr/lib', 'application_dsos': {}, 'campaign_complete': False,
            'output_path': reader.recorded(binary), 'output_sha256': native.digest(binary), 'manifest_sha256': native.digest(manifest),
            'owned_runtime_inputs': sorted(p.relative_to(product).as_posix() for p in [*runtime,builtins]),
            'input_receipts': [reader.binding(p) for p in [*runtime,obj,builtins]], 'resolved_linker': linker,
            'link_command': crypt.link_command(reader, obj, binary, 'pie', linker['path']),
            'link_trace': [reader.recorded(p) for p in [*runtime,obj,builtins]]}
        self.put(receipt_path, receipt)
        crypt.collect_link(reader, obj, binary, receipt_path, 'pie')
        for change in (lambda r:r['input_receipts'][-2].update(sha256='0'*64),
                       lambda r:r['link_command'].append('/foreign/runtime.o'),
                       lambda r:r.update(manifest_sha256='0'*64),
                       lambda r:r['link_trace'].append('/foreign/libc.a(x.o)'),
                       lambda r:r.update(campaign_complete=0)):
            changed = copy.deepcopy(receipt)
            change(changed)
            self.put(receipt_path, changed)
            with self.assertRaises(native.NativeObservationError):
                crypt.collect_link(reader, obj, binary, receipt_path, 'pie')


if __name__ == '__main__':
    unittest.main()
