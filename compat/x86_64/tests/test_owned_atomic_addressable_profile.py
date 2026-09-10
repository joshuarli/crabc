"""The installed atomic extension receipt has no permissive replay path."""
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_atomic_addressable_profile as atomic
import owned_posix_native_observations as native


class AtomicAddressableProfileTests(unittest.TestCase):
    def test_retained_tool_roster_is_host_reconstructible_and_exact(self):
        scratch = ROOT / '.work/x86_64/atomic-addressable-profile-unit-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            tools = {'compiler': {'path': '/pinned/clang', 'sha256': 'a' * 64},
                     'linker': {'path': '/pinned/ld.lld', 'sha256': 'b' * 64}}
            for phase in ('before', 'after'):
                (work / ('profile-tools-' + phase + '.json')).write_bytes(
                    (json.dumps(tools, sort_keys=True) + '\n').encode())
            with patch.object(atomic, 'live_tools', side_effect=AssertionError('collector resolved an ambient tool')):
                self.assertEqual(atomic._recorded_tools(work), tools)

            for name, path, value in (
                ('malformed roster', work / 'profile-tools-before.json', {}),
                ('different seal', work / 'profile-tools-after.json',
                 {'compiler': {'path': '/pinned/clang', 'sha256': '0' * 64},
                  'linker': tools['linker']}),
            ):
                with self.subTest(name=name):
                    original = path.read_bytes()
                    path.write_bytes((json.dumps(value, sort_keys=True) + '\n').encode())
                    try:
                        with self.assertRaises(native.NativeObservationError):
                            atomic._recorded_tools(work)
                    finally:
                        path.write_bytes(original)

    def test_link_receipt_must_use_the_retained_linker_identity(self):
        scratch = ROOT / '.work/x86_64/atomic-addressable-profile-unit-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            work, product = root / '.work/evidence', root / '.work/product'
            work.mkdir(parents=True)
            for name in ('crti.o', 'libc.so', 'crtn.o', 'Scrt1.o', 'crabc-dynamic-attach.o', 'libcrabc-builtins.a'):
                path = product / 'usr/lib' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            manifest = product / 'share/crabc/manifest.json'
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_bytes(json.dumps({'schema': 1, 'format': native.PRODUCT_FORMAT,
                                             'target': 'x86_64-unknown-linux-musl'}).encode())
            object_path, binary = work / 'atomic-c.o', work / 'dynamic-pie-consumer'
            object_path.write_bytes(b'canonical object')
            binary.write_bytes(b'canonical executable')
            reader = native.Reader(work, str(root), product, root)
            tools = {'compiler': {'path': '/pinned/clang', 'sha256': 'a' * 64},
                     'linker': {'path': '/pinned/ld.lld', 'sha256': 'b' * 64}}
            runtime = [product / 'usr/lib' / name for name in
                       ('crti.o', 'libc.so', 'crtn.o', 'Scrt1.o', 'crabc-dynamic-attach.o')]
            builtins = product / 'usr/lib/libcrabc-builtins.a'
            receipt = {'schema': 1, 'format': native.PRODUCT_FORMAT, 'mode': 'pie', 'binding': 'now',
                'runtime_imports': [], 'application_runpath': '/usr/lib', 'application_dsos': {},
                'campaign_complete': False, 'output_path': reader.recorded(binary),
                'output_sha256': native.digest(binary), 'manifest_sha256': native.digest(manifest),
                'owned_runtime_inputs': sorted(path.relative_to(product).as_posix() for path in [*runtime, builtins]),
                'input_receipts': [reader.binding(path) for path in [*runtime, object_path, builtins]],
                'resolved_linker': tools['linker'],
                'link_command': atomic._link_command(reader, [object_path], binary, 'pie', tools['linker']['path']),
                'link_trace': [reader.recorded(path) for path in [*runtime, object_path, builtins]]}
            receipt_path = Path(str(binary) + '.crabc-link.json')
            receipt_path.write_bytes((json.dumps(receipt, sort_keys=True) + '\n').encode())
            with patch.object(atomic.sealed, 'require_elf', return_value={'kind': 'test'}):
                atomic._collect_link(reader, [object_path], binary, 'pie', tools)
                changed = dict(receipt)
                changed['resolved_linker'] = {'path': '/pinned/other/ld.lld', 'sha256': '0' * 64}
                changed['link_command'] = atomic._link_command(reader, [object_path], binary, 'pie',
                                                                 changed['resolved_linker']['path'])
                receipt_path.write_bytes((json.dumps(changed, sort_keys=True) + '\n').encode())
                with self.assertRaises(native.NativeObservationError):
                    atomic._collect_link(reader, [object_path], binary, 'pie', tools)

    def test_execution_payload_reconstructs_only_through_the_sealed_workspace_mount(self):
        scratch = ROOT / '.work/x86_64/atomic-addressable-profile-unit-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            work, product = root / '.work/evidence', root / '.work/product'
            execution = work / 'dynamic-pie-root'
            manifest = product / 'share/crabc/manifest.json'
            payload = product / 'usr/lib/libc.so'
            binary, copied = work / 'dynamic-pie-consumer', execution / 'consumer'
            alias, target = 'lib/ld-musl-x86_64.so.1', 'ld-crabc-x86_64.so.1'
            work.mkdir(parents=True)
            manifest.parent.mkdir(parents=True)
            payload.parent.mkdir(parents=True)
            (product / 'lib').mkdir()
            payload.write_bytes(b'payload\n')
            manifest.write_text(json.dumps({'schema': 1, 'format': native.PRODUCT_FORMAT,
                                            'target': 'x86_64-unknown-linux-musl',
                                            'files': {'usr/lib/libc.so': native.digest(payload)},
                                            'symlinks': {alias: target}}))
            (product / alias).symlink_to(target)
            (execution / 'share/crabc').mkdir(parents=True)
            (execution / 'usr/lib').mkdir(parents=True)
            (execution / 'lib').mkdir()
            (execution / 'share/crabc/manifest.json').write_bytes(manifest.read_bytes())
            (execution / 'usr/lib/libc.so').write_bytes(payload.read_bytes())
            (execution / alias).symlink_to(target)
            binary.write_bytes(b'consumer\n')
            copied.write_bytes(binary.read_bytes())
            record = work / 'dynamic-pie-execution-payload.json'
            with patch.object(atomic.copies, '_validate_dynamic_product',
                              return_value=(manifest, {'usr/lib/libc.so': native.digest(payload)})):
                atomic.copies.record_execution_payload(product, execution, binary, copied, record)
            payload_record = native.read_json(record)

            def workspace(value):
                if isinstance(value, dict):
                    return {key: workspace(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [workspace(item) for item in value]
                if isinstance(value, str) and (value == str(root) or value.startswith(str(root) + '/')):
                    return '/workspace' + value[len(str(root)):]
                return value

            payload_record = workspace(payload_record)
            record.write_bytes((json.dumps(payload_record, sort_keys=True) + '\n').encode())
            reader = native.Reader(work, '/workspace', product, root)
            atomic._collect_copy(reader, 'pie', binary)
            payload_record['execution_root'] = '/workspace/unrelated-root'
            record.write_bytes((json.dumps(payload_record, sort_keys=True) + '\n').encode())
            with self.assertRaises(native.NativeObservationError):
                atomic._collect_copy(reader, 'pie', binary)

    def test_cxx_reference_contract_is_only_the_six_c_spellings(self):
        self.assertEqual(atomic.MODES, ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct'))
        self.assertEqual(len(atomic.ATOMIC_SYMBOLS), 6)
        observed = atomic._cxx_undefined(('                 U _GLOBAL_OFFSET_TABLE_\n' +
            ''.join('                 U ' + name + '\n' for name in atomic.ATOMIC_SYMBOLS)).encode())
        self.assertEqual(set(observed), {'_GLOBAL_OFFSET_TABLE_', *atomic.ATOMIC_SYMBOLS})
        for name in ('_Znew', '__cxa_throw', '__tls_get_addr', 'unexpected_import'):
            with self.assertRaises(native.NativeObservationError):
                atomic._cxx_undefined((' U ' + atomic.ATOMIC_SYMBOLS[0] + '\n U ' + name + '\n').encode())

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() == 0,
                         'the installed dynamic companion needs the pinned root container')
    def test_actual_receipt_rejects_cross_product_stale_source_missing_mode_raw_and_extra_artifacts(self):
        scratch = ROOT / '.work/x86_64/atomic-addressable-profile-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, run_root)
        environment = {**os.environ, 'TMPDIR': str(run_root)}
        result = subprocess.run(['bash', str(ROOT / 'compat/x86_64/run_owned_atomic_addressable_profile.sh')],
                                cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = next(run_root.rglob('atomic-addressable-profile.json'))
        # Collection is deliberately host-readable: it reconstructs commands from
        # the retained container tool identities and never resolves host tools.
        with patch.object(atomic, 'live_tools', side_effect=AssertionError('collector resolved an ambient tool')):
            self.assertEqual(atomic.validate_receipt(ROOT, receipt)['status'], 'profile-companion-verified')

        def replace(path, data):
            before, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode | stat.S_IWUSR)
            path.write_bytes(data)
            def restore():
                path.chmod(mode | stat.S_IWUSR)
                path.write_bytes(before)
                path.chmod(mode)
            return restore

        request = receipt.parent / 'profile-request.json'
        source = ROOT / atomic.MAIN_SOURCE
        mutations = (
            ('cross product', request, request.read_bytes().replace(b'dynamic-product', b'evidence/dynamic-pie-root')),
            ('unsealed source mount', request, request.read_bytes().replace(b'/workspace', b'/foreign-mount')),
            ('stale source', source, source.read_bytes() + b'/* stale-source test */\n'),
            ('missing mode', receipt.parent / 'dynamic-pie-direct.status', b''),
            ('altered raw pair', receipt.parent / 'dynamic-non-pie-kernel.stdout', b'changed\n'),
            ('malformed tool seal', receipt.parent / 'profile-tools-before.json', b'{}\n'),
        )
        for name, path, data in mutations:
            with self.subTest(name=name):
                restore = replace(path, data)
                try:
                    with self.assertRaises((native.NativeObservationError, atomic.AtomicAddressableProfileError, RuntimeError)):
                        atomic.validate_receipt(ROOT, receipt)
                finally:
                    restore()

        tools_after = receipt.parent / 'profile-tools-after.json'
        changed_tools = native.read_json(tools_after)
        changed_tools['compiler']['sha256'] = '0' * 64
        restore = replace(tools_after, (json.dumps(changed_tools, sort_keys=True) + '\n').encode())
        try:
            with self.assertRaises((native.NativeObservationError, atomic.AtomicAddressableProfileError, RuntimeError)):
                atomic.validate_receipt(ROOT, receipt)
        finally:
            restore()

        link_path = receipt.parent / 'dynamic-pie-consumer.crabc-link.json'
        changed_link = native.read_json(link_path)
        changed_link['resolved_linker'] = {'path': '/retained/other/ld.lld', 'sha256': '0' * 64}
        changed_link['link_command'][0] = changed_link['resolved_linker']['path']
        restore = replace(link_path, (json.dumps(changed_link, sort_keys=True) + '\n').encode())
        try:
            with self.assertRaises((native.NativeObservationError, atomic.AtomicAddressableProfileError, RuntimeError)):
                atomic.validate_receipt(ROOT, receipt)
        finally:
            restore()
        extra = receipt.parent / 'unexpected-artifact'
        extra.write_bytes(b'not sealed')
        try:
            with self.assertRaises((native.NativeObservationError, atomic.AtomicAddressableProfileError, RuntimeError)):
                atomic.validate_receipt(ROOT, receipt)
        finally:
            extra.unlink()


if __name__ == '__main__':
    unittest.main()
