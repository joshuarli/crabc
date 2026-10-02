"""Native installed phase-order evidence does not depend on a C product."""
from pathlib import Path
import importlib.util
import json
import tempfile
import shutil
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    'dynamic_native_allocator', ROOT / 'compat/x86_64/run_dynamic_native_allocator.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class DynamicNativeAllocatorTests(unittest.TestCase):
    def test_native_product_runs_both_dependency_graphs_without_c_product(self):
        (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp') as temporary:
            product = Path(temporary) / 'native'
            (product / 'share/crabc').mkdir(parents=True)
            (product / 'usr/lib').mkdir(parents=True)
            (product / 'share/crabc/manifest.json').write_text('{}')
            work = Path(temporary) / 'run'

            def command(arguments, log):
                arguments = list(map(str, arguments))
                log.write_text('')
                if '-o' in arguments:
                    Path(arguments[arguments.index('-o') + 1]).write_bytes(b'product')
                if arguments[0] == 'readelf':
                    return '(NEEDED)' if log.parent.name == 'dependent' else ''
                return ''

            def execute(arguments, directory, name, final_worker):
                phase = 1 if directory.name == 'dependent' else 2
                output = ('DSO_INIT\nMAIN_INIT\nMAIN\nATEXIT\nMAIN_FINI\n'
                          f'DSO_FINI={phase}\nFLUSH=2\n')
                (directory / (name + '.stdout')).write_text(output)
                (directory / (name + '.stderr')).write_text('')
                (directory / (name + '.status')).write_text('0\n')
                return output

            with patch.object(producer.producer.common, 'assert_native_target'), \
                    patch.object(producer, 'validate_product', return_value=product), \
                    patch.object(producer, 'command', side_effect=command), \
                    patch.object(producer, 'execute', side_effect=execute), \
                    patch.object(producer.producer.common, 'resolve_pinned_producer_tools',
                                 return_value={'rustup': {'path': '/rustup'}}), \
                    patch.object(producer.producer.common, 'pinned_rustc_sysroot',
                                 return_value=Path('/toolchain')), \
                    patch.object(producer.producer.installed_driver, 'validate'), \
                    patch.object(producer.shadow_receipt, 'write_receipt') as publish:
                producer.run(None, product, work)
            receipt = json.loads((work / 'receipt.json').read_text())
            self.assertEqual(set(receipt['products']), {'native-shadow'})
            self.assertEqual(len(receipt['cases']), 16)
            self.assertEqual(len(publish.call_args.args[4]), 16)
            self.assertEqual(publish.call_args.args[1], 'owned-native-allocator-lifecycle')
            cases = []
            for name, status, logs in publish.call_args.args[4]:
                names = {}
                for log in logs:
                    relative = log.relative_to(work)
                    retained = work / 'logs' / relative
                    retained.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(log, retained)
                    names[relative.as_posix()] = {}
                cases.append({'id': name, 'status': status, 'logs': names})
            retained = producer.shadow_receipt.Receipt(
                work / 'receipt.json', 'owned-native-allocator-lifecycle',
                {'revision': '0' * 40}, {}, cases, publish.call_args.args[5])
            with patch.object(producer.shadow_receipt, 'read_receipt', return_value=retained):
                self.assertIs(producer.read_lifecycle_receipt(), retained)
                damaged = next(name for name in cases[0]['logs'] if name.endswith('.stdout'))
                (work / 'logs' / damaged).write_text('DSO_FINI=2\n')
                with self.assertRaisesRegex(RuntimeError, 'phase order differs'):
                    producer.read_lifecycle_receipt()
                cases.pop()
                with self.assertRaisesRegex(RuntimeError, 'incomplete execution cases'):
                    producer.read_lifecycle_receipt()


if __name__ == '__main__':
    unittest.main()
