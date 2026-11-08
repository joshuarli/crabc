"""Dynamic native selection keeps the C allocator out of its producer and ELF."""
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_x86_64_owned_dynamic_sysroot as builder


class DynamicNativeAllocatorSelectionTests(unittest.TestCase):
    def test_dynamic_native_dependencies_receive_the_initial_exec_tls_model(self):
        commands = []

        class CargoCaptured(Exception):
            pass

        def capture(command, **_):
            commands.append(command)
            raise CargoCaptured()

        tools = {'rustup': {'path': '/opt/cargo/bin/rustup'}}
        scratch = Path(__file__).resolve().parents[2] / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary, \
             patch.object(builder.common, 'resolve_pinned_producer_tools', return_value=tools), \
             patch.object(builder.common, 'producer_tool_path', return_value='/usr/bin/ar'), \
             patch.object(builder.common, 'pinned_rustc_sysroot', return_value=Path('/opt/rustup/test-sysroot')), \
             patch.object(builder.common, 'deterministic_environment', return_value={}), \
             patch.object(builder.common, 'allocator_dependency_graph', return_value={}), \
             patch.object(builder.common, 'run', side_effect=capture):
            work = Path(temporary)
            (work / 'stage').mkdir()
            with self.assertRaises(CargoCaptured):
                builder.build_staged_payload(work / 'product', work / 'stage', allocator_backend='native')

        # Cargo target configuration reaches dependencies; final-crate rustc
        # arguments after the separator cannot select their TLS model.
        command = commands[0]
        cargo = command[:command.index('--')]
        configs = [tomllib.loads(cargo[index + 1])
                   for index, argument in enumerate(cargo) if argument == '--config']
        flags = next((config['target'][builder.common.TARGET]['rustflags']
                      for config in configs if 'target' in config), [])
        self.assertIn('-Ztls-model=initial-exec', flags)
        self.assertIn(['-C', 'link-dead-code'],
                      [flags[index:index + 2] for index in range(len(flags) - 1)])

    def test_stripped_loader_dynamic_symbols_are_still_checked(self):
        def symbols(command):
            return b'                 U malloc\n' if '--dynamic' in command else b''
        with patch.object(builder.common, 'run', side_effect=symbols):
            symbols = builder.elf_symbols('llvm-nm', Path('stripped-loader.so'), '--undefined-only')
        self.assertEqual(symbols, {'malloc'})
        with self.assertRaises(builder.common.BuildError):
            builder.validate_native_allocator_symbols(set(), set(), symbols)

    def test_native_symbol_closure_rejects_c_allocator_and_loader_allocation_edges(self):
        builder.validate_native_allocator_symbols({'malloc', 'free', '__libc_start_main'}, {'__tls_get_addr'}, set())
        for definitions, imports, loader_imports in (
            ({'malloc', 'mi_malloc'}, set(), set()),
            ({'malloc'}, {'_mi_heap_main'}, set()),
            ({'malloc'}, set(), {'malloc'}),
            ({'malloc'}, set(), {'__libc_calloc'}),
        ):
            with self.subTest(definitions=definitions, imports=imports, loader=loader_imports):
                with self.assertRaises(builder.common.BuildError):
                    builder.validate_native_allocator_symbols(definitions, imports, loader_imports)


if __name__ == '__main__':
    unittest.main()
