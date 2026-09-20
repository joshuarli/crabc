"""The standalone cleanup fixture may use only the selected unwind provider."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'unwinder_cleanup_link', Path(__file__).parents[1] / 'cleanup_link.py'
)
linker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linker)


class CleanupLinkContract(unittest.TestCase):
    archive = Path('/declared/libcrabc-unwind.a')
    stock_libdir = Path('/pinned-sysroot/lib/rustlib/x86_64-unknown-linux-musl/lib')

    def translate(self, arguments):
        return linker.translate_arguments(arguments, self.archive, self.stock_libdir)

    def test_standard_unwind_requests_become_the_selected_archive(self):
        command = self.translate(
            [
                '-m64', 'fixture.o', '-lgcc_s', '-lc',
                str(self.stock_libdir / 'libunwind-0123456789abcdef.rlib'),
                '-lunwind', '-nodefaultlibs',
            ],
        )
        self.assertEqual(
            command,
            ['-m64', 'fixture.o', str(self.archive), '-lc', '-nodefaultlibs'],
        )

    def test_direct_foreign_unwinder_archive_is_rejected(self):
        for argument in ('/usr/lib/libgcc_s.so.1', '-lgcc_eh'):
            with self.subTest(argument=argument), self.assertRaisesRegex(linker.LinkError, 'foreign unwind runtime'):
                self.translate(['fixture.o', argument])

    def test_exact_target_libunwind_archive_is_replaced_not_linked(self):
        stock_unwind = self.stock_libdir / 'libunwind-0123456789abcdef.rlib'
        command = self.translate(['fixture.o', str(stock_unwind), '-lunwind'])
        self.assertEqual(command, ['fixture.o', str(self.archive)])

    def test_other_rust_libunwind_archive_is_rejected(self):
        with self.assertRaisesRegex(linker.LinkError, 'foreign unwind runtime'):
            self.translate([
                'fixture.o', '/other-sysroot/libunwind-0123456789abcdef.rlib', '-lunwind',
            ])

    def test_linker_alternate_library_spelling_is_rejected(self):
        for arguments in (
            ('-l:libunwind.a',),
            ('-Wl,-lgcc_s',),
            ('-Wl,-l,unwind',),
            ('-Xlinker', '-lgcc_s'),
            ('-l', 'gcc_eh'),
        ):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(linker.LinkError, 'runtime|alternate'):
                self.translate(['fixture.o', *arguments, '-lunwind'])

    def test_response_file_cannot_hide_a_runtime_provider(self):
        with self.assertRaisesRegex(linker.LinkError, 'response file'):
            self.translate(['fixture.o', '@linker-arguments', '-lunwind'])

    def test_driver_forwarded_response_file_cannot_hide_a_runtime_provider(self):
        for argument in ('-Wl,@linker-arguments', '-Wl,--as-needed,@linker-arguments'):
            with self.subTest(argument=argument), self.assertRaisesRegex(linker.LinkError, 'response file'):
                self.translate([
                    'fixture.o', argument,
                    str(self.stock_libdir / 'libunwind-0123456789abcdef.rlib'),
                    '-lunwind',
                ])

    def test_missing_standard_unwind_request_cannot_hide_provider_selection(self):
        with self.assertRaisesRegex(linker.LinkError, 'unwind request'):
            self.translate(['fixture.o', '-lc', '-nodefaultlibs'])

    def test_missing_target_libunwind_archive_cannot_silently_change_consumer_graph(self):
        with self.assertRaisesRegex(linker.LinkError, 'stock Rust libunwind'):
            self.translate(['fixture.o', '-lunwind'])


if __name__ == '__main__':
    unittest.main()
