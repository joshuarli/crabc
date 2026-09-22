"""Dynamic shadow selection must exclude the attested C implementation."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_x86_64_owned_dynamic_sysroot as builder


class DynamicNativeAllocatorSelectionTests(unittest.TestCase):
    roster = (
        'c.libc.rcgu.o', 'abc-static.o', 'compiler_builtins-abc.rcgu.o',
        '45c91108d938afe8-addvdi3.o',
    )

    def test_default_keeps_only_the_attested_c_backend(self):
        selected, excluded = builder.select_allocator_members(self.roster, 'abc-static.o', 'accepted-c')
        self.assertEqual(selected, ('c.libc.rcgu.o', 'abc-static.o'))
        self.assertNotIn('abc-static.o', excluded)

    def test_native_shadow_excludes_c_and_does_not_admit_unknown_members(self):
        selected, excluded = builder.select_allocator_members(self.roster, 'abc-static.o', 'native-shadow')
        self.assertEqual(selected, ('c.libc.rcgu.o',))
        self.assertIn('abc-static.o', excluded)
        with self.assertRaisesRegex(builder.common.BuildError, 'unclassified'):
            builder.select_allocator_members((*self.roster, 'foreign-native.o'), 'abc-static.o', 'native-shadow')

    def test_native_shadow_accepts_omitted_c_member_with_complete_rust_roster(self):
        roster = tuple(member for member in self.roster if member != 'abc-static.o')
        selected, excluded = builder.select_allocator_members(roster, 'abc-static.o', 'native-shadow')
        self.assertEqual(selected, ('c.libc.rcgu.o',))
        self.assertEqual(excluded, roster[1:])
        with self.assertRaisesRegex(builder.common.BuildError, 'absent'):
            builder.select_allocator_members(roster, 'abc-static.o', 'accepted-c')
        for invalid in ((*roster, 'foreign-native.o'), roster[1:], roster[:-1], (*roster, roster[0])):
            with self.subTest(roster=invalid):
                with self.assertRaises(builder.common.BuildError):
                    builder.select_allocator_members(invalid, 'abc-static.o', 'native-shadow')

    def test_unknown_backend_cannot_fall_back_to_c(self):
        with self.assertRaisesRegex(builder.common.BuildError, 'allocator backend'):
            builder.select_allocator_members(self.roster, 'abc-static.o', 'unknown')

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
