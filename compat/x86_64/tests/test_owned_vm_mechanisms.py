#!/usr/bin/env python3
"""Provider, ABI, and lifecycle regressions for owned VM mechanisms."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_vm_mechanisms.rs"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SYSCALL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
QUALIFICATION = ROOT / "compat" / "x86_64" / "owned_dynamic_qualification.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_vm_mechanisms.sh"


def body_after(source: str, marker: str) -> str:
    start = source.index(marker)
    next_function = source.find("\n/// ", start + len(marker))
    return source[start:] if next_function < 0 else source[start:next_function]


class OwnedVmMechanismTests(unittest.TestCase):
    def test_owned_vm_module_is_the_only_selected_provider(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('pub unsafe extern "C" fn __mremap(', source)
        self.assertIn('pub extern "C" fn brk(', source)
        self.assertIn('pub extern "C" fn sbrk(', source)
        self.assertIn('pub unsafe extern "C" fn remap_file_pages(', source)

        root = STATIC_ROOT.read_text(encoding="utf-8")
        self.assertIn(
            '#[cfg(feature = "x86-owned-static-runtime")]\n'
            '#[path = "owned_vm_mechanisms.rs"]\n'
            "mod owned_vm_mechanisms;",
            root,
        )

    def test_mremap_preserves_musl_varargs_boundary_and_owned_vmlock(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        mremap = body_after(source, 'pub unsafe extern "C" fn __mremap(')

        self.assertIn("if new_size >= isize::MAX as usize", mremap)
        self.assertIn("errno::set_errno(ENOMEM)", mremap)
        self.assertIn("if flags & MREMAP_FIXED != 0", mremap)
        self.assertIn("pthread_vmlock::wait()", mremap)
        self.assertIn("args.next_arg::<*mut c_void>()", mremap)
        self.assertLess(
            mremap.index("pthread_vmlock::wait()"),
            mremap.index("args.next_arg::<*mut c_void>()"),
        )
        self.assertIn("raw_syscall::SYS_MREMAP", mremap)
        self.assertIn("c_pointer_status(result)", mremap)

    def test_mremap_keeps_musl_hidden_body_and_weak_public_alias(self) -> None:
        """The public name stays interposable while source calls bind internal."""
        source = MODULE.read_text(encoding="utf-8")

        for directive in (
            '".hidden __mremap"',
            '".weak mremap"',
            '".set mremap, __mremap"',
        ):
            self.assertIn(directive, source)
        self.assertIn('pub unsafe extern "C" fn __mremap(', source)
        self.assertNotIn('pub unsafe extern "C" fn mremap(', source)

    def test_break_and_legacy_remap_remain_strong_source_entries(self) -> None:
        """Only musl's mremap source uses a weak public alias."""
        source = MODULE.read_text(encoding="utf-8")
        for marker in (
            'pub extern "C" fn brk(',
            'pub extern "C" fn sbrk(',
            'pub unsafe extern "C" fn remap_file_pages(',
        ):
            self.assertNotIn('#[linkage = "weak"]', body_after(source, marker))

    def test_break_and_legacy_remap_keep_their_distinct_source_contracts(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        brk = body_after(source, 'pub extern "C" fn brk(')
        sbrk = body_after(source, 'pub extern "C" fn sbrk(')
        legacy_remap = body_after(source, 'pub unsafe extern "C" fn remap_file_pages(')
        syscall = SYSCALL.read_text(encoding="utf-8")

        self.assertIn("errno::set_errno(ENOMEM)", brk)
        self.assertIn("if increment != 0", sbrk)
        self.assertIn("raw_syscall::SYS_BRK", sbrk)
        self.assertNotIn("c_pointer_status", sbrk)
        self.assertIn("raw_syscall::SYS_REMAP_FILE_PAGES", legacy_remap)
        self.assertIn("c_status(result)", legacy_remap)
        self.assertIn("pub(crate) const SYS_BRK: i64 = 12;", syscall)
        self.assertIn("pub(crate) const SYS_REMAP_FILE_PAGES: i64 = 216;", syscall)

    def test_dynamic_qualification_replays_the_same_owned_vm_workload(self) -> None:
        source = QUALIFICATION.read_text(encoding="utf-8")
        self.assertIn('"vm-mechanisms": ("run_owned_vm_mechanisms.sh", None)', source)

    def test_product_runner_proves_source_bindings_and_dynamic_imports(self) -> None:
        """Every delivered mode keeps mremap interposable at its ELF boundary."""
        source = RUNNER.read_text(encoding="utf-8")

        self.assertIn("assert_owned_vm_bindings()", source)
        self.assertIn("assert_dynamic_vm_imports()", source)
        for required in (
            'assert_owned_vm_bindings "$work/oracle" --syms',
            'assert_owned_vm_bindings "$work/static-product/usr/lib/libc.a" --syms',
            'assert_owned_vm_bindings "$work/consumer-$mode" --syms',
            'assert_owned_vm_bindings "$installed/usr/lib/libc.so" --syms',
            'assert_owned_vm_bindings "$installed/usr/lib/libc.so" --dyn-syms',
            'assert_dynamic_vm_imports "$work/consumer-$mode"',
            '["FUNC", "WEAK", "DEFAULT"]',
            'internal[3] == "FUNC" and internal[5] == "HIDDEN"',
            '["FUNC", "GLOBAL", "DEFAULT"]',
            'R_X86_64_JUMP_SLOT',
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
