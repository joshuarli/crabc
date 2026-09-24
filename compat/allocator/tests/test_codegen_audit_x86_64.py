"""Reader contracts for the native x86-64 allocator codegen audit.

These tests cover instruction classification, AT&T effective-address
recovery, and executed-trace attribution against a synthetic image. They do
not build, disassemble, or ptrace anything.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "codegen_audit_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_codegen_audit_x86_64_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def instruction(address: int, text: str, target: int | None = None) -> "audit.Instruction":
    mnemonic, _, operands = text.partition(" ")
    operands = operands.strip()
    while mnemonic in {"lock", "rep"} and operands:
        inner, _, operands = operands.partition(" ")
        mnemonic = f"{mnemonic} {inner}"
        operands = operands.strip()
    return audit.Instruction(address, mnemonic, operands, text, target)


class FakeImage:
    """Just enough of `Image` for trace attribution."""

    def __init__(self) -> None:
        self.symbols = [(0x100, 0x110, "entry"), (0x200, 0x210, "helper"), (0x300, 0x310, "memset")]
        self.starts = [start for start, _, _ in self.symbols]
        self.by_name = {name: (start, end) for start, end, name in self.symbols}
        self.instructions = {
            0x100: instruction(0x100, "push %rbx"),
            0x101: instruction(0x101, "sub $0x48,%rsp"),
            0x105: instruction(0x105, "call 200 <helper>", 0x200),
            0x10a: instruction(0x10a, "xchg %al,%fs:0xffffffffffffffd8"),
            0x10f: instruction(0x10f, "jmp 300 <memset>", 0x300),
            0x200: instruction(0x200, "lock cmpxchg %ecx,0x40(%rsi)"),
            0x205: instruction(0x205, "div %r12d"),
            0x208: instruction(0x208, "ret"),
            0x300: instruction(0x300, "rep stos %rax,%es:(%rdi)"),
            0x303: instruction(0x303, "ret"),
        }
        self.data_symbols = [(0x5000, 0x6000, "PROCESS_STATIC")]
        self.data_starts = [0x5000]

    function_at = audit.Image.function_at
    data_symbol_at = audit.Image.data_symbol_at


class Registers:
    def __init__(self, **values: int) -> None:
        for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "fs_base"):
            setattr(self, name, values.get(name, 0))


class ClassificationTests(unittest.TestCase):
    def test_locked_and_memory_xchg_are_atomic_but_register_xchg_is_not(self) -> None:
        self.assertTrue(audit.is_atomic_rmw(instruction(0, "lock incq 0x28e8(%rcx)")))
        self.assertTrue(audit.is_atomic_rmw(instruction(0, "xchg %eax,(%rdi)")))
        self.assertTrue(audit.is_atomic_rmw(instruction(0, "xchg %al,%fs:0xffffffffffffffd8")))
        self.assertFalse(audit.is_atomic_rmw(instruction(0, "xchg %eax,%ebx")))
        self.assertTrue(audit.is_division(instruction(0, "div %r12d")))
        self.assertTrue(audit.is_division(instruction(0, "idivq (%rsi)")))
        self.assertFalse(audit.is_division(instruction(0, "divsd %xmm1,%xmm0")))
        self.assertTrue(audit.is_string_op(instruction(0, "rep movsq (%rsi),(%rdi)")))
        self.assertEqual(audit.stack_allocation(instruction(0, "sub $0x588,%rsp")), 0x588)

    def test_effective_address_recovery(self) -> None:
        registers = Registers(rsi=0x5000, rax=3, rdi=0x7000, fs_base=0x9000)
        self.assertEqual(audit.effective_address(instruction(0, "lock cmpxchg %ecx,0x40(%rsi)"), registers), (0x5040, "memory"))
        self.assertEqual(audit.effective_address(instruction(0, "lock addq $0x1,-0x8(%rdi,%rax,8)"), registers), (0x7010, "memory"))
        self.assertEqual(audit.effective_address(instruction(0, "xchg %al,%fs:0xffffffffffffffd8"), registers), (0x8FD8, "thread-local"))
        self.assertEqual(
            audit.effective_address(instruction(0, "lock incq 0x4a2c6(%rip)        # 494b20 <STATIC>"), registers),
            (0x494B20, "static"),
        )

    def test_target_classes_name_process_statics(self) -> None:
        image = FakeImage()
        self.assertEqual(audit.classify_target(image, 0x5040, "memory", 0x7FFF0000), "static:PROCESS_STATIC+0x40")
        self.assertEqual(audit.classify_target(image, 0x7FFEFF00, "memory", 0x7FFF0000), "stack")
        self.assertEqual(audit.classify_target(image, 0x9000, "thread-local", 0x7FFF0000), "thread-local")
        self.assertEqual(audit.classify_target(image, 0x12345000, "memory", 0x7FFF0000), "dynamic")


class TraceAnalysisTests(unittest.TestCase):
    def test_region_attributes_functions_calls_atomics_and_rep_iterations(self) -> None:
        image = FakeImage()
        rips = [0x100, 0x101, 0x105, 0x200, 0x205, 0x208, 0x10a, 0x10f, 0x300, 0x300, 0x300, 0x303]
        region = audit.Region(rips, {3: (0x5040, "memory", 0x7FFF0000), 6: (0x8FD8, "thread-local", 0x7FFF0000)})
        summary, listing = audit.analyze_region(image, region)
        self.assertEqual(summary["instructions"], 10)
        self.assertEqual(summary["single_steps"], 12)
        self.assertEqual([entry["name"] for entry in summary["functions"]], ["entry", "helper", "memset"])
        transitions = {(entry["from"], entry["to"]) for entry in summary["call_transitions"]}
        self.assertEqual(transitions, {("entry", "helper"), ("entry", "memset")})
        self.assertEqual(sum(entry["count"] for entry in summary["atomic_rmw"]), 2)
        self.assertEqual(summary["atomic_rmw_targets"], {"static:PROCESS_STATIC+0x40": 1, "thread-local": 1})
        self.assertEqual(summary["atomic_rmw_non_thread_local"], 1)
        self.assertEqual(sum(entry["count"] for entry in summary["divisions"]), 1)
        self.assertEqual(summary["entered_memory_helpers"], ["memset"])
        self.assertEqual(summary["stack_bytes_allocated"], 0x48)
        self.assertTrue(listing[8].endswith("x3"))

    def test_comparison_names_rust_excess(self) -> None:
        image = FakeImage()
        c, _ = audit.analyze_region(image, audit.Region([0x100, 0x101], {}))
        rust, _ = audit.analyze_region(image, audit.Region([0x200, 0x205, 0x208], {0: (0x5040, "memory", 0x7FFF0000)}))
        comparison = audit.compare_regions(c, rust)
        self.assertIn("atomic_rmw: rust 1 > pinned C 0", comparison["rust_excess"])
        self.assertIn("divisions: rust 1 > pinned C 0", comparison["rust_excess"])
        self.assertEqual(comparison["atomic_rmw_non_thread_local"], {"pinned_c": 0, "rust_engine": 1})

    def test_comparison_names_extra_calls_and_zeroing_helpers(self) -> None:
        image = FakeImage()
        c, _ = audit.analyze_region(image, audit.Region([0x100, 0x101], {}))
        rips = [0x100, 0x101, 0x105, 0x200, 0x205, 0x208, 0x10a, 0x10f, 0x300, 0x300, 0x303]
        rust, _ = audit.analyze_region(image, audit.Region(rips, {}))
        excess = audit.compare_regions(c, rust)["rust_excess"]
        self.assertIn("calls: rust 2 > pinned C 0", excess)
        self.assertIn("string_ops: rust 1 > pinned C 0", excess)
        self.assertIn("entered_memory_helpers: memset", excess)
        self.assertEqual(audit.compare_regions(rust, rust)["rust_excess"], [])


if __name__ == "__main__":
    unittest.main()
