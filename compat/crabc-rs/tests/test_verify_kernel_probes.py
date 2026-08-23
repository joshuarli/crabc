"""Focused semantic-proof tests for direct-kernel probe verification."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_kernel_probes", ROOT / "compat" / "crabc-rs" / "verify_kernel_probes.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class Verify0KernelTests(unittest.TestCase):
    def test_multimessage_probe_keeps_the_urgent_mark_boundary_live(self) -> None:
        probe = (ROOT / "crabc-rs/examples/network_mmsg_direct_probe.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("let mut first_storage = [MaybeUninit::<u8>::uninit(); 7]", probe)
        self.assertIn("incoming[0].bytes() != 7", probe)
        self.assertIn("match net::sockatmark(&receiver)", probe)

    def test_accepts_each_direct_probe_contract(self) -> None:
        for probe in VERIFY.PROBES.values():
            with self.subTest(entrypoint=probe.entrypoint):
                disassembly = "\n".join(
                    f"mov w8, #{number:#x}\nsvc #0" for number in probe.syscalls
                )
                report = VERIFY.inspect(
                    probe,
                    "Machine: AArch64",
                    disassembly,
                    f"0000000000000000 T {probe.entrypoint}\n",
                )
                self.assertTrue(report["direct_svc"])

    def test_rejects_missing_architecture_entrypoint_or_syscall(self) -> None:
        probe = VERIFY.PROBES["positioned"]
        with self.assertRaisesRegex(VERIFY.VerificationError, "AArch64"):
            VERIFY.inspect(probe, "Machine: x86-64", "", probe.entrypoint)
        with self.assertRaisesRegex(VERIFY.VerificationError, "entry point"):
            VERIFY.inspect(probe, "Machine: AArch64", "", "")
        with self.assertRaisesRegex(VERIFY.VerificationError, "missing direct"):
            VERIFY.inspect(probe, "Machine: AArch64", "svc #0", probe.entrypoint)

    def test_rejects_each_forbidden_public_symbol(self) -> None:
        for probe in VERIFY.PROBES.values():
            syscalls = "\n".join(
                f"mov w8, #{number:#x}\nsvc #0" for number in probe.syscalls
            )
            for symbol in probe.forbidden_symbols:
                with self.subTest(entrypoint=probe.entrypoint, symbol=symbol):
                    with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden"):
                        VERIFY.inspect(
                            probe,
                            "Machine: AArch64",
                            f"{syscalls}\nbl <{symbol}>\n",
                            probe.entrypoint,
                        )


if __name__ == "__main__":
    unittest.main()
