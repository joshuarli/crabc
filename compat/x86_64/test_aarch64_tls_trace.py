#!/usr/bin/env python3
"""Prove the native TLS rejection tracer observes TPIDR_EL0 writes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class Aarch64TlsTrace(unittest.TestCase):
    def test_thread_pointer_write_is_detected_before_execution(self):
        source = Path(__file__).with_name("ldso_general_initial_tls_trace.c")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            work = Path(directory)
            tracer = work / "tracer"
            subprocess.run(["cc", "-D_GNU_SOURCE", "-std=c11", "-static", source, "-o", tracer], check=True)
            atomic = work / "atomic.S"
            atomic.write_text(".bss\n.balign 8\ncell: .quad 0\n.text\n.global _start\n_start:\nadrp x1, cell\nadd x1, x1, :lo12:cell\n1: ldxr x2, [x1]\nadd x2, x2, #1\nstxr w3, x2, [x1]\ncbnz w3, 1b\nmov x0, #127\nmov x8, #93\nsvc #0\n")
            atomic_output = work / "atomic"
            subprocess.run(["cc", "-static", "-nostdlib", atomic, "-o", atomic_output], check=True)
            self.assertEqual(subprocess.run([tracer, atomic_output], capture_output=True, timeout=20).returncode, 0)
            mapped = work / "mapped.S"
            mapped.write_text(".text\n.global _start\n_start:\nmov x0, #0\nmov x1, #4096\nmov x2, #3\nmov x3, #0x22\nmov x4, #-1\nmov x5, #0\nmov x8, #222\nsvc #0\nmov x9, x0\nmovz w1, #0xd05f\nmovk w1, #0xd51b, lsl #16\nstr w1, [x9]\nmov x1, #4096\nmov x2, #5\nmov x8, #226\nsvc #0\nbr x9\n")
            mapped_output = work / "mapped"
            subprocess.run(["cc", "-static", "-nostdlib", mapped, "-o", mapped_output], check=True)
            self.assertEqual(subprocess.run([tracer, mapped_output], capture_output=True, timeout=20).returncode, 72)
            for write in (False, True):
                assembly = work / ("write.S" if write else "clean.S")
                executable = assembly.with_suffix("")
                assembly.write_text(".global _start\n_start:\n" +
                                    ("msr tpidr_el0, xzr\n" if write else "") +
                                    "mov x0, #127\nmov x8, #93\nsvc #0\n")
                subprocess.run(["cc", "-static", "-nostdlib", assembly, "-o", executable], check=True)
                result = subprocess.run([tracer, executable], capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 72 if write else 0, result.stderr.decode())
                if write:
                    self.assertIn(b"wrote TPIDR_EL0", result.stderr)


if __name__ == "__main__":
    unittest.main()
