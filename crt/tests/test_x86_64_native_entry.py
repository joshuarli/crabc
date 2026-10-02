"""Execute the small owned-runtime entry fixtures supplied by a debug build.

Set CRABC_X86_64_CRT_ENTRY_WORK to the directory containing the two static
applications and entry-root with the two dynamic applications, libc and
interpreter. The same C fixture checks startup vectors, TLS, errno, helper
calls and lifecycle order in every mode.
"""

import os
from pathlib import Path
import resource
import shutil
import subprocess
import unittest


class NativeEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get("CRABC_X86_64_CRT_ENTRY_WORK")
        if supplied is None:
            raise unittest.SkipTest("requires source-built debug entry applications")
        cls.work = Path(supplied).resolve(strict=True)

    def entry(self, mode, *, dynamic):
        command = (
            [shutil.which("chroot"), str(self.work / "entry-root"), "/app/" + mode]
            if dynamic else [str(self.work / mode)]
        )
        command.extend(("first", "second"))
        environment = {"CRT109_STACK": "present"}
        # A rejected entry must leave its raw refusal, without a core dump.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = subprocess.run(command, env=environment, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, (mode, result.stdout, result.stderr))
        self.assertEqual(result.stderr, b"")
        # The dynamic constructor walk omits the executable preinit array.
        self.assertEqual(result.stdout, b"IJMAYX\n" if dynamic else b"PIJMAYX\n")

    def test_static_kernel_stack_and_native_tls_before_preinit(self):
        self.entry("static", dynamic=False)

    def test_static_pie_relocations_and_native_tls_before_preinit(self):
        self.entry("static-pie", dynamic=False)

    def test_dynamic_pie_loader_tls_and_main_lifecycle(self):
        self.entry("dynamic-pie", dynamic=True)

    def test_dynamic_non_pie_loader_tls_and_main_lifecycle(self):
        self.entry("dynamic-non-pie", dynamic=True)


if __name__ == "__main__":
    unittest.main()
