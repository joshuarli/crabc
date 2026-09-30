"""Observable dispatch and diagnostic boundaries for managed callback clients."""

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_managed_callback as managed
import x86_64_m6_child_managed_callback as child


class ManagedCallbackProfilesTests(unittest.TestCase):
    def test_default_preserves_imported_release_workload(self):
        for module in (managed, child):
            with self.subTest(module=module.__name__), mock.patch.object(module, "run_differential", return_value=11) as release:
                module.main([])
                release.assert_called_once_with()

    def test_matrix_dispatches_explicit_client_without_default_release(self):
        for module in (managed, child):
            with self.subTest(module=module.__name__), mock.patch.object(module, "run_differential") as release, mock.patch.object(managed, "run_profile_matrix", create=True) as matrix:
                module.main(["--matrix"])
                release.assert_not_called()
                matrix.assert_called_once_with(module)

    def test_unknown_option_does_not_start_allocator(self):
        with mock.patch.object(managed, "run_differential") as release:
            with self.assertRaises(SystemExit):
                managed.main(["--unknown"])
            release.assert_not_called()

    def test_diagnostics_preserve_warning_and_source_assertion_semantics(self):
        raw = f"mimalloc: warning: thread 0x1234: {managed.WARNING}\nsource.callback=1,1\n".encode()
        managed.check_diagnostics(managed, "c", raw)
        child_raw = f"mimalloc: warning: thread 0x5678: {child.WARNING}source.child_callback=1,1,1\n".encode()
        managed.check_diagnostics(child, "c", child_raw)
        with self.assertRaises(managed.harness.HarnessError):
            managed.check_diagnostics(child, "c", child_raw.replace(b"1,1,1", b"1,0,1"))
        for broken in (raw.replace(b"1,1", b"1,0"), raw + b"unexpected\n", raw.replace(b"32767", b"32766"), raw.replace(b"0x1234", b"0x0")):
            with self.subTest(raw=broken), self.assertRaises(managed.harness.HarnessError):
                managed.check_diagnostics(managed, "c", broken)
        with self.assertRaises(managed.harness.HarnessError):
            managed.check_diagnostics(managed, "native", raw)


if __name__ == "__main__":
    unittest.main()
