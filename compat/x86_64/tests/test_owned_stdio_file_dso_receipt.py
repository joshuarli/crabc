"""Physical pathname checks for the cross-image FILE receipt."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_stdio_file_dso_receipt.py"
spec = importlib.util.spec_from_file_location("owned_stdio_file_dso_receipt", MODULE)
assert spec is not None and spec.loader is not None
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


class FileDsoReceiptTests(unittest.TestCase):
    def test_reopened_path_and_memstream_bytes_are_reread(self) -> None:
        case = "oracle-static-process"
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            work = Path(temporary)
            raw = work / "raw"
            raw.mkdir()
            execution = work / "execution-roots" / case
            scratch = execution / "scratch"
            scratch.mkdir(parents=True)
            scratch.chmod(0o755)
            (work / "oracle-static").write_bytes(b"baseline executable")
            (execution / "consumer").write_bytes(b"baseline executable")
            for name, contents in zip(receipt.RETAINED_PATHS, receipt.RETAINED_BYTES):
                (scratch / name).write_bytes(contents)
            (raw / f"{case}.status").write_bytes(b"0\n")
            (raw / f"{case}.stdout").write_bytes(receipt.EXPECTED_STDOUT)
            (raw / f"{case}.stderr").write_bytes(b"")
            (raw / f"{case}.scratch-before.json").write_text("[]\n")
            (raw / f"{case}.scratch-after.json").write_text(
                '["stream.exit", "stream.fini", "stream.new", "stream.old"]\n')
            (raw / f"{case}.strace").write_text(
                'unlink("/scratch/stream") = 0\n'
                'fcntl(3, F_GETFD) = -1 EBADF (Bad file descriptor)\n'
                'write(3, "\\xe2\\x82\\xac", 3) = 3\n'
                'write(3, "fini-before-flush:fd-live\\n", 26) = 26\n'
                'write(3, "dso-exit-once\\n", 14) = 14\n')
            with mock.patch.object(receipt, "CASES", (case,)):
                receipt.audit_runtime(work, work / "unused-dynamic")
                (raw / f"{case}.stdout").write_bytes(
                    receipt.EXPECTED_STDOUT.replace(b"alXYa!\0\0Z", b"alXYa!\0\0Y"))
                with self.assertRaisesRegex(receipt.ReceiptError, "stdout differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (raw / f"{case}.stdout").write_bytes(receipt.EXPECTED_STDOUT)
                (scratch / "stream.old").write_bytes(b"beforetaim")
                with self.assertRaisesRegex(receipt.ReceiptError, "retained pathname bytes differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")


if __name__ == "__main__":
    unittest.main()
