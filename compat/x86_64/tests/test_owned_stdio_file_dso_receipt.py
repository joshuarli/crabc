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
    def test_path_memory_orientation_and_full_sink_failures_are_reread(self) -> None:
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
                '["stream.dso-global", "stream.exit", "stream.fini", '
                '"stream.main-global", "stream.new", "stream.old", '
                '"stream.orientation-byte", "stream.orientation-wide"]\n')
            (raw / f"{case}.strace").write_text(
                'unlink("/scratch/stream") = 0\n'
                'fcntl(3, F_GETFD) = -1 EBADF (Bad file descriptor)\n'
                'write(3, "\\xe2\\x82\\xac", 3) = 3\n'
                'write(4, "dso-before\\n", 11) = 11\n'
                'write(3, "main-before\\n", 12) = 12\n'
                'write(4, "dso-after\\n", 10) = 10\n'
                'write(3, "main-after\\n", 11) = 11\n'
                'write(3, "\\xe2\\x82\\xac\\xce\\xbb", 5) = 5\n'
                'write(3, "M:dso", 5) = 5\n'
                'open("/dev/full", O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0666) = 3\n'
                'writev(3, [{iov_base="pending", iov_len=7}], 1) = -1 ENOSPC (No space left on device)\n'
                'close(3) = 0\n'
                'open("/dev/full", O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0666) = 3\n'
                'writev(3, [{iov_base="closing", iov_len=7}], 1) = -1 ENOSPC (No space left on device)\n'
                'close(3) = 0\n'
                'write(3, "fini-before-flush:fd-live\\n", 26) = 26\n'
                'write(3, "dso-exit-once\\n", 14) = 14\n')
            with mock.patch.object(receipt, "CASES", (case,)), mock.patch.object(
                    receipt, "expected_root", return_value=receipt.tree(execution)):
                receipt.audit_runtime(work, work / "unused-dynamic")
                (raw / f"{case}.stdout").write_bytes(
                    receipt.EXPECTED_STDOUT.replace(b"alXYa!\0\0Z", b"alXYa!\0\0Y"))
                with self.assertRaisesRegex(receipt.ReceiptError, "stdout differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (raw / f"{case}.stdout").write_bytes(receipt.EXPECTED_STDOUT)
                (raw / f"{case}.stdout").write_bytes(
                    receipt.EXPECTED_STDOUT.replace(b"abcDEFGH", b"abcDEFGI"))
                with self.assertRaisesRegex(receipt.ReceiptError, "stdout differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (raw / f"{case}.stdout").write_bytes(receipt.EXPECTED_STDOUT)
                (raw / f"{case}.stdout").write_bytes(
                    receipt.EXPECTED_STDOUT.replace(receipt.WIDE_MEMORY_FINAL,
                        receipt.WIDE_MEMORY_FINAL[:20] + b"\xa8\x03\0\0" +
                        receipt.WIDE_MEMORY_FINAL[24:]))
                with self.assertRaisesRegex(receipt.ReceiptError, "stdout differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (raw / f"{case}.stdout").write_bytes(receipt.EXPECTED_STDOUT)
                (scratch / "stream.old").write_bytes(b"beforetaim")
                with self.assertRaisesRegex(receipt.ReceiptError, "retained pathname bytes differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (scratch / "stream.old").write_bytes(b"beforetail")
                (scratch / "stream.dso-global").write_bytes(b"dso-before\ndso-after!")
                with self.assertRaisesRegex(receipt.ReceiptError, "retained pathname bytes differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (scratch / "stream.dso-global").write_bytes(b"dso-before\ndso-after\n")
                trace_path = raw / f"{case}.strace"
                trace = trace_path.read_text()
                trace_path.write_text(trace.replace(
                    'write(4, "dso-before\\n", 11) = 11\n'
                    'write(3, "main-before\\n", 12) = 12\n',
                    'write(3, "main-before\\n", 12) = 12\n'
                    'write(4, "dso-before\\n", 11) = 11\n'))
                with self.assertRaisesRegex(receipt.ReceiptError, "global flush order differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                trace_path.write_text(trace)
                (scratch / "stream.orientation-wide").write_bytes(b"\xe2\x82\xac\xce\xba")
                with self.assertRaisesRegex(receipt.ReceiptError, "retained pathname bytes differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (scratch / "stream.orientation-wide").write_bytes(b"\xe2\x82\xac\xce\xbb")
                (scratch / "stream.orientation-byte").write_bytes(b"M:dsO")
                with self.assertRaisesRegex(receipt.ReceiptError, "retained pathname bytes differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                (scratch / "stream.orientation-byte").write_bytes(b"M:dso")
                trace_path.write_text(trace.replace(
                    'write(3, "\\xe2\\x82\\xac\\xce\\xbb", 5) = 5\n'
                    'write(3, "M:dso", 5) = 5\n',
                    'write(3, "M:dso", 5) = 5\n'
                    'write(3, "\\xe2\\x82\\xac\\xce\\xbb", 5) = 5\n'))
                with self.assertRaisesRegex(receipt.ReceiptError, "orientation write order differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                trace_path.write_text(trace.replace(
                    'writev(3, [{iov_base="pending", iov_len=7}], 1) = -1 ENOSPC',
                    'writev(3, [{iov_base="pending", iov_len=7}], 1) = 7'))
                with self.assertRaisesRegex(receipt.ReceiptError, "full-sink buffered failures differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                trace_path.write_text(trace.replace(
                    'writev(3, [{iov_base="closing", iov_len=7}], 1) = -1 ENOSPC',
                    'writev(3, [{iov_base="closing", iov_len=7}], 1) = 7'))
                with self.assertRaisesRegex(receipt.ReceiptError, "full-sink buffered failures differ"):
                    receipt.audit_runtime(work, work / "unused-dynamic")
                trace_path.write_text(trace.replace(
                    'writev(3, [{iov_base="closing", iov_len=7}], 1) = -1 ENOSPC (No space left on device)\n'
                    'close(3) = 0\n',
                    'writev(3, [{iov_base="closing", iov_len=7}], 1) = -1 ENOSPC (No space left on device)\n'))
                with self.assertRaisesRegex(receipt.ReceiptError, "full-sink descriptor close differs"):
                    receipt.audit_runtime(work, work / "unused-dynamic")


if __name__ == "__main__":
    unittest.main()
