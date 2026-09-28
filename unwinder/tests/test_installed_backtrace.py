"""Post-exit backtrace replay rehashes each child observation."""
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))
import installed_backtrace as backtrace  # noqa: E402


WORK = Path(__file__).parents[2] / ".work/x86_64/unwinder-output-tests"


class InstalledBacktraceReplay(unittest.TestCase):
    def test_post_exit_reread_rejects_missing_or_changed_streams(self):
        WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            output = Path(temporary) / "static"
            line = ("backtrace static-nested thread=100 status=5 cutoff=3 cutoff_frames=3 "
                    "target=150:100:200 host=none pcs=120,130,300\n"
                    "unwind: backtrace cleanup payload main thread\n")
            stdout = output.with_suffix(".stdout")
            stderr = output.with_suffix(".stderr")
            status = output.with_suffix(".status")
            stdout.write_text(line)
            stderr.write_text("")
            status.write_text("0\n")
            record = {
                "command": ["/fixture"], "status": 0,
                "stdout": backtrace.owned.record_file(stdout, "test stdout"),
                "stderr": backtrace.owned.record_file(stderr, "test stderr"),
                "status_file": backtrace.owned.record_file(status, "test status"),
                "backtrace": backtrace.owned.assert_backtrace_execution(0, line, "", backtrace.STATIC_LABELS),
            }
            self.assertEqual(backtrace.replay_record(record, backtrace.STATIC_LABELS), record["backtrace"])
            stdout.write_text(line.replace("pcs=120,130,300", "pcs=120,300"))
            with self.assertRaisesRegex(backtrace.owned.OwnedCleanupError, "changed"):
                backtrace.replay_record(record, backtrace.STATIC_LABELS)
            stdout.unlink()
            with self.assertRaisesRegex(backtrace.owned.OwnedCleanupError, "unreadable"):
                backtrace.replay_record(record, backtrace.STATIC_LABELS)
