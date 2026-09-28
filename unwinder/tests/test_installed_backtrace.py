"""Post-exit backtrace replay rehashes each child observation."""
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))
import installed_backtrace as backtrace  # noqa: E402


WORK = Path(__file__).parents[2] / ".work/x86_64/unwinder-output-tests"


class InstalledBacktraceReplay(unittest.TestCase):
    def test_panic_dso_requires_control_cleanup_resume_and_worker_completion(self):
        self.assertEqual(backtrace.panic_dso_result(0, backtrace.PANIC_DSO_OUTPUT, ""),
                         {"status": 0, "mapped_control": 8, "direct_drops": 2,
                          "resume_drops": 3, "worker_join": 0})
        for output in (
            backtrace.PANIC_DSO_OUTPUT.replace("panic mapped-control=8\n", ""),
            backtrace.PANIC_DSO_OUTPUT.replace("panic direct worker drops=2", "panic direct worker drops=1"),
            backtrace.PANIC_DSO_OUTPUT.replace("panic resume main drops=3", "panic resume main drops=2"),
            backtrace.PANIC_DSO_OUTPUT.replace("panic worker-join=0", "panic worker-join=139"),
            backtrace.PANIC_DSO_OUTPUT + "extra\n",
        ):
            with self.subTest(output=output), self.assertRaises(backtrace.owned.OwnedCleanupError):
                backtrace.panic_dso_result(0, output, "")
        with self.assertRaises(backtrace.owned.OwnedCleanupError):
            backtrace.panic_dso_result(-11, backtrace.PANIC_DSO_OUTPUT, "")

    def test_guarded_dso_cfi_requires_phase_error_without_child_fault(self):
        self.assertEqual(backtrace.guarded_cfi_result(0, backtrace.GUARDED_CFI_OUTPUT, ""),
                         {"mapped": {"unwind": 5, "wait": 0},
                          "unreadable": {"unwind": 3, "wait": 0}})
        for output in (
            backtrace.GUARDED_CFI_OUTPUT.replace("unreadable wait=0", "unreadable wait=139"),
            backtrace.GUARDED_CFI_OUTPUT.replace("unreadable unwind=3", "unreadable unwind=5"),
            backtrace.GUARDED_CFI_OUTPUT.replace("mapped unwind=5\n", ""),
            backtrace.GUARDED_CFI_OUTPUT + "extra\n",
        ):
            with self.subTest(output=output), self.assertRaises(backtrace.owned.OwnedCleanupError):
                backtrace.guarded_cfi_result(0, output, "")
        with self.assertRaises(backtrace.owned.OwnedCleanupError):
            backtrace.guarded_cfi_result(-11, backtrace.GUARDED_CFI_OUTPUT, "")

    def test_guarded_dso_reader_rejects_changed_child_status_file(self):
        WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            output = Path(temporary) / "guarded-cfi"
            record = backtrace.capture(["/bin/sh", "-c", "printf 'child\\n'"], output)
            self.assertEqual(backtrace.capture_record(record), (0, "child\n", ""))
            output.with_suffix(".status").write_text("139\n")
            with self.assertRaises(backtrace.owned.OwnedCleanupError):
                backtrace.capture_record(record)

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
