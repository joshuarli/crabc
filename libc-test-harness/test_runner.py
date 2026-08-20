import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import runner


class RunnerTests(unittest.TestCase):
    def test_render_options_header_matches_libc_test_protocol(self) -> None:
        rendered = runner.render_options_header(
            "# 1 \"options.h.in\"\n"
            "optiongroups_unistd_end\n"
            "POSIX_ADVISORY_INFO\n"
            "200809L\n"
            "XOPEN_UNIX 700\n"
        )

        self.assertEqual(
            rendered,
            "/* Generated from libc-test/src/common/options.h.in. */\n"
            "#define POSIX_ADVISORY_INFO 200809L\n"
            "#define XOPEN_UNIX 700\n",
        )

    def test_rejects_unknown_or_extra_subset_arguments(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(["runner.py", "unknown"]), 2)
            self.assertEqual(runner.main(["runner.py", "api", "extra"]), 2)

    def test_human_summary_keeps_status_breakdown_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw.txt"
            raw.write_text(
                "BUILDERROR api/missing: compile failed\n"
                "FAIL functional/example\n"
                "  example failed\n"
                "SKIP regression/statvfs: pinned musl also fails\n"
                "PASS functional/ok\n"
            )
            summary = root / "summary.txt"
            counters = {
                "TOTAL": 4,
                "BUILDERROR": 1,
                "FAIL": 1,
                "PASS": 1,
                "TIMEOUT": 0,
                "SKIP": 1,
                "OTHER": 0,
            }

            text = runner.write_human_summary(
                summary, raw, root / "missing-libc.so", "functional", counters
            )

            self.assertIn("BUILDERROR: 1", text)
            self.assertIn("BUILDERROR tests:\n  api/missing: compile failed", text)
            self.assertIn("FAIL tests:\n  functional/example", text)
            self.assertIn("SKIP:       1", text)
            self.assertIn("SKIP tests:\n  regression/statvfs: pinned musl also fails", text)
            self.assertIn("PASS tests:\n  functional/ok", text)

    def test_symlink_replacement_does_not_follow_previous_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.txt"
            second = root / "second.txt"
            link = root / "latest.txt"
            first.write_text("first")
            second.write_text("second")

            runner.replace_symlink(first, link)
            runner.replace_symlink(second, link)

            self.assertEqual(link.read_text(), "second")
            self.assertTrue(link.is_symlink())


if __name__ == "__main__":
    unittest.main()
