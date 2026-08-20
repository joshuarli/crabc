import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import runner


class RunnerTests(unittest.TestCase):
    def test_math_oracle_expectations_are_narrow_and_have_evidence(self) -> None:
        expected = {
            ("math", "acosh"),
            ("math", "asinh"),
            ("math", "j0"),
            ("math", "jn"),
            ("math", "jnf"),
            ("math", "lgamma"),
            ("math", "lgammaf"),
            ("math", "lgammaf_r"),
            ("math", "sinh"),
            ("math", "tgamma"),
            ("math", "y0"),
            ("math", "y0f"),
            ("math", "ynf"),
        }
        self.assertEqual(set(runner.ORACLE_EXPECTATION_SKIPS), expected)
        for identity, record in runner.ORACLE_EXPECTATION_SKIPS.items():
            self.assertEqual(record["kind"], "oracle_expectation")
            self.assertEqual(record["architecture"], "aarch64")
            self.assertTrue(record["reason"])
            self.assertTrue(record["reference"].startswith("https://musl.libc.org/releases/musl-1.2.6.tar.gz"))
            self.assertEqual(len(record["verified"]), 10)
            evidence = Path(runner.__file__).parent / record["evidence"]
            self.assertTrue(evidence.is_file(), identity)

    def test_raw_bit_evidence_parses_every_oracle_vector(self) -> None:
        evidence_root = Path(runner.__file__).parent
        for (_, function), skip in runner.ORACLE_EXPECTATION_SKIPS.items():
            records = runner.parse_oracle_evidence(evidence_root / skip["evidence"], function)
            self.assertTrue(records, function)
            self.assertTrue(all("input_bits" in record for record in records), function)
            self.assertTrue(all("result_bits" in record for record in records), function)
            kind, width = runner.ORACLE_FUNCTIONS[function]
            limit = 1 << width
            self.assertTrue(all(0 <= record["input_bits"] < limit for record in records), function)
            self.assertTrue(all(0 <= record["result_bits"] < limit for record in records), function)
            if kind == "indexed":
                self.assertTrue(all(isinstance(record["n"], int) for record in records), function)

    def test_oracle_verifier_source_checks_bits_and_gamma_sign(self) -> None:
        evidence_root = Path(runner.__file__).parent
        gamma_skip = runner.ORACLE_EXPECTATION_SKIPS[("math", "lgamma")]
        gamma_records = runner.parse_oracle_evidence(
            evidence_root / gamma_skip["evidence"], "lgamma"
        )
        gamma_source = runner.render_oracle_verifier("lgamma", gamma_records)
        self.assertIn("lgamma(", gamma_source)
        self.assertIn("bits64(result_0)", gamma_source)
        self.assertIn("sign_0 != -1", gamma_source)

        indexed_skip = runner.ORACLE_EXPECTATION_SKIPS[("math", "ynf")]
        indexed_records = runner.parse_oracle_evidence(
            evidence_root / indexed_skip["evidence"], "ynf"
        )
        indexed_source = runner.render_oracle_verifier("ynf", indexed_records)
        self.assertIn("ynf(3,", indexed_source)
        self.assertIn("ynf(6,", indexed_source)

    def test_oracle_verifier_mismatch_is_a_failure(self) -> None:
        skip = runner.ORACLE_EXPECTATION_SKIPS[("math", "sinh")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def failed_verifier(
                command: list[str], cwd: Path, output_path: Path, env: dict[str, str]
            ) -> int:
                output_path.write_text("sinh vector mismatch\n")
                return 1

            with patch.object(runner, "execute", return_value=0), patch.object(
                runner, "execute_timeout", side_effect=failed_verifier
            ):
                verified, diagnostic, detail = runner.verify_oracle_expectation(
                    "sinh",
                    skip,
                    Path(runner.__file__).parent,
                    root,
                    root,
                    root / "fake-libs",
                    root / "libldso.so",
                    root / "build",
                    {},
                )
            self.assertFalse(verified)
            self.assertIn("current mismatch", detail)
            self.assertTrue(diagnostic.is_file())
            self.assertIn("sinh vector mismatch", diagnostic.read_text())
            self.assertIn("sinh(", (root / "build" / "oracle" / "sinh.c").read_text())

    def test_run_subset_does_not_classify_verifier_mismatch_as_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script_dir = root / "harness"
            script_dir.mkdir()
            libc_test_dir = root / "libc-test"
            (libc_test_dir / "src" / "math").mkdir(parents=True)
            (libc_test_dir / "src" / "math" / "sinh.c").write_text("/* mocked test */\n")
            fake_libs = root / "fake-libs"
            fake_libs.mkdir()
            build_dir = root / "build"
            report_dir = root / "reports"
            report_dir.mkdir()
            diagnostic = root / "sinh.err"

            with patch.object(
                runner,
                "setup_crabc",
                return_value=(fake_libs, build_dir, report_dir),
            ), patch.object(runner, "build_runtest", return_value=root / "runtest.exe"), patch.object(
                runner.platform, "machine", return_value="aarch64"
            ), patch.object(
                runner,
                "verify_oracle_expectation",
                return_value=(False, diagnostic, "oracle verifier found a current mismatch for sinh"),
            ) as verify, patch.object(
                runner, "generate_structured_reports"
            ), patch.object(runner, "exported_symbol_count", return_value=0):
                result = runner.run_subset("math", script_dir, root, libc_test_dir)

            self.assertEqual(result, 0)
            verify.assert_called_once()
            raw_reports = list(report_dir.glob("raw_*.txt"))
            self.assertEqual(len(raw_reports), 1)
            raw = raw_reports[0].read_text()
            self.assertIn("FAIL math/sinh: oracle verifier found a current mismatch", raw)
            self.assertNotIn("SKIP math/sinh", raw)

    def test_all_compile_applies_strict_header_flags_only_to_api(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script_dir = root / "harness"
            script_dir.mkdir()
            libc_test_dir = root / "libc-test"
            functional_dir = libc_test_dir / "src" / "functional"
            api_dir = libc_test_dir / "src" / "api"
            functional_dir.mkdir(parents=True)
            api_dir.mkdir(parents=True)
            functional_source = functional_dir / "socket.c"
            api_source = api_dir / "socket.h.c"
            functional_source.write_text("/* mocked functional source */\n")
            api_source.write_text("/* mocked API source */\n")
            fake_libs = root / "fake-libs"
            fake_libs.mkdir()
            build_dir = root / "build"
            report_dir = root / "reports"
            report_dir.mkdir()
            compile_commands: list[list[str]] = []

            def capture_compile(command: list[str], **kwargs: object) -> int:
                if "-c" in command:
                    compile_commands.append(command)
                    return 0
                return 1

            with patch.object(
                runner,
                "setup_crabc",
                return_value=(fake_libs, build_dir, report_dir),
            ), patch.object(runner, "build_runtest", return_value=root / "runtest.exe"), patch.object(
                runner, "execute", side_effect=capture_compile
            ), patch.object(
                runner, "generate_structured_reports"
            ), patch.object(runner, "exported_symbol_count", return_value=0):
                runner.run_subset("all", script_dir, root, libc_test_dir)

            functional_command = next(
                command for command in compile_commands if str(functional_source) in command
            )
            api_command = next(command for command in compile_commands if str(api_source) in command)
            self.assertNotIn("-nostdinc", functional_command)
            self.assertIn("-nostdinc", api_command)

    def test_raw_bit_evidence_rejects_non_nearest_rounding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "bad.txt"
            evidence.write_text("[j0]\n1 1 3ff0000000000000 0000000000000000 0000000000000000\n")
            with self.assertRaisesRegex(ValueError, "round-to-nearest"):
                runner.parse_oracle_evidence(evidence, "j0")

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
