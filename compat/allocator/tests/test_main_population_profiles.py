"""Exercise complete population dispatch, raw bytes, and failure propagation."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_main_visitor_population as population
import x86_64_m6_main_population_after_owner_exit as owners


class MainPopulationProducerTests(unittest.TestCase):
    def setUp(self):
        root = population.harness.ROOT / ".work/tmp"
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)

    def test_default_and_matrix_dispatch_preserve_complete_clients(self):
        for fixture in (population, owners):
            with self.subTest(fixture=fixture.RUNNER):
                with mock.patch.object(fixture, "run_differential", return_value=14) as release:
                    fixture.main([])
                    release.assert_called_once_with()
                with mock.patch.object(fixture, "run_differential") as release, mock.patch.object(population, "run_profiles") as matrix:
                    fixture.main(["--matrix"])
                    release.assert_not_called()
                    matrix.assert_called_once_with(fixture, population.PROFILES)
                with mock.patch.object(population, "run_profiles") as single:
                    fixture.main(["--profile", "stat-2"])
                    single.assert_called_once_with(fixture, ("stat-2",))

    def test_invalid_option_stops_before_population_execution(self):
        with mock.patch.object(population, "run_profiles") as execute:
            with self.assertRaises(SystemExit):
                owners.main(["--unknown"])
            execute.assert_not_called()

    def test_real_nonzero_process_keeps_exact_stdout_stderr_and_status(self):
        code = "import sys; sys.stdout.buffer.write(b'partial\\x00trace'); sys.stderr.buffer.write(b'warning\\xff\\n'); sys.exit(7)"
        result, logs = population.record(self.output, "failure", [sys.executable, "-c", code], self.output, 10, True)
        self.assertEqual(result["status"], 7)
        self.assertEqual((self.output / "failure.stdout").read_bytes(), b"partial\x00trace")
        self.assertEqual((self.output / "failure.stderr").read_bytes(), b"warning\xff\n")
        self.assertEqual(json.loads(logs[0].read_text()), result)

    def test_process_failure_preserves_every_original_case_and_both_backends(self):
        for fixture in (population, owners):
            with self.subTest(fixture=fixture.RUNNER):
                calls, cases = [], []
                def observed(output, label, argv, cwd, timeout, runtime):
                    calls.append(argv)
                    status = 7 if len(calls) == 1 else 0
                    result = {"kind": "process", "status": status,
                        "stdout": population.stress.bytes_record(b"trace"),
                        "stderr": population.stress.bytes_record(b"warning\n")}
                    log = output / f"{label}.json"
                    log.write_text(json.dumps(result))
                    return result, [log]
                with mock.patch.object(population, "record", side_effect=observed), \
                     mock.patch.object(population.m7, "parse_options_trace", return_value={"population.observed": "1"}), \
                     mock.patch.object(fixture, "validate_population"), \
                     mock.patch.object(fixture, "check_population_diagnostics"), \
                     mock.patch.object(population.m7, "compare_options_traces") as compare:
                    with self.assertRaises(population.harness.HarnessError):
                        population.observe(fixture, {"c": Path("c"), "native": Path("native")}, self.output, cases, "debug-1")
                self.assertEqual(calls, [[side, *case] for case in fixture.CASES for side in ("c", "native")])
                self.assertEqual(len(cases), 2 * len(fixture.CASES))
                self.assertEqual(cases[0][1], 7)
                self.assertEqual(compare.call_count, len(fixture.CASES) - 1)
                self.assertEqual(json.loads(cases[0][2][0].read_text())["status"], 7)

    def test_source_roster_checks_reject_missing_extra_and_changed_use(self):
        for profile in population.PROFILES:
            rows = population.SOURCE_SLOT_IMAGES[profile]
            raw = "\n".join(f"population.class={size},{used}" for size, used in rows)
            population.check_replaced_slot_images(raw, raw, profile)
            for changed in (raw.split("\n", 1)[1], raw + "\npopulation.class=1,1", raw.replace(",1", ",2", 1)):
                with self.subTest(profile=profile, changed=changed[:50]), self.assertRaises(population.harness.HarnessError):
                    population.check_replaced_slot_images(raw, changed, profile)

    def test_trace_difference_is_reported_after_remaining_cases(self):
        records = []
        def observed(output, label, argv, cwd, timeout, runtime):
            records.append(label)
            result = {"kind": "process", "status": 0,
                "stdout": population.stress.bytes_record(b"trace"),
                "stderr": population.stress.bytes_record(b"warning\n")}
            return result, []
        with mock.patch.object(population, "record", side_effect=observed), \
             mock.patch.object(population.m7, "parse_options_trace", return_value={"observed": "1"}), \
             mock.patch.object(population, "validate_population"), \
             mock.patch.object(population.m7, "compare_options_traces", side_effect=population.harness.HarnessError("changed population")):
            with self.assertRaisesRegex(population.harness.HarnessError, "changed population"):
                population.observe(population, {"c": Path("c"), "native": Path("native")}, self.output, [], "release")
        self.assertEqual(len(records), 2 * len(population.CASES))


if __name__ == "__main__":
    unittest.main()
