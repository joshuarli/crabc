#!/usr/bin/env python3
"""Ownership admission requires both full callers before their observations."""

from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_deleted_heap_remote_exit as ownership
import x86_64_m6_heap_delete_after_owner_exit as deletion


class OwnershipProfileReceiptTests(unittest.TestCase):
    def receipt(self, cases, profiles=("release",)):
        parameters = {"profiles": ",".join(profiles), "modes": "before,after",
            "watchdog-seconds": "60", "workload": "original-full",
            "boundary": "explicit-native-mi-adapter", "source-assertions": "active"}
        return ownership.receipts.Receipt(Path("receipt.json"), ownership.RUNNER, {}, {},
            [{"id": case, "status": 0, "logs": {}} for case in cases], parameters)

    def admit(self, cases, profiles=("release",)):
        with patch.object(ownership.receipts, "read_receipt", return_value=self.receipt(cases, profiles)):
            ownership.ownership_matrix(ownership.DRIVER, ownership.ARTIFACTS,
                ownership.RUNNER, profiles, ("before", "after"), ownership.BEGIN,
                ownership.END, ownership.EXPECTED, read=True)

    def release_cases(self):
        return ["release-oracle-build", "release-native-build",
            "release-c-compile", "release-c-link", "release-c-before", "release-c-after",
            "release-native-compile", "release-native-link",
            "release-native-before", "release-native-after",
            "release-before-observations", "release-after-observations"]

    def test_complete_original_release_callers_are_admitted(self):
        self.admit(self.release_cases())

    def test_missing_native_final_free_is_rejected(self):
        cases = self.release_cases()
        cases.remove("release-native-after")
        with self.assertRaises(ownership.harness.HarnessError):
            self.admit(cases)

    def test_observations_before_native_final_free_are_rejected(self):
        cases = self.release_cases()
        first = cases.index("release-native-after")
        second = cases.index("release-before-observations")
        cases[first], cases[second] = cases[second], cases[first]
        with self.assertRaises(ownership.harness.HarnessError):
            self.admit(cases)

    def test_release_callers_cannot_satisfy_all_selected_profiles(self):
        with self.assertRaises(ownership.harness.HarnessError):
            self.admit(self.release_cases(), ownership.PROFILES)

    def test_remote_diagnosis_requires_the_retained_debug1_free_crash(self):
        stdout = (ownership.BEGIN + "\nremote.event_alloc=1\nremote.event_deleted=1\n"
            "remote.event_owner_return=1\nremote.event_owner_exit=1\n"
            "remote.event_free_start=1\n").encode()
        stderr = b"m6-valid-domain profile=debug-1 backend=c guarded_precise=1\n"
        raw = {"kind": "process", "status": -11,
            "stdout": ownership.stress.bytes_record(stdout),
            "stderr": ownership.stress.bytes_record(stderr)}
        ownership.require_diagnostic_target(raw, "debug-1", "after")
        with self.assertRaises(ownership.harness.HarnessError):
            ownership.require_diagnostic_target(raw, "release", "after")
        with self.assertRaises(ownership.harness.HarnessError):
            ownership.require_diagnostic_target({**raw, "status": 0}, "debug-1", "after")
        with self.assertRaises(ownership.harness.HarnessError):
            ownership.require_diagnostic_target({**raw, "stdout": ownership.stress.bytes_record(
                stdout + b"remote.event_free_done=1\n")}, "debug-1", "after")
        with self.assertRaises(ownership.harness.HarnessError):
            ownership.require_diagnostic_target({**raw, "stderr": ownership.stress.bytes_record(b"")},
                "debug-1", "after")

    def test_diagnosis_rejects_a_selected_mode_without_a_retained_crash(self):
        output = Path("retained-run")
        run = (output, {}, output / "debug-1-c-after.json", {})
        with patch.object(ownership, "_retained_diagnostic_run", side_effect=[run,
                ownership.harness.HarnessError("no retained debug-1 before pinned-C SIGSEGV")]):
            with self.assertRaisesRegex(ownership.harness.HarnessError, "no retained debug-1 before"):
                ownership.retained_diagnostic_runs(("after", "before"))


class OwnershipProfileProducerTests(unittest.TestCase):
    def run_producer(self, root, profiles, expected, *, failure=None, native_change=False, diagnostic=b"",
                     commands=None, fixture=deletion, modes=("joined",)):
        source = root / "source"
        (source / "include").mkdir(parents=True)
        for name in ("mimalloc.h", "mimalloc-stats.h"):
            (source / "include" / name).write_text("fixture header\n")
        (source / "LICENSE").write_text("fixture license\n")
        seal = {"revision": "a" * 40, "worktree_sha256": "b" * 64}
        def execute(argv, **kwargs):
            if commands is not None:
                commands.append(argv)
            stdout, stderr, status = b"", b"", 0
            if "--target-dir" in argv:
                target = Path(argv[argv.index("--target-dir") + 1])
                library = target / ownership.m4.RUST_TARGET / "release" / ownership.m4.ADAPTER_STATICLIB
                library.parent.mkdir(parents=True)
                library.write_bytes(b"native adapter")
            elif "-E" in argv:
                stdout = (b"mi_option_guarded_precise mi_option_guarded_precise "
                          b"mi_option_is_enabled(mi_option_guarded_precise)\n")
            elif "-o" in argv:
                Path(argv[argv.index("-o") + 1]).write_bytes(b"retained caller or oracle")
            else:
                binary = Path(argv[0])
                profile, backend = binary.parent.name, binary.name
                mode = next((argument for argument in argv[1:] if argument in ("before", "after")), "joined")
                if profile == "debug-1":
                    stderr = (f"m6-valid-domain profile=debug-1 backend={backend} "
                              f"guarded_precise={int(backend == 'c')}\n").encode() + diagnostic
                else:
                    stderr = diagnostic
                trace = dict(expected[mode]) if mode in expected else dict(expected)
                if "exit.freed" in trace:
                    trace["exit.freed"] = "37,0,1" if profile == "debug-1" else "37,0,0"
                    trace["exit.collected"] = "0,1" if profile == "debug-1" else "0,0"
                if native_change and backend == "native":
                    trace["exit.collected"] = "0,0"
                stdout = (fixture.BEGIN + "\n" + "\n".join(f"{key}={value}" for key, value in trace.items()) + "\n" + fixture.END + "\n").encode()
                if failure is not None and profile == "release":
                    status = -11
                    stdout = b"before final free\xff\n"
                    stderr = b"retained diagnostic\n"
            return {"kind": "process", "status": status,
                "command": argv, "stdout": ownership.stress.bytes_record(stdout),
                "stderr": ownership.stress.bytes_record(stderr)}
        with ExitStack() as stack:
            stack.enter_context(patch.object(ownership.harness, "ROOT", root))
            stack.enter_context(patch.object(ownership.harness, "require_native_x86_64", return_value={}))
            stack.enter_context(patch.object(ownership.receipts, "source_seal", return_value=seal))
            stack.enter_context(patch.object(ownership.harness, "load_pin", return_value={"archive_root": "source"}))
            stack.enter_context(patch.object(ownership.harness, "fetch_archive", return_value=root / "archive"))
            stack.enter_context(patch.object(ownership.harness, "safe_extract", return_value=source))
            stack.enter_context(patch.object(ownership.harness, "require_tool", return_value="fixture-compiler"))
            stack.enter_context(patch.object(ownership.stress, "command_record", side_effect=execute))
            expected_by_mode = expected if set(expected) == set(modes) else {modes[0]: expected}
            ownership.ownership_matrix(fixture.DRIVER, root / "artifacts", fixture.RUNNER,
                profiles, modes, fixture.BEGIN, fixture.END, expected_by_mode)

    def test_debug_geometry_comes_from_the_full_matching_c_caller(self):
        work = ownership.harness.ROOT / ".work/tmp"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            self.run_producer(Path(temporary), ("debug-1",), deletion.EXPECTED)

    def test_debug_offset_clients_use_the_valid_client_profile_for_both_owners(self):
        work = ownership.harness.ROOT / ".work/tmp"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            commands = []
            self.run_producer(Path(temporary), ("debug-1",), deletion.EXPECTED, commands=commands)

        runtime_commands = {
            Path(command[0]).name: command[1:]
            for command in commands
            if Path(command[0]).name in ("c", "native")
        }
        self.assertEqual(runtime_commands, {
            "c": ["--valid-domain", "debug-1"],
            "native": ["--valid-domain", "debug-1"],
        })
        build_commands = {
            Path(command[command.index("-o") + 1]).name: command
            for command in commands
            if "-o" in command and Path(command[command.index("-o") + 1]).name in ("c.o", "native.o")
        }
        self.assertNotIn("-DCRABC_NATIVE_MI_ADAPTER=1", build_commands["c.o"])
        self.assertIn("-DCRABC_NATIVE_MI_ADAPTER=1", build_commands["native.o"])

        with tempfile.TemporaryDirectory(dir=work) as temporary:
            commands = []
            self.run_producer(Path(temporary), ("debug-1",), ownership.EXPECTED,
                              commands=commands, fixture=ownership, modes=("before", "after"))

        runtime_commands = {
            (Path(command[0]).name, command[-1]): command[1:]
            for command in commands
            if Path(command[0]).name in ("c", "native")
        }
        self.assertEqual(runtime_commands, {
            ("c", "before"): ["--valid-domain", "debug-1", "before"],
            ("c", "after"): ["--valid-domain", "debug-1", "after"],
            ("native", "before"): ["--valid-domain", "debug-1", "before"],
            ("native", "after"): ["--valid-domain", "debug-1", "after"],
        })

    def test_debug_receipt_reads_and_replays_its_recorded_callers(self):
        work = ownership.harness.ROOT / ".work/tmp"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            self.run_producer(root, ("debug-1",), deletion.EXPECTED)

            replay_commands = []
            with patch.object(ownership.harness, "ROOT", root), \
                 patch.object(ownership.harness, "require_native_x86_64", return_value={"image_id": "fixture-image"}), \
                 patch.object(ownership.harness, "validate_native_execution_provenance"), \
                 patch.object(ownership.receipts, "source_seal",
                              return_value={"revision": "a" * 40, "worktree_sha256": "b" * 64}), \
                 patch.object(ownership, "record") as replay:
                receipt = ownership.receipts.read_receipt(root, deletion.RUNNER + "-debug-1")

                def replay_record(scratch, case_id, argv, cwd, runtime):
                    replay_commands.append(argv)
                    case = next(item for item in receipt.cases if item["id"] == case_id)
                    record_path = next(path for path in case["logs"] if path.endswith(".json"))
                    return ownership.harness.read_json(receipt.path.parent / "logs" / record_path), []

                replay.side_effect = replay_record
                ownership.ownership_matrix(deletion.DRIVER, deletion.ARTIFACTS, deletion.RUNNER,
                    ("debug-1",), ("joined",), deletion.BEGIN, deletion.END,
                    {"joined": deletion.EXPECTED}, read=True, replay=True)

        self.assertEqual([command[1:] for command in replay_commands], [
            ["--valid-domain", "debug-1"], ["--valid-domain", "debug-1"]])

    def test_matching_nonzero_callers_do_not_admit_and_later_profiles_still_run(self):
        work = ownership.harness.ROOT / ".work/tmp"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            with self.assertRaises(ownership.receipts.ReceiptError):
                self.run_producer(root, ownership.PROFILES, deletion.EXPECTED, failure=True)
            output = next((root / "artifacts").glob("run-*"))
            self.assertEqual((output / "release-c-joined.stdout").read_bytes(), b"before final free\xff\n")
            self.assertEqual(json.loads((output / "release-native-joined.json").read_text())["status"], -11)
            self.assertTrue((output / "stat-2-c-joined.json").is_file())
            self.assertTrue((output / "stat-2-native-joined.json").is_file())
            receipt = json.loads(next((root / ownership.receipts.RECEIPTS).glob("*/latest/receipt.json")).read_text())
            cases = {case["id"]: case["status"] for case in receipt["cases"]}
            self.assertEqual(cases["release-c-joined"], -11)
            self.assertEqual(cases["release-native-joined"], -11)
            self.assertEqual(cases["release-joined-observations"], 1)

    def test_matching_invalid_free_diagnostics_do_not_admit_zero_exit_callers(self):
        work = ownership.harness.ROOT / ".work/tmp"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            with self.assertRaises(ownership.receipts.ReceiptError):
                self.run_producer(root, ("debug-1",), deletion.EXPECTED,
                    diagnostic=b"mimalloc: error: mi_free: invalid (unaligned) pointer\n")
            output = next((root / "artifacts").glob("run-*"))
            self.assertIn(b"invalid (unaligned) pointer", (output / "debug-1-c-joined.stderr").read_bytes())

    def test_native_geometry_must_match_c_even_when_both_callers_exit_zero(self):
        work = ownership.harness.ROOT / ".work/tmp"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            with self.assertRaises(ownership.receipts.ReceiptError):
                self.run_producer(root, ("debug-1",), deletion.EXPECTED, native_change=True)
            observations = json.loads(next((root / "artifacts").glob("run-*/debug-1-joined-observations.json")).read_text())
            self.assertIn("C/native ownership traces differ", observations["failures"])


if __name__ == "__main__":
    unittest.main()
