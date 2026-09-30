"""Selected configuration and complete-trace behavior for arena lifecycle callers."""
from pathlib import Path
import json
import tempfile
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import m2_arena_lifecycle_x86_64 as lifecycle
import run as harness


class ArenaLifecycleProfiles(unittest.TestCase):
    def test_selected_statistics_caller_uses_matching_native_features(self):
        trace = [-1001, -1023, -1027, 37, 1, 1, 1, -1026]
        output = "\n".join(f"m2.arena.lifecycle.{i}={value}" for i, value in enumerate(trace))
        record = {"status": 0, "stdout": output + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n", "stderr": ""}
        with mock.patch.object(lifecycle, "run_oracle", return_value=([], trace)) as oracle, mock.patch.object(harness, "require_native_x86_64"), mock.patch.object(lifecycle, "native_program", return_value={"path": Path(__file__), "execution": {"test_threads": 1}}) as product, mock.patch.object(harness, "command_record", return_value=record) as native, mock.patch.object(harness, "write_json"), mock.patch.object(lifecycle.Path, "write_text"):
            self.assertEqual(lifecycle.main(["--profile", "stat-2"]), 0)
        self.assertEqual(oracle.call_args.kwargs["profile"], "stat-2")
        command = native.call_args.args[0]
        self.assertEqual(product.call_args.args[1], "stat-2")
        self.assertIn("--exact", command)

    def test_zero_selected_native_tests_cannot_complete_configuration(self):
        trace = [-1001, -1023, -1027, -1026]
        output = "\n".join(f"m2.arena.lifecycle.{i}={value}" for i, value in enumerate(trace))
        record = {"status": 0, "stdout": output + "\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n", "stderr": ""}
        with mock.patch.object(lifecycle, "run_oracle", return_value=([], trace)), mock.patch.object(harness, "require_native_x86_64"), mock.patch.object(lifecycle, "native_program", return_value={"path": Path(__file__), "execution": {"test_threads": 1}}), mock.patch.object(harness, "command_record", return_value=record), mock.patch.object(harness, "write_json"), mock.patch.object(lifecycle.Path, "write_text"):
            self.assertEqual(lifecycle.main(["--profile", "debug-1"]), 1)

    def test_matching_compiler_product_binds_checkout_and_statistics_features(self):
        with tempfile.TemporaryDirectory(dir=harness.WORK_ROOT) as directory:
            artifacts = Path(directory)
            executable = artifacts / "compiler-program"
            executable.write_bytes(b"actual selected product")
            manifest = harness.ROOT / "crabc-mimalloc/Cargo.toml"
            event = {"reason": "compiler-artifact", "manifest_path": str(manifest),
                     "target": {"name": "crabc_mimalloc", "kind": ["lib"], "src_path": str(manifest.parent / "src/lib.rs")},
                     "profile": {"test": True}, "features": ["mi-stat-1", "mi-stat-2"], "executable": str(executable)}
            record = {"status": 0, "stdout": json.dumps(event), "stderr": ""}
            with mock.patch.object(harness, "command_record", return_value=record) as build, mock.patch.object(harness, "require_tool", return_value="/tool/cargo"), mock.patch.object(harness, "write_json"):
                product = lifecycle.native_program(harness, "stat-2", artifacts)
            self.assertEqual(product["path"].read_bytes(), executable.read_bytes())
            command = build.call_args.args[0]
            self.assertEqual(command[command.index("--features") + 1], "mi-stat-2")
            self.assertEqual(command[command.index("--manifest-path") + 1], str(manifest))
            event["manifest_path"] = str(artifacts / "unrelated/Cargo.toml")
            with mock.patch.object(harness, "command_record", return_value={**record, "stdout": json.dumps(event)}), mock.patch.object(harness, "require_tool", return_value="/tool/cargo"), mock.patch.object(harness, "write_json"):
                with self.assertRaises(harness.HarnessError):
                    lifecycle.native_program(harness, "stat-2", artifacts)
            event["manifest_path"] = str(manifest)
            event["features"] = []
            with mock.patch.object(harness, "command_record", return_value={**record, "stdout": json.dumps(event)}), mock.patch.object(harness, "require_tool", return_value="/tool/cargo"), mock.patch.object(harness, "write_json"):
                with self.assertRaises(harness.HarnessError):
                    lifecycle.native_program(harness, "stat-2", artifacts)

    def test_all_profiles_preserves_failure_and_executes_other_configurations(self):
        trace = [-1001, -1023, -1027, -1026]
        output = "\n".join(f"m2.arena.lifecycle.{i}={value}" for i, value in enumerate(trace))
        record = {"status": 0, "stdout": output + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n", "stderr": ""}
        seen = []
        def oracle(_, *, offline, profile):
            seen.append(profile)
            if profile == "debug-1":
                raise harness.HarnessError("actual selected source failure")
            return [], trace
        with mock.patch.object(lifecycle, "run_oracle", side_effect=oracle), mock.patch.object(harness, "require_native_x86_64"), mock.patch.object(lifecycle, "native_program", return_value={"path": Path(__file__), "execution": {"test_threads": 1}}), mock.patch.object(harness, "command_record", return_value=record), mock.patch.object(harness, "write_json"), mock.patch.object(lifecycle.Path, "write_text"):
            self.assertEqual(lifecycle.main(["--profile", "all"]), 1)
        self.assertEqual(seen, list(lifecycle.PROFILES))

    def test_changed_cross_thread_relation_still_rejects(self):
        c = [-1001, -1023, -1027, 37, 1, 1, 1, -1026]
        native = c.copy()
        native[-2] = 0
        with self.assertRaises(ValueError):
            lifecycle.compare(c, native)


if __name__ == "__main__":
    unittest.main()
