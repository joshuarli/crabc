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

    def test_retention_diagnostic_preserves_growth_and_requires_every_cycle(self):
        def output(cycles):
            return "\n".join(f"m2.arena.retention.{cycle}.{kind}={value}" for cycle in cycles
                             for kind, value in (("ranges", 100+cycle), ("bytes", 1048576+cycle*4096)))
        rows = lifecycle.parse_retention(output(range(33)), source="actual source")
        self.assertEqual(rows[-1]["bytes"]-rows[0]["bytes"], 32*4096)
        with self.assertRaises(ValueError):
            lifecycle.parse_retention(output(range(32)), source="incomplete source")
        with self.assertRaises(ValueError):
            lifecycle.parse_retention(output([0, 0, *range(1, 33)]), source="duplicate source")

    def test_interval_union_classifies_split_overlap_and_unexplained_growth(self):
        self.assertEqual(lifecycle.retention_interval_union([(10, 20), (15, 30), (30, 40)]), [(10, 40)])
        result = lifecycle.classify_retention_intervals(
            [(0, 10)], [(0, 5), (5, 10), (20, 30), (30, 40), (50, 55)],
            [(20, 35), (25, 40)])
        self.assertEqual(result, {"added_bytes": 25, "removed_bytes": 0,
                                  "attributed_bytes": 20, "unexplained_bytes": 5})
        with self.assertRaises(ValueError):
            lifecycle.retention_interval_union([(10, 10)])
        with self.assertRaises(ValueError):
            lifecycle.retention_interval_union([(20, 10)])

    def test_retention_attribution_requires_each_child_and_map_roster(self):
        def transcript():
            lines = []
            for cycle in range(33):
                for child in range(6):
                    lines.extend([
                        f"m2.arena.retention.root.{cycle}.{child}.0.external-raw=100,200,0",
                        f"m2.arena.retention.child.{cycle}.{child}=1"])
                lines.extend([f"m2.arena.retention.map.{cycle}.0=1000,2000",
                              f"m2.arena.retention.maps.{cycle}=1"])
                lines.extend([f"m2.arena.retention.{cycle}.ranges=1",
                              f"m2.arena.retention.{cycle}.bytes=1000"])
            return "\n".join(lines)
        text = transcript()
        rows = lifecycle.parse_retention_attribution(text, source="actual receiver")
        self.assertEqual(len(rows), 33)
        self.assertEqual(rows[0]["classification"]["unexplained_bytes"], 0)
        self.assertEqual(lifecycle.parse_attributed_retention(text, source="same observation")[0]["bytes"], 1000)
        with self.assertRaises(ValueError):
            lifecycle.parse_attributed_retention(text.replace(".7.bytes=1000", ".7.bytes=1001"), source="wrong aggregate")
        observed = text.replace("m2.arena.retention.child.1.0=1",
                                "m2.arena.retention.root.1.0.1.os-page=2000,2100,50\nm2.arena.retention.child.1.0=2")
        observed = observed.replace("m2.arena.retention.maps.1=1",
                                    "m2.arena.retention.map.1.1=2000,2100\nm2.arena.retention.maps.1=2")
        observed = observed.replace("m2.arena.retention.1.ranges=1", "m2.arena.retention.1.ranges=2")
        observed = observed.replace("m2.arena.retention.1.bytes=1000", "m2.arena.retention.1.bytes=1100")
        partial = lifecycle.parse_attributed_retention(observed, source="partial mapped root")
        self.assertEqual(partial[1]["classification"]["unexplained_bytes"], 100)
        complete = lifecycle.parse_attributed_retention(observed.replace("os-page=2000,2100,50", "os-page=2000,2100,100"),
                                                        source="fully mapped root")
        self.assertEqual(complete[1]["classification"]["attributed_bytes"], 100)
        process_maps = observed.replace("os-page=2000,2100,50", "process-pagemap=2000,2100,100")
        process = lifecycle.parse_attributed_retention(process_maps, source="actual global PageMap root")
        self.assertEqual(process[1]["classification"]["attributed_bytes"], 100)
        aggregate_only = "\n".join(line for line in text.splitlines()
                                   if line.split(".")[3].isdigit())
        with self.assertRaises(ValueError):
            lifecycle.parse_attributed_retention(aggregate_only, source="historical aggregate without provenance")
        for altered in (text.replace("m2.arena.retention.child.5.3=1", ""),
                        text + "\nm2.arena.retention.child.5.3=1",
                        text.replace("m2.arena.retention.root.4.2.0.external-raw=100,200,0",
                                     "m2.arena.retention.root.4.2.1.external-raw=100,200,0"),
                        text.replace("m2.arena.retention.map.4.0=1000,2000",
                                     "m2.arena.retention.map.4.0=1000,2000\nm2.arena.retention.map.4.1=1500,2100"),
                        text.replace("m2.arena.retention.maps.4=1", "m2.arena.retention.maps.4=2"),
                        text.replace("external-raw=100,200,0", "external-raw=100,200,1", 1),
                        text.replace("external-raw=100,200,0", "unknown-root=100,200,0", 1)):
            with self.assertRaises(ValueError):
                lifecycle.parse_retention_attribution(altered, source="corrupted receiver")

    def test_process_metadata_attribution_requires_current_owner_observation(self):
        lines = []
        for cycle in range(33):
            for child in range(6):
                lines.append(f"m2.arena.retention.root.{cycle}.{child}.0.external-raw=100,200,0")
                count = 1
                if cycle == 1 and child == 5:
                    lines.append(f"m2.arena.retention.root.{cycle}.{child}.1.process-metadata=2000,2100,100")
                    count = 2
                lines.append(f"m2.arena.retention.child.{cycle}.{child}={count}")
            lines.append(f"m2.arena.retention.map.{cycle}.0=1000,2000")
            if cycle > 0:
                lines.append(f"m2.arena.retention.map.{cycle}.1=2000,2100")
            lines.append(f"m2.arena.retention.maps.{cycle}={1 if cycle == 0 else 2}")
        rows = lifecycle.parse_retention_attribution("\n".join(lines), source="current parent ownership")
        self.assertEqual(rows[1]["classification"]["attributed_bytes"], 100)
        self.assertEqual(rows[2]["classification"]["unexplained_bytes"], 100)

    def test_changed_cross_thread_relation_still_rejects(self):
        c = [-1001, -1023, -1027, 37, 1, 1, 1, -1026]
        native = c.copy()
        native[-2] = 0
        with self.assertRaises(ValueError):
            lifecycle.compare(c, native)


if __name__ == "__main__":
    unittest.main()
