"""Selected configuration and complete-trace behavior for arena lifecycle callers."""
from pathlib import Path
import json
import hashlib
import struct
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
        extended = lifecycle.parse_retention(output(range(129)), source="extended source", last_cycle=128)
        self.assertEqual(len(extended), 129)
        self.assertEqual(extended[-1]["bytes"]-extended[0]["bytes"], 128*4096)
        with self.assertRaises(ValueError):
            lifecycle.parse_retention(output(range(129)), source="unchanged default")

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

    def test_current_ambient_pool_membership_explains_only_current_mapping(self):
        snapshots = [{"maps": [(0x1000, 0x2000)]},
                     {"maps": [(0x1000, 0x3000)]},
                     {"maps": [(0x1000, 0x3000)]}]
        text = "\n".join([
            "m2.arena.ambient.groups.0=0",
            "m2.arena.ambient.group.1.0=7,32792,32792,32792,8192,12288,3,0,1,1,100,2",
            "m2.arena.ambient.groups.1=1",
            "m2.arena.ambient.groups.2=0"])
        rows = lifecycle.parse_ambient_retention(text, snapshots)
        self.assertEqual(rows[1]["classification"]["attributed_bytes"], 4096)
        self.assertEqual(rows[1]["empty_bouncing_extents"], [(8192, 12288)])
        self.assertEqual(rows[2]["classification"]["unexplained_bytes"], 4096)
        for altered in (text.replace("32792,32792,32792", "32792,32832,32792"),
                        text.replace("3,0,1,1,100,2", "3,1,1,1,100,2"),
                        text.replace("8192,12288", "8192,16384"),
                        text.replace("groups.2=0", "groups.2=1"),
                        text.replace("groups.0=0", "groups.0=0\nm2.arena.ambient.groups.0=0")):
            with self.assertRaises(ValueError):
                lifecycle.parse_ambient_retention(altered, snapshots)
        not_bouncing = lifecycle.parse_ambient_retention(text.replace(
            "3,0,1,1,100,2", "3,0,1,1,99,2"), snapshots)
        self.assertEqual(not_bouncing[1]["empty_bouncing_extents"], [])

    def test_disconnected_size_class_roots_do_not_form_a_live_pool_witness(self):
        text = "\n".join([
            "m2.arena.ambient.group.0.0=7,32792,32792,32792,8192,12288,3,0,1,1,100,4",
            "m2.arena.ambient.group.0.1=7,32832,32832,32832,12288,16384,3,0,1,1,100,4",
            "m2.arena.ambient.groups.0=2"])
        with self.assertRaisesRegex(ValueError, "disconnected"):
            lifecycle.parse_ambient_retention(text, [{"maps": [(8192, 16384)]}])
        connected = text.replace("32792,32792,32792", "32792,32832,32832").replace(
            "32832,32832,32832", "32832,32792,32792")
        rows = lifecycle.parse_ambient_retention(connected, [{"maps": [(8192, 16384)]}])
        self.assertEqual(len(rows[0]["groups"]), 2)
        self.assertEqual(rows[0]["empty_bouncing_extents"], [])

    def test_ambient_archive_and_linked_code_are_both_authenticated(self):
        names = ("alloc_slot", "__libc_malloc_impl", "__malloc_alloc_meta",
                 "__malloc_atfork", "nontrivial_free", "__libc_free", "__malloc_context")
        strings = b"\0"
        symbols = bytes(24)
        for i, name in enumerate(names):
            offset = len(strings)
            strings += name.encode() + b"\0"
            symbols += struct.pack("<IBBHQQ", offset, 2, 0, 1, 0, 928 if i == 6 else 2)
        def elf(code):
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, 62)
            data += code + symbols + strings
            section_offset = len(data)
            sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                        (0, 1, 0, 0, 64, len(code), 0, 0, 1, 0),
                        (0, 2, 0, 0, 64+len(code), len(symbols), 3, 0, 8, 24),
                        (0, 3, 0, 0, 64+len(code)+len(symbols), len(strings), 0, 0, 1, 0)]
            for section in sections:
                data += struct.pack("<IIQQQQIIQQ", *section)
            struct.pack_into("<Q", data, 40, section_offset)
            struct.pack_into("<HH", data, 58, 64, 4)
            return bytes(data)
        obj = elf(b"\x90\xc3" + bytes(926))
        archive = b"!<arch>\n"
        for name in ("malloc.lo", "free.lo"):
            header = f"{name+'/':<16}{0:<12}{0:<6}{0:<6}{0:<8}{len(obj):<10}`\n".encode()
            archive += header + obj + (b"\n" if len(obj) % 2 else b"")
        with tempfile.TemporaryDirectory(dir=harness.WORK_ROOT) as directory:
            root = Path(directory)
            (root / "libc.a").write_bytes(archive)
            binary = root / "native"
            binary.write_bytes(obj)
            with mock.patch.object(harness, "rust_target_self_contained_native_library_search_path", return_value=str(root)), mock.patch.object(lifecycle, "AMBIENT_LIBC_SHA256", hashlib.sha256(archive).hexdigest()):
                proof = lifecycle.authenticate_ambient_pool(harness, binary)
                self.assertEqual(proof["ambient_musl_version"], "1.2.5")
                self.assertEqual(len(proof["functions"]), 6)
                binary.write_bytes(elf(b"\x91\xc3" + bytes(926)))
                with self.assertRaisesRegex(ValueError, "bytes differ"):
                    lifecycle.authenticate_ambient_pool(harness, binary)
                binary.write_bytes(obj)
                (root / "libc.a").write_bytes(archive + b"corruption")
                with self.assertRaisesRegex(ValueError, "archive identity"):
                    lifecycle.authenticate_ambient_pool(harness, binary)


if __name__ == "__main__":
    unittest.main()
