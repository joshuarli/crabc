#!/usr/bin/env python3
"""Contracts for pinned x86-64 allocation-operation evidence."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
from unittest import mock
from types import SimpleNamespace
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m4_gate", ROOT / "compat/allocator/x86_64_m4_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M4GateContractTests(unittest.TestCase):
    def test_private_realloc_keeps_the_source_mandated_live_identity(self) -> None:
        trace = {"realloc.source.0.100": "id:0,reuse:-,usable:100,align:4,slice:12",
                 "realloc.source.0.100.contract": "requested:100,alignment:16,offset:0,upper:160,success:1,aligned:1,distinct:1",
                 "realloc.source.0.100.payload": "1", "realloc.source.0.100.natural": "112",
                 "realloc.0.1": "id:1,reuse:0,usable:100,align:4,slice:12",
                 "realloc.0.1.contract": "requested:50,alignment:8,offset:0,upper:100,success:1,aligned:1,distinct:1",
                 "realloc.0.1.realloc": "old:100,old_id:0,dynamic:0,identity:1,payload:1,zero:1"}
        gate.compare_operations_traces(trace, trace, private_source_profile="secure-5")
        for key, before, after in (("realloc.0.1", "reuse:0", "reuse:-"),
                                  ("realloc.0.1.realloc", "old:100", "old:99"),
                                  ("realloc.0.1.realloc", "identity:1", "identity:0"),
                                  ("realloc.0.1.realloc", "payload:1", "payload:0"),
                                  ("realloc.0.1.realloc", "zero:1", "zero:0"),
                                  ("realloc.source.0.100", "usable:100", "usable:110")):
            invalid = {**trace, key: trace[key].replace(before, after)}
            with self.subTest(field=after), self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(invalid, invalid, private_source_profile="secure-5")
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces({**trace, "expand.fit.0.100": "1"},
                {**trace, "expand.fit.0.100": "1"}, private_source_profile="secure-5")

    def test_private_offset_rezalloc_validates_capacity_chain_and_required_identity(self) -> None:
        def trace(initial, grown, replacement):
            base = "offset_rezalloc.0.0.0"
            return {f"{base}.grow": f"grow:1,copy:1,tail:1,odd:1,old_usable:{initial},new_usable:{grown}",
                    f"{base}.reuse": "reuse:1,copy:1",
                    f"{base}.replace": f"replace:1,copy:1,tail:1,aligned:1,new_usable:{replacement}",
                    f"{base}.basis": f"requested:33,alignment:256,offset:1,initial:{initial},initial_upper:320,grown:{grown},grown_upper:512,replacement:{replacement},replacement_upper:512,initial_aligned:1,grown_aligned:1"}
        c, native = trace(103, 126, 68), trace(231, 254, 216)
        gate.compare_operations_traces(c, native, private_source_profile="secure-5")
        for key in ("grow", "reuse", "replace"):
            invalid = {**native, f"offset_rezalloc.0.0.0.{key}": native[f"offset_rezalloc.0.0.0.{key}"].replace("copy:1", "copy:0")}
            with self.subTest(key=key), self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(invalid, invalid, private_source_profile="secure-5")
        for invalid in (trace(31, 126, 68), trace(103, 119, 68), trace(103, 126, 61), trace(103, 126, 513)):
            with self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(invalid, invalid, private_source_profile="secure-5")

    def test_private_request_context_checks_each_randomized_allocation(self) -> None:
        contract = "requested:33,alignment:256,offset:1,upper:320,success:1,aligned:1,distinct:1"
        c = {"malloc_aligned_at.8.1": "id:12,reuse:-,usable:33,align:0,slice:20",
             "malloc_aligned_at.8.1.contract": contract, "malloc_aligned_at.ok.8.1": "1,0"}
        native = {**c, "malloc_aligned_at.8.1": "id:12,reuse:2,usable:289,align:0,slice:27"}
        gate.compare_operations_traces(c, native, private_source_profile="secure-5")
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces(c, native)
        for field, bad in (("usable:289", "usable:32"), ("usable:289", "usable:321"),
                           ("reuse:2", "reuse:12"), ("align:0", "align:1"),
                           ("slice:27", "slice:4096")):
            with self.subTest(field=bad), self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(c, {**native,
                    "malloc_aligned_at.8.1": native["malloc_aligned_at.8.1"].replace(field, bad)},
                    private_source_profile="secure-5")
        for flag in ("success", "aligned", "distinct"):
            invalid = {**c, "malloc_aligned_at.8.1.contract": contract.replace(f"{flag}:1", f"{flag}:0")}
            with self.subTest(flag=flag), self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(invalid, invalid, private_source_profile="secure-5")
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces(c, {**native,
                "malloc_aligned_at.8.1.contract": contract.replace("requested:33", "requested:34")},
                private_source_profile="secure-5")
        invalid = {**c, "malloc_aligned_at.ok.8.1": "0,0"}
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces(invalid, invalid, private_source_profile="secure-5")
        singleton = {"umalloc_aligned": "id:0,reuse:-,usable:100,align:8,slice:12",
                     "umalloc_aligned.contract": "requested:100,alignment:256,offset:0,upper:512,success:1,aligned:1,distinct:1",
                     "umalloc_aligned.payload": "1"}
        gate.compare_operations_traces(singleton, singleton, private_source_profile="secure-5")

    def test_private_secure_class_allocations_allow_only_surplus_alignment(self) -> None:
        c = {"malloc.11.33": "id:11,reuse:-,usable:33,align:5,slice:14",
             "malloc.keep.11.33": "1"}
        native = {**c, "malloc.11.33": c["malloc.11.33"].replace("align:5", "align:7")}
        gate.compare_operations_traces(c, native, private_source_profile="secure-5")
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces(c, native)
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces(c, native, private_source_profile="release")
        for before, after in (("align:7", "align:3"), ("usable:33", "usable:32"),
                              ("reuse:-", "reuse:2"), ("slice:14", "slice:15"),
                              ("id:11", "id:12")):
            with self.subTest(field=before), self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(c, {**native,
                    "malloc.11.33": native["malloc.11.33"].replace(before, after)},
                    private_source_profile="secure-5")
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces(c, {**native, "malloc.keep.11.33": "0"},
                                           private_source_profile="secure-5")
        for value in ("null", c["malloc.11.33"].replace("align:5", "align:17")):
            with self.subTest(value=value), self.assertRaises(harness.HarnessError):
                gate.compare_operations_traces(c, {**c, "malloc.11.33": value},
                                               private_source_profile="secure-5")
        with self.assertRaises(harness.HarnessError):
            gate.compare_operations_traces({"malloc_aligned.5.1": c["malloc.11.33"]},
                {"malloc_aligned.5.1": native["malloc.11.33"]}, private_source_profile="secure-5")

    def test_debug_build_uses_opt0_without_selecting_release_or_changing_source_features(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            with mock.patch.object(gate, "debug_adapter_environment", return_value=(
                    ["/cargo", "-Zbuild-std=core,compiler_builtins"],
                    {"CARGO_PROFILE_DEV_OPT_LEVEL": "0"}, {})), \
                    mock.patch.object(harness, "require_tool", return_value="/cargo"), \
                    mock.patch.object(harness, "command_record", return_value={"status": 0}) as compile, \
                    mock.patch.object(harness, "require_success"), \
                    mock.patch.object(harness, "artifact_record", return_value={}):
                library = gate.build_adapter_library(output, "debug-1", build_profile="debug")
            command = compile.call_args.args[0]
            self.assertIn("-Zbuild-std=core,compiler_builtins", command)
            self.assertNotIn("--release", command)
            self.assertIn("--offline", command)
            self.assertEqual(command[command.index("--features") + 1], "crabc-mimalloc/mi-debug-1")
            self.assertEqual(compile.call_args.kwargs["env"]["CARGO_PROFILE_DEV_OPT_LEVEL"], "0")
            self.assertEqual(library.parent.name, "debug")
            with mock.patch.object(harness, "require_tool", return_value="/musl-gcc"), \
                    mock.patch.object(harness, "command_record", return_value={"status": 0}) as compile, \
                    mock.patch.object(harness, "require_success"):
                gate.build_c_driver(output / "source", output, profile="debug-1", build_profile="debug")
            command = compile.call_args.args[0]
            self.assertIn("-O0", command)
            self.assertNotIn("-O2", command)
            self.assertNotIn("-O3", command)
            self.assertIn("-DMI_DEBUG=1", command)

    def test_guarded_profiles_select_independent_source_and_rust_features(self) -> None:
        for profile, base in (("guarded", "release"), ("guarded-debug-1", "debug-1"),
                              ("guarded-secure-3", "secure-3"), ("guarded-stat-2", "stat-2"),
                              ("guarded-debug-2", "debug-2"), ("guarded-debug-3", "debug-3"),
                              ("guarded-stat-1", "stat-1"), ("guarded-secure-1", "secure-1"),
                              ("guarded-secure-2", "secure-2"),
                              ("guarded-secure-4", "secure-4"), ("guarded-secure-5", "secure-5")):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
                flags = gate.api_profile_flags(profile)
                ordinary = gate.api_profile_flags(base)
                self.assertEqual([flag for flag in flags if flag.startswith("-DMI_GUARDED=")],
                                 ["-DMI_GUARDED=1"])
                self.assertEqual([flag for flag in flags if not flag.startswith("-DMI_GUARDED=")],
                                 [flag for flag in ordinary if not flag.startswith("-DMI_GUARDED=")])
                features = ("mi-guarded", *((f"mi-{base}",) if base != "release" else ()))
                self.assertEqual(gate.api_profile_features(profile), features)
                with mock.patch.object(harness, "require_tool", return_value="/cargo"), \
                        mock.patch.object(harness, "command_record", return_value={"status": 0}) as compile, \
                        mock.patch.object(harness, "require_success"), \
                        mock.patch.object(harness, "artifact_record", return_value={}):
                    gate.build_adapter_library(Path(directory), profile)
                command = compile.call_args.args[0]
                self.assertEqual(command[command.index("--features") + 1],
                                 ",".join(f"crabc-mimalloc/{feature}" for feature in features))

    def test_internal_debug_c_build_selects_exact_numeric_level(self) -> None:
        for profile, level in (("debug-2", 2), ("debug-3", 3)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
                output = Path(directory)
                with mock.patch.object(harness, "require_tool", return_value="/musl-gcc"), \
                        mock.patch.object(harness, "command_record", return_value={"status": 0}) as compile, \
                        mock.patch.object(harness, "require_success"):
                    gate.build_c_driver(output / "source", output, profile=profile)
                command = compile.call_args.args[0]
                self.assertEqual([flag for flag in command if flag.startswith("-DMI_DEBUG=")],
                                 [f"-DMI_DEBUG={level}"])
                self.assertIn("-DMI_STAT=2", command)
                self.assertIn("-DMI_PADDING=1", command)
                self.assertEqual(gate.API_PROFILES, ("release", "debug-1", "stat-1", "stat-2"))

    def test_secure_c_build_selects_one_exact_source_level(self) -> None:
        for profile, level in (("secure-1", 1), ("secure-2", 2), ("secure-3", 3),
                               ("secure-4", 4), ("secure-5", 5)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
                output = Path(directory)
                with mock.patch.object(harness, "require_tool", return_value="/musl-gcc"), \
                        mock.patch.object(harness, "command_record", return_value={"status": 0}) as compile, \
                        mock.patch.object(harness, "require_success"):
                    gate.build_c_driver(output / "source", output, profile=profile)
                command = compile.call_args.args[0]
                self.assertEqual([flag for flag in command if flag.startswith("-DMI_SECURE=")],
                                 [f"-DMI_SECURE={level}"])
                self.assertIn("-DMI_DEBUG=0", command)
                self.assertIn("-DMI_STAT=0", command)

    def test_private_valid_client_command_accepts_selected_source_modes(self) -> None:
        for profile in ("secure-4", "secure-5", "guarded-secure-5"):
            with self.subTest(profile=profile), mock.patch.object(gate, "run_operations_differential",
                    return_value={"compared_key_count": 1}) as run:
                self.assertEqual(gate.main(["--differential", "operations", "--offline",
                    "--build-profile", "debug", "--source-profile", profile, "--valid-clients-only"]), 0)
                run.assert_called_once_with(True, "operations", build_profile="debug",
                    source_profile=profile, valid_clients_only=True)

    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)
        self.api = harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json")
        self.sibling = gate.sibling_owned_items(self.contract["inventory"])

    def validate(self, contract=None, api=None, sibling=None):
        return gate.validate_contract(
            self.contract if contract is None else contract,
            self.api if api is None else api,
            self.pin,
            self.sibling if sibling is None else sibling,
        )

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_partitions_the_m4_items(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        owned = {name for entry in self.contract["gates"] for name in entry["items"]}
        for name in ("mi_malloc", "mi_calloc", "mi_realloc", "mi_expand", "mi_malloc_aligned_at",
                     "mi_posix_memalign", "mi_usable_size", "mi_good_size", "mi_collect", "mi_strdup"):
            self.assertIn(name, owned)
        # Heap-, arena-, and option-shaped members of the selected groups
        # belong to M6/M7; override-only and callback types are excluded to
        # their named owners rather than dropped.
        for name in ("mi_heap_malloc", "mi_reserve_os_memory", "mi_version", "mi_option_get",
                     "mi_malloc_size", "mi_output_fun"):
            self.assertNotIn(name, owned)
        self.assertIn("mi_malloc_size", summary["excluded_items"])

    def test_an_omitted_or_doubly_owned_item_is_rejected(self) -> None:
        omitted = copy.deepcopy(self.contract)
        self.gate_record(omitted, "m4.realloc")["items"].remove("mi_expand")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory items"):
            self.validate(omitted)

        doubled = copy.deepcopy(self.contract)
        self.gate_record(doubled, "m4.free")["items"].append("mi_malloc")
        with self.assertRaisesRegex(harness.HarnessError, "owned by both"):
            self.validate(doubled)

    def test_a_new_applicable_authority_entry_breaks_closure(self) -> None:
        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(item for item in api["items"] if item["name"] == "mi_malloc"))
        extra["name"] = "mi_malloc_ex"
        api["items"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "mi_malloc_ex"):
            self.validate(api=api)

    def test_exclusions_and_sibling_ownership_stay_honest(self) -> None:
        # A sibling-owned item may not be claimed by an M4 gate.
        claimed = copy.deepcopy(self.contract)
        self.gate_record(claimed, "m4.allocation")["items"].append("mi_reserve_os_memory")
        with self.assertRaisesRegex(harness.HarnessError, "unselected item"):
            self.validate(claimed)

        # An exclusion must name something the selection actually reaches.
        stray = copy.deepcopy(self.contract)
        stray["inventory"]["excluded_items"]["mi_heap_new"] = "M6"
        with self.assertRaisesRegex(harness.HarnessError, "does not reach"):
            self.validate(stray)

        unexplained = copy.deepcopy(self.contract)
        unexplained["inventory"]["excluded_items"]["mi_output_fun"] = ""
        with self.assertRaisesRegex(harness.HarnessError, "owner and reason"):
            self.validate(unexplained)

        # Dropping an exclusion without assigning the item breaks closure.
        dropped = copy.deepcopy(self.contract)
        del dropped["inventory"]["excluded_items"]["mi_output_fun"]
        with self.assertRaisesRegex(harness.HarnessError, "mi_output_fun"):
            self.validate(dropped)

    def test_inapplicable_or_itemless_ownership_is_rejected(self) -> None:
        inapplicable = copy.deepcopy(self.contract)
        inapplicable["inventory"]["additional_items"].append("mi_collect_reduce")
        with self.assertRaisesRegex(harness.HarnessError, "not applicable"):
            self.validate(inapplicable)

        itemless = copy.deepcopy(self.contract)
        self.gate_record(itemless, "m4.upstream")["items"].append("mi_malloc")
        with self.assertRaisesRegex(harness.HarnessError, "cross-cutting|owned by both"):
            self.validate(itemless)

    def test_missing_evidence_cannot_be_unblocked_by_editing_the_contract(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        unblocked["evidence"]["differential:collection"]["command"] = None
        self.gate_record(unblocked, "m4.collection")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

        undeclared = copy.deepcopy(self.contract)
        self.gate_record(undeclared, "m4.aligned")["evidence"].append("differential:invented")
        with self.assertRaisesRegex(harness.HarnessError, "undeclared evidence"):
            self.validate(undeclared)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["upstream:test-api"]["command"] = ["python3", "compat/allocator/absent.py"]
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        contract = copy.deepcopy(self.contract)
        self.gate_record(contract, "m4.realloc")["blocked_by"] = ["reviewed blocker"]
        report = gate.gate_report(contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        for record in report["gates"]:
            if record["blocked_by"]:
                self.assertEqual(record["status"], "blocked")
                self.assertIn(record["id"], report["unmet_required"])

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            record["command"] = ["python3", "compat/allocator/x86_64_m4_gate.py"]
        for entry in contract["gates"]:
            entry["blocked_by"] = []
        summary = self.validate(contract)
        results = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["differential:collection"] = {"status": "failed"}
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(self.gate_record(report, "m4.collection")["status"], "failed")
        # Evidence absent from this run leaves its gate unmet, never passed.
        del results["differential:collection"]
        self.assertEqual(self.gate_record(gate.gate_report(contract, summary, results), "m4.collection")["status"],
                         "blocked")

    def test_evidence_commands_bind_only_their_fresh_scratch_directory(self) -> None:
        bound = gate.evidence_command(["python3", "x.py", "--report", "{scratch}/r.json"], Path("/scratch/run"))
        self.assertEqual(bound, ["python3", "x.py", "--report", "/scratch/run/r.json"])
        self.assertEqual(gate.evidence_command(["python3", "x.py"], Path("/s")), ["python3", "x.py"])

    def test_upstream_test_api_inline_diagnostic_keeps_next_check_separate(self) -> None:
        raw = ("test: malloc-aligned5...  malloc_aligned5: usable size: 8192.  ok.\n"
               "test: malloc-aligned7...  ok.\n"
               "succeeded: 2\nfailed   : 0\n")
        self.assertEqual(gate.TEST_API_CHECK.findall(raw),
                         [("malloc-aligned5", "ok."), ("malloc-aligned7", "ok.")])
        self.assertEqual(gate.parse_upstream_test_api_checks(raw),
                         {"malloc-aligned5": True, "malloc-aligned7": True})

    def test_upstream_test_api_reader_rejects_missing_duplicate_and_malformed_outcomes(self) -> None:
        valid = "test: first...  ok.\ntest: second...  ok.\nsucceeded: 2\nfailed   : 0\n"
        for raw in (
            valid.replace("test: second...  ok.\n", "test: second...  no result\n"),
            valid.replace("test: second...  ok.\n", "test: first...  ok.\n"),
            valid.replace("test: second...  ok.\n", ""),
            valid.replace("test: second...  ok.\n", "test: second...  ok. trailing\n"),
        ):
            with self.subTest(raw=raw), self.assertRaises(harness.HarnessError):
                gate.parse_upstream_test_api_checks(raw)


class M4OperationsObservationTests(unittest.TestCase):
    def test_native_results_survive_a_later_unavailable_c_oracle(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            execution = {"command": ["cargo", "test"], "status": 0,
                         "stdout": "test result: ok. 1 passed; 0 failed\n" * len(gate.NATIVE_TESTS),
                         "stderr": "original native compiler log"}
            with (mock.patch.object(gate, "ARTIFACTS", output),
                  mock.patch.object(harness, "require_native_x86_64"),
                  mock.patch.object(harness, "require_tool", return_value="cargo"),
                  mock.patch.object(harness, "command_record", return_value=execution),
                  mock.patch.object(harness, "fetch_archive", return_value=output / "archive"),
                  mock.patch.object(harness, "safe_extract", return_value=output),
                  mock.patch.object(gate, "build_c_driver", side_effect=harness.HarnessError("missing C oracle"))):
                with self.assertRaisesRegex(harness.HarnessError, "missing C oracle"):
                    gate.run_native_tests()
            self.assertEqual(harness.read_json(output / "native-operations-execution.json"), execution)

    def test_debug_valid_client_differential_retains_programs_without_running_a_cohort(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            def build(side):
                def builder(source, destination, driver_source=None, profile="release", *, build_profile="release"):
                    self.assertEqual((profile, build_profile), ("debug-1", "debug"))
                    driver = destination / ("valid-" + side)
                    guard = int(side == "c")
                    driver.write_text("#!/usr/bin/python3\nimport sys\n"
                        "assert sys.argv[1:] == ['aligned-preservation', '--valid-domain']\n"
                        "print('CRABC_MI_M4_OPERATIONS_TRACE_BEGIN')\n"
                        "print('preserved=1')\n"
                        "print('CRABC_MI_M4_OPERATIONS_TRACE_END')\n"
                        f"print('valid-domain guarded_precise={guard}', file=sys.stderr)\n")
                    driver.chmod(0o755)
                    return driver
                return builder
            with (mock.patch.object(gate, "ARTIFACTS", output),
                  mock.patch.object(harness, "require_native_x86_64"),
                  mock.patch.object(harness, "fetch_archive", return_value=output / "archive"),
                  mock.patch.object(harness, "safe_extract", return_value=output),
                  mock.patch.object(gate, "build_c_driver", side_effect=build("c")),
                  mock.patch.object(gate, "build_rust_driver", side_effect=build("rust")),
                  mock.patch.object(gate, "run_operations_profiles", side_effect=AssertionError("unexpected cohort"))):
                report = gate.run_operations_differential(True, "aligned-preservation", build_profile="debug",
                    source_profile="debug-1", valid_clients_only=True)
            self.assertEqual(report["trace"], {"preserved": "1"})
            self.assertEqual(report["api_profiles"], {})
            self.assertFalse((output / "aligned-preservation.json").exists())
            self.assertIn("not-gate-qualification", report["scope"])
            for artifact in report["programs"].values():
                self.assertTrue(Path(artifact["path"]).is_file())

    def test_nondefault_source_mode_cannot_write_canonical_differential(self):
        with mock.patch.object(harness, "require_native_x86_64", side_effect=AssertionError("build reached")):
            with self.assertRaisesRegex(harness.HarnessError, "private valid-client"):
                gate.run_operations_differential(True, "operations", source_profile="stat-2")

    def test_full_gate_profile_commands_execute_the_selected_valid_client_domain(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            def build(side):
                def builder(source, destination, driver_source=None, profile="release"):
                    destination.mkdir(parents=True, exist_ok=True)
                    driver = destination / ("model-" + side)
                    guard = int(profile == "debug-1" and side == "c")
                    driver.write_text("#!/usr/bin/python3\nimport sys\n"
                        "valid = '--valid-domain' in sys.argv\n"
                        "selected = sys.argv[1] == 'api-modes'\n"
                        "print('CRABC_MI_M4_OPERATIONS_TRACE_BEGIN')\n"
                        f"print('domain=' + str(1 if valid or not selected or '{side}' == 'c' else 0))\n"
                        "print('CRABC_MI_M4_OPERATIONS_TRACE_END')\n"
                        f"print('valid-domain guarded_precise={guard}', file=sys.stderr)\n")
                    driver.chmod(0o755)
                    return driver
                return builder
            logs = output / "logs"
            logs.mkdir()
            receipt_path = output / "receipt.json"
            receipt_path.write_text("{}")
            def selected_profiles(offline, profiles, scenarios):
                self.assertIn("operations", scenarios)
                self.assertIn("api-modes", scenarios)
                for profile in profiles:
                    drivers = {side: build(side)(output, output / profile, profile=profile)
                               for side in ("c", "rust")}
                    gate.observe_operations_profile(logs, profile, "api-modes", drivers, [], valid_domain=True)
                return {"status": "passed"}
            with (mock.patch.object(gate, "ARTIFACTS", output),
                  mock.patch.object(harness, "require_native_x86_64"),
                  mock.patch.object(harness, "fetch_archive", return_value=output / "archive"),
                  mock.patch.object(harness, "safe_extract", return_value=output),
                  mock.patch.object(gate, "build_c_driver", side_effect=build("c")),
                  mock.patch.object(gate, "build_rust_driver", side_effect=build("rust")),
                  mock.patch.object(gate, "run_operations_profiles", side_effect=selected_profiles),
                  mock.patch.object(gate, "read_operations_profiles",
                                    return_value=SimpleNamespace(path=receipt_path))):
                result = gate.run_operations_differential(True, "aligned-preservation")
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["api_profiles"])

    def test_failed_original_workload_retains_both_results_and_revokes_old_pass(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            previous = output / "threads.json"
            previous.write_text('{"status":"passed"}')
            c = {"status": 1, "stdout": "original C output", "stderr": "original C diagnostic"}
            rust = {"status": 0, "stdout": "original native output", "stderr": ""}
            with (mock.patch.object(gate, "ARTIFACTS", output),
                  mock.patch.object(harness, "require_native_x86_64"),
                  mock.patch.object(harness, "fetch_archive", return_value=output / "archive"),
                  mock.patch.object(harness, "safe_extract", return_value=output),
                  mock.patch.object(gate, "build_c_driver", return_value=output / "c"),
                  mock.patch.object(gate, "build_rust_driver", return_value=output / "rust"),
                  mock.patch.object(gate, "run_driver", side_effect=[c, rust])):
                with self.assertRaises(harness.HarnessError):
                    gate.run_operations_differential(True, "threads")
            self.assertFalse(previous.exists(), "a failed rerun must not leave a passed report")
            self.assertEqual(harness.read_json(output / "threads-c.json"), c)
            self.assertEqual(harness.read_json(output / "threads-rust.json"), rust)
            self.assertIn("original C diagnostic", (output / "threads-c.log").read_text())
            self.assertIn("original native output", (output / "threads-rust.log").read_text())


    def test_profile_observation_runs_full_workload_on_both_sides_and_retains_failed_comparison(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            c = {"command": ["c", "threads"], "status": 0,
                 "stdout": gate.OPERATIONS_TRACE_BEGIN + "\nworker.join=1\n" + gate.OPERATIONS_TRACE_END,
                 "stderr": "source diagnostic"}
            rust = {**c, "command": ["rust", "threads"],
                    "stdout": c["stdout"].replace("worker.join=1", "worker.join=0")}
            cases = []
            with mock.patch.object(gate, "run_driver", side_effect=[c, rust]) as run:
                with self.assertRaisesRegex(harness.HarnessError, "mismatch"):
                    gate.observe_operations_profile(output, "debug-1", "threads",
                                                     {"c": output / "c", "rust": output / "rust"}, cases)
            self.assertEqual(run.call_args_list,
                [mock.call(output / "c", ("threads",)), mock.call(output / "rust", ("threads",))])
            self.assertEqual([row[0] for row in cases], ["debug-1-threads-c", "debug-1-threads-rust"])
            self.assertEqual(harness.read_json(output / "debug-1-threads-c.json"), c)
            self.assertEqual(harness.read_json(output / "debug-1-threads-rust.json"), rust)


    def test_retained_compiler_authority_rejects_a_profile_or_fixture_substitution(self):
        inputs = {"compiler": "/usr/bin/musl-gcc", "cargo": "/usr/local/bin/cargo",
                  "source_directory": "/own/source", "output_directory": "/own/run"}
        command = [inputs["compiler"], "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                   "-DCRABC_MI_M4_SOURCE_CANARY=1", *gate.api_profile_flags("debug-1"),
                   "-I", "/own/source/include", "/own/run/fixture.c", "/own/source/src/static.c",
                   "-pthread", "-o", "/own/run/debug-1/operations/operations-c"]
        valid = {"status": 0, "command": command, "stdout": "", "stderr": ""}
        gate.validate_operation_build(valid, inputs, "debug-1", "operations", "fixture.c", "c")
        changed = command[:]
        changed[changed.index("-DMI_DEBUG=1")] = "-DMI_DEBUG=0"
        with self.assertRaisesRegex(harness.HarnessError, "compiler authority"):
            gate.validate_operation_build({**valid, "command": changed}, inputs,
                                          "debug-1", "operations", "fixture.c", "c")
        changed = command[:]
        changed[changed.index("/own/run/fixture.c")] = "/other/fixture.c"
        with self.assertRaisesRegex(harness.HarnessError, "compiler authority"):
            gate.validate_operation_build({**valid, "command": changed}, inputs,
                                          "debug-1", "operations", "fixture.c", "c")


    def test_profile_reader_rejects_self_consistent_execution_from_a_different_image(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            products = output / "products"
            products.mkdir()
            pin = harness.load_pin()
            recorded = {"execution_mode": "native", "host_architecture": "x86_64",
                        "image_id": "sha256:" + "a" * 64}
            current = {**recorded, "image_id": "sha256:" + "b" * 64}
            inputs = {"source": {"revision": "source"}, "upstream": pin, "profiles": ["release"],
                      "scenarios": ["threads"], "compiler": "/pinned/tool", "cargo": "/pinned/tool",
                      "execution": recorded}
            harness.write_json(products / "inputs.json", inputs)
            harness.write_json(products / "native-execution-provenance.json", recorded)
            receipt = SimpleNamespace(path=output / "receipt.json", source=inputs["source"],
                parameters=gate.operation_profile_parameters(("release",), ("threads",)))
            with (mock.patch.object(gate, "operation_receipts", return_value=SimpleNamespace(
                    read_receipt=mock.Mock(return_value=receipt))),
                  mock.patch.object(harness, "require_tool", return_value="/pinned/tool"),
                  mock.patch.object(harness, "sha256_file", return_value=pin["sha256"]),
                  mock.patch.object(harness, "require_native_x86_64", return_value=current)):
                with self.assertRaisesRegex(harness.HarnessError, "image differs"):
                    gate.read_operations_profiles(("release",), ("threads",))


    def test_assertion_control_rejects_a_wrong_signal_or_assertion_and_native_payload_loss(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            c = {"status": -6, "stdout": gate.OPERATIONS_TRACE_BEGIN + "\ncontrol.input=null,1,1\n",
                 "stderr": 'mimalloc: assertion failed: mi_reallocarr\n  assertion: "ptrp != NULL"\n'}
            native = {"status": 0, "stdout": gate.OPERATIONS_TRACE_BEGIN +
                      "\ncontrol.input=null,1,1\ncontrol.outcome=22,22\n" + gate.OPERATIONS_TRACE_END + "\n",
                      "stderr": ""}
            gate.compare_assertion_control("debug-1", "reallocarr-null", c, native)
            for changed in ({**c, "status": -11}, {**c, "stderr": 'assertion: "size != 0"'}):
                with self.assertRaises(harness.HarnessError):
                    gate.compare_assertion_control("debug-1", "reallocarr-null", changed, native)
            zero = {**native, "stdout": native["stdout"].replace("null,1,1", "63,1,0").replace("22,22", "22,22,0")}
            zero_c = {**c, "stdout": c["stdout"].replace("null,1,1", "63,1,0"),
                      "stderr": 'mi_reallocarr\nassertion: "size != 0"'}
            with self.assertRaisesRegex(harness.HarnessError, "outcome"):
                gate.compare_assertion_control("debug-1", "reallocarr-zero-size", zero_c, zero)

    def test_nonword_invalid_alignment_control_does_not_admit_word_delegation(self):
        c = {"status": -6,
             "stdout": gate.OPERATIONS_TRACE_BEGIN + "\ncontrol.input=100,64;200,24\n",
             "stderr": 'mi_theap_realloc_zero_aligned_at\nassertion: "mi_alignment_is_valid(alignment)"'}
        native = {"status": 0, "stdout": gate.OPERATIONS_TRACE_BEGIN +
                  "\ncontrol.input=100,64;200,24\ncontrol.outcome=1,22,1\n" +
                  gate.OPERATIONS_TRACE_END + "\n", "stderr": ""}
        gate.compare_assertion_control("debug-1", "aligned-invalid", c, native)
        with self.assertRaises(harness.HarnessError):
            gate.compare_assertion_control("debug-1", "aligned-invalid", c,
                {**native, "stdout": native["stdout"].replace("200,24", "200,3")})

    def test_valid_workload_observer_binds_the_explicit_oracle_option_on_both_sides(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            output = Path(directory)
            drivers = {"c": output / "c", "rust": output / "rust"}
            trace = gate.OPERATIONS_TRACE_BEGIN + "\nclient.payload=1\n" + gate.OPERATIONS_TRACE_END + "\n"
            records = [{"status": 0, "stdout": trace, "stderr": "valid-domain guarded_precise=1\n"},
                       {"status": 0, "stdout": trace, "stderr": "valid-domain guarded_precise=0\n"}]
            with mock.patch.object(gate, "run_driver", side_effect=records) as run:
                gate.observe_operations_profile(output, "debug-1", "threads", drivers, [], valid_domain=True)
                self.assertEqual(run.call_args_list,
                    [mock.call(drivers[side], ("threads", "--valid-domain")) for side in ("c", "rust")])
            with mock.patch.object(gate, "run_driver", side_effect=[records[0],
                    {**records[1], "stderr": "valid-domain guarded_precise=1\n"}]):
                with self.assertRaisesRegex(harness.HarnessError, "oracle option"):
                    gate.observe_operations_profile(output, "debug-1", "threads", drivers, [], valid_domain=True)

    def test_registered_source_client_control_still_requires_a_valid_native_payload_and_exact_diagnostics(self):
        def record(trace, status=0, stderr=""):
            return {"status": status, "stdout": gate.OPERATIONS_TRACE_BEGIN + "\n" + trace +
                    gate.OPERATIONS_TRACE_END + "\n", "stderr": stderr}
        good = "control.input=73,64,7\ncontrol.client=1,1\ncontrol.usable=79,0,0\ncontrol.free=0,0\n"
        bad = good.replace("79,0,0", "0,0,1").replace("control.free=0,0", "control.free=0,2")
        diagnostic = "mimalloc: error: mi_usable_size: invalid (unaligned) pointer: 0x1001\n" +                      "mimalloc: error: mi_free: invalid (unaligned) pointer: 0x1001\n"
        original = {"c": record(bad, 1, diagnostic), "rust": record(good)}
        oracle = {"c": record(good, stderr="valid-domain guarded_precise=1\n"),
                  "rust": record(good, stderr="valid-domain guarded_precise=0\n")}
        gate.compare_source_client_control("debug-1", "usable-free-73", original, oracle)
        with self.assertRaises(harness.HarnessError):
            gate.compare_source_client_control("debug-1", "usable-free-73",
                {**original, "rust": record(good.replace("control.client=1,1", "control.client=1,0"))}, oracle)
        with self.assertRaises(harness.HarnessError):
            gate.compare_source_client_control("debug-1", "usable-free-73",
                {**original, "c": record(bad, 1, diagnostic + "mimalloc: error: mi_free: invalid (unaligned) pointer: 0x2001\n")}, oracle)


if __name__ == "__main__":
    unittest.main()
