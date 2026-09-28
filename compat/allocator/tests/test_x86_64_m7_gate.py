#!/usr/bin/env python3
"""Contracts for the fail-closed native allocator gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m7_gate", ROOT / "compat/allocator/x86_64_m7_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M7GateContractTests(unittest.TestCase):
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

    def test_checked_in_contract_partitions_the_m7_items_and_modes(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        self.assertEqual(sorted(summary["runnable_evidence"]), [
            "audit:default-baseline",
            "differential:adapter",
            "differential:deferred-free-callback",
            "differential:destroy-on-exit",
            "differential:diagnostic-output-owner",
            "differential:error-reporting-sites",
            "differential:option-effects",
            "differential:option-profiles",
            "differential:options-environment",
            "differential:page-max-candidates",
            "differential:reclaim-options",
            "differential:show-errors-profile",
            "differential:startup-page-map-failure",
            "differential:statistics",
            "differential:statistics-level-one",
            "differential:thread-init-failure",
        ])
        # The options/environment and baseline gates have executable evidence.
        self.assertEqual(
            summary["blocked_gate_ids"],
            [gate_id for gate_id in gate.GATE_IDS if gate_id not in ("m7.options-environment", "m7.baseline")],
        )
        owned = {name for entry in self.contract["gates"] for name in entry["items"]}
        for name in ("mi_option_get", "mi_option_reset_delay", "mi_options_print_out", "mi_version",
                     "mi_register_error", "mi_stats_print_out", "mi_debug_show_arenas"):
            self.assertIn(name, owned)
        # Heap/Theap/subprocess statistics and visitation belong to M6, and
        # the declaration-only `mi_stats_merge` is inapplicable.
        for name in ("mi_heap_stats_get", "mi_heap_visit_blocks", "mi_theap_guarded_set_sample_rate",
                     "mi_stats_merge", "mi_malloc"):
            self.assertNotIn(name, owned)
        modes = {name for entry in self.contract["gates"] for name in entry["compile_time_modes"]}
        self.assertIn("MI_GUARDED", modes)
        self.assertNotIn("MI_OVERRIDE", modes)

    def test_destroy_on_exit_requires_its_physical_option_effect_evidence(self) -> None:
        summary = self.validate()
        effect = self.gate_record(self.contract, "m7.option-effects")
        self.assertIn("differential:destroy-on-exit", effect["evidence"])
        self.assertIn("differential:destroy-on-exit", summary["runnable_evidence"])

    def test_destroy_on_exit_reader_rejects_missing_physical_state(self) -> None:
        rows = "".join(f"destroy_on_exit.{index}={value}\n" for index, value in enumerate((2, 1, 0, 0, 1, 0, 1)))
        self.assertEqual(gate.destroy_on_exit_fields(rows, "destroy_on_exit", "fixture"), [2, 1, 0, 0, 1, 0, 1])
        with self.assertRaises(harness.HarnessError):
            gate.destroy_on_exit_fields(rows.replace("destroy_on_exit.6=1\n", ""), "destroy_on_exit", "fixture")

    def test_page_max_candidates_requires_discriminating_option_effect_evidence(self) -> None:
        summary = self.validate()
        effect = self.gate_record(self.contract, "m7.option-effects")
        self.assertIn("differential:page-max-candidates", effect["evidence"])
        self.assertIn("differential:page-max-candidates", summary["runnable_evidence"])

    def test_page_max_candidates_reader_requires_changed_choice_and_intact_data(self) -> None:
        first = {"case.limit": "0", "case.distinct_pages": "1", "case.selected": "first",
                 "case.first_data": "1", "case.transferred_data": "1", "case.usable": "8192"}
        transferred = {**first, "case.limit": "4", "case.selected": "transferred"}
        gate.require_page_max_candidates_choice(first, 0, "first")
        gate.require_page_max_candidates_choice(transferred, 4, "transferred")
        with self.assertRaises(harness.HarnessError):
            gate.require_page_max_candidates_choice({**transferred, "case.selected": "first"}, 4, "unchanged")
        with self.assertRaises(harness.HarnessError):
            gate.require_page_max_candidates_choice({**first, "case.transferred_data": "0"}, 0, "corrupted")

    def test_statistics_level_one_requires_source_built_differential(self) -> None:
        summary = self.validate()
        statistics = self.gate_record(self.contract, "m7.statistics")
        self.assertIn("differential:statistics-level-one", statistics["evidence"])
        self.assertIn("differential:statistics-level-one", summary["runnable_evidence"])

    def test_statistics_level_one_reader_requires_merge_and_print(self) -> None:
        trace = {"profile.level": "1", "allocation.usable": "64", "allocated.normal": "64,64,64",
                 "merged.normal": "64,64,64", "freed.normal": "64,64,0", "print.binned": "1"}
        gate.require_statistics_level_one(trace, "fixture")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one({**trace, "merged.normal": "0,0,0"}, "lost merge")
        with self.assertRaises(harness.HarnessError):
            gate.require_statistics_level_one({**trace, "print.binned": "0"}, "missing output")

    def test_default_artifact_reader_rejects_changed_build_or_cpu(self) -> None:
        with harness.temporary_directory("m7-baseline-reader-") as name:
            target = Path(name) / "target"
            artifact = target / gate.RUST_TARGET / "release/libcrabc_mimalloc_native_mi_adapter.a"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"!<arch>\ncompiled archive")
            ir = target / gate.RUST_TARGET / "release/build/crabc-mimalloc-native-mi-adapter/x/out/adapter.ll"
            ir.parent.mkdir(parents=True)
            ir.write_text('target triple = "x86_64-unknown-linux-musl"\n'
                          'attributes #0 = { "target-cpu"="x86-64" }\n')
            record = {
                "reason": "compiler-artifact", "target": {"name": "crabc_mimalloc_native_mi_adapter",
                "kind": ["staticlib"]}, "profile": {"opt_level": "3", "debuginfo": 0,
                "debug_assertions": False, "overflow_checks": False, "test": False},
                "features": [], "filenames": [str(artifact)],
            }
            allocator = copy.deepcopy(record)
            allocator["target"] = {"name": "crabc_mimalloc", "kind": ["lib"]}
            output = json.dumps(record) + "\n" + json.dumps(allocator)
            self.assertEqual(gate.audit_default_baseline_artifact(output, target)["target_cpu"], "x86-64")
            changed = copy.deepcopy(record)
            changed["features"] = ["mi-show-errors"]
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(json.dumps(changed) + "\n" + json.dumps(allocator), target)
            changed = copy.deepcopy(record)
            changed["profile"]["debug_assertions"] = True
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(json.dumps(changed) + "\n" + json.dumps(allocator), target)
            changed = copy.deepcopy(allocator)
            changed["features"] = ["mi-show-errors"]
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(json.dumps(record) + "\n" + json.dumps(changed), target)
            ir.write_text(ir.read_text().replace('"x86-64"', '"x86-64-v3"'))
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(output, target)
            ir.write_text('target triple = "x86_64-unknown-linux-musl"\n'
                          'attributes #0 = { "target-cpu"="x86-64" "target-features"="+avx2" }\n')
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(output, target)
            ir.write_text('target triple = "x86_64-unknown-linux-musl"\n'
                          'attributes #0 = { "target-cpu"="x86-64" }\n')
            artifact.write_bytes(b"changed artifact")
            with self.assertRaises(harness.HarnessError):
                gate.audit_default_baseline_artifact(output, target)

    def test_default_configuration_reader_rejects_changed_release_image(self) -> None:
        baseline = "debug level : 0\nsecure level: 0\nmem tracking: none\nfree: aligned, page size: 256\n"
        self.assertEqual(gate.audit_default_baseline_configuration(baseline, baseline), baseline)
        with self.assertRaises(harness.HarnessError):
            gate.audit_default_baseline_configuration(baseline, baseline.replace("secure level: 0", "secure level: 1"))

    def test_an_omitted_or_doubly_owned_item_or_mode_is_rejected(self) -> None:
        omitted = copy.deepcopy(self.contract)
        self.gate_record(omitted, "m7.callbacks")["items"].remove("mi_register_error")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory items"):
            self.validate(omitted)

        doubled = copy.deepcopy(self.contract)
        self.gate_record(doubled, "m7.statistics")["items"].append("mi_option_get")
        with self.assertRaisesRegex(harness.HarnessError, "owned by both"):
            self.validate(doubled)

        mode_omitted = copy.deepcopy(self.contract)
        self.gate_record(mode_omitted, "m7.secure")["compile_time_modes"].remove("MI_SECURE_FULL")
        with self.assertRaisesRegex(harness.HarnessError, "omit applicable inventory modes"):
            self.validate(mode_omitted)

    def test_a_new_applicable_authority_entry_breaks_closure(self) -> None:
        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(item for item in api["items"] if item["name"] == "mi_option_get"))
        extra["name"] = "mi_option_get_ex"
        api["items"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "mi_option_get_ex"):
            self.validate(api=api)

        api = copy.deepcopy(self.api)
        extra = copy.deepcopy(next(mode for mode in api["compile_time_modes"] if mode["name"] == "MI_SECURE"))
        extra["name"] = "MI_SECURE_EXTRA"
        api["compile_time_modes"].append(extra)
        with self.assertRaisesRegex(harness.HarnessError, "MI_SECURE_EXTRA"):
            self.validate(api=api)

    def test_an_item_another_milestone_owns_is_rejected(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "another milestone owns"):
            self.validate(sibling={**self.sibling, "mi_option_get": "compat/allocator/m6-gate-v3.5.0.json"})

        overlapping = copy.deepcopy(self.contract)
        overlapping["inventory"]["additional_items"].append("mi_heap_stats_get")
        with self.assertRaisesRegex(harness.HarnessError, "another milestone owns"):
            self.validate(overlapping)

    def test_an_item_exported_by_libc_or_outside_the_adapter_is_rejected(self) -> None:
        for field, value, message in (
            ("crabc_libc_exported", True, "libc exports"),
            ("adapter_surface", "source-only", "outside the test-c-api-adapter-only"),
        ):
            api = copy.deepcopy(self.api)
            next(item for item in api["items"] if item["name"] == "mi_stats_get")[field] = value
            with self.assertRaisesRegex(harness.HarnessError, message):
                self.validate(api=api)
        exporting = copy.deepcopy(self.contract)
        exporting["inventory"]["abi_boundary"]["crabc_libc_exported"] = True
        with self.assertRaisesRegex(harness.HarnessError, "out of libc"):
            self.validate(exporting)

    def test_inapplicable_or_unselected_ownership_is_rejected(self) -> None:
        inapplicable = copy.deepcopy(self.contract)
        inapplicable["inventory"]["additional_items"].append("mi_collect_reduce")
        with self.assertRaisesRegex(harness.HarnessError, "not applicable"):
            self.validate(inapplicable)

        unowned = copy.deepcopy(self.contract)
        self.gate_record(unowned, "m7.debug")["compile_time_modes"].append("MI_OVERRIDE")
        with self.assertRaisesRegex(harness.HarnessError, "unselected mode"):
            self.validate(unowned)

        itemless = copy.deepcopy(self.contract)
        self.gate_record(itemless, "m7.baseline")["compile_time_modes"].append("MI_GUARDED")
        with self.assertRaisesRegex(harness.HarnessError, "cross-cutting"):
            self.validate(itemless)

    def test_missing_evidence_cannot_be_unblocked_by_editing_the_contract(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        self.gate_record(unblocked, "m7.visitation")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

        undeclared = copy.deepcopy(self.contract)
        self.gate_record(undeclared, "m7.guarded")["evidence"].append("differential:invented")
        with self.assertRaisesRegex(harness.HarnessError, "undeclared evidence"):
            self.validate(undeclared)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["differential:statistics"]["command"] = ["python3", "compat/allocator/absent.py"]
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

    def test_passing_runnable_evidence_never_removes_a_reviewed_blocker(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        report = gate.gate_report(self.contract, summary, passed)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(report["unmet_required"], summary["blocked_gate_ids"])
        callbacks = self.gate_record(report, "m7.callbacks")
        self.assertEqual(callbacks["status"], "blocked")
        self.assertTrue(all(status == "passed" for status in callbacks["evidence"].values()))
        self.assertEqual(self.gate_record(report, "m7.options-environment")["status"], "passed")

    def test_a_fully_evidenced_unblocked_gate_passes_and_a_failed_run_fails(self) -> None:
        contract = copy.deepcopy(self.contract)
        for record in contract["evidence"].values():
            record["command"] = ["python3", "compat/allocator/x86_64_m7_gate.py"]
        for entry in contract["gates"]:
            entry["blocked_by"] = []
        summary = self.validate(contract)
        results = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        self.assertEqual(gate.gate_report(contract, summary, results)["overall_status"], "passed")
        results["differential:error-reporting-sites"] = {"status": "failed"}
        report = gate.gate_report(contract, summary, results)
        self.assertEqual(report["overall_status"], "unmet")
        self.assertEqual(self.gate_record(report, "m7.callbacks")["status"], "failed")


    def test_evidence_commands_bind_only_their_fresh_scratch_directory(self) -> None:
        command = self.contract["evidence"]["differential:diagnostic-output-owner"]["command"]
        bound = gate.evidence_command(command, Path("/scratch/run"))
        self.assertIn("/scratch/run/diagnostic-output-owner.json", bound)
        self.assertEqual(gate.evidence_command(["python3", "x.py"], Path("/s")), ["python3", "x.py"])


class M7OptionsTraceTests(unittest.TestCase):
    def trace(self, *, drop: str | None = None) -> str:
        lines = [gate.OPTIONS_TRACE_BEGIN, "options.count=1", "options.descriptor.0=show_errors,-,0"]
        for scenario in gate.OPTIONS_SCENARIOS:
            lines += [
                f"scenario.{scenario}.environment=",
                f"scenario.{scenario}.messages=",
                f"scenario.{scenario}.option.show_errors=0,1,0",
                f"scenario.{scenario}.lazy_messages=",
            ]
        for scenario in gate.OPTIONS_ERROR_SCENARIOS:
            lines += [f"error.{scenario}.environment=", f"error.{scenario}.results=0/0/12",
                      f"error.{scenario}.messages="]
        for scenario in gate.OPTIONS_RECURSION_SCENARIOS:
            lines += [f"recursion.{scenario}.{suffix}=" for suffix in (
                "environment", "init.messages", "init.verbose", "final_verbose",
                "direct.messages", "direct.verbose")]
        lines += ["api.print=7631", gate.OPTIONS_TRACE_END]
        return "\n".join(line for line in lines if line != drop) + "\n"

    def test_a_trace_missing_a_scenario_or_descriptor_record_is_rejected(self) -> None:
        gate.require_complete_options_trace(gate.parse_options_trace(self.trace(), "trace"), "trace")
        # libtest prints the test name before captured stdout on the same line.
        libtest = "running 1 test\ntest tests::trace ... " + self.trace() + "ok\n"
        self.assertEqual(gate.parse_options_trace(libtest, "Rust"), gate.parse_options_trace(self.trace(), "C"))
        for drop in ("scenario.guarded_boolean.messages=", "scenario.cap.option.show_errors=0,1,0",
                     "error.capped.results=0/0/12", "recursion.invalid_verbose.init.verbose="):
            with self.assertRaisesRegex(harness.HarnessError, "lacks"):
                gate.require_complete_options_trace(
                    gate.parse_options_trace(self.trace(drop=drop), "trace"), "trace"
                )

    def test_a_single_differing_key_fails_the_comparison(self) -> None:
        c_trace = gate.parse_options_trace(self.trace(), "C")
        gate.compare_options_traces(c_trace, dict(c_trace))
        rust_trace = {**c_trace, "scenario.empty.option.show_errors": "1,2,1"}
        with self.assertRaisesRegex(harness.HarnessError, "scenario.empty.option.show_errors"):
            gate.compare_options_traces(c_trace, rust_trace)
        with self.assertRaisesRegex(harness.HarnessError, "repeated trace key"):
            gate.parse_options_trace(self.trace().replace("api.print=7631", "api.print=1\napi.print=2"), "C")


class M7ErrorSitesTraceTests(unittest.TestCase):
    def test_a_trace_missing_a_request_record_is_rejected(self) -> None:
        trace = {
            f"error_site.{case}.{suffix}": "0"
            for case in gate.ERROR_SITE_CASES for suffix in ("messages", "deferred", "null", "errno")
        }
        trace["error_site.startup.messages"] = ""
        gate.require_complete_error_sites_trace(trace, "trace")
        del trace["error_site.worker_malloc_too_large.errno"]
        with self.assertRaisesRegex(harness.HarnessError, "worker_malloc_too_large.errno"):
            gate.require_complete_error_sites_trace(trace, "trace")


class M7OptionEffectsTraceTests(unittest.TestCase):
    def trace(self, *, drop: str | None = None) -> str:
        lines = [gate.OPTION_EFFECTS_TRACE_BEGIN]
        lines += [f"{family}.0=1" for family in gate.OPTION_EFFECT_FAMILIES if family != drop]
        lines.append(gate.OPTION_EFFECTS_TRACE_END)
        return "\n".join(lines) + "\n"

    def parse(self, output: str) -> dict[str, str]:
        return gate.parse_options_trace(
            output, "trace", gate.OPTION_EFFECTS_TRACE_BEGIN, gate.OPTION_EFFECTS_TRACE_END
        )

    def test_a_trace_missing_a_decision_family_is_rejected(self) -> None:
        gate.require_complete_option_effects_trace(self.parse(self.trace()), "trace")
        with self.assertRaisesRegex(harness.HarnessError, "arena_reserve"):
            gate.require_complete_option_effects_trace(self.parse(self.trace(drop="arena_reserve")), "trace")

    def test_the_options_markers_do_not_delimit_an_effects_trace(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "markers"):
            gate.parse_options_trace(self.trace(), "trace")


if __name__ == "__main__":
    unittest.main()
