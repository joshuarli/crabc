#!/usr/bin/env python3
"""Regression controls for the finite native x86-64 fault-seam inventory."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_fault_seam_inventory.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_fault_seam_inventory", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INVENTORY
SPEC.loader.exec_module(INVENTORY)


def _trace(begin: str, end: str, keys: tuple[str, ...]) -> str:
    return "\n".join((begin, *(f"{key}=1" for key in keys), end, ""))


def _clean_source_state() -> dict[str, object]:
    return {
        "kind": "git",
        "revision": "0" * 40,
        "worktree_clean": True,
        "worktree_status": {
            "bytes": 0,
            "hex": "",
            "sha256": hashlib.sha256(b"").hexdigest(),
        },
    }


def _valid_report() -> dict[str, object]:
    runner = INVENTORY._load_runner()
    source = Path("/evidence/mimalloc-3.5.0")
    c_binary = Path("/evidence/fault-profile")
    c_command = INVENTORY._huge_branch_c_command(runner, "/usr/bin/musl-gcc", source, c_binary)
    rust_binary = (
        runner.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET
        / runner.X86_64_RUST_TARGET
        / "debug/deps/crabc_mimalloc-aaaaaaaa"
    )
    c_build = {"command": c_command, "cwd": str(source), "status": 0, "stdout": "", "stderr": ""}
    c_run = {
        "command": [str(c_binary)], "cwd": str(source), "status": 0,
        "stdout": _trace(INVENTORY.C_TRACE_BEGIN, INVENTORY.C_TRACE_END, INVENTORY.C_TRACE_KEYS),
        "stderr": "",
    }
    rust_build = {
        "command": runner._m2_x86_64_vm_rust_build_command(), "cwd": str(INVENTORY.ROOT),
        "status": 0, "stdout": "", "stderr": "",
    }
    rust_run = {
        "command": [str(rust_binary), INVENTORY.RUST_TARGET, "--exact", "--test-threads=1", "--nocapture"],
        "cwd": str(INVENTORY.ROOT), "status": 0,
        "stdout": _trace(INVENTORY.RUST_TRACE_BEGIN, INVENTORY.RUST_TRACE_END, INVENTORY.RUST_TRACE_KEYS)
        + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
        "stderr": "",
    }
    state = _clean_source_state()
    return {
        "architecture": "x86_64",
        "branch_records": INVENTORY._branch_records(),
        "diagnostic_owner_boundary": INVENTORY.DIAGNOSTIC_OWNER_BOUNDARY,
        "format": INVENTORY.FORMAT,
        "huge_branch_receipt": {
            "c_build": c_build,
            "c_compiled_source_closure": {
                "direct_fixture_source_units": list(INVENTORY.DIRECT_FIXTURE_SOURCE_UNITS),
                "resolved_direct_primitive": INVENTORY.RESOLVED_DIRECT_PRIMITIVE,
                "translation_units": list(runner.M2_X86_64_VM_C_ORACLE_SOURCES),
            },
            "c_run": c_run,
            "c_source_files": list(INVENTORY.PINNED_C_SOURCE_FILES),
            "fixture": INVENTORY._local_file_record(INVENTORY.FIXTURE),
            "rust_build": rust_build,
            "rust_passed_test_count": 1,
            "rust_run": rust_run,
            "rust_source_files": [INVENTORY._local_file_record(INVENTORY.ROOT / INVENTORY.RUST_TRACE_SOURCE)],
        },
        "inventory": INVENTORY.inventory_definition(),
        "nonclaims": ["bounded fixture only"],
        "schema": INVENTORY.SCHEMA,
        "source_state_after": state,
        "source_state_before": copy.deepcopy(state),
        "status": "passed",
        "stopped_receivers": [item.identifier for item in INVENTORY.STOPPED_RECEIVERS],
        "unqualified_branches": list(INVENTORY.UNQUALIFIED_BRANCHES),
        "upstream": {"archive_sha256": runner.load_pin()["sha256"], "revision": runner.load_pin()["revision"]},
        "vm_receipt": {
            "compared_value_count": 1,
            "schema": "crabc-mimalloc-x86_64-m2-vm-primitives-evidence",
            "status": "passed",
            "trace_sha256": "0" * 64,
        },
    }


class FaultInventoryShapeTests(unittest.TestCase):
    def test_runner_loader_registers_the_module_for_its_vm_producer(self) -> None:
        """The dynamically loaded runner names itself while invoking its producer."""

        module_name = "crabc_allocator_fault_inventory_runner"
        previous = sys.modules.pop(module_name, None)
        try:
            runner = INVENTORY._load_runner()
            self.assertIs(sys.modules.get(module_name), runner)
        finally:
            sys.modules.pop(module_name, None)
            if previous is not None:
                sys.modules[module_name] = previous

    def test_standalone_producer_builds_the_vm_validator_canonical_cargo_target(self) -> None:
        """The standalone producer must feed the same target the VM reader admits."""

        runner = INVENTORY._load_runner()
        observed: dict[str, object] = {}

        class StopAfterVmProvenance(Exception):
            pass

        def capture_target(execution: object, cargo_target: Path, *, gate_name: str) -> dict[str, object]:
            observed["execution"] = execution
            observed["cargo_target"] = cargo_target
            observed["gate_name"] = gate_name
            path = cargo_target / runner.X86_64_RUST_TARGET / "debug/deps/crabc_mimalloc-deadbeef"
            command = runner._m2_x86_64_vm_rust_build_command()
            return {
                "build": {"command": command, "status": 0, "stdout": "", "stderr": ""},
                "build_command": command,
                "cargo_target": str(cargo_target),
                "execution": runner._m2_x86_64_vm_rust_execution(),
                "path": path,
            }

        def capture_vm(*, offline: bool, test_program: object) -> object:
            del offline
            observed["vm_provenance_bound"] = runner._m2_x86_64_vm_test_program_is_bound(test_program)
            if not observed["vm_provenance_bound"]:
                raise AssertionError("standalone producer gave the VM validator an unbound test program")
            raise StopAfterVmProvenance

        with (
            mock.patch.object(INVENTORY, "_load_runner", return_value=runner),
            mock.patch.object(runner, "require_native_x86_64"),
            mock.patch.object(runner, "m2_memory_substrate_source_state", return_value={}),
            mock.patch.object(runner, "load_pin", return_value={}),
            mock.patch.object(runner, "fetch_archive", return_value=Path("/archive")),
            mock.patch.object(runner, "require_tool", return_value="/usr/bin/musl-gcc"),
            mock.patch.object(runner, "_x86_64_unit_test_program", side_effect=capture_target),
            mock.patch.object(runner, "_run_m2_x86_64_vm_evidence", side_effect=capture_vm),
            mock.patch.object(Path, "is_file", return_value=True),
        ):
            with self.assertRaises(StopAfterVmProvenance):
                INVENTORY.run_evidence(offline=True)

        self.assertEqual(observed["cargo_target"], runner.M2_X86_64_MEMORY_SUBSTRATE_CARGO_TARGET)
        self.assertEqual(observed["gate_name"], "native x86 fault seam inventory")
        self.assertTrue(observed["vm_provenance_bound"])

    def test_source_inventory_is_closed_and_retains_stopped_receivers(self) -> None:
        self.assertEqual(
            [row.identifier for row in INVENTORY.SOURCE_ROWS],
            [
                "os-full-release-owner",
                "os-regular-aligned-map-and-cleanup",
                "os-normal-offset-allocation-owner",
                "os-range-transition-fault-owners",
                "os-huge-branch-fault-owners",
                "page-map-completed-dependency",
            ],
        )
        self.assertEqual(
            [receiver.identifier for receiver in INVENTORY.STOPPED_RECEIVERS],
            ["metadata-map-commit-publication", "os-aligned-page-publication"],
        )

    def test_partial_m2_fragment_names_the_same_fixed_inventory(self) -> None:
        component = INVENTORY.load_fragment()["component"]
        self.assertEqual(component["id"], "fault-injection")
        self.assertEqual(component["completion_status"], "partial")
        self.assertEqual(
            [row["id"] for row in component["branch_matrix"]],
            [row.identifier for row in INVENTORY.BRANCH_ROWS],
        )
        self.assertEqual(
            component["checks"],
            [{
                "id": INVENTORY.FAULT_COMPONENT_CHECK_ID,
                "kind": "c-rust-fault-seam-inventory",
                "target": INVENTORY.RUST_TARGET,
                "expected_passed_test_count": 1,
            }],
        )

    def test_fragment_rejects_rewritten_anchor_scope_and_open_receiver(self) -> None:
        original = json.loads(INVENTORY.FRAGMENT_PATH.read_text(encoding="utf-8"))
        scratch = INVENTORY.ROOT / ".work/allocator-x86_64/fault-seam-inventory-host-fragment"
        scratch.mkdir(parents=True, exist_ok=True)
        for mutation in ("anchor", "scope", "unqualified"):
            changed = copy.deepcopy(original)
            if mutation == "anchor":
                changed["component"]["bounded_source_definitions"][0]["source_anchor"]["start_line"] += 1
            elif mutation == "scope":
                changed["component"]["branch_matrix"][0]["source_scope"] = "rewritten scope"
            else:
                changed["component"]["unqualified_failure_matrix"].pop()
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", dir=scratch, delete=False, encoding="utf-8"
            ) as stream:
                json.dump(changed, stream)
                candidate = Path(stream.name)
            try:
                with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    INVENTORY.EvidenceError, "fault inventory M2"
                ):
                    INVENTORY.load_fragment(candidate)
            finally:
                candidate.unlink()
    def test_definition_rejects_a_same_length_renamed_branch(self) -> None:
        definition = INVENTORY.inventory_definition()
        definition["branch_rows"][3] = "purge-replaced-by-a-same-length-name"
        with self.assertRaisesRegex(ValueError, "branch-row roster"):
            INVENTORY.validate_inventory_definition(definition)

    def test_branch_records_reject_wrong_point_even_when_owner_text_matches(self) -> None:
        records = []
        for row in INVENTORY.BRANCH_ROWS:
            records.append(
                {
                    "c_branch": row.c_branch,
                    "errno": row.errno,
                    "id": row.identifier,
                    "ordinal": row.ordinal,
                    "outcome": row.outcome,
                    "owner_statistics": row.owner_statistics,
                    "point": row.point,
                    "rust_receiver": row.rust_receiver,
                    "source_row": row.source_row,
                    "status": "admitted",
                }
            )
        records[0]["point"] = "Map"
        with self.assertRaisesRegex(ValueError, "branch record changed"):
            INVENTORY.validate_branch_records(records)

    def test_report_reconstructs_the_retained_fixed_streams(self) -> None:
        report = _valid_report()
        self.assertEqual(
            INVENTORY.validate_report(report)["huge_branch_receipt"],
            report["huge_branch_receipt"],
        )

    def test_report_rejects_forged_c_stream_even_with_valid_row_inventory(self) -> None:
        report = _valid_report()
        report["huge_branch_receipt"]["c_run"]["stdout"] = report["huge_branch_receipt"]["c_run"]["stdout"].replace(
            INVENTORY.C_TRACE_KEYS[0], "m2.fault.c.huge.forged"
        )
        with self.assertRaisesRegex(INVENTORY.EvidenceError, "observation changed"):
            INVENTORY.validate_report(report)

    def test_report_rejects_missing_rust_stream_even_with_a_valid_process_status(self) -> None:
        report = _valid_report()
        report["huge_branch_receipt"]["rust_run"]["stdout"] = (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "0 filtered out; finished in 0.00s\n"
        )
        with self.assertRaisesRegex(INVENTORY.EvidenceError, "marker count changed"):
            INVENTORY.validate_report(report)

    def test_report_rejects_a_c_command_with_an_added_source_file(self) -> None:
        report = _valid_report()
        report["huge_branch_receipt"]["c_build"]["command"].insert(-2, "/evidence/mimalloc-3.5.0/src/os.c")
        with self.assertRaisesRegex(ValueError, "C command or source closure"):
            INVENTORY.validate_report(report)


if __name__ == "__main__":
    unittest.main()
