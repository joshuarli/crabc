#!/usr/bin/env python3
"""Regression controls for the finite native x86-64 fault-seam inventory."""

from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import sys
import tempfile
import shutil
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


@contextmanager
def _retained_profile_contract() -> object:
    """Materialize small bytes so reader controls exercise real profile reopening."""

    runner = INVENTORY._load_runner()
    parent = runner.ARTIFACT_ROOT / "x86_64/fault-seam-inventory"
    parent.mkdir(parents=True, exist_ok=True)
    profile = Path(tempfile.mkdtemp(prefix="host-retained-mbind-", dir=parent))
    profile.chmod(INVENTORY.MBIND_PROFILE_DIRECTORY_MODE)
    direct = profile / "prim.c"
    unix = profile / "unix/prim.c"
    unix.parent.mkdir()
    direct.write_bytes(b"direct profile\n")
    unix.write_bytes(b"typed mbind profile\n")
    direct.chmod(INVENTORY.MBIND_PROFILE_FILE_MODE)
    unix.chmod(INVENTORY.MBIND_PROFILE_FILE_MODE)
    expected = (
        {
            "path": "prim.c", "bytes": direct.stat().st_size,
            "sha256": hashlib.sha256(direct.read_bytes()).hexdigest(),
        },
        {
            "path": "unix/prim.c", "bytes": unix.stat().st_size,
            "sha256": hashlib.sha256(unix.read_bytes()).hexdigest(),
        },
    )
    try:
        with (
            mock.patch.object(INVENTORY, "MBIND_PROFILE_DERIVED_FILES", expected),
            mock.patch.object(INVENTORY, "CONTAINER_WORK_ROOT", Path(runner.WORK_ROOT)),
        ):
            files = INVENTORY._retained_profile_file_records(runner, profile)
            yield runner, INVENTORY._mbind_profile_record(
                runner, profile, direct, pre_compile_files=files, post_compile_files=files
            )
    finally:
        shutil.rmtree(profile)


def _valid_report(runner: object, profile: dict[str, object]) -> dict[str, object]:
    source = Path("/evidence/mimalloc-3.5.0")
    c_binary = Path("/evidence/fault-profile")
    direct_include = Path(str(profile["compiler_direct_include"]))
    c_command = INVENTORY._huge_branch_c_command(
        runner, "/usr/bin/musl-gcc", source, c_binary, direct_include=direct_include
    )
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
                "mbind_direct_include_profile": copy.deepcopy(profile),
                "resolved_direct_primitive": INVENTORY.RESOLVED_DIRECT_PRIMITIVE,
                "translation_units": list(runner.M2_X86_64_VM_C_ORACLE_SOURCES),
            },
            "c_mbind_direct_include_profile": copy.deepcopy(profile),
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


def _valid_mbind_boundary_report(runner: object, profile: dict[str, object]) -> dict[str, object]:
    source = Path("/evidence/mimalloc-3.5.0")
    binary = Path("/evidence/mbind-boundary")
    command = INVENTORY._mbind_boundary_c_command(
        runner,
        "/usr/bin/musl-gcc",
        source,
        binary,
        direct_include=Path(str(profile["compiler_direct_include"])),
    )
    return {
        "build": {
            "command": command, "cwd": str(source), "status": 0, "stdout": "", "stderr": "",
        },
        "fixture": INVENTORY._local_file_record(INVENTORY.FIXTURE),
        "format": 1,
        "mbind_direct_include_profile": copy.deepcopy(profile),
        "run": {
            "command": [str(binary)], "cwd": str(source), "status": 0,
            "stdout": "allocator fault seam mbind boundary: PASS\n", "stderr": "",
        },
        "schema": INVENTORY.MBIND_BOUNDARY_SCHEMA,
        "upstream": {
            "archive_sha256": runner.load_pin()["sha256"], "revision": runner.load_pin()["revision"],
        },
    }


class FaultInventoryShapeTests(unittest.TestCase):
    def test_mbind_profile_derivation_records_the_pinned_two_file_bytes(self) -> None:
        self.assertEqual(
            INVENTORY.MBIND_PROFILE_DERIVED_FILES,
            (
                {
                    "path": "prim.c", "bytes": 2449,
                    "sha256": "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229",
                },
                {
                    "path": "unix/prim.c", "bytes": 36836,
                    "sha256": "7748ea6e69890f2b8e7f81fa9411ae19c4862f2fc7ad1d87d63df5d39e41fa00",
                },
            ),
        )

    def test_mbind_profile_render_keeps_unrelated_raw_syscalls(self) -> None:
        """Only the fixed `mi_prim_mbind` expression is rewritten in its body."""

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/allocator-x86_64") as temporary:
            source = Path(temporary) / "source"
            primitive = source / "src/prim"
            unix = primitive / "unix"
            unix.mkdir(parents=True)
            prim = '#include "unix/prim.c"\n'
            mbind = "return syscall(SYS_mbind, start, len, mode, nmask, maxnode, flags);"
            raw_open = "return syscall(SYS_open, fpath, flags, 0);"
            (primitive / "prim.c").write_text(prim, encoding="utf-8")
            (unix / "prim.c").write_text(f"{raw_open}\n{mbind}\n", encoding="utf-8")

            transformed = INVENTORY._render_mbind_profile_unix_body(
                (unix / "prim.c").read_bytes()
            ).decode("utf-8")
            self.assertIn(raw_open, transformed)
            self.assertEqual(
                transformed.count(
                    "return m2_fault_inventory_mbind_syscall(start, len, mode, nmask, maxnode, flags);"
                ),
                1,
            )
            self.assertNotIn(mbind, transformed)

    def test_mbind_profile_rejects_a_body_with_the_right_stub_but_wrong_bytes(self) -> None:
        """Expected mbind tokens cannot substitute for the pinned primitive source bytes."""

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/allocator-x86_64") as temporary:
            source = Path(temporary) / "source"
            primitive = source / "src/prim"
            unix = primitive / "unix"
            unix.mkdir(parents=True)
            (primitive / "prim.c").write_text('#include "unix/prim.c"\n', encoding="utf-8")
            (unix / "prim.c").write_text(
                "return syscall(SYS_open, fpath, flags, 0);\n"
                "return syscall(SYS_mbind, start, len, mode, nmask, maxnode, flags);\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(INVENTORY.EvidenceError, "source bytes changed"):
                INVENTORY._write_mbind_profile(source, Path(temporary) / "profile")

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
        with _retained_profile_contract() as (runner, profile):
            report = _valid_report(runner, profile)
            self.assertEqual(
                INVENTORY.validate_report(report)["huge_branch_receipt"],
                report["huge_branch_receipt"],
            )

    def test_report_rejects_forged_c_stream_even_with_valid_row_inventory(self) -> None:
        with _retained_profile_contract() as (runner, profile):
            report = _valid_report(runner, profile)
            report["huge_branch_receipt"]["c_run"]["stdout"] = report["huge_branch_receipt"]["c_run"]["stdout"].replace(
                INVENTORY.C_TRACE_KEYS[0], "m2.fault.c.huge.forged"
            )
            with self.assertRaisesRegex(INVENTORY.EvidenceError, "observation changed"):
                INVENTORY.validate_report(report)

    def test_report_rejects_missing_rust_stream_even_with_a_valid_process_status(self) -> None:
        with _retained_profile_contract() as (runner, profile):
            report = _valid_report(runner, profile)
            report["huge_branch_receipt"]["rust_run"]["stdout"] = (
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n"
            )
            with self.assertRaisesRegex(INVENTORY.EvidenceError, "marker count changed"):
                INVENTORY.validate_report(report)

    def test_report_rejects_a_c_command_with_an_added_source_file(self) -> None:
        with _retained_profile_contract() as (runner, profile):
            report = _valid_report(runner, profile)
            report["huge_branch_receipt"]["c_build"]["command"].insert(-2, "/evidence/mimalloc-3.5.0/src/os.c")
            with self.assertRaisesRegex(ValueError, "C command or source closure"):
                INVENTORY.validate_report(report)

    def test_report_rejects_a_mbind_profile_with_rewritten_derived_bytes(self) -> None:
        """The receipt binds its direct include to the one pinned derivation."""

        with _retained_profile_contract() as (runner, retained_profile):
            report = _valid_report(runner, retained_profile)
            profile = report["huge_branch_receipt"]["c_mbind_direct_include_profile"]
            profile["derived_files"][1]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "retained profile bytes changed"):
                INVENTORY.validate_report(report)

    def test_report_rejects_a_mbind_profile_compiler_input_outside_owned_evidence(self) -> None:
        """Reported hashes cannot redirect the compiler to an arbitrary overlay path."""

        with _retained_profile_contract() as (runner, retained_profile):
            report = _valid_report(runner, retained_profile)
            profile = report["huge_branch_receipt"]["c_mbind_direct_include_profile"]
            profile["compiler_direct_include"] = "/tmp/forged/prim.c"
            report["huge_branch_receipt"]["c_compiled_source_closure"][
                "mbind_direct_include_profile"
            ] = copy.deepcopy(profile)
            command = report["huge_branch_receipt"]["c_build"]["command"]
            macro = next(index for index, argument in enumerate(command) if "PRIM_PROFILE" in argument)
            command[macro] = '-DCRABC_M2_FAULT_SEAM_PRIM_PROFILE="/tmp/forged/prim.c"'
            with self.assertRaisesRegex(ValueError, "compiler direct include"):
                INVENTORY.validate_report(report)

    def test_report_rejects_profile_bytes_mutated_after_compilation(self) -> None:
        """Reader replay reopens retained compiler input instead of trusting its record."""

        with _retained_profile_contract() as (runner, retained_profile):
            report = _valid_report(runner, retained_profile)
            profile = runner.WORK_ROOT / retained_profile["directory"]["path"]
            (profile / "unix/prim.c").write_bytes(b"mutated after compilation\n")
            (profile / "unix/prim.c").chmod(INVENTORY.MBIND_PROFILE_FILE_MODE)
            with self.assertRaisesRegex(ValueError, "files changed after compilation"):
                INVENTORY.validate_report(report)

    def test_report_rejects_a_retained_profile_symlink_or_mode_change(self) -> None:
        """Replay requires a regular 0600 compiler input beneath a real directory."""

        for mutation in ("symlink", "mode"):
            with self.subTest(mutation=mutation), _retained_profile_contract() as (runner, retained_profile):
                report = _valid_report(runner, retained_profile)
                profile = runner.WORK_ROOT / retained_profile["directory"]["path"]
                target = profile / "unix/prim.c"
                if mutation == "symlink":
                    target.unlink()
                    target.symlink_to(profile / "prim.c")
                else:
                    target.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "retained profile files"):
                    INVENTORY.validate_report(report)

    def test_mbind_boundary_report_replays_exact_retained_input(self) -> None:
        with _retained_profile_contract() as (runner, retained_profile):
            report = _valid_mbind_boundary_report(runner, retained_profile)
            self.assertEqual(INVENTORY.validate_mbind_boundary_report(report), report)

    def test_mbind_boundary_report_rejects_profile_command_and_output_changes(self) -> None:
        """The boundary receipt is independently replayable after collection."""

        for mutation in (
            "profile-path", "pre-compile-bytes", "profile-bytes", "build-command",
            "run-command", "run-status", "output",
        ):
            with self.subTest(mutation=mutation), _retained_profile_contract() as (runner, retained_profile):
                report = _valid_mbind_boundary_report(runner, retained_profile)
                if mutation == "profile-path":
                    report["mbind_direct_include_profile"]["directory"]["path"] = "target/forged"
                elif mutation == "pre-compile-bytes":
                    report["mbind_direct_include_profile"]["pre_compile_files"][1]["sha256"] = "0" * 64
                elif mutation == "profile-bytes":
                    report["mbind_direct_include_profile"]["post_compile_files"][1]["sha256"] = "0" * 64
                elif mutation == "build-command":
                    report["build"]["command"].append("-Dforged")
                elif mutation == "run-command":
                    report["run"]["command"] = ["/evidence/forged"]
                elif mutation == "run-status":
                    report["run"]["status"] = 1
                else:
                    report["run"]["stdout"] = "allocator fault seam mbind boundary: forged\n"
                with self.assertRaises(ValueError):
                    INVENTORY.validate_mbind_boundary_report(report)


if __name__ == "__main__":
    unittest.main()
