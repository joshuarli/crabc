#!/usr/bin/env python3
"""Host behavior of the native x86 ``consumer.rust-std-lto`` gate runner."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("consumer_rust_std_lto", ROOT / "compat/x86_64/consumer_rust_std_lto.py")
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)
WORK = ROOT / ".work/x86_64/consumer-rust-std-lto-tests"


def execution(status: object, stdout: bytes, stderr: bytes = b"") -> dict[str, object]:
    return {"status": status, "stdout": {"sha256": GATE.hashlib.sha256(stdout).hexdigest()},
            "stderr": {"sha256": GATE.hashlib.sha256(stderr).hexdigest()}}


class ComparisonTests(unittest.TestCase):
    def test_raw_comparison_requires_a_successful_identical_oracle(self) -> None:
        self.assertTrue(GATE.raw_comparison(execution(0, b"a\n"), execution(0, b"a\n"))["passed"])
        failed_oracle = GATE.raw_comparison(execution(1, b"a\n"), execution(1, b"a\n"))
        self.assertFalse(failed_oracle["passed"])
        differs = GATE.raw_comparison(execution(0, b"dns:2\n"), execution(0, b"dns:1\n"))
        self.assertEqual(differs["same"], {"status": True, "stdout": False, "stderr": True})
        self.assertFalse(differs["passed"])


class OwnedLinkConditionTests(unittest.TestCase):
    def build(self, **facts: object) -> dict[str, object]:
        link = {"unwind_requests": ["-lgcc_s"], "provider_members_extracted": ["crabc-unwind.o"]}
        link.update(facts)
        return {"status": "built", "link_facts": link}

    def test_provider_member_must_be_extracted_for_the_unwind_request(self) -> None:
        self.assertEqual(GATE.owned_link_conditions("lane", self.build(), provider={}), [])
        missing = GATE.owned_link_conditions("lane", self.build(provider_members_extracted=[]), provider={})
        self.assertIn("ordinary archive extraction", missing[0])

    def test_std_graph_without_an_unwinder_request_is_not_evidence(self) -> None:
        unmet = GATE.owned_link_conditions("lane", self.build(unwind_requests=[], provider_members_extracted=[]),
                                           provider={})
        self.assertIn("no native unwinder request", unmet[0])

    def test_failed_build_is_named_with_its_compiler_output(self) -> None:
        unmet = GATE.owned_link_conditions("lane", {"status": "build-failed", "stderr_tail": "E0425"}, provider={})
        self.assertIn("E0425", unmet[0])


class NativeRouteTests(unittest.TestCase):
    DISASSEMBLY = """
0000000000001000 <crabc_rs_native_facade_getpid_witness>:
    1000:\tmov    $0x27,%eax
    1005:\tsyscall
    1007:\tmov    $0x27,%eax
    100c:\tsyscall
    100e:\tret

0000000000001010 <native_facade_direct_route>:
    1010:\tmov    $0x1,%eax
    1015:\tsyscall
    1017:\tret
"""

    def test_direct_syscalls_without_public_edges_prove_the_route(self) -> None:
        route = GATE.inspect_native_route(self.DISASSEMBLY)
        self.assertTrue(route["direct_route_proven"])
        self.assertEqual(route["witness_direct_getpid_syscalls"], 2)

    def test_public_c_or_errno_edges_in_the_witness_fail(self) -> None:
        for callee in ("getpid@plt", "__errno_location"):
            with self.subTest(callee=callee):
                text = self.DISASSEMBLY.replace("    100e:\tret", f"    100e:\tcall   2000 <{callee}>")
                self.assertFalse(GATE.inspect_native_route(text)["direct_route_proven"])

    def test_llvm_objdump_spelling_is_the_same_route(self) -> None:
        llvm = (self.DISASSEMBLY.replace("mov    $0x27,%eax", "movl\t$0x27, %eax")
                .replace("mov    $0x1,%eax", "movl\t$0x1, %eax"))
        self.assertTrue(GATE.inspect_native_route(llvm)["direct_route_proven"])

    def test_absent_anchor_is_not_a_route(self) -> None:
        self.assertFalse(GATE.inspect_native_route("")["direct_route_proven"])


class FixtureVendorTests(unittest.TestCase):
    def test_checked_in_fixture_locks_form_one_consistent_closure(self) -> None:
        closure = GATE.fixture_lock_closure()
        self.assertIn("smol-2.0.2", closure)
        self.assertIn("bitflags-2.13.1", closure)
        self.assertFalse(any(name.startswith("crabc-") for name in closure))


class ArgumentTests(unittest.TestCase):
    def test_cohort_and_development_products_are_exclusive(self) -> None:
        base = ["run", "--provider-vendor", "p", "--dependency-vendor", "d", "--output", "o"]
        GATE.parse_arguments([*base, "--static-preparation", "s", "--dynamic-qualification", "q"])
        GATE.parse_arguments([*base, "--development-static-sysroot", "s", "--development-dynamic-sysroot", "q"])
        GATE.parse_arguments([*base, "--allocator-evidence", "native-shadow",
                              "--development-static-sysroot", "s", "--development-dynamic-sysroot", "q"])
        for extra in (["--static-preparation", "s"],
                      ["--allocator-evidence", "native-shadow", "--static-preparation", "s",
                       "--dynamic-qualification", "q"],
                      ["--static-preparation", "s", "--dynamic-qualification", "q", "--development-static-sysroot", "x"],
                      []):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), \
                    mock.patch("sys.stderr"):
                GATE.parse_arguments([*base, *extra])


class ReceiptReaderTests(unittest.TestCase):
    """The gate reader rejects every receipt that no longer proves the gate."""

    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        root = Path(self.temporary.name)
        self.evidence = root / "candidate.stdout"
        self.evidence.write_bytes(b"ok\n")
        self.cohort = {"request": {"static_preparation": "s.json", "dynamic_qualification": "q.json"},
                       "evidence": {"source": "x"}}
        self.record = {
            "schema": GATE.SCHEMA, "gate": GATE.GATE, "source_sha256": "a" * 64, "qualifying": True,
            "cohort": self.cohort, "passed": True, "unmet_conditions": [],
            "gates": {gate: {"lanes": {"lane": {"unmet": []}}} for gate in GATE.FROZEN_GATES},
            "unwind": {label: {"unmet": []} for label in GATE.UNWIND_PRODUCTS},
            "provider_regressions": {"lanes": {script: {"unmet": []} for script in GATE.PROVIDER_REGRESSIONS}},
            "retained_files": {str(self.evidence): GATE.sha256_file(self.evidence)},
        }
        self.receipt = root / "receipt.json"
        qualification = mock.MagicMock()
        qualification.source_digest.return_value = "a" * 64
        self.patches = [
            mock.patch.dict(sys.modules, {"owned_dynamic_qualification": qualification}),
            mock.patch.object(GATE, "cohort_products", side_effect=lambda *_: (copy.deepcopy(self.cohort), {})),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def validate(self, record: dict[str, object]) -> dict[str, object]:
        self.receipt.unlink(missing_ok=True)
        # The runner writes sorted keys; the reader must not depend on order.
        self.receipt.write_text(json.dumps(record, sort_keys=True))
        return GATE.validate_receipt(GATE.ROOT, self.receipt)

    def test_complete_current_receipt_is_read(self) -> None:
        self.assertTrue(self.validate(self.record)["passed"])

    def test_failure_modes_fail_closed(self) -> None:
        cases = {
            "development products": {"qualifying": False},
            "stale source": {"source_sha256": "b" * 64},
            "failed lane": {"gates": {**self.record["gates"],
                                      "lto": {"lanes": {"D": {"unmet": ["lto/D: build-failed"]}}}}},
            "missing frozen gate": {"gates": {gate: self.record["gates"][gate] for gate in GATE.FROZEN_GATES[:-1]}},
            "extracted unwind omitted": {"unwind": {"primary": {"unmet": []}}},
            "failed unwind": {"unwind": {"primary": {"unmet": []}, "extracted": {"unmet": ["cleanup"]}}},
            "no retained evidence": {"retained_files": {}},
            "failed provider regression": {"provider_regressions": {"lanes": {
                script: {"unmet": ["exit 1"] if script == "frame_bounds.py" else []}
                for script in GATE.PROVIDER_REGRESSIONS}}},
        }
        for description, change in cases.items():
            with self.subTest(description), self.assertRaises(GATE.GateError):
                self.validate({**self.record, **change})

    def test_failed_receipt_names_its_unmet_conditions(self) -> None:
        failed = {**self.record, "passed": False, "unmet_conditions": ["lto/D: build-failed"]}
        with self.assertRaisesRegex(GATE.GateError, "did not pass: lto/D: build-failed"):
            self.validate(failed)

    def test_changed_retained_bytes_or_cohort_fail_closed(self) -> None:
        self.evidence.write_bytes(b"changed\n")
        with self.assertRaisesRegex(GATE.GateError, "evidence changed"):
            self.validate(self.record)
        self.evidence.write_bytes(b"ok\n")
        with mock.patch.object(GATE, "cohort_products", return_value=({"request": {}, "evidence": {}}, {})):
            with self.assertRaisesRegex(GATE.GateError, "cohort changed"):
                self.validate(self.record)


if __name__ == "__main__":
    unittest.main()
