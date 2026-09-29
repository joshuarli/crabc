#!/usr/bin/env python3
"""Fail-closed checks for source-bound local primitive trace coverage."""

from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("m3_x86_64", ROOT / "compat/allocator/m3_x86_64.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


RETIREMENT_TRACE = """M3R start regular=ABC full= direct=A state=RRR bytes=0 pages=3
M3R retire-head regular=BC full= direct=B state=DRR bytes=0 pages=2
M3R reuse-tail regular=BCA full= direct=B state=RRR bytes=0 pages=3
M3R move-head regular=CBA full= direct=C state=RRR bytes=0 pages=3
M3R full-head regular=BA full=C direct=B state=RRF bytes=256 pages=3
M3R full-next regular=A full=CB direct=A state=RFF bytes=448 pages=3
M3R retire-last-regular regular= full=CB direct=- state=DFF bytes=448 pages=2
M3R reuse-from-full regular=C full=B direct=C state=DFR bytes=192 pages=2
M3R retire-full regular=C full= direct=C state=DDR bytes=0 pages=1
M3R retire-final regular= full= direct=- state=DDD bytes=0 pages=0
"""


class LocalPrimitiveTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = gate.load_contract()

    def read_trace(self, trace: str):
        with tempfile.TemporaryDirectory(prefix="m3-reader-", dir=ROOT / ".work") as directory:
            with mock.patch.object(gate, "ARTIFACT_ROOT", Path(directory)):
                with mock.patch.object(gate.run, "command_record", return_value={"status": 0, "stdout": trace, "stderr": ""}):
                    return gate.run_queue_retirement_differential(self.contract)

    def test_one_retirement_sequence_cannot_qualify_bin_and_free_list_parity(self) -> None:
        result = self.read_trace(RETIREMENT_TRACE)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("queue matrix did not execute bin" in item for item in result["unmet"]))
        self.assertTrue(any("free-list matrix did not execute every source mode" in item for item in result["unmet"]))

    def test_a_cache_snapshot_must_match_the_queue_and_unrelated_live_bin(self) -> None:
        trace = RETIREMENT_TRACE + (
            "M3B bin=4 size=32 seed=331572594510 step=0 action=init page=- regular= full= "
            f"direct={'A' * 129} state=DDD bytes=0 pages=1 sentinel=1\n"
        )
        result = self.read_trace(trace)
        self.assertTrue(any("owner/cache/transition invariant" in item for item in result["unmet"]))

    def test_a_free_list_cannot_own_an_allocated_block(self) -> None:
        trace = RETIREMENT_TRACE + "M3F size=32 stage=exhausted capacity=4 reserved=4 used=4 zero=0 free=0 local=-\n"
        result = self.read_trace(trace)
        self.assertTrue(any("initialized ownership/counts" in item for item in result["unmet"]))

    def test_green_local_checks_preserve_incomplete_prerequisites(self) -> None:
        checks = {check: {"status": "passed"} for component in self.contract["components"] for check in component["checks"]}
        checks["prerequisites"] = {"milestones": {}, "unmet": ["M1 and M2 receipts are absent"]}
        result = gate.evaluate_gate(self.contract, checks)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(all(component["status"] == "complete" for component in result["components"]))

    def test_a_failed_required_check_cannot_be_hidden_by_omitting_its_component(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["components"] = [component for component in contract["components"] if component["id"] != "miri-execution"]
        checks = {check: {"status": "passed"} for component in self.contract["components"] for check in component["checks"]}
        checks["miri"] = {"status": "failed", "unmet": ["undefined behaviour"]}
        checks["prerequisites"] = {"milestones": {}, "unmet": []}
        with self.assertRaisesRegex(gate.GateError, "required checks.*miri"):
            gate.evaluate_gate(contract, checks)


if __name__ == "__main__":
    unittest.main()
