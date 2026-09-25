#!/usr/bin/env python3
"""The structural source-convergence reader over synthetic and real manifests."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
import source_convergence as convergence  # noqa: E402


PIN = {"version": "3.5.0", "revision": "a" * 40}


def row(**changes: object) -> dict:
    value = {"upstream": "src/alloc.c", "name": "mi_malloc", "source_region": "mi_malloc", "rust_item": "malloc",
             "intentional_difference": "", "implemented": True, "unit_verified": True,
             "differential_verified": True, "stress_verified": False, "performance_qualified": True}
    value.update(changes)
    return value


def port_map(*rows: dict) -> dict:
    return {"metadata": {"upstream_version": "3.5.0", "upstream_revision": "a" * 40}, "item": list(rows)}


REGISTER = """# Register

### `CRABC-MI-ONE` — accepted boundary

text

## Entry requirements
"""


class SourceConvergenceTests(unittest.TestCase):
    def evaluate(self, manifest: dict, register: str = REGISTER, upstream: str = "a" * 40) -> dict:
        return {row["id"]: row for row in convergence.conditions(manifest, register, upstream, PIN)}

    def test_a_closed_carried_register_and_complete_port_map_converge(self) -> None:
        result = self.evaluate(port_map(row(intentional_difference="See CRABC-MI-ONE.")))
        self.assertTrue(all(value["met"] for value in result.values()), result)

    def test_names_unimplemented_partial_and_unverified_rows(self) -> None:
        result = self.evaluate(port_map(row(name="a", implemented=False, rust_item="unimplemented"),
                                        row(name="b", rust_item="partial: some", differential_verified=False),
                                        row(intentional_difference="CRABC-MI-ONE")))
        self.assertEqual(result["implemented"]["detail"], [
            "src/alloc.c:a lacks implemented", "src/alloc.c:b lacks differential_verified"])
        self.assertEqual(result["transitional"]["detail"], ["src/alloc.c:a is unimplemented", "src/alloc.c:b is partial"])

    def test_an_intentional_difference_needs_differential_and_performance_evidence(self) -> None:
        result = self.evaluate(port_map(row(intentional_difference="CRABC-MI-ONE", performance_qualified=False)))
        self.assertEqual(result["intentional-differences"]["detail"], [
            "src/alloc.c:mi_malloc states an intentional difference without performance_qualified"])

    def test_names_open_unidentified_and_uncarried_register_entries(self) -> None:
        register = REGISTER + "\n### `CRABC-MI-TWO` — observed red\n\n### A prose heading\n"
        result = self.evaluate(port_map(row()), register)
        self.assertEqual(result["known-differences"]["detail"], [
            "known-differences.md:3 accepted CRABC-MI-ONE is carried by no port-map row's evidence flags",
            "known-differences.md:9 CRABC-MI-TWO is 'observed', not accepted or rejected",
            "known-differences.md:11 entry 'A prose heading' has no stable identifier",
        ])

    def test_names_a_pin_mismatch(self) -> None:
        manifest = port_map(row(intentional_difference="CRABC-MI-ONE"))
        manifest["metadata"]["upstream_revision"] = "b" * 40
        result = self.evaluate(manifest, upstream="nothing")
        self.assertEqual(len(result["pin"]["detail"]), 2)

    def test_the_real_manifests_are_readable_and_currently_unconverged(self) -> None:
        result = {row["id"]: row for row in convergence.evaluate()}
        self.assertTrue(result["pin"]["met"])
        self.assertFalse(result["transitional"]["met"])


if __name__ == "__main__":
    unittest.main()
