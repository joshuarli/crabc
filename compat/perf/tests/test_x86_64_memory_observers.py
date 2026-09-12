#!/usr/bin/env python3
"""Validate the closed source-local legacy memory-observer contract."""

from __future__ import annotations

import ast
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/perf/run.py"
PROFILE = ROOT / "compat/perf/x86_64-profile.toml"
PROTOCOL = ROOT / "compat/perf/x86_64_memory_observer_protocol.h"
PROFILE_PHASE_CATEGORIES = {
    "before and after original main; dependencies and constructor/main state remain live": "startup",
    "after final successful selected call with calling frame live": "clock",
    "before final close with the real descriptor open": "open",
    "after final verified round trip and before descriptor close": "fd",
    "before final fclose with the real FILE, buffer, and caller frame live": "stdio",
    "final worker callback result is ready while its real exit/TLS/TSD remain held": (
        "pthread_create_join_tls"
    ),
    "counter verified while the initialized mutex remains live before destruction": "mutex_uncontended",
    "final protected counter is complete while worker exit, mutex, and condition remain live": (
        "mutex_cond_ping_pong"
    ),
    "parent after each of eight loads, then worker after all TLS instances are checked before exit and dlclose": (
        "tls_growth"
    ),
    "loops complete with exactly their original touched static arrays retained": "scalar",
    "before first munmap with exactly the original touched mappings retained; search rows do not prefault an unused destination": (
        "span"
    ),
    "after original touch and before final free with exactly one allocation live": "allocator",
    "final lookup result is checked before dlclose": "dlsym",
    "result 31 is checked before handle closure": "graph",
}


def runner_rows() -> list[str]:
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "WORKLOADS" for target in node.targets)
    )
    assert isinstance(assignment.value, ast.Tuple)
    rows: list[str] = []
    for element in assignment.value.elts:
        assert isinstance(element, ast.Call)
        assert element.args and isinstance(element.args[0], ast.Constant)
        assert isinstance(element.args[0].value, str)
        rows.append(element.args[0].value)
    return rows


def contract_rows() -> list[tuple[str, str, str]]:
    text = PROTOCOL.read_text(encoding="utf-8")
    return re.findall(
        r"^    X\(([a-z0-9_]+), (workload|constructor|graph), ([a-z0-9_]+)\)(?: \\)?$",
        text,
        flags=re.MULTILINE,
    )


class MemoryObserverContractTests(unittest.TestCase):
    def test_exact_74_runner_rows_have_one_native_observer_family(self) -> None:
        expected = runner_rows()
        actual = contract_rows()

        self.assertEqual(len(expected), 74)
        self.assertEqual(len(actual), 74)
        self.assertEqual([row for row, _source, _category in actual], expected)
        self.assertEqual(len({row for row, _source, _category in actual}), 74)
        sources = {row: source for row, source, _category in actual}
        self.assertEqual(sources["startup"], "workload")
        self.assertEqual(sources["startup_constructor_destructor"], "constructor")
        self.assertEqual(sources["startup_dependency_graph"], "graph")
        self.assertTrue(
            all(source == "workload" for row, source in sources.items()
                if row not in {"startup_constructor_destructor", "startup_dependency_graph"})
        )

    def test_profile_legacy_mapping_and_native_contract_cover_the_same_rows(self) -> None:
        with PROFILE.open("rb") as stream:
            profile = tomllib.load(stream)
        profile_rows = [
            row
            for phase in profile["legacy_memory_phase"]
            for row in phase["rows"]
        ]
        roster_rows = [row for row, _source, _category in contract_rows()]

        self.assertEqual(profile["legacy_memory_phase_count"], 74)
        self.assertEqual(len(profile_rows), 74)
        self.assertEqual(len(set(profile_rows)), 74)
        self.assertEqual(set(profile_rows), set(roster_rows))
        self.assertEqual(set(profile_rows), set(runner_rows()))

        expected_categories = {
            row: PROFILE_PHASE_CATEGORIES[phase["checkpoint"]]
            for phase in profile["legacy_memory_phase"]
            for row in phase["rows"]
        }
        actual_categories = {row: category for row, _source, category in contract_rows()}
        self.assertEqual(actual_categories, expected_categories)

    def test_protocol_is_strict(self) -> None:
        text = PROTOCOL.read_text(encoding="utf-8")
        self.assertIn('CRABC_PERF_MEMORY_OBSERVER_PROTOCOL "crabc.perf.observer-r-c/v1"', text)
        self.assertIn("CRABC_PERF_MEMORY_OBSERVER_READY_FD 97", text)
        self.assertIn("CRABC_PERF_MEMORY_OBSERVER_CONTINUE_FD 98", text)
        self.assertIn('strcmp(ready, "97") != 0', text)
        self.assertIn('strcmp(continued, "98") != 0', text)
        self.assertIn("errno = saved_errno;", text)
        self.assertIn("CRABC_PERF_MEMORY_MAIN_INITIAL", text)
        self.assertIn("CRABC_PERF_MEMORY_MAIN_FINAL", text)

if __name__ == "__main__":
    unittest.main()
