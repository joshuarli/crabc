#!/usr/bin/env python3
"""Shared table-driven dispatch assertions for leaf header-abi tests."""

from __future__ import annotations

from pathlib import Path


def header_abi_cases(root: Path) -> dict[str, str]:
    cases: dict[str, str] = {}
    table = root / "compat" / "x86_64" / "header_abi_cases.txt"
    for line in table.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        case, runner = line.split("\t")
        if case in cases:
            raise AssertionError(f"duplicate header-abi case: {case}")
        cases[case] = runner
    return cases


def assert_header_abi_dispatches(
    test: object, root: Path, case: str, runner: str
) -> None:
    cases = header_abi_cases(root)
    test.assertEqual(cases.get(case), runner)
    dispatcher = (root / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    test.assertIn("    header-abi)", dispatcher)
    test.assertIn('"$ROOT_DIR/compat/x86_64/header_abi_cases.txt"', dispatcher)
    test.assertIn(
        'run_in_container bash "/workspace/compat/x86_64/$header_abi_runner"',
        dispatcher,
    )
