"""Shared fail-closed preconditions for ordered x86 qualification cases."""

from __future__ import annotations

from pathlib import Path
import sys
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import qualification_case as case


def ledger_report(open_families: set[str]) -> dict[str, object]:
    """Return campaign family rows from the real ledger graph with chosen states."""

    with (ROOT / "compat/x86_64/parity.toml").open("rb") as stream:
        families = tomllib.load(stream)["family"]
    return {"families": [
        {
            "id": family["id"],
            "dependencies": list(family["depends_on"]),
            "status": "planned" if family["id"] in open_families else "foundation-verified",
        }
        for family in families
    ]}


class QualificationCaseTests(unittest.TestCase):
    def test_transitive_prerequisites_are_named_in_dependency_order(self) -> None:
        # compat.loader-corpus reaches libc.pthread-tls only through
        # ldso.dynamic-runtime, so a transitive blocker must still be named.
        report = ledger_report({"libc.pthread-tls", "compat.abi-differential", "sysroot.owned-artifact"})
        self.assertEqual(
            case.unverified_prerequisites(report, "compat.loader-corpus"),
            ["libc.pthread-tls", "sysroot.owned-artifact", "compat.abi-differential"],
        )
        self.assertEqual(case.unverified_prerequisites(ledger_report(set()), "compat.loader-corpus"), [])

    def test_the_gate_family_itself_is_not_its_own_prerequisite(self) -> None:
        report = ledger_report({"compat.loader-corpus"})
        self.assertEqual(case.unverified_prerequisites(report, "compat.loader-corpus"), [])
        self.assertEqual(case.unverified_prerequisites(report, "consumer.source-build"), ["compat.loader-corpus"])

    def test_unknown_family_and_malformed_rows_fail_closed(self) -> None:
        with self.assertRaisesRegex(case.QualificationCaseError, "no compat.unknown family"):
            case.unverified_prerequisites(ledger_report(set()), "compat.unknown")
        with self.assertRaisesRegex(case.QualificationCaseError, "dependencies are invalid"):
            case.unverified_prerequisites({"families": [{"id": "x", "status": "planned"}]}, "x")

    def test_open_prerequisites_are_reported_with_the_gate_family(self) -> None:
        report = ledger_report({"ldso.dynamic-runtime"})
        with mock.patch.object(case.CAMPAIGN, "build_report", return_value=report):
            with self.assertRaisesRegex(
                case.QualificationCaseError,
                r"^compat.loader-corpus prerequisites are not foundation-verified: ldso.dynamic-runtime$",
            ):
                case.require_prerequisites_closed("compat.loader-corpus")
        with mock.patch.object(case.CAMPAIGN, "build_report", return_value=ledger_report(set())):
            case.require_prerequisites_closed("compat.loader-corpus")

    def test_dirty_source_is_a_case_error(self) -> None:
        with mock.patch.object(
            case.PRODUCT, "require_clean_source",
            side_effect=case.PRODUCT.QualificationError("qualification publication requires clean source"),
        ), mock.patch.object(case.PRODUCT, "source_digest", side_effect=AssertionError("digest before clean check")):
            with self.assertRaisesRegex(case.QualificationCaseError, "clean source"):
                case.clean_source_identity()


if __name__ == "__main__":
    unittest.main()
