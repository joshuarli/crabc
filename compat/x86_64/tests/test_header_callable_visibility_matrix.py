#!/usr/bin/env python3
"""Focused contracts for the x86 all-header callable visibility matrix."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "compat" / "x86_64" / "header_callable_visibility_matrix.py"
CHECKED_REPORT = (
    ROOT
    / "compat"
    / "x86_64"
    / "generated"
    / "header_callable_visibility_matrix"
    / "report.json"
)
CHECKED_INVENTORY = ROOT / "compat" / "x86_64" / "header_callable_inventory.json"
RUNNER = ROOT / "compat" / "x86_64" / "run_header_callable_visibility_matrix.sh"


# Musl's GNU/BSD direct <sys/types.h> tail imports these public endian/select
# callables.  A type-consuming root must request its own alltypes vocabulary,
# not inherit this convenience tail by including <sys/types.h>.
SYS_TYPES_GNU_BSD_TAIL_PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-bsd",
    "cxx17-strict",
)
SYS_TYPES_GNU_BSD_TAIL_CALLABLES = frozenset(
    {
        ("external", "pselect"),
        ("external", "select"),
        ("macro", "FD_CLR"),
        ("macro", "FD_ISSET"),
        ("macro", "FD_SET"),
        ("macro", "FD_ZERO"),
        ("macro", "be16toh"),
        ("macro", "be32toh"),
        ("macro", "be64toh"),
        ("macro", "betoh16"),
        ("macro", "betoh32"),
        ("macro", "betoh64"),
        ("macro", "htobe16"),
        ("macro", "htobe32"),
        ("macro", "htobe64"),
        ("macro", "htole16"),
        ("macro", "htole32"),
        ("macro", "htole64"),
        ("macro", "le16toh"),
        ("macro", "le32toh"),
        ("macro", "le64toh"),
        ("macro", "letoh16"),
        ("macro", "letoh32"),
        ("macro", "letoh64"),
    }
)
SYS_TYPES_GNU_BSD_NON_OWNER_ROOTS = frozenset(
    {
        "dirent.h",
        "fcntl.h",
        "mqueue.h",
        "spawn.h",
        "sys/ipc.h",
        "sys/msg.h",
        "sys/sem.h",
        "sys/shm.h",
        "sys/mman.h",
        "sys/timeb.h",
        "utime.h",
    }
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = load_module("header_callable_visibility_matrix_test", MATRIX_PATH)


class HeaderCallableVisibilityMatrixTests(unittest.TestCase):
    def test_checked_matrix_is_a_finite_callable_only_red_baseline(self) -> None:
        contract = MATRIX.load_contract()
        report = MATRIX.build_file_report(contract)
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))

        self.assertEqual(checked, report)
        self.assertEqual(contract.profiles, MATRIX.PROFILES)
        self.assertEqual(
            tuple(header.path for header in contract.project_only_headers),
            MATRIX.PROJECT_ONLY_PATHS,
        )
        self.assertEqual(tuple(contract.oracle_not_applicable), (("aio.h", "c11-strict"),))
        self.assertTrue(
            all(
                header.disposition == "retained-pending-c-abi-policy"
                and header.removal_requires_abi_decision
                for header in contract.project_only_headers
            )
        )
        self.assertEqual(
            report["summary"]["comparison_counts"],
            {
                "candidate-only-retained-pending-c-abi-policy": 56,
                "matched": 1110,
                "mismatch": 170,
                "oracle-not-applicable": 1,
            },
        )
        self.assertFalse(report["summary"]["complete"])
        self.assertFalse(report["scope"]["prototype_or_macro_replacement_equality"])
        self.assertFalse(report["scope"]["noncallable_abi"])
        self.assertFalse(report["scope"]["linkage_or_runtime"])
        aio_row = next(
            row
            for row in report["rows"]
            if row["header"] == "aio.h" and row["profile"] == "c11-strict"
        )
        self.assertEqual(aio_row["comparison"], "oracle-not-applicable")
        self.assertEqual(len(aio_row["candidate_visible"]), aio_row["candidate_callable_count"])
        self.assertTrue(aio_row["candidate_visible"])
        self.assertEqual(
            report["summary"]["oracle_not_applicable_candidate_visible_callable_count"],
            aio_row["candidate_callable_count"],
        )
        stdatomic_cxx_rows = [
            row
            for row in report["rows"]
            if row["header"] == "stdatomic.h" and row["profile"].startswith("cxx17")
        ]
        self.assertEqual(len(stdatomic_cxx_rows), 2)
        self.assertTrue(all(row["candidate_callable_count"] == 0 for row in stdatomic_cxx_rows))
        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "header_callable_inventory.py",
            "header_callable_visibility_matrix.py",
            "--check",
            "checked finite report",
        ):
            self.assertIn(phrase, runner)

    def test_unistd_and_sendfile_keep_the_exact_musl_callable_surface(self) -> None:
        """The process/file ownership repair cannot leave callable leakage."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )
        for header in ("unistd.h", "sys/sendfile.h"):
            for profile in profiles:
                row = rows[(header, profile)]
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(row["comparison"], "matched")
                self.assertEqual(row["candidate_only"], [])
                self.assertEqual(row["reference_only"], [])
                self.assertEqual(
                    row["candidate_callable_count"],
                    row["reference_callable_count"],
                )
                self.assertEqual(
                    row["matched_callable_count"],
                    row["candidate_callable_count"],
                )

    def test_build_report_uses_direct_consumer_visibility_and_keeps_red_rows_explicit(self) -> None:
        contract = MATRIX.MatrixContract(
            inventory=ROOT / "compat" / "x86_64" / "header_callable_inventory.json",
            public_headers=ROOT / "compat" / "x86_64" / "public_headers.txt",
            generated_report=ROOT / "compat" / "x86_64" / "generated" / "header_callable_visibility_matrix" / "report.json",
            profiles=("c11-gnu",),
            oracle_not_applicable={
                ("beta.h", "c11-gnu"): "synthetic pinned-oracle limitation",
            },
            project_only_headers=(
                MATRIX.ProjectOnlyHeader(
                    path="extension.h",
                    disposition="retained-pending-c-abi-policy",
                    declared_symbols=("extension_only",),
                ),
            ),
        )
        inventory = {
            "schema": MATRIX.INVENTORY_SCHEMA,
            "profiles": [{"id": "c11-gnu"}],
            "profile_runs": [
                {"tree": "candidate", "header": "alpha.h", "profile": "c11-gnu", "status": "ok"},
                {"tree": "candidate", "header": "beta.h", "profile": "c11-gnu", "status": "ok"},
                {"tree": "candidate", "header": "extension.h", "profile": "c11-gnu", "status": "ok"},
                {"tree": "reference", "header": "alpha.h", "profile": "c11-gnu", "status": "ok"},
                {"tree": "reference", "header": "beta.h", "profile": "c11-gnu", "status": "oracle-not-applicable"},
            ],
            "callables": [
                {
                    "tree": "candidate",
                    "profile": "c11-gnu",
                    "classification": "external",
                    "name": "common",
                    "declaring_header": "bits/internal.h",
                    "visible_from_headers": ["alpha.h"],
                },
                {
                    "tree": "candidate",
                    "profile": "c11-gnu",
                    "classification": "macro",
                    "name": "candidate_only",
                    "visible_from_headers": ["alpha.h"],
                },
                {
                    "tree": "candidate",
                    "profile": "c11-gnu",
                    "classification": "external",
                    "name": "candidate_visible_only",
                    "visible_from_headers": ["beta.h"],
                },
                {
                    "tree": "reference",
                    "profile": "c11-gnu",
                    "classification": "external",
                    "name": "common",
                    "visible_from_headers": ["alpha.h"],
                },
                {
                    "tree": "reference",
                    "profile": "c11-gnu",
                    "classification": "inline",
                    "name": "reference_only",
                    "visible_from_headers": ["alpha.h"],
                },
                {
                    "tree": "candidate",
                    "profile": "c11-gnu",
                    "classification": "inline",
                    "name": "extension_only",
                    "visible_from_headers": ["extension.h"],
                },
            ],
        }

        report = MATRIX.build_report(
            contract=contract,
            inventory=inventory,
            pinned_headers=("alpha.h", "beta.h"),
            candidate_headers=("alpha.h", "beta.h", "extension.h"),
            input_digests={
                "callable_inventory_sha256": "inventory",
                "matrix_contract_sha256": "contract",
                "public_header_inventory_sha256": "headers",
            },
        )

        rows = {(row["header"], row["profile"]): row for row in report["rows"]}
        self.assertEqual(rows[("alpha.h", "c11-gnu")]["comparison"], "mismatch")
        self.assertEqual(
            rows[("alpha.h", "c11-gnu")]["candidate_only"],
            [{"classification": "macro", "name": "candidate_only"}],
        )
        self.assertEqual(
            rows[("alpha.h", "c11-gnu")]["reference_only"],
            [{"classification": "inline", "name": "reference_only"}],
        )
        self.assertEqual(rows[("beta.h", "c11-gnu")]["comparison"], "oracle-not-applicable")
        self.assertEqual(
            rows[("beta.h", "c11-gnu")]["candidate_visible"],
            [{"classification": "external", "name": "candidate_visible_only"}],
        )
        self.assertEqual(
            rows[("extension.h", "c11-gnu")]["comparison"],
            "candidate-only-retained-pending-c-abi-policy",
        )
        self.assertEqual(report["summary"]["row_count"], 3)
        self.assertEqual(report["summary"]["comparable_row_count"], 1)
        self.assertEqual(report["summary"]["candidate_only_callable_count"], 1)
        self.assertEqual(
            report["summary"]["oracle_not_applicable_candidate_visible_callable_count"], 1
        )
        self.assertFalse(report["summary"]["complete"])

        stale_inventory = json.loads(json.dumps(inventory))
        stale_inventory["profile_runs"][-1]["status"] = "ok"
        with self.assertRaisesRegex(MATRIX.MatrixError, "oracle exception roster is stale"):
            MATRIX.build_report(
                contract=contract,
                inventory=stale_inventory,
                pinned_headers=("alpha.h", "beta.h"),
                candidate_headers=("alpha.h", "beta.h", "extension.h"),
                input_digests={
                    "callable_inventory_sha256": "inventory",
                    "matrix_contract_sha256": "contract",
                    "public_header_inventory_sha256": "headers",
                },
            )

        stale_metadata_contract = replace(
            contract,
            project_only_headers=(
                replace(contract.project_only_headers[0], declared_symbols=("missing_symbol",)),
            ),
        )
        with self.assertRaisesRegex(MATRIX.MatrixError, "declared symbols are absent"):
            MATRIX.build_report(
                contract=stale_metadata_contract,
                inventory=inventory,
                pinned_headers=("alpha.h", "beta.h"),
                candidate_headers=("alpha.h", "beta.h", "extension.h"),
                input_digests={
                    "callable_inventory_sha256": "inventory",
                    "matrix_contract_sha256": "contract",
                    "public_header_inventory_sha256": "headers",
                },
            )

    def test_statx_has_no_remaining_gnu_callable_visibility_gap(self) -> None:
        report = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in report["rows"]
        }
        for header in ("sys/stat.h", "ftw.h"):
            for profile in ("c11-gnu", "cxx17-gnu", "cxx17-strict"):
                row = rows[(header, profile)]
                for field in ("candidate_only", "reference_only"):
                    self.assertNotIn(
                        {"classification": "external", "name": "statx"},
                        row[field],
                        f"{header}:{profile} retains a statx visibility gap",
                    )

    def test_sys_types_gnu_bsd_tail_stays_with_its_direct_owner(self) -> None:
        """The source-faithful types tail must not turn type consumers into umbrellas."""
        inventory = json.loads(CHECKED_INVENTORY.read_text(encoding="utf-8"))
        callables = inventory["callables"]
        assert isinstance(callables, list)

        for tree in ("candidate", "reference"):
            for profile in SYS_TYPES_GNU_BSD_TAIL_PROFILES:
                tail = {
                    (row["classification"], row["name"]): row
                    for row in callables
                    if row.get("tree") == tree
                    and row.get("profile") == profile
                    and (row.get("classification"), row.get("name"))
                    in SYS_TYPES_GNU_BSD_TAIL_CALLABLES
                    and "sys/types.h" in row.get("visible_from_headers", ())
                }
                self.assertEqual(
                    set(tail),
                    SYS_TYPES_GNU_BSD_TAIL_CALLABLES,
                    f"{tree}:{profile} no longer exposes the direct sys/types.h GNU/BSD tail",
                )
                for callable_id, row in tail.items():
                    leaked_roots = set(row["visible_from_headers"]) & SYS_TYPES_GNU_BSD_NON_OWNER_ROOTS
                    self.assertEqual(
                        leaked_roots,
                        set(),
                        f"{tree}:{profile}:{callable_id} leaked the sys/types.h tail into "
                        f"{sorted(leaked_roots)}",
                    )


if __name__ == "__main__":
    unittest.main()
