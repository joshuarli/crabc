#!/usr/bin/env python3
"""Fail-closed preconditions shared by ordered x86 qualification cases.

A pinned qualification case runs only on clean committed source, and only
after every family its gate depends on, directly or transitively, is
`foundation-verified` in the validated campaign report. Callers check both
before starting any build or execution and recheck the source afterwards, so
a case result is never bound to a different revision or content digest.
"""

from __future__ import annotations

from typing import Any, Mapping

import campaign_report as CAMPAIGN
import owned_dynamic_qualification as PRODUCT


class QualificationCaseError(RuntimeError):
    """A qualification case precondition is unmet."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationCaseError(message)


def clean_source_identity() -> dict[str, str]:
    """Return the committed revision and live source digest of a clean checkout."""

    try:
        revision = PRODUCT.require_clean_source()
        source = PRODUCT.source_digest()
    except PRODUCT.QualificationError as error:
        raise QualificationCaseError(str(error)) from error
    return {"revision": revision, "source_sha256": source}


def unverified_prerequisites(report: Mapping[str, Any], family: str) -> list[str]:
    """Return `family`'s transitive prerequisites that are not yet verified."""

    rows = report.get("families")
    require(isinstance(rows, list), "campaign report has no family rows")
    families: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        require(isinstance(row, Mapping) and isinstance(row.get("id"), str), "campaign family row is invalid")
        dependencies = row.get("dependencies")
        require(isinstance(dependencies, list), f"campaign family {row['id']} dependencies are invalid")
        families[row["id"]] = {"status": row.get("status"), "depends_on": dependencies}
    require(family in families, f"campaign report has no {family} family")
    try:
        prerequisites = CAMPAIGN.transitive_dependencies(family, families)
    except CAMPAIGN.CampaignReportError as error:
        raise QualificationCaseError(str(error)) from error
    return [
        prerequisite for prerequisite in prerequisites
        if families[prerequisite]["status"] != CAMPAIGN.COMPLETED_STATUS
    ]


def require_prerequisites_closed(family: str) -> None:
    """Refuse a case while any family prerequisite remains open."""

    try:
        report = CAMPAIGN.build_report()
    except CAMPAIGN.CampaignReportError as error:
        raise QualificationCaseError(f"campaign report is invalid: {error}") from error
    blockers = unverified_prerequisites(report, family)
    require(not blockers, f"{family} prerequisites are not foundation-verified: {', '.join(blockers)}")
