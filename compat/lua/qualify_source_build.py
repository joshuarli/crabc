#!/usr/bin/env python3
"""Run the frozen Lua roster as the `consumer.source-build` qualification case.

The ordered qualification manifest names this file as the gate's only case.
It reproduces the frozen AArch64 `lua` source-build gate on native x86-64:
static ET_EXEC and static-PIE programs through the installed static driver,
then the dynamic `liblua`/`lua`/`luac`/C-module graph through both the
installed and the package-extracted dynamic sysroot, each compared with a
fresh pinned-musl 1.2.6 source build. The existing admission reader then binds
both physical reports to one source identity.

The case fails closed before it builds anything unless the checkout is clean
committed source and every transitive family prerequisite of
`consumer.source-build` is `foundation-verified` in the validated campaign
report. It rechecks the clean source afterwards. Its stdout marker is
non-promoting: qualification receipts, not this case, bind the final chain.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

# Qualification cases run with PYTHONSAFEPATH=1, which deliberately omits the
# script directory from the import path. Name both owning directories here.
LUA_DIRECTORY = Path(__file__).resolve().parent
X86_DIRECTORY = LUA_DIRECTORY.parents[1] / "compat/x86_64"
for directory in (X86_DIRECTORY, LUA_DIRECTORY):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import run as LUA  # noqa: E402
import run_x86_dynamic as DYNAMIC  # noqa: E402
import source_build_admission as ADMISSION  # noqa: E402
import campaign_report as CAMPAIGN  # noqa: E402
import owned_dynamic_qualification as PRODUCT  # noqa: E402

FAMILY = "consumer.source-build"
PASS_MARKER = "x86 consumer.source-build Lua roster: PASS (non-promoting)"
JOBS = LUA.DEFAULT_JOBS
# The widest per-command bound both Lua dispatchers accept. It bounds hung
# producers and workloads; it is not a performance measurement.
COMMAND_TIMEOUT = 300.0


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LUA.RunnerError(message)


def clean_source_identity() -> dict[str, str]:
    """Return the Lua lanes' source identity only for clean committed source."""

    revision = PRODUCT.require_clean_source()
    identity = LUA.current_source_identity()
    require(identity.get("revision") == revision, "source revision changed while sealing the case")
    return identity


def prerequisite_blockers(report: Mapping[str, Any]) -> list[str]:
    """Return transitive family prerequisites that are not yet verified."""

    rows = report.get("families")
    require(isinstance(rows, list), "campaign report has no family rows")
    families: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        require(isinstance(row, Mapping) and isinstance(row.get("id"), str), "campaign family row is invalid")
        dependencies = row.get("dependencies")
        require(isinstance(dependencies, list), f"campaign family {row['id']} dependencies are invalid")
        families[row["id"]] = {"status": row.get("status"), "depends_on": dependencies}
    require(FAMILY in families, f"campaign report has no {FAMILY} family")
    try:
        prerequisites = CAMPAIGN.transitive_dependencies(FAMILY, families)
    except CAMPAIGN.CampaignReportError as error:
        raise LUA.RunnerError(str(error)) from error
    return [
        family for family in prerequisites
        if families[family]["status"] != CAMPAIGN.COMPLETED_STATUS
    ]


def require_prerequisites_closed() -> None:
    try:
        report = CAMPAIGN.build_report()
    except CAMPAIGN.CampaignReportError as error:
        raise LUA.RunnerError(f"campaign report is invalid: {error}") from error
    blockers = prerequisite_blockers(report)
    require(
        not blockers,
        f"{FAMILY} prerequisites are not foundation-verified: {', '.join(blockers)}",
    )


def require_lane(result: tuple[Mapping[str, Any], Path, Path | None], lane: str) -> dict[str, str]:
    report, report_path, latest = result
    require(
        report.get("passed") is True and report.get("result") == "pass" and latest is not None,
        f"Lua {lane} lane did not pass; retained report: {report_path}",
    )
    return {"report": str(report_path), "latest_report": str(latest)}


def qualify() -> dict[str, object]:
    source = clean_source_identity()
    require_prerequisites_closed()
    static = require_lane(
        LUA.run_x86_static_dispatch(jobs=JOBS, timeout=COMMAND_TIMEOUT), "static"
    )
    dynamic = require_lane(
        DYNAMIC.run_dynamic_dispatch(jobs=JOBS, timeout=COMMAND_TIMEOUT, offline=False), "dynamic"
    )
    admission = ADMISSION.validate()
    require(
        admission.get("source_identity") == source,
        "Lua admission is bound to a different source than this case",
    )
    require(clean_source_identity() == source, "source changed during the Lua qualification case")
    return {
        "family": FAMILY,
        "source_identity": source,
        "static": static,
        "dynamic": dynamic,
        "admission": admission,
    }


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    # Source sealing reads Git state; never let it take an optional index lock.
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        summary = qualify()
    except (LUA.RunnerError, PRODUCT.QualificationError, OSError, ValueError) as error:
        print(f"x86 consumer.source-build Lua roster: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
