#!/usr/bin/env python3
"""Run the frozen Lua roster as the `consumer.source-build` qualification case.

With no arguments this case authenticates the published current-source Lua
admission receipt. Explicit cohort arguments compile the pinned Lua consumers
against already prepared static/dynamic products. Neither route builds or
packages runtime products.
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
import run_x86_static_dispatch as STATIC
import run_x86_dynamic_supplied as SUPPLIED_DYNAMIC
import run_x86_dynamic as DYNAMIC  # noqa: E402
import source_build_admission as ADMISSION  # noqa: E402
import qualification_gates as GATES
import qualification_case as CASE  # noqa: E402
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


def require_lane(result: tuple[Mapping[str, Any], Path], lane: str) -> dict[str, str]:
    report, report_path = result
    require(
        report.get("passed") is True and report.get("result") == "pass",
        f"Lua {lane} lane did not pass; retained report: {report_path}",
    )
    return {"report": str(report_path)}


def require_current_products(args: argparse.Namespace, source: Mapping[str, str]) -> None:
    """Bind every supplied runtime root to this source and one release backend."""
    ADMISSION.require_current_supplied_products(
        [args.static_installed_sysroot, args.static_rebuilt_sysroot, args.static_extracted_sysroot],
        [args.dynamic_installed_sysroot, args.dynamic_extracted_sysroot], source,
    )


def qualify(args: argparse.Namespace) -> dict[str, object]:
    source = CASE.clean_source_identity()
    CASE.require_prerequisites_closed(FAMILY)
    if args.cohort_checkout is None:
        receipt = GATES.read_publication(FAMILY, "lua-source-build")
        admission = receipt["admission"]
        require(admission.get("source_identity") == source,
                "published Lua admission is bound to a different source than this case")
        require(CASE.clean_source_identity() == source, "source changed during the Lua qualification case")
        return {"family": FAMILY, "source_identity": source, "admission": admission}
    require_current_products(args, source)
    static = require_lane(
        STATIC.run_supplied(argparse.Namespace(
            cohort_checkout=args.cohort_checkout, static_preparation=args.static_preparation,
            installed_sysroot=args.static_installed_sysroot, rebuilt_sysroot=args.static_rebuilt_sysroot,
            extracted_sysroot=args.static_extracted_sysroot, archive_seed=args.archive_seed,
            work_root=args.work_root / "static", jobs=JOBS, timeout=COMMAND_TIMEOUT,
        )), "static"
    )
    dynamic = require_lane(
        SUPPLIED_DYNAMIC.run_supplied_dynamic(
            cohort_checkout=args.cohort_checkout, cohort_receipt=args.dynamic_cohort_receipt,
            installed_sysroot=args.dynamic_installed_sysroot, extracted_sysroot=args.dynamic_extracted_sysroot,
            archive_seed=args.archive_seed, state_parent=args.work_root / "dynamic",
            jobs=JOBS, timeout=COMMAND_TIMEOUT,
        ), "dynamic"
    )
    admission = ADMISSION.validate(static_report=Path(static["report"]), dynamic_report=Path(dynamic["report"]))
    require(
        admission.get("source_identity") == source,
        "Lua admission is bound to a different source than this case",
    )
    require(CASE.clean_source_identity() == source, "source changed during the Lua qualification case")
    return {
        "family": FAMILY,
        "source_identity": source,
        "static": static,
        "dynamic": dynamic,
        "admission": admission,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cohort_arguments = ("cohort-checkout", "static-preparation", "static-installed-sysroot",
                 "static-rebuilt-sysroot", "static-extracted-sysroot", "dynamic-cohort-receipt",
                 "dynamic-installed-sysroot", "dynamic-extracted-sysroot", "archive-seed")
    for name in cohort_arguments:
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--work-root", type=Path, default=LUA.ROOT / ".work/x86_64/lua-source-build-supplied")
    args = parser.parse_args(argv)
    selected = [getattr(args, name.replace("-", "_")) for name in cohort_arguments]
    if any(value is not None for value in selected) and not all(value is not None for value in selected):
        parser.error("explicit production requires the complete supplied cohort arguments")
    # Source sealing reads Git state; never let it take an optional index lock.
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        summary = qualify(args)
    except (LUA.RunnerError, CASE.QualificationCaseError, PRODUCT.QualificationError,
            GATES.GateError, GATES.EvidenceUnmet, OSError, ValueError) as error:
        print(f"x86 consumer.source-build Lua roster: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
