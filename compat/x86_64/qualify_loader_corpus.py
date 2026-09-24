#!/usr/bin/env python3
"""Run the frozen loader/corpus roster as the `compat.loader-corpus` case.

The ordered qualification manifest names this file as the gate's only case.
It reproduces the frozen AArch64 `ldso`, `loader-inventory`, and `corpus`
gates on native x86-64 through one qualified three-product dynamic cohort:

* the cohort is the reviewed publication of
  `./scripts/dev-x86_64.sh materialized-dynamic-sysroot` for this exact clean
  revision (two clean builds and the package-extracted product). Its receipt
  already executed the 21 frozen synthetic loader workloads and the 34 frozen
  Alpine package workloads on each product, among its other cases;
* this case collects a fresh loader ELF inventory for each cohort product;
* the loader-family collector then joins the cohort and inventories, checks
  the complete synthetic and package catalogs and every retained case tree,
  and this case replays that receipt.

The case never builds or publishes a product. It fails closed before any
work unless the checkout is clean committed source, every transitive family
prerequisite of `compat.loader-corpus` is `foundation-verified`, and a
current cohort publication exists. It also refuses a changed frozen roster,
then rechecks the clean source afterwards. Its stdout marker is
non-promoting: qualification receipts, not this case, bind the final chain.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Sequence

# Qualification cases run with PYTHONSAFEPATH=1, which omits this script's
# directory from sys.path; name it so sibling imports still resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import owned_dynamic_qualification as PRODUCT  # noqa: E402
import owned_loader_corpus_evidence as CORPUS  # noqa: E402
import owned_loader_family as LOADER_FAMILY  # noqa: E402
import owned_loader_inventory as INVENTORY  # noqa: E402
import qualification_case as CASE  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FAMILY = "compat.loader-corpus"
PASS_MARKER = "x86 compat.loader-corpus loader/corpus roster: PASS (non-promoting)"
WORK_PARENT = ROOT / ".work/x86_64/loader-corpus-qualification"
FROZEN_BASELINE = ROOT / "compat/x86_64/aarch64_frozen_baseline.json"
CORPUS_WORKLOADS = "compat/corpus/manifest.toml"
MUSL_ROOT = Path("/opt/musl-1.2.6")
READELF = Path("/usr/bin/readelf")
# The frozen AArch64 `ldso` gate's `--case` choices, in its order
# (`compat/ldso/run.py` at the frozen baseline commit).
FROZEN_SYNTHETIC_CASES = (
    "nested-needed", "nested-dlopen", "search-path", "dso-origin",
    "initial-tls", "dlerror", "hash-formats", "hash-many", "relro",
    "auxv", "legacy-lifecycle", "lookup-scope", "visibility",
    "constructor-order", "main-handle", "lifecycle", "preload", "aslr",
    "dynamic-tls", "relocations", "weak-strong",
)
FROZEN_CORPUS_CASE_COUNT = 34


def require(condition: bool, message: str) -> None:
    CASE.require(condition, message)


def git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-c", f"safe.directory={ROOT}", *arguments], cwd=ROOT, check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ).stdout.strip()


def frozen_commit() -> str:
    commit = json.loads(FROZEN_BASELINE.read_text(encoding="utf-8")).get("source_commit")
    require(isinstance(commit, str) and len(commit) == 40, "frozen baseline has no source commit")
    return commit


def require_frozen_rosters() -> dict[str, object]:
    """Refuse a synthetic or package roster that is not the frozen one."""

    try:
        rows = {row["id"]: row for row in LOADER_FAMILY.load_roster()["required"]}
    except (LOADER_FAMILY.LoaderFamilyError, CORPUS.LoaderCorpusEvidenceError) as error:
        raise CASE.QualificationCaseError(f"loader/corpus roster is invalid: {error}") from error
    synthetic = tuple(rows["synthetic-loader-catalog"]["synthetic_cases"])
    corpus = tuple(rows["frozen-package-corpus"]["package_cases"])
    require(synthetic == FROZEN_SYNTHETIC_CASES, "synthetic loader roster differs from the frozen ldso gate")
    require(len(corpus) == FROZEN_CORPUS_CASE_COUNT, "package corpus roster differs from the frozen 34 workloads")
    commit = frozen_commit()
    observed = git("hash-object", "--", CORPUS_WORKLOADS)
    require(
        observed == git("rev-parse", f"{commit}:{CORPUS_WORKLOADS}"),
        f"{CORPUS_WORKLOADS} differs from the frozen baseline commit {commit}",
    )
    return {"synthetic_cases": len(synthetic), "package_cases": len(corpus),
            "corpus_workloads_blob": observed, "frozen_commit": commit}


def published_cohort() -> Path:
    """Return the current reviewed three-product cohort's qualification.json."""

    receipt = PRODUCT.load_publication()
    require(
        receipt is not None,
        "no current qualified dynamic cohort: run ./scripts/dev-x86_64.sh materialized-dynamic-sysroot "
        f"on this clean revision and publish its reviewed qualification.json to {PRODUCT.PUBLICATION}",
    )
    path = PRODUCT.evidence_path(ROOT / str(receipt["work"]) / "qualification.json")
    require(set(receipt["products"]) == set(LOADER_FAMILY.PRODUCTS), "published cohort product roster differs")
    return path


def collect_inventories(run: Path, cohort: Path) -> dict[str, dict[str, str]]:
    """Collect one fresh loader inventory per cohort product."""

    selections: dict[str, dict[str, str]] = {}
    for product in LOADER_FAMILY.PRODUCTS:
        directory = run / "inventories" / product
        directory.mkdir(parents=True)
        output = directory / "inventory.json"
        INVENTORY.collect(cohort.parent / product, MUSL_ROOT, output, READELF)
        inputs = directory / "inventory.json.inputs"
        selections[product] = {
            "receipt": output.relative_to(ROOT).as_posix(),
            "oracle_capture": (inputs / "oracle-capture.json").relative_to(ROOT).as_posix(),
            "readelf_capture": (inputs / "readelf-capture.json").relative_to(ROOT).as_posix(),
        }
    return selections


def allocate_run() -> Path:
    WORK_PARENT.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=WORK_PARENT))
    require(run.resolve() == run and not run.is_symlink(), "loader/corpus case work is not physical")
    return run


def qualify() -> dict[str, Any]:
    source = CASE.clean_source_identity()
    CASE.require_prerequisites_closed(FAMILY)
    rosters = require_frozen_rosters()
    cohort = published_cohort()
    run = allocate_run()
    request = {
        "schema": LOADER_FAMILY.SCHEMA,
        "qualification": cohort.relative_to(ROOT).as_posix(),
        "inventories": collect_inventories(run, cohort),
    }
    (run / "request.json").write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt = LOADER_FAMILY.execute(ROOT, run)
    LOADER_FAMILY.validate_receipt(ROOT, receipt)
    require(CASE.clean_source_identity() == source, "source changed during the loader/corpus qualification case")
    return {
        "family": FAMILY,
        "source_identity": source,
        "rosters": rosters,
        "cohort": request["qualification"],
        "loader_family_receipt": receipt.relative_to(ROOT).as_posix(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    # Source sealing reads Git state; never let it take an optional index lock.
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        summary = qualify()
    except (
        CASE.QualificationCaseError,
        PRODUCT.QualificationError,
        INVENTORY.InventoryError,
        LOADER_FAMILY.LoaderFamilyError,
        CORPUS.LoaderCorpusEvidenceError,
        subprocess.CalledProcessError,
        tarfile.TarError,
        OSError,
        ValueError,
    ) as error:
        print(f"x86 compat.loader-corpus loader/corpus roster: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
