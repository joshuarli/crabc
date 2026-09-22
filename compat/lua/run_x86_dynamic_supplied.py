#!/usr/bin/env python3
"""Consume a sealed owned dynamic cohort for Lua without rebuilding it.

This is a live source-consumer gate.  It verifies the originating cohort from
its own frozen checkout, then runs Lua against only the supplied installed and
extracted roots.  It neither creates a sysroot nor packages or extracts one,
and it never publishes a product or capability result.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping, Sequence

import run as LUA
import run_x86_dynamic as DYNAMIC


ROOT = LUA.ROOT
DEFAULT_WORK_ROOT = ROOT / ".work/x86_64/lua-dynamic-supplied"
SOURCE_INPUTS = (
    Path(__file__).resolve(),
    ROOT / "compat/lua/run.py",
    ROOT / "compat/lua/run_x86_dynamic.py",
    ROOT / "compat/lua/manifest.toml",
)
_NONPROMOTING = ("runtime_v1_published", "family_completion", "promotion_ready", "public_support")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LUA.RunnerError(message)


def consumer_source_seal() -> dict[str, object]:
    """Record this consumer's clean source independently of its product cohort."""

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise LUA.RunnerError("cannot seal supplied Lua consumer source") from error
    require(not status.stdout, "supplied Lua consumer source is not clean")
    commit = revision.stdout.strip()
    require(len(commit) == 40 and all(character in "0123456789abcdef" for character in commit),
            "supplied Lua consumer has an invalid revision")
    return {
        "revision": commit,
        "inputs": {
            path.relative_to(ROOT).as_posix(): LUA.artifact_record(
                LUA.require_physical_regular_file(path, "supplied Lua consumer source input")
            )
            for path in SOURCE_INPUTS
        },
    }


def _cohort_path(checkout: Path, path: Path, description: str, *, directory: bool = False) -> Path:
    checkout = LUA.require_physical_directory(Path(os.path.abspath(checkout)), "supplied Lua cohort checkout")
    path = Path(os.path.abspath(path))
    candidate = (
        LUA.require_physical_directory(path, description)
        if directory else LUA.require_physical_regular_file(path, description)
    )
    boundary = LUA.require_physical_directory(checkout / ".work", "supplied Lua cohort work root")
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise LUA.RunnerError(f"{description} is outside the cohort work root") from error
    return candidate


def _cohort_git_context(checkout: Path, state: Path) -> tuple[dict[str, str], dict[str, object]]:
    """Bind the frozen worktree reader to its mounted Git metadata.

    A linked worktree stores host-absolute paths in both of its Git pointer
    files.  The supplied consumer runs in a container where the primary
    checkout is mounted at a different absolute path, so invoking the frozen
    reader without an explicit worktree context makes its source seal fail
    before it reaches the retained receipt.  Derive the matching metadata
    beneath this consumer checkout's ``.git/worktrees`` directory, preserve
    the frozen pointer files, and let Git use that read-only context.
    """

    try:
        relative_checkout = checkout.relative_to(ROOT)
    except ValueError as error:
        raise LUA.RunnerError("supplied Lua cohort checkout is not beneath this checkout") from error
    require(
        len(relative_checkout.parts) == 3 and relative_checkout.parts[:2] == (".work", "worktrees"),
        "supplied Lua cohort checkout is not a linked worktree",
    )
    pointer = LUA.require_physical_regular_file(checkout / ".git", "supplied Lua cohort Git pointer")
    try:
        pointer_text = pointer.read_text(encoding="utf-8")
    except OSError as error:
        raise LUA.RunnerError("cannot read supplied Lua cohort Git pointer") from error
    require(pointer_text.startswith("gitdir: ") and pointer_text.count("\n") == 1,
            "supplied Lua cohort Git pointer is malformed")
    recorded_git_dir = Path(pointer_text.removeprefix("gitdir: ").strip())
    require(recorded_git_dir.is_absolute() and recorded_git_dir.parent.name == "worktrees",
            "supplied Lua cohort Git pointer is not a linked-worktree reference")
    name = recorded_git_dir.name
    require(name == relative_checkout.name and name not in {"", ".", ".."},
            "supplied Lua cohort Git pointer names a different worktree")
    metadata = LUA.require_physical_directory(
        ROOT / ".git/worktrees" / name, "supplied Lua cohort Git metadata"
    )
    metadata_pointer = LUA.require_physical_regular_file(
        metadata / "gitdir", "supplied Lua cohort Git metadata pointer"
    )
    try:
        metadata_text = metadata_pointer.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise LUA.RunnerError("cannot read supplied Lua cohort Git metadata pointer") from error
    expected_tail = (*relative_checkout.parts, ".git")
    require(
        tuple(Path(metadata_text).parts[-len(expected_tail):]) == expected_tail,
        "supplied Lua cohort Git metadata names a different checkout",
    )
    environment = DYNAMIC.dynamic_environment(state)
    environment.update({"GIT_DIR": str(metadata), "GIT_WORK_TREE": str(checkout)})
    return environment, {
        "git_dir": str(metadata),
        "git_work_tree": str(checkout),
        "worktree_pointer": LUA.artifact_record(pointer),
        "metadata_pointer": LUA.artifact_record(metadata_pointer),
    }


def _read_qualification_receipt(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LUA.RunnerError("supplied Lua cohort receipt is not JSON") from error
    require(isinstance(payload, dict), "supplied Lua cohort receipt is not an object")
    require(payload.get("status") == "qualified-pending-review", "supplied Lua cohort is not qualified-pending-review")
    products = payload.get("products")
    require(isinstance(products, dict) and set(products) == {"installed", "second", "extracted"},
            "supplied Lua cohort receipt has the wrong dynamic product roster")
    require(all(isinstance(value, str) and len(value) == 64 for value in products.values()),
            "supplied Lua cohort receipt has malformed manifest identities")
    source = payload.get("source_sha256")
    require(isinstance(source, str) and len(source) == 64, "supplied Lua cohort receipt lacks a source identity")
    for field in _NONPROMOTING:
        require(payload.get(field) is False, f"supplied Lua cohort changes non-promoting state: {field}")
    return payload


def _supplied_root_identity(root: Path, label: str, expected_manifest: str) -> dict[str, object]:
    root, wrapper, runtime, _manifest = DYNAMIC.owned_dynamic_sysroot(root)
    manifest = LUA.require_physical_regular_file(root / "share/crabc/manifest.json", f"supplied Lua {label} manifest")
    observed_manifest = LUA.sha256_file(manifest)
    require(observed_manifest == expected_manifest,
            f"supplied Lua {label} root does not match the cohort receipt")
    metadata = root.stat()
    return {
        "path": str(root),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "manifest": LUA.artifact_record(manifest),
        "compiler_wrapper": LUA.artifact_record(wrapper),
        "runtime": {
            name: LUA.artifact_record(path)
            for name, path in runtime.items() if name != "headers"
        },
        "headers": str(runtime["headers"]),
    }


def validate_cohort(
    *, checkout: Path, receipt: Path, installed: Path, extracted: Path, state: Path, timeout: float,
) -> tuple[dict[str, object], dict[str, object]]:
    """Replay the frozen cohort reader and bind two physical dynamic roots."""

    checkout = LUA.require_physical_directory(Path(os.path.abspath(checkout)), "supplied Lua cohort checkout")
    receipt = _cohort_path(checkout, receipt, "supplied Lua cohort receipt")
    installed = _cohort_path(checkout, installed, "supplied Lua installed root", directory=True)
    extracted = _cohort_path(checkout, extracted, "supplied Lua extracted root", directory=True)
    require((installed.stat().st_dev, installed.stat().st_ino) != (extracted.stat().st_dev, extracted.stat().st_ino),
            "supplied Lua installed and extracted roots must be distinct")
    reader = LUA.require_physical_regular_file(
        checkout / "compat/x86_64/owned_dynamic_qualification.py", "supplied Lua cohort receipt reader"
    )
    environment, git_context = _cohort_git_context(checkout, state / "cohort-reader")
    validation = LUA.command_record(
        [sys.executable, "-B", str(reader), "validate", "--receipt", str(receipt.relative_to(checkout))],
        cwd=checkout, environment=environment, timeout=timeout,
    )
    DYNAMIC.require_success(validation, "supplied Lua cohort receipt reader")
    payload = _read_qualification_receipt(receipt)
    products = payload["products"]
    assert isinstance(products, dict)
    roots = {
        "installed": _supplied_root_identity(installed, "installed", products["installed"]),
        "extracted": _supplied_root_identity(extracted, "extracted", products["extracted"]),
    }
    snapshot = {
        "checkout": str(checkout),
        "receipt": LUA.artifact_record(receipt),
        "reader": LUA.artifact_record(reader),
        "git_context": git_context,
        "source_sha256": payload["source_sha256"],
        "products": products,
        "roots": roots,
    }
    return snapshot, validation


def seed_archive(manifest: Mapping[str, object], seed: Path, state: Path) -> dict[str, object]:
    """Copy one authenticated Lua source archive into the private lane cache."""

    seed = LUA.require_physical_regular_file(seed, "supplied Lua pinned archive seed")
    lua = manifest.get("lua")
    require(isinstance(lua, Mapping) and isinstance(lua.get("sha256"), str),
            "supplied Lua manifest lacks an archive checksum")
    require(LUA.sha256_file(seed) == lua["sha256"], "supplied Lua archive seed hash differs from the manifest")
    cache = LUA.native_source_cache(state)
    destination = LUA.source_archive_path(manifest, cache)
    require(not os.path.lexists(destination), "supplied Lua private archive cache is unexpectedly occupied")
    shutil.copyfile(seed, destination)
    os.chmod(destination, 0o644)
    destination = LUA.require_physical_regular_file(destination, "supplied Lua private archive cache entry")
    require(LUA.sha256_file(destination) == lua["sha256"], "supplied Lua private archive cache drifted")
    return {
        "cache": str(cache),
        "seed": LUA.artifact_record(seed),
        "private_copy": LUA.artifact_record(destination),
    }


def run_supplied_dynamic(
    *, cohort_checkout: Path, cohort_receipt: Path, installed_sysroot: Path, extracted_sysroot: Path,
    archive_seed: Path, jobs: int, timeout: float, state_parent: Path = DEFAULT_WORK_ROOT,
) -> tuple[dict[str, object], Path]:
    """Run the two supplied dynamic Lua lanes and retain a private report."""

    require(1 <= jobs <= LUA.MAX_JOBS, f"supplied Lua jobs must be from 1 through {LUA.MAX_JOBS}")
    require(math.isfinite(timeout) and 0 < timeout <= 300,
            "supplied Lua timeout must be > 0 and <= 300")
    LUA.disable_core_dump_inheritance()
    state = LUA.allocate_x86_static_dispatch_state(state_parent)
    report_path = state / "report.json"
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "crabc-lua-native-x86-dynamic-supplied-cohort",
        "result": "fail",
        "passed": False,
        "dispatcher": {
            "state_root": str(state),
            "authoritative_report": str(report_path),
            "producer": "absent (supplied immutable cohort)",
            "package": "absent (supplied immutable cohort)",
            "extract": "absent (supplied immutable cohort)",
            "publication": "absent (live source-consumer gate only)",
        },
    }
    try:
        source_before = consumer_source_seal()
        report["consumer_source_before"] = source_before
        cohort_before, cohort_validation = validate_cohort(
            checkout=cohort_checkout, receipt=cohort_receipt, installed=installed_sysroot,
            extracted=extracted_sysroot, state=state, timeout=timeout,
        )
        report["dispatcher"]["cohort"] = cohort_before
        report["dispatcher"]["cohort_validation_before"] = cohort_validation
        manifest = LUA.load_manifest(LUA.MANIFEST)
        report["manifest"] = {
            "path": str(LUA.MANIFEST), "sha256": LUA.sha256_file(LUA.MANIFEST), "contents": manifest,
        }
        seeded = seed_archive(manifest, archive_seed, state)
        report["dispatcher"]["source_cache"] = seeded
        cache = Path(seeded["cache"])
        installed_lane = DYNAMIC.run_dynamic_lane(
            sysroot_path=installed_sysroot, work_root=state / "installed-runs", cache=cache,
            offline=True, jobs=jobs, timeout=timeout,
        )
        extracted_lane = DYNAMIC.run_dynamic_lane(
            sysroot_path=extracted_sysroot, work_root=state / "extracted-runs", cache=cache,
            offline=True, jobs=jobs, timeout=timeout,
        )
        report["installed"] = installed_lane
        report["extracted"] = extracted_lane
        installed_hashes = DYNAMIC.source_artifact_hashes(installed_lane)
        extracted_hashes = DYNAMIC.source_artifact_hashes(extracted_lane)
        report["reproducibility"] = {
            "status": "passed" if installed_hashes == extracted_hashes else "rejected",
            "installed_artifacts": installed_hashes,
            "extracted_artifacts": extracted_hashes,
            "contract": "identical Lua source artifacts through supplied installed and extracted dynamic roots",
        }
        cohort_after, cohort_validation_after = validate_cohort(
            checkout=cohort_checkout, receipt=cohort_receipt, installed=installed_sysroot,
            extracted=extracted_sysroot, state=state, timeout=timeout,
        )
        report["dispatcher"]["cohort_validation_after"] = cohort_validation_after
        require(cohort_before == cohort_after, "supplied Lua cohort changed during lane execution")
        source_after = consumer_source_seal()
        report["consumer_source_after"] = source_after
        require(source_before == source_after, "supplied Lua consumer source changed during lane execution")
        report["passed"] = (
            installed_lane.get("passed") is True
            and extracted_lane.get("passed") is True
            and installed_hashes == extracted_hashes
        )
        report["result"] = "pass" if report["passed"] else "fail"
    except LUA.RunnerError as error:
        report["error"] = str(error)
    LUA.write_json_atomic(report_path, report)
    return report, report_path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-checkout", type=Path, required=True)
    parser.add_argument("--cohort-receipt", type=Path, required=True)
    parser.add_argument("--installed-sysroot", type=Path, required=True)
    parser.add_argument("--extracted-sysroot", type=Path, required=True)
    parser.add_argument("--archive-seed", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--jobs", type=int, default=LUA.DEFAULT_JOBS)
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.jobs > LUA.MAX_JOBS:
        parser.error(f"--jobs must be an integer from 1 through {LUA.MAX_JOBS}")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be > 0 and <= 300")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, report_path = run_supplied_dynamic(
            cohort_checkout=args.cohort_checkout, cohort_receipt=args.cohort_receipt,
            installed_sysroot=args.installed_sysroot, extracted_sysroot=args.extracted_sysroot,
            archive_seed=args.archive_seed, jobs=args.jobs, timeout=args.timeout,
            state_parent=args.work_root,
        )
    except LUA.RunnerError as error:
        print(f"x86 supplied Lua dynamic source-build failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"state_root": str(report_path.parent), "report": str(report_path),
                      "passed": report.get("passed") is True}, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
