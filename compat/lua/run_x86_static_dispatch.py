#!/usr/bin/env python3
"""Invoke one isolated native x86 Lua static source-build qualification."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

# Qualification cases run with PYTHONSAFEPATH=1, which omits this script's
# directory from sys.path; name it so sibling imports still resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as LUA  # noqa: E402


SUPPLIED_ROOTS = ("primary", "reproduction", "extracted")


def supplied_products(args: argparse.Namespace, state: Path) -> tuple[dict, dict, dict]:
    """Bind each independent static root to the originating preparation reader."""
    checkout = LUA.require_physical_directory(args.cohort_checkout.absolute(), "Lua static cohort checkout")
    receipt = LUA.require_physical_regular_file(args.static_preparation.absolute(), "Lua static preparation")
    try:
        receipt.relative_to(checkout / ".work")
        payload = json.loads(receipt.read_text())
    except (ValueError, OSError) as error:
        raise LUA.RunnerError("Lua static preparation is outside its cohort or invalid") from error
    if not isinstance(payload, dict) or set(payload.get("products", {})) != set(SUPPLIED_ROOTS):
        raise LUA.RunnerError("Lua static preparation has an incomplete product roster")
    roots = {}
    identities = set()
    for label, selected in zip(SUPPLIED_ROOTS, (args.installed_sysroot, args.rebuilt_sysroot, args.extracted_sysroot)):
        root = LUA.require_physical_directory(selected.absolute(), f"Lua static {label} root")
        record = payload["products"][label]
        if not isinstance(record, dict):
            raise LUA.RunnerError("Lua static preparation has an invalid product record")
        relative = Path(record.get("path", ""))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != ".work":
            raise LUA.RunnerError("Lua static preparation has an invalid product path")
        if root != checkout / relative:
            raise LUA.RunnerError(f"Lua static {label} root differs from preparation")
        identity = (root.stat().st_dev, root.stat().st_ino)
        if identity in identities:
            raise LUA.RunnerError("Lua static supplied roots must be physically independent")
        identities.add(identity)
        LUA.owned_static_sysroot(root)
        roots[label] = root
    reader = LUA.require_physical_regular_file(
        checkout / "compat/x86_64/owned_posix_static_products.py", "Lua static cohort reader")
    environment = LUA.static_environment(state / "cohort-reader")
    environment.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory",
                        "GIT_CONFIG_VALUE_0": str(checkout)})
    validation = LUA.command_record([sys.executable, "-B", str(reader), "validate", str(receipt)],
                                    cwd=checkout, environment=environment, timeout=args.timeout)
    LUA.require_success(validation, "Lua supplied static preparation reader")
    return payload, roots, validation


def run_supplied(args: argparse.Namespace) -> tuple[dict, Path]:
    """Run the unchanged complete static Lua workloads through all supplied roots."""
    LUA.disable_core_dump_inheritance()
    state = LUA.allocate_x86_static_dispatch_state(args.work_root)
    report_path = state / "report.json"
    report = {"schema_version": 2, "runner": "crabc-lua-native-x86-static-source-build",
              "passed": False, "result": "fail", "supplied": {"state_root": str(state)}, "products": {}}
    try:
        status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                                cwd=LUA.ROOT, check=True, capture_output=True).stdout
        if status:
            raise LUA.RunnerError("Lua static consumer source is not clean")
        source = LUA.current_source_identity()
        report["consumer_source"] = source
        payload, roots, validation = supplied_products(args, state)
        report["supplied"].update({"preparation": LUA.artifact_record(args.static_preparation),
                                  "source": payload["source"], "validation_before": validation})
        manifest = LUA.load_manifest(LUA.MANIFEST)
        seed = LUA.require_physical_regular_file(args.archive_seed, "Lua static archive seed")
        if LUA.sha256_file(seed) != manifest["lua"]["sha256"]:
            raise LUA.RunnerError("Lua static archive seed differs from pin")
        for label, root in roots.items():
            work = state / label
            work.mkdir()
            cache = LUA.native_source_cache(work)
            shutil.copyfile(seed, LUA.source_archive_path(manifest, cache))
            inner = argparse.Namespace(manifest=LUA.MANIFEST, sysroot=root, target="x86_64-static",
                                       mode=None, work_root=work, jobs=args.jobs, report=work / "report.json",
                                       offline=True, timeout=args.timeout)
            lane = LUA.run_x86_static(inner)
            LUA.write_json_atomic(inner.report, lane)
            report["products"][label] = lane
        after, _roots, validation_after = supplied_products(args, state)
        report["supplied"]["validation_after"] = validation_after
        if payload != after or LUA.current_source_identity() != source:
            raise LUA.RunnerError("Lua static source or preparation changed during execution")
        report["passed"] = all(report["products"][label].get("passed") is True for label in SUPPLIED_ROOTS)
        report["result"] = "pass" if report["passed"] else "fail"
    except (LUA.RunnerError, OSError, ValueError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
    LUA.write_json_atomic(report_path, report)
    return report, report_path



def read_supplied(args: argparse.Namespace) -> tuple[dict, Path]:
    """Recheck retained reports and optionally replay their complete workloads."""
    import source_build_admission as admission

    selected = LUA.require_physical_regular_file(args.read, "Lua supplied static report")
    report = json.loads(selected.read_text())
    if (report.get("passed") is not True or report.get("result") != "pass"
            or set(report.get("products", {})) != set(SUPPLIED_ROOTS)):
        raise LUA.RunnerError("Lua supplied static report has not passed all three products")
    if report.get("consumer_source") != LUA.current_source_identity():
        raise LUA.RunnerError("Lua supplied static report uses stale consumer source")
    state = LUA.allocate_x86_static_dispatch_state(args.work_root)
    payload, roots, validation = supplied_products(args, state)
    if (report["supplied"].get("source") != payload["source"]
            or report["supplied"].get("preparation") != LUA.artifact_record(args.static_preparation)):
        raise LUA.RunnerError("Lua supplied static report uses a different cohort")
    admission.validate_report_records(report)
    replay = {"passed": True, "validation": validation, "products": {}}
    for label in SUPPLIED_ROOTS:
        lane = report["products"][label]
        admission.validate_pinned_input(lane)
        if (lane.get("passed") is not True or set(lane.get("modes", {})) != {"static-et-exec", "static-pie"}
                or lane["environment"]["sysroot_manifest"] != LUA.owned_static_sysroot(roots[label])[3]
                or lane["environment"]["sysroot"] != str(roots[label])):
            raise LUA.RunnerError("Lua supplied static product or mode roster differs")
        for mode in LUA.selected_static_modes(None):
            row = lane["modes"][mode.identifier]
            for role in ("candidate", "reference"):
                for name in ("lua", "luac"):
                    recorded = row[role]["artifacts"][name]
                    artifact = LUA.require_physical_regular_file(Path(recorded["artifact"]["path"]), "retained Lua tool")
                    selected_mode = mode if role == "candidate" else LUA.static_reference_mode()
                    if LUA.static_elf_record(artifact, selected_mode, f"retained {role} {name}") != recorded:
                        raise LUA.RunnerError("Lua retained tool ELF evidence differs")
            for name in ("source", "bytecode"):
                admission.validate_result_comparison(row["workloads"][name])
            if args.replay:
                work = state / label / mode.identifier
                work.mkdir(parents=True)
                paths = {role: {name: Path(row[role]["artifacts"][name]["artifact"]["path"])
                                for name in ("lua", "luac")} for role in ("candidate", "reference")}
                support = Path(lane["work_directory"]) / "source" / lane["manifest"]["contents"]["lua"]["archive_root"] / "src"
                workloads = LUA.run_static_workloads(paths["candidate"], paths["reference"], support,
                                                    work, args.timeout)
                if any(workloads[name]["candidate"] != row["workloads"][name]["candidate"]
                       or workloads[name]["reference"] != row["workloads"][name]["reference"]
                       for name in ("source", "bytecode")):
                    raise LUA.RunnerError("Lua retained workload replay differs from its original observations")
                replay["products"].setdefault(label, {})[mode.identifier] = workloads
    LUA.write_json_atomic(state / "report.json", replay)
    return report, selected


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=LUA.DEFAULT_JOBS)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--allocator-backend", choices=LUA.X86_ALLOCATOR_BACKENDS, default="accepted-c",
                        help="sysroot allocator backend; native-shadow runs never publish the latest report")
    parser.add_argument("--cohort-checkout", type=Path)
    parser.add_argument("--static-preparation", type=Path)
    parser.add_argument("--installed-sysroot", type=Path)
    parser.add_argument("--rebuilt-sysroot", type=Path)
    parser.add_argument("--extracted-sysroot", type=Path)
    parser.add_argument("--archive-seed", type=Path)
    parser.add_argument("--work-root", type=Path, default=LUA.DEFAULT_X86_STATIC_WORK_ROOT.with_name("lua-static-supplied"))
    parser.add_argument("--read", type=Path, help="recheck a retained supplied-mode report")
    parser.add_argument("--replay", action="store_true", help="also execute all retained source and bytecode workloads")
    args = parser.parse_args(argv)
    supplied = (args.cohort_checkout, args.static_preparation, args.installed_sysroot,
                args.rebuilt_sysroot, args.extracted_sysroot, args.archive_seed)
    if any(value is not None for value in supplied) and not all(value is not None for value in supplied):
        parser.error("supplied mode requires cohort checkout, preparation, all three roots and archive seed")
    if args.read is not None and args.cohort_checkout is None:
        parser.error("--read requires the complete supplied cohort arguments")
    if args.replay and args.read is None:
        parser.error("--replay requires --read")
    if args.cohort_checkout is not None and args.allocator_backend != "accepted-c":
        parser.error("supplied mode authenticates its allocator from the preparation")
    if args.jobs < 1 or args.jobs > LUA.MAX_JOBS:
        parser.error(f"--jobs must be an integer from 1 through {LUA.MAX_JOBS}")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be > 0 and <= 300")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.cohort_checkout is not None:
            report, report_path = read_supplied(args) if args.read is not None else run_supplied(args)
            latest = None
        elif args.allocator_backend == "accepted-c":
            report, report_path, latest = LUA.run_x86_static_dispatch(jobs=args.jobs, timeout=args.timeout)
        else:
            report, report_path, latest = LUA.run_x86_static_dispatch(
                jobs=args.jobs, timeout=args.timeout, allocator_backend=args.allocator_backend,
                state_parent=LUA.DEFAULT_X86_STATIC_WORK_ROOT.with_name(
                    f"{LUA.DEFAULT_X86_STATIC_WORK_ROOT.name}-{args.allocator_backend}"),
                latest_report=None,
            )
    except (LUA.RunnerError, OSError, ValueError) as error:
        print(f"x86 Lua static source-build dispatcher failed: {error}", file=sys.stderr)
        return 1
    result = {
        "state_root": str(report_path.parent),
        "report": str(report_path),
        "latest_report": str(latest) if latest is not None else None,
        "passed": report.get("passed") is True,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
