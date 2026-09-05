#!/usr/bin/env python3
"""Materialize/package/extract the owned x86 resolver-network products before isolation.

This preparation step is intentionally separate from ``run_x86_64.py``.  The
pinned product builders may need the pinned Cargo registry state, while the
resolver differential must execute with Docker's network namespace set to
``none``.  The dispatcher invokes this script in its ordinary pinned container
and passes the resulting installed and extracted exact directories to the
isolated runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
WORK_BOUNDARY = ROOT / ".work/x86_64"
STATIC_BUILDER = ROOT / "scripts/build_x86_64_owned_sysroot.py"
DYNAMIC_BUILDER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"
STATIC_PACKAGE = ROOT / "compat/x86_64/owned_static_sysroot_package.py"
DYNAMIC_PACKAGE = ROOT / "compat/x86_64/owned_dynamic_package.py"


class PreparationError(RuntimeError):
    """The exact pre-isolation owned products could not be materialized."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stream_record(value: bytes) -> dict[str, object]:
    return {
        "byte_length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "text": value.decode("utf-8", errors="replace"),
    }


def artifact_record(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise PreparationError(f"required regular artifact is absent or unsafe: {path}")
    return {"path": str(path), "sha256": sha256_file(path), "byte_length": path.stat().st_size}


def physical_directory(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise PreparationError(f"{description} is absent or unsafe: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise PreparationError(f"cannot resolve {description}: {path}") from error


def physical_regular(path: Path, description: str) -> Path:
    # Builders are passed to the pinned Python interpreter, so executable mode
    # is not part of their authority boundary.
    if path.is_symlink() or not path.is_file():
        raise PreparationError(f"{description} is absent or unsafe: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise PreparationError(f"cannot resolve {description}: {path}") from error


def prepare_root(path: Path) -> Path:
    """Create one fresh state root below the shared native x86 work boundary."""

    boundary = WORK_BOUNDARY.resolve(strict=True)
    candidate = path if path.is_absolute() else ROOT / path
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(boundary)
    except (OSError, ValueError) as error:
        raise PreparationError(f"resolver-network preparation root must stay below {boundary}") from error
    if resolved.exists() or resolved.is_symlink():
        raise PreparationError(f"resolver-network preparation root must be fresh: {resolved}")
    resolved.mkdir(parents=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise PreparationError(f"resolver-network preparation root is unsafe: {resolved}")
    return resolved.resolve(strict=True)


def command_record(arguments: Sequence[str], *, timeout: float) -> dict[str, object]:
    try:
        result = subprocess.run(
            list(arguments), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        return {"argv": list(arguments), "status": "TIMEOUT", "stdout": stream_record(stdout), "stderr": stream_record(stderr)}
    except OSError as error:
        return {"argv": list(arguments), "status": f"EXEC_ERROR:{error.errno or 'unknown'}", "stdout": stream_record(b""), "stderr": stream_record(str(error).encode("utf-8"))}
    return {"argv": list(arguments), "status": result.returncode, "stdout": stream_record(result.stdout), "stderr": stream_record(result.stderr)}


def write_report(path: Path, report: Mapping[str, object]) -> None:
    with tempfile.NamedTemporaryFile(prefix=".prepare-", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    try:
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="fresh directory below .work/x86_64")
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 1800:
        parser.error("--timeout must be > 0 and <= 1800")
    return args


def run(args: argparse.Namespace) -> tuple[dict[str, object], Path]:
    state = prepare_root(args.output)
    report_path = state / "prepare.json"
    static = state / "static-sysroot"
    dynamic = state / "dynamic-sysroot"
    static_package_one = state / "static-one.tar.xz"
    static_package_two = state / "static-two.tar.xz"
    dynamic_package_one = state / "dynamic-one.tar"
    dynamic_package_two = state / "dynamic-two.tar"
    static_extraction = state / "static-extraction"
    static_extracted = static_extraction / "crabc-x86_64-owned-static-sysroot"
    dynamic_extracted = state / "dynamic-extraction"
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "crabc-resolver-network-native-x86-prepare",
        "result": "fail",
        "prepared_products": {
            "static": str(static), "dynamic": str(dynamic),
            "extracted_static": str(static_extracted), "extracted_dynamic": str(dynamic_extracted),
        },
        "steps": {},
    }
    try:
        static_builder = physical_regular(STATIC_BUILDER, "owned static sysroot builder")
        dynamic_builder = physical_regular(DYNAMIC_BUILDER, "owned dynamic sysroot builder")
        static_package = physical_regular(STATIC_PACKAGE, "owned static package tool")
        dynamic_package = physical_regular(DYNAMIC_PACKAGE, "owned dynamic package tool")
        for label, command, destination, kind in (
            ("static-build", [sys.executable, "-B", str(static_builder), "--output", str(static)], static, "directory"),
            ("dynamic-build", [sys.executable, "-B", str(dynamic_builder), "--output", str(dynamic)], dynamic, "directory"),
            ("static-package-one", [sys.executable, "-B", str(static_package), "create", "--source", str(static), "--archive", str(static_package_one)], static_package_one, "file"),
            ("static-package-two", [sys.executable, "-B", str(static_package), "create", "--source", str(static), "--archive", str(static_package_two)], static_package_two, "file"),
            ("dynamic-package-one", [sys.executable, "-B", str(dynamic_package), "package", str(dynamic), str(dynamic_package_one)], dynamic_package_one, "file"),
            ("dynamic-package-two", [sys.executable, "-B", str(dynamic_package), "package", str(dynamic), str(dynamic_package_two)], dynamic_package_two, "file"),
            ("static-extract", [sys.executable, "-B", str(static_package), "extract", "--archive", str(static_package_one), "--destination", str(static_extraction)], static_extracted, "directory"),
            ("dynamic-extract", [sys.executable, "-B", str(dynamic_package), "extract", str(dynamic_package_one), str(dynamic_extracted)], dynamic_extracted, "directory"),
        ):
            record = command_record(command, timeout=args.timeout)
            report["steps"][label] = record
            if record["status"] != 0:
                raise PreparationError(f"owned resolver-network {label} failed: {record['status']}")
            if kind == "directory":
                physical_directory(destination, f"owned resolver-network {label} output")
            else:
                artifact_record(destination)
        static_packages = (artifact_record(static_package_one), artifact_record(static_package_two))
        dynamic_packages = (artifact_record(dynamic_package_one), artifact_record(dynamic_package_two))
        if static_packages[0]["sha256"] != static_packages[1]["sha256"]:
            raise PreparationError("two static package operations produced different archive bytes")
        if dynamic_packages[0]["sha256"] != dynamic_packages[1]["sha256"]:
            raise PreparationError("two dynamic package operations produced different archive bytes")
        report["packages"] = {
            "static": {"one": static_packages[0], "two": static_packages[1], "byte_identical": True},
            "dynamic": {"one": dynamic_packages[0], "two": dynamic_packages[1], "byte_identical": True},
        }
        report["result"] = "pass"
    except PreparationError as error:
        report["error"] = str(error)
    write_report(report_path, report)
    return report, report_path


def main(argv: Sequence[str] | None = None) -> int:
    try:
        report, report_path = run(parse_args(argv))
    except PreparationError as error:
        print(f"native resolver-network preparation: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"state_root": str(report_path.parent), "report": str(report_path), **report["prepared_products"], "passed": report["result"] == "pass"}, sort_keys=True))
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
