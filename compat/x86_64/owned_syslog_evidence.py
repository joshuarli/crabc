#!/usr/bin/env python3
"""Bind the owned-syslog witness's one installed-header workload object.

The runner owns orchestration.  This small helper owns the two durable records
which let later receipt audits distinguish the exact translated object from a
lookalike: the installed dynamic driver's source-translation/header trace and
the object binding shared by every static and dynamic link receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


sys.dont_write_bytecode = True

WORKLOAD_BINDING_FORMAT = "crabc-x86-64-owned-syslog-workload-binding-v1"
HEADER_TRANSLATION_FORMAT = "crabc-x86-64-owned-syslog-header-translation-v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class WorkloadBindingError(RuntimeError):
    """A one-object syslog evidence record is malformed or changed."""


def _fail(message: str) -> None:
    raise WorkloadBindingError(message)


def _regular(path: Path, description: str) -> Path:
    try:
        if path.is_symlink() or not path.is_file():
            _fail(f"owned syslog {description} is missing or unsafe: {path}")
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise WorkloadBindingError(
            f"owned syslog {description} is missing or unsafe: {path}"
        ) from error


def _directory(path: Path, description: str) -> Path:
    try:
        if path.is_symlink() or not path.is_dir():
            _fail(f"owned syslog {description} is missing or unsafe: {path}")
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise WorkloadBindingError(
            f"owned syslog {description} is missing or unsafe: {path}"
        ) from error


def _executable_identity(path: Path, description: str) -> Path:
    """Resolve the fixed-image compiler spelling to its physical executable."""

    try:
        physical = path.resolve(strict=True)
        if not physical.is_file() or not os.access(physical, os.X_OK):
            _fail(f"owned syslog {description} is missing or unsafe: {path}")
        return physical
    except (OSError, RuntimeError) as error:
        raise WorkloadBindingError(
            f"owned syslog {description} is missing or unsafe: {path}"
        ) from error


def sha256_file(path: Path) -> str:
    """Return a physical regular artifact's SHA-256 identity."""

    physical = _regular(Path(path), "evidence artifact")
    digest = hashlib.sha256()
    try:
        with physical.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise WorkloadBindingError(
            f"owned syslog cannot hash evidence artifact: {path}"
        ) from error
    return digest.hexdigest()


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_object(path: Path, description: str) -> dict[str, Any]:
    physical = _regular(path, description)
    try:
        value = json.loads(
            physical.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object
        )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise WorkloadBindingError(
            f"owned syslog {description} is not valid JSON: {path}"
        ) from error
    if type(value) is not dict:
        _fail(f"owned syslog {description} must be a JSON object")
    return value


def _same_json_value(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's ``True == 1`` coercion."""

    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _same_json_value(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _same_json_value(actual, expected)
            for actual, expected in zip(left, right)
        )
    return left == right


def _artifact(path: Path, description: str) -> dict[str, str]:
    physical = _regular(path, description)
    return {"path": str(physical), "sha256": sha256_file(physical)}


def _expected_identity(path: Path, workload: Path) -> dict[str, Any]:
    value = _json_object(path, "link identity")
    expected_keys = {
        "linkage",
        "product",
        "product_format",
        "product_manifest_sha256",
        "workload_sha256",
        "executable_sha256",
        "receipt_sha256",
    }
    if set(value) != expected_keys:
        _fail("owned syslog link identity drifted")
    for key in ("linkage", "product", "product_format"):
        if type(value[key]) is not str or not value[key]:
            _fail("owned syslog link identity drifted")
    if value["linkage"] not in {"static", "static-pie", "pie", "non-pie"}:
        _fail("owned syslog link identity drifted")
    for key in (
        "product_manifest_sha256",
        "workload_sha256",
        "executable_sha256",
        "receipt_sha256",
    ):
        if type(value[key]) is not str or SHA256.fullmatch(value[key]) is None:
            _fail("owned syslog link identity drifted")
    if sha256_file(workload) != value["workload_sha256"]:
        _fail("owned syslog receipt names another workload object")
    return value


def _new_json(path: Path, value: dict[str, Any], description: str) -> None:
    if path.exists() or path.is_symlink():
        _fail(f"owned syslog {description} already exists or is unsafe: {path}")
    _directory(path.parent, f"{description} parent")
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except OSError as error:
        raise WorkloadBindingError(
            f"owned syslog cannot write {description}: {path}"
        ) from error


def _installed_compiler_contract(installed: Path) -> tuple[Any, Path, Path]:
    """Load the exact helper imported by installed ``crabc-cc-dynamic``."""

    driver = _regular(installed / "bin/crabc-cc-dynamic", "installed dynamic driver")
    helper = _regular(
        installed / "share/crabc/crabc_cc_static.py", "installed compiler contract"
    )
    source = driver.read_text(encoding="utf-8")
    fragments = (
        "import crabc_cc_static as shared",
        'run([shared.compiler(), "-nostdinc", "-isystem", str(root / "usr/include"),',
        '"-ffreestanding", "-fno-builtin", "-fstack-protector-strong",',
        '*invocation.compiler_flags, "-fPIC" if mode == "shared" else "-fPIE" if mode == "pie" else "-fno-pie",',
    )
    if not all(fragment in source for fragment in fragments):
        _fail("owned syslog installed dynamic compiler composition drifted")
    specification = importlib.util.spec_from_file_location(
        "owned_syslog_installed_compiler_contract", helper
    )
    if specification is None or specification.loader is None:
        _fail("owned syslog cannot load installed compiler contract")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    try:
        specification.loader.exec_module(module)
    except (ImportError, OSError, RuntimeError) as error:
        raise WorkloadBindingError(
            "owned syslog cannot load installed compiler contract"
        ) from error
    return module, driver, helper


def capture_installed_header_translation(
    installed: Path,
    source: Path,
    workload: Path,
    header_trace: Path,
    translation_record: Path,
) -> None:
    """Record the installed driver's exact PIE translation composition.

    ``crabc-cc-dynamic`` imports the installed static helper and composes its
    source command from that helper's fixed compiler and clean environment.
    The witness imports that same installed helper rather than assuming a host
    spelling such as ``/usr/bin/gcc``.  It records the prospective compile
    command and the header-trace command, along with both installed sources.
    """

    installed_root = _directory(Path(installed), "installed dynamic product")
    source_path = _regular(Path(source), "workload source")
    workload_path = Path(workload).absolute()
    if workload_path.exists() or workload_path.is_symlink():
        _fail(f"owned syslog workload output already exists or is unsafe: {workload}")
    _directory(workload_path.parent, "workload output parent")
    contract, driver, helper = _installed_compiler_contract(installed_root)
    try:
        selected_compiler = contract.compiler()
        environment = contract.clean_environment()
    except (AttributeError, OSError, RuntimeError) as error:
        raise WorkloadBindingError(
            "owned syslog installed compiler contract is incomplete"
        ) from error
    if type(selected_compiler) is not str or not selected_compiler:
        _fail("owned syslog installed compiler contract selected no compiler")
    if type(environment) is not dict or not all(
        type(key) is str and type(value) is str for key, value in environment.items()
    ):
        _fail("owned syslog installed compiler environment drifted")
    compiler = _executable_identity(Path(selected_compiler), "installed compiler")
    caller_flags = ["-std=c11", "-fno-builtin", "-fno-stack-protector"]
    prefix = [
        selected_compiler,
        "-nostdinc",
        "-isystem",
        str(installed_root / "usr/include"),
        "-ffreestanding",
        "-fno-builtin",
        "-fstack-protector-strong",
        *caller_flags,
        "-fPIE",
    ]
    translation_command = [
        *prefix,
        "-c",
        str(source_path),
        "-o",
        str(workload_path),
    ]
    trace_command = [*prefix, "-E", "-H", str(source_path)]
    working_directory = str(Path.cwd().resolve())
    if header_trace.exists() or header_trace.is_symlink():
        _fail(f"owned syslog header trace already exists or is unsafe: {header_trace}")
    _directory(header_trace.parent, "header trace parent")
    try:
        with header_trace.open("x", encoding="utf-8", newline="\n") as stream:
            completed = subprocess.run(
                trace_command,
                cwd=working_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stream,
                text=True,
                check=False,
            )
    except OSError as error:
        raise WorkloadBindingError("owned syslog installed compiler could not start") from error
    if completed.returncode != 0:
        _fail("owned syslog installed header translation failed")
    record = {
        "schema": 1,
        "format": HEADER_TRANSLATION_FORMAT,
        "source_translation_command": translation_command,
        "header_trace_command": trace_command,
        "working_directory": working_directory,
        "environment": environment,
        "compiler": {
            "selected_path": selected_compiler,
            "resolved_path": str(compiler),
            "sha256": sha256_file(compiler),
        },
        "dynamic_driver": _artifact(driver, "installed dynamic driver"),
        "compiler_contract": _artifact(helper, "installed compiler contract"),
        "header_trace": _artifact(header_trace, "header trace"),
    }
    _new_json(Path(translation_record), record, "header translation record")


def bind_workload_object(
    source: Path,
    workload: Path,
    initial_source_sha256: str,
    identity_path: Path,
    binding_path: Path,
    relocation_report: Path,
    translation_record: Path,
) -> None:
    """Write or type-strictly revalidate the one-object receipt binding."""

    source_path = _regular(Path(source), "workload source")
    workload_path = _regular(Path(workload), "workload object")
    if type(initial_source_sha256) is not str or SHA256.fullmatch(initial_source_sha256) is None:
        _fail("owned syslog initial workload source hash is invalid")
    if sha256_file(source_path) != initial_source_sha256:
        _fail("owned syslog workload source changed before binding")
    identity = _expected_identity(Path(identity_path), workload_path)
    record = {
        "schema": 1,
        "format": WORKLOAD_BINDING_FORMAT,
        "source": _artifact(source_path, "workload source"),
        "workload": _artifact(workload_path, "workload object"),
        "relocation_report": _artifact(
            Path(relocation_report), "workload relocation report"
        ),
        "header_translation": _artifact(
            Path(translation_record), "installed header translation record"
        ),
    }
    if record["source"]["sha256"] != initial_source_sha256:
        _fail("owned syslog workload source changed before binding")
    if record["workload"]["sha256"] != identity["workload_sha256"]:
        _fail("owned syslog receipt names another workload object")
    binding = Path(binding_path)
    if binding.exists() or binding.is_symlink():
        observed = _json_object(binding, "workload object binding")
        if not _same_json_value(observed, record):
            _fail("owned syslog workload object binding drifted")
    else:
        _new_json(binding, record, "workload object binding")
    if sha256_file(source_path) != initial_source_sha256:
        _fail("owned syslog workload object binding drifted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    header = commands.add_parser("capture-header-translation")
    header.add_argument("installed", type=Path)
    header.add_argument("source", type=Path)
    header.add_argument("workload", type=Path)
    header.add_argument("header_trace", type=Path)
    header.add_argument("translation_record", type=Path)
    bind = commands.add_parser("bind-workload")
    bind.add_argument("source", type=Path)
    bind.add_argument("workload", type=Path)
    bind.add_argument("initial_source_sha256")
    bind.add_argument("identity_path", type=Path)
    bind.add_argument("binding_path", type=Path)
    bind.add_argument("relocation_report", type=Path)
    bind.add_argument("translation_record", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "capture-header-translation":
            capture_installed_header_translation(
                arguments.installed,
                arguments.source,
                arguments.workload,
                arguments.header_trace,
                arguments.translation_record,
            )
        else:
            bind_workload_object(
                arguments.source,
                arguments.workload,
                arguments.initial_source_sha256,
                arguments.identity_path,
                arguments.binding_path,
                arguments.relocation_report,
                arguments.translation_record,
            )
    except WorkloadBindingError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
