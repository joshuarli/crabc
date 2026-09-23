#!/usr/bin/env python3
"""Admit current native Lua static and dynamic source-build reports."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

import run as LUA
import run_x86_dynamic as DYNAMIC

ROOT = LUA.ROOT
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as QUALIFICATION

STATIC_REPORT = LUA.DEFAULT_X86_STATIC_REPORT
DYNAMIC_REPORT = DYNAMIC.DEFAULT_REPORT
WORK = ROOT / ".work/x86_64"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LUA.RunnerError(message)


def validate_stream(record: object, description: str) -> bytes:
    require(isinstance(record, Mapping), f"{description} stream record is invalid")
    try:
        data = bytes.fromhex(str(record.get("hex", "")))
    except ValueError as error:
        raise LUA.RunnerError(f"{description} stream hex is invalid") from error
    require(
        record.get("byte_length") == len(data)
        and record.get("sha256") == hashlib.sha256(data).hexdigest()
        and record.get("text") == data.decode("utf-8", errors="replace"),
        f"{description} stream raw bytes do not match their recorded identity",
    )
    return data


def validate_result_comparison(value: Mapping[str, Any]) -> None:
    reference = value.get("reference")
    candidate = value.get("candidate")
    require(isinstance(reference, Mapping) and isinstance(candidate, Mapping), "Lua workload comparison is incomplete")
    require(
        reference.get("status") == 0
        and candidate.get("status") == 0
        and reference.get("timed_out") is False
        and candidate.get("timed_out") is False,
        "Lua source or bytecode workload did not exit successfully on both runtimes",
    )
    status_match = reference.get("status") == candidate.get("status") and reference.get("timed_out") == candidate.get("timed_out")
    stdout_match = validate_stream(reference.get("stdout"), "reference workload stdout") == validate_stream(candidate.get("stdout"), "candidate workload stdout")
    stderr_match = validate_stream(reference.get("stderr"), "reference workload stderr") == validate_stream(candidate.get("stderr"), "candidate workload stderr")
    require(
        value.get("normalization") == "none"
        and value.get("status_match") is status_match
        and value.get("stdout_match") is stdout_match
        and value.get("stderr_match") is stderr_match
        and value.get("passed") is (status_match and stdout_match and stderr_match),
        "Lua source or bytecode result flags differ from their retained raw outcomes",
    )


def validate_report_records(value: object, *, parent: Mapping[str, Any] | None = None, key: str = "report") -> None:
    """Recheck retained command bytes, artifact hashes, and comparison flags."""

    if isinstance(value, Mapping):
        if {"path", "sha256", "byte_length"} <= set(value):
            artifact = Path(str(value["path"]))
            require(artifact.is_file(), f"{key} artifact is missing")
            require(
                artifact.stat().st_size == value["byte_length"]
                and LUA.sha256_file(artifact) == value["sha256"],
                f"{key} artifact bytes differ from the retained report",
            )
        if {"command", "cwd", "status", "stdout", "stderr"} <= set(value):
            command = value["command"]
            require(
                isinstance(command, list)
                and command
                and all(isinstance(argument, str) for argument in command),
                f"{key} command record has invalid argv",
            )
            validate_stream(value["stdout"], f"{key} command stdout")
            validate_stream(value["stderr"], f"{key} command stderr")
            known_diagnostic = (
                parent is not None
                and parent.get("status") == "known-broken"
                and str(parent.get("purpose", "")).startswith("pinned musl wrapper static-PIE")
                and key.endswith(".execution")
            )
            if known_diagnostic:
                artifact = parent.get("artifact")
                require(isinstance(artifact, Mapping), "known musl static-PIE diagnostic lacks its executable")
                executable = str(artifact.get("path", ""))
                require(
                    isinstance(value["status"], int)
                    and not isinstance(value["status"], bool)
                    and value["status"] != 0
                    and value["command"] == [executable]
                    and value["cwd"] == str(Path(executable).parent)
                    and parent.get("limitation") == (
                        "pinned wrapper -static-pie does not execute this minimal program; "
                        "the separately linked pinned-musl ET_EXEC oracle remains the semantic reference"
                    ),
                    "known musl static-PIE diagnostic no longer matches its declared failing execution",
                )
            else:
                require(value["status"] == 0, f"{key} command did not complete successfully")
        if {"reference", "candidate", "normalization", "status_match", "stdout_match", "stderr_match", "passed"} <= set(value):
            validate_result_comparison(value)
        for child_key, child in value.items():
            validate_report_records(child, parent=value, key=f"{key}.{child_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_report_records(child, parent=parent, key=f"{key}[{index}]")


def physical_file(path: Path, description: str) -> Path:
    path = LUA.require_physical_regular_file(Path(os.path.abspath(path)), description)
    require(path.is_relative_to(ROOT), f"{description} is outside the checkout")
    return path


def read_report(path: Path, expected_runner: str) -> dict[str, Any]:
    report_path = physical_file(path, "Lua source-build report")
    try:
        value = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LUA.RunnerError(f"Lua source-build report is invalid JSON: {report_path}") from error
    require(isinstance(value, dict), f"Lua source-build report is not an object: {report_path}")
    require(
        value.get("runner") == expected_runner
        and value.get("passed") is True
        and value.get("result") == "pass",
        f"Lua source-build report is not a passing {expected_runner} result",
    )
    dispatcher = value.get("dispatcher")
    require(isinstance(dispatcher, Mapping), "Lua source-build report lacks dispatcher provenance")
    state = LUA.require_physical_directory(
        Path(str(dispatcher.get("state_root", ""))), "Lua source-build state root"
    )
    require(state.is_relative_to(WORK), "Lua source-build state escaped .work/x86_64")
    authoritative = physical_file(
        Path(str(dispatcher.get("authoritative_report", ""))),
        "Lua authoritative source-build report",
    )
    require(authoritative == state / "report.json", "Lua authoritative report is outside its state root")
    require(
        hashlib.sha256(authoritative.read_bytes()).digest()
        == hashlib.sha256(report_path.read_bytes()).digest(),
        "published Lua source-build report differs from its authoritative report",
    )
    latest = Path(str(dispatcher.get("latest_report", ""))).resolve(strict=True)
    require(latest == report_path, "Lua source-build report is not the selected latest report")
    require(
        dispatcher.get("source_identity") == LUA.current_source_identity(),
        "Lua source-build report was produced from stale source",
    )
    if expected_runner == "crabc-lua-native-x86-dynamic-source-build-dispatch":
        for lane in ("installed", "extracted"):
            lane_report = value.get(lane)
            require(isinstance(lane_report, Mapping), f"dynamic Lua report lacks {lane} lane")
            validate_pinned_input(lane_report)
    else:
        validate_pinned_input(value)
    validate_report_records(value)
    return value


def validate_pinned_input(value: Mapping[str, Any]) -> None:
    manifest_record = value.get("manifest")
    require(isinstance(manifest_record, Mapping), "Lua source-build report lacks its pinned manifest")
    contents = manifest_record.get("contents")
    require(isinstance(contents, Mapping), "Lua source-build report manifest contents are invalid")
    require(
        manifest_record.get("sha256") == LUA.sha256_file(LUA.MANIFEST)
        and contents == LUA.load_manifest(LUA.MANIFEST),
        "Lua source-build report uses a stale manifest",
    )
    source_record = value.get("source_archive")
    require(isinstance(source_record, Mapping), "Lua source-build report lacks its pinned source archive")
    archive = physical_file(Path(str(source_record.get("path", ""))), "Lua source archive")
    require(archive.is_relative_to(WORK), "Lua source archive escaped .work/x86_64")
    lua_pin = contents.get("lua")
    require(isinstance(lua_pin, Mapping), "Lua source-build report lacks the Lua source pin")
    expected_archive = lua_pin.get("sha256")
    require(
        source_record.get("sha256") == expected_archive
        and LUA.sha256_file(archive) == expected_archive,
        "Lua source archive does not match the pinned manifest",
    )


def admit_static() -> dict[str, str]:
    report = read_report(STATIC_REPORT, "crabc-lua-native-x86-static-source-build")
    dispatcher = report["dispatcher"]
    state = Path(str(dispatcher["state_root"]))
    environment = report.get("environment")
    require(isinstance(environment, Mapping), "static Lua report lacks environment provenance")
    sysroot = LUA.owned_static_sysroot(state / "sysroot")
    require(
        environment.get("sysroot_manifest") == sysroot[3],
        "static Lua report and installed product manifest differ",
    )
    modes = report.get("modes")
    require(
        isinstance(modes, Mapping)
        and set(modes) == {"static-et-exec", "static-pie"}
        and all(isinstance(row, Mapping) for row in modes.values()),
        "static Lua report lacks ET_EXEC and static-PIE results",
    )
    for name, row in modes.items():
        workloads = row.get("workloads")
        require(isinstance(workloads, Mapping), f"static Lua {name} report lacks workloads")
        for workload in ("source", "bytecode"):
            result = workloads.get(workload)
            require(
                isinstance(result, Mapping) and result.get("passed") is True,
                f"static Lua {name} {workload} comparison did not pass",
            )
    return {"report_sha256": LUA.sha256_file(STATIC_REPORT), "product_sha256": LUA.sha256_file(sysroot[0] / "share/crabc/manifest.json")}


def admit_dynamic() -> dict[str, str]:
    report = read_report(DYNAMIC_REPORT, "crabc-lua-native-x86-dynamic-source-build-dispatch")
    dispatcher = report["dispatcher"]
    state = Path(str(dispatcher["state_root"]))
    manifests: dict[str, str] = {}
    artifacts: dict[str, dict[str, str]] = {}
    for lane, directory in (("installed", "sysroot"), ("extracted", "extracted")):
        result = report.get(lane)
        require(isinstance(result, Mapping) and result.get("passed") is True, f"dynamic Lua {lane} lane did not pass")
        environment = result.get("environment")
        require(isinstance(environment, Mapping), f"dynamic Lua {lane} report lacks environment provenance")
        root, _wrapper, _runtime, manifest = DYNAMIC.owned_dynamic_sysroot(state / directory)
        QUALIFICATION.product_identity(root)
        require(environment.get("sysroot_manifest") == manifest, f"dynamic Lua {lane} report and product differ")
        workloads = result.get("workloads")
        require(isinstance(workloads, Mapping), f"dynamic Lua {lane} report lacks workloads")
        for workload in ("source", "bytecode"):
            comparison = workloads.get(workload)
            require(
                isinstance(comparison, Mapping) and comparison.get("passed") is True,
                f"dynamic Lua {lane} {workload} comparison did not pass",
            )
        manifests[lane] = LUA.sha256_file(root / "share/crabc/manifest.json")
        artifacts[lane] = DYNAMIC.source_artifact_hashes(result)
    reproducibility = report.get("reproducibility")
    require(
        isinstance(reproducibility, Mapping)
        and reproducibility.get("status") == "passed"
        and manifests["installed"] == manifests["extracted"]
        and reproducibility.get("installed_artifacts") == artifacts["installed"]
        and reproducibility.get("extracted_artifacts") == artifacts["extracted"]
        and artifacts["installed"] == artifacts["extracted"],
        "dynamic Lua installed/extracted products are not reproducible",
    )
    return {"report_sha256": LUA.sha256_file(DYNAMIC_REPORT), **manifests}


def validate() -> dict[str, object]:
    """Require physical, passing, current-source receipts for both lanes."""

    source = LUA.current_source_identity()
    return {"source_identity": source, "static": admit_static(), "dynamic": admit_dynamic()}


def main() -> int:
    try:
        report = validate()
    except (LUA.RunnerError, QUALIFICATION.QualificationError, OSError, ValueError) as error:
        print(f"Lua source-build admission: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": "pass", **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
