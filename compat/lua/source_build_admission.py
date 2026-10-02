#!/usr/bin/env python3
"""Admit current native Lua static and dynamic source-build reports.

Without arguments this validates both conventional latest lane reports and
prints the admission. ``--static-report`` and ``--dynamic-report`` select the
physical latest paths recorded by their dispatchers. Nondefault paths are
retained as checkout-relative locators and authenticated again on replay.
``--output NEW_DIR`` also retains that admission as
``NEW_DIR/admission.json``: the receipt the ``consumer.source-build``
qualification gate selects through its ``lua-source-build`` publication.
The receipt asserts nothing by itself; ``validate_receipt`` reruns the
admission and requires the identical result, so a replaced lane report, a
changed product, or a source edit after admission cannot pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

# Qualification cases run with PYTHONSAFEPATH=1, which omits this script's
# directory from sys.path; name it so sibling imports still resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as LUA  # noqa: E402
import run_x86_dynamic as DYNAMIC  # noqa: E402

ROOT = LUA.ROOT
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as QUALIFICATION

STATIC_REPORT = LUA.DEFAULT_X86_STATIC_REPORT
DYNAMIC_REPORT = DYNAMIC.DEFAULT_REPORT
WORK = ROOT / ".work/x86_64"
RECEIPT_SCHEMA = "crabc.x86_64-lua-source-build-admission/v1"
RECEIPT_NAME = "admission.json"
GATE = "consumer.source-build"


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
    latest = physical_file(Path(str(dispatcher.get("latest_report", ""))), "Lua dispatcher latest report")
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


def admit_static(report_path: Path | None = None) -> dict[str, str]:
    selected = Path(os.path.abspath(ROOT / report_path)) if report_path is not None else STATIC_REPORT
    report = read_report(selected, "crabc-lua-native-x86-static-source-build")
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
    admission = {"report_sha256": LUA.sha256_file(selected), "product_sha256": LUA.sha256_file(sysroot[0] / "share/crabc/manifest.json")}
    if selected != STATIC_REPORT:
        admission["report_path"] = str(selected.relative_to(ROOT))
    return admission


def admit_dynamic(report_path: Path | None = None) -> dict[str, str]:
    selected = Path(os.path.abspath(ROOT / report_path)) if report_path is not None else DYNAMIC_REPORT
    report = read_report(selected, "crabc-lua-native-x86-dynamic-source-build-dispatch")
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
    admission = {"report_sha256": LUA.sha256_file(selected), **manifests}
    if selected != DYNAMIC_REPORT:
        admission["report_path"] = str(selected.relative_to(ROOT))
    return admission


def require_current_supplied_products(
    static_roots: Sequence[Path], dynamic_roots: Sequence[Path], source: Mapping[str, str],
) -> None:
    """Admission binds runtime and consumer bytes to one source, profile and backend."""
    backends = set()
    products = [(root, LUA.owned_static_sysroot) for root in static_roots]
    products.extend((root, DYNAMIC.owned_dynamic_sysroot) for root in dynamic_roots)
    for root, reader in products:
        manifest = reader(root)[3]
        if reader is DYNAMIC.owned_dynamic_sysroot:
            QUALIFICATION.product_identity(root)
            manifest = {**manifest, **QUALIFICATION.read(root / "share/crabc/dynamic-product-state.json")}
        require(manifest.get("source_sha256") == source["source_sha256"],
                "Lua qualification product uses different source")
        require(manifest.get("build_profile", "release") == "release",
                "Lua qualification requires release products")
        backends.add(manifest.get("allocator_backend"))
    require(len(backends) == 1 and backends <= {"accepted-c", "native-shadow"},
            "Lua qualification products use different or invalid allocator backends")


def admit_supplied(static_report: Path, dynamic_report: Path) -> dict[str, object]:
    """Authenticate retained consumer reports against their original owned cohort."""
    import run_x86_static_dispatch as STATIC
    import run_x86_dynamic_supplied as SUPPLIED

    static_path = physical_file(static_report, "supplied static Lua report")
    dynamic_path = physical_file(dynamic_report, "supplied dynamic Lua report")
    static = json.loads(static_path.read_text())
    dynamic = json.loads(dynamic_path.read_text())
    context = static["supplied"]
    state_parent = WORK / "lua-supplied-admission"
    args = argparse.Namespace(
        read=static_path, replay=False, work_root=state_parent / "static",
        cohort_checkout=Path(context["checkout"]), static_preparation=Path(context["preparation"]["path"]),
        installed_sysroot=Path(context["roots"]["primary"]),
        rebuilt_sysroot=Path(context["roots"]["reproduction"]),
        extracted_sysroot=Path(context["roots"]["extracted"]),
        archive_seed=Path(context["archive_seed"]["path"]), timeout=300.0,
    )
    STATIC.read_supplied(args)
    require(dynamic.get("runner") == "crabc-lua-native-x86-dynamic-supplied-cohort"
            and dynamic.get("passed") is True and dynamic.get("result") == "pass",
            "supplied dynamic Lua report did not pass")
    seal = SUPPLIED.consumer_source_seal()
    require(dynamic.get("consumer_source_before") == seal and dynamic.get("consumer_source_after") == seal,
            "supplied dynamic Lua consumer source changed")
    dispatcher = dynamic["dispatcher"]
    require(dispatcher.get("authoritative_report") == str(dynamic_path)
            and dispatcher.get("state_root") == str(dynamic_path.parent),
            "supplied dynamic Lua authoritative report moved")
    validate_report_records(dynamic)
    cohort = dispatcher["cohort"]
    require(cohort["checkout"] == context["checkout"], "Lua consumers use different cohort checkouts")
    state = LUA.allocate_x86_static_dispatch_state(state_parent / "dynamic")
    current, _validation = SUPPLIED.validate_cohort(
        checkout=Path(cohort["checkout"]), receipt=Path(cohort["receipt"]["path"]),
        installed=Path(cohort["roots"]["installed"]["path"]),
        extracted=Path(cohort["roots"]["extracted"]["path"]), state=state, timeout=300.0,
    )
    require(current == cohort, "supplied dynamic Lua cohort changed")
    source = LUA.current_source_identity()
    require(cohort.get("source_sha256") == source["source_sha256"],
            "supplied Lua runtime cohort uses different source than the consumer")
    require_current_supplied_products(
        [Path(context["roots"][label]) for label in STATIC.SUPPLIED_ROOTS],
        [Path(cohort["roots"][label]["path"]) for label in ("installed", "extracted")], source,
    )
    artifacts = {}
    for label in ("installed", "extracted"):
        lane = dynamic[label]
        validate_pinned_input(lane)
        root = Path(cohort["roots"][label]["path"])
        require(lane.get("passed") is True and lane["environment"]["sysroot"] == str(root)
                and lane["environment"]["sysroot_manifest"] == DYNAMIC.owned_dynamic_sysroot(root)[3],
                "supplied dynamic Lua product differs from report")
        for name in ("source", "bytecode"):
            require(lane["workloads"][name].get("passed") is True,
                    "supplied dynamic Lua source or bytecode comparison failed")
        artifacts[label] = DYNAMIC.source_artifact_hashes(lane)
    require(dynamic["reproducibility"] == {
        "status": "passed", "installed_artifacts": artifacts["installed"],
        "extracted_artifacts": artifacts["extracted"],
        "contract": "identical Lua source artifacts through supplied installed and extracted dynamic roots",
    } and artifacts["installed"] == artifacts["extracted"], "supplied Lua artifact reproducibility differs")
    require(LUA.current_source_identity() == source, "source changed during supplied Lua admission")
    return {"source_identity": source,
            "static": {"report_path": str(static_path.relative_to(ROOT)), "report_sha256": LUA.sha256_file(static_path)},
            "dynamic": {"report_path": str(dynamic_path.relative_to(ROOT)), "report_sha256": LUA.sha256_file(dynamic_path)}}


def validate(*, static_report: Path | None = None, dynamic_report: Path | None = None) -> dict[str, object]:
    """Require physical, passing, current-source receipts for both lanes."""

    if static_report is not None and dynamic_report is not None:
        selected = physical_file(ROOT / static_report, "Lua selected static report")
        payload = json.loads(selected.read_text())
        if isinstance(payload, dict) and "supplied" in payload:
            try:
                return admit_supplied(selected, ROOT / dynamic_report)
            except (KeyError, TypeError) as error:
                raise LUA.RunnerError(f"supplied Lua report is incomplete: {error}") from error
    source = LUA.current_source_identity()
    return {"source_identity": source, "static": admit_static(static_report), "dynamic": admit_dynamic(dynamic_report)}


def write_receipt(output: Path, *, static_report: Path | None = None, dynamic_report: Path | None = None) -> Path:
    """Admit both lanes now and retain that admission below a fresh directory."""

    output = Path(os.path.abspath(output))
    require(output.is_relative_to(ROOT / ".work"), "Lua admission output must be below this checkout's .work")
    require(not output.exists() and not output.is_symlink(), f"Lua admission output is not fresh: {output}")
    LUA.require_physical_directory(output.parent, "Lua admission output parent")
    receipt = {"schema": RECEIPT_SCHEMA, "gate": GATE, "admission": validate(static_report=static_report, dynamic_report=dynamic_report)}
    output.mkdir()
    path = output / RECEIPT_NAME
    LUA.write_json_atomic(path, receipt)
    return path


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    """Reread one retained admission: it must equal a fresh admission now."""

    require(Path(root).resolve() == ROOT, "Lua admission receipt must be read by this checkout")
    path = physical_file(path, "Lua admission receipt")
    require(path.name == RECEIPT_NAME and path.is_relative_to(ROOT / ".work"),
            f"Lua admission receipt must be a .work {RECEIPT_NAME}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LUA.RunnerError(f"Lua admission receipt is invalid JSON: {path}") from error
    require(
        isinstance(record, dict)
        and set(record) == {"schema", "gate", "admission"}
        and record["schema"] == RECEIPT_SCHEMA
        and record["gate"] == GATE,
        "Lua admission receipt does not match its schema",
    )
    admission = record.get("admission")
    require(isinstance(admission, Mapping), "Lua admission receipt has invalid admission fields")
    selections: dict[str, Path] = {}
    for lane in ("static", "dynamic"):
        fields = admission.get(lane)
        require(isinstance(fields, Mapping), f"Lua admission receipt has invalid {lane} fields")
        if "report_path" in fields:
            locator = fields["report_path"]
            require(isinstance(locator, str) and bool(locator), f"Lua {lane} report locator is invalid")
            relative = Path(locator)
            require(not relative.is_absolute() and ".." not in relative.parts and str(relative) == locator,
                    f"Lua {lane} report locator must be checkout-relative")
            # A locator selects bytes to authenticate; it does not waive the
            # report's physical latest path, source or product validation.
            selections[f"{lane}_report"] = physical_file(ROOT / relative, f"Lua {lane} selected report")
    current = validate(**selections)
    require(
        record["admission"] == current,
        "Lua admission receipt differs from a fresh admission of the current source, reports and products",
    )
    return record


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, help="fresh .work directory that retains admission.json")
    parser.add_argument("--static-report", type=Path, help="physical static report selected by its dispatcher; defaults to the conventional latest report")
    parser.add_argument("--dynamic-report", type=Path, help="physical dynamic report selected by its dispatcher; defaults to the conventional latest report")
    arguments = parser.parse_args(argv)
    try:
        if arguments.output is not None:
            receipt = write_receipt(arguments.output, static_report=arguments.static_report, dynamic_report=arguments.dynamic_report)
            report = json.loads(receipt.read_text(encoding="utf-8"))["admission"]
        else:
            report = validate(static_report=arguments.static_report, dynamic_report=arguments.dynamic_report)
    except (LUA.RunnerError, QUALIFICATION.QualificationError, OSError, ValueError) as error:
        print(f"Lua source-build admission: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": "pass", **report}, sort_keys=True))
    if arguments.output is not None:
        print(f"Lua source-build admission receipt: {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
