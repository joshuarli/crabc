#!/usr/bin/env python3
"""Execute only fully pinned x86 qualification evidence, in promotion order.

The runner refuses a planned gate before invoking any child.  It cannot turn a
private admission artifact, a mutable case manifest, or an unpinned receipt
into promotion evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import generate_qualification_manifest as manifest


ROOT = Path(__file__).resolve().parents[2]
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class QualificationRunError(RuntimeError):
    """A native qualification transaction did not meet its pinned contract."""


def controlled_environment() -> dict[str, str]:
    """Return the one scrubbed environment allowed for qualification cases.

    A qualification case has to invoke the checked repository runner named in
    its immutable manifest.  Inheriting ``PATH``, Python import settings, or
    shell startup hooks would let a caller replace that interpreter boundary
    after the case and receipt have been pinned.  Start from an allowlist
    instead of attempting to blacklist every ambient build/runtime variable.
    """
    return {
        "PATH": TRUSTED_PATH,
        "CRABC_WORK_DIR": manifest.EXECUTION_CONTRACT["work_directory"],
        "TMPDIR": manifest.EXECUTION_CONTRACT["temporary_directory"],
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }


def require_native_linux_x86_64() -> None:
    if platform.system() != "Linux":
        raise QualificationRunError("qualification requires native Linux")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise QualificationRunError(f"qualification refuses emulation on {platform.machine()}")


def require_pinned_native_execution() -> None:
    """Refuse to execute receipts outside the pinned dispatcher environment."""
    require_native_linux_x86_64()
    expected_work = manifest.EXECUTION_CONTRACT["work_directory"]
    expected_temporary = manifest.EXECUTION_CONTRACT["temporary_directory"]
    if os.environ.get("CRABC_WORK_DIR") != expected_work:
        raise QualificationRunError("qualification has no pinned work directory")
    if os.environ.get("TMPDIR") != expected_temporary:
        raise QualificationRunError("qualification has no pinned temporary directory")
    if not Path(expected_work).is_dir():
        raise QualificationRunError("qualification pinned work directory is unavailable")
    if not Path(expected_temporary).is_dir():
        raise QualificationRunError("qualification pinned temporary directory is unavailable")
    for path in (Path(expected_work), Path(expected_temporary)):
        if path.resolve() != path:
            raise QualificationRunError("qualification work and temporary directories must be physical paths")
    if not Path(manifest.EXECUTION_CONTRACT["oracle_compiler"]).is_file():
        raise QualificationRunError("qualification pinned musl oracle compiler is unavailable")


def load_case_manifest(gate: Mapping[str, object]) -> dict[str, Any]:
    path = gate.get("case_manifest")
    if not isinstance(path, str):
        raise QualificationRunError(f"{gate.get('id')} has no pinned case manifest")
    case_path = ROOT / path
    expected_hash = gate.get("case_manifest_sha256")
    if not isinstance(expected_hash, str) or manifest.sha256_file(case_path) != expected_hash:
        raise QualificationRunError(f"{gate['id']} case manifest changed after receipt validation")
    receipt_path = gate.get("receipt")
    receipt_hash = gate.get("receipt_sha256")
    if not isinstance(receipt_path, str) or not isinstance(receipt_hash, str):
        raise QualificationRunError(f"{gate['id']} has no pinned receipt")
    if manifest.sha256_file(ROOT / receipt_path) != receipt_hash:
        raise QualificationRunError(f"{gate['id']} receipt changed after receipt validation")
    return manifest.load_json(case_path, f"{gate['id']} case manifest")


def verify_case_output(gate_id: str, case: Mapping[str, Any], returncode: int, stdout: bytes, stderr: bytes) -> None:
    if returncode != 0:
        raise QualificationRunError(f"{gate_id}/{case['id']} exited {returncode}")
    marker = str(case["expected_stdout_line"]).encode("utf-8")
    lines = [line for line in stdout.splitlines() if line]
    if lines.count(marker) != 1 or not lines or lines[-1] != marker:
        raise QualificationRunError(f"{gate_id}/{case['id']} did not emit one final completion marker")
    del stderr


def verify_case_runner(gate: Mapping[str, object], case: Mapping[str, Any]) -> None:
    """Rehash the repository runner immediately before starting it.

    The case file's own hash protects its declared runner hash during contract
    validation.  This second check closes the interval between that validation
    and ``Popen``: a changed runner cannot satisfy a receipt for old bytes.
    """
    command = case.get("command")
    if not isinstance(command, list) or len(command) != 2 or not all(
        isinstance(token, str) and token for token in command
    ):
        raise QualificationRunError(f"{gate['id']}/{case.get('id')} has an invalid runner command")
    expected_hash = case.get("runner_sha256")
    if not isinstance(expected_hash, str) or not expected_hash:
        raise QualificationRunError(f"{gate['id']}/{case.get('id')} has no pinned runner hash")
    try:
        _, runner_path = manifest.repository_file(
            command[1], f"{gate['id']}/{case.get('id')} runner"
        )
        observed_hash = manifest.sha256_file(runner_path)
    except manifest.QualificationManifestError as error:
        raise QualificationRunError(str(error)) from error
    if observed_hash != expected_hash:
        raise QualificationRunError(f"{gate['id']}/{case.get('id')} runner bytes changed after case validation")


def run_case(gate: Mapping[str, object], case: Mapping[str, Any]) -> None:
    command = case["command"]
    assert isinstance(command, list)
    verify_case_runner(gate, case)
    process = subprocess.Popen(command, cwd=ROOT, env=controlled_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=case["timeout_seconds"])
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        if stdout:
            sys.stderr.buffer.write(stdout)
        if stderr:
            sys.stderr.buffer.write(stderr)
        raise QualificationRunError(f"{gate['id']}/{case['id']} timed out after {case['timeout_seconds']}s") from error
    try:
        verify_case_output(str(gate["id"]), case, process.returncode, stdout, stderr)
    except QualificationRunError:
        if stdout:
            sys.stderr.buffer.write(stdout)
        if stderr:
            sys.stderr.buffer.write(stderr)
        raise


def incomplete_payload(report: Mapping[str, object]) -> str:
    return json.dumps({"target": manifest.TARGET["triple"], "promotion_ready": False, "incomplete_gates": report["incomplete_gates"], "private_admission": [row["id"] for row in report["private_admission"]], "reason": "private admission is non-promoting and every promotion gate requires pinned immutable case-manifest and receipt hashes"}, indent=2, sort_keys=True)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-contract", action="store_true", help="validate planning and pins without native execution")
    parsed = parser.parse_args(arguments)
    report = manifest.load_contract()
    # The checked-in generated projection is a second immutable handoff point:
    # a caller cannot execute a source contract while ignoring stale generated
    # state consumed by a future campaign integration.
    manifest.write_or_check(manifest.GENERATED_PATH, report, check=True)
    if parsed.check_contract:
        print(f"x86 qualification manifest contract: PASS ({len(report['promotion_chain'])} ordered gates; {len(report['incomplete_gates'])} planned; non-promoting private admission)")
        return 0
    if report["incomplete_gates"]:
        print(incomplete_payload(report), file=sys.stderr)
        return 1
    require_pinned_native_execution()
    for gate in report["promotion_chain"]:
        case_manifest = load_case_manifest(gate)
        for case in case_manifest["cases"]:
            assert isinstance(case, Mapping)
            run_case(gate, case)
        print(f"x86 qualification: {gate['id']}: PASS")
    print("x86 qualification: PASS (all immutable promotion receipts and native cases)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QualificationRunError, manifest.QualificationManifestError) as error:
        raise SystemExit(f"x86 qualification: ERROR: {error}") from error
