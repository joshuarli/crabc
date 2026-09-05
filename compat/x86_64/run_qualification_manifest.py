#!/usr/bin/env python3
"""Execute an explicitly selected, non-promoting ordered qualification prefix.

Ready declarations pin case manifests and runner bytes. A prefix always starts
at the first gate and includes every predecessor; later planned gates do not
block it. Case execution alone is not a source/tool/runtime/artifact-bound
qualification receipt, so the default full-qualification entry stays closed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import generate_qualification_manifest as manifest


ROOT = Path(__file__).resolve().parents[2]
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MUSL_RUNTIME_PATHS = {
    "compiler_wrapper": "/usr/local/bin/crabc-x86_64-musl-gcc",
    "libc": "/opt/musl-1.2.6/lib/libc.so",
    "loader": "/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1",
    "specs": "/opt/musl-1.2.6/lib/musl-gcc.specs",
    "source_manifest": "/opt/musl-1.2.6/.crabc-oracle",
    "specs_manifest": "/opt/musl-1.2.6/.crabc-musl-gcc-specs.sha256",
    "headers": "/opt/musl-1.2.6/include",
}
TOOL_COMMANDS = (
    "python3",
    "bash",
    "cargo",
    "rustc",
    "rustup",
    "gcc",
    "ar",
    "nm",
    "objdump",
    "readelf",
    "sha256sum",
    "timeout",
)


class QualificationRunError(RuntimeError):
    """A native qualification transaction did not meet its pinned contract."""


def controlled_environment() -> dict[str, str]:
    """Return the one scrubbed environment allowed for qualification cases.

    A qualification case has to invoke the checked repository runner named in
    its pinned manifest.  Inheriting ``PATH``, Python import settings, or
    shell startup hooks would let a caller replace that interpreter boundary
    after the case has been pinned.  Start from an allowlist
    instead of attempting to blacklist every ambient build/runtime variable.
    """
    return {
        "PATH": manifest.EXECUTION_CONTRACT["rust_bin_directory"] + ":" + TRUSTED_PATH,
        "RUSTUP_HOME": manifest.EXECUTION_CONTRACT["rustup_home"],
        "CARGO_HOME": manifest.EXECUTION_CONTRACT["cargo_home"],
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


def require_unconfigured_cargo_home(cargo_home: Path) -> None:
    """Reject ignored Cargo configuration that can alter a pinned build."""
    for name in ("config", "config.toml"):
        path = cargo_home / name
        if path.exists() or path.is_symlink():
            raise QualificationRunError(
                f"qualification mutable Cargo home must not contain {name}"
            )


def require_pinned_native_execution() -> None:
    """Refuse to execute cases outside the pinned dispatcher environment."""
    require_native_linux_x86_64()
    expected_work = manifest.EXECUTION_CONTRACT["work_directory"]
    expected_temporary = manifest.EXECUTION_CONTRACT["temporary_directory"]
    expected_rust_bin = manifest.EXECUTION_CONTRACT["rust_bin_directory"]
    expected_rustup = manifest.EXECUTION_CONTRACT["rustup_home"]
    expected_cargo = manifest.EXECUTION_CONTRACT["cargo_home"]
    if os.environ.get("CRABC_WORK_DIR") != expected_work:
        raise QualificationRunError("qualification has no pinned work directory")
    if os.environ.get("TMPDIR") != expected_temporary:
        raise QualificationRunError("qualification has no pinned temporary directory")
    if os.environ.get("RUSTUP_HOME") != expected_rustup:
        raise QualificationRunError("qualification has no pinned Rustup home")
    if os.environ.get("CARGO_HOME") != expected_cargo:
        raise QualificationRunError("qualification has no pinned Cargo home")
    if not os.environ.get("PATH", "").startswith(expected_rust_bin + ":"):
        raise QualificationRunError("qualification has no pinned Rust binary path")
    for path in (
        Path(expected_work),
        Path(expected_temporary),
        Path(expected_rust_bin),
        Path(expected_rustup),
        Path(expected_cargo),
    ):
        if not path.is_dir():
            raise QualificationRunError(f"qualification pinned directory is unavailable: {path}")
        if path.resolve() != path:
            raise QualificationRunError("qualification work and temporary directories must be physical paths")
    if not Path(manifest.EXECUTION_CONTRACT["oracle_compiler"]).is_file():
        raise QualificationRunError("qualification pinned musl oracle compiler is unavailable")
    require_unconfigured_cargo_home(Path(expected_cargo))


def load_case_manifest(gate: Mapping[str, object]) -> dict[str, Any]:
    path = gate.get("case_manifest")
    if not isinstance(path, str):
        raise QualificationRunError(f"{gate.get('id')} has no pinned case manifest")
    case_path = ROOT / path
    expected_hash = gate.get("case_manifest_sha256")
    if not isinstance(expected_hash, str) or manifest.sha256_file(case_path) != expected_hash:
        raise QualificationRunError(f"{gate['id']} case manifest changed after declaration validation")
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationRunError(message)


def git(*arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", *arguments],
        cwd=ROOT,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )


def require_clean_source() -> str:
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise QualificationRunError("qualification receipt requires clean committed source")
    return git("rev-parse", "HEAD").decode("utf-8").strip()


def source_identity() -> dict[str, str]:
    """Bind an execution to checked-out bytes, modes, and its clean revision.

    Git's tree identifies the committed revision, while this independent hash
    makes the physical content observed before and after the transaction
    explicit. Receipts remain beneath ignored `.work` and are not self-hashed.
    """
    revision = require_clean_source()
    content = hashlib.sha256()
    for name in sorted(name for name in git("ls-files", "-z").split(b"\0") if name):
        path = ROOT / os.fsdecode(name)
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise QualificationRunError(f"tracked source is absent: {path}") from error
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        content.update(name + b"\0" + str(stat.S_IMODE(mode)).encode("ascii") + b"\0")
        content.update(hashlib.sha256(data).digest())
    return {"revision": revision, "content_sha256": content.hexdigest()}


def sha256_file(path: Path, label: str) -> str:
    try:
        if not path.is_file() or path.is_symlink():
            raise OSError("not a regular file")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise QualificationRunError(f"cannot hash {label}: {path}") from error


def physical_file_identity(path_text: str, label: str) -> dict[str, str]:
    path = Path(path_text)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise QualificationRunError(f"{label} is unavailable: {path}") from error
    if not resolved.is_file() or resolved.is_symlink():
        raise QualificationRunError(f"{label} is not a regular file: {path}")
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "sha256": sha256_file(resolved, label),
    }


def physical_directory_identity(path_text: str, label: str) -> dict[str, str]:
    path = Path(path_text)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise QualificationRunError(f"{label} is unavailable: {path}") from error
    if not resolved.is_dir() or resolved.is_symlink() or resolved != path:
        raise QualificationRunError(f"{label} is not a physical directory: {path}")
    return {
        "path": str(path),
        "sha256": directory_tree_sha256(resolved, label),
    }


def directory_tree_sha256(root: Path, label: str) -> str:
    digest = hashlib.sha256()
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir(), reverse=True):
            relative = child.relative_to(root).as_posix().encode("utf-8")
            mode = child.lstat().st_mode
            digest.update(relative + b"\0" + str(stat.S_IMODE(mode)).encode("ascii") + b"\0")
            if stat.S_ISREG(mode):
                digest.update(b"regular\0" + bytes.fromhex(sha256_file(child, label)))
            elif stat.S_ISDIR(mode):
                if child.is_symlink():
                    raise QualificationRunError(f"{label} has an unsafe directory symlink")
                digest.update(b"directory\0")
                pending.append(child)
            elif stat.S_ISLNK(mode):
                digest.update(b"symlink\0" + os.fsencode(os.readlink(child)))
            else:
                raise QualificationRunError(f"{label} has an unsupported file type")
    return digest.hexdigest()


def resolved_directory_identity(path_text: str, label: str) -> dict[str, str]:
    """Hash an actual PATH/toolchain directory, recording symlink resolution."""
    path = Path(path_text)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise QualificationRunError(f"{label} is unavailable: {path}") from error
    if not resolved.is_dir() or resolved.is_symlink():
        raise QualificationRunError(f"{label} is not a directory: {path}")
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "sha256": directory_tree_sha256(resolved, label),
    }


def tool_identity(command: str) -> dict[str, object]:
    location = shutil.which(command, path=controlled_environment()["PATH"])
    if location is None:
        raise QualificationRunError(f"qualification required tool is unavailable: {command}")
    identity: dict[str, object] = {"command": command, **physical_file_identity(location, command)}
    version = subprocess.run(
        [location, "--version"],
        cwd=ROOT,
        env=controlled_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    identity["version"] = {
        "command": [location, "--version"],
        "exit_status": version.returncode,
        "stdout": version.stdout.decode("utf-8", errors="replace"),
        "stderr": version.stderr.decode("utf-8", errors="replace"),
    }
    return identity


def trusted_tool_directories() -> list[dict[str, str]]:
    """Bind every executable directory reachable from the scrubbed PATH."""
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in controlled_environment()["PATH"].split(":"):
        configured = Path(path)
        if not configured.exists() and not configured.is_symlink():
            result.append({"path": path, "state": "absent"})
            continue
        identity = resolved_directory_identity(path, f"tool directory {path}")
        if identity["resolved_path"] not in seen:
            seen.add(identity["resolved_path"])
            result.append(identity)
    return result


def pinned_rust_toolchain_identity() -> dict[str, dict[str, str]]:
    """Bind rustup's selected executables and their complete sysroot."""
    rustup = shutil.which("rustup", path=controlled_environment()["PATH"])
    if rustup is None:
        raise QualificationRunError("qualification required rustup is unavailable")
    selected: dict[str, dict[str, str]] = {}
    for command in ("cargo", "rustc"):
        process = subprocess.run(
            [rustup, "which", command],
            cwd=ROOT,
            env=controlled_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        location = process.stdout.decode("utf-8", errors="strict").strip()
        if process.returncode != 0 or not location or "\n" in location:
            raise QualificationRunError(f"rustup could not select pinned {command}")
        selected[command] = physical_file_identity(location, f"pinned {command}")
    sysroot = subprocess.run(
        [selected["rustc"]["resolved_path"], "--print", "sysroot"],
        cwd=ROOT,
        env=controlled_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    sysroot_path = sysroot.stdout.decode("utf-8", errors="strict").strip()
    if sysroot.returncode != 0 or not sysroot_path or "\n" in sysroot_path:
        raise QualificationRunError("pinned rustc could not identify its sysroot")
    selected["sysroot"] = physical_directory_identity(sysroot_path, "pinned Rust sysroot")
    return selected


def gcc_builtin_include_identity() -> dict[str, str]:
    """Bind GCC's builtin header tree used by the same-object workload."""
    gcc = shutil.which("gcc", path=controlled_environment()["PATH"])
    if gcc is None:
        raise QualificationRunError("qualification required gcc is unavailable")
    process = subprocess.run(
        [gcc, "-print-file-name=include"],
        cwd=ROOT,
        env=controlled_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    include = process.stdout.decode("utf-8", errors="strict").strip()
    if process.returncode != 0 or not include or "\n" in include:
        raise QualificationRunError("gcc could not identify its builtin include directory")
    return physical_directory_identity(include, "gcc builtin headers")


def execution_inputs() -> dict[str, object]:
    """Capture the complete selected tool, compiler, and runtime closure."""
    runtime: dict[str, dict[str, str]] = {}
    for name, path in MUSL_RUNTIME_PATHS.items():
        runtime[name] = (
            physical_directory_identity(path, f"musl {name}")
            if name == "headers"
            else physical_file_identity(path, f"musl {name}")
        )
    return {
        "environment": controlled_environment(),
        "tools": [tool_identity(command) for command in TOOL_COMMANDS],
        "tool_directories": trusted_tool_directories(),
        "rust_toolchain": pinned_rust_toolchain_identity(),
        "gcc_builtin_include": gcc_builtin_include_identity(),
        "runtime": runtime,
    }


def ensure_physical_receipt_directory() -> Path:
    work = Path(manifest.EXECUTION_CONTRACT["work_directory"])
    receipt = Path(manifest.EXECUTION_CONTRACT["receipt_directory"])
    try:
        relative = receipt.relative_to(work)
    except ValueError as error:
        raise QualificationRunError("qualification receipt directory escapes pinned work") from error
    if not work.is_dir() or work.is_symlink() or work.resolve() != work:
        raise QualificationRunError("qualification pinned work directory is not physical")
    current = work
    for component in relative.parts:
        current = current / component
        if not current.exists():
            current.mkdir(mode=0o755)
        if not current.is_dir() or current.is_symlink() or current.resolve() != current:
            raise QualificationRunError("qualification receipt directory is not physical")
    return receipt


def evidence_path(path: Path, owner: Path | None = None) -> Path:
    """Return an existing receipt path contained by its physical owner.

    A receipt references only paths below its transaction. Resolve neither a
    final symlink nor a parent symlink before checking that lexical boundary:
    otherwise a sibling transaction can donate a matching log or a final
    symlink can silently escape the evidence tree.
    """
    candidate = Path(os.path.abspath(ROOT / path if not path.is_absolute() else path))
    receipt_root = ensure_physical_receipt_directory()
    try:
        relative = candidate.relative_to(receipt_root)
    except ValueError as error:
        raise QualificationRunError("qualification receipt escapes pinned work") from error
    if ".." in relative.parts:
        raise QualificationRunError("qualification receipt path has parent traversal")
    if owner is not None:
        try:
            owner_relative = candidate.relative_to(owner)
        except ValueError as error:
            raise QualificationRunError("qualification receipt escapes its transaction") from error
        if ".." in owner_relative.parts:
            raise QualificationRunError("qualification receipt path has parent traversal")
    current = receipt_root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise QualificationRunError("qualification receipt path is a symlink")
    if candidate.exists() and candidate.resolve() != candidate:
        raise QualificationRunError("qualification receipt path is not physical")
    return candidate


def relative_evidence_path(transaction: Path, path: Path) -> str:
    try:
        return path.relative_to(transaction).as_posix()
    except ValueError as error:
        raise QualificationRunError("receipt file escapes its transaction") from error


def write_new_bytes(path: Path, value: bytes) -> None:
    evidence_path(path.parent)
    with path.open("xb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o444)


def write_new_json(path: Path, value: Mapping[str, object]) -> None:
    write_new_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def read_json(path: Path, label: str, owner: Path | None = None) -> dict[str, Any]:
    evidence_path(path, owner)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualificationRunError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict):
        raise QualificationRunError(f"{label} is not a JSON object")
    return value


def transaction_directory(admission: Mapping[str, object]) -> Path:
    root = ensure_physical_receipt_directory()
    identifier = admission.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise QualificationRunError("private admission has no identifier")
    path = Path(
        tempfile.mkdtemp(
            prefix=f"{identifier}-{time.time_ns()}-",
            dir=root,
        )
    )
    if path.is_symlink() or path.resolve() != path:
        raise QualificationRunError("new qualification receipt transaction is not physical")
    return path


def verify_private_admission_runner(admission: Mapping[str, object]) -> None:
    command = admission.get("command")
    expected_hash = admission.get("runner_sha256")
    if not isinstance(command, list) or len(command) != 2 or not isinstance(expected_hash, str):
        raise QualificationRunError("private admission command or runner hash is invalid")
    try:
        _, path = manifest.repository_file(command[1], "private admission runner")
    except manifest.QualificationManifestError as error:
        raise QualificationRunError(str(error)) from error
    if manifest.sha256_file(path) != expected_hash:
        raise QualificationRunError("private admission runner bytes changed after declaration validation")


def select_private_admission(report: Mapping[str, object]) -> Mapping[str, object]:
    admissions = report.get("private_admission")
    if not isinstance(admissions, list) or len(admissions) != 1:
        raise QualificationRunError("private admission roster drifted")
    admission = admissions[0]
    if not isinstance(admission, Mapping) or admission.get("non_promoting") is not True:
        raise QualificationRunError("private admission is not explicitly non-promoting")
    if admission.get("id") in manifest.CHAIN:
        raise QualificationRunError("private admission cannot be a promotion gate")
    return admission


def private_admission_runner_module() -> Any:
    """Load the private receipt producer without trusting an ambient import."""
    path = ROOT / "compat/x86_64/run_qualification_posix_abi.py"
    spec = importlib.util.spec_from_file_location("qualification_private_admission_runner", path)
    if spec is None or spec.loader is None:
        raise QualificationRunError("cannot load private admission receipt runner")
    value = importlib.util.module_from_spec(spec)
    # Dataclasses resolves postponed annotations through ``sys.modules``.
    # Register this explicitly loaded trusted file before executing it; a
    # direct script invocation happens to have this effect already.
    sys.modules[spec.name] = value
    try:
        spec.loader.exec_module(value)
    except BaseException:
        del sys.modules[spec.name]
        raise
    return value


def terminate_active_private_case(private_runner: Any, cases_root: Path) -> None:
    """Kill a receipt leaf's own session before killing its Python supervisor."""
    record = private_runner.active_child_record(cases_root)
    try:
        mode = record.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode) or record.is_symlink():
        raise QualificationRunError("private admission active-child record is unsafe")
    try:
        value = record.read_text(encoding="ascii")
        process_group = int(value.strip(), 10)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise QualificationRunError("private admission active-child record is invalid") from error
    if process_group <= 0 or value != f"{process_group}\n":
        raise QualificationRunError("private admission active-child record is invalid")
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def terminate_private_admission_process(
    process: subprocess.Popen[bytes], private_runner: Any, cases_root: Path
) -> None:
    """Reap the nested leaf group before its owner can leave its pipes open."""
    terminate_active_private_case(private_runner, cases_root)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def private_case_receipts(transaction: Path) -> list[dict[str, object]]:
    """Load and seal the finite private roster written by its runner."""
    private_runner = private_admission_runner_module()
    cases_root = transaction / "cases"
    evidence_path(cases_root, transaction)
    source = source_identity()
    expected_cases = private_runner.load_contract()
    result: list[dict[str, object]] = []
    expected_names: set[str] = set()
    for order, case in enumerate(expected_cases, start=1):
        directory = private_runner.case_receipt_directory(case, cases_root)
        receipt = directory / "receipt.json"
        expected_names.add(directory.name)
        record = read_json(receipt, f"private case {case.identifier} receipt", directory)
        expected = {
            "schema": private_runner.CASE_RECEIPT_SCHEMA,
            "id": case.identifier,
            "family": case.family,
            "order": order,
            "runner": case.runner.relative_to(ROOT).as_posix(),
            "runner_sha256": manifest.sha256_file(case.runner),
            "command": ["bash", str(case.runner)],
            "expected_stdout_line": case.expected_stdout_line.decode("utf-8"),
            "timeout_seconds": case.timeout_seconds,
            "exit_status": 0,
            "outcome": "passed",
            "source_before": source,
            "source_after": source,
        }
        if any(record.get(name) != value for name, value in expected.items()):
            raise QualificationRunError(f"private case receipt drifted: {case.identifier}")
        if set(record) != set(expected) | {
            "started_at_unix_ns",
            "finished_at_unix_ns",
            "duration_ns",
            "stdout",
            "stderr",
            "artifacts",
        }:
            raise QualificationRunError(f"private case receipt fields drifted: {case.identifier}")
        timing = (record["started_at_unix_ns"], record["finished_at_unix_ns"], record["duration_ns"])
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in timing) or timing[1] < timing[0] or timing[2] != timing[1] - timing[0]:
            raise QualificationRunError(f"private case receipt timing drifted: {case.identifier}")
        for stream in ("stdout", "stderr"):
            value = record[stream]
            if not isinstance(value, Mapping) or set(value) != {"path", "sha256"} or not isinstance(value.get("path"), str) or not isinstance(value.get("sha256"), str):
                raise QualificationRunError(f"private case receipt {stream} is invalid: {case.identifier}")
            expected_path = f"{directory.name}/{stream}.log"
            if value["path"] != expected_path:
                raise QualificationRunError(f"private case receipt {stream} escapes its case: {case.identifier}")
            path = cases_root / expected_path
            if evidence_path(path, directory) != path or sha256_file(path, f"private {stream}") != value["sha256"]:
                raise QualificationRunError(f"private case receipt {stream} changed: {case.identifier}")
            if stream == "stdout":
                lines = [line for line in path.read_bytes().splitlines() if line]
                if lines.count(case.expected_stdout_line) != 1 or not lines or lines[-1] != case.expected_stdout_line:
                    raise QualificationRunError(f"private case receipt marker drifted: {case.identifier}")
        artifact = record["artifacts"]
        expected_artifact = private_runner.case_artifact_directory(case, cases_root)
        if expected_artifact is None:
            if artifact is not None:
                raise QualificationRunError(f"private case has unexpected retained artifacts: {case.identifier}")
        else:
            if not isinstance(artifact, Mapping) or set(artifact) != {"path", "entries"}:
                raise QualificationRunError(f"same-object artifact receipt is invalid")
            if artifact.get("path") != private_runner.receipt_relative(cases_root, expected_artifact):
                raise QualificationRunError("same-object artifact receipt path drifted")
            evidence_path(expected_artifact, directory)
            if artifact.get("entries") != private_runner.artifact_snapshot(expected_artifact):
                raise QualificationRunError("same-object retained artifact bytes changed")
        result.append(
            {
                "order": order,
                "id": case.identifier,
                "receipt": relative_evidence_path(transaction, receipt),
                "receipt_sha256": sha256_file(receipt, f"private case {case.identifier} receipt"),
            }
        )
    actual_names = set()
    for path in cases_root.iterdir():
        if path.is_symlink():
            raise QualificationRunError("private case receipt roster contains a symlink")
        if path.is_dir():
            actual_names.add(path.name)
        else:
            raise QualificationRunError("private case receipt roster has transient supervisor state")
    if actual_names != expected_names:
        raise QualificationRunError("private case receipt roster drifted")
    return result


def prefix_record(
    admission: Mapping[str, object],
    source_before: Mapping[str, str],
    source_after: Mapping[str, str],
    inputs_before: Mapping[str, object],
    inputs_after: Mapping[str, object],
    command: list[str],
    started_at_unix_ns: int,
    finished_at_unix_ns: int,
    exit_status: int,
    outcome: str,
    stdout_path: Path,
    stderr_path: Path,
    cases: list[dict[str, object]],
    error: str | None,
    transaction: Path,
) -> dict[str, object]:
    return {
        "schema": manifest.RECEIPT_SCHEMA,
        "kind": "private-admission-prefix",
        "id": admission["id"],
        "target": manifest.TARGET,
        "non_promoting": True,
        "promotion_ready": False,
        "completed_gate_count": 0,
        "case_manifest": admission["case_manifest"],
        "case_manifest_sha256": admission["case_manifest_sha256"],
        "runner_sha256": admission["runner_sha256"],
        "source_before": dict(source_before),
        "source_after": dict(source_after),
        "inputs_before": dict(inputs_before),
        "inputs_after": dict(inputs_after),
        "command": command,
        "started_at_unix_ns": started_at_unix_ns,
        "finished_at_unix_ns": finished_at_unix_ns,
        "duration_ns": finished_at_unix_ns - started_at_unix_ns,
        "exit_status": exit_status,
        "outcome": outcome,
        "stdout": {
            "path": relative_evidence_path(transaction, stdout_path),
            "sha256": sha256_file(stdout_path, "private admission stdout"),
        },
        "stderr": {
            "path": relative_evidence_path(transaction, stderr_path),
            "sha256": sha256_file(stderr_path, "private admission stderr"),
        },
        "cases": cases,
        "error": error,
    }


def validate_private_admission_receipt(path: Path) -> dict[str, object]:
    """Reject stale source, tool, log, runtime, or retained-artifact proof."""
    path = evidence_path(path)
    transaction = path.parent
    evidence_path(transaction)
    receipt = read_json(path, "private admission receipt", transaction)
    required = {
        "schema",
        "kind",
        "id",
        "target",
        "non_promoting",
        "promotion_ready",
        "completed_gate_count",
        "case_manifest",
        "case_manifest_sha256",
        "runner_sha256",
        "source_before",
        "source_after",
        "inputs_before",
        "inputs_after",
        "command",
        "started_at_unix_ns",
        "finished_at_unix_ns",
        "duration_ns",
        "exit_status",
        "outcome",
        "stdout",
        "stderr",
        "cases",
        "error",
    }
    if set(receipt) != required:
        raise QualificationRunError("private admission receipt fields drifted")
    report = manifest.load_contract()
    admission = select_private_admission(report)
    expected = {
        "schema": manifest.RECEIPT_SCHEMA,
        "kind": "private-admission-prefix",
        "id": admission["id"],
        "target": manifest.TARGET,
        "non_promoting": True,
        "promotion_ready": False,
        "completed_gate_count": 0,
        "case_manifest": admission["case_manifest"],
        "case_manifest_sha256": admission["case_manifest_sha256"],
        "runner_sha256": admission["runner_sha256"],
        "command": admission["command"],
        "outcome": "passed-non-promoting",
        "exit_status": 0,
        "error": None,
    }
    if any(receipt.get(name) != value for name, value in expected.items()):
        raise QualificationRunError("private admission receipt contract drifted")
    timing = (receipt["started_at_unix_ns"], receipt["finished_at_unix_ns"], receipt["duration_ns"])
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in timing) or timing[1] < timing[0] or timing[2] != timing[1] - timing[0]:
        raise QualificationRunError("private admission receipt timing drifted")
    source = source_identity()
    if receipt["source_before"] != source or receipt["source_after"] != source:
        raise QualificationRunError("private admission receipt source is stale")
    inputs = execution_inputs()
    if receipt["inputs_before"] != inputs or receipt["inputs_after"] != inputs:
        raise QualificationRunError("private admission receipt tool or runtime inputs drifted")
    verify_private_admission_runner(admission)
    for stream in ("stdout", "stderr"):
        record = receipt[stream]
        if not isinstance(record, Mapping) or set(record) != {"path", "sha256"}:
            raise QualificationRunError(f"private admission receipt {stream} is invalid")
        expected_path = f"{stream}.log"
        if record.get("path") != expected_path:
            raise QualificationRunError(f"private admission receipt {stream} escapes its transaction")
        stream_path = transaction / expected_path
        if evidence_path(stream_path, transaction) != stream_path or sha256_file(stream_path, stream) != record.get("sha256"):
            raise QualificationRunError(f"private admission receipt {stream} changed")
    cases = private_case_receipts(transaction)
    if receipt["cases"] != cases:
        raise QualificationRunError("private admission receipt case order or bytes drifted")
    return receipt


def run_private_admission(report: Mapping[str, object]) -> Path:
    """Execute the fixed five-case private prefix and seal its evidence.

    This is deliberately an admission transaction. Its receipt says only that
    this private ordered inventory executed against one clean revision; it
    cannot advance a promotion gate or make the full chain runnable.
    """
    admission = select_private_admission(report)
    verify_private_admission_runner(admission)
    require_pinned_native_execution()
    source_before = source_identity()
    private_runner = private_admission_runner_module()
    inputs_before = execution_inputs()
    transaction = transaction_directory(admission)
    cases_root = transaction / "cases"
    cases_root.mkdir(mode=0o755)
    command = list(admission["command"])
    environment = controlled_environment()
    environment["CRABC_QUALIFICATION_RECEIPT_ROOT"] = str(cases_root)
    started_at_unix_ns = time.time_ns()
    error: QualificationRunError | None = None
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(
            timeout=sum(case.timeout_seconds for case in private_runner.load_contract())
        )
    except subprocess.TimeoutExpired as timeout:
        terminate_private_admission_process(process, private_runner, cases_root)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired as cleanup:
            # The supervisor and its published leaf group were killed above.
            # Do not let a misbehaving descendant retaining a pipe turn a
            # bounded failed admission into an unbounded parent wait.
            stdout = cleanup.stdout or b""
            stderr = cleanup.stderr or b""
        error = QualificationRunError("private admission prefix timed out")
        error.__cause__ = timeout
    finished_at_unix_ns = time.time_ns()
    if error is None and process.returncode != 0:
        error = QualificationRunError(f"private admission prefix exited {process.returncode}")
    stdout_path = transaction / "stdout.log"
    stderr_path = transaction / "stderr.log"
    write_new_bytes(stdout_path, stdout)
    write_new_bytes(stderr_path, stderr)
    try:
        source_after = source_identity()
        if source_after != source_before:
            raise QualificationRunError("source changed during private admission receipt")
        inputs_after = execution_inputs()
        if inputs_after != inputs_before:
            raise QualificationRunError("tool or runtime input changed during private admission receipt")
        if error is None:
            cases = private_case_receipts(transaction)
        else:
            cases = []
    except QualificationRunError as failure:
        source_after = {"revision": "unavailable", "content_sha256": "unavailable"}
        inputs_after = {"unavailable": True}
        cases = []
        if error is None:
            error = failure
    record = prefix_record(
        admission,
        source_before,
        source_after,
        inputs_before,
        inputs_after,
        command,
        started_at_unix_ns,
        finished_at_unix_ns,
        process.returncode,
        "failed" if error is not None else "passed-non-promoting",
        stdout_path,
        stderr_path,
        cases,
        str(error) if error is not None else None,
        transaction,
    )
    receipt = transaction / "receipt.json"
    write_new_json(receipt, record)
    if error is not None:
        if stdout:
            sys.stderr.buffer.write(stdout)
        if stderr:
            sys.stderr.buffer.write(stderr)
        raise error
    validate_private_admission_receipt(receipt)
    return receipt


def select_promotion_prefix(report: Mapping[str, object], through: str) -> list[Mapping[str, object]]:
    """Select exactly the first N gates, with no skipped or imported dependency.

    All predecessors execute again in this invocation. A ready gate after a
    planned predecessor cannot be selected independently or inherit a private
    admission result as its missing dependency.
    """
    if through not in manifest.CHAIN:
        raise QualificationRunError(f"unknown qualification prefix endpoint: {through}")
    gates = report.get("promotion_chain")
    if not isinstance(gates, list) or tuple(gate.get("id") for gate in gates) != manifest.CHAIN:
        raise QualificationRunError("qualification prefix gate roster or order drifted")
    selected = gates[:manifest.CHAIN.index(through) + 1]
    blocked = [str(gate["id"]) for gate in selected if gate.get("state") != "ready"]
    if blocked:
        raise QualificationRunError("qualification prefix has planned dependencies: " + ", ".join(blocked))
    return selected


def incomplete_payload(report: Mapping[str, object]) -> str:
    return json.dumps({"target": manifest.TARGET["triple"], "promotion_ready": False, "incomplete_gates": report["incomplete_gates"], "private_admission": [row["id"] for row in report["private_admission"]], "runnable_prefix": report["runnable_prefix"], "reason": "private admission and ready declarations are not completion; source/tool/runtime/artifact-bound execution receipts remain required"}, indent=2, sort_keys=True)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-contract", action="store_true", help="validate planning and pins without native execution")
    parser.add_argument("--private-admission", action="store_true", help="execute and retain the fixed non-promoting private admission receipt")
    parser.add_argument("--through", choices=manifest.CHAIN, help="execute the ready prefix through this gate without a qualification claim")
    parser.add_argument("--validate-receipt", type=Path, help="revalidate one ignored private-admission receipt in the pinned native image")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argument_parser()
    parsed = parser.parse_args(arguments)
    operation_count = sum(
        bool(value)
        for value in (
            parsed.check_contract,
            parsed.private_admission,
            parsed.through,
            parsed.validate_receipt,
        )
    )
    if operation_count > 1:
        parser.error("select exactly one qualification operation")
    report = manifest.load_contract()
    # The checked-in generated projection is a second immutable handoff point:
    # a caller cannot execute a source contract while ignoring stale generated
    # state consumed by a future campaign integration.
    manifest.write_or_check(manifest.GENERATED_PATH, report, check=True)
    if parsed.check_contract:
        print(f"x86 qualification manifest contract: PASS ({len(report['promotion_chain'])} ordered gates; {report['ready_gate_count']} ready; no execution-completion claim)")
        return 0
    if parsed.validate_receipt is not None:
        require_pinned_native_execution()
        receipt = validate_private_admission_receipt(parsed.validate_receipt)
        print(f"x86 qualification private admission receipt: PASS ({receipt['id']}; non-promoting)")
        return 0
    if parsed.private_admission:
        receipt = run_private_admission(report)
        print(f"x86 qualification private admission receipt: PASS ({receipt}; non-promoting)")
        return 0
    if parsed.through is None:
        print(incomplete_payload(report), file=sys.stderr)
        return 1
    selected = select_promotion_prefix(report, parsed.through)
    # Validate every selected case manifest and runner before any case starts.
    # Immediate pre-Popen checks remain in run_case as well.
    cases = [(gate, load_case_manifest(gate)) for gate in selected]
    for gate, case_manifest in cases:
        for case in case_manifest["cases"]:
            verify_case_runner(gate, case)
    require_pinned_native_execution()
    for gate, case_manifest in cases:
        for case in case_manifest["cases"]:
            assert isinstance(case, Mapping)
            run_case(gate, case)
        print(f"x86 qualification prefix execution: {gate['id']}: PASS (non-promoting)")
    print(f"x86 qualification prefix execution: PASS (through {parsed.through}; execution receipts and final chain qualification remain required)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QualificationRunError, manifest.QualificationManifestError) as error:
        raise SystemExit(f"x86 qualification: ERROR: {error}") from error
