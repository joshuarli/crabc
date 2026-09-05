#!/usr/bin/env python3
"""Execute the closed private x86 POSIX/ABI qualification-admission inventory.

This consumes real selected static crabc-libc artifacts.  It is deliberately
not the future dynamic os-test, libc-test, pthread-stress, signal-process, or
full ABI-inventory gate, and it cannot promote the x86 platform.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "qualification_posix_abi.json"
EXPECTED_SCHEMA = "crabc.x86_64-qualification-posix-abi-admission/v1"
EXPECTED_ID = "qualification-posix-abi-admission"
EXPECTED_TARGET = "Linux/x86-64 little-endian"
CASE_RECEIPT_SCHEMA = "crabc.x86_64-qualification-case-receipt/v1"
RUST_BIN_DIRECTORY = "/opt/cargo/bin"
RUSTUP_HOME = "/opt/rustup"
CARGO_HOME = "/workspace/.work/x86_64/cargo"
TRUSTED_PATH = \
    RUST_BIN_DIRECTORY + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
RECEIPT_ROOT_ENVIRONMENT = "CRABC_QUALIFICATION_RECEIPT_ROOT"
ARTIFACT_DIRECTORY_ENVIRONMENT = "CRABC_QUALIFICATION_ARTIFACT_DIR"
EXPECTED_CASES = (
    (
        "same-object-static-c-abi",
        "compat.abi-differential",
        "compat/x86_64/run_libc_same_object_static_c_abi_differential.sh",
        "x86 static C ABI same-object differential: PASS (libc.a; pinned musl 1.2.6)",
        1200,
    ),
    (
        "static-process-context",
        "compat.posix-process",
        "compat/x86_64/run_libc_process_context.sh",
        "x86 static crabc-libc process context: PASS",
        1200,
    ),
    (
        "static-signal-execution",
        "compat.posix-process",
        "compat/x86_64/run_libc_signal_execution.sh",
        "x86 static crabc-libc signal execution: PASS",
        1200,
    ),
    (
        "static-child-reaping",
        "compat.posix-process",
        "compat/x86_64/run_libc_child_reaping.sh",
        "x86 static libc child reaping: PASS",
        1200,
    ),
    (
        "static-pthread-tls-aggregate",
        "compat.posix-process",
        "compat/x86_64/run_libc_pthread_tls_aggregate.sh",
        "x86 static crabc-libc pthread/TLS aggregate: PASS",
        1200,
    ),
)


class ContractError(ValueError):
    """The checked-in admission inventory is incomplete or has drifted."""


class EvidenceError(RuntimeError):
    """A selected native child transaction did not satisfy its contract."""


def digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"missing or unsafe receipt file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", *arguments],
        cwd=ROOT,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )


def require_clean_source() -> str:
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise EvidenceError("receipted admission requires clean committed source")
    return git("rev-parse", "HEAD").decode("utf-8").strip()


def source_identity() -> dict[str, str]:
    """Hash live tracked content and modes, independently of Git's index.

    Receipt mode also requires a clean worktree, but a content hash closes the
    interval around execution and makes the exact checked-out bytes explicit.
    Generated receipts live in ignored `.work`, so this does not hash itself.
    """
    names = sorted(
        name
        for name in git("ls-files", "-z").split(b"\0")
        if name
    )
    content = hashlib.sha256()
    for name in names:
        path = ROOT / os.fsdecode(name)
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise EvidenceError(f"tracked source is absent: {path}") from error
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        content.update(name + b"\0" + str(stat.S_IMODE(mode)).encode("ascii") + b"\0")
        content.update(hashlib.sha256(data).digest())
    return {
        "revision": require_clean_source(),
        "content_sha256": content.hexdigest(),
    }


@dataclass(frozen=True)
class Case:
    identifier: str
    family: str
    runner: Path
    expected_stdout_line: bytes
    timeout_seconds: int


def _exact_keys(value: dict[str, Any], expected: set[str], location: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        unexpected = ", ".join(sorted(actual - expected)) or "none"
        raise ContractError(
            f"{location} keys drifted (missing: {missing}; unexpected: {unexpected})"
        )


def load_contract(path: Path = CONTRACT_PATH) -> tuple[Case, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read qualification contract: {error}") from error
    if not isinstance(document, dict):
        raise ContractError("qualification contract must be an object")
    _exact_keys(document, {"schema", "id", "target", "cases"}, "contract")
    if document["schema"] != EXPECTED_SCHEMA:
        raise ContractError("qualification contract schema drifted")
    if document["id"] != EXPECTED_ID:
        raise ContractError("qualification contract id drifted")
    if document["target"] != EXPECTED_TARGET:
        raise ContractError("qualification target drifted")
    records = document["cases"]
    if not isinstance(records, list):
        raise ContractError("qualification cases must be an array")

    actual_records: list[tuple[str, str, str, str, int]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ContractError(f"cases[{index}] must be an object")
        _exact_keys(
            record,
            {
                "id",
                "family",
                "runner",
                "expected_stdout_line",
                "timeout_seconds",
            },
            f"cases[{index}]",
        )
        values = (
            record["id"],
            record["family"],
            record["runner"],
            record["expected_stdout_line"],
            record["timeout_seconds"],
        )
        if not all(isinstance(value, str) and value for value in values[:4]):
            raise ContractError(f"cases[{index}] has an empty non-string field")
        if not isinstance(values[4], int) or isinstance(values[4], bool):
            raise ContractError(f"cases[{index}] timeout must be an integer")
        actual_records.append(values)
    if tuple(actual_records) != EXPECTED_CASES:
        raise ContractError("qualification case roster or order drifted")

    cases: list[Case] = []
    for identifier, family, runner_text, marker, timeout_seconds in actual_records:
        runner = (ROOT / runner_text).resolve()
        try:
            runner.relative_to(ROOT)
        except ValueError as error:
            raise ContractError(f"case {identifier} runner escapes the repository") from error
        if runner.suffix != ".sh" or not runner.is_file():
            raise ContractError(f"case {identifier} runner is not a checked-in shell file")
        cases.append(
            Case(
                identifier=identifier,
                family=family,
                runner=runner,
                expected_stdout_line=marker.encode("utf-8"),
                timeout_seconds=timeout_seconds,
            )
        )
    return tuple(cases)


def validate_completed_process(
    case: Case, returncode: int, stdout: bytes, stderr: bytes
) -> None:
    if returncode != 0:
        raise EvidenceError(f"{case.identifier} exited {returncode}")
    nonempty_lines = [line for line in stdout.splitlines() if line]
    if nonempty_lines.count(case.expected_stdout_line) != 1:
        raise EvidenceError(
            f"{case.identifier} did not emit its unique completion marker"
        )
    if not nonempty_lines or nonempty_lines[-1] != case.expected_stdout_line:
        raise EvidenceError(
            f"{case.identifier} wrote output after its completion marker"
        )
    # Child gates own and validate their runtime streams.  Cargo and binutils
    # diagnostics from the build transaction remain visible here on failure;
    # they are not normalized or used as a success oracle.
    del stderr


def controlled_environment() -> dict[str, str]:
    """Return the receipt runner's fixed, scrubbed child environment.

    Cargo's cache remains checkout-local, while rustup and the selected binary
    directory stay at the image-pinned locations.  No ambient variable can
    redirect a compiler, loader, Python import, or shell startup boundary.
    """
    return {
        "PATH": TRUSTED_PATH,
        "RUSTUP_HOME": RUSTUP_HOME,
        "CARGO_HOME": CARGO_HOME,
        "CRABC_WORK_DIR": "/workspace/.work/x86_64",
        "TMPDIR": "/workspace/.work/x86_64/tmp",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }


def receipt_root_from_environment() -> Path | None:
    value = os.environ.get(RECEIPT_ROOT_ENVIRONMENT)
    if value is None:
        return None
    root = Path(value)
    work = ROOT / ".work"
    try:
        root.relative_to(work)
    except ValueError as error:
        raise EvidenceError("receipt root escapes checkout .work") from error
    if not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise EvidenceError("receipt root must be a physical pre-created checkout .work directory")
    return root


def case_receipt_directory(case: Case, root: Path) -> Path:
    index = next(index for index, entry in enumerate(EXPECTED_CASES, start=1) if entry[0] == case.identifier)
    return root / f"{index:03d}-{case.identifier}"


def case_artifact_directory(case: Case, root: Path) -> Path | None:
    if case.identifier != "same-object-static-c-abi":
        return None
    return case_receipt_directory(case, root) / "artifacts"


def write_new_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o444)


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    write_new_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def receipt_relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError as error:
        raise EvidenceError("receipt path escapes its transaction") from error


def artifact_snapshot(root: Path) -> dict[str, dict[str, Any]]:
    """Describe retained evidence without following a symlink out of it."""
    if not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise EvidenceError("retained artifact directory is not physical")
    result: dict[str, dict[str, Any]] = {}
    pending = [root]
    while pending:
        path = pending.pop()
        for child in sorted(path.iterdir(), reverse=True):
            mode = child.lstat().st_mode
            relative = child.relative_to(root).as_posix()
            entry: dict[str, Any] = {"mode": stat.S_IMODE(mode)}
            if stat.S_ISREG(mode):
                entry.update({"type": "regular", "sha256": digest(child)})
            elif stat.S_ISDIR(mode):
                if child.is_symlink():
                    raise EvidenceError("retained artifact directory symlink is unsafe")
                entry["type"] = "directory"
                pending.append(child)
            elif stat.S_ISLNK(mode):
                entry.update({"type": "symlink", "target": os.readlink(child)})
            else:
                raise EvidenceError("retained artifact has an unsupported file type")
            result[relative] = entry
    if not result:
        raise EvidenceError("same-object ABI harness did not retain artifacts")
    return dict(sorted(result.items()))


def case_receipt(
    case: Case,
    order: int,
    receipt_root: Path,
    command: list[str],
    started_at_unix_ns: int,
    finished_at_unix_ns: int,
    returncode: int,
    outcome: str,
    stdout: bytes,
    stderr: bytes,
    source_before: dict[str, str],
    source_after: dict[str, str],
    runner_sha256: str,
) -> Path:
    directory = case_receipt_directory(case, receipt_root)
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir() or directory.resolve() != directory:
            raise EvidenceError(f"case receipt directory is unsafe: {directory}")
        if case_artifact_directory(case, receipt_root) is None:
            raise EvidenceError(f"case receipt already exists: {directory}")
    else:
        directory.mkdir(mode=0o755)
    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    write_new_bytes(stdout_path, stdout)
    write_new_bytes(stderr_path, stderr)
    artifacts = case_artifact_directory(case, receipt_root)
    artifact_record: dict[str, Any] | None = None
    if artifacts is not None:
        artifact_record = {
            "path": receipt_relative(receipt_root, artifacts),
            "entries": artifact_snapshot(artifacts),
        }
    record = {
        "schema": CASE_RECEIPT_SCHEMA,
        "id": case.identifier,
        "family": case.family,
        "order": order,
        "runner": case.runner.relative_to(ROOT).as_posix(),
        "runner_sha256": runner_sha256,
        "command": command,
        "expected_stdout_line": case.expected_stdout_line.decode("utf-8"),
        "timeout_seconds": case.timeout_seconds,
        "started_at_unix_ns": started_at_unix_ns,
        "finished_at_unix_ns": finished_at_unix_ns,
        "duration_ns": finished_at_unix_ns - started_at_unix_ns,
        "exit_status": returncode,
        "outcome": outcome,
        "stdout": {"path": receipt_relative(receipt_root, stdout_path), "sha256": digest(stdout_path)},
        "stderr": {"path": receipt_relative(receipt_root, stderr_path), "sha256": digest(stderr_path)},
        "source_before": source_before,
        "source_after": source_after,
        "artifacts": artifact_record,
    }
    path = directory / "receipt.json"
    write_new_json(path, record)
    os.chmod(directory, 0o555, follow_symlinks=False)
    return path


def run_case(case: Case, receipt_root: Path | None = None, order: int | None = None) -> Path | None:
    command = ["bash", str(case.runner)]
    environment = controlled_environment()
    artifact_directory: Path | None = None
    source_before: dict[str, str] | None = None
    if receipt_root is not None:
        if order is None:
            raise EvidenceError("receipted case has no execution order")
        source_before = source_identity()
        artifact_directory = case_artifact_directory(case, receipt_root)
        if artifact_directory is not None:
            artifact_directory.mkdir(parents=True, mode=0o755)
            environment[ARTIFACT_DIRECTORY_ENVIRONMENT] = str(artifact_directory)
    # Capture the runner bytes at the direct execution boundary. The source
    # snapshots around it make a post-run rehash an independent check.
    runner_sha256 = digest(case.runner)
    started_at_unix_ns = time.time_ns()
    outcome = "passed"
    error: EvidenceError | None = None
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=case.timeout_seconds)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        outcome = "timed-out"
        failure = EvidenceError(f"{case.identifier} timed out after {case.timeout_seconds}s")
        failure.__cause__ = error
        error = failure
    try:
        if error is None:
            validate_completed_process(case, process.returncode, stdout, stderr)
    except EvidenceError as failure:
        outcome = "failed"
        error = failure
    finished_at_unix_ns = time.time_ns()
    receipt_path: Path | None = None
    if receipt_root is not None:
        assert source_before is not None and order is not None
        try:
            source_after = source_identity()
            if source_after != source_before:
                raise EvidenceError("source changed during receipted admission case")
        except EvidenceError as failure:
            source_after = {"revision": "unavailable", "content_sha256": "unavailable"}
            if error is None:
                outcome = "failed"
                error = failure
        receipt_path = case_receipt(
            case,
            order,
            receipt_root,
            command,
            started_at_unix_ns,
            finished_at_unix_ns,
            process.returncode,
            outcome,
            stdout,
            stderr,
            source_before,
            source_after,
            runner_sha256,
        )
    if error is not None:
        if stdout:
            sys.stderr.buffer.write(stdout)
        if stderr:
            sys.stderr.buffer.write(stderr)
        raise error
    return receipt_path


def require_native_linux_x86_64() -> None:
    if platform.system() != "Linux":
        raise EvidenceError("qualification admission requires native Linux")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise EvidenceError(
            f"qualification admission refuses emulation on {platform.machine()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-contract",
        action="store_true",
        help="validate the closed inventory without executing native artifacts",
    )
    arguments = parser.parse_args()
    cases = load_contract()
    if arguments.check_contract:
        print(f"x86 qualification POSIX/ABI contract: PASS ({len(cases)} cases)")
        return 0

    require_native_linux_x86_64()
    receipt_root = receipt_root_from_environment()
    for order, case in enumerate(cases, start=1):
        run_case(case, receipt_root, order if receipt_root is not None else None)
        print(f"x86 qualification POSIX/ABI admission: {case.identifier}: PASS")
    print(
        "x86 qualification POSIX/ABI admission: PASS "
        f"({len(cases)} selected artifact transactions; non-promoting"
        + ("; receipts retained)" if receipt_root is not None else ")")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, EvidenceError) as error:
        raise SystemExit(f"x86 qualification POSIX/ABI admission: ERROR: {error}") from error
