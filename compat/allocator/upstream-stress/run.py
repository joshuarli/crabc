#!/usr/bin/env python3
"""Run the exact pinned mimalloc upstream stress source through selected crabc libc.

This is deliberately separate from the reviewed ``native-shadow-stress``
fixture. That fixture applies a source patch which moves transferred-object
cleanup into fresh pthreads. This lane does not apply a patch or copy the
source: it verifies and compiles the archived ``test/test-stress.c`` with the
upstream ``USE_STD_MALLOC`` conditional enabled, so standard allocation names
bind to the selected native-mimalloc-shadow ``libc.so``.

The lane runs exactly once at the smallest audited configuration, records the
first runtime failure or pass fact atomically, and never retries with a changed
schedule. It is a failure-preservation gate, not an allocator promotion claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
ALLOCATOR_ROOT = ROOT / "compat/allocator"
CONTRACT_PATH = ALLOCATOR_ROOT / "upstream-stress-v3.5.0.json"
UPSTREAMS_PATH = ROOT / "compat/upstreams.toml"
CACHE = ALLOCATOR_ROOT / ".cache"
DEFAULT_TARGET_DIR = ROOT / "target/debug"
DEFAULT_OUTPUT_DIR = ROOT / "target/compat/allocator/upstream-stress"
DEFAULT_REPORT = ROOT / "compat/reports/allocator/upstream-stress/latest.json"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
FIXED_PIN = {
    "version": "3.5.0",
    "repository": "https://github.com/microsoft/mimalloc.git",
    "tag": "v3.5.0",
    "source": "https://codeload.github.com/microsoft/mimalloc/tar.gz/refs/tags/v3.5.0",
    "sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
    "tag_object": "438b0c4b78d2599aede7fca3ddacc28863b0eae8",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "archive_root": "mimalloc-3.5.0",
}


class EvidenceError(RuntimeError):
    """The canonical workload could not establish its one recorded fact."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bytes_record(value: bytes) -> dict[str, Any]:
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "hex": value.hex(),
    }


def file_record(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    return {
        "bytes": path.stat().st_size,
        "path": relative_path(path, root),
        "sha256": sha256_file(path),
    }


def relative_path(path: Path, root: Path | None = None) -> str:
    resolved = path.expanduser().resolve()
    if root is not None:
        try:
            return str(resolved.relative_to(root.resolve()))
        except ValueError:
            pass
    return str(resolved)


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            exactly_matches(left, right) for left, right in zip(observed, expected)
        )
    return observed == expected


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read canonical upstream stress contract: {path}") from error
    if not isinstance(value, dict):
        raise EvidenceError("canonical upstream stress contract must be a JSON object")
    return value


def load_mimalloc_pin(path: Path = UPSTREAMS_PATH) -> dict[str, str]:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"cannot read upstream pin file: {path}") from error
    pin = raw.get("mimalloc")
    if not isinstance(pin, dict):
        raise EvidenceError("compat/upstreams.toml requires a [mimalloc] table")
    required = (
        "version",
        "repository",
        "tag",
        "source",
        "sha256",
        "tag_object",
        "revision",
        "archive_root",
    )
    if any(not isinstance(pin.get(key), str) or not pin[key] for key in required):
        raise EvidenceError("mimalloc pin has a missing or invalid required identity")
    normalized = {key: str(pin[key]) for key in required}
    if not exactly_matches(normalized, FIXED_PIN):
        raise EvidenceError("canonical upstream stress is fixed to mimalloc v3.5.0")
    return normalized


def expected_contract(pin: Mapping[str, str]) -> dict[str, Any]:
    """Return the closed contract this lane accepts.

    Keeping the values in one executable shape means a prose edit cannot
    silently turn the canonical source gate into another adapted fixture.
    """

    upstream = {
        "project": "microsoft/mimalloc",
        "version": pin["version"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
        "repository": pin["repository"],
        "archive_source": pin["source"],
        "archive_path": "compat/allocator/.cache/mimalloc-3.5.0.tar.gz",
        "archive_root": pin["archive_root"],
        "archive_sha256": pin["sha256"],
    }
    return {
        "format": 1,
        "schema": "crabc-mimalloc-canonical-upstream-stress",
        "scope": {
            "claim": "one canonical executable of the exact pinned upstream test/test-stress.c through the selected native-mimalloc-shadow crabc libc",
            "not_a_promotion_gate": True,
            "purpose": "record the first smallest upstream failure or pass without changing upstream scheduling, transfer ownership, or initial-thread cleanup",
        },
        "upstream": upstream,
        "fixture": {
            "archive_member": "test/test-stress.c",
            "sha256": "e2bed5f2be12239b1fa696dafffda384d19140cb50a6ee2f6e096f70934d73df",
            "upstream_file_license": "MIT",
            "upstream_notice": "Copyright (c) 2018-2026 Microsoft Research, Daan Leijen",
        },
        "source_adaptation": {
            "kind": "upstream-preprocessor-symbol-selection-only",
            "compile_defines": ["USE_STD_MALLOC"],
            "patches": [],
            "forbidden_changes": [
                "checked-in source copy or patch",
                "worker scheduling change",
                "transfer ownership change",
                "post-worker cleanup relocation",
                "initial-thread cleanup change",
            ],
            "explanation": "USE_STD_MALLOC is an upstream conditional that binds custom allocation names to calloc, realloc, and free. The archived source is compiled byte-for-byte after its hash is verified.",
        },
        "execution": {
            "arguments": ["1", "1", "1"],
            "watchdog_seconds": 30,
            "process_attempt_count": 1,
            "expected_stdout": "Using 1 threads with a 1% load-per-thread and 1 iterations\n",
            "expected_stderr": "",
            "expected_exit_status": 0,
            "scheduler_and_ownership": [
                "The unmodified upstream main_participates value remains false.",
                "The unmodified upstream run_os_threads creates and joins the requested pthread workers before returning to test_stress.",
                "The unmodified upstream shared transfer buffer carries live allocations between source workers and source iterations.",
                "After run_os_threads returns, the unmodified initial thread performs free_items cleanup of transferred objects in test_stress.",
            ],
        },
        "compile_requirements": {
            "allocator_feature": "native-mimalloc-shadow",
            "compiler": "crabc-cc from the installed owned crabc sysroot",
            "language": "C11",
            "compile_flags": ["-O2", "-DNDEBUG", "-fPIE", "-pie", "-ftls-model=initial-exec", "-pthread"],
            "include_directories": ["<extracted-root>/include"],
            "link_flags": ["-Wl,--allow-shlib-undefined"],
            "link_libraries": ["-lc"],
            "expected_dynamic_dependencies": ["libc.so"],
            "canonical_loader": "/lib/ld-crabc-aarch64.so.1",
            "owned_test_launcher": "scripts/run_owned_test_suite.py",
            "selected_runtime_directory": "target/debug",
            "isolated_output_directory": "target/compat/allocator/upstream-stress",
            "notes": "The caller builds crabc-libc with native-mimalloc-shadow last. The lane then compiles the exact archive member through the owned driver, selects that debug libc with LD_LIBRARY_PATH, and has no source-level adaptation beyond the upstream USE_STD_MALLOC symbol.",
        },
    }


def load_contract() -> tuple[dict[str, Any], dict[str, str]]:
    pin = load_mimalloc_pin()
    contract = read_json(CONTRACT_PATH)
    expected = expected_contract(pin)
    if not exactly_matches(contract, expected):
        raise EvidenceError("canonical upstream stress contract drifted from its closed execution boundary")
    return contract, pin


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="require the SHA-256-verified pinned archive to already be cached",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the source, build, and ownership contract without compiling or running it",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", DEFAULT_TARGET_DIR)),
        help="selected debug libc and loader directory (default: CRABC_TARGET_DIR or target/debug)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_UPSTREAM_STRESS_OUTPUT_DIR", DEFAULT_OUTPUT_DIR)),
        help="isolated fixture output directory (default: CRABC_UPSTREAM_STRESS_OUTPUT_DIR or target/compat/allocator/upstream-stress)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(os.environ.get("CRABC_UPSTREAM_STRESS_REPORT", DEFAULT_REPORT)),
        help="JSON report path (default: CRABC_UPSTREAM_STRESS_REPORT or compat/reports/allocator/upstream-stress/latest.json)",
    )
    return parser.parse_args(arguments)


def archive_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tar.gz"


def tag_attestation_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tag.json"


def verify_archive(path: Path, pin: Mapping[str, str]) -> Path:
    if not path.is_file():
        raise EvidenceError(f"pinned mimalloc archive is unavailable: {path}")
    actual = sha256_file(path)
    if actual != pin["sha256"]:
        raise EvidenceError(
            "pinned mimalloc archive SHA-256 mismatch: "
            f"expected {pin['sha256']}, observed {actual}"
        )
    return path


def fetch_archive(pin: Mapping[str, str], *, offline: bool) -> Path:
    archive = archive_path(pin)
    if archive.exists():
        verified = verify_archive(archive, pin)
        verify_tag_identity(pin, offline=offline)
        return verified
    if offline:
        raise EvidenceError(
            "verified pinned mimalloc archive is absent from offline cache: "
            f"{archive}"
        )
    CACHE.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(pin["source"], timeout=30) as response:
            payload = response.read()
    except urllib.error.URLError as error:
        raise EvidenceError(f"failed to download pinned mimalloc archive: {error}") from error
    digest = hashlib.sha256(payload).hexdigest()
    if digest != pin["sha256"]:
        raise EvidenceError(
            "downloaded pinned mimalloc archive SHA-256 mismatch: "
            f"expected {pin['sha256']}, observed {digest}"
        )
    with tempfile.NamedTemporaryFile(dir=CACHE, prefix="mimalloc-download-", delete=False) as stream:
        stream.write(payload)
        staged = Path(stream.name)
    os.replace(staged, archive)
    verified = verify_archive(archive, pin)
    verify_tag_identity(pin, offline=False)
    return verified


def extract_exact_archive(archive: Path, pin: Mapping[str, str], destination: Path) -> Path:
    """Extract the oracle safely, retaining its root exactly once."""

    destination.mkdir(parents=True, exist_ok=True)
    root_name = pin["archive_root"]
    root = destination / root_name
    try:
        with tarfile.open(archive, "r:gz") as stream:
            members = stream.getmembers()
            for member in members:
                name = PurePosixPath(member.name)
                if not name.parts or name.parts[0] != root_name or ".." in name.parts:
                    raise EvidenceError(f"pinned archive member escapes expected root: {member.name}")
                if not (member.isdir() or member.isfile()):
                    raise EvidenceError(
                        f"pinned archive contains unsupported link/device member: {member.name}"
                    )
            for member in members:
                output = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                source = stream.extractfile(member)
                if source is None:
                    raise EvidenceError(f"cannot read pinned archive member: {member.name}")
                with source, output.open("wb") as target:
                    shutil.copyfileobj(source, target)
    except (OSError, tarfile.TarError) as error:
        raise EvidenceError(f"cannot extract pinned mimalloc archive: {archive}") from error
    if not root.is_dir():
        raise EvidenceError(f"pinned archive root was not extracted: {root}")
    return root


def require_native_aarch64() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise EvidenceError(
            "canonical upstream stress requires native Linux/AArch64; "
            f"observed {platform.system()}/{platform.machine()}"
        )


def require_runtime_inputs(target_dir: Path) -> tuple[Path, Path, Path]:
    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise EvidenceError(
            "canonical upstream stress requires CRABC_TEST_SYSROOT from "
            "scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    manifest = sysroot / "share/crabc/manifest.json"
    compiler = sysroot / "bin/crabc-cc"
    if not manifest.is_file() or not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise EvidenceError("canonical upstream stress requires a complete owned crabc sysroot")
    target_dir = target_dir.expanduser().resolve()
    for name in ("libc.so", "libldso.so"):
        artifact = target_dir / name
        if not artifact.is_file() or artifact.is_symlink():
            raise EvidenceError(f"selected crabc runtime artifact is unavailable: {artifact}")
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise EvidenceError(
            "canonical upstream stress must run under scripts/run_owned_test_suite.py "
            "canonical-loader staging"
        )
    return sysroot, compiler, target_dir


def command_record(
    command: Sequence[str], *, cwd: Path, environment: Mapping[str, str] | None = None, timeout: int | None = None
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=None if environment is None else dict(environment),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        return {
            "command": list(command),
            "kind": "execution-error",
            "message": str(error),
            "status": "execution-error",
        }
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        return {
            "command": list(command),
            "kind": "timeout",
            "status": "timeout",
            "stdout": bytes_record(stdout),
            "stderr": bytes_record(stderr),
            "timeout_seconds": timeout,
        }
    return {
        "command": list(command),
        "kind": "process",
        "status": completed.returncode,
        "stdout": bytes_record(completed.stdout),
        "stderr": bytes_record(completed.stderr),
    }


def cached_tag_attestation(pin: Mapping[str, str]) -> dict[str, Any] | None:
    path = tag_attestation_path(pin)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    expected = {
        "format": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
    }
    return value if exactly_matches(value, expected) else None


def verify_tag_identity(pin: Mapping[str, str], *, offline: bool) -> dict[str, Any]:
    """Verify the annotated v3.5.0 tag before accepting its source archive."""

    cached = cached_tag_attestation(pin)
    if cached is not None:
        return cached
    if offline:
        raise EvidenceError(
            "verified mimalloc tag identity is absent from offline cache: "
            f"{tag_attestation_path(pin)}"
        )
    git = shutil.which("git")
    if git is None:
        raise EvidenceError("git is required to verify the pinned mimalloc annotated tag")
    reference = f"refs/tags/{pin['tag']}"
    peeled = reference + "^{}"
    record = command_record((git, "ls-remote", pin["repository"], reference, peeled), cwd=ROOT)
    if record.get("kind") != "process" or record.get("status") != 0:
        raise EvidenceError(f"mimalloc annotated tag identity probe failed: {record}")
    stdout = record.get("stdout")
    if not isinstance(stdout, dict):
        raise EvidenceError("mimalloc annotated tag identity probe had no stdout record")
    identities: dict[str, str] = {}
    for line in bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict").splitlines():
        object_id, separator, name = line.partition("\t")
        if separator and re.fullmatch(r"[0-9a-f]{40}", object_id):
            identities[name] = object_id
    if identities.get(reference) != pin["tag_object"] or identities.get(peeled) != pin["revision"]:
        raise EvidenceError(
            "mimalloc annotated tag identity mismatch: "
            f"expected tag {pin['tag_object']} peeled {pin['revision']}, "
            f"observed tag {identities.get(reference)!r} peeled {identities.get(peeled)!r}"
        )
    attestation = {
        "format": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
    }
    write_json(tag_attestation_path(pin), attestation)
    return attestation


def dynamic_dependencies(binary: Path) -> list[str]:
    readelf = shutil.which("readelf")
    if readelf is None:
        raise EvidenceError("readelf is required to verify the fixture's dynamic dependency boundary")
    record = command_record((readelf, "-d", str(binary)), cwd=ROOT)
    if record.get("status") != 0:
        raise EvidenceError(f"readelf could not inspect canonical stress fixture: {record}")
    stderr = record["stderr"]
    stdout = record["stdout"]
    assert isinstance(stderr, dict) and isinstance(stdout, dict)
    if stderr["bytes"] != 0:
        raise EvidenceError("readelf wrote diagnostics while inspecting canonical stress fixture")
    output = bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict")
    return re.findall(r"\(NEEDED\).*?\[(.*?)\]", output)


def build_command(
    compiler: Path, source_root: Path, source_member: str, target_dir: Path, binary: Path, contract: Mapping[str, Any]
) -> list[str]:
    requirements = contract["compile_requirements"]
    adaptation = contract["source_adaptation"]
    assert isinstance(requirements, dict) and isinstance(adaptation, dict)
    flags = requirements["compile_flags"]
    defines = adaptation["compile_defines"]
    link_flags = requirements["link_flags"]
    libraries = requirements["link_libraries"]
    assert all(isinstance(value, list) for value in (flags, defines, link_flags, libraries))
    return [
        str(compiler),
        "-std=c11",
        *flags,
        *(f"-D{value}" for value in defines),
        "-I",
        str(source_root / "include"),
        "-L",
        str(target_dir),
        str(source_root / source_member),
        *link_flags,
        *libraries,
        "-o",
        str(binary),
    ]


def runtime_environment(target_dir: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for name in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
        environment.pop(name, None)
    environment["LD_LIBRARY_PATH"] = str(target_dir)
    return environment


def report_base(contract: Mapping[str, Any], pin: Mapping[str, str], args: argparse.Namespace) -> dict[str, Any]:
    fixture = contract["fixture"]
    adaptation = contract["source_adaptation"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(adaptation, dict) and isinstance(execution, dict)
    return {
        "format": 1,
        "schema": "crabc-mimalloc-canonical-upstream-stress-report",
        "status": "failed",
        "contract": {
            "path": relative_path(CONTRACT_PATH, ROOT),
            "sha256": sha256_file(CONTRACT_PATH),
            "upstream": dict(contract["upstream"]),
        },
        "fixture": {
            "archive_member": fixture["archive_member"],
            "expected_sha256": fixture["sha256"],
            "source_adaptation": {
                "compile_defines": list(adaptation["compile_defines"]),
                "patches": list(adaptation["patches"]),
            },
        },
        "execution": {
            "arguments": list(execution["arguments"]),
            "process_attempt_count": execution["process_attempt_count"],
            "watchdog_seconds": execution["watchdog_seconds"],
        },
        "requested_runtime": {
            "allocator_feature": contract["compile_requirements"]["allocator_feature"],
            "target_dir": relative_path(args.target_dir, ROOT),
            "output_dir": relative_path(args.output_dir, ROOT),
        },
        "target": {"architecture": platform.machine(), "system": platform.system()},
        "first_fact": None,
        "upstream_pin": dict(pin),
    }


def successful_run(record: Mapping[str, Any], execution: Mapping[str, Any]) -> bool:
    if record.get("kind") != "process" or record.get("status") != execution["expected_exit_status"]:
        return False
    stdout = record.get("stdout")
    stderr = record.get("stderr")
    if not isinstance(stdout, dict) or not isinstance(stderr, dict):
        return False
    return (
        bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict")
        == execution["expected_stdout"]
        and bytes.fromhex(str(stderr["hex"])).decode("utf-8", errors="strict")
        == execution["expected_stderr"]
    )


def execute(contract: Mapping[str, Any], pin: Mapping[str, str], args: argparse.Namespace, report: dict[str, Any]) -> None:
    require_native_aarch64()
    archive = fetch_archive(pin, offline=args.offline)
    report["archive"] = file_record(archive, root=ROOT)
    attestation = cached_tag_attestation(pin)
    if attestation is None:
        raise EvidenceError("pinned archive was accepted without a tag attestation")
    report["tag_attestation"] = attestation
    sysroot, compiler, target_dir = require_runtime_inputs(args.target_dir)
    report["runtime"] = {
        "compiler": relative_path(compiler, ROOT),
        "loader": file_record(target_dir / "libldso.so", root=ROOT),
        "selected_libc": file_record(target_dir / "libc.so", root=ROOT),
        "sysroot": relative_path(sysroot, ROOT),
    }

    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = output_dir / "canonical-upstream-test-stress"
    fixture = contract["fixture"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(execution, dict)

    with tempfile.TemporaryDirectory(prefix="pinned-source-", dir=output_dir) as temporary:
        source_root = extract_exact_archive(archive, pin, Path(temporary))
        source = source_root / str(fixture["archive_member"])
        if not source.is_file() or sha256_file(source) != fixture["sha256"]:
            raise EvidenceError("canonical stress source differs from the pinned archive member")
        report["fixture"]["observed_source"] = file_record(source)
        build = command_record(
            build_command(compiler, source_root, str(fixture["archive_member"]), target_dir, binary, contract),
            cwd=source_root,
        )
    report["build"] = build
    if build.get("kind") != "process" or build.get("status") != 0:
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "build",
            "observation": build,
        }
        return

    report["artifact"] = file_record(binary, root=ROOT)
    dependencies = dynamic_dependencies(binary)
    report["dynamic_dependencies"] = dependencies
    requirements = contract["compile_requirements"]
    assert isinstance(requirements, dict)
    if dependencies != requirements["expected_dynamic_dependencies"]:
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "dynamic-link-boundary",
            "observed_dependencies": dependencies,
            "expected_dependencies": requirements["expected_dynamic_dependencies"],
        }
        return

    run = command_record(
        [str(binary), *execution["arguments"]],
        cwd=output_dir,
        environment=runtime_environment(target_dir),
        timeout=int(execution["watchdog_seconds"]),
    )
    report["execution"]["attempts"] = [run]
    if successful_run(run, execution):
        report["status"] = "passed"
        report["first_fact"] = {
            "kind": "pass",
            "stage": "run",
            "process_attempt": 1,
            "observation": run,
        }
        return
    report["first_fact"] = {
        "kind": "first-failure",
        "stage": "run",
        "process_attempt": 1,
        "observation": run,
        "expected": {
            "exit_status": execution["expected_exit_status"],
            "stderr": execution["expected_stderr"],
            "stdout": execution["expected_stdout"],
        },
    }


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        staged = Path(stream.name)
    os.replace(staged, path)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_arguments(arguments)
    try:
        contract, pin = load_contract()
        if args.check:
            print(json.dumps({"contract": relative_path(CONTRACT_PATH, ROOT), "status": "passed"}, sort_keys=True))
            return 0
        report = report_base(contract, pin, args)
        try:
            execute(contract, pin, args, report)
        except EvidenceError as error:
            report["first_fact"] = {
                "kind": "first-failure",
                "stage": "harness",
                "message": str(error),
            }
        write_json(args.report, report)
        print(args.report.expanduser().resolve())
        return 0 if report["status"] == "passed" else 1
    except EvidenceError as error:
        print(f"canonical-upstream-stress: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
