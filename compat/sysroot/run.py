#!/usr/bin/env python3
"""Run owned-sysroot mode, isolation, and artifact evidence.

The runner is intentionally strict: a missing crabc-owned sysroot is a setup
failure, not an invitation to borrow musl CRT objects or ambient target search
paths.  It writes the current report atomically even when a fixture fails so a
red hard gate retains its exact command and diagnostic evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import platform
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import time
from pathlib import Path
from typing import Any, Iterator, Sequence


ROOT = Path(__file__).resolve().parents[2]
HARNESS_ROOT = Path(__file__).resolve().parent
TOOL_PATH = ROOT / "scripts/crabc_sysroot.py"
FIXTURES = HARNESS_ROOT / "fixtures"
MANIFEST = HARNESS_ROOT / "manifest.toml"
DEFAULT_SYSROOT = ROOT / "target/crabc-sysroot"
DEFAULT_REPORT = ROOT / "compat/reports/sysroot/latest.json"
DEFAULT_TIMEOUT = 60.0
MAX_TIMEOUT = 300.0


SPEC = importlib.util.spec_from_file_location("crabc_sysroot_tool", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOL
SPEC.loader.exec_module(TOOL)


class RunnerError(RuntimeError):
    """A host setup, fixture, or ownership-contract failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_manifest(path: Path = MANIFEST) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"invalid sysroot harness manifest: {path}") from error
    target = value.get("target")
    fixtures = value.get("fixtures")
    if not isinstance(target, dict) or not isinstance(fixtures, dict):
        raise RunnerError("sysroot harness manifest requires [target] and [fixtures]")
    if target.get("triple") != TOOL.TARGET_TRIPLE or target.get("interpreter") != TOOL.CANONICAL_INTERPRETER:
        raise RunnerError("sysroot harness manifest does not identify the crabc target")
    for key in (
        "main",
        "shared",
        "header_trace",
        "startup_contract",
        "exit_contract",
        "exit_contract_dso",
        "cxa_finalize",
        "lifecycle_main",
        "lifecycle_leaf",
        "lifecycle_mid",
        "lifecycle_late",
        "lifecycle_late_tls",
        "stack_guard",
        "stack_smash",
        "tls_threads",
        "compiler_helpers",
    ):
        name = fixtures.get(key)
        if not isinstance(name, str) or not name:
            raise RunnerError(f"sysroot harness manifest requires fixtures.{key}")
        if not (FIXTURES / name).is_file():
            raise RunnerError(f"required sysroot fixture is missing: {name}")
    return value


def require_native_aarch64() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise RunnerError("requires native Linux AArch64; the owned sysroot has no host fallback")


def command_record(command: Sequence[str], *, timeout: float, environment: dict[str, str] | None = None) -> dict[str, object]:
    return TOOL.run_command(command, timeout=timeout, environment=environment).record()


def require_success(record: dict[str, object], description: str) -> None:
    if record.get("status") != 0:
        raise RunnerError(f"{description} failed: {record.get('status')}")


def wrapper_for(sysroot: Path) -> Path:
    root = TOOL.require_directory(sysroot, "sysroot")
    wrapper = root / "bin/crabc-cc"
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        raise RunnerError(f"owned compiler wrapper is missing or not executable: {wrapper}")
    return wrapper


def mode_requests(wrapper: Path, work: Path, manifest: dict[str, object]) -> list[tuple[str, list[str], bool]]:
    fixtures = manifest["fixtures"]
    assert isinstance(fixtures, dict)
    main_source = FIXTURES / str(fixtures["main"])
    shared_source = FIXTURES / str(fixtures["shared"])
    return [
        ("dynamic_pie", [str(main_source), "-o", str(work / "dynamic-pie")], True),
        ("dynamic_non_pie", ["-no-pie", str(main_source), "-o", str(work / "dynamic-exec")], True),
        ("static_non_pie", ["-static", "-no-pie", str(main_source), "-o", str(work / "static-exec")], True),
        ("static_pie", ["-static-pie", str(main_source), "-o", str(work / "static-pie")], True),
        ("shared_dso", ["-shared", str(shared_source), "-o", str(work / "libfixture.so")], False),
        ("relocatable", ["-r", str(main_source), "-o", str(work / "fixture-reloc.o")], False),
    ]


def inspect_mode_artifact(name: str, output: Path) -> dict[str, object]:
    elf = TOOL.inspect_elf(output)
    expected_types = {
        "dynamic_pie": 3,
        "dynamic_non_pie": 2,
        "static_non_pie": 2,
        "static_pie": 3,
        "shared_dso": 3,
        "relocatable": 1,
    }
    expected_interpreter = TOOL.CANONICAL_INTERPRETER if name in {"dynamic_pie", "dynamic_non_pie"} else None
    errors: list[str] = []
    if elf["elf_type"] != expected_types[name]:
        errors.append(f"ELF type {elf['elf_type']} does not match expected {expected_types[name]}")
    if elf["interpreter"] != expected_interpreter:
        errors.append(f"PT_INTERP {elf['interpreter']!r} does not match expected {expected_interpreter!r}")
    if name in {"static_non_pie", "static_pie"} and elf["dynamic_needed"]:
        errors.append(f"static output has DT_NEEDED entries: {elf['dynamic_needed']}")
    if 22 in elf["dynamic_tags"]:
        errors.append("output has forbidden DT_TEXTREL")
    if name != "relocatable" and bool(elf["gnu_stack_executable"]):
        errors.append("output requests an executable GNU stack")
    if name != "relocatable" and not bool(elf["has_relro"]):
        errors.append("output has no PT_GNU_RELRO")
    if name in {"dynamic_pie", "dynamic_non_pie", "shared_dso"}:
        entries = elf["dynamic_entries"]
        assert isinstance(entries, list)
        has_now = any(
            isinstance(entry, dict)
            and (
                entry.get("tag") == 24
                or (entry.get("tag") == 30 and isinstance(entry.get("value"), int) and entry["value"] & 8)
                or (
                    entry.get("tag") == 0x6FFF_FFFB
                    and isinstance(entry.get("value"), int)
                    and entry["value"] & 1
                )
            )
            for entry in entries
        )
        if not has_now:
            errors.append("dynamic output does not record NOW binding")
    return {"artifact": elf, "passed": not errors, "errors": errors}


def header_trace_paths(output: bytes) -> list[Path]:
    """Extract real absolute headers from Clang's ``-H`` include trace."""

    paths: list[Path] = []
    seen: set[Path] = set()
    for line in output.decode("utf-8", errors="replace").splitlines():
        candidate = Path(line.lstrip(". "))
        if not candidate.is_absolute() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)
    return paths


def audit_header_trace(output: bytes, allowed_roots: Sequence[Path]) -> dict[str, object]:
    paths = header_trace_paths(output)
    allowed = [root.resolve() for root in allowed_roots]
    unexpected: list[str] = []
    for path in paths:
        if all(not path.is_relative_to(root) for root in allowed):
            unexpected.append(str(path))
    return {
        "status": "passed" if paths and not unexpected else ("rejected" if unexpected else "unverified"),
        "headers": [str(path) for path in paths],
        "allowed_roots": [str(root) for root in allowed],
        "ambient_headers": unexpected,
    }


def process_map_paths(maps: bytes) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for line in maps.decode("utf-8", errors="replace").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        path = Path(fields[5].removesuffix(" (deleted)"))
        if path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                paths.append(resolved)
    return paths


def audit_process_maps(
    maps: bytes,
    sysroot: Path,
    *,
    dynamic: bool,
    expected_artifacts: Sequence[Path] = (),
) -> dict[str, object]:
    paths = process_map_paths(maps)
    identities = [{"path": str(path), "sha256": sha256_file(path)} for path in paths]
    loader_hash = sha256_file(TOOL.installed_runtime_paths(sysroot)["loader"])
    libc_hash = sha256_file(TOOL.installed_runtime_paths(sysroot)["libc.so"])
    own_loader = [item for item in identities if item["sha256"] == loader_hash]
    own_libc = [item for item in identities if item["sha256"] == libc_hash]
    foreign_musl = [item for item in identities if "musl" in item["path"].lower() and item not in own_loader]
    errors: list[str] = []
    if dynamic and not own_loader:
        errors.append("candidate loader hash is absent from /proc/self/maps")
    if dynamic and not own_libc:
        errors.append("candidate libc hash is absent from /proc/self/maps")
    if foreign_musl:
        errors.append("foreign musl identity appears in /proc/self/maps")
    expected: list[dict[str, str]] = []
    for artifact in expected_artifacts:
        expected_hash = sha256_file(artifact)
        matching = [item for item in identities if item["sha256"] == expected_hash]
        expected.append({"path": str(artifact), "sha256": expected_hash, "mapped": bool(matching)})
        if not matching:
            errors.append(f"expected application DSO hash is absent from /proc/self/maps: {artifact.name}")
    return {
        "status": "passed" if not errors else "rejected",
        "maps": TOOL.stream_record(maps),
        "mapped_files": identities,
        "loader_identities": own_loader,
        "libc_identities": own_libc,
        "foreign_musl_identities": foreign_musl,
        "expected_application_artifacts": expected,
        "errors": errors,
    }


def map_snapshot_is_ready(maps: bytes, sysroot: Path, *, dynamic: bool) -> bool:
    """Reject an early loader-only map snapshot while a dynamic process starts."""

    if not maps:
        return False
    return not dynamic or audit_process_maps(maps, sysroot, dynamic=dynamic)["status"] == "passed"


def run_map_blocked_binary(binary: Path, sysroot: Path, *, dynamic: bool, timeout: float) -> dict[str, object]:
    """Capture maps while the fixture is blocked on its owned stdin pipe."""

    environment = TOOL.seal_environment()
    if dynamic:
        environment["LD_LIBRARY_PATH"] = str(sysroot / "usr/lib")
    try:
        process = subprocess.Popen(
            [str(binary), "proof"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as error:
        return {"status": f"EXEC_ERROR:{error.errno or 'unknown'}", "error": str(error)}
    maps_path = Path(f"/proc/{process.pid}/maps")
    deadline = time.monotonic() + timeout
    maps = b""
    while time.monotonic() < deadline:
        if maps_path.is_file():
            snapshot = maps_path.read_bytes()
            if snapshot:
                maps = snapshot
            if map_snapshot_is_ready(maps, sysroot, dynamic=dynamic):
                break
        if process.poll() is not None:
            break
        time.sleep(0.01)
    if not maps:
        process.kill()
        stdout, stderr = process.communicate()
        return {
            "status": "MAP_CAPTURE_FAILED",
            "stdout": TOOL.stream_record(stdout),
            "stderr": TOOL.stream_record(stderr),
            "library_search_path": environment.get("LD_LIBRARY_PATH"),
        }
    try:
        stdout, stderr = process.communicate(input=b"x", timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {
            "status": "TIMEOUT",
            "stdout": TOOL.stream_record(stdout),
            "stderr": TOOL.stream_record(stderr),
            "maps": audit_process_maps(maps, sysroot, dynamic=dynamic),
            "library_search_path": environment.get("LD_LIBRARY_PATH"),
        }
    maps_audit = audit_process_maps(maps, sysroot, dynamic=dynamic)
    status: int | str = process.returncode
    if status == 0 and maps_audit["status"] != "passed":
        status = "MAP_AUDIT_FAILED"
    return {
        "status": status,
        "stdout": TOOL.stream_record(stdout),
        "stderr": TOOL.stream_record(stderr),
        "maps": maps_audit,
        "library_search_path": environment.get("LD_LIBRARY_PATH"),
    }


def fixture(manifest: dict[str, object], name: str) -> Path:
    fixtures = manifest["fixtures"]
    assert isinstance(fixtures, dict)
    value = fixtures[name]
    assert isinstance(value, str)
    return FIXTURES / value


def build_with_owned_wrapper(
    wrapper: Path,
    arguments: Sequence[str],
    sysroot: Path,
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Build one fixture and retain its resolved target-link-input evidence."""

    request = [*arguments, "-Wl,--trace"]
    record = command_record([str(wrapper), *request], timeout=timeout, environment=environment)
    result: dict[str, object] = {"command": record}
    if record["status"] != 0:
        result["status"] = "rejected"
        result["reason"] = "owned wrapper link failed"
        return result
    trace = bytes.fromhex(str(record["stdout"]["hex"])) + bytes.fromhex(str(record["stderr"]["hex"]))
    audit = TOOL.audit_linker_trace(
        trace,
        sysroot,
        TOOL._application_paths(request),
        TOOL.application_library_roots(request),
    )
    result["link_trace_audit"] = audit
    result["status"] = "passed" if audit["status"] == "passed" else "rejected"
    return result


def run_binary(
    binary: Path,
    arguments: Sequence[str],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Run one target binary without a shell and retain raw results."""

    return command_record([str(binary), *arguments], timeout=timeout, environment=environment)


def dynamic_environment(sysroot: Path, *application_roots: Path, base: dict[str, str] | None = None) -> dict[str, str]:
    environment = TOOL.seal_environment(base)
    roots = [str(path) for path in application_roots]
    roots.append(str(sysroot / "usr/lib"))
    environment["LD_LIBRARY_PATH"] = ":".join(roots)
    return environment


def run_startup_contracts(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Prove startup vectors and ASLR through all four executable CRT paths."""

    source = fixture(manifest, "startup_contract")
    modes = (
        ("dynamic_pie", [], True),
        ("dynamic_non_pie", ["-no-pie"], True),
        ("static_non_pie", ["-static", "-no-pie"], False),
        ("static_pie", ["-static-pie"], False),
    )
    result: dict[str, object] = {"modes": {}, "passed": False}
    for name, flags, dynamic in modes:
        output = work / f"startup-{name}"
        build = build_with_owned_wrapper(
            wrapper,
            [*flags, str(source), "-o", str(output)],
            sysroot,
            timeout=timeout,
            environment=environment,
        )
        mode: dict[str, object] = {"build": build}
        if build["status"] != "passed" or not output.is_file():
            mode["passed"] = False
            result["modes"][name] = mode
            continue
        verification = inspect_mode_artifact(name, output)
        mode["verification"] = verification
        run_environment = dynamic_environment(sysroot) if dynamic else TOOL.seal_environment()
        run = run_binary(output, ["first", "second"], timeout=timeout, environment=run_environment)
        mode["startup_run"] = run
        mode["passed"] = verification["passed"] and run["status"] == 73
        if name in {"dynamic_pie", "static_pie"} and mode["passed"]:
            addresses: list[int] = []
            address_runs: list[dict[str, object]] = []
            for _ in range(2):
                address_environment = dict(run_environment)
                address_environment["CRABC_STARTUP_PRINT_ADDRESS"] = "1"
                address_run = run_binary(output, ["first", "second"], timeout=timeout, environment=address_environment)
                address_runs.append(address_run)
                stdout = bytes.fromhex(str(address_run["stdout"]["hex"]))
                if address_run["status"] == 73 and len(stdout) == 8:
                    addresses.append(struct.unpack("<Q", stdout)[0])
            aslr_passed = len(addresses) == 2 and addresses[0] != addresses[1]
            mode["aslr"] = {"runs": address_runs, "addresses": addresses, "passed": aslr_passed}
            mode["passed"] = bool(mode["passed"]) and aslr_passed
        result["modes"][name] = mode
    result["passed"] = all(
        isinstance(value, dict) and value.get("passed") is True for value in result["modes"].values()
    ) and len(result["modes"]) == len(modes)
    return result


def run_exit_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Prove normal and abnormal exits against musl, including DSO finalizers."""

    candidate_root = work / "exit-contract-candidate"
    reference_root = work / "exit-contract-reference"
    candidate_root.mkdir()
    reference_root.mkdir()
    candidate_dso = candidate_root / "libexit-contract.so"
    candidate_binary = candidate_root / "exit-contract"
    source_dso = fixture(manifest, "exit_contract_dso")
    source_main = fixture(manifest, "exit_contract")
    sysroot_libraries = sysroot / "usr/lib"
    candidate_builds = {
        "dso": build_with_owned_wrapper(
            wrapper,
            [
                "-shared", "-fPIC", str(source_dso), "-Wl,-soname,libexit-contract.so",
                "-L", str(sysroot_libraries), "-lc", "-l:libcrabc-builtins.a", "-o", str(candidate_dso),
            ],
            sysroot,
            timeout=timeout,
            environment=environment,
        ),
        "main": build_with_owned_wrapper(
            wrapper,
            [str(source_main), "-L", str(candidate_root), "-l:libexit-contract.so", "-o", str(candidate_binary)],
            sysroot,
            timeout=timeout,
            environment=environment,
        ),
    }
    result: dict[str, object] = {"candidate_builds": candidate_builds, "reference_builds": {}, "runs": {}, "passed": False}
    if any(build.get("status") != "passed" for build in candidate_builds.values()) or not candidate_binary.is_file():
        return result

    musl_gcc = shutil.which("musl-gcc")
    if musl_gcc is None:
        raise RunnerError("pinned musl-gcc is unavailable for exit/finalizer ordering oracle")
    reference_dso = reference_root / "libexit-contract.so"
    reference_binary = reference_root / "exit-contract"
    reference_commands = {
        "dso": [
            musl_gcc, "-shared", "-fPIC", str(source_dso), "-Wl,-soname,libexit-contract.so", "-o", str(reference_dso),
        ],
        "main": [
            musl_gcc, "-fPIE", "-pie", str(source_main), "-L", str(reference_root), "-l:libexit-contract.so",
            f"-Wl,-rpath-link,{reference_root}", "-o", str(reference_binary),
        ],
    }
    for name, command in reference_commands.items():
        record = command_record(command, timeout=timeout, environment=TOOL.seal_environment())
        result["reference_builds"][name] = record
        if record["status"] != 0:
            return result

    expected = {
        "return": (73, b"ordinary\nexe-fini\ndso-fini\n"),
        "exit": (74, b"ordinary\nexe-fini\ndso-fini\n"),
        "_Exit": (75, b""),
        "quick": (76, b"quick\n"),
    }
    candidate_environment = dynamic_environment(sysroot, candidate_root)
    reference_environment = TOOL.seal_environment()
    reference_environment["LD_LIBRARY_PATH"] = str(reference_root)
    for mode, (status, stdout) in expected.items():
        candidate_run = run_binary(candidate_binary, [mode], timeout=timeout, environment=candidate_environment)
        reference_run = run_binary(reference_binary, [mode], timeout=timeout, environment=reference_environment)
        candidate_stdout = bytes.fromhex(str(candidate_run["stdout"]["hex"]))
        reference_stdout = bytes.fromhex(str(reference_run["stdout"]["hex"]))
        result["runs"][mode] = {
            "candidate": candidate_run,
            "reference": reference_run,
            "expected_status": status,
            "expected_stdout": TOOL.stream_record(stdout),
            "passed": (
                candidate_run["status"] == status
                and reference_run["status"] == status
                and candidate_stdout == stdout
                and reference_stdout == stdout
                and candidate_stdout == reference_stdout
            ),
        }
    result["passed"] = all(
        isinstance(value, dict) and value.get("passed") is True for value in result["runs"].values()
    )
    return result


def run_cxa_finalize_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Exercise the installed sysroot's public musl-compatible cxa ABI."""

    source = fixture(manifest, "cxa_finalize")
    candidate = work / "cxa-finalize-candidate"
    reference = work / "cxa-finalize-reference"
    candidate_build = build_with_owned_wrapper(
        wrapper,
        [str(source), "-o", str(candidate)],
        sysroot,
        timeout=timeout,
        environment=environment,
    )
    result: dict[str, object] = {"candidate_build": candidate_build, "passed": False}
    if candidate_build["status"] != "passed" or not candidate.is_file():
        return result
    musl_gcc = shutil.which("musl-gcc")
    if musl_gcc is None:
        raise RunnerError("pinned musl-gcc is unavailable for __cxa_finalize oracle")
    reference_build = command_record(
        [musl_gcc, "-fPIE", "-pie", "-fno-builtin", str(source), "-o", str(reference)],
        timeout=timeout,
        environment=TOOL.seal_environment(),
    )
    result["reference_build"] = reference_build
    if reference_build["status"] != 0 or not reference.is_file():
        return result
    candidate_marker = work / "cxa-finalize-candidate.trace"
    reference_marker = work / "cxa-finalize-reference.trace"
    candidate_run = run_binary(
        candidate, [str(candidate_marker)], timeout=timeout, environment=dynamic_environment(sysroot)
    )
    reference_run = run_binary(
        reference, [str(reference_marker)], timeout=timeout, environment=TOOL.seal_environment()
    )
    expected = b"first-new\nsecond\nfirst-old\n"
    candidate_trace = candidate_marker.read_bytes() if candidate_marker.is_file() else b""
    reference_trace = reference_marker.read_bytes() if reference_marker.is_file() else b""
    result.update(
        {
            "candidate_run": candidate_run,
            "reference_run": reference_run,
            "expected_trace": TOOL.stream_record(expected),
            "candidate_trace": TOOL.stream_record(candidate_trace),
            "reference_trace": TOOL.stream_record(reference_trace),
        }
    )
    result["passed"] = (
        candidate_run["status"] == 0
        and reference_run["status"] == 0
        and candidate_trace == expected
        and reference_trace == expected
        and candidate_trace == reference_trace
    )
    return result


def run_stack_guard_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Exercise protected constructors, guard variation, and smash failure."""

    guard_source = fixture(manifest, "stack_guard")
    smash_source = fixture(manifest, "stack_smash")
    assembly = work / "stack-guard.s"
    guard_binary = work / "stack-guard"
    smash_binary = work / "stack-smash"
    assembly_record = command_record(
        [str(wrapper), "-S", "-fstack-protector-all", str(guard_source), "-o", str(assembly)],
        timeout=timeout,
        environment=environment,
    )
    guard_build = build_with_owned_wrapper(
        wrapper,
        ["-O2", "-fstack-protector-all", str(guard_source), "-o", str(guard_binary)],
        sysroot,
        timeout=timeout,
        environment=environment,
    )
    smash_build = build_with_owned_wrapper(
        wrapper,
        ["-O0", "-fstack-protector-all", str(smash_source), "-o", str(smash_binary)],
        sysroot,
        timeout=timeout,
        environment=environment,
    )
    result: dict[str, object] = {
        "guard_assembly": assembly_record,
        "guard_build": guard_build,
        "smash_build": smash_build,
        "passed": False,
    }
    if assembly_record["status"] != 0 or not assembly.is_file():
        return result
    assembly_text = assembly.read_text(encoding="utf-8", errors="replace")
    result["guard_access"] = {
        "model": "AArch64 global __stack_chk_guard reference",
        "assembly_sha256": hashlib.sha256(assembly_text.encode()).hexdigest(),
        "references_guard": "__stack_chk_guard" in assembly_text,
    }
    if guard_build["status"] != "passed" or smash_build["status"] != "passed":
        return result
    guard_runs: list[dict[str, object]] = []
    guards: list[int] = []
    run_environment = dynamic_environment(sysroot)
    for _ in range(2):
        run = run_binary(guard_binary, [], timeout=timeout, environment=run_environment)
        guard_runs.append(run)
        stdout = bytes.fromhex(str(run["stdout"]["hex"]))
        if run["status"] == 0 and len(stdout) == 8:
            guards.append(struct.unpack("<Q", stdout)[0])
    smash = run_binary(smash_binary, [], timeout=timeout, environment=run_environment)
    guard_passed = len(guards) == 2 and all(guard != 0 for guard in guards) and guards[0] != guards[1]
    smash_passed = smash["status"] in {-6, 134}
    result.update(
        {
            "guard_runs": guard_runs,
            "guards": guards,
            "smash_run": smash,
            "guard_passed": guard_passed,
            "smash_passed": smash_passed,
        }
    )
    result["passed"] = bool(result["guard_access"]["references_guard"]) and guard_passed and smash_passed
    return result


def run_tls_thread_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Prove constructor/main/pthread TLS and errno isolation dynamically."""

    output = work / "tls-threads"
    arguments = ["-pthread", str(fixture(manifest, "tls_threads")), "-o", str(output)]
    plan = command_record(
        [str(wrapper), "--crabc-print-link-plan", *arguments], timeout=timeout, environment=environment
    )
    build = build_with_owned_wrapper(wrapper, arguments, sysroot, timeout=timeout, environment=environment)
    result: dict[str, object] = {"link_plan": plan, "build": build, "passed": False}
    if plan["status"] != 0 or build["status"] != "passed" or not output.is_file():
        return result
    plan_text = bytes.fromhex(str(plan["stdout"]["hex"]))
    run = run_binary(output, [], timeout=timeout, environment=dynamic_environment(sysroot))
    result["run"] = run
    result["passed"] = b"-pthread" in plan_text and run["status"] == 0
    return result


def run_compiler_helper_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
    clang: Path,
    lld: Path,
    resource_include: Path,
) -> dict[str, object]:
    """Prove representative C codegen never reaches a foreign helper runtime.

    The fixture deliberately combines integer and binary128 arithmetic,
    complex operations, overflow lowering, C atomics, and a protected stack
    object.  Every optimized dynamic link is audited from LLD's resolved
    ``--trace`` output; the static-PIE variant proves the same helper boundary
    does not silently change with CRT mode.
    """

    source = fixture(manifest, "compiler_helpers")
    variants = (
        ("O0_dynamic_pie", ["-O0"], "dynamic_pie", True),
        ("O2_dynamic_pie", ["-O2"], "dynamic_pie", True),
        ("O3_dynamic_pie", ["-O3"], "dynamic_pie", True),
        ("O2_static_pie", ["-O2", "-static-pie"], "static_pie", False),
    )
    result: dict[str, object] = {"variants": {}, "tool_inventory": {}, "passed": False}
    successful_outputs: dict[str, Path] = {}
    for name, flags, mode, dynamic in variants:
        output = work / f"compiler-helpers-{name}"
        build = build_with_owned_wrapper(
            wrapper,
            [*flags, "-fstack-protector-all", str(source), "-o", str(output)],
            sysroot,
            timeout=timeout,
            environment=environment,
        )
        variant: dict[str, object] = {"build": build, "passed": False}
        if build["status"] == "passed" and output.is_file():
            verification = inspect_mode_artifact(mode, output)
            run_environment = dynamic_environment(sysroot) if dynamic else TOOL.seal_environment()
            execution = run_binary(output, [], timeout=timeout, environment=run_environment)
            variant.update(
                {
                    "verification": verification,
                    "run": execution,
                    "passed": verification["passed"] and execution["status"] == 0,
                }
            )
            successful_outputs[name] = output
        result["variants"][name] = variant

    inventory_output = work / "compiler-inventory.o"
    clang_verbose = command_record(
        [
            str(clang),
            "-v",
            f"--target={TOOL.TARGET_TRIPLE}",
            "-mno-outline-atomics",
            "-nostdinc",
            "-isystem",
            str(sysroot / "usr/include"),
            "-isystem",
            str(resource_include),
            "-O2",
            "-fstack-protector-all",
            "-c",
            str(source),
            "-o",
            str(inventory_output),
        ],
        timeout=timeout,
        environment=environment,
    )
    clang_driver = command_record(
        [str(wrapper), "-###", "-O2", str(source), "-o", str(work / "compiler-driver-trace")],
        timeout=timeout,
        environment=environment,
    )
    result["tool_inventory"] = {
        "clang_verbose": clang_verbose,
        "clang_driver_trace": clang_driver,
        "ld_lld_version": command_record([str(lld), "--version"], timeout=timeout, environment=environment),
        # Each dynamic/static build above passes -Wl,--trace. Keep one raw
        # resolved trace beside the tool records rather than infer link inputs
        # from an argv string.
        "ld_lld_trace": result["variants"].get("O2_dynamic_pie", {}).get("build"),
    }
    inspected = successful_outputs.get("O2_dynamic_pie")
    llvm_tools = {name: shutil.which(name) for name in ("llvm-readelf", "llvm-nm", "llvm-ar")}
    if inspected is not None and all(llvm_tools.values()):
        result["tool_inventory"].update(
            {
                "llvm_readelf": command_record(
                    [str(llvm_tools["llvm-readelf"]), "-h", "-l", "-d", "-r", str(inspected)],
                    timeout=timeout,
                    environment=environment,
                ),
                "llvm_nm": command_record(
                    [str(llvm_tools["llvm-nm"]), "--undefined-only", str(sysroot / "usr/lib/libcrabc-builtins.a")],
                    timeout=timeout,
                    environment=environment,
                ),
                "llvm_ar": command_record(
                    [str(llvm_tools["llvm-ar"]), "t", str(sysroot / "usr/lib/libcrabc-builtins.a")],
                    timeout=timeout,
                    environment=environment,
                ),
            }
        )
    else:
        result["tool_inventory"]["llvm_tools"] = {
            "status": "unverified",
            "reason": "llvm-readelf, llvm-nm, and llvm-ar are required for compiler-helper inventory",
            "tools": llvm_tools,
        }

    inventory_records = [
        value
        for key, value in result["tool_inventory"].items()
        if key != "ld_lld_trace" and isinstance(value, dict) and "status" in value
    ]
    result["passed"] = (
        all(isinstance(value, dict) and value.get("passed") is True for value in result["variants"].values())
        and all(value.get("status") == 0 for value in inventory_records)
        and "llvm_tools" not in result["tool_inventory"]
    )
    return result


def mutation_static_pie_failure(binary: Path, *, timeout: float, environment: dict[str, str]) -> dict[str, object]:
    """Corrupt one bootstrap relocation and require rcrt1.o to fail closed."""

    elf = TOOL.inspect_elf(binary)
    corrupted = binary.with_name(f"{binary.name}-malformed-relocation")
    data = bytearray(binary.read_bytes())
    mutation: dict[str, object] | None = None
    for relocation in elf["relocations"]:
        if not isinstance(relocation, dict):
            continue
        file_offset = relocation.get("file_offset")
        if not isinstance(file_offset, int):
            continue
        relocation_type = relocation.get("type")
        if relocation_type == 1027:
            info_offset = file_offset + 8
            original = struct.unpack_from("<Q", data, info_offset)[0]
            struct.pack_into("<Q", data, info_offset, (original & ~0xffff_ffff) | 0x7fff_ffff)
            mutation = {"kind": "RELA", "file_offset": file_offset, "old_info": original}
            break
        if "relr_word" in relocation:
            original = struct.unpack_from("<Q", data, file_offset)[0]
            struct.pack_into("<Q", data, file_offset, 1)
            mutation = {"kind": "RELR", "file_offset": file_offset, "old_word": original}
            break
    if mutation is None:
        return {"status": "unverified", "reason": "static PIE has no mutable RELA/RELR bootstrap record"}
    corrupted.write_bytes(data)
    corrupted.chmod(binary.stat().st_mode)
    run = run_binary(corrupted, ["proof"], timeout=timeout, environment=environment)
    return {
        "status": "passed" if run["status"] == 127 else "rejected",
        "mutation": mutation,
        "run": run,
    }


def run_static_pie_relr_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Exercise rcrt1.o's packed-RELR path when this lld can emit it."""

    output = work / "static-pie-relr"
    build = build_with_owned_wrapper(
        wrapper,
        [
            "-static-pie",
            "-Wl,--pack-dyn-relocs=relr",
            str(fixture(manifest, "main")),
            "-o",
            str(output),
        ],
        sysroot,
        timeout=timeout,
        environment=environment,
    )
    if build["status"] != "passed":
        command = build.get("command")
        stderr = ""
        if isinstance(command, dict):
            stream = command.get("stderr")
            if isinstance(stream, dict):
                text = stream.get("text")
                if isinstance(text, str):
                    stderr = text
        if "pack-dyn-relocs" in stderr and any(token in stderr.lower() for token in ("unknown", "unsupported")):
            return {
                "status": "passed",
                "available": False,
                "reason": "configured lld does not support packed RELR emission",
                "build": build,
            }
        return {"status": "rejected", "available": None, "build": build}
    artifact = inspect_mode_artifact("static_pie", output)
    elf = artifact["artifact"]
    assert isinstance(elf, dict)
    relr_present = any(
        isinstance(relocation, dict) and "relr_word" in relocation for relocation in elf["relocations"]
    )
    run = run_map_blocked_binary(output, sysroot, dynamic=False, timeout=timeout)
    return {
        "status": "passed" if artifact["passed"] and relr_present and run["status"] == 0 else "rejected",
        "available": True,
        "build": build,
        "verification": artifact,
        "relr_present": relr_present,
        "run": run,
    }


def build_lifecycle_reference(source_root: Path, output_root: Path, *, timeout: float) -> dict[str, object]:
    """Build the same C application graph with the pinned musl oracle only."""

    compiler = shutil.which("musl-gcc")
    if compiler is None:
        raise RunnerError("pinned musl-gcc is unavailable for lifecycle ordering oracle")
    output_root.mkdir(parents=True, exist_ok=True)
    records: dict[str, object] = {}
    common = [compiler, "-fPIC", "-I", str(source_root)]
    commands = {
        "leaf": [
            *common,
            "-shared",
            str(source_root / "lifecycle_leaf.c"),
            "-Wl,-soname,libleaf.so",
            "-o",
            str(output_root / "libleaf.so"),
        ],
        "mid": [
            *common,
            "-shared",
            str(source_root / "lifecycle_mid.c"),
            "-L",
            str(output_root),
            "-l:libleaf.so",
            "-Wl,-soname,liblifecycle_mid.so",
            "-o",
            str(output_root / "liblifecycle_mid.so"),
        ],
        "late": [
            *common,
            "-shared",
            str(source_root / "lifecycle_late.c"),
            "-Wl,-soname,liblifecycle_late.so",
            "-o",
            str(output_root / "liblifecycle_late.so"),
        ],
        "late_tls": [
            *common,
            "-shared",
            str(source_root / "lifecycle_late_tls.c"),
            "-Wl,-soname,liblifecycle_late_tls.so",
            "-o",
            str(output_root / "liblifecycle_late_tls.so"),
        ],
        "main": [
            compiler,
            "-fPIE",
            "-pie",
            "-I",
            str(source_root),
            str(source_root / "lifecycle_main.c"),
            "-L",
            str(output_root),
            "-llifecycle_mid",
            f"-Wl,-rpath-link,{output_root}",
            "-o",
            str(output_root / "lifecycle-main"),
        ],
    }
    for name, command in commands.items():
        record = command_record(command, timeout=timeout, environment=TOOL.seal_environment())
        records[name] = record
        if record["status"] != 0:
            return {"status": "rejected", "records": records}
    return {"status": "passed", "records": records, "binary": str(output_root / "lifecycle-main")}


def run_lifecycle_candidate_with_maps(
    binary: Path,
    sysroot: Path,
    library_root: Path,
    trace: Path,
    *,
    expected_dsos: Sequence[Path],
    timeout: float,
) -> dict[str, object]:
    """Hold the late DSO open long enough to audit normal-kernel maps."""

    environment = dynamic_environment(sysroot, library_root)
    environment["CRABC_LIFECYCLE_TRACE"] = str(trace)
    environment["CRABC_LIFECYCLE_MAPS_WAIT"] = "1"
    try:
        process = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as error:
        return {"status": f"EXEC_ERROR:{error.errno or 'unknown'}", "error": str(error)}
    assert process.stdin is not None and process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        process.kill()
        stdout, stderr = process.communicate()
        return {"status": "TIMEOUT", "stdout": TOOL.stream_record(stdout), "stderr": TOOL.stream_record(stderr)}
    marker = process.stdout.readline()
    if marker != b"maps-ready\n":
        process.kill()
        stdout, stderr = process.communicate()
        return {
            "status": "PROTOCOL_ERROR",
            "stdout": TOOL.stream_record(marker + stdout),
            "stderr": TOOL.stream_record(stderr),
        }
    maps_path = Path(f"/proc/{process.pid}/maps")
    maps = maps_path.read_bytes() if maps_path.is_file() else b""
    try:
        stdout, stderr = process.communicate(input=b"continue\n", timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {"status": "TIMEOUT", "stdout": TOOL.stream_record(stdout), "stderr": TOOL.stream_record(stderr)}
    maps_audit = audit_process_maps(maps, sysroot, dynamic=True, expected_artifacts=expected_dsos)
    status: int | str = process.returncode
    if status == 0 and maps_audit["status"] != "passed":
        status = "MAP_AUDIT_FAILED"
    return {
        "status": status,
        "stdout": TOOL.stream_record(stdout),
        "stderr": TOOL.stream_record(stderr),
        "maps": maps_audit,
        "library_search_path": environment["LD_LIBRARY_PATH"],
    }


def run_lifecycle_contract(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Prove owned executable hooks and compare shared-DSO ordering to musl."""

    candidate_root = work / "lifecycle-candidate"
    candidate_root.mkdir()
    source_root = FIXTURES
    sysroot_libraries = sysroot / "usr/lib"
    builds: dict[str, object] = {}
    commands = {
        "leaf": [
            "-shared", "-fPIC", "-I", str(source_root), str(fixture(manifest, "lifecycle_leaf")),
            "-Wl,-soname,libleaf.so", "-L", str(sysroot_libraries), "-lc", "-l:libcrabc-builtins.a",
            "-o", str(candidate_root / "libleaf.so"),
        ],
        "mid": [
            "-shared", "-fPIC", "-I", str(source_root), str(fixture(manifest, "lifecycle_mid")),
            "-Wl,-soname,liblifecycle_mid.so", "-L", str(candidate_root), "-l:libleaf.so",
            "-L", str(sysroot_libraries), "-lc", "-l:libcrabc-builtins.a",
            "-o", str(candidate_root / "liblifecycle_mid.so"),
        ],
        "late": [
            "-shared", "-fPIC", "-I", str(source_root), str(fixture(manifest, "lifecycle_late")),
            "-Wl,-soname,liblifecycle_late.so", "-L", str(sysroot_libraries), "-lc", "-l:libcrabc-builtins.a",
            "-o", str(candidate_root / "liblifecycle_late.so"),
        ],
        "late_tls": [
            "-shared", "-fPIC", "-I", str(source_root), str(fixture(manifest, "lifecycle_late_tls")),
            "-Wl,-soname,liblifecycle_late_tls.so", "-L", str(sysroot_libraries), "-lc", "-l:libcrabc-builtins.a",
            "-o", str(candidate_root / "liblifecycle_late_tls.so"),
        ],
        "main": [
            "-I", str(source_root), str(fixture(manifest, "lifecycle_main")), "-L", str(candidate_root),
            "-llifecycle_mid", "-o", str(candidate_root / "lifecycle-main"),
        ],
    }
    for name, command in commands.items():
        build = build_with_owned_wrapper(wrapper, command, sysroot, timeout=timeout, environment=environment)
        builds[name] = build
        if build["status"] != "passed":
            return {"builds": builds, "passed": False}
    reference_root = work / "lifecycle-reference"
    reference = build_lifecycle_reference(source_root, reference_root, timeout=timeout)
    result: dict[str, object] = {"builds": builds, "reference_build": reference, "passed": False}
    if reference["status"] != "passed":
        return result
    reference_trace = work / "lifecycle-reference.trace"
    reference_environment = TOOL.seal_environment()
    reference_environment["LD_LIBRARY_PATH"] = str(reference_root)
    reference_environment["CRABC_LIFECYCLE_TRACE"] = str(reference_trace)
    reference_binary = reference["binary"]
    assert isinstance(reference_binary, str)
    reference_run = run_binary(Path(reference_binary), [], timeout=timeout, environment=reference_environment)
    result["reference_run"] = reference_run
    if reference_run["status"] != 0 or not reference_trace.is_file():
        return result
    candidate_trace = work / "lifecycle-candidate.trace"
    candidate_run = run_lifecycle_candidate_with_maps(
        candidate_root / "lifecycle-main",
        sysroot,
        candidate_root,
        candidate_trace,
        expected_dsos=(
            candidate_root / "libleaf.so",
            candidate_root / "liblifecycle_mid.so",
            candidate_root / "liblifecycle_late.so",
            candidate_root / "liblifecycle_late_tls.so",
        ),
        timeout=timeout,
    )
    result["candidate_run"] = candidate_run
    reference_bytes = reference_trace.read_bytes()
    candidate_bytes = candidate_trace.read_bytes() if candidate_trace.is_file() else b""
    # Pinned musl proves the dependency/main-array order below. Its ordinary
    # GCC startup objects do not execute this fixture's explicit preinit or
    # crti/crtn fragments, while the owned CRT intentionally does; audit those
    # executable-owned hooks as an additional exact local contract instead of
    # pretending the two linkers supplied the same startup objects.
    common_order_events = b"LMABN21baml"
    owned_expected = b"PLMIABNDd21baFml"
    reference_common = bytes(event for event in reference_bytes if event in common_order_events)
    candidate_common = bytes(event for event in candidate_bytes if event in common_order_events)
    result["traces"] = {
        "reference": TOOL.stream_record(reference_bytes),
        "candidate": TOOL.stream_record(candidate_bytes),
        "musl_compared_events": common_order_events.decode("ascii"),
        "reference_common_order": TOOL.stream_record(reference_common),
        "candidate_common_order": TOOL.stream_record(candidate_common),
        "shared_dependency_order_matches_musl": reference_common == candidate_common,
        "owned_executable_expected_order": owned_expected.decode("ascii"),
        "owned_executable_order_matches": candidate_bytes == owned_expected,
        "dlopen_events_once": {
            "candidate": candidate_bytes.count(b"D") == 1 and candidate_bytes.count(b"d") == 1,
            "reference": reference_bytes.count(b"D") == 1 and reference_bytes.count(b"d") == 1,
        },
    }
    result["passed"] = (
        candidate_run["status"] == 0
        and result["traces"]["shared_dependency_order_matches_musl"] is True
        and result["traces"]["owned_executable_order_matches"] is True
        and all(result["traces"]["dlopen_events_once"].values())
    )
    return result


def run_driver_semantics(
    wrapper: Path,
    sysroot: Path,
    work: Path,
    manifest: dict[str, object],
    *,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, object]:
    """Exercise every driver-only mode and the three omission contracts."""

    source = fixture(manifest, "main")
    operations = {
        "compile": ["-c", str(source), "-o", str(work / "driver.o")],
        "preprocess": ["-E", str(source), "-o", str(work / "driver.i")],
        "assembly": ["-S", str(source), "-o", str(work / "driver.s")],
    }
    result: dict[str, object] = {"operations": {}, "omission_plans": {}, "passed": False}
    for name, arguments in operations.items():
        record = command_record([str(wrapper), *arguments], timeout=timeout, environment=environment)
        output = Path(arguments[-1])
        result["operations"][name] = {"command": record, "output_exists": output.is_file()}

    plan_arguments = {
        "nostdlib": ["-nostdlib", str(source), "-o", str(work / "nostdlib")],
        "nostartfiles": ["-nostartfiles", str(source), "-o", str(work / "nostartfiles")],
        "nodefaultlibs": ["-nodefaultlibs", str(source), "-o", str(work / "nodefaultlibs")],
    }
    for name, arguments in plan_arguments.items():
        record = command_record(
            [str(wrapper), "--crabc-print-link-plan", *arguments], timeout=timeout, environment=environment
        )
        plan: dict[str, object] | None = None
        if record["status"] == 0:
            try:
                decoded = json.loads(bytes.fromhex(str(record["stdout"]["hex"])).decode("utf-8"))
                if isinstance(decoded, dict):
                    plan = decoded
            except (UnicodeDecodeError, json.JSONDecodeError):
                plan = None
        valid = plan is not None
        if name == "nostdlib":
            valid = valid and plan.get("startup_objects") == [] and plan.get("default_libraries") == []
        elif name == "nostartfiles":
            valid = valid and plan.get("startup_objects") == [] and bool(plan.get("default_libraries"))
        else:
            valid = valid and bool(plan.get("startup_objects")) and plan.get("default_libraries") == []
        result["omission_plans"][name] = {"command": record, "plan": plan, "passed": valid}

    clang_trace = command_record(
        [str(wrapper), "-###", "-c", str(source), "-o", str(work / "driver-trace.o")],
        timeout=timeout,
        environment=environment,
    )
    result["clang_driver_trace"] = {
        "command": clang_trace,
        "passed": clang_trace["status"] == 0,
    }
    polluted = dict(environment)
    for key in TOOL.SEALED_ENVIRONMENT_KEYS:
        polluted[key] = "/opt/musl-1.2.6/ambient"
    pollution_record = command_record(
        [str(wrapper), "-c", str(source), "-o", str(work / "driver-pollution.o")],
        timeout=timeout,
        environment=polluted,
    )
    result["ambient_search_rejection"] = {
        "command": pollution_record,
        "output_exists": (work / "driver-pollution.o").is_file(),
        "passed": pollution_record["status"] == 0 and (work / "driver-pollution.o").is_file(),
    }
    result["passed"] = (
        all(
            isinstance(value, dict)
            and isinstance(value.get("command"), dict)
            and value["command"].get("status") == 0
            and value.get("output_exists") is True
            for value in result["operations"].values()
        )
        and all(isinstance(value, dict) and value.get("passed") is True for value in result["omission_plans"].values())
        and result["clang_driver_trace"]["passed"] is True
        and result["ambient_search_rejection"]["passed"] is True
    )
    return result


@contextlib.contextmanager
def staged_canonical_loader(sysroot: Path, enabled: bool) -> Iterator[None]:
    """Temporarily install only an absent canonical loader in disposable Linux."""

    if not enabled:
        yield
        return
    if os.geteuid() != 0:
        raise RunnerError("--stage-canonical-loader requires root in the disposable Linux container")
    source = TOOL.installed_runtime_paths(sysroot)["loader"]
    canonical = Path(TOOL.CANONICAL_INTERPRETER)
    if canonical.exists() or canonical.is_symlink():
        raise RunnerError(f"refusing to replace existing canonical loader: {canonical}")
    canonical.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, canonical)
    try:
        yield
    finally:
        if canonical.exists() and sha256_file(canonical) == sha256_file(source):
            canonical.unlink()
        elif canonical.exists():
            raise RunnerError(f"staged canonical loader changed unexpectedly and was retained: {canonical}")


def regular_file_hashes(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[str(path.relative_to(root))] = sha256_file(path)
    return result


def relative_symlink_violations(root: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_symlink():
            continue
        target = os.readlink(path)
        if Path(target).is_absolute() or ".." in Path(target).parts:
            violations.append(f"{path.relative_to(root)} -> {target}")
    return violations


def reproducibility_record(sysroot: Path, comparison: Path | None) -> dict[str, object]:
    symlink_violations = relative_symlink_violations(sysroot)
    if comparison is None:
        return {
            "status": "unverified",
            "reason": "no independently assembled comparison sysroot was supplied",
            "symlink_violations": symlink_violations,
        }
    other = TOOL.require_directory(comparison, "comparison sysroot")
    current_hashes = regular_file_hashes(sysroot)
    comparison_hashes = regular_file_hashes(other)
    differences = sorted(
        key
        for key in set(current_hashes) | set(comparison_hashes)
        if current_hashes.get(key) != comparison_hashes.get(key)
    )
    other_violations = relative_symlink_violations(other)
    return {
        "status": "passed" if not differences and not symlink_violations and not other_violations else "rejected",
        "comparison_sysroot": str(other),
        "different_regular_files": differences,
        "symlink_violations": symlink_violations,
        "comparison_symlink_violations": other_violations,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_manifest()
    sysroot = TOOL.require_directory(args.sysroot, "sysroot")
    wrapper = wrapper_for(sysroot)
    installed_manifest = TOOL.load_installed_manifest(sysroot)
    report: dict[str, Any] = {
        "runner": "crabc-owned-sysroot",
        "schema": 1,
        "passed": False,
        "target": manifest["target"],
        "harness_manifest": {"path": str(MANIFEST), "sha256": sha256_file(MANIFEST)},
        "sysroot": {"path": str(sysroot), "manifest": installed_manifest},
        "provenance": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version},
        "modes": {},
        "failures": [],
    }
    require_native_aarch64()
    sealed = TOOL.seal_environment()
    introspection = {
        "sysroot": command_record([str(wrapper), "--print-sysroot"], timeout=args.timeout, environment=sealed),
        "manifest": command_record([str(wrapper), "--crabc-print-manifest"], timeout=args.timeout, environment=sealed),
    }
    report["introspection"] = introspection
    for name, record in introspection.items():
        if record["status"] != 0:
            raise RunnerError(f"wrapper {name} introspection failed")
    fixture_config = manifest["fixtures"]
    assert isinstance(fixture_config, dict)
    configuration = TOOL.DriverConfiguration.from_manifest(installed_manifest)
    clang = TOOL._compiler_from_configuration(configuration)
    lld = TOOL._linker_from_configuration(configuration)
    resource_include = TOOL._resource_include(clang, sealed)
    header_trace = command_record(
        [str(wrapper), "-H", "-E", str(FIXTURES / str(fixture_config["header_trace"]))],
        timeout=args.timeout,
        environment=sealed,
    )
    report["header_trace"] = {"command": header_trace}
    if header_trace["status"] != 0:
        raise RunnerError("sealed header trace failed")
    header_bytes = bytes.fromhex(str(header_trace["stdout"]["hex"])) + bytes.fromhex(
        str(header_trace["stderr"]["hex"])
    )
    header_audit = audit_header_trace(header_bytes, [sysroot / "usr/include", resource_include, FIXTURES])
    report["header_trace"]["audit"] = header_audit
    if header_audit["status"] != "passed":
        report["failures"].append({"taxonomy": "header isolation"})
    with tempfile.TemporaryDirectory(prefix="crabc-owned-sysroot-") as work_name:
        work = Path(work_name)
        executable_modes: list[tuple[str, Path]] = []
        mode_outputs: dict[str, Path] = {}
        for name, request, executes in mode_requests(wrapper, work, manifest):
            plan_record = command_record(
                [str(wrapper), "--crabc-print-link-plan", *request], timeout=args.timeout, environment=sealed
            )
            mode_record: dict[str, object] = {"link_plan": plan_record}
            if plan_record["status"] != 0:
                mode_record["passed"] = False
                mode_record["failure"] = "driver-plan"
                report["modes"][name] = mode_record
                report["failures"].append({"mode": name, "taxonomy": "driver semantics"})
                continue
            trace_request = [*request, "-Wl,--trace"]
            build_record = command_record([str(wrapper), *trace_request], timeout=args.timeout, environment=sealed)
            mode_record["build"] = build_record
            output = Path(request[-1])
            if build_record["status"] != 0 or not output.is_file():
                mode_record["passed"] = False
                mode_record["failure"] = "build"
                report["modes"][name] = mode_record
                report["failures"].append({"mode": name, "taxonomy": "link/sysroot gap"})
                continue
            trace_bytes = bytes.fromhex(str(build_record["stdout"]["hex"])) + bytes.fromhex(
                str(build_record["stderr"]["hex"])
            )
            trace_audit = TOOL.audit_linker_trace(
                trace_bytes,
                sysroot,
                TOOL._application_paths(request),
                TOOL.application_library_roots(request),
            )
            if name == "relocatable" and trace_audit["status"] == "unverified":
                # Clang may compile a C source to an ephemeral /tmp object
                # before passing it to ld.lld -r. This mode owns no CRT or
                # default library input, so an empty resolved-runtime trace is
                # the expected sealed result rather than missing provenance.
                trace_audit = {
                    **trace_audit,
                    "status": "passed",
                    "reason": "relocatable link consumed no resolved target-runtime input",
                }
            mode_record["link_trace_audit"] = trace_audit
            if trace_audit["status"] != "passed":
                mode_record["passed"] = False
                mode_record["failure"] = "link-trace"
                report["modes"][name] = mode_record
                report["failures"].append({"mode": name, "taxonomy": "link-input purity"})
                continue
            verification = inspect_mode_artifact(name, output)
            mode_record["verification"] = verification
            mode_record["passed"] = verification["passed"]
            report["modes"][name] = mode_record
            mode_outputs[name] = output
            if not verification["passed"]:
                report["failures"].append({"mode": name, "taxonomy": "ELF artifact contract"})
            if executes and verification["passed"]:
                executable_modes.append((name, output))
        driver_semantics = run_driver_semantics(
            wrapper,
            sysroot,
            work,
            manifest,
            timeout=args.timeout,
            environment=sealed,
        )
        report["driver_semantics"] = driver_semantics
        if driver_semantics["passed"] is not True:
            report["failures"].append({"taxonomy": "driver semantics"})
        execution: dict[str, object] = {"status": "unverified", "reason": "--stage-canonical-loader was not supplied"}
        if args.stage_canonical_loader and not report["failures"]:
            runs: list[dict[str, object]] = []
            runtime_contracts: dict[str, object] = {}
            with staged_canonical_loader(sysroot, True):
                for name, binary in executable_modes:
                    result = run_map_blocked_binary(
                        binary,
                        sysroot,
                        dynamic=name in {"dynamic_pie", "dynamic_non_pie"},
                        timeout=args.timeout,
                    )
                    runs.append({"binary": binary.name, "result": result})
                runtime_contracts["initial_process"] = run_startup_contracts(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
                runtime_contracts["exit"] = run_exit_contract(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
                runtime_contracts["cxa_finalize"] = run_cxa_finalize_contract(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
                runtime_contracts["stack_protector"] = run_stack_guard_contract(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
                runtime_contracts["tls_threads"] = run_tls_thread_contract(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
                runtime_contracts["compiler_helpers"] = run_compiler_helper_contract(
                    wrapper,
                    sysroot,
                    work,
                    manifest,
                    timeout=args.timeout,
                    environment=sealed,
                    clang=clang,
                    lld=lld,
                    resource_include=resource_include,
                )
                runtime_contracts["lifecycle"] = run_lifecycle_contract(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
                static_pie = mode_outputs.get("static_pie")
                runtime_contracts["malformed_static_pie_relocation"] = (
                    mutation_static_pie_failure(
                        static_pie,
                        timeout=args.timeout,
                        environment=TOOL.seal_environment(),
                    )
                    if static_pie is not None
                    else {"status": "unverified", "reason": "static PIE mode did not produce an artifact"}
                )
                runtime_contracts["packed_relr_static_pie"] = run_static_pie_relr_contract(
                    wrapper, sysroot, work, manifest, timeout=args.timeout, environment=sealed
                )
            report["runtime_contracts"] = runtime_contracts
            contracts_passed = all(
                isinstance(value, dict)
                and (value.get("passed") is True or value.get("status") == "passed")
                for value in runtime_contracts.values()
            )
            execution = {
                "status": "passed" if all(item["result"]["status"] == 0 for item in runs) and contracts_passed else "rejected",
                "runs": runs,
                "runtime_contracts_passed": contracts_passed,
            }
            if execution["status"] != "passed":
                report["failures"].append({"taxonomy": "kernel canonical-interpreter execution or runtime contract"})
        elif args.stage_canonical_loader:
            report["runtime_contracts"] = {
                "status": "unverified",
                "reason": "earlier mode or driver evidence failed; runtime execution was not attempted",
            }
        report["execution"] = execution
    report["artifact_audit"] = TOOL.audit_installed_sysroot(sysroot)
    report["reproducibility"] = reproducibility_record(sysroot, args.comparison_sysroot)
    report["purity"] = json.loads((sysroot / "share/crabc/purity.json").read_text(encoding="utf-8"))
    report["passed"] = (
        not report["failures"]
        and report["execution"]["status"] == "passed"
        and report["reproducibility"]["status"] == "passed"
        and bool(report["purity"].get("crt_sysroot_pure_rust"))
    )
    return report


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sysroot", type=Path, default=DEFAULT_SYSROOT)
    parser.add_argument("--comparison-sysroot", type=Path)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--stage-canonical-loader",
        action="store_true",
        help="temporarily stage an absent /lib/ld-crabc-aarch64.so.1 in disposable native Linux",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    report: dict[str, Any]
    try:
        if args.timeout <= 0 or args.timeout > MAX_TIMEOUT:
            raise RunnerError(f"--timeout must be > 0 and <= {MAX_TIMEOUT:g}")
        report = run(args)
    except (RunnerError, TOOL.SysrootError) as error:
        report = {
            "runner": "crabc-owned-sysroot",
            "schema": 1,
            "passed": False,
            "failure": {"taxonomy": "harness setup or ownership contract", "message": str(error)},
        }
    TOOL.atomic_json_write(args.report, report)
    print(args.report)
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
