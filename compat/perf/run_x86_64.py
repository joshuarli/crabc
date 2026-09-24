#!/usr/bin/env python3
"""Supplied-product native x86-64 C performance adapter.

This is deliberately separate from :mod:`run`.  The historical AArch64 lane
compiles one musl application and changes ``PT_INTERP``.  Native x86 instead
compiles every application/DSO source once through the supplied product's
installed headers, then separately links those exact objects through the
installed crabc driver and the pinned musl compiler.  The two provider-owned
CRT/attach/helper closures are expected to differ and are retained as such.

Nothing in this file builds a product, patches an ELF interpreter, runs an
ambient executable, or turns a smoke into a release claim.  All mutable state
belongs to an explicit fresh directory below ``.work/x86_64``.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import platform
import random
import re
import resource
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import run as aarch64_contract
import x86_64_evidence as evidence
import x86_64_peers as peers
import x86_64_profile as performance_profile


SCHEMA = evidence.SCHEMA
KIND = evidence.KIND
MUSL_VERSION = evidence.MUSL_VERSION
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
DEFAULT_MUSL_CC = "/usr/local/bin/crabc-x86_64-musl-gcc"
DEFAULT_SAMPLES = 31
DEFAULT_WARMUP = 3
# A smoke is deliberately a one-pair construction/runtime proof.  It cannot
# consume the normal qualification process budget under a softer label while
# the correctness-closed predecessor chain remains absent.
SMOKE_SAMPLES = 1
SMOKE_WARMUP = 0
IMAGE_TOOL_MANIFEST = Path("/usr/local/share/crabc-x86_64-performance-image-tools.manifest")
IMAGE_TOOL_MANIFEST_FORMAT = evidence.IMAGE_TOOL_MANIFEST_FORMAT
EXPECTED_STDOUT = b"ok\n"
APP_RUNPATH = "/app/lib:/usr/lib"
MARKER_FD = 97
READY_FD = 97
CONTINUE_FD = 98
FIXED_COMPILE_FLAGS = ("-std=c11", "-O3", "-fno-builtin")
TIMING_LAUNCHER_SCHEMA = evidence.TIMING_LAUNCHER_SCHEMA
TIMING_LAUNCHER_FLAGS = evidence.TIMING_LAUNCHER_FLAGS
TIMING_LAUNCHER_SOURCE = evidence.TIMING_LAUNCHER_SOURCE
FIXED_LINK_FLAGS = ("--hash-style=sysv", "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text")
GRAPH_NEEDED = {
    "libbench_graph_leaf_left.so": ["libc.so"],
    "libbench_graph_leaf_right.so": ["libc.so"],
    "libbench_graph_mid_left.so": ["libbench_graph_leaf_left.so", "libc.so"],
    "libbench_graph_mid_right.so": ["libbench_graph_leaf_right.so", "libc.so"],
    "libbench_graph_root.so": ["libbench_graph_mid_left.so", "libbench_graph_mid_right.so", "libc.so"],
}
GRAPH_SOURCES = evidence.GRAPH_SOURCES
ROSTER_SCHEMA = evidence.ROSTER_SCHEMA
ROSTER_KIND = evidence.ROSTER_KIND


class AdapterError(RuntimeError):
    """A setup, product, or evidence boundary failed."""


class CgroupUnsupported(AdapterError):
    """The contained cgroup/ptrace diagnostic cannot be performed honestly."""


def fail(message: str) -> AdapterError:
    return AdapterError(message)


def repository_root() -> Path:
    return HERE.parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    aarch64_contract.atomic_write_json(path, dict(value))
    # Every caller writes into an explicit adapter work directory.  Normalize
    # immediately, before its identity is embedded in another retained record.
    normalize_retained_path(repository_root(), path)


def json_with_recorded_paths(root: Path, value: Any) -> Any:
    """Convert retained in-checkout paths before serializing an evidence report."""

    if isinstance(value, Path):
        return recorded_path(root, value)
    if isinstance(value, dict):
        return {str(key): json_with_recorded_paths(root, item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_with_recorded_paths(root, item) for item in value]
    if isinstance(value, tuple):
        return [json_with_recorded_paths(root, item) for item in value]
    return value


def command_text(command: Sequence[str]) -> str:
    # This is report-only rendering.  The invoked command remains a list, so
    # no source path or application argument reaches a shell.
    return " ".join(command)


def physical_path(path: Path, label: str, *, directory: bool = False, fresh: bool = False) -> Path:
    require(".." not in path.parts, f"{label} has parent traversal: {path}")
    absolute = Path(os.path.abspath(path))
    if fresh:
        require(not absolute.exists() and not absolute.is_symlink(), f"{label} must be fresh: {absolute}")
        parent = absolute.parent.resolve(strict=True)
        require(parent.is_dir(), f"{label} parent is not a physical directory: {absolute.parent}")
        return parent / absolute.name
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise AdapterError(f"{label} is unavailable: {absolute}") from error
    require(resolved == absolute, f"{label} traverses a symlink: {absolute}")
    require(resolved.is_dir() if directory else resolved.is_file(), f"{label} has the wrong type: {absolute}")
    return resolved


def work_boundary(root: Path) -> Path:
    boundary = root / ".work/x86_64"
    boundary.mkdir(parents=True, exist_ok=True)
    boundary = physical_path(boundary, "x86 work boundary", directory=True)
    # Evidence may be produced while Docker has umask 077.  The adapter owns
    # this boundary, so make it traversable before any retained child is
    # sealed.  Individual retained files are normalized by
    # ``retained_identity`` after their producer has finished writing.
    os.chmod(boundary, stat.S_IMODE(boundary.stat().st_mode) | 0o555)
    return boundary


def fresh_work_directory(root: Path, value: Path) -> Path:
    boundary = work_boundary(root)
    candidate = physical_path(value, "native performance work directory", fresh=True)
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise AdapterError(f"native performance work directory must be below {boundary}") from error
    candidate.mkdir(mode=0o700)
    return candidate


def recorded_path(root: Path, path: Path) -> str:
    path = path.resolve(strict=True)
    try:
        return str(Path(evidence.SOURCE_MOUNT) / path.relative_to(root.resolve(strict=True)))
    except ValueError as error:
        raise AdapterError(f"retained path is outside the checkout: {path}") from error


def planned_recorded_path(root: Path, path: Path) -> str:
    """Record one not-yet-created roster path below the physical checkout.

    A roster names three fresh future work roots.  Unlike evidence identities,
    those paths cannot be resolved yet; keep the operation lexical and reject
    parent traversal before any child is created.
    """

    candidate = Path(os.path.abspath(path))
    require(".." not in candidate.parts, f"planned retained path has parent traversal: {candidate}")
    try:
        relative = candidate.relative_to(root.resolve(strict=True))
    except ValueError as error:
        raise AdapterError(f"planned retained path is outside the checkout: {candidate}") from error
    return str(Path(evidence.SOURCE_MOUNT) / relative)


def roster_path_to_host(root: Path, value: object, label: str, *, must_exist: bool, directory: bool = False) -> Path:
    """Translate a roster-declared `/workspace` path without ambient lookup."""

    require(isinstance(value, str) and value.startswith(evidence.SOURCE_MOUNT + "/"),
            f"{label} is not below the fixed source mount")
    relative = Path(value).relative_to(evidence.SOURCE_MOUNT)
    require(".." not in relative.parts, f"{label} has parent traversal")
    candidate = root.resolve(strict=True) / relative
    require(candidate.is_relative_to(root / ".work/x86_64"), f"{label} escapes native x86 work")
    if must_exist:
        return physical_path(candidate, label, directory=directory)
    ancestor = candidate.parent
    while not ancestor.exists() and ancestor != root:
        ancestor = ancestor.parent
    require(ancestor.is_dir() and not ancestor.is_symlink() and ancestor.resolve(strict=True) == ancestor,
            f"{label} parent is not below a physical directory")
    return candidate


def recorded_identity(root: Path, path: Path) -> dict[str, Any]:
    return evidence.container_file_identity(root, evidence.SOURCE_MOUNT, path)


def recorded_command(root: Path, command: Sequence[str]) -> list[str]:
    """Translate checkout-local command operands for tool-free host replay.

    Commands execute with physical container paths, but the retained report
    uses the fixed `/workspace` mount just like file identities.  Leave image
    tools and ordinary flags untouched; translate only existing physical paths
    below this checkout after the command has completed.
    """

    result: list[str] = []
    resolved_root = root.resolve(strict=True)
    for argument in command:
        candidate = Path(argument)
        if candidate.is_absolute():
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(resolved_root)
            except (OSError, ValueError):
                result.append(argument)
            else:
                result.append(recorded_path(root, resolved))
        else:
            result.append(argument)
    return result


def normalize_retained_path(root: Path, path: Path) -> None:
    """Make one adapter-owned evidence path readable before sealing it.

    Native commands commonly run with umask 077.  A later host-only ``check``
    must still be able to traverse a retained attempt without changing a mode
    after it was hashed.  This routine is deliberately limited to this
    checkout's ``.work/x86_64`` tree; it never changes supplied-product or
    source permissions.  It adds only read/traverse bits and preserves an
    executable's existing execute bits, special nodes, and symlink spelling.
    """

    boundary = root.resolve(strict=True) / ".work/x86_64"
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(boundary)
    except ValueError as error:
        raise AdapterError(f"retained evidence escapes .work/x86_64: {candidate}") from error
    require(".." not in relative.parts, f"retained evidence has parent traversal: {candidate}")
    pending = [boundary]
    current = boundary
    for component in relative.parts[:-1]:
        current = current / component
        pending.append(current)
    for directory in pending:
        state = directory.lstat()
        require(stat.S_ISDIR(state.st_mode) and not stat.S_ISLNK(state.st_mode),
                f"retained evidence parent is not a physical directory: {directory}")
        os.chmod(directory, stat.S_IMODE(state.st_mode) | 0o555, follow_symlinks=False)
    state = candidate.lstat()
    if stat.S_ISREG(state.st_mode):
        os.chmod(candidate, stat.S_IMODE(state.st_mode) | 0o444, follow_symlinks=False)
    elif stat.S_ISDIR(state.st_mode):
        os.chmod(candidate, stat.S_IMODE(state.st_mode) | 0o555, follow_symlinks=False)
    elif stat.S_ISLNK(state.st_mode) or stat.S_ISCHR(state.st_mode):
        return
    else:
        raise AdapterError(f"retained evidence has an unsupported node: {candidate}")


def normalize_retained_tree(root: Path, tree: Path) -> None:
    """Normalize an owned retained tree without following symlinks."""

    normalize_retained_path(root, tree)
    for path in sorted(tree.rglob("*"), key=lambda value: value.as_posix()):
        normalize_retained_path(root, path)


def retained_identity(root: Path, path: Path) -> dict[str, Any]:
    """Seal a newly retained adapter artifact after mode normalization."""

    normalize_retained_path(root, path)
    return recorded_identity(root, path)


def external_tool_identity(path: Path) -> dict[str, Any]:
    """Seal an image-owned executable without pretending host replay owns it.

    The retained image ID is the replayable identity for image-owned tools;
    host-side `check` must not require a native compiler, musl tree, or
    binutils installation.  The path/hash/mode/length still make an accidental
    image drift visible in the collected report.
    """

    identity = evidence.file_identity(path)
    # The musl loader is a compatibility symlink to libc in the pinned image.
    # Keep the fixed logical oracle pathname while hashing the resolved bytes,
    # so replay can distinguish its loader role from the same libc payload.
    identity["path"] = str(path)
    return identity


def capture_image_tool_manifest(root: Path, retained: Path) -> dict[str, Any]:
    """Copy the image-owned tool manifest into replayable attempt evidence.

    Docker's image ID is content-addressed but unavailable to a host-only
    replay.  This manifest is created in that image, copied before the first
    seal, and matched to the actual image tool hashes on both snapshots.
    """

    require(IMAGE_TOOL_MANIFEST.is_file() and not IMAGE_TOOL_MANIFEST.is_symlink(),
            "pinned image lacks its external-tool manifest")
    if not retained.exists():
        retained.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(IMAGE_TOOL_MANIFEST, retained)
    require(retained.is_file() and not retained.is_symlink(),
            "retained image tool manifest is not a physical file")
    try:
        lines = retained.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise AdapterError(f"cannot read retained image tool manifest: {error}") from error
    expected_paths = (
        DEFAULT_MUSL_CC, evidence.FIXED_READELF, evidence.FIXED_STRACE,
        evidence.FIXED_MUSL_LOADER, evidence.FIXED_MUSL_LIBC,
    )
    require(lines and lines[0] == f"format={IMAGE_TOOL_MANIFEST_FORMAT}",
            "image tool manifest format differs")
    require(len(lines) == 1 + len(expected_paths), "image tool manifest row count differs")
    tools: dict[str, str] = {}
    for line, expected_path in zip(lines[1:], expected_paths, strict=True):
        path, separator, digest = line.partition(" ")
        require(separator == " " and path == expected_path
                and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and path not in tools,
                "image tool manifest row differs")
        tools[path] = digest
    return {
        "raw": retained_identity(root, retained),
        "format": IMAGE_TOOL_MANIFEST_FORMAT,
        "tools": tools,
    }


def tool_snapshot(
    root: Path,
    product: Path,
    musl_cc: Path,
    cpu: int,
    allowed_affinity: Sequence[int],
    peer_cpu: int | None,
    image_manifest: Path,
) -> dict[str, Any]:
    """Seal image-owned tool bytes and their content-addressed manifest."""

    musl = external_tool_identity(musl_cc)
    readelf = external_tool_identity(Path(evidence.FIXED_READELF))
    strace = external_tool_identity(Path(evidence.FIXED_STRACE))
    musl_loader = external_tool_identity(Path(evidence.FIXED_MUSL_LOADER))
    musl_libc = external_tool_identity(Path(evidence.FIXED_MUSL_LIBC))
    manifest = capture_image_tool_manifest(root, image_manifest)
    require(manifest["tools"] == {
        DEFAULT_MUSL_CC: musl["sha256"],
        evidence.FIXED_READELF: readelf["sha256"],
        evidence.FIXED_STRACE: strace["sha256"],
        evidence.FIXED_MUSL_LOADER: musl_loader["sha256"],
        evidence.FIXED_MUSL_LIBC: musl_libc["sha256"],
    }, "image tool manifest does not bind the selected external tools")
    return {
        "candidate_driver": recorded_identity(root, product / "bin/crabc-cc-dynamic"),
        "musl_compiler": musl,
        "readelf": readelf,
        "strace": strace,
        "musl_loader": musl_loader,
        "musl_libc": musl_libc,
        "image_tool_manifest": manifest,
        "host": host_snapshot(cpu, allowed_affinity, peer_cpu),
    }


def record_product(root: Path, product: Path) -> dict[str, Any]:
    current = evidence.dynamic_product_identity(root, product)
    current["root"] = recorded_path(root, product)
    current["installed_headers"] = recorded_path(root, product / "usr/include")
    current["manifest"] = recorded_identity(root, product / "share/crabc/manifest.json")
    current["driver"] = recorded_identity(root, product / "bin/crabc-cc-dynamic")
    current["payload"] = {name: recorded_identity(root, product / name) for name in sorted(current["payload"])}
    return current


def git_clean(root: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.returncode == 0 and not result.stdout


def git_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", result.stdout.strip()) is not None, "cannot seal source revision")
    return result.stdout.strip()


def command_capture(command: Sequence[str], cwd: Path, output: Path, label: str) -> dict[str, Any]:
    """Run one construction/inspection command and retain both raw streams."""

    output.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = output.with_suffix(output.suffix + ".stdout")
    stderr_path = output.with_suffix(output.suffix + ".stderr")
    try:
        completed = subprocess.run(list(command), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as error:
        stdout_path.write_bytes(b"")
        stderr_path.write_text(f"execution failure: {error}\n", encoding="utf-8")
        raise AdapterError(f"{label} could not execute {command[0]}: {error}") from error
    stdout_path.write_bytes(completed.stdout)
    stderr_path.write_bytes(completed.stderr)
    record = {
        "command": list(command),
        "status": {"kind": "exit", "code": completed.returncode},
        "stdout": stdout_path,
        "stderr": stderr_path,
    }
    if completed.returncode:
        preview = (completed.stdout + completed.stderr)[:1024].decode("utf-8", errors="replace")
        raise AdapterError(f"{label} failed ({completed.returncode}): {command_text(command)}\n{preview}")
    return record


def readelf_capture(readelf: str, binary: Path, raw_root: Path, label: str, root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, arguments in {
        "header": ["-hW"],
        "program_headers": ["-lW"],
        "dynamic": ["-dW"],
        "dynamic_symbols": ["--dyn-syms", "-W"],
    }.items():
        capture = command_capture([readelf, *arguments, str(binary)], root, raw_root / f"{label}.{name}", f"readelf {label} {name}")
        # Preserve command stream identities in addition to the parsed raw file.
        result[name] = {
            "command": recorded_command(root, capture["command"]),
            "status": capture["status"],
            "output": retained_identity(root, capture["stdout"]),
            "stderr": retained_identity(root, capture["stderr"]),
        }
    return result


def static_readelf_capture(binary: Path, raw_root: Path, label: str, root: Path) -> dict[str, dict[str, Any]]:
    """Retain the two static-ELF observations used by the timing supervisor."""

    result: dict[str, dict[str, Any]] = {}
    for name, arguments in {"header": ["-hW"], "program_headers": ["-lW"]}.items():
        capture = command_capture(
            [evidence.FIXED_READELF, *arguments, str(binary)], root,
            raw_root / f"{label}.{name}", f"readelf {label} {name}",
        )
        result[name] = {
            "command": recorded_command(root, capture["command"]),
            "status": capture["status"],
            "output": retained_identity(root, capture["stdout"]),
            "stderr": retained_identity(root, capture["stderr"]),
        }
    return result


def raw_outputs(record: Mapping[str, Any]) -> dict[str, Any]:
    return {"stdout": record["stdout"], "stderr": record["stderr"]}


def parse_needed(dynamic_raw: Path) -> list[str]:
    return evidence.parse_dynamic_section(dynamic_raw.read_text(encoding="utf-8", errors="replace"))["needed"]


def cpuinfo_identity_sha256(raw: bytes) -> str:
    """Hash CPU identity while excluding kernel frequency telemetry.

    Linux regenerates ``cpu MHz`` and ``bogomips`` in ``/proc/cpuinfo`` from
    live frequency state.  They are useful observations, but cannot be a
    before/after tool identity because an otherwise valid fresh-process attempt
    may change them while it is running.  The remaining `/proc/cpuinfo` fields
    retain vendor, model, family, stepping, flags, topology, and cache identity.
    """

    return evidence.cpuinfo_identity_sha256(raw)


def capture_cpuinfo_diagnostic(root: Path, retained: Path) -> dict[str, Any]:
    """Retain raw CPU model/frequency telemetry outside the stable tool seal."""

    source = Path("/proc/cpuinfo")
    require(source.is_file(), "native performance image lacks readable /proc/cpuinfo")
    retained.parent.mkdir(parents=True, exist_ok=True)
    raw = source.read_bytes()
    retained.write_bytes(raw)
    return {
        "raw": retained_identity(root, retained),
        **evidence.cpuinfo_diagnostics(raw),
    }


def host_snapshot(cpu: int, allowed_affinity: Sequence[int], peer_cpu: int | None) -> dict[str, Any]:
    governors: dict[str, Any] = {}
    for name in ("scaling_governor", "scaling_available_governors"):
        path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/{name}")
        governors[name] = path.read_text(encoding="utf-8", errors="replace").strip() if path.is_file() else None
    environment = {
        name: os.environ.get(name)
        for name in sorted(("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "CRABC_PERF_DOCKER_IMAGE_ID", "CRABC_PERF_CONTAINER_POLICY", "CRABC_WORK_DIR", "CARGO_HOME"))
        if name in os.environ
    }
    cache = aarch64_contract.benchmark_cpu_cache_topology(cpu)
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "cpuinfo_sha256": cpuinfo_identity_sha256(Path("/proc/cpuinfo").read_bytes()) if Path("/proc/cpuinfo").is_file() else None,
        "benchmark_cpu": cpu,
        "allowed_affinity_before_pin": list(allowed_affinity),
        "peer_cpu": peer_cpu,
        "affinity": sorted(os.sched_getaffinity(0)),
        "cache_topology": cache,
        "governor": governors,
        "environment": environment,
        "docker_image_id": os.environ.get("CRABC_PERF_DOCKER_IMAGE_ID"),
    }


def pin_cpu(requested: int | None) -> tuple[int, tuple[int, ...]]:
    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        raise AdapterError("Linux CPU affinity APIs are unavailable")
    allowed = tuple(sorted(os.sched_getaffinity(0)))
    require(bool(allowed), "native performance runner has no allowed CPU")
    cpu = min(allowed) if requested is None else requested
    require(cpu in allowed, f"requested CPU {cpu} is outside allowed affinity {sorted(allowed)}")
    os.sched_setaffinity(0, {cpu})
    require(os.sched_getaffinity(0) == {cpu}, f"runner affinity did not remain pinned to CPU {cpu}")
    return cpu, allowed


def validate_environment(args: argparse.Namespace, root: Path) -> tuple[Path, Path, Path, int, tuple[int, ...], int | None]:
    require(sys.platform == "linux", f"requires native Linux, got {sys.platform}")
    require(platform.machine().lower() in {"x86_64", "amd64"}, f"requires native x86-64, got {platform.machine()}")
    samples = getattr(args, "samples", 1)
    warmup = getattr(args, "warmup", 0)
    require(samples > 0 and warmup >= 0 and args.timeout > 0 and args.seed >= 0,
            "invalid sample, warmup, timeout, or seed")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.label) is not None, "label has unsafe characters")
    product = physical_path(args.dynamic_product, "supplied dynamic product", directory=True)
    musl_root = physical_path(args.musl_root, "pinned musl root", directory=True)
    require(musl_root == DEFAULT_MUSL_ROOT, f"musl root must be the fixed {DEFAULT_MUSL_ROOT}")
    require(musl_root.name == f"musl-{MUSL_VERSION}", f"musl root is not pinned musl-{MUSL_VERSION}")
    require((musl_root / "lib/ld-musl-x86_64.so.1").is_file() and (musl_root / "lib/libc.so").is_file(), "pinned musl loader/libc are absent")
    musl_cc = physical_path(Path(args.musl_cc), "pinned musl compiler")
    require(musl_cc == Path(DEFAULT_MUSL_CC), f"musl compiler must be the fixed {DEFAULT_MUSL_CC}")
    require((product / "bin/crabc-cc-dynamic").is_file(), "supplied product has no installed dynamic driver")
    require(Path("/usr/bin/readelf").is_file(), "pinned image lacks /usr/bin/readelf")
    require(Path(evidence.FIXED_STRACE).is_file(), "pinned image lacks fixed /usr/bin/strace for the non-timed syscall diagnostic")
    evidence.dynamic_product_identity(root, product)
    cpu, allowed_affinity = pin_cpu(args.cpu)
    peer_cpu = next((candidate for candidate in allowed_affinity if candidate != cpu), None)
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", os.environ.get("CRABC_PERF_DOCKER_IMAGE_ID", "")) is not None,
            "native performance command must record a content-addressed Docker image ID")
    return product, musl_root, musl_cc, cpu, allowed_affinity, peer_cpu


def resolve_run_budget(args: argparse.Namespace) -> None:
    """Resolve normal and smoke process budgets before any build or timing work.

    The normal command surface remains the 31-pair/three-warmup contract.  A
    caller explicitly asking for implementation smoke gets a fixed small
    budget and cannot override it into a normal benchmark run.
    """

    if args.samples is None:
        args.samples = SMOKE_SAMPLES if args.implementation_smoke else DEFAULT_SAMPLES
    if args.warmup is None:
        args.warmup = SMOKE_WARMUP if args.implementation_smoke else DEFAULT_WARMUP
    require(isinstance(args.samples, int) and isinstance(args.warmup, int),
            "sample and warmup settings must be integers")
    if args.implementation_smoke:
        require((args.samples, args.warmup) == (SMOKE_SAMPLES, SMOKE_WARMUP),
                f"implementation smoke uses the fixed --samples {SMOKE_SAMPLES} --warmup {SMOKE_WARMUP} budget")


def require_full_run_admission(args: argparse.Namespace) -> None:
    """Admit a full-budget run only through an immutable roster and the chain.

    Checked before any environment, build, or timed child.  Omitting a roster
    cannot turn the release budget into an unbound benchmark, and the ordered
    qualification chain's reader is the only source of correctness admission.
    """

    if getattr(args, "implementation_smoke", False):
        return
    require(getattr(args, "attempt_roster", None) is not None,
            "full native performance run is unavailable without an immutable --attempt-roster")
    admission = evidence.correctness_admission(repository_root())
    require(admission["status"] == "available",
            f"full native performance run is unavailable pending {admission['owner']}: "
            + "; ".join(admission["unmet"]))


def selected_workloads(values: list[str] | None) -> tuple[aarch64_contract.Workload, ...]:
    return aarch64_contract.select_workloads(values)


def performance_rows(root: Path) -> tuple[performance_profile.PerformanceRow, ...]:
    """Return the closed timed and memory-observer contract for all 114 rows.

    The historical workload definitions remain their sole owner for the frozen
    74 invocations. The profile supplies the separate 40 native rows and the
    finite observer envelope for every row; this adapter only joins those two
    established contracts.
    """

    try:
        return performance_profile.performance_rows(root, aarch64_contract.WORKLOADS)
    except performance_profile.ProfileError as error:
        raise AdapterError(str(error)) from error


def selected_rows(root: Path, values: list[str] | None) -> tuple[performance_profile.PerformanceRow, ...]:
    """Select exact names from the combined 114-row contract."""

    rows = performance_rows(root)
    if values is None:
        return rows
    by_name = {row.name: row for row in rows}
    selected: list[performance_profile.PerformanceRow] = []
    for name in values:
        row = by_name.get(name)
        require(row is not None, f"unknown native x86 performance workload: {name}")
        require(row not in selected, f"native x86 performance workload repeats: {name}")
        selected.append(row)
    require(selected, "native x86 performance workload selection is empty")
    return tuple(selected)


@dataclass
class ObjectRecord:
    name: str
    source: Path
    object: Path
    mode: str
    command: list[str]
    raw: dict[str, Any]


@dataclass
class BuiltProvider:
    output: Path
    command: list[str]
    raw: dict[str, Any]
    receipt: Path | None = None
    # Provider-specific direct DSOs are ordinary linker inputs.  Retain their
    # identities separately from validation-only closure inputs so replay can
    # prove schema-2 and schema-3 links did not flatten their graphs.
    direct_inputs: tuple[Path, ...] = ()
    validated_closure: tuple[Path, ...] = ()


@dataclass(frozen=True)
class TimingLauncher:
    """Pinned static timing supervisor, distinct from provider artifacts."""

    source: Path
    output: Path
    command: list[str]
    raw: dict[str, Any]


@dataclass
class BuildState:
    # ``root`` is the immutable checkout/source mount.  Every generated
    # source, object, executable, receipt, and raw command stream belongs to
    # the fresh per-attempt ``work`` tree below `.work/x86_64`.
    root: Path
    work: Path
    product: Path
    musl_cc: Path
    raw_root: Path
    objects: dict[str, ObjectRecord] = field(default_factory=dict)
    candidate: dict[str, BuiltProvider] = field(default_factory=dict)
    musl: dict[str, BuiltProvider] = field(default_factory=dict)
    local_sources: dict[str, Path] = field(default_factory=dict)
    local_headers: dict[str, Path] = field(default_factory=dict)
    # Only links that use a non-empty validation-only DSO closure produce a
    # schema-3 receipt.  Keep the reader's verdict beside the link record so a
    # later host replay can re-run the narrow graph contract rather than
    # treating a receipt hash as a substitute for graph evidence.
    graph_receipts: dict[str, dict[str, Any]] = field(default_factory=dict)
    timing_launcher: TimingLauncher | None = None

    @property
    def driver(self) -> Path:
        return self.product / "bin/crabc-cc-dynamic"


def make_generated_sources(state: BuildState, rows: Sequence[performance_profile.PerformanceRow]) -> None:
    generated = state.work / "build/generated"
    generated.mkdir(parents=True, exist_ok=True)
    needed = {row.name for row in rows if row.legacy}
    if "dlsym_1" in needed:
        path = generated / "symbols_1.c"
        path.write_text(evidence.generated_source_contents("symbols_1"), encoding="utf-8")
        state.local_sources["symbols_1"] = path
    if "dlsym_1024" in needed:
        path = generated / "symbols_1024.c"
        path.write_text(evidence.generated_source_contents("symbols_1024"), encoding="utf-8")
        state.local_sources["symbols_1024"] = path
    if {"startup_dependency_graph", "dlopen_graph"} & needed:
        for name in GRAPH_SOURCES:
            path = generated / f"{name}.c"
            path.write_text(evidence.generated_source_contents(f"graph:{name}"), encoding="utf-8")
            state.local_sources[f"graph:{name}"] = path


def source_roster(
    root: Path,
    state: BuildState,
    rows: Sequence[performance_profile.PerformanceRow],
    *,
    include_memory_observers: bool,
) -> tuple[dict[str, Path], dict[str, Path]]:
    """Seal exactly the selected timed and, when requested, observer sources."""

    fixtures = root / "compat/perf/fixtures"
    names = {row.name for row in rows}
    legacy_families = {row.source_family for row in rows if row.legacy}
    supplemental_families = {row.source_family for row in rows if not row.legacy}
    sources: dict[str, Path] = {}
    # This static supervisor is a harness tool, not one of the application
    # objects or provider inputs.  Its source still belongs in every timed
    # attempt's seal because it owns the measured-child wait4 boundary.
    sources["timing_launcher"] = root / TIMING_LAUNCHER_SOURCE
    headers = {
        name: fixtures / name
        for name in evidence.HEADER_FILES
    }
    if "workload" in legacy_families:
        sources["workload"] = fixtures / evidence.STATIC_SOURCE_FILES["workload"]
    if "constructor" in legacy_families:
        sources["constructor"] = fixtures / evidence.STATIC_SOURCE_FILES["constructor"]
    if "graph" in legacy_families:
        sources["startup_graph"] = fixtures / evidence.STATIC_SOURCE_FILES["startup_graph"]
    if "dlsym_128" in names:
        sources["symbols_128"] = fixtures / evidence.STATIC_SOURCE_FILES["symbols_128"]
    if "loader_dynamic_tls_growth" in names:
        sources["tls_growth"] = fixtures / evidence.STATIC_SOURCE_FILES["tls_growth"]
    sources.update(state.local_sources)
    try:
        profile = performance_profile.load_profile(root)
        fixtures_by_binary = performance_profile.supplemental_fixtures(profile)
    except performance_profile.ProfileError as error:
        raise AdapterError(str(error)) from error
    for family in sorted(supplemental_families):
        fixture = fixtures_by_binary.get(family)
        require(fixture is not None, f"supplemental fixture source is absent: {family}")
        sources[f"supplemental:{family}"] = root / fixture.source
    peer_rows = [row for row in rows if row_uses_private_peer(row)]
    if peer_rows:
        # These helpers run outside the measured client but define the exact
        # loopback/DNS inputs that its conventional resolver and sockets see.
        sources["peer_helper"] = root / "compat/perf/x86_64_peers.py"
    if any(row.requires_hermetic_resolver_files for row in peer_rows):
        sources["dns_server"] = root / "compat/resolver-network/dns_server.py"
    if supplemental_families:
        headers["x86_64_workload_protocol.h"] = root / "compat/perf/x86_64_workload_protocol.h"
    if include_memory_observers:
        for family in sorted(legacy_families):
            artifact = performance_profile.LEGACY_MEMORY_ARTIFACTS.get(family)
            source = performance_profile.LEGACY_MEMORY_SOURCES.get(family)
            require(artifact is not None and source is not None, f"legacy memory observer source is absent: {family}")
            sources[f"memory_observer:{artifact}"] = root / source
        for family in sorted(supplemental_families):
            artifact = performance_profile.SUPPLEMENTAL_MEMORY_ARTIFACTS.get(family)
            source = performance_profile.SUPPLEMENTAL_MEMORY_SOURCES.get(family)
            require(artifact is not None and source is not None, f"supplemental memory observer source is absent: {family}")
            sources[f"memory_observer:{artifact}"] = root / source
        headers["x86_64_memory_observer_protocol.h"] = root / "compat/perf/x86_64_memory_observer_protocol.h"
        headers["x86_64_supplemental_memory_observer.h"] = root / "compat/perf/x86_64_supplemental_memory_observer.h"
    headers["x86_64-profile.toml"] = root / performance_profile.PROFILE_RELATIVE_PATH
    for name, path in [*sources.items(), *headers.items()]:
        require(path.is_file() and not path.is_symlink(), f"performance source/header is absent: {name}")
    return sources, headers


def compile_object(state: BuildState, name: str, source: Path, *, shared: bool, extra: Sequence[str] = ()) -> ObjectRecord:
    require(name not in state.objects, f"duplicate compilation object: {name}")
    destination = state.work / "build/objects" / f"{name.replace(':', '_')}.o"
    destination.parent.mkdir(parents=True, exist_ok=True)
    mode = "--dynamic-shared-object" if shared else "--dynamic-pie"
    command = [
        str(state.driver), mode, *FIXED_COMPILE_FLAGS,
        "--application-quote-include-dir", str(state.root / "compat/perf/fixtures"),
        *extra, "-c", str(source), "-o", str(destination),
    ]
    capture = command_capture(command, state.root, state.raw_root / f"compile-{name}", f"compile {name}")
    require(destination.is_file(), f"installed driver did not produce object: {name}")
    record = ObjectRecord(
        name=name,
        source=source,
        object=destination,
        mode=mode,
        command=recorded_command(state.root, capture["command"]),
        raw={
            "stdout": retained_identity(state.root, capture["stdout"]),
            "stderr": retained_identity(state.root, capture["stderr"]),
        },
    )
    state.objects[name] = record
    return record


def supplemental_compile_flags(root: Path, family: str) -> tuple[str, ...]:
    """Translate the profile's closed source defines into driver flags."""

    try:
        fixtures = performance_profile.supplemental_fixtures(performance_profile.load_profile(root))
    except performance_profile.ProfileError as error:
        raise AdapterError(str(error)) from error
    fixture = fixtures.get(family)
    require(fixture is not None and fixture.c_standard == "c11", f"supplemental fixture compile contract differs: {family}")
    return tuple(f"-D{value}" for value in fixture.compile_defines)


def supplemental_link_flags(root: Path, family: str) -> tuple[str, ...]:
    """Return the profile-owned provider flags for one supplemental family.

    ``-pthread`` is a normal C driver spelling.  It deliberately reaches both
    provider links: the installed driver forwards it to its C translation
    policy, while the pinned musl compiler resolves pthread symbols from its
    integrated libc without adding a second runtime input.
    """

    try:
        fixtures = performance_profile.supplemental_fixtures(performance_profile.load_profile(root))
    except performance_profile.ProfileError as error:
        raise AdapterError(str(error)) from error
    fixture = fixtures.get(family)
    require(fixture is not None, f"supplemental fixture link contract is absent: {family}")
    return fixture.link_flags


def compile_required_objects(
    state: BuildState,
    sources: Mapping[str, Path],
    rows: Sequence[performance_profile.PerformanceRow],
) -> None:
    if "workload" in sources:
        compile_object(state, "workload", sources["workload"], shared=False)
    if "constructor" in sources:
        compile_object(state, "constructor", sources["constructor"], shared=False)
    if "startup_graph" in sources:
        compile_object(state, "startup_graph", sources["startup_graph"], shared=False)
    if "symbols_1" in sources:
        compile_object(state, "symbols_1", sources["symbols_1"], shared=True)
    if "symbols_128" in sources:
        compile_object(state, "symbols_128", sources["symbols_128"], shared=True)
    if "symbols_1024" in sources:
        compile_object(state, "symbols_1024", sources["symbols_1024"], shared=True)
    if "tls_growth" in sources:
        for index in range(8):
            compile_object(state, f"tls_{index}", sources["tls_growth"], shared=True, extra=(f"-DTLS_GROWTH_INDEX={index}",))
    for name, source in sorted(sources.items()):
        if name.startswith("graph:"):
            compile_object(state, name, source, shared=True)
        elif name.startswith("supplemental:"):
            family = name.removeprefix("supplemental:")
            compile_object(state, name, source, shared=False, extra=supplemental_compile_flags(state.root, family))
        elif name.startswith("memory_observer:"):
            compile_object(state, name, source, shared=False)


def compile_timing_launcher(state: BuildState, source: Path) -> TimingLauncher:
    """Build the static supervisor as harness evidence, never a lane input."""

    require(state.timing_launcher is None, "timing launcher was compiled more than once")
    require(source == state.root / TIMING_LAUNCHER_SOURCE and source.is_file() and not source.is_symlink(),
            "timing launcher source differs")
    output = state.work / "build/harness/x86_64_timing_launcher"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [str(state.musl_cc), *TIMING_LAUNCHER_FLAGS, str(source), "-o", str(output)]
    capture = command_capture(command, state.root, state.raw_root / "timing-launcher-compile", "timing launcher compile")
    require(output.is_file() and not output.is_symlink() and output.stat().st_mode & 0o111,
            "pinned compiler did not produce the static timing launcher")
    static_raw = static_readelf_capture(output, state.raw_root, "timing-launcher", state.root)
    header = Path(str(static_raw["header"]["output"]["path"]).replace(evidence.SOURCE_MOUNT, str(state.root), 1))
    programs = Path(str(static_raw["program_headers"]["output"]["path"]).replace(evidence.SOURCE_MOUNT, str(state.root), 1))
    evidence.parse_x86_64_static_exec_header(header.read_text(encoding="utf-8", errors="replace"))
    require(not evidence.parse_program_interpreters(programs.read_text(encoding="utf-8", errors="replace")),
            "static timing launcher unexpectedly has PT_INTERP")
    require(evidence.physical_x86_64_static_exec_facts(output) == {"interpreters": [], "dynamic_segments": 0},
            "static timing launcher bytes differ")
    launcher = TimingLauncher(
        source=source,
        output=output,
        command=recorded_command(state.root, capture["command"]),
        raw={
            "compile": {
                "stdout": retained_identity(state.root, capture["stdout"]),
                "stderr": retained_identity(state.root, capture["stderr"]),
            },
            "readelf": static_raw,
        },
    )
    state.timing_launcher = launcher
    return launcher


def candidate_link(
    state: BuildState,
    name: str,
    objects: Sequence[ObjectRecord],
    *,
    shared: bool,
    direct: Sequence[Path] = (),
    transitive: Sequence[Path] = (),
    link_flags: Sequence[str] = (),
) -> BuiltProvider:
    output = state.work / "build/candidate" / ("lib" if shared else "bin") / name
    output.parent.mkdir(parents=True, exist_ok=True)
    mode = "--dynamic-shared-object" if shared else "--dynamic-pie"
    command = [
        str(state.driver), mode, "--binding", "now", "--application-runpath", APP_RUNPATH,
        "--application-hash-style", "sysv",
        *link_flags,
        *(str(item.object) for item in objects),
        *(argument for path in direct for argument in ("--application-dso", str(path))),
        *(argument for path in transitive for argument in ("--transitive-application-dso", str(path))),
        "-o", str(output),
    ]
    capture = command_capture(command, state.root, state.raw_root / f"candidate-link-{name}", f"candidate link {name}")
    receipt = Path(str(output) + ".crabc-link.json")
    require(output.is_file() and receipt.is_file(), f"installed driver did not retain output/receipt: {name}")
    raw = readelf_capture("/usr/bin/readelf", output, state.raw_root, f"candidate-{name}", state.root)
    raw["link_stdout"] = retained_identity(state.root, capture["stdout"])
    raw["link_stderr"] = retained_identity(state.root, capture["stderr"])
    raw["receipt"] = retained_identity(state.root, receipt)
    provider = BuiltProvider(
        output=output,
        command=recorded_command(state.root, capture["command"]),
        raw=raw,
        receipt=receipt,
        direct_inputs=tuple(direct),
        validated_closure=tuple(transitive),
    )
    if not transitive:
        evidence.validate_dynamic_direct_receipt(
            checkout=state.root,
            product=state.product,
            receipt_path=receipt,
            output=output,
            dynamic_raw=dynamic_raw_path(provider, state.root),
            expected_direct=tuple(direct),
            expected_mode="shared" if shared else "pie",
            expected_search_path=APP_RUNPATH,
        )
    state.candidate[name] = provider
    return provider


def musl_link(
    state: BuildState,
    name: str,
    objects: Sequence[ObjectRecord],
    *,
    shared: bool,
    direct: Sequence[Path] = (),
    closure: Sequence[Path] = (),
    link_flags: Sequence[str] = (),
) -> BuiltProvider:
    output = state.work / "build/musl" / ("lib" if shared else "bin") / name
    output.parent.mkdir(parents=True, exist_ok=True)
    linker_flags = [
        "-Wl,--hash-style=sysv", "-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack", "-Wl,-z,text",
        "-Wl,--enable-new-dtags", f"-Wl,-rpath,{APP_RUNPATH}", "-Wl,--no-as-needed",
    ]
    # The fixed musl compiler has no application-closure spelling.  Its LLD
    # command receives only executable-direct roots; rpath-link gives the
    # linker a validation/search directory for those roots' declared edges
    # without putting any transitive DSO on the command line or DT_NEEDED.
    linker_flags.extend(
        f"-Wl,-rpath-link,{directory}"
        for directory in sorted({str(path.parent) for path in closure})
    )
    command = [str(state.musl_cc), *( ["-shared", f"-Wl,-soname,{name}"] if shared else ["-pie"] ), *linker_flags,
               *link_flags,
               *(str(item.object) for item in objects), *(str(path) for path in direct), "-o", str(output)]
    capture = command_capture(command, state.root, state.raw_root / f"musl-link-{name}", f"musl link {name}")
    require(output.is_file(), f"pinned musl compiler did not produce output: {name}")
    raw = readelf_capture("/usr/bin/readelf", output, state.raw_root, f"musl-{name}", state.root)
    raw["link_stdout"] = retained_identity(state.root, capture["stdout"])
    raw["link_stderr"] = retained_identity(state.root, capture["stderr"])
    provider = BuiltProvider(
        output=output,
        command=recorded_command(state.root, capture["command"]),
        raw=raw,
        direct_inputs=tuple(direct),
        validated_closure=tuple(closure),
    )
    state.musl[name] = provider
    return provider


def dynamic_raw_path(provider: BuiltProvider, root: Path) -> Path:
    raw = provider.raw["dynamic"]["output"]
    return Path(str(raw["path"]).replace(evidence.SOURCE_MOUNT, str(root), 1))


def assert_provider_dynamic(provider: BuiltProvider, root: Path, expected_needed: Sequence[str], label: str) -> None:
    raw_path = dynamic_raw_path(provider, root)
    parsed = evidence.parse_dynamic_section(raw_path.read_text(encoding="utf-8", errors="replace"))
    require(parsed["needed"] == list(expected_needed), f"{label} DT_NEEDED differs: {parsed['needed']}")
    require(parsed["runpath"] == [APP_RUNPATH] and not parsed["rpath"], f"{label} search policy differs")
    require(parsed["hashes"] == ["sysv"], f"{label} hash style differs")


def link_required_artifacts(state: BuildState, rows: Sequence[performance_profile.PerformanceRow]) -> None:
    names = {row.name for row in rows if row.legacy}
    # Link application-owned DSOs before their users.  Every matching pair
    # receives the same installed-header object; only provider closures vary.
    for dso_name, object_name in (("libsymbols_1.so", "symbols_1"), ("libsymbols_128.so", "symbols_128"), ("libsymbols_1024.so", "symbols_1024")):
        if object_name in state.objects:
            candidate_link(state, dso_name, [state.objects[object_name]], shared=True)
            musl_link(state, dso_name, [state.objects[object_name]], shared=True)
            assert_provider_dynamic(state.candidate[dso_name], state.root, ["libc.so"], f"candidate {dso_name}")
            assert_provider_dynamic(state.musl[dso_name], state.root, ["libc.so"], f"musl {dso_name}")
    for index in range(8):
        object_name = f"tls_{index}"
        if object_name in state.objects:
            name = f"libbench_tls_growth_{index}.so"
            candidate_link(state, name, [state.objects[object_name]], shared=True)
            musl_link(state, name, [state.objects[object_name]], shared=True)
            assert_provider_dynamic(state.candidate[name], state.root, ["libc.so"], f"candidate {name}")
            assert_provider_dynamic(state.musl[name], state.root, ["libc.so"], f"musl {name}")
    graph_needed = any(name.startswith("graph:") for name in state.objects)
    if graph_needed:
        leaves = ("libbench_graph_leaf_left.so", "libbench_graph_leaf_right.so")
        middles = ("libbench_graph_mid_left.so", "libbench_graph_mid_right.so")
        root_closure_needed = {name: GRAPH_NEEDED[name] for name in (*leaves, *middles)}
        for name in leaves:
            object_record = state.objects[f"graph:{name}"]
            candidate_link(state, name, [object_record], shared=True)
            musl_link(state, name, [object_record], shared=True)
            assert_provider_dynamic(state.candidate[name], state.root, GRAPH_NEEDED[name], f"candidate {name}")
            assert_provider_dynamic(state.musl[name], state.root, GRAPH_NEEDED[name], f"musl {name}")
        direct_leaf = {
            "libbench_graph_mid_left.so": "libbench_graph_leaf_left.so",
            "libbench_graph_mid_right.so": "libbench_graph_leaf_right.so",
        }
        for name in middles:
            leaf = direct_leaf[name]
            object_record = state.objects[f"graph:{name}"]
            candidate_link(state, name, [object_record], shared=True, direct=[state.candidate[leaf].output])
            musl_link(state, name, [object_record], shared=True, direct=[state.musl[leaf].output])
            assert_provider_dynamic(state.candidate[name], state.root, GRAPH_NEEDED[name], f"candidate {name}")
            assert_provider_dynamic(state.musl[name], state.root, GRAPH_NEEDED[name], f"musl {name}")
        root_name = "libbench_graph_root.so"
        root_object = state.objects[f"graph:{root_name}"]
        candidate_link(
            state, root_name, [root_object], shared=True,
            direct=[state.candidate[name].output for name in middles],
            transitive=[state.candidate[name].output for name in leaves],
        )
        musl_link(
            state, root_name, [root_object], shared=True,
            direct=[state.musl[name].output for name in middles],
            closure=[state.musl[name].output for name in leaves],
        )
        assert_provider_dynamic(state.candidate[root_name], state.root, GRAPH_NEEDED[root_name], f"candidate {root_name}")
        assert_provider_dynamic(state.musl[root_name], state.root, GRAPH_NEEDED[root_name], f"musl {root_name}")
        evidence.validate_dynamic_graph_receipt(
            checkout=state.root, product=state.product, receipt_path=state.candidate[root_name].receipt, output=state.candidate[root_name].output,
            dynamic_raw=dynamic_raw_path(state.candidate[root_name], state.root), expected_direct=middles,
            expected_needed=root_closure_needed, expected_search_path=APP_RUNPATH,
        )
        state.graph_receipts[root_name] = {
            "receipt": retained_identity(state.root, state.candidate[root_name].receipt),
            "output": retained_identity(state.root, state.candidate[root_name].output),
            "dynamic_raw": retained_identity(state.root, dynamic_raw_path(state.candidate[root_name], state.root)),
            "direct_dsos": list(middles),
            "closure_needed": {name: list(root_closure_needed[name]) for name in sorted(root_closure_needed)},
        }

    def link_plain_executable(name: str, object_name: str, *, link_flags: Sequence[str] = ()) -> None:
        """Link one non-graph executable through both fixed providers."""

        candidate_link(
            state, name, [state.objects[object_name]], shared=False,
            link_flags=link_flags,
        )
        musl_link(
            state, name, [state.objects[object_name]], shared=False,
            link_flags=link_flags,
        )
        assert_provider_dynamic(state.candidate[name], state.root, ["libc.so"], f"candidate {name}")
        assert_provider_dynamic(state.musl[name], state.root, ["libc.so"], f"musl {name}")

    def link_graph_executable(name: str, object_name: str) -> None:
        """Link a graph consumer with only its root as an executable edge."""

        root_name = "libbench_graph_root.so"
        closure = (
            "libbench_graph_mid_left.so", "libbench_graph_mid_right.so",
            "libbench_graph_leaf_left.so", "libbench_graph_leaf_right.so",
        )
        candidate_link(
            state, name, [state.objects[object_name]], shared=False,
            direct=[state.candidate[root_name].output],
            transitive=[state.candidate[item].output for item in closure],
        )
        musl_link(
            state, name, [state.objects[object_name]], shared=False,
            direct=[state.musl[root_name].output],
            closure=[state.musl[item].output for item in closure],
        )
        assert_provider_dynamic(state.candidate[name], state.root, [root_name, "libc.so"], f"candidate {name}")
        assert_provider_dynamic(state.musl[name], state.root, [root_name, "libc.so"], f"musl {name}")
        evidence.validate_dynamic_graph_receipt(
            checkout=state.root, product=state.product,
            receipt_path=state.candidate[name].receipt,
            output=state.candidate[name].output,
            dynamic_raw=dynamic_raw_path(state.candidate[name], state.root),
            expected_direct=[root_name], expected_needed=GRAPH_NEEDED,
            expected_search_path=APP_RUNPATH,
        )
        state.graph_receipts[name] = {
            "receipt": retained_identity(state.root, state.candidate[name].receipt),
            "output": retained_identity(state.root, state.candidate[name].output),
            "dynamic_raw": retained_identity(state.root, dynamic_raw_path(state.candidate[name], state.root)),
            "direct_dsos": [root_name],
            "closure_needed": {item: list(GRAPH_NEEDED[item]) for item in sorted(GRAPH_NEEDED)},
        }

    if "workload" in state.objects:
        link_plain_executable("workload", "workload")
    if "constructor" in state.objects:
        link_plain_executable("constructor", "constructor")
    if "startup_graph" in state.objects:
        link_graph_executable("graph", "startup_graph")

    # The supplemental timed sources are separate C artifacts.  Compile once
    # with installed headers, then link those exact object bytes through both
    # providers.  The profile's normal C driver flags apply symmetrically.
    for family in sorted(performance_profile.SUPPLEMENTAL_TIMED_SOURCES):
        object_name = f"supplemental:{family}"
        if object_name in state.objects:
            link_plain_executable(family, object_name, link_flags=supplemental_link_flags(state.root, family))

    # Memory observers are deliberately separate non-timed artifacts.  They
    # use the same source family link policy, but never replace the timed
    # binary in a CPU/syscall sample.
    for family, artifact in sorted(performance_profile.LEGACY_MEMORY_ARTIFACTS.items()):
        object_name = f"memory_observer:{artifact}"
        if object_name not in state.objects:
            continue
        if family == "graph":
            link_graph_executable(artifact, object_name)
        else:
            link_plain_executable(artifact, object_name)
    for family, artifact in sorted(performance_profile.SUPPLEMENTAL_MEMORY_ARTIFACTS.items()):
        object_name = f"memory_observer:{artifact}"
        if object_name in state.objects:
            link_plain_executable(artifact, object_name, link_flags=supplemental_link_flags(state.root, family))


def build_record(root: Path, state: BuildState) -> dict[str, Any]:
    objects: dict[str, Any] = {}
    for name, item in sorted(state.objects.items()):
        objects[name] = {
            "source": retained_identity(root, item.source) if item.source.is_relative_to(root / ".work/x86_64") else recorded_identity(root, item.source),
            "object": retained_identity(root, item.object),
            "mode": item.mode,
            "compile_command": item.command,
            "raw": item.raw,
        }
    links: dict[str, Any] = {}
    for name in sorted(set(state.candidate) | set(state.musl)):
        candidate = state.candidate[name]
        musl = state.musl[name]
        object_records = [
            retained_identity(root, state.objects[item].object)
            for item in sorted(state.objects)
            if state.objects[item].object.as_posix() in candidate.command
        ]
        require(object_records, f"link {name} has no tracked application object")
        links[name] = {
            "objects": object_records,
            "candidate": {
                "output": retained_identity(root, candidate.output),
                "command": candidate.command,
                "raw": candidate.raw,
                "direct_inputs": [retained_identity(root, path) for path in candidate.direct_inputs],
                "validated_closure": [retained_identity(root, path) for path in candidate.validated_closure],
            },
            "musl": {
                "output": retained_identity(root, musl.output),
                "command": musl.command,
                "raw": musl.raw,
                "direct_inputs": [retained_identity(root, path) for path in musl.direct_inputs],
                "validated_closure": [retained_identity(root, path) for path in musl.validated_closure],
            },
            **({"dynamic_graph": state.graph_receipts[name]} if name in state.graph_receipts else {}),
        }
    inputs = {"io_fixture": sha256_bytes(bytes(range(256)) * 16)}
    launcher = state.timing_launcher
    require(launcher is not None, "timing launcher build record is absent")
    return {
        "objects": objects,
        "links": links,
        "harness": {
            "timing_launcher": {
                "source": recorded_identity(root, launcher.source),
                "output": retained_identity(root, launcher.output),
                "compile_command": launcher.command,
                "compile_raw": launcher.raw["compile"],
                "readelf": launcher.raw["readelf"],
            },
        },
        "same_object_input_proof": {
            "objects": {name: item["object"]["sha256"] for name, item in sorted(objects.items())},
            "inputs": inputs,
        },
    }


def verify_same_object_input_proof(path: Path, proof: Mapping[str, Any]) -> None:
    prior = evidence.load_json(path, "same-object/input proof")
    require(prior == proof, "installed and extracted smoke products did not receive the same object/input proof")


@dataclass
class Lane:
    name: str
    root: Path
    binaries: dict[str, str]
    dsos: dict[str, str]
    io_file: str
    span_inputs: dict[str, str]
    environment: dict[str, str]
    inventory: list[dict[str, Any]] | None = None
    observed_mappings: dict[str, Any] | None = None


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def stage_musl_runtime(root: Path, musl_root: Path) -> None:
    """Stage musl at both its canonical interpreter and library locations.

    The pinned compiler emits the kernel-visible absolute interpreter
    ``/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1``. It must remain unmodified.
    A relative alias from that canonical path to the staged ``/lib`` payload
    keeps one retained loader/libc byte source while making the selected
    `PT_INTERP` path reachable inside the private chroot.
    """

    staged = {
        "ld-musl-x86_64.so.1": root / "lib/ld-musl-x86_64.so.1",
        "libc.so": root / "lib/libc.so",
    }
    for name, destination in staged.items():
        copy_file(musl_root / "lib" / name, destination)
    copy_file(musl_root / "lib/libc.so", root / "usr/lib/libc.so")
    canonical = root / evidence.FIXED_MUSL_LOADER.lstrip("/")
    canonical.parent.mkdir(parents=True, exist_ok=True)
    for name, destination in staged.items():
        alias = canonical.parent / name
        alias.symlink_to(os.path.relpath(destination, alias.parent))


def create_dev_null(root: Path) -> None:
    path = root / "dev/null"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(1, 3))
    except FileExistsError:
        pass
    except OSError as error:
        raise AdapterError(f"cannot stage Linux /dev/null char 1:3 fixture: {error}") from error
    state = path.lstat()
    require(stat.S_ISCHR(state.st_mode) and os.major(state.st_rdev) == 1 and os.minor(state.st_rdev) == 3, "staged /dev/null is not char 1:3")


def copy_candidate_product(product: Path, destination: Path) -> None:
    identity = evidence.dynamic_product_identity(repository_root(), product)
    for relative in identity["payload"]:
        copy_file(product / relative, destination / relative)
    alias = destination / "lib/ld-musl-x86_64.so.1"
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.symlink_to("ld-crabc-x86_64.so.1")


def stage_lane(
    work: Path,
    state: BuildState,
    *,
    name: str,
    selected: Sequence[performance_profile.PerformanceRow],
    product: Path,
    musl_root: Path,
) -> Lane:
    lane_root = work / "execution/roots" / name
    lane_root.mkdir(parents=True, exist_ok=False)
    if name == "crabc":
        copy_candidate_product(product, lane_root)
        provider = state.candidate
    else:
        stage_musl_runtime(lane_root, musl_root)
        provider = state.musl
    create_dev_null(lane_root)
    binaries = {key: f"/app/bin/{key}" for key in sorted(provider) if not key.endswith(".so")}
    for key, virtual in binaries.items():
        copy_file(provider[key].output, lane_root / virtual.lstrip("/"))
    dsos: dict[str, str] = {}
    for key, artifact in provider.items():
        if key.endswith(".so"):
            virtual = f"/app/lib/{key}"
            copy_file(artifact.output, lane_root / virtual.lstrip("/"))
            dsos[key] = virtual
    io_file = "/app/input/io-fixture.bin"
    io_bytes = bytes(range(256)) * 16
    destination = lane_root / io_file.lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(io_bytes)
    span_inputs: dict[str, str] = {}
    if any(row.legacy and row.fixture_mode == "span_matrix" for row in selected):
        for input_name, offset in (("span-aligned.bin", 0), ("span-unaligned.bin", 3)):
            virtual = f"/app/input/{input_name}"
            aarch64_contract.stage_cache_span_source(lane_root / virtual.lstrip("/"), span_bytes=aarch64_contract.CACHE_SPAN_BYTES, offset=offset)
            span_inputs[input_name] = virtual
        virtual = "/app/input/span-destination.bin"
        path = lane_root / virtual.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as output:
            output.truncate(3 + aarch64_contract.CACHE_SPAN_BYTES + aarch64_contract.CACHE_SPAN_PADDING_BYTES)
        span_inputs["span-destination.bin"] = virtual
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "LD_LIBRARY_PATH": "/app/lib:/usr/lib:/lib",
    }
    return Lane(name=name, root=lane_root, binaries=binaries, dsos=dsos, io_file=io_file, span_inputs=span_inputs, environment=environment)


def virtual_arguments(row: performance_profile.PerformanceRow, lane: Lane) -> list[str]:
    # A focused smoke may select a row that does not need any loader fixture.
    # `workload_arguments` only consumes the corresponding value for the rows
    # that declare it, so a physical sentinel keeps that narrow smoke from
    # accidentally requiring unrelated DSOs while never making an absent DSO
    # usable by a selected row.
    if not row.legacy:
        return list(row.arguments)
    workload = row.legacy_workload
    require(workload is not None, f"legacy workload is absent for {row.name}")
    dso = lambda name: Path(lane.dsos.get(name, "/missing"))
    return aarch64_contract.workload_arguments(
        workload,
        dso("libsymbols_1.so"), dso("libsymbols_128.so"), dso("libsymbols_1024.so"),
        Path(lane.dsos.get("libbench_graph_root.so", "/missing")), Path(lane.io_file),
        Path(lane.span_inputs.get("span-aligned.bin", "/missing")),
        Path(lane.span_inputs.get("span-unaligned.bin", "/missing")),
        Path(lane.span_inputs.get("span-destination.bin", "/missing")),
        Path("/app/lib"),
    )


def virtual_binary(row: performance_profile.PerformanceRow, lane: Lane) -> str:
    key = row.timed_artifact
    require(key in lane.binaries, f"staged {lane.name} lane lacks binary for {row.name}")
    return lane.binaries[key]


def row_uses_private_peer(row: performance_profile.PerformanceRow) -> bool:
    """Return whether this exact row needs owned loopback/DNS infrastructure."""

    return row.requires_loopback_peer or row.requires_hermetic_resolver_files


def start_row_peer(
    checkout: Path,
    lane: Lane,
    row: performance_profile.PerformanceRow,
    invocation_work: Path,
    client_cpu: int,
    peer_cpu: int | None,
    allowed_affinity: Sequence[int],
    timeout: float,
    *,
    iterations: int | None = None,
) -> peers.PeerContext | None:
    """Start one non-client peer context for a selected network invocation.

    Peer processes stay outside the chroot and its diagnostic cgroup leaf.
    The returned context is stopped by the caller after the exact client child
    is reaped; it never launches or measures that client itself.
    """

    if not row_uses_private_peer(row):
        return None
    require(peer_cpu is not None and peer_cpu != client_cpu and peer_cpu in allowed_affinity,
            f"private peer row lacks a distinct allowed peer CPU: {row.name}")
    require(not row.legacy and row.fixture_mode is not None,
            f"private peer row lacks its supplemental fixture contract: {row.name}")
    arguments = virtual_arguments(row, lane)
    require(arguments[:2] == [row.fixture_mode, str(row.iterations)],
            f"private peer invocation prefix differs for {row.name}")
    context: peers.PeerContext | None = None
    try:
        context = peers.start_context(
            checkout,
            row_id=row.name,
            mode=row.fixture_mode,
            invocation_work=invocation_work,
            client_root=lane.root,
            cpu=peer_cpu,
            allowed_affinity=allowed_affinity,
            iterations=iterations,
            timeout_seconds=timeout,
        )
        require(list(context.argv) == arguments[2:], f"private peer argv differs for {row.name}")
        context.stage_resolver_files()
        return context
    except (peers.PeerError, AdapterError) as error:
        if context is not None:
            context.stop()
        raise AdapterError(f"private peer setup failed for {row.name}: {error}") from error


def stop_row_peer(checkout: Path, context: peers.PeerContext | None) -> tuple[dict[str, Any] | None, str | None]:
    """Retain one peer result without replacing a primary client failure."""

    if context is None:
        return None, None
    record = context.stop()
    try:
        peers.validate_context(checkout, record, require_complete=True)
    except peers.PeerError as error:
        return record, str(error)
    return record, None


def rusage_record(value: resource.struct_rusage) -> dict[str, int]:
    return aarch64_contract.rusage_record(value)


def wait_child(pid: int, timeout: float) -> tuple[int, resource.struct_rusage, bool]:
    """Wait for exactly one child without an unbounded post-timeout wait.

    Timed children normally exit quickly, but a measurement harness must not
    turn a stuck child into an indefinitely blocked collector.  The same
    bounded wait is used after SIGKILL, so a failed attempt retains its actual
    failure instead of creating a synthetic successful sample.
    """

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            completed, status, usage = os.wait4(pid, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError as error:
            raise AdapterError("timed child disappeared before wait4 completed") from error
        if completed == pid:
            if os.WIFSTOPPED(status):
                continue
            return status, usage, False
        time.sleep(min(0.001, max(0.0, deadline - time.monotonic())))
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    reap_deadline = time.monotonic() + max(0.25, min(timeout, 2.0))
    while time.monotonic() < reap_deadline:
        try:
            completed, status, usage = os.wait4(pid, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError as error:
            raise AdapterError("timed child disappeared during timeout cleanup") from error
        if completed == pid:
            if os.WIFSTOPPED(status):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                continue
            return status, usage, True
        time.sleep(min(0.001, max(0.0, reap_deadline - time.monotonic())))
    raise AdapterError("timed child could not be reaped before cleanup deadline")


def kill_and_reap_child(pid: int, timeout: float) -> tuple[int, resource.struct_rusage] | None:
    """Best-effort bounded cleanup for one ordinary child.

    This is only used on failed diagnostics.  A ``None`` result is itself a
    retained failure condition; callers must never replace it with a guessed
    status or block forever in ``wait4(pid, 0)``.
    """

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + max(0.25, min(timeout, 2.0))
    while time.monotonic() < deadline:
        try:
            waited, status, usage = os.wait4(pid, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError:
            return None
        if waited == pid:
            if os.WIFSTOPPED(status):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                continue
            return status, usage
        time.sleep(min(0.001, max(0.0, deadline - time.monotonic())))
    return None


def status_record(status: int, timed_out: bool) -> dict[str, Any]:
    return aarch64_contract.status_record(status, timed_out)


# Linux introduced close_range(2) in 5.9, so the project's 5.10 baseline has
# it.  The timed and diagnostic children retain only a small fixed FD set; a
# syscall interval on either side of those descriptors closes everything else
# without charging an RLIMIT-sized Python close loop to the child.  This is
# native x86-64 only, hence the explicit syscall number rather than an
# incomplete portability wrapper.
SYS_CLOSE_RANGE_X86_64 = 436
CLOSE_RANGE_LAST = (1 << 32) - 1


def _kernel_close_range(first: int, last: int) -> None:
    """Close one inclusive descriptor interval with Linux ``close_range``."""

    require(0 <= first <= last <= CLOSE_RANGE_LAST, "close_range descriptor interval is invalid")
    result = _libc.syscall(
        ctypes.c_long(SYS_CLOSE_RANGE_X86_64),
        ctypes.c_ulong(first),
        ctypes.c_ulong(last),
        ctypes.c_ulong(0),
    )
    if result == -1:
        code = ctypes.get_errno()
        if code == errno.ENOSYS:
            raise AdapterError("Linux 5.10 close_range syscall is unavailable")
        raise OSError(code, f"close_range({first}, {last}, 0) failed")


def close_inherited_descriptors(keep: set[int]) -> None:
    """Close every nonstandard inherited descriptor with fixed child setup.

    Keep descriptors divide the unsigned 32-bit kernel range into a handful
    of disjoint intervals.  There is deliberately no per-number fallback:
    the required native kernel provides ``close_range`` and an unavailable
    syscall makes the attempted child fail with its real error.
    """

    require(all(type(descriptor) is int and 0 <= descriptor <= CLOSE_RANGE_LAST for descriptor in keep),
            "inherited descriptor roster is invalid")
    start = 3
    for descriptor in sorted(value for value in keep if value >= 3):
        if start < descriptor:
            _kernel_close_range(start, descriptor - 1)
        start = descriptor + 1
    if start <= CLOSE_RANGE_LAST:
        _kernel_close_range(start, CLOSE_RANGE_LAST)


def child_exec(
    root: Path,
    binary: str,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    ready_write: int | None = None,
    continue_read: int | None = None,
    marker_fd: int | None = None,
) -> None:
    """The sole diagnostic/observer child setup: FDs, chroot, cwd, execve.

    The timed launcher has a separate supervisor so its measured child needs
    no Python setup.  This controlled path remains necessary for ptrace and
    memory diagnostics.  Marker and observer use the same fixed descriptor
    number 97, therefore one child may carry exactly one protocol.
    """

    try:
        require((ready_write is None) == (continue_read is None),
                "memory observer descriptors must be supplied as one pair")
        require(marker_fd is None or ready_write is None,
                "diagnostic marker and memory observer cannot share descriptor 97")
        stdin = os.open(root / "dev/null", os.O_RDONLY)
        stdout = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        stderr = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.dup2(stdin, 0)
        os.dup2(stdout, 1)
        os.dup2(stderr, 2)
        keep = {0, 1, 2}
        if ready_write is not None:
            os.dup2(ready_write, READY_FD)
            keep.add(READY_FD)
        if continue_read is not None:
            os.dup2(continue_read, CONTINUE_FD)
            keep.add(CONTINUE_FD)
        if marker_fd is not None:
            os.dup2(marker_fd, MARKER_FD)
            keep.add(MARKER_FD)
        for descriptor in (stdin, stdout, stderr, ready_write, continue_read, marker_fd):
            if descriptor is not None and descriptor not in keep:
                os.close(descriptor)
        close_inherited_descriptors(keep)
        os.chroot(root)
        os.chdir("/app")
        env = dict(environment)
        if ready_write is not None:
            env[performance_profile.READY_ENV] = str(READY_FD)
            env[performance_profile.CONTINUE_ENV] = str(CONTINUE_FD)
        elif marker_fd is not None:
            env[aarch64_contract.DIAGNOSTIC_MARKER_ENV] = str(MARKER_FD)
        os.execve(binary, [binary, *arguments], env)
    except BaseException as error:
        try:
            os.write(2, f"native performance exec failure: {error}\n".encode("utf-8", errors="replace"))
        finally:
            os._exit(127)


def timeout_milliseconds(timeout: float) -> str:
    """Encode one positive child deadline for the static supervisor."""

    require(type(timeout) in {int, float} and timeout > 0, "timing timeout differs")
    milliseconds = int(float(timeout) * 1000.0 + 0.999_999)
    require(0 < milliseconds <= (1 << 31) - 1, "timing timeout exceeds launcher range")
    return str(milliseconds)


def launcher_process_status(returncode: int | None, parent_timed_out: bool) -> dict[str, Any]:
    if parent_timed_out:
        return {"kind": "timeout"}
    if returncode is None:
        return {"kind": "not-waited"}
    if returncode >= 0:
        return {"kind": "exit", "code": returncode}
    return {"kind": "signal", "signal": -returncode}


def kill_timing_supervisor(process: subprocess.Popen[bytes], timeout: float) -> tuple[bytes, bytes]:
    """Bounded parent-abort cleanup for one fresh launcher process group."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise AdapterError(f"could not kill timing-launcher process group: {error}") from error
    try:
        return process.communicate(timeout=max(0.25, min(float(timeout), 2.0)))
    except subprocess.TimeoutExpired as error:
        raise AdapterError("timing-launcher process group did not exit after SIGKILL") from error


def abort_timing_supervisor_group(process: subprocess.Popen[bytes]) -> None:
    """Kill a fresh launcher session even after its supervisor has exited.

    A malformed or signalled supervisor can leave its direct client alive in
    the inherited process group.  The parent has already collected the
    supervisor's status in this path, so it must explicitly kill that owned
    group before retaining the failed attempt.
    """

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        # A group with no remaining member is already cleaned up.
        return
    except OSError as error:
        raise AdapterError(f"could not abort timing-launcher process group: {error}") from error


def run_timed(
    checkout: Path,
    lane: Lane,
    row: performance_profile.PerformanceRow,
    output: Path,
    timeout: float,
    launcher: TimingLauncher,
    client_cpu: int,
    peer_cpu: int | None,
    allowed_affinity: Sequence[int],
) -> dict[str, Any]:
    """Collect a fresh timed client through the static pre-fork supervisor.

    The launcher performs root/FD/cwd setup before its own fork, so the raw
    wait4 resources in its result describe only the direct workload execve.
    Python remains responsible for retained raw output, external peers, and
    aborting the launcher's separate process group on a supervisor failure.
    """

    output.mkdir(parents=True, exist_ok=True)
    stdout = output / "stdout"
    stderr = output / "stderr"
    result_path = output / "timing-launcher-result.json"
    launcher_stdout = output / "timing-launcher.stdout"
    launcher_stderr = output / "timing-launcher.stderr"
    require(all(not path.exists() for path in (stdout, stderr, result_path, launcher_stdout, launcher_stderr)),
            f"timing sample output already exists for {row.name}/{lane.name}")
    command = [
        str(launcher.output.resolve(strict=True)), str(lane.root.resolve(strict=True)),
        str(stdout.resolve()), str(stderr.resolve()), str(result_path.resolve()),
        timeout_milliseconds(timeout), virtual_binary(row, lane), *virtual_arguments(row, lane),
    ]
    process: subprocess.Popen[bytes] | None = None
    process_stdout = b""
    process_stderr = b""
    parent_timed_out = False
    parent_failure: str | None = None
    context: peers.PeerContext | None = None
    peer_record: dict[str, Any] | None = None
    raw_result: Mapping[str, Any] | None = None
    try:
        context = start_row_peer(
            checkout, lane, row, output / "peer", client_cpu, peer_cpu, allowed_affinity, timeout,
        )
        process = subprocess.Popen(
            command, cwd=checkout, env=dict(lane.environment), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            process_stdout, process_stderr = process.communicate(timeout=float(timeout) + 2.0)
        except subprocess.TimeoutExpired:
            parent_timed_out = True
            process_stdout, process_stderr = kill_timing_supervisor(process, timeout)
        if process.returncode != 0:
            parent_failure = f"timing launcher exited with {process.returncode}"
        if result_path.exists():
            try:
                raw_result = evidence.validate_timing_launcher_result(
                    evidence.load_json(result_path, f"timing launcher result {row.name}/{lane.name}"),
                )
            except evidence.EvidenceError as error:
                parent_failure = parent_failure or str(error)
        else:
            parent_failure = parent_failure or "timing launcher produced no result JSON"
        # A success exit code proves only that the supervisor itself returned;
        # it does not prove it reaped its direct client.  A missing or invalid
        # result is therefore an abnormal supervisor outcome too.  Kill the
        # fresh session before retaining the failed sample, so a malformed
        # zero-exit supervisor cannot leave an unmeasured client alive.
        if parent_failure is not None and not parent_timed_out:
            try:
                abort_timing_supervisor_group(process)
            except AdapterError as cleanup_error:
                parent_failure += f"; {cleanup_error}"
    except (OSError, AdapterError, peers.PeerError, ValueError) as error:
        parent_failure = str(error)
        if process is not None and process.poll() is None:
            try:
                process_stdout, process_stderr = kill_timing_supervisor(process, timeout)
            except AdapterError as cleanup_error:
                parent_failure += f"; {cleanup_error}"
        elif process is not None:
            try:
                abort_timing_supervisor_group(process)
            except AdapterError as cleanup_error:
                parent_failure += f"; {cleanup_error}"
    finally:
        launcher_stdout.write_bytes(process_stdout)
        launcher_stderr.write_bytes(process_stderr)
        if context is not None:
            try:
                peer_record, peer_failure = stop_row_peer(checkout, context)
                parent_failure = parent_failure or peer_failure
            except (OSError, AdapterError, peers.PeerError) as error:
                parent_failure = parent_failure or f"timing peer cleanup failed: {error}"

    stdout_bytes = stdout.read_bytes() if stdout.exists() else b""
    stderr_bytes = stderr.read_bytes() if stderr.exists() else b""
    supervisor_status = launcher_process_status(None if process is None else process.returncode, parent_timed_out)
    launcher_record = {
        "command": recorded_command(checkout, command),
        "status": supervisor_status,
        "stdout": retained_identity(checkout, launcher_stdout),
        "stderr": retained_identity(checkout, launcher_stderr),
        "result": retained_identity(checkout, result_path) if result_path.exists() else None,
    }
    if raw_result is not None and parent_failure is None and supervisor_status == {"kind": "exit", "code": 0}:
        return {
            "elapsed_wall_ns": raw_result["elapsed_wall_ns"],
            "status": evidence.timing_launcher_status(raw_result),
            "resources": raw_result["resources"],
            "stdout": retained_identity(checkout, stdout) if stdout.exists() else None,
            "stderr": retained_identity(checkout, stderr) if stderr.exists() else None,
            "stdout_matches": stdout_bytes == EXPECTED_STDOUT,
            "stderr_bytes": len(stderr_bytes),
            "stdout_sha256": sha256_bytes(stdout_bytes),
            "stderr_sha256": sha256_bytes(stderr_bytes),
            "launcher": launcher_record,
            "peer": peer_record,
        }
    return {
        "status": {"kind": "launcher-failed", "reason": parent_failure or "launcher did not collect a client"},
        "elapsed_wall_ns": raw_result["elapsed_wall_ns"] if raw_result is not None else None,
        "resources": raw_result["resources"] if raw_result is not None else {},
        "stdout": retained_identity(checkout, stdout) if stdout.exists() else None,
        "stderr": retained_identity(checkout, stderr) if stderr.exists() else None,
        "stdout_matches": stdout_bytes == EXPECTED_STDOUT,
        "stderr_bytes": len(stderr_bytes),
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "launcher": launcher_record,
        "peer": peer_record,
    }


def valid_sample(sample: Mapping[str, Any]) -> bool:
    return sample.get("status") == {"kind": "exit", "code": 0} and sample.get("stdout_matches") is True and sample.get("stderr_bytes") == 0


def read_memory_stat(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition(" ")
        if separator and value.isdecimal():
            result[key] = int(value)
    return result


PTRACE_TRACEME = 0
PTRACE_SETOPTIONS = 0x4200
PTRACE_GET_SYSCALL_INFO = 0x420E
PTRACE_SYSCALL = 24
PTRACE_DETACH = 17
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_SYSCALL_INFO_ENTRY = 1
SYSCALL_EXECVE_X86_64 = 59
AUDIT_ARCH_X86_64 = 0xC000003E


class PtraceSyscallEntry(ctypes.Structure):
    _fields_ = (("nr", ctypes.c_ulonglong), ("args", ctypes.c_ulonglong * 6))


class PtraceSyscallExit(ctypes.Structure):
    _fields_ = (("rval", ctypes.c_longlong), ("is_error", ctypes.c_ubyte))


class PtraceSyscallSeccomp(ctypes.Structure):
    _fields_ = (("nr", ctypes.c_ulonglong), ("args", ctypes.c_ulonglong * 6), ("ret_data", ctypes.c_uint32))


class PtraceSyscallUnion(ctypes.Union):
    _fields_ = (("entry", PtraceSyscallEntry), ("exit", PtraceSyscallExit), ("seccomp", PtraceSyscallSeccomp))


class PtraceSyscallInfo(ctypes.Structure):
    """Linux 5.3+ ``struct __ptrace_syscall_info`` for x86-64 entry stops."""

    _fields_ = (
        ("op", ctypes.c_ubyte),
        ("pad", ctypes.c_ubyte * 3),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_ulonglong),
        ("stack_pointer", ctypes.c_ulonglong),
        ("data", PtraceSyscallUnion),
    )


_libc = ctypes.CDLL(None, use_errno=True)
_libc.ptrace.restype = ctypes.c_long
_libc.syscall.restype = ctypes.c_long


def ptrace(request: int, pid: int, address: int = 0, data: Any = 0) -> int:
    result = _libc.ptrace(request, pid, ctypes.c_void_p(address), data)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def waitpid_until(pid: int, deadline: float, *, phase: str) -> int:
    """Poll one tracee without leaving an unbounded ``waitpid`` call.

    ``waitpid(pid, 0)`` can block forever if a capability/LSM policy leaves a
    tracee stalled before the selected execve.  The diagnostic uses a bounded
    poll for both its initial SIGSTOP and every syscall stop; callers kill and
    reap explicitly on timeout.
    """

    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError as error:
            raise CgroupUnsupported(f"ptrace child disappeared during {phase}") from error
        if waited == pid:
            return status
        time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
    raise CgroupUnsupported(f"ptrace timed out during {phase}")


def kill_and_reap_ptrace_child(pid: int, *, timeout: float) -> int | None:
    """Terminate one stopped tracee and reap only it without a blocking wait."""

    try:
        ptrace(PTRACE_DETACH, pid, 0, signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return None
    deadline = time.monotonic() + max(0.25, min(timeout, 2.0))
    try:
        return waitpid_until(pid, deadline, phase="failure cleanup")
    except CgroupUnsupported:
        # Do not turn a diagnostic timeout into an unbounded parent wait.
        # The caller retains the exact failure; an occupied probe leaf then
        # also prevents a false successful memory observation.
        return None


def ptrace_syscall_info(pid: int) -> PtraceSyscallInfo:
    info = PtraceSyscallInfo()
    copied = ptrace(PTRACE_GET_SYSCALL_INFO, pid, ctypes.sizeof(info), ctypes.byref(info))
    require(copied >= 24, "PTRACE_GET_SYSCALL_INFO returned no syscall record")
    return info


def read_tracee_bytes(pid: int, address: int, count: int, label: str) -> bytes:
    require(address != 0 and 0 < count <= 65536, f"ptrace {label} address/length is invalid")
    try:
        descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
        try:
            value = os.pread(descriptor, count, address)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CgroupUnsupported(f"cannot read traced {label}: {error}") from error
    require(len(value) == count, f"traced {label} is truncated")
    return value


def read_tracee_c_string(pid: int, address: int, label: str, *, limit: int = 4096) -> str:
    # Do not require a full fixed-length read: an otherwise valid argv string
    # can end at a tracee page boundary.  Read small bounded chunks and stop at
    # its first NUL, retaining the same hard upper bound on a malformed argv.
    require(address != 0 and limit > 0, f"ptrace {label} address/length is invalid")
    value = bytearray()
    terminated = False
    try:
        descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
        try:
            while len(value) < limit:
                count = min(128, limit - len(value))
                piece = os.pread(descriptor, count, address + len(value))
                if not piece:
                    break
                terminator = piece.find(b"\0")
                if terminator >= 0:
                    value.extend(piece[:terminator])
                    terminated = True
                    break
                value.extend(piece)
                if len(piece) != count:
                    break
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CgroupUnsupported(f"cannot read traced {label}: {error}") from error
    require(terminated, f"traced {label} has no terminating NUL")
    try:
        return bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise CgroupUnsupported(f"traced {label} is not UTF-8") from error


def read_tracee_argv(pid: int, address: int, expected_count: int) -> list[str]:
    require(expected_count > 0, "selected execve has no argv contract")
    values: list[str] = []
    for index in range(expected_count):
        pointer = int.from_bytes(read_tracee_bytes(pid, address + index * 8, 8, f"execve argv[{index}] pointer"), "little")
        require(pointer != 0, f"traced execve argv terminates before argv[{index}]")
        values.append(read_tracee_c_string(pid, pointer, f"execve argv[{index}]"))
    terminator = int.from_bytes(read_tracee_bytes(pid, address + expected_count * 8, 8, "execve argv terminator"), "little")
    require(terminator == 0, "traced execve argv has unexpected trailing arguments")
    return values


def process_threads(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Threads:"):
            value = line.split(maxsplit=1)[1]
            if value.isdecimal():
                return int(value)
    raise AdapterError("cannot read stopped child's thread count")


@dataclass
class CgroupSession:
    root: Path
    control: Path
    mount_root: Path
    raw_root: Path
    setup: dict[str, Any]
    leaves: set[Path] = field(default_factory=set)
    owned_leaves: set[Path] = field(default_factory=set)
    leaf_results: dict[Path, str | None] = field(default_factory=dict)

    @staticmethod
    def _default_cgroup_state() -> dict[str, Any]:
        mount = Path("/sys/fs/cgroup")
        return {
            "path": str(mount),
            "exists": mount.is_dir(),
            "memory_peak_exists": (mount / "memory.peak").is_file(),
            "subtree_control_writable": os.access(mount / "cgroup.subtree_control", os.W_OK),
            "mount_read_only": any(
                "ro" in fields[5].split(",")
                for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace").splitlines()
                if (fields := line.split()) and len(fields) > 5 and fields[4] == "/sys/fs/cgroup"
            ),
        }

    @classmethod
    def create(cls, work: Path) -> "CgroupSession":
        default = cls._default_cgroup_state()
        mount_root = work / "cgroup2-private"
        mount_root.mkdir(mode=0o700)
        command = ["mount", "-t", "cgroup2", "none", str(mount_root)]
        try:
            # A denied private mount is an unsupported diagnostic, not a
            # reason to fall back to Docker's parent peak or an ambient cgroup.
            capture = command_capture(command, work, work / "raw/cgroup-mount", "private cgroup2 mount")
            root_procs = mount_root / "cgroup.procs"
            subtree = mount_root / "cgroup.subtree_control"
            require(root_procs.is_file() and subtree.is_file(), "private cgroup2 mount lacks controller files")
            control = mount_root / "control"
            control.mkdir()
            # Move every task in this namespace's cgroup root, including the
            # Docker init process, before enabling memory below that root.
            for raw_pid in root_procs.read_text(encoding="ascii").split():
                require(raw_pid.isdecimal(), "private cgroup task roster is invalid")
                (control / "cgroup.procs").write_text(raw_pid + "\n", encoding="ascii")
            require(not root_procs.read_text(encoding="ascii").strip(), "private cgroup root retained a task")
            subtree.write_text("+memory\n", encoding="ascii")
            contents = subtree.read_text(encoding="ascii")
            require("memory" in contents.split(), "private cgroup memory controller was not delegated")
        except (OSError, AdapterError) as error:
            try:
                subprocess.run(["umount", str(mount_root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            finally:
                raise CgroupUnsupported(f"contained cgroup-v2 setup is unsupported: {error}") from error
        return cls(
            root=mount_root,
            control=control,
            mount_root=mount_root,
            raw_root=work / "raw",
            setup={
                "default_container_cgroup": default,
                "private_mount_command": recorded_command(repository_root(), capture["command"]),
                "private_mount_status": capture["status"],
                "private_mount_stdout": retained_identity(repository_root(), capture["stdout"]),
                "private_mount_stderr": retained_identity(repository_root(), capture["stderr"]),
                "controller": "memory",
                "control_leaf": recorded_path(repository_root(), control),
            },
        )

    def fresh_probe(self, label: str) -> Path:
        path = self.root / f"probe-{label}"
        require(path not in self.leaves and not path.exists(), f"cgroup probe leaf is not fresh: {path}")
        path.mkdir()
        require(not (path / "cgroup.procs").read_text(encoding="ascii").strip(), "fresh cgroup probe leaf is populated")
        self.leaves.add(path)
        self.owned_leaves.add(path)
        return path

    def move_pre_exec(self, pid: int, probe: Path, expected_root: Path) -> dict[str, Any]:
        root_link = Path(f"/proc/{pid}/root").resolve(strict=True)
        executable = os.readlink(f"/proc/{pid}/exe")
        parent_executable = os.readlink("/proc/self/exe")
        threads = process_threads(pid)
        require(root_link == expected_root.resolve(strict=True), "pre-exec child has the wrong chroot root")
        require(executable == parent_executable, "pre-exec child changed executable before the selected workload execve")
        require(threads == 1, "pre-exec child is not single-threaded")
        require(not (probe / "cgroup.procs").read_text(encoding="ascii").strip(), "probe leaf was not empty before migration")
        (probe / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
        observed = (probe / "cgroup.procs").read_text(encoding="ascii").split()
        require(observed == [str(pid)], "pre-exec child did not become the sole probe task")
        return {
            "pid": pid,
            "root": recorded_path(repository_root(), root_link),
            "executable": executable,
            "expected_executable": parent_executable,
            "threads": threads,
            "probe": recorded_path(repository_root(), probe),
        }

    def remove_probe(self, probe: Path) -> str | None:
        try:
            populated = (probe / "cgroup.events").read_text(encoding="ascii")
            require("populated 0" in populated.splitlines(), "probe leaf remains populated after child reap")
            probe.rmdir()
            self.leaves.remove(probe)
            self.leaf_results[probe] = None
            return None
        except (OSError, AdapterError) as error:
            message = str(error)
            self.leaf_results[probe] = message
            return message

    def close(self) -> dict[str, Any]:
        cleanup: dict[str, Any] = {
            "owned_leaves": [planned_recorded_path(repository_root(), path) for path in sorted(self.owned_leaves)],
        }
        for probe in list(self.leaves):
            self.remove_probe(probe)
        cleanup["leaf_results"] = [
            {"path": planned_recorded_path(repository_root(), probe), "error": self.leaf_results.get(probe)}
            for probe in sorted(self.owned_leaves)
        ]
        cleanup["remaining_leaves"] = [recorded_path(repository_root(), path) for path in sorted(self.leaves)]
        result = subprocess.run(["umount", str(self.mount_root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        stdout = self.raw_root / "cgroup-unmount.stdout"
        stderr = self.raw_root / "cgroup-unmount.stderr"
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        cleanup["unmount_status"] = result.returncode
        cleanup["unmount_stdout"] = retained_identity(repository_root(), stdout)
        cleanup["unmount_stderr"] = retained_identity(repository_root(), stderr)
        return cleanup


def ptrace_until_preexec(
    pid: int,
    session: CgroupSession,
    probe: Path,
    root: Path,
    timeout: float,
    *,
    expected_binary: str,
    expected_arguments: Sequence[str],
) -> dict[str, Any]:
    """Migrate exactly the selected workload's ``execve`` entry stop.

    The child has already completed its fixed Python/FD/chroot setup while it
    remains in the control cgroup.  We use Linux 5.3+'s explicit
    ``PTRACE_GET_SYSCALL_INFO`` entry record rather than alternating blind
    entry/exit state, then read the pending filename and argv from the stopped
    tracee.  That prevents an unrelated Python-side ``execve`` from becoming
    a plausible migration boundary.
    """

    deadline = time.monotonic() + timeout
    try:
        initial = waitpid_until(pid, deadline, phase="initial stop")
        require(os.WIFSTOPPED(initial), "ptrace child did not stop before setup")
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)
        while time.monotonic() < deadline:
            ptrace(PTRACE_SYSCALL, pid, 0, 0)
            status = waitpid_until(pid, deadline, phase="syscall stop")
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                raise CgroupUnsupported("ptrace child exited before workload execve")
            if not os.WIFSTOPPED(status):
                continue
            if os.WSTOPSIG(status) != signal.SIGTRAP | 0x80:
                # No expected signal is sent before the controlled execve.
                # Resume without forwarding it; an unexpected exit remains a
                # retained failed diagnostic rather than a migration success.
                continue
            info = ptrace_syscall_info(pid)
            if info.op != PTRACE_SYSCALL_INFO_ENTRY:
                continue
            require(info.arch == AUDIT_ARCH_X86_64, "ptrace syscall architecture is not x86-64")
            if info.data.entry.nr != SYSCALL_EXECVE_X86_64:
                continue
            observed_path = read_tracee_c_string(pid, info.data.entry.args[0], "execve pathname")
            observed_argv = read_tracee_argv(pid, info.data.entry.args[1], 1 + len(expected_arguments))
            expected_argv = [expected_binary, *expected_arguments]
            require(observed_path == expected_binary and observed_argv == expected_argv,
                    "ptrace reached an execve other than the selected workload argv/path")
            record = session.move_pre_exec(pid, probe, root)
            ptrace(PTRACE_DETACH, pid, 0, 0)
            record["event"] = "syscall-entry-execve"
            record["syscall"] = {
                "api": "PTRACE_GET_SYSCALL_INFO",
                "entry": True,
                "architecture": "x86_64",
                "number": SYSCALL_EXECVE_X86_64,
                "path": observed_path,
                "argv": observed_argv,
            }
            return record
        raise CgroupUnsupported("ptrace did not reach selected workload execve before timeout")
    except (OSError, AdapterError) as error:
        reaped = kill_and_reap_ptrace_child(pid, timeout=timeout)
        suffix = "" if reaped is not None else "; exact child could not be reaped before cleanup deadline"
        raise CgroupUnsupported(f"ptrace pre-exec migration is unsupported: {error}{suffix}") from error


def capture_proc_memory_snapshot(pid: int, output: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    """Copy proc observations first, then derive PSS from those retained bytes."""

    raw_paths = {
        "status": output / "proc-status.raw",
        "smaps_rollup": output / "smaps-rollup.raw",
        "smaps": output / "smaps.raw",
    }
    texts: dict[str, str] = {}
    for name, source in (
        ("status", Path(f"/proc/{pid}/status")),
        ("smaps_rollup", Path(f"/proc/{pid}/smaps_rollup")),
        ("smaps", Path(f"/proc/{pid}/smaps")),
    ):
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            raise AdapterError(f"cannot retain /proc memory observation {source}: {error}") from error
        raw_paths[name].write_text(text, encoding="utf-8")
        texts[name] = text
    memory: dict[str, Any] = {}
    for line in texts["status"].splitlines():
        match = re.match(r"^(VmRSS|VmHWM|VmSize):\s+(\d+)\s+kB$", line)
        if match is not None:
            memory[match.group(1).lower() + "_kib"] = int(match.group(2))
    for line in texts["smaps_rollup"].splitlines():
        match = re.match(r"^(Rss|Pss|Private_Clean|Private_Dirty):\s+(\d+)\s+kB$", line)
        if match is not None:
            memory[match.group(1).lower() + "_kib"] = int(match.group(2))
    memory["mapping_attribution"] = aarch64_contract.smaps_mapping_summary(texts["smaps"])
    return memory, raw_paths


def capture_cgroup_number(path: Path, destination: Path, label: str) -> tuple[int, Path]:
    try:
        text = path.read_text(encoding="ascii")
    except OSError as error:
        raise AdapterError(f"cannot retain {label}: {error}") from error
    destination.write_text(text, encoding="ascii")
    value = text.strip()
    require(value.isdecimal(), f"{label} is not a decimal byte value")
    return int(value), destination


def capture_cgroup_stat(path: Path, destination: Path, label: str) -> tuple[dict[str, int], Path]:
    try:
        text = path.read_text(encoding="ascii")
    except OSError as error:
        raise AdapterError(f"cannot retain {label}: {error}") from error
    destination.write_text(text, encoding="ascii")
    return read_memory_stat(destination), destination


def observed_mappings(pid: int, root: Path, raw_path: Path) -> dict[str, Any]:
    raw = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace")
    raw_path.write_text(raw, encoding="utf-8")
    expected_prefix = str(root.resolve(strict=True))
    paths: list[str] = []
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        path = fields[5].removesuffix(" (deleted)")
        if path.startswith(expected_prefix):
            paths.append(path)
        else:
            raise AdapterError(f"runtime mapping escaped sealed root: {path}")
    require(paths, "runtime mapping observation contains no sealed files")
    return {"raw": raw_path, "paths": sorted(set(paths))}


def spawn_memory_child(lane: Lane, mode: str, output: Path) -> tuple[int, int, int, Path, Path]:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    stdout = output / "stdout"
    stderr = output / "stderr"
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read)
            os.close(continue_write)
            ptrace(PTRACE_TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            child_exec(
                lane.root, lane.binaries["workload"],
                [mode, "128", "262144", str(READY_FD), str(CONTINUE_FD)], lane.environment,
                stdout, stderr, ready_write=ready_write, continue_read=continue_read,
            )
        except BaseException:
            os._exit(127)
    os.close(ready_write)
    os.close(continue_read)
    return pid, ready_read, continue_write, stdout, stderr


def spawn_memory_observer_child(
    lane: Lane,
    row: performance_profile.PerformanceRow,
    output: Path,
) -> tuple[int, int, int, Path, Path, str, list[str]]:
    """Fork one ptrace-stopped, non-timed memory-observer client.

    The observer has the source family's unchanged timed arguments but a
    separately linked binary.  Its finite R/C envelope is intentionally the
    only difference visible to this diagnostic child.
    """

    require(row.memory_artifact in lane.binaries,
            f"staged {lane.name} lane lacks memory observer for {row.name}")
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    stdout = output / "stdout"
    stderr = output / "stderr"
    binary = lane.binaries[row.memory_artifact]
    arguments = virtual_arguments(row, lane)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read)
            os.close(continue_write)
            ptrace(PTRACE_TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            child_exec(
                lane.root, binary, arguments, lane.environment, stdout, stderr,
                ready_write=ready_write, continue_read=continue_read,
            )
        except BaseException:
            os._exit(127)
    os.close(ready_write)
    os.close(continue_read)
    return pid, ready_read, continue_write, stdout, stderr, binary, arguments


def read_observer_ready(descriptor: int, timeout: float, *, row: str, phase: str) -> None:
    """Require one bounded ready byte for one declared observer phase."""

    readable, _, _ = select.select([descriptor], [], [], timeout)
    if not readable:
        raise AdapterError(f"memory observer {row}/{phase} did not reach its ready checkpoint")
    received = os.read(descriptor, 1)
    require(received == b"R", f"memory observer {row}/{phase} ready byte differs")


def write_observer_continue(descriptor: int, *, row: str, phase: str) -> None:
    """Release exactly one observer checkpoint after its raw snapshot."""

    written = os.write(descriptor, b"C")
    require(written == 1, f"memory observer {row}/{phase} continue byte was partial")


def observer_mapping_record(checkout: Path, pid: int, lane: Lane, output: Path) -> dict[str, Any]:
    """Retain one complete root-bounded maps observation at a checkpoint."""

    observed = observed_mappings(pid, lane.root, output / "maps.raw")
    return {
        "raw": retained_identity(checkout, observed["raw"]),
        "paths": [recorded_path(checkout, Path(path)) for path in observed["paths"]],
    }


def observer_checkpoint(
    checkout: Path,
    lane: Lane,
    row: performance_profile.PerformanceRow,
    probe: Path,
    pid: int,
    output: Path,
    index: int,
    phase: str,
) -> dict[str, Any]:
    """Capture raw PSS, mappings, and private-cgroup state before one C."""

    checkpoint_root = output / f"checkpoint-{index:02d}-{phase}"
    checkpoint_root.mkdir(parents=True, exist_ok=False)
    memory, memory_raw = capture_proc_memory_snapshot(pid, checkpoint_root)
    peak, peak_raw = capture_cgroup_number(
        probe / "memory.peak", checkpoint_root / "memory-peak.raw",
        f"memory observer {row.name}/{phase} memory.peak",
    )
    memory_stat, memory_stat_raw = capture_cgroup_stat(
        probe / "memory.stat", checkpoint_root / "memory-stat.raw",
        f"memory observer {row.name}/{phase} memory.stat",
    )
    return {
        "index": index,
        "phase": phase,
        "ready": "R",
        "continue": "C",
        "memory": {
            **memory,
            "raw": {name: retained_identity(checkout, path) for name, path in sorted(memory_raw.items())},
        },
        "mappings": observer_mapping_record(checkout, pid, lane, checkpoint_root),
        "cgroup_memory": {
            "memory_peak_bytes": peak,
            "memory_stat": memory_stat,
            "raw": {
                "memory_peak": retained_identity(checkout, peak_raw),
                "memory_stat": retained_identity(checkout, memory_stat_raw),
            },
        },
    }


def memory_observer_probe(
    checkout: Path,
    lane: Lane,
    row: performance_profile.PerformanceRow,
    session: CgroupSession | None,
    raw_root: Path,
    timeout: float,
    client_cpu: int,
    peer_cpu: int | None,
    allowed_affinity: Sequence[int],
) -> dict[str, Any]:
    """Collect every declared R/C memory plateau for one provider and row.

    This path is diagnostic-only.  It uses a fresh private cgroup leaf and
    migrates the stopped Python child at the selected observer ``execve``
    entry, before the observer can allocate its main-state or plateau data.
    No Docker-parent cgroup value, post-ready migration, or estimated setup
    subtraction enters the result.
    """

    observer_binary = lane.binaries.get(row.memory_artifact)
    arguments = virtual_arguments(row, lane)
    observer_invocation = {
        "timed_binary": virtual_binary(row, lane),
        "arguments": arguments,
        "memory_artifact": row.memory_artifact,
        "observer_binary": observer_binary,
        "phases": list(row.memory_phases),
        "protocol": performance_profile.OBSERVER_PROTOCOL,
    }
    base = raw_root / f"memory-observer-{lane.name}-{row.name}"
    base.mkdir(parents=True, exist_ok=True)
    if session is None:
        return {
            "status": "unsupported",
            "protocol": performance_profile.OBSERVER_PROTOCOL,
            "observer": observer_invocation,
            "reason": "private delegated cgroup-v2/ptrace path is unavailable",
        }

    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", row.name) is not None,
            f"memory observer row has an unsafe cgroup label: {row.name}")
    probe = session.fresh_probe(f"{lane.name}-observer-{row.name}")
    pid: int | None = None
    ready_read: int | None = None
    continue_write: int | None = None
    stdout = base / "stdout"
    stderr = base / "stderr"
    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    failure: str | None = None
    migration: dict[str, Any] | None = None
    checkpoints: list[dict[str, Any]] = []
    after_peak: int | None = None
    after_stat: dict[str, int] | None = None
    final_raw: dict[str, Path] = {}
    context: peers.PeerContext | None = None
    peer_record: dict[str, Any] | None = None
    try:
        context = start_row_peer(
            checkout, lane, row, base / "peer", client_cpu, peer_cpu, allowed_affinity, timeout,
        )
        pid, ready_read, continue_write, stdout, stderr, binary, child_arguments = spawn_memory_observer_child(
            lane, row, base,
        )
        require(binary == observer_binary and child_arguments == arguments,
                f"memory observer invocation drifted for {row.name}")
        migration = ptrace_until_preexec(
            pid,
            session,
            probe,
            lane.root,
            timeout,
            expected_binary=binary,
            expected_arguments=child_arguments,
        )
        for index, phase in enumerate(row.memory_phases):
            read_observer_ready(ready_read, timeout, row=row.name, phase=phase)
            checkpoint = observer_checkpoint(
                checkout, lane, row, probe, pid, base, index, phase,
            )
            checkpoints.append(checkpoint)
            write_observer_continue(continue_write, row=row.name, phase=phase)
        status, usage, timed_out = wait_child(pid, timeout)
        after_peak, final_raw["memory_peak_after_exit"] = capture_cgroup_number(
            probe / "memory.peak", base / "memory-peak-after-exit.raw",
            f"memory observer {row.name} memory.peak after exit",
        )
        after_stat, final_raw["memory_stat_after_exit"] = capture_cgroup_stat(
            probe / "memory.stat", base / "memory-stat-after-exit.raw",
            f"memory observer {row.name} memory.stat after exit",
        )
    except (OSError, ValueError, AdapterError, peers.PeerError) as error:
        failure = str(error)
    finally:
        if pid is not None and status is None:
            reaped = kill_and_reap_child(pid, timeout)
            if reaped is None:
                failure = failure or "memory observer child could not be reaped before cleanup deadline"
            else:
                status, usage = reaped
                timed_out = True
        for descriptor in (ready_read, continue_write):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if context is not None:
            try:
                peer_record, peer_failure = stop_row_peer(checkout, context)
                failure = failure or peer_failure
            except (OSError, AdapterError, peers.PeerError) as error:
                failure = failure or f"memory observer peer cleanup failed: {error}"
        cleanup_error = session.remove_probe(probe)
        failure = failure or cleanup_error

    stdout_bytes = stdout.read_bytes() if stdout.exists() else b""
    stderr_bytes = stderr.read_bytes() if stderr.exists() else b""
    child_ok = (
        status is not None and usage is not None and not timed_out
        and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        and stdout_bytes == EXPECTED_STDOUT and not stderr_bytes
    )
    complete_checkpoints = [checkpoint["phase"] for checkpoint in checkpoints] == list(row.memory_phases)
    cgroup_ok = after_peak is not None and after_stat is not None and len(final_raw) == 2
    result: dict[str, Any] = {
        "status": "ok" if child_ok and complete_checkpoints and cgroup_ok and failure is None else "failed",
        "protocol": performance_profile.OBSERVER_PROTOCOL,
        "observer": observer_invocation,
        "migration": migration,
        "checkpoints": checkpoints,
        "cgroup_memory": {
            "status": "ok" if cgroup_ok and failure is None else "failed",
            "memory_peak_after_exit_bytes": after_peak,
            "memory_stat_after_exit": after_stat,
            "raw": {name: retained_identity(checkout, path) for name, path in sorted(final_raw.items())},
            "attribution_limit": "memory.peak can include warm file-cache charges; it is retained as cgroup high-water and is never reset, subtracted, or read from Docker's parent cgroup",
        },
        "child": status_record(status, timed_out) if status is not None else {"kind": "not-waited"},
        "resources": rusage_record(usage) if usage is not None else {},
        "stdout": retained_identity(checkout, stdout) if stdout.exists() else None,
        "stderr": retained_identity(checkout, stderr) if stderr.exists() else None,
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "peer": peer_record,
    }
    if failure is not None:
        result["reason"] = failure
    return result


def memory_metric(reference: int, candidate: int) -> dict[str, Any]:
    """Record one exact 0.90 memory threshold comparison without floats."""

    require(type(reference) is int and reference >= 0 and type(candidate) is int and candidate >= 0,
            "memory metric values are invalid")
    if reference == 0:
        return {
            "reference": reference,
            "candidate": candidate,
            "threshold_numerator": 9,
            "threshold_denominator": 10,
            "release_gate": "reference-zero",
        }
    return {
        "reference": reference,
        "candidate": candidate,
        "threshold_numerator": 9,
        "threshold_denominator": 10,
        "release_gate": "pass" if candidate * 10 <= reference * 9 else "fail",
    }


def memory_observer_comparison(reference: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Derive PSS plateau and full-process peak comparisons from raw records."""

    if reference.get("status") != "ok" or candidate.get("status") != "ok":
        return {"status": "incomplete", "reason": "one provider memory observer is incomplete"}
    try:
        reference_checkpoints = reference["checkpoints"]
        candidate_checkpoints = candidate["checkpoints"]
        require(isinstance(reference_checkpoints, list) and isinstance(candidate_checkpoints, list)
                and reference_checkpoints and candidate_checkpoints,
                "memory observer checkpoints are absent")
        reference_pss = max(item["memory"]["pss_kib"] for item in reference_checkpoints)
        candidate_pss = max(item["memory"]["pss_kib"] for item in candidate_checkpoints)
        reference_peak = reference["cgroup_memory"]["memory_peak_after_exit_bytes"]
        candidate_peak = candidate["cgroup_memory"]["memory_peak_after_exit_bytes"]
        return {
            "status": "ok",
            "pss_max_kib": memory_metric(reference_pss, candidate_pss),
            "memory_peak_after_exit_bytes": memory_metric(reference_peak, candidate_peak),
        }
    except (AdapterError, KeyError, TypeError, ValueError) as error:
        return {"status": "incomplete", "reason": str(error)}


def collect_memory_observers(
    checkout: Path,
    lanes: Mapping[str, Lane],
    rows: Sequence[performance_profile.PerformanceRow],
    session: CgroupSession | None,
    raw_root: Path,
    timeout: float,
    client_cpu: int,
    peer_cpu: int | None,
    allowed_affinity: Sequence[int],
) -> dict[str, Any]:
    """Run the finite non-timed observer envelope for every selected row."""

    result: dict[str, Any] = {}
    for row in rows:
        invocation = {
            "timed_binary": virtual_binary(row, lanes["musl"]),
            "arguments": virtual_arguments(row, lanes["musl"]),
            "memory_artifact": row.memory_artifact,
            "observer_binary": lanes["musl"].binaries.get(row.memory_artifact),
            "phases": list(row.memory_phases),
            "protocol": performance_profile.OBSERVER_PROTOCOL,
        }
        require(invocation["timed_binary"] == virtual_binary(row, lanes["crabc"])
                and invocation["arguments"] == virtual_arguments(row, lanes["crabc"])
                and invocation["observer_binary"] == lanes["crabc"].binaries.get(row.memory_artifact),
                f"provider observer invocation differs for {row.name}")
        provider = {
            lane_name: memory_observer_probe(
                checkout, lane, row, session, raw_root, timeout,
                # The peer helper must run outside the measured client CPU and
                # receive the controller's original allowed mask.
                client_cpu, peer_cpu, allowed_affinity,
            )
            for lane_name, lane in lanes.items()
        }
        result[row.name] = {
            "invocation": invocation,
            "musl": provider["musl"],
            "crabc": provider["crabc"],
            "comparison": memory_observer_comparison(provider["musl"], provider["crabc"]),
        }
    return result


def memory_probe(checkout: Path, lane: Lane, session: CgroupSession, label: str, mode: str, raw_root: Path, timeout: float, *, capture_mappings: bool) -> dict[str, Any]:
    output = raw_root / f"memory-{lane.name}-{label}"
    output.mkdir(parents=True, exist_ok=True)
    probe = session.fresh_probe(f"{lane.name}-{label}")
    pid, ready_read, continue_write, stdout, stderr = spawn_memory_child(lane, mode, output)
    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    failure: str | None = None
    migration: dict[str, Any] | None = None
    before_peak: int | None = None
    after_peak: int | None = None
    memory: dict[str, Any] = {}
    memory_raw: dict[str, Path] = {}
    mappings: dict[str, Any] | None = None
    memory_stat: dict[str, Any] = {}
    cgroup_raw: dict[str, Path] = {}
    try:
        migration = ptrace_until_preexec(
            pid,
            session,
            probe,
            lane.root,
            timeout,
            expected_binary=lane.binaries["workload"],
            expected_arguments=[mode, "128", "262144", str(READY_FD), str(CONTINUE_FD)],
        )
        ready, _, _ = select.select([ready_read], [], [], timeout)
        if not ready or os.read(ready_read, 1) != b"R":
            raise AdapterError("memory fixture failed before its ready barrier")
        peak_path = probe / "memory.peak"
        before_peak, cgroup_raw["memory_peak_before_ready"] = capture_cgroup_number(
            peak_path, output / "memory-peak-before-ready.raw", "memory.peak before ready"
        )
        memory_stat["before_continue"], cgroup_raw["memory_stat_before_continue"] = capture_cgroup_stat(
            probe / "memory.stat", output / "memory-stat-before-continue.raw", "memory.stat before continue"
        )
        if mode == "allocator_live":
            memory, memory_raw = capture_proc_memory_snapshot(pid, output)
            if capture_mappings:
                observed = observed_mappings(pid, lane.root, output / "maps.raw")
                mappings = {
                    "raw": retained_identity(checkout, observed["raw"]),
                    "paths": [recorded_path(checkout, Path(path)) for path in observed["paths"]],
                }
        os.write(continue_write, b"C")
        status, usage, timed_out = wait_child(pid, timeout)
        after_peak, cgroup_raw["memory_peak_after_exit"] = capture_cgroup_number(
            peak_path, output / "memory-peak-after-exit.raw", "memory.peak after exit"
        )
        memory_stat["after_exit"], cgroup_raw["memory_stat_after_exit"] = capture_cgroup_stat(
            probe / "memory.stat", output / "memory-stat-after-exit.raw", "memory.stat after exit"
        )
    except (OSError, ValueError, AdapterError) as error:
        failure = str(error)
    finally:
        if status is None:
            reaped = kill_and_reap_child(pid, timeout)
            if reaped is None:
                failure = failure or "memory diagnostic child could not be reaped before cleanup deadline"
            else:
                status, usage = reaped
        os.close(ready_read)
        os.close(continue_write)
    stdout_bytes = stdout.read_bytes() if stdout.exists() else b""
    stderr_bytes = stderr.read_bytes() if stderr.exists() else b""
    cleanup_error = session.remove_probe(probe)
    if cleanup_error:
        failure = failure or cleanup_error
    child_ok = status is not None and usage is not None and not timed_out and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and stdout_bytes == EXPECTED_STDOUT and not stderr_bytes
    if before_peak is None or after_peak is None or (mode == "allocator_after_ready" and after_peak <= before_peak):
        failure = failure or "memory.peak did not increase after the ready barrier"
    return {
        "status": "ok" if child_ok and failure is None else "failed",
        "mode": mode,
        "live_allocation_bytes": 128 * 262144,
        "memory": {
            **memory,
            "raw": {name: retained_identity(checkout, path) for name, path in sorted(memory_raw.items())},
        },
        "cgroup_memory": {
            "status": "ok" if failure is None else "failed",
            "memory_peak_before_ready_bytes": before_peak,
            "memory_peak_after_exit_bytes": after_peak,
            "memory_stat": memory_stat,
            "raw": {name: retained_identity(checkout, path) for name, path in sorted(cgroup_raw.items())},
            "attribution_limit": "memory.peak can include warm file-cache charges; it is retained as cgroup high-water and is never reset, subtracted, or read from Docker's parent cgroup",
        },
        "migration": migration,
        "child": status_record(status, timed_out) if status is not None else {"kind": "not-waited"},
        "resources": rusage_record(usage) if usage is not None else {},
        "stdout": retained_identity(checkout, stdout) if stdout.exists() else None,
        "stderr": retained_identity(checkout, stderr) if stderr.exists() else None,
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "mappings": mappings,
        **({"reason": failure} if failure else {}),
    }


def live_memory_diagnostic(checkout: Path, lane: Lane, session: CgroupSession | None, raw_root: Path, timeout: float) -> dict[str, Any]:
    if session is None:
        return {"status": "unsupported", "reason": "private delegated cgroup-v2/ptrace path is unavailable"}
    live = memory_probe(checkout, lane, session, "live", "allocator_live", raw_root, timeout, capture_mappings=True)
    after_ready = memory_probe(
        checkout, lane, session, "after-ready", "allocator_after_ready", raw_root, timeout, capture_mappings=False
    )
    cgroup = dict(live.get("cgroup_memory", {}))
    cgroup["after_ready_self_test"] = after_ready
    live["cgroup_memory"] = cgroup
    if live["status"] == "ok" and after_ready["status"] != "ok":
        live["status"] = "failed"
        live["reason"] = "post-ready memory.peak self-test failed"
    return live


def marker_pattern(fd: int, marker: str) -> re.Pattern[str]:
    prefix = r"(?:\[pid\s+\d+\]\s+)?(?:\d+\s+)?"
    return re.compile(rf'^{prefix}write\({fd},\s*"{re.escape(marker)}",\s*{len(marker)}\)\s+=\s+{len(marker)}$')


def marker_summary(trace: str, fd: int) -> dict[str, Any]:
    return evidence.replay_marker_region(
        trace, fd, aarch64_contract.DIAGNOSTIC_MARKER_BEGIN, aarch64_contract.DIAGNOSTIC_MARKER_END
    )


def successful_workload_execve_boundary(trace: str, expected_binary: str, expected_arguments: Sequence[str]) -> int | None:
    """Return the one successful selected-workload execve trace index.

    The diagnostic deliberately attaches before Python performs its fixed FD,
    chroot, and direct-exec setup.  Those launcher calls remain in the raw
    trace, but cannot enter the whole-process syscall score: that score begins
    at this exact successful workload ``execve`` line.
    """

    return evidence.replay_successful_execve(trace, expected_binary, expected_arguments)


def whole_process_summary_from_workload_execve(trace: str, expected_binary: str, expected_arguments: Sequence[str], marker_fd: int) -> dict[str, Any]:
    """Count calls from the selected execve boundary while retaining raw prelude."""

    return evidence.replay_whole_process_after_execve(
        trace, expected_binary, expected_arguments, marker_fd,
        aarch64_contract.DIAGNOSTIC_MARKER_BEGIN, aarch64_contract.DIAGNOSTIC_MARKER_END,
    )


def fixed_strace_attach_command(trace: Path, pid: int) -> list[str]:
    """Return the diagnostic tracer command without consulting ambient PATH."""

    return [evidence.FIXED_STRACE, "-f", "-qq", "-s", "4096", "-o", str(trace), "-p", str(pid)]


def trace_diagnostic(
    checkout: Path,
    lane: Lane,
    row: performance_profile.PerformanceRow,
    output: Path,
    timeout: float,
    client_cpu: int,
    peer_cpu: int | None,
    allowed_affinity: Sequence[int],
) -> dict[str, Any]:
    """Attach strace before direct child setup and retain every failed attempt.

    The initial SIGSTOP and attachment wait are polled with deadlines.  A
    denied or stalled tracer therefore becomes a retained failed diagnostic,
    never an unbounded parent wait or an invented successful record.
    """

    output.mkdir(parents=True, exist_ok=True)
    trace = output / "trace.raw"
    trace.touch(exist_ok=False)
    stdout = output / "stdout"
    stderr = output / "stderr"
    stdout.touch(exist_ok=False)
    stderr.touch(exist_ok=False)
    markers = output / "markers"
    marker_fd = os.open(markers, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    # Network/DNS diagnostics execute the same client invocation as timed
    # samples.  Their peer is deliberately fresh, pinned away from the client,
    # and retained separately so a timed peer context cannot be recycled for a
    # trace result.
    context = start_row_peer(
        checkout, lane, row, output / "peer", client_cpu, peer_cpu, allowed_affinity, timeout,
    )
    peer_record: dict[str, Any] | None = None
    pid = os.fork()
    if pid == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        child_exec(
            lane.root, virtual_binary(row, lane), virtual_arguments(row, lane), lane.environment,
            stdout, stderr, marker_fd=marker_fd,
        )

    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    reason: str | None = None
    attached = False
    tracer: subprocess.Popen[bytes] | None = None
    tracer_stdout = b""
    tracer_stderr = b""
    deadline = time.monotonic() + timeout
    try:
        try:
            initial = waitpid_until(pid, deadline, phase="diagnostic initial stop")
        except CgroupUnsupported as error:
            reason = str(error)
            timed_out = True
        else:
            if not os.WIFSTOPPED(initial):
                # waitpid has already returned the actual terminal status; it
                # may not carry rusage, so retain that distinction explicitly.
                status = initial
                reason = "diagnostic child did not stop before strace attachment"
            else:
                try:
                    tracer = subprocess.Popen(
                        fixed_strace_attach_command(trace, pid),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    while time.monotonic() < deadline:
                        try:
                            status_text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
                        except OSError as error:
                            reason = f"cannot inspect diagnostic tracer attachment: {error}"
                            break
                        tracer_pid = next(
                            (line.split()[1] for line in status_text.splitlines() if line.startswith("TracerPid:")), "0"
                        )
                        if tracer_pid != "0":
                            attached = True
                            break
                        if tracer.poll() is not None:
                            reason = "strace exited before attaching"
                            break
                        time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
                    if not attached and reason is None:
                        timed_out = True
                        reason = "strace did not attach before diagnostic deadline"
                    if attached:
                        os.kill(pid, signal.SIGCONT)
                        status, usage, timed_out = wait_child(pid, timeout)
                    else:
                        reaped = kill_and_reap_child(pid, timeout)
                        if reaped is None:
                            reason = (reason or "strace attachment failed") + "; exact child could not be reaped before cleanup deadline"
                        else:
                            status, usage = reaped
                            timed_out = True
                except (OSError, AdapterError) as error:
                    reason = str(error)
                    reaped = kill_and_reap_child(pid, timeout)
                    if reaped is None:
                        reason += "; exact child could not be reaped before cleanup deadline"
                    else:
                        status, usage = reaped
                        timed_out = True
    finally:
        os.close(marker_fd)

    if status is None:
        reaped = kill_and_reap_child(pid, timeout)
        if reaped is not None:
            status, usage = reaped
            timed_out = True
        elif reason is None:
            reason = "diagnostic child could not be reaped before cleanup deadline"
    if tracer is not None:
        try:
            tracer_stdout, tracer_stderr = tracer.communicate(timeout=max(0.25, min(timeout, 2.0)))
        except subprocess.TimeoutExpired:
            tracer.kill()
            try:
                tracer_stdout, tracer_stderr = tracer.communicate(timeout=max(0.25, min(timeout, 2.0)))
            except subprocess.TimeoutExpired:
                tracer_stdout, tracer_stderr = b"", b"strace did not terminate after SIGKILL\n"
                reason = (reason or "strace did not terminate") + "; strace output collection timed out"
    else:
        tracer_stderr = (reason or "strace was not started").encode("utf-8", errors="replace") + b"\n"
    strace_stdout_path = output / "strace.stdout"
    strace_stderr_path = output / "strace.stderr"
    strace_stdout_path.write_bytes(tracer_stdout)
    strace_stderr_path.write_bytes(tracer_stderr)

    try:
        peer_record, peer_failure = stop_row_peer(checkout, context)
        if peer_failure is not None:
            reason = reason or peer_failure
    except (OSError, AdapterError, peers.PeerError) as error:
        reason = reason or f"diagnostic peer cleanup failed: {error}"

    raw_bytes = trace.read_bytes()
    raw = raw_bytes.decode("utf-8", errors="replace")
    marked = marker_summary(raw, MARKER_FD)
    expected_exec = virtual_binary(row, lane)
    expected_arguments = virtual_arguments(row, lane)
    whole_process = whole_process_summary_from_workload_execve(raw, expected_exec, expected_arguments, MARKER_FD)
    exec_lines = [whole_process["boundary_trace_line"]] if whole_process.get("status") == "ok" else []
    stdout_bytes = stdout.read_bytes()
    stderr_bytes = stderr.read_bytes()
    status_ok = (
        attached and status is not None and usage is not None and not timed_out
        and reason is None
        and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        and stdout_bytes == EXPECTED_STDOUT and not stderr_bytes
        and marked.get("status") == "ok" and len(exec_lines) == 1
    )
    result: dict[str, Any] = {
        "status": "ok" if status_ok else "failed",
        "diagnostic": True,
        "timing": False,
        "child": status_record(status, timed_out) if status is not None else {"kind": "not-waited"},
        "resources": rusage_record(usage) if usage is not None else {},
        "trace": retained_identity(checkout, trace),
        "stdout": retained_identity(checkout, stdout),
        "stderr": retained_identity(checkout, stderr),
        "markers": retained_identity(checkout, markers),
        "strace_stdout": retained_identity(checkout, strace_stdout_path),
        "strace_stderr": retained_identity(checkout, strace_stderr_path),
        "trace_sha256": sha256_bytes(raw_bytes),
        "whole_process": whole_process,
        "marked_region": marked,
        "workload_execve": {"path": expected_exec, "argv": [expected_exec, *expected_arguments]},
        "successful_workload_execve_trace_lines": exec_lines,
        "marker_writes_excluded_from_whole_process": True,
        "peer": peer_record,
    }
    if reason is not None:
        result["reason"] = reason
    return result

def summarize_samples(samples: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return aarch64_contract.summarize_samples(samples)


def timed_measurements_are_complete(workloads: Mapping[str, Any]) -> bool:
    """Return whether clients and syscall diagnostics completed successfully.

    This deliberately does not inspect CPU, memory, or syscall *verdicts*.
    A fully replayable red result is evidence, whereas a missing diagnostic or
    failed client is incomplete measurement data.
    """

    return bool(workloads) and all(
        isinstance(item, Mapping)
        and item.get("comparison", {}).get("status") == "ok"
        and all(item.get(lane, {}).get("syscalls", {}).get("status") == "ok" for lane in ("musl", "crabc"))
        for item in workloads.values()
    )


def measure_pair(
    checkout: Path,
    lanes: Mapping[str, Lane],
    row: performance_profile.PerformanceRow,
    args: argparse.Namespace,
    raw_root: Path,
    seed: int,
    launcher: TimingLauncher,
    client_cpu: int,
    peer_cpu: int | None,
    allowed_affinity: Sequence[int],
) -> dict[str, Any]:
    invocation = {
        "binary": virtual_binary(row, lanes["musl"]),
        "arguments": virtual_arguments(row, lanes["musl"]),
        "fixture_mode": row.fixture_mode,
        "iterations_per_process": row.iterations,
        "operations_per_process": row.operations,
    }
    require(
        invocation["binary"] == virtual_binary(row, lanes["crabc"])
        and invocation["arguments"] == virtual_arguments(row, lanes["crabc"]),
        f"{row.name} lane invocation differs",
    )
    warmups: dict[str, list[dict[str, Any]]] = {"musl": [], "crabc": []}
    for lane_name in ("musl", "crabc"):
        for index in range(args.warmup):
            sample = run_timed(
                checkout, lanes[lane_name], row, raw_root / f"warmup-{lane_name}-{row.name}-{index}", args.timeout,
                launcher, client_cpu, peer_cpu, allowed_affinity,
            )
            sample["warmup_index"] = index
            warmups[lane_name].append(sample)
            if not valid_sample(sample):
                return {"invocation": invocation, lane_name: {"status": "warmup-failed", "warmups": warmups[lane_name]}, "comparison": {"status": "warmup-failed", "seed": seed}}
    observed: dict[str, list[dict[str, Any] | None]] = {"musl": [None] * args.samples, "crabc": [None] * args.samples}
    plan = aarch64_contract.paired_sample_plan(args.samples, seed)
    for order, (lane_name, index) in enumerate(plan):
        sample = run_timed(
            checkout, lanes[lane_name], row, raw_root / f"sample-{lane_name}-{row.name}-{index}", args.timeout,
            launcher, client_cpu, peer_cpu, allowed_affinity,
        )
        sample["sample_index"] = index
        sample["execution_order"] = order
        if not valid_sample(sample):
            prior = [item for item in observed[lane_name] if item is not None]
            return {"invocation": invocation, lane_name: {"status": "sample-failed", "samples": prior, "failure": sample}, "comparison": {"status": "sample-failed", "seed": seed, "sample_plan": plan}}
        observed[lane_name][index] = sample
    result: dict[str, Any] = {"invocation": invocation}
    for lane_name in ("musl", "crabc"):
        samples = [item for item in observed[lane_name] if item is not None]
        diagnostic = trace_diagnostic(
            checkout, lanes[lane_name], row, raw_root / f"diagnostic-{lane_name}-{row.name}", args.timeout,
            client_cpu, peer_cpu, allowed_affinity,
        ) if not args.skip_syscalls else {"status": "skipped", "timing": False}
        result[lane_name] = {
            "status": "ok",
            "iterations_per_process": row.iterations,
            "operations_per_process": row.operations,
            "warmup_processes": args.warmup,
            "warmups": warmups[lane_name],
            "sample_count": args.samples,
            "samples": samples,
            "summary": summarize_samples(samples),
            "syscalls": diagnostic,
        }
    reference_cpu = [sample["resources"]["user_cpu_ns"] + sample["resources"]["system_cpu_ns"] for sample in result["musl"]["samples"]]
    candidate_cpu = [sample["resources"]["user_cpu_ns"] + sample["resources"]["system_cpu_ns"] for sample in result["crabc"]["samples"]]
    comparison: dict[str, Any] = {"status": "ok", "seed": seed, "sample_plan": [{"lane": lane, "sample_index": index} for lane, index in plan]}
    try:
        cpu = aarch64_contract.bootstrap_cpu_ratio(reference_cpu, candidate_cpu, seed=seed, resamples=evidence.CPU_RESAMPLES)
        comparison["cpu"] = {**cpu, "release_gate": "pass" if cpu["one_sided_95_upper"] <= 0.90 else "fail"}
    except ValueError as error:
        comparison["status"] = "cpu-unsupported"
        comparison["cpu"] = {"release_gate": "unsupported", "reason": str(error)}
    if result["musl"]["syscalls"].get("status") == "ok" and result["crabc"]["syscalls"].get("status") == "ok":
        comparison["syscall_gate"] = evidence.scorecard_syscall_gate(
            result["musl"]["syscalls"], result["crabc"]["syscalls"],
            operations=row.operations,
        )
    else:
        comparison["syscall_gate"] = {"status": "fail", "violations": ["diagnostic is incomplete"]}
    result["comparison"] = comparison
    return result


def raw_registry(root: Path, raw_root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for path in sorted(raw_root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(raw_root).as_posix()] = retained_identity(root, path)
    return result


def dynamic_product_prerequisite(
    root: Path,
    receipt_path: Path | None,
    product: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a real dynamic-product qualification without inventing correctness.

    The existing owner validates the live 70-case, three-product dynamic gate.
    That is meaningful product provenance, but it intentionally does *not*
    close the larger native correctness predecessor chain required before a
    performance result can be admitted as qualification evidence.
    """

    if receipt_path is None:
        return {
            "status": "unavailable",
            "reason": "no validated owned-dynamic-qualification receipt was supplied",
        }
    receipt_path = physical_path(receipt_path, "dynamic product qualification receipt")
    try:
        qualification = evidence._x86_module(root, "owned_dynamic_qualification")
        receipt = qualification.validate_receipt(receipt_path)
    except (OSError, RuntimeError, ValueError) as error:
        raise AdapterError(f"dynamic product qualification receipt is invalid: {error}") from error
    require(receipt.get("schema") == "crabc.x86_64-owned-dynamic-qualification/v1"
            and receipt.get("status") == "qualified-pending-review",
            "dynamic product qualification receipt is not a validated three-product record")
    require(receipt.get("source_sha256") == qualification.source_digest(),
            "dynamic product qualification receipt is stale for the current source")
    products = receipt.get("products")
    require(isinstance(products, dict) and set(products) == {"installed", "second", "extracted"},
            "dynamic product qualification receipt lacks the exact three-product roster")
    manifest = product["manifest"]["sha256"]
    require(all(value == manifest for value in products.values()),
            "dynamic product qualification receipt does not bind this supplied product")
    return {
        "status": "validated-product-prerequisite",
        "receipt": recorded_identity(root, receipt_path),
        "source_sha256": receipt["source_sha256"],
        "products": products,
    }


def native_source_digest(root: Path) -> str:
    """Use the existing x86 source owner for a full nonignored source seal."""

    try:
        qualification = evidence._x86_module(root, "owned_dynamic_qualification")
        digest = qualification.source_digest()
    except (OSError, RuntimeError, ValueError) as error:
        raise AdapterError(f"cannot calculate native source provenance: {error}") from error
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "native source provenance digest is invalid")
    return digest


def load_attempt_roster(root: Path, path: Path, product: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Read one immutable ordered three-attempt request roster."""

    path = physical_path(path, "native performance attempt roster")
    roster = evidence.load_json(path, "native performance attempt roster")
    expected = {
        "schema", "kind", "status", "source_mount", "source_revision", "source_sha256", "product",
        "dynamic_product_qualification", "correctness_admission", "budget", "attempts",
    }
    require(set(roster) == expected and roster["schema"] == ROSTER_SCHEMA and roster["kind"] == ROSTER_KIND
            and roster["status"] == "planned" and roster["source_mount"] == evidence.SOURCE_MOUNT
            and roster["budget"] in evidence.ATTEMPT_BUDGETS,
            "native performance attempt roster fields differ")
    require(roster["source_revision"] == git_revision(root), "attempt roster targets a different source revision")
    source_sha256 = native_source_digest(root)
    require(roster["source_sha256"] == source_sha256, "attempt roster source digest is stale")
    require(roster["product"] == product, "attempt roster targets a different supplied product")
    dynamic = roster["dynamic_product_qualification"]
    require(isinstance(dynamic, dict) and dynamic.get("status") in {"unavailable", "validated-product-prerequisite"},
            "attempt roster product prerequisite differs")
    if dynamic["status"] == "unavailable":
        require(set(dynamic) == {"status", "reason"}, "attempt roster unavailable product prerequisite differs")
    else:
        expected_dynamic = {"status", "receipt", "source_sha256", "products"}
        require(set(dynamic) == expected_dynamic, "attempt roster dynamic product prerequisite fields differ")
        # The semantic owner has already checked this receipt when the roster
        # was written.  A later collector replays the recorded receipt identity
        # and revalidates it in the native image before relying on it.
        require(isinstance(dynamic["receipt"], dict), "attempt roster dynamic product receipt is absent")
        receipt_path = evidence.retained_file_identity(
            root, evidence.SOURCE_MOUNT, dynamic["receipt"], "attempt roster dynamic product receipt"
        )
        require(dynamic == dynamic_product_prerequisite(root, receipt_path, product),
                "attempt roster dynamic product prerequisite no longer validates")
    # The roster binds one source revision, so the chain reader must agree
    # with its recorded admission.  A roster can record, never assert, it.
    require(roster["correctness_admission"] == evidence.correctness_admission(root),
            "attempt roster correctness admission differs from the ordered qualification chain")
    attempts = roster["attempts"]
    require(isinstance(attempts, list) and len(attempts) == evidence.COLLECTOR_ATTEMPTS,
            "attempt roster must request exactly three attempts")
    expected_parent = path.parent
    for expected_index, request in enumerate(attempts, start=1):
        require(isinstance(request, dict) and set(request) == {"index", "work_dir", "report", "predecessor_report"}
                and request["index"] == expected_index,
                "attempt roster request fields differ")
        work = roster_path_to_host(root, request["work_dir"], f"attempt roster work {expected_index}", must_exist=False)
        report = roster_path_to_host(root, request["report"], f"attempt roster report {expected_index}", must_exist=False)
        require(work == expected_parent / f"attempt-{expected_index}" and report == work / "report.json",
                "attempt roster request path differs")
        expected_predecessor = None if expected_index == 1 else attempts[expected_index - 2]["report"]
        require(request["predecessor_report"] == expected_predecessor,
                "attempt roster predecessor chain differs")
    return path, roster


def bind_attempt_roster(
    args: argparse.Namespace,
    root: Path,
    work: Path,
    product: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind one run to its immutable roster position and predecessor."""

    # Keep this gate here as well as at the start of ``run_attempt``.  Roster
    # absence must never be a route around the unavailable full-run admission.
    require_full_run_admission(args)
    if getattr(args, "attempt_roster", None) is None:
        return {"status": "unbound"}
    path, roster = load_attempt_roster(root, args.attempt_roster, product)
    budget = evidence.SMOKE_BUDGET if args.implementation_smoke else evidence.FULL_BUDGET
    require(roster["budget"] == budget,
            f"attempt budget {budget} differs from the immutable {roster['budget']} roster")
    admission = roster["correctness_admission"]
    require(admission["status"] == "available" or args.implementation_smoke,
            f"full native performance run is unavailable pending {admission['owner']}: " + "; ".join(admission["unmet"]))
    require(not getattr(args, "skip_syscalls", False) and getattr(args, "workload", None) is None,
            "a roster-bound attempt runs every canonical row with syscall diagnostics")
    require(1 <= args.attempt_index <= evidence.COLLECTOR_ATTEMPTS, "attempt index is outside the three-run roster")
    request = roster["attempts"][args.attempt_index - 1]
    requested_work = roster_path_to_host(root, request["work_dir"], "attempt roster work", must_exist=True, directory=True)
    require(requested_work == work, "run work directory does not match its immutable roster request")
    predecessor: dict[str, Any] | None = None
    if request["predecessor_report"] is not None:
        prior_path = roster_path_to_host(root, request["predecessor_report"], "attempt roster predecessor report", must_exist=True)
        prior = evidence.load_json(prior_path, "attempt roster predecessor report")
        require(prior.get("schema") == SCHEMA and prior.get("kind") == KIND
                and evidence.ATTEMPT_STATUS_BUDGETS.get(prior.get("status")) == roster["budget"]
                and prior.get("attempt", {}).get("index") == args.attempt_index - 1,
                "attempt roster predecessor is incomplete or mismatched")
        predecessor = recorded_identity(root, prior_path)
    return {
        "status": "bound",
        "plan": recorded_identity(root, path),
        "request": request,
        "predecessor": predecessor,
    }


def plan_attempt_roster(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    """Create the immutable consecutive three-attempt request roster."""

    root = repository_root()
    output = fresh_work_directory(root, args.work_dir)
    product_path, _musl, _compiler, _cpu, _allowed_affinity, _peer_cpu = validate_environment(args, root)
    require(git_clean(root), "attempt roster requires a clean source revision")
    product = record_product(root, product_path)
    qualification = dynamic_product_prerequisite(root, args.dynamic_qualification, product)
    attempts: list[dict[str, Any]] = []
    for index in range(1, evidence.COLLECTOR_ATTEMPTS + 1):
        work = output / f"attempt-{index}"
        report = work / "report.json"
        attempts.append({
            "index": index,
            "work_dir": planned_recorded_path(root, work),
            "report": planned_recorded_path(root, report),
            "predecessor_report": None if index == 1 else attempts[index - 2]["report"],
        })
    roster: dict[str, Any] = {
        "schema": ROSTER_SCHEMA,
        "kind": ROSTER_KIND,
        "status": "planned",
        "source_mount": evidence.SOURCE_MOUNT,
        "source_revision": git_revision(root),
        "source_sha256": native_source_digest(root),
        "product": product,
        "dynamic_product_qualification": qualification,
        "correctness_admission": evidence.correctness_admission(root),
        "budget": evidence.SMOKE_BUDGET if args.implementation_smoke else evidence.FULL_BUDGET,
        "attempts": attempts,
    }
    path = output / "attempt-roster.json"
    write_json(path, roster)
    return path, roster


def run_attempt(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    root = repository_root()
    work = fresh_work_directory(root, args.work_dir)
    report_path = work / "report.json"
    raw_root = work / "raw"
    raw_root.mkdir()
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": KIND,
        "status": "failed",
        "source_mount": evidence.SOURCE_MOUNT,
        "attempt": {
            "index": args.attempt_index,
            "docker_image_id": os.environ.get("CRABC_PERF_DOCKER_IMAGE_ID"),
            "invocation_nonce": secrets.token_hex(16),
            "clean_revision": git_clean(root),
            "source_revision": git_revision(root),
            "roster": {"status": "unbound"},
        },
        "source": {},
        "product": {},
        "tools": {},
        "build": {},
        "execution": {},
        "measurement": {},
        "release": {"qualified": False, "reason": evidence.RELEASE_QUALIFICATION_REASON},
    }
    try:
        resolve_run_budget(args)
        # Reject a non-smoke command before it can construct objects, links,
        # roots, or timed children.  The failed report still records the
        # attempted command's identity below.
        require_full_run_admission(args)
        product, musl_root, musl_cc, cpu, allowed_affinity, peer_cpu = validate_environment(args, root)
        require(report["attempt"]["clean_revision"] is True, "performance evidence requires a clean source revision")
        selected = selected_rows(root, args.workload)
        state = BuildState(root=root, work=work, product=product, musl_cc=musl_cc, raw_root=raw_root / "build")
        make_generated_sources(state, selected)
        sources, headers = source_roster(root, state, selected, include_memory_observers=True)
        for generated in state.local_sources.values():
            normalize_retained_path(root, generated)
        source_paths = {
            **{f"source:{name}": path for name, path in sources.items()},
            **{f"header:{name}": path for name, path in headers.items()},
        }
        report["source"] = {
            "before": evidence.seal_files(source_paths),
            "after": {},
            "source_sha256_before": native_source_digest(root),
            "source_sha256_after": None,
        }
        report["product"] = {"before": record_product(root, product), "after": {}}
        report["attempt"]["roster"] = bind_attempt_roster(args, root, work, report["product"]["before"])
        report["tools"] = {
            "before": tool_snapshot(
                root, product, musl_cc, cpu, allowed_affinity, peer_cpu,
                raw_root / "image-tools.manifest",
            ),
            "after": {},
            "host_cpuinfo_diagnostics": {
                "before": capture_cpuinfo_diagnostic(root, raw_root / "host" / "cpuinfo.before.raw"),
                "after": None,
            },
            "compile_policy": {"flags": list(FIXED_COMPILE_FLAGS), "pie": "installed driver --dynamic-pie", "pic": "installed driver --dynamic-shared-object", "headers": "installed product usr/include"},
            "link_policy": {"binding": "now", "hash_style": "sysv", "runpath": APP_RUNPATH, "candidate": "installed bin/crabc-cc-dynamic", "reference": DEFAULT_MUSL_CC},
        }
        compile_required_objects(state, sources, selected)
        compile_timing_launcher(state, sources["timing_launcher"])
        link_required_artifacts(state, selected)
        report["build"] = build_record(root, state)
        proof_path = work / "same-object-input-proof.json"
        write_json(proof_path, report["build"]["same_object_input_proof"])
        report["build"]["same_object_input_proof_file"] = recorded_identity(root, proof_path)
        report["build"]["companion_same_object_input_proof"] = None
        if args.same_object_input_proof is not None:
            companion = physical_path(args.same_object_input_proof, "same object/input proof")
            verify_same_object_input_proof(companion, report["build"]["same_object_input_proof"])
            report["build"]["companion_same_object_input_proof"] = recorded_identity(root, companion)
        lanes = {
            "musl": stage_lane(work, state, name="musl", selected=selected, product=product, musl_root=musl_root),
            "crabc": stage_lane(work, state, name="crabc", selected=selected, product=product, musl_root=musl_root),
        }
        # Cgroup leaves are diagnostic-only, but their cleanup is not optional:
        # an exception during a memory probe, inventory seal, or timed row must
        # still reap/remove the exact owned leaves and unmount the private view.
        cgroup: CgroupSession | None = None
        cgroup_setup: dict[str, Any] = {"status": "not-created"}
        cleanup: dict[str, Any] = {"status": "not-created"}
        memory: dict[str, Any]
        memory_observers: dict[str, Any]
        workloads: dict[str, Any] = {}
        try:
            # Both budgets run the identical memory route.  A smoke differs
            # only in its process roster, so it proves every collector that a
            # full attempt uses without becoming a scorecard result.
            try:
                cgroup = CgroupSession.create(work)
                cgroup_setup = {"status": "ok", **cgroup.setup}
            except CgroupUnsupported as error:
                cgroup_setup = {
                    "status": "unsupported", "reason": str(error),
                    "default_container_cgroup": CgroupSession._default_cgroup_state(),
                }
            memory = {
                name: live_memory_diagnostic(root, lane, cgroup, raw_root / "execution", args.timeout)
                for name, lane in lanes.items()
            }
            memory_observers = collect_memory_observers(
                root, lanes, selected, cgroup, raw_root / "execution", args.timeout,
                cpu, peer_cpu, allowed_affinity,
            )
            for name, lane in lanes.items():
                # The chroot tree is retained evidence after timed children and
                # diagnostics have finished.  Normalize it before sealing the
                # inventory so host replay does not need to chmod a 0700 attempt.
                normalize_retained_tree(root, lane.root)
                lane.inventory = evidence.inventory_tree(lane.root)
                observed = memory[name].get("mappings") if isinstance(memory[name], dict) else None
                if isinstance(observed, dict):
                    lane.observed_mappings = dict(observed)
                else:
                    # The report is intentionally incomplete if contained
                    # memory evidence is unavailable.  Do not fabricate an
                    # ambient map.
                    missing = raw_root / "execution" / f"missing-{name}-mappings.raw"
                    missing.parent.mkdir(parents=True, exist_ok=True)
                    missing.write_text("memory diagnostic unavailable\n", encoding="utf-8")
                    lane.observed_mappings = {"raw": retained_identity(root, missing), "paths": []}
            for index, row in enumerate(selected):
                launcher = state.timing_launcher
                require(launcher is not None, "timing launcher build is absent")
                workloads[row.name] = measure_pair(
                    root, lanes, row, args, raw_root / "execution", args.seed + index,
                    launcher, cpu, peer_cpu, allowed_affinity,
                )
        finally:
            if cgroup is not None:
                cleanup = cgroup.close()
        report["execution"] = {
            "roots": {
                name: {"root": recorded_path(root, lane.root), "inventory": lane.inventory, "observed_mappings": lane.observed_mappings}
                for name, lane in lanes.items()
            },
            # One registry covers construction, cgroup setup, timed children,
            # and diagnostics.  Link/object records point at the relevant
            # leaves; retaining the complete roster means a failed or unused
            # command stream cannot be silently discarded.
            "raw": raw_registry(root, raw_root),
        }
        report["measurement"] = {
            "selected_workloads": [row.name for row in selected],
            "samples": args.samples,
            "warmup": args.warmup,
            "seed": args.seed,
            "cgroup_setup": cgroup_setup,
            "cgroup_cleanup": cleanup,
            "memory": memory,
            "memory_observers": memory_observers,
            "workloads": workloads,
        }
        report["source"]["after"] = evidence.seal_files(source_paths)
        report["source"]["source_sha256_after"] = native_source_digest(root)
        report["product"]["after"] = record_product(root, product)
        report["tools"]["after"] = tool_snapshot(
            root, product, musl_cc, cpu, allowed_affinity, peer_cpu,
            raw_root / "image-tools.manifest",
        )
        report["tools"]["host_cpuinfo_diagnostics"]["after"] = capture_cpuinfo_diagnostic(
            root, raw_root / "host" / "cpuinfo.after.raw",
        )
        require(report["tools"]["before"] == report["tools"]["after"], "tool/image identity changed during performance attempt")
        require(git_clean(root), "source became dirty during performance attempt")
        require(git_revision(root) == report["attempt"]["source_revision"],
                "source revision changed during performance attempt")
        require(report["source"]["before"] == report["source"]["after"],
                "sealed performance source/header inputs changed during attempt")
        require(report["source"]["source_sha256_before"] == report["source"]["source_sha256_after"],
                "full native source provenance changed during performance attempt")
        require(report["product"]["before"] == report["product"]["after"],
                "supplied dynamic product changed during performance attempt")
        # A measured red scorecard result is still complete evidence.  Keep
        # successful clients, raw sample plans, and replayable diagnostics
        # distinct from the numerical CPU/syscall verdicts they derive; the
        # latter remain visible blockers in the report rather than making a
        # complete failed measurement look like a missing measurement.
        timed_complete = timed_measurements_are_complete(workloads)
        observer_complete = isinstance(memory_observers, dict) and set(memory_observers) == {row.name for row in selected} and all(
            item.get("musl", {}).get("status") == "ok"
            and item.get("crabc", {}).get("status") == "ok"
            and item.get("comparison", {}).get("status") == "ok"
            for item in memory_observers.values()
        )
        complete = timed_complete and all(value.get("status") == "ok" for value in memory.values()) and observer_complete
        if not complete:
            report["status"] = "partial-evidence"
        else:
            report["status"] = evidence.SMOKE_BUDGET if args.implementation_smoke else "complete-evidence"
    except (AdapterError, evidence.EvidenceError, OSError) as error:
        report["failure"] = str(error)
        # Preserve every command/raw file already produced.  The partial report
        # cannot be collected, which makes failures visible rather than hidden.
        report["failure_raw"] = raw_registry(root, raw_root)
    finally:
        persisted = json_with_recorded_paths(root, report)
        write_json(report_path, persisted)
    return report_path, persisted


# The collector's own derivation code is sealed into its report; replay must
# use these same bytes, just as each attempt seals its fixture sources.
COLLECTOR_SOURCES = (
    "compat/perf/run.py",
    "compat/perf/run_x86_64.py",
    "compat/perf/x86_64-profile.toml",
    "compat/perf/x86_64_evidence.py",
    "compat/perf/x86_64_profile.py",
)


def collect(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    """Collect one immutable three-attempt roster into a replayed scorecard.

    Every attempt is replayed from raw evidence by the same reader that
    ``check`` uses.  The per-workload scorecard and the release decision are
    derived, never supplied: release qualifies only when the ordered chain has
    admitted correctness, the roster is the full budget, and every row passes
    every metric in all three attempts.  A smoke roster exercises the identical
    path and always reports its budget as a blocker.
    """

    root = repository_root()
    require(git_clean(root), "three-run collector requires a clean source revision")
    output = fresh_work_directory(root, args.work_dir)
    product_path = physical_path(args.dynamic_product, "supplied dynamic product", directory=True)
    product = record_product(root, product_path)
    roster_path, roster = load_attempt_roster(root, args.attempt_roster, product)
    attempts = [
        {
            "index": request["index"],
            "report": recorded_identity(
                root, roster_path_to_host(root, request["report"], f"attempt {request['index']} report", must_exist=True),
            ),
        }
        for request in roster["attempts"]
    ]
    budget = roster["budget"]
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": KIND,
        "status": "complete-evidence" if budget == evidence.FULL_BUDGET else evidence.SMOKE_BUDGET,
        "source_mount": evidence.SOURCE_MOUNT,
        "collector": {
            "attempt_roster": recorded_identity(root, roster_path),
            "dynamic_product_qualification": roster["dynamic_product_qualification"],
            "correctness_admission": roster["correctness_admission"],
            "budget": budget,
            "attempt_count": evidence.COLLECTOR_ATTEMPTS,
            "source": {name: recorded_identity(root, root / name) for name in COLLECTOR_SOURCES},
            "source_revision": roster["source_revision"],
            "source_sha256": roster["source_sha256"],
            "product": product,
        },
        "attempts": attempts,
        "scorecard": {},
        "release": {},
    }
    report["scorecard"], report["release"] = evidence.replay_collection(root, report)
    path = output / "collector.json"
    write_json(path, report)
    # The persisted bytes, not the in-memory derivation, are the handoff.
    result = evidence.validate_collector_report(root, path)
    print_check(result)
    return path, report


def print_check(result: evidence.CheckedReport) -> None:
    print(json.dumps({
        "evidence_valid": result.evidence_valid,
        "release_qualified": result.release_qualified,
        "blockers": list(result.blockers),
        "scorecard": result.scorecard,
    }, indent=2, sort_keys=True))


def check(args: argparse.Namespace) -> evidence.CheckedReport:
    """Replay a retained collector report or one retained attempt report."""

    root = repository_root()
    report = physical_path(args.report, "retained performance report")
    fields = set(evidence.load_json(report, "retained performance report"))
    if fields == evidence.COLLECTOR_REPORT_FIELDS:
        result = evidence.validate_collector_report(root, report)
    else:
        require(fields == evidence.ATTEMPT_FIELDS, "retained performance report is neither a collector nor an attempt")
        result = evidence.validate_attempt_report(root, report)
    print_check(result)
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    def common(target: argparse.ArgumentParser, *, needs_work: bool) -> None:
        target.add_argument("--dynamic-product", type=Path, required=True, help="physical installed or extracted dynamic product")
        if needs_work:
            target.add_argument("--work-dir", type=Path, required=True, help="fresh .work/x86_64 directory")
        target.add_argument("--musl-root", type=Path, default=DEFAULT_MUSL_ROOT)
        target.add_argument("--musl-cc", default=DEFAULT_MUSL_CC)
        target.add_argument("--cpu", type=int, default=None)
        target.add_argument("--timeout", type=float, default=20.0)
        target.add_argument("--seed", type=int, default=0x4352_4142)
        target.add_argument("--label", default="native-c")
    plan = commands.add_parser("plan", help="seal one immutable ordered three-attempt request roster")
    common(plan, needs_work=True)
    plan.add_argument("--implementation-smoke", action="store_true",
                      help="plan a smoke-budget roster: the complete route with one pair and no warm-up; never qualifies")
    plan.add_argument("--dynamic-qualification", type=Path, default=None,
                      help="optional validated owned-dynamic-qualification receipt for the supplied product")
    run = commands.add_parser("run", help="build and measure one supplied-product attempt")
    common(run, needs_work=True)
    run.add_argument("--samples", type=int, default=None,
                     help="paired samples (default: 31; implementation smoke fixes this to 1)")
    run.add_argument("--warmup", type=int, default=None,
                     help="warmup processes per lane (default: 3; implementation smoke fixes this to 0)")
    run.add_argument("--workload", action="append", metavar="NAME")
    run.add_argument("--attempt-index", type=int, default=1)
    run.add_argument("--attempt-roster", type=Path, default=None,
                     help="immutable plan binding this exact attempt/work directory")
    run.add_argument("--skip-syscalls", action="store_true", help="implementation-only; makes the attempt uncollectable")
    run.add_argument("--implementation-smoke", action="store_true",
                     help="complete metric route with one pair and no warm-up; collectable only into a nonqualifying smoke scorecard")
    run.add_argument("--same-object-input-proof", type=Path, default=None, help="proof emitted by an installed/extracted companion smoke")
    collect_parser = commands.add_parser("collect", help="replay an immutable three-attempt roster into its per-workload scorecard")
    common(collect_parser, needs_work=True)
    collect_parser.add_argument("--attempt-roster", type=Path, required=True)
    check_parser = commands.add_parser("check", help="host-safe replay of a retained collector or single-attempt report")
    check_parser.add_argument("report", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "plan":
            roster_path, _roster = plan_attempt_roster(args)
            print(roster_path)
            return 0
        if args.command == "run":
            report_path, report = run_attempt(args)
            print(report_path)
            return 0 if report.get("status") in {"complete-evidence", "implementation-smoke"} else 1
        if args.command == "collect":
            report_path, _report = collect(args)
            print(report_path)
            return 0
        if args.command == "check":
            check(args)
            return 0
        raise AssertionError("unknown command")
    except (AdapterError, evidence.EvidenceError, OSError) as error:
        print(f"native x86 C performance: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
