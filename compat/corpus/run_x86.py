#!/usr/bin/env python3
"""Run the finite x86_64 Alpine corpus with an installed candidate and musl.

The native corpus has one frozen, signed APK closure.  It never invokes apk's
installer or solver: archives are hash- and signature-checked, safely copied
into a fresh root, and entered by a chroot leaf that directly ``execve``s the
package executable.  Each side gets the same application payload and fixture
state.  Only the canonical musl loader/libc bytes differ.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import os
import platform
import resource
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("manifest-x86_64.toml")
DEFAULT_INPUT = ROOT / ".work/x86_64/owned-package-corpus-input/apks"
DEFAULT_INDEX = ROOT / ".work/x86_64/owned-package-corpus-input/index/main-x86_64.APKINDEX.tar.gz"
DEFAULT_WORK = ROOT / ".work/x86_64/tmp/owned-package-corpus"
PRIVATE_WORK_ROOT = ROOT / ".work"
ORACLE_ROOT = Path("/opt/musl-1.2.6")
APK = Path("/sbin/apk")
KEYS = Path("/etc/apk/keys")
ORACLE_SOURCE_MANIFEST = ORACLE_ROOT / ".crabc-oracle"
LIFETIME_HELPER = ROOT / "compat/x86_64/run_qualification_manifest.py"
LIFETIME_HELPER_MANIFEST = ROOT / "compat/x86_64/generate_qualification_manifest.py"
TIERS = ("A", "B", "C", "D")
TIMEOUT_SECONDS = 12
SCHEMA = "crabc.x86_64-owned-package-corpus/v3"
PRODUCT_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
CANONICAL_INTERPRETER = "/lib/ld-musl-x86_64.so.1"
CANONICAL_LIBC = "/lib/libc.musl-x86_64.so.1"
CASE_ENVIRONMENT = {"PATH": "/bin:/usr/bin", "HOME": "/root", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
SUPERVISOR_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}


class CorpusError(RuntimeError):
    """The finite corpus input or its private execution boundary was unsafe."""


@dataclasses.dataclass(frozen=True)
class SetupFile:
    path: str
    contents: bytes


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    id: str
    tier: str
    package: str
    path: str
    argv: tuple[str, ...]
    stdin: bytes
    setup: tuple[SetupFile, ...]
    cwd: str
    stateful: bool
    requires_dt_relr: bool


@dataclasses.dataclass(frozen=True)
class ManifestSpec:
    bytes: bytes
    archive_roster: Mapping[str, str]
    excluded_archives: frozenset[str]
    package_library_dirs: tuple[str, ...]
    required_paths: tuple[str, ...]
    base_fixtures: Mapping[str, bytes]
    base_image_files: Mapping[str, Mapping[str, object]]
    cases: tuple[CaseSpec, ...]
    direct_packages: Mapping[str, str]
    source_manifest: Path
    image: str


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    status: int | str
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def fail(message: str) -> None:
    raise CorpusError(message)


def require(value: object, message: str) -> None:
    if not value:
        fail(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, label: str) -> str:
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or path.is_symlink():
            fail(f"{label} is not a physical regular file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as error:
        raise CorpusError(f"cannot hash {label}: {path}") from error


def require_physical_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{label} traverses a symlink: {path}")
        if not stat.S_ISDIR(absolute.lstat().st_mode):
            fail(f"{label} is not a physical directory: {path}")
    except OSError as error:
        raise CorpusError(f"{label} is unavailable: {path}") from error
    return absolute


def _absolute_lexical_path(path: Path, label: str) -> Path:
    """Anchor one caller path at this checkout without accepting ``..``."""
    candidate = path if path.is_absolute() else ROOT / path
    if ".." in candidate.parts:
        fail(f"{label} has parent traversal: {path}")
    return Path(os.path.abspath(candidate))


def _reject_symlinked_components(path: Path, label: str) -> None:
    """Reject every present alias in a lexical state/output path."""
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            if os.path.lexists(current) and stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{label} traverses a symlink: {path}")
    except OSError as error:
        raise CorpusError(f"{label} is unavailable: {path}") from error


def _private_work_root() -> Path:
    """Create the sole physical mutable boundary for native corpus evidence."""
    boundary = _absolute_lexical_path(PRIVATE_WORK_ROOT, "checkout .work")
    _reject_symlinked_components(boundary, "checkout .work")
    try:
        boundary.mkdir(mode=0o755, exist_ok=True)
    except OSError as error:
        raise CorpusError(f"cannot create checkout .work: {boundary}") from error
    return require_physical_directory(boundary, "checkout .work")


def _private_directory(path: Path, label: str, *, dedicated: bool) -> Path:
    """Create readable evidence parents inside the checkout-local boundary.

    Each fresh execution root is separately private until its run ends.
    Existing parent permissions belong to the caller and are not changed.
    """
    boundary = _private_work_root()
    candidate = _absolute_lexical_path(path, label)
    _reject_symlinked_components(candidate, label)
    try:
        relative = candidate.relative_to(boundary)
    except ValueError as error:
        raise CorpusError(f"{label} must stay below checkout .work: {candidate}") from error
    if dedicated and not relative.parts:
        fail(f"{label} must name a dedicated directory below checkout .work")
    current = boundary
    for component in relative.parts:
        current /= component
        if os.path.lexists(current):
            require_physical_directory(current, label)
            continue
        try:
            current.mkdir(mode=0o755)
        except OSError as error:
            raise CorpusError(f"cannot create {label}: {current}") from error
        require_physical_directory(current, label)
    return require_physical_directory(candidate, label)


def private_campaign_parent(path: Path) -> Path:
    """Admit ``--work`` as the parent for one campaign's retained run roots."""
    return _private_directory(path, "native corpus work parent", dedicated=True)


def prepare_report_destination(path: Path) -> Path:
    """Admit one fresh report file below ``.work`` without overwriting evidence."""
    candidate = _absolute_lexical_path(path, "native corpus report")
    if candidate == _private_work_root() or not candidate.name:
        fail("native corpus report must name a file below checkout .work")
    _private_directory(candidate.parent, "native corpus report parent", dedicated=False)
    _reject_symlinked_components(candidate, "native corpus report")
    if os.path.lexists(candidate):
        fail(f"native corpus report already exists: {candidate}")
    return candidate


def write_new_report(path: Path, encoded: str) -> Path:
    """Create a report exactly once after rechecking its physical destination."""
    destination = prepare_report_destination(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            # Publish host-readable evidence only after its complete bytes
            # have reached the owned descriptor. Partial writes stay private.
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
    except OSError as error:
        raise CorpusError(f"cannot create native corpus report: {destination}") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
    return destination


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def _case_from_raw(raw: object, index: int, package_names: set[str]) -> CaseSpec:
    if not isinstance(raw, dict):
        fail(f"source cases[{index}] is not a table")
    def text(name: str) -> str:
        value = raw.get(name)
        if not isinstance(value, str) or not value:
            fail(f"source cases[{index}].{name} is invalid")
        return value
    case_id, tier, package, path = text("id"), text("tier"), text("package"), text("path")
    if tier not in TIERS or package not in package_names or not path.startswith("/") or "\x00" in path:
        fail(f"source case {case_id} has an invalid tier, package, or executable path")
    argv = raw.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) and "\x00" not in value for value in argv):
        fail(f"source case {case_id} argv is invalid")
    stdin = raw.get("stdin", "")
    if not isinstance(stdin, str):
        fail(f"source case {case_id} stdin is invalid")
    setup: list[SetupFile] = []
    raw_setup = raw.get("setup", [])
    if not isinstance(raw_setup, list):
        fail(f"source case {case_id} setup is invalid")
    for setup_index, item in enumerate(raw_setup):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("contents"), str):
            fail(f"source case {case_id} setup[{setup_index}] is invalid")
        setup_path = item["path"]
        if not setup_path.startswith("/") or "\x00" in setup_path:
            fail(f"source case {case_id} setup path is invalid")
        setup.append(SetupFile(setup_path, item["contents"].encode("utf-8")))
    cwd = raw.get("cwd", "/tmp")
    if not isinstance(cwd, str) or not cwd.startswith("/") or "\x00" in cwd:
        fail(f"source case {case_id} cwd is invalid")
    stateful = raw.get("stateful", False)
    relr = raw.get("requires_dt_relr", False)
    if not isinstance(stateful, bool) or not isinstance(relr, bool):
        fail(f"source case {case_id} flags are invalid")
    return CaseSpec(case_id, tier, package, path, tuple(argv), stdin.encode("utf-8"), tuple(setup), cwd, stateful, relr)


def load_manifest(path: Path = MANIFEST) -> ManifestSpec:
    """Load the native package snapshot and exact shared workload semantics."""
    try:
        raw_bytes = path.read_bytes()
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CorpusError(f"native corpus manifest is unreadable: {path}") from error
    if raw.get("schema") != 1 or raw.get("architecture") != "x86_64" or raw.get("musl_version") != "1.2.6":
        fail("native corpus manifest identity drifted")
    if not isinstance(raw.get("image"), str) or "@sha256:" not in raw["image"]:
        fail("native corpus image is not digest pinned")
    roster = raw.get("archive_roster")
    excluded = raw.get("excluded_payload")
    workload = raw.get("workload")
    direct = raw.get("direct_packages")
    deltas = raw.get("native_version_deltas")
    repository = raw.get("repository")
    payload = raw.get("payload")
    fixtures = raw.get("fixtures")
    base_image_files = raw.get("base_image_files")
    if not isinstance(roster, dict) or not isinstance(excluded, dict) or not isinstance(workload, dict) or not isinstance(direct, dict) or not isinstance(deltas, dict) or not isinstance(repository, dict) or not isinstance(payload, dict) or not isinstance(fixtures, dict) or not isinstance(base_image_files, dict):
        fail("native corpus manifest required tables are absent")
    required_paths = payload.get("required_paths")
    library_dirs = payload.get("package_library_dirs")
    if not isinstance(required_paths, list) or not isinstance(library_dirs, list):
        fail("native corpus required payload paths or library directories are absent")
    archive_roster: dict[str, str] = {}
    for name, digest in roster.items():
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".apk"):
            fail("native corpus archive roster has an unsafe filename")
        archive_roster[name] = require_sha256(digest, f"archive digest {name}")
    if len(archive_roster) != 59:
        fail("native corpus archive roster count drifted")
    excluded_values = excluded.get("archives")
    if excluded_values != ["musl-1.2.6-r2.apk"] or excluded_values[0] not in archive_roster:
        fail("native corpus excluded libc archive contract drifted")
    source_text = workload.get("source_manifest")
    if not isinstance(source_text, str):
        fail("native corpus source workload manifest is missing")
    if workload.get("case_count") != 34:
        fail("native corpus case count drifted")
    source_manifest = ROOT / source_text
    try:
        source_raw = tomllib.loads(source_manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CorpusError("native corpus source workload cannot be parsed") from error
    package_names = set(direct)
    if len(package_names) != 15 or not all(isinstance(name, str) and isinstance(version, str) for name, version in direct.items()):
        fail("native corpus direct package roster drifted")
    expected_direct = {"busybox", "coreutils", "coreutils-env", "grep", "sed", "file", "tar", "gzip", "zstd", "sqlite", "curl", "openssl", "openssh-client-default", "git", "python3"}
    if package_names != expected_direct:
        fail("native corpus direct package names drifted")
    source_packages = source_raw.get("packages")
    if not isinstance(source_packages, list):
        fail("native corpus source package roster is invalid")
    source_versions = {item.get("name"): item.get("version") for item in source_packages if isinstance(item, dict)}
    if set(source_versions) != package_names or not all(isinstance(value, str) for value in source_versions.values()):
        fail("native corpus source package identities drifted")
    changed = {name for name in package_names if direct[name] != source_versions[name]}
    expected_changed = {"gzip", "sqlite", "curl", "openssl", "openssh-client-default"}
    if changed != expected_changed or set(deltas) != expected_changed:
        fail("native corpus target-specific version delta roster drifted")
    for name in expected_changed:
        delta = deltas[name]
        if not isinstance(delta, dict) or delta.get("aarch64") != source_versions[name] or delta.get("x86_64") != direct[name]:
            fail(f"native corpus target-specific version delta is invalid: {name}")
    cases = tuple(_case_from_raw(item, index, package_names) for index, item in enumerate(source_raw.get("cases", [])))
    if len(cases) != 34 or len({case.id for case in cases}) != 34:
        fail("native corpus source case roster drifted")
    required = tuple(required_paths)
    if not all(isinstance(value, str) and value.startswith("/") and ".." not in Path(value).parts for value in required):
        fail("native corpus required payload paths are unsafe")
    libraries = tuple(library_dirs)
    if libraries != ("/usr/lib",):
        fail("native corpus package library-directory contract drifted")
    base_fixtures: dict[str, bytes] = {}
    for fixture_path, contents in fixtures.items():
        if not isinstance(fixture_path, str) or not fixture_path.startswith("/") or ".." in Path(fixture_path).parts or not isinstance(contents, str):
            fail("native corpus fixture contract is unsafe")
        base_fixtures[fixture_path] = contents.encode("utf-8")
    if base_fixtures != {"/etc/alpine-release": b"3.24.1\n"}:
        fail("native corpus fixture contract drifted")
    expected_base_paths = {"/etc/passwd", "/etc/group"}
    if set(base_image_files) != expected_base_paths:
        fail("native corpus base image file roster drifted")
    checked_base_files: dict[str, Mapping[str, object]] = {}
    for base_path, identity in base_image_files.items():
        if not isinstance(identity, dict) or require_sha256(identity.get("sha256"), f"base image digest {base_path}") is None:
            fail("native corpus base image identity is malformed")
        if not all(isinstance(identity.get(key), int) and identity[key] >= 0 for key in ("mode", "uid", "gid")):
            fail("native corpus base image metadata is malformed")
        checked_base_files[base_path] = dict(identity)
    return ManifestSpec(raw_bytes, archive_roster, frozenset(excluded_values), libraries, required, base_fixtures, checked_base_files, cases, dict(direct), source_manifest, raw["image"])


def select_cases(manifest: ManifestSpec, tiers: Sequence[str], case_ids: Sequence[str] = ()) -> tuple[CaseSpec, ...]:
    requested_tiers = set(TIERS if "all" in tiers else tiers)
    if not requested_tiers <= set(TIERS):
        fail("unknown native corpus tier")
    known = {case.id for case in manifest.cases}
    if set(case_ids) - known:
        fail("unknown native corpus case")
    chosen = set(case_ids)
    result = tuple(case for case in manifest.cases if case.tier in requested_tiers and (not chosen or case.id in chosen))
    if not result:
        fail("native corpus selection is empty")
    return result


def safe_archive_name(name: str) -> tuple[str, ...]:
    path = Path(name)
    if not name or name.startswith("/") or "\\" in name or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"archive member escapes private root: {name!r}")
    return path.parts


def safe_archive_members(names: Iterable[str]) -> tuple[str, ...]:
    """Expose lexical rejection for focused archive traversal regression tests."""
    values = tuple(names)
    for name in values:
        safe_archive_name(name)
    return values


def _destination(root: Path, name: str) -> Path:
    parts = safe_archive_name(name)
    current = root
    for part in parts[:-1]:
        current /= part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                fail(f"archive member traverses non-directory payload path: {name!r}")
        else:
            current.mkdir(mode=0o755)
    return current / parts[-1]


def _safe_link_target(member_name: str, linkname: str) -> tuple[str, ...]:
    """Normalize an archive link target while proving it cannot leave root.

    Package symlinks such as ``usr/bin/[ -> ../../bin/coreutils`` legitimately
    contain parent components.  They are safe only if their lexical walk ends
    beneath this root; rejecting every ``..`` would reject that fixed Alpine
    payload and accepting it blindly would permit traversal.
    """
    if not linkname or "\x00" in linkname:
        fail(f"archive link target is invalid: {member_name!r}")
    member_parts = safe_archive_name(member_name)
    target = PurePosixPath(linkname)
    parts: list[str] = [] if target.is_absolute() else list(member_parts[:-1])
    for part in target.parts:
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            if not parts:
                fail(f"archive link escapes private root: {member_name!r}")
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        fail(f"archive link target is invalid: {member_name!r}")
    return tuple(parts)


def extract_archive(archive: Path, root: Path) -> None:
    """Extract one signed APK without hooks and without following payload links."""
    try:
        with tarfile.open(archive, "r:*") as stream:
            for member in stream:
                if member.name in {".PKGINFO", ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"} or member.name.startswith(".post-") or member.name == ".trigger":
                    continue
                destination = _destination(root, member.name.rstrip("/"))
                if member.isdir():
                    if destination.exists() or destination.is_symlink():
                        if destination.is_symlink() or not destination.is_dir():
                            fail(f"archive directory collides with payload: {member.name!r}")
                    else:
                        destination.mkdir(mode=member.mode & 0o777 or 0o755)
                elif member.isreg():
                    if destination.exists() or destination.is_symlink():
                        fail(f"archive regular file collides with payload: {member.name!r}")
                    source = stream.extractfile(member)
                    if source is None:
                        fail(f"archive cannot read payload file: {member.name!r}")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(destination, flags, member.mode & 0o777 or 0o644)
                    try:
                        with os.fdopen(descriptor, "wb") as output:
                            descriptor = -1
                            shutil.copyfileobj(source, output)
                    finally:
                        if descriptor != -1:
                            os.close(descriptor)
                elif member.issym():
                    _safe_link_target(member.name, member.linkname)
                    if destination.exists() or destination.is_symlink():
                        fail(f"archive symlink collides with payload: {member.name!r}")
                    os.symlink(member.linkname, destination)
                elif member.islnk():
                    # Tar hard-link names address archive-root members; unlike
                    # symlink text they are not relative to this member's
                    # parent directory.
                    target = root.joinpath(*safe_archive_name(member.linkname))
                    current = root
                    for part in target.relative_to(root).parts[:-1]:
                        current /= part
                        if current.is_symlink() or not current.is_dir():
                            fail(f"archive hardlink traverses a non-directory payload path: {member.name!r}")
                    if not target.is_file() or target.is_symlink() or destination.exists() or destination.is_symlink():
                        fail(f"archive hardlink is not a prior physical payload file: {member.name!r}")
                    os.link(target, destination)
                else:
                    fail(f"archive has unsupported payload type: {member.name!r}")
    except (OSError, tarfile.TarError) as error:
        raise CorpusError(f"cannot safely extract archive {archive.name}") from error


def make_tree_readable(root: Path) -> dict[str, int]:
    """Retain a completed private tree while recording only changed modes.

    Runtime and base-fixture checks precede this operation. Read/traverse bits
    make the evidence inspectable by the host; the sparse original modes let
    its reader reconstruct the exact execution-time hash. Symlinks and device
    nodes keep their modes, and symlink targets are never traversed.
    """
    root = require_physical_directory(root, "retained corpus tree")
    original_modes: dict[str, int] = {}
    pending = [root]
    while pending:
        path = pending.pop()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            readable = stat.S_IMODE(mode) | 0o555
            pending.extend(path.iterdir())
        elif stat.S_ISREG(mode):
            readable = stat.S_IMODE(mode) | 0o444
        else:
            continue
        if readable != stat.S_IMODE(mode):
            if path != root:
                original_modes[path.relative_to(root).as_posix()] = stat.S_IMODE(mode)
            os.chmod(path, readable, follow_symlinks=False)
    return original_modes


def tree_sha256(root: Path, label: str, *, retention_modes: Mapping[str, int] | None = None) -> str:
    """Hash a tree, optionally reconstructing its pre-retention permissions.

    Only an exact recorded read/traverse-bit addition can be reconstructed.
    Missing paths, symlink/device overrides, unchanged modes, or any other
    permission change fail instead of hiding drift in retained evidence.
    """
    root = require_physical_directory(root, label)
    if retention_modes is None:
        retention_modes = {}
    if not isinstance(retention_modes, dict):
        fail(f"{label} retained modes are not an object")
    for path, mode in retention_modes.items():
        if (not isinstance(path, str) or "\0" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or type(mode) is not int or not 0 <= mode <= 0o7777):
            fail(f"{label} has an invalid retained mode entry")
    observed_modes: set[str] = set()
    digest = hashlib.sha256()
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir(), key=lambda value: value.name, reverse=True):
            relative_path = child.relative_to(root).as_posix()
            relative = relative_path.encode("utf-8")
            mode = child.lstat().st_mode
            permissions = stat.S_IMODE(mode)
            if relative_path in retention_modes:
                original = retention_modes[relative_path]
                addition = 0o555 if stat.S_ISDIR(mode) else 0o444 if stat.S_ISREG(mode) else 0
                if addition == 0 or original == permissions or permissions != original | addition:
                    fail(f"{label} retained permissions differ: {relative_path}")
                observed_modes.add(relative_path)
                permissions = original
            digest.update(relative + b"\0" + str(permissions).encode("ascii") + b"\0")
            if stat.S_ISREG(mode):
                digest.update(b"regular\0" + bytes.fromhex(sha256_file(child, label)))
            elif stat.S_ISDIR(mode):
                digest.update(b"directory\0")
                pending.append(child)
            elif stat.S_ISLNK(mode):
                digest.update(b"symlink\0" + os.fsencode(os.readlink(child)))
            elif stat.S_ISCHR(mode):
                digest.update(b"char-device\0" + str(os.major(child.stat().st_rdev)).encode("ascii") + b":" + str(os.minor(child.stat().st_rdev)).encode("ascii"))
            else:
                fail(f"{label} has an unsupported payload type: {child}")
    if observed_modes != set(retention_modes):
        fail(f"{label} retained modes name an absent path")
    return digest.hexdigest()


def stream_snapshot(value: bytes) -> dict[str, object]:
    return {"byte_length": len(value), "sha256": sha256_bytes(value), "hex": value.hex()}


def compare_results(oracle: ProcessResult, candidate: ProcessResult) -> dict[str, object]:
    status_match = oracle.status == candidate.status
    stdout_match = oracle.stdout == candidate.stdout
    stderr_match = oracle.stderr == candidate.stderr
    passed = not oracle.timed_out and not candidate.timed_out and oracle.status == 0 and candidate.status == 0 and status_match and stdout_match and stderr_match
    return {"passed": passed, "normalization": "none", "status_match": status_match, "stdout_match": stdout_match, "stderr_match": stderr_match,
            "oracle": {"status": oracle.status, "timed_out": oracle.timed_out, "stdout": stream_snapshot(oracle.stdout), "stderr": stream_snapshot(oracle.stderr)},
            "candidate": {"status": candidate.status, "timed_out": candidate.timed_out, "stdout": stream_snapshot(candidate.stdout), "stderr": stream_snapshot(candidate.stderr)}}


def has_dynamic_tag(output: str, tag: str) -> bool:
    """Match one `readelf -dW` tag, without accepting a longer tag name."""
    return re.search(r"\([^)]*\b" + re.escape(tag) + r"\)", output) is not None


def require_native_environment() -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        fail("native package corpus requires Linux/x86_64 without emulation")
    if os.geteuid() != 0:
        fail("native package corpus requires root for a private chroot")


def apk_identity() -> dict[str, object]:
    if not APK.is_file() or not KEYS.is_dir():
        fail("pinned Alpine apk verifier or keys are unavailable")
    version = subprocess.run([str(APK), "--version"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode("utf-8", "replace").splitlines()
    if not version or version[0] != "apk-tools 3.0.6-r0, compiled for x86_64.":
        fail("pinned Alpine apk verifier version drifted")
    keys = {path.name: sha256_file(path, f"apk key {path.name}") for path in sorted(KEYS.glob("*.pub"))}
    if "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub" not in keys:
        fail("pinned Alpine signing key is unavailable")
    readelf = Path("/usr/bin/readelf")
    if not readelf.is_file() or readelf.is_symlink():
        fail("pinned ELF inspector is unavailable")
    return {"path": str(APK), "sha256": sha256_file(APK, "apk verifier"), "version": version[0], "keys": keys,
            "readelf": {"path": str(readelf), "sha256": sha256_file(readelf, "ELF inspector")}}


def oracle_source_identity() -> dict[str, object]:
    """Bind both the pinned musl declaration and the actual interpreter bytes."""
    root = require_physical_directory(ORACLE_ROOT, "pinned musl root")
    runtime = root / "lib/libc.so"
    loader = root / "lib/ld-musl-x86_64.so.1"
    try:
        if not loader.is_symlink() or loader.resolve(strict=True) != runtime:
            fail("pinned musl loader does not alias its physical libc")
        loader_target = os.readlink(loader)
    except OSError as error:
        raise CorpusError("pinned musl interpreter alias is unavailable") from error
    return {
        "root": str(root),
        "runtime": {"path": str(runtime), "sha256": sha256_file(runtime, "pinned musl runtime")},
        "loader": {"path": str(loader), "target": loader_target, "resolved_path": str(runtime)},
        "source_manifest": {
            "path": str(ORACLE_SOURCE_MANIFEST),
            "sha256": sha256_file(ORACLE_SOURCE_MANIFEST, "pinned musl oracle source manifest"),
        },
    }


def _repository_source_identity(path: Path, label: str) -> dict[str, str]:
    source = _absolute_lexical_path(path, label)
    try:
        relative = source.relative_to(ROOT)
    except ValueError as error:
        raise CorpusError(f"{label} escapes this checkout: {source}") from error
    return {"path": relative.as_posix(), "sha256": sha256_file(source, label)}


def _module_source(module: Any, expected: Path, label: str) -> Path:
    source = getattr(module, "__file__", None)
    if not isinstance(source, str):
        fail(f"{label} has no source file")
    try:
        actual = Path(source).resolve(strict=True)
    except OSError as error:
        raise CorpusError(f"{label} source is unavailable") from error
    if actual != expected:
        fail(f"{label} source differs from the owned process-lifetime helper")
    return actual


def source_identity(manifest: ManifestSpec) -> dict[str, object]:
    """Seal every local source actually used before private roots are made.

    ``execute_case`` imports the descendant-lifetime owner on demand.  Import it
    here as well, prove the exact two local source files it executed, and bind
    those same bytes before and after the corpus transaction.
    """
    qualification = _lifetime_module()
    helper = _module_source(qualification, LIFETIME_HELPER, "process-lifetime helper")
    helper_manifest = _module_source(
        qualification.manifest,
        LIFETIME_HELPER_MANIFEST,
        "process-lifetime helper manifest",
    )
    return {
        "runner": _repository_source_identity(Path(__file__), "native corpus runner"),
        "native_manifest": _repository_source_identity(MANIFEST, "native corpus manifest"),
        "workload_source": _repository_source_identity(manifest.source_manifest, "workload source manifest"),
        "process_lifetime_helpers": {
            "subreaper": _repository_source_identity(helper, "process-lifetime helper"),
            "manifest": _repository_source_identity(helper_manifest, "process-lifetime helper manifest"),
        },
    }


def apk_metadata(archive: Path) -> dict[str, str]:
    """Read the signed archive metadata that names this exact payload."""
    try:
        with tarfile.open(archive, "r:*") as stream:
            member = stream.getmember(".PKGINFO")
            content = stream.extractfile(member)
            if content is None:
                fail(f"APK metadata is unavailable: {archive.name}")
            fields: dict[str, str] = {}
            for line in content.read().decode("utf-8", "strict").splitlines():
                key, separator, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if separator and key and key not in fields:
                    fields[key] = value
    except (OSError, UnicodeDecodeError, tarfile.TarError) as error:
        raise CorpusError(f"APK metadata is unreadable: {archive.name}") from error
    if not all(isinstance(fields.get(key), str) and fields[key] for key in ("pkgname", "pkgver", "arch")):
        fail(f"APK metadata identity is incomplete: {archive.name}")
    if fields["arch"] not in {"x86_64", "noarch"} or archive.name != f"{fields['pkgname']}-{fields['pkgver']}.apk":
        fail(f"APK metadata identity differs from archive filename: {archive.name}")
    return {key: fields[key] for key in ("pkgname", "pkgver", "arch")}


def require_exact_archive_roster(received: Iterable[str], expected: Iterable[str]) -> None:
    """Reject both an absent closure member and an unpinned extra payload."""
    if set(received) != set(expected):
        fail("APK archive directory does not exactly match the finite native closure")


def input_identity(manifest: ManifestSpec, archive_dir: Path, index: Path) -> dict[str, object]:
    """Hash the exact finite APK/index source without invoking the verifier.

    Archive digests are pinned by the manifest. The repository index is a
    mutable upstream snapshot that Alpine regenerates, so a pinned index digest
    could never be fetched again; it is identified by the observed bytes that
    this run verifies, and the post-execution identity must repeat them.
    """
    archive_dir = require_physical_directory(archive_dir, "APK archive directory")
    index_sha256 = sha256_file(index, "signed APK index")
    entries = list(archive_dir.iterdir())
    if any(entry.is_symlink() or not stat.S_ISREG(entry.lstat().st_mode) for entry in entries):
        fail("APK archive directory contains a non-regular or linked entry")
    require_exact_archive_roster((path.name for path in entries), manifest.archive_roster)
    archives: dict[str, dict[str, str]] = {}
    for name, expected in sorted(manifest.archive_roster.items()):
        archive = archive_dir / name
        observed = sha256_file(archive, f"APK archive {name}")
        if observed != expected:
            fail(f"APK archive digest differs: {name}")
        archives[name] = {"sha256": observed}
    return {
        "directory": str(archive_dir),
        "index": {"path": str(index), "sha256": index_sha256},
        "archives": archives,
    }


def verify_inputs(manifest: ManifestSpec, archive_dir: Path, index: Path) -> dict[str, object]:
    """Verify signatures once, retaining the corresponding raw input identity."""
    identity = input_identity(manifest, archive_dir, index)
    archive_dir = Path(identity["directory"])
    verification: dict[str, dict[str, object]] = {}
    for name in sorted(manifest.archive_roster):
        archive = archive_dir / name
        result = subprocess.run([str(APK), "--keys-dir", str(KEYS), "verify", str(archive)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            fail(f"APK archive signature verification failed: {name}")
        metadata = apk_metadata(archive)
        expected_direct_version = manifest.direct_packages.get(metadata["pkgname"])
        if expected_direct_version is not None and metadata["pkgver"] != expected_direct_version:
            fail(f"direct package metadata differs from native manifest: {metadata['pkgname']}")
        verification[name] = {"metadata": metadata, "signature_stdout": result.stdout.decode("utf-8", "strict"), "signature_stderr": result.stderr.decode("utf-8", "strict")}
    index_result = subprocess.run([str(APK), "--keys-dir", str(KEYS), "verify", str(index)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if index_result.returncode != 0:
        fail("APK index signature verification failed")
    return {
        "identity": identity,
        "index_signature": {
            "stdout": index_result.stdout.decode("utf-8", "strict"),
            "stderr": index_result.stderr.decode("utf-8", "strict"),
        },
        "archive_signatures": verification,
    }


def stage_application_payload(manifest: ManifestSpec, archive_dir: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for name in sorted(manifest.archive_roster):
        if name not in manifest.excluded_archives:
            extract_archive(archive_dir / name, destination)
    for fixture_path, contents in manifest.base_fixtures.items():
        fixture = destination / fixture_path.lstrip("/")
        fixture.parent.mkdir(parents=True, exist_ok=True)
        if fixture.exists() or fixture.is_symlink():
            fail(f"base fixture collides with application payload: {fixture_path}")
        fixture.write_bytes(contents)
        os.chmod(fixture, 0o644)
    for required_path in manifest.required_paths:
        candidate = destination / required_path.lstrip("/")
        if not candidate.exists() and not candidate.is_symlink():
            fail(f"finite application closure lacks required payload: {required_path}")
    for forbidden in (CANONICAL_INTERPRETER, CANONICAL_LIBC, "/lib/libc.so", "/usr/lib/libc.musl-x86_64.so.1"):
        if (destination / forbidden.lstrip("/")).exists() or (destination / forbidden.lstrip("/")).is_symlink():
            fail("application APK closure supplies a foreign libc or loader")


def stage_base_image_fixtures(manifest: ManifestSpec, destination: Path) -> dict[str, object]:
    """Copy the named pinned-image records and create the minimal root nodes."""
    copied: dict[str, dict[str, object]] = {}
    for virtual_path, expected in manifest.base_image_files.items():
        source = Path(virtual_path)
        try:
            metadata = source.lstat()
        except OSError as error:
            raise CorpusError(f"pinned native image file is unavailable: {virtual_path}") from error
        if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            fail(f"pinned native image file is not physical: {virtual_path}")
        observed = {"sha256": sha256_file(source, f"pinned native image {virtual_path}"), "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid}
        if observed != expected:
            fail(f"pinned native image file identity differs: {virtual_path}")
        target = destination / virtual_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            fail(f"pinned native image file collides with APK payload: {virtual_path}")
        shutil.copyfile(source, target)
        os.chmod(target, observed["mode"])
        os.chown(target, observed["uid"], observed["gid"])
        copied[virtual_path] = observed
    for virtual_path, mode in (("/tmp", 0o1777), ("/root", 0o700), ("/dev", 0o755)):
        target = destination / virtual_path.lstrip("/")
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_dir():
                fail(f"private base directory collides with APK payload: {virtual_path}")
        else:
            target.mkdir(mode=mode)
        os.chmod(target, mode)
    null = destination / "dev/null"
    if null.exists() or null.is_symlink():
        fail("private base device collides with APK payload")
    os.mknod(null, stat.S_IFCHR | 0o666, os.makedev(1, 3))
    # mknod is subject to the supervisor's umask; the sealed fixture contract
    # records the intended node mode independently of that ambient setting.
    os.chmod(null, 0o666)
    null_metadata = null.lstat()
    if not stat.S_ISCHR(null_metadata.st_mode) or (stat.S_IMODE(null_metadata.st_mode), os.major(null_metadata.st_rdev), os.minor(null_metadata.st_rdev)) != (0o666, 1, 3):
        fail("private /dev/null fixture is not the expected character device")
    return {"image_files": copied, "directories": {"/tmp": {"mode": 0o1777}, "/root": {"mode": 0o700}, "/dev": {"mode": 0o755}},
            "device": {"path": "/dev/null", "kind": "character", "mode": 0o666, "major": 1, "minor": 3}}


def assert_base_image_fixtures(manifest: ManifestSpec, destination: Path) -> dict[str, object]:
    """Prove one private execution root retained every approved base fixture."""
    copied: dict[str, dict[str, object]] = {}
    for virtual_path, expected in manifest.base_image_files.items():
        target = destination / virtual_path.lstrip("/")
        try:
            metadata = target.lstat()
        except OSError as error:
            raise CorpusError(f"private base image file is unavailable: {virtual_path}") from error
        observed = {"sha256": sha256_file(target, f"private base image {virtual_path}"), "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid}
        if target.is_symlink() or observed != expected:
            fail(f"private base image file identity differs: {virtual_path}")
        copied[virtual_path] = observed
    directories: dict[str, dict[str, int]] = {}
    for virtual_path, mode in (("/tmp", 0o1777), ("/root", 0o700), ("/dev", 0o755)):
        target = destination / virtual_path.lstrip("/")
        try:
            metadata = target.lstat()
        except OSError as error:
            raise CorpusError(f"private base directory is unavailable: {virtual_path}") from error
        if target.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != mode:
            fail(f"private base directory identity differs: {virtual_path}")
        directories[virtual_path] = {"mode": mode}
    null = destination / "dev/null"
    try:
        metadata = null.lstat()
    except OSError as error:
        raise CorpusError("private /dev/null fixture is unavailable") from error
    if not stat.S_ISCHR(metadata.st_mode) or (stat.S_IMODE(metadata.st_mode), os.major(metadata.st_rdev), os.minor(metadata.st_rdev)) != (0o666, 1, 3):
        fail("private /dev/null fixture is not the expected character device")
    return {"image_files": copied, "directories": directories,
            "device": {"path": "/dev/null", "kind": "character", "mode": 0o666, "major": 1, "minor": 3}}


def stage_execution_root(manifest: ManifestSpec, payload: Path, destination: Path) -> dict[str, object]:
    """Clone ordinary application bytes, then create base nodes in this root.

    ``copytree`` intentionally treats special files as ordinary files.  The
    shared application payload contains only files, directories, and links
    admitted from the APK closure; every execution root gets its own pinned
    base records and its own character device after that copy.
    """
    shutil.copytree(payload, destination, symlinks=True)
    staged = stage_base_image_fixtures(manifest, destination)
    if assert_base_image_fixtures(manifest, destination) != staged:
        fail("private base fixture receipt changed while staging execution root")
    return staged


def audit_application_elf_closure(
    root: Path, library_dirs: Sequence[str], runtime: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Prove every package ELF dependency resolves inside this finite root.

    The APK closure deliberately includes application DSOs such as libgcc and
    libstdc++.  They are shared, byte-identical package payload on both sides.
    The sole omitted dependency is musl's libc SONAME, which must resolve to
    the separately sealed runtime installed at ``CANONICAL_LIBC``.
    """
    records: list[dict[str, object]] = []
    for directory, _, names in os.walk(root, followlinks=False):
        for name in sorted(names):
            path = Path(directory) / name
            try:
                if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) or path.read_bytes()[:4] != b"\x7fELF":
                    continue
            except OSError as error:
                raise CorpusError(f"cannot inspect package payload ELF: {path}") from error
            dynamic = subprocess.run(["/usr/bin/readelf", "-dW", str(path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            headers = subprocess.run(["/usr/bin/readelf", "-lW", str(path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if dynamic.returncode != 0 or headers.returncode != 0:
                fail(f"cannot inspect package payload ELF: {path.relative_to(root)}")
            needed = tuple(re.findall(rb"Shared library: \[([^]]+)\]", dynamic.stdout))
            raw_search_paths = re.findall(rb"Library (?:rpath|runpath): \[([^]]*)\]", dynamic.stdout, flags=re.IGNORECASE)
            search_paths: list[str] = []
            for raw_path in raw_search_paths:
                try:
                    values = raw_path.decode("ascii", "strict").split(":")
                except UnicodeDecodeError as error:
                    raise CorpusError("package ELF has a non-ASCII library path") from error
                if any(value not in library_dirs for value in values):
                    fail(f"package payload ELF declares a library path outside the frozen closure: {path.relative_to(root)}")
                search_paths.extend(values)
            if b"Requesting program interpreter:" in headers.stdout and CANONICAL_INTERPRETER.encode("ascii") not in headers.stdout:
                fail(f"package executable interpreter differs from canonical musl path: {path.relative_to(root)}")
            providers: dict[str, dict[str, str]] = {}
            for soname_bytes in needed:
                try:
                    soname = soname_bytes.decode("ascii", "strict")
                except UnicodeDecodeError as error:
                    raise CorpusError("package ELF has a non-ASCII SONAME") from error
                if "/" in soname or not soname:
                    fail("package ELF SONAME is unsafe")
                if soname == "libc.musl-x86_64.so.1":
                    if runtime is None:
                        providers[soname] = {"kind": "sealed-runtime", "path": CANONICAL_LIBC}
                    else:
                        libc = root / CANONICAL_LIBC.lstrip("/")
                        if sha256_file(libc, "private runtime libc") != runtime["libc"]["sha256"]:
                            fail("package libc SONAME does not resolve to sealed runtime bytes")
                        providers[soname] = {"kind": "sealed-runtime", "path": CANONICAL_LIBC, "sha256": runtime["libc"]["sha256"]}
                    continue
                located: Path | None = None
                virtual_provider: str | None = None
                for library_dir in library_dirs:
                    candidate_virtual = library_dir.rstrip("/") + "/" + soname
                    try:
                        candidate = resolve_payload_path(root, candidate_virtual)
                    except CorpusError:
                        continue
                    located, virtual_provider = candidate, candidate_virtual
                    break
                if located is None or virtual_provider is None:
                    fail(f"package ELF dependency is outside the frozen payload: {soname}")
                providers[soname] = {"kind": "package-payload", "path": virtual_provider, "sha256": sha256_file(located, f"package DSO {soname}")}
            records.append({"path": "/" + path.relative_to(root).as_posix(), "sha256": sha256_file(path, "package ELF"), "search_paths": search_paths, "needed": providers})
    if not records:
        fail("finite application payload has no ELF objects")
    return records


def validate_product(product: Path) -> dict[str, object]:
    product = require_physical_directory(product, "supplied owned dynamic product")
    manifest_path = product / "share/crabc/manifest.json"
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CorpusError("supplied owned dynamic product manifest is unreadable") from error
    if (raw.get("schema"), raw.get("format"), raw.get("target")) != (1, PRODUCT_FORMAT, "x86_64-unknown-linux-musl"):
        fail("supplied owned dynamic product identity drifted")
    files, aliases = raw.get("files"), raw.get("symlinks")
    if not isinstance(files, dict) or aliases != {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}:
        fail("supplied owned dynamic product payload map drifted")
    required = {"lib/ld-crabc-x86_64.so.1", "usr/lib/libc.so"}
    if not required <= set(files):
        fail("supplied owned dynamic product lacks loader or libc")
    checked: dict[str, str] = {}
    for relative, expected in files.items():
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            fail("supplied owned dynamic product has unsafe file path")
        if not isinstance(expected, str) or sha256_file(product / relative, f"owned product {relative}") != expected:
            fail(f"supplied owned dynamic product payload differs: {relative}")
        checked[relative] = expected
    return {"path": str(product), "manifest_sha256": sha256_file(manifest_path, "owned product manifest"), "files": dict(sorted(checked.items())), "aliases": aliases}


def copy_runtime(root: Path, side: str, product: Path | None) -> dict[str, object]:
    lib = root / "lib"
    lib.mkdir(exist_ok=True)
    if side == "candidate":
        if product is None:
            fail("candidate runtime requires a supplied owned dynamic product")
        loader, libc = product / "lib/ld-crabc-x86_64.so.1", product / "usr/lib/libc.so"
    elif side == "oracle":
        loader, libc = ORACLE_ROOT / "lib/ld-musl-x86_64.so.1", ORACLE_ROOT / "lib/libc.so"
    else:
        fail("unknown runtime side")
    try:
        loader_bytes = loader.resolve(strict=True)
        libc_bytes = libc.resolve(strict=True)
    except OSError as error:
        raise CorpusError(f"{side} runtime input is unavailable") from error
    if not loader_bytes.is_file() or not libc_bytes.is_file() or loader_bytes.is_symlink() or libc_bytes.is_symlink():
        fail(f"{side} runtime input is not a physical regular file")
    if side == "oracle" and (not loader.is_symlink() or loader_bytes != libc_bytes):
        fail("pinned musl loader alias drifted")
    if side == "candidate" and loader.is_symlink():
        fail("candidate loader is not a physical product file")
    shutil.copyfile(loader_bytes, root / CANONICAL_INTERPRETER.lstrip("/"))
    shutil.copyfile(libc_bytes, root / CANONICAL_LIBC.lstrip("/"))
    os.chmod(root / CANONICAL_INTERPRETER.lstrip("/"), 0o755)
    os.chmod(root / CANONICAL_LIBC.lstrip("/"), 0o755)
    return {"loader": {"source": str(loader), "resolved_source": str(loader_bytes), "sha256": sha256_file(loader_bytes, f"{side} loader")}, "libc": {"source": str(libc), "resolved_source": str(libc_bytes), "sha256": sha256_file(libc_bytes, f"{side} libc")}, "canonical_interpreter": CANONICAL_INTERPRETER, "canonical_libc": CANONICAL_LIBC}


def assert_runtime_boundary(root: Path, runtime: Mapping[str, object]) -> None:
    loader = root / CANONICAL_INTERPRETER.lstrip("/")
    libc = root / CANONICAL_LIBC.lstrip("/")
    if sha256_file(loader, "private loader") != runtime["loader"]["sha256"] or sha256_file(libc, "private libc") != runtime["libc"]["sha256"]:
        fail("private root runtime bytes changed")
    if (root / "usr/lib/libc.so").exists() or (root / "usr/lib/libc.so").is_symlink():
        fail("private application root contains a foreign libc")


def create_fixture(root: Path, case: CaseSpec) -> None:
    for setup in case.setup:
        destination = root / setup.path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            fail(f"case fixture collides with application payload: {setup.path}")
        destination.write_bytes(setup.contents)
        os.chmod(destination, 0o600)
    cwd = root / case.cwd.lstrip("/")
    cwd.mkdir(parents=True, exist_ok=True)


def resolve_payload_path(root: Path, virtual_path: str) -> Path:
    """Resolve one chroot path without allowing host-absolute symlink escape."""
    if not virtual_path.startswith("/"):
        fail("private executable path is not absolute")
    pending = list(PurePosixPath(virtual_path).parts[1:])
    resolved: list[str] = []
    symlink_budget = 40
    while pending:
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                fail("private executable path escapes its root")
            resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        try:
            mode = candidate.lstat().st_mode
        except OSError as error:
            raise CorpusError(f"private executable path is unavailable: {virtual_path}") from error
        if stat.S_ISLNK(mode):
            symlink_budget -= 1
            if symlink_budget < 0:
                fail("private executable symlink chain is too deep")
            target = os.readlink(candidate)
            target_parts = list(PurePosixPath(target).parts)
            if PurePosixPath(target).is_absolute():
                resolved = []
                target_parts = target_parts[1:]
            pending = target_parts + pending
            continue
        resolved.append(part)
    result = root.joinpath(*resolved)
    try:
        if not stat.S_ISREG(result.lstat().st_mode):
            fail("private executable does not resolve to a regular file")
    except OSError as error:
        raise CorpusError("private executable resolution is unavailable") from error
    return result


CHROOT_LEAF = """
import json, os, resource, sys
root, cwd, program, argv, environment = json.loads(sys.argv[1])
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.chroot(root)
os.chdir(cwd)
os.execve(program, argv, environment)
"""


def _lifetime_module() -> Any:
    directory = str(ROOT / "compat/x86_64")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    try:
        import run_qualification_manifest as qualification
    except ImportError as error:
        raise CorpusError("owned private-root descendant boundary is unavailable") from error
    _module_source(qualification, LIFETIME_HELPER, "process-lifetime helper")
    _module_source(
        qualification.manifest,
        LIFETIME_HELPER_MANIFEST,
        "process-lifetime helper manifest",
    )
    return qualification


def execute_case(root: Path, case: CaseSpec) -> ProcessResult:
    program = resolve_payload_path(root, case.path)
    if not os.access(program, os.X_OK):
        fail(f"case package executable is unavailable: {case.path}")
    request = json.dumps([str(root), case.cwd, case.path, list(case.argv), CASE_ENVIRONMENT], separators=(",", ":"))
    qualification = _lifetime_module()
    try:
        with qualification.private_admission_subreaper() as boundary:
            process = subprocess.Popen([sys.executable, "-c", CHROOT_LEAF, request], cwd=ROOT, env=SUPERVISOR_ENVIRONMENT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            boundary.register_private_runner(process)
            try:
                stdout, stderr = process.communicate(case.stdin, timeout=TIMEOUT_SECONDS)
                boundary.reject_unexpected_descendants()
                return ProcessResult(process.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                boundary.terminate_and_reap(process)
                stdout, stderr = process.communicate()
                return ProcessResult(process.returncode, stdout, stderr, True)
            except BaseException:
                boundary.terminate_and_reap(process)
                raise
    except qualification.QualificationRunError as error:
        raise CorpusError(f"private root descendant boundary failed: {error}") from error


def executable_elf_record(root: Path, case: CaseSpec) -> dict[str, object]:
    executable = resolve_payload_path(root, case.path)
    headers = subprocess.run(["/usr/bin/readelf", "-lW", str(executable)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dynamic = subprocess.run(["/usr/bin/readelf", "-dW", str(executable)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if headers.returncode != 0 or CANONICAL_INTERPRETER.encode("ascii") not in headers.stdout:
        fail(f"case executable does not retain the canonical musl interpreter: {case.id}")
    if dynamic.returncode != 0:
        fail(f"cannot inspect case executable dynamic tags: {case.id}")
    relr = has_dynamic_tag(dynamic.stdout.decode("utf-8", "strict"), "RELR")
    if case.requires_dt_relr and not relr:
        fail(f"case executable lacks its frozen DT_RELR obligation: {case.id}")
    return {"path": case.path, "sha256": sha256_file(executable, f"case executable {case.id}"), "interpreter": CANONICAL_INTERPRETER, "dt_relr": relr}


def run(manifest: ManifestSpec, archive_dir: Path, index: Path, dynamic_sysroot: Path, work: Path, cases: Sequence[CaseSpec]) -> dict[str, object]:
    require_native_environment()
    work_parent = private_campaign_parent(work)
    if not cases:
        fail("native corpus selection is empty")
    source_before = source_identity(manifest)
    tools_before = apk_identity()
    inputs_before = verify_inputs(manifest, archive_dir, index)
    oracle_before = oracle_source_identity()
    product_before = validate_product(dynamic_sysroot)
    temporary_root = Path(tempfile.mkdtemp(prefix="owned-package-corpus-", dir=work_parent))
    try:
        if temporary_root.parent != work_parent or temporary_root.is_symlink():
            fail("native corpus private run root escaped its campaign parent")
        temporary_root = require_physical_directory(temporary_root, "native corpus private run root")
    except OSError as error:
        raise CorpusError("native corpus private run root is unavailable") from error
    try:
        payload = temporary_root / "application-payload"
        stage_application_payload(manifest, archive_dir, payload)
        elf_graph = audit_application_elf_closure(payload, manifest.package_library_dirs)
        payload_seal = tree_sha256(payload, "finite application payload")
        outcomes: list[dict[str, object]] = []
        for case in cases:
            side_results: dict[str, ProcessResult] = {}
            roots: dict[str, dict[str, object]] = {}
            for side in ("oracle", "candidate"):
                root = temporary_root / f"{case.id}-{side}"
                base_fixtures = stage_execution_root(manifest, payload, root)
                runtime = copy_runtime(root, side, dynamic_sysroot if side == "candidate" else None)
                create_fixture(root, case)
                if assert_base_image_fixtures(manifest, root) != base_fixtures:
                    fail(f"{case.id} {side} private base fixture changed before execution")
                assert_runtime_boundary(root, runtime)
                audit_application_elf_closure(root, manifest.package_library_dirs, runtime)
                before = tree_sha256(root, f"{case.id} {side} pre-execution root")
                elf = executable_elf_record(root, case)
                side_results[side] = execute_case(root, case)
                if assert_base_image_fixtures(manifest, root) != base_fixtures:
                    fail(f"{case.id} {side} private base fixture changed during execution")
                assert_runtime_boundary(root, runtime)
                after = tree_sha256(root, f"{case.id} {side} post-execution root")
                roots[side] = {"base_fixtures": base_fixtures, "runtime": runtime, "execution_tree_before_sha256": before, "execution_tree_after_sha256": after, "executable": elf}
            comparison = compare_results(side_results["oracle"], side_results["candidate"])
            outcomes.append({"id": case.id, "tier": case.tier, "package": case.package, "path": case.path, "argv": list(case.argv), "environment": CASE_ENVIRONMENT, "stateful": case.stateful, "requires_dt_relr": case.requires_dt_relr, "roots": roots, "comparison": comparison})
        if tree_sha256(payload, "finite application payload") != payload_seal:
            fail("finite application payload changed during private executions")
    except BaseException:
        # Preserve the root as a receipt/debug artifact even when a strict
        # boundary rejects the run.  It remains below the caller's .work.
        raise
    product_after = validate_product(dynamic_sysroot)
    if product_after != product_before:
        fail("supplied owned dynamic product changed during corpus execution")
    source_after = source_identity(manifest)
    if source_after != source_before:
        fail("native corpus source changed during execution")
    tools_after = apk_identity()
    if tools_after != tools_before:
        fail("pinned APK tools or key material changed during execution")
    inputs_after = input_identity(manifest, archive_dir, index)
    if inputs_after != inputs_before["identity"]:
        fail("signed APK index or archive source changed during execution")
    oracle_after = oracle_source_identity()
    if oracle_after != oracle_before:
        fail("pinned musl oracle source changed during execution")
    # Preserve the runtime-time hashes above. A stateful workload may change
    # its private tree; retention only adds host-readable permission bits
    # after all native checks and never changes the application or product.
    for outcome in outcomes:
        for side in ("oracle", "candidate"):
            outcome["roots"][side]["retention_modes"] = make_tree_readable(
                temporary_root / f"{outcome['id']}-{side}"
            )
    payload_retention_modes = make_tree_readable(payload)
    os.chmod(temporary_root, stat.S_IMODE(temporary_root.stat().st_mode) | 0o555)
    report_path = temporary_root / "report.json"
    return {"schema": SCHEMA, "source_mount": str(ROOT), "passed": all(item["comparison"]["passed"] for item in outcomes), "source": {"before": source_before, "after": source_after}, "tools": {"before": tools_before, "after": tools_after}, "inputs": {"verification_before": inputs_before, "after": inputs_after}, "oracle": {"before": oracle_before, "after": oracle_after}, "candidate_product": {"before": product_before, "after": product_after}, "application_payload": {"path": str(payload), "sha256": payload_seal, "retention_modes": payload_retention_modes, "package_library_dirs": list(manifest.package_library_dirs), "elf_closure": elf_graph}, "execution_root": str(temporary_root), "report_path": str(report_path), "case_count": len(outcomes), "outcomes": outcomes}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dynamic-sysroot", type=Path, required=True, help="existing owned dynamic product; never rebuilt")
    parser.add_argument("--archive-dir", type=Path, default=DEFAULT_INPUT, help="signed exact APK closure")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX, help="signed exact APK index")
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK, help="private per-campaign parent below checkout .work")
    parser.add_argument("--report", type=Path, help="additional fresh JSON copy below checkout .work")
    parser.add_argument("--quiet", action="store_true", help="write the retained report without duplicating it to stdout")
    parser.add_argument("--tier", action="append", choices=(*TIERS, "all"), default=None, help="select a frozen tier; omitted selects all")
    parser.add_argument("--case", action="append", default=[], help="select one frozen case within the requested tiers")
    arguments = parser.parse_args(argv)
    try:
        manifest = load_manifest()
        cases = select_cases(manifest, arguments.tier or ("all",), arguments.case)
        explicit_report = prepare_report_destination(arguments.report) if arguments.report is not None else None
        report = run(manifest, arguments.archive_dir, arguments.index, arguments.dynamic_sysroot, arguments.work, cases)
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        evidence = report.get("execution_root")
        if not isinstance(evidence, str):
            fail("native corpus run did not return its retained evidence directory")
        default_report = report.get("report_path")
        if not isinstance(default_report, str):
            fail("native corpus run did not return its retained report path")
        if Path(default_report) != Path(evidence) / "report.json":
            fail("native corpus default report is outside its retained evidence directory")
        destination = write_new_report(Path(default_report), encoded)
        if explicit_report is not None and explicit_report != destination:
            write_new_report(explicit_report, encoded)
        if not arguments.quiet:
            sys.stdout.write(encoded)
        print(f"owned package corpus evidence: {evidence}", file=sys.stderr)
        print(f"owned x86_64 package corpus: status: {'pass' if report['passed'] else 'fail'}", file=sys.stderr)
        print(f"owned x86_64 package corpus: report: {destination}", file=sys.stderr)
        return 0 if report["passed"] else 1
    except CorpusError as error:
        print(f"owned x86_64 package corpus: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
