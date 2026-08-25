#!/usr/bin/env python3
"""Validate and package an installed crabc application sysroot.

The build and release policy belongs to the callers.  This module owns the
small, reusable file-format boundary: an installed tree is checked against
its manifest, copied to a package staging tree with release provenance, and
written as a deterministic ``tar.xz`` archive.  It deliberately uses only
the Python standard library so a smoke runner can import it directly.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import re
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SYSROOT = ROOT / "target/crabc-sysroot"
DEFAULT_ARCHIVE = ROOT / "target/crabc-sysroot.tar.xz"
DEFAULT_DIST_DIRECTORY = ROOT / "dist"
DEFAULT_SMOKE_REPORT = ROOT / "compat/reports/sysroot-smoke/latest.json"
TARGET_TRIPLE = "aarch64-unknown-linux-musl"
CANONICAL_INTERPRETER = "/lib/ld-crabc-aarch64.so.1"
SCHEMA_VERSION = 1
ARCHIVE_ROOT = "crabc-sysroot"
DEFAULT_EPOCH = 0
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ARCHIVE_NAME_PATTERN = re.compile(r"^crabc-sysroot-aarch64-([0-9a-f]{12})\.tar\.xz$")
RELEASE_ASSET_NAME_PATTERN = re.compile(
    r"^crabc-sysroot-aarch64-[0-9a-f]{12}\.(?:tar\.xz(?:\.sha256)?|manifest\.json|smoke\.json)$"
)
EMBEDDED_BUILD_MARKERS = (
    b"/workspace/",
    b"/tmp/",
    b"/home/",
    b"/Users/",
    b"/root/",
    b"target/crabc-sysroot",
    b"crabc-sysroot-build-primary",
    b"crabc-sysroot-build-comparison",
)


class DistError(RuntimeError):
    """A violated distribution, archive, or installed-tree contract."""


def _load_sysroot_tool() -> Any:
    """Load the authoritative installed-sysroot helpers in both entry modes."""

    try:
        import crabc_sysroot

        return crabc_sysroot
    except ModuleNotFoundError:
        path = Path(__file__).with_name("crabc_sysroot.py")
        spec = importlib.util.spec_from_file_location("crabc_sysroot_for_dist", path)
        if spec is None or spec.loader is None:
            raise DistError(f"could not load installed-sysroot helper: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module


TOOL = _load_sysroot_tool()


@dataclasses.dataclass(frozen=True)
class SysrootInventory:
    """Validated source-tree paths and manifest for a package operation."""

    root: Path
    manifest: dict[str, object]
    regular_files: tuple[Path, ...]
    symlinks: tuple[Path, ...]


@dataclasses.dataclass(frozen=True)
class ArchiveMember:
    """A validated archive member with its archive-relative POSIX name."""

    info: tarfile.TarInfo
    name: PurePosixPath


@dataclasses.dataclass(frozen=True)
class SourceIdentity:
    """The immutable Git commit identity bound into a distribution archive."""

    commit: str
    epoch: int


def _uname(argument: str) -> str:
    """Read one native-kernel identity field without inheriting a shell."""

    try:
        completed = subprocess.run(
            ["uname", argument],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise DistError(f"could not invoke uname {argument}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise DistError(f"uname {argument} failed: {detail or completed.returncode}")
    return completed.stdout.decode("utf-8", errors="replace").strip()


def require_native_aarch64() -> None:
    """Assert the container's native Linux/AArch64 kernel identity exactly."""

    system = _uname("-s")
    machine = _uname("-m")
    if system != "Linux" or machine != "aarch64":
        raise DistError(
            "sysroot distribution requires native Linux AArch64 "
            f"(uname -s={system!r}, uname -m={machine!r})"
        )


def _relative_parts(value: str, description: str) -> PurePosixPath:
    if not value or "\x00" in value:
        raise DistError(f"{description} is empty or contains NUL: {value!r}")
    if value.startswith("/"):
        raise DistError(f"{description} is absolute: {value!r}")
    path = PurePosixPath(value)
    if path == PurePosixPath(".") or any(part in ("", ".", "..") for part in path.parts):
        raise DistError(f"{description} is not a clean relative path: {value!r}")
    return path


def _inside_link(parent: PurePosixPath, target: str) -> PurePosixPath:
    if not target or "\x00" in target or target.startswith("/"):
        raise DistError(f"symlink target is absolute or invalid: {target!r}")
    stack = list(parent.parts)
    for part in PurePosixPath(target).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise DistError(f"symlink target escapes its tree: {target!r}")
            stack.pop()
        else:
            stack.append(part)
    return PurePosixPath(*stack)


def _path_in_root(root: Path, relative: PurePosixPath) -> Path:
    candidate = root.joinpath(*relative.parts)
    try:
        candidate.resolve(strict=False).relative_to(root.resolve())
    except ValueError as error:
        raise DistError(f"path escapes sysroot: {relative}") from error
    return candidate


def _require_path(path: Path, description: str, *, directory: bool = False) -> None:
    if path.is_symlink():
        raise DistError(f"{description} must not be a symlink: {path}")
    if directory:
        if not path.is_dir():
            raise DistError(f"{description} must be a directory: {path}")
    elif not path.is_file():
        raise DistError(f"{description} must be a regular file: {path}")


def _validate_symlinks(root: Path, symlinks: Iterable[Path]) -> None:
    for path in symlinks:
        relative = PurePosixPath(path.relative_to(root).as_posix())
        target = os.readlink(path)
        resolved = _inside_link(relative.parent, target)
        if not resolved.parts:
            raise DistError(f"symlink resolves to the sysroot root: {path}")
        _path_in_root(root, resolved)


def _archive_root_from_name(archive: Path) -> tuple[str, str]:
    """Return the required archive root and embedded short commit identity."""

    match = ARCHIVE_NAME_PATTERN.fullmatch(archive.name)
    if match is None:
        raise DistError(
            "archive name must be crabc-sysroot-aarch64-<12-lowercase-hex>.tar.xz: "
            f"{archive.name}"
        )
    return archive.name.removesuffix(".tar.xz"), match.group(1)


def _top_level_archive_root(value: str) -> PurePosixPath:
    root = _relative_parts(value, "archive root")
    if len(root.parts) != 1:
        raise DistError(f"archive root must name one top-level directory: {value!r}")
    return root


def load_manifest(path: Path) -> dict[str, object]:
    """Load and validate the authoritative installed manifest identity."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (DistError, OSError, json.JSONDecodeError) as error:
        raise DistError(f"invalid sysroot manifest: {path}") from error
    if not isinstance(value, dict):
        raise DistError("sysroot manifest must be a JSON object")
    if value.get("schema") != SCHEMA_VERSION:
        raise DistError(f"sysroot manifest must use schema {SCHEMA_VERSION}")
    if value.get("target") != TARGET_TRIPLE or value.get("canonical_interpreter") != CANONICAL_INTERPRETER:
        raise DistError("sysroot manifest does not identify the crabc AArch64 sysroot")
    platform_value = value.get("platform")
    if not isinstance(platform_value, dict) or platform_value != {
        "os": "linux",
        "architecture": "aarch64",
        "endianness": "little",
        "kernel_minimum": "5.10",
    }:
        raise DistError("sysroot manifest has an invalid Linux/AArch64 platform contract")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_sysroot(sysroot: Path) -> SysrootInventory:
    """Validate layout, manifest artifacts, and all symlink boundaries."""

    source = sysroot.expanduser()
    if source.is_symlink():
        raise DistError(f"sysroot must be a real directory: {sysroot}")
    root = source.resolve()
    if not root.is_dir():
        raise DistError(f"sysroot must be a real directory: {sysroot}")
    manifest_path = root / "share/crabc/manifest.json"
    manifest = load_manifest(manifest_path)
    _require_path(root / "bin/crabc-cc", "compiler wrapper")
    _require_path(root / "share/crabc/purity.json", "purity record")
    _require_path(root / "share/crabc/crabc_sysroot.py", "installed driver module")
    _require_path(root / "usr/include", "public include tree", directory=True)

    runtime_paths = TOOL.installed_runtime_paths(root)
    for name, path in runtime_paths.items():
        _require_path(path, f"runtime artifact {name}")
    loader_alias = root / "lib/ld-musl-aarch64.so.1"
    if not loader_alias.is_symlink() or os.readlink(loader_alias) != "ld-crabc-aarch64.so.1":
        raise DistError("compatibility loader alias is not the required relative symlink")
    for name in ("libm.so", "libdl.so", "libpthread.so", "librt.so", "libutil.so"):
        alias = root / "usr/lib" / name
        if not alias.is_symlink() or os.readlink(alias) != "libc.so":
            raise DistError(f"runtime alias is not the required libc symlink: {name}")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise DistError("sysroot manifest has no artifacts table")
    for name, record in artifacts.items():
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("path"), str)
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"]))
        ):
            raise DistError(f"manifest artifact has no relative path: {name}")
        artifact = _path_in_root(root, _relative_parts(str(record["path"]), f"artifact {name}"))
        if not artifact.is_file() and not artifact.is_symlink():
            raise DistError(f"manifest artifact is absent: {artifact}")
        if sha256_file(artifact) != record["sha256"]:
            raise DistError(f"manifest artifact hash does not match: {artifact}")
        if artifact.suffix in {".a", ".o", ".so"} or artifact.parent.name == "lib":
            data = artifact.read_bytes()
            if any(marker in data for marker in EMBEDDED_BUILD_MARKERS):
                raise DistError(f"runtime artifact contains an embedded build path: {artifact}")

    regular_files: list[Path] = []
    symlinks: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            symlinks.append(path)
        elif path.is_file():
            regular_files.append(path)
        elif not path.is_dir():
            raise DistError(f"unsupported special file in sysroot: {path}")
    _validate_symlinks(root, symlinks)
    return SysrootInventory(root, manifest, tuple(regular_files), tuple(symlinks))


def validate_packaged_tree(sysroot: Path, *, expected_source_commit: str) -> SysrootInventory:
    """Validate a staged/package tree and require its release source commit."""

    if not SOURCE_COMMIT_PATTERN.fullmatch(expected_source_commit):
        raise DistError("expected_source_commit must be exactly 40 hexadecimal characters")
    inventory = validate_sysroot(sysroot)
    observed = inventory.manifest.get("source_commit")
    if observed != expected_source_commit:
        raise DistError(f"packaged manifest source_commit mismatch: {observed!r}")
    return inventory


def _set_tree_epoch(root: Path, epoch: int) -> None:
    if epoch < 0:
        raise DistError("archive epoch must be non-negative")
    for path in sorted(root.rglob("*"), reverse=True):
        try:
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        except OSError as error:
            raise DistError(f"could not normalize staging timestamp: {path}") from error
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def stage_sysroot(source: Path, destination: Path, *, source_commit: str, epoch: int = DEFAULT_EPOCH) -> Path:
    """Copy a validated sysroot and inject release provenance only in the copy."""

    if not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise DistError("source_commit must be exactly 40 hexadecimal characters")
    inventory = validate_sysroot(source)
    destination_input = destination.expanduser()
    if destination_input.exists() or destination_input.is_symlink():
        raise DistError(f"staging destination already exists: {destination}")
    target = destination_input.resolve()
    if target == inventory.root or target.is_relative_to(inventory.root):
        raise DistError("staging destination must not be inside the source sysroot")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(inventory.root, target, symlinks=True)
        package_manifest_path = target / "share/crabc/manifest.json"
        package_manifest = load_manifest(package_manifest_path)
        package_manifest["source_commit"] = source_commit
        package_manifest_path.write_text(
            json.dumps(package_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        _set_tree_epoch(target, epoch)
    except (DistError, OSError, json.JSONDecodeError) as error:
        shutil.rmtree(target, ignore_errors=True)
        raise DistError(f"could not stage sysroot: {target}") from error
    return target


def _tar_info(path: Path, name: str, *, epoch: int) -> tuple[tarfile.TarInfo, BinaryIO | None]:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    if path.is_symlink():
        # Linux ignores symlink modes.  Normalize them anyway so the archive
        # cannot inherit metadata quirks from the staging filesystem.
        info.mode = 0o777
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
        return info, None
    if path.is_dir():
        info.mode = 0o755
        info.type = tarfile.DIRTYPE
        return info, None
    if path.is_file():
        info.mode = 0o755 if stat.S_IMODE(path.lstat().st_mode) & 0o111 else 0o644
        info.type = tarfile.REGTYPE
        info.size = path.stat().st_size
        return info, path.open("rb")
    raise DistError(f"unsupported special file in archive source: {path}")


def create_deterministic_archive(
    source: Path,
    archive: Path,
    *,
    archive_root: str = ARCHIVE_ROOT,
    epoch: int = DEFAULT_EPOCH,
) -> Path:
    """Write a byte-stable tar.xz archive of a validated sysroot tree."""

    if epoch < 0:
        raise DistError("archive epoch must be non-negative")
    root_name = _top_level_archive_root(archive_root)
    inventory = validate_sysroot(source)
    output_input = archive.expanduser()
    if output_input.is_symlink():
        raise DistError(f"archive output must not be a symlink: {archive}")
    output = output_input.resolve()
    if output == inventory.root or output.is_relative_to(inventory.root):
        raise DistError("archive output must not be inside the source sysroot")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise DistError(f"refusing to replace unexpected archive temporary: {temporary}")
    try:
        with tarfile.open(temporary, mode="w:xz", format=tarfile.PAX_FORMAT, preset=9) as stream:
            paths = [inventory.root, *sorted(inventory.root.rglob("*"))]
            for path in paths:
                relative = PurePosixPath(path.relative_to(inventory.root).as_posix()) if path != inventory.root else PurePosixPath()
                name = root_name.as_posix() if not relative.parts else f"{root_name.as_posix()}/{relative.as_posix()}"
                info, handle = _tar_info(path, name, epoch=epoch)
                try:
                    stream.addfile(info, handle)
                finally:
                    if handle is not None:
                        handle.close()
        os.replace(temporary, output)
    except (DistError, OSError, tarfile.TarError) as error:
        if temporary.is_file() or temporary.is_symlink():
            temporary.unlink(missing_ok=True)
        raise DistError(f"could not create deterministic archive: {output}") from error
    return output


def _validated_members(stream: tarfile.TarFile, archive_root: str) -> tuple[ArchiveMember, ...]:
    root = _top_level_archive_root(archive_root)
    members: list[ArchiveMember] = []
    names: set[PurePosixPath] = set()
    symlinks: set[PurePosixPath] = set()
    for info in stream.getmembers():
        relative = _relative_parts(info.name, "archive member")
        if relative != root and (not relative.parts or relative.parts[: len(root.parts)] != root.parts):
            raise DistError(f"archive member is outside expected root: {info.name!r}")
        if relative in names:
            raise DistError(f"archive contains duplicate member: {info.name!r}")
        names.add(relative)
        if info.islnk() or info.isdev() or info.isfifo() or info.ischr() or info.isblk():
            raise DistError(f"archive contains unsupported link/device member: {info.name!r}")
        if not (info.isdir() or info.isreg() or info.issym()):
            raise DistError(f"archive contains unsupported member type: {info.name!r}")
        mode = stat.S_IMODE(info.mode)
        if info.isdir() and mode != 0o755:
            raise DistError(f"archive directory does not use normalized 0755 mode: {info.name!r}")
        if info.isreg() and mode not in {0o644, 0o755}:
            raise DistError(f"archive regular file has an unsupported normalized mode: {info.name!r}")
        if info.issym() and mode != 0o777:
            raise DistError(f"archive symlink does not use normalized 0777 mode: {info.name!r}")
        if info.issym():
            target = _inside_link(relative.parent, info.linkname)
            if not target.parts:
                raise DistError(f"archive symlink resolves outside its root: {info.name!r}")
            symlinks.add(relative)
        members.append(ArchiveMember(info, relative))
    if root not in names or not next(item.info.isdir() for item in members if item.name == root):
        raise DistError("archive has no expected root directory")
    directories = {item.name for item in members if item.info.isdir()}
    for item in members:
        if item.name != root and item.name.parent not in directories:
            raise DistError(f"archive member has no explicit directory parent: {item.info.name!r}")
    for item in members:
        if any(parent in symlinks for parent in item.name.parents):
            raise DistError(f"archive member traverses a symlink directory: {item.info.name!r}")
    return tuple(members)


def validate_archive(archive: Path, *, archive_root: str = ARCHIVE_ROOT) -> tuple[ArchiveMember, ...]:
    """Prevalidate every tar member without writing to the filesystem."""

    try:
        with tarfile.open(archive, mode="r:xz", errorlevel=2) as stream:
            return _validated_members(stream, archive_root)
    except (DistError, OSError, tarfile.TarError) as error:
        raise DistError(f"invalid tar.xz archive: {archive}") from error


def safe_extract_archive(archive: Path, destination: Path, *, archive_root: str = ARCHIVE_ROOT) -> Path:
    """Extract a prevalidated archive without following archive-controlled links."""

    # Validate and reopen: TarInfo objects belong to their TarFile stream.
    validate_archive(archive, archive_root=archive_root)
    destination_input = destination.expanduser()
    if destination_input.exists() or destination_input.is_symlink():
        raise DistError(f"extraction destination already exists: {destination}")
    target = destination_input.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    root = _top_level_archive_root(archive_root)
    try:
        with tarfile.open(archive, mode="r:xz", errorlevel=2) as stream:
            members = _validated_members(stream, archive_root)
            target.mkdir(mode=0o755)
            root_member = next(item for item in members if item.name == root)
            extracted_root = target / root.as_posix()
            extracted_root.mkdir(mode=stat.S_IMODE(root_member.info.mode))
            os.chmod(extracted_root, stat.S_IMODE(root_member.info.mode))
            for item in sorted(members, key=lambda value: (len(value.name.parts), value.name.as_posix())):
                if item.name == root:
                    continue
                path = target.joinpath(*item.name.parts)
                if item.info.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                    os.chmod(path, stat.S_IMODE(item.info.mode))
                elif item.info.issym():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.symlink_to(item.info.linkname)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    source = stream.extractfile(item.info)
                    if source is None:
                        raise DistError(f"could not read archive member: {item.info.name}")
                    with source, path.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    os.chmod(path, stat.S_IMODE(item.info.mode))
    except (DistError, OSError, tarfile.TarError) as error:
        shutil.rmtree(target, ignore_errors=True)
        raise DistError(f"could not safely extract archive: {archive}") from error
    return target / root.as_posix()


def _git_output(arguments: list[str]) -> str:
    """Run a narrow Git query against the mounted source checkout."""

    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise DistError(
            f"Git query failed ({completed.returncode}): git {' '.join(arguments)}\n"
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed.stdout.decode("utf-8", errors="strict").strip()


def source_identity(*, allow_dirty: bool) -> SourceIdentity:
    """Read the immutable commit and timestamp used for a release snapshot."""

    commit = _git_output(["rev-parse", "--verify", "HEAD"])
    if not SOURCE_COMMIT_PATTERN.fullmatch(commit):
        raise DistError(f"Git did not return a full lowercase commit SHA: {commit!r}")
    timestamp_text = _git_output(["show", "-s", "--format=%ct", "HEAD"])
    try:
        epoch = int(timestamp_text)
    except ValueError as error:
        raise DistError(f"Git did not return a numeric commit timestamp: {timestamp_text!r}") from error
    if epoch < 0:
        raise DistError(f"Git returned a negative commit timestamp: {epoch}")
    if not allow_dirty:
        dirty = _git_output(["status", "--porcelain=v1", "--untracked-files=normal"])
        if dirty:
            raise DistError(
                "refusing to label a dirty source tree as an immutable commit snapshot; "
                "commit or discard the changes before running sysroot-dist"
            )
    return SourceIdentity(commit=commit, epoch=epoch)


def _run_checked(command: list[str], *, description: str, quiet_success: bool = False) -> None:
    """Run a local release subcommand and retain useful failure context."""

    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL if quiet_success else subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.stdout:
        sys.stdout.buffer.write(completed.stdout)
    if completed.stderr:
        sys.stderr.buffer.write(completed.stderr)
    if completed.returncode != 0:
        raise DistError(f"{description} failed with exit status {completed.returncode}")


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write one release sidecar without exposing a partial file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise DistError(f"refusing to replace unexpected temporary output: {temporary}")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise DistError(f"could not write release sidecar: {path}") from error


def _load_json_object(path: Path, description: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DistError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        raise DistError(f"{description} must be a JSON object: {path}")
    return value


def _validate_smoke_report(report_path: Path, identity: SourceIdentity, archive: Path) -> dict[str, object]:
    report = _load_json_object(report_path, "sysroot smoke report")
    archive_record = report.get("archive")
    if (
        report.get("schema") != 1
        or report.get("passed") is not True
        or report.get("target") != "aarch64"
        or report.get("source_commit") != identity.commit
        or not isinstance(archive_record, dict)
        or archive_record.get("name") != archive.name
        or archive_record.get("sha256") != sha256_file(archive)
        or not isinstance(report.get("tests"), dict)
    ):
        raise DistError("sysroot smoke report does not attest to the exact packaged archive")
    return report


def _extract_packaged_manifest(archive: Path, archive_root: str, identity: SourceIdentity) -> bytes:
    """Safely obtain the exact manifest bytes stored in a release archive."""

    with tempfile.TemporaryDirectory(prefix="crabc-sysroot-dist-extract-", dir="/tmp") as temporary:
        extracted = safe_extract_archive(archive, Path(temporary) / "archive", archive_root=archive_root)
        validate_packaged_tree(extracted, expected_source_commit=identity.commit)
        manifest = extracted / "share/crabc/manifest.json"
        if not manifest.is_file() or manifest.is_symlink():
            raise DistError("packaged sysroot has no regular manifest")
        return manifest.read_bytes()


def _copy_release_assets(assets: Iterable[Path], destination: Path) -> None:
    """Publish only one tested snapshot into the command-owned dist directory.

    ``dist/`` is a generated command boundary rather than a release cache. A
    fresh invocation must leave exactly its four snapshot assets there, so
    stale files with the precise generated naming scheme are removed only
    after the new, smoke-tested copies are in place.  Any other user-created
    entry is a hard error and is never removed implicitly.
    """

    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise DistError(f"distribution output is not a real directory: {destination}")
    selected = tuple(assets)
    if not selected:
        raise DistError("distribution has no final release assets to copy")
    names = [asset.name for asset in selected]
    if len(set(names)) != len(names):
        raise DistError("distribution final assets have duplicate names")
    for asset in selected:
        if not asset.is_file() or asset.is_symlink():
            raise DistError(f"release asset is not a regular file: {asset}")
        if not RELEASE_ASSET_NAME_PATTERN.fullmatch(asset.name):
            raise DistError(f"release asset has an invalid generated name: {asset.name}")

    destination.mkdir(parents=True, exist_ok=True)
    selected_names = set(names)
    stale: list[Path] = []
    unexpected: list[Path] = []
    for existing in destination.iterdir():
        if existing.name in selected_names:
            if existing.is_symlink() or not existing.is_file():
                raise DistError(f"refusing to replace non-file distribution output: {existing}")
            continue
        if existing.is_symlink() or not existing.is_file() or not RELEASE_ASSET_NAME_PATTERN.fullmatch(existing.name):
            unexpected.append(existing)
        else:
            stale.append(existing)
    if unexpected:
        labels = ", ".join(str(item) for item in sorted(unexpected))
        raise DistError(
            "distribution output contains unrelated entries; refusing to remove them: "
            f"{labels}"
        )

    for asset in selected:
        output = destination / asset.name
        temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise DistError(f"refusing to replace unexpected distribution temporary: {temporary}")
        try:
            shutil.copy2(asset, temporary)
            os.replace(temporary, output)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise DistError(f"could not copy release asset into distribution output: {output}") from error
    for existing in stale:
        existing.unlink()


def _run_smoke(archive: Path, identity: SourceIdentity, report: Path, timeout: float) -> dict[str, object]:
    command = [
        sys.executable,
        str(ROOT / "compat/sysroot-smoke/run.py"),
        "--archive",
        str(archive),
        "--source-commit",
        identity.commit,
        "--report",
        str(report),
        "--timeout",
        str(timeout),
    ]
    _run_checked(command, description="packaged-sysroot smoke")
    return _validate_smoke_report(report, identity, archive)


def run_distribution(*, timeout: float, allow_dirty: bool, dist_directory: Path = DEFAULT_DIST_DIRECTORY) -> dict[str, object]:
    """Build, package twice, smoke the exact archive, then publish four files."""

    if not 0 < timeout <= 300:
        raise DistError("distribution timeout must be > 0 and <= 300")
    require_native_aarch64()
    identity = source_identity(allow_dirty=allow_dirty)
    _run_checked(
        [sys.executable, "scripts/build_owned_sysroot.py", "--timeout", str(timeout)],
        description="owned sysroot exporter",
        quiet_success=True,
    )
    source = DEFAULT_SYSROOT
    inventory = validate_sysroot(source)
    del inventory
    short_commit = identity.commit[:12]
    archive_name = f"crabc-sysroot-aarch64-{short_commit}.tar.xz"
    archive_root, observed_short_commit = _archive_root_from_name(Path(archive_name))
    if observed_short_commit != short_commit:
        raise AssertionError("release archive short commit construction drifted")

    # Everything through the four final copy operations lives on the Linux
    # container filesystem.  The macOS bind mount is deliberately touched only
    # after the archive has passed both deterministic packaging and extraction
    # smoke contracts.
    with tempfile.TemporaryDirectory(prefix="crabc-sysroot-dist-", dir="/tmp") as temporary:
        work = Path(temporary)
        staged = stage_sysroot(source, work / "staged", source_commit=identity.commit, epoch=identity.epoch)
        validate_packaged_tree(staged, expected_source_commit=identity.commit)
        archive = work / archive_name
        comparison_archive = work / f"comparison-{archive_name}"
        create_deterministic_archive(staged, archive, archive_root=archive_root, epoch=identity.epoch)
        create_deterministic_archive(staged, comparison_archive, archive_root=archive_root, epoch=identity.epoch)
        archive_hash = sha256_file(archive)
        if archive_hash != sha256_file(comparison_archive):
            raise DistError("two package operations for the same commit produced different archive bytes")
        validate_archive(archive, archive_root=archive_root)
        manifest_asset = work / f"crabc-sysroot-aarch64-{short_commit}.manifest.json"
        _atomic_write_bytes(manifest_asset, _extract_packaged_manifest(archive, archive_root, identity))
        checksum_asset = work / f"{archive_name}.sha256"
        _atomic_write_bytes(checksum_asset, f"{archive_hash}  {archive_name}\n".encode("ascii"))
        smoke_asset = work / f"crabc-sysroot-aarch64-{short_commit}.smoke.json"
        smoke = _run_smoke(archive, identity, smoke_asset, timeout)
        if sha256_file(archive) != archive_hash:
            raise DistError("archive changed after it was smoke-tested")
        assets = (archive, checksum_asset, manifest_asset, smoke_asset)
        _copy_release_assets(assets, dist_directory.expanduser().resolve())

    return {
        "schema": 1,
        "source_commit": identity.commit,
        "source_date_epoch": identity.epoch,
        "archive": {
            "name": archive_name,
            "sha256": archive_hash,
            "deterministic_second_hash": archive_hash,
        },
        "smoke": {"passed": smoke.get("passed") is True, "report": f"crabc-sysroot-aarch64-{short_commit}.smoke.json"},
        "dist_directory": str(dist_directory.expanduser().resolve()),
    }


def run_smoke_archive(*, archive: Path, report: Path, timeout: float) -> dict[str, object]:
    """Rerun the extracted-archive smoke against an existing release asset."""

    if not 0 < timeout <= 300:
        raise DistError("smoke timeout must be > 0 and <= 300")
    require_native_aarch64()
    archive = archive.expanduser().resolve()
    if not archive.is_file() or archive.is_symlink():
        raise DistError(f"archive is not a regular file: {archive}")
    archive_root, short_commit = _archive_root_from_name(archive)
    with tempfile.TemporaryDirectory(prefix="crabc-sysroot-smoke-identity-", dir="/tmp") as temporary:
        extracted = safe_extract_archive(archive, Path(temporary) / "archive", archive_root=archive_root)
        manifest = load_manifest(extracted / "share/crabc/manifest.json")
        source_commit = manifest.get("source_commit")
        if not isinstance(source_commit, str) or not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
            raise DistError("archive manifest has no full lowercase source_commit")
        if source_commit[:12] != short_commit:
            raise DistError("archive filename does not match its manifest source_commit")
        identity = SourceIdentity(source_commit, 0)
        validate_packaged_tree(extracted, expected_source_commit=identity.commit)
    smoke = _run_smoke(archive, identity, report.expanduser().resolve(), timeout)
    return {
        "schema": 1,
        "source_commit": identity.commit,
        "archive": {"name": archive.name, "sha256": sha256_file(archive)},
        "smoke": {"passed": smoke.get("passed") is True, "report": str(report.expanduser().resolve())},
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    distribution = subcommands.add_parser("dist", help="build and smoke-test a deterministic commit snapshot")
    distribution.add_argument("--timeout", type=float, default=120.0)
    distribution.add_argument(
        "--allow-dirty",
        action="store_true",
        help="diagnostic-only: permit a dirty checkout while testing this release path",
    )
    smoke = subcommands.add_parser("smoke", help="smoke-test an existing sysroot archive without rebuilding")
    smoke.add_argument("--archive", type=Path, required=True)
    smoke.add_argument("--report", type=Path, default=DEFAULT_SMOKE_REPORT)
    smoke.add_argument("--timeout", type=float, default=60.0)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "dist":
            result = run_distribution(timeout=args.timeout, allow_dirty=args.allow_dirty)
        elif args.command == "smoke":
            result = run_smoke_archive(archive=args.archive, report=args.report, timeout=args.timeout)
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except DistError as error:
        print(f"crabc-sysroot-dist: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = [
    "ARCHIVE_ROOT",
    "ARCHIVE_NAME_PATTERN",
    "DEFAULT_ARCHIVE",
    "DEFAULT_DIST_DIRECTORY",
    "DEFAULT_EPOCH",
    "DEFAULT_SMOKE_REPORT",
    "DEFAULT_SYSROOT",
    "DistError",
    "SourceIdentity",
    "SysrootInventory",
    "create_deterministic_archive",
    "load_manifest",
    "main",
    "parse_args",
    "require_native_aarch64",
    "run_distribution",
    "run_smoke_archive",
    "safe_extract_archive",
    "source_identity",
    "stage_sysroot",
    "validate_archive",
    "validate_packaged_tree",
    "validate_sysroot",
]


if __name__ == "__main__":
    raise SystemExit(main())
