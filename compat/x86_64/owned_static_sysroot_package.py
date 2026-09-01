#!/usr/bin/env python3
"""Deterministic, regular-file-only packaging for the private static sysroot.

This is deliberately narrower than the AArch64 distribution tooling.  It
packages an already-built x86 owned-static sysroot only for the local consumer
gate's extracted-tree smoke.  It accepts no symlinks, links, device nodes, or
path traversal, and normalizes tar metadata so two archives of the same tree
are byte-identical.

Extraction is deliberately bounded before it creates its private staging tree:
at most ``MAX_ARCHIVE_MEMBER_COUNT`` members, no individual regular member
larger than ``MAX_ARCHIVE_MEMBER_BYTES``, and no aggregate regular payload
larger than ``MAX_ARCHIVE_TOTAL_BYTES``.  The fixed Linux/x86-64 5.10 baseline
supplies ``renameat2(RENAME_NOREPLACE)`` for the final no-replace publication
of both files and directories; no replacement fallback is admitted.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping


PACKAGE_FORMAT = "crabc-x86-64-owned-static-sysroot-package/v1"
ARCHIVE_ROOT = "crabc-x86_64-owned-static-sysroot"
SYSROOT_FORMAT = "crabc-x86-64-owned-static-sysroot-v1"
TARGET = "x86_64-unknown-linux-musl"
DRIVER_FORMAT = "crabc-x86-64-sealed-static-driver-v1"
MANIFEST_RELATIVE_PATH = Path("share/crabc/manifest.json")
REQUIRED_CRT_OBJECTS = (
    "usr/lib/crt1.o",
    "usr/lib/Scrt1.o",
    "usr/lib/rcrt1.o",
    "usr/lib/crti.o",
    "usr/lib/crtn.o",
)
REQUIRED_INSTALLED_PATHS = (
    "bin/crabc-cc",
    "usr/lib/libc.a",
    "usr/lib/libcrabc-builtins.a",
    *REQUIRED_CRT_OBJECTS,
)
LINUX_X86_64_SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_NOREPLACE = 1
MAX_ARCHIVE_MEMBER_COUNT = 4096
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024


class PackageError(RuntimeError):
    """The private package boundary would contain an unsafe filesystem entry."""


def require_regular_file(path: Path, description: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"{description} is missing or unsafe: {path}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reject_existing_symlink_components(path: Path, description: str) -> None:
    """Reject a lexical path which enters an existing symlinked directory."""

    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise PackageError(f"{description} traverses an existing symlink: {path}")


def require_safe_directory(path: Path, description: str) -> Path:
    """Resolve an existing directory only after checking its lexical ancestry."""

    reject_existing_symlink_components(path, description)
    if not path.is_dir() or path.is_symlink():
        raise PackageError(f"{description} is missing or unsafe: {path}")
    return path.resolve()


def prospective_path(path: Path, description: str) -> Path:
    """Resolve a prospective path after rejecting lexical symlink traversal."""

    reject_existing_symlink_components(path, description)
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise PackageError(f"{description} is unsafe: {path}") from error


def is_within(directory: Path, path: Path) -> bool:
    """Whether two already-resolved paths name the same directory tree."""

    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def publish_noreplace(staged: Path, destination: Path, description: str) -> None:
    """Atomically publish one same-parent staged file or directory without replacement.

    This package is Linux/x86-64-only.  Linux 5.10 x86-64 fixes
    ``renameat2=316`` and ``RENAME_NOREPLACE=1``; unlike ``os.replace`` this
    operation returns ``EEXIST`` when a competing publisher has claimed the
    final pathname.  There is intentionally no replacement or non-atomic
    fallback because it would weaken the extracted-artifact contract.
    """

    system = os.uname()
    if system.sysname != "Linux" or system.machine not in {"x86_64", "amd64"}:
        raise PackageError("atomic package publication requires Linux/x86-64 renameat2")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
    except (AttributeError, OSError) as error:
        raise PackageError("atomic package publication cannot access Linux renameat2") from error
    syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = syscall(
        ctypes.c_long(LINUX_X86_64_SYS_RENAMEAT2),
        ctypes.c_long(AT_FDCWD),
        ctypes.c_char_p(os.fsencode(staged)),
        ctypes.c_long(AT_FDCWD),
        ctypes.c_char_p(os.fsencode(destination)),
        ctypes.c_long(RENAME_NOREPLACE),
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise PackageError(f"{description} already exists: {destination}")
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise PackageError(
            "atomic package publication requires Linux renameat2 RENAME_NOREPLACE"
        )
    detail = os.strerror(error_number) if error_number else "unknown error"
    raise PackageError(f"cannot atomically publish {description}: {detail}")


def relative_payload_path(value: str, description: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageError(f"{description} has an unsafe relative path: {value}")
    return path.as_posix()


def manifest_payload_hashes(manifest: object) -> dict[str, str]:
    """Validate the installed static-sysroot identity and return its file hashes."""

    if not isinstance(manifest, Mapping):
        raise PackageError("installed manifest is not an object")
    if manifest.get("format") != SYSROOT_FORMAT or manifest.get("target") != TARGET:
        raise PackageError("installed manifest does not identify the x86 owned static sysroot")
    package = manifest.get("package")
    if package != {"format": PACKAGE_FORMAT, "archive_root": ARCHIVE_ROOT}:
        raise PackageError("installed manifest private package contract drifted")
    installed = manifest.get("installed")
    if not isinstance(installed, Mapping):
        raise PackageError("installed manifest lacks its installed-file record")
    expected_installed = {
        "headers": "usr/include",
        "crt_objects": list(REQUIRED_CRT_OBJECTS),
        "static_libc": "usr/lib/libc.a",
        "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
        "sealed_static_driver": "bin/crabc-cc",
    }
    for key, expected in expected_installed.items():
        if installed.get(key) != expected:
            raise PackageError(f"installed manifest {key} record drifted")
    driver = manifest.get("sealed_static_driver")
    if not isinstance(driver, Mapping) or driver.get("format") != DRIVER_FORMAT:
        raise PackageError("installed manifest sealed static driver record drifted")
    if driver.get("path") != "bin/crabc-cc":
        raise PackageError("installed manifest sealed static driver path drifted")
    files = installed.get("files")
    if not isinstance(files, Mapping) or not files:
        raise PackageError("installed manifest lacks payload hashes")
    result: dict[str, str] = {}
    for relative, expected_hash in files.items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            raise PackageError("installed manifest has an invalid payload hash record")
        normalized = relative_payload_path(relative, "installed manifest")
        if normalized in result or len(expected_hash) != 64 or any(
            character not in "0123456789abcdef" for character in expected_hash
        ):
            raise PackageError(f"installed manifest has an invalid payload hash: {relative}")
        result[normalized] = expected_hash
    missing_required = sorted(set(REQUIRED_INSTALLED_PATHS) - set(result))
    if missing_required:
        raise PackageError(
            "installed manifest omits required static payload: " + ", ".join(missing_required)
        )
    return result


def normalized_mode(path: Path) -> int:
    return 0o755 if path.stat().st_mode & 0o111 else 0o644


def source_entries(source: Path) -> list[tuple[Path, Path]]:
    """Return sorted, symlink-free directories and regular files below source."""

    source = require_safe_directory(source, "source tree")
    entries: list[tuple[Path, Path]] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise PackageError(f"source tree contains a symlink: {relative}")
        mode = path.stat().st_mode
        if stat.S_ISDIR(mode) or stat.S_ISREG(mode):
            entries.append((relative, path))
        else:
            raise PackageError(f"source tree contains a non-regular entry: {relative}")
    return entries


def validate_installed_tree(source: Path, entries: list[tuple[Path, Path]]) -> None:
    """Require a package source to be exactly the manifest-bound static tree."""

    regular_files = {
        relative.as_posix(): path for relative, path in entries if path.is_file()
    }
    manifest_key = MANIFEST_RELATIVE_PATH.as_posix()
    manifest_path = regular_files.get(manifest_key)
    if manifest_path is None:
        raise PackageError("source tree lacks the installed manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackageError("source tree installed manifest is unreadable") from error
    expected_hashes = manifest_payload_hashes(manifest)
    observed = set(regular_files) - {manifest_key}
    expected = set(expected_hashes)
    undeclared = sorted(observed - expected)
    if undeclared:
        raise PackageError(f"source tree has an undeclared installed regular file: {undeclared[0]}")
    missing = sorted(expected - observed)
    if missing:
        raise PackageError(f"source tree is missing a manifest payload file: {missing[0]}")
    for relative, expected_hash in expected_hashes.items():
        if sha256_file(regular_files[relative]) != expected_hash:
            raise PackageError(f"source tree payload hash mismatch: {relative}")
    header_root = source / "usr" / "include"
    if not header_root.is_dir() or header_root.is_symlink():
        raise PackageError("source tree has no safe installed header directory")
    for relative in REQUIRED_INSTALLED_PATHS:
        require_regular_file(source / relative, f"source tree required payload {relative}")


def archive_member(relative: Path) -> str:
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise PackageError(f"source tree has an unsafe relative path: {relative}")
    return f"{ARCHIVE_ROOT}/{relative.as_posix()}"


def deterministic_info(name: str, *, directory: bool, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def create_archive(source: Path, archive: Path) -> None:
    """Create an xz tar archive with deterministic metadata and ordering."""

    source = require_safe_directory(source, "source tree")
    archive = prospective_path(archive, "archive destination")
    if is_within(source, archive):
        raise PackageError(f"archive destination is inside the source tree: {archive}")
    if archive.exists() or archive.is_symlink():
        raise PackageError(f"archive destination already exists or is unsafe: {archive}")
    parent = require_safe_directory(archive.parent, "archive parent")
    archive = parent / archive.name
    entries = source_entries(source)
    validate_installed_tree(source, entries)
    staged_archive: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".crabc-x86-static-package.", suffix=".tar.xz", dir=parent, delete=False
        ) as temporary:
            staged_archive = Path(temporary.name)
        with tarfile.open(staged_archive, "w:xz") as output:
            output.addfile(deterministic_info(ARCHIVE_ROOT, directory=True, mode=0o755))
            for relative, path in entries:
                name = archive_member(relative)
                if path.is_dir():
                    output.addfile(deterministic_info(name, directory=True, mode=0o755))
                else:
                    info = deterministic_info(name, directory=False, mode=normalized_mode(path))
                    info.size = path.stat().st_size
                    with path.open("rb") as content:
                        output.addfile(info, content)
        publish_noreplace(staged_archive, archive, "archive destination")
        staged_archive = None
    except PackageError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise PackageError(f"cannot create deterministic private package: {archive}") from error
    finally:
        if staged_archive is not None:
            try:
                staged_archive.unlink()
            except FileNotFoundError:
                pass


def checked_member_path(name: str) -> Path:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageError(f"archive has an unsafe member name: {name}")
    if path.parts[0] != ARCHIVE_ROOT:
        raise PackageError(f"archive member escapes its private root: {name}")
    return Path(*path.parts)


def checked_archive_members(
    input_archive: Iterable[tarfile.TarInfo],
) -> list[tuple[tarfile.TarInfo, Path]]:
    """Bound and reject unsafe, duplicate, or rootless members before materialization."""

    checked: list[tuple[tarfile.TarInfo, Path]] = []
    names: set[str] = set()
    root_seen = False
    regular_payload_bytes = 0
    for member_count, member in enumerate(input_archive, start=1):
        if member_count > MAX_ARCHIVE_MEMBER_COUNT:
            raise PackageError(
                f"archive exceeds {MAX_ARCHIVE_MEMBER_COUNT} member safety limit"
            )
        relative = checked_member_path(member.name)
        if member.name in names:
            raise PackageError(f"archive contains a duplicate member: {member.name}")
        names.add(member.name)
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise PackageError(f"archive has a non-regular member: {member.name}")
        if not (member.isdir() or member.isreg()):
            raise PackageError(f"archive has an unsupported member: {member.name}")
        if member.isreg():
            if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise PackageError(
                    f"archive member exceeds {MAX_ARCHIVE_MEMBER_BYTES} byte safety limit: "
                    f"{member.name}"
                )
            regular_payload_bytes += member.size
            if regular_payload_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                raise PackageError(
                    f"archive exceeds {MAX_ARCHIVE_TOTAL_BYTES} byte regular-payload safety limit"
                )
        if member.name == ARCHIVE_ROOT:
            if not member.isdir():
                raise PackageError("archive private root is not a directory")
            root_seen = True
        checked.append((member, relative))
    if not root_seen:
        raise PackageError("archive lacks its private root directory")
    return checked


def materialize_checked_members(
    input_archive: tarfile.TarFile,
    members: list[tuple[tarfile.TarInfo, Path]],
    destination: Path,
) -> None:
    """Copy only prevalidated regular members into a private staging tree."""

    for member, relative in members:
        target = destination / relative
        if member.isdir():
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.chmod(0o755)
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        content = input_archive.extractfile(member)
        if content is None:
            raise PackageError(f"archive regular member lacks content: {member.name}")
        try:
            with content, target.open("xb") as output:
                shutil.copyfileobj(content, output)
        except OSError as error:
            raise PackageError(f"cannot materialize archive member: {member.name}") from error
        target.chmod(0o755 if member.mode & 0o111 else 0o644)


def extract_archive(archive: Path, destination: Path) -> Path:
    """Safely materialize the one regular-file package root into destination."""

    archive = prospective_path(archive, "archive")
    require_regular_file(archive, "archive")
    destination = prospective_path(destination, "extraction destination")
    if destination.exists() or destination.is_symlink():
        raise PackageError(f"extraction destination already exists or is unsafe: {destination}")
    parent = require_safe_directory(destination.parent, "extraction parent")
    destination = parent / destination.name
    try:
        with tarfile.open(archive, "r:xz") as input_archive:
            members = checked_archive_members(input_archive)
            with tempfile.TemporaryDirectory(
                prefix=".crabc-x86-static-package.", dir=parent
            ) as temporary:
                staged_destination = Path(temporary) / "extract"
                staged_destination.mkdir(mode=0o755)
                materialize_checked_members(input_archive, members, staged_destination)
                root = staged_destination / ARCHIVE_ROOT
                entries = source_entries(root)
                validate_installed_tree(root, entries)
                publish_noreplace(staged_destination, destination, "extraction destination")
    except PackageError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise PackageError(f"cannot safely extract private package: {archive}") from error
    root = destination / ARCHIVE_ROOT
    if not root.is_dir() or root.is_symlink():
        raise PackageError("archive did not extract a safe private root")
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--source", type=Path, required=True)
    create.add_argument("--archive", type=Path, required=True)
    extract = commands.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "create":
            create_archive(arguments.source, arguments.archive)
        else:
            print(extract_archive(arguments.archive, arguments.destination))
    except PackageError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
