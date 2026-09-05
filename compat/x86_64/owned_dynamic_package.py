#!/usr/bin/env python3
"""Deterministic package/extraction of one exactly manifested dynamic install."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

import crabc_cc_owned_dynamic as driver
import owned_static_sysroot_package as shared_package


def package(root: Path, output: Path) -> None:
    root = shared_package.require_safe_directory(root, "dynamic package source")
    output = shared_package.prospective_path(output, "dynamic package output")
    record = driver.validate(root)
    driver.shared.validate_application_output(root, output)
    if output.exists(): raise driver.shared.DriverError("package output already exists")
    entries = sorted({*record["files"], "share/crabc/manifest.json", *record["symlinks"]})
    with tempfile.TemporaryDirectory(prefix=".dynamic-package.", dir=output.parent) as temporary:
        staged = Path(temporary) / "runtime.tar"
        write_archive(root, staged, record, entries)
        shared_package.publish_noreplace(staged, output, "dynamic package output")


def write_archive(root: Path, output: Path, record: dict, entries: list[str]) -> None:
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in entries:
            entry = tarfile.TarInfo(relative)
            entry.mtime = 1
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ""
            if relative in record["symlinks"]:
                entry.type = tarfile.SYMTYPE
                entry.linkname = record["symlinks"][relative]
                entry.mode = 0o777
                archive.addfile(entry)
            else:
                payload = (root / relative).read_bytes()
                entry.size = len(payload)
                entry.mode = 0o755 if relative.startswith("bin/") or relative == "lib/ld-crabc-x86_64.so.1" else 0o644
                archive.addfile(entry, io.BytesIO(payload))


def extract(package_path: Path, output: Path) -> None:
    package_path = shared_package.prospective_path(package_path, "dynamic package")
    shared_package.require_regular_file(package_path, "dynamic package")
    output = shared_package.prospective_path(output, "dynamic extraction output")
    if output.exists(): raise driver.shared.DriverError("extraction output already exists")
    driver.shared.reject_existing_symlink_components(output, "extraction output")
    # Validate all archive members and all payload hashes before writing. This
    # deliberately does not invoke tarfile.extract or follow archive links.
    with tarfile.open(package_path, "r:") as archive:
        members = archive.getmembers()
        if len(members) > shared_package.MAX_ARCHIVE_MEMBER_COUNT:
            raise driver.shared.DriverError("dynamic package member safety limit")
        if any(entry.size < 0 or entry.size > shared_package.MAX_ARCHIVE_MEMBER_BYTES for entry in members):
            raise driver.shared.DriverError("dynamic package member size safety limit")
        if sum(entry.size for entry in members) > shared_package.MAX_ARCHIVE_TOTAL_BYTES:
            raise driver.shared.DriverError("dynamic package aggregate size safety limit")
        names = [entry.name for entry in members]
        if len(set(names)) != len(names): raise driver.shared.DriverError("duplicate package member")
        for entry in members:
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != entry.name or not entry.name:
                raise driver.shared.DriverError("unsafe package member path")
            if not (entry.isfile() or entry.issym()): raise driver.shared.DriverError("nonregular package member")
            if entry.issym() and driver.ALIASES.get(entry.name) != entry.linkname:
                raise driver.shared.DriverError("unapproved package symlink")
        manifest_member = archive.getmember("share/crabc/manifest.json")
        if not manifest_member.isfile(): raise driver.shared.DriverError("manifest is not a regular file")
        manifest = json.loads(archive.extractfile(manifest_member).read())
        if manifest.get("format") != driver.FORMAT or manifest.get("symlinks") != driver.ALIASES:
            raise driver.shared.DriverError("wrong package contract")
        files = manifest.get("files", {})
        if manifest.get("target") != driver.shared.TARGET or not isinstance(files, dict) or not driver.REQUIRED <= files.keys():
            raise driver.shared.DriverError("incomplete package contract")
        if set(names) != {*files, "share/crabc/manifest.json", *driver.ALIASES}:
            raise driver.shared.DriverError("package manifest roster mismatch")
        payloads = {}
        for entry in members:
            if entry.name in driver.ALIASES and not entry.issym():
                raise driver.shared.DriverError("canonical compatibility alias is not a symlink")
            if entry.name not in driver.ALIASES and not entry.isfile():
                raise driver.shared.DriverError("regular payload replaced by symlink")
            if entry.isfile():
                payload = archive.extractfile(entry).read()
                if entry.name != "share/crabc/manifest.json" and hashlib.sha256(payload).hexdigest() != files[entry.name]:
                    raise driver.shared.DriverError("package payload hash mismatch")
                payloads[entry.name] = (payload, entry.mode)
        paths = {PurePosixPath(name) for name in names}
        if any(parent in paths for path in paths for parent in path.parents):
            raise driver.shared.DriverError("package member is also an ancestor")
    with tempfile.TemporaryDirectory(prefix=".dynamic-extraction.", dir=output.parent) as temporary:
        staged = Path(temporary) / "installed"
        materialize_payload(staged, payloads)
        driver.validate(staged)
        shared_package.publish_noreplace(staged, output, "dynamic extraction output")


def materialize_payload(output: Path, payloads: dict[str, tuple[bytes, int]]) -> None:
    output.mkdir()
    for relative, (payload, mode) in payloads.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode & 0o755)
    for relative, target in driver.ALIASES.items():
        (output / relative).symlink_to(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("package", "extract"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        (package if args.action == "package" else extract)(args.source, args.output)
    except (driver.shared.DriverError, shared_package.PackageError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"dynamic package: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
