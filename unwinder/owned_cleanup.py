#!/usr/bin/env python3
"""Run the full Rust cleanup fixture through supplied owned runtime products.

This is consumer-development evidence. Stock consumers receive the selected
standalone provider beside the receipt; source-built consumers instead stage
the exact patched provider as a normal Cargo dependency. Neither form is
installed into a supplied product. Packaging, broad build-std/LTO/DSO
qualification, and complete malformed-metadata behavior remain separate
requirements before any qualification or promotion claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any

import cleanup
import build
import owned_rust_link


ROOT = Path(__file__).resolve().parent
CHECKOUT = ROOT.parent
WORK = CHECKOUT / ".work/x86_64/owned-rust-std-cleanup"
TARGET = "x86_64-unknown-linux-musl"
FIXTURE = ROOT / "fixtures/cleanup.rs"
BUILD_STD_FIXTURE = ROOT / "fixtures/build_std_cleanup"
BUILD_STD_DSO_FIXTURE = ROOT / "fixtures/cleanup_dso"
DEPENDENCY_FIXTURE = ROOT / "fixtures/cleanup-dependency"
DEPENDENCY_PACKAGE = "crabc-cleanup-dependency"
DEPENDENCY_CRATE = "crabc_cleanup_dependency"
DEPENDENCY_VERSION = "0.1.0"
BUILD_STD_BINARY = "crabc-owned-cleanup-build-std"
BUILD_STD_DSO_HOST = "crabc-owned-cleanup-dso-host"
BUILD_STD_DSO_LIBRARY = "libcrabc_owned_cleanup_plugin.so"
BUILD_STD_CRATES = ("std", "core", "alloc", "panic_unwind", "unwind", "compiler_builtins", "proc_macro")
SOURCE_LTO_RUNTIME_TARGETS = {
    "core": ("core/src/lib.rs", ["lib"], ["lib"]),
    "alloc": ("alloc/src/lib.rs", ["lib"], ["lib"]),
    "panic_unwind": ("panic_unwind/src/lib.rs", ["lib"], ["lib"]),
    "std": ("std/src/lib.rs", ["rlib"], ["rlib"]),
    "compiler_builtins": ("compiler-builtins/compiler-builtins/src/lib.rs", ["lib"], ["lib"]),
    "proc_macro": ("proc_macro/src/lib.rs", ["lib"], ["lib"]),
}
SOURCE_GRAPH_PACKAGES = frozenset(build.FEATURES)
HOST_BUILD_LINKER = Path("/usr/bin/gcc")
HOST_BUILD_SCRIPT_OUTPUT = re.compile(r"build_script_build-[0-9a-f]+\Z")
SERIAL_BUILD_ENVIRONMENT = {
    "CARGO_BUILD_JOBS": "1",
    "CMAKE_BUILD_PARALLEL_LEVEL": "1",
    "MAKEFLAGS": "-j1",
    "NINJAFLAGS": "-j1",
}
SOURCE_BUILD_PROFILE = {
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
    "CARGO_PROFILE_RELEASE_LTO": "fat",
}
PROVIDER_LINK_ANCHOR_DEFINITION = (
    'pub fn link_anchor() -> unsafe extern "C-unwind" fn(\n'
    '    *mut unwinding::abi::UnwindException,\n'
    ') -> unwinding::abi::UnwindReasonCode {\n'
    '    unwinding::abi::_Unwind_RaiseException\n'
    '}'
)
DSO_HOST_POST_CLOSE_SUCCESS = "if release() != 0 || !matches!(running.join(), Ok(0)) || run() != 0 {"
DSO_PLUGIN_WORKER_SUCCESS = "if !matches!(worker.join(), Ok(true)) {"
DSO_RESULT_EQUALITIES = ("running.join() != Ok(0)", "worker.join() != Ok(true)")
CARGO_VENDOR_CONFIG = """[source.crates-io]
replace-with = \"crabc-owned-composite-vendor\"

[source.crabc-owned-composite-vendor]
directory = \"{directory}\"

[net]
offline = true
"""
CARGO_PROVIDER_VENDOR_CONFIG = """[source.crates-io]
replace-with = \"crabc-owned-provider-vendor\"

[source.crabc-owned-provider-vendor]
directory = \"{directory}\"

[net]
offline = true
"""
# Cargo's extracted registry tree carries two transport markers which Cargo
# omits from a directory source.  ``build.py`` pins the extracted-tree digest,
# so restore these fixed markers only in a private derivative after the vendor
# checksum has authenticated every package source file.
CARGO_REGISTRY_UNWINDING_MARKERS = {
    ".cargo-ok": b'{"v":1}',
    ".gitignore": b".vscode/\ntarget\n",
}
# Cargo coordinates fat LTO with its embed-bitcode setting. Duplicating these
# profile settings in CARGO_ENCODED_RUSTFLAGS makes rustc reject the build.
SOURCE_BUILD_RUSTFLAGS = (
    "-C", "panic=unwind", "-C", "force-unwind-tables=yes", "-C", "link-self-contained=no",
    "-C", "target-feature=-crt-static", "-C", "link-arg=-Wl,--eh-frame-hdr",
)
SOURCE_INPUTS = (
    ROOT / "owned_cleanup.py", ROOT / "owned_rust_link.py", ROOT / "cleanup.py",
    ROOT / "build.py", ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "src/lib.rs",
    ROOT / "patches/unwinding-0.2.10-phdr-bounds.rs", ROOT / "patches/unwinding-0.2.10-frame-bounds.rs", FIXTURE,
    BUILD_STD_FIXTURE / "Cargo.toml", BUILD_STD_FIXTURE / "Cargo.lock", BUILD_STD_FIXTURE / "src/main.rs",
    BUILD_STD_DSO_FIXTURE / "Cargo.toml", BUILD_STD_DSO_FIXTURE / "Cargo.lock",
    BUILD_STD_DSO_FIXTURE / "src/main.rs", BUILD_STD_DSO_FIXTURE / "src/plugin.rs",
    DEPENDENCY_FIXTURE / "Cargo.toml", DEPENDENCY_FIXTURE / "src/lib.rs",
)


class OwnedCleanupError(RuntimeError):
    """The supplied products or one recorded owned Rust consumer are unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OwnedCleanupError(message)


def assert_nonpromoting(record: dict[str, Any], description: str) -> None:
    for field in ("qualified", "family_completion", "promotion_ready", "public_support"):
        require(record.get(field) is False, f"{description} changes non-promoting state: {field}")


def physical(path: Path, description: str, *, directory: bool = False, executable: bool = False) -> Path:
    if ".." in path.parts:
        raise OwnedCleanupError(f"{description} has parent traversal: {path}")
    candidate = Path(os.path.abspath(path))
    current = Path(candidate.anchor)
    try:
        for part in candidate.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise OwnedCleanupError(f"{description} traverses a symlink: {path}")
        metadata = candidate.lstat()
    except OSError as error:
        raise OwnedCleanupError(f"{description} is unreadable: {path}") from error
    kind = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not kind:
        expected = "directory" if directory else "regular file"
        raise OwnedCleanupError(f"{description} is not a physical {expected}: {path}")
    if executable and not metadata.st_mode & 0o111:
        raise OwnedCleanupError(f"{description} is not executable: {path}")
    return candidate


def digest(path: Path) -> str:
    path = physical(path, "hashed artifact")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def json_object(path: Path, description: str) -> dict[str, Any]:
    path = physical(path, description)
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OwnedCleanupError(f"{description} has a duplicate key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OwnedCleanupError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        raise OwnedCleanupError(f"{description} is not a JSON object: {path}")
    return value


def record_file(path: Path, description: str) -> dict[str, str]:
    return {"path": str(physical(path, description)), "sha256": digest(path)}


def physical_tree_files(root: Path, description: str) -> list[Path]:
    """Return one regular, non-symlinked source tree in deterministic order."""

    root = physical(root, description, directory=True)
    files: list[Path] = []

    def visit(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
        except OSError as error:
            raise OwnedCleanupError(f"{description} is unreadable: {directory}") from error
        for entry in entries:
            try:
                metadata = entry.lstat()
            except OSError as error:
                raise OwnedCleanupError(f"{description} is unreadable: {entry}") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise OwnedCleanupError(f"{description} contains a symlink: {entry}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(entry)
            elif stat.S_ISREG(metadata.st_mode):
                files.append(entry)
            else:
                raise OwnedCleanupError(f"{description} contains a non-regular entry: {entry}")

    visit(root)
    return files


def cargo_vendor_tree(
    root: Path, expected: dict[str, tuple[str, str, str]], description: str,
) -> dict[str, Any]:
    """Bind a Cargo directory source to its locked package checksums.

    A Cargo vendor checksum is not a trust boundary on its own.  This reader
    checks it against the checked-in lock checksum and rehashes every source
    file it names, so the later offline source replacement has no implicit
    registry/cache input.
    """

    root = physical(root, description, directory=True)
    try:
        entries = sorted(root.iterdir(), key=lambda entry: entry.name)
    except OSError as error:
        raise OwnedCleanupError(f"{description} is unreadable: {root}") from error
    expected_identities = {(name, version): (directory_name, checksum)
                           for directory_name, (name, version, checksum) in expected.items()}
    require(len(expected_identities) == len(expected), f"{description} lock has duplicate package identities")
    observed: dict[str, Path] = {}
    for entry in entries:
        directory = physical(entry, f"{description} package directory", directory=True)
        manifest = physical(directory / "Cargo.toml", f"{description} package manifest")
        try:
            manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise OwnedCleanupError(f"{description} package manifest is invalid: {entry.name}") from error
        package = manifest_data.get("package")
        require(isinstance(package, dict) and isinstance(package.get("name"), str)
                and isinstance(package.get("version"), str),
                f"{description} package has no manifest identity: {entry.name}")
        identity = (package["name"], package["version"])
        expected_entry = expected_identities.get(identity)
        require(expected_entry is not None, f"{description} package is outside its lock: {entry.name}")
        directory_name, _checksum = expected_entry
        require(directory_name not in observed,
                f"{description} repeats a locked package identity: {directory_name}")
        observed[directory_name] = directory
    require(set(observed) == set(expected), f"{description} package roster differs from its lock")
    packages: list[dict[str, Any]] = []
    identity = hashlib.sha256()
    for directory_name in sorted(expected):
        name, version, package_checksum = expected[directory_name]
        directory = observed[directory_name]
        manifest = physical(directory / "Cargo.toml", f"{description} package manifest")
        try:
            manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise OwnedCleanupError(f"{description} package manifest is invalid: {directory_name}") from error
        package = manifest_data.get("package")
        require(
            isinstance(package, dict) and package.get("name") == name and package.get("version") == version,
            f"{description} package identity differs from its lock: {directory_name}",
        )
        checksum_path = physical(directory / ".cargo-checksum.json", f"{description} package checksum")
        checksum = json_object(checksum_path, f"{description} package checksum")
        require(
            set(checksum) == {"$comment", "files", "package"}
            and isinstance(checksum["$comment"], str)
            and checksum.get("package") == package_checksum
            and isinstance(checksum.get("files"), dict),
            f"{description} package checksum differs from its lock: {directory_name}",
        )
        expected_files = checksum["files"]
        require(
            all(
                isinstance(relative, str) and isinstance(value, str)
                and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                and relative not in {"", ".cargo-checksum.json"}
                and not Path(relative).is_absolute() and ".." not in Path(relative).parts
                for relative, value in expected_files.items()
            ),
            f"{description} package checksum file roster is malformed: {directory_name}",
        )
        actual_files = {
            path.relative_to(directory).as_posix(): digest(path)
            for path in physical_tree_files(directory, f"{description} package tree")
            if path != checksum_path
        }
        require(actual_files == expected_files,
                f"{description} package files differ from its checksum: {directory_name}")
        file_records = [{"path": relative, "sha256": actual_files[relative]} for relative in sorted(actual_files)]
        package_record = {
            "name": name,
            "version": version,
            "package_checksum": package_checksum,
            "directory": str(directory),
            "manifest": record_file(manifest, f"{description} package manifest"),
            "checksum": record_file(checksum_path, f"{description} package checksum"),
            "files": file_records,
        }
        packages.append(package_record)
        identity.update(directory_name.encode())
        identity.update(b"\0")
        identity.update(package_checksum.encode())
        identity.update(b"\0")
        identity.update(digest(checksum_path).encode())
        identity.update(b"\0")
        for file_record in file_records:
            identity.update(file_record["path"].encode())
            identity.update(b"\0")
            identity.update(file_record["sha256"].encode())
            identity.update(b"\0")
    return {"root": str(root), "packages": packages, "identity": identity.hexdigest()}


def locked_registry_vendor_packages(lock: Path, description: str) -> dict[str, tuple[str, str, str]]:
    """Return the complete crates.io directory-source closure for one lock."""

    lock = physical(lock, description)
    try:
        data = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise OwnedCleanupError(f"{description} is invalid") from error
    records = data.get("package")
    require(isinstance(records, list) and all(isinstance(record, dict) for record in records),
            f"{description} has no package records")
    expected: dict[str, tuple[str, str, str]] = {}
    for record in records:
        if record.get("source") != build.CRATES_IO_REGISTRY:
            continue
        name, version, checksum = record.get("name"), record.get("version"), record.get("checksum")
        require(
            isinstance(name, str) and isinstance(version, str)
            and isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None,
            f"{description} has a malformed registry package",
        )
        directory_name = f"{name}-{version}"
        require(directory_name not in expected, f"{description} has a duplicate registry package")
        expected[directory_name] = (name, version, checksum)
    require(expected, f"{description} has no registry package closure")
    return expected


def rust_source_vendor(rust_source: Path) -> tuple[dict[str, Any], dict[str, tuple[str, str, str]]]:
    """Read Rust's pinned complete build-std vendor source, not an ambient cache."""

    rust_source = physical(rust_source, "pinned rust-src library", directory=True)
    config = physical(rust_source / ".cargo/config.toml", "pinned rust-src vendor config")
    try:
        config_data = tomllib.loads(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise OwnedCleanupError("pinned rust-src vendor config is invalid") from error
    require(
        config_data == {
            "source": {
                "crates-io": {"replace-with": "vendored-sources"},
                "vendored-sources": {"directory": "vendor"},
            },
        },
        "pinned rust-src vendor config differs from the declared source replacement",
    )
    lock = physical(rust_source / "Cargo.lock", "pinned rust-src lock")
    expected = locked_registry_vendor_packages(lock, "pinned rust-src lock")
    record = cargo_vendor_tree(rust_source / "vendor", expected, "pinned rust-src complete vendor")
    record["config"] = record_file(config, "pinned rust-src vendor config")
    record["lock"] = record_file(lock, "pinned rust-src lock")
    return record, expected


def provider_vendor(provider_vendor: Path) -> tuple[dict[str, Any], dict[str, tuple[str, str, str]]]:
    """Read the independently authenticated, exact provider source closure."""

    provider_vendor = work_child(provider_vendor, "owned Rust provider vendor input", existing=True)
    expected = {
        f"{name}-{version}": (name, version, checksum)
        for name, (version, checksum) in build.PINS.items()
    }
    return cargo_vendor_tree(provider_vendor, expected, "owned Rust provider vendor input"), expected


def prepare_standalone_provider_cargo_home(output: Path, provider_vendor_root: Path) -> dict[str, Any]:
    """Bind the stock-provider build to the same verified offline vendor input."""

    output = physical(output, "owned Rust cleanup output", directory=True)
    provider, _expected = provider_vendor(provider_vendor_root)
    cargo_home = output / "provider-cargo-home"
    require(not cargo_home.exists() and not cargo_home.is_symlink(),
            "private standalone provider Cargo home must be fresh")
    cargo_home.mkdir(mode=0o755)
    cargo_home = physical(cargo_home, "private standalone provider Cargo home", directory=True)
    config = cargo_home / "config.toml"
    config.write_text(
        CARGO_PROVIDER_VENDOR_CONFIG.format(
            directory=_toml_path(Path(provider["root"]), "owned Rust provider vendor input", directory=True),
        ),
        encoding="utf-8",
    )
    config = physical(config, "private standalone provider Cargo source config")
    return {
        "provider_vendor": provider,
        "cargo_home": str(cargo_home),
        "cargo_config": record_file(config, "private standalone provider Cargo source config"),
    }


def prepare_offline_cargo_sources(
    application: Path, rust_source: Path, provider_vendor_root: Path, cargo_home: Path,
) -> dict[str, Any]:
    """Compose Rust's full vendor with the checked provider-only source closure."""

    standard, standard_expected = rust_source_vendor(rust_source)
    provider, provider_expected = provider_vendor(provider_vendor_root)
    combined_expected = dict(standard_expected)
    standard_by_name = {f"{package['name']}-{package['version']}": package for package in standard["packages"]}
    provider_by_name = {f"{package['name']}-{package['version']}": package for package in provider["packages"]}
    for directory_name, expected in provider_expected.items():
        existing = combined_expected.get(directory_name)
        if existing is not None:
            require(existing == expected, "Rust and provider vendor source pins conflict")
            require(
                standard_by_name[directory_name]["package_checksum"] == provider_by_name[directory_name]["package_checksum"]
                and standard_by_name[directory_name]["files"] == provider_by_name[directory_name]["files"],
                "Rust and provider vendor source contents differ",
            )
        else:
            combined_expected[directory_name] = expected
    composite_root = application / "cargo-vendor"
    require(not composite_root.exists() and not composite_root.is_symlink(),
            "private offline Cargo vendor must be fresh")
    shutil.copytree(Path(standard["root"]), composite_root, copy_function=shutil.copy2)
    for directory_name in sorted(set(provider_expected) - set(standard_expected)):
        shutil.copytree(Path(provider_by_name[directory_name]["directory"]), composite_root / directory_name,
                        copy_function=shutil.copy2)
    composite = cargo_vendor_tree(composite_root, combined_expected, "private composite Cargo vendor")
    config = cargo_home / "config.toml"
    require(not config.exists() and not config.is_symlink(), "private Cargo source config must be fresh")
    config.write_text(
        CARGO_VENDOR_CONFIG.format(
            directory=_toml_path(composite_root, "private composite Cargo vendor", directory=True),
        ),
        encoding="utf-8",
    )
    config = physical(config, "private Cargo source config")
    return {
        "rust_source_vendor": standard,
        "provider_vendor": provider,
        "composite_vendor": composite,
        "composite_vendor_custom_build_inputs": cargo_vendor_custom_build_inputs(composite),
        "cargo_config": record_file(config, "private Cargo source config"),
    }


def cargo_vendor_custom_build_inputs(vendor: dict[str, Any]) -> list[dict[str, dict[str, str]]]:
    """Bind every composite-vendor build script to its authenticated package.

    Cargo compiles directory-source build scripts from the private composite,
    not Rust's original vendor tree.  The composite has already been rehashed
    against both locked source closures; this records the exact manifest and
    declared build source that Cargo may later name in a host artifact record.
    """

    packages = vendor.get("packages")
    require(isinstance(packages, list) and all(isinstance(package, dict) for package in packages),
            "private composite Cargo vendor package records are malformed")
    inputs: list[dict[str, dict[str, str]]] = []
    identities: set[tuple[Path, Path]] = set()
    for package in packages:
        directory_value = package.get("directory")
        name, version = package.get("name"), package.get("version")
        require(isinstance(directory_value, str) and isinstance(name, str) and isinstance(version, str),
                "private composite Cargo vendor package identity is malformed")
        directory = physical(Path(directory_value), "private composite Cargo vendor package", directory=True)
        manifest = physical(directory / "Cargo.toml", "private composite Cargo vendor manifest")
        try:
            manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise OwnedCleanupError("private composite Cargo vendor manifest is invalid") from error
        package_data = manifest_data.get("package")
        require(
            isinstance(package_data, dict) and package_data.get("name") == name and package_data.get("version") == version,
            "private composite Cargo vendor manifest identity drifted",
        )
        build = package_data.get("build")
        if build is False:
            continue
        if build is None:
            candidate = directory / "build.rs"
            if not candidate.exists() and not candidate.is_symlink():
                continue
        else:
            require(isinstance(build, str) and build and not Path(build).is_absolute()
                    and ".." not in Path(build).parts,
                    "private composite Cargo vendor build source is invalid")
            candidate = directory / build
        build_source = physical(candidate, "private composite Cargo vendor build source")
        require(build_source.is_relative_to(directory),
                "private composite Cargo vendor build source escapes its package")
        identity = (manifest, build_source)
        require(identity not in identities, "private composite Cargo vendor repeats a build source")
        identities.add(identity)
        inputs.append({
            "manifest": record_file(manifest, "private composite Cargo vendor manifest"),
            "source": record_file(build_source, "private composite Cargo vendor build source"),
        })
    return inputs


def recorded_custom_build_inputs(
    records: Any, description: str,
) -> list[dict[str, Path]]:
    """Turn source-bound manifest/source records back into checked paths."""

    require(isinstance(records, list) and all(isinstance(record, dict) for record in records),
            f"{description} records are malformed")
    inputs: list[dict[str, Path]] = []
    identities: set[tuple[Path, Path]] = set()
    for record in records:
        manifest_record, source_record = record.get("manifest"), record.get("source")
        require(isinstance(manifest_record, dict) and isinstance(source_record, dict)
                and isinstance(manifest_record.get("path"), str) and isinstance(source_record.get("path"), str),
                f"{description} record is malformed")
        manifest = physical(Path(manifest_record["path"]), f"{description} manifest")
        build_source = physical(Path(source_record["path"]), f"{description} build source")
        require(
            manifest_record == record_file(manifest, f"{description} manifest")
            and source_record == record_file(build_source, f"{description} build source"),
            f"{description} record differs from its source",
        )
        identity = (manifest, build_source)
        require(identity not in identities, f"{description} repeats a build source")
        identities.add(identity)
        inputs.append({"manifest": manifest, "source": build_source})
    return inputs


def provider_registry_unwinding_source(application: Path, offline_sources: dict[str, Any]) -> dict[str, Any]:
    """Derive build.py's pinned registry-tree shape from the verified vendor.

    Cargo directory sources intentionally omit ``.cargo-ok`` and ``.gitignore``
    while adding ``.cargo-checksum.json``. The checked provider vendor has
    already authenticated the actual package files; this private derivative
    restores only the two fixed registry transport markers, removes only the
    directory-source checksum manifest, and then proves the pre-existing
    registry-tree identity before the normal patch staging code sees it.
    """

    provider = offline_sources.get("provider_vendor")
    require(isinstance(provider, dict) and isinstance(provider.get("packages"), list),
            "offline provider vendor record is malformed")
    candidates = [package for package in provider["packages"] if isinstance(package, dict)
                  and package.get("name") == build.PATCHED_UNWINDING
                  and package.get("version") == build.PINS[build.PATCHED_UNWINDING][0]]
    require(len(candidates) == 1 and isinstance(candidates[0].get("directory"), str),
            "offline provider vendor lacks its pinned unwinding source")
    source = physical(Path(candidates[0]["directory"]), "offline provider unwinding source", directory=True)
    source_checksum = candidates[0].get("checksum")
    require(isinstance(source_checksum, dict) and isinstance(source_checksum.get("path"), str),
            "offline provider unwinding checksum record is malformed")
    destination = application / "provider-registry-source" / f"{build.PATCHED_UNWINDING}-{build.PINS[build.PATCHED_UNWINDING][0]}"
    require(not destination.exists() and not destination.is_symlink(),
            "private provider registry source must be fresh")
    destination.parent.mkdir(mode=0o755)
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    destination = physical(destination, "private provider registry source", directory=True)
    destination_mode = stat.S_IMODE(destination.stat().st_mode)
    # The vendor input may intentionally be read-only. Its fresh private copy
    # needs one owner-write transition for the declared transport conversion;
    # always restore the copied source mode before returning or propagating an
    # error so later staging cannot inherit write authority from this step.
    try:
        destination.chmod(destination_mode | stat.S_IWUSR)
        checksum = physical(destination / ".cargo-checksum.json", "private provider directory-source checksum")
        checksum.unlink()
        markers: dict[str, dict[str, str]] = {}
        for relative, contents in CARGO_REGISTRY_UNWINDING_MARKERS.items():
            marker = destination / relative
            require(not marker.exists() and not marker.is_symlink(),
                    f"private provider registry marker already exists: {relative}")
            marker.write_bytes(contents)
            markers[relative] = record_file(marker, f"private provider registry marker {relative}")
        upstream_tree_sha256 = build.tree_digest(destination)
        require(upstream_tree_sha256 == build.PATCHED_UNWINDING_UPSTREAM_TREE_SHA256,
                "offline provider vendor does not reconstruct the pinned upstream identity")
    finally:
        destination.chmod(destination_mode)
    return {
        "source": str(source),
        "removed_directory_checksum": record_file(
            physical(Path(source_checksum["path"]), "offline provider vendor checksum"),
            "offline provider vendor checksum",
        ),
        "registry_source": str(destination),
        "registry_manifest": record_file(destination / "Cargo.toml", "private provider registry manifest"),
        "restored_registry_markers": markers,
        "upstream_tree_sha256": upstream_tree_sha256,
    }


def work_child(path: Path, description: str, *, existing: bool = False) -> Path:
    candidate = Path(os.path.abspath(path))
    boundary = physical(CHECKOUT / ".work", "checkout work boundary", directory=True)
    if not candidate.is_relative_to(boundary) or candidate == boundary:
        raise OwnedCleanupError(f"{description} must remain below checkout .work: {path}")
    if existing:
        return physical(candidate, description, directory=True)
    parent = candidate.parent
    physical(parent, f"{description} parent", directory=True)
    if candidate.exists() or candidate.is_symlink():
        raise OwnedCleanupError(f"{description} must be fresh: {path}")
    return candidate


def product_snapshot(root: Path, mode: str) -> dict[str, Any]:
    """Use the existing product reader, then retain all of its physical state."""

    compat = CHECKOUT / "compat/x86_64"
    if str(compat) not in sys.path:
        sys.path.insert(0, str(compat))
    import owned_posix_product_evidence as product  # pylint: disable=import-outside-toplevel

    root = work_child(root, f"supplied owned {mode} product", existing=True)
    try:
        manifest, files = (
            product._validate_static_product(root) if mode == "static"
            else product._validate_dynamic_product(root)
        )
    except product.ProductEvidenceError as error:
        raise OwnedCleanupError(f"invalid supplied owned {mode} product: {error}") from error
    return {
        "root": str(root),
        "manifest": record_file(manifest, f"owned {mode} manifest"),
        "files": dict(files),
    }


def assert_same_product(snapshot: dict[str, Any], mode: str) -> None:
    current = product_snapshot(Path(str(snapshot["root"])), mode)
    if current != snapshot:
        raise OwnedCleanupError(f"supplied owned {mode} product changed during consumer collection")


def clean_environment() -> dict[str, str]:
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith(("CARGO_", "RUSTFLAGS", "RUSTUP_TOOLCHAIN", "LD_"))
    }


def run_logged(command: list[str | Path], environment: dict[str, str], log: Path, description: str) -> str:
    if log.exists() or log.is_symlink():
        raise OwnedCleanupError(f"{description} log must be fresh: {log}")
    result = subprocess.run([str(item) for item in command], env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(result.stdout, encoding="utf-8")
    if result.returncode:
        raise OwnedCleanupError(f"{description} exited {result.returncode}; retained diagnostics: {log}")
    return result.stdout


def run_logged_streams(
    command: list[str | Path], environment: dict[str, str], stdout_log: Path, stderr_log: Path, description: str,
) -> tuple[str, str]:
    """Retain Cargo's machine-readable stream apart from verbose diagnostics."""

    if any(path.exists() or path.is_symlink() for path in (stdout_log, stderr_log)):
        raise OwnedCleanupError(f"{description} logs must be fresh")
    result = subprocess.run([str(item) for item in command], env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_log.write_text(result.stdout, encoding="utf-8")
    stderr_log.write_text(result.stderr, encoding="utf-8")
    if result.returncode:
        raise OwnedCleanupError(f"{description} exited {result.returncode}; retained diagnostics: {stderr_log}")
    return result.stdout, result.stderr


def source_built_link_receipt(
    path: Path, binary: Path, source_library_root: Path, description: str,
    toolchain_search_root: Path | None = None, built_unwind: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Read one source-built fat-LTO link without admitting stock target rlibs."""

    record = json_object(path, description)
    require(record.get("schema") == 6 and record.get("format") == "crabc-owned-rust-source-build-link/v5",
            f"{description} has the wrong source-built link schema")
    require(record.get("rust_library_origin") == "source-built"
            and record.get("source_built_target_library_root") == str(source_library_root),
            f"{description} does not bind the source-built target library root")
    declared_search = record.get("declared_toolchain_search_root")
    require(isinstance(declared_search, str),
            f"{description} does not bind the Cargo toolchain search root")
    if toolchain_search_root is not None:
        require(declared_search == str(toolchain_search_root),
                f"{description} changes the declared Cargo toolchain search root")
    unused_searches = record.get("unused_search_paths")
    application_root = source_library_root.parent
    require(
        isinstance(unused_searches, list) and all(isinstance(value, str) for value in unused_searches)
        and declared_search in unused_searches
        and all(
            value == declared_search or Path(value).is_relative_to(application_root)
            for value in unused_searches
        ),
        f"{description} has an unapproved Cargo Rust search path",
    )
    require("omitted_stock_rust_unwind" not in record and "omitted_compiler_builtins" not in record,
            f"{description} retains a stock Rust runtime archive")
    require("provider_archive" not in record,
            f"{description} retains a standalone provider beside its Cargo graph")
    require("omitted_source_built_rust_unwind" not in record,
            f"{description} admits a direct source-built Rust libunwind archive")
    require("cargo_graph_provider" not in record,
            f"{description} retains a direct Cargo provider archive after LTO")
    compiler_builtins = record.get("omitted_source_built_compiler_builtins")
    require(
        isinstance(compiler_builtins, dict)
        and isinstance(compiler_builtins.get("path"), str)
        and compiler_builtins["path"].startswith(str(source_library_root) + os.sep),
        f"{description} does not omit its source-built compiler-builtins archive",
    )
    inputs = record.get("application_inputs")
    require(isinstance(inputs, list) and all(isinstance(value, dict) for value in inputs),
            f"{description} lacks its Rust application inputs")
    input_paths = [value.get("path") for value in inputs if isinstance(value.get("path"), str)]
    require(len(inputs) == 1 and len(input_paths) == 1 and input_paths[0].endswith(".o"),
            f"{description} does not retain one fused Cargo LTO object")
    # Cargo may remove its original rcgu.o after rustc returns.  The owned
    # linker must therefore preserve a byte-identical, confined copy and use
    # that copy for LLD.  Rehash the durable link input here; the original
    # Cargo path remains a recorded source fact rather than a live file.
    lto_object = physical(Path(input_paths[0]), f"{description} retained fused Cargo LTO object")
    require(lto_object.is_relative_to(application_root),
            f"{description} fused Cargo LTO object escapes its application root")
    require(not any(path.endswith(".rlib") for path in input_paths),
            f"{description} retains a direct Rust archive after LTO")
    retained_object = record_file(lto_object, f"{description} retained fused Cargo LTO object")
    source_lto = record.get("source_lto_object")
    cargo_object = source_lto.get("cargo_object") if isinstance(source_lto, dict) else None
    cargo_path = cargo_object.get("path") if isinstance(cargo_object, dict) else None
    cargo_digest = cargo_object.get("sha256") if isinstance(cargo_object, dict) else None
    cargo_input = Path(cargo_path) if isinstance(cargo_path, str) else None
    require(
        isinstance(source_lto, dict)
        and set(source_lto) == {
            "cargo_object", "retained_object", "defined_unwind_abi", "rust_eh_personality",
        }
        and isinstance(cargo_object, dict)
        and set(cargo_object) == {"path", "sha256"}
        and cargo_input is not None and cargo_input.is_absolute() and ".." not in cargo_input.parts
        and cargo_input.suffix == ".o" and cargo_input.is_relative_to(application_root)
        and isinstance(cargo_digest, str) and re.fullmatch(r"[0-9a-f]{64}", cargo_digest) is not None
        and cargo_digest == retained_object["sha256"]
        and source_lto.get("retained_object") == retained_object
        and source_lto.get("defined_unwind_abi") == sorted(build.UNWIND_ABI)
        and source_lto.get("rust_eh_personality") is True,
        f"{description} does not prove the retained fused Cargo LTO unwind ABI",
    )
    if built_unwind is not None:
        built_path = built_unwind.get("path")
        require(isinstance(built_path, str),
                f"{description} has a malformed source-built Rust libunwind record")
        built_archive = physical(Path(built_path), f"{description} source-built Rust libunwind archive")
        require(
            built_unwind == record_file(built_archive, f"{description} source-built Rust libunwind archive")
            and built_archive.name.startswith("libunwind-")
            and built_archive.is_relative_to(source_library_root)
            and str(built_archive) not in input_paths,
            f"{description} does not retain an unselected source-built Rust libunwind archive",
        )
    require(record.get("output") == record_file(binary, f"{description} output"),
            f"{description} does not identify its output")
    assert_nonpromoting(record, description)
    trace = record.get("resolved_input_trace")
    command = record.get("command")
    require(isinstance(trace, str) and isinstance(command, list) and all(isinstance(item, str) for item in command),
            f"{description} lacks exact command or trace")
    if record.get("rust_requested_mode") == "shared":
        require("--no-undefined-version" in command,
                f"{description} does not retain Rust's cdylib version-script safety flag")
        export_script = record.get("rust_cdylib_export_script")
        cargo_script = export_script.get("cargo_script") if isinstance(export_script, dict) else None
        retained_script = export_script.get("retained_script") if isinstance(export_script, dict) else None
        dynamic_exports = export_script.get("dynamic_exports") if isinstance(export_script, dict) else None
        cargo_path = cargo_script.get("path") if isinstance(cargo_script, dict) else None
        cargo_digest = cargo_script.get("sha256") if isinstance(cargo_script, dict) else None
        retained_path = retained_script.get("path") if isinstance(retained_script, dict) else None
        retained = Path(retained_path) if isinstance(retained_path, str) else None
        expected_retained = binary.with_name(binary.name + ".crabc-owned-rust-export-script.map")
        expected_dynamic_exports = sorted({*owned_rust_link.RUST_CDYLIB_EXPORTS, *build.UNWIND_ABI})
        require(
            isinstance(export_script, dict)
            and set(export_script) == {"cargo_script", "retained_script", "dynamic_exports"}
            and isinstance(cargo_script, dict) and set(cargo_script) == {"path", "sha256"}
            and isinstance(cargo_path, str) and isinstance(cargo_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", cargo_digest) is not None
            and Path(cargo_path).is_absolute() and ".." not in Path(cargo_path).parts
            and Path(cargo_path).is_relative_to(application_root)
            and retained is not None and retained == expected_retained
            and retained.is_relative_to(application_root)
            and cargo_path != str(retained)
            and retained_script == record_file(retained, f"{description} retained Rust cdylib export script")
            and cargo_digest == retained_script["sha256"]
            and dynamic_exports == expected_dynamic_exports
            and command.count("--version-script") == 1 and command.count(str(retained)) == 1,
            f"{description} does not bind Cargo's retained cdylib export script",
        )
    def ambient_runtime(value: str) -> bool:
        name = Path(value).name
        return "libgcc" in value or value in {"-lgcc", "-lgcc_s", "-lunwind", "-lc"} or (
            name == "libunwind" or name.startswith(("libunwind-", "libunwind."))
        ) or re.search(r"(?:^|/)libunwind(?:[-.]|$)", value) is not None

    require(not any(ambient_runtime(item) for item in command),
            f"{description} linker command admits an ambient native runtime request")
    require(
        "libcrabc-unwind.a" not in trace and "libunwind" not in trace and str(lto_object) in trace
        and not ambient_runtime(trace),
        f"{description} link trace does not prove its fused Cargo LTO object without ambient unwind runtimes",
    )
    return record


def cargo_json_records(stream: str, description: str) -> list[dict[str, Any]]:
    """Read Cargo's JSON messages while retaining build-script text as noise.

    Cargo interleaves a build script's literal ``cargo:`` output with its JSON
    message stream even when the requested message format is JSON. Only JSON
    object records can establish graph, artifact, or host-link facts; raw text
    stays retained in the stream but cannot be treated as a Cargo record.
    """

    records: list[dict[str, Any]] = []
    for line in stream.splitlines():
        if not line:
            continue
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise OwnedCleanupError(f"{description} has malformed Cargo JSON") from error
        require(isinstance(record, dict), f"{description} has a non-object Cargo JSON record")
        records.append(record)
    require(records, f"{description} has no Cargo JSON records")
    return records


def cargo_artifact(
    stream: str, *, package: Path, target: Path, name: str, crate_type: str,
) -> Path:
    """Find one exact Cargo artifact from its JSON stream, not target-dir globbing."""

    selected: list[Path] = []
    source = package / "src" / ("main.rs" if crate_type == "bin" else "plugin.rs")
    for record in cargo_json_records(stream, "Cargo artifact stream"):
        if record.get("reason") != "compiler-artifact":
            continue
        artifact_target = record.get("target")
        if not isinstance(artifact_target, dict) or artifact_target.get("name") != name:
            continue
        kinds = artifact_target.get("crate_types")
        if not isinstance(kinds, list) or crate_type not in kinds:
            continue
        if artifact_target.get("src_path") != str(source):
            continue
        candidates = [record.get("executable")] if crate_type == "bin" else record.get("filenames")
        if not isinstance(candidates, list):
            raise OwnedCleanupError(f"Cargo {crate_type} artifact lacks output paths")
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            path = physical(Path(candidate), f"Cargo {crate_type} artifact")
            if not path.is_relative_to(target):
                raise OwnedCleanupError(f"Cargo {crate_type} artifact escapes its target directory")
            if crate_type == "bin" or path.name == BUILD_STD_DSO_LIBRARY:
                selected.append(path)
    if len(selected) != 1:
        raise OwnedCleanupError(f"expected one Cargo {crate_type} artifact {name!r}, found {selected!r}")
    return selected[0]


def cargo_application_dependency_artifact(stream: str, *, package_root: Path, target: Path) -> Path:
    """Select the one declared local cleanup dependency from Cargo's stream."""

    target = physical(target, "source-built Cargo target", directory=True)
    source = physical(package_root.parent / "cleanup-dependency/src/lib.rs",
                      "generated cleanup dependency source")
    selected: list[Path] = []
    for record in cargo_json_records(stream, "Cargo application dependency artifact stream"):
        if record.get("reason") != "compiler-artifact":
            continue
        artifact_target = record.get("target")
        if not isinstance(artifact_target, dict) or artifact_target.get("src_path") != str(source):
            continue
        require(
            artifact_target.get("name") == DEPENDENCY_CRATE
            and artifact_target.get("kind") == ["lib"]
            and artifact_target.get("crate_types") == ["lib"]
            and record.get("executable") is None,
            "Cargo cleanup dependency artifact identity drifted",
        )
        filenames = record.get("filenames")
        require(isinstance(filenames, list), "Cargo cleanup dependency artifact has malformed outputs")
        for filename in filenames:
            if isinstance(filename, str) and filename.endswith(".rlib"):
                artifact = physical(Path(filename), "Cargo cleanup dependency archive")
                require(artifact.is_relative_to(target),
                        "Cargo cleanup dependency archive escapes its target directory")
                selected.append(artifact)
    require(len(selected) == 1, f"expected one local cleanup dependency archive, found {selected!r}")
    return selected[0]


def cargo_link_receipt_for_artifact(artifact: Path, source_library_root: Path, description: str) -> tuple[Path, Path]:
    """Find the linker-side output Cargo may have hard-linked into release/."""

    artifact_digest = digest(artifact)
    candidates: list[tuple[Path, Path]] = []
    for receipt in sorted(source_library_root.glob("*.crabc-owned-rust-link.json")):
        record = json_object(receipt, f"{description} candidate link receipt")
        output = record.get("output")
        if not isinstance(output, dict) or output.get("sha256") != artifact_digest:
            continue
        path = output.get("path")
        if not isinstance(path, str):
            raise OwnedCleanupError(f"{description} candidate link receipt has no output path")
        linked = physical(Path(path), f"{description} linker-side output")
        candidates.append((physical(receipt, f"{description} link receipt"), linked))
    if len(candidates) != 1:
        raise OwnedCleanupError(f"expected one linker receipt for Cargo artifact {artifact}, found {candidates!r}")
    return candidates[0]


def cargo_build_std_unwind_artifact(stream: str, target: Path, rust_source: Path) -> Path:
    """Select Cargo's one fresh build-std unwind archive without linking it.

    ``-Zbuild-std=std,panic_unwind`` compiles the standard unwind crate, but
    Cargo's final normal graph selects the source provider rather than passing
    that archive to the owned final link.  Record the built artifact and later
    prove its absence from the final link inputs.
    """

    target = physical(target, "source-built Cargo target", directory=True)
    unwind_source = physical(rust_source / "unwind/src/lib.rs", "pinned rust-src unwind source")
    selected: list[Path] = []
    for record in cargo_json_records(stream, "Cargo build-std unwind artifact stream"):
        if record.get("reason") != "compiler-artifact":
            continue
        target_record = record.get("target")
        if not isinstance(target_record, dict) or target_record.get("name") != "unwind":
            continue
        require(
            target_record.get("kind") == ["lib"] and target_record.get("crate_types") == ["lib"]
            and target_record.get("src_path") == str(unwind_source),
            "Cargo build-std unwind artifact identity drifted",
        )
        filenames = record.get("filenames")
        require(isinstance(filenames, list) and record.get("executable") is None,
                "Cargo build-std unwind artifact has malformed outputs")
        for filename in filenames:
            if isinstance(filename, str) and filename.endswith(".rlib"):
                artifact = physical(Path(filename), "Cargo build-std unwind archive")
                require(artifact.is_relative_to(target), "Cargo build-std unwind archive escapes its target directory")
                selected.append(artifact)
    require(len(selected) == 1, f"expected one Cargo build-std unwind archive, found {selected!r}")
    return selected[0]


def cargo_build_std_runtime_artifacts(stream: str, target: Path, rust_source: Path) -> dict[str, Path]:
    """Select the full source std closure from Cargo's artifact records.

    The filenames come from the compiler-artifact records, whose target source
    paths tie each archive to the pinned rust-src tree. They are later tied to
    the primary consumer rustc invocation, rather than inferred from a target
    directory scan or from the native linker argv after fat LTO has absorbed
    them.
    """

    target = physical(target, "source-built Cargo target", directory=True)
    rust_source = physical(rust_source, "pinned rust-src library", directory=True)
    selected: dict[str, list[Path]] = {name: [] for name in SOURCE_LTO_RUNTIME_TARGETS}
    for record in cargo_json_records(stream, "Cargo build-std runtime artifact stream"):
        if record.get("reason") != "compiler-artifact":
            continue
        target_record = record.get("target")
        if not isinstance(target_record, dict):
            continue
        name = target_record.get("name")
        if name not in SOURCE_LTO_RUNTIME_TARGETS:
            continue
        relative_source, kinds, crate_types = SOURCE_LTO_RUNTIME_TARGETS[name]
        require(
            target_record.get("kind") == kinds and target_record.get("crate_types") == crate_types
            and target_record.get("src_path") == str(rust_source / relative_source),
            f"Cargo build-std {name} artifact identity drifted",
        )
        filenames = record.get("filenames")
        require(isinstance(filenames, list) and record.get("executable") is None,
                f"Cargo build-std {name} artifact has malformed outputs")
        for filename in filenames:
            if isinstance(filename, str) and filename.endswith(".rlib"):
                artifact = physical(Path(filename), f"Cargo build-std {name} archive")
                require(artifact.is_relative_to(target),
                        f"Cargo build-std {name} archive escapes its target directory")
                selected[name].append(artifact)
    missing = [name for name, artifacts in selected.items() if len(artifacts) != 1]
    require(not missing, f"expected one Cargo build-std runtime archive for each crate, found {missing!r}")
    return {name: artifacts[0] for name, artifacts in selected.items()}


def cargo_source_lto_extern_closure(
    log: str, *, target_name: str, binary_name: str | None, link_output: Path, source_library_root: Path,
    runtime_artifacts: dict[str, dict[str, str]], cargo_provider: dict[str, str],
    application_dependency: dict[str, str], built_unwind: dict[str, str],
) -> dict[str, Any]:
    """Bind one primary Cargo rustc input graph to its fused native-link output."""

    source_library_root = physical(source_library_root, "source-built Rust target library root", directory=True)
    link_output = physical(link_output, "Cargo linker-side consumer output")
    crate_name = target_name.replace("-", "_")
    prefix = "Running `"
    invocations = [line.strip() for line in log.splitlines()
                   if line.strip().startswith(prefix) and f"--crate-name {crate_name}" in line]
    require(len(invocations) == 1, "Cargo diagnostics do not retain one primary consumer rustc invocation")
    invocation = invocations[0]
    require(invocation.endswith("`") and "CARGO_PRIMARY_PACKAGE=1" in invocation
            and f"CARGO_CRATE_NAME={crate_name}" in invocation
            and (binary_name is None or f"CARGO_BIN_NAME={binary_name}" in invocation),
            "Cargo diagnostics primary consumer invocation drifted")
    try:
        arguments = shlex.split(invocation[len(prefix):-1])
    except ValueError as error:
        raise OwnedCleanupError("Cargo diagnostics primary consumer invocation is not shell-quoted") from error

    def one_value(option: str) -> str:
        values = [arguments[index + 1] for index, argument in enumerate(arguments)
                  if argument == option and index + 1 < len(arguments)]
        require(len(values) == 1, f"Cargo primary consumer rustc has no unique {option} option")
        return values[0]

    require(one_value("--crate-name") == crate_name,
            "Cargo primary consumer rustc crate name drifted")
    output_directory = physical(Path(one_value("--out-dir")), "Cargo primary consumer output directory", directory=True)
    extra_filenames = [arguments[index + 1].removeprefix("extra-filename=")
                       for index, argument in enumerate(arguments)
                       if argument == "-C" and index + 1 < len(arguments)
                       and arguments[index + 1].startswith("extra-filename=")]
    if binary_name is not None:
        require(len(extra_filenames) == 1 and re.fullmatch(r"-[0-9a-f]+", extra_filenames[0]) is not None,
                "Cargo primary consumer rustc extra filename drifted")
        expected_output = physical(output_directory / f"{crate_name}{extra_filenames[0]}",
                                   "Cargo primary consumer expected linker output")
        require(expected_output == link_output,
                "Cargo primary consumer rustc does not bind the final linker output")
    else:
        require(not extra_filenames,
                "Cargo primary cdylib rustc has an unapproved extra filename")
        require(link_output.parent == output_directory,
                "Cargo primary cdylib rustc output directory differs from its final linker output")

    externs: dict[str, dict[str, str]] = {}
    index = 0
    while index < len(arguments):
        if arguments[index] != "--extern":
            index += 1
            continue
        require(index + 1 < len(arguments), "Cargo primary consumer rustc has a malformed --extern")
        specification = arguments[index + 1]
        name_value = specification.rsplit(":", 1)[-1]
        name, separator, raw_path = name_value.partition("=")
        require(separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None,
                "Cargo primary consumer rustc has a malformed --extern")
        external = physical(Path(raw_path), f"Cargo primary consumer {name} extern")
        require(external.is_relative_to(source_library_root),
                "Cargo primary consumer rustc admits an external Rust artifact")
        require(name not in externs, f"Cargo primary consumer rustc repeats its {name} extern")
        externs[name] = record_file(external, f"Cargo primary consumer {name} extern")
        index += 2

    expected = {
        **runtime_artifacts,
        "crabc_unwinder": cargo_provider,
        DEPENDENCY_CRATE: application_dependency,
    }
    built_unwind_path = built_unwind.get("path")
    require(isinstance(built_unwind_path, str) and all(
        record.get("path") != built_unwind_path for record in externs.values()
    ), "Cargo primary consumer rustc admits the unselected source-built libunwind archive")
    require(
        set(externs) == set(expected),
        "Cargo primary consumer rustc extern closure differs from the declared source runtime/provider graph",
    )
    for name, artifact in expected.items():
        require(externs[name] == artifact,
                f"Cargo primary consumer rustc {name} extern differs from Cargo's declared artifact")
    return {
        "primary_crate": crate_name,
        "linker_output": record_file(link_output, "Cargo linker-side consumer output"),
        "externs": {name: externs[name] for name in sorted(expected)},
    }


def source_build_log_contract(log: str, rust_source: Path) -> None:
    """Require a fresh full-std source build and fat-LTO compiler invocations."""

    missing = [name for name in BUILD_STD_CRATES if f"--crate-name {name}" not in log]
    require(not missing, f"Cargo build-std log omits required Rust crates: {missing!r}")
    require(str(rust_source) in log, "Cargo build-std log does not name pinned rust-src")
    lto = "lto=fat" in log or "linker-plugin-lto" in log
    require(lto and "codegen-units=1" in log,
            "Cargo build-std log does not retain the requested fat-LTO profile")


def host_build_script_output(arguments: list[str], description: str) -> str:
    """Read the one ``-o`` output from a pinned host-link command."""

    selected: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if argument != "-o":
            continue
        require(index < len(arguments) and selected is None,
                f"{description} has an invalid output")
        selected = arguments[index]
        index += 1
    require(selected is not None, f"{description} has no output")
    return selected


def file_identity(path: Path) -> tuple[int, int]:
    """Return the physical inode identity Cargo preserves when it hard-links."""

    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino


def cargo_custom_build_artifacts(
    stream: str, rust_source: Path, host_build_root: Path, provider_custom_builds: list[dict[str, Path]] | None = None,
    composite_vendor_custom_builds: list[dict[str, Path]] | None = None,
) -> list[dict[str, Any]]:
    """Select the finite Cargo-declared host build-script artifacts.

    Cargo publishes the build-script executable as ``build-script-build`` and
    hard-links the rustc linker output named ``build_script_build-*`` to it.
    Both names must denote the same physical file; the later receipt closure
    therefore binds the provisional wrapper exception to Cargo's own record.
    """

    rust_source = physical(rust_source, "pinned rust-src library", directory=True)
    host_build_root = physical(host_build_root, "Cargo host build-script root", directory=True)
    provider_custom_builds = provider_custom_builds or []
    composite_vendor_custom_builds = composite_vendor_custom_builds or []
    approved_vendor_sources = {
        (physical(entry["manifest"], "approved Cargo vendor build manifest"),
         physical(entry["source"], "approved Cargo vendor build source"))
        for entry in [*provider_custom_builds, *composite_vendor_custom_builds]
    }
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    seen_identities: set[tuple[int, int]] = set()
    for record in cargo_json_records(stream, "Cargo host custom-build stream"):
        if record.get("reason") != "compiler-artifact":
            continue
        target = record.get("target")
        if not isinstance(target, dict) or target.get("kind") != ["custom-build"]:
            continue
        require(
            target.get("crate_types") == ["bin"] and target.get("name") == "build-script-build",
            "Cargo custom-build artifact identity drifted",
        )
        package_id = record.get("package_id")
        manifest_value = record.get("manifest_path")
        source_value = target.get("src_path")
        filenames = record.get("filenames")
        require(
            isinstance(package_id, str) and isinstance(manifest_value, str) and isinstance(source_value, str)
            and isinstance(filenames, list) and len(filenames) == 1 and isinstance(filenames[0], str)
            and record.get("executable") is None,
            "Cargo custom-build artifact record is malformed",
        )
        manifest = physical(Path(manifest_value), "Cargo custom-build manifest")
        source = physical(Path(source_value), "Cargo custom-build source")
        output = physical(Path(filenames[0]), "Cargo custom-build artifact output", executable=True)
        source_is_rust = manifest.is_relative_to(rust_source) and source.is_relative_to(rust_source)
        require(source_is_rust or (manifest, source) in approved_vendor_sources,
                "Cargo custom-build artifact is outside approved pinned source")
        require(
            output.is_relative_to(host_build_root) and output.name == "build-script-build",
            "Cargo custom-build artifact is outside the declared host root",
        )
        identity = file_identity(output)
        require(output not in seen_paths and identity not in seen_identities,
                "Cargo declared a duplicate custom-build artifact")
        seen_paths.add(output)
        seen_identities.add(identity)
        artifacts.append({
            "package_id": package_id,
            "manifest": manifest,
            "source": source,
            "output": output,
            "identity": identity,
        })
    require(artifacts, "Cargo build-std did not declare its same-triple host build-script artifacts")
    return artifacts


def host_build_script_receipts(root: Path, host_build_root: Path) -> list[dict[str, Any]]:
    """Read one exclusive receipt for every provisional host linker output."""

    root = physical(root, "Cargo host build-script receipt root", directory=True)
    host_build_root = physical(host_build_root, "Cargo host build-script root", directory=True)
    records: list[dict[str, Any]] = []
    seen_outputs: set[tuple[int, int]] = set()
    try:
        entries = sorted(root.iterdir())
    except OSError as error:
        raise OwnedCleanupError(f"Cargo host build-script receipt root is unreadable: {root}") from error
    for receipt in entries:
        require(receipt.suffix == ".json", "Cargo host build-script receipt has an unapproved name")
        receipt = physical(receipt, "Cargo host build-script receipt")
        record = json_object(receipt, "Cargo host build-script receipt")
        require(set(record) == {"schema", "kind", "linker", "command", "output"},
                "Cargo host build-script receipt fields drifted")
        require(record["schema"] == 1 and record["kind"] == "cargo-host-build-script",
                "Cargo host build-script receipt identity drifted")
        linker = record["linker"]
        command = record["command"]
        output = record["output"]
        require(
            linker == record_file(HOST_BUILD_LINKER, "pinned Cargo host build-script linker")
            and isinstance(command, list) and all(isinstance(item, str) for item in command)
            and command and command[0] == str(HOST_BUILD_LINKER),
            "Cargo host build-script linker identity drifted",
        )
        require(isinstance(output, dict) and isinstance(output.get("path"), str),
                "Cargo host build-script receipt output is malformed")
        linked = physical(Path(output["path"]), "Cargo host build-script linker output", executable=True)
        require(
            linked.is_relative_to(host_build_root)
            and HOST_BUILD_SCRIPT_OUTPUT.fullmatch(linked.name) is not None
            and output == record_file(
                linked, "Cargo host build-script linker output",
            ),
            "Cargo host build-script receipt output is outside the declared host root or drifted",
        )
        require(host_build_script_output(command[1:], "Cargo host build-script receipt command") == str(linked),
                "Cargo host build-script receipt command differs from its output")
        expected_name = hashlib.sha256(str(linked).encode()).hexdigest() + ".json"
        require(receipt.name == expected_name,
                "Cargo host build-script receipt name does not bind its output")
        identity = file_identity(linked)
        require(identity not in seen_outputs, "Cargo host build-script receipts duplicate an output")
        seen_outputs.add(identity)
        records.append({"receipt": receipt, "record": record, "output": linked, "identity": identity})
    require(records, "Cargo build-std did not retain its same-triple host build-script links")
    return records


def host_build_script_manifest(
    *, cargo_stream: str, cargo_stdout: Path, rust_source: Path, rust_source_lock: Path,
    host_build_root: Path, receipts_root: Path, output: Path, provider_custom_builds: list[dict[str, Path]] | None = None,
    composite_vendor_custom_build_inputs: list[dict[str, dict[str, str]]] | None = None,
) -> dict[str, Any]:
    """Close Cargo custom-build artifacts over their independent host receipts."""

    cargo_stdout = physical(cargo_stdout, "Cargo JSON stream")
    try:
        retained_stream = cargo_stdout.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise OwnedCleanupError(f"Cargo JSON stream is unreadable: {cargo_stdout}") from error
    require(retained_stream == cargo_stream,
            "Cargo JSON stream changed before host receipt closure")
    rust_source = physical(rust_source, "pinned rust-src library", directory=True)
    rust_source_lock = physical(rust_source_lock, "pinned rust-src lock")
    require(rust_source_lock.parent == rust_source,
            "pinned rust-src lock is outside its source library")
    provider_custom_builds = provider_custom_builds or []
    composite_vendor_custom_build_inputs = composite_vendor_custom_build_inputs or []
    composite_vendor_custom_builds = recorded_custom_build_inputs(
        composite_vendor_custom_build_inputs, "approved composite Cargo vendor build",
    )
    declared = cargo_custom_build_artifacts(
        cargo_stream, rust_source, host_build_root, provider_custom_builds, composite_vendor_custom_builds,
    )
    receipts = host_build_script_receipts(receipts_root, host_build_root)
    declared_by_identity = {entry["identity"]: entry for entry in declared}
    receipt_by_identity = {entry["identity"]: entry for entry in receipts}
    require(
        set(declared_by_identity) == set(receipt_by_identity),
        "Cargo custom-build artifact and host-link receipt closure differs",
    )
    output = Path(os.path.abspath(output))
    physical(output.parent, "Cargo host build-script manifest parent", directory=True)
    require(not output.exists() and not output.is_symlink(),
            "Cargo host build-script manifest must be fresh")
    artifacts: list[dict[str, Any]] = []
    for identity in sorted(declared_by_identity):
        artifact = declared_by_identity[identity]
        receipt = receipt_by_identity[identity]
        artifacts.append({
            "package_id": artifact["package_id"],
            "manifest": record_file(artifact["manifest"], "Cargo custom-build manifest"),
            "source": record_file(artifact["source"], "Cargo custom-build source"),
            "artifact_output": record_file(artifact["output"], "Cargo custom-build artifact output"),
            "host_link_receipt": record_file(receipt["receipt"], "Cargo host build-script receipt"),
            "host_link_output": record_file(receipt["output"], "Cargo host build-script linker output"),
        })
    manifest = {
        "schema": 3,
        "format": "crabc-owned-rust-host-build-manifest/v3",
        "cargo_stdout": record_file(cargo_stdout, "Cargo JSON stream"),
        "rust_source_library": str(rust_source),
        "rust_source_lock": record_file(rust_source_lock, "pinned rust-src lock"),
        "host_build_root": str(physical(host_build_root, "Cargo host build-script root", directory=True)),
        "provider_custom_build_inputs": [
            {
                "manifest": record_file(entry["manifest"], "approved provider build manifest"),
                "source": record_file(entry["source"], "approved provider build source"),
            }
            for entry in provider_custom_builds
        ],
        "composite_vendor_custom_build_inputs": composite_vendor_custom_build_inputs,
        "artifacts": artifacts,
    }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, sort_keys=True)
        stream.write("\n")
    return manifest


def provider_snapshot(provider: Path, toolchain: str) -> dict[str, Any]:
    archive = physical(provider / "libcrabc-unwind.a", "selected provider archive")
    provenance_path = physical(provider / "provenance.json", "selected provider provenance")
    provenance = json_object(provenance_path, "selected provider provenance")
    require(provenance.get("schema") == 1 and provenance.get("target") == TARGET,
            "provider provenance has the wrong schema or target")
    require(provenance.get("qualified") is False and provenance.get("native_build_products") is False,
            "provider provenance has an unapproved qualification or product state")
    require(provenance.get("personality_owner") == "consumer Rust std",
            "provider provenance changes Rust personality ownership")
    require(provenance.get("archive") == {"name": archive.name, "sha256": digest(archive)},
            "provider provenance does not identify the selected archive")
    require(provenance.get("unwind_abi") == sorted(build.UNWIND_ABI),
            "provider provenance changes the selected unwind ABI")
    symbols = cleanup.archive_unwind_symbols(physical(provider / "defined-symbols.txt", "provider symbol inventory"))
    require(symbols == set(provenance["unwind_abi"]), "provider symbol inventory differs from provenance")
    require(toolchain == provenance.get("toolchain"), "consumer compiler differs from selected provider compiler")
    return {
        "archive": record_file(archive, "selected provider archive"),
        "provenance": record_file(provenance_path, "selected provider provenance"),
        "record": provenance,
        "defined_unwind_abi": sorted(symbols),
    }


def source_provider_link_anchor(provider_source: Path) -> dict[str, str]:
    """Bind the generated Cargo graph to its real LTO provider anchor."""

    provider_source = physical(provider_source, "staged crabc-unwinder source")
    contents = provider_source.read_text(encoding="utf-8")
    require(
        contents.count(PROVIDER_LINK_ANCHOR_DEFINITION) == 1,
        "staged crabc-unwinder source lacks the real _Unwind_RaiseException link anchor",
    )
    return record_file(provider_source, "staged crabc-unwinder source link anchor")


def dso_thread_join_contract(host_source: Path, plugin_source: Path) -> dict[str, dict[str, str]]:
    """Require each DSO thread result to distinguish panic from expected success."""

    host_source = physical(host_source, "cleanup DSO host source")
    plugin_source = physical(plugin_source, "cleanup DSO plugin source")
    host_contents = host_source.read_text(encoding="utf-8")
    plugin_contents = plugin_source.read_text(encoding="utf-8")
    require(
        host_contents.count(DSO_HOST_POST_CLOSE_SUCCESS) == 1
        and not any(pattern in host_contents for pattern in DSO_RESULT_EQUALITIES),
        "cleanup DSO host does not match its first post-close plugin result",
    )
    require(
        plugin_contents.count(DSO_PLUGIN_WORKER_SUCCESS) == 1
        and not any(pattern in plugin_contents for pattern in DSO_RESULT_EQUALITIES),
        "cleanup DSO plugin does not match its worker cleanup result",
    )
    return {
        "host_post_close": record_file(host_source, "cleanup DSO host post-close result contract"),
        "plugin_worker": record_file(plugin_source, "cleanup DSO plugin worker result contract"),
    }


def _unique_packages(metadata: dict[str, Any], description: str) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    packages = metadata.get("packages")
    require(isinstance(packages, list) and all(isinstance(package, dict) for package in packages),
            f"{description} has no package records")
    names = [package.get("name") for package in packages]
    identifiers = [package.get("id") for package in packages]
    require(all(isinstance(name, str) for name in names) and len(names) == len(set(names)),
            f"{description} has duplicate or malformed package names")
    require(all(isinstance(identifier, str) for identifier in identifiers) and len(identifiers) == len(set(identifiers)),
            f"{description} has duplicate or malformed package identities")
    return ({package["name"]: package for package in packages}, {package["id"]: package for package in packages})


def audit_source_graph(
    metadata: dict[str, Any], lock: dict[str, Any], package_root: Path, staged: dict[str, Any],
) -> dict[str, Any]:
    """Close the generated consumer workspace over the reviewed provider graph."""

    package_root = physical(package_root, "generated source-built consumer package", directory=True)
    manifest = physical(package_root / "Cargo.toml", "generated source-built consumer manifest")
    manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    root = manifest_data.get("package")
    require(isinstance(root, dict) and isinstance(root.get("name"), str) and isinstance(root.get("version"), str),
            "generated source-built consumer manifest has no package identity")
    root_name = root["name"]
    packages, packages_by_id = _unique_packages(metadata, "source-built Cargo metadata")
    expected_names = {root_name, DEPENDENCY_PACKAGE, *SOURCE_GRAPH_PACKAGES}
    require(set(packages) == expected_names, "source-built Cargo graph has an unapproved package")
    require(packages[root_name].get("manifest_path") == str(manifest),
            "Cargo did not compile the generated source-built consumer manifest")
    staged_manifest = physical(Path(staged["manifest"]), "staged crabc-unwinder manifest")
    staged_unwinding = physical(Path(staged["staged"]), "staged unwinding source", directory=True)
    require(packages["crabc-unwinder"].get("manifest_path") == str(staged_manifest),
            "Cargo did not compile the staged crabc-unwinder root")
    require(Path(packages[build.PATCHED_UNWINDING].get("manifest_path", "")).parent == staged_unwinding,
            "Cargo did not compile the staged patched unwinding source")
    dependency_manifest = physical(package_root.parent / "cleanup-dependency/Cargo.toml",
                                   "generated cleanup dependency manifest")
    require(packages[DEPENDENCY_PACKAGE].get("manifest_path") == str(dependency_manifest)
            and packages[DEPENDENCY_PACKAGE].get("version") == DEPENDENCY_VERSION,
            "Cargo did not compile the pinned local cleanup dependency")

    records = lock.get("package")
    require(isinstance(records, list) and all(isinstance(record, dict) for record in records),
            "generated source-built lock has no package records")
    lock_names = [record.get("name") for record in records]
    require(all(isinstance(name, str) for name in lock_names) and len(lock_names) == len(set(lock_names)),
            "generated source-built lock has duplicate package names")
    locked = {record["name"]: record for record in records}
    require(set(locked) == expected_names, "generated source-built lock has an unapproved package")
    root_lock = locked[root_name]
    require(root_lock.get("version") == root["version"] and "source" not in root_lock and "checksum" not in root_lock,
            "generated source-built lock does not bind its local consumer")
    require(set(root_lock.get("dependencies", [])) == {"crabc-unwinder", DEPENDENCY_PACKAGE},
            "generated source-built lock does not bind its exact local consumer dependencies")
    dependency_lock = locked[DEPENDENCY_PACKAGE]
    require(dependency_lock.get("version") == DEPENDENCY_VERSION
            and "source" not in dependency_lock and "checksum" not in dependency_lock,
            "generated source-built lock does not bind its local cleanup dependency")

    resolve = metadata.get("resolve")
    require(isinstance(resolve, dict) and isinstance(resolve.get("nodes"), list),
            "source-built Cargo metadata has no resolve nodes")
    nodes = resolve["nodes"]
    require(all(isinstance(node, dict) and isinstance(node.get("id"), str) for node in nodes),
            "source-built Cargo metadata has malformed resolve nodes")
    node_ids = [node["id"] for node in nodes]
    require(len(node_ids) == len(set(node_ids)) and set(node_ids) == set(packages_by_id),
            "source-built Cargo resolve does not close its package graph")
    nodes_by_id = {node["id"]: node for node in nodes}
    root_id = packages[root_name]["id"]
    provider_id = packages["crabc-unwinder"]["id"]
    dependency_id = packages[DEPENDENCY_PACKAGE]["id"]
    require(set(nodes_by_id[root_id].get("dependencies", [])) == {provider_id, dependency_id},
            "generated consumer dependency IDs differ from the provider and cleanup crate")
    root_deps = nodes_by_id[root_id].get("deps")
    require(isinstance(root_deps, list) and len(root_deps) == 2
            and all(isinstance(item, dict) for item in root_deps)
            and {(item.get("name"), item.get("pkg")) for item in root_deps}
            == {("crabc_unwinder", provider_id), (DEPENDENCY_CRATE, dependency_id)},
            "generated consumer does not use the exact provider and cleanup dependencies")
    require(not nodes_by_id[dependency_id].get("dependencies"),
            "local cleanup dependency has an unapproved dependency closure")
    provider_dependencies = {packages_by_id.get(identifier, {}).get("name") for identifier in nodes_by_id[provider_id].get("dependencies", [])}
    require(provider_dependencies == set(build.PINS), "staged crabc-unwinder dependency closure drifted")

    projected_metadata = {
        "packages": [packages[name] for name in sorted(SOURCE_GRAPH_PACKAGES)],
        "resolve": {"nodes": [nodes_by_id[packages[name]["id"]] for name in sorted(SOURCE_GRAPH_PACKAGES)]},
    }
    projected_lock = {"package": [locked[name] for name in sorted(SOURCE_GRAPH_PACKAGES)]}
    build.audit_graph(projected_metadata, projected_lock, patched_unwinding=True)
    build.verify_staged_patched_unwinding(staged)
    libc_targets = packages["libc"].get("targets")
    require(isinstance(libc_targets, list), "Cargo libc package has no targets")
    provider_custom_builds: list[dict[str, Path]] = []
    for target in libc_targets:
        require(isinstance(target, dict), "Cargo libc package has a malformed target")
        if target.get("kind") != ["custom-build"]:
            continue
        source = target.get("src_path")
        require(isinstance(source, str), "Cargo libc custom build has no source")
        provider_custom_builds.append({
            "manifest": physical(Path(packages["libc"]["manifest_path"]), "Cargo libc manifest"),
            "source": physical(Path(source), "Cargo libc custom-build source"),
        })
    require(len(provider_custom_builds) == 1,
            "Cargo source-built provider graph has an unexpected custom-build roster")
    provider_source = staged_manifest.parent / "src/lib.rs"
    return {
        "root_package_id": root_id,
        "provider_package_id": provider_id,
        "application_dependency_package_id": dependency_id,
        "application_dependency_manifest": record_file(dependency_manifest, "generated cleanup dependency manifest"),
        "application_dependency_source": record_file(dependency_manifest.parent / "src/lib.rs", "generated cleanup dependency source"),
        "provider_manifest": record_file(staged_manifest, "staged crabc-unwinder manifest"),
        "provider_source": record_file(provider_source, "staged crabc-unwinder source"),
        "provider_link_anchor": source_provider_link_anchor(provider_source),
        "patched_unwinding_manifest": record_file(staged_unwinding / "Cargo.toml", "staged patched unwinding manifest"),
        "source_input": str(Path(staged["source_input"])),
        "upstream_tree_sha256": staged["upstream_tree_sha256"],
        "patched_tree_sha256": staged["patched_tree_sha256"],
        "patches": staged["patches"],
        "provider_custom_builds": provider_custom_builds,
    }


def _toml_path(path: Path, description: str, *, directory: bool = False) -> str:
    value = str(physical(path, description, directory=directory))
    require('"' not in value and "\\" not in value and "\n" not in value,
            f"{description} cannot be represented in the generated Cargo manifest")
    return value


def _write_anchored_source(source: Path, output: Path, marker: str, description: str) -> dict[str, dict[str, str]]:
    source = physical(source, f"{description} source")
    contents = source.read_text(encoding="utf-8")
    require(contents.count(marker) == 1, f"{description} has no unique anchor insertion point")
    rendered = contents.replace(marker, marker + "\n    std::hint::black_box(crabc_unwinder::link_anchor());", 1)
    if output.parent.exists() or output.parent.is_symlink():
        physical(output.parent, f"generated {description} source parent", directory=True)
    else:
        output.parent.mkdir(parents=True, mode=0o755)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(rendered)
    output = physical(output, f"generated {description} source")
    return {"source": record_file(source, f"{description} source"), "generated": record_file(output, f"generated {description} source")}


def prepare_source_graph_package(
    application: Path, package: Path, staged: dict[str, Any], with_plugin: bool,
) -> dict[str, Any]:
    """Copy one fixed fixture into a fresh workspace with the staged provider edge."""

    application = physical(application, "source-built consumer application", directory=True)
    package = physical(package, "source-built fixture package", directory=True)
    manifest_source = physical(package / "Cargo.toml", "source-built fixture manifest")
    lock_source = physical(package / "Cargo.lock", "source-built fixture lock")
    fixture_manifest = tomllib.loads(manifest_source.read_text(encoding="utf-8"))
    fixture_dependencies = fixture_manifest.get("dependencies")
    require(isinstance(fixture_dependencies, dict)
            and fixture_dependencies == {DEPENDENCY_PACKAGE: {"path": "../cleanup-dependency"}}
            and "patch" not in fixture_manifest,
            "source-built fixture dependency graph differs from the cleanup crate")
    root = application / "cargo-package"
    require(not root.exists() and not root.is_symlink(), "generated source-built consumer package must be fresh")
    root.mkdir(mode=0o755)
    staged_manifest = Path(staged["manifest"])
    staged_unwinding = Path(staged["staged"])
    manifest_text = manifest_source.read_text(encoding="utf-8").rstrip()
    dependency_section = re.search(r"(?m)^\[dependencies\]\s*$", manifest_text)
    require(dependency_section is not None, "source-built fixture lost its cleanup dependency section")
    next_section = re.search(r"(?m)^\[", manifest_text[dependency_section.end():])
    insertion = dependency_section.end() + (next_section.start() if next_section else len(manifest_text[dependency_section.end():]))
    provider_dependency = (
        f"\ncrabc-unwinder = {{ path = \"{_toml_path(staged_manifest.parent, 'staged crabc-unwinder source', directory=True)}\" }}\n"
    )
    manifest_text = manifest_text[:insertion].rstrip() + provider_dependency + manifest_text[insertion:]
    rendered_manifest = (
        manifest_text + "\n\n[patch.crates-io]\n"
        f"unwinding = {{ path = \"{_toml_path(staged_unwinding, 'staged patched unwinding source', directory=True)}\" }}\n"
    )
    generated_manifest = root / "Cargo.toml"
    generated_manifest.write_text(rendered_manifest, encoding="utf-8")
    sources: list[dict[str, dict[str, str]]] = []
    dependency_target = application / "cleanup-dependency"
    dependency_target.mkdir(mode=0o755)
    dependency_sources = []
    for relative in ("Cargo.toml", "src/lib.rs"):
        source_path = physical(DEPENDENCY_FIXTURE / relative, "pinned cleanup dependency source")
        target_path = dependency_target / relative
        if target_path.parent != dependency_target:
            target_path.parent.mkdir(mode=0o755)
        shutil.copyfile(source_path, target_path)
        dependency_sources.append({
            "source": record_file(source_path, "pinned cleanup dependency source"),
            "generated": record_file(target_path, "generated cleanup dependency source"),
        })
    sources.extend(dependency_sources)
    if package == BUILD_STD_FIXTURE:
        sources.append(_write_anchored_source(
            package / "src/main.rs", root / "src/main.rs", "fn main() {", "dependency cleanup fixture",
        ))
    elif package == BUILD_STD_DSO_FIXTURE and with_plugin:
        thread_join_contracts = dso_thread_join_contract(package / "src/main.rs", package / "src/plugin.rs")
        sources.append(_write_anchored_source(package / "src/main.rs", root / "src/main.rs", "fn main() {", "cleanup DSO host"))
        sources.append(_write_anchored_source(
            package / "src/plugin.rs", root / "src/plugin.rs",
            "pub extern \"C\" fn crabc_owned_cleanup_dso() -> i32 {", "cleanup DSO plugin",
        ))
    else:
        raise OwnedCleanupError("source-built fixture has no approved Cargo graph adapter")
    result = {
        "root": physical(root, "generated source-built consumer package", directory=True),
        "fixture_manifest": record_file(manifest_source, "source-built fixture manifest"),
        "fixture_lock": record_file(lock_source, "source-built fixture lock"),
        "generated_manifest": record_file(generated_manifest, "generated source-built consumer manifest"),
        "sources": sources,
    }
    if package == BUILD_STD_DSO_FIXTURE and with_plugin:
        result["thread_join_contracts"] = thread_join_contracts
    return result


def cargo_graph_provider_artifact(
    stream: str, *, target: Path, provider_package_id: str, provider_source: Path,
) -> Path:
    """Select the one provider rlib Cargo actually compiled for this consumer."""

    target = physical(target, "source-built Cargo target", directory=True)
    provider_source = physical(provider_source, "staged crabc-unwinder source")
    selected: list[Path] = []
    for record in cargo_json_records(stream, "Cargo provider artifact stream"):
        if record.get("reason") != "compiler-artifact":
            continue
        target_record = record.get("target")
        if record.get("package_id") != provider_package_id or not isinstance(target_record, dict):
            continue
        require(
            target_record.get("name") == "crabc_unwinder" and target_record.get("kind") == ["rlib"]
            and target_record.get("crate_types") == ["rlib"] and target_record.get("src_path") == str(provider_source),
            "Cargo provider artifact identity drifted",
        )
        filenames = record.get("filenames")
        require(isinstance(filenames, list) and record.get("executable") is None,
                "Cargo provider artifact has malformed outputs")
        for filename in filenames:
            if isinstance(filename, str) and filename.endswith(".rlib"):
                artifact = physical(Path(filename), "Cargo crabc-unwinder archive")
                require(artifact.is_relative_to(target), "Cargo crabc-unwinder archive escapes its target directory")
                selected.append(artifact)
    require(len(selected) == 1, f"expected one Cargo crabc-unwinder archive, found {selected!r}")
    return selected[0]


def source_graph_profile_contract(log: str) -> None:
    """The generated workspace must override the standalone provider abort profile."""

    provider_lines = [line for line in log.splitlines() if "--crate-name crabc_unwinder" in line]
    require(len(provider_lines) == 1, "Cargo log does not retain one crabc-unwinder compiler invocation")
    provider_line = provider_lines[0]
    require("panic=unwind" in provider_line and "panic=abort" not in provider_line,
            "source-built crabc-unwinder did not inherit the consumer unwind profile")
    require(("lto=fat" in provider_line or "linker-plugin-lto" in provider_line) and "codegen-units=1" in provider_line,
            "source-built crabc-unwinder did not inherit the consumer fat-LTO profile")


def source_graph_provider(
    *, application: Path, package: Path, channel: str, environment: dict[str, str], with_plugin: bool,
    offline_sources: dict[str, Any],
) -> dict[str, Any]:
    """Stage and audit one patched provider as a dependency of one consumer workspace."""

    application = physical(application, "source-built provider application", directory=True)
    source_manifest = physical(ROOT / "Cargo.toml", "checked-in crabc-unwinder manifest")
    source_lock = physical(ROOT / "Cargo.lock", "checked-in crabc-unwinder lock")
    source_command: list[str | Path] = [
        "rustup", "run", channel, "cargo", "metadata", "--manifest-path", source_manifest,
        "--locked", "--offline", "--format-version=1", "--filter-platform", TARGET,
    ]
    source_stdout, _ = run_logged_streams(
        source_command, environment, application / "provider-source-metadata.json", application / "provider-source-metadata.stderr.log",
        "checked-in crabc-unwinder graph audit",
    )
    try:
        source_metadata = json.loads(source_stdout)
    except json.JSONDecodeError as error:
        raise OwnedCleanupError("checked-in crabc-unwinder metadata is not JSON") from error
    require(isinstance(source_metadata, dict), "checked-in crabc-unwinder metadata is not an object")
    source_packages = build.audit_graph(source_metadata, tomllib.loads(source_lock.read_text(encoding="utf-8")))
    registry_source = provider_registry_unwinding_source(application, offline_sources)
    offline_sources["provider_registry_source"] = registry_source
    source_packages[build.PATCHED_UNWINDING] = dict(source_packages[build.PATCHED_UNWINDING])
    source_packages[build.PATCHED_UNWINDING]["manifest_path"] = registry_source["registry_manifest"]["path"]
    # The checkout is read-only for supplied-product consumers. Keep this
    # second private provider derivative beside the authenticated Cargo vendor
    # conversion, beneath the already validated per-consumer application.
    stage_root = work_child(application / "unwinder-source-inputs", "private patched unwinding stage root")
    staged = build.stage_patched_unwinding(source_packages, stage_root=stage_root)
    build.verify_staged_patched_unwinding(staged)
    prepared = prepare_source_graph_package(application, package, staged, with_plugin)
    generated_manifest = Path(prepared["root"]) / "Cargo.toml"
    run_logged(
        ["rustup", "run", channel, "cargo", "generate-lockfile", "--offline", "--manifest-path", generated_manifest], environment,
        application / "provider-generated-lock.log", "generated source-built provider lock",
    )
    generated_lock = physical(Path(prepared["root"]) / "Cargo.lock", "generated source-built provider lock")
    metadata_command: list[str | Path] = [
        "rustup", "run", channel, "cargo", "metadata", "--manifest-path", generated_manifest,
        "--locked", "--offline", "--format-version=1", "--filter-platform", TARGET,
    ]
    metadata_stdout, _ = run_logged_streams(
        metadata_command, environment, application / "provider-graph-metadata.json", application / "provider-graph-metadata.stderr.log",
        "generated source-built provider graph audit",
    )
    try:
        metadata = json.loads(metadata_stdout)
    except json.JSONDecodeError as error:
        raise OwnedCleanupError("generated source-built provider metadata is not JSON") from error
    require(isinstance(metadata, dict), "generated source-built provider metadata is not an object")
    graph = audit_source_graph(metadata, tomllib.loads(generated_lock.read_text(encoding="utf-8")), Path(prepared["root"]), staged)
    receipt = {
        "fixture": {
            "root": str(prepared["root"]),
            "fixture_manifest": prepared["fixture_manifest"],
            "fixture_lock": prepared["fixture_lock"],
            "generated_manifest": prepared["generated_manifest"],
            "sources": prepared["sources"],
        },
        "provider": {
            key: value for key, value in graph.items() if key != "provider_custom_builds"
        },
        "provider_custom_build_inputs": [
            {
                "manifest": record_file(entry["manifest"], "Cargo libc manifest"),
                "source": record_file(entry["source"], "Cargo libc custom-build source"),
            }
            for entry in graph["provider_custom_builds"]
        ],
        "source_manifest": record_file(source_manifest, "checked-in crabc-unwinder manifest"),
        "source_lock": record_file(source_lock, "checked-in crabc-unwinder lock"),
        "source_metadata": record_file(application / "provider-source-metadata.json", "checked-in crabc-unwinder metadata"),
        "generated_lock": record_file(generated_lock, "generated source-built provider lock"),
        "generated_lock_log": record_file(application / "provider-generated-lock.log", "generated source-built provider lock log"),
        "metadata": record_file(application / "provider-graph-metadata.json", "generated source-built provider metadata"),
        "offline_sources": offline_sources,
        "commands": {
            "source_metadata": [str(item) for item in source_command],
            "generate_lockfile": [
                "rustup", "run", channel, "cargo", "generate-lockfile", "--offline",
                "--manifest-path", str(generated_manifest),
            ],
            "generated_metadata": [str(item) for item in metadata_command],
        },
    }
    if "thread_join_contracts" in prepared:
        receipt["fixture"]["thread_join_contracts"] = prepared["thread_join_contracts"]
    return {
        "package": prepared,
        "graph": graph,
        "receipt": receipt,
    }


def compile_mode(
    *, mode: str, root: Path, provider: dict[str, Any], channel: str, output: Path,
) -> dict[str, Any]:
    application = output / mode
    application.mkdir(mode=0o755)
    binary = application / "cleanup"
    stock_libdir = Path(run_logged(
        ["rustup", "run", channel, "rustc", "--target", TARGET, "--print", "target-libdir"],
        clean_environment(), application / "target-libdir.log", f"{mode} target-library discovery",
    ).strip())
    stock_libdir = physical(stock_libdir, f"{mode} stock target library directory", directory=True)
    environment = clean_environment()
    environment.update({
        "CRABC_OWNED_RUST_LINK_MODE": mode,
        "CRABC_OWNED_RUST_PRODUCT": str(root),
        "CRABC_OWNED_RUST_PROVIDER": str(provider["archive"]["path"]),
        "CRABC_OWNED_RUST_STOCK_LIBDIR": str(stock_libdir),
        "CRABC_OWNED_RUST_APPLICATION_ROOT": str(application),
        "CRABC_OWNED_RUST_CHANNEL": channel,
    })
    rust_arguments: list[str | Path] = [
        "rustup", "run", channel, "rustc", "--edition=2024", "--target", TARGET,
        "-C", "panic=unwind", "-C", "force-unwind-tables=yes",
        # The owned linker selects either static or dynamic crabc inputs.
        # Rust's musl defaults would inject its bundled CRT objects and native
        # unwind archive before that boundary, which must reject them.
        "-C", "link-self-contained=no", "-C", "target-feature=-crt-static",
        "-C", f"linker={ROOT / 'owned_rust_link.py'}", "-C", "link-arg=-Wl,--eh-frame-hdr",
    ]
    if mode == "static":
        rust_arguments.extend(("-C", "relocation-model=static"))
    rust_arguments.extend((FIXTURE, "-o", binary))
    run_logged(rust_arguments, environment, application / "compile.log", f"{mode} full Rust cleanup compile")
    binary = physical(binary, f"{mode} cleanup executable", executable=True)
    link_receipt_path = physical(Path(str(binary) + ".crabc-owned-rust-link.json"), f"{mode} link receipt")
    link_receipt = json_object(link_receipt_path, f"{mode} link receipt")
    require(link_receipt.get("mode") == mode and link_receipt.get("output") == record_file(binary, f"{mode} cleanup executable"),
            f"{mode} link receipt does not identify this executable")
    if link_receipt.get("provider_archive") != provider["archive"]:
        raise OwnedCleanupError(f"{mode} link receipt does not retain the selected provider archive")
    assert_nonpromoting(link_receipt, f"{mode} link receipt")
    trace = link_receipt.get("resolved_input_trace")
    command = link_receipt.get("command")
    require(isinstance(trace, str) and isinstance(command, list) and all(isinstance(item, str) for item in command),
            f"{mode} link receipt lacks exact command or trace")
    forbidden = ("libgcc", "libunwind", "-lgcc", "-lunwind", "-lc")
    require(not any(token in str(item) for item in command for token in forbidden),
            f"{mode} linker command admits an ambient native runtime request")
    require("libcrabc-unwind.a" in trace and not any(token in trace for token in ("libgcc", "libunwind")),
            f"{mode} link trace does not prove the selected provider without ambient unwind runtimes")
    return {
        "mode": mode,
        "stock_target_libdir": str(stock_libdir),
        "compile_log": record_file(application / "compile.log", f"{mode} compile log"),
        "target_libdir_log": record_file(application / "target-libdir.log", f"{mode} target library log"),
        "link_receipt": record_file(link_receipt_path, f"{mode} link receipt"),
        "link_command": command,
        "link_trace": trace,
        "binary": record_file(binary, f"{mode} cleanup executable"),
    }


def compile_source_built_mode(
    *, label: str, mode: str, root: Path, channel: str, output: Path,
    package: Path, binary_name: str, with_plugin: bool, provider_vendor_root: Path,
) -> dict[str, Any]:
    """Build a fresh full std through Cargo, then bind each final owned link."""

    application = output / label
    application.mkdir(mode=0o755)
    target = application / "cargo-target"
    release = target / TARGET / "release"
    source_library_root = release / "deps"
    host_build_root = target / "release/build"
    temporary = application / "tmp"
    cargo_home = application / "cargo-home"
    for directory in (source_library_root, host_build_root, temporary, cargo_home):
        directory.mkdir(parents=True, mode=0o755)
    host_build_receipt_root = application / "host-build-link-receipts"
    host_build_receipt_root.mkdir(mode=0o755)
    host_build_manifest_path = application / "host-build-manifest.json"
    rust_sysroot = Path(run_logged(
        ["rustup", "run", channel, "rustc", "--print", "sysroot"], clean_environment(),
        application / "rust-sysroot.log", f"{label} Rust sysroot discovery",
    ).strip())
    toolchain_search_root = Path(run_logged(
        ["rustup", "run", channel, "rustc", "--target", TARGET, "--print", "target-libdir"], clean_environment(),
        application / "toolchain-target-libdir.log", f"{label} Rust target-library discovery",
    ).strip())
    toolchain_search_root = physical(
        toolchain_search_root, f"{label} declared Rust toolchain search root", directory=True,
    )
    rust_source = physical(
        rust_sysroot / "lib/rustlib/src/rust/library", f"{label} pinned rust-src library", directory=True,
    )
    rust_source_lock = physical(rust_source / "Cargo.lock", f"{label} pinned rust-src lock")
    environment = clean_environment()
    environment.update({
        **SERIAL_BUILD_ENVIRONMENT,
        **SOURCE_BUILD_PROFILE,
        "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(SOURCE_BUILD_RUSTFLAGS),
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER": str(ROOT / "owned_rust_link.py"),
        "CRABC_OWNED_RUST_LINK_MODE": mode,
        "CRABC_OWNED_RUST_PRODUCT": str(root),
        "CRABC_OWNED_RUST_SOURCE_BUILT_LIBDIR": str(source_library_root),
        "CRABC_OWNED_RUST_TOOLCHAIN_SEARCH_ROOT": str(toolchain_search_root),
        "CRABC_OWNED_RUST_SOURCE_LTO_UNWIND_ABI": json.dumps(sorted(build.UNWIND_ABI)),
        "CRABC_OWNED_RUST_APPLICATION_ROOT": str(release),
        "CRABC_OWNED_RUST_HOST_BUILD_ROOT": str(host_build_root),
        "CRABC_OWNED_RUST_HOST_BUILD_LINKER": str(HOST_BUILD_LINKER),
        "CRABC_OWNED_RUST_HOST_BUILD_RECEIPTS": str(host_build_receipt_root),
        "CRABC_OWNED_RUST_CHANNEL": channel,
        "TMPDIR": str(temporary),
    })
    offline_sources = prepare_offline_cargo_sources(application, rust_source, provider_vendor_root, cargo_home)
    provider_graph = source_graph_provider(
        application=application, package=package, channel=channel, environment=environment, with_plugin=with_plugin,
        offline_sources=offline_sources,
    )
    generated_package = Path(provider_graph["package"]["root"])
    command: list[str | Path] = [
        "rustup", "run", channel, "cargo", "build", "--manifest-path", generated_package / "Cargo.toml", "--release",
        "--target", TARGET, "--locked", "--offline", "-Zbuild-std=std,panic_unwind", "-vv",
        "--message-format=json-render-diagnostics", "--bin", binary_name,
    ]
    if with_plugin:
        command.append("--lib")
    stdout, stderr = run_logged_streams(
        command, environment, application / "cargo.stdout.jsonl", application / "cargo.stderr.log",
        f"{label} source-built Rust std cleanup compile",
    )
    source_build_log_contract(stdout + stderr, rust_source)
    source_graph_profile_contract(stdout + stderr)
    build.verify_staged_patched_unwinding({
        "staged": Path(provider_graph["graph"]["patched_unwinding_manifest"]["path"]).parent,
        "patched_tree_sha256": provider_graph["graph"]["patched_tree_sha256"],
        "patches": provider_graph["graph"]["patches"],
    })
    host_build_script_manifest(
        cargo_stream=stdout,
        cargo_stdout=application / "cargo.stdout.jsonl",
        rust_source=rust_source,
        rust_source_lock=rust_source_lock,
        host_build_root=host_build_root,
        receipts_root=host_build_receipt_root,
        output=host_build_manifest_path,
        provider_custom_builds=provider_graph["graph"]["provider_custom_builds"],
        composite_vendor_custom_build_inputs=offline_sources["composite_vendor_custom_build_inputs"],
    )
    cargo_provider = cargo_graph_provider_artifact(
        stdout, target=target, provider_package_id=provider_graph["graph"]["provider_package_id"],
        provider_source=Path(provider_graph["graph"]["provider_source"]["path"]),
    )
    cargo_provider_record = record_file(cargo_provider, f"{label} Cargo crabc-unwinder archive")
    runtime_archives = cargo_build_std_runtime_artifacts(stdout, target, rust_source)
    runtime_archive_records = {
        name: record_file(archive, f"{label} Cargo build-std {name} archive")
        for name, archive in runtime_archives.items()
    }
    built_unwind = cargo_build_std_unwind_artifact(stdout, target, rust_source)
    built_unwind_record = record_file(built_unwind, f"{label} Cargo build-std unwind archive")
    application_dependency = cargo_application_dependency_artifact(
        stdout, package_root=generated_package, target=target,
    )
    application_dependency_record = record_file(
        application_dependency, f"{label} Cargo cleanup dependency archive",
    )
    binary = cargo_artifact(stdout, package=generated_package, target=target, name=binary_name, crate_type="bin")
    binary = physical(binary, f"{label} source-built cleanup executable", executable=True)
    binary_receipt_path, binary_link_output = cargo_link_receipt_for_artifact(
        binary, source_library_root, f"{label} source-built cleanup executable",
    )
    cargo_lto_externs = cargo_source_lto_extern_closure(
        stderr, target_name=binary_name, binary_name=binary_name, link_output=binary_link_output,
        source_library_root=source_library_root, runtime_artifacts=runtime_archive_records,
        cargo_provider=cargo_provider_record, application_dependency=application_dependency_record,
        built_unwind=built_unwind_record,
    )
    binary_receipt = source_built_link_receipt(
        binary_receipt_path, binary_link_output, source_library_root, f"{label} source-built cleanup link receipt",
        toolchain_search_root, built_unwind_record,
    )
    consumer: dict[str, Any] = {
        "mode": mode,
        "rust_library_origin": "source-built",
        "lto": "fat",
        "cargo_command": [str(item) for item in command],
        "cargo_stdout": record_file(application / "cargo.stdout.jsonl", f"{label} Cargo JSON stream"),
        "cargo_stderr": record_file(application / "cargo.stderr.log", f"{label} Cargo diagnostics"),
        "rust_sysroot_log": record_file(application / "rust-sysroot.log", f"{label} Rust sysroot log"),
        "toolchain_search_root": str(toolchain_search_root),
        "toolchain_target_libdir_log": record_file(
            application / "toolchain-target-libdir.log", f"{label} Rust target-library log",
        ),
        "rust_source_library": str(rust_source),
        "rust_source_lock": record_file(rust_source_lock, f"{label} pinned rust-src lock"),
        "source_built_target_library_root": str(source_library_root),
        "offline_sources": offline_sources,
        "cargo_source_lto_runtime_artifacts": runtime_archive_records,
        "cargo_application_dependency": application_dependency_record,
        "cargo_source_lto_extern_closure": cargo_lto_externs,
        "cargo_graph_provider": cargo_provider_record,
        "built_but_unselected_source_built_rust_unwind": built_unwind_record,
        "provider_graph": provider_graph["receipt"],
        "host_build_script_manifest": record_file(
            host_build_manifest_path, f"{label} Cargo host build-script manifest",
        ),
        "binary": record_file(binary, f"{label} source-built cleanup executable"),
        "link_receipt": record_file(binary_receipt_path, f"{label} source-built cleanup link receipt"),
        "link_command": binary_receipt["command"],
        "link_trace": binary_receipt["resolved_input_trace"],
    }
    if with_plugin:
        plugin = cargo_artifact(
            stdout, package=generated_package, target=target, name="crabc_owned_cleanup_plugin", crate_type="cdylib",
        )
        plugin = physical(plugin, f"{label} source-built cleanup plugin")
        plugin_receipt_path, plugin_link_output = cargo_link_receipt_for_artifact(
            plugin, source_library_root, f"{label} source-built cleanup plugin",
        )
        plugin_receipt = source_built_link_receipt(
            plugin_receipt_path, plugin_link_output, source_library_root,
            f"{label} source-built cleanup plugin link receipt", toolchain_search_root, built_unwind_record,
        )
        plugin_lto_externs = cargo_source_lto_extern_closure(
            stderr, target_name="crabc_owned_cleanup_plugin", binary_name=None, link_output=plugin_link_output,
            source_library_root=source_library_root, runtime_artifacts=runtime_archive_records,
            cargo_provider=cargo_provider_record, application_dependency=application_dependency_record,
            built_unwind=built_unwind_record,
        )
        require(plugin_receipt.get("rust_requested_mode") == "shared",
                f"{label} source-built cleanup plugin was not linked as a shared object")
        consumer["plugin"] = {
            "binary": record_file(plugin, f"{label} source-built cleanup plugin"),
            "link_receipt": record_file(plugin_receipt_path, f"{label} source-built cleanup plugin link receipt"),
            "link_command": plugin_receipt["command"],
            "link_trace": plugin_receipt["resolved_input_trace"],
            "cargo_source_lto_extern_closure": plugin_lto_externs,
        }
    return consumer


def binary_unwind_symbols(binary: Path, environment: dict[str, str], log: Path, description: str) -> list[str]:
    symbols = run_logged(["nm", "--defined-only", binary], environment, log, description)
    return sorted({
        line.split()[-1] for line in symbols.splitlines()
        if len(line.split()) >= 3 and line.split()[-1].startswith("_Unwind_")
    })


def execute_mode(mode: str, consumer: dict[str, Any], dynamic_root: Path, output: Path) -> None:
    binary = Path(consumer["binary"]["path"])
    environment = clean_environment()
    if mode == "static":
        command: list[str | Path] = [binary]
    else:
        loader = physical(dynamic_root / "lib/ld-crabc-x86_64.so.1", "owned dynamic loader", executable=True)
        command = [loader, "--library-path", dynamic_root / "usr/lib", binary]
    result = subprocess.run([str(item) for item in command], env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / "execution.stdout").write_text(result.stdout, encoding="utf-8")
    (output / "execution.stderr").write_text(result.stderr, encoding="utf-8")
    cleanup.assert_execution(result.returncode, result.stdout + result.stderr)
    consumer["execution"] = {
        "command": [str(item) for item in command],
        "status": result.returncode,
        "stdout": record_file(output / "execution.stdout", f"{mode} execution stdout"),
        "stderr": record_file(output / "execution.stderr", f"{mode} execution stderr"),
    }


def execute_dso_mode(consumer: dict[str, Any], dynamic_root: Path, output: Path) -> None:
    """Load the Rust cleanup plugin by SONAME through the owned loader path."""

    plugin = Path(consumer["plugin"]["binary"]["path"])
    binary = Path(consumer["binary"]["path"])
    loader = physical(dynamic_root / "lib/ld-crabc-x86_64.so.1", "owned dynamic loader", executable=True)
    library_path = f"{plugin.parent}:{dynamic_root / 'usr/lib'}"
    command: list[str | Path] = [loader, "--library-path", library_path, binary]
    result = subprocess.run([str(item) for item in command], env=clean_environment(), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / "execution.stdout").write_text(result.stdout, encoding="utf-8")
    (output / "execution.stderr").write_text(result.stderr, encoding="utf-8")
    require(
        result.returncode == 0
        and result.stdout == "unwind: backtrace cleanup payload main thread dso\n" * 2
        and result.stderr == "",
        "source-built Rust cleanup DSO execution did not prove retained post-close cleanup",
    )
    consumer["execution"] = {
        "command": [str(item) for item in command],
        "status": result.returncode,
        "stdout": record_file(output / "execution.stdout", "source-built DSO execution stdout"),
        "stderr": record_file(output / "execution.stderr", "source-built DSO execution stderr"),
    }


def source_snapshot() -> list[dict[str, str]]:
    return [
        {"path": source.relative_to(CHECKOUT).as_posix(), "sha256": digest(source)}
        for source in SOURCE_INPUTS
    ]


def run_source_graph_preflight(provider_vendor_root: Path, output: Path | None = None) -> Path:
    """Exercise the generated provider workspace through Cargo without compiling it.

    This development gate authenticates the same complete offline source closure
    and runs both metadata passes plus lock generation that the source-built
    static consumer uses.  It deliberately stops before rustc or the owned
    linker, leaving the real source-built static round trip as the next judge.
    """

    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "native Linux/x86-64 required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source_before = source_snapshot()
    WORK.mkdir(parents=True, exist_ok=True)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="source-graph-preflight-", dir=WORK))
        output.chmod(0o755)
    else:
        output = work_child(output, "source-built Cargo provider preflight output")
        output.mkdir(mode=0o755)
    output = physical(output, "source-built Cargo provider preflight output", directory=True)
    application = output / "source-graph-preflight"
    application.mkdir(mode=0o755)
    cargo_home = application / "cargo-home"
    target = application / "cargo-target"
    temporary = application / "tmp"
    for directory in (cargo_home, target, temporary):
        directory.mkdir(mode=0o755)
    channel = tomllib.loads((CHECKOUT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    rust_sysroot = Path(run_logged(
        ["rustup", "run", channel, "rustc", "--print", "sysroot"], clean_environment(),
        application / "rust-sysroot.log", "source-built Cargo provider preflight Rust sysroot discovery",
    ).strip())
    rust_source = physical(
        rust_sysroot / "lib/rustlib/src/rust/library", "source-built Cargo provider preflight pinned rust-src library",
        directory=True,
    )
    rust_source_lock = physical(
        rust_source / "Cargo.lock", "source-built Cargo provider preflight pinned rust-src lock",
    )
    environment = clean_environment()
    environment.update({
        **SERIAL_BUILD_ENVIRONMENT,
        **SOURCE_BUILD_PROFILE,
        "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(SOURCE_BUILD_RUSTFLAGS),
        "TMPDIR": str(temporary),
    })
    offline_sources = prepare_offline_cargo_sources(application, rust_source, provider_vendor_root, cargo_home)
    provider_graph = source_graph_provider(
        application=application, package=BUILD_STD_FIXTURE, channel=channel, environment=environment,
        with_plugin=False, offline_sources=offline_sources,
    )
    require(source_snapshot() == source_before, "owned Rust consumer source changed during Cargo provider preflight")
    receipt = {
        "schema": 1,
        "scope": "owned source-built Rust provider Cargo graph preflight development",
        "source_inputs": source_before,
        "rust_sysroot_log": record_file(
            application / "rust-sysroot.log", "source-built Cargo provider preflight Rust sysroot log",
        ),
        "rust_source_library": str(rust_source),
        "rust_source_lock": record_file(
            rust_source_lock, "source-built Cargo provider preflight pinned rust-src lock",
        ),
        "offline_sources": offline_sources,
        "provider_graph": provider_graph["receipt"],
        "qualified": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
        "limitations": [
            "this preflight runs Cargo metadata and lock generation only; it does not compile, link, or execute a consumer",
            "the source-built static cleanup round trip remains required before any consumer behavior claim",
        ],
    }
    receipt_path = output / "receipt.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return output


def run_source_built_static(static_root: Path, provider_vendor_root: Path, output: Path | None = None) -> Path:
    """Run the smallest real source-built Rust std/provider round trip."""

    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "native Linux/x86-64 required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source_before = source_snapshot()
    static = product_snapshot(static_root, "static")
    WORK.mkdir(parents=True, exist_ok=True)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="source-static-", dir=WORK))
        output.chmod(0o755)
    else:
        output = work_child(output, "source-built static Rust cleanup output")
        output.mkdir(mode=0o755)
    output = physical(output, "source-built static Rust cleanup output", directory=True)
    channel = tomllib.loads((CHECKOUT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    consumer = compile_source_built_mode(
        label="source-built-static", mode="static", root=Path(static["root"]), channel=channel,
        output=output, package=BUILD_STD_FIXTURE, binary_name=BUILD_STD_BINARY, with_plugin=False,
        provider_vendor_root=provider_vendor_root,
    )
    binary = Path(consumer["binary"]["path"])
    symbols = binary_unwind_symbols(
        binary, clean_environment(), output / "source-built-static" / "symbols.log",
        "source-built static cleanup symbol inventory",
    )
    cleanup.assert_binary_unwind_symbols(set(symbols), set(build.UNWIND_ABI))
    consumer["defined_unwind_abi"] = symbols
    consumer["symbols_log"] = record_file(
        output / "source-built-static" / "symbols.log", "source-built static cleanup symbol inventory",
    )
    execute_mode("static", consumer, Path(static["root"]), output / "source-built-static")
    assert_same_product(static, "static")
    require(source_snapshot() == source_before, "owned Rust consumer source changed during collection")
    receipt = {
        "schema": 1,
        "scope": "owned static source-built Rust std fat-LTO cleanup consumer development",
        "source_inputs": source_before,
        "fixture": record_file(FIXTURE, "full Rust cleanup fixture"),
        "product": static,
        "source_built_consumer": consumer,
        "qualified": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
        "limitations": [
            "this focused static consumer does not package the provider or qualify source-built Rust std distribution",
            "dynamic, DSO, stock-Rust, complete malformed unwind-metadata behavior, runtime-family completion, promotion, and public support remain unqualified",
        ],
    }
    receipt_path = output / "receipt.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return output


def run_mixed_source_generated_compile_diagnostics(
    static_root: Path, dynamic_root: Path, provider_vendor_root: Path, output: Path | None = None,
) -> Path:
    """Compile both generated Cargo fixtures against retained older products.

    This catches generator and Rust type errors before a new same-source product
    cohort is admitted. It deliberately performs neither fixture execution nor
    a normal consumer collection, and records the product/source relationship
    as mixed-source development diagnostics.
    """

    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "native Linux/x86-64 required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source_before = source_snapshot()
    static = product_snapshot(static_root, "static")
    dynamic = product_snapshot(dynamic_root, "dynamic")
    require(static["root"] != dynamic["root"], "static and dynamic product roots must be distinct")
    WORK.mkdir(parents=True, exist_ok=True)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="mixed-source-generated-compile-", dir=WORK))
        output.chmod(0o755)
    else:
        output = work_child(output, "mixed-source generated compile diagnostics output")
        output.mkdir(mode=0o755)
    output = physical(output, "mixed-source generated compile diagnostics output", directory=True)
    channel = tomllib.loads((CHECKOUT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    source_static = compile_source_built_mode(
        label="source-built-static", mode="static", root=Path(static["root"]), channel=channel,
        output=output, package=BUILD_STD_FIXTURE, binary_name=BUILD_STD_BINARY, with_plugin=False,
        provider_vendor_root=provider_vendor_root,
    )
    source_dynamic_dso = compile_source_built_mode(
        label="source-built-dynamic-dso", mode="dynamic", root=Path(dynamic["root"]), channel=channel,
        output=output, package=BUILD_STD_DSO_FIXTURE, binary_name=BUILD_STD_DSO_HOST, with_plugin=True,
        provider_vendor_root=provider_vendor_root,
    )
    assert_same_product(static, "static")
    assert_same_product(dynamic, "dynamic")
    require(source_snapshot() == source_before, "source changed during mixed-source generated compile diagnostics")
    receipt = {
        "schema": 1,
        "scope": "mixed-source generated Rust consumer compile diagnostics",
        "source_product_relation": "mixed-source development diagnostics only",
        "source_inputs": source_before,
        "products": {"static": static, "dynamic": dynamic},
        "source_built_generated_consumers": {"static": source_static, "dynamic_dso": source_dynamic_dso},
        "qualified": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
        "limitations": [
            "this compiles generated source-built fixtures against supplied older products without executing either fixture",
            "a fresh same-source static/dynamic product cohort and full consumer matrix remain required",
        ],
    }
    receipt_path = output / "generated-source-compile-diagnostics.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return output


def run(static_root: Path, dynamic_root: Path, provider_vendor_root: Path, output: Path | None = None) -> Path:
    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "native Linux/x86-64 required")
    # Retain failed executions through their logs, never checkout-root cores.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source_before = source_snapshot()
    static = product_snapshot(static_root, "static")
    dynamic = product_snapshot(dynamic_root, "dynamic")
    require(static["root"] != dynamic["root"], "static and dynamic product roots must be distinct")
    WORK.mkdir(parents=True, exist_ok=True)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="run-", dir=WORK))
        output.chmod(0o755)
    else:
        output = work_child(output, "owned Rust cleanup output")
        output.mkdir(mode=0o755)
    output = physical(output, "owned Rust cleanup output", directory=True)
    channel = tomllib.loads((CHECKOUT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    environment = clean_environment()
    environment.update(SERIAL_BUILD_ENVIRONMENT)
    toolchain = run_logged(
        ["rustup", "run", channel, "rustc", "-Vv"], environment, output / "toolchain.log",
        "consumer compiler identity",
    )
    standalone_provider_sources = prepare_standalone_provider_cargo_home(output, provider_vendor_root)
    standalone_registry_source = provider_registry_unwinding_source(output, standalone_provider_sources)
    run_logged([
        sys.executable, "-B", ROOT / "build.py", "--output", output / "provider",
        "--stage-root", output / "provider" / "source-inputs",
        "--cargo-home", standalone_provider_sources["cargo_home"],
        "--registry-unwinding-source", standalone_registry_source["registry_source"],
    ], environment,
               output / "provider-build.log", "selected unwind provider build")
    provider = provider_snapshot(output / "provider", toolchain)
    stock_consumers: dict[str, dict[str, Any]] = {}
    for mode, snapshot in (("static", static), ("dynamic", dynamic)):
        consumer = compile_mode(mode=mode, root=Path(snapshot["root"]), provider=provider, channel=channel, output=output)
        binary = Path(consumer["binary"]["path"])
        symbols = binary_unwind_symbols(binary, clean_environment(), output / mode / "symbols.log", f"{mode} cleanup symbol inventory")
        cleanup.assert_binary_unwind_symbols(set(symbols), set(provider["defined_unwind_abi"]))
        consumer["defined_unwind_abi"] = symbols
        consumer["symbols_log"] = record_file(output / mode / "symbols.log", f"{mode} cleanup symbol inventory")
        execute_mode(mode, consumer, Path(dynamic["root"]), output / mode)
        stock_consumers[mode] = consumer
    source_static = compile_source_built_mode(
        label="source-built-static", mode="static", root=Path(static["root"]), channel=channel,
        output=output, package=BUILD_STD_FIXTURE, binary_name=BUILD_STD_BINARY, with_plugin=False,
        provider_vendor_root=provider_vendor_root,
    )
    source_static_binary = Path(source_static["binary"]["path"])
    source_static_symbols = binary_unwind_symbols(
        source_static_binary, clean_environment(), output / "source-built-static" / "symbols.log",
        "source-built static cleanup symbol inventory",
    )
    cleanup.assert_binary_unwind_symbols(set(source_static_symbols), set(build.UNWIND_ABI))
    source_static["defined_unwind_abi"] = source_static_symbols
    source_static["symbols_log"] = record_file(
        output / "source-built-static" / "symbols.log", "source-built static cleanup symbol inventory",
    )
    execute_mode("static", source_static, Path(dynamic["root"]), output / "source-built-static")
    source_dynamic_dso = compile_source_built_mode(
        label="source-built-dynamic-dso", mode="dynamic", root=Path(dynamic["root"]), channel=channel,
        output=output, package=BUILD_STD_DSO_FIXTURE, binary_name=BUILD_STD_DSO_HOST, with_plugin=True,
        provider_vendor_root=provider_vendor_root,
    )
    plugin = Path(source_dynamic_dso["plugin"]["binary"]["path"])
    plugin_symbols = binary_unwind_symbols(
        plugin, clean_environment(), output / "source-built-dynamic-dso" / "plugin-symbols.log",
        "source-built DSO cleanup plugin symbol inventory",
    )
    cleanup.assert_binary_unwind_symbols(set(plugin_symbols), set(build.UNWIND_ABI))
    source_dynamic_dso["plugin"]["defined_unwind_abi"] = plugin_symbols
    source_dynamic_dso["plugin"]["symbols_log"] = record_file(
        output / "source-built-dynamic-dso" / "plugin-symbols.log", "source-built DSO cleanup plugin symbol inventory",
    )
    execute_dso_mode(source_dynamic_dso, Path(dynamic["root"]), output / "source-built-dynamic-dso")
    assert_same_product(static, "static")
    assert_same_product(dynamic, "dynamic")
    require(provider_snapshot(output / "provider", toolchain) == provider, "selected provider changed during consumer collection")
    require(source_snapshot() == source_before, "owned Rust consumer source changed during collection")
    receipt = {
        "schema": 1,
        "scope": "owned static/dynamic stock and source-built Rust std fat-LTO cleanup consumer development",
        "source_inputs": source_before,
        "fixture": record_file(FIXTURE, "full Rust cleanup fixture"),
        "products": {"static": static, "dynamic": dynamic},
        "provider": provider,
        "standalone_provider_sources": standalone_provider_sources,
        "stock_consumers": stock_consumers,
        "source_built_consumers": {"static": source_static, "dynamic_dso": source_dynamic_dso},
        "qualified": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
        "limitations": [
            "provider archive and provenance are separately supplied build evidence, not installed-product packaging",
            "this focused consumer does not package the provider or qualify source-built Rust std distribution",
            "complete malformed unwind-metadata behavior, runtime-family completion, promotion, and public support remain unqualified",
        ],
    }
    receipt_path = output / "receipt.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-sysroot", type=Path)
    parser.add_argument("--dynamic-sysroot", type=Path)
    parser.add_argument("--provider-vendor", required=True, type=Path,
                        help="exact offline Cargo vendor for the approved crabc-unwinder dependency graph")
    parser.add_argument("--source-graph-preflight-only", action="store_true",
                        help="run the generated Cargo provider graph metadata/lock preflight without compiling")
    parser.add_argument("--source-built-static-only", action="store_true",
                        help="run only the source-built static Cargo/provider consumer")
    parser.add_argument("--mixed-source-generated-compile-diagnostics-only", action="store_true",
                        help="compile both generated Cargo consumers against supplied older products without execution")
    parser.add_argument("--output", type=Path, help="fresh checkout .work child for retained consumer evidence")
    arguments = parser.parse_args()
    try:
        selected_modes = sum((arguments.source_graph_preflight_only, arguments.source_built_static_only,
                              arguments.mixed_source_generated_compile_diagnostics_only))
        require(selected_modes <= 1, "owned Rust cleanup modes are mutually exclusive")
        if arguments.source_graph_preflight_only:
            require(arguments.static_sysroot is None and arguments.dynamic_sysroot is None,
                    "Cargo provider preflight does not accept supplied sysroots")
            print(run_source_graph_preflight(arguments.provider_vendor, arguments.output))
        elif arguments.source_built_static_only:
            require(arguments.static_sysroot is not None and arguments.dynamic_sysroot is None,
                    "source-built static-only cleanup requires exactly one static sysroot")
            print(run_source_built_static(arguments.static_sysroot, arguments.provider_vendor, arguments.output))
        elif arguments.mixed_source_generated_compile_diagnostics_only:
            require(arguments.static_sysroot is not None and arguments.dynamic_sysroot is not None,
                    "mixed-source generated compile diagnostics require static and dynamic sysroots")
            print(run_mixed_source_generated_compile_diagnostics(
                arguments.static_sysroot, arguments.dynamic_sysroot, arguments.provider_vendor, arguments.output,
            ))
        else:
            require(arguments.static_sysroot is not None and arguments.dynamic_sysroot is not None,
                    "full owned Rust cleanup requires static and dynamic sysroots")
            print(run(arguments.static_sysroot, arguments.dynamic_sysroot, arguments.provider_vendor, arguments.output))
    except (OwnedCleanupError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"crabc-owned-rust-std-cleanup: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
