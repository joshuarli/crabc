#!/usr/bin/env python3
"""Produce and audit the private source-built runtime for one native C fixture.

This is deliberately tied to the selected-native pthread teardown runner.  It
is not an installed sysroot builder: the output never leaves the runner's
private `.work` directory and the C link remains the closure authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Sequence
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
TOOLCHAIN = "nightly-2026-07-24"
PINNED_CARGO_BIN = pathlib.Path("/opt/cargo/bin")
PINNED_RUSTUP_FRONTEND = PINNED_CARGO_BIN / "rustup"
# Alpine packages the installed rustup executable under this bootstrap name.
# The command must retain the `/opt/cargo/bin/rustup` argv[0], however: that
# selects manager mode while invoking the resolved bootstrap name re-enters
# installer mode and rejects `rustup run`.
PINNED_RUSTUP_TARGET = pathlib.Path("/usr/bin/rustup-init")
PINNED_RUSTUP_HOME = pathlib.Path("/opt/rustup")
FIXED_HOST_PATH = "/usr/bin:/bin"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
RUNTIME_SOURCES = {
    "core": pathlib.PurePosixPath("core/src/lib.rs"),
    "alloc": pathlib.PurePosixPath("alloc/src/lib.rs"),
    "compiler_builtins": pathlib.PurePosixPath("compiler-builtins/compiler-builtins/src/lib.rs"),
}
RUNTIME_FLAGS = (
    "-Ztls-model=initial-exec",
    "-Zunstable-options",
    "-Cpanic=immediate-abort",
    "-Cforce-unwind-tables=no",
    "-Crelocation-model=static",
    "-Ccode-model=small",
)
FORBIDDEN_RUNTIME_NAMES = re.compile(r"(?:^|[-_])(std|panic_abort|panic_unwind|unwind|libunwind)(?:[-_.]|$)")
FORBIDDEN_FINAL_SYMBOL = re.compile(r"(?:rust_eh_personality|_Unwind_|panic_(?:abort|unwind))")


class ClosureError(RuntimeError):
    """The source-runtime closure did not meet its narrow evidence contract."""


def fail(message: str) -> None:
    raise ClosureError(message)


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def physical(path: pathlib.Path, description: str, *, directory: bool = False) -> pathlib.Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ClosureError(f"{description} is missing or unsafe: {path}") from error
    if directory:
        if not resolved.is_dir():
            fail(f"{description} is not a directory: {path}")
    elif not resolved.is_file():
        fail(f"{description} is not a regular file: {path}")
    return resolved


def work_child(root: pathlib.Path, path: pathlib.Path, description: str, *, existing: bool = False,
               directory: bool = False) -> pathlib.Path:
    root = physical(root, "private source-runtime work root", directory=True)
    lexical = path if path.is_absolute() else root / path
    try:
        candidate = lexical.resolve(strict=existing)
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ClosureError(f"{description} escapes private source-runtime work root: {path}") from error
    if existing:
        return physical(candidate, description, directory=directory)
    if candidate.exists() or candidate.is_symlink():
        fail(f"{description} already exists: {candidate}")
    return candidate


def file_record(path: pathlib.Path, description: str) -> dict[str, object]:
    path = physical(path, description)
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size}


def checked_relative(value: str, description: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts or any(part in ("", ".", "..") for part in candidate.parts):
        fail(f"{description} has an unsafe path: {value!r}")
    return candidate


def walk_regular_tree(root: pathlib.Path, description: str) -> Iterable[pathlib.Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            fail(f"{description} contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"{description} contains a non-regular file: {path}")
        yield path


def vendor_package_record(directory: pathlib.Path, name: str, version: str, package_checksum: str,
                          description: str) -> dict[str, object]:
    directory = physical(directory, description, directory=True)
    checksum_path = physical(directory / ".cargo-checksum.json", f"{description} checksum")
    try:
        checksum_data = json.loads(checksum_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ClosureError(f"{description} checksum is invalid") from error
    if not isinstance(checksum_data, dict) or checksum_data.get("package") != package_checksum:
        fail(f"{description} package checksum differs from its lock record")
    files = checksum_data.get("files")
    if not isinstance(files, dict) or not files or not all(
        isinstance(path, str) and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
        for path, value in files.items()
    ):
        fail(f"{description} checksum file manifest is invalid")
    expected = {checked_relative(path, f"{description} checksum file") for path in files}
    actual = {path.relative_to(directory) for path in walk_regular_tree(directory, description)}
    actual.discard(pathlib.Path(".cargo-checksum.json"))
    if {pathlib.PurePosixPath(path.as_posix()) for path in actual} != expected:
        fail(f"{description} file set differs from its checksum manifest")
    for relative, expected_digest in files.items():
        path = physical(directory / checked_relative(relative, f"{description} checksum file"),
                        f"{description} checked file")
        if digest(path) != expected_digest:
            fail(f"{description} file digest differs from its checksum manifest: {relative}")
    tree = hashlib.sha256()
    for relative in sorted(expected):
        tree.update(relative.as_posix().encode("utf-8"))
        tree.update(b"\0")
        tree.update(files[relative.as_posix()].encode("ascii"))
        tree.update(b"\n")
    return {
        "name": name,
        "version": version,
        "package_checksum": package_checksum,
        "directory": str(directory),
        "file_tree_sha256": tree.hexdigest(),
        "file_count": len(expected),
    }


def lock_registry_packages(lock: pathlib.Path, description: str) -> dict[str, tuple[str, str, str]]:
    lock = physical(lock, description)
    try:
        data = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ClosureError(f"{description} is invalid") from error
    packages = data.get("package")
    if not isinstance(packages, list):
        fail(f"{description} has no package list")
    result: dict[str, tuple[str, str, str]] = {}
    for record in packages:
        if not isinstance(record, dict) or record.get("source") != REGISTRY:
            continue
        name, version, checksum = record.get("name"), record.get("version"), record.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            fail(f"{description} has a malformed registry package")
        key = f"{name}-{version}"
        expected = (name, version, checksum)
        if key in result and result[key] != expected:
            fail(f"{description} repeats package {key} with conflicting identity")
        result[key] = expected
    if not result:
        fail(f"{description} has no registry package closure")
    return result


def find_project_vendor_package(project_vendor: pathlib.Path, name: str, version: str,
                                description: str) -> pathlib.Path:
    """Return one lock-named package from the authenticated project vendor tree."""

    project_vendor = physical(project_vendor, "authenticated project Cargo vendor", directory=True)
    key = checked_relative(f"{name}-{version}", f"{description} lock identity")
    package = physical(project_vendor / key, description, directory=True)
    try:
        package.relative_to(project_vendor)
    except ValueError as error:
        raise ClosureError(f"{description} escapes authenticated project Cargo vendor: {package}") from error
    return package


def copy_vendor_tree(source: pathlib.Path, destination: pathlib.Path, description: str) -> None:
    if destination.exists() or destination.is_symlink():
        fail(f"{description} destination already exists: {destination}")
    # Validate before copying; copy2 then preserves the audited regular files.
    list(walk_regular_tree(source, description))
    shutil.copytree(source, destination, copy_function=shutil.copy2)


def private_vendor(work: pathlib.Path, rust_source: pathlib.Path, project_vendor: pathlib.Path) -> dict[str, object]:
    rust_config = physical(rust_source / ".cargo" / "config.toml", "pinned rust-src vendor config")
    try:
        config = tomllib.loads(rust_config.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ClosureError("pinned rust-src vendor config is invalid") from error
    expected_config = {
        "source": {
            "crates-io": {"replace-with": "vendored-sources"},
            "vendored-sources": {"directory": "vendor"},
        },
    }
    if config != expected_config:
        fail("pinned rust-src vendor config differs from the declared source replacement")
    rust_lock = physical(rust_source / "Cargo.lock", "pinned rust-src lock")
    project_lock = physical(ROOT / "Cargo.lock", "workspace lock")
    rust_packages = lock_registry_packages(rust_lock, "pinned rust-src lock")
    project_packages = lock_registry_packages(project_lock, "workspace lock")
    vendor = work_child(work, pathlib.Path("cargo-vendor"), "private composite vendor")
    source_vendor = physical(rust_source / "vendor", "pinned rust-src vendor", directory=True)
    copy_vendor_tree(source_vendor, vendor, "pinned rust-src vendor")
    records: dict[str, dict[str, object]] = {}
    for key, (name, version, checksum) in sorted(rust_packages.items()):
        records[key] = vendor_package_record(vendor / key, name, version, checksum, f"pinned rust-src vendor package {key}")
    for key, (name, version, checksum) in sorted(project_packages.items()):
        existing = records.get(key)
        if existing is not None:
            if existing["package_checksum"] != checksum:
                fail(f"workspace and pinned rust-src disagree about registry package {key}")
            continue
        source = find_project_vendor_package(
            project_vendor, name, version, f"workspace registry package {key}"
        )
        validated = vendor_package_record(source, name, version, checksum, f"workspace registry package {key}")
        copy_vendor_tree(source, vendor / key, f"workspace registry package {key}")
        copied = vendor_package_record(vendor / key, name, version, checksum, f"private vendor package {key}")
        if copied["file_tree_sha256"] != validated["file_tree_sha256"]:
            fail(f"private vendor copy differs from workspace registry package {key}")
        records[key] = copied
    cargo_home = work_child(work, pathlib.Path("cargo-home"), "private Cargo home")
    cargo_home.mkdir(mode=0o755)
    config_path = cargo_home / "config.toml"
    config_path.write_text(
        "[source.crates-io]\nreplace-with = \"crabc-native-source-runtime\"\n\n"
        "[source.crabc-native-source-runtime]\n"
        f"directory = {json.dumps(str(vendor))}\n\n[net]\noffline = true\n",
        encoding="utf-8",
    )
    config_path.chmod(0o644)
    return {
        "rust_source_lock": file_record(rust_lock, "pinned rust-src lock"),
        "workspace_lock": file_record(project_lock, "workspace lock"),
        "rust_source_vendor_config": file_record(rust_config, "pinned rust-src vendor config"),
        "project_vendor_root": str(physical(project_vendor, "authenticated project Cargo vendor", directory=True)),
        "private_vendor_root": str(physical(vendor, "private composite vendor", directory=True)),
        "packages": [records[key] for key in sorted(records)],
        "cargo_config": file_record(config_path, "private Cargo source config"),
    }


def run(command: Sequence[str], environment: dict[str, str], stdout_path: pathlib.Path,
        stderr_path: pathlib.Path, description: str) -> None:
    completed = subprocess.run(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        fail(f"{description} failed with exit {completed.returncode}; see {stderr_path}")


def cargo_records(stdout_path: pathlib.Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for number, line in enumerate(stdout_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ClosureError(f"Cargo JSON stream has malformed record at line {number}") from error
        if not isinstance(record, dict):
            fail(f"Cargo JSON stream has non-object record at line {number}")
        records.append(record)
    if not records:
        fail("Cargo JSON stream has no records")
    return records


def artifact_path(record: dict[str, Any], target: pathlib.Path, description: str, suffix: str) -> pathlib.Path:
    filenames = record.get("filenames")
    if not isinstance(filenames, list):
        fail(f"{description} has no Cargo artifact filenames")
    candidates: list[pathlib.Path] = []
    for raw in filenames:
        if not isinstance(raw, str) or not raw.endswith(suffix):
            continue
        path = physical(pathlib.Path(raw), description)
        try:
            path.relative_to(target)
        except ValueError as error:
            raise ClosureError(f"{description} escapes private target root: {path}") from error
        candidates.append(path)
    if len(candidates) != 1:
        fail(f"{description} has ambiguous {suffix} artifacts: {candidates!r}")
    return candidates[0]


def artifact_for_source(records: Sequence[dict[str, Any]], source: pathlib.Path, name: str,
                        target: pathlib.Path, suffix: str) -> pathlib.Path:
    matches: list[dict[str, Any]] = []
    for record in records:
        if record.get("reason") != "compiler-artifact":
            continue
        target_record = record.get("target")
        if not isinstance(target_record, dict) or target_record.get("name") != name:
            continue
        src_path = target_record.get("src_path")
        if not isinstance(src_path, str):
            continue
        try:
            if physical(pathlib.Path(src_path), f"Cargo {name} source") == source:
                matches.append(record)
        except ClosureError:
            continue
    if len(matches) != 1:
        fail(f"Cargo did not retain exactly one {name} compiler artifact for {source}: {len(matches)}")
    return artifact_path(matches[0], target, f"Cargo {name} artifact", suffix)


def emitted_artifacts(records: Sequence[dict[str, Any]], target: pathlib.Path) -> dict[pathlib.Path, dict[str, object]]:
    """Index Cargo-declared target artifacts before any rustc extern is trusted."""

    emitted: dict[pathlib.Path, dict[str, object]] = {}
    for record in records:
        if record.get("reason") != "compiler-artifact":
            continue
        target_record = record.get("target")
        package_id = record.get("package_id")
        if not isinstance(target_record, dict) or not isinstance(package_id, str):
            fail("Cargo compiler artifact lacks target identity")
        name = target_record.get("name")
        source = target_record.get("src_path")
        filenames = record.get("filenames")
        if not isinstance(name, str) or not isinstance(source, str) or not isinstance(filenames, list):
            fail("Cargo compiler artifact has malformed identity")
        source_path = physical(pathlib.Path(source), f"Cargo {name} artifact source")
        for raw in filenames:
            if not isinstance(raw, str):
                fail(f"Cargo {name} artifact has a non-path filename")
            artifact = physical(pathlib.Path(raw), f"Cargo {name} emitted artifact")
            try:
                artifact.relative_to(target)
            except ValueError as error:
                raise ClosureError(f"Cargo {name} emitted artifact escapes private target root: {artifact}") from error
            identity = {"target_name": name, "package_id": package_id, "source": str(source_path)}
            existing = emitted.get(artifact)
            if existing is not None and existing != identity:
                fail(f"Cargo emits one artifact path with conflicting identities: {artifact}")
            emitted[artifact] = identity
    if not emitted:
        fail("Cargo JSON stream declares no target artifacts")
    return emitted


def cargo_commands(stderr_path: pathlib.Path) -> list[list[str]]:
    commands: list[list[str]] = []
    for rendered in re.findall(r"Running `([^`]+)`", stderr_path.read_text(encoding="utf-8")):
        try:
            command = __import__("shlex").split(rendered)
        except ValueError as error:
            raise ClosureError("Cargo verbose log has an unparsable command") from error
        if "--crate-name" in command:
            commands.append(command)
    if not commands:
        fail("Cargo verbose diagnostics retain no rustc commands")
    return commands


def option_values(command: Sequence[str], option: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(command):
        item = command[index]
        if item == option:
            if index + 1 >= len(command):
                fail(f"Cargo rustc command has malformed {option}")
            values.append(command[index + 1])
            index += 2
            continue
        prefix = option + "="
        if item.startswith(prefix):
            values.append(item[len(prefix):])
        elif option in ("-C", "-Z") and item.startswith(option) and len(item) > len(option):
            values.append(item[len(option):])
        index += 1
    return values


def invocation_for(commands: Sequence[list[str]], crate: str) -> list[str]:
    matches = [command for command in commands if option_values(command, "--crate-name") == [crate]
               and option_values(command, "--target") == [TARGET]]
    if len(matches) != 1:
        fail(f"Cargo did not retain exactly one target rustc invocation for {crate}: {len(matches)}")
    return matches[0]


def externs(command: Sequence[str], description: str) -> dict[str, pathlib.Path]:
    result: dict[str, pathlib.Path] = {}
    for value in option_values(command, "--extern"):
        name, delimiter, raw_path = value.partition("=")
        if not delimiter or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            fail(f"{description} has malformed --extern {value!r}")
        path = physical(pathlib.Path(raw_path), f"{description} {name} extern")
        if name in result:
            fail(f"{description} repeats --extern {name}")
        result[name] = path
    return result


def command_record(command: Sequence[str], target: pathlib.Path, expected_runtime: dict[str, pathlib.Path],
                   emitted: dict[pathlib.Path, dict[str, object]], crate: str, source: pathlib.Path) -> dict[str, object]:
    """Bind one target rustc command to source and Cargo-declared artifacts."""

    command_has_source(command, source, f"Cargo {crate} rustc")
    values = [*option_values(command, "-C"), *option_values(command, "-Z")]
    missing = [flag for flag in RUNTIME_FLAGS if flag.removeprefix("-C").removeprefix("-Z") not in values]
    if missing:
        fail(f"Cargo {crate} rustc invocation omits source-runtime flags: {missing!r}")
    crate_externs = externs(command, f"Cargo {crate} rustc")
    selected: dict[str, dict[str, object]] = {}
    for name, artifact in expected_runtime.items():
        actual = crate_externs.get(name)
        if actual is None:
            fail(f"Cargo {crate} rustc invocation omits --extern {name}")
        if actual != artifact:
            fail(f"Cargo {crate} rustc {name} extern differs from the source-built artifact")
        selected[name] = file_record(actual, f"Cargo {crate} {name} extern")
    all_externs: dict[str, dict[str, object]] = {}
    for name, artifact in crate_externs.items():
        try:
            artifact.relative_to(target)
        except ValueError as error:
            raise ClosureError(f"Cargo {crate} rustc admits external Rust artifact {name}: {artifact}") from error
        identity = emitted.get(artifact)
        if identity is None:
            fail(f"Cargo {crate} rustc {name} extern does not bind an emitted Cargo artifact")
        target_name = identity["target_name"]
        if not isinstance(target_name, str):
            fail(f"Cargo {crate} rustc {name} extern has malformed emitted target identity")
        if FORBIDDEN_RUNTIME_NAMES.search(name) or FORBIDDEN_RUNTIME_NAMES.search(target_name):
            fail(f"Cargo {crate} rustc admits forbidden runtime extern {name} from {target_name}")
        all_externs[name] = {**file_record(artifact, f"Cargo {crate} {name} extern"), "artifact": identity}
    return {"arguments": list(command), "runtime_externs": selected, "all_externs": all_externs}


def required_tool(sysroot: pathlib.Path, name: str) -> pathlib.Path:
    return physical(sysroot / "lib" / "rustlib" / TARGET / "bin" / name, f"pinned Rust {name}")


def pinned_rustup_frontend(frontend: pathlib.Path, expected_target: pathlib.Path) -> dict[str, str]:
    """Bind Alpine's installed rustup target without losing the manager argv[0]."""

    if frontend.name != "rustup":
        fail(f"pinned Rust command must use its lexical rustup frontend: {frontend}")
    if not frontend.is_file() or not os.access(frontend, os.X_OK):
        fail(f"pinned Rust lexical frontend is missing or not executable: {frontend}")
    resolved = physical(frontend, "pinned Rust lexical frontend")
    target = physical(expected_target, "pinned Rust installed target")
    if resolved != target:
        fail(f"pinned Rust lexical frontend resolves to an unexpected target: {resolved}")
    return {
        "argv0": frontend.name,
        "frontend": str(frontend),
        "resolved_target": str(target),
        "resolved_target_sha256": digest(target),
    }


def pinned_environment() -> tuple[dict[str, str], dict[str, str]]:
    """Select the image-owned frontend without inheriting host Cargo state."""

    rustup = pinned_rustup_frontend(PINNED_RUSTUP_FRONTEND, PINNED_RUSTUP_TARGET)
    rustup_root = physical(PINNED_RUSTUP_HOME, "pinned rustup home", directory=True)
    return rustup, {
        "LC_ALL": "C",
        "PATH": f"{PINNED_CARGO_BIN}:{FIXED_HOST_PATH}",
        "RUSTUP_HOME": str(rustup_root),
        "SOURCE_DATE_EPOCH": "1",
        "TZ": "UTC",
    }


def command_has_source(command: Sequence[str], source: pathlib.Path, description: str) -> None:
    expected = str(source)
    if expected not in command:
        fail(f"{description} does not compile its exact checked-in source")


def archive_members(ar: pathlib.Path, archive: pathlib.Path, destination: pathlib.Path,
                    description: str) -> dict[str, pathlib.Path]:
    listing = subprocess.run([str(ar), "t", str(archive)], stdin=subprocess.DEVNULL, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if listing.returncode != 0:
        fail(f"{description} member listing failed: {listing.stderr}")
    names = [line for line in listing.stdout.splitlines() if line]
    if not names or len(names) != len(set(names)):
        fail(f"{description} member list is empty or repeats names")
    for name in names:
        if pathlib.PurePosixPath(name).name != name or name in (".", ".."):
            fail(f"{description} has unsafe member name {name!r}")
    destination.mkdir(mode=0o755)
    extract = subprocess.run([str(ar), "x", str(archive)], cwd=destination, stdin=subprocess.DEVNULL,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if extract.returncode != 0:
        fail(f"{description} member extraction failed: {extract.stderr}")
    extracted = {name: physical(destination / name, f"{description} member") for name in names}
    if set(extracted) != {path.name for path in destination.iterdir()}:
        fail(f"{description} extraction produced unexpected files")
    return extracted


def runtime_members(ar: pathlib.Path, rlibs: dict[str, pathlib.Path], work: pathlib.Path) -> dict[str, dict[str, str]]:
    expected: dict[str, dict[str, str]] = {}
    for name, rlib in rlibs.items():
        members = archive_members(ar, rlib, work_child(work, pathlib.Path(f"{name}-rlib-members"), f"{name} rlib members"),
                                  f"source-built {name} rlib")
        objects = {member: digest(path) for member, path in members.items() if member.endswith(".o")}
        if not objects:
            fail(f"source-built {name} rlib has no object members")
        for member in objects:
            if member in expected:
                fail(f"source-built runtime repeats object member name {member}")
        expected.update({member: {"runtime": name, "sha256": value} for member, value in objects.items()})
    return expected


def undefined_symbols(nm: pathlib.Path, archive: pathlib.Path, output: pathlib.Path) -> list[str]:
    completed = subprocess.run([str(nm), "-A", "--undefined-only", str(archive)], stdin=subprocess.DEVNULL,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    output.write_text(completed.stdout, encoding="utf-8")
    if completed.returncode != 0:
        fail(f"selected staticlib undefined-symbol audit failed: {completed.stderr}")
    return [line for line in completed.stdout.splitlines() if FORBIDDEN_FINAL_SYMBOL.search(line)]


def staticlib_closure(ar: pathlib.Path, nm: pathlib.Path, archive: pathlib.Path,
                      source_rlibs: dict[str, pathlib.Path], work: pathlib.Path) -> dict[str, object]:
    expected = runtime_members(ar, source_rlibs, work)
    members = archive_members(ar, archive, work_child(work, pathlib.Path("staticlib-members"), "selected staticlib members"),
                              "selected source-runtime staticlib")
    selected: list[dict[str, object]] = []
    for name, path in sorted(members.items()):
        if FORBIDDEN_RUNTIME_NAMES.search(name):
            fail(f"selected source-runtime staticlib admits forbidden runtime member {name}")
        entry = expected.get(name)
        if entry is None:
            continue
        actual = digest(path)
        if actual != entry["sha256"]:
            fail(f"selected staticlib member differs from source-built {entry['runtime']} member: {name}")
        selected.append({"member": name, **entry})
    if len(selected) != len(expected):
        missing = sorted(set(expected) - {entry["member"] for entry in selected})
        fail(f"selected staticlib omits source-built runtime members: {missing!r}")
    forbidden = undefined_symbols(nm, archive, work / "staticlib-undefined-symbols.txt")
    if forbidden:
        fail(f"selected source-runtime staticlib retains personality/unwind candidates: {forbidden!r}")
    return {
        "archive": file_record(archive, "selected source-runtime staticlib"),
        "source_runtime_members": selected,
        "undefined_symbols": file_record(work / "staticlib-undefined-symbols.txt", "staticlib undefined-symbol inventory"),
    }


def build(arguments: argparse.Namespace) -> pathlib.Path:
    work_root = ROOT / ".work" / "x86_64"
    work = work_child(work_root, pathlib.Path(arguments.work), "source-runtime closure work")
    work.mkdir(mode=0o755)
    rustup, base_environment = pinned_environment()
    sysroot_result = subprocess.run([rustup["argv0"], "run", TOOLCHAIN, "rustc", "--print", "sysroot"], cwd=ROOT,
                                    env=base_environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, check=False)
    if sysroot_result.returncode != 0:
        fail(f"pinned rustc sysroot discovery failed: {sysroot_result.stderr}")
    sysroot = physical(pathlib.Path(sysroot_result.stdout.strip()), "pinned Rust sysroot", directory=True)
    try:
        sysroot.relative_to(physical(PINNED_RUSTUP_HOME / "toolchains", "pinned Rust toolchain root", directory=True))
    except ValueError as error:
        raise ClosureError(f"pinned Rust sysroot escapes the image toolchain root: {sysroot}") from error
    if not sysroot.name.startswith(TOOLCHAIN):
        fail(f"pinned Rust sysroot drifted: {sysroot}")
    rust_source = physical(sysroot / "lib" / "rustlib" / "src" / "rust" / "library", "pinned rust-src library", directory=True)
    project_vendor = physical(
        ROOT / ".work" / "x86_64" / "cargo" / "native-static-source-runtime-vendor",
        "authenticated project Cargo vendor",
        directory=True,
    )
    vendor = private_vendor(work, rust_source, project_vendor)
    target = work_child(work, pathlib.Path("cargo-target"), "private source-runtime target")
    temporary = work_child(work, pathlib.Path("tmp"), "private source-runtime temporary directory")
    target.mkdir(mode=0o755)
    temporary.mkdir(mode=0o755)
    environment = {
        **base_environment,
        "CARGO_HOME": str(work / "cargo-home"),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(RUNTIME_FLAGS),
        "TMPDIR": str(temporary),
    }
    command = [
        rustup["argv0"], "run", TOOLCHAIN, "cargo", "-Zbuild-std=core,alloc,compiler_builtins", "rustc",
        "--locked", "--offline", "-vv", "--message-format=json-render-diagnostics", "-p", "crabc-libc", "--lib",
        "--target", TARGET, "--features", arguments.features,
    ]
    stdout_path, stderr_path = work / "cargo.stdout.jsonl", work / "cargo.stderr.log"
    run(command, environment, stdout_path, stderr_path, "source-built native static runtime Cargo graph")
    records = cargo_records(stdout_path)
    emitted = emitted_artifacts(records, target)
    runtime_sources = {
        name: physical(rust_source / source, f"pinned {name} source")
        for name, source in RUNTIME_SOURCES.items()
    }
    rlibs = {
        name: artifact_for_source(records, source, name, target, ".rlib")
        for name, source in runtime_sources.items()
    }
    libc_source = physical(ROOT / "libc" / "src" / "lib.rs", "crabc-libc source")
    archive = artifact_for_source(records, libc_source, "c", target, ".a")
    commands = cargo_commands(stderr_path)
    expected_runtime = dict(rlibs)
    source_runtime_rustc = {
        name: command_record(
            invocation_for(commands, name), target, {}, emitted, name, source,
        )
        for name, source in runtime_sources.items()
    }
    primary = command_record(
        invocation_for(commands, "c"), target, expected_runtime, emitted, "crabc-libc", libc_source,
    )
    allocator = command_record(
        invocation_for(commands, "crabc_mimalloc"), target, expected_runtime, emitted, "crabc-mimalloc",
        physical(ROOT / "crabc-mimalloc" / "src" / "lib.rs", "crabc-mimalloc source"),
    )
    ar, nm = required_tool(sysroot, "llvm-ar"), required_tool(sysroot, "llvm-nm")
    closure = staticlib_closure(ar, nm, archive, rlibs, work)
    receipt = {
        "schema": 1,
        "scope": "private-native-static-source-runtime-closure-not-product-or-dynamic-qualification",
        "target": TARGET,
        "toolchain": TOOLCHAIN,
        "pinned_rustup": rustup,
        "immediate_abort_semantics": "development-only Rust panics abort immediately instead of using static_c_abi.rs's nonreturning spin panic handler",
        "cargo_command": command,
        "runtime_flags": list(RUNTIME_FLAGS),
        "cargo_stdout": file_record(stdout_path, "source-runtime Cargo JSON stream"),
        "cargo_stderr": file_record(stderr_path, "source-runtime Cargo diagnostics"),
        "rust_source": str(rust_source),
        "vendor": vendor,
        "source_runtime_artifacts": {name: file_record(path, f"source-built {name} rlib") for name, path in rlibs.items()},
        "source_runtime_rustc": source_runtime_rustc,
        "primary_rustc": primary,
        "allocator_rustc": allocator,
        "staticlib_closure": closure,
    }
    receipt_path = work / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt_path.chmod(0o644)
    return archive


def audit_final_link(arguments: argparse.Namespace) -> None:
    receipt_path = physical(pathlib.Path(arguments.receipt), "source-runtime receipt")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ClosureError("source-runtime receipt is invalid") from error
    if not isinstance(receipt, dict) or receipt.get("schema") != 1:
        fail("source-runtime receipt schema differs")
    archive_value = receipt.get("staticlib_closure", {}).get("archive", {}) if isinstance(receipt.get("staticlib_closure"), dict) else {}
    if not isinstance(archive_value, dict) or not isinstance(archive_value.get("path"), str):
        fail("source-runtime receipt lacks staticlib identity")
    archive = physical(pathlib.Path(archive_value["path"]), "receipt staticlib")
    if archive_value.get("sha256") != digest(archive):
        fail("receipt staticlib digest changed before final link audit")
    candidate = physical(pathlib.Path(arguments.candidate), "source-runtime candidate")
    link_map = physical(pathlib.Path(arguments.link_map), "source-runtime link map")
    trace = physical(pathlib.Path(arguments.trace), "source-runtime link trace")
    map_text = link_map.read_text(encoding="utf-8", errors="replace")
    trace_text = trace.read_text(encoding="utf-8", errors="replace")
    selected = sorted(set(re.findall(re.escape(str(archive)) + r"\(([^()]+)\)", map_text)))
    if not selected:
        fail("final link map does not identify selected source-runtime archive members")
    if FORBIDDEN_FINAL_SYMBOL.search(trace_text):
        fail("final link trace retains a Rust personality, panic runtime, or unwinder symbol")
    nm = subprocess.run(["nm", "-A", str(candidate)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, check=False)
    if nm.returncode != 0:
        fail(f"final candidate symbol audit failed: {nm.stderr}")
    if FORBIDDEN_FINAL_SYMBOL.search(nm.stdout):
        fail("final candidate retains a Rust personality, panic runtime, or unwinder symbol")
    links = receipt.setdefault("final_links", [])
    if not isinstance(links, list):
        fail("source-runtime receipt final link records are malformed")
    links.append({
        "label": arguments.label,
        "candidate": file_record(candidate, "source-runtime candidate"),
        "map": file_record(link_map, "source-runtime link map"),
        "trace": file_record(trace, "source-runtime link trace"),
        "selected_staticlib_members": selected,
    })
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build", help="build and audit a source-runtime staticlib")
    build_command.add_argument("--work", required=True, help="new child of .work/x86_64")
    build_command.add_argument("--features", required=True)
    build_command.add_argument("--print-archive", action="store_true")
    final_link = commands.add_parser("audit-final-link", help="bind one C link to a source-runtime receipt")
    final_link.add_argument("--receipt", required=True)
    final_link.add_argument("--candidate", required=True)
    final_link.add_argument("--link-map", required=True)
    final_link.add_argument("--trace", required=True)
    final_link.add_argument("--label", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "build":
            archive = build(arguments)
            if arguments.print_archive:
                print(archive)
        else:
            audit_final_link(arguments)
    except ClosureError as error:
        print(f"ERROR: native static source runtime closure: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
