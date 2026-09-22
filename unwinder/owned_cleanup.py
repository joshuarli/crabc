#!/usr/bin/env python3
"""Run the full Rust cleanup fixture through supplied owned runtime products.

This is consumer-development evidence.  The selected provider is built beside
the receipt and passed directly to each link; it is deliberately *not*
installed into either supplied product.  Packaging that provider, a build-std
consumer, LTO, DSO discovery, and complete malformed-metadata behavior remain
separate requirements before any qualification or promotion claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
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
BUILD_STD_BINARY = "crabc-owned-cleanup-build-std"
BUILD_STD_DSO_HOST = "crabc-owned-cleanup-dso-host"
BUILD_STD_DSO_LIBRARY = "libcrabc_owned_cleanup_plugin.so"
BUILD_STD_CRATES = ("std", "core", "alloc", "panic_unwind", "unwind", "compiler_builtins")
HOST_BUILD_LINKER = Path("/usr/bin/gcc")
SERIAL_BUILD_ENVIRONMENT = {
    "CARGO_BUILD_JOBS": "1",
    "CMAKE_BUILD_PARALLEL_LEVEL": "1",
    "MAKEFLAGS": "-j1",
    "NINJAFLAGS": "-j1",
}
SOURCE_INPUTS = (
    ROOT / "owned_cleanup.py", ROOT / "owned_rust_link.py", ROOT / "cleanup.py",
    ROOT / "build.py", FIXTURE,
    BUILD_STD_FIXTURE / "Cargo.toml", BUILD_STD_FIXTURE / "Cargo.lock", BUILD_STD_FIXTURE / "src/main.rs",
    BUILD_STD_DSO_FIXTURE / "Cargo.toml", BUILD_STD_DSO_FIXTURE / "Cargo.lock",
    BUILD_STD_DSO_FIXTURE / "src/main.rs", BUILD_STD_DSO_FIXTURE / "src/plugin.rs",
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
) -> dict[str, Any]:
    """Read one source-built final link without admitting stock target rlibs."""

    record = json_object(path, description)
    require(record.get("schema") == 2 and record.get("format") == "crabc-owned-rust-source-build-link/v1",
            f"{description} has the wrong source-built link schema")
    require(record.get("rust_library_origin") == "source-built"
            and record.get("source_built_target_library_root") == str(source_library_root),
            f"{description} does not bind the source-built target library root")
    require("omitted_stock_rust_unwind" not in record and "omitted_compiler_builtins" not in record,
            f"{description} retains a stock Rust runtime archive")
    for field in ("omitted_source_built_rust_unwind", "omitted_source_built_compiler_builtins"):
        value = record.get(field)
        require(isinstance(value, dict) and value.get("path", "").startswith(str(source_library_root) + os.sep),
                f"{description} does not omit a source-built Rust runtime archive")
    inputs = record.get("application_inputs")
    require(isinstance(inputs, list) and all(isinstance(value, dict) for value in inputs),
            f"{description} lacks its Rust application inputs")
    archives = [value.get("path") for value in inputs if isinstance(value.get("path"), str)
                and value["path"].endswith(".rlib")]
    require(archives and all(path.startswith(str(source_library_root) + os.sep) for path in archives),
            f"{description} admits a non-source-built Rust archive")
    required_archives = ("libstd-", "libcore-", "liballoc-", "libpanic_unwind-")
    require(all(any(Path(path).name.startswith(prefix) for path in archives) for prefix in required_archives),
            f"{description} lacks the source-built standard-library closure")
    require(record.get("output") == record_file(binary, f"{description} output"),
            f"{description} does not identify its output")
    assert_nonpromoting(record, description)
    trace = record.get("resolved_input_trace")
    command = record.get("command")
    require(isinstance(trace, str) and isinstance(command, list) and all(isinstance(item, str) for item in command),
            f"{description} lacks exact command or trace")
    forbidden = ("libgcc", "libunwind", "-lgcc", "-lunwind", "-lc")
    require(not any(token in item for item in command for token in forbidden),
            f"{description} linker command admits an ambient native runtime request")
    require("libcrabc-unwind.a" in trace and not any(token in trace for token in ("libgcc", "libunwind")),
            f"{description} link trace does not prove the selected provider without ambient unwind runtimes")
    return record


def cargo_artifact(
    stream: str, *, package: Path, target: Path, name: str, crate_type: str,
) -> Path:
    """Find one exact Cargo artifact from its JSON stream, not target-dir globbing."""

    selected: list[Path] = []
    source = package / "src" / ("main.rs" if crate_type == "bin" else "plugin.rs")
    for line in stream.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise OwnedCleanupError("Cargo emitted a non-JSON machine-readable record") from error
        if not isinstance(record, dict) or record.get("reason") != "compiler-artifact":
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


def source_build_log_contract(log: str, rust_source: Path) -> None:
    """Require a fresh full-std source build and fat-LTO compiler invocations."""

    missing = [name for name in BUILD_STD_CRATES if f"--crate-name {name}" not in log]
    require(not missing, f"Cargo build-std log omits required Rust crates: {missing!r}")
    require(str(rust_source) in log, "Cargo build-std log does not name pinned rust-src")
    require("lto=fat" in log and "codegen-units=1" in log,
            "Cargo build-std log does not retain the requested fat-LTO profile")


def host_build_script_links(path: Path, root: Path) -> list[dict[str, Any]]:
    """Audit the same-triple Cargo host-tool exception outside final links."""

    path = physical(path, "Cargo host build-script link log")
    root = physical(root, "Cargo host build-script root", directory=True)
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise OwnedCleanupError("Cargo host build-script link log is not JSON lines") from error
        require(isinstance(record, dict), "Cargo host build-script link record is not an object")
        require(set(record) == {"schema", "kind", "linker", "command", "output"},
                "Cargo host build-script link record fields drifted")
        require(record["schema"] == 1 and record["kind"] == "cargo-host-build-script",
                "Cargo host build-script link record identity drifted")
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
                "Cargo host build-script output record is malformed")
        candidate = physical(Path(output["path"]), "Cargo host build-script output", executable=True)
        require(candidate.is_relative_to(root) and candidate.name.startswith("build_script_build-"),
                "Cargo host build-script output is outside the declared host root")
        require(output == record_file(candidate, "Cargo host build-script output"),
                "Cargo host build-script output identity drifted")
        records.append(record)
    require(records, "Cargo build-std did not retain its same-triple host build-script links")
    return records


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
    *, label: str, mode: str, root: Path, provider: dict[str, Any], channel: str, output: Path,
    package: Path, binary_name: str, with_plugin: bool,
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
    host_build_log = application / "host-build-links.jsonl"
    with host_build_log.open("x", encoding="utf-8"):
        pass
    rust_sysroot = Path(run_logged(
        ["rustup", "run", channel, "rustc", "--print", "sysroot"], clean_environment(),
        application / "rust-sysroot.log", f"{label} Rust sysroot discovery",
    ).strip())
    rust_source = physical(
        rust_sysroot / "lib/rustlib/src/rust/library", f"{label} pinned rust-src library", directory=True,
    )
    rust_source_lock = physical(rust_source / "Cargo.lock", f"{label} pinned rust-src lock")
    environment = clean_environment()
    flags = (
        "-C", "panic=unwind", "-C", "force-unwind-tables=yes", "-C", "link-self-contained=no",
        "-C", "target-feature=-crt-static", "-C", "lto=fat", "-C", "codegen-units=1",
        "-C", "link-arg=-Wl,--eh-frame-hdr",
    )
    environment.update({
        **SERIAL_BUILD_ENVIRONMENT,
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        "CARGO_PROFILE_RELEASE_LTO": "fat",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER": str(ROOT / "owned_rust_link.py"),
        "CRABC_OWNED_RUST_LINK_MODE": mode,
        "CRABC_OWNED_RUST_PRODUCT": str(root),
        "CRABC_OWNED_RUST_PROVIDER": str(provider["archive"]["path"]),
        "CRABC_OWNED_RUST_SOURCE_BUILT_LIBDIR": str(source_library_root),
        "CRABC_OWNED_RUST_APPLICATION_ROOT": str(release),
        "CRABC_OWNED_RUST_HOST_BUILD_ROOT": str(host_build_root),
        "CRABC_OWNED_RUST_HOST_BUILD_LINKER": str(HOST_BUILD_LINKER),
        "CRABC_OWNED_RUST_HOST_BUILD_LOG": str(host_build_log),
        "CRABC_OWNED_RUST_CHANNEL": channel,
        "TMPDIR": str(temporary),
    })
    command: list[str | Path] = [
        "rustup", "run", channel, "cargo", "build", "--manifest-path", package / "Cargo.toml", "--release",
        "--target", TARGET, "--locked", "-Zbuild-std=std,panic_unwind", "-vv",
        "--message-format=json-render-diagnostics", "--bin", binary_name,
    ]
    if with_plugin:
        command.append("--lib")
    stdout, stderr = run_logged_streams(
        command, environment, application / "cargo.stdout.jsonl", application / "cargo.stderr.log",
        f"{label} source-built Rust std cleanup compile",
    )
    source_build_log_contract(stdout + stderr, rust_source)
    host_build_script_links(host_build_log, host_build_root)
    binary = cargo_artifact(stdout, package=package, target=target, name=binary_name, crate_type="bin")
    binary = physical(binary, f"{label} source-built cleanup executable", executable=True)
    binary_receipt_path, binary_link_output = cargo_link_receipt_for_artifact(
        binary, source_library_root, f"{label} source-built cleanup executable",
    )
    binary_receipt = source_built_link_receipt(
        binary_receipt_path, binary_link_output, source_library_root, f"{label} source-built cleanup link receipt",
    )
    consumer: dict[str, Any] = {
        "mode": mode,
        "rust_library_origin": "source-built",
        "lto": "fat",
        "cargo_command": [str(item) for item in command],
        "cargo_stdout": record_file(application / "cargo.stdout.jsonl", f"{label} Cargo JSON stream"),
        "cargo_stderr": record_file(application / "cargo.stderr.log", f"{label} Cargo diagnostics"),
        "rust_sysroot_log": record_file(application / "rust-sysroot.log", f"{label} Rust sysroot log"),
        "rust_source_library": str(rust_source),
        "rust_source_lock": record_file(rust_source_lock, f"{label} pinned rust-src lock"),
        "source_built_target_library_root": str(source_library_root),
        "host_build_script_links": record_file(host_build_log, f"{label} Cargo host build-script links"),
        "binary": record_file(binary, f"{label} source-built cleanup executable"),
        "link_receipt": record_file(binary_receipt_path, f"{label} source-built cleanup link receipt"),
        "link_command": binary_receipt["command"],
        "link_trace": binary_receipt["resolved_input_trace"],
    }
    if with_plugin:
        plugin = cargo_artifact(
            stdout, package=package, target=target, name="crabc_owned_cleanup_plugin", crate_type="cdylib",
        )
        plugin = physical(plugin, f"{label} source-built cleanup plugin")
        plugin_receipt_path, plugin_link_output = cargo_link_receipt_for_artifact(
            plugin, source_library_root, f"{label} source-built cleanup plugin",
        )
        plugin_receipt = source_built_link_receipt(
            plugin_receipt_path, plugin_link_output, source_library_root,
            f"{label} source-built cleanup plugin link receipt",
        )
        require(plugin_receipt.get("rust_requested_mode") == "shared",
                f"{label} source-built cleanup plugin was not linked as a shared object")
        consumer["plugin"] = {
            "binary": record_file(plugin, f"{label} source-built cleanup plugin"),
            "link_receipt": record_file(plugin_receipt_path, f"{label} source-built cleanup plugin link receipt"),
            "link_command": plugin_receipt["command"],
            "link_trace": plugin_receipt["resolved_input_trace"],
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
        result.returncode == 0 and result.stdout == "unwind: backtrace cleanup payload main thread dso\n"
        and result.stderr == "",
        "source-built Rust cleanup DSO execution did not prove owned loader discovery and cleanup",
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


def run(static_root: Path, dynamic_root: Path, output: Path | None = None) -> Path:
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
    run_logged([sys.executable, "-B", ROOT / "build.py", "--output", output / "provider"], environment,
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
        label="source-built-static", mode="static", root=Path(static["root"]), provider=provider, channel=channel,
        output=output, package=BUILD_STD_FIXTURE, binary_name=BUILD_STD_BINARY, with_plugin=False,
    )
    source_static_binary = Path(source_static["binary"]["path"])
    source_static_symbols = binary_unwind_symbols(
        source_static_binary, clean_environment(), output / "source-built-static" / "symbols.log",
        "source-built static cleanup symbol inventory",
    )
    cleanup.assert_binary_unwind_symbols(set(source_static_symbols), set(provider["defined_unwind_abi"]))
    source_static["defined_unwind_abi"] = source_static_symbols
    source_static["symbols_log"] = record_file(
        output / "source-built-static" / "symbols.log", "source-built static cleanup symbol inventory",
    )
    execute_mode("static", source_static, Path(dynamic["root"]), output / "source-built-static")
    source_dynamic_dso = compile_source_built_mode(
        label="source-built-dynamic-dso", mode="dynamic", root=Path(dynamic["root"]), provider=provider, channel=channel,
        output=output, package=BUILD_STD_DSO_FIXTURE, binary_name=BUILD_STD_DSO_HOST, with_plugin=True,
    )
    plugin = Path(source_dynamic_dso["plugin"]["binary"]["path"])
    plugin_symbols = binary_unwind_symbols(
        plugin, clean_environment(), output / "source-built-dynamic-dso" / "plugin-symbols.log",
        "source-built DSO cleanup plugin symbol inventory",
    )
    cleanup.assert_binary_unwind_symbols(set(plugin_symbols), set(provider["defined_unwind_abi"]))
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
    parser.add_argument("--static-sysroot", required=True, type=Path)
    parser.add_argument("--dynamic-sysroot", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="fresh checkout .work child for retained consumer evidence")
    arguments = parser.parse_args()
    try:
        print(run(arguments.static_sysroot, arguments.dynamic_sysroot, arguments.output))
    except (OwnedCleanupError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"crabc-owned-rust-std-cleanup: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
