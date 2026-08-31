#!/usr/bin/env python3
"""Assemble the private, static-only Linux/x86-64 owned-sysroot slice.

This builder installs only contracts that already have independent native x86
evidence: the regular-file project header tree, the five Rust CRT objects, a
reconstructed crabc-libc archive, and the bounded Rust compiler-helper archive.
It deliberately installs no compiler driver, shared libc, dynamic loader, or
compatibility linker-script aliases.  The native consumer gate owns the final
link trace and proves that these installed files are sufficient for one static
pthread/initial-TLS executable; this builder is not a general x86 sysroot or a
platform-promotion claim.
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
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-musl"
FORMAT = "crabc-x86-64-owned-static-sysroot-v1"
PINNED_TOOLCHAIN = "nightly-2026-07-24"
DEFAULT_OUTPUT = ROOT / "target" / "crabc-sysroot-x86_64-static"
CRT_OBJECTS = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
LIBC_MEMBER = re.compile(r"^c\..+\.rcgu\.o$")
STOCK_COMPILER_BUILTINS_MEMBER = re.compile(r"^compiler_builtins-.+\.rcgu\.o$")
STOCK_RUST_CORE_MEMBER = re.compile(
    r"^core-[0-9a-f]+\.core\.[0-9a-f]+-cgu\.[0-9]+\.rcgu\.o$"
)
NATIVE_COMPILER_RT_MEMBER = re.compile(
    r"^[0-9a-f]+-(?:absv|addv|cmp|div|ffs|fp_mode|int_util|mul|neg|parity|popcount|subv|ucmp)"
    r"[a-z0-9_]*\.o$"
)
REQUIRED_LIBC_SYMBOLS = frozenset(
    {
        "__crabc_x86_static_tls_bootstrap",
        "__errno_location",
        "__libc_start_main",
        "exit",
        "pthread_create",
        "pthread_join",
    }
)
SCOPE = "private-static-pthread-tls-consumer-slice-not-family-completion-not-public-support"
TARGET_RUNTIME_INPUTS = (
    "project regular-file headers",
    "Rust-produced x86 CRT objects",
    "crabc-libc c.*.rcgu.o members",
    "Rust-produced bounded x86 compiler helpers",
)
NOT_SELECTED = (
    "compiler driver",
    "shared libc",
    "dynamic loader or PT_INTERP",
    "dynamic link modes",
    "complete libc archive closure",
    "complete compiler-helper closure",
    "distribution archive or extracted smoke",
    "sysroot.static-tls family completion",
    "sysroot.owned-artifact family completion",
    "x86-64 promotion or public support",
)


class BuildError(RuntimeError):
    """An owned-input, reproducibility, or installed-tree invariant failed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        stream.write(encoded)
        temporary = Path(stream.name)
    temporary.replace(path)
    path.chmod(0o644)


def deterministic_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "LIBRARY_PATH",
        "COMPILER_PATH",
        "GCC_EXEC_PREFIX",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CC",
        "CFLAGS",
        "CXX",
        "CXXFLAGS",
        "CPPFLAGS",
        "AR",
        "ARFLAGS",
    ):
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("CARGO_TARGET_") and name.endswith(("_LINKER", "_RUSTFLAGS")):
            environment.pop(name, None)
        if name.startswith(("CC_", "CFLAGS_", "CXX_", "CXXFLAGS_", "AR_", "ARFLAGS_")):
            environment.pop(name, None)
    environment.update(
        {
            "CARGO_INCREMENTAL": "0",
            "LC_ALL": "C",
            "SOURCE_DATE_EPOCH": "1",
            "TZ": "UTC",
        }
    )
    return environment


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise BuildError(f"required build/inspection tool is unavailable: {name}")
    return path


def rust_target_tool(name: str) -> str:
    value = shutil.which(name)
    if value is not None:
        return value
    rustup = require_tool("rustup")
    completed = subprocess.run(
        [rustup, "run", PINNED_TOOLCHAIN, "rustc", "--print", "sysroot"],
        env=deterministic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BuildError(f"could not resolve pinned Rust toolchain for {name}: {completed.stderr}")
    sysroot = Path(completed.stdout.strip())
    for candidate in (
        sysroot / "lib" / "rustlib" / TARGET / "bin" / name,
        sysroot / "lib" / "rustlib" / TARGET / "bin" / "gcc-ld" / name,
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise BuildError(f"pinned Rust target tool is unavailable: {name}")


def run(command: Sequence[str], *, cwd: Path = ROOT) -> bytes:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=deterministic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise BuildError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout.decode(errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode(errors='replace')}"
        )
    return completed.stdout


def assert_native_target() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise BuildError("private owned-sysroot evidence requires native Linux/x86-64")


def validate_output_path(path: Path) -> Path:
    output = path.expanduser().resolve()
    if output in {Path("/"), ROOT, ROOT.parent}:
        raise BuildError("--output must name a dedicated directory")
    if output.parent == output:
        raise BuildError("--output must have a parent directory")
    return output


def remove_owned_output(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise BuildError(f"refusing to replace non-directory output: {path}")
    manifest = path / "share" / "crabc" / "manifest.json"
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"refusing to replace unrecognized output: {path}") from error
    if record.get("format") != FORMAT or record.get("target") != TARGET:
        raise BuildError(f"refusing to replace unrecognized output: {path}")
    shutil.rmtree(path)


def validate_relative_path(path: Path) -> None:
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BuildError(f"unsafe installed relative path: {path}")


def copy_regular_tree(source: Path, destination: Path) -> dict[str, str]:
    """Copy one regular-file-only tree with normalized installed modes."""

    if not source.is_dir() or source.is_symlink():
        raise BuildError(f"source tree is not a regular directory: {source}")
    destination.mkdir(parents=True, exist_ok=False)
    destination.chmod(0o755)
    records: dict[str, str] = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        validate_relative_path(relative)
        target = destination / relative
        if path.is_symlink():
            raise BuildError(f"source tree contains a symlink: {relative}")
        if path.is_dir():
            target.mkdir(exist_ok=False)
            target.chmod(0o755)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o644)
            records[relative.as_posix()] = sha256_file(target)
        else:
            raise BuildError(f"source tree contains a non-regular entry: {relative}")
    return records


def classify_libc_members(members: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not members or len(set(members)) != len(members):
        raise BuildError("Cargo libc archive has an empty or duplicate member roster")
    selected = tuple(member for member in members if LIBC_MEMBER.fullmatch(member))
    excluded = tuple(member for member in members if member not in selected)
    if not selected:
        raise BuildError("Cargo libc archive has no crabc Rust object members")
    unexpected = tuple(
        member
        for member in excluded
        if STOCK_COMPILER_BUILTINS_MEMBER.fullmatch(member) is None
        and STOCK_RUST_CORE_MEMBER.fullmatch(member) is None
        and NATIVE_COMPILER_RT_MEMBER.fullmatch(member) is None
    )
    if unexpected:
        raise BuildError(
            "Cargo libc archive contains unclassified target-runtime members: "
            + ", ".join(unexpected)
        )
    required_exclusions = {
        "stock compiler_builtins": any(
            STOCK_COMPILER_BUILTINS_MEMBER.fullmatch(member) for member in excluded
        ),
        "native compiler-rt": any(
            NATIVE_COMPILER_RT_MEMBER.fullmatch(member) for member in excluded
        ),
    }
    missing_exclusions = [name for name, present in required_exclusions.items() if not present]
    if missing_exclusions:
        raise BuildError(
            "Cargo libc archive did not expose required exclusion classes: "
            + ", ".join(missing_exclusions)
        )
    return selected, excluded


def archive_defined_symbols(nm: str, archive: Path) -> set[str]:
    output = run([nm, "--defined-only", "--extern-only", str(archive)])
    result: set[str] = set()
    for line in output.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and not line.endswith(":"):
            result.add(fields[-1])
    return result


def rebuild_libc_archive(source: Path, output: Path) -> dict[str, object]:
    llvm_ar = rust_target_tool("llvm-ar")
    llvm_nm = rust_target_tool("llvm-nm")
    members = tuple(
        line
        for line in run([llvm_ar, "t", str(source)]).decode("utf-8", errors="replace").splitlines()
        if line
    )
    selected, excluded = classify_libc_members(members)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="x86-libc-members.", dir=output.parent) as temporary:
        member_root = Path(temporary)
        run([llvm_ar, "x", str(source), *selected], cwd=member_root)
        selected_paths = tuple(member_root / member for member in selected)
        if any(not path.is_file() for path in selected_paths):
            raise BuildError("llvm-ar did not extract every selected crabc-libc member")
        run([llvm_ar, "rcsD", str(output), *(str(path) for path in selected_paths)])
        rebuilt = tuple(
            line
            for line in run([llvm_ar, "t", str(output)]).decode("utf-8", errors="replace").splitlines()
            if line
        )
        if rebuilt != selected:
            raise BuildError("deterministic libc archive member order drifted")
        member_hashes = {path.name: sha256_file(path) for path in selected_paths}
    defined = archive_defined_symbols(llvm_nm, output)
    missing = sorted(REQUIRED_LIBC_SYMBOLS.difference(defined))
    if missing:
        raise BuildError(f"reconstructed libc archive lacks selected runtime symbols: {missing}")
    return {
        "archive": {"name": output.name, "sha256": sha256_file(output)},
        "selected_members": [
            {"name": member, "sha256": member_hashes[member]} for member in selected
        ],
        "excluded_members": {
            "stock_compiler_builtins": [
                member for member in excluded if STOCK_COMPILER_BUILTINS_MEMBER.fullmatch(member)
            ],
            "stock_rust_core": [
                member for member in excluded if STOCK_RUST_CORE_MEMBER.fullmatch(member)
            ],
            "native_compiler_rt": [
                member for member in excluded if NATIVE_COMPILER_RT_MEMBER.fullmatch(member)
            ],
        },
        "required_defined_symbols": sorted(REQUIRED_LIBC_SYMBOLS),
        "policy": "only c.*.rcgu.o members are installed; stock core/compiler_builtins and native compiler-rt members are classified then excluded",
    }


def copy_artifact(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise BuildError(f"owned artifact is missing or unsafe: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def regular_file_hashes(root: Path, *, exclude: frozenset[str] = frozenset()) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise BuildError(f"installed tree contains a symlink: {path.relative_to(root)}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative not in exclude:
                result[relative] = sha256_file(path)
        elif not path.is_dir():
            raise BuildError(f"installed tree contains a non-regular entry: {path.relative_to(root)}")
    return result


def installed_manifest(payload_hashes: dict[str, str]) -> dict[str, object]:
    """Describe the bounded installed contract without promoting either family."""

    return {
        "schema": 1,
        "format": FORMAT,
        "target": TARGET,
        "toolchain": PINNED_TOOLCHAIN,
        "scope": SCOPE,
        "installed": {
            "headers": "usr/include",
            "crt_objects": [f"usr/lib/{name}" for name in CRT_OBJECTS],
            "static_libc": "usr/lib/libc.a",
            "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
            "files": payload_hashes,
        },
        "purity": {
            "target_runtime_inputs": list(TARGET_RUNTIME_INPUTS),
            "stock_compiler_builtins_members_installed": False,
            "ambient_target_crt_or_library_installed": False,
            "symlinks_installed": False,
        },
        "not_selected": list(NOT_SELECTED),
    }


def build_runtime_inputs(stage: Path) -> dict[str, object]:
    rustup = require_tool("rustup")
    python = sys.executable
    cargo_root = stage / "cargo"
    cargo_command = [
        rustup,
        "run",
        PINNED_TOOLCHAIN,
        "cargo",
        "rustc",
        "--locked",
        "-p",
        "crabc-libc",
        "--lib",
        "--release",
        "--target",
        TARGET,
        "--target-dir",
        str(cargo_root),
        "--",
        "-C",
        "relocation-model=static",
        "-C",
        "code-model=small",
        "-C",
        "panic=abort",
        "--remap-path-prefix",
        f"{ROOT}=/crabc",
    ]
    run(cargo_command)
    raw_libc = cargo_root / TARGET / "release" / "libc.a"
    if not raw_libc.is_file():
        raise BuildError("Cargo did not produce the x86 crabc-libc static archive")

    crt_root = stage / "crt"
    run(
        [
            python,
            str(ROOT / "crt" / "build_x86_64.py"),
            "--out-dir",
            str(crt_root),
            "--llvm-objdump",
            rust_target_tool("llvm-objdump"),
        ]
    )
    builtins_root = stage / "builtins"
    builtins_root.mkdir()
    builtins = builtins_root / "libcrabc-builtins.a"
    builtins_provenance = builtins_root / "provenance.json"
    run(
        [
            python,
            str(ROOT / "builtins" / "build_x86_64.py"),
            "--output",
            str(builtins),
            "--provenance",
            str(builtins_provenance),
            "--verify-reproducible",
        ]
    )
    libc = stage / "runtime" / "libc.a"
    libc_provenance = rebuild_libc_archive(raw_libc, libc)
    return {
        "cargo_command": [
            "rustup",
            "run",
            PINNED_TOOLCHAIN,
            "cargo",
            "rustc",
            "--locked",
            "-p",
            "crabc-libc",
            "--lib",
            "--release",
            "--target",
            TARGET,
            "--target-dir",
            "$CRABC_X86_BUILD/cargo",
            "--",
            "-C",
            "relocation-model=static",
            "-C",
            "code-model=small",
            "-C",
            "panic=abort",
            "--remap-path-prefix",
            "$CRABC_SOURCE=/crabc",
        ],
        "crt_root": crt_root,
        "builtins": builtins,
        "builtins_provenance": builtins_provenance,
        "libc": libc,
        "libc_provenance": libc_provenance,
    }


def assemble(output: Path, inputs: dict[str, object]) -> dict[str, object]:
    remove_owned_output(output)
    output.mkdir(parents=True)
    output.chmod(0o755)
    include_manifest = copy_regular_tree(ROOT / "include", output / "usr" / "include")
    library_root = output / "usr" / "lib"
    library_root.mkdir(parents=True)
    library_root.chmod(0o755)
    crt_root = inputs["crt_root"]
    assert isinstance(crt_root, Path)
    for name in CRT_OBJECTS:
        copy_artifact(crt_root / name, library_root / name)
    libc = inputs["libc"]
    builtins = inputs["builtins"]
    assert isinstance(libc, Path) and isinstance(builtins, Path)
    copy_artifact(libc, library_root / "libc.a")
    copy_artifact(builtins, library_root / "libcrabc-builtins.a")

    metadata_root = output / "share" / "crabc"
    copy_artifact(crt_root / "objects.json", metadata_root / "crt.provenance.json")
    copy_artifact(crt_root / "commands.json", metadata_root / "crt.commands.json")
    builtins_provenance = inputs["builtins_provenance"]
    assert isinstance(builtins_provenance, Path)
    copy_artifact(
        builtins_provenance,
        metadata_root / "libcrabc-builtins.provenance.json",
    )
    libc_provenance = inputs["libc_provenance"]
    assert isinstance(libc_provenance, dict)
    write_json(metadata_root / "libc-static.provenance.json", libc_provenance)
    write_json(
        metadata_root / "headers.provenance.json",
        {
            "schema": 1,
            "source": "include",
            "regular_file_count": len(include_manifest),
            "files": include_manifest,
        },
    )
    cargo_command = inputs["cargo_command"]
    assert isinstance(cargo_command, list)
    write_json(
        metadata_root / "build.commands.json",
        {
            "schema": 1,
            "target": TARGET,
            "commands": {
                "libc": cargo_command,
                "crt": [
                    "python3",
                    "crt/build_x86_64.py",
                    "--out-dir",
                    "$CRABC_X86_BUILD/crt",
                ],
                "builtins": [
                    "python3",
                    "builtins/build_x86_64.py",
                    "--output",
                    "$CRABC_X86_BUILD/builtins/libcrabc-builtins.a",
                    "--verify-reproducible",
                ],
            },
        },
    )

    manifest_path = metadata_root / "manifest.json"
    payload_hashes = regular_file_hashes(
        output,
        exclude=frozenset({manifest_path.relative_to(output).as_posix()}),
    )
    manifest = installed_manifest(payload_hashes)
    write_json(manifest_path, manifest)
    installed_hashes = regular_file_hashes(output)
    expected = set(payload_hashes) | {manifest_path.relative_to(output).as_posix()}
    if set(installed_hashes) != expected:
        raise BuildError("installed tree changed while writing its manifest")
    return manifest


def build(output: Path) -> dict[str, object]:
    assert_native_target()
    output = validate_output_path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="crabc-x86-owned-sysroot.", dir=output.parent) as temporary:
        temporary_root = Path(temporary)
        inputs = build_runtime_inputs(temporary_root)
        staged_output = temporary_root / "installed"
        manifest = assemble(staged_output, inputs)
        remove_owned_output(output)
        staged_output.replace(output)
        return manifest


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        parsed = parse_args(arguments)
        manifest = build(parsed.output)
    except BuildError as error:
        print(f"x86 owned static sysroot failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
