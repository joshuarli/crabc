#!/usr/bin/env python3
"""Assemble the private, static-only Linux/x86-64 owned-sysroot slice.

This builder installs only contracts that already have independent native x86
evidence: the regular-file project header tree, the five Rust CRT objects, a
reconstructed crabc-libc archive, and the bounded Rust compiler-helper archive.
It installs a deliberately narrow sealed ``bin/crabc-cc`` product seed in
addition to those runtime files.  The driver names only installed static
inputs for ET_EXEC or static-PIE and rejects ambient target-runtime injection;
it does not establish the product coverage, either sysroot family, or x86
platform support.  Shared libc, a dynamic loader, and compatibility
linker-script aliases remain deliberately absent.
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
PINNED_CARGO_HOME = Path("/opt/cargo")
PINNED_RUSTUP_HOME = Path("/opt/rustup")
PINNED_TARGET_TOOLS = ("llvm-ar", "llvm-nm", "llvm-objdump")
FIXED_HOST_BUILD_PATH = "/usr/bin:/bin"
DEFAULT_OUTPUT = ROOT / "target" / "crabc-sysroot-x86_64-static"
CRT_OBJECTS = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
STATIC_DRIVER_SOURCE = ROOT / "compat" / "x86_64" / "crabc_cc_static.py"
STATIC_DRIVER_PATH = "bin/crabc-cc"
PACKAGE_FORMAT = "crabc-x86-64-owned-static-sysroot-package/v1"
PACKAGE_ARCHIVE_ROOT = "crabc-x86_64-owned-static-sysroot"
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
    "shared libc",
    "dynamic loader or PT_INTERP",
    "dynamic link modes",
    "complete libc archive closure",
    "complete compiler-helper closure",
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
    """Return the complete producer environment, never a filtered caller copy.

    The owned-static artifact is meaningful only if its Rust and LLVM producer
    inputs are selected by the pinned evidence image.  In particular, neither
    a caller's ``PATH`` nor its ``CARGO_HOME``/``RUSTUP_HOME`` may redirect a
    toolchain proxy or target tool. The executable selection stays pinned,
    while Cargo's writable registry and producer scratch belong to the checkout.
    """

    work_root = ROOT.resolve() / ".work" / "x86_64"
    state_paths = {"CARGO_HOME": work_root / "cargo", "TMPDIR": work_root / "tmp"}
    # Validate both paths before creating either: a late escaping scratch
    # symlink must not leave behind a newly created Cargo directory.
    for path in state_paths.values():
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError) as error:
            raise BuildError(f"unsafe producer build state: {path}") from error
        if not resolved.is_relative_to(work_root):
            raise BuildError(f"producer build state escapes checkout: {path}")
        if resolved.exists() and not resolved.is_dir():
            raise BuildError(f"producer build state is not a directory: {path}")
    for path in state_paths.values():
        path.mkdir(parents=True, exist_ok=True)

    return {
        **{name: str(path) for name, path in state_paths.items()},
        "RUSTUP_HOME": str(PINNED_RUSTUP_HOME),
        # Cargo runs a host build script while producing crabc-libc.  Its
        # compiler must remain available, but this is a fixed evidence-image
        # baseline rather than a caller-derived search path.  Rustup itself
        # remains first, and every target LLVM tool below is an absolute path
        # resolved from the selected nightly sysroot.
        "PATH": f"{PINNED_CARGO_HOME / 'bin'}:{FIXED_HOST_BUILD_PATH}",
        "CARGO_INCREMENTAL": "0",
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "1",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def required_executable(path: Path, description: str, *, within: Path | None = None) -> Path:
    """Resolve one fixed executable and optionally require its closed root."""

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BuildError(f"{description} is missing or unsafe: {path}") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BuildError(f"{description} is missing or not executable: {path}")
    if within is not None:
        try:
            resolved.relative_to(within.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as error:
            raise BuildError(f"{description} escapes its pinned toolchain root: {path}") from error
    return resolved


def executable_identity(path: Path, description: str, *, within: Path | None = None) -> dict[str, str]:
    """Record both a stable selection path and the digest of its resolved binary."""

    resolved = required_executable(path, description, within=within)
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "sha256": sha256_file(resolved),
    }


def pinned_rustup() -> Path:
    """Return the image-owned frontend without consulting ambient ``PATH``."""

    path = PINNED_CARGO_HOME / "bin" / "rustup"
    required_executable(path, "pinned rustup")
    return path


def pinned_rustc_sysroot(rustup: Path) -> Path:
    """Ask the fixed frontend for the one permitted pinned nightly sysroot."""

    completed = subprocess.run(
        [str(rustup), "run", PINNED_TOOLCHAIN, "rustc", "--print", "sysroot"],
        env=deterministic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BuildError(f"could not resolve pinned Rust toolchain: {completed.stderr}")
    reported = completed.stdout.strip()
    if not reported or "\n" in reported:
        raise BuildError("pinned Rust toolchain reported an unsafe sysroot")
    path = Path(reported)
    if not path.is_absolute():
        raise BuildError("pinned Rust toolchain reported a relative sysroot")
    try:
        resolved = path.resolve(strict=True)
        toolchains = (PINNED_RUSTUP_HOME / "toolchains").resolve(strict=True)
        resolved.relative_to(toolchains)
    except (OSError, RuntimeError, ValueError) as error:
        raise BuildError("pinned Rust toolchain sysroot escapes /opt/rustup/toolchains") from error
    if not (
        resolved.name == PINNED_TOOLCHAIN
        or resolved.name.startswith(f"{PINNED_TOOLCHAIN}-")
    ):
        raise BuildError(f"pinned Rust toolchain name drifted: {resolved.name}")
    return resolved


def pinned_rustc_version(rustup: Path) -> dict[str, str]:
    """Capture the immutable compiler identity selected by the fixed frontend."""

    completed = subprocess.run(
        [str(rustup), "run", PINNED_TOOLCHAIN, "rustc", "-Vv"],
        env=deterministic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BuildError(f"could not identify pinned Rust toolchain: {completed.stderr}")
    fields: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        name, separator, value = line.partition(": ")
        if separator:
            fields[name] = value
    required = ("release", "commit-hash", "commit-date", "host")
    missing = [name for name in required if not fields.get(name)]
    if missing:
        raise BuildError(f"pinned rustc -Vv lacks identity fields: {', '.join(missing)}")
    if "nightly" not in fields["release"]:
        raise BuildError("pinned rustc identity is not a nightly compiler")
    return {
        "release": fields["release"],
        "commit_hash": fields["commit-hash"],
        "commit_date": fields["commit-date"],
        "host": fields["host"],
    }


def pinned_target_tool(path_root: Path, name: str) -> dict[str, str]:
    """Resolve a target LLVM binary only underneath the selected nightly sysroot."""

    if name not in PINNED_TARGET_TOOLS:
        raise BuildError(f"unrecognized pinned LLVM target tool: {name}")
    path = path_root / "lib" / "rustlib" / TARGET / "bin" / name
    return executable_identity(path, f"pinned Rust target tool {name}", within=path_root)


def resolve_pinned_producer_tools() -> dict[str, object]:
    """Resolve and fingerprint every Rust/LLVM producer used by this builder."""

    rustup = pinned_rustup()
    sysroot = pinned_rustc_sysroot(rustup)
    return {
        "schema": 1,
        "toolchain": PINNED_TOOLCHAIN,
        "target": TARGET,
        "selection": {
            "cargo_home": "$CRABC_SOURCE/.work/x86_64/cargo",
            "rustup_home": str(PINNED_RUSTUP_HOME),
            "path": f"{PINNED_CARGO_HOME / 'bin'}:{FIXED_HOST_BUILD_PATH}",
            "rustup_bin": str(PINNED_CARGO_HOME / "bin"),
            "ambient_path_inherited": False,
            "ambient_cargo_home_inherited": False,
            "ambient_rustup_home_inherited": False,
        },
        "rustup": executable_identity(rustup, "pinned rustup"),
        "rustc": {
            "sysroot": str(sysroot),
            "version": pinned_rustc_version(rustup),
        },
        "llvm_target_tools": {
            name: pinned_target_tool(sysroot, name) for name in PINNED_TARGET_TOOLS
        },
    }


def producer_tool_path(producer_tools: dict[str, object], name: str) -> str:
    """Extract an already-resolved producer tool path without a second lookup."""

    tools = producer_tools.get("llvm_target_tools")
    if not isinstance(tools, dict):
        raise BuildError("pinned producer record lacks LLVM target tools")
    identity = tools.get(name)
    if not isinstance(identity, dict):
        raise BuildError(f"pinned producer record lacks {name}")
    path = identity.get("path")
    if not isinstance(path, str) or not path:
        raise BuildError(f"pinned producer record has no {name} path")
    return path


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
    unsafe = tuple(
        member
        for member in members
        if (
            not member
            or member in {".", ".."}
            or "/" in member
            or "\\" in member
            or "\x00" in member
        )
    )
    if unsafe:
        raise BuildError(
            "Cargo libc archive has an unsafe member path: " + ", ".join(unsafe)
        )
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


def rebuild_libc_archive(
    source: Path, output: Path, *, llvm_ar: str, llvm_nm: str
) -> dict[str, object]:
    """Rebuild from the already-attested target LLVM archive tools."""

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


def install_static_driver(destination: Path) -> None:
    """Install the audited static-only driver as an executable regular file."""

    copy_artifact(STATIC_DRIVER_SOURCE, destination)
    destination.chmod(0o755)


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


def installed_manifest(
    payload_hashes: dict[str, str], producer_tools: dict[str, object]
) -> dict[str, object]:
    """Describe the bounded installed contract without promoting either family."""

    return {
        "schema": 1,
        "format": FORMAT,
        "target": TARGET,
        "toolchain": PINNED_TOOLCHAIN,
        "producer_tools": producer_tools,
        "scope": SCOPE,
        "package": {
            "format": PACKAGE_FORMAT,
            "archive_root": PACKAGE_ARCHIVE_ROOT,
        },
        "installed": {
            "headers": "usr/include",
            "crt_objects": [f"usr/lib/{name}" for name in CRT_OBJECTS],
            "static_libc": "usr/lib/libc.a",
            "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
            "sealed_static_driver": STATIC_DRIVER_PATH,
            "files": payload_hashes,
        },
        "sealed_static_driver": {
            "format": "crabc-x86-64-sealed-static-driver-v1",
            "path": STATIC_DRIVER_PATH,
            "status": "planned-owned-static-product-seed-not-family-completion-not-public-support",
            "modes": [
                {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"},
                {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"},
            ],
            "rejected_ambient_target_inputs": [
                "headers",
                "CRT",
                "libc",
                "libgcc",
                "compiler-rt",
                "loader",
            ],
            "not_proven_by_this_seed": [
                "accepted allocator backend",
                "complete libc archive closure",
                "complete compiler-helper closure",
                "declared static-product coverage suite",
                "sysroot.static-tls family completion",
                "sysroot.owned-artifact family completion",
                "x86-64 promotion or public support",
            ],
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
    producer_tools = resolve_pinned_producer_tools()
    rustup_record = producer_tools["rustup"]
    if not isinstance(rustup_record, dict):
        raise BuildError("pinned producer record lacks rustup")
    rustup = rustup_record.get("path")
    if not isinstance(rustup, str) or not rustup:
        raise BuildError("pinned producer record has no rustup path")
    llvm_ar = producer_tool_path(producer_tools, "llvm-ar")
    llvm_nm = producer_tool_path(producer_tools, "llvm-nm")
    llvm_objdump = producer_tool_path(producer_tools, "llvm-objdump")
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
        "--cfg",
        "crabc_owned_static_sysroot",
        "-C",
        "relocation-model=pic",
        "-C",
        "code-model=small",
        "-C",
        "panic=abort",
        "-Ztls-model=initial-exec",
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
            llvm_objdump,
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
    libc_provenance = rebuild_libc_archive(
        raw_libc,
        libc,
        llvm_ar=llvm_ar,
        llvm_nm=llvm_nm,
    )
    return {
        "cargo_command": [
            "$CRABC_PINNED_CARGO_HOME/bin/rustup",
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
            "--cfg",
            "crabc_owned_static_sysroot",
            "-C",
            "relocation-model=pic",
            "-C",
            "code-model=small",
            "-C",
            "panic=abort",
            "-Ztls-model=initial-exec",
            "--remap-path-prefix",
            "$CRABC_SOURCE=/crabc",
        ],
        "crt_root": crt_root,
        "builtins": builtins,
        "builtins_provenance": builtins_provenance,
        "libc": libc,
        "libc_provenance": libc_provenance,
        "producer_tools": producer_tools,
    }


def build_commands_record(
    cargo_command: list[str], producer_tools: dict[str, object]
) -> dict[str, object]:
    """Make the installed build record carry the exact producer identity."""

    return {
        "schema": 1,
        "target": TARGET,
        "producer_tools": producer_tools,
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
    }


def assemble(output: Path, inputs: dict[str, object]) -> dict[str, object]:
    remove_owned_output(output)
    output.mkdir(parents=True)
    output.chmod(0o755)
    include_manifest = copy_regular_tree(ROOT / "include", output / "usr" / "include")
    install_static_driver(output / STATIC_DRIVER_PATH)
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
    producer_tools = inputs["producer_tools"]
    assert isinstance(cargo_command, list) and isinstance(producer_tools, dict)
    write_json(
        metadata_root / "build.commands.json",
        build_commands_record(cargo_command, producer_tools),
    )

    manifest_path = metadata_root / "manifest.json"
    payload_hashes = regular_file_hashes(
        output,
        exclude=frozenset({manifest_path.relative_to(output).as_posix()}),
    )
    manifest = installed_manifest(payload_hashes, producer_tools)
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
