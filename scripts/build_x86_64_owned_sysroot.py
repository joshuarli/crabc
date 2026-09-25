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
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.rust_toolchain import pinned_toolchain
TARGET = "x86_64-unknown-linux-musl"
FORMAT = "crabc-x86-64-owned-static-sysroot-v1"
PINNED_TOOLCHAIN = pinned_toolchain(ROOT)
PINNED_CARGO_HOME = Path("/opt/cargo")
PINNED_RUSTUP_HOME = Path("/opt/rustup")
PINNED_TARGET_TOOLS = ("llvm-ar", "llvm-nm", "llvm-objdump")
FIXED_HOST_BUILD_PATH = "/usr/bin:/bin"
DEFAULT_OUTPUT = ROOT / ".work" / "x86_64" / "owned-static-sysroot"
CRT_OBJECTS = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
STATIC_DRIVER_SOURCE = ROOT / "compat" / "x86_64" / "crabc_cc_static.py"
STATIC_DRIVER_PATH = "bin/crabc-cc"
PACKAGE_FORMAT = "crabc-x86-64-owned-static-sysroot-package/v1"
PACKAGE_ARCHIVE_ROOT = "crabc-x86_64-owned-static-sysroot"
LIBC_MEMBER = re.compile(r"^c\..+\.rcgu\.o$")
ALLOCATOR_MEMBER = re.compile(r"^[0-9a-f]+-static\.o$")
C_ALLOCATOR_PIN = {
    "name": "libmimalloc-sys",
    "version": "0.1.49",
    "checksum": "6a45a52f43e1c16f667ccfe4dd8c85b7f7c204fd5e3bf46c5b0db9a5c3c0b8e9",
}
# The C backend's compiler constructor is disabled only when this matching
# Rust cfg selects the private same-image replacement entries.  Keeping the
# two spellings here makes the product builder, rather than an ambient Cargo
# invocation, the authority for this coupled lifecycle profile.
MIMALLOC_LIFECYCLE_C_FLAG = "-DMI_PRIM_HAS_PROCESS_ATTACH=1"
MIMALLOC_LIFECYCLE_RUST_CFG = "crabc_owned_mimalloc_lifecycle"
MIMALLOC_LIFECYCLE_INIT_SYMBOL = "__crabc_x86_owned_mimalloc_process_initializer"
MIMALLOC_LIFECYCLE_FINI_SYMBOL = "__crabc_x86_owned_mimalloc_process_finalizer"
STOCK_COMPILER_BUILTINS_MEMBER = re.compile(r"^compiler_builtins-.+\.rcgu\.o$")
STOCK_RUST_CORE_MEMBER = re.compile(
    r"^core-[0-9a-f]+\.core\.[0-9a-f]+-cgu\.[0-9]+\.rcgu\.o$"
)
NATIVE_COMPILER_RT_MEMBER = re.compile(
    r"^[0-9a-f]+-(?:absv|addv|cmp|div|ffs|fp_mode|int_util|mul|neg|parity|popcount|subv|ucmp)"
    r"[a-z0-9_]*\.o$"
)
# Ordinary archive extraction needs libc providers in separate members: an
# application that defines one libc function must not collide with the rest
# of libc, as it does not with musl's one-object-per-source-file libc.a. The
# workspace release profile's fat LTO with one codegen unit fuses all of libc
# into one object. ThinLTO keeps cross-crate optimization and the stock
# `core` closure (so no unwinding `core` member or personality escapes into
# the archive) while emitting one member per codegen unit; a unit ceiling above
# libc's module count gives each Rust module its own member, and rustc never
# splits a module to reach it. Member names derive from crate and module
# names, so their order stays deterministic.
STATIC_ARCHIVE_PROFILE = (
    "--config",
    'profile.release.lto="thin"',
    "--config",
    "profile.release.codegen-units=65536",
)
REQUIRED_LIBC_SYMBOLS = frozenset(
    {
        "__crabc_x86_static_tls_bootstrap",
        "__errno_location",
        "__libc_start_main",
        "__stack_chk_guard",
        "exit",
        "clone",
        "vfork",
        "daemon",
        "pthread_create",
        "pthread_join",
        "fdopen",
        "flockfile",
        "ftrylockfile",
        "funlockfile",
        "__stdio_exit",
        "fflush",
        "fprintf",
        "fscanf",
    }
)
SCOPE = "private-static-pthread-tls-consumer-slice-not-family-completion-not-public-support"
TARGET_RUNTIME_INPUTS = (
    "project regular-file headers",
    "Rust-produced x86 CRT objects",
    "crabc-libc c.*.rcgu.o members",
    "Cargo-pinned libmimalloc-sys C allocator compiled against project headers",
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


def run(
    command: Sequence[str], *, cwd: Path = ROOT, environment: dict[str, str] | None = None
) -> bytes:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=deterministic_environment() if environment is None else environment,
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


def owned_mimalloc_lifecycle_profile(
    c_flags: Sequence[str], cargo_command: Sequence[str], allocator_archive: Path,
    raw_libc: Path, *, llvm_ar: str, llvm_nm: str, llvm_objdump: str, stage: Path,
) -> dict[str, object]:
    """Reject a one-sided C/Rust automatic-mimalloc lifecycle selection.

    The locked C source owns the normal compiler constructor. These native
    products suppress it only because the same Cargo invocation selects the
    private Rust entries below. Inspect the produced C object and raw Rust
    archive as well as the commands, so changing just a flag or just a cfg
    cannot silently create a missing or duplicate process callback.
    """

    if c_flags.count(MIMALLOC_LIFECYCLE_C_FLAG) != 1 or any(
        flag.startswith("-DMI_PRIM_HAS_PROCESS_ATTACH") and flag != MIMALLOC_LIFECYCLE_C_FLAG
        for flag in c_flags
    ):
        raise BuildError("owned mimalloc lifecycle C profile is missing or ambiguous")
    if sum(
        (cargo_command[index], cargo_command[index + 1]) == ("--cfg", MIMALLOC_LIFECYCLE_RUST_CFG)
        for index in range(len(cargo_command) - 1)
    ) != 1:
        raise BuildError("owned mimalloc lifecycle Rust cfg is missing or ambiguous")

    members = run([llvm_ar, "t", str(allocator_archive)]).decode("utf-8", errors="replace").splitlines()
    if len(members) != 1 or ALLOCATOR_MEMBER.fullmatch(members[0]) is None:
        raise BuildError("owned mimalloc lifecycle requires one accepted allocator object")
    if stage.exists() or stage.is_symlink():
        raise BuildError("owned mimalloc lifecycle inspection path is already occupied")
    stage.mkdir(mode=0o700)
    backend = stage / members[0]
    backend.write_bytes(run([llvm_ar, "p", str(allocator_archive), members[0]]))
    sections = run([llvm_objdump, "--section-headers", str(backend)]).decode("utf-8", errors="replace")
    symbols = run([llvm_nm, str(backend)]).decode("utf-8", errors="replace")
    if re.search(r"\.(?:init|fini)_array\b", sections) or re.search(
        r"(?m)^.*\bmi_process_(?:attach|detach)$", symbols
    ):
        raise BuildError("accepted allocator retains its implicit process attach/detach hooks")

    rust_symbols = run([llvm_nm, "--defined-only", str(raw_libc)]).decode("utf-8", errors="replace")
    for symbol in (MIMALLOC_LIFECYCLE_INIT_SYMBOL, MIMALLOC_LIFECYCLE_FINI_SYMBOL):
        entry_types = re.findall(
            rf"(?m)^[0-9A-Fa-f]+\s+([A-Za-z])\s+{re.escape(symbol)}$", rust_symbols,
        )
        if entry_types != ["d"]:
            raise BuildError(f"raw libc lacks exactly one local-data owned mimalloc lifecycle entry: {symbol}")
    return {
        "c_define": MIMALLOC_LIFECYCLE_C_FLAG,
        "rust_cfg": MIMALLOC_LIFECYCLE_RUST_CFG,
        "backend_implicit_attach_detach": "absent",
        "same_image_entries": [MIMALLOC_LIFECYCLE_INIT_SYMBOL, MIMALLOC_LIFECYCLE_FINI_SYMBOL],
    }


def assert_native_target() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise BuildError("private owned-sysroot evidence requires native Linux/x86-64")


def validate_output_path(path: Path) -> Path:
    # Preserve the requested spelling until it has been checked. Resolving
    # first would hide a symlink from remove_owned_output's replacement guard.
    output = path.expanduser().absolute()
    try:
        resolved = output.resolve()
    except (OSError, RuntimeError) as error:
        raise BuildError("--output has an unsafe filesystem path") from error
    if resolved != output:
        raise BuildError("--output must not cross a symlink or contain traversal")
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


def classify_libc_members(
    members: Sequence[str], *, allocator_member: str | None = None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
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
    if allocator_member is not None and (
        ALLOCATOR_MEMBER.fullmatch(allocator_member) is None or allocator_member not in members
    ):
        raise BuildError("attested allocator member is invalid or absent from Cargo libc")
    selected = tuple(
        member for member in members
        if LIBC_MEMBER.fullmatch(member) or member == allocator_member
    )
    excluded = tuple(member for member in members if member not in selected)
    if not any(LIBC_MEMBER.fullmatch(member) for member in selected):
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
    source: Path, output: Path, *, llvm_ar: str, llvm_nm: str,
    allocator_archive: Path | None = None,
) -> dict[str, object]:
    """Rebuild from the already-attested target LLVM archive tools."""

    members = tuple(
        line
        for line in run([llvm_ar, "t", str(source)]).decode("utf-8", errors="replace").splitlines()
        if line
    )
    allocator_record = None
    allocator_member = None
    if allocator_archive is not None:
        # The backend must be the exact single object produced by the locked
        # dependency build, not any archive member with a convenient suffix.
        backend_members = run([llvm_ar, "t", str(allocator_archive)]).decode().splitlines()
        if len(backend_members) != 1 or ALLOCATOR_MEMBER.fullmatch(backend_members[0]) is None:
            raise BuildError("accepted allocator archive must contain one named static object")
        allocator_member = backend_members[0]
        backend_object = run([llvm_ar, "p", str(allocator_archive), allocator_member])
        cargo_object = run([llvm_ar, "p", str(source), allocator_member])
        if backend_object != cargo_object:
            raise BuildError("Cargo libc allocator object differs from its dependency producer")
        allocator_record = {
            "crate": dict(C_ALLOCATOR_PIN),
            "archive_sha256": sha256_file(allocator_archive),
            "member": allocator_member,
            "member_sha256": hashlib.sha256(backend_object).hexdigest(),
            "implementation": "accepted C backend; native Rust promotion remains separate",
        }
    selected, excluded = classify_libc_members(members, allocator_member=allocator_member)
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
    result = {
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
        "policy": "crabc objects and the explicitly attested allocator object only; stock core/compiler_builtins and native compiler-rt members are classified then excluded",
    }
    if allocator_record is not None:
        result["allocator_backend"] = allocator_record
    return result


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
    payload_hashes: dict[str, str], producer_tools: dict[str, object],
    *, allocator_backend: str = "accepted-c",
) -> dict[str, object]:
    """Describe the bounded installed contract without promoting either family."""

    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise BuildError("unknown owned allocator backend")
    target_inputs = list(TARGET_RUNTIME_INPUTS)
    if allocator_backend in NATIVE_ALLOCATOR_BACKENDS:
        target_inputs[3] = "fixed-upstream Rust mimalloc in the selected crabc-libc Rust object"
    if allocator_backend == EVIDENCE_ALLOCATOR_BACKEND:
        target_inputs[3] = "exact pinned mimalloc v3.5.0 src/static.c in place of the libmimalloc-sys object (evidence only)"
    return {
        "schema": 1,
        "format": FORMAT,
        "target": TARGET,
        "toolchain": PINNED_TOOLCHAIN,
        "producer_tools": producer_tools,
        "scope": EVIDENCE_SCOPE if allocator_backend == EVIDENCE_ALLOCATOR_BACKEND else SCOPE,
        "allocator_backend": allocator_backend,
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
                "complete libc archive closure",
                "complete compiler-helper closure",
                "declared static-product coverage suite",
                "sysroot.static-tls family completion",
                "sysroot.owned-artifact family completion",
                "x86-64 promotion or public support",
            ],
        },
        "purity": {
            "target_runtime_inputs": target_inputs,
            "stock_compiler_builtins_members_installed": False,
            "ambient_target_crt_or_library_installed": False,
            "symlinks_installed": False,
        },
        "not_selected": list(NOT_SELECTED),
    }


def accepted_allocator_pin() -> dict[str, str]:
    """Bind the accepted backend to the reviewed Cargo lock, not a filename."""

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    packages = [item for item in lock.get("package", []) if item.get("name") == C_ALLOCATOR_PIN["name"]]
    if len(packages) != 1 or any(packages[0].get(key) != value for key, value in C_ALLOCATOR_PIN.items()):
        raise BuildError("accepted allocator Cargo pin changed; review its production provenance")
    return dict(C_ALLOCATOR_PIN)


def allocator_header_provenance(dependencies: Path, cargo_home: Path) -> dict[str, str]:
    """Reject target headers outside the project and pinned allocator source."""

    packages = list((cargo_home / "registry/src").glob("*/libmimalloc-sys-0.1.49"))
    if len(packages) != 1:
        raise BuildError("accepted allocator source package is absent or ambiguous")
    package = packages[0].resolve()
    source_root = package / "c_src/mimalloc/v3"
    if not package.is_relative_to(cargo_home.resolve()):
        raise BuildError("accepted allocator source package escapes the checkout cache")
    text = dependencies.read_text(encoding="utf-8").replace("\\\n", " ")
    _, separator, inputs = text.partition(":")
    if not separator:
        raise BuildError("allocator compiler dependency trace has no target")
    records: dict[str, str] = {}
    for spelling in shlex.split(inputs):
        path = Path(spelling)
        path = (path if path.is_absolute() else package / path).resolve(strict=True)
        if path.is_relative_to(ROOT / "include"):
            name = path.relative_to(ROOT).as_posix()
        elif path.is_relative_to(source_root):
            name = "libmimalloc-sys/" + path.relative_to(package).as_posix()
        else:
            raise BuildError(f"allocator compiler used an unowned source/header: {path}")
        records[name] = sha256_file(path)
    if "libmimalloc-sys/c_src/mimalloc/v3/src/static.c" not in records or not any(
        name.startswith("include/") for name in records
    ):
        raise BuildError("allocator dependency trace lacks its source or project headers")
    return records


ALLOCATOR_BACKENDS = ("accepted-c", "native-shadow", "pinned-c-evidence", "native")
# The one compile-time default. Allocator M10 switches it to "native" in this
# single line once `allocator-m10 --check` passes; nothing else selects it.
DEFAULT_ALLOCATOR_BACKEND = "accepted-c"
# `native` is the production-shaped Rust allocator product: the same Rust
# selection as the evidence-only `native-shadow` build (so the identical
# libc Cargo features), but refused together with any test-audit feature and
# audited for the complete absence of C mimalloc by
# compat/allocator/x86_64_m10_gate.py.
NATIVE_ALLOCATOR_BACKEND = "native"
NATIVE_ALLOCATOR_BACKENDS = ("native-shadow", NATIVE_ALLOCATOR_BACKEND)


def backend_selection(allocator_backend: str, lifecycle_test_audit: bool) -> str:
    """The compile-time build selection a recorded backend uses."""

    if allocator_backend == NATIVE_ALLOCATOR_BACKEND:
        if lifecycle_test_audit:
            raise BuildError("the production native backend admits no allocator test-audit feature")
        return "native-shadow"
    return allocator_backend
# `pinned-c-evidence` is never a production product: it is the accepted-C
# build with its one libmimalloc-sys object replaced by exact pinned
# mimalloc v3.5.0 `src/static.c`, compiled by the command that reproduces
# that libmimalloc-sys object byte for byte. It exists only as the C
# reference of the allocator's integrated-product comparison
# (compat/allocator/perf_integrated_x86_64.py). Its product records
# `allocator_backend = "pinned-c-evidence"` and an evidence-only scope, so no
# production qualification, which selects `accepted-c`, can admit it.
EVIDENCE_ALLOCATOR_BACKEND = "pinned-c-evidence"
C_ALLOCATOR_BACKENDS = ("accepted-c", EVIDENCE_ALLOCATOR_BACKEND)
PINNED_C_EVIDENCE_MEMBER = "pinned-mimalloc-v3.5.0-static.o"
EVIDENCE_SCOPE = "evidence-only-pinned-c-allocator-reference-never-a-production-product"


def allocator_dependency_graph(cargo: list[str], features: str, allocator_backend: str,
                               environment: dict[str, str]) -> dict[str, object]:
    """Attest Cargo's selected target normal/build edges, excluding test oracles."""
    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise BuildError("unknown owned allocator backend")
    command = [*cargo, "tree", "--locked", "--offline", "-p", "crabc-libc",
               "--target", TARGET, "--no-default-features", "--features", features,
               "--edges", "normal,build", "--prefix", "none", "--format", "{p}"]
    packages = sorted(set(run(command, environment=environment).decode().splitlines()))
    c_selected = any(line.startswith("libmimalloc-sys ") for line in packages)
    native_selected = any(line.startswith("crabc-mimalloc ") for line in packages)
    if allocator_backend == "native-shadow" and (c_selected or not native_selected):
        raise BuildError("native production dependency graph must select Rust mimalloc without C mimalloc")
    if allocator_backend == "accepted-c" and (not c_selected or native_selected):
        raise BuildError("accepted-C production dependency graph selected an unexpected allocator")
    return {"target": TARGET, "edges": ["normal", "build"], "features": features.split(","),
            "packages": [line.replace(str(ROOT), "$SOURCE") for line in packages],
            "c_allocator_selected": c_selected, "native_allocator_selected": native_selected}


def selected_allocator_archive(cargo_root: Path, allocator_backend: str) -> Path | None:
    build_root = cargo_root / TARGET / "release/build"
    # The pinned nightly uses `libmimalloc-sys/<hash>` instead of the older
    # single `libmimalloc-sys-<hash>` build-directory component. Keep the
    # archive selection exact for both layouts so the C backend remains
    # uniquely attested and native-shadow builds still reject any C archive.
    archives = [
        *build_root.glob("libmimalloc-sys-*/out/libmimalloc.a"),
        *build_root.glob("libmimalloc-sys/*/out/libmimalloc.a"),
    ]
    if allocator_backend == "native-shadow":
        if archives:
            raise BuildError("native production build contains a C mimalloc archive")
        return None
    if allocator_backend != "accepted-c" or len(archives) != 1:
        raise BuildError("Cargo did not produce one unambiguous accepted allocator archive")
    return archives[0]


def _allocator_perf_helpers():
    """The allocator harness's authenticated pinned-archive helpers."""

    import importlib.util

    path = ROOT / "compat/allocator/perf_x86_64.py"
    spec = importlib.util.spec_from_file_location("crabc_owned_sysroot_pinned_mimalloc", path)
    if spec is None or spec.loader is None:
        raise BuildError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def libmimalloc_sys_compile_command(c_flags: Sequence[str], source_root: Path, output: Path) -> list[str]:
    """The exact gcc command the pinned cc crate runs for libmimalloc-sys 0.1.49.

    cc's release defaults, then the target CFLAGS, then the crate's include
    directories and its release defines (see libmimalloc-sys build.rs).
    `pinned_c_evidence_object` proves the reconstruction by reproducing the
    Cargo-built object byte for byte before reusing it for v3.5.0.
    """

    return [
        "/usr/bin/gcc", "-O3", "-ffunction-sections", "-fdata-sections", "-fPIC", "-m64", *c_flags,
        "-I", str(source_root / "include"), "-I", str(source_root / "src"),
        "-Wno-error=date-time", "-ftls-model=initial-exec",
        "-DMI_DEBUG=0", "-DMI_BUILD_RELEASE", "-DNDEBUG",
        "-o", str(output), "-c", str(source_root / "src" / "static.c"),
    ]


def default_visibility_definitions(object_path: Path) -> list[str]:
    """Defined GLOBAL/WEAK symbols with DEFAULT visibility, the ones libc.so would export."""

    output = run(["/usr/bin/readelf", "-sW", str(object_path)]).decode("utf-8", errors="replace")
    names = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[4] in {"GLOBAL", "WEAK"} and fields[5] == "DEFAULT" and fields[6] != "UND":
            names.add(fields[7])
    return sorted(names)


def pinned_c_evidence_object(
    stage: Path, c_flags: Sequence[str], allocator_archive: Path, *, llvm_ar: str, environment: dict[str, str],
) -> tuple[Path, dict[str, object]]:
    """Compile exact pinned mimalloc v3.5.0 as the accepted wrapper's allocator object."""

    helpers = _allocator_perf_helpers()
    try:
        pin = helpers.load_pin()
        archive = helpers.fetch_archive(pin, offline=True)
    except helpers.HarnessError as error:
        raise BuildError(f"pinned mimalloc archive is not authenticated: {error}") from error
    work = stage / "pinned-c-evidence"
    work.mkdir(mode=0o700)
    source = helpers.safe_extract(archive, work / "source", pin["archive_root"])

    members = run([llvm_ar, "t", str(allocator_archive)]).decode().splitlines()
    if len(members) != 1 or ALLOCATOR_MEMBER.fullmatch(members[0]) is None:
        raise BuildError("accepted allocator archive must contain one named static object")
    accepted_object = run([llvm_ar, "p", str(allocator_archive), members[0]])
    registry = sorted(Path(environment["CARGO_HOME"]).glob(
        f"registry/src/*/{C_ALLOCATOR_PIN['name']}-{C_ALLOCATOR_PIN['version']}/c_src/mimalloc/v3"))
    if len(registry) != 1:
        raise BuildError("the locked libmimalloc-sys source is not uniquely present in the Cargo registry")
    flags = [flag for flag in c_flags if flag not in {"-MD"} and not flag.startswith(str(stage))]
    flags = [flag for index, flag in enumerate(flags) if flag != "-MF" and (index == 0 or flags[index - 1] != "-MF")]
    reproduced = work / "reproduced-accepted.o"
    run(libmimalloc_sys_compile_command(flags, registry[0], reproduced), environment=environment)
    if reproduced.read_bytes() != accepted_object:
        raise BuildError("the reconstructed libmimalloc-sys compile command does not reproduce its Cargo object")

    evidence = work / PINNED_C_EVIDENCE_MEMBER
    dependencies = work / "pinned.d"
    command = libmimalloc_sys_compile_command([*flags, "-MD", "-MF", str(dependencies)], source, evidence)
    run(command, environment=environment)
    version = re.search(r"(?m)^#define MI_MALLOC_VERSION (\d+)", (source / "include/mimalloc.h").read_text())
    if version is None or int(version.group(1)) != 30500:
        raise BuildError("the pinned mimalloc archive does not declare MI_MALLOC_VERSION 30500")
    headers = {}
    for item in dependencies.read_text().replace("\\\n", " ").split(":", 1)[1].split():
        path = Path(item).resolve()
        if path.is_relative_to(source.resolve()):
            headers["mimalloc-3.5.0/" + path.relative_to(source.resolve()).as_posix()] = sha256_file(path)
        elif path.is_relative_to((ROOT / "include").resolve()):
            headers["include/" + path.relative_to((ROOT / "include").resolve()).as_posix()] = sha256_file(path)
        else:
            raise BuildError(f"pinned mimalloc compile read a header outside the project and pinned source: {item}")
    reviewed = (ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list").read_text(encoding="utf-8").split()
    if default_visibility_definitions(reproduced) != sorted(reviewed):
        raise BuildError("the default-visibility rule does not reproduce the reviewed accepted-C hidden list")
    normalize = lambda value: str(value).replace(str(stage), "$CRABC_X86_BUILD").replace(str(ROOT), "$CRABC_SOURCE")
    return evidence, {
        "implementation": "evidence-only exact pinned mimalloc C; never a production allocator",
        "upstream": {key: pin[key] for key in ("version", "tag", "revision")} | {"archive_sha256": pin["sha256"]},
        "mi_malloc_version": int(version.group(1)),
        "member": PINNED_C_EVIDENCE_MEMBER,
        "member_sha256": sha256_file(evidence),
        "compile_command": [normalize(item) for item in command],
        "flag_reconstruction": {
            "reproduces": f"{C_ALLOCATOR_PIN['name']} {C_ALLOCATOR_PIN['version']} member {members[0]}",
            "accepted_member_sha256": hashlib.sha256(accepted_object).hexdigest(),
            "reproduced_member_sha256": sha256_file(reproduced),
        },
        "replaced_accepted_member": members[0],
        "source_and_header_sha256": dict(sorted(headers.items())),
        "default_visibility_definitions": default_visibility_definitions(evidence),
    }


def require_no_implicit_lifecycle(object_path: Path, *, llvm_nm: str, llvm_objdump: str) -> None:
    """The same object rule `owned_mimalloc_lifecycle_profile` applies to the accepted member."""

    sections = run([llvm_objdump, "--section-headers", str(object_path)]).decode("utf-8", errors="replace")
    symbols = run([llvm_nm, str(object_path)]).decode("utf-8", errors="replace")
    if re.search(r"\.(?:init|fini)_array\b", sections) or re.search(
        r"(?m)^.*\bmi_process_(?:attach|detach)$", symbols
    ):
        raise BuildError("pinned mimalloc evidence object retains its implicit process attach/detach hooks")


def replace_allocator_member(
    archive: Path, stage: Path, accepted_member: str, evidence: Path, *, llvm_ar: str, llvm_nm: str,
) -> None:
    """Swap the accepted allocator member of a rebuilt libc archive for the evidence object."""

    run([llvm_ar, "d", str(archive), accepted_member])
    run([llvm_ar, "rcsD", str(archive), str(evidence)])
    members = run([llvm_ar, "t", str(archive)]).decode().splitlines()
    if accepted_member in members or members.count(evidence.name) != 1:
        raise BuildError("libc archive allocator member replacement did not take")
    undefined = {line.split()[-1] for line in run([llvm_nm, "--undefined-only", str(archive)]).decode().splitlines()
                 if len(line.split()) >= 2}
    defined = archive_defined_symbols(llvm_nm, archive)
    missing = sorted(name for name in undefined - defined if name.startswith(("mi_", "_mi_")))
    if missing:
        raise BuildError(f"pinned mimalloc object lacks symbols the accepted wrapper imports: {missing}")


def build_runtime_inputs(stage: Path, *, allocator_backend: str = DEFAULT_ALLOCATOR_BACKEND,
                         lifecycle_test_audit: bool = False) -> dict[str, object]:
    recorded_backend = allocator_backend
    allocator_backend = backend_selection(allocator_backend, lifecycle_test_audit)
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
    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise BuildError("unknown owned allocator backend")
    evidence_c = allocator_backend == EVIDENCE_ALLOCATOR_BACKEND
    accepted_c = allocator_backend in C_ALLOCATOR_BACKENDS
    allocator_pin = accepted_allocator_pin() if accepted_c else None
    c_compiler = executable_identity(Path("/usr/bin/gcc"), "pinned-image allocator C compiler") if accepted_c else None
    dependency_file = stage / "allocator.d"
    c_flags = [
        "-nostdinc", "-isystem", str(ROOT / "include"),
        "-fPIC", "-ftls-model=initial-exec", "-fstack-protector-strong",
        # The Rust libc owns the matching init/fini entries.  Do not let the
        # fixed C backend install a second hidden constructor.
        MIMALLOC_LIFECYCLE_C_FLAG,
        f"-ffile-prefix-map={ROOT}=/crabc", "-MD", "-MF", str(dependency_file),
    ]
    environment = deterministic_environment()
    environment["CARGO_BUILD_JOBS"] = "2"
    if accepted_c:
        environment.update({
        "CC_x86_64_unknown_linux_musl": str(c_compiler["path"]),
        "CFLAGS_x86_64_unknown_linux_musl": shlex.join(c_flags),
        "CC_SHELL_ESCAPED_FLAGS": "1",
    })
    selected_feature = "x86-owned-static-runtime" if accepted_c else "x86-owned-static-native-shadow"
    # The explicit scalar lifecycle audit mirrors the dynamic producer's
    # development flag. It selects no allocator and exposes no pointer.
    if lifecycle_test_audit:
        selected_feature += ",x86-owned-allocator-lifecycle-test-audit"
    dependency_graph = allocator_dependency_graph([rustup, "run", PINNED_TOOLCHAIN, "cargo"],
                                                 selected_feature, "accepted-c" if accepted_c else allocator_backend,
                                                 environment)
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
        "--no-default-features",
        "--features",
        selected_feature,
        "--target",
        TARGET,
        "--target-dir",
        str(cargo_root),
        *STATIC_ARCHIVE_PROFILE,
        "--",
        "--cfg",
        "crabc_owned_static_sysroot",
        "--cfg",
        MIMALLOC_LIFECYCLE_RUST_CFG,
        "-C",
        "relocation-model=pic",
        "-C",
        "code-model=small",
        "-C",
        "panic=abort",
        "-Ztls-model=initial-exec",
        # C requires distinct functions to have distinct addresses; rustc's
        # identical-function merging would alias exports musl keeps apart.
        "-Zmerge-functions=disabled",
        "--remap-path-prefix",
        f"{ROOT}=/crabc",
    ]
    run(cargo_command, environment=environment)
    raw_libc = cargo_root / TARGET / "release" / "libc.a"
    if not raw_libc.is_file():
        raise BuildError("Cargo did not produce the x86 crabc-libc static archive")
    allocator_archive = selected_allocator_archive(cargo_root, "accepted-c" if accepted_c else allocator_backend)
    allocator_headers = (allocator_header_provenance(dependency_file, Path(environment["CARGO_HOME"]))
                         if accepted_c else None)
    allocator_lifecycle = (owned_mimalloc_lifecycle_profile(
        c_flags, cargo_command, allocator_archive, raw_libc,
        llvm_ar=llvm_ar, llvm_nm=llvm_nm, llvm_objdump=llvm_objdump,
        stage=stage / "allocator-lifecycle-profile",
    ) if accepted_c else {"initialization": "owned-static-startup-before-constructors",
                          "process_done": "same-image-fini-array-before-stdio-flush",
                          "post_done_backing": "source-default-release-retained"})

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
        allocator_archive=allocator_archive,
    )
    if evidence_c:
        evidence_object, evidence_record = pinned_c_evidence_object(
            stage, c_flags, allocator_archive, llvm_ar=llvm_ar, environment=environment)
        require_no_implicit_lifecycle(evidence_object, llvm_nm=llvm_nm, llvm_objdump=llvm_objdump)
        replace_allocator_member(libc, stage, evidence_record["replaced_accepted_member"], evidence_object,
                                 llvm_ar=llvm_ar, llvm_nm=llvm_nm)
        libc_provenance["archive"]["sha256"] = sha256_file(libc)
        libc_provenance["selected_members"] = [
            item for item in libc_provenance["selected_members"]
            if item["name"] != evidence_record["replaced_accepted_member"]
        ] + [{"name": evidence_object.name, "sha256": sha256_file(evidence_object)}]
        libc_provenance["allocator_backend"]["pinned_c_evidence"] = evidence_record
    if not accepted_c:
        symbols = archive_defined_symbols(llvm_nm, libc)
        if any(name.startswith(("mi_", "_mi_")) for name in symbols):
            raise BuildError("native static archive defines C mimalloc symbols")
        libc_provenance["allocator_backend"] = {
            "implementation": ("native Rust; production-shaped selection" if recorded_backend == NATIVE_ALLOCATOR_BACKEND
                               else "native Rust shadow; promotion remains separate"),
            "upstream_sha256": sha256_file(ROOT / "crabc-mimalloc/UPSTREAM.md"),
        }
    libc_provenance["dependency_graph"] = dependency_graph
    libc_provenance["allocator_lifecycle_test_audit"] = lifecycle_test_audit
    libc_provenance["allocator_backend"].update({
        "crate": allocator_pin,
        "compiler": c_compiler,
        "target_flags": [flag.replace(str(stage), "$CRABC_X86_BUILD").replace(str(ROOT), "$CRABC_SOURCE") for flag in c_flags] if accepted_c else [],
        "source_and_header_sha256": allocator_headers,
        "lifecycle_profile": allocator_lifecycle,
    })
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
            "--no-default-features",
            "--features",
            selected_feature,
            "--target",
            TARGET,
            "--target-dir",
            "$CRABC_X86_BUILD/cargo",
            *STATIC_ARCHIVE_PROFILE,
            "--",
            "--cfg",
            "crabc_owned_static_sysroot",
            "--cfg",
            MIMALLOC_LIFECYCLE_RUST_CFG,
            "-C",
            "relocation-model=pic",
            "-C",
            "code-model=small",
            "-C",
            "panic=abort",
            "-Ztls-model=initial-exec",
            "-Zmerge-functions=disabled",
            "--remap-path-prefix",
            "$CRABC_SOURCE=/crabc",
        ],
        "allocator_backend": recorded_backend,
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
    manifest = installed_manifest(payload_hashes, producer_tools, allocator_backend=inputs.get("allocator_backend", DEFAULT_ALLOCATOR_BACKEND))
    write_json(manifest_path, manifest)
    installed_hashes = regular_file_hashes(output)
    expected = set(payload_hashes) | {manifest_path.relative_to(output).as_posix()}
    if set(installed_hashes) != expected:
        raise BuildError("installed tree changed while writing its manifest")
    return manifest


def build(output: Path, *, allocator_backend: str = DEFAULT_ALLOCATOR_BACKEND,
          lifecycle_test_audit: bool = False) -> dict[str, object]:
    assert_native_target()
    output = validate_output_path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="crabc-x86-owned-sysroot.", dir=output.parent) as temporary:
        temporary_root = Path(temporary)
        inputs = build_runtime_inputs(temporary_root, allocator_backend=allocator_backend,
                                      lifecycle_test_audit=lifecycle_test_audit)
        staged_output = temporary_root / "installed"
        manifest = assemble(staged_output, inputs)
        remove_owned_output(output)
        staged_output.replace(output)
        return manifest


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--allocator-backend", choices=ALLOCATOR_BACKENDS, default=DEFAULT_ALLOCATOR_BACKEND)
    parser.add_argument("--allocator-lifecycle-test-audit", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        parsed = parse_args(arguments)
        manifest = build(parsed.output, allocator_backend=parsed.allocator_backend,
                         lifecycle_test_audit=parsed.allocator_lifecycle_test_audit)
    except BuildError as error:
        print(f"x86 owned static sysroot failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
