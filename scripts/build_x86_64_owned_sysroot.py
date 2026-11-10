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
import contextlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.rust_toolchain import pinned_toolchain
from scripts import native_build_tools
from compat.x86_64 import source_seal
from compat.x86_64.native_runtime_profile import NativeRuntimeProfile
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
NATIVE_PROFILE_SOURCE = ROOT / "compat" / "x86_64" / "native_runtime_profile.py"
NATIVE_PROFILE_PATH = "share/crabc/native_runtime_profile.py"
PACKAGE_FORMAT = "crabc-x86-64-owned-static-sysroot-package/v1"
PACKAGE_ARCHIVE_ROOT = "crabc-x86_64-owned-static-sysroot"
LIBC_MEMBER = re.compile(r"^c\..+\.rcgu\.o$")
THIN_LTO_RUST_RUNTIME_MEMBER = re.compile(r"^c\.(core|alloc)-([0-9a-f]+)\..+\.rcgu\.o$")
RUST_ALLOC_SHIM_MEMBER = re.compile(r"^c\.[a-z0-9]+\.rcgu\.o$")
C_ALLOCATOR_MEMBER = "mimalloc-v3.5.0-static.o"
C_ALLOCATOR_MI_MALLOC_VERSION = 30500


def _c_allocator_pin() -> dict[str, str]:
    pin = tomllib.loads((ROOT / "compat/upstreams.toml").read_text(encoding="utf-8"))["mimalloc"]
    return {"version": pin["version"], "tag": pin["tag"], "revision": pin["revision"],
            "archive_sha256": pin["sha256"]}


C_ALLOCATOR_PIN = _c_allocator_pin()

# The C backend's compiler constructor is disabled only when this matching
# Rust cfg selects the private same-image replacement entries.  Keeping the
# two spellings here makes the product builder, rather than an ambient Cargo
# invocation, the authority for this coupled lifecycle profile.
MIMALLOC_LIFECYCLE_C_FLAG = "-DMI_PRIM_HAS_PROCESS_ATTACH=1"
# Musl's allocator maps memory through its internal __mmap family
# (src/malloc/mallocng/glue.h `#define mmap __mmap` and likewise madvise and
# mremap; it never calls mprotect), so an application's own definition of
# those public names never sees libc-internal allocation. Compile the C
# backend the same way against the hidden bodies that
# libc/src/c_abi/x86_64/memory_mapping.rs and owned_vm_mechanisms.rs define.
# Musl's free still unmaps through the public munmap; so does this backend.
MIMALLOC_INTERNAL_VM_C_FLAGS = ("-Dmmap=__mmap", "-Dmadvise=__madvise", "-Dmremap=__mremap", "-Dmprotect=__mprotect")
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
# into one object. ThinLTO keeps cross-crate optimization while emitting one
# member per codegen unit; a unit ceiling above libc's module count gives each
# Rust module its own member, and rustc never splits a module to reach it.
# ThinLTO also imports core and alloc code into `c.*` members. Their definitions
# shared with the pinned Rust rlibs must be weak so ordinary C links can use
# them and a Rust application can supply its own strong runtime definitions.
# Member names derive from crate and module names, so their order is stable.
STATIC_ARCHIVE_PROFILE = (
    "--config",
    'profile.release.lto="thin"',
    "--config",
    "profile.release.codegen-units=65536",
)
# Installed libc and its allocator dependencies use initial-exec TLS. Cargo
# target flags reach every dependency; a final-crate rustc flag alone leaves
# allocator accesses in the GD model, requiring module-base resolution even
# when that allocator is part of the initial runtime image. Retain the
# build-wide dead-code setting when selecting the target TLS model.
TARGET_TLS_CONFIG = (
    "--config",
    f'target.{TARGET}.rustflags=["-C","link-dead-code","-Ztls-model=initial-exec"]',
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
    "pinned upstream mimalloc v3.5.0 src/static.c compiled against project headers",
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
        **native_build_tools.environment(),
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
        "rustc_wrapper": executable_identity(native_build_tools.KACHE, "pinned kache"),
        "linker": executable_identity(native_build_tools.MOLD, "image mold"),
        "cargo_linker": executable_identity(native_build_tools.CARGO_LINKER, "image mold GCC driver"),
        "rustc": {
            **executable_identity(sysroot / "bin/rustc", "pinned physical rustc", within=sysroot),
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
    c_flags: Sequence[str], cargo_command: Sequence[str], allocator_object: Path,
    raw_libc: Path, *, llvm_nm: str, llvm_objdump: str,
) -> dict[str, object]:
    """Reject a one-sided C/Rust automatic-mimalloc lifecycle selection.

    Upstream mimalloc owns the normal compiler constructor. These native
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
    sections = run([llvm_objdump, "--section-headers", str(allocator_object)]).decode("utf-8", errors="replace")
    symbols = run([llvm_nm, str(allocator_object)]).decode("utf-8", errors="replace")
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
    if any(name.startswith(("mi_", "_mi_")) for name in archive_defined_symbols(llvm_nm, raw_libc)):
        raise BuildError("Cargo libc defines C mimalloc symbols")
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


def install_header_tree(destination: Path) -> dict[str, object]:
    """Install project headers and authenticated selected Linux kernel interfaces."""
    from compat.x86_64 import header_callable_inventory as inventory
    uapi = Path("/opt/linux-5.10-uapi/include")
    inventory.require_pinned_linux_uapi_include(uapi)
    manifest = uapi.parent / ".crabc-linux-uapi.headers.sha256"
    if manifest.is_symlink() or not manifest.is_file() or sha256_file(manifest) != inventory.LINUX_UAPI_HEADER_MANIFEST_SHA256:
        raise BuildError("pinned Linux UAPI hash manifest differs")
    expected = {}
    for line in manifest.read_text().splitlines():
        value, relative = line.split("  ", 1)
        validate_relative_path(Path(relative))
        relative = Path(relative).as_posix()
        if relative in expected:
            raise BuildError("pinned Linux UAPI manifest repeats a header")
        expected[relative] = value
    if len(expected) != int(inventory.LINUX_UAPI_MARKER["header_count"]):
        raise BuildError("pinned Linux UAPI header roster differs")
    observed = regular_file_hashes(uapi)
    if observed != expected:
        raise BuildError("pinned Linux UAPI header bytes differ from their authenticated roster")
    project = copy_regular_tree(ROOT / "include", destination)
    installed_uapi = copy_regular_tree(uapi, destination / "crabc-linux-uapi")
    if installed_uapi != expected:
        raise BuildError("installed Linux UAPI header bytes changed during copying")
    return {"schema": 1, "source": "include", "regular_file_count": len(project), "files": project,
            "linux_uapi": {"version": inventory.LINUX_UAPI_VERSION,
                           "source_sha256": inventory.LINUX_UAPI_SOURCE_SHA256,
                           "manifest_sha256": sha256_file(manifest), "include_path": "usr/include/crabc-linux-uapi",
                           "files": expected, "project_header_precedence": {
                               name: {"project_sha256": project[name], "uapi_sha256": expected[name]}
                               for name in sorted(project.keys() & expected.keys())}}}


def classify_libc_members(
    members: Sequence[str],
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
    if C_ALLOCATOR_MEMBER in members:
        raise BuildError("Cargo libc archive already contains the C allocator member name")
    selected = tuple(member for member in members if LIBC_MEMBER.fullmatch(member))
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


def global_definitions(nm: str, object_or_archive: Path) -> dict[str, str]:
    """Read ELF global bindings, ignoring archive member headings and metadata."""

    output = run([nm, "--format=posix", "--defined-only", "--extern-only", str(object_or_archive)])
    definitions: dict[str, str] = {}
    for line in output.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 2 or len(fields[1]) != 1 or not fields[1].isalpha():
            continue
        name, kind = fields[:2]
        if name in definitions and definitions[name] != kind:
            raise BuildError(f"global symbol has inconsistent bindings: {name}")
        definitions[name] = kind
    return definitions


def rebuild_libc_archive(
    source: Path, output: Path, *, llvm_ar: str, llvm_nm: str,
    allocator_object: Path | None = None,
    llvm_objcopy: str | None = None, stock_runtime_libdir: Path | None = None,
) -> dict[str, object]:
    """Rebuild from the already-attested target LLVM archive tools."""

    members = tuple(
        line
        for line in run([llvm_ar, "t", str(source)]).decode("utf-8", errors="replace").splitlines()
        if line
    )
    selected, excluded = classify_libc_members(members)
    output.parent.mkdir(parents=True, exist_ok=True)
    rebound_runtime: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="x86-libc-members.", dir=output.parent) as temporary:
        member_root = Path(temporary)
        run([llvm_ar, "x", str(source), *selected], cwd=member_root)
        selected_paths = tuple(member_root / member for member in selected)
        if any(not path.is_file() for path in selected_paths):
            raise BuildError("llvm-ar did not extract every selected crabc-libc member")
        if allocator_object is not None:
            copy_artifact(allocator_object, member_root / C_ALLOCATOR_MEMBER)
            selected = (*selected, C_ALLOCATOR_MEMBER)
            selected_paths = (*selected_paths, member_root / C_ALLOCATOR_MEMBER)
        for path in selected_paths:
            imported = THIN_LTO_RUST_RUNTIME_MEMBER.fullmatch(path.name)
            shim = RUST_ALLOC_SHIM_MEMBER.fullmatch(path.name)
            if imported is None and shim is None:
                continue
            if llvm_objcopy is None or stock_runtime_libdir is None:
                raise BuildError("ThinLTO Rust runtime member lacks an owned rebinding tool or stock runtime")
            source_symbols = global_definitions(llvm_nm, path)
            if imported is not None:
                runtime, crate_hash = imported.groups()
                stock = stock_runtime_libdir / f"lib{runtime}-{crate_hash}.rlib"
            else:
                shim_names = {"___rust_alloc_error_handler", "___rust_no_alloc_shim_is_unstable_v2"}
                if len(source_symbols) != 2 or {
                    suffix for symbol in source_symbols for suffix in shim_names if symbol.endswith(suffix)
                } != shim_names:
                    raise BuildError("unclassified Rust allocator shim member")
                runtime = "std-alloc-shim"
                stock_candidates = list(stock_runtime_libdir.glob("libstd-*.rlib"))
                if len(stock_candidates) != 1:
                    raise BuildError("Rust allocator shim has no unique pinned std rlib")
                stock = stock_candidates[0]
            if not stock.is_file() or stock.is_symlink():
                raise BuildError(f"ThinLTO {runtime} member has no matching pinned Rust rlib")
            stock_symbols = global_definitions(llvm_nm, stock)
            duplicates = sorted(name for name, binding in source_symbols.items()
                                if binding.isupper() and binding not in {"W", "V"}
                                and stock_symbols.get(name, "").isupper()
                                and stock_symbols[name] not in {"W", "V"})
            if not duplicates:
                raise BuildError(f"ThinLTO {runtime} member has no duplicate strong stock runtime definitions")
            symbols_file = member_root / f"{path.name}.weaken-symbols"
            symbols_file.write_text("\n".join(duplicates) + "\n", encoding="ascii")
            original_hash = sha256_file(path)
            run([llvm_objcopy, f"--weaken-symbols={symbols_file}", str(path)])
            rebound = global_definitions(llvm_nm, path)
            if any(rebound.get(name) not in {"W", "V"} for name in duplicates):
                raise BuildError(f"ThinLTO {runtime} duplicate symbols did not become weak")
            if any(rebound.get(name) != binding for name, binding in source_symbols.items()
                   if name not in duplicates):
                raise BuildError(f"ThinLTO {runtime} changed a nonduplicate global binding")
            rebound_runtime.append({"member": path.name, "source_sha256": original_hash,
                                    "installed_sha256": sha256_file(path), "stock_rlib": stock.name,
                                    "stock_rlib_sha256": sha256_file(stock), "weakened_symbols": duplicates})
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
        "rust_runtime_duplicate_bindings": rebound_runtime,
        "policy": "crabc objects and the explicitly attested allocator object only; duplicate ThinLTO core/alloc and Rust allocation-shim definitions are weak, while stock core/compiler_builtins and native compiler-rt members are excluded",
    }
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
    copy_artifact(NATIVE_PROFILE_SOURCE, destination.parent.parent / NATIVE_PROFILE_PATH)


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
    *, allocator_backend: str = "accepted-c", source_sha256: str | None = None,
    lifecycle_test_audit: bool = False,
    hardening_profile: NativeRuntimeProfile = NativeRuntimeProfile.COMPATIBILITY,
) -> dict[str, object]:
    """Describe the bounded installed contract without promoting either family."""

    if not isinstance(hardening_profile, NativeRuntimeProfile):
        raise BuildError("unknown native runtime profile")
    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise BuildError("unknown owned allocator backend")
    if source_sha256 is None:
        source_sha256 = source_seal.product_source_digest(ROOT)
    if len(source_sha256) != 64 or any(character not in "0123456789abcdef" for character in source_sha256):
        raise BuildError("invalid owned static source digest")
    target_inputs = list(TARGET_RUNTIME_INPUTS)
    if allocator_backend in NATIVE_ALLOCATOR_BACKENDS:
        target_inputs[3] = "fixed-upstream Rust mimalloc in the selected crabc-libc Rust object"
    return {
        "schema": 1,
        "format": FORMAT,
        "target": TARGET,
        "toolchain": PINNED_TOOLCHAIN,
        "source_sha256": source_sha256,
        "producer_tools": producer_tools,
        "scope": EVIDENCE_SCOPE if allocator_backend == EVIDENCE_ALLOCATOR_BACKEND else SCOPE,
        "allocator_backend": allocator_backend,
        "hardening_profile": hardening_profile.value,
        "allocator_lifecycle_test_audit": lifecycle_test_audit,
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
            "modes": hardening_profile.static_modes,
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


ALLOCATOR_BACKENDS = ("accepted-c", "native-shadow", "pinned-c-evidence", "native")
# The one compile-time default. Select the native allocator here only after
# its production checks pass; no other setting changes ordinary products.
DEFAULT_ALLOCATOR_BACKEND = "accepted-c"
# `native` is the production-shaped Rust allocator product: the same Rust
# selection as the evidence-only `native-shadow` build (so the identical
# libc Cargo features), but refused together with any test-audit feature and
# audited for the complete absence of C mimalloc.
NATIVE_ALLOCATOR_BACKEND = "native"
NATIVE_ALLOCATOR_BACKENDS = ("native-shadow", NATIVE_ALLOCATOR_BACKEND)


def backend_selection(allocator_backend: str, lifecycle_test_audit: bool) -> str:
    """The compile-time build selection a recorded backend uses."""

    if allocator_backend == NATIVE_ALLOCATOR_BACKEND:
        if lifecycle_test_audit:
            raise BuildError("the production native backend admits no allocator test-audit feature")
        return "native-shadow"
    if allocator_backend == EVIDENCE_ALLOCATOR_BACKEND:
        return "accepted-c"
    return allocator_backend
# `pinned-c-evidence` is never a production product: it is the accepted-C
# build recorded under an evidence-only backend name and scope. It exists only
# as the C reference of the allocator's integrated-product comparison
# (compat/allocator/perf_integrated_x86_64.py), so no production
# qualification, which selects `accepted-c`, can admit it.
EVIDENCE_ALLOCATOR_BACKEND = "pinned-c-evidence"
C_ALLOCATOR_BACKENDS = ("accepted-c", EVIDENCE_ALLOCATOR_BACKEND)
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
    if any(line.startswith("libmimalloc-sys ") for line in packages):
        raise BuildError("x86 dependency graph selects a Cargo-built C allocator")
    native_selected = any(line.startswith("crabc-mimalloc ") for line in packages)
    if native_selected != (backend_selection(allocator_backend, False) == "native-shadow"):
        raise BuildError("x86 dependency graph selects an unexpected allocator")
    return {"target": TARGET, "edges": ["normal", "build"], "features": features.split(","),
            "packages": [line.replace(str(ROOT), "$SOURCE") for line in packages],
            "native_allocator_selected": native_selected}


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


C_ALLOCATOR_OPTIMIZATION = {"release": "-O3", "debug": "-O0"}


def c_allocator_compile_command(c_flags: Sequence[str], source_root: Path, output: Path,
                                dependencies: Path, *, profile: str) -> list[str]:
    """The one gcc command that builds the accepted C allocator object.

    The build profile's optimization and section splitting, then the product's
    target flags, then upstream's include directories and release defines.
    """

    return [
        "/usr/bin/gcc", C_ALLOCATOR_OPTIMIZATION[profile], "-ffunction-sections", "-fdata-sections",
        "-fPIC", "-m64", *c_flags,
        f"-ffile-prefix-map={source_root}=/mimalloc",
        "-I", str(source_root / "include"), "-I", str(source_root / "src"),
        "-Wno-error=date-time", "-ftls-model=initial-exec",
        "-DMI_DEBUG=0", "-DMI_BUILD_RELEASE", "-DNDEBUG",
        "-MD", "-MF", str(dependencies),
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


def compile_c_allocator(work: Path, c_flags: Sequence[str], *, profile: str) -> tuple[Path, dict[str, object]]:
    """Compile unedited pinned upstream mimalloc `src/static.c` into one object.

    The archive comes only through the allocator harness's SHA-256-verified
    route and must be the `[mimalloc]` pin. The compiler's dependency trace
    must name only that source tree and project headers.
    """

    if profile not in C_ALLOCATOR_OPTIMIZATION:
        raise BuildError("unknown C allocator build profile")
    helpers = _allocator_perf_helpers()
    try:
        pin = helpers.load_pin()
        archive = helpers.fetch_archive(pin, offline=False)
    except helpers.HarnessError as error:
        raise BuildError(f"pinned mimalloc archive is not authenticated: {error}") from error
    if {"version": pin["version"], "tag": pin["tag"], "revision": pin["revision"],
            "archive_sha256": pin["sha256"]} != C_ALLOCATOR_PIN:
        raise BuildError("authenticated mimalloc archive is not the accepted C allocator pin")
    if work.exists() or work.is_symlink():
        raise BuildError("C allocator build path is already occupied")
    work.mkdir(mode=0o700)
    try:
        source = helpers.safe_extract(archive, work / "source", pin["archive_root"]).resolve()
    except helpers.HarnessError as error:
        raise BuildError(f"pinned mimalloc archive is unsafe: {error}") from error
    version = re.search(r"(?m)^#define MI_MALLOC_VERSION (\d+)", (source / "include/mimalloc.h").read_text())
    if version is None or int(version.group(1)) != C_ALLOCATOR_MI_MALLOC_VERSION:
        raise BuildError(f"the pinned mimalloc archive does not declare MI_MALLOC_VERSION {C_ALLOCATOR_MI_MALLOC_VERSION}")
    output = work / C_ALLOCATOR_MEMBER
    dependencies = work / "static.d"
    command = c_allocator_compile_command(c_flags, source, output, dependencies, profile=profile)
    run(command)
    headers: dict[str, str] = {}
    for item in shlex.split(dependencies.read_text(encoding="utf-8").replace("\\\n", " ").partition(":")[2]):
        path = Path(item).resolve(strict=True)
        if path.is_relative_to(source):
            name = f"{pin['archive_root']}/{path.relative_to(source).as_posix()}"
        elif path.is_relative_to((ROOT / "include").resolve()):
            name = path.relative_to(ROOT.resolve()).as_posix()
        elif not any(flag == "-nostdinc" for flag in c_flags):
            continue
        else:
            raise BuildError(f"C allocator compile read a header outside the project and pinned source: {item}")
        headers[name] = sha256_file(path)
    if f"{pin['archive_root']}/src/static.c" not in headers:
        raise BuildError("C allocator dependency trace lacks its pinned translation unit")
    normalize = lambda value: str(value).replace(str(work), "$CRABC_C_ALLOCATOR").replace(str(ROOT), "$CRABC_SOURCE")
    return output, {
        "implementation": "accepted C backend; native Rust promotion remains separate",
        "upstream": dict(C_ALLOCATOR_PIN),
        "mi_malloc_version": int(version.group(1)),
        "member": C_ALLOCATOR_MEMBER,
        "member_sha256": sha256_file(output),
        "compiler": executable_identity(Path("/usr/bin/gcc"), "pinned-image allocator C compiler"),
        "compile_command": [normalize(item) for item in command],
        "source_and_header_sha256": dict(sorted(headers.items())),
    }


def require_reviewed_hidden_list(object_path: Path) -> list[str]:
    """The reviewed shared-libc local list is exactly the object's default-visibility definitions."""

    reviewed = (ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list").read_text(encoding="utf-8").split()
    defined = default_visibility_definitions(object_path)
    if defined != sorted(reviewed):
        raise BuildError("the C allocator's default-visibility definitions differ from the reviewed hidden list")
    return defined


def c_allocator_target_flags() -> list[str]:
    """The product target flags for the accepted C allocator object."""

    return ["-nostdinc", "-isystem", str(ROOT / "include"), "-fPIC", "-ftls-model=initial-exec",
            "-fstack-protector-strong", MIMALLOC_LIFECYCLE_C_FLAG, *MIMALLOC_INTERNAL_VM_C_FLAGS,
            f"-ffile-prefix-map={ROOT}=/crabc"]


def build_debug_runtime_inputs(stage: Path, *, allocator_backend: str = DEFAULT_ALLOCATOR_BACKEND,
                               lifecycle_test_audit: bool = False, dynamic: bool = False,
                               hardening_profile: NativeRuntimeProfile = NativeRuntimeProfile.COMPATIBILITY) -> dict[str, object]:
    from compat.x86_64 import native_static_source_runtime_closure as closure
    recorded_backend = allocator_backend
    allocator_backend = backend_selection(allocator_backend, lifecycle_test_audit)
    accepted_c = allocator_backend == "accepted-c"
    linkage = "dynamic" if dynamic else "static"
    feature = f"x86-owned-{linkage}-runtime" if accepted_c else f"x86-owned-{linkage}-native-shadow"
    if lifecycle_test_audit:
        feature += ",x86-owned-allocator-lifecycle-test-audit"
    tools = resolve_pinned_producer_tools()
    ar = producer_tool_path(tools, "llvm-ar")
    nm = producer_tool_path(tools, "llvm-nm")
    objdump = producer_tool_path(tools, "llvm-objdump")
    graph = stage / "source-runtime"
    arguments = closure.parser().parse_args(["build", "--work", str(graph.relative_to(ROOT / ".work/x86_64")),
                                             "--features", feature, "--relocation-model", "pic"])
    arguments.rustc_arguments = ["--cfg", "crabc_owned_static_sysroot", "--cfg", MIMALLOC_LIFECYCLE_RUST_CFG,
                                "-Zmerge-functions=disabled", "--remap-path-prefix", f"{ROOT}=/crabc"]
    previous = os.environ.get("CARGO_PROFILE_DEV_OPT_LEVEL")
    os.environ["CARGO_PROFILE_DEV_OPT_LEVEL"] = "0"
    try:
        raw = closure.build(arguments, c_allocator_flags=c_allocator_target_flags() if accepted_c else None)
    finally:
        if previous is None:
            os.environ.pop("CARGO_PROFILE_DEV_OPT_LEVEL", None)
        else:
            os.environ["CARGO_PROFILE_DEV_OPT_LEVEL"] = previous
    return collect_debug_runtime_inputs(stage, graph, raw, allocator_backend=recorded_backend,
                                        lifecycle_test_audit=lifecycle_test_audit, dynamic=dynamic,
                                        hardening_profile=hardening_profile)


def collect_debug_runtime_inputs(stage: Path, graph: Path, raw: Path, *, allocator_backend: str,
                                 lifecycle_test_audit: bool = False, dynamic: bool = False,
                                 hardening_profile: NativeRuntimeProfile = NativeRuntimeProfile.COMPATIBILITY) -> dict[str, object]:
    """Assemble installed inputs from the producer's recorded source-built graph."""
    from compat.x86_64 import native_static_source_runtime_closure as closure
    recorded_backend = allocator_backend
    allocator_backend = backend_selection(allocator_backend, lifecycle_test_audit)
    accepted_c = allocator_backend == "accepted-c"
    tools = resolve_pinned_producer_tools()
    ar = producer_tool_path(tools, "llvm-ar")
    nm = producer_tool_path(tools, "llvm-nm")
    objdump = producer_tool_path(tools, "llvm-objdump")
    receipt = json.loads((graph / "receipt.json").read_text())
    expected_features = f"x86-owned-{'dynamic' if dynamic else 'static'}-{'runtime' if accepted_c else 'native-shadow'}"
    if lifecycle_test_audit:
        expected_features += ",x86-owned-allocator-lifecycle-test-audit"
    if (receipt["cargo_profile"] != "dev" or receipt["target"] != TARGET or receipt["toolchain"] != PINNED_TOOLCHAIN
            or receipt["features"] != closure.normalized_features(expected_features)):
        raise BuildError("debug runtime graph has a different profile, target or backend")
    recorded_archive = receipt["staticlib_closure"]["archive"]
    if recorded_archive["path"] != str(raw) or recorded_archive["sha256"] != sha256_file(raw):
        raise BuildError("debug runtime archive differs from its source-built graph")
    c_allocator = receipt["c_allocator"]
    if accepted_c != (c_allocator is not None) or (
            accepted_c and c_allocator["target_flags"] != c_allocator_target_flags()):
        raise BuildError("debug runtime graph does not carry the product C allocator")
    cargo_root = graph / "cargo-target"
    core = Path(receipt["source_runtime_artifacts"]["core"]["path"])
    compiler = Path(receipt["source_runtime_artifacts"]["compiler_builtins"]["path"])
    environment = deterministic_environment()
    runtime_arguments = ["--profile", "debug", "--runtime-core", str(core.with_suffix(".rmeta")),
                         "--runtime-compiler-builtins", str(compiler.with_suffix(".rmeta"))]
    crt = stage / "crt"
    run([sys.executable, str(ROOT / "crt/build_x86_64.py"), "--out-dir", str(crt), "--llvm-objdump", objdump,
         "--hardening-profile", hardening_profile.value, *runtime_arguments,
         *(["--owned-dynamic-sysroot"] if dynamic else [])], environment=environment)
    builtins = stage / "builtins/libcrabc-builtins.a"
    builtins.parent.mkdir()
    builtins_provenance = builtins.parent / "provenance.json"
    run([sys.executable, str(ROOT / "builtins/build_x86_64.py"), "--output", str(builtins),
         "--provenance", str(builtins_provenance), *runtime_arguments, "--runtime-libc", str(raw)], environment=environment)
    members = tuple(run([ar, "t", str(raw)]).decode().splitlines())
    emitted = closure.emitted_artifacts(closure.cargo_records(graph / "cargo.stdout.jsonl"), cargo_root)
    permitted = set()
    compiler_members = set(run([ar, "t", str(compiler)]).decode().splitlines())
    for artifact in emitted:
        if artifact.suffix == ".rlib":
            permitted.update(run([ar, "t", str(artifact)]).decode().splitlines())
    if c_allocator is not None:
        if hashlib.sha256(run([ar, "p", str(raw), C_ALLOCATOR_MEMBER])).hexdigest() != c_allocator["member_sha256"]:
            raise BuildError("debug libc C allocator member differs from its compiled object")
        permitted.add(C_ALLOCATOR_MEMBER)
    selected = tuple(name for name in members if name not in compiler_members)
    if any(not LIBC_MEMBER.fullmatch(name) and name not in permitted for name in selected):
        raise BuildError("debug libc contains a member outside its audited source-built Cargo graph")
    objects = stage / "debug-objects"
    objects.mkdir()
    run([ar, "x", str(raw), *selected], cwd=objects)
    objcopy = str(Path(nm).with_name("llvm-objcopy"))
    private_runtime = []
    undefined = {line.split()[-1] for line in run([nm, "--undefined-only", str(raw)]).decode().splitlines()
                 if len(line.split()) >= 2 and not line.endswith(":")}
    for name in selected:
        path = objects / name
        original_sha256 = sha256_file(path)
        bindings = global_definitions(nm, path)
        panic = [symbol for symbol in bindings if symbol.endswith("17rust_begin_unwind") and "___rustc" in symbol]
        allocation = [symbol for symbol in bindings if "___rustc" in symbol and
                      symbol.endswith(("12___rust_alloc", "14___rust_dealloc", "14___rust_realloc", "19___rust_alloc_zeroed"))]
        if set(panic) & undefined:
            raise BuildError("debug runtime panic owner has unresolved callers outside its object")
        if panic or allocation:
            run([objcopy, *(f"--localize-symbol={symbol}" for symbol in panic),
                 *(f"--weaken-symbol={symbol}" for symbol in allocation), str(path)])
            after = global_definitions(nm, path)
            if any(symbol in after for symbol in panic) or any(after.get(symbol) not in {"W", "V"} for symbol in allocation):
                raise BuildError("debug private Rust runtime ownership rebinding failed")
            if any(after.get(symbol) != binding for symbol, binding in bindings.items() if symbol not in panic + allocation):
                raise BuildError("debug runtime changed an unrelated global binding")
            private_runtime.append({"member": name, "private_panic": panic, "weak_allocator_shims": allocation,
                                    "original_sha256": original_sha256, "packaged_sha256": sha256_file(path)})
    libc = stage / "runtime/libc.a"
    libc.parent.mkdir()
    run([ar, "rcsD", str(libc), *(str(objects / name) for name in selected)])
    required_symbols = REQUIRED_LIBC_SYMBOLS
    if dynamic:
        required_symbols = required_symbols - {"__crabc_x86_static_tls_bootstrap", "__stdio_exit"}
    missing = required_symbols - archive_defined_symbols(nm, libc)
    if missing:
        raise BuildError(f"debug libc lacks selected runtime symbols: {sorted(missing)}")
    provenance = {"archive": {"name": libc.name, "sha256": sha256_file(libc)}, "build_profile": "debug",
                  "source_runtime": receipt, "allocator_backend": recorded_backend,
                  "allocator_lifecycle_test_audit": lifecycle_test_audit,
                  "accepted_allocator": c_allocator,
                  "selected_members": [{"name": name, "sha256": sha256_file(objects / name)} for name in selected],
                  "excluded_members": [name for name in members if name in compiler_members]}
    provenance["rust_private_runtime_bindings"] = private_runtime
    return {"build_profile": "debug", "allocator_backend": recorded_backend, "hardening_profile": hardening_profile,
            "cargo_command": receipt["cargo_command"],
            "crt_root": crt, "builtins": builtins, "builtins_provenance": builtins_provenance,
            "libc": libc, "libc_provenance": provenance, "producer_tools": tools,
            "source_core": core, "source_compiler_builtins": compiler, "source_objects": objects, "source_libc": raw}


def build_runtime_inputs(stage: Path, *, allocator_backend: str = DEFAULT_ALLOCATOR_BACKEND,
                         lifecycle_test_audit: bool = False, profile: str = "release",
                         hardening_profile: NativeRuntimeProfile = NativeRuntimeProfile.COMPATIBILITY) -> dict[str, object]:
    if profile == "debug":
        return build_debug_runtime_inputs(stage, allocator_backend=allocator_backend, lifecycle_test_audit=lifecycle_test_audit,
                                          hardening_profile=hardening_profile)
    if profile != "release":
        raise BuildError("unknown owned runtime build profile")
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
    rustc_record = producer_tools["rustc"]
    if not isinstance(rustc_record, dict) or not isinstance(rustc_record.get("sysroot"), str):
        raise BuildError("pinned producer record lacks Rust sysroot")
    rust_sysroot = Path(rustc_record["sysroot"])
    runtime_libdir = rust_sysroot / "lib" / "rustlib" / TARGET / "lib"
    objcopy = executable_identity(rust_sysroot / "lib" / "rustlib" / TARGET / "bin" / "llvm-objcopy",
                                  "pinned Rust target llvm-objcopy", within=rust_sysroot)
    python = sys.executable
    cargo_root = stage / "cargo"
    if allocator_backend not in ALLOCATOR_BACKENDS:
        raise BuildError("unknown owned allocator backend")
    accepted_c = allocator_backend == "accepted-c"
    c_flags = c_allocator_target_flags()
    environment = deterministic_environment()
    environment["CARGO_BUILD_JOBS"] = "2"
    selected_feature = "x86-owned-static-runtime" if accepted_c else "x86-owned-static-native-shadow"
    # The explicit scalar lifecycle audit mirrors the dynamic producer's
    # development flag. It selects no allocator and exposes no pointer.
    if lifecycle_test_audit:
        selected_feature += ",x86-owned-allocator-lifecycle-test-audit"
    dependency_graph = allocator_dependency_graph([rustup, "run", PINNED_TOOLCHAIN, "cargo"],
                                                 selected_feature, allocator_backend, environment)
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
        *TARGET_TLS_CONFIG,
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
    allocator_object, allocator_record = (compile_c_allocator(stage / "c-allocator", c_flags, profile="release")
                                          if accepted_c else (None, None))
    if allocator_object is not None:
        require_reviewed_hidden_list(allocator_object)
    allocator_lifecycle = (owned_mimalloc_lifecycle_profile(
        c_flags, cargo_command, allocator_object, raw_libc, llvm_nm=llvm_nm, llvm_objdump=llvm_objdump,
    ) if allocator_object is not None else {"initialization": "owned-static-startup-before-constructors",
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
            "--hardening-profile",
            hardening_profile.value,
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
        allocator_object=allocator_object,
        llvm_objcopy=str(objcopy["path"]),
        stock_runtime_libdir=runtime_libdir,
    )
    libc_provenance["rust_runtime_duplicate_binding_tool"] = objcopy
    if allocator_record is None:
        symbols = archive_defined_symbols(llvm_nm, libc)
        if any(name.startswith(("mi_", "_mi_")) for name in symbols):
            raise BuildError("native static archive defines C mimalloc symbols")
        libc_provenance["allocator_backend"] = {
            "implementation": ("native Rust; production-shaped selection" if recorded_backend == NATIVE_ALLOCATOR_BACKEND
                               else "native Rust shadow; promotion remains separate"),
            "upstream_sha256": sha256_file(ROOT / "crabc-mimalloc/UPSTREAM.md"),
            "target_flags": [],
        }
    else:
        libc_provenance["allocator_backend"] = {
            **allocator_record,
            "target_flags": [flag.replace(str(ROOT), "$CRABC_SOURCE") for flag in c_flags],
        }
        if recorded_backend == EVIDENCE_ALLOCATOR_BACKEND:
            libc_provenance["allocator_backend"]["pinned_c_evidence"] = allocator_record
    libc_provenance["dependency_graph"] = dependency_graph
    libc_provenance["allocator_lifecycle_test_audit"] = lifecycle_test_audit
    libc_provenance["allocator_backend"]["lifecycle_profile"] = allocator_lifecycle
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
            *TARGET_TLS_CONFIG,
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
        "hardening_profile": hardening_profile,
        "allocator_lifecycle_test_audit": lifecycle_test_audit,
        "crt_root": crt_root,
        "builtins": builtins,
        "builtins_provenance": builtins_provenance,
        "libc": libc,
        "libc_provenance": libc_provenance,
        "producer_tools": producer_tools,
    }


def build_commands_record(
    cargo_command: list[str], producer_tools: dict[str, object], *, profile: str = "release",
    hardening_profile: NativeRuntimeProfile = NativeRuntimeProfile.COMPATIBILITY,
    source_core: Path | None = None, source_compiler_builtins: Path | None = None,
    source_libc: Path | None = None,
) -> dict[str, object]:
    """Make the installed build record carry the exact producer identity."""

    record = {
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
                "--hardening-profile",
                hardening_profile.value,
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
    record["build_profile"] = profile
    if profile == "debug":
        if source_core is None or source_compiler_builtins is None or source_libc is None:
            raise BuildError("debug build record lacks its source-runtime metadata")
        arguments = ["--profile", "debug", "--runtime-core", str(source_core.with_suffix(".rmeta")),
                     "--runtime-compiler-builtins", str(source_compiler_builtins.with_suffix(".rmeta"))]
        record["commands"]["crt"].extend(arguments)
        record["commands"]["builtins"].remove("--verify-reproducible")
        record["commands"]["builtins"].extend(arguments)
        record["commands"]["builtins"].extend(["--runtime-libc", str(source_libc)])
    return record


def validate_crt_profile(crt_root: Path, profile: NativeRuntimeProfile) -> None:
    try:
        receipt = json.loads((crt_root / "objects.json").read_text(encoding="utf-8"))
        if (not isinstance(profile, NativeRuntimeProfile)
                or receipt["hardening_profile"] != profile.value
                or receipt["objects"]["rcrt1.o"]["sha256"] != sha256_file(crt_root / "rcrt1.o")):
            raise BuildError("CRT profile or static PIE object does not match product")
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise BuildError("invalid CRT profile receipt") from error


def assemble(output: Path, inputs: dict[str, object], source_sha256: str) -> dict[str, object]:
    crt_root = inputs["crt_root"]
    assert isinstance(crt_root, Path)
    validate_crt_profile(crt_root, inputs["hardening_profile"])
    remove_owned_output(output)
    output.mkdir(parents=True)
    output.chmod(0o755)
    include_manifest = install_header_tree(output / "usr" / "include")
    install_static_driver(output / STATIC_DRIVER_PATH)
    library_root = output / "usr" / "lib"
    library_root.mkdir(parents=True)
    library_root.chmod(0o755)
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
        include_manifest,
    )
    cargo_command = inputs["cargo_command"]
    producer_tools = inputs["producer_tools"]
    assert isinstance(cargo_command, list) and isinstance(producer_tools, dict)
    write_json(
        metadata_root / "build.commands.json",
        build_commands_record(cargo_command, producer_tools, profile=inputs.get("build_profile", "release"),
                              hardening_profile=inputs["hardening_profile"],
                              source_core=inputs.get("source_core"), source_compiler_builtins=inputs.get("source_compiler_builtins"),
                              source_libc=inputs.get("source_libc")),
    )

    manifest_path = metadata_root / "manifest.json"
    payload_hashes = regular_file_hashes(
        output,
        exclude=frozenset({manifest_path.relative_to(output).as_posix()}),
    )
    manifest = installed_manifest(payload_hashes, producer_tools,
                                  allocator_backend=inputs.get("allocator_backend", DEFAULT_ALLOCATOR_BACKEND),
                                  hardening_profile=inputs["hardening_profile"],
                                  source_sha256=source_sha256,
                                  lifecycle_test_audit=inputs["libc_provenance"].get("allocator_lifecycle_test_audit", False))
    manifest["build_profile"] = inputs.get("build_profile", "release")
    write_json(manifest_path, manifest)
    installed_hashes = regular_file_hashes(output)
    expected = set(payload_hashes) | {manifest_path.relative_to(output).as_posix()}
    if set(installed_hashes) != expected:
        raise BuildError("installed tree changed while writing its manifest")
    return manifest


def build(output: Path, *, allocator_backend: str = DEFAULT_ALLOCATOR_BACKEND,
          lifecycle_test_audit: bool = False, profile: str = "release",
          hardening_profile: NativeRuntimeProfile = NativeRuntimeProfile.COMPATIBILITY) -> dict[str, object]:
    assert_native_target()
    source_before_build = source_seal.product_source_digest(ROOT)
    output = validate_output_path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if profile == "debug":
        stage = output.parent / (output.name + ".build")
        stage.mkdir(mode=0o700)
        stage_context = contextlib.nullcontext(str(stage))
    else:
        stage_context = tempfile.TemporaryDirectory(prefix="crabc-x86-owned-sysroot.", dir=output.parent)
    with stage_context as temporary:
        temporary_root = Path(temporary)
        inputs = build_runtime_inputs(temporary_root, allocator_backend=allocator_backend,
                                      lifecycle_test_audit=lifecycle_test_audit, profile=profile,
                                      hardening_profile=hardening_profile)
        staged_output = temporary_root / "installed"
        manifest = assemble(staged_output, inputs, source_before_build)
        if source_seal.product_source_digest(ROOT) != source_before_build:
            raise BuildError("owned static source changed during build")
        remove_owned_output(output)
        staged_output.replace(output)
        return manifest


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--allocator-backend", choices=ALLOCATOR_BACKENDS, default=DEFAULT_ALLOCATOR_BACKEND)
    parser.add_argument("--allocator-lifecycle-test-audit", action="store_true")
    parser.add_argument("--profile", choices=("release", "debug"), default="release")
    parser.add_argument("--hardening-profile", type=NativeRuntimeProfile, choices=tuple(NativeRuntimeProfile),
                        default=NativeRuntimeProfile.COMPATIBILITY)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        parsed = parse_args(arguments)
        manifest = build(parsed.output, allocator_backend=parsed.allocator_backend,
                         lifecycle_test_audit=parsed.allocator_lifecycle_test_audit, profile=parsed.profile,
                         hardening_profile=parsed.hardening_profile)
    except BuildError as error:
        print(f"x86 owned static sysroot failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
