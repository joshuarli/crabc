#!/usr/bin/env python3
"""Sealed private Linux/x86-64 static compiler-driver seed.

This file is installed verbatim as ``bin/crabc-cc`` by
``scripts/build_x86_64_owned_sysroot.py``.  It is deliberately a small,
fail-closed link boundary: source translation may use the pinned development
environment, while every target header, CRT object, library, and compiler
helper is named from the installed tree next to this driver.  It does not
admit dynamic linking, target search paths, linker injection, or a host
compiler runtime.

The two link modes are a planned owned-static product seed only.  Their
presence is not evidence that the static-product coverage, either sysroot
family, or x86-64 support has completed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


TARGET = "x86_64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"
DRIVER_FORMAT = "crabc-x86-64-sealed-static-driver-v1"
SYSROOT_FORMAT = "crabc-x86-64-owned-static-sysroot-v1"
LINK_RECEIPT_SCHEMA = 1
APPLICATION_OBJECTS = "<application-objects>"
OUTPUT = "<output>"
MANIFEST_RELATIVE_PATH = "share/crabc/manifest.json"

# Caller-owned ``.o`` inputs cross directly into LLD.  Keep their format
# boundary explicit instead of allowing suffix-based dispatch to reinterpret a
# linker script, archive, bitcode file, or foreign ELF as an input graph.
ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_REL = 1
EM_X86_64 = 62
ELF64_HEADER_SIZE = 64
ELF64_SECTION_HEADER_SIZE = 64
SHT_LLVM_LINKER_OPTIONS = 0x6FFF4C01
SHT_LLVM_DEPENDENT_LIBRARIES = 0x6FFF4C04
FORBIDDEN_APPLICATION_SECTION_TYPES = frozenset(
    {SHT_LLVM_LINKER_OPTIONS, SHT_LLVM_DEPENDENT_LIBRARIES}
)


class DriverError(RuntimeError):
    """The invocation would escape the installed owned-static boundary."""


@dataclass(frozen=True)
class StaticMode:
    """One target-ELF mode and the CRT object which owns its entry path."""

    identifier: str
    elf_type: str
    crt_object: str
    compiler_flag: str
    linker_flags: tuple[str, ...]


STATIC_ET_EXEC = StaticMode(
    identifier="static-et-exec",
    elf_type="ET_EXEC",
    crt_object="crt1.o",
    compiler_flag="-fno-pie",
    linker_flags=(),
)
STATIC_PIE = StaticMode(
    identifier="static-pie",
    elf_type="ET_DYN",
    crt_object="rcrt1.o",
    compiler_flag="-fPIE",
    linker_flags=("-pie",),
)
STATIC_MODES = {mode.identifier: mode for mode in (STATIC_ET_EXEC, STATIC_PIE)}

REQUIRED_RUNTIME_PATHS = (
    "usr/lib/crt1.o",
    "usr/lib/rcrt1.o",
    "usr/lib/crti.o",
    "usr/lib/crtn.o",
    "usr/lib/libc.a",
    "usr/lib/libcrabc-builtins.a",
)

# Header, CRT, library, and linker controls are all target-runtime authority.
# Letting an application supply any one of these would make a successful link
# unable to prove which runtime it consumed.  This intentionally conservative
# seed accepts ordinary source/object inputs and non-runtime translation flags
# only; broader application flag support belongs to a later product contract.
REJECTED_FLAGS_WITH_VALUE = frozenset(
    {
        "-I",
        "-isystem",
        "-iquote",
        "-idirafter",
        "-include",
        "-imacros",
        "-isysroot",
        "--sysroot",
        "-L",
        "-l",
        "-B",
        "-Xlinker",
        "-T",
        "-u",
        "-e",
        "-rtlib",
        "-stdlib",
    }
)
REJECTED_FLAG_PREFIXES = (
    "-I",
    "-isystem",
    "-iquote",
    "-idirafter",
    "-include",
    "-imacros",
    "-isysroot",
    "--sysroot=",
    "-L",
    "-l",
    "-B",
    # GCC spells direct preprocessor/assembler argv forwarding as ``-Wp,``
    # and ``-Wa,``.  They are not diagnostic ``-W`` flags and can re-open the
    # sealed target-input boundary.
    "-Wp,",
    "-Wa,",
    "-Wl,",
    "-Xlinker",
    "-rtlib=",
    "-stdlib=",
)
REJECTED_EXACT_FLAGS = frozenset(
    {
        "-shared",
        "-dynamic",
        "-rdynamic",
        "-pie",
        "-no-pie",
        "-fPIC",
        "-fpic",
        "-fPIE",
        "-fpie",
        "-nostdinc",
        "-nostdlib",
        "-nodefaultlibs",
        "-nostartfiles",
        "-static-libgcc",
        "-static-libstdc++",
    }
)
REJECTED_APPLICATION_OBJECT_NAMES = frozenset(
    {
        "crt1.o",
        "Scrt1.o",
        "rcrt1.o",
        "crti.o",
        "crtn.o",
        "crtbegin.o",
        "crtend.o",
        "libgcc.o",
        "compiler-rt.o",
    }
)


def installed_root(program: Path | None = None) -> Path:
    """Return the installed tree owning the executable driver, never CWD."""

    executable = (program or Path(__file__)).resolve()
    if executable.parent.name != "bin":
        raise DriverError("crabc-cc must be installed at <sysroot>/bin/crabc-cc")
    return executable.parent.parent


def require_regular(path: Path, description: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise DriverError(f"owned {description} is missing or unsafe: {path}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_payload_files(root: Path) -> dict[str, str]:
    """Load the builder's regular-file hash boundary without trusting CWD."""

    manifest_path = root / "share" / "crabc" / "manifest.json"
    require_regular(manifest_path, "manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DriverError(f"owned manifest is unreadable: {manifest_path}") from error
    if not isinstance(manifest, dict):
        raise DriverError("owned manifest is not an object")
    if manifest.get("format") != SYSROOT_FORMAT or manifest.get("target") != TARGET:
        raise DriverError("owned manifest does not identify this x86 static sysroot")
    installed = manifest.get("installed")
    driver = manifest.get("sealed_static_driver")
    if not isinstance(installed, dict) or installed.get("sealed_static_driver") != "bin/crabc-cc":
        raise DriverError("owned manifest does not bind the sealed static driver")
    if not isinstance(driver, dict) or driver.get("format") != DRIVER_FORMAT:
        raise DriverError("owned manifest sealed static driver record drifted")
    if driver.get("status") != "planned-owned-static-product-seed-not-family-completion-not-public-support":
        raise DriverError("owned manifest sealed static driver status drifted")
    files = installed.get("files")
    if not isinstance(files, dict) or not files:
        raise DriverError("owned manifest has no regular-file payload hashes")
    result: dict[str, str] = {}
    for relative, expected_hash in files.items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            raise DriverError("owned manifest has an invalid payload hash record")
        candidate = Path(relative)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise DriverError(f"owned manifest has an unsafe payload path: {relative}")
        if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash):
            raise DriverError(f"owned manifest has an invalid payload hash: {relative}")
        result[relative] = expected_hash
    return result


def validate_manifest_payload(root: Path) -> None:
    """Bind driver execution to the immutable installed regular-file payload."""

    files = manifest_payload_files(root)
    expected_files = set(files)
    observed_files: set[str] = set()
    for artifact in sorted(root.rglob("*")):
        relative = artifact.relative_to(root).as_posix()
        if artifact.is_symlink():
            raise DriverError(f"owned installed tree contains a symlink: {relative}")
        if artifact.is_dir():
            continue
        if not artifact.is_file():
            raise DriverError(f"owned installed tree contains a non-regular entry: {relative}")
        if relative == MANIFEST_RELATIVE_PATH:
            continue
        observed_files.add(relative)
    undeclared = sorted(observed_files - expected_files)
    if undeclared:
        raise DriverError(f"owned manifest has an undeclared installed regular file: {undeclared[0]}")
    missing = sorted(expected_files - observed_files)
    if missing:
        raise DriverError(f"owned manifest payload is missing: {missing[0]}")
    for relative, expected_hash in files.items():
        artifact = root / relative
        require_regular(artifact, relative)
        if sha256_file(artifact) != expected_hash:
            raise DriverError(f"owned manifest payload hash mismatch: {relative}")


def validate_installed_runtime(root: Path) -> None:
    """Fail before source translation if the installed static boundary is absent."""

    validate_manifest_payload(root)
    include = root / "usr" / "include"
    if not include.is_dir() or include.is_symlink():
        raise DriverError(f"owned installed headers are missing or unsafe: {include}")
    for relative in REQUIRED_RUNTIME_PATHS:
        require_regular(root / relative, relative)


def static_mode(identifier: str) -> StaticMode:
    try:
        return STATIC_MODES[identifier]
    except KeyError as error:
        raise DriverError(f"unsupported owned static mode: {identifier}") from error


def owned_link_plan(root: Path, mode: StaticMode) -> list[str]:
    """Return the complete explicit LLD plan with only an application hole."""

    library = root / "usr" / "lib"
    return [
        "ld.lld",
        "-static",
        *mode.linker_flags,
        "--no-dynamic-linker",
        "--no-undefined",
        "--gc-sections",
        "-z",
        "relro",
        "-z",
        "now",
        "-e",
        "_start",
        str(library / mode.crt_object),
        str(library / "crti.o"),
        APPLICATION_OBJECTS,
        str(library / "libc.a"),
        str(library / "libcrabc-builtins.a"),
        str(library / "crtn.o"),
        "-o",
        OUTPUT,
    ]


def plan_record(root: Path, mode: StaticMode) -> dict[str, object]:
    """Serialize the inspected, deterministic link contract without executing it."""

    return {
        "schema": 1,
        "format": DRIVER_FORMAT,
        "target": TARGET,
        "status": "planned-owned-static-product-seed-not-family-completion-not-public-support",
        "mode": {
            "id": mode.identifier,
            "elf_type": mode.elf_type,
            "crt_object": mode.crt_object,
            "interpreter": "absent",
        },
        "headers": str(root / "usr" / "include"),
        "owned_target_inputs": [
            str(root / "usr" / relative) for relative in REQUIRED_RUNTIME_PATHS
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
        "linker": owned_link_plan(root, mode),
    }


@dataclass(frozen=True)
class Invocation:
    mode: StaticMode
    compile_only: bool
    print_link_plan: bool
    link_receipt: Path | None
    output: Path | None
    sources: tuple[Path, ...]
    objects: tuple[Path, ...]
    compiler_flags: tuple[str, ...]


def rejects_runtime_flag(argument: str) -> bool:
    if argument in REJECTED_EXACT_FLAGS or argument in REJECTED_FLAGS_WITH_VALUE:
        return True
    return argument.startswith(REJECTED_FLAG_PREFIXES)


def rejects_runtime_object(path: Path) -> bool:
    """Do not let a named application object impersonate target runtime input."""

    name = path.name
    return (
        name in REJECTED_APPLICATION_OBJECT_NAMES
        or name.startswith(("libgcc", "compiler-rt"))
        or "compiler-rt" in path.as_posix()
    )


def parse_invocation(arguments: Sequence[str]) -> Invocation:
    """Parse a deliberately narrow application surface without fallback flags."""

    mode = STATIC_ET_EXEC
    mode_selected = False
    compile_only = False
    print_link_plan = False
    link_receipt: Path | None = None
    output: Path | None = None
    sources: list[Path] = []
    objects: list[Path] = []
    compiler_flags: list[str] = []
    index = 0

    while index < len(arguments):
        argument = arguments[index]
        if argument == "--print-link-plan":
            print_link_plan = True
        elif argument == "--link-receipt":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-"):
                raise DriverError("--link-receipt requires a non-option JSON path")
            if link_receipt is not None:
                raise DriverError("--link-receipt may be specified only once")
            link_receipt = Path(arguments[index])
        elif argument in {"-static", "--static-et-exec"}:
            if mode_selected:
                raise DriverError("select exactly one owned static link mode")
            mode = STATIC_ET_EXEC
            mode_selected = True
        elif argument in {"-static-pie", "--static-pie"}:
            if mode_selected:
                raise DriverError("select exactly one owned static link mode")
            mode = STATIC_PIE
            mode_selected = True
        elif argument == "-c":
            compile_only = True
        elif argument == "-o":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-"):
                raise DriverError("-o requires a non-option output path")
            output = Path(arguments[index])
        elif rejects_runtime_flag(argument):
            raise DriverError(f"unowned target-runtime flag is rejected: {argument}")
        elif argument.startswith("-"):
            if argument.startswith(("-D", "-U", "-O", "-g", "-std=", "-W", "-fno-")):
                compiler_flags.append(argument)
            else:
                raise DriverError(f"unsupported driver flag: {argument}")
        else:
            path = Path(argument)
            if path.suffix == ".c":
                sources.append(path)
            elif path.suffix == ".o":
                if rejects_runtime_object(path):
                    raise DriverError(f"unowned target-runtime object is rejected: {argument}")
                objects.append(path)
            else:
                raise DriverError(f"only admitted application .c and .o inputs are supported: {argument}")
        index += 1

    if print_link_plan:
        if compile_only or link_receipt is not None or output is not None or sources or objects or compiler_flags:
            raise DriverError("--print-link-plan accepts only one optional static mode")
        return Invocation(mode, False, True, None, None, (), (), ())
    if compile_only and link_receipt is not None:
        raise DriverError("--link-receipt is available only for a link invocation")
    if link_receipt is not None and sources:
        raise DriverError(
            "--link-receipt requires caller-owned application object (.o) inputs"
        )
    if compile_only and objects:
        raise DriverError("-c accepts source files, not prebuilt application objects")
    if compile_only and len(sources) != 1:
        raise DriverError("-c requires exactly one admitted application source")
    if not compile_only and not (sources or objects):
        raise DriverError("linking requires at least one admitted application source or object")
    return Invocation(
        mode,
        compile_only,
        False,
        link_receipt,
        output,
        tuple(sources),
        tuple(objects),
        tuple(compiler_flags),
    )


def clean_environment() -> dict[str, str]:
    """Do not propagate ambient include/library/toolchain controls to children."""

    return {
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "SOURCE_DATE_EPOCH": "1",
        "TZ": "UTC",
    }


def pinned_rustup_environment() -> tuple[Path, dict[str, str]]:
    """Locate the pinned Rust producer without admitting a caller tool path.

    The x86 evidence image owns the Rust installation under ``/opt``.  Its
    immutable toolchain name, rather than a caller-supplied linker setting or
    PATH lookup, selects the fallback LLD.  The two location variables are
    retained solely so that the absolute rustup executable can find its own
    pinned installation after the child environment drops all ambient target
    include/library/compiler controls.
    """

    cargo_home = Path("/opt/cargo")
    rustup_home = Path("/opt/rustup")
    rustup = cargo_home / "bin" / "rustup"
    require_regular(rustup.resolve(), "pinned rustup")
    environment = clean_environment()
    environment["CARGO_HOME"] = str(cargo_home)
    environment["RUSTUP_HOME"] = str(rustup_home)
    # Alpine's installed ``rustup`` frontend is a symlink whose invoked name
    # selects its command-line mode.  Validate its resolved regular target,
    # but execute the fixed frontend path rather than flattening that name.
    return rustup, environment


def resolved_path(path: Path, description: str) -> Path:
    """Resolve an existing or prospective path without masking unsafe loops."""

    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise DriverError(f"{description} is unsafe: {path}") from error


def is_within_installed_root(root: Path, path: Path) -> bool:
    """Whether a resolved path belongs to this driver's sealed payload root."""

    try:
        resolved_path(path, "application path").relative_to(
            resolved_path(root, "installed sysroot")
        )
    except ValueError:
        return False
    return True


def reject_existing_symlink_components(path: Path, description: str) -> None:
    """Reject output routing through any existing symlink, including a parent."""

    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise DriverError(f"{description} traverses an existing symlink: {path}")


def validate_application_output(root: Path, output: Path) -> None:
    """Keep compiler/linker writes outside the immutable installed sysroot."""

    reject_existing_symlink_components(output, "application output")
    if is_within_installed_root(root, output):
        raise DriverError(f"application output must not modify the installed sysroot: {output}")


def validate_application_output_disjoint(
    output: Path, application_inputs: Sequence[Path]
) -> None:
    """Keep a compiler/linker output distinct from every consumed application file."""

    normalized_output = resolved_path(output, "application output")
    for application_input in application_inputs:
        normalized_input = resolved_path(application_input, "admitted application input")
        try:
            aliases_input = normalized_output == normalized_input or (
                normalized_output.exists() and normalized_output.samefile(normalized_input)
            )
        except OSError as error:
            raise DriverError(
                f"application output/input alias check is unsafe: {output}"
            ) from error
        if aliases_input:
            raise DriverError(
                f"application output collides with admitted application input: {output}"
            )


def require_application_file(root: Path, path: Path, kind: str) -> Path:
    """Admit an external regular application input, never a sealed-root file."""

    resolved = resolved_path(path, f"admitted application {kind}")
    if not resolved.is_file() or path.is_symlink():
        raise DriverError(f"admitted application {kind} is missing or unsafe: {path}")
    if is_within_installed_root(root, resolved):
        raise DriverError(f"admitted application {kind} is inside the installed sysroot: {path}")
    return resolved


def require_x86_64_relocatable_object(root: Path, path: Path) -> Path:
    """Admit only a structurally complete Linux/x86-64 ET_REL object.

    LLD dispatches a named input by file contents, not by its ``.o`` suffix.
    In particular, linker scripts and thin archives can make a caller-owned
    path add further ambient inputs.  The two LLVM section types below carry
    linker-control metadata rather than ordinary object payload: dependent
    libraries make LLD search or open another library, while linker options
    reserve a second route for embedded linker authority.  Reject both before
    the fixed plan reaches LLD.
    """

    object_path = require_application_file(root, path, "object")

    def malformed(detail: str) -> None:
        raise DriverError(
            "admitted application object is not a Linux/x86-64 ELF64 ET_REL object: "
            f"{path} ({detail})"
        )

    try:
        file_size = object_path.stat().st_size
        with object_path.open("rb") as stream:
            header = stream.read(ELF64_HEADER_SIZE)
            if len(header) != ELF64_HEADER_SIZE:
                malformed("truncated ELF header")
            if (
                header[:4] != ELF_MAGIC
                or header[4] != ELFCLASS64
                or header[5] != ELFDATA2LSB
                or header[6] != EV_CURRENT
            ):
                malformed("not an ELF64 little-endian current object")
            if (
                int.from_bytes(header[16:18], "little") != ET_REL
                or int.from_bytes(header[18:20], "little") != EM_X86_64
                or int.from_bytes(header[20:24], "little") != EV_CURRENT
                or int.from_bytes(header[52:54], "little") != ELF64_HEADER_SIZE
            ):
                malformed("wrong ELF type, machine, version, or header size")

            section_table_offset = int.from_bytes(header[40:48], "little")
            section_header_size = int.from_bytes(header[58:60], "little")
            encoded_section_count = int.from_bytes(header[60:62], "little")
            if section_header_size != ELF64_SECTION_HEADER_SIZE:
                malformed("unexpected section-header size")
            if (
                section_table_offset < ELF64_HEADER_SIZE
                or section_table_offset > file_size - ELF64_SECTION_HEADER_SIZE
            ):
                malformed("missing or out-of-bounds section table")

            stream.seek(section_table_offset)
            first_section = stream.read(ELF64_SECTION_HEADER_SIZE)
            if len(first_section) != ELF64_SECTION_HEADER_SIZE:
                malformed("truncated first section header")
            if int.from_bytes(first_section[4:8], "little") != 0:
                malformed("section zero is not SHT_NULL")
            section_count = encoded_section_count or int.from_bytes(
                first_section[32:40], "little"
            )
            if (
                section_count == 0
                or section_count
                > (file_size - section_table_offset) // ELF64_SECTION_HEADER_SIZE
            ):
                malformed("invalid section count")

            for index in range(section_count):
                section = (
                    first_section
                    if index == 0
                    else stream.read(ELF64_SECTION_HEADER_SIZE)
                )
                if len(section) != ELF64_SECTION_HEADER_SIZE:
                    malformed("truncated section header")
                section_type = int.from_bytes(section[4:8], "little")
                if section_type in FORBIDDEN_APPLICATION_SECTION_TYPES:
                    raise DriverError(
                        "admitted application object contains forbidden LLVM linker-control "
                        f"section: {path}"
                    )
    except OSError as error:
        raise DriverError(f"admitted application object is unreadable: {path}") from error
    return object_path


def run_checked(command: Sequence[str]) -> None:
    completed = subprocess.run(
        list(command),
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise DriverError(f"owned static command failed ({completed.returncode}): {' '.join(command)}")


def receipt_sidecars(root: Path, receipt: Path) -> tuple[Path, Path, Path]:
    """Reserve a regular, relative receipt/map/trace set owned by this driver.

    The application may choose where its evidence is written, but it cannot
    pass that value through to LLD as an arbitrary linker flag.  The map and
    trace names are mechanically derived here, and every sidecar must be new;
    this prevents a link audit request from following or overwriting a
    pre-existing target.
    """

    if receipt.is_absolute() or not receipt.parts or receipt.suffix != ".json":
        raise DriverError("--link-receipt requires a relative .json path")
    if any(part in {"", ".", ".."} for part in receipt.parts):
        raise DriverError("--link-receipt path is unsafe")
    parent = receipt.parent
    if not parent.is_dir() or parent.is_symlink():
        raise DriverError("--link-receipt parent is missing or unsafe")
    map_path = receipt.with_suffix(".map")
    trace_path = receipt.with_suffix(".trace")
    for path in (receipt, map_path, trace_path):
        reject_existing_symlink_components(path, "--link-receipt sidecar")
        if is_within_installed_root(root, path):
            raise DriverError("--link-receipt must not modify the installed sysroot")
        if path.exists() or path.is_symlink():
            raise DriverError(f"--link-receipt sidecar already exists or is unsafe: {path}")
    return receipt, map_path, trace_path


def validate_receipt_output_disjoint(root: Path, output: Path, receipt: Path) -> None:
    """Reject a link output which aliases any driver-owned audit sidecar.

    The receipt is created after LLD has written its map and trace.  An output
    collision would otherwise make the successful link erase an audit artifact
    or make receipt creation fail after target code was already produced.  Use
    resolved prospective paths so ``./receipt.json``, an absolute spelling,
    and lexical parent traversal cannot evade the pairwise-disjoint boundary.
    """

    normalized_output = resolved_path(output, "application output")
    for label, sidecar in zip(("JSON", "map", "trace"), receipt_sidecars(root, receipt)):
        if normalized_output == resolved_path(sidecar, "--link-receipt sidecar"):
            raise DriverError(
                f"application output collides with --link-receipt {label} sidecar: {output}"
            )


def validate_link_trace(
    root: Path, mode: StaticMode, applications: Sequence[Path], trace_path: Path
) -> None:
    """Require LLD's actual inputs to equal the sealed plan plus application objects.

    The fixed command line is a declaration, while ``--trace`` is the linker
    observation.  A receipt is meaningful only when those agree: the three
    direct CRT objects, both owned archives (or their selected members), and
    the caller objects must be all and only the trace inputs.
    """

    require_regular(trace_path, "link trace")
    try:
        trace_lines = trace_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise DriverError(f"owned static link trace is unreadable: {trace_path}") from error

    library = root / "usr" / "lib"
    direct_inputs = (
        library / mode.crt_object,
        library / "crti.o",
        *applications,
        library / "crtn.o",
    )
    archive_inputs = (library / "libc.a", library / "libcrabc-builtins.a")
    direct_texts = {str(path) for path in direct_inputs}
    archive_texts = {str(path) for path in archive_inputs}
    expected = direct_texts | archive_texts
    seen: set[str] = set()
    for line in trace_lines:
        if not line:
            continue
        if line in direct_texts:
            seen.add(line)
            continue
        for archive in archive_inputs:
            archive_text = str(archive)
            if line == archive_text or (
                line.startswith(f"{archive_text}(") and line.endswith(")")
            ):
                seen.add(archive_text)
                break
        else:
            raise DriverError(f"owned static link trace contains unadmitted input: {line}")
    missing = sorted(expected - seen)
    if missing:
        raise DriverError(f"owned static link trace omitted expected input: {missing[0]}")


def receipt_input_records(root: Path, mode: StaticMode, applications: Sequence[Path]) -> list[dict[str, str]]:
    """Hash the exact target inputs consumed by one sealed static link."""

    library = root / "usr" / "lib"
    runtime = (
        ("crt-entry", library / mode.crt_object),
        ("crt-prologue", library / "crti.o"),
        ("libc", library / "libc.a"),
        ("builtins", library / "libcrabc-builtins.a"),
        ("crt-epilogue", library / "crtn.o"),
    )
    records = [
        {
            "role": role,
            "path": str(path.relative_to(root)),
            "sha256": sha256_file(path),
        }
        for role, path in runtime
    ]
    records.extend(
        {
            "role": "application",
            "path": str(path),
            "sha256": sha256_file(path),
        }
        for path in applications
    )
    return records


def write_link_receipt(
    root: Path,
    mode: StaticMode,
    applications: Sequence[Path],
    output: Path,
    linker_path: Path,
    receipt: Path,
    map_path: Path,
    trace_path: Path,
) -> None:
    """Write a stable receipt after LLD produced the driver-owned sidecars."""

    require_regular(output, "link output")
    require_regular(linker_path, "resolved linker")
    require_regular(map_path, "link map")
    require_regular(trace_path, "link trace")
    record = {
        "schema": LINK_RECEIPT_SCHEMA,
        "format": DRIVER_FORMAT,
        "target": TARGET,
        "mode": {
            "id": mode.identifier,
            "elf_type": mode.elf_type,
            "crt_object": mode.crt_object,
            "interpreter": "absent",
        },
        "resolved_linker": {
            "path": str(linker_path),
            "sha256": sha256_file(linker_path),
        },
        "owned_link_contract": owned_link_plan(root, mode),
        "input_receipts": receipt_input_records(root, mode, applications),
        "output": {"path": str(output), "sha256": sha256_file(output)},
        "map": {"path": str(map_path), "sha256": sha256_file(map_path)},
        "trace": {"path": str(trace_path), "sha256": sha256_file(trace_path)},
    }
    try:
        with receipt.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    except OSError as error:
        raise DriverError(f"cannot write owned link receipt: {receipt}") from error


def run_link_with_receipt(
    root: Path,
    mode: StaticMode,
    applications: Sequence[Path],
    command: Sequence[str],
    receipt: Path,
) -> tuple[Path, Path, Path]:
    """Run LLD with internally-selected trace/map evidence, never user flags."""

    receipt, map_path, trace_path = receipt_sidecars(root, receipt)
    if len(command) < 3 or command[-2] != "-o":
        raise DriverError("sealed link plan has no terminal output")
    audited_command = [
        *command[:-2],
        "--trace",
        f"-Map={map_path}",
        *command[-2:],
    ]
    try:
        with trace_path.open("x", encoding="utf-8", newline="\n") as trace:
            completed = subprocess.run(
                audited_command,
                env=clean_environment(),
                stdin=subprocess.DEVNULL,
                stdout=trace,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
    except OSError as error:
        raise DriverError("owned static linker could not start") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        suffix = f": {detail}" if detail else ""
        raise DriverError(f"owned static command failed ({completed.returncode}){suffix}")
    validate_link_trace(root, mode, applications, trace_path)
    return receipt, map_path, trace_path


def compiler() -> str:
    path = shutil.which("gcc", path=clean_environment()["PATH"])
    if path is None:
        raise DriverError("the fixed-image source translator gcc is unavailable")
    return path


def linker() -> str:
    path = shutil.which("ld.lld", path=clean_environment()["PATH"])
    if path is not None:
        return str(Path(path).resolve())
    rustup, environment = pinned_rustup_environment()
    completed = subprocess.run(
        [str(rustup), "run", PINNED_TOOLCHAIN, "rustc", "--print", "sysroot"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise DriverError("the pinned Rust toolchain cannot report its sysroot")
    sysroot = Path(completed.stdout.strip())
    if not sysroot.is_absolute():
        raise DriverError("the pinned Rust toolchain reported an unsafe sysroot")
    bundled = sysroot / "lib" / "rustlib" / TARGET / "bin" / "gcc-ld" / "ld.lld"
    require_regular(bundled.resolve(), "pinned Rust-toolchain ld.lld")
    return str(bundled.resolve())


def compile_source(root: Path, mode: StaticMode, source: Path, output: Path, flags: Sequence[str]) -> None:
    run_checked(
        [
            compiler(),
            "-nostdinc",
            "-isystem",
            str(root / "usr" / "include"),
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            *flags,
            # Place the mode last so an admitted optimization/debug flag cannot
            # alter the selected ET_EXEC versus static-PIE code-generation mode.
            mode.compiler_flag,
            "-c",
            str(require_application_file(root, source, "source")),
            "-o",
            str(output),
        ]
    )


def materialize_link_plan(root: Path, mode: StaticMode, applications: Sequence[Path], output: Path) -> list[str]:
    plan = owned_link_plan(root, mode)
    result: list[str] = []
    for item in plan:
        if item == "ld.lld":
            result.append(linker())
        elif item == APPLICATION_OBJECTS:
            result.extend(str(path) for path in applications)
        elif item == OUTPUT:
            result.append(str(output))
        else:
            result.append(item)
    return result


def execute(root: Path, invocation: Invocation) -> None:
    if invocation.print_link_plan:
        print(json.dumps(plan_record(root, invocation.mode), indent=2, sort_keys=True))
        return
    if invocation.compile_only:
        source = invocation.sources[0]
        output = invocation.output or source.with_suffix(".o")
        validate_application_output(root, output)
        source_path = require_application_file(root, source, "source")
        validate_application_output_disjoint(output, (source_path,))
        compile_source(root, invocation.mode, source, output, invocation.compiler_flags)
        return

    with tempfile.TemporaryDirectory(prefix="crabc-cc-static.") as temporary:
        temporary_root = Path(temporary)
        output = invocation.output or Path("a.out")
        validate_application_output(root, output)
        if invocation.link_receipt is not None:
            validate_receipt_output_disjoint(root, output, invocation.link_receipt)
        source_inputs = [
            require_application_file(root, path, "source") for path in invocation.sources
        ]
        objects = [
            require_x86_64_relocatable_object(root, path) for path in invocation.objects
        ]
        validate_application_output_disjoint(output, (*source_inputs, *objects))
        for index, source in enumerate(source_inputs):
            object_path = temporary_root / f"application-{index}.o"
            compile_source(root, invocation.mode, source, object_path, invocation.compiler_flags)
            objects.append(object_path)
        command = materialize_link_plan(root, invocation.mode, objects, output)
        if invocation.link_receipt is None:
            run_checked(command)
        else:
            receipt, map_path, trace_path = run_link_with_receipt(
                root,
                invocation.mode,
                objects,
                command,
                invocation.link_receipt,
            )
            write_link_receipt(
                root,
                invocation.mode,
                objects,
                output,
                Path(command[0]),
                receipt,
                map_path,
                trace_path,
            )


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        root = installed_root()
        validate_installed_runtime(root)
        execute(root, parse_invocation(sys.argv[1:] if arguments is None else arguments))
    except DriverError as error:
        print(f"crabc-cc: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
