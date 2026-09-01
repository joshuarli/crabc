#!/usr/bin/env python3
"""Sealed planned Linux/x86-64 dynamic compiler-driver seed.

The future owned dynamic installer may install this file as
``bin/crabc-cc-dynamic``.  It deliberately names every target runtime input
from its installed tree: dynamic PIE and non-PIE executables select their
owned CRT and canonical interpreter, while a shared object deliberately has
no PT_INTERP. Its plan records the future application-object and explicit-DSO
holes, but this non-materialized seed accepts only ``--print-link-plan``;
source translation and linking are rejected.

This is a link-boundary seed.  It does not materialize a dynamic sysroot,
prove the general loader, run the dynamic product suite, complete a family, or
make Linux/x86-64 publicly supported.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


TARGET = "x86_64-unknown-linux-musl"
DRIVER_FORMAT = "crabc-x86-64-sealed-dynamic-driver-v1"
CANONICAL_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
CANONICAL_INTERPRETER_RELATIVE_PATH = Path("lib/ld-crabc-x86_64.so.1")
COMPATIBILITY_INTERPRETER_RELATIVE_PATH = Path("lib/ld-musl-x86_64.so.1")
DYNAMIC_PRODUCT_STATE_RELATIVE_PATH = Path("share/crabc/dynamic-product-state.json")
PLANNED_PRODUCT_STATE_SCHEMA = "crabc.x86_64-owned-dynamic-product-state/v1"
PLANNED_PRODUCT_CONTRACT_SHA256 = "fe5053e696b158d69d98e96e0e78e5c935261a360c750b6892278eed752663a8"
PLANNED_PRODUCT_OWNER_FAMILY = "sysroot.owned-artifact"
PLANNED_DRIVER_STATUS = "planned-owned-dynamic-product-seed-not-family-completion-not-public-support"
APPLICATION_OBJECTS = "<application-objects>"
APPLICATION_DSOS = "<declared-application-dsos>"
OUTPUT = "<output>"


class DriverError(RuntimeError):
    """The invocation would escape the planned owned-dynamic boundary."""


@dataclass(frozen=True)
class DynamicMode:
    """One installed dynamic-link mode with its code-generation and CRT rules."""

    identifier: str
    elf_type: str
    crt_object: str | None
    compiler_flag: str
    linker_flags: tuple[str, ...]
    interpreter: str


DYNAMIC_PIE = DynamicMode(
    identifier="dynamic-pie",
    elf_type="ET_DYN",
    crt_object="Scrt1.o",
    compiler_flag="-fPIE",
    linker_flags=("-pie",),
    interpreter=CANONICAL_INTERPRETER,
)
DYNAMIC_NON_PIE = DynamicMode(
    identifier="dynamic-non-pie",
    elf_type="ET_EXEC",
    crt_object="crt1.o",
    compiler_flag="-fno-pie",
    linker_flags=("-no-pie",),
    interpreter=CANONICAL_INTERPRETER,
)
DYNAMIC_SHARED_OBJECT = DynamicMode(
    identifier="dynamic-shared-object",
    elf_type="ET_DYN",
    crt_object=None,
    compiler_flag="-fPIC",
    linker_flags=("-shared",),
    interpreter="absent",
)
DYNAMIC_MODES = {
    mode.identifier: mode
    for mode in (DYNAMIC_PIE, DYNAMIC_NON_PIE, DYNAMIC_SHARED_OBJECT)
}

REQUIRED_RUNTIME_PATHS = (
    CANONICAL_INTERPRETER_RELATIVE_PATH.as_posix(),
    "usr/lib/crt1.o",
    "usr/lib/Scrt1.o",
    "usr/lib/crti.o",
    "usr/lib/crtn.o",
    "usr/lib/libc.so",
    "usr/lib/libcrabc-builtins.a",
)

# Header, CRT, library, linker, and interpreter controls are target-runtime
# authority. A caller that can supply any of them could make a successful link
# look owned while resolving its target runtime elsewhere. The plan-only seed
# retains these parse-time rejections so a future materialized driver cannot
# silently broaden the recorded boundary; no caller input reaches a translator
# or linker today.
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
    "-Wl,",
    "-Xlinker",
    "-rtlib=",
    "-stdlib=",
)
REJECTED_EXACT_FLAGS = frozenset(
    {
        "-static",
        "-static-pie",
        "-dynamic",
        "-rdynamic",
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
        "libc.so",
        "libldso.so",
        "ld-crabc-x86_64.so.1",
        "ld-musl-x86_64.so.1",
    }
)


def installed_root(program: Path | None = None) -> Path:
    """Return the installed tree owning this driver, never the current directory."""

    executable = (program or Path(__file__)).resolve()
    if executable.parent.name != "bin":
        raise DriverError("crabc-cc-dynamic must be installed at <sysroot>/bin/crabc-cc-dynamic")
    return executable.parent.parent


def require_regular(path: Path, description: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise DriverError(f"owned {description} is missing or unsafe: {path}")


def validate_planned_dynamic_product_state(root: Path) -> None:
    """Bind this plan-only driver to the checked non-materialized seed.

    This driver is intentionally not a usable dynamic compiler driver.  A
    later materialized product gets a separate driver and receipt contract;
    accepting a state other than this exact non-promoting seed would let a
    plan record look like evidence for an unverified installed runtime.
    """

    state_path = root / DYNAMIC_PRODUCT_STATE_RELATIVE_PATH
    require_regular(state_path, "dynamic product state")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DriverError(f"owned dynamic product state is unreadable: {state_path}") from error
    if not isinstance(state, dict):
        raise DriverError("owned dynamic product state is not an object")
    expected_keys = {
        "schema",
        "owner_family",
        "contract_sha256",
        "status",
        "materialized_sysroot",
        "evidence",
        "reason",
        "promotion",
    }
    if set(state) != expected_keys:
        raise DriverError("owned dynamic product state schema drifted")
    if state.get("schema") != PLANNED_PRODUCT_STATE_SCHEMA:
        raise DriverError("owned dynamic product state schema drifted")
    if state.get("owner_family") != PLANNED_PRODUCT_OWNER_FAMILY:
        raise DriverError("owned dynamic product state owner drifted")
    if state.get("contract_sha256") != PLANNED_PRODUCT_CONTRACT_SHA256:
        raise DriverError("owned dynamic product state contract digest drifted")
    if state.get("status") != "not-materialized":
        raise DriverError("owned dynamic product state is not the checked-in not-materialized seed")
    if state.get("materialized_sysroot") is not None or state.get("evidence") != []:
        raise DriverError("owned dynamic product seed must not name materialized evidence")
    promotion = state.get("promotion")
    if promotion != {
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }:
        raise DriverError("owned dynamic product seed must remain non-promoting")
    if not isinstance(state.get("reason"), str) or not state["reason"]:
        raise DriverError("owned dynamic product seed reason is invalid")


def validate_compatibility_alias(root: Path) -> None:
    """Require a relative musl-name alias resolving exactly to the crabc loader."""

    alias = root / COMPATIBILITY_INTERPRETER_RELATIVE_PATH
    canonical = root / CANONICAL_INTERPRETER_RELATIVE_PATH
    if not alias.is_symlink():
        raise DriverError(f"compatibility interpreter alias is missing or unsafe: {alias}")
    try:
        target = alias.readlink()
    except OSError as error:
        raise DriverError(f"cannot read compatibility interpreter alias: {alias}") from error
    if str(target) != Path(CANONICAL_INTERPRETER).name:
        raise DriverError(f"compatibility interpreter alias does not name the canonical loader: {alias}")
    try:
        resolved_alias = alias.resolve(strict=True)
        resolved_canonical = canonical.resolve(strict=True)
    except OSError as error:
        raise DriverError(f"compatibility interpreter alias is not resolvable: {alias}") from error
    if resolved_alias != resolved_canonical:
        raise DriverError(f"compatibility interpreter alias escapes the owned loader: {alias}")


def validate_installed_runtime(root: Path) -> None:
    """Fail before emitting a plan if the declared installed boundary is absent."""

    validate_planned_dynamic_product_state(root)
    include = root / "usr" / "include"
    if not include.is_dir() or include.is_symlink():
        raise DriverError(f"owned installed headers are missing or unsafe: {include}")
    for relative in REQUIRED_RUNTIME_PATHS:
        require_regular(root / relative, relative)
    validate_compatibility_alias(root)


def dynamic_mode(identifier: str) -> DynamicMode:
    try:
        return DYNAMIC_MODES[identifier]
    except KeyError as error:
        raise DriverError(f"unsupported owned dynamic mode: {identifier}") from error


def owned_link_plan(root: Path, mode: DynamicMode) -> list[str]:
    """Return an explicit LLD plan with application inputs represented by holes."""

    library = root / "usr" / "lib"
    security = ["-z", "relro", "-z", "now", "-z", "noexecstack"]
    common = [
        "ld.lld",
        *mode.linker_flags,
        "--no-undefined",
        *security,
    ]
    if mode.crt_object is not None:
        common.extend(
            [
                "--dynamic-linker",
                CANONICAL_INTERPRETER,
                str(library / mode.crt_object),
                str(library / "crti.o"),
                APPLICATION_OBJECTS,
                APPLICATION_DSOS,
                str(library / "libc.so"),
                str(library / "libcrabc-builtins.a"),
                str(library / "crtn.o"),
                "-o",
                OUTPUT,
            ]
        )
    else:
        common.extend(
            [
                str(library / "crti.o"),
                APPLICATION_OBJECTS,
                APPLICATION_DSOS,
                str(library / "libc.so"),
                str(library / "libcrabc-builtins.a"),
                str(library / "crtn.o"),
                "-o",
                OUTPUT,
            ]
        )
    return common


def plan_record(root: Path, mode: DynamicMode) -> dict[str, object]:
    """Serialize the deterministic planned link boundary without executing it."""

    return {
        "schema": 1,
        "format": DRIVER_FORMAT,
        "target": TARGET,
        "status": PLANNED_DRIVER_STATUS,
        "mode": {
            "id": mode.identifier,
            "elf_type": mode.elf_type,
            "crt_object": mode.crt_object,
            "interpreter": mode.interpreter,
        },
        "headers": str(root / "usr" / "include"),
        "installed_manifest": str(root / "share" / "crabc" / "manifest.json"),
        "dynamic_product_state": str(root / DYNAMIC_PRODUCT_STATE_RELATIVE_PATH),
        "canonical_interpreter": CANONICAL_INTERPRETER,
        "compatibility_interpreter_alias": str(root / COMPATIBILITY_INTERPRETER_RELATIVE_PATH),
        "owned_target_inputs": [str(root / relative) for relative in REQUIRED_RUNTIME_PATHS],
        "rejected_ambient_target_inputs": [
            "headers",
            "CRT",
            "libc",
            "libgcc",
            "compiler-rt",
            "loader",
            "undeclared DSO search paths",
        ],
        "not_proven_by_this_seed": [
            "installed dynamic sysroot materialization",
            "general loader behavior",
            "dynamic CRT handoff and lifecycle",
            "declared dynamic smoke suite",
            "two-clean-build and extracted-install dynamic reproducibility",
            "sysroot.owned-artifact family completion",
            "x86-64 promotion or public support",
        ],
        "linker": owned_link_plan(root, mode),
    }


@dataclass(frozen=True)
class Invocation:
    mode: DynamicMode
    compile_only: bool
    print_link_plan: bool
    output: Path | None
    sources: tuple[Path, ...]
    objects: tuple[Path, ...]
    application_dsos: tuple[Path, ...]
    compiler_flags: tuple[str, ...]


def rejects_runtime_flag(argument: str) -> bool:
    if argument in REJECTED_EXACT_FLAGS or argument in REJECTED_FLAGS_WITH_VALUE:
        return True
    return argument.startswith(REJECTED_FLAG_PREFIXES)


def rejects_runtime_object(path: Path) -> bool:
    """Do not let application input impersonate a target runtime object or DSO."""

    name = path.name
    return (
        name in REJECTED_APPLICATION_OBJECT_NAMES
        or name.startswith(("libgcc", "compiler-rt", "libc."))
        or "compiler-rt" in path.as_posix()
        or "ld-musl" in name
        or "ld-crabc" in name
    )


def parse_invocation(arguments: Sequence[str]) -> Invocation:
    """Parse the sealed plan-only dynamic driver surface."""

    mode: DynamicMode | None = None
    compile_only = False
    print_link_plan = False
    output: Path | None = None
    sources: list[Path] = []
    objects: list[Path] = []
    application_dsos: list[Path] = []
    compiler_flags: list[str] = []
    index = 0

    while index < len(arguments):
        argument = arguments[index]
        if argument == "--print-link-plan":
            print_link_plan = True
        elif argument in {"--dynamic-pie", "-pie"}:
            if mode is not None:
                raise DriverError("select exactly one owned dynamic link mode")
            mode = DYNAMIC_PIE
        elif argument in {"--dynamic-non-pie", "-no-pie"}:
            if mode is not None:
                raise DriverError("select exactly one owned dynamic link mode")
            mode = DYNAMIC_NON_PIE
        elif argument in {"--dynamic-shared-object", "-shared"}:
            if mode is not None:
                raise DriverError("select exactly one owned dynamic link mode")
            mode = DYNAMIC_SHARED_OBJECT
        elif argument == "--application-dso":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-"):
                raise DriverError("--application-dso requires one non-option DSO path")
            path = Path(arguments[index])
            if path.suffix != ".so" or rejects_runtime_object(path):
                raise DriverError(f"unowned target-runtime DSO is rejected: {path}")
            application_dsos.append(path)
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
                raise DriverError(
                    f"only admitted application .c/.o inputs and --application-dso paths are supported: {argument}"
                )
        index += 1

    if mode is None:
        raise DriverError("select exactly one owned dynamic link mode")
    if print_link_plan:
        if compile_only or output is not None or sources or objects or application_dsos or compiler_flags:
            raise DriverError("--print-link-plan accepts exactly one owned dynamic mode")
        return Invocation(mode, False, True, None, (), (), (), ())
    raise DriverError(
        "planned owned dynamic product seed is plan-only; source translation and linking require a materialized product"
    )


def execute(root: Path, invocation: Invocation) -> None:
    if invocation.print_link_plan:
        print(json.dumps(plan_record(root, invocation.mode), indent=2, sort_keys=True))
        return
    raise DriverError(
        "planned owned dynamic product seed is plan-only; source translation and linking require a materialized product"
    )


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        root = installed_root()
        validate_installed_runtime(root)
        execute(root, parse_invocation(sys.argv[1:] if arguments is None else arguments))
    except DriverError as error:
        print(f"crabc-cc-dynamic: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
