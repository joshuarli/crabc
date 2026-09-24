#!/usr/bin/env python3
"""Replayable installed-provider evidence for text/locale/numeric rows.

The row map is the semantic boundary.  This module supplies the separate ELF
fact: every normal-role C entry point selected by that map stays an undefined
import in the installed-header ET_REL aggregate and has a physical provider in
both supplied products.  It intentionally does not treat an export inventory
as behavior evidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

import owned_text_locale_numeric_component_contract as contract


SCHEMA = "crabc.x86_64-owned-text-locale-numeric-provider-evidence/v1"
REQUIRED_PROVIDER_SYMBOLS = contract.PROVIDER_SYMBOLS
INSTALLED_HEADERS = (
    "ctype.h", "errno.h", "fenv.h", "float.h", "iconv.h", "inttypes.h", "langinfo.h", "locale.h",
    "monetary.h", "pthread.h", "stdarg.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h", "string.h",
    "strings.h", "sys/mman.h", "time.h", "uchar.h", "unistd.h", "wchar.h", "wctype.h", "features.h",
    "bits/alltypes.h",
)
HEADER_TRACE = re.compile(r"^\.+\s+(.+)$")
COMPILER_ENVIRONMENT = (
    "env", "-i", "LC_ALL=C", "PATH=/usr/bin:/bin", "SOURCE_DATE_EPOCH=1", "TZ=UTC",
)
NM = "/usr/bin/nm"
READELF = "/usr/bin/readelf"


class EvidenceError(ValueError):
    """A retained ELF/provider observation no longer matches the fixed rows."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _command(path: Path) -> list[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read retained command {path.name}") from error
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"retained command {path.name} is not a string argv")
    return value


def compiler_path(dynamic_product: Path) -> Path:
    """Recover the physical compiler chosen by the supplied installed driver."""

    helper = dynamic_product / "share/crabc/crabc_cc_static.py"
    try:
        require(helper.is_file() and not helper.is_symlink(), "dynamic compiler helper is not physical")
        spec = importlib.util.spec_from_file_location("owned_text_locale_numeric_component_compiler", helper)
        require(spec is not None and spec.loader is not None, "cannot load supplied compiler helper")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            compiler = Path(module.compiler()).resolve(strict=True)
        finally:
            sys.modules.pop(spec.name, None)
    except (OSError, AttributeError, ImportError, RuntimeError) as error:
        raise EvidenceError("cannot recover supplied fixed-image compiler") from error
    require(compiler.is_file() and not compiler.is_symlink(), "supplied fixed-image compiler is not physical")
    return compiler


def _recorded_path(root: Path, path: Path, source_mount: str | None) -> str:
    """Render a retained command path without confusing host replay with `/workspace`.

    The component runs in the pinned container where the checkout is mounted at
    ``/workspace``.  A later reader can run from a different checkout spelling,
    so physical replays use the real paths while argv validation uses this
    fixed mount spelling.
    """

    path = path.resolve(strict=False)
    if source_mount is not None:
        try:
            return str(Path(source_mount) / path.relative_to(root.resolve(strict=True)))
        except ValueError:
            pass
    return str(path)


def define_flags(define: str | tuple[str, ...] | None) -> tuple[str, ...]:
    """Normalize one role's literal preprocessor definitions.

    Ordinary parity roles have at most a renamed private ``main``.  The three
    candidate-only supplement roles add their existing source selector as a
    second literal definition, so preserve its order in retained argv.
    """

    if define is None:
        return ()
    if isinstance(define, str):
        return (define,)
    require(isinstance(define, tuple) and define and all(isinstance(item, str) and item for item in define),
            "role preprocessor definition is malformed")
    return define


def compile_argv(root: Path, work: Path, dynamic_product: Path,
                 role: str, relative: str, define: str | tuple[str, ...] | None,
                 *, source_mount: str | None = None) -> list[str]:
    """Exact installed-driver compilation for one role object."""

    contract.load_capability_roster(root)
    command = [
        _recorded_path(root, dynamic_product / "bin/crabc-cc-dynamic", source_mount),
        "--dynamic-pie", "-std=c11",
        "-D_GNU_SOURCE", "-fno-builtin", "-frounding-math", "-fno-stack-protector",
    ]
    command.extend(f"-D{item}" for item in define_flags(define))
    return [*command, "-c", _recorded_path(root, root / relative, source_mount), "-o",
            _recorded_path(root, work / f"{role}.o", source_mount)]


def header_argv(root: Path, dynamic_product: Path, compiler: Path,
                relative: str, define: str | tuple[str, ...] | None,
                *, source_mount: str | None = None) -> list[str]:
    """Directly replay the installed driver's header selection for one role."""

    flags = ["-std=c11", "-D_GNU_SOURCE", "-fno-builtin", "-frounding-math",
             "-fno-stack-protector"]
    flags.extend(f"-D{item}" for item in define_flags(define))
    return [
        *COMPILER_ENVIRONMENT, _recorded_path(root, compiler, source_mount), "-nostdinc", "-isystem",
        _recorded_path(root, dynamic_product / "usr/include", source_mount), "-ffreestanding", "-fno-builtin",
        "-fstack-protector-strong", *flags, "-fPIE", "-E", "-H",
        _recorded_path(root, root / relative, source_mount),
    ]


def trace_headers(text: str) -> tuple[Path, ...]:
    return tuple(Path(match.group(1)) for line in text.splitlines()
                 if (match := HEADER_TRACE.match(line)) is not None)


def validate_header_traces(root: Path, work: Path, dynamic_product: Path,
                           *, source_mount: str | None = None) -> None:
    """Reject ambient headers in every retained installed-header translation."""

    include = dynamic_product / "usr/include"
    observed: set[Path] = set()
    for role, _relative, _define, _group in contract.all_object_roles():
        try:
            paths = trace_headers((work / f"header-{role}.stderr").read_text(encoding="utf-8"))
        except OSError as error:
            raise EvidenceError(f"cannot read header trace for role {role}") from error
        require(paths, f"header trace has no installed headers for role {role}")
        for path in paths:
            physical = path
            if source_mount is not None:
                try:
                    physical = root.resolve(strict=True) / path.relative_to(Path(source_mount))
                except ValueError:
                    pass
            require(physical.is_absolute() and physical.is_relative_to(include),
                    f"header trace escapes installed product for role {role}: {path}")
            observed.add(physical)
    require({include / name for name in INSTALLED_HEADERS}.issubset(observed),
            "installed header traces omit a required public header")


def validate_invocations(root: Path, work: Path, dynamic_product: Path,
                         compiler: Path | None = None, *, source_mount: str | None = None) -> None:
    """Reconstruct role compile/header argv from the sealed installed product."""

    contract.load_capability_roster(root)
    compiler = compiler if compiler is not None else compiler_path(dynamic_product)
    for role, relative, define, _group in contract.all_object_roles():
        require(_command(work / f"compile-{role}.argv.json") ==
                compile_argv(root, work, dynamic_product, role, relative, define,
                             source_mount=source_mount),
                f"compile argv differs for role {role}")
        require(_command(work / f"header-{role}.argv.json") ==
                header_argv(root, dynamic_product, compiler, relative, define,
                            source_mount=source_mount),
                f"header argv differs for role {role}")
    validate_header_traces(root, work, dynamic_product, source_mount=source_mount)


def parse_posix_undefined(text: str, selected: set[str]) -> set[str]:
    """Return selected undefined normal-aggregate imports from physical nm text."""

    found: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if not fields or fields[0] not in selected:
            continue
        require(len(fields) >= 2 and fields[1] in {"U", "w", "v"},
                f"selected ET_REL import malformed at line {line_number}: {line}")
        found.add(fields[0])
    return found


def parse_dynamic_definitions(text: str, selected: set[str]) -> dict[str, dict[str, str]]:
    """Return selected dynamic providers from physical readelf output."""

    found: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        value, _size, kind, binding, visibility, section, name = fields[1:8]
        if name not in selected:
            continue
        require(binding in {"GLOBAL", "WEAK"} and section != "UND",
                f"selected dynamic provider undefined at line {line_number}: {line}")
        require(visibility in {"DEFAULT", "PROTECTED"},
                f"selected dynamic provider hidden at line {line_number}: {line}")
        require(name not in found, f"selected dynamic provider duplicated: {name}")
        found[name] = {"value": value, "type": kind, "binding": binding,
                       "visibility": visibility}
    return found


def parse_static_definitions(text: str, selected: set[str]) -> dict[str, list[str]]:
    """Return selected archive-member providers from physical nm output."""

    found: dict[str, list[str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) < 3 or fields[1] not in selected:
            continue
        require(fields[0].endswith(":"),
                f"static provider has no archive-member owner at line {line_number}: {line}")
        binding = fields[2]
        require(len(binding) == 1 and binding not in {"U", "w", "v"},
                f"static provider is undefined at line {line_number}: {line}")
        found.setdefault(fields[1], []).append(fields[0])
    return {name: sorted(owners) for name, owners in sorted(found.items())}


def validate(imports: str, dynamic_definitions: str, static_definitions: str) -> dict[str, object]:
    """Validate raw physical-symbol projections for the normal aggregate."""

    selected = set(REQUIRED_PROVIDER_SYMBOLS)
    imported = parse_posix_undefined(imports, selected)
    require(imported == selected,
            f"normal ET_REL imports differ; missing={sorted(selected - imported)}")
    dynamic = parse_dynamic_definitions(dynamic_definitions, selected)
    require(set(dynamic) == selected,
            f"dynamic providers differ; missing={sorted(selected - set(dynamic))}")
    static = parse_static_definitions(static_definitions, selected)
    require(set(static) == selected,
            f"static providers differ; missing={sorted(selected - set(static))}")
    return {
        "schema": SCHEMA,
        "selected_symbols": list(REQUIRED_PROVIDER_SYMBOLS),
        "et_rel_imports": sorted(imported),
        "dynamic_providers": dynamic,
        "static_provider_members": static,
    }


def binary_commands(root: Path, work: Path, static_product: Path, dynamic_product: Path,
                    *, source_mount: str | None = None) -> dict[str, list[str]]:
    """The three physical binary queries replayed by the public receipt."""

    return {
        "normal-imports": [NM, "--undefined-only", "--format=posix",
                           _recorded_path(root, work / "normal-workload.o", source_mount)],
        "dynamic-provider-symbols": [READELF, "--dyn-syms", "-W",
                                     _recorded_path(root, dynamic_product / "usr/lib/libc.so", source_mount)],
        "static-provider-symbols": [NM, "-A", "-g", "--defined-only", "--format=posix",
                                    _recorded_path(root, static_product / "usr/lib/libc.a", source_mount)],
    }


def replay_binary_queries(root: Path, work: Path, static_product: Path, dynamic_product: Path,
                          retained: dict[str, bytes]) -> dict[str, object]:
    """Rerun nm/readelf over sealed physical artifacts before accepting a receipt."""

    # The retained argv use `/workspace`; replay from the physical checkout.
    commands = binary_commands(root, work, static_product, dynamic_product)
    observed: dict[str, bytes] = {}
    for name, command in commands.items():
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False)
        except OSError as error:
            raise EvidenceError(f"cannot replay {name}") from error
        require(result.returncode == 0 and not result.stderr,
                f"physical {name} replay failed")
        require(retained.get(name) == result.stdout,
                f"retained {name} output differs from physical replay")
        observed[name] = result.stdout
    return validate(observed["normal-imports"].decode("utf-8"),
                    observed["dynamic-provider-symbols"].decode("utf-8"),
                    observed["static-provider-symbols"].decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--imports", type=Path, required=True)
    parser.add_argument("--dynamic-definitions", type=Path, required=True)
    parser.add_argument("--static-definitions", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        print(json.dumps(validate(arguments.imports.read_text(encoding="utf-8"),
                             arguments.dynamic_definitions.read_text(encoding="utf-8"),
                             arguments.static_definitions.read_text(encoding="utf-8")),
                         sort_keys=True, separators=(",", ":")))
    except (OSError, EvidenceError) as error:
        print(f"owned text/locale/numeric provider evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
