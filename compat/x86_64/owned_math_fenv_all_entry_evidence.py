#!/usr/bin/env python3
"""Validate installed-provider and ET_REL evidence for the math/fenv slice.

The selected names come from the checked capability ledger, while this reader
works only from retained binary-tool output.  It deliberately does not infer
ownership from a source-text pattern: the installed shared/static providers,
the combined object imports, and ordinary product link receipts are distinct
parts of the boundary.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

import owned_math_fenv_all_entry_contract as contract

SCHEMA = "crabc.x86_64-owned-math-fenv-all-entry-provider-evidence/v1"
ALIAS_GROUPS = (
    ("exp10", "pow10"),
    ("exp10f", "pow10f"),
    ("exp10l", "pow10l"),
)
INSTALLED_HEADERS = (
    "complex.h", "fenv.h", "float.h", "math.h", "stddef.h", "stdint.h", "unistd.h",
    "features.h", "bits/alltypes.h",
)
HEADER_TRACE = re.compile(r"^\.+\s+(.+)$")
COMPILER_ENVIRONMENT = (
    "env", "-i", "LC_ALL=C", "PATH=/usr/bin:/bin", "SOURCE_DATE_EPOCH=1", "TZ=UTC",
)


class EvidenceError(ValueError):
    """Retained binary evidence does not prove the selected provider route."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def selected_symbols(root: Path) -> tuple[str, ...]:
    return tuple(symbol for symbols in contract.load_roster(root).values() for symbol in symbols)


def parse_posix_undefined(text: str, selected: set[str]) -> set[str]:
    """Read selected undefined names from ``nm --format=posix`` ET_REL output."""

    found: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if not fields or fields[0] not in selected:
            continue
        require(len(fields) >= 2 and fields[1] in {"U", "w", "v"},
                f"selected ET_REL import is malformed at line {line_number}: {line}")
        found.add(fields[0])
    return found


def parse_dynamic_definitions(text: str, selected: set[str]) -> dict[str, dict[str, str]]:
    """Read selected global/weak definitions from ``readelf --dyn-syms -W``."""

    found: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        value, _size, kind, binding, visibility, section, name = fields[1:8]
        if name not in selected:
            continue
        require(binding in {"GLOBAL", "WEAK"} and section != "UND",
                f"selected dynamic provider is not defined at line {line_number}: {line}")
        require(visibility in {"DEFAULT", "PROTECTED"},
                f"selected dynamic provider is not externally visible at line {line_number}: {line}")
        require(name not in found,
                f"selected dynamic provider is duplicated at line {line_number}: {name}")
        found[name] = {
            "value": value,
            "type": kind,
            "binding": binding,
            "visibility": visibility,
        }
    return found


def parse_static_definitions(text: str, selected: set[str]) -> dict[str, list[str]]:
    """Read selected defined global/weak names from ``nm -A -g --format=posix``."""

    found: dict[str, list[str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) < 3 or fields[1] not in selected:
            continue
        require(fields[0].endswith(":"),
                f"selected static provider has no archive-member owner at line {line_number}: {line}")
        binding = fields[2]
        require(len(binding) == 1 and binding not in {"U", "w", "v"},
                f"selected static provider is not defined at line {line_number}: {line}")
        found.setdefault(fields[1], []).append(fields[0])
    return {name: sorted(owners) for name, owners in sorted(found.items())}


def _command(path: Path) -> list[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read retained command {path.name}") from error
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"retained command {path.name} is not a string argv")
    return value


def compiler_path(dynamic_product: Path) -> Path:
    """Recover the fixed-image compiler selected by the sealed helper."""

    helper = dynamic_product / "share/crabc/crabc_cc_static.py"
    try:
        if helper.is_symlink() or not helper.is_file():
            raise EvidenceError("supplied compiler helper is not a physical file")
        spec = importlib.util.spec_from_file_location(
            "owned_math_fenv_all_entry_provider_compiler", helper
        )
        if spec is None or spec.loader is None:
            raise EvidenceError("cannot load supplied compiler helper")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            compiler = Path(module.compiler()).resolve(strict=True)
        finally:
            sys.modules.pop(spec.name, None)
    except (OSError, AttributeError, ImportError, RuntimeError) as error:
        raise EvidenceError("cannot recover supplied fixed-image compiler") from error
    if compiler.is_symlink() or not compiler.is_file():
        raise EvidenceError("supplied fixed-image compiler is not physical")
    return compiler


def compile_argv(root: Path, work: Path, dynamic_product: Path,
                 role: str, relative: str, define: str | None) -> list[str]:
    """Return the installed driver's exact compile-only role invocation."""

    # Loading first makes the capability ledger and its complex expansion a
    # required, current input even though these argv select only their probes.
    selected_symbols(root)
    common = [
        str(dynamic_product / "bin/crabc-cc-dynamic"), "--dynamic-pie",
        "-std=c11", "-D_GNU_SOURCE", "-fno-builtin", "-frounding-math",
        "-fno-stack-protector",
    ]
    prefix = [*common, *([f"-D{define}"] if define is not None else [])]
    source = str(root / relative)
    return [*prefix, "-c", source, "-o", str(work / f"{role}.o")]


def header_argv(root: Path, dynamic_product: Path, compiler: Path,
                relative: str, define: str | None) -> list[str]:
    """Return the direct preprocessor replay of the driver's translation.

    The sealed application driver intentionally refuses ``-E``.  This replay
    therefore invokes the same fixed-image compiler which that driver selects,
    with the driver's clean environment, installed include root, fixed flags,
    admitted flags, and dynamic-PIE mode in their translation order.
    """

    flags = ["-std=c11", "-D_GNU_SOURCE", "-fno-builtin", "-fno-stack-protector"]
    if define is not None:
        flags.append(f"-D{define}")
    return [
        *COMPILER_ENVIRONMENT, str(compiler),
        "-nostdinc", "-isystem", str(dynamic_product / "usr/include"),
        "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
        *flags, "-frounding-math", "-fPIE", "-E", "-H", str(root / relative),
    ]


def trace_headers(text: str) -> tuple[Path, ...]:
    return tuple(Path(match.group(1)) for line in text.splitlines()
                 if (match := HEADER_TRACE.match(line)) is not None)


def validate_header_traces(work: Path, dynamic_product: Path) -> None:
    """Require every retained header trace to name installed headers only."""

    include = dynamic_product / "usr/include"
    observed: set[Path] = set()
    for role, _relative, _define in contract.OBJECT_ROLES:
        try:
            paths = trace_headers((work / f"header-{role}.stderr").read_text(encoding="utf-8"))
        except OSError as error:
            raise EvidenceError(f"cannot read header trace for role {role}") from error
        require(paths, f"header trace has no installed headers for role {role}")
        for path in paths:
            require(path.is_absolute() and path.is_relative_to(include),
                    f"header trace escapes installed dynamic headers for role {role}: {path}")
            observed.add(path)
    require({include / name for name in INSTALLED_HEADERS}.issubset(observed),
            "installed header trace omits a required public header")


def validate_invocations(root: Path, work: Path, dynamic_product: Path,
                         compiler: Path | None = None) -> None:
    """Replay the retained compile and installed-header translation boundary."""

    selected_symbols(root)
    compiler = compiler if compiler is not None else compiler_path(dynamic_product)
    for role, relative, define in contract.OBJECT_ROLES:
        compile_expected = compile_argv(root, work, dynamic_product, role, relative, define)
        header_expected = header_argv(root, dynamic_product, compiler, relative, define)
        require(_command(work / f"compile-{role}.argv.json") == compile_expected,
                f"compile argv differs for role {role}")
        require(_command(work / f"header-{role}.argv.json") == header_expected,
                f"header argv differs for role {role}")
    validate_header_traces(work, dynamic_product)


def validate(
    root: Path,
    imports: str,
    dynamic_definitions: str,
    static_definitions: str | None = None,
    work: Path | None = None,
    dynamic_product: Path | None = None,
) -> dict[str, object]:
    """Return the exact selected binary ownership projection or raise."""

    symbols = selected_symbols(root)
    if work is not None or dynamic_product is not None:
        require(work is not None and dynamic_product is not None,
                "retained invocation audit requires both work and dynamic product")
        validate_invocations(root, work, dynamic_product)
    expected = set(symbols)
    imported = parse_posix_undefined(imports, expected)
    require(imported == expected,
            f"combined ET_REL imports differ; missing={sorted(expected - imported)} "
            f"unexpected-selected={sorted(imported - expected)}")

    dynamic = parse_dynamic_definitions(dynamic_definitions, expected)
    require(set(dynamic) == expected,
            f"installed dynamic providers differ; missing={sorted(expected - set(dynamic))}")
    aliases = {}
    for group in ALIAS_GROUPS:
        values = {dynamic[name]["value"] for name in group}
        require(len(values) == 1, f"dynamic alias address differs: {'/'.join(group)}")
        aliases["/".join(group)] = next(iter(values))

    record: dict[str, object] = {
        "schema": SCHEMA,
        "selected_symbols": list(symbols),
        "et_rel_imports": sorted(imported),
        "dynamic_providers": dynamic,
        "dynamic_alias_addresses": aliases,
    }
    if static_definitions is not None:
        static = parse_static_definitions(static_definitions, expected)
        require(set(static) == expected,
                f"installed static providers differ; missing={sorted(expected - set(static))}")
        record["static_provider_members"] = static
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--imports", type=Path, required=True)
    parser.add_argument("--dynamic-definitions", type=Path, required=True)
    parser.add_argument("--static-definitions", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--dynamic-product", type=Path)
    arguments = parser.parse_args()
    try:
        record = validate(
            arguments.root,
            arguments.imports.read_text(encoding="utf-8"),
            arguments.dynamic_definitions.read_text(encoding="utf-8"),
            (arguments.static_definitions.read_text(encoding="utf-8")
             if arguments.static_definitions is not None else None),
            arguments.work,
            arguments.dynamic_product,
        )
    except (OSError, EvidenceError, contract.ContractError) as error:
        print(f"owned math/fenv provider evidence: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
