#!/usr/bin/env python3
"""Audit one selected native-mimalloc shadow artifact without promoting it.

This standalone primitive compares an explicitly supplied ordinary C-mimalloc
``libc.so`` snapshot with an explicitly supplied
``native-mimalloc-shadow`` ``libc.so``.  It requires the two reviewed Cargo
feature identities, rejects anything other than Linux/AArch64 little-endian
ELF, and binds the observed artifacts to direct branches from the named public
malloc-family entry points.

The check is intentionally narrower than allocator qualification.  A passing
report says only that the selected shadow's direct public routes did not branch
to ``mi_*`` while the compared ordinary artifact did.  It also records retained
C-backend ``mi_*`` API symbols as an artifact fact: their presence prevents
this primitive from claiming that C mimalloc is absent, while their absence
still does not prove source-level or transitive-call-graph purity.  The report
always refuses default selection, promotion, and full-runtime-purity
completion.

It is not wired into ``compat/allocator/run.py`` or any canonical gate.  A
later gate may call this file after supplying its own artifact provenance and
broader qualification evidence.

Cargo may replace one profile's ``lib-c.json`` when its feature set changes.
Callers therefore retain each explicit artifact and matching fingerprint in
separate target roots (or an equivalent reviewed snapshot); this script never
searches for or selects either input on its own.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc-native-mimalloc-shadow-native-purity-audit-v1"
SELECTED_BACKEND = "native-rust-mimalloc-shadow"
DEFAULT_BACKEND = "ordinary-c-mimalloc"
SELECTED_FEATURES = ["default", "native-mimalloc-shadow"]
DEFAULT_FEATURES = ["default"]
AARCH64_ELF_IDENTITY = {
    "class": "ELF64",
    "data": "little-endian",
    "os_abi": "UNIX - System V",
    "abi_version": "0",
    "type": "DYN",
    "machine": "AArch64",
}

# These are direct public C ABI routes, not a transitive native-runtime call
# graph.  Keeping the expected C and selected routes side by side makes the
# nondefault selection test observable without treating either artifact as a
# runtime selector or promotion result.
SELECTED_NATIVE_ROUTES = {
    "malloc": "native_allocate_aligned",
    "free": "native_free",
    "calloc": "native_allocate_aligned",
    "realloc": "native_reallocate",
    "aligned_alloc": "native_allocate_aligned",
    "posix_memalign": "native_allocate_aligned",
    "malloc_usable_size": "native_usable_size",
}
DEFAULT_C_ROUTES = {
    "malloc": "mi_malloc_aligned",
    "free": "mi_free",
    "calloc": "mi_zalloc",
    "realloc": "mi_realloc",
    "aligned_alloc": "mi_malloc_aligned",
    "posix_memalign": "mi_malloc_aligned",
    "malloc_usable_size": "mi_usable_size",
}
NATIVE_ROUTE_FRAGMENTS = tuple(sorted(set(SELECTED_NATIVE_ROUTES.values())))
MIMALLOC_BACKEND_API_SYMBOLS = tuple(sorted(set(DEFAULT_C_ROUTES.values())))


class NativePurityAuditError(RuntimeError):
    """An explicit artifact cannot support this narrowly bounded audit."""


def relative_path(path: Path) -> str:
    """Render paths inside this checkout relatively when possible."""

    resolved = path.expanduser().resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def sha256_file(path: Path) -> str:
    """Hash one checked artifact without loading it all into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    """Describe a required artifact by immutable bytes and location."""

    path = path.expanduser().resolve()
    if not path.is_file():
        raise NativePurityAuditError(f"required file is absent: {relative_path(path)}")
    return {
        "path": relative_path(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Write an explicitly requested report atomically; never choose a default."""

    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        staged = Path(stream.name)
    os.replace(staged, path)


def command_text(command: Sequence[str], subject: str) -> str:
    """Run one local ELF-inspection command with a checked diagnostic."""

    tool = shutil.which(command[0])
    if tool is None:
        raise NativePurityAuditError(f"{subject} requires unavailable tool {command[0]!r}")
    try:
        completed = subprocess.run(
            [tool, *command[1:]],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise NativePurityAuditError(f"{subject} could not run: {error}") from error
    if completed.returncode != 0:
        raise NativePurityAuditError(
            f"{subject} failed with status {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.stdout


def attested_aarch64_elf_identity(header: str, subject: str) -> dict[str, str]:
    """Reject a non-Linux/AArch64 artifact before inspecting its allocator code."""

    fields: dict[str, str] = {}
    for line in header.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        fields[key] = value.strip()
    identity = {
        "class": fields.get("Class", ""),
        "data": "little-endian" if "little endian" in fields.get("Data", "") else fields.get("Data", ""),
        "os_abi": fields.get("OS/ABI", ""),
        "abi_version": fields.get("ABI Version", ""),
        "type": fields.get("Type", "").split(maxsplit=1)[0],
        "machine": fields.get("Machine", ""),
    }
    if identity != AARCH64_ELF_IDENTITY:
        raise NativePurityAuditError(
            f"{subject} ELF identity differs from required AArch64 artifact: "
            f"expected {AARCH64_ELF_IDENTITY!r}, got {identity!r}"
        )
    return identity


def read_json_object(path: Path, subject: str) -> dict[str, Any]:
    """Read one Cargo fingerprint without accepting an arbitrary JSON shape."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise NativePurityAuditError(f"cannot read {subject}: {relative_path(path)}") from error
    if not isinstance(value, dict):
        raise NativePurityAuditError(f"{subject} must be a JSON object")
    return value


def cargo_fingerprint(path: Path, expected_features: list[str], subject: str) -> dict[str, Any]:
    """Require one exact crabc-libc Cargo feature identity.

    A Cargo fingerprint identifies the requested build configuration but does
    not by itself bind generated machine code to a particular ``libc.so``.
    ``inspect_artifact`` supplies that separate public-route observation.
    """

    path = path.expanduser().resolve()
    if (
        path.name != "lib-c.json"
        or not path.parent.name.startswith("crabc-libc-")
        or path.parent.parent.name != ".fingerprint"
    ):
        raise NativePurityAuditError(
            f"{subject} must name target/debug/.fingerprint/crabc-libc-*/lib-c.json"
        )
    value = read_json_object(path, f"{subject} Cargo fingerprint")
    encoded_features = value.get("features")
    if not isinstance(encoded_features, str):
        raise NativePurityAuditError(f"{subject} Cargo fingerprint omits encoded features")
    try:
        features = json.loads(encoded_features)
    except json.JSONDecodeError as error:
        raise NativePurityAuditError(
            f"{subject} Cargo fingerprint has malformed encoded features"
        ) from error
    if (
        not isinstance(features, list)
        or not all(isinstance(feature, str) and feature for feature in features)
        or len(features) != len(set(features))
    ):
        raise NativePurityAuditError(
            f"{subject} Cargo fingerprint features are not a unique string list"
        )
    if sorted(features) != sorted(expected_features):
        raise NativePurityAuditError(
            f"{subject} Cargo feature identity differs: expected {expected_features!r}, "
            f"got {features!r}"
        )
    return {
        "artifact": file_record(path),
        "features": features,
        "declared_features": value.get("declared_features"),
    }


def defined_dynamic_functions(symbols: str) -> dict[str, dict[str, str]]:
    """Extract default-visible, defined dynamic function symbols from readelf."""

    result: dict[str, dict[str, str]] = {}
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        symbol_type, binding, visibility, section = fields[3:7]
        name = fields[-1].split("@", 1)[0]
        if (
            symbol_type == "FUNC"
            and binding in {"GLOBAL", "WEAK"}
            and visibility == "DEFAULT"
            and section != "UND"
        ):
            result[name] = {
                "binding": binding,
                "visibility": visibility,
                "section": section,
            }
    return result


def embedded_mimalloc_api_symbols(symbols: str) -> list[str]:
    """Record retained ``mi_*`` API names without inferring their language.

    A retained API symbol is a material artifact/dependency fact relevant to a
    C-backend fallback investigation.  It cannot prove source provenance by
    itself, and an empty list cannot prove that C allocator code is absent.
    """

    known = set(MIMALLOC_BACKEND_API_SYMBOLS)
    return sorted(
        {
            fields[-1].split("@", 1)[0]
            for line in symbols.splitlines()
            if len(fields := line.split()) >= 8 and fields[-1].split("@", 1)[0] in known
        }
    )


_BRANCH_TARGET = re.compile(r"\b(?:b|bl)\s+[^<\n]*<([^>]+)>")


def direct_branch_targets(disassembly: str) -> list[str]:
    """Return named direct AArch64 branch destinations in one function body."""

    return sorted(set(_BRANCH_TARGET.findall(disassembly)))


def attest_public_allocator_routes(
    dynamic_symbols: str,
    disassemblies: Mapping[str, str],
    required_routes: Mapping[str, str],
    forbidden_fragments: Sequence[str],
    subject: str,
) -> list[dict[str, Any]]:
    """Bind public C allocator exports to direct expected backend calls only."""

    exported = defined_dynamic_functions(dynamic_symbols)
    routes: list[dict[str, Any]] = []
    for symbol, required_fragment in required_routes.items():
        metadata = exported.get(symbol)
        if metadata is None:
            raise NativePurityAuditError(
                f"{subject} does not define default-visible dynamic {symbol}"
            )
        disassembly = disassemblies.get(symbol)
        if not isinstance(disassembly, str):
            raise NativePurityAuditError(f"{subject} omitted disassembly for {symbol}")
        targets = direct_branch_targets(disassembly)
        for forbidden_fragment in forbidden_fragments:
            if any(forbidden_fragment in target for target in targets):
                raise NativePurityAuditError(
                    f"{subject} {symbol} branches to forbidden direct target "
                    f"containing {forbidden_fragment!r}"
                )
        if not any(required_fragment in target for target in targets):
            raise NativePurityAuditError(
                f"{subject} {symbol} does not branch directly to a target containing "
                f"{required_fragment!r}"
            )
        routes.append(
            {
                "symbol": symbol,
                "dynamic_symbol": metadata,
                "required_direct_target_fragment": required_fragment,
                "forbidden_direct_target_fragments": list(forbidden_fragments),
                "direct_branch_targets": targets,
            }
        )
    return routes


def inspect_artifact(
    libc: Path,
    backend: str,
    expected_routes: Mapping[str, str],
    forbidden_fragments: Sequence[str],
) -> dict[str, Any]:
    """Inspect one selected AArch64 libc artifact at its public ABI boundary."""

    libc = libc.expanduser().resolve()
    artifact = file_record(libc)
    header = command_text(("readelf", "-h", str(libc)), f"{backend} ELF header inspection")
    identity = attested_aarch64_elf_identity(header, f"{backend} artifact")
    dynamic_symbols = command_text(
        ("readelf", "-W", "--dyn-syms", str(libc)),
        f"{backend} dynamic symbol inspection",
    )
    disassemblies = {
        symbol: command_text(
            ("objdump", "-d", f"--disassemble={symbol}", str(libc)),
            f"{backend} {symbol} route inspection",
        )
        for symbol in expected_routes
    }
    routes = attest_public_allocator_routes(
        dynamic_symbols,
        disassemblies,
        expected_routes,
        forbidden_fragments,
        backend,
    )
    all_symbols = command_text(
        ("readelf", "-W", "--syms", str(libc)),
        f"{backend} complete symbol inspection",
    )
    return {
        "backend": backend,
        "artifact": artifact,
        "elf_identity": identity,
        "public_allocator_routes": routes,
        "embedded_mimalloc_api_symbols": embedded_mimalloc_api_symbols(all_symbols),
    }


def require_observation_binding(
    observation: Mapping[str, Any], expected_backend: str, artifact: Mapping[str, Any]
) -> None:
    """Prevent internal report composition from disconnecting evidence bytes."""

    if observation.get("backend") != expected_backend:
        raise NativePurityAuditError(
            f"artifact inspection selected {observation.get('backend')!r}, expected {expected_backend!r}"
        )
    if observation.get("artifact") != artifact:
        raise NativePurityAuditError("artifact inspection no longer binds the supplied libc bytes")


def mimalloc_artifact_fact(symbols: object) -> dict[str, Any]:
    """Describe the retained-symbol observation without turning it into promotion."""

    if not isinstance(symbols, list) or not all(isinstance(symbol, str) for symbol in symbols):
        raise NativePurityAuditError("embedded mimalloc API symbol observation changed shape")
    if any(symbol not in MIMALLOC_BACKEND_API_SYMBOLS for symbol in symbols):
        raise NativePurityAuditError("embedded mimalloc API symbol observation lost its boundary")
    return {
        "status": "observed" if symbols else "not_observed",
        "symbols": symbols,
        "interpretation": (
            "Observed mi_* names are an artifact/dependency fact relevant to C allocator "
            "fallback review; their presence prevents this audit from claiming C mimalloc "
            "is absent. Their absence would still not establish source-level or transitive "
            "allocator purity."
        ),
    }


def audit_selected_shadow(
    selected_libc: Path | str,
    selected_fingerprint_path: Path | str,
    default_libc: Path | str,
    default_fingerprint_path: Path | str,
) -> dict[str, Any]:
    """Compare the selected nondefault shadow with its ordinary C counterpart."""

    selected_libc = Path(selected_libc)
    selected_fingerprint_path = Path(selected_fingerprint_path)
    default_libc = Path(default_libc)
    default_fingerprint_path = Path(default_fingerprint_path)
    selected_artifact = file_record(selected_libc)
    default_artifact = file_record(default_libc)
    if selected_artifact["sha256"] == default_artifact["sha256"]:
        raise NativePurityAuditError(
            "selected native shadow and ordinary C backend artifacts must differ"
        )
    selected_fingerprint = cargo_fingerprint(
        selected_fingerprint_path, SELECTED_FEATURES, "selected native shadow"
    )
    default_fingerprint = cargo_fingerprint(
        default_fingerprint_path, DEFAULT_FEATURES, "ordinary C backend"
    )
    selected = inspect_artifact(
        selected_libc,
        SELECTED_BACKEND,
        SELECTED_NATIVE_ROUTES,
        ("mi_",),
    )
    default = inspect_artifact(
        default_libc,
        DEFAULT_BACKEND,
        DEFAULT_C_ROUTES,
        NATIVE_ROUTE_FRAGMENTS,
    )
    require_observation_binding(selected, SELECTED_BACKEND, selected_artifact)
    require_observation_binding(default, DEFAULT_BACKEND, default_artifact)
    selected_symbols = selected["embedded_mimalloc_api_symbols"]
    artifact_fact = mimalloc_artifact_fact(selected_symbols)
    return {
        "format": 1,
        "schema": SCHEMA,
        "status": "passed",
        "scope": {
            "evidence_scope": "shadow_subset",
            "standalone_not_integrated": True,
            "selected_nondefault_shadow": True,
            "selected_shadow_is_default": False,
            "default_backend_complete": False,
            "promotion_complete": False,
            "full_runtime_pure_rust": False,
            "does_not_claim": [
                "default backend selection",
                "default completion",
                "promotion qualification",
                "full transitive allocator call graph purity",
                "C mimalloc absence from default production artifacts",
            ],
        },
        "selected": {
            "backend": SELECTED_BACKEND,
            "artifact": selected_artifact,
            "cargo_fingerprint": selected_fingerprint["artifact"],
            "cargo_features": selected_fingerprint["features"],
            "elf_identity": selected["elf_identity"],
            "public_allocator_routes": selected["public_allocator_routes"],
            "embedded_mimalloc_api_symbols": selected_symbols,
            "embedded_mimalloc_artifact_fact": artifact_fact,
        },
        "default": {
            "backend": DEFAULT_BACKEND,
            "artifact": default_artifact,
            "cargo_fingerprint": default_fingerprint["artifact"],
            "cargo_features": default_fingerprint["features"],
            "elf_identity": default["elf_identity"],
            "public_allocator_routes": default["public_allocator_routes"],
        },
        "no_c_allocator_fallback": {
            "status": "passed_at_direct_public_allocator_routes",
            "inspection": (
                "Direct named AArch64 branches from the listed public malloc-family exports "
                "were compared; selected routes reject mi_* targets and ordinary routes "
                "reject selected native target fragments."
            ),
            "selected_forbidden_direct_target_prefix": "mi_",
            "does_not_establish": [
                "transitive native-runtime call graph purity",
                "C mimalloc absence from the selected artifact",
                "C mimalloc absence from default production artifacts",
                "promotion or default backend completion",
            ],
        },
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse only explicit input paths; this primitive selects no artifacts itself."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selected-libc",
        required=True,
        type=Path,
        help="AArch64 libc.so built with default,native-mimalloc-shadow",
    )
    parser.add_argument(
        "--selected-fingerprint",
        required=True,
        type=Path,
        help="matching target/debug/.fingerprint/crabc-libc-*/lib-c.json",
    )
    parser.add_argument(
        "--default-libc",
        required=True,
        type=Path,
        help="snapshotted AArch64 ordinary C-mimalloc libc.so",
    )
    parser.add_argument(
        "--default-fingerprint",
        required=True,
        type=Path,
        help="matching ordinary target/debug/.fingerprint/crabc-libc-*/lib-c.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional explicitly selected JSON destination; stdout remains the default",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the standalone audit and return a conventional checked failure status."""

    args = parse_args(argv)
    try:
        report = audit_selected_shadow(
            args.selected_libc,
            args.selected_fingerprint,
            args.default_libc,
            args.default_fingerprint,
        )
    except NativePurityAuditError as error:
        print(f"native purity audit: {error}", file=sys.stderr)
        return 2
    if args.output is not None:
        write_json(args.output, report)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
