#!/usr/bin/env python3
"""Fail closed on an unavailable no-Clang GCC declaration backend.

The x86 header callable inventory requires compiler-derived function records
and compiler preprocessor records. This probe tests every existing GCC route
in the pinned x86 evidence image without changing that image: built-in dumps,
the installed `libcc1plugin`, and a custom plugin compile against the headers
that GCC advertises. It records why none is currently a sound replacement for
the canonical Clang JSON-AST frontend.

The probe is evidence only. It does not read project or musl headers, modify
the canonical inventory, or make any promotion claim.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SOURCE = ROOT / "compat" / "x86_64" / "header_callable_gcc_plugin_compile_probe.cc"
SCHEMA = "crabc.x86_64-gcc-callable-backend-availability/v1"
SYNTHETIC_SOURCE = """\
extern int archive_owner(int value);
static inline int header_local(int value) { return value + 1; }
#define CALLBACK(value) (value)
"""


class ProbeError(ValueError):
    """The no-dependency GCC probe could not establish a precise result."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def command_result(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def first_diagnostic(result: subprocess.CompletedProcess[str]) -> str:
    lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
    return next((line for line in lines if "fatal error:" in line or "error:" in line), lines[0] if lines else "compiler produced no diagnostic")


def require_native_x86_64() -> None:
    require(platform.system() == "Linux", f"requires native Linux, found {platform.system()}")
    require(platform.machine() in {"x86_64", "amd64"}, f"requires native x86-64, found {platform.machine()}")


def require_tool(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"requires {name}")
    return path


def command_output(command: Sequence[str]) -> str:
    result = command_result(command)
    require(result.returncode == 0, f"{' '.join(command)} failed: {first_diagnostic(result)}")
    return result.stdout.strip()


def compiler_version(compiler: str) -> str:
    version = command_output([compiler, "-dumpfullversion", "-dumpversion"])
    require(version and all(part.isdigit() for part in version.split(".")), f"{compiler} has an unusable version: {version!r}")
    return version


def gcc_plugin_root(gcc: str) -> Path:
    root = Path(command_output([gcc, "-print-file-name=plugin"]))
    require(root.is_dir() and not root.is_symlink(), f"GCC plugin root is missing or unsafe: {root}")
    return root


def compile_plugin_probe(gxx: str, include: Path, destination: Path) -> dict[str, Any]:
    result = command_result(
        [
            gxx,
            "-std=gnu++17",
            "-fPIC",
            "-fno-exceptions",
            "-fno-rtti",
            "-shared",
            "-I",
            str(include),
            str(PLUGIN_SOURCE),
            "-o",
            str(destination),
        ]
    )
    diagnostic = first_diagnostic(result)
    if result.returncode == 0:
        return {
            "detail": "the GCC plugin probe compiled; a separate reviewed backend implementation would still be required",
            "missing_gmp_header": False,
            "status": "compiled-not-a-canonical-backend",
        }
    return {
        "detail": diagnostic,
        "missing_gmp_header": "gmp.h" in result.stderr,
        "status": "compile-failed",
    }


def dump_name_presence(gcc: str, work_dir: Path) -> dict[str, Any]:
    source = work_dir / "callables.c"
    source.write_text(SYNTHETIC_SOURCE, encoding="utf-8")

    unsupported: dict[str, dict[str, Any]] = {}
    for option in ("-fdump-lang-raw", "-fdump-translation-unit"):
        result = command_result([gcc, "-x", "c", "-fsyntax-only", option, str(source)])
        unsupported[option] = {
            "detail": first_diagnostic(result),
            "rejected": result.returncode != 0,
        }

    tree_object = work_dir / "tree.o"
    tree_result = command_result(
        [gcc, "-c", "-O0", "-dumpdir", str(work_dir) + "/", "-fdump-tree-original-raw", str(source), "-o", str(tree_object)]
    )
    require(tree_result.returncode == 0, f"GCC tree dump failed: {first_diagnostic(tree_result)}")
    tree_dumps = sorted(work_dir.glob("*.original"))
    require(len(tree_dumps) == 1, "GCC tree dump did not produce one deterministic original dump")
    tree_text = tree_dumps[0].read_text(encoding="utf-8")

    go_dump = work_dir / "callables.go.spec"
    go_object = work_dir / "go.o"
    go_result = command_result([gcc, "-c", "-O0", f"-fdump-go-spec={go_dump}", str(source), "-o", str(go_object)])
    require(go_result.returncode == 0 and go_dump.is_file(), f"GCC Go-spec dump failed: {first_diagnostic(go_result)}")
    go_text = go_dump.read_text(encoding="utf-8")

    json_diagnostics = command_result([gcc, "-x", "c", "-fsyntax-only", "-fdiagnostics-format=json", str(source)])
    require(json_diagnostics.returncode == 0, f"GCC JSON diagnostics failed: {first_diagnostic(json_diagnostics)}")
    try:
        diagnostics_value = json.loads(json_diagnostics.stderr or json_diagnostics.stdout)
    except json.JSONDecodeError as error:
        raise ProbeError(f"GCC JSON diagnostics were not JSON: {error}") from error

    preprocessor = command_result([gcc, "-x", "c", "-E", "-dD", str(source)])
    require(preprocessor.returncode == 0, f"GCC preprocessor records failed: {first_diagnostic(preprocessor)}")
    return {
        "json_diagnostics": {
            "declaration_records": False,
            "value_kind": type(diagnostics_value).__name__,
        },
        "preprocessor_records": {
            "contains_callback_macro": "#define CALLBACK(value) (value)" in preprocessor.stdout,
            "function_declarations": False,
        },
        "tree_original_raw": {
            "contains_archive_owner": "archive_owner" in tree_text,
            "contains_header_local": "header_local" in tree_text,
            "status": "insufficient-partial-definition-dump",
        },
        "go_spec": {
            "contains_archive_owner": "archive_owner" in go_text,
            "contains_header_local": "header_local" in go_text,
            "status": "insufficient-external-declaration-dump",
        },
        "unsupported_ast_options": unsupported,
    }


def installed_cc1_plugin(gcc: str, plugin_root: Path, source: Path) -> dict[str, Any]:
    candidate = plugin_root / "libcc1plugin.so.0.0.0"
    if not candidate.is_file():
        return {"status": "not-installed"}
    result = command_result([gcc, "-x", "c", "-fsyntax-only", f"-fplugin={candidate}", str(source)])
    return {
        "detail": first_diagnostic(result),
        "status": "does-not-provide-standalone-declaration-records" if result.returncode != 0 else "loaded-without-inventory-protocol",
    }


def build_report(gcc: str = "gcc", gxx: str = "g++") -> dict[str, Any]:
    require_native_x86_64()
    gcc_path = require_tool(gcc)
    gxx_path = require_tool(gxx)
    require(PLUGIN_SOURCE.is_file() and not PLUGIN_SOURCE.is_symlink(), "GCC plugin compile-probe source is missing or unsafe")
    gcc_version = compiler_version(gcc_path)
    require(compiler_version(gxx_path) == gcc_version, "gcc and g++ versions differ")
    plugin_root = gcc_plugin_root(gcc_path)
    plugin_include = plugin_root / "include"
    for header in ("gcc-plugin.h", "plugin-version.h", "tree.h"):
        require((plugin_include / header).is_file(), f"GCC plugin header is missing: {plugin_include / header}")

    with tempfile.TemporaryDirectory(prefix="crabc-x86-gcc-callable-availability.") as temporary:
        work_dir = Path(temporary)
        source = work_dir / "callables.c"
        source.write_text(SYNTHETIC_SOURCE, encoding="utf-8")
        plugin_compile = compile_plugin_probe(gxx_path, plugin_include, work_dir / "declaration-probe.so")
        dump_evidence = dump_name_presence(gcc_path, work_dir)
        cc1_plugin = installed_cc1_plugin(gcc_path, plugin_root, source)

    blocked = plugin_compile["status"] == "compile-failed" and plugin_compile["missing_gmp_header"]
    require(dump_evidence["tree_original_raw"] == {
        "contains_archive_owner": False,
        "contains_header_local": True,
        "status": "insufficient-partial-definition-dump",
    }, "GCC tree dump behavior changed; reassess no-Clang fallback evidence")
    require(dump_evidence["go_spec"] == {
        "contains_archive_owner": True,
        "contains_header_local": False,
        "status": "insufficient-external-declaration-dump",
    }, "GCC Go-spec dump behavior changed; reassess no-Clang fallback evidence")
    require(all(value["rejected"] for value in dump_evidence["unsupported_ast_options"].values()), "GCC unexpectedly accepted a raw AST dump option")
    require(dump_evidence["preprocessor_records"]["contains_callback_macro"], "GCC preprocessor stopped emitting macro records")

    return {
        "schema": SCHEMA,
        "scope": {
            "canonical_inventory_changed": False,
            "family_promotion": False,
            "header_text_parsing": False,
            "public_support": False,
        },
        "toolchain": {
            "gcc": gcc_path,
            "gcc_plugin_include": str(plugin_include),
            "gcc_version": gcc_version,
            "gmp_header_installed": Path("/usr/include/gmp.h").is_file(),
            "gxx": gxx_path,
        },
        "custom_plugin_compile": plugin_compile,
        "existing_compiler_routes": {**dump_evidence, "libcc1plugin": cc1_plugin},
        "summary": {
            "exact_user_approval_boundary": "Add gmp-dev to docker/Dockerfile.x86_64 only after approving a pinned GCC-plugin inventory backend contract.",
            "no_docker_dependency_backend_available": False,
            "status": "blocked-missing-gmp-dev" if blocked else "changed-requires-reassessment",
        },
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gcc", default="gcc")
    parser.add_argument("--gxx", default="g++")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-no-docker-blocker",
        action="store_true",
        help="fail unless the current toolchain remains blocked without a Docker dependency",
    )
    parsed = parser.parse_args(arguments)
    report = build_report(parsed.gcc, parsed.gxx)
    rendered = canonical_json(report)
    if parsed.output is None:
        sys.stdout.write(rendered)
    else:
        require(not parsed.output.is_symlink(), f"output path is a symlink: {parsed.output}")
        parsed.output.write_text(rendered, encoding="utf-8")
    if parsed.require_no_docker_blocker:
        require(report["summary"]["status"] == "blocked-missing-gmp-dev", "GCC availability changed; do not infer a canonical inventory backend")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        raise SystemExit(f"x86 GCC callable backend availability: ERROR: {error}") from error
