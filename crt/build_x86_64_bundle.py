#!/usr/bin/env python3
"""Stage and prove the private Linux/x86-64 Rust CRT object bundle.

This is deliberately a *bundle provenance* proof, not an x86 sysroot builder.
It invokes ``build_x86_64.py`` twice into independently created directories,
requires byte-identical output, and stages exactly the five CRT objects plus a
machine-readable manifest.  The staged tree has no headers, libraries,
compiler helpers, linker, compiler runtime, or driver; a future owned x86
sysroot must establish those contracts separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CRT_ROOT = ROOT / "crt"
BUILDER = CRT_ROOT / "build_x86_64.py"
TARGET = "x86_64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"
OBJECT_NAMES = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
DEFAULT_OUTPUT = ROOT / "target" / "crt-x86_64-object-bundle"
MANIFEST_NAME = "manifest.json"


class BundleError(RuntimeError):
    """A sealed CRT bundle or provenance invariant was violated."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--llvm-objdump", default="llvm-objdump")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def normalized_output(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT / "target")
    except ValueError as error:
        raise BundleError("--out-dir must remain below target/ for this private evidence") from error
    if resolved == ROOT / "target":
        raise BundleError("--out-dir must name a dedicated directory below target/")
    return resolved


def remove_previous_bundle(path: Path) -> None:
    if not path.exists():
        return
    manifest = path / MANIFEST_NAME
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"refusing to replace unrecognized bundle output: {path}") from error
    if record.get("format") != "crabc-x86-64-crt-object-bundle-v1":
        raise BundleError(f"refusing to replace unrecognized bundle output: {path}")
    shutil.rmtree(path)


def run_build(out_dir: Path, llvm_objdump: str) -> dict[str, Any]:
    command = [sys.executable, str(BUILDER), "--out-dir", str(out_dir), "--llvm-objdump", llvm_objdump]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise BundleError(
            "x86 CRT object build failed: " + result.stderr.decode("utf-8", errors="replace").strip()
        )
    try:
        report = json.loads((out_dir / "objects.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError("x86 CRT builder did not emit a readable objects.json") from error
    if report.get("target") != TARGET or report.get("toolchain") != PINNED_TOOLCHAIN:
        raise BundleError("x86 CRT builder report has an unexpected target or toolchain")
    return report


def require_producer_closure(report: dict[str, Any]) -> None:
    objects = report.get("objects")
    if not isinstance(objects, dict) or tuple(sorted(objects)) != tuple(sorted(OBJECT_NAMES)):
        raise BundleError("x86 CRT builder report must contain exactly the five selected objects")
    forbidden_exact = {"-L", "--extern", "-l"}
    forbidden_substrings = ("link-arg", "compiler-rt", "crtbegin", "crtend", "libgcc")
    for name in OBJECT_NAMES:
        record = objects[name]
        if not isinstance(record, dict):
            raise BundleError(f"x86 CRT object record is malformed: {name}")
        producer = record.get("producer")
        if not isinstance(producer, list) or not all(isinstance(item, str) for item in producer):
            raise BundleError(f"x86 CRT object lacks a machine-readable producer: {name}")
        if "--emit=obj" not in producer or "--target" not in producer or TARGET not in producer:
            raise BundleError(f"x86 CRT object is not a direct target object build: {name}")
        if any(argument in forbidden_exact for argument in producer) or any(
            marker in argument for marker in forbidden_substrings for argument in producer
        ):
            raise BundleError(f"x86 CRT object producer admits ambient CRT/compiler-runtime input: {name}")
        if record.get("source_languages") != ["Rust"]:
            raise BundleError(f"x86 CRT object is not recorded as Rust-produced: {name}")
        if not str(record.get("source", "")).startswith("/crabc/crt/src/x86_64_"):
            raise BundleError(f"x86 CRT object source is outside the owned x86 CRT set: {name}")
        if not isinstance(record.get("sha256"), str) or len(record["sha256"]) != 64:
            raise BundleError(f"x86 CRT object hash is missing: {name}")


def compare_clean_builds(primary: Path, comparison: Path, primary_report: dict[str, Any], comparison_report: dict[str, Any]) -> None:
    require_producer_closure(primary_report)
    require_producer_closure(comparison_report)
    for name in OBJECT_NAMES:
        first, second = primary / name, comparison / name
        if not first.is_file() or not second.is_file():
            raise BundleError(f"clean CRT build did not produce {name}")
        if first.read_bytes() != second.read_bytes():
            raise BundleError(f"two clean x86 CRT builds diverged for {name}")
        if primary_report["objects"][name] != comparison_report["objects"][name]:
            raise BundleError(f"two clean x86 CRT build contracts diverged for {name}")


def stage_bundle(primary: Path, report: dict[str, Any], output: Path) -> dict[str, Any]:
    remove_previous_bundle(output)
    objects_dir = output / "objects"
    objects_dir.mkdir(parents=True)
    staged: dict[str, dict[str, Any]] = {}
    for name in OBJECT_NAMES:
        source, destination = primary / name, objects_dir / name
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o644)
        source_record = report["objects"][name]
        actual_hash = sha256_file(destination)
        if actual_hash != source_record["sha256"]:
            raise BundleError(f"staged object hash differs from clean build: {name}")
        staged[name] = {
            "path": f"objects/{name}",
            "sha256": actual_hash,
            "producer": source_record["producer"],
            "source": source_record["source"],
            "source_languages": source_record["source_languages"],
            "elf_contract": {
                key: source_record[key]
                for key in ("entry_contract", "owned_lifecycle_note", "sections", "defined_symbols", "undefined_symbols", "relocation_types")
            },
            **({"entry_machine_contract": source_record["entry_machine_contract"]} if "entry_machine_contract" in source_record else {}),
        }
    manifest = {
        "format": "crabc-x86-64-crt-object-bundle-v1",
        "schema": 1,
        "target": TARGET,
        "toolchain": PINNED_TOOLCHAIN,
        "scope": "private-five-object-crt-provenance-not-sysroot-not-public-support",
        "objects": staged,
        "proof": {
            "two_clean_builds_byte_identical": True,
            "objects_directory_contains_exactly": list(OBJECT_NAMES),
            "only_rust_produced_objects": True,
            "direct_object_producers_only": True,
            "no_ambient_crt_or_compiler_runtime_input": True,
            "no_headers_libraries_loader_driver_or_sysroot_staged": True,
            "elf_contracts_verified_by": "crt/build_x86_64.py",
        },
    }
    write_json(output / MANIFEST_NAME, manifest)
    actual_paths = sorted(item.relative_to(output).as_posix() for item in output.rglob("*") if item.is_file())
    expected_paths = sorted([MANIFEST_NAME, *(f"objects/{name}" for name in OBJECT_NAMES)])
    if actual_paths != expected_paths:
        raise BundleError("staged x86 CRT bundle contains an unexpected file")
    return manifest


def build_bundle(args: argparse.Namespace) -> dict[str, Any]:
    output = normalized_output(args.out_dir)
    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="crt-x86-64-bundle-primary.", dir=target) as first_temp, tempfile.TemporaryDirectory(
        prefix="crt-x86-64-bundle-comparison.", dir=target
    ) as second_temp:
        primary, comparison = Path(first_temp), Path(second_temp)
        primary_report = run_build(primary, args.llvm_objdump)
        comparison_report = run_build(comparison, args.llvm_objdump)
        compare_clean_builds(primary, comparison, primary_report, comparison_report)
        return stage_bundle(primary, primary_report, output)


def main() -> int:
    try:
        manifest = build_bundle(parse_args())
    except BundleError as error:
        print(f"crabc x86-64 CRT object bundle failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
