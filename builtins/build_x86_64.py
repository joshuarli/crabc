#!/usr/bin/env python3
"""Build a bounded Rust-only x86-64 helper archive for static consumers.

This is intentionally separate from ``build.py``'s complete installed
Linux/AArch64 sysroot archive. It makes the existing audited Rust integer and
complex helper object available to bounded native x86 static-PIE and installed
static-consumer proofs. It is not a complete x86 compiler runtime.
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


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "src" / "lib.rs"
TOOLCHAIN = "nightly-2026-07-24"
TARGET = "x86_64-unknown-linux-musl"
ARCHIVE_NAME = "libcrabc-builtins.a"
MEMBER_NAME = "crabc-builtins.o"
REQUIRED_SYMBOLS = frozenset({"__udivti3", "__umodti3", "__multi3", "__muldc3"})
FORBIDDEN_SYMBOL_PARTS = ("memcpy", "memmove", "memset", "__gcc_", "__gxx_", "__cxa_", "__atomic_")
FORBIDDEN_SECTIONS = (".eh_frame", ".gcc_except_table")


class BuildError(RuntimeError):
    """A bounded x86 helper-archive contract was violated."""


def run(command: list[str], *, cwd: Path = ROOT) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise BuildError(f"required tool is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        raise BuildError(
            f"command failed: {' '.join(command)}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return completed.stdout


def tool(name: str) -> str:
    value = shutil.which(name)
    if value is not None:
        return value
    rustup = shutil.which("rustup")
    if rustup is not None:
        completed = subprocess.run(
            [rustup, "run", TOOLCHAIN, "rustc", "--print", "sysroot"],
            check=False,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode == 0:
            sysroot = Path(completed.stdout.strip())
            for candidate in (
                sysroot / "lib" / "rustlib" / TARGET / "bin" / name,
                sysroot / "lib" / "rustlib" / TARGET / "bin" / "gcc-ld" / name,
            ):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
    if name == "llvm-readelf":
        fallback = shutil.which("readelf")
        if fallback is not None:
            return fallback
    raise BuildError(f"required tool is unavailable: {name}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rustc() -> list[str]:
    return [tool("rustup"), "run", TOOLCHAIN, "rustc"]


def compile_object(output: Path) -> list[str]:
    command = [
        *rustc(),
        "--crate-name", "crabc_builtins_x86_64",
        "--crate-type=lib",
        "--edition=2021",
        "--target", TARGET,
        "--emit=obj",
        "-C", "panic=abort",
        "-C", "force-unwind-tables=no",
        "-C", "overflow-checks=off",
        "-C", "opt-level=2",
        "-C", "codegen-units=1",
        "-C", "debuginfo=0",
        "-C", "relocation-model=pic",
        "-C", "embed-bitcode=no",
        "-C", "metadata=crabc-builtins-x86_64-static-pie-v1",
        "--remap-path-prefix", f"{ROOT}=/crabc/builtins",
        "-o", str(output), str(SOURCE),
    ]
    run(command)
    return command


def symbols(llvm_nm: str, artifact: Path, flag: str) -> set[str]:
    result: set[str] = set()
    for line in run([llvm_nm, flag, "--extern-only", str(artifact)]).splitlines():
        fields = line.split()
        if len(fields) >= 2 and not line.endswith(":"):
            result.add(fields[-1])
    return result


def audit_object(llvm_readelf: str, object_path: Path) -> None:
    header = run([llvm_readelf, "--file-header", str(object_path)])
    for line in (
        "Class:                             ELF64",
        "Data:                              2's complement, little endian",
        "Type:                              REL (Relocatable file)",
        "Machine:                           Advanced Micro Devices X86-64",
    ):
        if line not in header:
            raise BuildError(f"local helper object is not x86-64 ELF REL: missing {line!r}")
    sections = run([llvm_readelf, "--sections", str(object_path)])
    forbidden = [section for section in FORBIDDEN_SECTIONS if section in sections]
    if forbidden:
        raise BuildError(f"local helper object contains unwind sections: {forbidden!r}")


def build(output: Path) -> dict[str, object]:
    if output.name != ARCHIVE_NAME:
        raise BuildError(f"output must be named {ARCHIVE_NAME}")
    output.parent.mkdir(parents=True, exist_ok=True)
    llvm_ar = tool("llvm-ar")
    llvm_nm = tool("llvm-nm")
    llvm_readelf = tool("llvm-readelf")
    lld = tool("ld.lld")
    with tempfile.TemporaryDirectory(prefix="crabc-builtins-x86_64-", dir=output.parent) as temporary:
        stage = Path(temporary)
        member = stage / MEMBER_NAME
        compile_object(member)
        audit_object(llvm_readelf, member)
        staged = stage / ARCHIVE_NAME
        run([llvm_ar, "rcsD", str(staged), str(member)])
        members = run([llvm_ar, "t", str(staged)]).splitlines()
        if members != [MEMBER_NAME]:
            raise BuildError(f"x86 helper archive members drifted: {members!r}")
        defined = symbols(llvm_nm, staged, "--defined-only")
        missing = sorted(REQUIRED_SYMBOLS.difference(defined))
        if missing:
            raise BuildError(f"x86 helper archive is missing required symbols: {missing!r}")
        rejected = sorted(symbol for symbol in defined if any(part in symbol for part in FORBIDDEN_SYMBOL_PARTS))
        if rejected:
            raise BuildError(f"x86 helper archive exports forbidden ambient-runtime symbols: {rejected!r}")
        closure = stage / "closure.o"
        run([lld, "-r", "--whole-archive", str(staged), "--no-whole-archive", "-o", str(closure)])
        undefined = symbols(llvm_nm, closure, "--undefined-only")
        if undefined:
            raise BuildError(f"x86 helper archive requests an ambient runtime: {sorted(undefined)!r}")
        shutil.copyfile(staged, output)
        return {
            "members": members,
            "defined_symbols": sorted(defined),
            "archive_sha256": sha256(output),
            "portable_compile_command": [
                "rustup", "run", TOOLCHAIN, "rustc", "--crate-name", "crabc_builtins_x86_64",
                "--crate-type=lib", "--edition=2021", "--target", TARGET, "--emit=obj",
                "-C", "panic=abort", "-C", "force-unwind-tables=no", "-C", "overflow-checks=off",
                "-C", "opt-level=2", "-C", "codegen-units=1", "-C", "debuginfo=0",
                "-C", "relocation-model=pic", "-C", "embed-bitcode=no", "-C",
                "metadata=crabc-builtins-x86_64-static-pie-v1", "--remap-path-prefix",
                "/crabc/builtins=/crabc/builtins", "-o", "$CRABC_BUILTINS_STAGE/crabc-builtins.o",
                "/crabc/builtins/src/lib.rs",
            ],
        }


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--verify-reproducible", action="store_true")
    return parser.parse_args()


def main() -> int:
    parsed = arguments()
    output = parsed.output.resolve()
    archive = build(output)
    reproducible = None
    if parsed.verify_reproducible:
        with tempfile.TemporaryDirectory(prefix="crabc-builtins-x86_64-repro-") as temporary:
            comparison = Path(temporary) / ARCHIVE_NAME
            reproducible = archive["archive_sha256"] == build(comparison)["archive_sha256"]
            if not reproducible:
                raise BuildError("clean x86 helper archive builds produced different bytes")
    provenance = {
        "schema": 1,
        "target": TARGET,
        "scope": "bounded private x86 static consumers only; not a complete compiler runtime or public sysroot",
        "source": "builtins/src/lib.rs",
        "archive": archive,
        "reproducible": reproducible,
    }
    destination = (parsed.provenance or output.with_suffix(output.suffix + ".provenance.json")).resolve()
    destination.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"x86 static-PIE builtins: PASS ({output})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
