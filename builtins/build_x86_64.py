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
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "src" / "lib.rs"
CONTRACT = ROOT / "x86_64-helper-contract.toml"
sys.path.insert(0, str(ROOT))
from scripts.rust_toolchain import pinned_toolchain
TOOLCHAIN = pinned_toolchain(ROOT.parent)
TARGET = "x86_64-unknown-linux-musl"
ARCHIVE_NAME = "libcrabc-builtins.a"
MEMBER_NAME = "crabc-builtins.o"
REQUIRED_SYMBOLS = frozenset({
    "__addoti4", "__ashlti3", "__ashrti3", "__bswapdi2", "__bswapsi2", "__bswapti2",
    "__clzti2", "__ctzti2", "__divmodti4", "__divti3", "__ffsti2", "__lshrti3",
    "__modti3", "__muldc3", "__muloti4", "__multi3", "__parityti2", "__popcountdi2",
    "__popcountti2", "__suboti4", "__udivmodti4", "__udivti3", "__umodti3",
})
HELPER_METADATA = {"type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT", "version": None, "version_default": False}
SHARED_LIBC_METADATA = {
    "artifact": "candidate-shared",
    "linker_option": "--exclude-libs=libcrabc-builtins.a",
    "type": "FUNC",
    "binding": "LOCAL",
    "visibility": "DEFAULT",
    "dynsym": False,
}
HELPER_ABIS = frozenset({
    "complex-double", "u128-binary", "u128-bit-count", "u128-byte-swap",
    "u128-divmod-slot", "u128-overflow-slot", "u128-shift", "u32-byte-swap",
    "u64-bit-count", "u64-byte-swap",
})
FORBIDDEN_SYMBOL_PARTS = ("memcpy", "memmove", "memset", "__gcc_", "__gxx_", "__cxa_", "__atomic_")
FORBIDDEN_SECTIONS = (".eh_frame", ".gcc_except_table")


class BuildError(RuntimeError):
    """A bounded x86 helper-archive contract was violated."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def native_source_definitions(source: Path) -> dict[str, str]:
    """Return the exact public C definitions from the owned Rust source."""

    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise BuildError(f"cannot read native helper source: {source}") from error
    definitions: dict[str, str] = {}
    pattern = re.compile(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(__\w+)\s*\((.*?)\)\s*->\s*([\w:<>]+)', re.S)
    for match in pattern.finditer(text):
        name = match.group(1)
        _require(name not in definitions, f"duplicate native helper definition: {name}")
        definitions[name] = " ".join(match.group(0).split())
    return definitions


def load_native_contract_value(value: object) -> dict[str, object]:
    """Validate the finite producer contract; no symbol prefix is an input."""
    _require(type(value) is dict and set(value) == {"schema", "target", "owner_group", "source", "builder", "producer_scope", "archive", "shared_libc", "helpers"},
             "native helper contract fields differ")
    _require(type(value["schema"]) is int and value["schema"] == 1 and value["target"] == TARGET,
             "native helper contract schema/target differs")
    _require(value["owner_group"] == "owned-compiler-helper-archive" and value["source"] == "builtins/src/lib.rs"
             and value["builder"] == "builtins/build_x86_64.py" and type(value["producer_scope"]) is str,
             "native helper contract ownership differs")
    archive = value["archive"]
    _require(type(archive) is dict and archive == {"name": ARCHIVE_NAME, "member": MEMBER_NAME,
             "placements": ["static-builtins", "dynamic-builtins"]}, "native helper archive placements differ")
    shared_libc = value["shared_libc"]
    _require(type(shared_libc) is dict and type(shared_libc.get("dynsym")) is bool
             and shared_libc == SHARED_LIBC_METADATA,
             "native helper shared-libc placement differs")
    helpers = value["helpers"]
    _require(type(helpers) is list and len(helpers) == len(REQUIRED_SYMBOLS), "native helper roster differs")
    names: list[str] = []
    normalized: list[dict[str, object]] = []
    for row in helpers:
        _require(type(row) is dict and set(row) == {"name", "rust_signature", "c_abi", "caller_obligation", "metadata"},
                 "native helper record differs")
        name, signature, c_abi, obligation, metadata = (row["name"], row["rust_signature"], row["c_abi"], row["caller_obligation"], row["metadata"])
        _require(all(type(item) is str and item for item in (name, signature, c_abi, obligation)), "native helper scalar contract differs")
        _require(c_abi in HELPER_ABIS, "native helper C ABI role differs")
        _require(type(metadata) is dict and set(metadata) == {"type", "binding", "visibility", "version", "version_default"},
                 "native helper metadata fields differ")
        _require(type(metadata["type"]) is str and type(metadata["binding"]) is str
                 and type(metadata["visibility"]) is str and type(metadata["version"]) is str
                 and type(metadata["version_default"]) is bool, "native helper metadata types differ")
        normalized_metadata = {**metadata}
        _require(normalized_metadata.pop("version") == "unversioned", "native helper version differs")
        normalized_metadata["version"] = None
        _require(normalized_metadata == HELPER_METADATA, "native helper metadata differs")
        names.append(name)
        normalized.append({"name": name, "rust_signature": signature, "c_abi": c_abi,
                           "caller_obligation": obligation, "metadata": normalized_metadata})
    _require(len(names) == len(set(names)) and set(names) == REQUIRED_SYMBOLS and names == sorted(names),
             "native helper roster differs")
    return {"schema": value["schema"], "target": value["target"], "owner_group": value["owner_group"],
            "source": value["source"], "builder": value["builder"], "producer_scope": value["producer_scope"],
            "archive": archive, "shared_libc": dict(SHARED_LIBC_METADATA), "helpers": normalized}


def load_native_contract() -> dict[str, object]:
    """Load the exact native helper producer contract from its owned TOML."""

    try:
        value = tomllib.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise BuildError("native helper contract is unreadable") from error
    return load_native_contract_value(value)


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


def require_exact_defined_symbols(defined: set[str]) -> None:
    """Reject both missing and extra public archive definitions."""

    missing = sorted(REQUIRED_SYMBOLS.difference(defined))
    unexpected = sorted(defined.difference(REQUIRED_SYMBOLS))
    if missing or unexpected:
        raise BuildError(f"x86 helper archive definition roster differs: missing={missing!r} unexpected={unexpected!r}")


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
    contract = load_native_contract()
    _require(native_source_definitions(SOURCE) == {row["name"]: row["rust_signature"] for row in contract["helpers"]},
             "native helper source definitions differ from contract")
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
        require_exact_defined_symbols(defined)
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
            "contract": contract,
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
        with tempfile.TemporaryDirectory(prefix="crabc-builtins-x86_64-repro-", dir=output.parent) as temporary:
            comparison = Path(temporary) / ARCHIVE_NAME
            reproducible = archive["archive_sha256"] == build(comparison)["archive_sha256"]
            if not reproducible:
                raise BuildError("clean x86 helper archive builds produced different bytes")
    provenance = {
        "schema": 1,
        "target": TARGET,
        "scope": "bounded private x86 static consumers only; not a complete compiler runtime or public sysroot",
        "source": "builtins/src/lib.rs",
        "contract": "builtins/x86_64-helper-contract.toml",
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
