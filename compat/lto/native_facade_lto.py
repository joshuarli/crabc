#!/usr/bin/env python3
"""Collect bounded native-facade crabc-rs LTO evidence.

This is a focused Linux/AArch64 fixture, separate from ``run.py``'s older
four-configuration experiment.  The fixture is a normal Cargo application
whose manifest is supplied explicitly (and defaults to the fixture
manifest).  Fat LTO is requested for the application and its Rust path
dependencies, then the resulting ELF is checked for the two representative
direct syscall paths used by the fixture: ``getpid`` (172) and ``write`` (64).

The checks intentionally assert properties of the generated program rather
than compiler-version-specific bytes. Seeing both syscall-number-to-``svc``
paths and no branch/PLT edge in the named witness to the corresponding public
C ABI or TLS errno entry points is bounded evidence that the facade/core
boundary was optimized into direct Linux operations. Global undefined symbols
are recorded as context because a stock-``std`` application may retain
unrelated runtime edges. This is not a claim about every possible facade
operation or a whole-program C ABI link.

Run in the pinned native Linux/AArch64 development container:

    python3 compat/lto/native_facade_lto.py

Use ``--manifest`` when a caller keeps the fixture in a different
compat/lto subdirectory.  No source filename is assumed by the harness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
LTO_ROOT = Path(__file__).resolve().parent
# The fixture is deliberately selected through its manifest.  A caller
# may use --manifest for a companion fixture kept under another directory.
DEFAULT_MANIFEST = LTO_ROOT / "native-facade-lto-fixture/Cargo.toml"
DEFAULT_STOCK_STD_MANIFEST = LTO_ROOT / "native-std-lto-fixture/Cargo.toml"
DEFAULT_REPORT = ROOT / "compat/reports/lto/native-facade/latest.json"
TARGET = "aarch64-unknown-linux-musl"
TOOLCHAIN = "nightly-2026-07-24"
MUSL_VERSION = "1.2.6"
MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")

# These are the public edges that the representative facade route must not
# use.  malloc/free are intentionally not forbidden here: a normal std
# application may legitimately use the C allocator outside the inspected
# direct getpid/write operation. The branch check is deliberately exact enough
# to avoid rejecting Rust symbols which merely contain one of these words.
FORBIDDEN_PUBLIC_SYMBOLS = ("getpid", "write", "__errno_location")
REQUIRED_SYSCALLS = {172: "getpid", 64: "write"}
DEFAULT_ENTRY_SYMBOL = "crabc_rs_native_facade_getpid_witness"
DEFAULT_STDOUT = b"native-facade:ok\n"
# The stock-std fixture reserves a short musl PT_INTERP slot.  This semantic
# prefix keeps the disposable `/tmp/.../c` candidate-loader path patchable.
STOCK_STD_RUNTIME_PREFIX = "lto-"


class RunnerError(RuntimeError):
    """A setup or evidence-contract error."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot(value: bytes, *, preview_limit: int = 131_072) -> dict[str, object]:
    preview = value[:preview_limit]
    return {
        "byte_length": len(value),
        "sha256": sha256_bytes(value),
        "preview": preview.decode("utf-8", errors="replace"),
        "preview_truncated": len(value) > len(preview),
    }


def command_text(record: Mapping[str, object]) -> str:
    """Return bounded stdout/stderr text from a command record."""

    result = ""
    for key in ("stdout", "stderr"):
        value = record.get(key)
        if isinstance(value, Mapping):
            text = value.get("preview")
            if isinstance(text, str):
                result += text
    return result


def command_record(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    preview_limit: int = 131_072,
) -> dict[str, object]:
    """Run one tool without a shell and retain bounded reproducibility data."""

    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            check=False,
            capture_output=True,
        )
    except OSError as error:
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "returncode": f"OSERROR:{error.errno or 'unknown'}",
            "stdout": snapshot(b"", preview_limit=preview_limit),
            "stderr": snapshot(str(error).encode(), preview_limit=preview_limit),
        }
    return {
        "command": list(command),
        "cwd": str(cwd) if cwd is not None else None,
        "returncode": result.returncode,
        "stdout": snapshot(result.stdout, preview_limit=preview_limit),
        "stderr": snapshot(result.stderr, preview_limit=preview_limit),
    }


def require_command(name: str) -> str | None:
    return shutil.which(name)


def select_command(*names: str) -> tuple[str | None, list[str]]:
    for name in names:
        path = require_command(name)
        if path is not None:
            return path, list(names)
    return None, list(names)


def reject_glibc(text: str, description: str) -> None:
    markers = ("glibc", "gnu c library", "ld-linux", "libc.so.6")
    lowered = text.lower()
    if any(marker in lowered for marker in markers):
        raise RunnerError(f"glibc artifact/toolchain evidence detected in {description}")


def fixture_metadata(manifest: Path) -> dict[str, object]:
    """Read the package without assuming a source filename or bin name."""

    try:
        with manifest.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"invalid fixture manifest: {manifest}") from error
    package = raw.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("name"), str):
        raise RunnerError(f"fixture manifest lacks package.name: {manifest}")
    package_name = package["name"]
    if not package_name:
        raise RunnerError(f"fixture package.name is empty: {manifest}")
    targets = raw.get("bin")
    bin_names: list[str] = []
    if isinstance(targets, list):
        for target in targets:
            if isinstance(target, dict) and isinstance(target.get("name"), str):
                bin_names.append(target["name"])
    binary_name = bin_names[0] if bin_names else package_name
    metadata = package.get("metadata", {})
    native_facade_metadata = metadata.get("crabc-lto", {}) if isinstance(metadata, dict) else {}
    if not isinstance(native_facade_metadata, dict):
        native_facade_metadata = {}

    source_files = sorted(
        path
        for path in manifest.parent.rglob("*.rs")
        if "/target/" not in path.as_posix()
    )
    if not source_files:
        raise RunnerError(f"fixture manifest has no Rust source files: {manifest.parent}")
    lockfile = manifest.with_name("Cargo.lock")
    entry_symbol = native_facade_metadata.get("entry-symbol", DEFAULT_ENTRY_SYMBOL)
    expected_stdout = native_facade_metadata.get("stdout", DEFAULT_STDOUT.decode())
    if not isinstance(entry_symbol, str) or not entry_symbol:
        raise RunnerError("package.metadata.crabc-lto.entry-symbol must be a non-empty string")
    if not isinstance(expected_stdout, str):
        raise RunnerError("package.metadata.crabc-lto.stdout must be a string")
    return {
        "manifest": manifest,
        "package_name": package_name,
        "binary_name": binary_name,
        "source_files": source_files,
        "lockfile": lockfile,
        "entry_symbol": entry_symbol,
        "expected_stdout": expected_stdout.encode(),
        "metadata": native_facade_metadata,
    }


def fixture_evidence(metadata: Mapping[str, object]) -> dict[str, object]:
    manifest = metadata["manifest"]
    source_files = metadata["source_files"]
    lockfile = metadata["lockfile"]
    assert isinstance(manifest, Path)
    assert isinstance(source_files, list) and all(isinstance(path, Path) for path in source_files)
    assert isinstance(lockfile, Path)
    sources = {
        str(path): sha256_file(path)
        for path in source_files
    }
    return {
        "manifest": str(manifest),
        "manifest_sha256": sha256_file(manifest),
        "package_name": metadata["package_name"],
        "binary_name": metadata["binary_name"],
        "entry_symbol": metadata["entry_symbol"],
        "source_files": sources,
        "lockfile": str(lockfile) if lockfile.is_file() else None,
        "lockfile_sha256": sha256_file(lockfile) if lockfile.is_file() else None,
        "dependency_lock_required": True,
        "expected_stdout": snapshot(metadata["expected_stdout"]),
    }


def sanitize_environment() -> dict[str, str]:
    """Keep runtime observations independent of host Rust/loader variables."""

    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_", "RUST", "CARGO", "CRABC", "MUSL")):
            environment.pop(key, None)
    environment.update(
        {
            "PATH": "/bin:/usr/bin",
            "HOME": "/root",
            "TMPDIR": "/tmp",
            "PWD": "/tmp",
            "OLDPWD": "/tmp",
            "LC_ALL": "C",
            "CRABC_NATIVE_FACADE_LTO_FIXTURE": "aarch64-musl",
        }
    )
    return environment


def environment_evidence(environment: Mapping[str, str]) -> dict[str, object]:
    encoded = "\0".join(f"{key}={environment[key]}" for key in sorted(environment)).encode()
    visible_keys = {
        "PATH",
        "HOME",
        "TMPDIR",
        "PWD",
        "OLDPWD",
        "LC_ALL",
        "CRABC_NATIVE_FACADE_LTO_FIXTURE",
        "CARGO_HOME",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
        "RUSTFLAGS",
    }
    return {
        "sha256": sha256_bytes(encoded),
        "variables": {
            key: environment[key]
            for key in sorted(environment)
            if key in visible_keys or key.startswith("CARGO_TARGET_")
        },
        "redacted_variable_names": sorted(set(environment) - visible_keys),
    }


def rustflags(*, lto: str, dynamic: bool, no_start_files: bool) -> str:
    """Return a complete optimization/link contract, independent of repo config."""

    flags = [
        "-C opt-level=3",
        "-C codegen-units=1",
        "-C panic=abort",
        f"-C lto={lto}",
        "-C embed-bitcode=yes",
        f"-C target-feature={'-' if dynamic else '+'}crt-static",
        "-C link-arg=-L/usr/lib",
    ]
    flags.extend(
        (
            "-C link-arg=--target=aarch64-unknown-linux-musl",
            f"-C link-arg=--sysroot=/opt/musl-{MUSL_VERSION}",
            "-C link-arg=-fuse-ld=lld",
        )
    )
    if no_start_files:
        flags.append("-C link-arg=-nostartfiles")
    return " ".join(flags)


def discover_tools() -> tuple[dict[str, str], dict[str, object]]:
    selected: dict[str, str] = {}
    attempts: dict[str, object] = {}
    for key, names in (
        ("cargo", ("cargo",)),
        ("rustc", ("rustc",)),
        ("rustup", ("rustup",)),
        ("musl_gcc", ("musl-gcc",)),
        ("llvm_nm", ("llvm-nm", "nm")),
        ("readelf", ("llvm-readelf", "readelf")),
        ("objdump", ("llvm-objdump", "objdump")),
        ("file", ("file",)),
        ("clang", ("clang",)),
    ):
        path, tried = select_command(*names)
        attempts[key] = {"tried": tried, "selected": path}
        if path is not None:
            selected[key] = path
    return selected, attempts


def load_pins() -> dict[str, object]:
    try:
        with (ROOT / "compat/upstreams.toml").open("rb") as stream:
            upstreams = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RunnerError("compat/upstreams.toml is unavailable or invalid") from error
    environment = upstreams.get("environment")
    musl = upstreams.get("musl")
    if not isinstance(environment, dict) or not isinstance(musl, dict):
        raise RunnerError("compat/upstreams.toml lacks environment/musl pins")
    if environment.get("platform") != "linux/arm64":
        raise RunnerError("compat/upstreams.toml is not pinned to linux/arm64")
    if environment.get("rust_toolchain") != TOOLCHAIN:
        raise RunnerError("compat/upstreams.toml has an unexpected Rust toolchain")
    if musl.get("version") != MUSL_VERSION:
        raise RunnerError("compat/upstreams.toml has an unexpected musl version")
    return {"environment": environment, "musl": musl}


def validate_manifest(manifest: Path) -> dict[str, object]:
    manifest = manifest.expanduser().resolve()
    if not manifest.is_file():
        raise RunnerError(f"fixture manifest unavailable: {manifest}")
    return fixture_metadata(manifest)


def capability_reasons(
    metadata: Mapping[str, object],
    tools: Mapping[str, str],
    attempts: Mapping[str, object],
    musl_root: Path,
) -> list[str]:
    reasons: list[str] = []
    if platform.system() != "Linux":
        reasons.append(f"requires Linux, got {platform.system()}")
    if platform.machine().lower() not in {"aarch64", "arm64"}:
        reasons.append(f"requires native AArch64, got {platform.machine()!r}")
    required = ("cargo", "rustc", "rustup", "musl_gcc", "clang", "llvm_nm", "readelf", "objdump", "file")
    for name in required:
        if name not in tools:
            reasons.append(f"required tool unavailable: {attempts.get(name)}")
    if musl_root.name != f"musl-{MUSL_VERSION}":
        reasons.append(f"musl root must name pinned musl-{MUSL_VERSION}: {musl_root}")
    for path in (
        musl_root / "include",
        musl_root / "lib/libc.so",
        musl_root / "lib/libc.a",
        musl_root / "lib/ld-musl-aarch64.so.1",
    ):
        if not path.exists():
            reasons.append(f"pinned musl artifact unavailable: {path}")
    lockfile = metadata["lockfile"]
    if isinstance(lockfile, Path) and not lockfile.is_file():
        reasons.append(f"fixture requires a checked-in Cargo.lock: {lockfile}")
    # Toolchain probing is meaningful only on the target host; on macOS the
    # host reasons above are sufficient and no fake Rust/AArch64 result is made.
    if platform.system() == "Linux" and platform.machine().lower() in {"aarch64", "arm64"}:
        rustup = tools.get("rustup")
        rustc = tools.get("rustc")
        if rustup and rustc:
            active = command_record([rustup, "show", "active-toolchain"])
            active_text = command_text(active)
            if not active_text.startswith(TOOLCHAIN):
                reasons.append(f"active Rust toolchain is not pinned {TOOLCHAIN}: {active_text}")
            version = command_record([rustc, f"+{TOOLCHAIN}", "-Vv"])
            version_text = command_text(version)
            if f"host: {TARGET}" not in version_text:
                reasons.append(f"rustc host is not {TARGET}: {version_text}")
            try:
                reject_glibc(version_text, "rustc -Vv")
            except RunnerError as error:
                reasons.append(str(error))
        musl_gcc = tools.get("musl_gcc")
        if musl_gcc:
            wrapper = Path(musl_gcc)
            try:
                wrapper_text = wrapper.read_text(encoding="utf-8")
            except OSError:
                wrapper_text = ""
            if f"/opt/musl-{MUSL_VERSION}" not in wrapper_text:
                reasons.append(f"musl-gcc is not the pinned wrapper: {wrapper}")
    return reasons


def parse_named_section_sizes(readelf_text: str, prefix: str) -> list[int]:
    sizes: list[int] = []
    for line in readelf_text.splitlines():
        fields = line.split()
        if not fields:
            continue
        index = 2 if fields[0] == "[" else 1 if fields[0].startswith("[") else -1
        if index < 0 or len(fields) <= index + 4 or not fields[index].startswith(prefix):
            continue
        try:
            sizes.append(int(fields[index + 4], 16))
        except ValueError:
            continue
    return sizes


def parse_text_size(readelf_text: str) -> int | None:
    sizes = parse_named_section_sizes(readelf_text, ".text")
    return sum(sizes) if sizes else None


def symbol_names(nm_text: str) -> tuple[list[str], list[str]]:
    """Return defined and undefined symbol names from llvm-nm/nm text."""

    defined: list[str] = []
    undefined: list[str] = []
    symbol_types = set("BbCdDeEfFgGiIjJkLlNnOoPpRrSsTtUuVvWwXxYyZz?")
    for raw_line in nm_text.splitlines():
        line = raw_line.strip()
        if not line or line.endswith(":"):
            continue
        fields = line.split()
        if len(fields) >= 3 and len(fields[-2]) == 1 and fields[-2] in symbol_types:
            name = fields[-1]
            (undefined if fields[-2].upper() == "U" else defined).append(name)
        elif len(fields) >= 2 and fields[0].upper() == "U":
            undefined.append(fields[-1])
    return defined, undefined


def _symbol_exact(name: str, candidate: str) -> bool:
    return name == candidate or name == f"{candidate}@plt" or name == f"{candidate}@GLIBC"


def syscall_pattern(number: int) -> str:
    # LLVM/binutils spellings vary between ``mov w8`` and ``mov x8`` and may
    # print the immediate in hexadecimal or decimal.  Keep the instruction
    # window bounded to the containing witness instead of matching unrelated
    # constants elsewhere in the executable.
    return rf"\b(?:mov|movz|movk)\s+[wx]8,\s*#(?:0x{number:x}|{number})\b[\s\S]{{0,800}}?\bsvc(?:\s+#?0)?\b"


def function_disassembly(disassembly: str, symbol: str) -> str:
    """Extract one objdump function block for a function-scoped witness."""

    import re

    marker = re.compile(rf"(?m)^\s*[0-9a-fA-F]+\s+<{re.escape(symbol)}>:\s*$")
    match = marker.search(disassembly)
    if match is None:
        raise RunnerError(f"witness function is absent from disassembly: {symbol}")
    next_function = re.search(r"(?m)^\s*[0-9a-fA-F]+\s+<[^>]+>:\s*$", disassembly[match.end() :])
    end = match.end() + next_function.start() if next_function else len(disassembly)
    return disassembly[match.start() : end]


def inspect_direct_route(
    *,
    readelf_text: str,
    nm_text: str,
    disassembly: str,
    entry_symbol: str,
) -> dict[str, object]:
    """Check semantic assembly/symbol properties without byte-exact claims."""

    if "AArch64" not in readelf_text:
        raise RunnerError("fixture is not an AArch64 ELF")
    if not entry_symbol or entry_symbol not in nm_text:
        raise RunnerError(f"entry symbol is absent from symbol evidence: {entry_symbol}")
    import re

    witness = function_disassembly(disassembly, entry_symbol)
    witness_getpid = bool(re.search(syscall_pattern(172), witness))
    if not witness_getpid:
        raise RunnerError("witness lacks direct getpid syscall 172 followed by svc")
    if "svc" not in witness:
        raise RunnerError("witness contains no AArch64 svc instruction")

    direct_syscalls = {
        name: bool(re.search(syscall_pattern(number), disassembly))
        for number, name in REQUIRED_SYSCALLS.items()
    }
    missing = [name for name, present in direct_syscalls.items() if not present]
    if missing:
        raise RunnerError("fixture is missing direct syscall path(s): " + ", ".join(missing))

    defined, undefined = symbol_names(nm_text)
    undefined_forbidden = [
        name
        for name in undefined
        if any(_symbol_exact(name, candidate) for candidate in FORBIDDEN_PUBLIC_SYMBOLS)
    ]
    # Undefined symbols are retained as whole-image context only.  A stock
    # std lane may carry an unrelated C runtime edge; the contract under test
    # is the named witness's branch/PLT body, checked below.
    # Public-wrapper absence is checked in the named witness, not by scanning
    # every std/musl helper in the final executable.  A stock Rust application
    # may legitimately retain unrelated allocator/runtime calls.
    branch_forbidden: list[str] = []
    for candidate in FORBIDDEN_PUBLIC_SYMBOLS:
        if re.search(rf"\b(?:bl|blr|b)\s+[^\n]*<{re.escape(candidate)}(?:@[^>]*)?>", witness):
            branch_forbidden.append(candidate)
    if branch_forbidden:
        raise RunnerError(
            "fixture branches to forbidden public C/TLS symbol(s): "
            + ", ".join(branch_forbidden)
        )
    internal_facade_calls = bool(
        re.search(r"\b(?:bl|blr)\s+[^\n]*<(?:crabc_rs|crabc_core)[^>]*>", witness)
    )

    return {
        "machine": "AArch64",
        "entry_symbol": entry_symbol,
        "entry_symbol_observed": True,
        "direct_svc_observed": True,
        "witness_function_scoped": True,
        "witness_direct_getpid": witness_getpid,
        "direct_syscalls": direct_syscalls,
        "forbidden_public_symbols": list(FORBIDDEN_PUBLIC_SYMBOLS),
        "undefined_forbidden_symbols": undefined_forbidden,
        "branch_forbidden_symbols": branch_forbidden,
        "witness_internal_facade_call_observed": internal_facade_calls,
        "defined_global_symbol_count": len(defined),
        "defined_global_symbol_sha256": sha256_bytes("\n".join(sorted(defined)).encode()),
        "undefined_symbol_count": len(undefined),
        "assembly_byte_exactness_claimed": False,
    }


def artifact_inspection(
    binary: Path,
    tools: Mapping[str, str],
    entry_symbol: str | None,
) -> dict[str, object]:
    records: dict[str, object] = {}
    file_record = command_record([tools["file"], str(binary)])
    nm_record = command_record([tools["llvm_nm"], "-a", "-C", str(binary)], preview_limit=2_000_000)
    readelf_record = command_record(
        [tools["readelf"], "-h", "-l", "-S", str(binary)], preview_limit=2_000_000
    )
    objdump_record = command_record(
        [tools["objdump"], "-d", "--demangle", str(binary)], preview_limit=2_000_000
    )
    records.update(
        {
            "file": file_record,
            "llvm_nm": nm_record,
            "readelf": readelf_record,
            "objdump": objdump_record,
        }
    )
    file_text = command_text(file_record)
    nm_text = command_text(nm_record)
    readelf_text = command_text(readelf_record)
    disassembly = command_text(objdump_record)
    reject_glibc(file_text + nm_text + readelf_text + disassembly, "ELF inspection")
    route = (
        inspect_direct_route(
            readelf_text=readelf_text,
            nm_text=nm_text,
            disassembly=disassembly,
            entry_symbol=entry_symbol,
        )
        if entry_symbol is not None
        else None
    )
    records.update(
        {
            "binary_sha256": sha256_file(binary),
            "file_size_bytes": binary.stat().st_size,
            "text_size_bytes": parse_text_size(readelf_text),
            "has_interpreter": "INTERP" in readelf_text,
            "readelf_sha256": sha256_bytes(readelf_text.encode()),
            "disassembly_sha256": sha256_bytes(disassembly.encode()),
            "route": route,
        }
    )
    return records


def sanitize_build_environment(
    target_dir: Path,
    linker: str,
    *,
    lto: str,
    dynamic: bool,
    no_start_files: bool,
    candidate_dir: Path | None = None,
) -> dict[str, str]:
    environment = dict(os.environ)
    for key in tuple(environment):
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"} or key.startswith(
            "CARGO_TARGET_"
        ):
            environment.pop(key, None)
    flags = rustflags(lto=lto, dynamic=dynamic, no_start_files=no_start_files)
    if dynamic and candidate_dir is not None:
        # The pinned Docker image's clang/lld needs the candidate C runtime in
        # its search path.  This is only a link/runtime boundary; Rust LTO is
        # not claimed to cross into the dynamically loaded DSO.
        gcc_support = "/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0"
        flags += f" -C link-arg=-L{candidate_dir} -C link-arg=-lc -C link-arg=-B{gcc_support} -C link-arg=-L{gcc_support}"
    environment.update(
        {
            "CARGO_TARGET_DIR": str(target_dir),
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": linker,
            "RUSTFLAGS": flags,
        }
    )
    return environment


def rlib_provenance(target_dir: Path, tools: Mapping[str, str]) -> dict[str, object]:
    """Record intermediate Rust bitcode without claiming unique inlining."""

    rlibs = sorted(target_dir.rglob("*.rlib"))
    # Keep the positive observation scoped to the two Rust crates that form
    # this experiment's shared facade/core path.  Other dependency rlibs are
    # retained only as bounded context.
    relevant = [
        path
        for path in rlibs
        if "libcrabc_rs-" in path.name or "libcrabc_core-" in path.name
    ]
    examined = (relevant + [path for path in rlibs if path not in relevant])[:96]
    bitcode_rlibs = 0
    bitcode_bytes = 0
    records: list[dict[str, object]] = []
    for rlib in examined:
        record = command_record([tools["readelf"], "-SW", str(rlib)])
        sizes = parse_named_section_sizes(command_text(record), ".llvmbc")
        raw_marker = b".llvmbc" in rlib.read_bytes()
        if sizes:
            bitcode_rlibs += 1
            bitcode_bytes += sum(sizes)
        elif raw_marker:
            # llvm-readelf versions differ in how much of an ar archive they
            # print.  The archive marker is still positive section provenance;
            # it is deliberately recorded separately from a byte count.
            bitcode_rlibs += 1
        records.append(
            {
                "path": str(rlib),
                "sha256": sha256_file(rlib),
                "llvmbc_section_bytes": sum(sizes),
                "llvmbc_raw_marker": raw_marker,
                "inspection": record,
            }
        )
    return {
        "status": "observed" if bitcode_rlibs else "not-observed",
        "rlib_count": len(rlibs),
        "rlibs_examined": len(examined),
        "bitcode_rlib_count": bitcode_rlibs,
        "bitcode_section_bytes": bitcode_bytes,
        "scope": "intermediate Rust rlibs only; not proof of unique inlining or dynamic libc participation",
        "required_crabc_rlibs": {
            "crabc-rs": any(
                ("libcrabc_rs-" in item["path"] and (item["llvmbc_raw_marker"] or item["llvmbc_section_bytes"]))
                for item in records
            ),
            "crabc-core": any(
                ("libcrabc_core-" in item["path"] and (item["llvmbc_raw_marker"] or item["llvmbc_section_bytes"]))
                for item in records
            ),
        },
        "artifacts": records,
    }


def build_fixture(
    metadata: Mapping[str, object],
    tools: Mapping[str, str],
    target_dir: Path,
    temporary: Path,
    *,
    lane: str,
    lto: str,
    dynamic: bool = False,
    binary_name: str | None = None,
    build_std: bool = False,
    candidate_dir: Path | None = None,
) -> tuple[Path, dict[str, object]]:
    manifest = metadata["manifest"]
    lockfile = metadata["lockfile"]
    default_binary_name = metadata["binary_name"]
    assert isinstance(manifest, Path) and isinstance(lockfile, Path) and isinstance(default_binary_name, str)
    binary_name = binary_name or default_binary_name
    linker = tools["clang"] if (lto == "fat" or not build_std) else tools["musl_gcc"]
    command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "build",
        "--manifest-path",
        str(manifest),
        "--release",
        "--target",
        TARGET,
        "--target-dir",
        str(target_dir),
        "--bin",
        binary_name or str(metadata["binary_name"]),
    ]
    if build_std:
        command.append("-Z")
        command.append("build-std=std,panic_abort")
    if lockfile.is_file():
        command.append("--locked")
    environment = sanitize_build_environment(
        target_dir,
        linker,
        lto=lto,
        dynamic=dynamic,
        # The fixture uses the target's normal Rust/musl CRT startup.  A
        # custom _start plus Rust's self-contained crt1.o is not a stable
        # linker contract, so the harness keeps this false for every lane.
        no_start_files=False,
        candidate_dir=candidate_dir,
    )
    # Running Cargo outside the repository prevents the checked-in .cargo
    # configuration from adding target-feature or dead-code flags to this
    # focused measurement.  Path dependencies still resolve from the manifest.
    build_cwd = temporary / f"cargo-cwd-{lane}"
    build_cwd.mkdir(parents=True)
    started = time.monotonic_ns()
    result = subprocess.run(
        command,
        cwd=build_cwd,
        env=environment,
        capture_output=True,
        check=False,
    )
    build: dict[str, object] = {
        "command": command,
        "cwd": str(build_cwd),
        "cwd_isolated_from_repository_config": True,
        "linker": linker,
        "rustflags": environment["RUSTFLAGS"],
        "environment": environment_evidence(environment),
        "returncode": result.returncode,
        "wall_time_ns": time.monotonic_ns() - started,
        "stdout": snapshot(result.stdout),
        "stderr": snapshot(result.stderr),
        "lane": lane,
        "optimization_contract": {
            "opt_level": 3,
            "codegen_units": 1,
            "panic": "abort",
            "lto": lto,
            "embed_bitcode": True,
            "build_std": build_std,
            "dynamic": dynamic,
        },
    }
    output_text = result.stdout.decode("utf-8", errors="replace") + result.stderr.decode(
        "utf-8", errors="replace"
    )
    reject_glibc(output_text, "compiler output")
    binary = target_dir / TARGET / "release" / binary_name
    build["binary"] = str(binary)
    if result.returncode != 0:
        return binary, {**build, "status": "unbuildable", "reason": "Cargo returned non-zero"}
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return binary, {**build, "status": "unbuildable", "reason": f"executable unavailable: {binary}"}
    build["rlib_provenance"] = rlib_provenance(target_dir, tools)
    return binary, {**build, "status": "built", "binary_sha256": sha256_file(binary)}


def run_binary(
    binary: Path,
    expected_stdout: bytes,
    timeout: float,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    process_environment = dict(environment) if environment is not None else sanitize_environment()

    def disable_core_dump() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            [str(binary)],
            cwd="/tmp",
            env=process_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=disable_core_dump,
            close_fds=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            status: int | str = process.returncode
            timed_out = False
        except subprocess.TimeoutExpired as error:
            process.kill()
            stdout, stderr = process.communicate()
            stdout = stdout or error.stdout or b""
            stderr = stderr or error.stderr or b""
            status = "TIMEOUT"
            timed_out = True
    except OSError as error:
        stdout, stderr = b"", str(error).encode()
        status = f"EXEC_ERROR:{error.errno or 'unknown'}"
        timed_out = False
    return {
        "status": status,
        "timed_out": timed_out,
        "wall_time_ns": time.monotonic_ns() - started,
        "stdout": snapshot(stdout),
        "stderr": snapshot(stderr),
        "expected_stdout": snapshot(expected_stdout),
        "stdout_exact": stdout == expected_stdout,
        "stderr_empty": not stderr,
    }


def parse_syscall_summary(text: str) -> dict[str, object]:
    """Parse stable rows from ``strace -f -c`` as corroborating observations."""

    rows: list[dict[str, object]] = []
    in_table = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "syscall" in line and "calls" in line:
            in_table = True
            continue
        if not in_table or line.startswith("---") or line.startswith("% time"):
            continue
        fields = line.split()
        if len(fields) < 4 or fields[-1] == "total":
            continue
        if len(fields) >= 6 and fields[-3].isdigit() and fields[-2].isdigit():
            calls, errors = int(fields[-3]), int(fields[-2])
        elif fields[-2].isdigit():
            calls, errors = int(fields[-2]), 0
        else:
            continue
        rows.append({"syscall": fields[-1], "calls": calls, "errors": errors})
    return {"syscalls": rows, "total_calls": sum(row["calls"] for row in rows)}


def strace_measurement(
    binary: Path,
    timeout: float,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    output_file: Path,
) -> dict[str, object]:
    tracer = require_command("strace")
    if tracer is None:
        return {"status": "unsupported", "reason": "strace is unavailable"}
    command = [tracer, "-f", "-c", "-o", str(output_file), str(binary)]
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "status": "TIMEOUT",
            "command": command,
            "timed_out": True,
            "wall_time_ns": time.monotonic_ns() - started,
            "stderr": snapshot((error.stderr or b"") if isinstance(error.stderr, bytes) else str(error).encode()),
        }
    trace = output_file.read_bytes() if output_file.is_file() else b""
    return {
        "status": result.returncode,
        "command": command,
        "timed_out": False,
        "wall_time_ns": time.monotonic_ns() - started,
        "stdout": snapshot(result.stdout),
        "stderr": snapshot(result.stderr),
        "trace": snapshot(trace),
        **parse_syscall_summary(trace.decode("utf-8", errors="replace")),
    }


def patched_interpreter_bytes(binary: bytes, interpreter: str) -> bytes:
    """Patch only PT_INTERP in an ELF64 little-endian AArch64 executable."""

    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        raise RunnerError("stock-std output is not an ELF64 little-endian executable")
    if int.from_bytes(binary[18:20], "little") != 183:
        raise RunnerError("stock-std output is not an AArch64 ELF")
    phoff = int.from_bytes(binary[32:40], "little")
    phentsize = int.from_bytes(binary[54:56], "little")
    phnum = int.from_bytes(binary[56:58], "little")
    result = bytearray(binary)
    encoded = interpreter.encode("ascii") + b"\0"
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(result):
            raise RunnerError("stock-std program headers exceed the file")
        if int.from_bytes(result[offset : offset + 4], "little") != 3:
            continue
        file_offset = int.from_bytes(result[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(result[offset + 32 : offset + 40], "little")
        if len(encoded) > file_size or file_offset + file_size > len(result):
            raise RunnerError("stock-std interpreter path does not fit PT_INTERP")
        result[file_offset : file_offset + file_size] = encoded + b"\0" * (file_size - len(encoded))
        return bytes(result)
    raise RunnerError("stock-std output has no PT_INTERP segment")


def patch_interpreter(source: Path, destination: Path, interpreter: str) -> None:
    destination.write_bytes(patched_interpreter_bytes(source.read_bytes(), interpreter))
    destination.chmod(source.stat().st_mode | 0o100)


def stock_std_comparison(
    binary: Path,
    tools: Mapping[str, str],
    musl_root: Path,
    target_dir: Path,
    candidate_dir: Path,
    expected_stdout: bytes,
    timeout: float,
    temporary: Path,
) -> dict[str, object]:
    """Run one build-std binary against raw musl and crabc loader/libc bytes."""

    del target_dir  # The build target is retained in the lane report; runtime artifacts are separate.
    candidate_loader = candidate_dir / "libldso.so"
    candidate_libc = candidate_dir / "libc.so"
    if not candidate_loader.is_file() or not candidate_libc.is_file():
        return {
            "status": "unsupported",
            "reason": "crabc target/debug/libldso.so and libc.so are required for stock-std comparison",
        }
    # musl's PT_INTERP slot is short. Keep the disposable absolute runtime
    # root under /tmp with a short generated name, then remove that exact
    # directory after both observations complete.
    runtime = Path(tempfile.mkdtemp(prefix=STOCK_STD_RUNTIME_PREFIX, dir="/tmp"))
    reference_loader = runtime / "r"
    candidate_loader_path = runtime / "c"
    shutil.copy2(musl_root / "lib/ld-musl-aarch64.so.1", reference_loader)
    shutil.copy2(candidate_loader, candidate_loader_path)
    candidate_loader_path.chmod(candidate_loader_path.stat().st_mode | 0o100)
    library = runtime / "lib"
    library.mkdir()
    libgcc = Path("/usr/lib/libgcc_s.so.1")
    if libgcc.is_file():
        shutil.copy2(libgcc, library / "libgcc_s.so.1")
    reference_binary = runtime / "reference"
    candidate_binary = runtime / "candidate"
    patch_interpreter(binary, reference_binary, str(reference_loader))
    patch_interpreter(binary, candidate_binary, str(candidate_loader_path))
    environment = sanitize_environment()
    shutil.copy2(musl_root / "lib/libc.so", library / "libc.musl-aarch64.so.1")
    shutil.copy2(musl_root / "lib/libc.so", library / "libc.so")
    reference = run_binary(
        reference_binary,
        expected_stdout,
        timeout,
        environment={**environment, "LD_LIBRARY_PATH": str(library)},
    )
    reference["runtime"] = "pinned-musl"
    reference["loader_sha256"] = sha256_file(reference_loader)
    reference["libc_sha256"] = sha256_file(library / "libc.musl-aarch64.so.1")
    reference["strace"] = strace_measurement(
        reference_binary,
        timeout,
        cwd=runtime,
        environment={**environment, "LD_LIBRARY_PATH": str(library)},
        output_file=runtime / "reference.strace",
    )
    shutil.copy2(candidate_libc, library / "libc.musl-aarch64.so.1")
    shutil.copy2(candidate_libc, library / "libc.so")
    candidate = run_binary(
        candidate_binary,
        expected_stdout,
        timeout,
        environment={**environment, "LD_LIBRARY_PATH": str(library)},
    )
    candidate["runtime"] = "crabc"
    candidate["loader_sha256"] = sha256_file(candidate_loader_path)
    candidate["libc_sha256"] = sha256_file(library / "libc.musl-aarch64.so.1")
    candidate["strace"] = strace_measurement(
        candidate_binary,
        timeout,
        cwd=runtime,
        environment={**environment, "LD_LIBRARY_PATH": str(library)},
        output_file=runtime / "candidate.strace",
    )
    comparison = {
        "status": "pass"
        if reference["status"] == candidate["status"] == 0
        and reference["stdout_exact"]
        and candidate["stdout_exact"]
        and reference["stderr_empty"]
        and candidate["stderr_empty"]
        and reference["stdout"]["sha256"] == candidate["stdout"]["sha256"]
        and reference["stderr"]["sha256"] == candidate["stderr"]["sha256"]
        else "fail",
        "normalization": "none",
        "reference": reference,
        "candidate": candidate,
        "same_status": reference["status"] == candidate["status"],
        "same_stdout": reference["stdout"]["sha256"] == candidate["stdout"]["sha256"],
        "same_stderr": reference["stderr"]["sha256"] == candidate["stderr"]["sha256"],
        "lto_into_dynamic_libc_proven": False,
    }
    shutil.rmtree(runtime, ignore_errors=True)
    return comparison


def classify_build_failure(output: str) -> str:
    lowered = output.lower()
    markers = ("unsupported", "not supported", "could not execute", "linker `", "can't find crate")
    return "unsupported" if any(marker in lowered for marker in markers) else "unbuildable"


def atomic_write_json(path: Path, report: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(os.environ.get("CRABC_NATIVE_FACADE_LTO_MANIFEST", DEFAULT_MANIFEST)))
    parser.add_argument(
        "--stock-std-manifest",
        type=Path,
        default=Path(os.environ.get("CRABC_NATIVE_STD_LTO_MANIFEST", DEFAULT_STOCK_STD_MANIFEST)),
    )
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/native-facade-lto")
    parser.add_argument("--candidate-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--entry-symbol", default=None, help="override package.metadata.crabc-lto.entry-symbol")
    parser.add_argument("--expected-stdout", default=None, help="override package.metadata.crabc-lto.stdout")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> tuple[str, Path]:
    if args.timeout <= 0:
        raise RunnerError("--timeout must be positive")
    pins = load_pins()
    metadata = validate_manifest(args.manifest)
    stock_metadata = validate_manifest(args.stock_std_manifest)
    if args.entry_symbol is not None:
        metadata = {**metadata, "entry_symbol": args.entry_symbol}
    if args.expected_stdout is not None:
        metadata = {**metadata, "expected_stdout": args.expected_stdout.encode()}
    tools, attempts = discover_tools()
    musl_root = Path(os.environ.get("MUSL_ROOT", str(MUSL_ROOT)))
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "compat/lto/native_facade_lto.py",
        "result": "error",
        "target": TARGET,
        "host": {"system": platform.system(), "machine": platform.machine(), "python": sys.version},
        "tool_attempts": attempts,
        "selected_tools": tools,
        "pins": pins,
        "fixture": fixture_evidence(metadata),
        "stock_std_fixture": fixture_evidence(stock_metadata),
        "environment_contract": environment_evidence(sanitize_environment()),
        "claims": {
            "lto_requested": True,
            "assembly_byte_exactness_claimed": False,
            "whole_program_lto_proven": False,
            "facade_boundary_eliminated": False,
            "direct_syscall_route_proven": False,
            "cross_boundary_unique_inlining_proven": False,
        },
    }
    reasons = capability_reasons(metadata, tools, attempts, musl_root)
    reasons.extend(
        f"stock-std fixture: {reason}"
        for reason in capability_reasons(stock_metadata, tools, attempts, musl_root)
        if reason not in reasons
    )
    report_path = args.report.expanduser().resolve()
    if reasons:
        report["result"] = "partial"
        report["capability_reasons"] = reasons
        report["status"] = "unsupported"
        atomic_write_json(report_path, report)
        return "partial", report_path

    target_dir = args.target_dir.expanduser().resolve()
    candidate_dir = args.candidate_dir.expanduser().resolve()
    report["inputs"] = {
        "target_dir": str(target_dir),
        "candidate_dir": str(candidate_dir),
        "musl_root": str(musl_root),
        "candidate_loader": str(candidate_dir / "libldso.so"),
        "candidate_libc": str(candidate_dir / "libc.so"),
        "candidate_loader_sha256": (
            sha256_file(candidate_dir / "libldso.so")
            if (candidate_dir / "libldso.so").is_file()
            else None
        ),
        "candidate_libc_sha256": (
            sha256_file(candidate_dir / "libc.so")
            if (candidate_dir / "libc.so").is_file()
            else None
        ),
    }
    lanes: dict[str, object] = {}
    all_static_passed = True
    with tempfile.TemporaryDirectory(prefix="crabc-native-facade-lto-") as temporary_name:
        temporary = Path(temporary_name)
        for lane, lto in (("control-o3", "off"), ("fat-lto", "fat")):
            lane_target = target_dir / lane
            binary, build = build_fixture(
                metadata,
                tools,
                lane_target,
                temporary,
                lane=lane,
                lto=lto,
                dynamic=True,
                candidate_dir=candidate_dir,
            )
            lane_report: dict[str, object] = {"build": build}
            if build["status"] != "built":
                lane_report["status"] = classify_build_failure(command_text(build))
                all_static_passed = False
                lanes[lane] = lane_report
                continue
            try:
                inspection = artifact_inspection(binary, tools, str(metadata["entry_symbol"]))
                lane_report["inspection"] = inspection
                lane_report["runtime_comparison"] = stock_std_comparison(
                    binary,
                    tools,
                    musl_root,
                    lane_target,
                    candidate_dir,
                    metadata["expected_stdout"],
                    args.timeout,
                    temporary,
                )
                runtime = lane_report["runtime_comparison"]
                assert isinstance(runtime, Mapping)
                route = inspection["route"]
                assert isinstance(route, Mapping)
                provenance = build.get("rlib_provenance", {})
                required = provenance.get("required_crabc_rlibs", {}) if isinstance(provenance, Mapping) else {}
                required_bitcode = isinstance(required, Mapping) and all(bool(value) for value in required.values())
                direct = (
                    bool(route["witness_direct_getpid"])
                    and all(bool(value) for value in route["direct_syscalls"].values())
                    and not route["branch_forbidden_symbols"]
                )
                lane_report["direct_route_proven"] = direct
                boundary_eliminated = direct and not bool(route["witness_internal_facade_call_observed"])
                lane_report["facade_boundary_eliminated_observed"] = boundary_eliminated
                lane_report["required_crabc_rlibs_bitcode_observed"] = required_bitcode
                lane_report["status"] = (
                    "built"
                    if direct
                    and runtime["status"] == "pass"
                    and (lto != "fat" or required_bitcode)
                    and (lto != "fat" or boundary_eliminated)
                    else "runtime-failed"
                    if runtime["status"] != "pass"
                    else "invalid"
                )
                if not direct or lane_report["status"] != "built":
                    all_static_passed = False
                if direct and lto == "fat":
                    report["claims"]["facade_boundary_eliminated"] = boundary_eliminated
                    report["claims"]["direct_syscall_route_proven"] = True
            except RunnerError as error:
                lane_report["status"] = "invalid"
                lane_report["error"] = str(error)
                all_static_passed = False
            lanes[lane] = lane_report

        stock_target = target_dir / "stock-std-fat"
        stock_binary, stock_build = build_fixture(
            stock_metadata,
            tools,
            stock_target,
            temporary,
            lane="stock-std-fat",
            lto="fat",
            dynamic=True,
            build_std=True,
            candidate_dir=candidate_dir,
        )
        stock_report: dict[str, object] = {"build": stock_build}
        if stock_build["status"] != "built":
            stock_report["status"] = classify_build_failure(command_text(stock_build))
        else:
            try:
                stock_report["inspection"] = artifact_inspection(
                    stock_binary,
                    tools,
                    str(stock_metadata["entry_symbol"]),
                )
                stock_report["runtime_comparison"] = stock_std_comparison(
                    stock_binary,
                    tools,
                    musl_root,
                    stock_target,
                    candidate_dir,
                    stock_metadata["expected_stdout"],
                    args.timeout,
                    temporary,
                )
                comparison = stock_report["runtime_comparison"]
                assert isinstance(comparison, Mapping)
                stock_report["status"] = "built" if comparison["status"] == "pass" else comparison["status"]
            except RunnerError as error:
                stock_report["status"] = "invalid"
                stock_report["error"] = str(error)
        lanes["stock-std-fat"] = stock_report

    report["lanes"] = lanes
    stock_passed = lanes["stock-std-fat"].get("status") == "built" if isinstance(lanes["stock-std-fat"], Mapping) else False
    report["claims"]["stock_std_musl_crabc_raw_output_match"] = bool(stock_passed)
    report["claims"]["stock_std_lto_into_dynamic_libc_proven"] = False
    report["status"] = "built" if all_static_passed and stock_passed else "partial"
    report["result"] = "complete" if report["status"] == "built" else "partial"
    atomic_write_json(report_path, report)
    return str(report["result"]), report_path


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result, report = run(parse_args(argv))
    except RunnerError as error:
        print(f"native-facade-lto: ERROR: {error}", file=sys.stderr)
        return 2
    print(f"native-facade-lto: {result.upper()}: report: {report}")
    # Unsupported, unbuildable, invalid, and runtime-failed target evidence is
    # retained as a report rather than being mistaken for harness setup error.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
