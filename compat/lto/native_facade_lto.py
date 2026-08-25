#!/usr/bin/env python3
"""Collect bounded native-facade crabc-rs LTO evidence.

This is a focused Linux/AArch64 fixture, separate from ``run.py``'s older
four-configuration experiment. The two native-facade candidate lanes are
normal Cargo applications whose manifests are supplied explicitly (and
default to the fixture manifest). They link through the installed
``target/crabc-sysroot/bin/crabc-cc`` driver: that driver's Rust CRT objects,
``libc.so``, compiler-helper archive, and canonical interpreter are the only
candidate C-runtime boundary. Fat LTO is requested for the application and
its Rust path dependencies, then the resulting ELF is checked for the two
representative direct syscall paths used by the fixture: ``getpid`` (172) and
``write`` (64).

The optional stock-``std`` lane remains a separately labelled pinned-musl
oracle. Its musl target link and patched musl/crabc runtime comparison do not
contribute candidate CRT/sysroot provenance and must never be mistaken for a
native-facade candidate lane.

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
import contextlib
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
from typing import Iterator, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
LTO_ROOT = Path(__file__).resolve().parent
# The fixture is deliberately selected through its manifest.  A caller
# may use --manifest for a companion fixture kept under another directory.
DEFAULT_MANIFEST = LTO_ROOT / "native-facade-lto-fixture/Cargo.toml"
DEFAULT_STOCK_STD_MANIFEST = LTO_ROOT / "native-std-lto-fixture/Cargo.toml"
DEFAULT_REPORT = ROOT / "compat/reports/lto/native-facade/latest.json"
DEFAULT_SYSROOT = ROOT / "target/crabc-sysroot"
TARGET = "aarch64-unknown-linux-musl"
TOOLCHAIN = "nightly-2026-07-24"
MUSL_VERSION = "1.2.6"
MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
CANONICAL_INTERPRETER = "/lib/ld-crabc-aarch64.so.1"
OWNED_SYSROOT_RUNTIME = "owned-crabc-sysroot"
MUSL_ORACLE_RUNTIME = "pinned-musl-oracle"

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
            "CRABC_NATIVE_FACADE_LTO_FIXTURE": "aarch64-native-facade",
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


def rustflags(
    *,
    lto: str,
    dynamic: bool,
    no_start_files: bool,
    runtime: str,
    sysroot: Path | None = None,
) -> str:
    """Return the complete optimization and explicitly selected runtime contract."""

    flags = [
        "-C opt-level=3",
        "-C codegen-units=1",
        "-C panic=abort",
        f"-C lto={lto}",
        "-C embed-bitcode=yes",
        f"-C target-feature={'-' if dynamic else '+'}crt-static",
    ]
    if runtime == OWNED_SYSROOT_RUNTIME:
        if sysroot is None:
            raise RunnerError("owned-sysroot Rust flags require an installed sysroot")
        # Rust's built-in musl target otherwise selects its self-contained
        # CRT/libc/GCC support path. The installed driver owns CRT selection;
        # these explicit libraries satisfy Cargo's -nodefaultlibs final link
        # with only the installed crabc runtime inputs.
        owned_lib = sysroot / "usr/lib"
        flags.extend(
            (
                "-C link-self-contained=no",
                f"-C link-arg=-L{owned_lib}",
                "-C link-arg=-lc",
                "-C link-arg=-l:libcrabc-builtins.a",
            )
        )
    elif runtime == MUSL_ORACLE_RUNTIME:
        # This is intentionally retained only for the separately named stock
        # std oracle lane. Candidate native-facade lanes must not reach here.
        flags.extend(
            (
                "-C link-arg=-L/usr/lib",
                "-C link-arg=--target=aarch64-unknown-linux-musl",
                f"-C link-arg=--sysroot=/opt/musl-{MUSL_VERSION}",
                "-C link-arg=-fuse-ld=lld",
            )
        )
    else:
        raise RunnerError(f"unknown native-facade runtime contract: {runtime}")
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


def common_capability_reasons(
    metadata: Mapping[str, object],
    tools: Mapping[str, str],
    attempts: Mapping[str, object],
    *,
    required_tools: Sequence[str],
) -> list[str]:
    reasons: list[str] = []
    if platform.system() != "Linux":
        reasons.append(f"requires Linux, got {platform.system()}")
    if platform.machine().lower() not in {"aarch64", "arm64"}:
        reasons.append(f"requires native AArch64, got {platform.machine()!r}")
    for name in required_tools:
        if name not in tools:
            reasons.append(f"required tool unavailable: {attempts.get(name)}")
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
    return reasons


def owned_sysroot_reasons(sysroot: Path) -> list[str]:
    """Reject an incomplete or unproven installed tree before a candidate build."""

    reasons: list[str] = []
    if not sysroot.is_dir():
        return [f"owned crabc sysroot is unavailable: {sysroot}"]
    manifest_path = sysroot / "share/crabc/manifest.json"
    purity_path = sysroot / "share/crabc/purity.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        reasons.append(f"owned crabc sysroot manifest is unavailable or invalid: {manifest_path}: {error}")
        manifest = None
    if isinstance(manifest, Mapping):
        if manifest.get("target") != TARGET:
            reasons.append(f"owned crabc sysroot has unexpected target: {manifest.get('target')!r}")
        if manifest.get("canonical_interpreter") != CANONICAL_INTERPRETER:
            reasons.append("owned crabc sysroot does not select the canonical crabc interpreter")
    try:
        purity = json.loads(purity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        reasons.append(f"owned crabc sysroot purity record is unavailable or invalid: {purity_path}: {error}")
        purity = None
    if isinstance(purity, Mapping) and purity.get("crt_sysroot_pure_rust") is not True:
        reasons.append("owned crabc sysroot does not pass its CRT/sysroot purity contract")
    for path in (
        sysroot / "bin/crabc-cc",
        sysroot / "lib/ld-crabc-aarch64.so.1",
        sysroot / "usr/lib/libc.so",
        sysroot / "usr/lib/libc.a",
        sysroot / "usr/lib/libcrabc-builtins.a",
        *(sysroot / "usr/lib" / name for name in ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")),
    ):
        if not path.is_file():
            reasons.append(f"owned crabc sysroot runtime input is unavailable: {path}")
    driver = sysroot / "bin/crabc-cc"
    if driver.is_file() and not os.access(driver, os.X_OK):
        reasons.append(f"owned crabc sysroot driver is not executable: {driver}")
    return reasons


def candidate_capability_reasons(
    metadata: Mapping[str, object],
    tools: Mapping[str, str],
    attempts: Mapping[str, object],
    sysroot: Path,
) -> list[str]:
    reasons = common_capability_reasons(
        metadata,
        tools,
        attempts,
        required_tools=("cargo", "rustc", "rustup", "llvm_nm", "readelf", "objdump", "file"),
    )
    reasons.extend(owned_sysroot_reasons(sysroot))
    if platform.system() == "Linux" and platform.machine().lower() in {"aarch64", "arm64"} and os.geteuid() != 0:
        reasons.append("candidate runtime needs root to stage the absent canonical crabc interpreter")
    return reasons


def musl_oracle_capability_reasons(
    metadata: Mapping[str, object],
    tools: Mapping[str, str],
    attempts: Mapping[str, object],
    musl_root: Path,
) -> list[str]:
    """Keep the stock-std musl comparison explicitly outside candidate provenance."""

    reasons = common_capability_reasons(
        metadata,
        tools,
        attempts,
        required_tools=("cargo", "rustc", "rustup", "musl_gcc", "clang", "llvm_nm", "readelf", "objdump", "file"),
    )
    if musl_root.name != f"musl-{MUSL_VERSION}":
        reasons.append(f"musl oracle root must name pinned musl-{MUSL_VERSION}: {musl_root}")
    for path in (
        musl_root / "include",
        musl_root / "lib/libc.so",
        musl_root / "lib/libc.a",
        musl_root / "lib/ld-musl-aarch64.so.1",
    ):
        if not path.exists():
            reasons.append(f"pinned musl oracle artifact unavailable: {path}")
    musl_gcc = tools.get("musl_gcc")
    if musl_gcc:
        wrapper = Path(musl_gcc)
        try:
            wrapper_text = wrapper.read_text(encoding="utf-8")
        except OSError:
            wrapper_text = ""
        if f"/opt/musl-{MUSL_VERSION}" not in wrapper_text:
            reasons.append(f"musl-gcc is not the pinned oracle wrapper: {wrapper}")
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


def elf_interpreter(readelf_text: str) -> str | None:
    match = re.search(r"Requesting program interpreter:\s*([^\]\s]+)", readelf_text)
    return match.group(1) if match is not None else None


def elf_needed_libraries(readelf_text: str) -> list[str]:
    return re.findall(r"Shared library:\s*\[([^\]]+)\]", readelf_text)


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
    *,
    expected_interpreter: str | None,
    runtime: str,
) -> dict[str, object]:
    records: dict[str, object] = {}
    file_record = command_record([tools["file"], str(binary)])
    nm_record = command_record([tools["llvm_nm"], "-a", "-C", str(binary)], preview_limit=2_000_000)
    readelf_record = command_record(
        [tools["readelf"], "-h", "-l", "-S", "-d", str(binary)], preview_limit=2_000_000
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
    observed_interpreter = elf_interpreter(readelf_text)
    if expected_interpreter is not None and observed_interpreter != expected_interpreter:
        raise RunnerError(
            "fixture interpreter does not match its runtime contract: "
            f"expected {expected_interpreter!r}, observed {observed_interpreter!r}"
        )
    needed_libraries = elf_needed_libraries(readelf_text)
    if runtime == OWNED_SYSROOT_RUNTIME:
        forbidden_needed = [
            name
            for name in needed_libraries
            if any(marker in name.lower() for marker in ("musl", "gcc", "atomic", "ssp", "compiler_rt"))
        ]
        if forbidden_needed:
            raise RunnerError(
                "candidate ELF retains a foreign target runtime dependency: " + ", ".join(forbidden_needed)
            )
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
            "runtime_contract": runtime,
            "interpreter": observed_interpreter,
            "expected_interpreter": expected_interpreter,
            "interpreter_matches_contract": observed_interpreter == expected_interpreter,
            "dynamic_needed_libraries": needed_libraries,
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
    runtime: str,
    sysroot: Path | None = None,
) -> dict[str, str]:
    environment = dict(os.environ)
    for key in tuple(environment):
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"} or key.startswith(
            "CARGO_TARGET_"
        ):
            environment.pop(key, None)
    flags = rustflags(
        lto=lto,
        dynamic=dynamic,
        no_start_files=no_start_files,
        runtime=runtime,
        sysroot=sysroot,
    )
    environment.update(
        {
            "CARGO_TARGET_DIR": str(target_dir),
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": linker,
            "RUSTFLAGS": flags,
        }
    )
    return environment


def write_linker_recorder(temporary: Path, driver: Path, lane: str) -> tuple[Path, Path]:
    """Create a transparent Cargo-link argv recorder around the sealed driver.

    Rust's final link argv is otherwise only compiler diagnostic text. Recording
    it lets the report reject an attempted musl, self-contained, or GCC target
    runtime selection rather than inferring purity from the final ELF alone.
    The wrapper only records and ``execv``s the installed ``crabc-cc`` driver.
    """

    record = temporary / f"{lane}-cargo-linker.jsonl"
    wrapper = temporary / f"{lane}-cargo-linker.py"
    wrapper.write_text(
        "#!" + sys.executable + "\n"
        "from __future__ import annotations\n"
        "import json\n"
        "import os\n"
        "import shlex\n"
        "import sys\n"
        f"_DRIVER = {str(driver)!r}\n"
        f"_RECORD = {str(record)!r}\n"
        "_argv = sys.argv[1:]\n"
        "_response_files = {}\n"
        "for _argument in _argv:\n"
        "    if not _argument.startswith('@'):\n"
        "        continue\n"
        "    try:\n"
        "        with open(_argument[1:], encoding='utf-8') as _response:\n"
        "            _response_files[_argument] = shlex.split(_response.read())\n"
        "    except (OSError, ValueError):\n"
        "        _response_files[_argument] = None\n"
        "with open(_RECORD, 'a', encoding='utf-8') as _stream:\n"
        "    _stream.write(json.dumps({'argv': _argv, 'response_files': _response_files}) + '\\n')\n"
        "os.execv(_DRIVER, [_DRIVER, *_argv])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper, record


def cargo_linker_argument_audit(record: Path) -> dict[str, object]:
    """Classify actual Cargo linker arguments without pretending to trace LLD."""

    invocations: list[dict[str, object]] = []
    if record.is_file():
        for line in record.read_text(encoding="utf-8").splitlines():
            try:
                arguments = json.loads(line)
            except json.JSONDecodeError as error:
                raise RunnerError(f"invalid Cargo linker record: {record}: {error}") from error
            # Accept the original list form so the host-only parser contract
            # remains backwards compatible with historical diagnostic records.
            if isinstance(arguments, list):
                invocation = {"argv": arguments, "response_files": {}}
            elif isinstance(arguments, Mapping):
                invocation = dict(arguments)
            else:
                raise RunnerError(f"invalid Cargo linker argv in record: {record}")
            argv = invocation.get("argv")
            response_files = invocation.get("response_files")
            if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
                raise RunnerError(f"invalid Cargo linker argv in record: {record}")
            if not isinstance(response_files, Mapping) or not all(isinstance(key, str) for key in response_files):
                raise RunnerError(f"invalid Cargo linker response-file record: {record}")
            for value in response_files.values():
                if value is not None and (not isinstance(value, list) or not all(isinstance(item, str) for item in value)):
                    raise RunnerError(f"invalid Cargo linker response-file arguments: {record}")
            invocations.append({"argv": argv, "response_files": dict(response_files)})
    forbidden_markers = (
        "/opt/musl-",
        "/usr/lib/gcc/",
        "crtbegin",
        "crtend",
        "-lgcc",
        "libgcc",
        "libatomic",
        "libssp",
        "compiler-rt",
        "self-contained",
    )
    forbidden: list[str] = []
    for invocation in invocations:
        argv = invocation["argv"]
        response_files = invocation["response_files"]
        assert isinstance(argv, list) and isinstance(response_files, Mapping)
        expanded_response_arguments = [
            item
            for value in response_files.values()
            if isinstance(value, list)
            for item in value
        ]
        for argument in [*argv, *expanded_response_arguments]:
            lowered = argument.lower()
            if any(marker in lowered for marker in forbidden_markers):
                forbidden.append(argument)
    return {
        "status": "passed" if invocations and not forbidden else "rejected" if forbidden else "unverified",
        "scope": (
            "Cargo-to-sealed-driver argv only; the installed driver owns final CRT/library selection "
            "and this is not an LLD resolved-input trace."
        ),
        "invocation_count": len(invocations),
        "invocations": invocations,
        "forbidden_target_runtime_arguments": forbidden,
        "forbidden_markers": list(forbidden_markers),
    }


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
    runtime: str,
    sysroot: Path | None = None,
) -> tuple[Path, dict[str, object]]:
    manifest = metadata["manifest"]
    lockfile = metadata["lockfile"]
    default_binary_name = metadata["binary_name"]
    assert isinstance(manifest, Path) and isinstance(lockfile, Path) and isinstance(default_binary_name, str)
    binary_name = binary_name or default_binary_name
    if runtime == OWNED_SYSROOT_RUNTIME:
        if sysroot is None:
            raise RunnerError("candidate fixture build requires an owned crabc sysroot")
        sealed_driver = sysroot / "bin/crabc-cc"
        linker_path, linker_record = write_linker_recorder(temporary, sealed_driver, lane)
        linker = str(linker_path)
    elif runtime == MUSL_ORACLE_RUNTIME:
        sealed_driver = None
        linker_record = None
        # The retained stock-std oracle still needs clang/lld for its existing
        # fat-LTO `--target`/`--sysroot` contract. Keep that musl-only choice
        # separate from the candidate driver's owned-runtime contract.
        linker = tools["clang"] if lto == "fat" else tools["musl_gcc"]
    else:
        raise RunnerError(f"unknown fixture runtime contract: {runtime}")
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
        # The fixture's C ABI main still needs startup. In candidate lanes the
        # sealed installed driver owns that choice; Rust's self-contained CRT
        # is disabled by `link-self-contained=no` in `rustflags` above.
        no_start_files=False,
        runtime=runtime,
        sysroot=sysroot,
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
        "runtime_contract": runtime,
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
            "rust_link_self_contained": "no" if runtime == OWNED_SYSROOT_RUNTIME else "target-default",
        },
    }
    if sealed_driver is not None:
        build["sealed_driver"] = str(sealed_driver)
        build["owned_sysroot"] = str(sysroot)
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
    if linker_record is not None:
        linker_audit = cargo_linker_argument_audit(linker_record)
        build["cargo_linker_argument_audit"] = linker_audit
        if linker_audit["status"] != "passed":
            return binary, {
                **build,
                "status": "invalid",
                "reason": "Cargo requested a foreign or self-contained target runtime input",
            }
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


def owned_sysroot_evidence(sysroot: Path) -> dict[str, object]:
    """Record the installed candidate inputs selected before Cargo starts."""

    manifest = sysroot / "share/crabc/manifest.json"
    purity = sysroot / "share/crabc/purity.json"
    runtime_paths = {
        "driver": sysroot / "bin/crabc-cc",
        "loader": sysroot / "lib/ld-crabc-aarch64.so.1",
        "libc_shared": sysroot / "usr/lib/libc.so",
        "libc_static": sysroot / "usr/lib/libc.a",
        "compiler_helpers": sysroot / "usr/lib/libcrabc-builtins.a",
        "crt1": sysroot / "usr/lib/crt1.o",
        "Scrt1": sysroot / "usr/lib/Scrt1.o",
        "rcrt1": sysroot / "usr/lib/rcrt1.o",
        "crti": sysroot / "usr/lib/crti.o",
        "crtn": sysroot / "usr/lib/crtn.o",
    }
    return {
        "runtime_contract": OWNED_SYSROOT_RUNTIME,
        "sysroot": str(sysroot),
        "manifest": {"path": str(manifest), "sha256": sha256_file(manifest)},
        "purity": {"path": str(purity), "sha256": sha256_file(purity)},
        "canonical_interpreter": CANONICAL_INTERPRETER,
        "runtime_inputs": {
            name: {"path": str(path), "sha256": sha256_file(path)} for name, path in runtime_paths.items()
        },
        "forbidden_candidate_inputs": ["musl CRT", "musl libc", "GCC target runtime", "Rust self-contained CRT"],
    }


@contextlib.contextmanager
def staged_canonical_loader(sysroot: Path) -> Iterator[None]:
    """Temporarily make only the owned canonical interpreter kernel-resolvable."""

    if os.geteuid() != 0:
        raise RunnerError("candidate runtime needs root to stage the absent canonical crabc interpreter")
    source = sysroot / "lib/ld-crabc-aarch64.so.1"
    canonical = Path(CANONICAL_INTERPRETER)
    if canonical.exists() or canonical.is_symlink():
        raise RunnerError(f"refusing to replace existing canonical loader: {canonical}")
    canonical.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, canonical)
    canonical.chmod(canonical.stat().st_mode | 0o100)
    try:
        yield
    finally:
        if canonical.exists() and sha256_file(canonical) == sha256_file(source):
            canonical.unlink()
        elif canonical.exists():
            raise RunnerError(f"staged canonical loader changed unexpectedly and was retained: {canonical}")


def owned_runtime_run(binary: Path, sysroot: Path, expected_stdout: bytes, timeout: float) -> dict[str, object]:
    """Run a candidate ELF through the kernel-visible owned loader and libc only."""

    environment = sanitize_environment()
    environment["LD_LIBRARY_PATH"] = str(sysroot / "usr/lib")
    with staged_canonical_loader(sysroot):
        result = run_binary(binary, expected_stdout, timeout, environment=environment)
    result.update(
        {
            "runtime": OWNED_SYSROOT_RUNTIME,
            "loader": str(sysroot / "lib/ld-crabc-aarch64.so.1"),
            "loader_sha256": sha256_file(sysroot / "lib/ld-crabc-aarch64.so.1"),
            "libc": str(sysroot / "usr/lib/libc.so"),
            "libc_sha256": sha256_file(sysroot / "usr/lib/libc.so"),
            "status": "pass"
            if result["status"] == 0 and result["stdout_exact"] and result["stderr_empty"]
            else "fail",
        }
    )
    return result


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


def stock_std_musl_oracle_comparison(
    binary: Path,
    tools: Mapping[str, str],
    musl_root: Path,
    sysroot: Path,
    expected_stdout: bytes,
    timeout: float,
    temporary: Path,
) -> dict[str, object]:
    """Run the separately labelled musl-linked stock-std oracle comparison."""

    del tools  # Retained in the report's top-level tool provenance.
    candidate_loader = sysroot / "lib/ld-crabc-aarch64.so.1"
    candidate_libc = sysroot / "usr/lib/libc.so"
    if not candidate_loader.is_file() or not candidate_libc.is_file():
        return {
            "status": "unsupported",
            "reason": "owned crabc dynamic interpreter and libc are required for the stock-std oracle comparison",
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
    reference["runtime"] = "pinned-musl-oracle"
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
    candidate["runtime"] = "owned-crabc-sysroot-runtime"
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
        "lane_class": "musl-oracle",
        "candidate_crt_or_sysroot_provenance": False,
        "scope": (
            "The binary was linked through pinned musl for a stock-std runtime oracle; "
            "only its staged crabc runtime observation consumes the owned sysroot."
        ),
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
    parser.add_argument(
        "--sysroot",
        type=Path,
        default=Path(os.environ.get("CRABC_NATIVE_FACADE_LTO_SYSROOT", DEFAULT_SYSROOT)),
        help="installed crabc sysroot used by the candidate native-facade lanes",
    )
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
    sysroot = args.sysroot.expanduser().resolve()
    report_path = args.report.expanduser().resolve()
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
        "lane_groups": {
            "candidate_native_facade": ["control-o3", "fat-lto"],
            "separate_musl_oracle": ["stock-std-fat"],
        },
        "claims": {
            "lto_requested": True,
            "assembly_byte_exactness_claimed": False,
            "whole_program_lto_proven": False,
            "facade_boundary_eliminated": False,
            "direct_syscall_route_proven": False,
            "cross_boundary_unique_inlining_proven": False,
            "candidate_lanes_use_owned_sysroot": False,
            "stock_std_oracle_contributes_candidate_crt_sysroot_provenance": False,
        },
    }
    target_dir = args.target_dir.expanduser().resolve()
    candidate_reasons = candidate_capability_reasons(metadata, tools, attempts, sysroot)
    oracle_reasons = musl_oracle_capability_reasons(stock_metadata, tools, attempts, musl_root)
    oracle_reasons.extend(
        reason
        for reason in owned_sysroot_reasons(sysroot)
        if reason not in oracle_reasons
    )
    report["capability_reasons"] = {
        "candidate_native_facade": candidate_reasons,
        "separate_musl_oracle": oracle_reasons,
    }
    report["inputs"] = {
        "target_dir": str(target_dir),
        "candidate_owned_sysroot": owned_sysroot_evidence(sysroot) if not owned_sysroot_reasons(sysroot) else {
            "runtime_contract": OWNED_SYSROOT_RUNTIME,
            "sysroot": str(sysroot),
            "status": "unavailable",
        },
        "separate_musl_oracle_root": str(musl_root),
    }
    lanes: dict[str, object] = {}
    candidate_passed = not candidate_reasons
    with tempfile.TemporaryDirectory(prefix="crabc-native-facade-lto-") as temporary_name:
        temporary = Path(temporary_name)
        for lane, lto in (("control-o3", "off"), ("fat-lto", "fat")):
            if candidate_reasons:
                lanes[lane] = {
                    "lane_class": "candidate-native-facade",
                    "runtime_contract": OWNED_SYSROOT_RUNTIME,
                    "candidate_crt_sysroot_provenance": True,
                    "status": "unsupported",
                    "capability_reasons": candidate_reasons,
                }
                continue
            lane_target = target_dir / lane
            binary, build = build_fixture(
                metadata,
                tools,
                lane_target,
                temporary,
                lane=lane,
                lto=lto,
                dynamic=True,
                runtime=OWNED_SYSROOT_RUNTIME,
                sysroot=sysroot,
            )
            lane_report: dict[str, object] = {
                "lane_class": "candidate-native-facade",
                "runtime_contract": OWNED_SYSROOT_RUNTIME,
                "candidate_crt_sysroot_provenance": True,
                "build": build,
            }
            if build["status"] != "built":
                lane_report["status"] = (
                    build["status"] if build["status"] == "invalid" else classify_build_failure(command_text(build))
                )
                candidate_passed = False
                lanes[lane] = lane_report
                continue
            try:
                inspection = artifact_inspection(
                    binary,
                    tools,
                    str(metadata["entry_symbol"]),
                    expected_interpreter=CANONICAL_INTERPRETER,
                    runtime=OWNED_SYSROOT_RUNTIME,
                )
                lane_report["inspection"] = inspection
                runtime = owned_runtime_run(
                    binary,
                    sysroot,
                    metadata["expected_stdout"],
                    args.timeout,
                )
                lane_report["runtime"] = runtime
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
                    candidate_passed = False
                if direct and lto == "fat":
                    report["claims"]["facade_boundary_eliminated"] = boundary_eliminated
                    report["claims"]["direct_syscall_route_proven"] = True
            except RunnerError as error:
                lane_report["status"] = "invalid"
                lane_report["error"] = str(error)
                candidate_passed = False
            lanes[lane] = lane_report

        if oracle_reasons:
            stock_report: dict[str, object] = {
                "lane_class": "separate-musl-oracle",
                "runtime_contract": MUSL_ORACLE_RUNTIME,
                "candidate_crt_sysroot_provenance": False,
                "status": "unsupported",
                "capability_reasons": oracle_reasons,
            }
        else:
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
                runtime=MUSL_ORACLE_RUNTIME,
            )
            stock_report = {
                "lane_class": "separate-musl-oracle",
                "runtime_contract": MUSL_ORACLE_RUNTIME,
                "candidate_crt_sysroot_provenance": False,
                "build": stock_build,
            }
            if stock_build["status"] != "built":
                stock_report["status"] = classify_build_failure(command_text(stock_build))
            else:
                try:
                    stock_report["inspection"] = artifact_inspection(
                        stock_binary,
                        tools,
                        str(stock_metadata["entry_symbol"]),
                        expected_interpreter="/lib/ld-musl-aarch64.so.1",
                        runtime=MUSL_ORACLE_RUNTIME,
                    )
                    stock_report["runtime_comparison"] = stock_std_musl_oracle_comparison(
                        stock_binary,
                        tools,
                        musl_root,
                        sysroot,
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
    report["claims"]["candidate_lanes_use_owned_sysroot"] = bool(candidate_passed)
    report["status"] = "built" if candidate_passed else "partial"
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
