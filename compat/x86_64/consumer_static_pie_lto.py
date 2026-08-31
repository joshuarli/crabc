#!/usr/bin/env python3
"""Run a closed no-std x86 crabc-rs control/full-LTO consumer.

The current x86 lane owns a private Rust CRT object bundle, the selected C
bulk-memory leaf, and a bounded one-member Rust compiler-helper archive. The
pinned Rust toolchain supplies only its exact-hashed no-std ``core`` rlib. The
lane does not yet own the installed libc/loader/sysroot required by stock Rust
``std``. This runner therefore
proves only the largest executable consumer those artifacts honestly admit:
the same cross-crate no-std ``crabc-rs`` source is compiled as native O3 input
and as LLVM linker-plugin input for LLD full LTO, linked through an explicit
closed input list, inspected, and executed natively.  It cannot promote
``consumer.rust-std-lto``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/x86_64/consumer_static_pie_lto_fixture.rs"
HELPER_SOURCE = ROOT / "compat/x86_64/consumer_static_pie_lto_helper.rs"
MEMORY_PROBE = ROOT / "compat/x86_64/libc_memory_probe.rs"
MEMORY_SOURCE = ROOT / "libc/src/c_abi/x86_64/memory.rs"
CORE_CRATE_ROOT = ROOT / "crabc-core" / "src" / "lib.rs"
FACADE_CRATE_ROOT = ROOT / "crabc-rs" / "src" / "lib.rs"
ROUTE_SOURCES = (
    ROOT / "crabc-core/src/process.rs",
    ROOT / "crabc-core/src/io.rs",
    ROOT / "crabc-core/src/syscall_x86_64.rs",
    ROOT / "crabc-core/src/error.rs",
    ROOT / "crabc-rs/src/process_x86_64.rs",
    ROOT / "crabc-rs/src/io.rs",
    ROOT / "crabc-rs/src/fd.rs",
)
CRT_BUILDER = ROOT / "crt/build_x86_64.py"
BUILTINS_BUILDER = ROOT / "builtins/build_x86_64.py"
TARGET = "x86_64-unknown-linux-musl"
TOOLCHAIN = "nightly-2026-07-24"
EXPECTED_STDOUT = b"x86-static-pie-lto:ok\n"
DEFAULT_REPORT = ROOT / "compat/reports/x86_64/consumer-static-pie-lto/latest.json"
HELPER_SYMBOL_FRAGMENT = "crabc_x86_consumer_lto_helper::fingerprint"
FORBIDDEN_RUNTIME_MARKERS = (
    "/opt/musl-",
    "/usr/lib/gcc/",
    "compiler-rt",
    "crtbegin",
    "crtend",
    "ld-linux",
    "libatomic",
    "libc.so.6",
    "libgcc",
    "libssp",
)


class EvidenceError(RuntimeError):
    """The private consumer or its provenance contract was violated."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stream_record(value: bytes, limit: int = 131_072) -> dict[str, object]:
    preview = value[:limit]
    return {
        "byte_length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "preview": preview.decode("utf-8", errors="replace"),
        "preview_truncated": len(preview) != len(value),
    }


def command_record(
    command: Sequence[str],
    *,
    cwd: Path = ROOT,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        return {
            "command": list(command),
            "cwd": str(cwd),
            "returncode": f"OSERROR:{error.errno or 'unknown'}",
            "stdout": stream_record(b""),
            "stderr": stream_record(str(error).encode()),
        }
    return {
        "command": list(command),
        "cwd": str(cwd),
        "returncode": result.returncode,
        "stdout": stream_record(result.stdout),
        "stderr": stream_record(result.stderr),
    }


def command_text(record: Mapping[str, object]) -> str:
    text = ""
    for name in ("stdout", "stderr"):
        stream = record.get(name)
        if isinstance(stream, Mapping) and isinstance(stream.get("preview"), str):
            text += str(stream["preview"])
    return text


def require_success(record: Mapping[str, object], description: str) -> None:
    if record.get("returncode") != 0:
        raise EvidenceError(f"{description} failed:\n{command_text(record)}")


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required tool is unavailable: {name}")
    return path


def rustc_command() -> list[str]:
    return [require_tool("rustup"), "run", TOOLCHAIN, "rustc"]


def deterministic_environment(tool_path: Path) -> dict[str, str]:
    allowed = {
        "PATH": f"{tool_path}:{os.environ.get('PATH', '')}",
        "LC_ALL": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "0",
    }
    for name in ("CARGO_HOME", "RUSTUP_HOME"):
        if name in os.environ:
            allowed[name] = os.environ[name]
    return allowed


def pinned_tools(work: Path) -> tuple[dict[str, str], Path]:
    """Resolve LLVM tools from the pinned Rust toolchain, never ambient GCC."""

    sysroot_record = command_record([*rustc_command(), "--print", "sysroot"])
    require_success(sysroot_record, "pinned rustc sysroot discovery")
    stdout = sysroot_record.get("stdout")
    if not isinstance(stdout, Mapping) or not isinstance(stdout.get("preview"), str):
        raise EvidenceError("pinned rustc sysroot discovery returned no path")
    rust_sysroot = Path(str(stdout["preview"]).strip()).resolve()
    rust_tools = rust_sysroot / "lib/rustlib" / TARGET / "bin"
    shims = work / "pinned-tools"
    shims.mkdir()
    required = {
        "linker": rust_tools / "rust-lld",
        "nm": rust_tools / "llvm-nm",
        "objdump": rust_tools / "llvm-objdump",
        "ar": rust_tools / "llvm-ar",
    }
    for name, path in required.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise EvidenceError(f"pinned Rust LLVM tool is unavailable ({name}): {path}")
    system_readelf = Path(require_tool("readelf")).resolve()
    # The bounded x86 builders use conventional LLVM tool names.  The rustup
    # llvm-tools component ships `rust-lld` and no `llvm-readelf`, so expose
    # exact temporary aliases while retaining their resolved provenance.
    aliases = {
        "ld.lld": required["linker"],
        "llvm-ar": required["ar"],
        "llvm-nm": required["nm"],
        "llvm-objdump": required["objdump"],
        "llvm-readelf": system_readelf,
    }
    for name, target in aliases.items():
        (shims / name).symlink_to(target)
    return {
        "linker": str(shims / "ld.lld"),
        "nm": str(required["nm"]),
        "readelf": str(system_readelf),
        "objdump": str(required["objdump"]),
        "ar": str(required["ar"]),
        "rust_sysroot": str(rust_sysroot),
        "target_libdir": str(rust_sysroot / "lib/rustlib" / TARGET / "lib"),
    }, shims


def resolve_pinned_core(target_libdir: Path) -> Path:
    """Select only the pinned target's no-std core library."""

    candidates = sorted(target_libdir.glob("libcore-*.rlib"))
    if len(candidates) != 1:
        raise EvidenceError(
            f"expected exactly one pinned target libcore, found {len(candidates)} under {target_libdir}"
        )
    return candidates[0]


def closed_link_inputs(
    *,
    crt: Path,
    application: Path,
    helper: Path,
    facade: Path,
    core: Path,
    bitflags: Path,
    toolchain_core: Path,
    memory: Path,
    builtins: Path,
    extras: tuple[Path, ...] = (),
) -> list[Path]:
    """Return the only target inputs admitted by this private executable."""

    if extras:
        raise EvidenceError("private LTO consumer rejects ambient CRT/runtime inputs")
    return [
        crt / "rcrt1.o",
        crt / "crti.o",
        application,
        helper,
        facade,
        core,
        bitflags,
        toolchain_core,
        memory,
        crt / "crtn.o",
        builtins,
    ]


def parse_defined_symbols(output: str) -> set[str]:
    symbols: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and not line.rstrip().endswith(":"):
            symbols.add(fields[-1])
    return symbols


def forbidden_runtime_markers(text: str) -> list[str]:
    lowered = text.lower()
    return sorted(marker for marker in FORBIDDEN_RUNTIME_MARKERS if marker in lowered)


def rust_library_command(
    *,
    crate_name: str,
    source: Path,
    output: Path,
    dependencies: Sequence[tuple[str, Path]] = (),
    linker_plugin_lto: bool,
) -> list[str]:
    command = [
        *rustc_command(),
        "--crate-name", crate_name,
        "--crate-type", "rlib",
        "--edition=2021",
        "--target", TARGET,
        "--emit=link",
        "-C", "panic=abort",
        "-C", "force-unwind-tables=no",
        "-C", "overflow-checks=off",
        "-C", "opt-level=3",
        "-C", "codegen-units=1",
        "-C", "debuginfo=0",
        "-C", "relocation-model=pic",
        "-C", f"metadata=crabc-x86-consumer-{crate_name}-v1",
        "--remap-path-prefix", f"{ROOT}=/crabc",
    ]
    if linker_plugin_lto:
        command.extend(("-C", "linker-plugin-lto=yes"))
    else:
        command.extend(("-C", "embed-bitcode=yes"))
    if dependencies:
        command.extend(("-L", f"dependency={output.parent}"))
        for name, path in dependencies:
            command.extend(("--extern", f"{name}={path}"))
    command.extend((str(source), "-o", str(output)))
    return command


def locked_bitflags_source() -> tuple[Path, dict[str, str]]:
    """Resolve the already-pinned no-std dependency from Cargo's source cache."""

    with (ROOT / "Cargo.lock").open("rb") as stream:
        lock = tomllib.load(stream)
    records = [package for package in lock.get("package", []) if package.get("name") == "bitflags"]
    if len(records) != 1:
        raise EvidenceError("workspace lock must contain exactly one bitflags package")
    record = records[0]
    version = record.get("version")
    checksum = record.get("checksum")
    if not isinstance(version, str) or not isinstance(checksum, str):
        raise EvidenceError("locked bitflags package lacks version/checksum provenance")
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    candidates = sorted((cargo_home / "registry/src").glob(f"*/bitflags-{version}/src/lib.rs"))
    if len(candidates) != 1:
        raise EvidenceError(
            f"expected one cached locked bitflags-{version} source, found {len(candidates)} under {cargo_home}"
        )
    source = candidates[0]
    package_root = source.parents[1]
    manifest = package_root / "Cargo.toml"
    if not manifest.is_file():
        raise EvidenceError(f"cached bitflags source lacks its Cargo manifest: {manifest}")
    checksum_record = package_root / ".cargo-checksum.json"
    return source, {
        "version": version,
        "package_checksum": checksum,
        "source": str(source),
        "source_sha256": sha256(source),
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "manifest": str(manifest),
        "manifest_sha256": sha256(manifest),
        "cargo_checksum_record": str(checksum_record) if checksum_record.is_file() else None,
        "cargo_checksum_record_sha256": sha256(checksum_record) if checksum_record.is_file() else None,
        "features": "default-features=false",
    }


def application_command(
    *,
    output: Path,
    lto: str,
    linker_plugin_lto: bool,
    helper: Path,
    facade: Path,
    core: Path,
) -> list[str]:
    command = [
        *rustc_command(),
        "--crate-name", "crabc_x86_consumer_static_pie_lto",
        "--crate-type", "bin",
        "--edition=2021",
        "--target", TARGET,
        "--emit=obj",
        "-C", "panic=abort",
        "-C", "force-unwind-tables=no",
        "-C", "overflow-checks=off",
        "-C", "opt-level=3",
        "-C", "codegen-units=1",
        "-C", "debuginfo=0",
        "-C", "relocation-model=pic",
        "-C", f"metadata=crabc-x86-consumer-application-{lto}-v1",
    ]
    if linker_plugin_lto:
        command.extend(("-C", "linker-plugin-lto=yes"))
    else:
        command.extend(("-C", "embed-bitcode=yes", "-C", "lto=off"))
    command.extend(
        (
            "--remap-path-prefix", f"{ROOT}=/crabc",
            "-L", f"dependency={output.parent}",
            "--extern", f"crabc_x86_consumer_lto_helper={helper}",
            "--extern", f"crabc_rs={facade}",
            "--extern", f"crabc_core={core}",
            str(FIXTURE),
            "-o", str(output),
        )
    )
    return command


def build_crt(work: Path, environment: Mapping[str, str]) -> tuple[Path, dict[str, object]]:
    primary = work / "crt-primary"
    comparison = work / "crt-comparison"
    first = command_record(
        [sys.executable, str(CRT_BUILDER), "--out-dir", str(primary)],
        environment=environment,
    )
    second = command_record(
        [sys.executable, str(CRT_BUILDER), "--out-dir", str(comparison)],
        environment=environment,
    )
    require_success(first, "primary x86 CRT build")
    require_success(second, "comparison x86 CRT build")
    names = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
    hashes: dict[str, str] = {}
    for name in names:
        if (primary / name).read_bytes() != (comparison / name).read_bytes():
            raise EvidenceError(f"two clean x86 CRT builds diverged: {name}")
        hashes[name] = sha256(primary / name)
    report = json.loads((primary / "objects.json").read_text(encoding="utf-8"))
    if report.get("target") != TARGET or report.get("toolchain") != TOOLCHAIN:
        raise EvidenceError("x86 CRT producer report has an unexpected target/toolchain")
    return primary, {
        "commands": [first, second],
        "target": report.get("target"),
        "toolchain": report.get("toolchain"),
        "two_clean_builds_byte_identical": True,
        "object_sha256": hashes,
        "producer_report_sha256": sha256(primary / "objects.json"),
    }


def build_builtins(work: Path, environment: Mapping[str, str]) -> tuple[Path, dict[str, object]]:
    archive = work / "libcrabc-builtins.a"
    record = command_record(
        [
            sys.executable,
            str(BUILTINS_BUILDER),
            "--output", str(archive),
            "--verify-reproducible",
        ],
        environment=environment,
    )
    require_success(record, "x86 crabc builtins build")
    provenance_path = archive.with_suffix(".a.provenance.json")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("target") != TARGET or provenance.get("reproducible") is not True:
        raise EvidenceError("x86 helper archive lacks reproducible target provenance")
    archive_record = provenance.get("archive")
    if not isinstance(archive_record, Mapping) or archive_record.get("members") != ["crabc-builtins.o"]:
        raise EvidenceError("x86 helper archive is not the closed one-member artifact")
    if "__udivti3" not in archive_record.get("defined_symbols", []):
        raise EvidenceError("x86 helper archive does not define __udivti3")
    return archive, {
        "command": record,
        "archive_sha256": sha256(archive),
        "provenance_sha256": sha256(provenance_path),
        "provenance": provenance,
    }


def build_memory_leaf(
    work: Path,
    environment: Mapping[str, str],
    tools: Mapping[str, str],
) -> tuple[Path, dict[str, object]]:
    """Build the already-selected crabc C bulk-memory leaf as one closed object."""

    primary = work / "crabc-memory.o"
    comparison = work / "crabc-memory-comparison.o"
    commands: list[dict[str, object]] = []
    for output in (primary, comparison):
        command = [
            *rustc_command(),
            "--crate-name", "crabc_x86_consumer_memory",
            "--crate-type", "lib",
            "--edition=2021",
            "--target", TARGET,
            "--emit=obj",
            "-C", "panic=abort",
            "-C", "force-unwind-tables=no",
            "-C", "overflow-checks=off",
            "-C", "opt-level=3",
            "-C", "codegen-units=1",
            "-C", "debuginfo=0",
            "-C", "relocation-model=pic",
            "--remap-path-prefix", f"{ROOT}=/crabc",
            str(MEMORY_PROBE),
            "-o", str(output),
        ]
        record = command_record(command, environment=environment)
        require_success(record, "crabc x86 bulk-memory leaf")
        commands.append(record)
    if primary.read_bytes() != comparison.read_bytes():
        raise EvidenceError("two clean crabc x86 bulk-memory builds diverged")
    defined_text, defined_record = tool_output(
        [tools["nm"], "--defined-only", "--extern-only", str(primary)],
        "bulk-memory defined-symbol inspection",
    )
    undefined_text, undefined_record = tool_output(
        [tools["nm"], "--undefined-only", "--extern-only", str(primary)],
        "bulk-memory undefined-symbol inspection",
    )
    defined = parse_defined_symbols(defined_text)
    expected = {"__memcpy_fwd", "bcmp", "memcmp", "memcpy", "memmove", "memset"}
    if defined != expected or undefined_text.strip():
        raise EvidenceError(
            "crabc x86 bulk-memory object escaped its exact closed symbol surface: "
            f"defined={sorted(defined)}, undefined={undefined_text.strip()!r}"
        )
    return primary, {
        "commands": commands,
        "two_clean_builds_byte_identical": True,
        "path": str(primary),
        "sha256": sha256(primary),
        "byte_length": primary.stat().st_size,
        "defined_symbols": sorted(defined),
        "records": {"defined_symbols": defined_record, "undefined_symbols": undefined_record},
        "sources": {
            str(MEMORY_PROBE.relative_to(ROOT)): sha256(MEMORY_PROBE),
            str(MEMORY_SOURCE.relative_to(ROOT)): sha256(MEMORY_SOURCE),
        },
    }


def build_rust_inputs(
    work: Path,
    environment: Mapping[str, str],
    *,
    name: str,
    linker_plugin_lto: bool,
) -> tuple[dict[str, Path], dict[str, object]]:
    core = work / f"libcrabc_core-{name}.rlib"
    facade = work / f"libcrabc_rs-{name}.rlib"
    helper = work / f"libcrabc_x86_consumer_lto_helper-{name}.rlib"
    bitflags = work / f"libbitflags-{name}.rlib"
    bitflags_source, bitflags_provenance = locked_bitflags_source()
    commands = [
        rust_library_command(
            crate_name="bitflags",
            source=bitflags_source,
            output=bitflags,
            linker_plugin_lto=linker_plugin_lto,
        ),
        rust_library_command(
            crate_name="crabc_core",
            source=CORE_CRATE_ROOT,
            output=core,
            linker_plugin_lto=linker_plugin_lto,
        ),
        rust_library_command(
            crate_name="crabc_rs",
            source=FACADE_CRATE_ROOT,
            output=facade,
            dependencies=(("crabc_core", core), ("bitflags", bitflags)),
            linker_plugin_lto=linker_plugin_lto,
        ),
        rust_library_command(
            crate_name="crabc_x86_consumer_lto_helper",
            source=HELPER_SOURCE,
            output=helper,
            linker_plugin_lto=linker_plugin_lto,
        ),
    ]
    records: list[dict[str, object]] = []
    for command, description in zip(
        commands,
        ("locked bitflags rlib", "crabc-core rlib", "crabc-rs rlib", "consumer helper rlib"),
    ):
        record = command_record(command, environment=environment)
        require_success(record, description)
        records.append(record)
    artifacts = {"bitflags": bitflags, "core": core, "facade": facade, "helper": helper}
    embedded_bitcode = {
        artifact_name: b".llvmbc" in path.read_bytes()
        for artifact_name, path in artifacts.items()
    }
    if not linker_plugin_lto and not all(embedded_bitcode.values()):
        raise EvidenceError(
            f"control Rust inputs lack their auditable embedded bitcode: {embedded_bitcode}"
        )
    return artifacts, {
        "commands": records,
        "locked_existing_dependency": bitflags_provenance,
        "linker_plugin_lto": linker_plugin_lto,
        "embedded_bitcode_sections": embedded_bitcode,
        "artifacts": {
            name: {"path": str(path), "sha256": sha256(path), "byte_length": path.stat().st_size}
            for name, path in artifacts.items()
        },
    }


def tool_output(command: Sequence[str], description: str) -> tuple[str, dict[str, object]]:
    record = command_record(command)
    require_success(record, description)
    return command_text(record), record


def inspect_executable(path: Path, tools: Mapping[str, str]) -> dict[str, object]:
    header, header_record = tool_output([tools["readelf"], "-h", str(path)], "ELF header inspection")
    programs, program_record = tool_output([tools["readelf"], "-lW", str(path)], "program-header inspection")
    dynamic, dynamic_record = tool_output([tools["readelf"], "-dW", str(path)], "dynamic inspection")
    undefined, undefined_record = tool_output(
        [tools["nm"], "--undefined-only", "--extern-only", str(path)],
        "undefined-symbol inspection",
    )
    defined, defined_record = tool_output(
        [tools["nm"], "--defined-only", "--demangle", str(path)],
        "defined-symbol inspection",
    )
    disassembly, disassembly_record = tool_output(
        [tools["objdump"], "-d", "--demangle", str(path)],
        "disassembly inspection",
    )
    combined = "\n".join((header, programs, dynamic, undefined, defined))
    rejected = forbidden_runtime_markers(combined)
    if "Advanced Micro Devices X86-64" not in header or "DYN" not in header:
        raise EvidenceError(f"consumer output is not an x86-64 ET_DYN image: {path}")
    if "INTERP" in programs or "Shared library:" in dynamic or undefined.strip():
        raise EvidenceError(f"consumer output has an interpreter, dependency, or unresolved symbol: {path}")
    if rejected:
        raise EvidenceError(f"consumer output exposes a foreign runtime marker: {rejected}")
    symbols = parse_defined_symbols(defined)
    if "crabc_x86_consumer_lto_route" not in symbols or "__udivti3" not in symbols:
        raise EvidenceError("consumer output lacks its facade route or owned helper anchor")
    if "syscall" not in disassembly:
        raise EvidenceError("consumer output contains no direct x86 syscall instruction")
    return {
        "path": str(path),
        "sha256": sha256(path),
        "byte_length": path.stat().st_size,
        "defined_symbols": sorted(symbols),
        "helper_symbol_present": any(HELPER_SYMBOL_FRAGMENT in symbol for symbol in symbols),
        "records": {
            "header": header_record,
            "program_headers": program_record,
            "dynamic": dynamic_record,
            "undefined_symbols": undefined_record,
            "defined_symbols": defined_record,
            "disassembly": disassembly_record,
        },
    }


def build_lane(
    *,
    name: str,
    lto: str,
    linker_plugin_lto: bool,
    work: Path,
    crt: Path,
    builtins: Path,
    rust_inputs: Mapping[str, Path],
    toolchain_core: Path,
    memory: Path,
    tools: Mapping[str, str],
    environment: Mapping[str, str],
) -> dict[str, object]:
    application = work / f"{name}.o"
    compile_record = command_record(
        application_command(
            output=application,
            lto=lto,
            linker_plugin_lto=linker_plugin_lto,
            helper=rust_inputs["helper"],
            facade=rust_inputs["facade"],
            core=rust_inputs["core"],
        ),
        environment=environment,
    )
    require_success(compile_record, f"{name} application compile")
    executable = work / f"x86-static-pie-{name}"
    link_map = work / f"{name}.map"
    inputs = closed_link_inputs(
        crt=crt,
        application=application,
        helper=rust_inputs["helper"],
        facade=rust_inputs["facade"],
        core=rust_inputs["core"],
        bitflags=rust_inputs["bitflags"],
        toolchain_core=toolchain_core,
        memory=memory,
        builtins=builtins,
    )
    link_command = [
        tools["linker"],
        "-pie",
        "-static",
        "--no-dynamic-linker",
        "--gc-sections",
        "--build-id=none",
        "-z", "noexecstack",
        "-z", "relro",
        "-z", "now",
        "-e", "_start",
        f"-Map={link_map}",
        "--trace-symbol=__udivti3",
    ]
    if linker_plugin_lto:
        link_command.append("--lto-O3")
    link_command.extend((*(str(path) for path in inputs), "-o", str(executable)))
    link_record = command_record(link_command, environment=environment)
    require_success(link_record, f"{name} closed final link")
    link_text = command_text(link_record) + link_map.read_text(encoding="utf-8", errors="replace")
    rejected = forbidden_runtime_markers(link_text)
    if rejected:
        raise EvidenceError(f"{name} link selected a forbidden target runtime: {rejected}")
    if str(builtins) not in command_text(link_record):
        raise EvidenceError(f"{name} link trace does not attribute __udivti3 to the owned archive")
    inspection = inspect_executable(executable, tools)
    executions: list[dict[str, object]] = []
    for _ in range(2):
        record = command_record([str(executable)], environment={"PATH": "/bin:/usr/bin", "LC_ALL": "C"})
        stdout = record["stdout"]
        stderr = record["stderr"]
        passed = (
            record["returncode"] == 0
            and isinstance(stdout, Mapping)
            and stdout.get("sha256") == hashlib.sha256(EXPECTED_STDOUT).hexdigest()
            and stdout.get("byte_length") == len(EXPECTED_STDOUT)
            and isinstance(stderr, Mapping)
            and stderr.get("byte_length") == 0
        )
        record["passed"] = passed
        executions.append(record)
        if not passed:
            raise EvidenceError(f"{name} execution differed from the fixed output contract")
    return {
        "status": "passed",
        "lto": lto,
        "compile": compile_record,
        "application_object": {
            "path": str(application),
            "sha256": sha256(application),
            "byte_length": application.stat().st_size,
        },
        "link": link_record,
        "closed_inputs": [
            {"path": str(path), "sha256": sha256(path), "byte_length": path.stat().st_size}
            for path in inputs
        ],
        "link_map": {"sha256": sha256(link_map), "byte_length": link_map.stat().st_size},
        "inspection": inspection,
        "executions": executions,
    }


def atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run(report_path: Path) -> dict[str, object]:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise EvidenceError(
            f"native Linux/x86-64 is required, got {platform.system()}/{platform.machine()}"
        )
    version = command_record([*rustc_command(), "-Vv"])
    require_success(version, "pinned rustc identity")
    if f"host: {TARGET}" not in command_text(version):
        raise EvidenceError(f"pinned rustc host is not {TARGET}")
    with tempfile.TemporaryDirectory(prefix="crabc-x86-static-pie-lto-") as temporary:
        work = Path(temporary)
        tools, tool_path = pinned_tools(work)
        environment = deterministic_environment(tool_path)
        toolchain_core = resolve_pinned_core(Path(tools["target_libdir"]))
        crt, crt_record = build_crt(work, environment)
        builtins, builtins_record = build_builtins(work, environment)
        memory, memory_record = build_memory_leaf(work, environment, tools)
        control_inputs, control_rust_record = build_rust_inputs(
            work,
            environment,
            name="control-o3",
            linker_plugin_lto=False,
        )
        lto_inputs, lto_rust_record = build_rust_inputs(
            work,
            environment,
            name="full-lto",
            linker_plugin_lto=True,
        )
        rust_inputs_by_lane = {"control-o3": control_inputs, "full-lto": lto_inputs}
        lanes = {
            name: build_lane(
                name=name,
                lto=lto,
                linker_plugin_lto=linker_plugin_lto,
                work=work,
                crt=crt,
                builtins=builtins,
                rust_inputs=rust_inputs_by_lane[name],
                toolchain_core=toolchain_core,
                memory=memory,
                tools=tools,
                environment=environment,
            )
            for name, lto, linker_plugin_lto in (
                ("control-o3", "off", False),
                ("full-lto", "full-linker-plugin", True),
            )
        }
        control = lanes["control-o3"]["inspection"]
        optimized = lanes["full-lto"]["inspection"]
        assert isinstance(control, Mapping) and isinstance(optimized, Mapping)
        if control.get("helper_symbol_present") is not True:
            raise EvidenceError("control lane did not retain the cross-crate helper boundary")
        if optimized.get("helper_symbol_present") is not False:
            raise EvidenceError("full-LTO lane did not internalize the cross-crate helper boundary")
        if control.get("sha256") == optimized.get("sha256"):
            raise EvidenceError("control and full-LTO final artifacts are byte-identical")
        report = {
            "schema": "crabc.x86_64-consumer-static-pie-lto/v1",
            "status": "passed",
            "target": TARGET,
            "toolchain": TOOLCHAIN,
            "scope": (
                "private no-std crabc-rs control/full-linker-plugin-LTO executable through the current "
                "Rust CRT/pinned-core/owned-memory/builtins boundary; not stock std, libc, loader, sysroot, source-build, "
                "family completion, promotion, or public support"
            ),
            "claims": {
                "native_execution": True,
                "cross_crate_full_lto": True,
                "direct_crabc_rs_facade": True,
                "closed_final_link_inputs": True,
                "owned_crt_and_builtins": True,
                "owned_memory_leaf": True,
                "pinned_toolchain_core": True,
                "ambient_target_libc": False,
                "ambient_crt": False,
                "ambient_loader": False,
                "ambient_compiler_runtime": False,
                "stock_rust_std": False,
                "owned_sysroot": False,
                "dynamic_runtime": False,
                "source_build": False,
                "promotion": False,
                "public_support": False,
            },
            "sources": {
                "compat/x86_64/consumer_static_pie_lto.py": sha256(
                    ROOT / "compat/x86_64/consumer_static_pie_lto.py"
                ),
                str(FIXTURE.relative_to(ROOT)): sha256(FIXTURE),
                str(HELPER_SOURCE.relative_to(ROOT)): sha256(HELPER_SOURCE),
                "Cargo.lock": sha256(ROOT / "Cargo.lock"),
                "rust-toolchain.toml": sha256(ROOT / "rust-toolchain.toml"),
                **{
                    str(source.relative_to(ROOT)): sha256(source)
                    for source in ROUTE_SOURCES
                },
            },
            "rustc": version,
            "tools": {
                name: {
                    "path": str(Path(tools[name]).resolve()),
                    "sha256": sha256(Path(tools[name]).resolve()),
                }
                for name in ("linker", "nm", "readelf", "objdump", "ar")
            },
            "crt": crt_record,
            "builtins": builtins_record,
            "memory": memory_record,
            "pinned_toolchain_core": {
                "path": str(toolchain_core),
                "sha256": sha256(toolchain_core),
                "byte_length": toolchain_core.stat().st_size,
                "target_libdir": tools["target_libdir"],
            },
            "rust_inputs": {
                "control-o3": control_rust_record,
                "full-lto": lto_rust_record,
            },
            "lanes": lanes,
            "comparison": {
                "same_source_and_owned_runtime_inputs": True,
                "control_helper_symbol_present": True,
                "full_lto_helper_symbol_present": False,
                "raw_status_stdout_stderr_match": True,
                "normalization": "none",
            },
        }
    atomic_write(report_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        report = run(arguments.report.expanduser().resolve())
    except EvidenceError as error:
        print(f"x86 static-PIE Rust LTO consumer: ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "x86 static-PIE Rust LTO consumer: PASS "
        "(no-std crabc-rs O3/full LTO; closed CRT/libcore/memory/builtins; non-promoting)"
    )
    print(f"report: {arguments.report.expanduser().resolve()}")
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
