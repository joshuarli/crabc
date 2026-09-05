#!/usr/bin/env python3
"""Build pinned Lua through owned crabc application sysroots.

The established AArch64 lane builds a dynamic Lua graph.  The native x86-64
lane is intentionally separate: it builds complete ET_EXEC and static-PIE Lua
programs through the sealed installed static driver, and compares them with
separately linked pinned-musl static programs.  In particular, the x86 oracle
never launches candidate bytes under a different loader.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import resource
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
LUA_ROOT = Path(__file__).resolve().parent
MANIFEST = LUA_ROOT / "manifest.toml"
FIXTURES = LUA_ROOT / "fixtures"
CACHE = LUA_ROOT / ".cache"
DEFAULT_REPORT = ROOT / "compat/reports/lua/latest.json"
DEFAULT_X86_STATIC_REPORT = ROOT / "compat/reports/lua/x86_64-static-latest.json"
MUSL_ROOT = Path("/opt/musl-1.2.6")
SYSROOT_TOOL = ROOT / "scripts/crabc_sysroot.py"
DEFAULT_SYSROOT = ROOT / "target/crabc-sysroot"
DEFAULT_X86_STATIC_WORK_ROOT = ROOT / ".work/x86_64/lua-static-source-build"
X86_MUSL_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
DEFAULT_JOBS = 4
MAX_JOBS = 8
CORE_SOURCES = (
    "lapi.c",
    "lcode.c",
    "lctype.c",
    "ldebug.c",
    "ldo.c",
    "ldump.c",
    "lfunc.c",
    "lgc.c",
    "llex.c",
    "lmem.c",
    "lobject.c",
    "lopcodes.c",
    "lparser.c",
    "lstate.c",
    "lstring.c",
    "ltable.c",
    "ltm.c",
    "lundump.c",
    "lvm.c",
    "lzio.c",
)
LIB_SOURCES = (
    "lauxlib.c",
    "lbaselib.c",
    "lcorolib.c",
    "ldblib.c",
    "liolib.c",
    "lmathlib.c",
    "loadlib.c",
    "loslib.c",
    "lstrlib.c",
    "ltablib.c",
    "lutf8lib.c",
    "linit.c",
)


class RunnerError(RuntimeError):
    """A setup, isolation, or build-contract error."""


SPEC = importlib.util.spec_from_file_location("crabc_lua_sysroot", SYSROOT_TOOL)
assert SPEC is not None and SPEC.loader is not None
SYSROOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SYSROOT
SPEC.loader.exec_module(SYSROOT)


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    status: int | str
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


@dataclasses.dataclass(frozen=True)
class StaticLuaMode:
    """One sealed-driver mode exercised by the native Lua source build."""

    identifier: str
    driver_flag: str
    driver_id: str
    elf_type: str
    crt_object: str


STATIC_ET_EXEC = StaticLuaMode("static-et-exec", "-static", "static-et-exec", "EXEC", "crt1.o")
STATIC_PIE = StaticLuaMode("static-pie", "-static-pie", "static-pie", "DYN", "rcrt1.o")
STATIC_LUA_MODES = {mode.identifier: mode for mode in (STATIC_ET_EXEC, STATIC_PIE)}


def static_reference_mode() -> StaticLuaMode:
    """Return the one pinned-musl semantic-oracle startup mode.

    The pinned musl wrapper's ``-static-pie`` startup selection uses
    ``Scrt1.o`` and currently produces a crashing minimal executable. The
    static ET_EXEC oracle remains an independently linked and launched musl
    behavior reference for both owned product modes; it is deliberately not
    an input to either candidate link.
    """

    return STATIC_ET_EXEC


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stream_record(data: bytes) -> dict[str, object]:
    return {
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex": data.hex(),
        "text": data.decode("utf-8", errors="replace"),
    }


def disable_core_dump_inheritance() -> None:
    """Set the runner's inherited no-core policy before it creates workers.

    ``preexec_fn`` is unsafe once the bounded compile executor has threads:
    a child can deadlock between fork and exec while another thread owns a
    runtime lock. Setting this process-wide limit once is inherited by every
    later child without executing Python in a forked worker.
    """

    try:
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
    except (OSError, ValueError) as error:
        raise RunnerError("cannot disable core dumps for Lua runner children") from error


def owned_group_has_live_members(process_group: int) -> bool:
    """Return whether a process group still has a non-zombie member."""

    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                fields = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
                state = fields[0]
                group = int(fields[2])
            except (IndexError, OSError, ValueError):
                continue
            if group == process_group and state not in {"X", "Z"}:
                return True
    except OSError:
        # We cannot safely call a group clean if its membership cannot be
        # observed. Fail closed and let the cancellation path kill it.
        return True
    return False


def stop_owned_process_group(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    """Stop a child session, including descendants that still hold its pipes."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 1.0
    while owned_group_has_live_members(process.pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    if owned_group_has_live_members(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 1.0
        while owned_group_has_live_members(process.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
    if owned_group_has_live_members(process.pid):
        raise RunnerError("owned Lua child process group did not exit after forced cancellation")
    try:
        return process.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        raise RunnerError("owned Lua child leader did not exit after group cancellation")


def command_record(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout: float = 120.0,
) -> dict[str, object]:
    """Run one build/probe command and retain raw output without shell parsing."""

    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=timeout)
        if owned_group_has_live_members(process.pid):
            stop_owned_process_group(process)
            return {
                "command": list(command),
                "cwd": str(cwd) if cwd is not None else None,
                "status": "PROCESS_GROUP_LEAK",
                "stdout": stream_record(stdout),
                "stderr": stream_record(stderr),
            }
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "status": process.returncode,
            "stdout": stream_record(stdout),
            "stderr": stream_record(stderr),
        }
    except subprocess.TimeoutExpired:
        assert process is not None
        stdout, stderr = stop_owned_process_group(process)
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "status": "TIMEOUT",
            "stdout": stream_record(stdout),
            "stderr": stream_record(stderr),
        }
    except OSError as error:
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "status": f"EXEC_ERROR:{error.errno or 'unknown'}",
            "stdout": stream_record(b""),
            "stderr": stream_record(str(error).encode()),
        }
    except BaseException:
        if process is not None:
            stop_owned_process_group(process)
        raise


def require_success(record: Mapping[str, object], description: str) -> None:
    if record.get("status") != 0:
        raise RunnerError(f"{description} failed: {record.get('status')}")


def require_command(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RunnerError(f"required command is unavailable: {name}")
    return path


def command_output(command: Sequence[str]) -> str:
    record = command_record(command)
    require_success(record, "command output probe")
    stdout = record["stdout"]
    assert isinstance(stdout, dict)
    text = stdout["text"]
    assert isinstance(text, str)
    return text.strip()


def load_manifest(path: Path = MANIFEST) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"invalid Lua manifest: {path}") from error
    lua = raw.get("lua")
    musl = raw.get("musl")
    if not isinstance(lua, dict) or not isinstance(musl, dict):
        raise RunnerError("Lua manifest requires [lua] and [musl] tables")
    for key in ("version", "source_url", "sha256", "archive_root"):
        if not isinstance(lua.get(key), str) or not lua[key]:
            raise RunnerError(f"Lua manifest requires lua.{key}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(lua["sha256"])):
        raise RunnerError("Lua manifest lua.sha256 is not lowercase SHA-256")
    if musl.get("version") != "1.2.6":
        raise RunnerError("Lua owned-sysroot gate requires pinned musl 1.2.6 as its execution oracle")
    return raw


def source_archive_path(manifest: Mapping[str, object], cache: Path = CACHE) -> Path:
    lua = manifest["lua"]
    assert isinstance(lua, dict)
    return cache / f"lua-{lua['version']}.tar.gz"


def fetch_archive(manifest: Mapping[str, object], offline: bool, cache: Path = CACHE) -> Path:
    """Fetch the pinned source only when a verified cache entry is absent."""

    lua = manifest["lua"]
    assert isinstance(lua, dict)
    archive = source_archive_path(manifest, cache)
    expected = str(lua["sha256"])
    if archive.is_file() and sha256_file(archive) == expected:
        return archive
    if archive.exists():
        archive.unlink()
    if offline:
        raise RunnerError(f"verified Lua archive is absent from offline cache: {archive}")
    cache.mkdir(parents=True, exist_ok=True)
    partial = cache / f".{archive.name}.part"
    try:
        with urllib.request.urlopen(str(lua["source_url"]), timeout=30) as response:
            with partial.open("wb") as stream:
                shutil.copyfileobj(response, stream)
    except OSError as error:
        partial.unlink(missing_ok=True)
        raise RunnerError(f"failed to download pinned Lua source: {error}") from error
    observed = sha256_file(partial)
    if observed != expected:
        partial.unlink(missing_ok=True)
        raise RunnerError(f"Lua archive SHA-256 mismatch: expected {expected}, observed {observed}")
    partial.replace(archive)
    return archive


def safe_extract(archive: Path, destination: Path, archive_root: str) -> Path:
    """Extract one pinned archive without allowing path traversal or links."""

    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        prefix = f"{archive_root}/"
        for member in members:
            name = member.name
            if (name != archive_root and not name.startswith(prefix)) or Path(name).is_absolute() or ".." in Path(name).parts:
                raise RunnerError(f"Lua archive member escapes expected root: {name}")
            if member.issym() or member.islnk() or member.isdev():
                raise RunnerError(f"Lua archive contains unsupported link/device member: {name}")
        stream.extractall(destination, members, filter="data")
    source = destination / archive_root
    if not (source / "src/lua.c").is_file():
        raise RunnerError("Lua archive lacks expected src/lua.c")
    return source


def write_json_atomic(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def require_native_aarch64() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise RunnerError("Lua source-build gate requires native Linux/AArch64")


def artifact_record(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise RunnerError(f"required artifact is absent: {path}")
    return {"path": str(path), "sha256": sha256_file(path), "byte_length": path.stat().st_size}


def owned_sysroot(path: Path) -> tuple[Path, Path, dict[str, Path], dict[str, object]]:
    """Resolve the installed runtime inputs without accepting an unverified tree."""

    try:
        root = SYSROOT.require_directory(path, "owned crabc sysroot")
        manifest = SYSROOT.load_installed_manifest(root)
        runtime = SYSROOT.installed_runtime_paths(root)
    except SYSROOT.SysrootError as error:
        raise RunnerError(str(error)) from error
    wrapper = root / "bin/crabc-cc"
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        raise RunnerError(f"owned crabc compiler wrapper is missing or not executable: {wrapper}")
    for name, runtime_path in runtime.items():
        if not runtime_path.is_file():
            raise RunnerError(f"owned sysroot runtime input is absent ({name}): {runtime_path}")
    return root, wrapper, runtime, manifest


def compiler_flags() -> list[str]:
    """Lua's application flags; include and runtime policy belong to crabc-cc."""

    return [
        "-std=gnu99",
        "-O2",
        "-fPIC",
        "-fno-builtin",
        "-fno-stack-protector",
        "-DLUA_USE_LINUX",
    ]


def header_trace_paths(output: bytes) -> list[Path]:
    """Extract real headers from Clang's ``-H`` include trace."""

    paths: list[Path] = []
    seen: set[Path] = set()
    for line in output.decode("utf-8", errors="replace").splitlines():
        candidate = Path(line.lstrip(". "))
        if not candidate.is_absolute() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)
    return paths


def header_probe(wrapper: Path, flags: Sequence[str], work: Path, sysroot: Path, timeout: float) -> dict[str, object]:
    """Prove headers are selected only from the installed sysroot/toolchain."""

    probe = FIXTURES / "header_probe.c"
    output = work / "header-probe.o"
    record = command_record(
        [str(wrapper), *flags, "-H", "-c", str(probe), "-o", str(output)],
        environment=SYSROOT.seal_environment(),
        timeout=timeout,
    )
    require_success(record, "owned-sysroot C header probe")
    trace = bytes.fromhex(str(record["stdout"]["hex"])) + bytes.fromhex(str(record["stderr"]["hex"]))
    configuration = SYSROOT.DriverConfiguration.from_manifest(SYSROOT.load_installed_manifest(sysroot))
    clang = SYSROOT._compiler_from_configuration(configuration)
    resource_include = SYSROOT._resource_include(clang, SYSROOT.seal_environment())
    allowed = [sysroot / "usr/include", resource_include, FIXTURES]
    headers = header_trace_paths(trace)
    ambient = [str(path) for path in headers if all(not path.is_relative_to(root.resolve()) for root in allowed)]
    audit = {
        "status": "passed" if headers and not ambient else ("rejected" if ambient else "unverified"),
        "headers": [str(path) for path in headers],
        "allowed_roots": [str(path.resolve()) for path in allowed],
        "ambient_headers": ambient,
    }
    record["header_trace_audit"] = audit
    if audit["status"] != "passed":
        raise RunnerError("header probe fell through to an ambient or foreign header path")
    return record


def compile_source(
    wrapper: Path,
    flags: Sequence[str],
    source: Path,
    object_path: Path,
    timeout: float,
    extra: Sequence[str] = (),
) -> dict[str, object]:
    record = command_record(
        [str(wrapper), *flags, *extra, "-c", str(source), "-o", str(object_path)],
        environment=SYSROOT.seal_environment(),
        timeout=timeout,
    )
    require_success(record, f"compile {source.name}")
    return record


def link_with_owned_driver(
    wrapper: Path,
    arguments: Sequence[str],
    sysroot: Path,
    application_paths: Sequence[Path],
    application_library_roots: Sequence[Path],
    timeout: float,
) -> dict[str, object]:
    """Link once through crabc-cc and reject every unowned target input."""

    record = command_record(
        [str(wrapper), *arguments, "-Wl,--trace"],
        environment=SYSROOT.seal_environment(),
        timeout=timeout,
    )
    require_success(record, "owned-sysroot link")
    trace = bytes.fromhex(str(record["stdout"]["hex"])) + bytes.fromhex(str(record["stderr"]["hex"]))
    audit = SYSROOT.audit_linker_trace(trace, sysroot, application_paths, application_library_roots)
    record["link_trace_audit"] = audit
    if audit.get("status") != "passed":
        raise RunnerError(f"owned-sysroot link consumed an unapproved target input: {audit}")
    return record


def link_shared(
    wrapper: Path,
    objects: Sequence[Path],
    output: Path,
    sysroot: Path,
    soname: str,
    libraries: Sequence[str],
    timeout: float,
    allow_undefined: bool = False,
) -> dict[str, object]:
    definition_flags = ["-Wl,--allow-shlib-undefined"] if allow_undefined else ["-Wl,-z,defs"]
    record = command_record(
        [
            str(wrapper),
            "-shared",
            *definition_flags,
            "-Wl,--no-as-needed",
            f"-Wl,-soname,{soname}",
            "-o",
            str(output),
            *(str(item) for item in objects),
            "-L",
            str(sysroot / "usr/lib"),
            *libraries,
            "-Wl,--trace",
        ],
        environment=SYSROOT.seal_environment(),
        timeout=timeout,
    )
    require_success(record, f"link {output.name}")
    trace = bytes.fromhex(str(record["stdout"]["hex"])) + bytes.fromhex(str(record["stderr"]["hex"]))
    audit = SYSROOT.audit_linker_trace(trace, sysroot, objects, ())
    record["link_trace_audit"] = audit
    if audit.get("status") != "passed":
        raise RunnerError(f"link {output.name} consumed an unapproved target input: {audit}")
    return record


def link_executable(
    wrapper: Path,
    objects: Sequence[Path],
    output: Path,
    sysroot: Path,
    link_liblua: bool,
    application_library: Path,
    timeout: float,
) -> dict[str, object]:
    arguments = ["-o", str(output), *(str(item) for item in objects)]
    if link_liblua:
        arguments.extend(("-L", str(application_library), "-llua"))
    arguments.extend(("-L", str(sysroot / "usr/lib"), "-lm", "-ldl"))
    return link_with_owned_driver(
        wrapper,
        arguments,
        sysroot,
        objects,
        (application_library,) if link_liblua else (),
        timeout,
    )


def readelf(path: Path, *arguments: str) -> str:
    record = command_record([require_command("readelf"), *arguments, str(path)])
    require_success(record, f"readelf {path.name}")
    stdout = record["stdout"]
    assert isinstance(stdout, dict)
    text = stdout["text"]
    assert isinstance(text, str)
    return text


def elf_record(path: Path) -> dict[str, object]:
    dynamic = readelf(path, "-d")
    headers = readelf(path, "-lW")
    machine = readelf(path, "-h")
    if "AArch64" not in machine:
        raise RunnerError(f"artifact is not AArch64: {path}")
    return {"artifact": artifact_record(path), "dynamic": dynamic, "program_headers": headers, "header": machine}


def validate_candidate_elf(artifacts: Mapping[str, object]) -> None:
    """Reject an apparently successful graph with the wrong runtime boundary."""

    forbidden = ("ld-musl-", "libc.musl-", "/opt/musl-1.2.6", "libc.so.6", "ld-linux")
    for name, record in artifacts.items():
        if not isinstance(record, dict):
            raise RunnerError(f"invalid ELF record for {name}")
        dynamic = record.get("dynamic")
        headers = record.get("program_headers")
        header = record.get("header")
        if not all(isinstance(value, str) for value in (dynamic, headers, header)):
            raise RunnerError(f"incomplete ELF record for {name}")
        text = "\n".join((dynamic, headers, header))
        if any(marker in text for marker in forbidden):
            raise RunnerError(f"candidate {name} ELF leaks a foreign runtime marker")
        if "Type:" not in header or "DYN" not in header:
            raise RunnerError(f"candidate {name} is not a shared/PIE ELF")
    for name in ("lua", "luac"):
        record = artifacts[name]
        assert isinstance(record, dict)
        headers = record["program_headers"]
        assert isinstance(headers, str)
        if SYSROOT.CANONICAL_INTERPRETER not in headers:
            raise RunnerError(f"candidate {name} does not name the canonical crabc loader")
    lua = artifacts["lua"]
    assert isinstance(lua, dict)
    dynamic = lua["dynamic"]
    assert isinstance(dynamic, str)
    if "liblua.so.5.4" not in dynamic:
        raise RunnerError("candidate lua is not dynamically linked to liblua.so.5.4")


def patch_interpreter_bytes(binary: bytes, interpreter: str) -> bytes:
    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        raise RunnerError("output is not little-endian ELF64")
    if int.from_bytes(binary[18:20], "little") != 183:
        raise RunnerError("output is not AArch64 ELF")
    phoff = int.from_bytes(binary[32:40], "little")
    phentsize = int.from_bytes(binary[54:56], "little")
    phnum = int.from_bytes(binary[56:58], "little")
    if phentsize < 56:
        raise RunnerError("ELF has an invalid program-header size")
    result = bytearray(binary)
    encoded = interpreter.encode("ascii") + b"\0"
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(result):
            raise RunnerError("ELF program headers exceed file")
        if int.from_bytes(result[offset : offset + 4], "little") != 3:
            continue
        file_offset = int.from_bytes(result[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(result[offset + 32 : offset + 40], "little")
        if len(encoded) > file_size or file_offset + file_size > len(result):
            raise RunnerError("reference musl interpreter does not fit PT_INTERP")
        result[file_offset : file_offset + file_size] = encoded + b"\0" * (file_size - len(encoded))
        return bytes(result)
    raise RunnerError("ELF has no PT_INTERP")


def patch_interpreter(source: Path, destination: Path, interpreter: Path) -> None:
    destination.write_bytes(patch_interpreter_bytes(source.read_bytes(), str(interpreter)))
    destination.chmod(source.stat().st_mode | stat.S_IXUSR)


def sanitize_environment(
    *, home: Path | None = None, temporary_directory: Path | None = None
) -> dict[str, str]:
    """Drop runtime/toolchain overrides and select deterministic local state."""

    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_", "LUA_", "CRABC_", "MUSL_", "RUST", "CARGO")):
            environment.pop(key, None)
    environment.update(
        {
            "PATH": "/bin:/usr/bin",
            "HOME": str(home) if home is not None else "/tmp",
            "TMPDIR": str(temporary_directory) if temporary_directory is not None else "/tmp",
            "LC_ALL": "C",
        }
    )
    return environment


def runtime_library_path(sysroot: Path, application_library: Path) -> str:
    """Construct the only runtime search path needed by a Lua build tree."""

    return ":".join((str(application_library), str(sysroot / "usr/lib")))


@contextlib.contextmanager
def staged_canonical_loader(sysroot: Path) -> Iterator[None]:
    """Temporarily make the owned canonical interpreter kernel-resolvable."""

    if os.geteuid() != 0:
        raise RunnerError("owned Lua execution requires root in the disposable Linux container")
    source = SYSROOT.installed_runtime_paths(sysroot)["loader"]
    canonical = Path(SYSROOT.CANONICAL_INTERPRETER)
    if canonical.exists() or canonical.is_symlink():
        raise RunnerError(f"refusing to replace existing canonical loader: {canonical}")
    canonical.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, canonical)
    try:
        yield
    finally:
        if canonical.exists() and sha256_file(canonical) == sha256_file(source):
            canonical.unlink()
        elif canonical.exists():
            raise RunnerError(f"staged canonical loader changed unexpectedly and was retained: {canonical}")


def run_lua(
    command: Sequence[str],
    script: Path,
    module_directory: Path,
    runtime_libraries: str,
    fixture_dir: Path,
    timeout: float,
    capture_maps: bool,
) -> tuple[ProcessResult, str | None]:
    environment = sanitize_environment()
    environment.update(
        {
            "LD_LIBRARY_PATH": runtime_libraries,
            "CRABC_LUA_ENV": "owned-sysroot",
            "CRABC_LUA_MAPS_WAIT": "1",
            "CRABC_LUA_DYNAMIC_MODULES": "1",
        }
    )
    try:
        process = subprocess.Popen(
            [*command, str(script), str(module_directory), str(fixture_dir)],
            cwd=fixture_dir,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode()), None
    assert process.stdin is not None and process.stdout is not None
    ready = b""
    maps: str | None = None
    try:
        ready_stream, _, _ = select.select([process.stdout], [], [], timeout)
        if not ready_stream:
            stdout, stderr = stop_owned_process_group(process)
            return ProcessResult("TIMEOUT", stdout, stderr, True), None
        ready = process.stdout.readline()
        if ready != b"maps-ready\n":
            stdout, stderr = stop_owned_process_group(process)
            return ProcessResult("PROTOCOL_ERROR", ready + stdout, stderr), None
        if capture_maps:
            maps_path = Path(f"/proc/{process.pid}/maps")
            maps = maps_path.read_text(encoding="utf-8")
        process.stdin.write(b"continue\n")
        process.stdin.flush()
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = stop_owned_process_group(process)
        return ProcessResult("TIMEOUT", ready + stdout, stderr, True), maps
    except BaseException:
        stop_owned_process_group(process)
        raise
    if owned_group_has_live_members(process.pid):
        stop_owned_process_group(process)
        return ProcessResult("PROCESS_GROUP_LEAK", ready + stdout, stderr), maps
    return ProcessResult(process.returncode, ready + stdout, stderr), maps


def result_comparison(reference: ProcessResult, candidate: ProcessResult) -> dict[str, object]:
    status_match = reference.status == candidate.status and reference.timed_out == candidate.timed_out
    stdout_match = reference.stdout == candidate.stdout
    stderr_match = reference.stderr == candidate.stderr
    return {
        "passed": status_match and stdout_match and stderr_match,
        "normalization": "none",
        "status_match": status_match,
        "stdout_match": stdout_match,
        "stderr_match": stderr_match,
        "reference": {
            "status": reference.status,
            "timed_out": reference.timed_out,
            "stdout": stream_record(reference.stdout),
            "stderr": stream_record(reference.stderr),
        },
        "candidate": {
            "status": candidate.status,
            "timed_out": candidate.timed_out,
            "stdout": stream_record(candidate.stdout),
            "stderr": stream_record(candidate.stderr),
        },
    }


def syscall_summary(trace: str) -> dict[str, object]:
    calls: dict[str, int] = {}
    errors: dict[str, int] = {}
    for line in trace.splitlines():
        match = re.search(r"(?:\d+\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\(", line)
        if match is None:
            continue
        name = match.group(1)
        calls[name] = calls.get(name, 0) + 1
        if " = -1 " in line:
            errors[name] = errors.get(name, 0) + 1
    return {"calls": dict(sorted(calls.items())), "errors": dict(sorted(errors.items())), "total_calls": sum(calls.values())}


def syscall_diagnostic(
    command: Sequence[str],
    script: Path,
    module_directory: Path,
    runtime_libraries: str,
    fixture_dir: Path,
    trace: Path,
    timeout: float,
) -> dict[str, object]:
    if shutil.which("strace") is None:
        return {"status": "unsupported", "reason": "strace unavailable", "diagnostic": True, "timing": False}
    environment = sanitize_environment()
    environment.update(
        {
            "LD_LIBRARY_PATH": runtime_libraries,
            "CRABC_LUA_ENV": "owned-sysroot",
            "CRABC_LUA_DYNAMIC_MODULES": "1",
        }
    )
    record = command_record(
        ["strace", "-f", "-qq", "-o", str(trace), *command, str(script), str(module_directory), str(fixture_dir)],
        cwd=fixture_dir,
        environment=environment,
        timeout=timeout,
    )
    result: dict[str, object] = {"diagnostic": True, "timing": False, "command": record, "status": record["status"]}
    if trace.is_file():
        result.update(syscall_summary(trace.read_text(encoding="utf-8", errors="replace")))
    return result


def mapped_files(maps: str) -> list[Path]:
    """Return unique regular files recorded by a process map snapshot."""

    paths: list[Path] = []
    seen: set[Path] = set()
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        path = Path(fields[5].removesuffix(" (deleted)"))
        if path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                paths.append(resolved)
    return paths


def verify_candidate_maps(maps: str, sysroot: Path, candidate_library: Path) -> dict[str, object]:
    """Prove the candidate maps owned runtime bytes and its application DSOs."""

    runtime = SYSROOT.installed_runtime_paths(sysroot)
    expected = {
        "owned_loader": runtime["loader"],
        "owned_libc": runtime["libc.so"],
        "liblua": candidate_library / "liblua.so.5.4",
        "probe": candidate_library / "crabc_probe.so",
    }
    identities = [{"path": str(path), "sha256": sha256_file(path)} for path in mapped_files(maps)]
    expected_records: dict[str, object] = {}
    missing: list[str] = []
    for name, path in expected.items():
        digest = sha256_file(path)
        mapped = any(item["sha256"] == digest for item in identities)
        expected_records[name] = {"path": str(path), "sha256": digest, "mapped": mapped}
        if not mapped:
            missing.append(name)
    forbidden = ("/opt/musl-1.2.6", "libc.so.6", "ld-linux", "libc.musl-")
    seen_forbidden = [item for item in identities if any(marker in item["path"] for marker in forbidden)]
    return {
        "status": "passed" if not missing and not seen_forbidden else "rejected",
        "path": "/proc/<candidate>/maps",
        "text": maps,
        "mapped_files": identities,
        "expected_artifacts": expected_records,
        "no_musl_libc": True,
        "errors": {
            "missing_expected_artifacts": missing,
            "foreign_runtime_identities": seen_forbidden,
        },
    }


def build_graph(manifest: Mapping[str, object], installed_sysroot: Path, work: Path, timeout: float) -> dict[str, object]:
    """Compile the pinned Lua graph as application objects through crabc-cc."""

    lua = manifest["lua"]
    assert isinstance(lua, dict)
    source = safe_extract(source_archive_path(manifest), work / "source", str(lua["archive_root"]))
    sysroot, wrapper, runtime, installed_manifest = owned_sysroot(installed_sysroot)
    candidate = work / "candidate"
    candidate_lib = candidate / "lib"
    candidate_bin = candidate / "bin"
    candidate_lib.mkdir(parents=True)
    candidate_bin.mkdir()
    object_dir = work / "objects"
    object_dir.mkdir()
    flags = compiler_flags()
    records: dict[str, object] = {
        "compiler_wrapper": str(wrapper),
        "installed_sysroot": {
            "path": str(sysroot),
            "manifest": installed_manifest,
            "runtime_inputs": {name: artifact_record(path) for name, path in runtime.items()},
        },
        "header_probe": header_probe(wrapper, flags, work, sysroot, timeout),
        "compile": {},
        "link": {},
    }
    compile_records = records["compile"]
    assert isinstance(compile_records, dict)
    objects: list[Path] = []
    for name in (*CORE_SOURCES, *LIB_SOURCES):
        object_path = object_dir / f"{name}.o"
        compile_records[name] = compile_source(wrapper, flags, source / "src" / name, object_path, timeout)
        objects.append(object_path)
    liblua = candidate_lib / "liblua.so.5.4"
    link_records = records["link"]
    assert isinstance(link_records, dict)
    link_records["liblua"] = link_shared(
        wrapper,
        objects,
        liblua,
        sysroot,
        "liblua.so.5.4",
        ("-lc", "-lm", "-ldl", "-l:libcrabc-builtins.a"),
        timeout,
    )
    (candidate_lib / "liblua.so").symlink_to("liblua.so.5.4")
    for main in ("lua", "luac"):
        object_path = object_dir / f"{main}.o"
        compile_records[f"{main}.c"] = compile_source(
            wrapper, flags, source / "src" / f"{main}.c", object_path, timeout
        )
        main_objects = [object_path] if main == "lua" else [object_path, *objects]
        link_records[main] = link_executable(
            wrapper, main_objects, candidate_bin / main, sysroot, main == "lua", candidate_lib, timeout
        )
    lua_include = source / "src"
    for source_name, soname in (("crabc_probe.c", "crabc_probe.so"), ("crabc_fail.c", "crabc_fail.so")):
        object_path = object_dir / f"{source_name}.o"
        compile_records[source_name] = compile_source(
            wrapper,
            [*flags, "-I", str(lua_include)],
            FIXTURES / source_name,
            object_path,
            timeout,
        )
        # A Lua module deliberately leaves Lua API references unresolved.  At
        # module load they resolve from the interpreter's already-loaded
        # liblua, exercising the loader's normal module path.
        link_records[soname] = link_shared(
            wrapper,
            [object_path],
            candidate_lib / soname,
            sysroot,
            soname,
            ("-lc", "-l:libcrabc-builtins.a"),
            timeout,
            allow_undefined=True,
        )
    shutil.copy2(candidate_lib / "crabc_probe.so", candidate_lib / "crabc_missing.so")
    artifacts_by_name = {
        name: elf_record(path)
        for name, path in {
            "liblua": liblua,
            "lua": candidate_bin / "lua",
            "luac": candidate_bin / "luac",
            "probe": candidate_lib / "crabc_probe.so",
            "failure": candidate_lib / "crabc_fail.so",
            "missing_symbol": candidate_lib / "crabc_missing.so",
        }.items()
    }
    validate_candidate_elf(artifacts_by_name)
    records["artifacts"] = artifacts_by_name
    return {"installed_sysroot": sysroot, "candidate": candidate, "source": source, "records": records}


def prepare_reference(candidate: Path, work: Path) -> Path:
    """Stage candidate DSOs next to the pinned musl libc execution oracle."""

    reference = work / "reference"
    reference_lib = reference / "lib"
    reference_lib.mkdir(parents=True)
    for name in ("liblua.so.5.4", "crabc_probe.so", "crabc_fail.so", "crabc_missing.so"):
        shutil.copy2(candidate / "lib" / name, reference_lib / name)
    # Keep the reference runtime self-contained and pinned.  The executable
    # and DSOs are the candidate-built bytes, but their reference execution
    # must resolve libc from the recorded musl installation rather than an
    # incidental Alpine system library-search path.
    musl_libc = MUSL_ROOT / "lib/libc.so"
    musl_loader = MUSL_ROOT / "lib/ld-musl-aarch64.so.1"
    if not musl_libc.is_file() or not musl_loader.is_file():
        raise RunnerError("pinned musl loader/libc oracle is absent")
    shutil.copy2(musl_libc, reference_lib / "libc.so")
    (reference_lib / "liblua.so").symlink_to("liblua.so.5.4")
    return reference


def run_workloads(graph: Mapping[str, object], work: Path, timeout: float) -> dict[str, object]:
    sysroot = graph["installed_sysroot"]
    assert isinstance(sysroot, Path)
    candidate = graph["candidate"]
    assert isinstance(candidate, Path)
    candidate_lib = candidate / "lib"
    candidate_bin = candidate / "bin"
    reference = prepare_reference(candidate, work)
    reference_lib = reference / "lib"
    fixture_dir = work / "fixture-state"
    fixture_dir.mkdir()
    script = FIXTURES / "exercise.lua"
    luac_output = fixture_dir / "exercise.luac"
    candidate_runtime = runtime_library_path(sysroot, candidate_lib)
    reference_runtime = str(reference_lib)
    reference_lua = [str(MUSL_ROOT / "lib/ld-musl-aarch64.so.1"), str(candidate_bin / "lua")]
    with staged_canonical_loader(sysroot):
        candidate_luac = command_record(
            [str(candidate_bin / "luac"), "-o", str(luac_output), str(script)],
            cwd=fixture_dir,
            environment={**sanitize_environment(), "LD_LIBRARY_PATH": candidate_runtime},
            timeout=timeout,
        )
        require_success(candidate_luac, "candidate luac bytecode build")
        if not luac_output.is_file():
            raise RunnerError("candidate luac did not produce bytecode")
        source_reference, _ = run_lua(
            reference_lua,
            script,
            reference_lib,
            reference_runtime,
            fixture_dir,
            timeout,
            False,
        )
        source_candidate, maps = run_lua(
            [str(candidate_bin / "lua")], script, candidate_lib, candidate_runtime, fixture_dir, timeout, True
        )
        bytecode_reference, _ = run_lua(
            reference_lua,
            luac_output,
            reference_lib,
            reference_runtime,
            fixture_dir,
            timeout,
            False,
        )
        bytecode_candidate, _ = run_lua(
            [str(candidate_bin / "lua")], luac_output, candidate_lib, candidate_runtime, fixture_dir, timeout, False
        )
        trace_dir = work / "traces"
        trace_dir.mkdir()
        syscalls = {
            "normal_module": syscall_diagnostic(
                [str(candidate_bin / "lua")],
                script,
                candidate_lib,
                candidate_runtime,
                fixture_dir,
                trace_dir / "normal.strace",
                timeout,
            ),
            "failure_module": syscall_diagnostic(
                [str(candidate_bin / "lua")],
                script,
                candidate_lib,
                candidate_runtime,
                fixture_dir,
                trace_dir / "failure.strace",
                timeout,
            ),
        }
        if maps is None:
            raise RunnerError("candidate Lua process did not provide /proc maps evidence")
        # Keep the temporary canonical loader in place until its map identity
        # is resolved and hashed. Parsing after the context exits would make
        # the now-unlinked `/lib/ld-crabc-aarch64.so.1` disappear from the
        # evidence even though it was mapped by the candidate process.
        maps_record = verify_candidate_maps(maps, sysroot, candidate_lib)
    return {
        "reference": str(reference),
        "reference_launcher": reference_lua,
        "candidate_luac": candidate_luac,
        "source": result_comparison(source_reference, source_candidate),
        "bytecode": result_comparison(bytecode_reference, bytecode_candidate),
        "candidate_maps": maps_record,
        "syscalls": syscalls,
    }


def require_native_x86_64() -> None:
    """Refuse a source-build result produced through emulation."""

    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise RunnerError("native Lua static source-build gate requires native Linux/x86-64")


def selected_static_modes(requested: Sequence[str] | None) -> tuple[StaticLuaMode, ...]:
    """Select the finite static product modes without silently dropping one."""

    names = ("static-et-exec", "static-pie") if not requested else tuple(requested)
    if len(names) != len(set(names)):
        raise RunnerError("each native Lua static mode may be requested only once")
    try:
        return tuple(STATIC_LUA_MODES[name] for name in names)
    except KeyError as error:
        raise RunnerError(f"unsupported native Lua static mode: {error.args[0]}") from error


def reject_symlinked_components(path: Path, description: str) -> None:
    """Reject an absolute lexical path with traversal or a symlink component."""

    if not path.is_absolute() or any(component in {"", ".", ".."} for component in path.parts[1:]):
        raise RunnerError(f"{description} must be an absolute path without traversal: {path}")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if os.path.lexists(current) and current.is_symlink():
            raise RunnerError(f"{description} crosses a symlink: {path}")


def require_physical_directory(path: Path, description: str) -> Path:
    """Require an existing directory whose spelling is its physical location."""

    reject_symlinked_components(path, description)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RunnerError(f"{description} does not exist: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RunnerError(f"{description} is not a physical directory: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RunnerError(f"{description} is unreadable: {path}") from error
    if resolved != path:
        raise RunnerError(f"{description} is not a physical directory: {path}")
    return resolved


def native_work_root(path: Path) -> Path:
    """Create one physical x86 state root only below this checkout's ``.work``."""

    checkout = ROOT.resolve(strict=True)
    boundary = checkout / ".work"
    boundary.mkdir(parents=True, exist_ok=True)
    boundary = require_physical_directory(boundary, "checkout .work root")
    raw = path if path.is_absolute() else checkout / path
    if ".." in raw.parts:
        raise RunnerError(f"native Lua work root must not contain traversal: {path}")
    candidate = Path(os.path.abspath(raw))
    reject_symlinked_components(candidate, "native Lua work root")
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise RunnerError(f"native Lua work root must stay below checkout .work: {candidate}") from error
    if candidate == boundary:
        raise RunnerError("native Lua work root must name a dedicated directory below checkout .work")
    candidate.mkdir(parents=True, exist_ok=True)
    return require_physical_directory(candidate, "native Lua work root")


def native_source_cache(work_root: Path) -> Path:
    """Create the source cache as a physical child of an admitted work root."""

    cache = work_root / "cache"
    try:
        cache.mkdir(exist_ok=True)
    except OSError as error:
        raise RunnerError(f"native Lua source cache is not creatable: {cache}") from error
    return require_physical_directory(cache, "native Lua source cache")


def require_physical_regular_file(path: Path, description: str) -> Path:
    """Resolve a regular file without admitting an alias through a symlink."""

    reject_symlinked_components(path, description)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RunnerError(f"{description} is absent: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RunnerError(f"{description} is not a regular physical file: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RunnerError(f"{description} is unreadable: {path}") from error
    if resolved != path:
        raise RunnerError(f"{description} is not a regular physical file: {path}")
    return resolved


def owned_static_sysroot(path: Path) -> tuple[Path, Path, dict[str, Path], dict[str, object]]:
    """Validate the x86 installed static tree rather than the AArch64 sysroot."""

    root = require_physical_directory(Path(os.path.abspath(path)), "owned x86 static sysroot")
    manifest_path = require_physical_regular_file(root / "share/crabc/manifest.json", "static sysroot manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError(f"invalid owned x86 static sysroot manifest: {manifest_path}") from error
    if not isinstance(manifest, dict) or (
        manifest.get("schema"), manifest.get("format"), manifest.get("target")
    ) != (1, "crabc-x86-64-owned-static-sysroot-v1", "x86_64-unknown-linux-musl"):
        raise RunnerError("manifest does not identify the owned x86 static sysroot")
    installed = manifest.get("installed")
    driver = manifest.get("sealed_static_driver")
    if not isinstance(installed, dict) or not isinstance(driver, dict):
        raise RunnerError("owned x86 static sysroot manifest lacks installed-driver records")
    if installed.get("sealed_static_driver") != "bin/crabc-cc" or driver.get("path") != "bin/crabc-cc":
        raise RunnerError("owned x86 static sysroot manifest does not bind crabc-cc")
    if driver.get("format") != "crabc-x86-64-sealed-static-driver-v1":
        raise RunnerError("owned x86 static sysroot driver format drifted")
    files = installed.get("files")
    if not isinstance(files, dict) or not files:
        raise RunnerError("owned x86 static sysroot manifest lacks payload hashes")
    expected_files: dict[str, str] = {}
    for relative, digest in files.items():
        candidate = Path(relative) if isinstance(relative, str) else Path()
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise RunnerError("owned x86 static sysroot manifest has an invalid payload hash")
        expected_files[relative] = digest
    observed_files: set[str] = set()
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            raise RunnerError(f"owned x86 static sysroot contains a symlink: {relative}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise RunnerError(f"owned x86 static sysroot contains a non-regular entry: {relative}")
        if relative != "share/crabc/manifest.json":
            observed_files.add(relative)
    if observed_files != set(expected_files):
        raise RunnerError("owned x86 static sysroot payload file set drifted")
    for relative, digest in expected_files.items():
        artifact = require_physical_regular_file(root / relative, f"static sysroot payload {relative}")
        if sha256_file(artifact) != digest:
            raise RunnerError(f"owned x86 static sysroot payload hash drifted: {relative}")
    wrapper = require_physical_regular_file(root / "bin/crabc-cc", "owned x86 static compiler wrapper")
    if not os.access(wrapper, os.X_OK):
        raise RunnerError("owned x86 static compiler wrapper is not executable")
    runtime_names = {
        "headers": root / "usr/include",
        "crt1.o": root / "usr/lib/crt1.o",
        "rcrt1.o": root / "usr/lib/rcrt1.o",
        "crti.o": root / "usr/lib/crti.o",
        "crtn.o": root / "usr/lib/crtn.o",
        "libc.a": root / "usr/lib/libc.a",
        "builtins": root / "usr/lib/libcrabc-builtins.a",
    }
    require_physical_directory(runtime_names["headers"], "owned x86 static headers")
    for name, runtime in runtime_names.items():
        if name != "headers":
            require_physical_regular_file(runtime, f"owned x86 static runtime {name}")
    return root, wrapper, runtime_names, manifest


def static_compiler_flags() -> list[str]:
    """Keep Lua's POSIX behavior enabled without enabling runtime DSO loading."""

    return [
        "-std=gnu99",
        "-O2",
        "-fno-builtin",
        "-fno-stack-protector",
        "-DLUA_USE_POSIX",
        "-DLUA_COMPAT_5_3",
    ]


def static_environment(state: Path) -> dict[str, str]:
    """Give every native build/run child a private checkout-local home and tmp."""

    home = state / "home"
    temporary = state / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    temporary.mkdir(parents=True, exist_ok=True)
    environment = SYSROOT.seal_environment(sanitize_environment(home=home, temporary_directory=temporary))
    environment["TZ"] = "UTC"
    return environment


def static_driver_plan(
    wrapper: Path,
    sysroot: Path,
    mode: StaticLuaMode,
    work: Path,
    timeout: float,
) -> dict[str, object]:
    """Check the installed driver's fixed header and static-runtime selection."""

    record = command_record(
        [str(wrapper), "--print-link-plan", mode.driver_flag],
        cwd=work,
        environment=static_environment(work / "driver-plan"),
        timeout=timeout,
    )
    require_success(record, f"sealed static driver plan ({mode.identifier})")
    stdout = record["stdout"]
    assert isinstance(stdout, dict)
    try:
        plan = json.loads(str(stdout["text"]))
    except json.JSONDecodeError as error:
        raise RunnerError("sealed static driver emitted an invalid plan") from error
    if not isinstance(plan, dict):
        raise RunnerError("sealed static driver plan is not an object")
    selected = plan.get("mode")
    if not isinstance(selected, dict) or (
        selected.get("id"), selected.get("elf_type"), selected.get("crt_object"), selected.get("interpreter")
    ) != (mode.driver_id, f"ET_{mode.elf_type}", mode.crt_object, "absent"):
        raise RunnerError(f"sealed static driver selected the wrong {mode.identifier} plan")
    if plan.get("target") != "x86_64-unknown-linux-musl" or plan.get("headers") != str(sysroot / "usr/include"):
        raise RunnerError("sealed static driver plan escapes the installed x86 target headers")
    linker = plan.get("linker")
    if not isinstance(linker, list):
        raise RunnerError("sealed static driver plan has no linker argv")
    for runtime in (mode.crt_object, "crti.o", "libc.a", "libcrabc-builtins.a", "crtn.o"):
        if str(sysroot / "usr/lib" / runtime) not in linker:
            raise RunnerError(f"sealed static driver plan omits owned {runtime}")
    record["plan_audit"] = {
        "status": "passed",
        "headers": str(sysroot / "usr/include"),
        "mode": mode.identifier,
        "interpreter": "absent",
    }
    return record


def static_compile_record(
    wrapper: Path,
    mode: StaticLuaMode,
    flags: Sequence[str],
    source: Path,
    output: Path,
    work: Path,
    temporary_state: Path,
    timeout: float,
) -> dict[str, object]:
    record = command_record(
        [str(wrapper), mode.driver_flag, *flags, "-c", str(source), "-o", str(output)],
        cwd=work,
        environment=static_environment(temporary_state),
        timeout=timeout,
    )
    require_success(record, f"sealed static compile {source.name}")
    if not output.is_file() or output.is_symlink():
        raise RunnerError(f"sealed static compile did not produce a regular object: {output.name}")
    return record


def parallel_static_compiles(
    wrapper: Path,
    mode: StaticLuaMode,
    flags: Sequence[str],
    sources: Sequence[tuple[str, Path]],
    object_directory: Path,
    work: Path,
    timeout: float,
    jobs: int,
) -> tuple[dict[str, object], dict[str, Path]]:
    """Compile independent Lua application sources with bounded owned children."""

    if not sources or len({name for name, _ in sources}) != len(sources):
        raise RunnerError("native Lua static compile source roster is empty or ambiguous")
    object_directory.mkdir(parents=True, exist_ok=False)
    temporary_root = work / "compile-tmp"
    temporary_root.mkdir(parents=True, exist_ok=False)
    prepared: list[tuple[str, Path, Path, Path]] = []
    for index, (name, source) in enumerate(sources):
        if not source.is_file() or source.is_symlink():
            raise RunnerError(f"native Lua source is absent or unsafe: {source}")
        object_path = object_directory / f"{index:02d}-{name.replace('/', '_').replace('.', '_')}.o"
        temporary = temporary_root / f"{index:02d}"
        prepared.append((name, source, object_path, temporary))

    def compile_one(item: tuple[str, Path, Path, Path]) -> tuple[str, dict[str, object], Path]:
        name, source, output, temporary = item
        return name, static_compile_record(wrapper, mode, flags, source, output, work, temporary, timeout), output

    futures: list[concurrent.futures.Future[tuple[str, dict[str, object], Path]]] = []
    results: dict[str, tuple[dict[str, object], Path]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(jobs, len(prepared))) as executor:
        futures = [executor.submit(compile_one, item) for item in prepared]
        try:
            for future in futures:
                name, record, output = future.result()
                results[name] = (record, output)
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    return (
        {name: results[name][0] for name, _, _, _ in prepared},
        {name: results[name][1] for name, _, _, _ in prepared},
    )


def validate_static_elf_facts(
    *, header: str, program_headers: str, dynamic: str, relocations: str, mode: StaticLuaMode, label: str
) -> None:
    """Reject a static source-build result with an interpreter or dynamic import."""

    if "Advanced Micro Devices X86-64" not in header:
        raise RunnerError(f"{label} is not an x86-64 ELF")
    if not re.search(rf"Type:\s+{mode.elf_type}\b", header):
        raise RunnerError(f"{label} has the wrong ELF type for {mode.identifier}")
    if "INTERP" in program_headers or "Requesting program interpreter" in program_headers:
        raise RunnerError(f"{label} unexpectedly has PT_INTERP")
    combined = "\n".join((header, program_headers, dynamic, relocations))
    for marker in ("NEEDED", "TEXTREL", "JMPREL", "PLTGOT", "ld-musl-", "ld-linux", "libc.so"):
        if marker in combined:
            raise RunnerError(f"{label} leaks a dynamic runtime marker: {marker}")
    relocations_seen = re.findall(r"R_X86_64_[A-Z0-9_]+", relocations)
    if mode is STATIC_PIE:
        if any(relocation != "R_X86_64_RELATIVE" for relocation in relocations_seen):
            raise RunnerError(f"{label} static PIE retains a non-relative relocation")
    elif relocations_seen:
        raise RunnerError(f"{label} static ET_EXEC retains a dynamic relocation")


def static_elf_record(path: Path, mode: StaticLuaMode, label: str) -> dict[str, object]:
    header = readelf(path, "-h")
    program_headers = readelf(path, "-lW")
    dynamic = readelf(path, "-dW")
    relocations = readelf(path, "-rW")
    validate_static_elf_facts(
        header=header,
        program_headers=program_headers,
        dynamic=dynamic,
        relocations=relocations,
        mode=mode,
        label=label,
    )
    return {
        "artifact": artifact_record(path),
        "header": header,
        "program_headers": program_headers,
        "dynamic": dynamic,
        "relocations": relocations,
    }


def prepare_static_preload_support(source: Path) -> tuple[Path, dict[str, object]]:
    """Stage the small linked-preload adapter without modifying the pinned archive."""

    # The sealed driver deliberately rejects caller include paths.  Put each
    # staged C file beside Lua's upstream local headers in this private
    # extraction, rather than weakening that header boundary with ``-I``.
    support = source / "src"
    if not support.is_dir() or support.is_symlink():
        raise RunnerError("pinned Lua source directory is absent or unsafe")
    staged_fixture_names = {
        "crabc_probe.c": "crabc_probe.crabc-static.c",
        "crabc_fail.c": "crabc_fail.crabc-static.c",
        "static_preload.c": "static_preload.crabc-static.c",
    }
    for name, staged_name in staged_fixture_names.items():
        origin = FIXTURES / name
        if not origin.is_file() or origin.is_symlink():
            raise RunnerError(f"Lua static fixture is absent or unsafe: {name}")
        shutil.copy2(origin, support / staged_name)
    upstream = source / "src/linit.c"
    try:
        contents = upstream.read_text(encoding="utf-8")
    except OSError as error:
        raise RunnerError("pinned Lua source lacks linit.c") from error
    declaration_marker = '#include "lauxlib.h"\n'
    declaration = "\n/* Linked static fixtures are deliberately not runtime DSOs. */\nvoid crabc_lua_install_static_preloads(lua_State *L);\n"
    loop_marker = (
        "  for (lib = loadedlibs; lib->func; lib++) {\n"
        "    luaL_requiref(L, lib->name, lib->func, 1);\n"
        "    lua_pop(L, 1);  /* remove lib */\n"
        "  }\n"
    )
    if contents.count(declaration_marker) != 1 or contents.count(loop_marker) != 1:
        raise RunnerError("pinned Lua linit.c no longer matches the static-preload staging contract")
    staged_contents = contents.replace(declaration_marker, declaration_marker + declaration).replace(
        loop_marker, loop_marker + "  crabc_lua_install_static_preloads(L);\n"
    )
    staged_linit = support / "linit.crabc-static.c"
    staged_linit.write_text(staged_contents, encoding="utf-8", newline="\n")
    return support, {
        "status": "passed",
        "upstream_linit": artifact_record(upstream),
        "staged_linit": artifact_record(staged_linit),
        "adapter": artifact_record(support / "static_preload.crabc-static.c"),
        "contract": "upstream linit.c copied into private work state; only package.preload registration is added",
    }


def static_source_roster(source: Path, support: Path) -> tuple[tuple[str, Path], ...]:
    """Return every source that crosses the sealed static-driver boundary."""

    roster: list[tuple[str, Path]] = []
    for name in (*CORE_SOURCES, *LIB_SOURCES):
        roster.append(
            (f"src/{name}", support / "linit.crabc-static.c" if name == "linit.c" else source / "src" / name)
        )
    roster.extend(
        (
            ("src/lua.c", source / "src/lua.c"),
            ("src/luac.c", source / "src/luac.c"),
            ("fixture/crabc_probe.c", support / "crabc_probe.crabc-static.c"),
            ("fixture/crabc_fail.c", support / "crabc_fail.crabc-static.c"),
            ("fixture/static_preload.c", support / "static_preload.crabc-static.c"),
        )
    )
    if len({name for name, _ in roster}) != len(roster):
        raise RunnerError("native Lua static source roster has duplicate names")
    return tuple(roster)


def audit_static_link_receipt(
    *,
    sysroot: Path,
    mode: StaticLuaMode,
    objects: Sequence[Path],
    work: Path,
    output: Path,
    receipt: Path,
) -> dict[str, object]:
    """Bind one static Lua link to the driver's observed closed input trace."""

    try:
        decoded = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError(f"sealed static Lua link receipt is unreadable: {receipt}") from error
    if not isinstance(decoded, dict) or (
        decoded.get("schema"), decoded.get("format"), decoded.get("target")
    ) != (1, "crabc-x86-64-sealed-static-driver-v1", "x86_64-unknown-linux-musl"):
        raise RunnerError("sealed static Lua link receipt schema drifted")
    selected = decoded.get("mode")
    if not isinstance(selected, dict) or (
        selected.get("id"), selected.get("elf_type"), selected.get("crt_object"), selected.get("interpreter")
    ) != (mode.driver_id, f"ET_{mode.elf_type}", mode.crt_object, "absent"):
        raise RunnerError("sealed static Lua link receipt selected the wrong mode")
    library = sysroot / "usr/lib"
    expected_runtime = (
        ("crt-entry", library / mode.crt_object),
        ("crt-prologue", library / "crti.o"),
        ("libc", library / "libc.a"),
        ("builtins", library / "libcrabc-builtins.a"),
        ("crt-epilogue", library / "crtn.o"),
    )
    records = decoded.get("input_receipts")
    if not isinstance(records, list) or len(records) != len(expected_runtime) + len(objects):
        raise RunnerError("sealed static Lua link receipt has the wrong input count")
    for actual, (role, path) in zip(records[: len(expected_runtime)], expected_runtime):
        expected = {"role": role, "path": str(path.relative_to(sysroot)), "sha256": sha256_file(path)}
        if actual != expected:
            raise RunnerError(f"sealed static Lua runtime receipt drifted: {role}")
    resolved_objects = tuple(path.resolve(strict=True) for path in objects)
    for actual, path in zip(records[len(expected_runtime) :], resolved_objects):
        expected = {"role": "application", "path": str(path), "sha256": sha256_file(path)}
        if actual != expected:
            raise RunnerError(f"sealed static Lua application receipt drifted: {path.name}")
    output_record = decoded.get("output")
    if output_record != {"path": str(output.relative_to(work)), "sha256": sha256_file(output)}:
        raise RunnerError("sealed static Lua output receipt drifted")
    for field, suffix in (("map", ".map"), ("trace", ".trace")):
        sidecar = receipt.with_suffix(suffix)
        expected = {"path": str(sidecar.relative_to(work)), "sha256": sha256_file(sidecar)}
        if decoded.get(field) != expected:
            raise RunnerError(f"sealed static Lua {field} receipt drifted")
    trace_path = receipt.with_suffix(".trace")
    trace_lines = [line for line in trace_path.read_text(encoding="utf-8").splitlines() if line]
    direct = {str(library / mode.crt_object), str(library / "crti.o"), str(library / "crtn.o"), *(str(path) for path in resolved_objects)}
    archives = (str(library / "libc.a"), str(library / "libcrabc-builtins.a"))
    seen: set[str] = set()
    for line in trace_lines:
        if line in direct:
            seen.add(line)
        elif any(line == archive or (line.startswith(f"{archive}(") and line.endswith(")")) for archive in archives):
            seen.add(next(archive for archive in archives if line == archive or line.startswith(f"{archive}(")))
        else:
            raise RunnerError(f"sealed static Lua link trace consumed an unowned input: {line}")
    expected_seen = direct | set(archives)
    if seen != expected_seen:
        raise RunnerError("sealed static Lua link trace omitted an expected input")
    map_text = receipt.with_suffix(".map").read_text(encoding="utf-8", errors="replace")
    for marker in ("/opt/musl-", "/usr/lib/gcc", "compiler-rt", "libgcc", "libc.so", "ld-musl", "ld-linux"):
        if marker in "\n".join(trace_lines) + "\n" + map_text:
            raise RunnerError(f"sealed static Lua link evidence names an ambient runtime input: {marker}")
    return {
        "status": "passed",
        "receipt": artifact_record(receipt),
        "map": artifact_record(receipt.with_suffix(".map")),
        "trace": artifact_record(trace_path),
        "application_object_count": len(objects),
        "runtime_inputs": [role for role, _ in expected_runtime],
    }


def static_link_program(
    wrapper: Path,
    sysroot: Path,
    mode: StaticLuaMode,
    objects: Sequence[Path],
    label: str,
    work: Path,
    timeout: float,
) -> tuple[Path, dict[str, object]]:
    """Link one program only from caller-owned objects and installed runtime bytes."""

    candidate = work / "candidate"
    receipts = work / "receipts"
    candidate.mkdir(exist_ok=True)
    receipts.mkdir(exist_ok=True)
    output = Path("candidate") / label
    receipt = Path("receipts") / f"{label}.json"
    record = command_record(
        [
            str(wrapper),
            mode.driver_flag,
            "--link-receipt",
            str(receipt),
            *(str(path.resolve(strict=True)) for path in objects),
            "-o",
            str(output),
        ],
        cwd=work,
        environment=static_environment(work / f"link-{label}"),
        timeout=timeout,
    )
    require_success(record, f"sealed static link {label}")
    artifact = work / output
    if not artifact.is_file() or artifact.is_symlink():
        raise RunnerError(f"sealed static link did not produce {label}")
    audit = audit_static_link_receipt(
        sysroot=sysroot,
        mode=mode,
        objects=objects,
        work=work,
        output=artifact,
        receipt=work / receipt,
    )
    record["receipt_audit"] = audit
    return artifact, record


def build_static_candidate(
    source: Path,
    support: Path,
    sysroot: Path,
    wrapper: Path,
    mode: StaticLuaMode,
    work: Path,
    timeout: float,
    jobs: int,
) -> dict[str, object]:
    """Build both native Lua tools from a complete object roster through crabc-cc."""

    work.mkdir(parents=True, exist_ok=False)
    flags = static_compiler_flags()
    header_object = work / "header-probe.o"
    header_probe = static_compile_record(
        wrapper,
        mode,
        flags,
        FIXTURES / "header_probe.c",
        header_object,
        work,
        work / "header-probe-tmp",
        timeout,
    )
    plan = static_driver_plan(wrapper, sysroot, mode, work, timeout)
    roster = static_source_roster(source, support)
    compile_records, objects_by_source = parallel_static_compiles(
        wrapper,
        mode,
        flags,
        roster,
        work / "objects",
        work,
        timeout,
        jobs,
    )
    main_lua = "src/lua.c"
    main_luac = "src/luac.c"
    shared = [
        objects_by_source[name]
        for name, _ in roster
        if name not in {main_lua, main_luac}
    ]
    lua, lua_link = static_link_program(
        wrapper, sysroot, mode, [*shared, objects_by_source[main_lua]], "lua", work, timeout
    )
    luac, luac_link = static_link_program(
        wrapper, sysroot, mode, [*shared, objects_by_source[main_luac]], "luac", work, timeout
    )
    artifacts = {
        "lua": static_elf_record(lua, mode, f"candidate {mode.identifier} lua"),
        "luac": static_elf_record(luac, mode, f"candidate {mode.identifier} luac"),
    }
    return {
        "paths": {"lua": lua, "luac": luac},
        "records": {
            "mode": mode.identifier,
            "header_probe": header_probe,
            "driver_plan": plan,
            "compile": compile_records,
            "link": {"lua": lua_link, "luac": luac_link},
            "artifacts": artifacts,
        },
    }


def require_pinned_x86_musl_compiler() -> Path:
    """Admit the independently linked oracle compiler only from its pinned path."""

    compiler = require_physical_regular_file(X86_MUSL_COMPILER, "pinned x86 musl oracle compiler")
    if not os.access(compiler, os.X_OK):
        raise RunnerError("pinned x86 musl oracle compiler is not executable")
    return compiler


def pinned_musl_static_pie_wrapper_diagnostic(work: Path, timeout: float) -> dict[str, object]:
    """Record the pinned wrapper's broken static-PIE startup route separately.

    This is intentionally a tiny independent source input, rather than an
    alternate way to run a candidate. Its result explains why the pinned
    semantic oracle is ET_EXEC for both candidate modes without claiming that
    the owned static-PIE executable shares its startup mode.
    """

    compiler = require_pinned_x86_musl_compiler()
    diagnostic = work / "pinned-musl-static-pie-wrapper"
    diagnostic.mkdir(parents=True, exist_ok=False)
    source = diagnostic / "minimal.c"
    output = diagnostic / "minimal-static-pie"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8", newline="\n")
    compile_record = command_record(
        [str(compiler), "-static-pie", "-fPIE", "-fno-stack-protector", str(source), "-o", str(output)],
        cwd=diagnostic,
        environment=static_environment(diagnostic / "compile"),
        timeout=timeout,
    )
    if compile_record.get("status") != 0:
        return {
            "status": "compile-failed",
            "purpose": "pinned musl wrapper static-PIE startup diagnostic only; not a candidate input",
            "compiler": artifact_record(compiler),
            "source": artifact_record(source),
            "compile": compile_record,
        }
    if not output.is_file() or output.is_symlink():
        raise RunnerError("pinned-musl static-PIE wrapper diagnostic produced no regular executable")
    execution = command_record(
        [str(output)],
        cwd=diagnostic,
        environment=static_environment(diagnostic / "run"),
        timeout=timeout,
    )
    usable = execution.get("status") == 0
    return {
        "status": "executes" if usable else "known-broken",
        "purpose": "pinned musl wrapper static-PIE startup diagnostic only; not a candidate input",
        "compiler": artifact_record(compiler),
        "source": artifact_record(source),
        "artifact": artifact_record(output),
        "compile": compile_record,
        "execution": execution,
        "limitation": (
            "pinned wrapper -static-pie does not execute this minimal program; "
            "the separately linked pinned-musl ET_EXEC oracle remains the semantic reference"
            if not usable
            else "pinned wrapper -static-pie now executes; ET_EXEC remains the recorded semantic reference"
        ),
    }


def build_static_reference(
    source: Path,
    support: Path,
    work: Path,
    timeout: float,
) -> dict[str, object]:
    """Build the independent ET_EXEC pinned-musl behavior oracle from source."""

    compiler = require_pinned_x86_musl_compiler()
    reference_mode = static_reference_mode()
    reference = work / "reference"
    reference.mkdir(parents=True, exist_ok=False)
    roster = static_source_roster(source, support)
    sources_by_name = dict(roster)
    shared = [
        path for name, path in roster if name not in {"src/lua.c", "src/luac.c"}
    ]
    records: dict[str, object] = {}
    paths: dict[str, Path] = {}
    for label, main in (("lua", "src/lua.c"), ("luac", "src/luac.c")):
        output = Path("reference") / label
        record = command_record(
            [
                str(compiler),
                reference_mode.driver_flag,
                "-no-pie",
                *static_compiler_flags(),
                "-I",
                str(source / "src"),
                *(str(path) for path in [*shared, sources_by_name[main]]),
                "-lm",
                "-o",
                str(output),
            ],
            cwd=work,
            environment=static_environment(work / f"oracle-{label}"),
            timeout=timeout,
        )
        require_success(record, f"pinned-musl static {label} source build")
        artifact = work / output
        if not artifact.is_file() or artifact.is_symlink():
            raise RunnerError(f"pinned-musl static {label} source build produced no regular executable")
        records[label] = record
        paths[label] = artifact
    return {
        "paths": paths,
        "records": {
            "compiler": artifact_record(compiler),
            "mode": reference_mode.identifier,
            "role": (
                "pinned musl 1.2.6 ET_EXEC source-build execution oracle for both owned static modes; "
                "not a candidate input"
            ),
            "link": records,
            "artifacts": {
                name: static_elf_record(path, reference_mode, f"pinned-musl {reference_mode.identifier} {name}")
                for name, path in paths.items()
            },
        },
    }


def run_static_lua(
    command: Sequence[str],
    script: Path,
    module_directory: Path,
    fixture_directory: Path,
    state: Path,
    timeout: float,
) -> ProcessResult:
    """Execute a static Lua workload without loader paths or `/proc/maps` claims."""

    environment = static_environment(state)
    environment.update(
        {
            "CRABC_LUA_ENV": "owned-sysroot",
            "CRABC_LUA_DYNAMIC_MODULES": "0",
        }
    )
    if "LD_LIBRARY_PATH" in environment:
        raise RunnerError("native Lua static execution inherited LD_LIBRARY_PATH")
    try:
        process = subprocess.Popen(
            [*command, str(script), str(module_directory), str(fixture_directory)],
            cwd=fixture_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode())
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = stop_owned_process_group(process)
        return ProcessResult("TIMEOUT", stdout, stderr, True)
    except BaseException:
        stop_owned_process_group(process)
        raise
    if owned_group_has_live_members(process.pid):
        stop_owned_process_group(process)
        return ProcessResult("PROCESS_GROUP_LEAK", stdout, stderr)
    return ProcessResult(process.returncode, stdout, stderr)


def require_workload_success(result: ProcessResult, label: str) -> None:
    if result.status != 0 or result.timed_out:
        raise RunnerError(f"{label} did not complete successfully: {result.status}")


def run_static_workloads(
    candidate: Mapping[str, Path],
    reference: Mapping[str, Path],
    support: Path,
    work: Path,
    timeout: float,
) -> dict[str, object]:
    """Compare identical source and bytecode workloads against separate musl binaries."""

    script = FIXTURES / "exercise.lua"
    bytecode = work / "bytecode"
    bytecode.mkdir(parents=True, exist_ok=False)
    candidate_bytecode = bytecode / "candidate.luac"
    reference_bytecode = bytecode / "reference.luac"
    candidate_luac = command_record(
        [str(candidate["luac"]), "-o", str(candidate_bytecode), str(script)],
        cwd=work,
        environment=static_environment(work / "candidate-luac"),
        timeout=timeout,
    )
    require_success(candidate_luac, "candidate static luac bytecode build")
    reference_luac = command_record(
        [str(reference["luac"]), "-o", str(reference_bytecode), str(script)],
        cwd=work,
        environment=static_environment(work / "reference-luac"),
        timeout=timeout,
    )
    require_success(reference_luac, "pinned-musl static luac bytecode build")
    for path in (candidate_bytecode, reference_bytecode):
        if not path.is_file() or path.is_symlink():
            raise RunnerError(f"static luac did not produce bytecode: {path.name}")
    fixtures = work / "fixture-state"
    fixtures.mkdir(parents=True, exist_ok=False)
    runs = {
        "source_reference": (reference["lua"], script, fixtures / "source-reference"),
        "source_candidate": (candidate["lua"], script, fixtures / "source-candidate"),
        "bytecode_reference": (reference["lua"], reference_bytecode, fixtures / "bytecode-reference"),
        "bytecode_candidate": (candidate["lua"], candidate_bytecode, fixtures / "bytecode-candidate"),
    }
    results: dict[str, ProcessResult] = {}
    for label, (program, workload, fixture) in runs.items():
        fixture.mkdir(parents=True, exist_ok=False)
        results[label] = run_static_lua(
            [str(program)], workload, support, fixture, work / f"run-{label}", timeout
        )
        require_workload_success(results[label], f"static Lua {label}")
    source = result_comparison(results["source_reference"], results["source_candidate"])
    bytecode_result = result_comparison(results["bytecode_reference"], results["bytecode_candidate"])
    if source.get("passed") is not True or bytecode_result.get("passed") is not True:
        raise RunnerError("static Lua source or bytecode output differs from the pinned-musl oracle")
    return {
        "candidate_luac": candidate_luac,
        "reference_luac": reference_luac,
        "bytecode_artifacts": {
            "candidate": artifact_record(candidate_bytecode),
            "reference": artifact_record(reference_bytecode),
        },
        "source": source,
        "bytecode": bytecode_result,
        "static_mode_boundary": {
            "runtime_dso_loading": "not applicable: C modules are linked as package.preload entries",
            "candidate_maps": "not collected: static mode makes no loader or runtime-DSO map claim",
            "missing_dso_symbol": "not applicable: no runtime DSO is loaded in static mode",
            "linked_preload_extensions": ["crabc_probe", "crabc_fail"],
            "io_popen": "required and exercised by each source and bytecode workload",
        },
    }


def run_x86_static(args: argparse.Namespace) -> dict[str, object]:
    """Run the installed native static source-build qualification slice."""

    require_native_x86_64()
    work_root = native_work_root(args.work_root)
    manifest = load_manifest(args.manifest)
    archive = fetch_archive(manifest, args.offline, native_source_cache(work_root))
    sysroot, wrapper, runtime, installed_manifest = owned_static_sysroot(args.sysroot)
    oracle = require_pinned_x86_musl_compiler()
    modes = selected_static_modes(args.mode)
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=work_root))
    report: dict[str, object] = {
        "schema_version": 2,
        "runner": "crabc-lua-native-x86-static-source-build",
        "result": "fail",
        "passed": False,
        "manifest": {"path": str(args.manifest), "sha256": sha256_file(args.manifest), "contents": manifest},
        "source_archive": artifact_record(archive),
        "work_directory": str(run_root),
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "kernel": platform.release(),
            "sysroot": str(sysroot),
            "compiler_wrapper": str(wrapper),
            "owned_runtime_inputs": {name: artifact_record(path) for name, path in runtime.items() if name != "headers"},
            "owned_headers": str(runtime["headers"]),
            "sysroot_manifest": installed_manifest,
            "musl_compiler": artifact_record(oracle),
            "musl_role": (
                "pinned musl 1.2.6 separately links and executes ET_EXEC reference source for both candidate modes; "
                "it never receives candidate bytes"
            ),
            "timeout_seconds": args.timeout,
            "jobs": args.jobs,
        },
        "modes": {},
    }
    try:
        lua = manifest["lua"]
        assert isinstance(lua, dict)
        source = safe_extract(archive, run_root / "source", str(lua["archive_root"]))
        support, support_record = prepare_static_preload_support(source)
        report["static_preload_staging"] = support_record
        report["pinned_musl_static_pie_wrapper"] = pinned_musl_static_pie_wrapper_diagnostic(
            run_root, args.timeout
        )
        mode_records = report["modes"]
        assert isinstance(mode_records, dict)
        all_passed = True
        for mode in modes:
            mode_root = run_root / mode.identifier
            candidate = build_static_candidate(
                source, support, sysroot, wrapper, mode, mode_root, args.timeout, args.jobs
            )
            reference = build_static_reference(source, support, mode_root, args.timeout)
            candidate_paths = candidate["paths"]
            reference_paths = reference["paths"]
            assert isinstance(candidate_paths, dict) and isinstance(reference_paths, dict)
            workloads = run_static_workloads(candidate_paths, reference_paths, support, mode_root, args.timeout)
            mode_records[mode.identifier] = {
                "candidate_mode": mode.identifier,
                "reference_mode": static_reference_mode().identifier,
                "candidate": candidate["records"],
                "reference": reference["records"],
                "workloads": workloads,
            }
            all_passed = all_passed and workloads["source"]["passed"] is True and workloads["bytecode"]["passed"] is True
        report["passed"] = all_passed
        report["result"] = "pass" if all_passed else "fail"
    except RunnerError as error:
        report["error"] = str(error)
    return report


def allocate_x86_static_dispatch_state(parent: Path = DEFAULT_X86_STATIC_WORK_ROOT) -> Path:
    """Allocate one physical private producer/qualification root below ``.work``."""

    parent = native_work_root(parent)
    state = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    state = require_physical_directory(state, "native Lua static dispatcher invocation root")
    try:
        state.relative_to(parent)
    except ValueError as error:
        raise RunnerError("native Lua static dispatcher invocation root escaped its parent") from error
    return state


def publish_x86_static_dispatch_report(
    report: Path, latest_report: Path = DEFAULT_X86_STATIC_REPORT
) -> Path:
    """Atomically replace a latest report from a passing private report."""

    report = require_physical_regular_file(report, "native Lua static dispatcher report")
    latest_report = Path(os.path.abspath(latest_report))
    parent = latest_report.parent
    reject_symlinked_components(parent, "native Lua static report directory")
    parent.mkdir(parents=True, exist_ok=True)
    parent = require_physical_directory(parent, "native Lua static report directory")
    latest = parent / latest_report.name
    if os.path.lexists(latest) and latest.is_symlink():
        raise RunnerError(f"native Lua static latest report is a symlink: {latest}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".x86_64-static-latest.", dir=parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(report.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(latest)
    except OSError as error:
        raise RunnerError("cannot publish native Lua static latest report") from error
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return require_physical_regular_file(latest, "native Lua static published latest report")


def run_x86_static_dispatch(
    *,
    jobs: int,
    timeout: float,
    state_parent: Path = DEFAULT_X86_STATIC_WORK_ROOT,
    latest_report: Path = DEFAULT_X86_STATIC_REPORT,
    builder: Path | None = None,
    static_runner: Any | None = None,
) -> tuple[dict[str, object], Path, Path | None]:
    """Materialize and qualify one isolated installed x86 Lua static product.

    The producer is the only subprocess here. The Lua qualification runs in
    this process so its bounded compile children remain owned by the runner's
    existing process-group cleanup rather than escaping through a second
    dispatcher process group.
    """

    if jobs < 1 or jobs > MAX_JOBS:
        raise RunnerError(f"native Lua static dispatcher jobs must be from 1 through {MAX_JOBS}")
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
        raise RunnerError("native Lua static dispatcher timeout must be > 0 and <= 300")
    latest_report = Path(os.path.abspath(latest_report))
    disable_core_dump_inheritance()
    state = allocate_x86_static_dispatch_state(state_parent)
    report_path = state / "report.json"
    sysroot = state / "sysroot"
    dispatcher: dict[str, object] = {
        "state_root": str(state),
        "authoritative_report": str(report_path),
        "producer": None,
        "latest_report": str(latest_report),
        "latest_report_publication": "only after a passing private report",
    }
    try:
        selected_builder = require_physical_regular_file(
            builder if builder is not None else ROOT / "scripts/build_x86_64_owned_sysroot.py",
            "native Lua static sysroot builder",
        )
        producer = command_record(
            [sys.executable, "-B", str(selected_builder), "--output", str(sysroot)],
            cwd=ROOT,
            environment=static_environment(state / "producer"),
            timeout=timeout,
        )
        dispatcher["producer"] = producer
        require_success(producer, "native Lua static sysroot producer")
        require_physical_directory(sysroot, "native Lua static produced sysroot")
        inner_args = argparse.Namespace(
            manifest=MANIFEST,
            sysroot=sysroot,
            target="x86_64-static",
            mode=None,
            work_root=state / "runs",
            jobs=jobs,
            report=report_path,
            offline=False,
            timeout=timeout,
        )
        execute = run_x86_static if static_runner is None else static_runner
        report = execute(inner_args)
        if not isinstance(report, dict):
            raise RunnerError("native Lua static dispatcher runner returned no report object")
    except RunnerError as error:
        report = {
            "schema_version": 2,
            "runner": "crabc-lua-native-x86-static-source-build",
            "result": "fail",
            "passed": False,
            "error": str(error),
        }
    report["dispatcher"] = dispatcher
    write_json_atomic(report_path, report)
    if report.get("passed") is not True or report.get("result") != "pass":
        return report, report_path, None
    try:
        latest = publish_x86_static_dispatch_report(report_path, latest_report)
    except RunnerError as error:
        raise RunnerError(f"{error}; retained authoritative report: {report_path}") from error
    return report, report_path, latest


def run_aarch64_dynamic(args: argparse.Namespace) -> dict[str, object]:
    require_native_aarch64()
    manifest = load_manifest(args.manifest)
    archive = fetch_archive(manifest, args.offline)
    sysroot, wrapper, runtime, installed_manifest = owned_sysroot(args.sysroot)
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "crabc-lua-owned-sysroot",
        "result": "fail",
        "passed": False,
        "manifest": {"path": str(args.manifest), "sha256": sha256_file(args.manifest), "contents": manifest},
        "source_archive": artifact_record(archive),
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "kernel": platform.release(),
            "sysroot": str(sysroot),
            "compiler_wrapper": str(wrapper),
            "owned_runtime_inputs": {name: artifact_record(path) for name, path in runtime.items()},
            "sysroot_manifest": installed_manifest,
            "musl_root": str(MUSL_ROOT),
            "musl_role": "pinned execution oracle only; never a candidate build or link input",
            "timeout_seconds": args.timeout,
        },
    }
    try:
        with tempfile.TemporaryDirectory(prefix="crabc-lua-") as temporary:
            graph = build_graph(manifest, sysroot, Path(temporary), args.timeout)
            report["build"] = graph["records"]
            workloads = run_workloads(graph, Path(temporary), args.timeout)
            report["workloads"] = workloads
            maps = workloads["candidate_maps"]
            assert isinstance(maps, dict)
            if maps.get("status") != "passed":
                raise RunnerError(f"candidate runtime mapping isolation failed: {maps.get('errors')}")
            source = workloads["source"]
            bytecode = workloads["bytecode"]
            assert isinstance(source, dict) and isinstance(bytecode, dict)
            report["passed"] = source.get("passed") is True and bytecode.get("passed") is True
            report["result"] = "pass" if report["passed"] else "fail"
    except RunnerError as error:
        report["error"] = str(error)
    return report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--sysroot", type=Path, default=DEFAULT_SYSROOT)
    parser.add_argument(
        "--target",
        choices=("aarch64-dynamic", "x86_64-static"),
        default="aarch64-dynamic",
        help="preserve the established AArch64 dynamic lane or select native x86 static source builds",
    )
    parser.add_argument(
        "--mode",
        action="append",
        choices=("static", "static-pie"),
        help="native x86 static mode; repeat for both (the x86 default is both)",
    )
    parser.add_argument("--work-root", type=Path, default=DEFAULT_X86_STATIC_WORK_ROOT)
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be > 0 and <= 300")
    if args.target == "x86_64-static":
        if args.jobs < 1 or args.jobs > MAX_JOBS:
            parser.error(f"--jobs must be an integer from 1 through {MAX_JOBS}")
    if args.target == "aarch64-dynamic" and args.mode:
        parser.error("--mode is available only with --target x86_64-static")
    if args.mode:
        args.mode = ["static-et-exec" if mode == "static" else mode for mode in args.mode]
    if args.report is None:
        args.report = DEFAULT_X86_STATIC_REPORT if args.target == "x86_64-static" else DEFAULT_REPORT
    return args


def run(args: argparse.Namespace) -> dict[str, object]:
    disable_core_dump_inheritance()
    if args.target == "x86_64-static":
        return run_x86_static(args)
    return run_aarch64_dynamic(args)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = run(args)
    write_json_atomic(args.report, report)
    print(f"lua owned-sysroot: {report['result']}; report {args.report}")
    if report.get("error"):
        print(f"lua owned-sysroot error: {report['error']}", file=sys.stderr)
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
