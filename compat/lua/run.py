#!/usr/bin/env python3
"""Build pinned Lua as a crabc adapter-sysroot source-build gate.

The target program is compiled once with crabc headers and link names.  The
same Lua, luac, liblua, and extension bytes then run under a pinned-musl
reference interpreter and crabc's loader/libc.  Musl CRT start objects are an
explicitly recorded bridge only; no musl libc target library is permitted.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import platform
import re
import resource
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
LUA_ROOT = Path(__file__).resolve().parent
MANIFEST = LUA_ROOT / "manifest.toml"
FIXTURES = LUA_ROOT / "fixtures"
CACHE = LUA_ROOT / ".cache"
DEFAULT_REPORT = ROOT / "compat/reports/lua/latest.json"
MUSL_ROOT = Path("/opt/musl-1.2.6")
LINK_NAMES = (
    "libm.so",
    "libm.so.1",
    "libdl.so",
    "libdl.so.2",
    "libpthread.so",
    "libpthread.so.0",
    "librt.so",
    "librt.so.1",
    "libutil.so",
    "libutil.so.1",
)
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


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    status: int | str
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


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


def command_record(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout: float = 120.0,
) -> dict[str, object]:
    """Run one build/probe command and retain raw output without shell parsing."""

    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "status": result.returncode,
            "stdout": stream_record(result.stdout),
            "stderr": stream_record(result.stderr),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "status": "TIMEOUT",
            "stdout": stream_record(error.stdout or b""),
            "stderr": stream_record(error.stderr or b""),
        }
    except OSError as error:
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "status": f"EXEC_ERROR:{error.errno or 'unknown'}",
            "stdout": stream_record(b""),
            "stderr": stream_record(str(error).encode()),
        }


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
        raise RunnerError("Lua adapter gate must use pinned musl 1.2.6 CRT objects")
    return raw


def source_archive_path(manifest: Mapping[str, object]) -> Path:
    lua = manifest["lua"]
    assert isinstance(lua, dict)
    return CACHE / f"lua-{lua['version']}.tar.gz"


def fetch_archive(manifest: Mapping[str, object], offline: bool) -> Path:
    """Fetch the pinned source only when a verified cache entry is absent."""

    lua = manifest["lua"]
    assert isinstance(lua, dict)
    archive = source_archive_path(manifest)
    expected = str(lua["sha256"])
    if archive.is_file() and sha256_file(archive) == expected:
        return archive
    if archive.exists():
        archive.unlink()
    if offline:
        raise RunnerError(f"verified Lua archive is absent from offline cache: {archive}")
    CACHE.mkdir(parents=True, exist_ok=True)
    partial = CACHE / f".{archive.name}.part"
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


def copy_crabc_sysroot(target_dir: Path, sysroot: Path, compiler: str) -> dict[str, object]:
    """Create a disposable crabc-only target header/library sysroot."""

    include = sysroot / "include"
    library = sysroot / "lib"
    bridge = sysroot / "bridge"
    shutil.copytree(ROOT / "include", include)
    library.mkdir(parents=True)
    bridge.mkdir()
    artifacts: dict[str, object] = {}
    for name in ("libc.so", "libc.a", "libldso.so"):
        source = target_dir / name
        destination = library / name
        shutil.copy2(source, destination)
        artifacts[name] = artifact_record(destination)
    for name in LINK_NAMES:
        (library / name).symlink_to("libc.so")
    (library / "libc.musl-aarch64.so.1").symlink_to("libc.so")
    # These files are an explicit, narrowly-scoped bootstrap bridge.  crabc
    # does not yet publish its own application CRT objects; the library and
    # interpreter inputs remain entirely staged crabc artifacts.
    for name in ("Scrt1.o", "crti.o", "crtn.o"):
        source = MUSL_ROOT / "lib" / name
        if not source.is_file():
            raise RunnerError(f"pinned musl CRT bridge object is absent: {source}")
        destination = bridge / name
        shutil.copy2(source, destination)
        artifacts[f"bridge/{name}"] = artifact_record(destination)
    for name in ("crtbeginS.o", "crtendS.o"):
        source = Path(command_output([compiler, f"-print-file-name={name}"]))
        if not source.is_file():
            raise RunnerError(f"GCC CRT bridge object is absent: {source}")
        destination = bridge / name
        shutil.copy2(source, destination)
        artifacts[f"bridge/{name}"] = artifact_record(destination)
    return artifacts


def compiler_flags(sysroot: Path, builtin_include: Path) -> list[str]:
    return [
        "-std=gnu99",
        "-O2",
        "-fPIC",
        "-fno-builtin",
        "-fno-stack-protector",
        "-nostdinc",
        "-isystem",
        str(sysroot / "include"),
        "-isystem",
        str(builtin_include),
        "-DLUA_USE_LINUX",
    ]


def header_probe(compiler: str, flags: Sequence[str], work: Path) -> dict[str, object]:
    probe = FIXTURES / "header_probe.c"
    output = work / "header-probe.o"
    record = command_record([compiler, *flags, "-H", "-c", str(probe), "-o", str(output)])
    require_success(record, "crabc-only C header probe")
    stderr = record["stderr"]
    assert isinstance(stderr, dict)
    trace = stderr["text"]
    assert isinstance(trace, str)
    if "/opt/musl" in trace or "/usr/include" in trace:
        raise RunnerError("header probe fell through to musl or ambient system headers")
    return record


def compile_source(
    compiler: str,
    flags: Sequence[str],
    source: Path,
    object_path: Path,
    extra: Sequence[str] = (),
) -> dict[str, object]:
    record = command_record([compiler, *flags, *extra, "-c", str(source), "-o", str(object_path)])
    require_success(record, f"compile {source.name}")
    return record


def link_shared(
    compiler: str,
    objects: Sequence[Path],
    output: Path,
    sysroot: Path,
    soname: str,
    libraries: Sequence[str],
    allow_undefined: bool = False,
) -> dict[str, object]:
    definition_flags = ["-Wl,--allow-shlib-undefined"] if allow_undefined else ["-Wl,-z,defs"]
    record = command_record(
        [
            compiler,
            "-nostdlib",
            "-shared",
            *definition_flags,
            "-Wl,-z,relro",
            "-Wl,-z,now",
            "-Wl,--no-as-needed",
            "-Wl,-t",
            f"-Wl,-soname,{soname}",
            "-Wl,-rpath,$ORIGIN",
            "-o",
            str(output),
            *(str(item) for item in objects),
            "-L",
            str(sysroot / "lib"),
            *libraries,
            "-lgcc",
        ]
    )
    require_success(record, f"link {output.name}")
    link_text = json.dumps(record)
    if "/opt/musl-1.2.6/lib" in link_text:
        raise RunnerError(f"link {output.name} consumed a pinned-musl runtime library")
    return record


def link_executable(
    compiler: str,
    objects: Sequence[Path],
    output: Path,
    sysroot: Path,
    link_liblua: bool,
) -> dict[str, object]:
    bridge = sysroot / "bridge"
    interpreter = sysroot / "lib/libldso.so"
    record = command_record(
        [
            compiler,
            "-nostdlib",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro",
            "-Wl,-z,now",
            "-Wl,--no-as-needed",
            "-Wl,-t",
            "-Wl,-rpath,$ORIGIN/../lib",
            f"-Wl,--dynamic-linker={interpreter}",
            "-o",
            str(output),
            str(bridge / "Scrt1.o"),
            str(bridge / "crti.o"),
            str(bridge / "crtbeginS.o"),
            *(str(item) for item in objects),
            *( ["-L", str(sysroot / "lib"), "-llua"] if link_liblua else [] ),
            "-L",
            str(sysroot / "lib"),
            "-lm",
            "-ldl",
            "-lc",
            "-lgcc",
            str(bridge / "crtendS.o"),
            str(bridge / "crtn.o"),
        ]
    )
    require_success(record, f"link {output.name}")
    link_text = json.dumps(record)
    if "/opt/musl-1.2.6/lib" in link_text:
        raise RunnerError(f"link {output.name} consumed a pinned-musl runtime library")
    return record


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


def validate_candidate_elf(artifacts: Mapping[str, object], candidate_library: Path) -> None:
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
        expected = str(candidate_library / "libldso.so")
        if expected not in headers:
            raise RunnerError(f"candidate {name} does not name the staged crabc loader")
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


def sanitize_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_", "LUA_", "CRABC_", "MUSL_", "RUST", "CARGO")):
            environment.pop(key, None)
    environment.update({"PATH": "/bin:/usr/bin", "HOME": "/tmp", "TMPDIR": "/tmp", "LC_ALL": "C"})
    return environment


def run_lua(
    binary: Path,
    script: Path,
    library: Path,
    fixture_dir: Path,
    timeout: float,
    capture_maps: bool,
) -> tuple[ProcessResult, str | None]:
    environment = sanitize_environment()
    environment.update(
        {
            "LD_LIBRARY_PATH": str(library),
            "CRABC_LUA_ENV": "adapter-sysroot",
            "CRABC_LUA_MAPS_WAIT": "1",
        }
    )

    def disable_core_dump() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    try:
        process = subprocess.Popen(
            [str(binary), str(script), str(library), str(fixture_dir)],
            cwd=fixture_dir,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=disable_core_dump,
            close_fds=True,
        )
    except OSError as error:
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode()), None
    assert process.stdin is not None and process.stdout is not None
    ready = b""
    maps: str | None = None
    try:
        ready_stream, _, _ = select.select([process.stdout], [], [], timeout)
        if not ready_stream:
            process.kill()
            stdout, stderr = process.communicate()
            return ProcessResult("TIMEOUT", stdout, stderr, True), None
        ready = process.stdout.readline()
        if ready != b"maps-ready\n":
            process.kill()
            stdout, stderr = process.communicate()
            return ProcessResult("PROTOCOL_ERROR", ready + stdout, stderr), None
        if capture_maps:
            maps_path = Path(f"/proc/{process.pid}/maps")
            maps = maps_path.read_text(encoding="utf-8")
        process.stdin.write(b"continue\n")
        process.stdin.flush()
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        stdout, stderr = process.communicate()
        return ProcessResult("TIMEOUT", ready + stdout + (error.stdout or b""), stderr + (error.stderr or b""), True), maps
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


def syscall_diagnostic(binary: Path, script: Path, library: Path, fixture_dir: Path, trace: Path, timeout: float) -> dict[str, object]:
    if shutil.which("strace") is None:
        return {"status": "unsupported", "reason": "strace unavailable", "diagnostic": True, "timing": False}
    environment = sanitize_environment()
    environment.update({"LD_LIBRARY_PATH": str(library), "CRABC_LUA_ENV": "adapter-sysroot"})
    record = command_record(
        ["strace", "-f", "-qq", "-o", str(trace), str(binary), str(script), str(library), str(fixture_dir)],
        cwd=fixture_dir,
        environment=environment,
        timeout=timeout,
    )
    result: dict[str, object] = {"diagnostic": True, "timing": False, "command": record, "status": record["status"]}
    if trace.is_file():
        result.update(syscall_summary(trace.read_text(encoding="utf-8", errors="replace")))
    return result


def verify_candidate_maps(maps: str, candidate_library: Path) -> dict[str, object]:
    required = ("libldso.so", "libc.so", "liblua.so.5.4", "crabc_probe.so")
    missing = [name for name in required if name not in maps]
    forbidden = ("/opt/musl-1.2.6", "libc.so.6", "ld-linux", "libc.musl-")
    seen_forbidden = [name for name in forbidden if name in maps]
    if missing or seen_forbidden:
        raise RunnerError(f"candidate runtime mapping isolation failed; missing={missing}, forbidden={seen_forbidden}")
    expected = str(candidate_library / "libc.so")
    if expected not in maps:
        raise RunnerError(f"candidate map did not contain staged crabc libc: {expected}")
    return {"path": "/proc/<candidate>/maps", "text": maps, "no_musl_libc": True}


def build_graph(manifest: Mapping[str, object], target_dir: Path, work: Path, timeout: float) -> dict[str, object]:
    lua = manifest["lua"]
    assert isinstance(lua, dict)
    source = safe_extract(source_archive_path(manifest), work / "source", str(lua["archive_root"]))
    compiler = require_command("gcc")
    sysroot = work / "candidate"
    artifacts = copy_crabc_sysroot(target_dir, sysroot, compiler)
    candidate_lib = sysroot / "lib"
    candidate_bin = sysroot / "bin"
    candidate_bin.mkdir()
    object_dir = work / "objects"
    object_dir.mkdir()
    builtin = Path(command_output([compiler, "-print-file-name=include"])).resolve()
    if not builtin.is_dir():
        raise RunnerError(f"compiler builtin include directory is invalid: {builtin}")
    flags = compiler_flags(sysroot, builtin)
    records: dict[str, object] = {
        "compiler": compiler,
        "builtin_include": str(builtin),
        "header_probe": header_probe(compiler, flags, work),
        "compile": {},
        "link": {},
        "sysroot_artifacts": artifacts,
    }
    compile_records = records["compile"]
    assert isinstance(compile_records, dict)
    objects: list[Path] = []
    for name in (*CORE_SOURCES, *LIB_SOURCES):
        object_path = object_dir / f"{name}.o"
        compile_records[name] = compile_source(compiler, flags, source / "src" / name, object_path)
        objects.append(object_path)
    liblua = candidate_lib / "liblua.so.5.4"
    link_records = records["link"]
    assert isinstance(link_records, dict)
    link_records["liblua"] = link_shared(
        compiler, objects, liblua, sysroot, "liblua.so.5.4", ("-lc", "-lm", "-ldl")
    )
    (candidate_lib / "liblua.so").symlink_to("liblua.so.5.4")
    for main in ("lua", "luac"):
        object_path = object_dir / f"{main}.o"
        compile_records[f"{main}.c"] = compile_source(compiler, flags, source / "src" / f"{main}.c", object_path)
        main_objects = [object_path] if main == "lua" else [object_path, *objects]
        link_records[main] = link_executable(compiler, main_objects, candidate_bin / main, sysroot, main == "lua")
    lua_include = source / "src"
    for source_name, soname in (("crabc_probe.c", "crabc_probe.so"), ("crabc_fail.c", "crabc_fail.so")):
        object_path = object_dir / f"{source_name}.o"
        compile_records[source_name] = compile_source(compiler, [*flags, "-I", str(lua_include)], FIXTURES / source_name, object_path)
        # A Lua module deliberately leaves Lua API references unresolved.  At
        # module load they resolve from the interpreter's already-loaded
        # liblua, exercising the loader's normal module path.
        link_records[soname] = link_shared(
            compiler, [object_path], candidate_lib / soname, sysroot, soname, ("-lc",), allow_undefined=True
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
    validate_candidate_elf(artifacts_by_name, candidate_lib)
    records["artifacts"] = artifacts_by_name
    return {"sysroot": sysroot, "source": source, "records": records}


def prepare_reference(candidate_sysroot: Path, work: Path) -> Path:
    reference = work / "reference"
    reference_lib = reference / "lib"
    reference_bin = reference / "bin"
    reference_lib.mkdir(parents=True)
    reference_bin.mkdir()
    for name in ("liblua.so.5.4", "crabc_probe.so", "crabc_fail.so", "crabc_missing.so"):
        shutil.copy2(candidate_sysroot / "lib" / name, reference_lib / name)
    # Keep the reference runtime self-contained and pinned.  The executable
    # and DSOs are the candidate-built bytes, but their reference execution
    # must resolve libc from the recorded musl installation rather than an
    # incidental Alpine system library-search path.
    shutil.copy2(MUSL_ROOT / "lib/libc.so", reference_lib / "libc.so")
    (reference_lib / "liblua.so").symlink_to("liblua.so.5.4")
    for name in ("lua", "luac"):
        patch_interpreter(candidate_sysroot / "bin" / name, reference_bin / name, MUSL_ROOT / "lib/ld-musl-aarch64.so.1")
    return reference


def run_workloads(graph: Mapping[str, object], work: Path, timeout: float) -> dict[str, object]:
    sysroot = graph["sysroot"]
    assert isinstance(sysroot, Path)
    reference = prepare_reference(sysroot, work)
    fixture_dir = work / "fixture-state"
    fixture_dir.mkdir()
    script = FIXTURES / "exercise.lua"
    luac_output = fixture_dir / "exercise.luac"
    candidate_luac = command_record(
        [str(sysroot / "bin/luac"), "-o", str(luac_output), str(script)],
        cwd=fixture_dir,
        environment={**sanitize_environment(), "LD_LIBRARY_PATH": str(sysroot / "lib")},
        timeout=timeout,
    )
    require_success(candidate_luac, "candidate luac bytecode build")
    if not luac_output.is_file():
        raise RunnerError("candidate luac did not produce bytecode")
    source_reference, _ = run_lua(reference / "bin/lua", script, reference / "lib", fixture_dir, timeout, False)
    source_candidate, maps = run_lua(sysroot / "bin/lua", script, sysroot / "lib", fixture_dir, timeout, True)
    bytecode_reference, _ = run_lua(reference / "bin/lua", luac_output, reference / "lib", fixture_dir, timeout, False)
    bytecode_candidate, _ = run_lua(sysroot / "bin/lua", luac_output, sysroot / "lib", fixture_dir, timeout, False)
    if maps is None:
        raise RunnerError("candidate Lua process did not provide /proc maps evidence")
    maps_record = verify_candidate_maps(maps, sysroot / "lib")
    trace_dir = work / "traces"
    trace_dir.mkdir()
    return {
        "reference": str(reference),
        "candidate_luac": candidate_luac,
        "source": result_comparison(source_reference, source_candidate),
        "bytecode": result_comparison(bytecode_reference, bytecode_candidate),
        "candidate_maps": maps_record,
        "syscalls": {
            "normal_module": syscall_diagnostic(
                sysroot / "bin/lua", script, sysroot / "lib", fixture_dir, trace_dir / "normal.strace", timeout
            ),
            "failure_module": syscall_diagnostic(
                sysroot / "bin/lua", script, sysroot / "lib", fixture_dir, trace_dir / "failure.strace", timeout
            ),
        },
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    require_native_aarch64()
    manifest = load_manifest(args.manifest)
    archive = fetch_archive(manifest, args.offline)
    target_dir = args.target_dir.resolve()
    for name in ("libc.so", "libc.a", "libldso.so"):
        if not (target_dir / name).is_file():
            raise RunnerError(f"missing release crabc artifact: {target_dir / name}")
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "crabc-lua-adapter-sysroot",
        "result": "fail",
        "passed": False,
        "manifest": {"path": str(args.manifest), "sha256": sha256_file(args.manifest), "contents": manifest},
        "source_archive": artifact_record(archive),
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "kernel": platform.release(),
            "target_dir": str(target_dir),
            "musl_root": str(MUSL_ROOT),
            "timeout_seconds": args.timeout,
        },
    }
    try:
        with tempfile.TemporaryDirectory(prefix="crabc-lua-") as temporary:
            graph = build_graph(manifest, target_dir, Path(temporary), args.timeout)
            report["build"] = graph["records"]
            workloads = run_workloads(graph, Path(temporary), args.timeout)
            report["workloads"] = workloads
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
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/release")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be > 0 and <= 300")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = run(args)
    write_json_atomic(args.report, report)
    print(f"lua adapter-sysroot: {report['result']}; report {args.report}")
    if report.get("error"):
        print(f"lua adapter-sysroot error: {report['error']}", file=sys.stderr)
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
