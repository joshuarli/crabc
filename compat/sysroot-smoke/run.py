#!/usr/bin/env python3
"""Smoke-test an extracted crabc sysroot archive on native Linux/AArch64.

The archive is the boundary under test.  This runner never rebuilds or repairs
it, and it never installs its loader into the host root.  Build tools are used
only through the relocatable ``crabc-cc`` shipped in the extracted tree.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
DEFAULT_REPORT = ROOT / "compat/reports/sysroot-smoke/latest.json"
EXPECTED_OUTPUT = b"crabc sysroot dynamic smoke ok\n"
EXPECTED_STATIC_OUTPUT = b"static pthread tls ok\n"
MAX_TIMEOUT = 300.0
SHA256 = re.compile(r"[0-9a-f]{40}")
FORBIDDEN_BUILD_PATH_PREFIXES = ("/workspace/", "/tmp/", "/home/", "/Users/", "/root/")


class SmokeError(RuntimeError):
    """An archive, toolchain, or extracted-runtime contract failure."""


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SmokeError(f"cannot load reusable evidence module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SYSROOT = _load_module("crabc_sysroot_smoke_tool", ROOT / "scripts/crabc_sysroot.py")
SYSROOT_RUNNER = _load_module("crabc_sysroot_smoke_runner", ROOT / "compat/sysroot/run.py")
DIST = _load_module("crabc_sysroot_smoke_dist", ROOT / "scripts/sysroot_dist.py")


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
    environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float,
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
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "status": "TIMEOUT",
            "timed_out": True,
            "stdout": stream_record(error.stdout or b""),
            "stderr": stream_record(error.stderr or b""),
        }
    except OSError as error:
        return {
            "command": list(command),
            "status": f"EXEC_ERROR:{error.errno or 'unknown'}",
            "timed_out": False,
            "stdout": stream_record(b""),
            "stderr": stream_record(str(error).encode()),
        }
    return {
        "command": list(command),
        "status": result.returncode,
        "timed_out": False,
        "stdout": stream_record(result.stdout),
        "stderr": stream_record(result.stderr),
    }


def _member_relative(name: str, root: str) -> PurePosixPath:
    if not name or "\x00" in name:
        raise SmokeError(f"empty or NUL-containing archive member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise SmokeError(f"unsafe archive member path: {name!r}")
    if not path.parts or path.parts[0] != root:
        raise SmokeError(f"archive member is outside expected root {root!r}: {name!r}")
    return path


def _resolve_link(parent: PurePosixPath, target: str, root: str) -> PurePosixPath:
    if not target or "\x00" in target:
        raise SmokeError(f"invalid archive symlink target: {target!r}")
    target_path = PurePosixPath(target)
    if target_path.is_absolute():
        raise SmokeError(f"absolute archive symlink target: {target!r}")
    parts = list(parent.parts)
    for part in target_path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if len(parts) <= 1:
                raise SmokeError(f"archive symlink escapes root: {parent} -> {target}")
            parts.pop()
        else:
            parts.append(part)
    resolved = PurePosixPath(*parts)
    if not resolved.parts or resolved.parts[0] != root:
        raise SmokeError(f"archive symlink escapes root: {parent} -> {target}")
    return resolved


def validate_archive_members(members: Sequence[tarfile.TarInfo]) -> str:
    """Validate member names/types and return the sole top-level directory."""

    if not members:
        raise SmokeError("archive is empty")
    names: list[PurePosixPath] = []
    for member in members:
        path = PurePosixPath(member.name)
        if not path.parts:
            raise SmokeError("archive contains an unnamed member")
        names.append(path)
    roots = {path.parts[0] for path in names}
    if len(roots) != 1:
        raise SmokeError(f"archive must contain one top-level directory, found {sorted(roots)}")
    root = next(iter(roots))
    if root in ("", ".", ".."):
        raise SmokeError(f"invalid archive top-level directory: {root!r}")
    seen: set[PurePosixPath] = set()
    symlinks: dict[PurePosixPath, PurePosixPath] = {}
    for member, path in zip(members, names):
        _member_relative(member.name, root)
        if path in seen:
            raise SmokeError(f"duplicate archive member: {member.name}")
        seen.add(path)
        if member.issym():
            symlinks[path] = _resolve_link(path.parent, member.linkname, root)
        # TarInfo.isdev covers character/block devices and FIFOs.  Python's
        # TarInfo has no portable socket predicate; sockets are not representable
        # as normal tar members and are rejected by the unknown-type branch.
        elif member.islnk() or member.isdev():
            raise SmokeError(f"unsupported archive member type: {member.name}")
        elif not member.isdir() and not member.isreg():
            raise SmokeError(f"unsupported archive member type: {member.name}")
    if PurePosixPath(root) not in seen:
        raise SmokeError(f"archive lacks its top-level directory member: {root}")
    for link in symlinks:
        if any(link != other and link in other.parents for other in seen):
            raise SmokeError(f"archive symlink is used as a directory: {link}")
    for link, target in symlinks.items():
        if target not in seen:
            raise SmokeError(f"archive symlink target is absent: {link} -> {target}")
    return root


def safe_extract_archive(archive: Path, destination: Path, *, expected_root: str | None = None) -> Path:
    """Extract through the shared package validator, never ``tar -xf``."""

    if not archive.is_file() or archive.is_symlink():
        raise SmokeError(f"archive is not a regular file: {archive}")
    if expected_root is None:
        # The focused unit tests exercise arbitrary synthetic roots.  The real
        # runner below supplies the commit-derived root from the artifact name.
        with tarfile.open(archive, mode="r:xz", errorlevel=2) as stream:
            expected_root = validate_archive_members(stream.getmembers())
    try:
        return DIST.safe_extract_archive(archive, destination, archive_root=expected_root)
    except DIST.DistError as error:
        raise SmokeError(f"unsafe sysroot archive: {error}") from error


def _relative_manifest_path(root: Path, value: object, description: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SmokeError(f"manifest {description} path is invalid")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise SmokeError(f"manifest {description} path escapes the sysroot: {value}")
    return root / Path(*relative.parts)


def validate_symlinks(root: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_symlink():
            continue
        target = os.readlink(path)
        if Path(target).is_absolute():
            raise SmokeError(f"absolute extracted symlink: {path} -> {target}")
        resolved = path.parent.joinpath(target).resolve()
        if not resolved.is_relative_to(root.resolve()):
            raise SmokeError(f"extracted symlink escapes sysroot: {path} -> {target}")
        records.append({"path": str(path.relative_to(root)), "target": target})
    return records


def validate_manifest(root: Path, source_commit: str) -> dict[str, object]:
    try:
        packaged = DIST.validate_packaged_tree(root, expected_source_commit=source_commit)
    except DIST.DistError as error:
        raise SmokeError(f"extracted package contract failed: {error}") from error
    try:
        manifest = SYSROOT.load_installed_manifest(root)
    except Exception as error:  # the reusable module has its own typed error
        raise SmokeError(f"invalid extracted sysroot manifest: {error}") from error
    if manifest.get("source_commit") != source_commit:
        raise SmokeError("manifest source_commit does not match --source-commit")
    platform_record = manifest.get("platform")
    if not isinstance(platform_record, dict) or platform_record.get("architecture") != "aarch64" or platform_record.get("endianness") != "little":
        raise SmokeError("manifest does not identify little-endian AArch64")
    if manifest.get("canonical_interpreter") != SYSROOT.CANONICAL_INTERPRETER:
        raise SmokeError("manifest canonical interpreter is not crabc's loader")
    symlinks = validate_symlinks(root)
    runtime = SYSROOT.installed_runtime_paths(root)
    required_headers = ("assert.h", "dlfcn.h", "pthread.h", "stdio.h", "unistd.h")
    missing_headers = [name for name in required_headers if not (root / "usr/include" / name).is_file()]
    if missing_headers:
        raise SmokeError(f"extracted sysroot is missing public headers: {missing_headers}")
    for name, path in runtime.items():
        if not path.is_file() or path.is_symlink():
            raise SmokeError(f"extracted runtime input is missing or not regular ({name}): {path}")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise SmokeError("manifest artifact records are missing")
    artifact_records: list[dict[str, object]] = []
    for name, record in sorted(artifacts.items()):
        if not isinstance(record, dict):
            raise SmokeError(f"manifest artifact record is invalid: {name}")
        path = _relative_manifest_path(root, record.get("path"), name)
        expected = record.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SmokeError(f"manifest artifact hash is invalid: {name}")
        if not path.is_file() or path.is_symlink():
            raise SmokeError(f"manifest artifact is absent or symlinked: {name}")
        observed = sha256_file(path)
        retained_build_paths = record.get("absolute_build_paths", [])
        if not isinstance(retained_build_paths, list) or any(
            not isinstance(item, str) for item in retained_build_paths
        ):
            raise SmokeError(f"manifest artifact build-path record is invalid: {name}")
        forbidden_build_paths = [
            item for item in retained_build_paths if item.startswith(FORBIDDEN_BUILD_PATH_PREFIXES)
        ]
        if forbidden_build_paths:
            raise SmokeError(f"manifest artifact retains a build-environment path: {name}")
        artifact_records.append(
            {
                "name": name,
                "path": str(path.relative_to(root)),
                "sha256": observed,
                "expected": expected,
                "absolute_build_paths": retained_build_paths,
                "forbidden_build_paths": forbidden_build_paths,
                "passed": observed == expected,
            }
        )
        if observed != expected:
            raise SmokeError(f"manifest artifact hash mismatch: {name}")
    return {
        "manifest": manifest,
        "package_inventory": {
            "regular_file_count": len(packaged.regular_files),
            "symlink_count": len(packaged.symlinks),
        },
        "symlinks": symlinks,
        "artifacts": artifact_records,
        "required_runtime": {name: str(path.relative_to(root)) for name, path in runtime.items()},
    }


def header_trace_paths(output: bytes) -> list[Path]:
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


def header_probe(root: Path, work: Path, timeout: float) -> dict[str, object]:
    """Compile public headers with raw, explicit extracted-sysroot includes."""

    output = work / "headers.o"
    environment = SYSROOT.seal_environment()
    configuration = SYSROOT.DriverConfiguration.from_manifest(SYSROOT.load_installed_manifest(root))
    clang = SYSROOT._compiler_from_configuration(configuration)
    resource = SYSROOT._resource_include(clang, environment)
    command = [
        str(clang),
        f"--target={configuration.target}",
        "-mno-outline-atomics",
        "-nostdinc",
        "-isystem",
        str(root / "usr/include"),
        "-isystem",
        str(resource),
        "-H",
        "-c",
        str(FIXTURES / "headers.c"),
        "-o",
        str(output),
    ]
    record = command_record(command, environment=environment, timeout=timeout)
    trace = bytes.fromhex(str(record["stdout"]["hex"])) + bytes.fromhex(str(record["stderr"]["hex"]))
    allowed = [root / "usr/include", resource, FIXTURES]
    paths = header_trace_paths(trace)
    ambient = [str(path) for path in paths if all(not path.is_relative_to(item.resolve()) for item in allowed)]
    result = {
        "command": record,
        "headers": [str(path) for path in paths],
        "allowed_roots": [str(path.resolve()) for path in allowed],
        "ambient_headers": ambient,
        "passed": record.get("status") == 0 and output.is_file() and bool(paths) and not ambient,
    }
    if not result["passed"]:
        raise SmokeError("header include trace selected an ambient header")
    return result


def _trace_bytes(record: Mapping[str, object]) -> bytes:
    stdout = record.get("stdout")
    stderr = record.get("stderr")
    if not isinstance(stdout, dict) or not isinstance(stderr, dict):
        return b""
    return bytes.fromhex(str(stdout.get("hex", ""))) + bytes.fromhex(str(stderr.get("hex", "")))


def _path_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def link_plan(root: Path, wrapper: Path, arguments: Sequence[str], timeout: float) -> dict[str, object]:
    """Require the extracted driver to expose a sealed explicit link plan."""

    record = command_record([str(wrapper), "--crabc-print-link-plan", *arguments], environment=SYSROOT.seal_environment(), timeout=timeout)
    plan: object = None
    if record.get("status") == 0:
        try:
            plan = json.loads(bytes.fromhex(str(record["stdout"]["hex"])).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            plan = None
    if not isinstance(plan, dict):
        raise SmokeError("extracted crabc-cc did not expose an explicit nostdlib/lld link plan")
    command = plan.get("command")
    startup = plan.get("startup_objects")
    ending = plan.get("end_objects")
    default_libraries = plan.get("default_libraries")
    if (
        not isinstance(command, list)
        or "-nostdlib" not in command
        or "-fuse-ld=lld" not in command
        or not isinstance(startup, list)
        or not isinstance(ending, list)
        or not isinstance(default_libraries, list)
    ):
        raise SmokeError("extracted crabc-cc link plan is incomplete or lacks explicit isolation flags")
    runtime_paths = [Path(value) for value in [*startup, *ending] if isinstance(value, str)]
    if len(runtime_paths) != len(startup) + len(ending) or any(
        not path.is_file() or not _path_under(path, root) for path in runtime_paths
    ):
        raise SmokeError("extracted crabc-cc link plan names a non-sysroot CRT input")
    if "-r" not in arguments and "-shared" not in arguments and "-static" not in arguments and "-static-pie" not in arguments:
        if plan.get("interpreter") != SYSROOT.CANONICAL_INTERPRETER:
            raise SmokeError("dynamic link plan does not name the crabc interpreter")
    inputs = plan.get("link_inputs")
    if not isinstance(inputs, list) or any(
        isinstance(item, dict) and item.get("classification") == "rejected foreign target runtime" for item in inputs
    ):
        raise SmokeError("extracted crabc-cc link plan includes a foreign runtime input")
    return {
        "command": record,
        "plan": plan,
        "validated": {
            "nostdlib": True,
            "fuse_ld_lld": True,
            "runtime_crt_paths": [str(path) for path in runtime_paths],
            "default_libraries": default_libraries,
        },
    }


def link_artifact(root: Path, wrapper: Path, arguments: Sequence[str], output: Path, work: Path, timeout: float, application: Sequence[Path]) -> dict[str, object]:
    map_path = work / f"{output.name}.map"
    request = [*arguments, "-Wl,--trace", f"-Wl,-Map,{map_path}"]
    plan = link_plan(root, wrapper, arguments, timeout)
    record = command_record([str(wrapper), *request], environment=SYSROOT.seal_environment(), timeout=timeout)
    trace_audit = SYSROOT.audit_linker_trace(
        _trace_bytes(record),
        root,
        application_paths=application,
        application_library_roots=(work,),
    )
    result = {"plan": plan, "link": record, "link_trace_audit": trace_audit, "link_map": {"path": str(map_path), "present": map_path.is_file(), "text": map_path.read_text(encoding="utf-8", errors="replace") if map_path.is_file() else ""}}
    if record.get("status") != 0 or not output.is_file() or trace_audit.get("status") != "passed" or not map_path.is_file():
        raise SmokeError(f"extracted link failed or consumed an unapproved input: {output.name}")
    return result


def raw_elf_tools(path: Path, timeout: float) -> dict[str, object]:
    readelf = shutil.which("llvm-readelf") or shutil.which("readelf")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if readelf is None or nm is None:
        raise SmokeError("readelf or llvm-readelf is unavailable")
    records = {
        "readelf": command_record(
            [readelf, "-h", "-lW", "-d", "-s", "-r", str(path)],
            timeout=timeout,
            environment=SYSROOT.seal_environment(),
        ),
        "nm": command_record(
            [nm, "-g", str(path)],
            timeout=timeout,
            environment=SYSROOT.seal_environment(),
        ),
    }
    if any(record.get("status") != 0 for record in records.values()):
        raise SmokeError(f"raw ELF inspection tool failed for {path.name}")
    return {"tools": {"readelf": readelf, "nm": nm}, "records": records}


def elf_record(path: Path, timeout: float, *, kind: str, interpreter: str | None) -> dict[str, object]:
    try:
        parsed = SYSROOT.inspect_elf(path)
    except Exception as error:
        raise SmokeError(f"ELF inspection failed for {path.name}: {error}") from error
    errors: list[str] = []
    if parsed.get("machine") != SYSROOT.EM_AARCH64:
        errors.append("ELF is not AArch64")
    if parsed.get("interpreter") != interpreter:
        errors.append(f"unexpected PT_INTERP: {parsed.get('interpreter')!r}")
    if kind == "dynamic" and parsed.get("elf_type") != 3:
        errors.append("dynamic executable is not ET_DYN")
    if kind == "module" and parsed.get("elf_type") != 3:
        errors.append("module is not ET_DYN")
    if kind == "static" and (parsed.get("interpreter") is not None or parsed.get("dynamic_needed")):
        errors.append("static executable has dynamic runtime metadata")
    foreign = [item for item in parsed.get("dynamic_needed", []) if any(marker in str(item) for marker in ("ld-linux", "libc.so.6", "libgcc", "libatomic", "libssp"))]
    if foreign:
        errors.append(f"foreign dynamic dependencies: {foreign}")
    result = {"parsed": parsed, "raw_tools": raw_elf_tools(path, timeout), "passed": not errors, "errors": errors}
    if errors:
        raise SmokeError(f"ELF contract failed for {path.name}: {errors}")
    return result


def run_chroot_dynamic(root: Path, binary: Path, module: Path, work: Path, timeout: float) -> dict[str, object]:
    scratch = work / "scratch-root"
    # Deliberately construct only the runtime view needed by the test.  In
    # particular, no Alpine loader/libc and no host `/lib` are visible inside
    # this root; the executable's absolute PT_INTERP must resolve to the
    # archived loader below `scratch/lib`.
    scratch.mkdir()
    shutil.copytree(root / "lib", scratch / "lib", symlinks=True)
    (scratch / "usr").mkdir()
    shutil.copytree(root / "usr/lib", scratch / "usr/lib", symlinks=True)
    (scratch / "bin").mkdir()
    scratch_bin = scratch / "bin/sysroot-dynamic"
    scratch_module = scratch / "usr/lib/libcrabc-sysroot-smoke.so"
    shutil.copy2(binary, scratch_bin)
    shutil.copy2(module, scratch_module)
    environment = SYSROOT.seal_environment()
    environment.update({"LD_LIBRARY_PATH": "/usr/lib", "CRABC_SYSROOT_SMOKE": "1", "CRABC_SYSROOT_SMOKE_WAIT": "1"})
    command = ["chroot", str(scratch), "/bin/sysroot-dynamic", "/usr/lib/libcrabc-sysroot-smoke.so"]
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    except OSError as error:
        raise SmokeError(f"cannot execute chroot smoke: {error}") from error
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    maps = b""
    maps_audit: dict[str, object] | None = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        maps_path = Path(f"/proc/{process.pid}/maps")
        if maps_path.is_file():
            maps = maps_path.read_bytes()
            if maps:
                maps_audit = SYSROOT_RUNNER.audit_process_maps(maps, root, dynamic=True, expected_artifacts=[scratch_module])
                if maps_audit.get("status") == "passed":
                    break
        if process.poll() is not None:
            break
        time.sleep(0.01)
    if maps_audit is None or maps_audit.get("status") != "passed":
        process.kill()
        stdout, stderr = process.communicate()
        raise SmokeError(f"chroot process did not expose owned loader/libc/module maps: {stderr.decode(errors='replace')}")
    process.stdin.write(b"x")
    process.stdin.flush()
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise SmokeError("chroot dynamic smoke timed out")
    result = {"command": command, "run": {"status": process.returncode, "stdout": stream_record(stdout), "stderr": stream_record(stderr)}, "maps": maps_audit, "scratch_root": str(scratch), "passed": process.returncode == 0 and stdout == EXPECTED_OUTPUT and stderr == b""}
    if not result["passed"]:
        raise SmokeError("chroot dynamic smoke output or status mismatched")
    return result


def static_pthread_tls(root: Path, work: Path, timeout: float) -> dict[str, object]:
    """Link the established pthread/TLS fixture with only extracted inputs."""

    source = ROOT / "tests/fixtures/static_pthread_tls_test.c"
    if not source.is_file():
        raise SmokeError(f"static pthread/TLS fixture is absent: {source}")
    configuration = SYSROOT.DriverConfiguration.from_manifest(SYSROOT.load_installed_manifest(root))
    environment = SYSROOT.seal_environment()
    clang = SYSROOT._compiler_from_configuration(configuration)
    lld = SYSROOT._linker_from_configuration(configuration)
    resource = SYSROOT._resource_include(clang, environment)
    object_file = work / "static-pthread-tls.o"
    output = work / "static-pthread-tls"
    map_path = work / "static-pthread-tls.map"
    compile_command = [
        str(clang),
        f"--target={configuration.target}",
        "-mno-outline-atomics",
        "-nostdinc",
        "-isystem",
        str(root / "usr/include"),
        "-isystem",
        str(resource),
        "-fno-stack-protector",
        "-c",
        str(source),
        "-o",
        str(object_file),
    ]
    compile_record = command_record(compile_command, environment=environment, timeout=timeout)
    if compile_record.get("status") != 0 or not object_file.is_file():
        raise SmokeError("static pthread/TLS fixture did not compile with extracted headers")
    runtime = SYSROOT.installed_runtime_paths(root)
    explicit_inputs = [
        runtime["crt1.o"],
        runtime["crti.o"],
        object_file,
        runtime["libc.a"],
        runtime["builtins"],
        runtime["crtn.o"],
    ]
    if any(not item.is_file() or (item != object_file and not _path_under(item, root)) for item in explicit_inputs):
        raise SmokeError("static pthread/TLS link has a missing non-extracted runtime input")
    link_command = [
        str(clang),
        f"--target={configuration.target}",
        "-mno-outline-atomics",
        "-fuse-ld=lld",
        f"-B{lld.parent}",
        "-nostdlib",
        "-static",
        "-no-pie",
        "-Wl,--trace",
        f"-Wl,-Map,{map_path}",
        *(str(item) for item in explicit_inputs),
        "-o",
        str(output),
    ]
    link_record = command_record(link_command, environment=environment, timeout=timeout)
    trace_audit = SYSROOT.audit_linker_trace(
        _trace_bytes(link_record),
        root,
        application_paths=(source, object_file),
        application_library_roots=(work,),
    )
    if (
        link_record.get("status") != 0
        or not output.is_file()
        or trace_audit.get("status") != "passed"
        or not map_path.is_file()
    ):
        raise SmokeError("static pthread/TLS link selected an unapproved input or did not emit a map")
    elf = elf_record(output, timeout, kind="static", interpreter=None)
    run = command_record([str(output)], environment=environment, timeout=timeout)
    result = {
        "compile": compile_record,
        "link": link_record,
        "explicit_inputs": [str(item) for item in explicit_inputs],
        "link_trace_audit": trace_audit,
        "link_map": {
            "path": str(map_path),
            "present": map_path.is_file(),
            "text": map_path.read_text(encoding="utf-8", errors="replace") if map_path.is_file() else "",
        },
        "elf": elf,
        "run": run,
        "passed": run.get("status") == 0
        and bytes.fromhex(str(run["stdout"]["hex"])) == EXPECTED_STATIC_OUTPUT
        and bytes.fromhex(str(run["stderr"]["hex"])) == b"",
    }
    if not result["passed"]:
        raise SmokeError("extracted static pthread/TLS executable output or status mismatched")
    return result


def optional_modes(root: Path, wrapper: Path, work: Path, timeout: float, manifest: Mapping[str, object]) -> dict[str, object]:
    declared = manifest.get("supported_link_modes", manifest.get("link_modes", ()))
    if isinstance(declared, dict):
        declared = declared.keys()
    if not isinstance(declared, (list, tuple, set)):
        declared = ()
    result: dict[str, object] = {}
    source = FIXTURES / "dynamic.c"
    aliases = {str(item).replace("_", "-") for item in declared}
    if {"dynamic-non-pie", "dynamic-executable"} & aliases:
        output = work / "dynamic-non-pie"
        result["dynamic_non_pie"] = link_artifact(root, wrapper, ["-no-pie", str(source), "-o", str(output)], output, work, timeout, [source])
        result["dynamic_non_pie"]["elf"] = elf_record(output, timeout, kind="dynamic", interpreter=SYSROOT.CANONICAL_INTERPRETER)
    if {"static-pie"} & aliases:
        output = work / "static-pie"
        result["static_pie"] = link_artifact(root, wrapper, ["-static-pie", str(source), "-o", str(output)], output, work, timeout, [source])
        result["static_pie"]["elf"] = elf_record(output, timeout, kind="static", interpreter=None)
    return result


def run(args: argparse.Namespace) -> dict[str, object]:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise SmokeError("sysroot archive smoke requires native Linux AArch64")
    if not SHA256.fullmatch(args.source_commit):
        raise SmokeError("--source-commit must be a full lowercase 40-character commit")
    archive = args.archive.expanduser().resolve()
    if not archive.is_file() or archive.is_symlink():
        raise SmokeError(f"archive is not a regular file: {archive}")
    name_match = DIST.ARCHIVE_NAME_PATTERN.fullmatch(archive.name)
    if name_match is None:
        raise SmokeError("archive name is not a commit-derived crabc AArch64 sysroot asset")
    if name_match.group(1) != args.source_commit[:12]:
        raise SmokeError("archive name does not match --source-commit")
    archive_root = archive.name.removesuffix(".tar.xz")
    report: dict[str, object] = {
        "schema": 1,
        "runner": "crabc-sysroot-smoke",
        "passed": False,
        "target": "aarch64",
        "source_commit": args.source_commit,
        "archive": {"name": archive.name, "path": str(archive), "sha256": sha256_file(archive)},
        "environment": {"system": platform.system(), "machine": platform.machine(), "python": sys.version, "kernel": platform.release(), "compiler": shutil.which("clang"), "linker": shutil.which("ld.lld")},
        "tests": {},
    }
    with tempfile.TemporaryDirectory(prefix="crabc-sysroot-smoke-") as temporary:
        work = Path(temporary)
        root = safe_extract_archive(archive, work / "extracted", expected_root=archive_root)
        structural = validate_manifest(root, args.source_commit)
        report["tests"]["structural"] = structural
        wrapper = root / "bin/crabc-cc"
        report["tests"]["headers"] = header_probe(root, work, args.timeout)
        module = work / "libcrabc-sysroot-smoke.so"
        report["tests"]["module"] = link_artifact(root, wrapper, ["-shared", "-fPIC", str(FIXTURES / "module.c"), "-o", str(module)], module, work, args.timeout, [FIXTURES / "module.c"])
        report["tests"]["module"]["elf"] = elf_record(module, args.timeout, kind="module", interpreter=None)
        dynamic = work / "dynamic"
        report["tests"]["dynamic"] = link_artifact(root, wrapper, [str(FIXTURES / "dynamic.c"), "-o", str(dynamic)], dynamic, work, args.timeout, [FIXTURES / "dynamic.c"])
        report["tests"]["dynamic"]["elf"] = elf_record(dynamic, args.timeout, kind="dynamic", interpreter=SYSROOT.CANONICAL_INTERPRETER)
        report["tests"]["dynamic"]["runtime"] = run_chroot_dynamic(root, dynamic, module, work, args.timeout)
        report["tests"]["static_pthread_tls"] = static_pthread_tls(root, work, args.timeout)
        report["tests"]["optional_modes"] = optional_modes(root, wrapper, work, args.timeout, structural["manifest"])
    report["passed"] = True
    return report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= MAX_TIMEOUT:
        parser.error(f"--timeout must be > 0 and <= {MAX_TIMEOUT:g}")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run(args)
    except SmokeError as error:
        report = {"schema": 1, "runner": "crabc-sysroot-smoke", "passed": False, "target": "aarch64", "source_commit": args.source_commit, "error": str(error)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_name(f".{args.report.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.report)
    print(args.report)
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
