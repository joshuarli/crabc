#!/usr/bin/env python3
"""Run a pinned Alpine AArch64 package corpus under musl and crabc.

The runner makes the loader boundary explicit.  Disposable roots are staged
from the exact APK archives in ``manifest.toml`` and the non-libc DSOs from
the pinned Alpine development image.  The reference root has pinned musl
interpreter/libc files at ``/lib/ld-musl-aarch64.so.1`` and
``/lib/libc.musl-aarch64.so.1``; the candidate root has the corresponding
crabc files.  A byte-identical temporary copy of the package executable then
gets only its PT_INTERP string replaced with a short absolute overlay path and
is entered directly with ``execve``.  ``libldso.so package`` is intentionally
never used: that would make the loader the program and would change argv,
/proc/self/exe, and startup state.

Only raw process outcomes are compared: wait status, stdout, and stderr.
There is no output normalization.  The harness is Python standard-library
code so that report generation and setup remain inspectable and reproducible.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import platform
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urljoin


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("manifest.toml")
DEFAULT_CACHE = Path(os.environ.get("CRABC_CORPUS_PACKAGE_CACHE", Path(__file__).with_name(".cache")))
DEFAULT_REPORT = ROOT / "compat/reports/corpus/latest.json"
MUSL_VERSION = "1.2.6"
ALPINE_RELEASE = "3.24.1"
ARCHITECTURE = "aarch64"
TIERS = ("A", "B", "C", "D")


class CorpusError(RuntimeError):
    """Raised for invalid inputs or an unavailable corpus oracle."""


@dataclasses.dataclass(frozen=True)
class PackageSpec:
    name: str
    version: str
    filename: str
    sha256: str

    def url(self, base_url: str) -> str:
        return urljoin(base_url.rstrip("/") + "/", self.filename)

    def identity(self) -> str:
        return f"{self.name}={self.version}"


@dataclasses.dataclass(frozen=True)
class SetupFile:
    path: str
    contents: bytes


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    id: str
    tier: str
    package: str
    path: str
    argv: tuple[str, ...]
    stdin: bytes = b""
    setup: tuple[SetupFile, ...] = ()
    cwd: str = "/tmp"
    requires_dt_relr: bool = False
    stateful: bool = False


@dataclasses.dataclass(frozen=True)
class Manifest:
    schema: int
    alpine_release: str
    architecture: str
    image: str
    musl_version: str
    repository_base_url: str
    packages: tuple[PackageSpec, ...]
    cases: tuple[CaseSpec, ...]
    bytes: bytes


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    status: int | str
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def _require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise CorpusError(f"manifest field {field} must be a non-empty string")
    return value


def _require_sha256(value: object, field: str) -> str:
    digest = _require_string(value, field)
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise CorpusError(f"manifest field {field} must be a lowercase SHA-256 digest")
    return digest


def load_manifest(path: Path = MANIFEST) -> Manifest:
    """Parse and validate the explicit corpus contract.

    Validation is intentionally strict: duplicate package/case identities,
    relative executable paths, or an unpinned archive cannot reach execution.
    """

    raw_bytes = path.read_bytes()
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    if raw.get("schema") != 1:
        raise CorpusError(f"unsupported corpus manifest schema: {raw.get('schema')!r}")
    alpine_release = _require_string(raw.get("alpine_release"), "alpine_release")
    architecture = _require_string(raw.get("architecture"), "architecture")
    image = _require_string(raw.get("image"), "image")
    musl_version = _require_string(raw.get("musl_version"), "musl_version")
    repository = raw.get("repository")
    if not isinstance(repository, dict):
        raise CorpusError("manifest repository table is required")
    repository_base_url = _require_string(repository.get("base_url"), "repository.base_url")

    packages: list[PackageSpec] = []
    package_names: set[str] = set()
    for index, item in enumerate(raw.get("packages", [])):
        if not isinstance(item, dict):
            raise CorpusError(f"packages[{index}] must be a table")
        name = _require_string(item.get("name"), f"packages[{index}].name")
        if name in package_names:
            raise CorpusError(f"duplicate package in manifest: {name}")
        package_names.add(name)
        packages.append(
            PackageSpec(
                name=name,
                version=_require_string(item.get("version"), f"packages[{index}].version"),
                filename=_require_string(item.get("filename"), f"packages[{index}].filename"),
                sha256=_require_sha256(item.get("sha256"), f"packages[{index}].sha256"),
            )
        )

    cases: list[CaseSpec] = []
    case_ids: set[str] = set()
    for index, item in enumerate(raw.get("cases", [])):
        if not isinstance(item, dict):
            raise CorpusError(f"cases[{index}] must be a table")
        case_id = _require_string(item.get("id"), f"cases[{index}].id")
        if case_id in case_ids:
            raise CorpusError(f"duplicate case in manifest: {case_id}")
        case_ids.add(case_id)
        tier = _require_string(item.get("tier"), f"cases[{index}].tier")
        if tier not in TIERS:
            raise CorpusError(f"cases[{index}].tier must be one of {TIERS}")
        package = _require_string(item.get("package"), f"cases[{index}].package")
        if package not in package_names:
            raise CorpusError(f"case {case_id} names unknown package {package}")
        executable = _require_string(item.get("path"), f"cases[{index}].path")
        if not executable.startswith("/") or "\x00" in executable:
            raise CorpusError(f"case {case_id} path must be an absolute NUL-free path")
        argv = item.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
            raise CorpusError(f"case {case_id} argv must be a non-empty string array")
        stdin = item.get("stdin", "")
        if not isinstance(stdin, str):
            raise CorpusError(f"case {case_id} stdin must be a string")
        setup: list[SetupFile] = []
        for setup_index, setup_item in enumerate(item.get("setup", [])):
            if not isinstance(setup_item, dict):
                raise CorpusError(f"case {case_id} setup[{setup_index}] must be a table")
            setup_path = _require_string(setup_item.get("path"), f"case {case_id} setup path")
            if not setup_path.startswith("/") or "\x00" in setup_path:
                raise CorpusError(f"case {case_id} setup path must be absolute and NUL-free")
            contents = setup_item.get("contents", "")
            if not isinstance(contents, str):
                raise CorpusError(f"case {case_id} setup contents must be a string")
            setup.append(SetupFile(setup_path, contents.encode("utf-8")))
        cwd = item.get("cwd", "/tmp")
        if not isinstance(cwd, str) or not cwd.startswith("/"):
            raise CorpusError(f"case {case_id} cwd must be an absolute path")
        stateful = item.get("stateful", False)
        if not isinstance(stateful, bool):
            raise CorpusError(f"case {case_id} stateful must be a boolean")
        cases.append(
            CaseSpec(
                id=case_id,
                tier=tier,
                package=package,
                path=executable,
                argv=tuple(argv),
                stdin=stdin.encode("utf-8"),
                setup=tuple(setup),
                cwd=cwd,
                requires_dt_relr=bool(item.get("requires_dt_relr", False)),
                stateful=stateful,
            )
        )

    if not packages or not cases:
        raise CorpusError("corpus manifest must contain packages and cases")
    tiered_packages = {case.package for case in cases if case.tier in {"B", "C", "D"}}
    for package in package_names & tiered_packages:
        if not any(case.package == package and case.tier in {"B", "C", "D"} and case.stateful for case in cases):
            raise CorpusError(f"Tier B-D package lacks a stateful case: {package}")
    return Manifest(
        schema=1,
        alpine_release=alpine_release,
        architecture=architecture,
        image=image,
        musl_version=musl_version,
        repository_base_url=repository_base_url,
        packages=tuple(packages),
        cases=tuple(cases),
        bytes=raw_bytes,
    )


def select_cases(manifest: Manifest, tiers: Sequence[str], case_ids: Sequence[str] = ()) -> tuple[CaseSpec, ...]:
    """Select cases while retaining manifest order and rejecting unknown IDs."""

    wanted_tiers = set(TIERS if "all" in tiers else tiers)
    known = {case.id for case in manifest.cases}
    unknown = sorted(set(case_ids) - known)
    if unknown:
        raise CorpusError(f"unknown corpus case(s): {', '.join(unknown)}")
    selected_ids = set(case_ids)
    return tuple(
        case
        for case in manifest.cases
        if (case.tier in wanted_tiers and (not selected_ids or case.id in selected_ids))
    )


def stream_snapshot(stream: bytes) -> dict[str, object]:
    """Encode raw bytes for JSON without losing an exact comparison witness."""

    return {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
        "hex": stream.hex(),
        "text": stream.decode("utf-8", errors="replace"),
    }


def compare_results(reference: ProcessResult, candidate: ProcessResult) -> dict[str, object]:
    """Compare status and streams exactly; no normalization is permitted."""

    status_match = reference.status == candidate.status and reference.timed_out == candidate.timed_out
    stdout_match = reference.stdout == candidate.stdout
    stderr_match = reference.stderr == candidate.stderr
    return {
        "passed": status_match and stdout_match and stderr_match,
        "status_match": status_match,
        "stdout_match": stdout_match,
        "stderr_match": stderr_match,
        "normalization": "none",
        "reference": {
            "status": reference.status,
            "timed_out": reference.timed_out,
            "stdout": stream_snapshot(reference.stdout),
            "stderr": stream_snapshot(reference.stderr),
        },
        "candidate": {
            "status": candidate.status,
            "timed_out": candidate.timed_out,
            "stdout": stream_snapshot(candidate.stdout),
            "stderr": stream_snapshot(candidate.stderr),
        },
    }


def has_dynamic_tag(readelf_output: str | bytes, tag: str) -> bool:
    """Return whether ``readelf -d`` output contains an exact dynamic tag."""

    text = readelf_output.decode("utf-8", errors="replace") if isinstance(readelf_output, bytes) else readelf_output
    marker = f"({tag})"
    return any(marker in line for line in text.splitlines())


def patched_interpreter_bytes(binary: bytes, interpreter: str) -> bytes:
    """Replace PT_INTERP in a disposable byte copy of an AArch64 ELF.

    Alpine package payloads are never rewritten in place.  The copy differs
    only in its kernel-selected interpreter string, which is the same isolated
    overlay boundary a mounted ``/lib/ld-musl-aarch64.so.1`` would provide.
    """

    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        raise CorpusError("package executable is not a little-endian ELF64 binary")
    if int.from_bytes(binary[18:20], "little") != 183:
        raise CorpusError("package executable is not an AArch64 ELF")
    phoff = int.from_bytes(binary[32:40], "little")
    phentsize = int.from_bytes(binary[54:56], "little")
    phnum = int.from_bytes(binary[56:58], "little")
    if phentsize < 56:
        raise CorpusError("AArch64 ELF has an invalid program-header size")
    output = bytearray(binary)
    encoded = interpreter.encode("ascii") + b"\0"
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(output):
            raise CorpusError("AArch64 ELF program headers exceed the file")
        if int.from_bytes(output[offset : offset + 4], "little") != 3:  # PT_INTERP
            continue
        file_offset = int.from_bytes(output[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(output[offset + 32 : offset + 40], "little")
        if len(encoded) > file_size or file_offset + file_size > len(output):
            raise CorpusError(
                f"interpreter path {interpreter!r} does not fit PT_INTERP ({file_size} bytes)"
            )
        output[file_offset : file_offset + file_size] = encoded + b"\0" * (file_size - len(encoded))
        return bytes(output)
    raise CorpusError("package executable has no PT_INTERP segment")


def patch_interpreter(source: Path, destination: Path, interpreter: str) -> None:
    destination.write_bytes(patched_interpreter_bytes(source.read_bytes(), interpreter))
    destination.chmod(source.stat().st_mode | stat.S_IXUSR)


def sanitize_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep both roots on the same deterministic environment boundary.

    In particular, no ``LD_LIBRARY_PATH`` is used to select the candidate:
    the candidate alias is installed directly at the package binary's normal
    ``DT_NEEDED`` path inside its disposable root.
    """

    environment = dict(base if base is not None else os.environ)
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_", "CRABC_", "MUSL_", "CARGO_")):
            environment.pop(key, None)
    environment.update(
        {
            "PATH": "/bin:/usr/bin",
            "HOME": "/root",
            "TMPDIR": "/tmp",
            "PWD": "/tmp",
            "OLDPWD": "/tmp",
            "LC_ALL": environment.get("LC_ALL", "C"),
        }
    )
    return environment


def command_for_case(case: CaseSpec) -> list[str]:
    """Build the direct executable argv (the loader is never in this list)."""

    if not case.argv:
        raise CorpusError(f"case {case.id} has no argv")
    return [case.path, *case.argv[1:]]


def _safe_member_name(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or "\x00" in name or any(part == ".." for part in path.parts):
        raise CorpusError(f"unsafe APK archive member: {name!r}")
    return path


def _safe_link_name(name: str, parent: Path = Path(".")) -> str:
    if not name or "\x00" in name:
        raise CorpusError(f"unsafe APK link target: {name!r}")
    # APKs commonly use an absolute link such as /bin/gunzip.  It is safe when
    # it remains inside the staged root; the lexical check below rejects only
    # links that escape that root.
    stack = [] if name.startswith("/") else [part for part in parent.parts if part not in ("", ".")]
    for part in Path(name).parts:
        if part in ("", ".", "/"):
            continue
        if part == "..":
            if not stack:
                raise CorpusError(f"unsafe APK link target: {name!r}")
            stack.pop()
        else:
            stack.append(part)
    return name


def safe_archive_members(names: Iterable[str]) -> tuple[str, ...]:
    """Validate APK member paths without reading or writing the filesystem."""

    members: list[str] = []
    for name in names:
        if not name:
            continue
        # APK metadata lives at the archive root.  A dotted path containing a
        # slash still needs traversal validation (for example ``../outside``).
        if name.startswith(".") and "/" not in name:
            continue
        members.append(str(_safe_member_name(name)))
    return tuple(members)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _download_archive(spec: PackageSpec, base_url: str, cache: Path, offline: bool) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / spec.filename
    if destination.is_file() and sha256_file(destination) == spec.sha256:
        return destination
    if destination.exists():
        destination.unlink()
    if offline:
        raise CorpusError(f"offline corpus run is missing or has a bad archive: {destination}")
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with urllib.request.urlopen(spec.url(base_url), timeout=60) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        if sha256_file(temporary) != spec.sha256:
            raise CorpusError(f"SHA-256 mismatch for {spec.filename}")
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def package_archives(manifest: Manifest, cache: Path, packages: Iterable[str], offline: bool) -> dict[str, Path]:
    requested = set(packages)
    specs = [spec for spec in manifest.packages if spec.name in requested]
    if requested - {spec.name for spec in specs}:
        raise CorpusError(f"manifest has no package(s): {', '.join(sorted(requested - {spec.name for spec in specs}))}")
    return {spec.name: _download_archive(spec, manifest.repository_base_url, cache, offline) for spec in specs}


def _link_or_copy(source: str, destination: str) -> None:
    try:
        os.link(source, destination, follow_symlinks=False)
    except OSError:
        shutil.copy2(source, destination, follow_symlinks=False)


def _copy_tree(source: Path, destination: Path, *, hardlink: bool) -> None:
    if not source.exists() and not source.is_symlink():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    copy_function = _link_or_copy if hardlink else shutil.copy2
    shutil.copytree(
        source,
        destination,
        symlinks=True,
        copy_function=copy_function,
        dirs_exist_ok=True,
        ignore_dangling_symlinks=True,
    )


def _remove_existing(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _extract_archive(archive: Path, root: Path) -> None:
    with tarfile.open(archive, mode="r:*", errorlevel=2) as stream:
        for member in stream.getmembers():
            if not member.name:
                continue
            if member.name.startswith(".") and "/" not in member.name:
                continue
            relative = _safe_member_name(member.name)
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            _remove_existing(destination)
            if member.issym():
                _safe_link_name(member.linkname, relative.parent)
                destination.symlink_to(member.linkname)
                continue
            if member.islnk():
                target = root / _safe_member_name(member.linkname)
                os.link(target, destination)
                continue
            if not member.isreg():
                raise CorpusError(f"unsupported APK member type in {archive}: {member.name}")
            source = stream.extractfile(member)
            if source is None:
                raise CorpusError(f"could not read APK member {member.name} from {archive}")
            with destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(destination, member.mode & 0o7777)


def _make_device(root: Path, relative: str, major: int, minor: int) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(major, minor))
    except FileExistsError:
        pass
    except PermissionError:
        # The corpus still works for commands that do not touch /dev.  Keep
        # setup portable for restricted Docker configurations and let a real
        # command failure remain visible in its raw comparison report.
        pass


def _prepare_base_root(source_root: Path, destination: Path, archives: Iterable[Path]) -> None:
    destination.mkdir(parents=True)
    # /usr/lib and /usr/share are large but immutable for this workload.  A
    # hardlink clone keeps each reference/candidate root byte-identical without
    # duplicating hundreds of megabytes in the development volume.
    for relative in ("bin", "lib", "usr/lib", "usr/share"):
        _copy_tree(source_root / relative, destination / relative, hardlink=True)
    _copy_tree(source_root / "etc", destination / "etc", hardlink=False)
    for relative in ("sbin", "usr/sbin", "usr/libexec"):
        _copy_tree(source_root / relative, destination / relative, hardlink=True)
    (destination / "tmp").mkdir(parents=True, exist_ok=True)
    (destination / "tmp").chmod(0o1777)
    for relative in ("proc", "sys", "dev"):
        (destination / relative).mkdir(parents=True, exist_ok=True)
    _make_device(destination, "dev/null", 1, 3)
    _make_device(destination, "dev/zero", 1, 5)
    _make_device(destination, "dev/random", 1, 8)
    _make_device(destination, "dev/urandom", 1, 9)
    for archive in archives:
        _extract_archive(archive, destination)


def _install_runtime_overlay(root: Path, runtime: str, musl_root: Path, target_dir: Path) -> Path:
    """Install distinct regular loader and libc files in one staged root."""

    library = root / "lib"
    library.mkdir(parents=True, exist_ok=True)
    loader = library / "ld-musl-aarch64.so.1"
    soname = library / "libc.musl-aarch64.so.1"
    loader.unlink(missing_ok=True)
    soname.unlink(missing_ok=True)
    if runtime == "reference":
        source = musl_root / "lib/libc.so"
        if not source.is_file():
            raise CorpusError(f"pinned musl libc not found: {source}")
        destination = library / "crabc-corpus-reference-libc.so"
        shutil.copy2(source, destination)
        shutil.copy2(source, loader)
        shutil.copy2(source, soname)
    elif runtime == "candidate":
        source_libc = target_dir / "libc.so"
        source_loader = target_dir / "libldso.so"
        if not source_libc.is_file() or not source_loader.is_file():
            raise CorpusError(f"candidate libc.so/libldso.so not found in {target_dir}")
        destination_libc = library / "crabc-corpus-candidate-libc.so"
        destination_loader = library / "crabc-corpus-candidate-ldso.so"
        shutil.copy2(source_libc, destination_libc)
        shutil.copy2(source_loader, destination_loader)
        destination_loader.chmod(destination_loader.stat().st_mode | stat.S_IXUSR)
        shutil.copy2(destination_loader, loader)
        shutil.copy2(destination_libc, soname)
    else:
        raise CorpusError(f"unknown runtime overlay: {runtime}")
    if not loader.is_file() or not soname.is_file() or loader.is_symlink() or soname.is_symlink():
        raise CorpusError("runtime overlay must provide distinct regular interpreter/libc files")
    if os.stat(loader).st_ino == os.stat(soname).st_ino:
        raise CorpusError("runtime overlay interpreter and libc unexpectedly share an inode")
    return library


def _write_setup(root: Path, case: CaseSpec) -> None:
    for setup in case.setup:
        destination = root / setup.path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(setup.contents)
        destination.chmod(0o644)
    cwd = root / case.cwd.lstrip("/")
    cwd.mkdir(parents=True, exist_ok=True)


def _cleanup_host_case_paths(case: CaseSpec) -> None:
    paths: set[Path] = {Path(setup.path) for setup in case.setup}
    for argument in case.argv:
        if argument.startswith("/tmp/crabc-corpus-"):
            paths.add(Path(argument))
    for path in sorted(paths, key=lambda value: len(value.parts), reverse=True):
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)


def _write_host_setup(case: CaseSpec) -> None:
    _cleanup_host_case_paths(case)
    for setup in case.setup:
        destination = Path(setup.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(setup.contents)
        destination.chmod(0o644)
    Path(case.cwd).mkdir(parents=True, exist_ok=True)


def _execute(
    binary: Path,
    case: CaseSpec,
    timeout: float,
    environment: Mapping[str, str],
    library_path: Path | str,
) -> ProcessResult:
    command = command_for_case(case)
    process_environment = dict(environment)
    process_environment["LD_LIBRARY_PATH"] = str(library_path)
    # Keep the path value identical for both runtimes; only the staged alias
    # contents differ.  This is an overlay boundary, not a candidate-only
    # loader workaround.
    argv = [case.argv[0], *command[1:]]

    def disable_core_dump() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_environment,
            cwd=case.cwd,
            executable=str(binary),
            preexec_fn=disable_core_dump,
            close_fds=True,
        )
    except OSError as error:
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode())
    try:
        stdout, stderr = process.communicate(case.stdin, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        stdout, stderr = process.communicate()
        return ProcessResult("TIMEOUT", stdout or error.stdout or b"", stderr or error.stderr or b"", True)
    return ProcessResult(process.returncode, stdout, stderr)


def _check_case_shape(case: CaseSpec, root: Path) -> None:
    executable = root / case.path.lstrip("/")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise CorpusError(f"case {case.id} executable is absent from its package archive: {case.path}")
    if case.requires_dt_relr:
        result = subprocess.run(
            ["readelf", "-d", str(executable)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0 or not has_dynamic_tag(result.stdout, "RELR"):
            raise CorpusError(f"case {case.id} no longer exercises the required DT_RELR dynamic tag")


def _validate_environment(manifest: Manifest, system_root: Path, musl_root: Path) -> None:
    machine = platform.machine().lower()
    if machine not in {"aarch64", "arm64"}:
        raise CorpusError(f"real Alpine corpus requires native AArch64, got {machine!r}")
    release = (system_root / "etc/alpine-release").read_text(encoding="ascii").strip()
    if release != manifest.alpine_release:
        raise CorpusError(f"Alpine release is {release!r}, expected pinned {manifest.alpine_release!r}")
    if manifest.architecture != ARCHITECTURE or manifest.musl_version != MUSL_VERSION:
        raise CorpusError("corpus manifest is not pinned to AArch64 musl 1.2.6")
    if musl_root.name != f"musl-{MUSL_VERSION}" or not (musl_root / "include").is_dir():
        raise CorpusError(f"pinned musl root is unavailable: {musl_root}")
    # A glibc loader or ABI would invalidate this evidence.  The check covers
    # both the host image and every disposable root overlay.
    forbidden = ("ld-linux", "libc.so.6", "glibc")
    for relative in ("lib", "usr/lib"):
        directory = system_root / relative
        if directory.is_dir() and any(token in path.name for path in directory.iterdir() for token in forbidden):
            raise CorpusError(f"glibc artifact found in Alpine system root: {directory}")


def _atomic_write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--tier", choices=(*TIERS, "all"), action="append", default=None)
    parser.add_argument("--case", dest="case_ids", action="append", default=[])
    parser.add_argument("--package-cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--system-root", type=Path, default=Path("/"))
    parser.add_argument("--musl-root", type=Path, default=Path(f"/opt/musl-{MUSL_VERSION}"))
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> tuple[bool, Path]:
    manifest = load_manifest(args.manifest)
    if args.timeout <= 0:
        raise CorpusError("--timeout must be positive")
    tiers = args.tier or ["A"]
    selected = select_cases(manifest, tiers, args.case_ids)
    if not selected:
        raise CorpusError("case selection is empty")
    system_root = args.system_root.expanduser().resolve()
    musl_root = args.musl_root.expanduser().resolve()
    target_dir = args.target_dir.expanduser().resolve()
    _validate_environment(manifest, system_root, musl_root)
    package_names = {case.package for case in selected}
    archives = package_archives(manifest, args.package_cache.expanduser().resolve(), package_names, args.offline)
    environment = sanitize_environment()
    report_cases: dict[str, dict[str, object]] = {}
    runtime_artifacts: dict[str, dict[str, str]] = {}
    with tempfile.TemporaryDirectory(prefix="crabc-corpus-") as temporary_name:
        temporary = Path(temporary_name)
        reference_root = temporary / "reference"
        candidate_root = temporary / "candidate"
        archive_paths = [
            archives[package.name]
            for package in manifest.packages
            if package.name in package_names
        ]
        _prepare_base_root(system_root, reference_root, archive_paths)
        _prepare_base_root(system_root, candidate_root, archive_paths)
        _install_runtime_overlay(reference_root, "reference", musl_root, target_dir)
        _install_runtime_overlay(candidate_root, "candidate", musl_root, target_dir)
        runtime_artifacts = {
            "reference": {
                "loader_sha256": sha256_file(reference_root / "lib/ld-musl-aarch64.so.1"),
                "libc_sha256": sha256_file(reference_root / "lib/libc.musl-aarch64.so.1"),
            },
            "candidate": {
                "loader_sha256": sha256_file(candidate_root / "lib/ld-musl-aarch64.so.1"),
                "libc_sha256": sha256_file(candidate_root / "lib/libc.musl-aarch64.so.1"),
            },
        }
        runtime_library = temporary / "runtime-library"
        runtime_library.mkdir()
        reference_interpreter = Path("/tmp/crabc-ref")
        candidate_interpreter = Path("/tmp/crabc-cand")
        reference_interpreter.unlink(missing_ok=True)
        candidate_interpreter.unlink(missing_ok=True)
        shutil.copy2(reference_root / "lib/ld-musl-aarch64.so.1", reference_interpreter)
        shutil.copy2(candidate_root / "lib/ld-musl-aarch64.so.1", candidate_interpreter)
        common_library_path = ":".join(
            (
                str(runtime_library),
                str(reference_root / "lib"),
                str(reference_root / "usr/lib"),
            )
        )
        for case in selected:
            reference_executable = reference_root / case.path.lstrip("/")
            candidate_executable = candidate_root / case.path.lstrip("/")
            _check_case_shape(case, reference_root)
            package_spec = next(package for package in manifest.packages if package.name == case.package)
            original_binary_sha256 = sha256_file(reference_executable)
            reference_binary = temporary / f"{case.id}.reference"
            candidate_binary = temporary / f"{case.id}.candidate"
            patch_interpreter(reference_executable, reference_binary, str(reference_interpreter))
            patch_interpreter(candidate_executable, candidate_binary, str(candidate_interpreter))
            # Keep one textual library path in both environments.  The alias
            # bytes are swapped only after the reference process has exited.
            shutil.copy2(reference_root / "lib/libc.musl-aarch64.so.1", runtime_library / "libc.musl-aarch64.so.1")
            _write_host_setup(case)
            reference = _execute(reference_binary, case, args.timeout, environment, common_library_path)
            _cleanup_host_case_paths(case)
            shutil.copy2(candidate_root / "lib/libc.musl-aarch64.so.1", runtime_library / "libc.musl-aarch64.so.1")
            _write_host_setup(case)
            candidate = _execute(candidate_binary, case, args.timeout, environment, common_library_path)
            _cleanup_host_case_paths(case)
            comparison = compare_results(reference, candidate)
            report_cases[case.id] = {
                "tier": case.tier,
                "package": case.package,
                "package_version": package_spec.version,
                "package_archive": package_spec.filename,
                "package_archive_sha256": package_spec.sha256,
                "original_binary_sha256": original_binary_sha256,
                "path": case.path,
                "argv": list(case.argv),
                "requires_dt_relr": case.requires_dt_relr,
                "stateful": case.stateful,
                "result": "pass" if comparison["passed"] else "fail",
                **comparison,
            }
            print(f"corpus: {'PASS' if comparison['passed'] else 'FAIL'}: {case.id}")
    passed = all(case["passed"] is True for case in report_cases.values())
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "compat/corpus/run.py",
        "result": "pass" if passed else "fail",
        "passed": passed,
        "manifest": str(args.manifest),
        "manifest_sha256": hashlib.sha256(manifest.bytes).hexdigest(),
        "image": manifest.image,
        "alpine_release": manifest.alpine_release,
        "architecture": manifest.architecture,
        "musl_version": manifest.musl_version,
        "kernel_release": platform.release(),
        "runtime_artifacts": runtime_artifacts,
        "tiers": list(tiers),
        "case_count": len(report_cases),
        "cases": report_cases,
        "normalization": "none",
        "environment_boundary": {
            "same_kernel": True,
            "same_non_libc_dsos": True,
            "reference_interpreter": "/lib/ld-musl-aarch64.so.1 -> pinned musl libc.so",
            "candidate_interpreter": "/lib/ld-musl-aarch64.so.1 -> crabc libldso.so",
            "candidate_invocation": "direct package execve with disposable PT_INTERP overlay",
            "library_path": "same textual path for both runtimes; alias contents are the only runtime swap",
            "loader_as_program": False,
        },
    }
    _atomic_write_json(args.report.expanduser().resolve(), report)
    return passed, args.report.expanduser().resolve()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        passed, report = run(args)
    except (CorpusError, OSError, tarfile.TarError, urllib.error.URLError) as error:
        print(f"corpus: ERROR: {error}", file=sys.stderr)
        return 2
    print(f"corpus: report: {report}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
