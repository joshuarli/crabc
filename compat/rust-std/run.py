#!/usr/bin/env python3
"""Build and compare an ordinary Rust ``std`` program on pinned musl/crabc.

The application is compiled once with stock Rust sources and ``-Z build-std``
against the pinned musl-gcc specs.  Two disposable PT_INTERP copies then run
the same bytes: one with pinned musl and one with crabc's loader/libc.  The
only runtime swap is the staged ``libc.musl-aarch64.so.1`` and interpreter.
Process status, stdout, and stderr are compared as raw bytes; no normalization
or host-glibc fallback is permitted.
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
import tempfile
import tomllib
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures/src/main.rs"
FIXTURE_MANIFEST = FIXTURE.parents[1] / "Cargo.toml"
UPSTREAMS = ROOT / "compat/upstreams.toml"
REPORT = ROOT / "compat/reports/rust-std/latest.json"
TARGET = "aarch64-unknown-linux-musl"
TOOLCHAIN = "nightly-2026-07-24"
MUSL_VERSION = "1.2.6"
MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")


class RunnerError(RuntimeError):
    """A setup or execution-contract error, not a workload mismatch."""


class BuildFailure(RunnerError):
    """A build failure carrying complete compiler output for the report."""

    def __init__(self, message: str, report: dict[str, object]) -> None:
        super().__init__(message)
        self.report = report


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


def command_output(*command: str, environment: Mapping[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=dict(environment) if environment is not None else None,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RunnerError(f"command failed: {' '.join(command)}: {error}") from error
    return result.stdout.strip()


def require_command(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RunnerError(f"required command is unavailable: {name}")
    return path


def stream_snapshot(stream: bytes) -> dict[str, object]:
    return {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
        "hex": stream.hex(),
        "text": stream.decode("utf-8", errors="replace"),
    }


def compare_results(reference: ProcessResult, candidate: ProcessResult) -> dict[str, object]:
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


def patched_interpreter_bytes(binary: bytes, interpreter: str) -> bytes:
    """Return an ELF copy differing only in its PT_INTERP payload."""

    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        raise RunnerError("fixture output is not a little-endian ELF64 binary")
    if int.from_bytes(binary[18:20], "little") != 183:
        raise RunnerError("fixture output is not an AArch64 ELF")
    phoff = int.from_bytes(binary[32:40], "little")
    phentsize = int.from_bytes(binary[54:56], "little")
    phnum = int.from_bytes(binary[56:58], "little")
    if phentsize < 56:
        raise RunnerError("fixture ELF has an invalid program-header size")
    result = bytearray(binary)
    encoded = interpreter.encode("ascii") + b"\0"
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(result):
            raise RunnerError("fixture ELF program headers exceed the file")
        if int.from_bytes(result[offset : offset + 4], "little") != 3:  # PT_INTERP
            continue
        file_offset = int.from_bytes(result[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(result[offset + 32 : offset + 40], "little")
        if len(encoded) > file_size or file_offset + file_size > len(result):
            raise RunnerError(
                f"interpreter path {interpreter!r} does not fit PT_INTERP ({file_size} bytes)"
            )
        result[file_offset : file_offset + file_size] = encoded + b"\0" * (file_size - len(encoded))
        return bytes(result)
    raise RunnerError("fixture ELF has no PT_INTERP segment")


def patch_interpreter(source: Path, destination: Path, interpreter: str) -> None:
    destination.write_bytes(patched_interpreter_bytes(source.read_bytes(), interpreter))
    destination.chmod(source.stat().st_mode | stat.S_IXUSR)


def sanitize_environment() -> dict[str, str]:
    """Create one environment shared byte-for-byte by both runtime runs."""

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
            "CRABC_RUST_STD_TEST": "musl-abi",
        }
    )
    return environment


def run_binary(
    binary: Path,
    environment: Mapping[str, str],
    library_path: Path,
    timeout: float,
) -> ProcessResult:
    process_environment = dict(environment)
    process_environment["LD_LIBRARY_PATH"] = str(library_path)

    def disable_core_dump() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

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
    except OSError as error:
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode())
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        stdout, stderr = process.communicate()
        return ProcessResult("TIMEOUT", stdout or error.stdout or b"", stderr or error.stderr or b"", True)
    return ProcessResult(process.returncode, stdout, stderr)


def readelf(binary: Path, *arguments: str) -> str:
    result = subprocess.run(
        [require_command("readelf"), *arguments, str(binary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RunnerError(f"readelf failed for {binary}: {result.stderr.strip()}")
    return result.stdout


def reject_glibc(text: str, description: str) -> None:
    lowered = text.lower()
    forbidden = ("glibc", "ld-linux", "libc.so.6")
    if any(marker in lowered for marker in forbidden):
        raise RunnerError(f"glibc artifact detected in {description}")


def validate_inputs(args: argparse.Namespace) -> dict[str, object]:
    if platform.machine().lower() not in {"aarch64", "arm64"}:
        raise RunnerError(f"requires native AArch64, got {platform.machine()!r}")
    if args.timeout <= 0:
        raise RunnerError("--timeout must be positive")
    for command in ("cargo", "rustc", "rustup", "musl-gcc", "readelf"):
        require_command(command)

    musl_root = args.musl_root.expanduser().resolve()
    if musl_root.name != f"musl-{MUSL_VERSION}":
        raise RunnerError(f"--musl-root must name pinned musl-{MUSL_VERSION}: {musl_root}")
    musl_loader = musl_root / "lib/ld-musl-aarch64.so.1"
    musl_libc = musl_root / "lib/libc.so"
    if not musl_loader.is_file() or not musl_libc.is_file():
        raise RunnerError(f"pinned musl loader/libc unavailable under {musl_root}")
    if not (musl_root / "include").is_dir():
        raise RunnerError(f"pinned musl headers unavailable: {musl_root / 'include'}")

    target_dir = args.target_dir.expanduser().resolve()
    candidate_libc = target_dir / "libc.so"
    candidate_loader = target_dir / "libldso.so"
    if not candidate_libc.is_file() or not candidate_loader.is_file():
        raise RunnerError(f"crabc artifacts unavailable under {target_dir}")
    if not os.access(candidate_loader, os.X_OK):
        raise RunnerError(f"crabc loader is not executable: {candidate_loader}")
    fixture = args.fixture.expanduser().resolve()
    if not fixture.is_file():
        raise RunnerError(f"Rust fixture unavailable: {fixture}")
    if fixture == FIXTURE.resolve() and not FIXTURE_MANIFEST.is_file():
        raise RunnerError(f"Rust fixture manifest unavailable: {FIXTURE_MANIFEST}")

    active_toolchain = command_output("rustup", "show", "active-toolchain")
    if not active_toolchain.startswith(TOOLCHAIN):
        raise RunnerError(f"active Rust toolchain is not pinned {TOOLCHAIN}: {active_toolchain}")
    rustc_vv = command_output("rustc", f"+{TOOLCHAIN}", "-Vv")
    if f"host: {TARGET}" not in rustc_vv:
        raise RunnerError(f"Rust compiler host is not {TARGET}: {rustc_vv}")
    # GCC writes its version to stderr; a successful empty stdout is expected.
    musl_gcc_version_result = subprocess.run(
        [require_command("musl-gcc"), "-v"], check=False, capture_output=True, text=True
    )
    musl_gcc_evidence = musl_gcc_version_result.stderr + musl_gcc_version_result.stdout
    if "musl" not in musl_gcc_evidence.lower() or "/opt/musl-1.2.6" not in (
        Path(require_command("musl-gcc")).read_text(encoding="utf-8")
    ):
        raise RunnerError("musl-gcc is not the pinned /opt/musl-1.2.6 wrapper")
    reject_glibc(rustc_vv + musl_gcc_evidence, "toolchain evidence")
    return {
        "musl_root": musl_root,
        "musl_loader": musl_loader,
        "musl_libc": musl_libc,
        "target_dir": target_dir,
        "candidate_libc": candidate_libc,
        "candidate_loader": candidate_loader,
        "fixture": fixture,
        "fixture_manifest": FIXTURE_MANIFEST,
        "active_toolchain": active_toolchain,
        "rustc_vv": rustc_vv,
        "musl_gcc_evidence": musl_gcc_evidence.strip(),
        "musl_gcc_path": Path(require_command("musl-gcc")),
    }


def build_fixture(inputs: Mapping[str, object], workspace: Path) -> tuple[Path, dict[str, object]]:
    project = workspace / "project"
    source = inputs["fixture"]
    fixture_manifest = inputs["fixture_manifest"]
    assert isinstance(source, Path)
    assert isinstance(fixture_manifest, Path)
    (project / "src").mkdir(parents=True)
    shutil.copy2(source, project / "src/main.rs")
    shutil.copy2(fixture_manifest, project / "Cargo.toml")
    target_dir = workspace / "cargo-target"
    command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "build",
        "--release",
        "--target",
        TARGET,
        "-Z",
        "build-std=std,panic_abort",
    ]
    environment = dict(os.environ)
    for key in tuple(environment):
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"} or key.startswith("CARGO_TARGET_"):
            environment.pop(key, None)
    environment.update(
        {
            "CARGO_TARGET_DIR": str(target_dir),
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": "musl-gcc",
            # The repository's link-dead-code flag is for libc artifacts and
            # breaks this nightly's build-std compiler-builtins pass.  The
            # temporary project is outside the repository, and this is its
            # complete, explicit target configuration.
            "RUSTFLAGS": "-C target-feature=-crt-static -C link-arg=-L/usr/lib",
        }
    )
    result = subprocess.run(command, cwd=project, env=environment, capture_output=True, text=True)
    build_report: dict[str, object] = {
        "command": command,
        "cwd_isolated_from_repository_config": True,
        "rustflags": environment["RUSTFLAGS"],
        "linker": environment["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.returncode != 0:
        raise BuildFailure(
            f"stock Rust build-std failed ({result.returncode}); see report build.stderr",
            build_report,
        )
    binary = target_dir / TARGET / "release/crabc-rust-std-fixture"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RunnerError(f"build-std completed without executable: {binary}")
    dynamic = readelf(binary, "-l")
    needed = readelf(binary, "-d")
    reject_glibc(dynamic + needed, "Rust fixture ELF")
    if "INTERP" not in dynamic or "libc.musl-aarch64.so.1" not in needed:
        raise RunnerError("Rust fixture is not a dynamic musl binary")
    build_report.update(
        {
            "binary": str(binary),
            "binary_sha256": sha256_file(binary),
            "program_headers": dynamic,
            "dynamic_section": needed,
        }
    )
    return binary, build_report


def run_comparison(inputs: Mapping[str, object], binary: Path, timeout: float) -> tuple[dict[str, object], dict[str, object]]:
    candidate_libc = inputs["candidate_libc"]
    candidate_loader = inputs["candidate_loader"]
    musl_loader = inputs["musl_loader"]
    musl_libc = inputs["musl_libc"]
    assert isinstance(candidate_libc, Path)
    assert isinstance(candidate_loader, Path)
    assert isinstance(musl_loader, Path)
    assert isinstance(musl_libc, Path)
    environment = sanitize_environment()
    with tempfile.TemporaryDirectory(prefix="rstd-") as temporary_name:
        temporary = Path(temporary_name)
        runtime_lib = temporary / "lib"
        runtime_lib.mkdir()
        # GCC's unwinder is a non-libc musl image artifact.  Copying it into
        # the one common library path keeps the two executions identical.
        system_libgcc = Path("/usr/lib/libgcc_s.so.1")
        if not system_libgcc.is_file():
            raise RunnerError(f"pinned Alpine libgcc_s is unavailable: {system_libgcc}")
        shutil.copy2(system_libgcc, runtime_lib / "libgcc_s.so.1")
        reference_loader = temporary / "r"
        candidate_loader_path = temporary / "c"
        shutil.copy2(musl_loader, reference_loader)
        shutil.copy2(candidate_loader, candidate_loader_path)
        candidate_loader_path.chmod(candidate_loader_path.stat().st_mode | stat.S_IXUSR)
        reference_binary = temporary / "reference"
        candidate_binary = temporary / "candidate"
        patch_interpreter(binary, reference_binary, str(reference_loader))
        patch_interpreter(binary, candidate_binary, str(candidate_loader_path))

        shutil.copy2(musl_libc, runtime_lib / "libc.musl-aarch64.so.1")
        reference = run_binary(reference_binary, environment, runtime_lib, timeout)
        shutil.copy2(candidate_libc, runtime_lib / "libc.musl-aarch64.so.1")
        candidate = run_binary(candidate_binary, environment, runtime_lib, timeout)
        comparison = compare_results(reference, candidate)
        artifacts = {
            "fixture_original_sha256": sha256_file(binary),
            "reference_loader_sha256": sha256_file(reference_loader),
            "candidate_loader_sha256": sha256_file(candidate_loader_path),
            "reference_libc_sha256": sha256_file(musl_libc),
            "candidate_libc_sha256": sha256_file(candidate_libc),
            "libgcc_s_sha256": sha256_file(runtime_lib / "libgcc_s.so.1"),
            "library_path_text": str(runtime_lib),
            "reference_interpreter": str(reference_loader),
            "candidate_interpreter": str(candidate_loader_path),
        }
    return comparison, artifacts


def load_pins() -> dict[str, object]:
    try:
        with UPSTREAMS.open("rb") as stream:
            upstreams = tomllib.load(stream)
    except OSError as error:
        raise RunnerError(f"pinned upstream manifest unavailable: {UPSTREAMS}") from error
    environment = upstreams.get("environment")
    musl = upstreams.get("musl")
    if not isinstance(environment, dict) or not isinstance(musl, dict):
        raise RunnerError("compat/upstreams.toml lacks environment/musl pins")
    if environment.get("platform") != "linux/arm64" or environment.get("rust_toolchain") != TOOLCHAIN:
        raise RunnerError("compat/upstreams.toml is not pinned to the native Rust/musl environment")
    if musl.get("version") != MUSL_VERSION:
        raise RunnerError("compat/upstreams.toml has an unexpected musl version")
    return {"environment": environment, "musl": musl}


def atomic_write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--musl-root", type=Path, default=Path(os.environ.get("MUSL_ROOT", MUSL_ROOT)))
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> tuple[bool, Path]:
    pins = load_pins()
    inputs = validate_inputs(args)
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "compat/rust-std/run.py",
        "result": "error",
        "passed": False,
        "target": TARGET,
        "toolchain": inputs["active_toolchain"],
        "rustc_vv": inputs["rustc_vv"],
        "musl": {
            **pins["musl"],
            "root": str(inputs["musl_root"]),
            "loader_sha256": sha256_file(inputs["musl_loader"]),
            "libc_sha256": sha256_file(inputs["musl_libc"]),
        },
        "fixture": {
            "source": str(inputs["fixture"]),
            "source_sha256": sha256_file(inputs["fixture"]),
            "manifest": str(inputs["fixture_manifest"]),
            "manifest_sha256": sha256_file(inputs["fixture_manifest"]),
        },
        "candidate": {
            "target_dir": str(inputs["target_dir"]),
            "loader_sha256": sha256_file(inputs["candidate_loader"]),
            "libc_sha256": sha256_file(inputs["candidate_libc"]),
        },
        "environment_boundary": {
            **pins["environment"],
            "same_kernel": True,
            "same_non_libc_dsos": True,
            "musl_gcc": str(inputs["musl_gcc_path"]),
            "musl_gcc_evidence": inputs["musl_gcc_evidence"],
            "no_glibc": True,
            "build_uses_stock_std": True,
            "build_uses_build_std": True,
            "build_has_project_dependencies": False,
            "runtime_loader_is_program": False,
        },
        "normalization": "none",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="crabc-rust-std-") as temporary_name:
            binary, build_report = build_fixture(inputs, Path(temporary_name))
            report["build"] = build_report
            comparison, artifacts = run_comparison(inputs, binary, args.timeout)
            report["runtime_artifacts"] = artifacts
            report["comparison"] = comparison
            report["passed"] = bool(comparison["passed"])
            report["result"] = "pass" if report["passed"] else "fail"
    except BuildFailure as error:
        report["build"] = error.report
        report["error"] = str(error)
        report["result"] = "error"
        atomic_write_json(args.report.expanduser().resolve(), report)
        raise
    except RunnerError as error:
        report["error"] = str(error)
        report["result"] = "error"
        atomic_write_json(args.report.expanduser().resolve(), report)
        raise
    report_path = args.report.expanduser().resolve()
    atomic_write_json(report_path, report)
    return bool(report["passed"]), report_path


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        passed, report = run(args)
    except RunnerError as error:
        print(f"rust-std: ERROR: {error}", file=sys.stderr)
        return 2
    print(f"rust-std: {'PASS' if passed else 'FAIL'}: report: {report}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
