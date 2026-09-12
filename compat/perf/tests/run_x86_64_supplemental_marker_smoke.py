#!/usr/bin/env python3
"""Pinned-native regression smoke for supplemental syscall markers.

This is a diagnostic-boundary check, not a timing run or release
qualification. It compiles the ordinary supplemental artifacts with pinned
musl and proves that their opt-in marker pair delimits one successful selected
route without changing ordinary stdout or arguments.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import os
import re
import shutil
import socket
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORK = ROOT / ".work/x86_64/native-supplemental-marker-smoke"
FIXTURE_HELPERS_PATH = ROOT / "compat/perf/tests/run_x86_64_workloads_smoke.py"
PROFILE_PATH = ROOT / "compat/perf/x86_64-profile.toml"
EXPECTED_STDOUT = b"ok\n"
MARKER_ENV = "CRABC_PERF_MARKER_FD"
MARKER_FD = 97
MARKER_BEGIN = b"CRABC_PERF_BEGIN"
MARKER_END = b"CRABC_PERF_END"
EXPECTED_MARKERS = MARKER_BEGIN + MARKER_END

SOURCES = {
    "x86_64_clock_allocator_workload": (
        "compat/perf/x86_64_clock_allocator_workload.c", True,
    ),
    "x86_64_network_workload": ("compat/perf/x86_64_network_workload.c", False),
    "x86_64_primitive_boundary_workload": (
        "compat/perf/x86_64_primitive_boundary_workload.c", False,
    ),
}
EXPECTED_ROWS_PER_SOURCE = {
    "x86_64_clock_allocator_workload": 15,
    "x86_64_network_workload": 7,
    "x86_64_primitive_boundary_workload": 18,
}


class SmokeError(RuntimeError):
    """An ordinary supplemental artifact lacked its diagnostic boundary."""


def load_fixture_helpers() -> object:
    """Reuse the existing controlled loopback peer without changing it."""

    sys.dont_write_bytecode = True
    specification = importlib.util.spec_from_file_location(
        "crabc_supplemental_marker_fixture_helpers", FIXTURE_HELPERS_PATH
    )
    if specification is None or specification.loader is None:
        raise SmokeError("could not load the controlled loopback peer")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def work_directory(path: Path) -> Path:
    boundary = (ROOT / ".work/x86_64").resolve()
    candidate = path.resolve()
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise SmokeError(f"work directory must remain below {boundary}: {candidate}") from error
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def clean_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop(MARKER_ENV, None)
    environment.pop("CRABC_PERF_OBSERVER_READY_FD", None)
    environment.pop("CRABC_PERF_OBSERVER_CONTINUE_FD", None)
    return environment


def close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def marker_descriptor(descriptor: int) -> int:
    """Move a child-only marker endpoint to the runner's fixed descriptor."""

    if descriptor == MARKER_FD:
        return descriptor
    temporary = fcntl.fcntl(descriptor, fcntl.F_DUPFD, 100)
    try:
        os.dup2(temporary, MARKER_FD)
    finally:
        close_descriptor(temporary)
    close_descriptor(descriptor)
    return MARKER_FD


def terminate_and_reap(process: subprocess.Popen[bytes] | None) -> str | None:
    """Reap only a child this smoke owns within finite deadlines."""

    if process is None or process.poll() is not None:
        return None
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    except OSError as error:
        return f"could not terminate marker child: {error}"
    try:
        process.communicate(timeout=2)
        return None
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            return f"marker child could not be killed: {error}"
        try:
            process.communicate(timeout=2)
            return None
        except subprocess.TimeoutExpired:
            return "marker child could not be reaped after terminate/kill deadlines"
        except OSError as error:
            return f"marker child could not be reaped after kill: {error}"
    except OSError as error:
        return f"marker child could not be reaped: {error}"


def compile_checked(compiler: str, source: str, output: Path, *, pthread: bool) -> None:
    command = [
        compiler,
        "-std=c11",
        "-D_GNU_SOURCE",
        "-O2",
        "-fno-builtin",
        "-fno-stack-protector",
        "-Wall",
        "-Wextra",
        "-Werror",
        source,
        "-o",
        str(output),
    ]
    if pthread:
        command.insert(-2, "-pthread")
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise SmokeError(
            f"compile failed: argv={command!r} stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def validate_profile_roster() -> int:
    """Bind all 40 diagnostic rows to these three ordinary source artifacts."""

    profile = tomllib.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    expected_sources = {binary: source for binary, (source, _) in SOURCES.items()}
    fixtures = {
        fixture.get("binary"): fixture.get("source")
        for fixture in profile.get("fixture", [])
    }
    if fixtures != expected_sources:
        raise SmokeError(
            f"supplemental profile fixture roster changed: expected={expected_sources!r} "
            f"actual={fixtures!r}"
        )
    rows = profile.get("supplemental_row", [])
    counts = Counter(row.get("binary") for row in rows)
    if counts != EXPECTED_ROWS_PER_SOURCE:
        raise SmokeError(
            f"supplemental profile row roster changed: expected={EXPECTED_ROWS_PER_SOURCE!r} "
            f"actual={dict(counts)!r}"
        )
    return len(rows)


def build_artifacts(compiler: str, work: Path) -> dict[str, Path]:
    binaries = work / "binaries"
    if binaries.exists():
        shutil.rmtree(binaries)
    binaries.mkdir(parents=True)
    artifacts: dict[str, Path] = {}
    for binary, (source, pthread) in SOURCES.items():
        output = binaries / binary
        compile_checked(
            compiler,
            source,
            output,
            pthread=pthread,
        )
        artifacts[binary] = output
    return artifacts


def run_plain(binary: Path, arguments: Sequence[str]) -> None:
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        env=clean_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    if result.returncode != 0 or result.stdout != EXPECTED_STDOUT or result.stderr:
        raise SmokeError(
            f"ordinary source contract changed: argv={result.args!r} status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def run_marker_child(binary: Path, arguments: Sequence[str], *, expected_status: int,
                     expected_stdout: bytes, expected_markers: bytes) -> None:
    marker_read, marker_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        marker_write = marker_descriptor(marker_write)
        environment = clean_environment()
        environment[MARKER_ENV] = str(marker_write)
        process = subprocess.Popen(
            [str(binary), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(marker_write,),
        )
        close_descriptor(marker_write)
        marker_write = None
        stdout, stderr = process.communicate(timeout=20)
        markers = os.read(marker_read, len(EXPECTED_MARKERS) + 1)
        if process.returncode != expected_status or stdout != expected_stdout or stderr:
            raise SmokeError(
                f"marker source result changed: argv={[str(binary), *arguments]!r} status={process.returncode} "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        if markers != expected_markers:
            raise SmokeError(
                f"marker stream changed: expected={expected_markers!r} received={markers!r}: "
                f"argv={[str(binary), *arguments]!r}"
            )
    except BaseException:
        failed = True
        raise
    finally:
        close_descriptor(marker_read)
        close_descriptor(marker_write)
        cleanup_error = terminate_and_reap(process)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def run_marked(binary: Path, arguments: Sequence[str]) -> None:
    run_marker_child(
        binary,
        arguments,
        expected_status=0,
        expected_stdout=EXPECTED_STDOUT,
        expected_markers=EXPECTED_MARKERS,
    )


def run_failed_route(binary: Path, arguments: Sequence[str]) -> None:
    """A selected route that fails has begun but must never report a closed region."""

    run_marker_child(
        binary,
        arguments,
        expected_status=1,
        expected_stdout=b"",
        expected_markers=MARKER_BEGIN,
    )


def run_invalid_marker(binary: Path, arguments: Sequence[str]) -> None:
    environment = clean_environment()
    environment[MARKER_ENV] = "bad"
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if result.returncode != 2 or result.stdout or b"invalid CRABC_PERF_MARKER_FD" not in result.stderr:
        raise SmokeError(
            f"invalid marker descriptor did not fail before source work: status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def marker_trace_indices(trace: str) -> tuple[int, int]:
    begin = re.compile(
        rf"(?:^|\s)write\({MARKER_FD},\s*\"{MARKER_BEGIN.decode()}\",\s*{len(MARKER_BEGIN)}\)\s+=\s*{len(MARKER_BEGIN)}$"
    )
    end = re.compile(
        rf"(?:^|\s)write\({MARKER_FD},\s*\"{MARKER_END.decode()}\",\s*{len(MARKER_END)}\)\s+=\s*{len(MARKER_END)}$"
    )
    lines = trace.splitlines()
    begins = [index for index, line in enumerate(lines) if begin.search(line)]
    ends = [index for index, line in enumerate(lines) if end.search(line)]
    if len(begins) != 1 or len(ends) != 1 or ends[0] <= begins[0]:
        raise SmokeError(
            f"strace did not contain one ordered marker pair: begin={begins!r} end={ends!r}"
        )
    return begins[0], ends[0]


def run_strace_marker(binary: Path, arguments: Sequence[str], name: str, work: Path,
                      required_syscalls: set[str]) -> None:
    if shutil.which("strace") is None:
        raise SmokeError("pinned marker smoke requires strace")
    trace_path = work / f"{name}.strace"
    marker_path = work / f"{name}.markers"
    marker_path.unlink(missing_ok=True)
    trace_path.unlink(missing_ok=True)
    marker_descriptor_fd: int | None = None
    result: subprocess.CompletedProcess[bytes] | None = None
    try:
        marker_descriptor_fd = os.open(
            marker_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC,
            0o600,
        )
        marker_descriptor_fd = marker_descriptor(marker_descriptor_fd)
        environment = clean_environment()
        environment[MARKER_ENV] = str(marker_descriptor_fd)
        result = subprocess.run(
            ["strace", "-f", "-qq", "-o", str(trace_path), str(binary), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            pass_fds=(marker_descriptor_fd,),
        )
    finally:
        close_descriptor(marker_descriptor_fd)
    if result is None:
        raise SmokeError("strace diagnostic did not start")
    if result.returncode != 0 or result.stdout != EXPECTED_STDOUT or result.stderr:
        raise SmokeError(
            f"strace diagnostic failed: argv={[str(binary), *arguments]!r} status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    markers = marker_path.read_bytes()
    if markers != EXPECTED_MARKERS:
        raise SmokeError(f"strace diagnostic marker bytes changed: {markers!r}")
    trace = trace_path.read_text(encoding="utf-8", errors="replace")
    begin, end = marker_trace_indices(trace)
    lines = trace.splitlines()
    region = lines[begin + 1:end]
    found = {
        match.group(1)
        for line in region
        if (match := re.search(r"(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*)\(", line)) is not None
    }
    missing = required_syscalls.difference(found)
    if missing:
        raise SmokeError(
            f"strace marker region lacks {sorted(missing)!r}: found={sorted(found)!r}"
        )
    if not any(re.search(r"(?:^|\s)(?:write|writev)\(1,", line) for line in lines[end + 1:]):
        raise SmokeError("real stdout did not occur after the END marker")


def run_network_plain(helpers: object, binary: Path, arguments: Sequence[str]) -> None:
    peer = helpers.EchoPeer(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", int(arguments[3]),
                            int(arguments[1]))
    peer.start()
    try:
        run_plain(binary, arguments)
    finally:
        peer.close()


def run_network_marked(helpers: object, binary: Path, arguments: Sequence[str]) -> None:
    peer = helpers.EchoPeer(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", int(arguments[3]),
                            int(arguments[1]))
    peer.start()
    try:
        run_marked(binary, arguments)
    finally:
        peer.close()


def run_network_strace(helpers: object, binary: Path, arguments: Sequence[str], work: Path) -> None:
    peer = helpers.EchoPeer(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", int(arguments[3]),
                            int(arguments[1]))
    peer.start()
    try:
        run_strace_marker(binary, arguments, "network-loopback", work,
                          {"socket", "connect", "close"})
    finally:
        peer.close()


def run_smoke(compiler: str, work: Path) -> int:
    row_count = validate_profile_roster()
    helpers = load_fixture_helpers()
    artifacts = build_artifacts(compiler, work)
    clock = artifacts["x86_64_clock_allocator_workload"]
    network = artifacts["x86_64_network_workload"]
    primitive = artifacts["x86_64_primitive_boundary_workload"]

    clock_arguments = ("live", "1", "4", "64")
    network_arguments = ("loopback_tcp_ipv4", "1", "127.0.0.1", "39241")
    primitive_arguments = ("primitive", "1", "memcpy", "guard63")

    run_marked(clock, clock_arguments)
    run_marked(primitive, primitive_arguments)
    run_network_marked(helpers, network, network_arguments)
    run_failed_route(clock, ("clock_gettime", "1", "1"))

    run_plain(clock, clock_arguments)
    run_plain(primitive, primitive_arguments)
    run_network_plain(helpers, network, ("loopback_tcp_ipv4", "1", "127.0.0.1", "39242"))
    run_invalid_marker(clock, clock_arguments)
    run_invalid_marker(network, ("loopback_tcp_ipv4", "1", "127.0.0.1", "39243"))
    run_invalid_marker(primitive, primitive_arguments)

    run_strace_marker(
        clock,
        ("live", "1", "1024", "4096"),
        "clock-allocator-live",
        work,
        {"mmap", "munmap"},
    )
    run_network_strace(
        helpers,
        network,
        ("loopback_tcp_ipv4", "1", "127.0.0.1", "39244"),
        work,
    )
    run_strace_marker(
        primitive,
        primitive_arguments,
        "primitive-guard63",
        work,
        {"mmap", "mprotect", "munmap"},
    )
    return row_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compiler",
        default="/usr/local/bin/crabc-x86_64-musl-gcc",
        help="pinned native C compiler inside the x86 evidence container",
    )
    parser.add_argument(
        "--work",
        type=Path,
        default=DEFAULT_WORK,
        help="state directory below this checkout's .work/x86_64",
    )
    arguments = parser.parse_args()
    try:
        row_count = run_smoke(arguments.compiler, work_directory(arguments.work))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"x86_64 supplemental marker smoke: {error}", file=sys.stderr)
        return 1
    print(f"x86_64 supplemental marker smoke: ok ({row_count} profile rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
