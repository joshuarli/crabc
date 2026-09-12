#!/usr/bin/env python3
"""Pinned-native correctness smoke for the x86 timing-launcher supervisor.

The launcher is a measurement boundary, rather than a workload.  This smoke
builds it and a tiny static client with the pinned musl compiler, then retains
the command, source, ELF, raw result JSON, and client-output evidence below a
fresh ``.work/x86_64`` directory.  It deliberately collects no benchmark
score.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[3]
WORK_BOUNDARY = ROOT / ".work/x86_64"
LAUNCHER_SOURCE = ROOT / "compat/perf/x86_64_timing_launcher.c"
BURN_WRAPPER_SOURCE = ROOT / "compat/perf/tests/x86_64_timing_launcher_pre_fork_burn_wrapper.c"
SCHEMA = "crabc.perf.x86_64-timing-launcher/v1"
PINNED_COMPILER = "/usr/local/bin/crabc-x86_64-musl-gcc"
RESOURCE_KEYS = {
    "user_cpu_ns",
    "system_cpu_ns",
    "max_rss_kib",
    "minor_faults",
    "major_faults",
    "voluntary_context_switches",
    "involuntary_context_switches",
}


class SmokeError(RuntimeError):
    """The native launcher did not preserve its measurement boundary."""


CLIENT_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int only_standard_descriptors(void) {
    int descriptor;
    for (descriptor = 3; descriptor < 4096; ++descriptor) {
        errno = 0;
        if (fcntl(descriptor, F_GETFD) != -1 || errno != EBADF) {
            return 0;
        }
    }
    return 1;
}

static int inherited_probe_descriptor_closed(const char *environment_name) {
    const char *text = getenv(environment_name);
    char *end = NULL;
    long descriptor;

    if (text == NULL) {
        return 1;
    }
    errno = 0;
    descriptor = strtol(text, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || descriptor < 3 || descriptor > INT_MAX) {
        return 0;
    }
    errno = 0;
    return fcntl((int)descriptor, F_GETFD) == -1 && errno == EBADF;
}

int main(int argc, char **argv) {
    char cwd[PATH_MAX];
    char input;
    const char *mode = argc > 1 ? argv[1] : "ok";
    const char *environment = getenv("CRABC_TIMING_LAUNCHER_SMOKE_ENV");
    const char *library_path = getenv("LD_LIBRARY_PATH");

    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/app") != 0) {
        return 20;
    }
    if (environment == NULL || strcmp(environment, "exact-scrubbed-lane") != 0) {
        return 21;
    }
    if (getenv("CRABC_TIMING_LAUNCHER_FORBIDDEN") != NULL) {
        return 22;
    }
    if (library_path == NULL || strcmp(library_path, "/app/lib") != 0) {
        return 27;
    }
    if (read(STDIN_FILENO, &input, 1) != 0) {
        return 23;
    }
    if (!only_standard_descriptors()) {
        return 24;
    }
    if (!inherited_probe_descriptor_closed("CRABC_TIMING_LAUNCHER_SMOKE_LOW_FD") ||
        !inherited_probe_descriptor_closed("CRABC_TIMING_LAUNCHER_SMOKE_HIGH_FD")) {
        return 28;
    }

    printf("pid=%ld cwd=%s env=%s ld=%s stdin=eof fds=stdio-only\n",
           (long)getpid(), cwd, environment, library_path);
    fprintf(stderr, "client-stderr\n");
    fflush(stdout);
    fflush(stderr);

    if (strcmp(mode, "exit7") == 0) {
        return 7;
    }
    if (strcmp(mode, "signal") == 0) {
        raise(SIGTERM);
        return 25;
    }
    if (strcmp(mode, "sleep") == 0) {
        for (;;) {
            pause();
        }
    }
    if (strcmp(mode, "ok") != 0) {
        return 26;
    }
    return 0;
}
'''


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return str(path.resolve(strict=True).relative_to(ROOT.resolve(strict=True)))


def file_identity(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"retained file is not physical: {path}")
    return {"path": relative(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_host_readable(*paths: Path) -> None:
    """Expose completed container-owned proof bytes to the checkout owner."""

    for path in paths:
        if path.exists() and path.is_file() and not path.is_symlink():
            path.chmod(path.stat().st_mode | 0o444)


def bounded_fresh_work(value: Path | None) -> Path:
    boundary = WORK_BOUNDARY.resolve(strict=True)
    require(boundary.is_dir() and not boundary.is_symlink(), "native work boundary is not physical")
    if value is None:
        return Path(tempfile.mkdtemp(prefix="native-timing-launcher-smoke-", dir=boundary))
    candidate = value if value.is_absolute() else ROOT / value
    require(".." not in candidate.parts, "smoke work path has parent traversal")
    absolute = Path(os.path.abspath(candidate))
    try:
        absolute.relative_to(boundary)
    except ValueError as error:
        raise SmokeError(f"smoke work path escapes {boundary}: {absolute}") from error
    require(not absolute.exists() and not absolute.is_symlink(), f"smoke work path must be fresh: {absolute}")
    # The pinned container writes these retained proof artifacts as root.  Keep
    # the directories host-readable for review after the container exits.
    absolute.mkdir(mode=0o755)
    require(absolute.resolve(strict=True) == absolute, "smoke work path is not physical")
    return absolute


def run_capture(command: list[str], log_root: Path, name: str, *, timeout: float = 20.0,
                environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    (log_root / f"{name}.stdout").write_bytes(result.stdout)
    (log_root / f"{name}.stderr").write_bytes(result.stderr)
    write_json(log_root / f"{name}.command.json", {"argv": command, "returncode": result.returncode})
    return result


def compile_static(compiler: str, source: Path, output: Path, logs: Path, name: str,
                   extra: Sequence[str] = ()) -> list[str]:
    command = [
        compiler,
        "-static",
        "-no-pie",
        "-std=c11",
        "-O2",
        *extra,
        str(source),
        "-o",
        str(output),
    ]
    result = run_capture(command, logs, f"compile-{name}", timeout=30)
    require(result.returncode == 0, f"{name} compile failed: {result.stderr.decode('utf-8', errors='replace')}")
    require(output.is_file() and output.stat().st_mode & 0o111, f"{name} is not executable")
    return command


def inspect_static_elf(binary: Path, logs: Path, name: str) -> dict[str, Any]:
    header = run_capture(["readelf", "-h", str(binary)], logs, f"elf-{name}-header")
    program_headers = run_capture(["readelf", "-l", str(binary)], logs, f"elf-{name}-program-headers")
    require(header.returncode == 0 and program_headers.returncode == 0, f"readelf failed for {name}")
    header_text = header.stdout.decode("utf-8", errors="replace")
    program_text = program_headers.stdout.decode("utf-8", errors="replace")
    require("Type:" in header_text and "EXEC" in header_text, f"{name} is not static ET_EXEC")
    require("Machine:" in header_text and "X86-64" in header_text, f"{name} is not x86-64")
    require("INTERP" not in program_text, f"{name} unexpectedly has PT_INTERP")
    return {
        "binary": file_identity(binary),
        "header_log": file_identity(logs / f"elf-{name}-header.stdout"),
        "program_headers_log": file_identity(logs / f"elf-{name}-program-headers.stdout"),
    }


def stage_dev_null(root: Path) -> None:
    device = root / "dev/null"
    device.parent.mkdir(mode=0o755)
    os.mknod(device, stat.S_IFCHR | 0o666, os.makedev(1, 3))


def stage_client_root(case: Path, client: Path) -> Path:
    client_root = case / "client-root"
    destination = client_root / "app/bin/client"
    destination.parent.mkdir(parents=True, mode=0o755)
    stage_dev_null(client_root)
    shutil.copy2(client, destination)
    destination.chmod(0o755)
    return client_root


def read_record(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SmokeError(f"launcher did not write valid result JSON: {path}: {error}") from error
    require(isinstance(value, dict), "launcher result is not an object")
    require(set(value) == {"schema", "child_pid", "wait_status", "timed_out", "elapsed_wall_ns", "resources"},
            f"launcher result fields differ: {sorted(value)}")
    require(value["schema"] == SCHEMA, "launcher result schema differs")
    require(isinstance(value["child_pid"], int) and not isinstance(value["child_pid"], bool) and value["child_pid"] > 0,
            "launcher result child PID is invalid")
    require(isinstance(value["wait_status"], int) and not isinstance(value["wait_status"], bool),
            "launcher result wait status is invalid")
    require(isinstance(value["timed_out"], bool), "launcher result timeout flag is invalid")
    require(isinstance(value["elapsed_wall_ns"], int) and not isinstance(value["elapsed_wall_ns"], bool)
            and value["elapsed_wall_ns"] >= 0, "launcher elapsed time is invalid")
    resources = value["resources"]
    require(isinstance(resources, dict) and set(resources) == RESOURCE_KEYS,
            f"launcher resource fields differ: {sorted(resources) if isinstance(resources, dict) else resources!r}")
    for key, number in resources.items():
        require(isinstance(number, int) and not isinstance(number, bool) and number >= 0,
                f"launcher resource {key} is invalid")
    return value


def launch_case(launcher: Path, case_root: Path, *, binary: str = "/app/bin/client", mode: str = "ok",
                timeout_ms: int = 1_000, process_timeout: float = 8.0,
                environment: dict[str, str], pass_fds: tuple[int, ...] = ()) -> tuple[subprocess.CompletedProcess[bytes], Path, Path, Path]:
    output = case_root / "outputs"
    output.mkdir(mode=0o755)
    stdout_path = output / "stdout"
    stderr_path = output / "stderr"
    result_path = output / "result.json"
    command = [
        str(launcher), str(case_root / "client-root"), str(stdout_path), str(stderr_path), str(result_path),
        str(timeout_ms), binary, mode,
    ]
    result = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=process_timeout, pass_fds=pass_fds)
    make_host_readable(stdout_path, stderr_path, result_path)
    write_json(output / "launcher-command.json", {"argv": command, "returncode": result.returncode})
    (output / "launcher-parent.stdout").write_bytes(result.stdout)
    (output / "launcher-parent.stderr").write_bytes(result.stderr)
    return result, stdout_path, stderr_path, result_path


def assert_client_observables(record: dict[str, Any], stdout_path: Path, stderr_path: Path) -> None:
    stdout = stdout_path.read_text(encoding="utf-8")
    match = re.fullmatch(
        r"pid=(\d+) cwd=/app env=exact-scrubbed-lane ld=/app/lib stdin=eof fds=stdio-only\n", stdout,
    )
    require(match is not None, f"client stdout does not prove direct clean execution: {stdout!r}")
    require(int(match.group(1)) == record["child_pid"], "result child PID is not the direct exec client PID")
    require(stderr_path.read_bytes() == b"client-stderr\n", "client stderr did not reach its exact output")


def assert_exit(record: dict[str, Any], code: int) -> None:
    require(not record["timed_out"], "ordinary child exit was marked timed out")
    require(os.WIFEXITED(record["wait_status"]), "launcher did not retain an exited raw wait status")
    require(os.WEXITSTATUS(record["wait_status"]) == code, "launcher decoded the wrong child exit")


def assert_signal(record: dict[str, Any], expected: int, *, timed_out: bool) -> None:
    require(record["timed_out"] is timed_out, "launcher timeout classification differs")
    require(os.WIFSIGNALED(record["wait_status"]), "launcher did not retain a signalled raw wait status")
    require(os.WTERMSIG(record["wait_status"]) == expected, "launcher decoded the wrong child signal")


def run_burn_wrapper(launcher: Path, case: Path, environment: dict[str, str]) -> dict[str, Any]:
    root = stage_client_root(case, case.parent / "clients/client-static")
    output = case / "outputs"
    output.mkdir(mode=0o755)
    stdout_path = output / "stdout"
    stderr_path = output / "stderr"
    result_path = output / "result.json"
    arguments = [
        str(launcher), str(root), str(stdout_path), str(stderr_path), str(result_path), "1000", "/app/bin/client", "ok",
    ]
    pid = os.fork()
    if pid == 0:
        try:
            os.chdir(ROOT)
            os.execve(str(launcher), arguments, environment)
        except BaseException:
            os._exit(127)
    waited, status, usage = os.wait4(pid, 0)
    make_host_readable(stdout_path, stderr_path, result_path)
    require(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
            f"test-only burn wrapper did not finish: raw status {status}")
    record = read_record(result_path)
    assert_exit(record, 0)
    assert_client_observables(record, stdout_path, stderr_path)
    outer_user_ns = usage.ru_utime_ns if hasattr(usage, "ru_utime_ns") else round(usage.ru_utime * 1_000_000_000)
    outer_system_ns = usage.ru_stime_ns if hasattr(usage, "ru_stime_ns") else round(usage.ru_stime * 1_000_000_000)
    outer_cpu_ns = outer_user_ns + outer_system_ns
    require(outer_cpu_ns >= 100_000_000,
            f"outer wait4 did not observe the supervisor-only CPU burn: {outer_cpu_ns} ns")
    emitted_cpu_ns = record["resources"]["user_cpu_ns"] + record["resources"]["system_cpu_ns"]
    require(emitted_cpu_ns < 80_000_000,
            "emitted child rusage includes the supervisor-only CPU burn")
    return {
        "outer_wait4_user_cpu_ns": outer_user_ns,
        "outer_wait4_system_cpu_ns": outer_system_ns,
        "outer_wait4_cpu_ns": outer_cpu_ns,
        "emitted_child_cpu_ns": emitted_cpu_ns,
        "record": file_identity(result_path),
        "stdout": file_identity(stdout_path),
        "stderr": file_identity(stderr_path),
    }


def inherited_probe_descriptors(work: Path) -> tuple[int, int]:
    """Create two non-CLOEXEC descriptors that `pass_fds` must carry to C."""

    source = work / "inherited-descriptor-probe"
    source.write_bytes(b"timing launcher inherited descriptor probe\n")
    base = os.open(source, os.O_RDONLY)
    low = -1
    high = -1
    try:
        low = fcntl.fcntl(base, fcntl.F_DUPFD, 10)
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        require(limit != resource.RLIM_INFINITY and limit > 65_537,
                f"pinned smoke has no high descriptor range: {limit}")
        high = fcntl.fcntl(base, fcntl.F_DUPFD, min(900_000, int(limit) - 2))
        os.set_inheritable(low, True)
        os.set_inheritable(high, True)
        require(not (fcntl.fcntl(low, fcntl.F_GETFD) & fcntl.FD_CLOEXEC), "low probe descriptor stayed CLOEXEC")
        require(not (fcntl.fcntl(high, fcntl.F_GETFD) & fcntl.FD_CLOEXEC), "high probe descriptor stayed CLOEXEC")
        return low, high
    except BaseException:
        if low >= 0:
            os.close(low)
        if high >= 0:
            os.close(high)
        raise
    finally:
        os.close(base)


def run_smoke(compiler: str, work: Path) -> dict[str, Any]:
    require(LAUNCHER_SOURCE.is_file(), "timing launcher source is absent")
    require(BURN_WRAPPER_SOURCE.is_file(), "timing launcher test-only fork wrapper is absent")
    require(compiler == PINNED_COMPILER, f"timing launcher requires pinned compiler {PINNED_COMPILER}")
    compiler_path = Path(compiler)
    require(compiler_path.is_absolute() and compiler_path.is_file(), "pinned timing launcher compiler is unavailable")
    sources = work / "sources"
    logs = work / "logs"
    clients = work / "clients"
    sources.mkdir(mode=0o755)
    logs.mkdir(mode=0o755)
    clients.mkdir(mode=0o755)
    client_source = sources / "client.c"
    client_source.write_text(CLIENT_SOURCE, encoding="utf-8")
    compiler_version = run_capture([compiler, "--version"], logs, "compiler-version")
    require(compiler_version.returncode == 0, "could not inspect pinned musl compiler")

    launcher = work / "timing-launcher"
    burn_launcher = work / "timing-launcher-pre-fork-burn"
    client = clients / "client-static"
    launcher_command = compile_static(compiler, LAUNCHER_SOURCE, launcher, logs, "launcher")
    burn_command = compile_static(compiler, BURN_WRAPPER_SOURCE, burn_launcher, logs, "launcher-pre-fork-burn")
    client_command = compile_static(compiler, client_source, client, logs, "client")
    elf = {
        "launcher": inspect_static_elf(launcher, logs, "launcher"),
        "launcher_pre_fork_burn": inspect_static_elf(burn_launcher, logs, "launcher-pre-fork-burn"),
        "client": inspect_static_elf(client, logs, "client"),
    }
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "LD_LIBRARY_PATH": "/app/lib",
        "CRABC_TIMING_LAUNCHER_SMOKE_ENV": "exact-scrubbed-lane",
    }

    cases: dict[str, Any] = {}
    for name, mode, expected_exit in (("ok", "ok", 0), ("exit7", "exit7", 7)):
        case = work / f"case-{name}"
        root = stage_client_root(case, client)
        result, stdout_path, stderr_path, result_path = launch_case(launcher, case, mode=mode, environment=environment)
        require(result.returncode == 0, f"launcher returned {result.returncode} for child {name}")
        record = read_record(result_path)
        assert_exit(record, expected_exit)
        assert_client_observables(record, stdout_path, stderr_path)
        cases[name] = {
            "root": relative(root), "record": file_identity(result_path),
            "stdout": file_identity(stdout_path), "stderr": file_identity(stderr_path),
        }

    probe_low, probe_high = inherited_probe_descriptors(work)
    try:
        descriptor_case = work / "case-inherited-descriptor-closure"
        stage_client_root(descriptor_case, client)
        descriptor_environment = dict(environment)
        descriptor_environment["CRABC_TIMING_LAUNCHER_SMOKE_LOW_FD"] = str(probe_low)
        descriptor_environment["CRABC_TIMING_LAUNCHER_SMOKE_HIGH_FD"] = str(probe_high)
        result, stdout_path, stderr_path, result_path = launch_case(
            launcher, descriptor_case, environment=descriptor_environment, pass_fds=(probe_low, probe_high),
        )
    finally:
        os.close(probe_low)
        os.close(probe_high)
    require(result.returncode == 0, "launcher failed to close inherited descriptor probes")
    record = read_record(result_path)
    assert_exit(record, 0)
    assert_client_observables(record, stdout_path, stderr_path)
    cases["inherited_descriptor_closure"] = {
        "low_descriptor": probe_low,
        "high_descriptor": probe_high,
        "record": file_identity(result_path),
        "stdout": file_identity(stdout_path),
        "stderr": file_identity(stderr_path),
    }

    signal_case = work / "case-signal"
    stage_client_root(signal_case, client)
    result, stdout_path, stderr_path, result_path = launch_case(launcher, signal_case, mode="signal", environment=environment)
    require(result.returncode == 0, "launcher failed while collecting a signalled child")
    record = read_record(result_path)
    assert_signal(record, signal.SIGTERM, timed_out=False)
    assert_client_observables(record, stdout_path, stderr_path)
    cases["signal"] = {"record": file_identity(result_path), "stdout": file_identity(stdout_path), "stderr": file_identity(stderr_path)}

    timeout_case = work / "case-timeout"
    stage_client_root(timeout_case, client)
    result, stdout_path, stderr_path, result_path = launch_case(
        launcher, timeout_case, mode="sleep", timeout_ms=80, environment=environment,
    )
    require(result.returncode == 0, "launcher failed while collecting a timed-out child")
    record = read_record(result_path)
    assert_signal(record, signal.SIGKILL, timed_out=True)
    assert_client_observables(record, stdout_path, stderr_path)
    require(not Path(f"/proc/{record['child_pid']}").exists(), "timed-out child remained in proc after launcher reaped it")
    cases["timeout"] = {"record": file_identity(result_path), "stdout": file_identity(stdout_path), "stderr": file_identity(stderr_path)}

    missing_case = work / "case-missing-client"
    stage_client_root(missing_case, client)
    result, stdout_path, stderr_path, result_path = launch_case(
        launcher, missing_case, binary="/app/bin/missing", environment=environment,
    )
    require(result.returncode == 0, "launcher did not collect a direct exec failure")
    record = read_record(result_path)
    assert_exit(record, 127)
    require(stdout_path.read_bytes() == b"" and stderr_path.read_bytes() == b"", "direct exec failure wrote synthetic client output")
    cases["direct_exec_failure"] = {"record": file_identity(result_path), "stdout": file_identity(stdout_path), "stderr": file_identity(stderr_path)}

    setup_case = work / "case-setup-failure"
    (setup_case / "client-root").mkdir(parents=True, mode=0o755)
    stage_dev_null(setup_case / "client-root")
    result, stdout_path, stderr_path, result_path = launch_case(launcher, setup_case, environment=environment)
    require(result.returncode != 0, "launcher converted pre-fork setup failure into a collection result")
    require(result_path.exists() and result_path.read_bytes() == b"", "setup failure wrote a synthetic success JSON record")
    cases["setup_failure"] = {"stdout": file_identity(stdout_path), "stderr": file_identity(stderr_path), "result_size": result_path.stat().st_size}

    fifo_case = work / "case-fifo-stdin"
    fifo_root = fifo_case / "client-root"
    (fifo_root / "app/bin").mkdir(parents=True, mode=0o755)
    (fifo_root / "dev").mkdir(mode=0o755)
    os.mkfifo(fifo_root / "dev/null", 0o600)
    try:
        result, stdout_path, stderr_path, result_path = launch_case(
            launcher, fifo_case, mode="ok", process_timeout=0.4, environment=environment,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeError("FIFO ROOT/dev/null blocked launcher before its finite setup failure") from error
    require(result.returncode != 0, "FIFO ROOT/dev/null was admitted as client stdin")
    require(not stdout_path.exists() and not stderr_path.exists() and not result_path.exists(),
            "FIFO ROOT/dev/null created collection outputs")
    cases["fifo_stdin_failure"] = {"returncode": result.returncode}

    cases["pre_fork_burn"] = run_burn_wrapper(burn_launcher, work / "case-pre-fork-burn", environment)
    return {
        "schema": "crabc.perf.x86_64-timing-launcher-smoke/v1",
        "work": str(work.relative_to(ROOT)),
        "compiler": compiler,
        "compiler_identity": {
            "path": compiler,
            "sha256": sha256_file(compiler_path),
            "version_log": file_identity(logs / "compiler-version.stdout"),
        },
        "inputs": {
            "launcher_source": file_identity(LAUNCHER_SOURCE),
            "pre_fork_burn_wrapper_source": file_identity(BURN_WRAPPER_SOURCE),
            "client_source": file_identity(client_source),
            "launcher_compile": launcher_command,
            "launcher_pre_fork_burn_compile": burn_command,
            "client_compile": client_command,
        },
        "elf": elf,
        "cases": cases,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument("--work", type=Path, default=None)
    arguments = parser.parse_args(argv)
    try:
        work = bounded_fresh_work(arguments.work)
        report = run_smoke(arguments.compiler, work)
        write_json(work / "timing-launcher-smoke-report.json", report)
    except (OSError, SmokeError, subprocess.TimeoutExpired) as error:
        print(f"x86_64 timing launcher smoke: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
