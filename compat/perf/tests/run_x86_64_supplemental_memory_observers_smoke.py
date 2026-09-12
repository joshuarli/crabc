#!/usr/bin/env python3
"""Reduced pinned-native correctness smoke for supplemental memory observers.

This is not a benchmark or release qualification run. It compiles the three
separate memory artifacts with pinned musl, runs every closed supplemental
route at reduced iterations, and verifies the fixed initial/plateau/final R/C
envelope without changing the timed fixture argv.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import os
import pty
import select
import shutil
import socket
import subprocess
import sys
import termios
import tomllib
import tty
from pathlib import Path
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORK = ROOT / ".work/x86_64/native-supplemental-memory-observers-smoke"
PROFILE_PATH = ROOT / "compat/perf/x86_64-profile.toml"
FIXTURE_HELPERS_PATH = ROOT / "compat/perf/tests/run_x86_64_workloads_smoke.py"
EXPECTED_STDOUT = b"ok\n"
READY_ENV = "CRABC_PERF_OBSERVER_READY_FD"
CONTINUE_ENV = "CRABC_PERF_OBSERVER_CONTINUE_FD"
READY_FD = 97
CONTINUE_FD = 98

TIMED_SOURCES = {
    "x86_64_clock_allocator_workload": "compat/perf/x86_64_clock_allocator_workload.c",
    "x86_64_network_workload": "compat/perf/x86_64_network_workload.c",
    "x86_64_primitive_boundary_workload": "compat/perf/x86_64_primitive_boundary_workload.c",
}
OBSERVER_SOURCES = {
    "x86_64_clock_allocator_workload": "compat/perf/x86_64_memory_observer_clock_allocator.c",
    "x86_64_network_workload": "compat/perf/x86_64_memory_observer_network.c",
    "x86_64_primitive_boundary_workload": "compat/perf/x86_64_memory_observer_primitive.c",
}


class SmokeError(RuntimeError):
    """A memory artifact did not preserve its supplemental source contract."""


def load_fixture_helpers() -> object:
    """Reuse the frozen peer and hermetic resolver setup without copying it."""

    sys.dont_write_bytecode = True
    specification = importlib.util.spec_from_file_location(
        "crabc_supplemental_fixture_helpers", FIXTURE_HELPERS_PATH
    )
    if specification is None or specification.loader is None:
        raise SmokeError("could not load the supplemental fixture peer helpers")
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
    environment.pop(READY_ENV, None)
    environment.pop(CONTINUE_ENV, None)
    return environment


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


def build_artifacts(compiler: str, work: Path) -> dict[str, Path]:
    binaries = work / "binaries"
    if binaries.exists():
        shutil.rmtree(binaries)
    binaries.mkdir(parents=True)
    artifacts: dict[str, Path] = {}
    for binary, source in TIMED_SOURCES.items():
        output = binaries / f"timed-{binary}"
        compile_checked(
            compiler,
            source,
            output,
            pthread=binary == "x86_64_clock_allocator_workload",
        )
        artifacts[f"timed:{binary}"] = output
    for binary, source in OBSERVER_SOURCES.items():
        output = binaries / f"memory-{binary}"
        compile_checked(
            compiler,
            source,
            output,
            pthread=binary == "x86_64_clock_allocator_workload",
        )
        artifacts[f"memory:{binary}"] = output
    return artifacts


def assert_separate_artifacts(timed: Path, memory: Path) -> None:
    if timed.samefile(memory):
        raise SmokeError(f"memory observer reused its timed artifact: {memory}")
    if hashlib.sha256(timed.read_bytes()).digest() == hashlib.sha256(memory.read_bytes()).digest():
        raise SmokeError(f"memory observer lacks a distinct ELF identity: {memory}")


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


def close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def observer_descriptor(descriptor: int, target: int) -> int:
    """Move the inherited child endpoint to the fixed adapter descriptor."""

    if descriptor == target:
        return descriptor
    temporary = fcntl.fcntl(descriptor, fcntl.F_DUPFD, 100)
    try:
        os.dup2(temporary, target)
    finally:
        close_descriptor(temporary)
    close_descriptor(descriptor)
    return target


def terminate_and_reap(process: subprocess.Popen[bytes] | None) -> str | None:
    """Reap only this smoke's child, retaining the primary failure if any."""

    if process is None or process.poll() is not None:
        return None
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    except OSError as error:
        return f"could not terminate observer child: {error}"
    try:
        process.communicate(timeout=2)
        return None
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            return f"observer child could not be killed: {error}"
        try:
            process.communicate(timeout=2)
            return None
        except subprocess.TimeoutExpired:
            return "observer child could not be reaped after terminate/kill deadlines"
        except OSError as error:
            return f"observer child could not be reaped after kill: {error}"
    except OSError as error:
        return f"observer child could not be reaped: {error}"


def wait_for_ready(descriptor: int, context: str) -> None:
    readable, _, _ = select.select([descriptor], [], [], 5)
    if not readable:
        raise SmokeError(f"observer did not reach checkpoint deadline: {context}")
    if os.read(descriptor, 1) != b"R":
        raise SmokeError(f"observer checkpoint did not emit R: {context}")


def read_pty_stdout(descriptor: int) -> None:
    readable, _, _ = select.select([descriptor], [], [], 5)
    if not readable:
        raise SmokeError("source stdout was not present before main-final acknowledgement")
    received = os.read(descriptor, len(EXPECTED_STDOUT))
    if received != EXPECTED_STDOUT:
        raise SmokeError(f"source stdout changed before main-final: {received!r}")


Checkpoint = Callable[[str, subprocess.Popen[bytes]], None]


def run_observed(binary: Path, arguments: Sequence[str], plateau: str,
                 checkpoint: Checkpoint | None = None,
                 require_stdout_before_final: bool = False) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    output_master: int | None = None
    output_slave: int | None = None
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, READY_FD)
        continue_read = observer_descriptor(continue_read, CONTINUE_FD)
        if require_stdout_before_final:
            output_master, output_slave = pty.openpty()
            tty.setraw(output_slave, when=termios.TCSANOW)
        environment = clean_environment()
        environment[READY_ENV] = str(ready_write)
        environment[CONTINUE_ENV] = str(continue_read)
        process = subprocess.Popen(
            [str(binary), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=output_slave if output_slave is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(ready_write, continue_read),
        )
        close_descriptor(ready_write)
        ready_write = None
        close_descriptor(continue_read)
        continue_read = None
        if output_slave is not None:
            close_descriptor(output_slave)
            output_slave = None
        for phase in ("main-initial", plateau, "main-final"):
            wait_for_ready(ready_read, f"{binary.name} {arguments!r} phase={phase}")
            if checkpoint is not None:
                checkpoint(phase, process)
            if phase == "main-final" and require_stdout_before_final:
                assert output_master is not None
                read_pty_stdout(output_master)
            if os.write(continue_write, b"C") != 1:
                raise SmokeError("observer continue descriptor did not accept C")
        stdout, stderr = process.communicate(timeout=20)
        if process.returncode != 0 or stderr:
            raise SmokeError(
                f"observer failed: argv={[str(binary), *arguments]!r} status={process.returncode} "
                f"stderr={stderr!r}"
            )
        if not require_stdout_before_final and stdout != EXPECTED_STDOUT:
            raise SmokeError(f"observer changed source stdout: {stdout!r}")
        readable, _, _ = select.select([ready_read], [], [], 0)
        if readable and os.read(ready_read, 1):
            raise SmokeError("observer emitted an undeclared extra checkpoint")
    except BaseException:
        failed = True
        raise
    finally:
        close_descriptor(ready_read)
        close_descriptor(ready_write)
        close_descriptor(continue_read)
        close_descriptor(continue_write)
        close_descriptor(output_master)
        close_descriptor(output_slave)
        cleanup_error = terminate_and_reap(process)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def run_failure(binary: Path, arguments: Sequence[str], acknowledgements: Sequence[bytes | None],
                expected_stdout: bytes) -> None:
    """Drive a failed R/C sequence while requiring normal source cleanup."""

    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, READY_FD)
        continue_read = observer_descriptor(continue_read, CONTINUE_FD)
        environment = clean_environment()
        environment[READY_ENV] = str(ready_write)
        environment[CONTINUE_ENV] = str(continue_read)
        process = subprocess.Popen(
            [str(binary), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(ready_write, continue_read),
        )
        close_descriptor(ready_write)
        ready_write = None
        close_descriptor(continue_read)
        continue_read = None
        for index, acknowledgement in enumerate(acknowledgements):
            wait_for_ready(ready_read, f"{binary.name} {arguments!r} failure index={index}")
            if acknowledgement is None:
                close_descriptor(continue_write)
                continue_write = None
                break
            if os.write(continue_write, acknowledgement) != 1:
                raise SmokeError("observer continue descriptor did not accept failure acknowledgement")
        stdout, stderr = process.communicate(timeout=15)
        if process.returncode != 1 or stdout != expected_stdout or stderr:
            raise SmokeError(
                f"failed observer did not preserve source status/cleanup: status={process.returncode} "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        readable, _, _ = select.select([ready_read], [], [], 0)
        if readable and os.read(ready_read, 1):
            raise SmokeError("failed observer emitted an undeclared extra checkpoint")
    except BaseException:
        failed = True
        raise
    finally:
        close_descriptor(ready_read)
        close_descriptor(ready_write)
        close_descriptor(continue_read)
        close_descriptor(continue_write)
        cleanup_error = terminate_and_reap(process)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def run_bad_environment(binary: Path, arguments: Sequence[str]) -> None:
    for ready, continued in (("02", "98"), ("3", "4"), ("97", None)):
        environment = clean_environment()
        environment[READY_ENV] = ready
        if continued is not None:
            environment[CONTINUE_ENV] = continued
        result = subprocess.run(
            [str(binary), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        if result.returncode != 2 or result.stdout or result.stderr:
            raise SmokeError(
                f"invalid observer environment entered source work: ready={ready!r} "
                f"continue={continued!r} status={result.returncode}"
            )


def process_socket_targets(process: subprocess.Popen[bytes]) -> set[str]:
    descriptors = Path(f"/proc/{process.pid}/fd")
    return {
        os.readlink(descriptor)
        for descriptor in descriptors.iterdir()
        if os.readlink(descriptor).startswith("socket:[")
    }


def none_mapping_count(process: subprocess.Popen[bytes]) -> int:
    return sum(
        1
        for line in Path(f"/proc/{process.pid}/maps").read_text(encoding="utf-8").splitlines()
        if len(line.split()) >= 2 and line.split()[1] == "---p"
    )


def resident_kib(process: subprocess.Popen[bytes]) -> int:
    for line in Path(f"/proc/{process.pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            fields = line.split()
            return int(fields[1])
    raise SmokeError("observer process did not report VmRSS")


def reduced_arguments(row: dict[str, object]) -> tuple[str, ...]:
    iterations = min(2, int(row["iterations"]))
    return (str(row["mode"]), str(iterations), *(str(item) for item in row["argv"]))


def run_loopback_row(helpers: object, binary: Path, row: dict[str, object],
                     checkpoint: Checkpoint | None = None) -> None:
    mode = str(row["mode"])
    address, raw_port = (str(item) for item in row["argv"])
    family, socket_type = {
        "loopback_tcp_ipv4": (socket.AF_INET, socket.SOCK_STREAM),
        "loopback_tcp_ipv6": (socket.AF_INET6, socket.SOCK_STREAM),
        "loopback_udp_ipv4": (socket.AF_INET, socket.SOCK_DGRAM),
        "loopback_udp_ipv6": (socket.AF_INET6, socket.SOCK_DGRAM),
    }[mode]
    arguments = reduced_arguments(row)
    peer = helpers.EchoPeer(family, socket_type, address, int(raw_port), int(arguments[1]))
    peer.start()
    try:
        run_observed(binary, arguments, str(row["observer_phase"]), checkpoint)
    finally:
        peer.close()


def run_resolver_rows(helpers: object, binary: Path, rows: dict[str, dict[str, object]],
                      work: Path, profile: dict[str, object]) -> None:
    setup = profile["resolver_setup"]
    hosts_events = work / "resolver-observer-hosts-events.json"
    dns_events = work / "resolver-observer-dns-events.json"
    for path in (hosts_events, dns_events):
        if path.exists():
            path.unlink()
    with helpers.HermeticResolverFiles(setup["hosts_conf"], setup["resolv_conf"]):
        helpers.run_with_dns_server(
            hosts_events,
            lambda: run_observed(
                binary,
                reduced_arguments(rows["resolver_hosts"]),
                str(rows["resolver_hosts"]["observer_phase"]),
            ),
        )
        if helpers.read_dns_events(hosts_events):
            raise SmokeError("observed hosts-only lookup reached the DNS peer")

        def run_dns() -> None:
            for row_id in ("resolver_dns_dual", "resolver_dns_tcp"):
                row = rows[row_id]
                run_observed(binary, reduced_arguments(row), str(row["observer_phase"]))

        helpers.run_with_dns_server(dns_events, run_dns)
    events = helpers.read_dns_events(dns_events)
    if not any(
        event.get("name") == "batch.example.test." and event.get("qtype") == 1 and
        event.get("transport") == "udp" and event.get("action") == "batch-held-a"
        for event in events
    ) or not any(
        event.get("name") == "batch.example.test." and event.get("qtype") == 28 and
        event.get("transport") == "udp" and event.get("action") == "batch-release"
        for event in events
    ):
        raise SmokeError("observed AF_UNSPEC batch lookup lost the staged paired UDP contract")
    if not any(
        event.get("name") == "tc.example.test." and event.get("qtype") == 1 and
        event.get("transport") == "udp" and event.get("action") == "tc-sequence"
        for event in events
    ) or not any(
        event.get("name") == "tc.example.test." and event.get("qtype") == 1 and
        event.get("transport") == "tcp" and event.get("action") == "answer"
        for event in events
    ):
        raise SmokeError("observed truncated lookup lost the staged UDP-to-TCP contract")


def run_network_plain(helpers: object, binary: Path, port: int) -> None:
    peer = helpers.EchoPeer(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", port, 1)
    peer.start()
    try:
        run_plain(binary, ("loopback_tcp_ipv4", "1", "127.0.0.1", str(port)))
    finally:
        peer.close()


def run_smoke(compiler: str, work: Path) -> None:
    helpers = load_fixture_helpers()
    artifacts = build_artifacts(compiler, work)
    with PROFILE_PATH.open("rb") as stream:
        profile = tomllib.load(stream)
    rows = {str(row["id"]): row for row in profile["supplemental_row"]}

    if len(rows) != 40:
        raise SmokeError("supplemental observer smoke requires the closed 40-row profile")
    for binary in TIMED_SOURCES:
        assert_separate_artifacts(artifacts[f"timed:{binary}"], artifacts[f"memory:{binary}"])

    run_plain(artifacts["timed:x86_64_clock_allocator_workload"], ("clock_gettime", "1", "0"))
    run_plain(artifacts["memory:x86_64_clock_allocator_workload"], ("clock_gettime", "1", "0"))
    run_network_plain(helpers, artifacts["timed:x86_64_network_workload"], 39141)
    run_network_plain(helpers, artifacts["memory:x86_64_network_workload"], 39142)
    run_plain(
        artifacts["timed:x86_64_primitive_boundary_workload"],
        ("primitive", "1", "memcpy", "guard63"),
    )
    run_plain(
        artifacts["memory:x86_64_primitive_boundary_workload"],
        ("primitive", "1", "memcpy", "guard63"),
    )

    clock = artifacts["memory:x86_64_clock_allocator_workload"]
    network = artifacts["memory:x86_64_network_workload"]
    primitive = artifacts["memory:x86_64_primitive_boundary_workload"]

    for row_id, row in rows.items():
        if row["binary"] != "x86_64_clock_allocator_workload" or row_id == "allocator_live_32m":
            continue
        run_observed(clock, reduced_arguments(row), str(row["observer_phase"]))

    allocator_rss: dict[str, int] = {}

    def allocator_checkpoint(phase: str, process: subprocess.Popen[bytes]) -> None:
        if phase == "main-initial":
            allocator_rss[phase] = resident_kib(process)
        elif phase == "allocator-live":
            allocator_rss[phase] = resident_kib(process)
            if allocator_rss[phase] <= allocator_rss["main-initial"]:
                raise SmokeError("touched 32 MiB live allocation was absent at its source plateau")

    live_32m = rows["allocator_live_32m"]
    run_observed(
        clock,
        reduced_arguments(live_32m),
        str(live_32m["observer_phase"]),
        allocator_checkpoint,
    )

    socket_states: dict[str, set[str]] = {}

    def socket_checkpoint(phase: str, process: subprocess.Popen[bytes]) -> None:
        socket_states[phase] = process_socket_targets(process)
        if phase == "network-final-echo-open" and not socket_states[phase]:
            raise SmokeError("loopback client socket was absent at its source-owned plateau")
        if phase == "main-final" and socket_states[phase]:
            raise SmokeError("loopback client socket remained live after source cleanup")

    for row_id in (
        "loopback_tcp_ipv4_4k",
        "loopback_tcp_ipv6_4k",
        "loopback_udp_ipv4_4k",
        "loopback_udp_ipv6_4k",
    ):
        run_loopback_row(
            helpers,
            network,
            rows[row_id],
            socket_checkpoint if row_id == "loopback_tcp_ipv4_4k" else None,
        )
    run_resolver_rows(helpers, network, rows, work, profile)

    guard_maps: dict[str, int] = {}

    def guard_checkpoint(phase: str, process: subprocess.Popen[bytes]) -> None:
        guard_maps[phase] = none_mapping_count(process)
        if phase == "primitive-guard-window-live" and guard_maps[phase] <= guard_maps["main-initial"]:
            raise SmokeError("guard-adjacent primitive window was absent at its source plateau")
        if phase == "main-final" and guard_maps[phase] != guard_maps["main-initial"]:
            raise SmokeError("guard-adjacent primitive mapping survived source cleanup")

    for row_id, row in rows.items():
        if row["binary"] != "x86_64_primitive_boundary_workload" or row_id == "memcpy_guard63":
            continue
        run_observed(primitive, reduced_arguments(row), str(row["observer_phase"]))
    guard_row = rows["memcpy_guard63"]
    run_observed(
        primitive,
        reduced_arguments(guard_row),
        str(guard_row["observer_phase"]),
        guard_checkpoint,
        require_stdout_before_final=True,
    )

    run_bad_environment(clock, ("clock_gettime", "1", "0"))
    run_failure(clock, ("clock_gettime", "1", "0"), (None,), b"")

    peer = helpers.EchoPeer(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 39143, 1)
    peer.start()
    try:
        run_failure(
            network,
            ("loopback_tcp_ipv4", "1", "127.0.0.1", "39143"),
            (b"C", b"X"),
            b"",
        )
    finally:
        peer.close()
    run_failure(
        primitive,
        ("primitive", "1", "memcpy", "guard63"),
        (b"C", b"C", b"X"),
        EXPECTED_STDOUT,
    )


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
        run_smoke(arguments.compiler, work_directory(arguments.work))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"x86_64 supplemental memory observer smoke: {error}", file=sys.stderr)
        return 1
    print("x86_64 supplemental memory observer smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
