#!/usr/bin/env python3
"""Pinned-native implementation smoke for x86 supplemental C fixtures.

This is deliberately a reduced-run correctness check, not a benchmark and not
release evidence. It compiles the three new fixtures with the pinned musl
oracle compiler, checks observable results and the opt-in observer handshake,
and supplies loopback echo peers outside each client process.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import tomllib
from pathlib import Path
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORK = ROOT / ".work/x86_64/native-performance-workloads-smoke"
EXPECTED_STDOUT = b"ok\n"
PAYLOAD_BYTES = 4096
DNS_SERVER = ROOT / "compat/resolver-network/dns_server.py"
PROFILE_PATH = ROOT / "compat/perf/x86_64-profile.toml"


class SmokeError(RuntimeError):
    """A fixture did not provide its declared observable result."""


def work_directory(path: Path) -> Path:
    boundary = (ROOT / ".work/x86_64").resolve()
    candidate = path.resolve()
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise SmokeError(f"work directory must remain below {boundary}: {candidate}") from error
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def run_checked(arguments: Sequence[str], *, environment: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        list(arguments),
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if result.returncode != 0 or result.stdout != EXPECTED_STDOUT or result.stderr:
        raise SmokeError(
            f"fixture failed: argv={list(arguments)!r} status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def compile_fixture(compiler: str, source: Path, output: Path, *, pthread: bool = False) -> None:
    arguments = [
        compiler,
        "-std=c11",
        "-D_GNU_SOURCE",
        "-O2",
        "-fno-builtin",
        "-fno-stack-protector",
        str(source),
        "-o",
        str(output),
    ]
    if pthread:
        arguments.insert(-2, "-pthread")
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise SmokeError(
            f"compile failed: argv={arguments!r} stdout={result.stdout!r} stderr={result.stderr!r}"
        )


class EchoPeer:
    """One fixed loopback server that does not enter client measurements."""

    def __init__(self, family: int, socket_type: int, address: str, port: int,
                 expected_messages: int) -> None:
        self.family = family
        self.socket_type = socket_type
        self.address = address
        self.port = port
        self.expected_messages = expected_messages
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.failure: BaseException | None = None
        self.stop_requested = threading.Event()
        self.socket = socket.socket(family, socket_type)
        self.socket.settimeout(0.2)
        if family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.socket.bind((address, port))
        if socket_type == socket.SOCK_STREAM:
            self.socket.listen(1)
        self.thread = threading.Thread(target=self.run, daemon=True)

    @staticmethod
    def receive_exact(connection: socket.socket, length: int) -> bytes:
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = connection.recv(remaining)
            if not chunk:
                raise SmokeError("echo peer received an unexpected EOF")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=2):
            raise SmokeError("echo peer did not become ready")

    def run(self) -> None:
        self.ready.set()
        try:
            if self.socket_type == socket.SOCK_STREAM:
                connection: socket.socket | None = None
                while connection is None and not self.stop_requested.is_set():
                    try:
                        connection, _ = self.socket.accept()
                    except TimeoutError:
                        continue
                if connection is None:
                    return
                with connection:
                    connection.settimeout(5)
                    for _ in range(self.expected_messages):
                        connection.sendall(self.receive_exact(connection, PAYLOAD_BYTES))
            else:
                for _ in range(self.expected_messages):
                    while True:
                        try:
                            payload, peer = self.socket.recvfrom(PAYLOAD_BYTES)
                            break
                        except TimeoutError:
                            if self.stop_requested.is_set():
                                return
                    if len(payload) != PAYLOAD_BYTES:
                        raise SmokeError("echo peer received the wrong datagram length")
                    self.socket.sendto(payload, peer)
        except BaseException as error:
            self.failure = error
        finally:
            self.finished.set()

    def close(self) -> None:
        self.stop_requested.set()
        try:
            self.socket.close()
        except OSError:
            pass
        self.thread.join(timeout=2)
        if self.failure:
            raise SmokeError(f"echo peer failed: {self.failure}") from self.failure
        if not self.finished.is_set():
            raise SmokeError("echo peer did not finish")


def close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def observer_descriptor(descriptor: int, target: int) -> int:
    """Move one inherited endpoint to the adapter's fixed descriptor number."""

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
    """Finish only a child this smoke runner started, within finite deadlines."""

    if process is None or process.poll() is not None:
        return None
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    except OSError as error:
        return f"could not terminate owned child: {error}"
    try:
        process.communicate(timeout=2)
        return None
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            return f"owned child ignored termination and could not be killed: {error}"
        try:
            process.communicate(timeout=2)
            return None
        except subprocess.TimeoutExpired:
            return "owned child could not be reaped after termination and kill deadlines"
        except OSError as error:
            return f"owned child could not be reaped after kill: {error}"
    except OSError as error:
        return f"owned child could not be reaped after termination: {error}"


def run_barrier(binary: Path, arguments: Sequence[str]) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, 97)
        continue_read = observer_descriptor(continue_read, 98)
        environment = dict(os.environ)
        environment["CRABC_PERF_OBSERVER_READY_FD"] = str(ready_write)
        environment["CRABC_PERF_OBSERVER_CONTINUE_FD"] = str(continue_read)
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
        readable, _, _ = select.select([ready_read], [], [], 5)
        if not readable:
            raise SmokeError("observer-ready descriptor did not become readable")
        if os.read(ready_read, 1) != b"R":
            raise SmokeError("observer-ready descriptor did not receive R")
        if os.write(continue_write, b"C") != 1:
            raise SmokeError("observer-continue descriptor did not accept C")
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode != 0 or stdout != EXPECTED_STDOUT or stderr:
            raise SmokeError(
                f"observer barrier failed: status={process.returncode} stdout={stdout!r} stderr={stderr!r}"
            )
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

    malformed = dict(os.environ)
    malformed["CRABC_PERF_OBSERVER_READY_FD"] = "02"
    malformed["CRABC_PERF_OBSERVER_CONTINUE_FD"] = "98"
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        env=malformed,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if result.returncode != 2 or result.stdout or result.stderr:
        raise SmokeError("malformed observer descriptors did not fail before fixture work")

    partial = dict(os.environ)
    partial["CRABC_PERF_OBSERVER_READY_FD"] = "97"
    partial.pop("CRABC_PERF_OBSERVER_CONTINUE_FD", None)
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        env=partial,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if result.returncode != 2 or result.stdout or result.stderr:
        raise SmokeError("partial observer descriptor environment did not fail before fixture work")


def run_bad_acknowledgement(binary: Path, arguments: Sequence[str]) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, 97)
        continue_read = observer_descriptor(continue_read, 98)
        environment = dict(os.environ)
        environment["CRABC_PERF_OBSERVER_READY_FD"] = str(ready_write)
        environment["CRABC_PERF_OBSERVER_CONTINUE_FD"] = str(continue_read)
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
        readable, _, _ = select.select([ready_read], [], [], 5)
        if not readable or os.read(ready_read, 1) != b"R":
            raise SmokeError("observer-ready descriptor did not receive R before bad acknowledgement")
        if os.write(continue_write, b"X") != 1:
            raise SmokeError("observer-continue descriptor did not accept bad acknowledgement")
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode != 1 or stdout or stderr:
            raise SmokeError("non-C observer acknowledgement did not fail the completed fixture")
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


def run_echo_fixture(binary: Path) -> None:
    cases = (
        ("loopback_tcp_ipv4", socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 39041),
        ("loopback_tcp_ipv6", socket.AF_INET6, socket.SOCK_STREAM, "::1", 39042),
        ("loopback_udp_ipv4", socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1", 39043),
        ("loopback_udp_ipv6", socket.AF_INET6, socket.SOCK_DGRAM, "::1", 39044),
    )
    for mode, family, socket_type, address, port in cases:
        peer = EchoPeer(family, socket_type, address, port, expected_messages=2)
        peer.start()
        try:
            run_checked([str(binary), mode, "2", address, str(port)])
        finally:
            peer.close()


class HermeticResolverFiles:
    """Temporarily install profile-owned conventional resolver inputs."""

    def __init__(self, hosts: str, resolv_conf: str) -> None:
        self.contents = {
            Path("/etc/hosts"): hosts.encode("ascii"),
            Path("/etc/resolv.conf"): resolv_conf.encode("ascii"),
        }
        self.original: dict[Path, bytes] = {}

    def __enter__(self) -> "HermeticResolverFiles":
        if not Path("/.dockerenv").is_file() or os.geteuid() != 0:
            raise SmokeError("resolver smoke requires the disposable root-owned Docker container")
        try:
            for path, contents in self.contents.items():
                if path.is_symlink() or not path.is_file():
                    raise SmokeError(f"resolver conventional file is unsafe: {path}")
                self.original[path] = path.read_bytes()
                path.write_bytes(contents)
        except BaseException:
            self.restore()
            raise
        return self

    def restore(self) -> None:
        for path, contents in self.original.items():
            path.write_bytes(contents)

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.restore()


def start_dns_server(events_path: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [sys.executable, "-B", str(DNS_SERVER), "--events", str(events_path)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    readable, _, _ = select.select([process.stdout], [], [], 5)
    if not readable:
        cleanup_error = terminate_and_reap(process)
        suffix = f"; {cleanup_error}" if cleanup_error else ""
        raise SmokeError(f"resolver DNS server did not publish readiness{suffix}")
    try:
        ready = json.loads(process.stdout.readline().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        cleanup_error = terminate_and_reap(process)
        suffix = f"; {cleanup_error}" if cleanup_error else ""
        raise SmokeError(f"resolver DNS server readiness was malformed{suffix}") from error
    if ready.get("protocol") != "resolver-network-dns-v1":
        cleanup_error = terminate_and_reap(process)
        suffix = f"; {cleanup_error}" if cleanup_error else ""
        raise SmokeError(f"resolver DNS server protocol drifted{suffix}")
    return process


def stop_dns_server(process: subprocess.Popen[bytes]) -> str | None:
    if process.poll() is None:
        try:
            process.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_error = terminate_and_reap(process)
            suffix = f"; {cleanup_error}" if cleanup_error else ""
            return f"resolver DNS server could not receive SIGTERM: {error}{suffix}"
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        cleanup_error = terminate_and_reap(process)
        suffix = f"; {cleanup_error}" if cleanup_error else ""
        return f"resolver DNS server did not stop before its deadline{suffix}"
    except OSError as error:
        cleanup_error = terminate_and_reap(process)
        suffix = f"; {cleanup_error}" if cleanup_error else ""
        return f"resolver DNS server could not be reaped: {error}{suffix}"
    if process.returncode != 0 or stdout or stderr:
        return (
            f"resolver DNS server failed: status={process.returncode} "
            f"stdout={stdout!r} stderr={stderr!r}"
        )
    return None


def run_with_dns_server(events_path: Path, operation: Callable[[], None]) -> None:
    server = start_dns_server(events_path)
    failed = False
    try:
        operation()
    except BaseException:
        failed = True
        raise
    finally:
        cleanup_error = stop_dns_server(server)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def read_dns_events(events_path: Path) -> list[dict[str, object]]:
    try:
        # The pinned container creates this record as root.  Keep the evidence
        # inspectable from the checkout after the container exits.
        events_path.chmod(0o644)
        events = json.loads(events_path.read_text(encoding="utf-8"))["events"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise SmokeError("resolver DNS event record is unavailable") from error
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise SmokeError("resolver DNS event record has the wrong shape")
    return events


def run_resolver_fixture(binary: Path, work: Path) -> None:
    with PROFILE_PATH.open("rb") as stream:
        profile = tomllib.load(stream)
    setup = profile["resolver_setup"]
    rows = {row["id"]: row for row in profile["supplemental_row"]}
    hosts_events_path = work / "resolver-hosts-events.json"
    dns_events_path = work / "resolver-dns-events.json"
    for events_path in (hosts_events_path, dns_events_path):
        if events_path.exists():
            events_path.unlink()
    with HermeticResolverFiles(setup["hosts_conf"], setup["resolv_conf"]):
        host_row = rows["resolver_hosts"]
        run_with_dns_server(
            hosts_events_path,
            lambda: run_checked([str(binary), host_row["mode"], "2", *host_row["argv"]]),
        )
        if read_dns_events(hosts_events_path):
            raise SmokeError("hosts-only lookup reached the DNS peer")
        def run_dns_rows() -> None:
            for row_id in ("resolver_dns_dual", "resolver_dns_tcp"):
                row = rows[row_id]
                run_checked([str(binary), row["mode"], "2", *row["argv"]])
        run_with_dns_server(dns_events_path, run_dns_rows)
    events = read_dns_events(dns_events_path)
    if not any(
        event.get("name") == "batch.example.test." and event.get("qtype") == 1 and
        event.get("transport") == "udp" and event.get("action") == "batch-held-a"
        for event in events
    ) or not any(
        event.get("name") == "batch.example.test." and event.get("qtype") == 28 and
        event.get("transport") == "udp" and event.get("action") == "batch-release"
        for event in events
    ):
        raise SmokeError("AF_UNSPEC batch lookup did not retain the staged paired UDP contract")
    if not any(
        event.get("name") == "tc.example.test." and event.get("qtype") == 1 and
        event.get("transport") == "udp" and event.get("action") == "tc-sequence"
        for event in events
    ) or not any(
        event.get("name") == "tc.example.test." and event.get("qtype") == 1 and
        event.get("transport") == "tcp" and event.get("action") == "answer"
        for event in events
    ):
        raise SmokeError("truncated DNS lookup did not complete the staged UDP-to-TCP contract")


def run_fixture_smoke(compiler: str, work: Path) -> None:
    binaries = work / "binaries"
    if binaries.exists():
        shutil.rmtree(binaries)
    binaries.mkdir(parents=True)
    clock = binaries / "clock-allocator"
    network = binaries / "network"
    primitive = binaries / "primitive"

    compile_fixture(
        compiler,
        ROOT / "compat/perf/x86_64_clock_allocator_workload.c",
        clock,
        pthread=True,
    )
    compile_fixture(compiler, ROOT / "compat/perf/x86_64_network_workload.c", network)
    compile_fixture(
        compiler,
        ROOT / "compat/perf/x86_64_primitive_boundary_workload.c",
        primitive,
    )

    for clock_id in ("0", "2", "3", "4", "5", "6", "7", "8", "9", "11"):
        run_checked([str(clock), "clock_gettime", "2", clock_id])
    run_checked([str(clock), "live", "2", "4", "64"])
    run_checked([str(clock), "refill", "2", "8", "64", "4"])
    run_checked([str(clock), "worker", "2", "2", "4", "64"])
    run_barrier(clock, ("clock_gettime", "2", "0"))
    run_bad_acknowledgement(clock, ("clock_gettime", "2", "0"))
    run_echo_fixture(network)
    run_resolver_fixture(network, work)
    for primitive_name in ("memcpy", "memset", "strlen", "memchr", "strstr", "memmem"):
        for variant in ("empty", "short31_unaligned", "guard63"):
            run_checked([str(primitive), "primitive", "2", primitive_name, variant])
    run_barrier(primitive, ("primitive", "2", "memcpy", "guard63"))


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
        run_fixture_smoke(arguments.compiler, work_directory(arguments.work))
    except (OSError, SmokeError, subprocess.TimeoutExpired) as error:
        print(f"x86_64 supplemental workload implementation smoke: {error}", file=sys.stderr)
        return 1
    print("x86_64 supplemental workload implementation smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
