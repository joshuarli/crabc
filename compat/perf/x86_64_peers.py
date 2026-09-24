#!/usr/bin/env python3
"""Owned loopback/DNS peers for the native x86-64 performance clients.

The helper owns only test infrastructure.  A caller supplies one fresh
invocation directory, one private client root, and one peer CPU.  It starts an
external loopback echo child or the existing resolver-network DNS child,
returns the fixed profile argv and private resolver-file bytes, then retains
and replays peer evidence after the caller finishes its client.  It never
executes the client, creates a cgroup, changes the caller affinity, or writes
ambient ``/etc`` files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


PROFILE_RELATIVE = Path("compat/perf/x86_64-profile.toml")
DNS_SERVER_RELATIVE = Path("compat/resolver-network/dns_server.py")
NETWORK_FIXTURE_RELATIVE = Path("compat/perf/x86_64_network_workload.c")
WORK_RELATIVE = Path(".work/x86_64")

SCHEMA = "crabc.perf.x86_64-peer-context/v1"
ECHO_PROTOCOL = "crabc.perf.x86_64-loopback-echo/v1"
DNS_PROTOCOL = "resolver-network-dns-v1"
PAYLOAD_BYTES = 4096
STOP_TIMEOUT_SECONDS = 5.0


class PeerError(RuntimeError):
    """A peer lifecycle or retained peer record violates the fixed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PeerError(message)


@dataclass(frozen=True)
class NetworkRow:
    """One exact supplemental network row, independent of the collector."""

    row_id: str
    mode: str
    argv: tuple[str, ...]
    full_iterations: int
    operations: int
    requires_loopback_peer: bool
    requires_resolver_files: bool
    geometry: Mapping[str, Any]
    peer_kind: str
    endpoint: Mapping[str, Any] | None


# Upper bound on waiting for a finished echo peer to exit by itself.
ECHO_EXIT_GRACE_SECONDS = 5.0


@dataclass
class _LivePeer:
    root: Path
    kind: str
    process: subprocess.Popen[bytes]
    source: dict[str, Any]
    protocol: str
    endpoint: dict[str, Any]
    ready: dict[str, Any]
    affinity: dict[str, Any]
    events_path: Path
    stdout_path: Path
    stderr_path: Path


# Keep this finite map beside the lifecycle code.  Parsing the profile binds
# the inputs used by the fixture; this map prevents an unrelated supplemental
# row from silently acquiring peer authority.
_ROW_CONTRACTS: dict[str, dict[str, Any]] = {
    "loopback_tcp_ipv4_4k": {
        "mode": "loopback_tcp_ipv4",
        "argv": ("127.0.0.1", "39041"),
        "iterations": 10_000,
        "operations": 10_000,
        "loopback": True,
        "resolver": False,
        "geometry": {"request_echo_pairs": 10_000, "payload_bytes": 4096, "client_sockets": 1, "client_connections": 1},
        "peer_kind": "echo",
        "endpoint": {"family": "ipv4", "transport": "tcp", "address": "127.0.0.1", "port": 39041},
    },
    "loopback_tcp_ipv6_4k": {
        "mode": "loopback_tcp_ipv6",
        "argv": ("::1", "39042"),
        "iterations": 10_000,
        "operations": 10_000,
        "loopback": True,
        "resolver": False,
        "geometry": {"request_echo_pairs": 10_000, "payload_bytes": 4096, "client_sockets": 1, "client_connections": 1},
        "peer_kind": "echo",
        "endpoint": {"family": "ipv6", "transport": "tcp", "address": "::1", "port": 39042},
    },
    "loopback_udp_ipv4_4k": {
        "mode": "loopback_udp_ipv4",
        "argv": ("127.0.0.1", "39043"),
        "iterations": 10_000,
        "operations": 10_000,
        "loopback": True,
        "resolver": False,
        "geometry": {"request_echo_pairs": 10_000, "payload_bytes": 4096, "client_sockets": 1, "client_connections": 1},
        "peer_kind": "echo",
        "endpoint": {"family": "ipv4", "transport": "udp", "address": "127.0.0.1", "port": 39043},
    },
    "loopback_udp_ipv6_4k": {
        "mode": "loopback_udp_ipv6",
        "argv": ("::1", "39044"),
        "iterations": 10_000,
        "operations": 10_000,
        "loopback": True,
        "resolver": False,
        "geometry": {"request_echo_pairs": 10_000, "payload_bytes": 4096, "client_sockets": 1, "client_connections": 1},
        "peer_kind": "echo",
        "endpoint": {"family": "ipv6", "transport": "udp", "address": "::1", "port": 39044},
    },
    "resolver_hosts": {
        "mode": "resolver_hosts",
        "argv": ("perf-host.example.test", "80", "127.0.0.77", "2001:db8::77"),
        "iterations": 20_000,
        "operations": 20_000,
        "loopback": False,
        "resolver": True,
        "geometry": {"lookup_free_pairs": 20_000, "address_families": ["AF_INET", "AF_INET6"], "numeric_service": 80, "dns_queries": 0},
        # The profile deliberately says false because no DNS query is
        # required.  We still start the fixed observer to prove it stays zero.
        "peer_kind": "dns",
        "endpoint": None,
    },
    "resolver_dns_dual": {
        "mode": "resolver_dns_dual",
        "argv": ("batch.example.test.", "80", "198.51.100.48", "2001:db8::48"),
        "iterations": 1_000,
        "operations": 1_000,
        "loopback": True,
        "resolver": True,
        "geometry": {"lookup_free_pairs": 1_000, "address_families": ["AF_INET", "AF_INET6"], "numeric_service": 80, "dns_server_protocol": DNS_PROTOCOL},
        "peer_kind": "dns",
        "endpoint": None,
    },
    "resolver_dns_tcp": {
        "mode": "resolver_dns_tcp",
        "argv": ("tc.example.test.", "80", "198.51.100.45"),
        "iterations": 1_000,
        "operations": 1_000,
        "loopback": True,
        "resolver": True,
        "geometry": {"lookup_free_pairs": 1_000, "address_families": ["AF_INET"], "numeric_service": 80, "dns_server_protocol": DNS_PROTOCOL, "required_transports": ["udp-truncated", "tcp-answer"]},
        "peer_kind": "dns",
        "endpoint": None,
    },
}


def _root(root: Path) -> Path:
    candidate = Path(root).resolve(strict=True)
    require(candidate.is_dir() and not candidate.is_symlink(), f"repository root is not physical: {root}")
    return candidate


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _relative(root: Path, path: Path) -> str:
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError as error:
        raise PeerError(f"retained path escapes checkout: {resolved}") from error


def _work_root(root: Path) -> Path:
    boundary = root / WORK_RELATIVE
    boundary.mkdir(parents=True, exist_ok=True)
    resolved = boundary.resolve(strict=True)
    require(resolved == boundary and resolved.is_dir() and not resolved.is_symlink(),
            f"native peer work boundary is not physical: {boundary}")
    return resolved


def _physical_work_directory(root: Path, value: Path, label: str) -> Path:
    boundary = _work_root(root)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    require(".." not in candidate.parts, f"{label} has parent traversal")
    absolute = Path(os.path.abspath(candidate))
    try:
        relative = absolute.relative_to(boundary)
    except ValueError as error:
        raise PeerError(f"{label} escapes native peer work boundary: {absolute}") from error
    require(relative.parts, f"{label} cannot be the work boundary")
    require(absolute.exists() and not absolute.is_symlink(), f"{label} is absent or symlinked: {absolute}")
    resolved = absolute.resolve(strict=True)
    require(resolved == absolute and resolved.is_dir(), f"{label} is not a physical directory: {absolute}")
    return resolved


def _fresh_work_directory(root: Path, value: Path) -> Path:
    boundary = _work_root(root)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    require(".." not in candidate.parts, "peer invocation work directory has parent traversal")
    absolute = Path(os.path.abspath(candidate))
    try:
        relative = absolute.relative_to(boundary)
    except ValueError as error:
        raise PeerError(f"peer invocation work directory escapes {boundary}: {absolute}") from error
    require(relative.parts and not absolute.exists() and not absolute.is_symlink(),
            f"peer invocation work directory must be fresh: {absolute}")
    current = boundary
    for component in relative.parts[:-1]:
        current = current / component
        if current.exists() or current.is_symlink():
            require(current.is_dir() and not current.is_symlink() and current.resolve(strict=True) == current,
                    f"peer invocation parent is not physical: {current}")
        else:
            current.mkdir(mode=0o700)
    absolute.mkdir(mode=0o700)
    resolved = absolute.resolve(strict=True)
    require(resolved == absolute, f"peer invocation work directory traverses a symlink: {absolute}")
    return resolved


def _sha256(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"retained artifact is not a physical file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_identity(root: Path, path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"retained artifact is not a physical file: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    return {"path": _relative(root, path), "sha256": _sha256(path), "mode": mode, "bytes": path.stat().st_size}


def _validate_identity(root: Path, record: object, label: str) -> Path:
    expected = {"path", "sha256", "mode", "bytes"}
    require(isinstance(record, dict) and set(record) == expected, f"{label} identity fields differ")
    path_text = record.get("path")
    require(isinstance(path_text, str) and path_text and not path_text.startswith("/"), f"{label} identity path differs")
    relative = Path(path_text)
    require(".." not in relative.parts, f"{label} identity has parent traversal")
    candidate = root / relative
    require(candidate.exists() and not candidate.is_symlink(), f"{label} identity path is absent or symlinked")
    require(file_identity(root, candidate) == record, f"{label} identity differs")
    return candidate.resolve(strict=True)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is absent or symlinked: {path}")
    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise PeerError(f"{label} is not valid JSON") from error
    require(isinstance(result, dict), f"{label} is not a JSON object")
    return result


def _write_bytes(path: Path, contents: bytes) -> None:
    require(path.parent.is_dir() and not path.parent.is_symlink(), f"retained output parent is unsafe: {path.parent}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_bytes(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def _load_profile(root: Path) -> tuple[dict[str, Any], Path]:
    path = root / PROFILE_RELATIVE
    require(path.is_file() and not path.is_symlink(), "native performance profile is absent")
    try:
        with path.open("rb") as stream:
            profile = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PeerError("native performance profile is invalid") from error
    require(isinstance(profile, dict) and profile.get("profile", {}).get("schema") == "crabc.perf.x86_64-profile/v1",
            "native performance profile schema differs")
    return profile, path


def _resolver_setup(profile: Mapping[str, Any]) -> dict[str, Any]:
    setup = profile.get("resolver_setup")
    expected = {"dns_server", "dns_protocol", "dns_port", "loopback_nameservers", "resolv_conf", "hosts_conf"}
    require(isinstance(setup, dict) and set(setup) == expected, "native resolver setup fields differ")
    require(setup["dns_server"] == DNS_SERVER_RELATIVE.as_posix()
            and setup["dns_protocol"] == DNS_PROTOCOL
            and setup["dns_port"] == 53
            and setup["loopback_nameservers"] == ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
            "native resolver endpoint contract differs")
    require(isinstance(setup["resolv_conf"], str) and isinstance(setup["hosts_conf"], str),
            "native resolver input bytes are absent")
    return dict(setup)


def load_network_row(root: Path, row_id: str, mode: str) -> NetworkRow:
    """Load exactly one of the seven profile-owned peer rows."""

    root = _root(root)
    contract = _ROW_CONTRACTS.get(row_id)
    require(contract is not None, f"unrecognized native peer row: {row_id}")
    profile, _profile_path = _load_profile(root)
    _resolver_setup(profile)
    rows = profile.get("supplemental_row")
    require(isinstance(rows, list), "native performance profile lacks supplemental rows")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == row_id]
    require(len(matches) == 1, f"native peer row is not unique: {row_id}")
    row = matches[0]
    expected_fields = {
        "id", "binary", "mode", "iterations", "argv", "observer_phase",
        "requires_loopback_peer", "requires_hermetic_resolver_files", "operations",
        "result_contract", "geometry",
    }
    require(set(row) == expected_fields and row["binary"] == "x86_64_network_workload",
            f"native peer row fields differ: {row_id}")
    require(row["mode"] == contract["mode"] == mode, f"native peer row mode differs: {row_id}")
    require(row["argv"] == list(contract["argv"]), f"native peer row argv differs: {row_id}")
    require(row["iterations"] == contract["iterations"] and row["operations"] == contract["operations"],
            f"native peer row operation geometry differs: {row_id}")
    require(row["requires_loopback_peer"] is contract["loopback"]
            and row["requires_hermetic_resolver_files"] is contract["resolver"],
            f"native peer row peer/resolver flags differ: {row_id}")
    require(row["geometry"] == contract["geometry"], f"native peer row geometry differs: {row_id}")
    return NetworkRow(
        row_id=row_id,
        mode=mode,
        argv=tuple(contract["argv"]),
        full_iterations=contract["iterations"],
        operations=contract["operations"],
        requires_loopback_peer=contract["loopback"],
        requires_resolver_files=contract["resolver"],
        geometry=dict(contract["geometry"]),
        peer_kind=contract["peer_kind"],
        endpoint=None if contract["endpoint"] is None else dict(contract["endpoint"]),
    )


def _expected_dns_endpoints() -> dict[str, dict[str, Any]]:
    return {
        "valid": {"port": 53, "ipv4": "127.0.0.1", "udp4_port": 53, "tcp4_port": 53},
        "drop": {"port": 53, "ipv4": "127.0.0.2", "udp4_port": 53, "tcp4_port": 53},
        "fallback": {"port": 53, "ipv4": "127.0.0.3", "udp4_port": 53, "tcp4_port": 53},
    }


def _source_identities(root: Path, *, dns: bool) -> dict[str, Any]:
    sources: dict[str, Any] = {
        "helper": file_identity(root, root / "compat/perf/x86_64_peers.py"),
        "network_fixture": file_identity(root, root / NETWORK_FIXTURE_RELATIVE),
        "profile": file_identity(root, root / PROFILE_RELATIVE),
    }
    if dns:
        sources["dns_server"] = file_identity(root, root / DNS_SERVER_RELATIVE)
    return sources


def _valid_affinity(cpu: int, allowed_affinity: Sequence[int]) -> tuple[int, ...]:
    require(type(cpu) is int and cpu >= 0, "peer CPU differs")
    allowed = tuple(allowed_affinity)
    require(bool(allowed) and all(type(value) is int and value >= 0 for value in allowed)
            and tuple(sorted(set(allowed))) == allowed and cpu in allowed,
            "peer allowed affinity differs")
    return allowed


def _child_affinity(cpu: int) -> None:
    os.sched_setaffinity(0, {cpu})


def _parse_cpu_list(value: str) -> set[int]:
    result: set[int] = set()
    for item in value.split(","):
        if not item:
            raise PeerError("peer affinity raw list is empty")
        first, separator, last = item.partition("-")
        require(first.isdecimal() and (not separator or last.isdecimal()), "peer affinity raw list is malformed")
        start = int(first)
        end = int(last) if separator else start
        require(start <= end, "peer affinity raw range is reversed")
        result.update(range(start, end + 1))
    return result


def _status_value(raw: bytes, field: str, label: str) -> str:
    prefix = f"{field}:"
    values = [line[len(prefix):].strip() for line in raw.decode("utf-8", errors="replace").splitlines()
              if line.startswith(prefix)]
    require(len(values) == 1 and values[0], f"{label} lacks {field}")
    return values[0]


def _status_pid(raw: bytes, label: str) -> int:
    value = _status_value(raw, "Pid", label)
    require(value.isdecimal() and int(value) > 0, f"{label} Pid differs")
    return int(value)


def _capture_affinity(root: Path, pid: int, destination: Path) -> dict[str, Any]:
    try:
        observed = sorted(os.sched_getaffinity(pid))
        raw = Path(f"/proc/{pid}/status").read_bytes()
    except OSError as error:
        raise PeerError(f"cannot retain peer affinity for pid {pid}: {error}") from error
    _write_bytes(destination, raw)
    require(_status_pid(raw, "peer proc status") == pid, "peer proc status Pid differs")
    value = _status_value(raw, "Cpus_allowed_list", "peer proc status")
    require(_parse_cpu_list(value) == set(observed), "peer affinity raw status differs")
    return {"observed": observed, "raw": file_identity(root, destination)}


def _wait_ready(process: subprocess.Popen[bytes], timeout: float, label: str) -> tuple[bytes, dict[str, Any]]:
    """Read one readiness line without letting a partial line defeat the deadline."""

    require(process.stdout is not None, f"{label} has no stdout pipe")
    require(type(timeout) in {int, float} and timeout > 0, f"{label} readiness deadline differs")
    descriptor = process.stdout.fileno()
    was_blocking = os.get_blocking(descriptor)
    received = bytearray()
    deadline = time.monotonic() + float(timeout)
    try:
        os.set_blocking(descriptor, False)
        while True:
            newline = received.find(b"\n")
            if newline >= 0:
                require(not received[newline + 1:], f"{label} readiness contains trailing output")
                raw = bytes(received[:newline + 1])
                try:
                    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_object)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
                    raise PeerError(f"{label} readiness is not valid JSON") from error
                require(isinstance(value, dict), f"{label} readiness is not an object")
                return raw, value
            require(len(received) <= 64 * 1024, f"{label} readiness exceeds its bounded line size")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerError(f"{label} did not publish readiness before its deadline")
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if not readable:
                raise PeerError(f"{label} did not publish readiness before its deadline")
            try:
                chunk = os.read(descriptor, 4096)
            except BlockingIOError:
                continue
            require(chunk, f"{label} closed stdout before readiness")
            received.extend(chunk)
    finally:
        os.set_blocking(descriptor, was_blocking)


def _status_record(returncode: int | None) -> dict[str, Any]:
    if returncode is None:
        return {"kind": "not-reaped"}
    if returncode >= 0:
        return {"kind": "exit", "code": returncode}
    return {"kind": "signal", "number": -returncode}


def _stop_process(peer: _LivePeer, timeout: float) -> tuple[dict[str, Any], list[str]]:
    """Terminate/reap exactly one owned process without hiding cleanup errors."""

    errors: list[str] = []
    sent_sigterm = False
    sent_sigkill = False
    process = peer.process
    # An echo peer exits after the final echo. Give that clean path a grace
    # period before converting a just-finished peer into a cancellation; on a
    # contended host its exit may take far longer than a scheduling quantum,
    # while only a peer whose client failed early waits out the whole grace.
    if process.poll() is None and peer.kind == "echo":
        try:
            process.wait(timeout=min(ECHO_EXIT_GRACE_SECONDS, timeout))
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        try:
            process.send_signal(signal.SIGTERM)
            sent_sigterm = True
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append(f"could not terminate {peer.kind} peer: {error}")
    stdout = b""
    stderr = b""
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            sent_sigkill = True
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append(f"could not kill {peer.kind} peer: {error}")
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            errors.append(f"{peer.kind} peer could not be reaped after kill deadline")
    except OSError as error:
        errors.append(f"could not reap {peer.kind} peer: {error}")
    _write_bytes(peer.stdout_path, stdout)
    _write_bytes(peer.stderr_path, stderr)
    record: dict[str, Any] = {
        "kind": peer.kind,
        "pid": peer.process.pid,
        "protocol": peer.protocol,
        "source": peer.source,
        "endpoint": peer.endpoint,
        "ready": peer.ready,
        "affinity": peer.affinity,
        "stdout": file_identity(peer.root, peer.stdout_path),
        "stderr": file_identity(peer.root, peer.stderr_path),
        "events": None,
        "termination": {
            "deadline_seconds": timeout,
            "sent_sigterm": sent_sigterm,
            "sent_sigkill": sent_sigkill,
            "reaped": process.poll() is not None,
            "exit_status": _status_record(process.returncode),
        },
    }
    return record, errors


def _launch_echo(
    root: Path,
    work: Path,
    endpoint: Mapping[str, Any],
    iterations: int,
    cpu: int,
    timeout: float,
) -> _LivePeer:
    events = work / "echo-events.json"
    ready_path = work / "echo-ready.json"
    stdout_path = work / "echo.stdout"
    stderr_path = work / "echo.stderr"
    command = [
        sys.executable, "-B", str(root / "compat/perf/x86_64_peers.py"), "--echo-child",
        "--family", str(endpoint["family"]), "--transport", str(endpoint["transport"]),
        "--address", str(endpoint["address"]), "--port", str(endpoint["port"]),
        "--expected-echoes", str(iterations), "--events", str(events),
    ]
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=lambda: _child_affinity(cpu),
        )
        ready_raw, ready = _wait_ready(process, timeout, "loopback echo peer")
        _write_bytes(ready_path, ready_raw)
        expected = {
            "schema": ECHO_PROTOCOL, "status": "ready", "pid": process.pid,
            "endpoint": dict(endpoint), "expected_echoes": iterations, "affinity": [cpu],
        }
        require(ready == expected, "loopback echo peer readiness differs")
        live = _LivePeer(
            root=root, kind="echo", process=process, source=file_identity(root, root / "compat/perf/x86_64_peers.py"),
            protocol=ECHO_PROTOCOL, endpoint=dict(endpoint), ready=file_identity(root, ready_path),
            affinity=_capture_affinity(root, process.pid, work / "echo-affinity.status"),
            events_path=events, stdout_path=stdout_path, stderr_path=stderr_path,
        )
        return live
    except BaseException:
        if process is not None:
            temporary = _LivePeer(
                root=root, kind="echo", process=process, source={}, protocol=ECHO_PROTOCOL, endpoint=dict(endpoint),
                ready={}, affinity={}, events_path=events, stdout_path=stdout_path, stderr_path=stderr_path,
            )
            _stop_process(temporary, timeout)
        raise


def _launch_dns(root: Path, work: Path, cpu: int, timeout: float) -> _LivePeer:
    events = work / "dns-events.json"
    ready_path = work / "dns-ready.json"
    stdout_path = work / "dns.stdout"
    stderr_path = work / "dns.stderr"
    command = [sys.executable, "-B", str(root / DNS_SERVER_RELATIVE), "--events", str(events)]
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=lambda: _child_affinity(cpu),
        )
        ready_raw, ready = _wait_ready(process, timeout, "resolver DNS peer")
        _write_bytes(ready_path, ready_raw)
        expected = {"schema_version": 1, "protocol": DNS_PROTOCOL, "endpoints": _expected_dns_endpoints()}
        require(ready == expected, "resolver DNS peer readiness differs")
        live = _LivePeer(
            root=root, kind="dns", process=process, source=file_identity(root, root / DNS_SERVER_RELATIVE),
            protocol=DNS_PROTOCOL, endpoint=_expected_dns_endpoints(), ready=file_identity(root, ready_path),
            affinity=_capture_affinity(root, process.pid, work / "dns-affinity.status"),
            events_path=events, stdout_path=stdout_path, stderr_path=stderr_path,
        )
        return live
    except BaseException:
        if process is not None:
            temporary = _LivePeer(
                root=root, kind="dns", process=process, source={}, protocol=DNS_PROTOCOL, endpoint=_expected_dns_endpoints(),
                ready={}, affinity={}, events_path=events, stdout_path=stdout_path, stderr_path=stderr_path,
            )
            _stop_process(temporary, timeout)
        raise


def _make_payload(sequence: int) -> bytes:
    require(type(sequence) is int and sequence >= 0, "echo sequence differs")
    result = bytearray(PAYLOAD_BYTES)
    result[0:4] = sequence.to_bytes(4, byteorder="big", signed=False)
    for index in range(4, PAYLOAD_BYTES):
        result[index] = (sequence * 31 + index * 17) & 0xFF
    return bytes(result)


def _echo_summary(event: Mapping[str, Any], *, require_complete: bool) -> dict[str, Any] | None:
    expected = {
        "schema", "status", "pid", "endpoint", "expected_echoes", "received_messages",
        "sequence_verified_echoes", "echoed_messages", "connections", "affinity", "error",
    }
    require(isinstance(event, dict) and set(event) == expected and event["schema"] == ECHO_PROTOCOL,
            "echo event fields differ")
    count = event["expected_echoes"]
    endpoint = event["endpoint"]
    require(type(count) is int and count > 0
            and isinstance(endpoint, dict) and endpoint.get("transport") in {"tcp", "udp"}
            and isinstance(event["affinity"], list) and all(type(cpu) is int for cpu in event["affinity"]),
            "echo event identity differs")
    expected_connections = 1 if endpoint["transport"] == "tcp" else 0
    for name in ("received_messages", "sequence_verified_echoes", "echoed_messages"):
        require(type(event[name]) is int and 0 <= event[name] <= count,
                "echo event count differs")
    require(type(event["connections"]) is int and 0 <= event["connections"] <= expected_connections,
            "echo event connection count differs")
    if event["status"] != "complete":
        require(event["status"] in {"stopped", "failed"}, "echo event status differs")
        if require_complete:
            raise PeerError("echo peer did not complete its fixed echo count")
        return None
    require(event["received_messages"] == count
            and event["sequence_verified_echoes"] == count
            and event["echoed_messages"] == count
            and event["connections"] == expected_connections
            and event["error"] is None,
            "echo peer did not retain every sequence-checked echo")
    return {
        "expected_echoes": count,
        "received_messages": count,
        "sequence_verified_echoes": count,
        "echoed_messages": count,
        "connections": expected_connections,
    }


def _require_dns_route_event(
    event: Mapping[str, Any], *, role: str, transport: str, name: str, qtype: int, action: str, label: str,
) -> int | None:
    expected_fields = {"role", "family", "transport", "name", "qtype", "qclass", "action"}
    if transport == "udp":
        expected_fields.add("identifier")
    require(set(event) == expected_fields, f"{label} DNS event fields differ")
    require(event["role"] == role and event["family"] == "ipv4"
            and event["transport"] == transport and event["name"] == name
            and event["qtype"] == qtype and event["qclass"] == 1 and event["action"] == action,
            f"{label} DNS route differs")
    if transport == "udp":
        require(type(event["identifier"]) is int and 0 <= event["identifier"] <= 65535,
                f"{label} DNS identifier differs")
        return event["identifier"]
    return None


def _project_dual_routes(events: Sequence[Mapping[str, Any]], iterations: int) -> None:
    """Bind one A/AAAA route pair per server without imposing selector order."""

    roles = ("valid", "drop", "fallback")
    require(len(events) == 6 * iterations, "resolver_dns_dual DNS event count differs")
    projected: dict[str, list[tuple[int, int]]] = {role: [] for role in roles}
    pending: dict[str, int | None] = {role: None for role in roles}
    for index, event in enumerate(events):
        role = event.get("role")
        require(isinstance(role, str) and role in projected, f"dual DNS event {index} role differs")
        qtype = event.get("qtype")
        require(qtype in {1, 28}, f"dual DNS event {index} qtype differs")
        action = "batch-held-a" if qtype == 1 else "batch-release"
        identifier = _require_dns_route_event(
            event, role=role, transport="udp", name="batch.example.test.", qtype=qtype,
            action=action, label=f"dual DNS event {index}",
        )
        if qtype == 1:
            require(pending[role] is None, f"dual {role} DNS route omits its AAAA release")
            pending[role] = identifier
        else:
            require(pending[role] is not None, f"dual {role} DNS route reverses A before AAAA")
            projected[role].append((pending[role], identifier))
            pending[role] = None
    require(all(pending[role] is None and len(projected[role]) == iterations for role in roles),
            "dual DNS route pair count differs")
    reference = projected["valid"]
    require(projected["drop"] == reference and projected["fallback"] == reference,
            "dual DNS route identifiers do not bind corresponding server queries")


def _project_tcp_routes(events: Sequence[Mapping[str, Any]], iterations: int) -> None:
    """Bind UDP/TCP fallback causally, while allowing independent socket order."""

    roles = ("valid", "drop", "fallback")
    require(len(events) == 4 * iterations, "resolver_dns_tcp DNS event count differs")
    udp_identifiers: dict[str, list[int]] = {role: [] for role in roles}
    udp_positions: dict[str, list[int]] = {role: [] for role in roles}
    tcp_answers: list[tuple[str, int]] = []
    for index, event in enumerate(events):
        transport = event.get("transport")
        role = event.get("role")
        if transport == "udp":
            require(isinstance(role, str) and role in udp_identifiers, f"TCP DNS event {index} role differs")
            action = "drop" if role == "drop" else "tc-sequence"
            identifier = _require_dns_route_event(
                event, role=role, transport="udp", name="tc.example.test.", qtype=1,
                action=action, label=f"TCP DNS event {index}",
            )
            require(identifier is not None, "TCP UDP route lacks its identifier")
            udp_identifiers[role].append(identifier)
            udp_positions[role].append(index)
        elif transport == "tcp":
            require(isinstance(role, str) and role in {"valid", "fallback"},
                    f"TCP DNS event {index} answer role differs")
            _require_dns_route_event(
                event, role=role, transport="tcp", name="tc.example.test.", qtype=1,
                action="answer", label=f"TCP DNS event {index}",
            )
            tcp_answers.append((role, index))
        else:
            raise PeerError(f"TCP DNS event {index} transport differs")
    require(all(len(udp_identifiers[role]) == iterations for role in roles)
            and len(tcp_answers) == iterations,
            "TCP DNS route count differs")
    require(udp_identifiers["valid"] == udp_identifiers["drop"] == udp_identifiers["fallback"],
            "TCP DNS route identifiers do not bind corresponding server queries")
    for lookup, (answering_role, answer_position) in enumerate(tcp_answers):
        require(udp_positions[answering_role][lookup] < answer_position,
                f"TCP DNS answer {lookup} precedes its answering UDP truncation")


def summarize_dns_events(
    row_id: str, events: Sequence[Mapping[str, Any]], *, iterations: int,
) -> dict[str, Any]:
    """Replay every expected DNS route in the selected client invocation.

    Musl sends each fixed query to the profile's three loopback nameservers.
    The server's independent UDP sockets and TCP worker threads may interleave
    roles in the raw log.  Replay therefore projects each role's causal route:
    exact fields/counts and same-query identifiers remain required, while an
    incidental selector ordering across separate sockets is not treated as a
    client property.
    """

    require(row_id in {"resolver_hosts", "resolver_dns_dual", "resolver_dns_tcp"},
            f"row has no DNS event contract: {row_id}")
    require(type(iterations) is int and iterations > 0, "DNS invocation iteration count differs")
    require(isinstance(events, Sequence) and not isinstance(events, (str, bytes, bytearray))
            and all(isinstance(event, Mapping) for event in events),
            "DNS events are not an object list")
    if row_id == "resolver_hosts":
        require(not events, "hosts-only lookup must retain zero DNS queries")
        return {"event_count": 0, "zero_dns_queries": True}
    if row_id == "resolver_dns_dual":
        _project_dual_routes(events, iterations)
        return {
            "event_count": 6 * iterations,
            "batch_a_udp": 3 * iterations,
            "batch_aaaa_udp": 3 * iterations,
        }
    _project_tcp_routes(events, iterations)
    return {
        "event_count": 4 * iterations,
        "udp_truncated": 2 * iterations,
        "udp_drop": iterations,
        "tcp_answer": iterations,
    }


def _resolver_contents(setup: Mapping[str, Any]) -> dict[str, bytes]:
    return {
        "etc_resolv_conf_bytes": str(setup["resolv_conf"]).encode("ascii"),
        "etc_hosts_bytes": str(setup["hosts_conf"]).encode("ascii"),
    }


def _resolver_content_record(contents: Mapping[str, bytes]) -> dict[str, Any]:
    return {
        name: {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
        for name, value in sorted(contents.items())
    }


def _write_client_file(client_root: Path, relative: Path, contents: bytes) -> Path:
    current = client_root
    for component in relative.parts[:-1]:
        current = current / component
        if current.exists() or current.is_symlink():
            require(current.is_dir() and not current.is_symlink() and current.resolve(strict=True) == current,
                    f"private client resolver parent is unsafe: {current}")
        else:
            current.mkdir(mode=0o700)
    target = client_root / relative
    require(not target.is_symlink(), f"private client resolver target is symlinked: {target}")
    if target.exists():
        require(target.is_file(), f"private client resolver target has wrong type: {target}")
    _write_bytes(target, contents)
    return target


def _validate_staged_resolver_files(
    root: Path,
    client_root: Path,
    contents: Mapping[str, bytes],
    staged: object,
    *,
    require_complete: bool,
) -> None:
    require(isinstance(staged, dict), "peer staged resolver files differ")
    if not contents:
        require(staged == {}, "non-resolver row staged conventional resolver files")
        return
    expected_paths = {
        "etc_resolv_conf_bytes": Path("etc/resolv.conf"),
        "etc_hosts_bytes": Path("etc/hosts"),
    }
    if set(staged) != set(expected_paths):
        require(not require_complete and staged == {}, "peer resolver files were not staged")
        return
    for name, relative in expected_paths.items():
        path = _validate_identity(root, staged[name], f"staged {name}")
        expected_path = client_root / relative
        require(path == expected_path and path.read_bytes() == contents[name],
                f"staged {name} must be the exact private client resolver path and profile bytes")


class PeerContext:
    """Live peer infrastructure for one client invocation.

    ``argv`` is deliberately only the profile arguments that follow the
    caller's ``BINARY MODE ITERATIONS`` prefix.  ``resolver_files`` provides
    bytes; :meth:`stage_resolver_files` writes them only under ``client_root``.
    """

    def __init__(
        self,
        root: Path,
        row: NetworkRow,
        work: Path,
        client_root: Path,
        cpu: int,
        allowed_affinity: tuple[int, ...],
        iterations: int,
        resolver_contents: Mapping[str, bytes],
        sources: Mapping[str, Any],
        timeout: float,
    ) -> None:
        self.root = root
        self.row = row
        self.work = work
        self.client_root = client_root
        self.cpu = cpu
        self.allowed_affinity = allowed_affinity
        self.iterations = iterations
        self._resolver_contents = dict(resolver_contents)
        self.sources = dict(sources)
        self.timeout = timeout
        self._peers: dict[str, _LivePeer] = {}
        self._staged: dict[str, Any] = {}
        self._evidence: dict[str, Any] | None = None

    @property
    def status(self) -> str:
        return "stopped" if self._evidence is not None else "running"

    @property
    def protocol(self) -> str:
        return ECHO_PROTOCOL if self.row.peer_kind == "echo" else DNS_PROTOCOL

    @property
    def argv(self) -> tuple[str, ...]:
        return self.row.argv

    @property
    def resolver_files(self) -> dict[str, bytes | None]:
        return {
            "etc_resolv_conf_bytes": self._resolver_contents.get("etc_resolv_conf_bytes"),
            "etc_hosts_bytes": self._resolver_contents.get("etc_hosts_bytes"),
        }

    @property
    def peer_pids(self) -> dict[str, int]:
        return {name: peer.process.pid for name, peer in self._peers.items()}

    @property
    def events(self) -> dict[str, Path]:
        """Owned raw-event destinations, which become identity-ready after stop."""

        return {name: peer.events_path for name, peer in self._peers.items()}

    @property
    def evidence(self) -> dict[str, Any]:
        require(self._evidence is not None, "peer evidence is unavailable before stop")
        return self._evidence

    def stage_resolver_files(self) -> dict[str, Any]:
        """Stage profile-owned resolver files inside the supplied private root."""

        require(self._evidence is None, "cannot stage resolver files after peer stop")
        if not self.row.requires_resolver_files:
            require(not self._resolver_contents, "non-resolver row unexpectedly has resolver bytes")
            return {}
        require(not self._staged, "resolver files were already staged")
        paths = {
            "etc_resolv_conf_bytes": Path("etc/resolv.conf"),
            "etc_hosts_bytes": Path("etc/hosts"),
        }
        for name, relative in paths.items():
            self._staged[name] = file_identity(
                self.root, _write_client_file(self.client_root, relative, self._resolver_contents[name])
            )
        return dict(self._staged)

    def _final_peer_record(self, peer: _LivePeer) -> tuple[dict[str, Any], list[str]]:
        record, errors = _stop_process(peer, self.timeout)
        # `_stop_process` writes those raw files after the child is reaped.
        record["stdout"] = file_identity(self.root, peer.stdout_path)
        record["stderr"] = file_identity(self.root, peer.stderr_path)
        if peer.events_path.is_file() and not peer.events_path.is_symlink():
            # The peer child writes this record itself; the DNS server's
            # atomic writer leaves mkstemp's 0600. The adapter adds read bits
            # to every retained file before it seals an attempt, so seal the
            # identity under that final mode or host replay cannot match it.
            mode = stat.S_IMODE(peer.events_path.stat().st_mode)
            os.chmod(peer.events_path, mode | 0o444, follow_symlinks=False)
            record["events"] = file_identity(self.root, peer.events_path)
        else:
            errors.append(f"{peer.kind} peer did not retain an event record")
            record["events"] = None
        return record, errors

    def stop(self) -> dict[str, Any]:
        """Finish every owned peer with bounded TERM/KILL/reap cleanup.

        This method never replaces a caller's primary client exception.  It
        returns an incomplete record when teardown or peer completion failed;
        a caller without a primary error can use the context manager or
        :func:`validate_context` to require a complete record.
        """

        if self._evidence is not None:
            return self._evidence
        peers: dict[str, Any] = {}
        errors: list[str] = []
        for name, peer in reversed(tuple(self._peers.items())):
            record, peer_errors = self._final_peer_record(peer)
            peers[name] = record
            errors.extend(peer_errors)
        peers = {name: peers[name] for name in sorted(peers)}
        summaries: dict[str, Any] = {}
        for name, record in peers.items():
            events_record = record.get("events")
            if not isinstance(events_record, dict):
                continue
            try:
                events_path = _validate_identity(self.root, events_record, f"{name} peer events")
                event_value = _load_json(events_path, f"{name} peer events")
                if name == "echo":
                    summary = _echo_summary(event_value, require_complete=False)
                    if summary is not None:
                        summaries[name] = summary
                else:
                    require(set(event_value) == {"schema_version", "events"} and event_value["schema_version"] == 1
                            and isinstance(event_value["events"], list)
                            and all(isinstance(item, dict) for item in event_value["events"]),
                            "DNS event file fields differ")
                    summaries[name] = summarize_dns_events(
                        self.row.row_id, event_value["events"], iterations=self.iterations,
                    )
            except PeerError as error:
                errors.append(str(error))
        complete = not errors and set(peers) == ({"echo"} if self.row.peer_kind == "echo" else {"dns"})
        if self.row.requires_resolver_files:
            complete = complete and set(self._staged) == {"etc_resolv_conf_bytes", "etc_hosts_bytes"}
        if self.row.peer_kind == "echo":
            complete = complete and "echo" in summaries and summaries["echo"]["expected_echoes"] == self.iterations
        else:
            complete = complete and "dns" in summaries
        for record in peers.values():
            complete = complete and record["termination"]["reaped"] and record["termination"]["exit_status"] == {"kind": "exit", "code": 0}
        evidence: dict[str, Any] = {
            "schema": SCHEMA,
            "status": "complete" if complete else "incomplete",
            "protocol": self.protocol,
            "row": {
                "id": self.row.row_id,
                "mode": self.row.mode,
                "profile_iterations": self.row.full_iterations,
                "client_iterations": self.iterations,
                "operations": self.iterations,
                "reduced_smoke": self.iterations != self.row.full_iterations,
                "requires_loopback_peer": self.row.requires_loopback_peer,
                "requires_hermetic_resolver_files": self.row.requires_resolver_files,
                "geometry": dict(self.row.geometry),
            },
            "argv": list(self.argv),
            "sources": self.sources,
            "client": {
                "execution_root": _relative(self.root, self.client_root),
                "timing": "excluded-peer-infrastructure",
                "cgroup": "excluded-peer-infrastructure",
                "helper_executed_client": False,
            },
            "affinity": {"peer_cpu": self.cpu, "allowed_affinity": list(self.allowed_affinity)},
            "resolver_files": {
                "required": self.row.requires_resolver_files,
                "contents": _resolver_content_record(self._resolver_contents),
                "staged": self._staged,
            },
            "peers": peers,
            "event_summaries": summaries,
            "cleanup": {"deadline_seconds": self.timeout, "errors": errors},
            "record_file": _relative(self.root, self.work) + "/peer-context.json",
        }
        record_path = self.work / "peer-context.json"
        _write_json(record_path, evidence)
        self._evidence = evidence
        return evidence

    def __enter__(self) -> "PeerContext":
        return self

    def __exit__(self, exception_type: object, _value: object, _traceback: object) -> bool:
        evidence = self.stop()
        if exception_type is None:
            validate_context(self.root, evidence)
        # Returning false preserves a client exception even if cleanup itself
        # found an error; its retained record carries that secondary failure.
        return False


def start_context(
    root: Path,
    *,
    row_id: str,
    mode: str,
    invocation_work: Path,
    client_root: Path,
    cpu: int,
    allowed_affinity: Sequence[int],
    iterations: int | None = None,
    timeout_seconds: float = STOP_TIMEOUT_SECONDS,
) -> PeerContext:
    """Start exactly the selected peer without executing a client process."""

    root = _root(root)
    row = load_network_row(root, row_id, mode)
    allowed = _valid_affinity(cpu, allowed_affinity)
    require(type(timeout_seconds) in {int, float} and timeout_seconds > 0,
            "peer lifecycle timeout differs")
    selected_iterations = row.full_iterations if iterations is None else iterations
    require(type(selected_iterations) is int and 0 < selected_iterations <= row.full_iterations,
            "peer client iteration count differs")
    work = _fresh_work_directory(root, invocation_work)
    private_root = _physical_work_directory(root, client_root, "client execution root")
    require(not _within(work, private_root) and not _within(private_root, work),
            "peer invocation work and client execution root must be disjoint")
    profile, _profile_path = _load_profile(root)
    setup = _resolver_setup(profile)
    resolver_contents = _resolver_contents(setup) if row.requires_resolver_files else {}
    context = PeerContext(
        root=root,
        row=row,
        work=work,
        client_root=private_root,
        cpu=cpu,
        allowed_affinity=allowed,
        iterations=selected_iterations,
        resolver_contents=resolver_contents,
        sources=_source_identities(root, dns=row.peer_kind == "dns"),
        timeout=float(timeout_seconds),
    )
    try:
        if row.peer_kind == "echo":
            require(row.endpoint is not None, "echo row lacks its fixed endpoint")
            context._peers["echo"] = _launch_echo(root, work, row.endpoint, selected_iterations, cpu, context.timeout)
        else:
            context._peers["dns"] = _launch_dns(root, work, cpu, context.timeout)
    except BaseException:
        context.stop()
        raise
    return context


def _validate_affinity_record(root: Path, record: object, cpu: int, pid: int, label: str) -> None:
    require(isinstance(record, dict) and set(record) == {"observed", "raw"}
            and record["observed"] == [cpu], f"{label} affinity differs")
    raw = _validate_identity(root, record["raw"], f"{label} affinity raw").read_bytes()
    require(_status_pid(raw, f"{label} affinity raw") == pid, f"{label} raw affinity Pid differs")
    require(_parse_cpu_list(_status_value(raw, "Cpus_allowed_list", f"{label} affinity raw")) == {cpu},
            f"{label} raw affinity differs")


def _validate_echo_peer(root: Path, record: object, row: NetworkRow, iterations: int, cpu: int, *, require_complete: bool) -> dict[str, Any] | None:
    expected = {"kind", "pid", "protocol", "source", "endpoint", "ready", "affinity", "stdout", "stderr", "events", "termination"}
    require(isinstance(record, dict) and set(record) == expected
            and record["kind"] == "echo" and record["protocol"] == ECHO_PROTOCOL
            and type(record["pid"]) is int and record["pid"] > 0
            and record["endpoint"] == row.endpoint,
            "echo peer record differs")
    require(_validate_identity(root, record["source"], "echo source") == (root / "compat/perf/x86_64_peers.py"),
            "echo source path differs")
    ready_path = _validate_identity(root, record["ready"], "echo readiness")
    ready = _load_json(ready_path, "echo readiness")
    require(ready == {
        "schema": ECHO_PROTOCOL, "status": "ready", "pid": record["pid"], "endpoint": row.endpoint,
        "expected_echoes": iterations, "affinity": [cpu],
    }, "echo readiness contract differs")
    _validate_affinity_record(root, record["affinity"], cpu, record["pid"], "echo peer")
    stdout = _validate_identity(root, record["stdout"], "echo stdout")
    stderr = _validate_identity(root, record["stderr"], "echo stderr")
    require(not stdout.read_bytes() and not stderr.read_bytes(), "echo peer emitted unexpected output")
    events_path = _validate_identity(root, record["events"], "echo events")
    event = _load_json(events_path, "echo events")
    require(event["pid"] == record["pid"] and event["endpoint"] == row.endpoint
            and event["expected_echoes"] == iterations and event["affinity"] == [cpu],
            "echo event does not bind its started peer")
    summary = _echo_summary(event, require_complete=require_complete)
    termination = record["termination"]
    require(isinstance(termination, dict) and set(termination) == {
        "deadline_seconds", "sent_sigterm", "sent_sigkill", "reaped", "exit_status",
    } and termination["reaped"] is True and termination["exit_status"] == {"kind": "exit", "code": 0},
            "echo peer termination differs")
    return summary


def _validate_peer_artifact_paths(
    root: Path,
    record: object,
    invocation_work: Path,
    client_root: Path,
    peer_name: str,
) -> None:
    require(isinstance(record, dict), f"{peer_name} peer record differs")
    prefix = "echo" if peer_name == "echo" else "dns"
    expected = {
        "ready": f"{prefix}-ready.json",
        "stdout": f"{prefix}.stdout",
        "stderr": f"{prefix}.stderr",
        "events": f"{prefix}-events.json",
    }
    identities: dict[str, object] = {field: record.get(field) for field in expected}
    affinity = record.get("affinity")
    require(isinstance(affinity, dict), f"{peer_name} peer affinity differs")
    identities["affinity raw"] = affinity.get("raw")
    expected["affinity raw"] = f"{prefix}-affinity.status"
    for field, filename in expected.items():
        path = _validate_identity(root, identities[field], f"{peer_name} peer {field}")
        require(path == invocation_work / filename and not _within(path, client_root),
                f"{peer_name} peer retained {field} must remain in invocation work outside client root")


def _validate_dns_peer(root: Path, record: object, row: NetworkRow, iterations: int, cpu: int) -> dict[str, Any]:
    expected = {"kind", "pid", "protocol", "source", "endpoint", "ready", "affinity", "stdout", "stderr", "events", "termination"}
    require(isinstance(record, dict) and set(record) == expected
            and record["kind"] == "dns" and record["protocol"] == DNS_PROTOCOL
            and type(record["pid"]) is int and record["pid"] > 0
            and record["endpoint"] == _expected_dns_endpoints(),
            "DNS peer record differs")
    require(_validate_identity(root, record["source"], "DNS source") == (root / DNS_SERVER_RELATIVE),
            "DNS source path differs")
    ready = _load_json(_validate_identity(root, record["ready"], "DNS readiness"), "DNS readiness")
    require(ready == {"schema_version": 1, "protocol": DNS_PROTOCOL, "endpoints": _expected_dns_endpoints()},
            "DNS readiness contract differs")
    _validate_affinity_record(root, record["affinity"], cpu, record["pid"], "DNS peer")
    stdout = _validate_identity(root, record["stdout"], "DNS stdout")
    stderr = _validate_identity(root, record["stderr"], "DNS stderr")
    require(not stdout.read_bytes() and not stderr.read_bytes(), "DNS peer emitted unexpected output")
    events = _load_json(_validate_identity(root, record["events"], "DNS events"), "DNS events")
    require(set(events) == {"schema_version", "events"} and events["schema_version"] == 1
            and isinstance(events["events"], list) and all(isinstance(event, dict) for event in events["events"]),
            "DNS event file differs")
    summary = summarize_dns_events(row.row_id, events["events"], iterations=iterations)
    termination = record["termination"]
    require(isinstance(termination, dict) and set(termination) == {
        "deadline_seconds", "sent_sigterm", "sent_sigkill", "reaped", "exit_status",
    } and termination["reaped"] is True and termination["exit_status"] == {"kind": "exit", "code": 0},
            "DNS peer termination differs")
    return summary


def validate_context(root: Path, record: Mapping[str, Any], *, require_complete: bool = True) -> dict[str, Any]:
    """Purely replay a retained peer context without starting a peer or client."""

    root = _root(root)
    expected = {
        "schema", "status", "protocol", "row", "argv", "sources", "client", "affinity",
        "resolver_files", "peers", "event_summaries", "cleanup", "record_file",
    }
    require(isinstance(record, Mapping) and set(record) == expected and record["schema"] == SCHEMA,
            "peer context fields differ")
    row_record = record["row"]
    require(isinstance(row_record, dict) and set(row_record) == {
        "id", "mode", "profile_iterations", "client_iterations", "operations", "reduced_smoke",
        "requires_loopback_peer", "requires_hermetic_resolver_files", "geometry",
    }, "peer row record differs")
    row = load_network_row(root, str(row_record.get("id")), str(row_record.get("mode")))
    iterations = row_record["client_iterations"]
    require(type(iterations) is int and 0 < iterations <= row.full_iterations
            and row_record == {
                "id": row.row_id, "mode": row.mode, "profile_iterations": row.full_iterations,
                "client_iterations": iterations, "operations": iterations,
                "reduced_smoke": iterations != row.full_iterations,
                "requires_loopback_peer": row.requires_loopback_peer,
                "requires_hermetic_resolver_files": row.requires_resolver_files,
                "geometry": dict(row.geometry),
            }, "peer row replay differs")
    require(record["protocol"] == (ECHO_PROTOCOL if row.peer_kind == "echo" else DNS_PROTOCOL)
            and record["argv"] == list(row.argv), "peer protocol or argv differs")
    expected_sources = _source_identities(root, dns=row.peer_kind == "dns")
    require(record["sources"] == expected_sources, "peer source identities differ")
    client = record["client"]
    require(isinstance(client, dict) and client.get("timing") == "excluded-peer-infrastructure"
            and client.get("cgroup") == "excluded-peer-infrastructure"
            and client.get("helper_executed_client") is False
            and isinstance(client.get("execution_root"), str),
            "peer client boundary differs")
    client_root = _physical_work_directory(root, Path(client["execution_root"]), "retained client execution root")
    record_path = Path(record["record_file"])
    require(not record_path.is_absolute() and ".." not in record_path.parts,
            "peer context record path differs")
    retained_record_path = (root / record_path).resolve(strict=True)
    require(retained_record_path.name == "peer-context.json"
            and _within(retained_record_path, _work_root(root))
            and not _within(retained_record_path, client_root),
            "peer context record must remain in invocation work outside client root")
    invocation_work = retained_record_path.parent
    require(not _within(invocation_work, client_root) and not _within(client_root, invocation_work),
            "peer invocation work and retained client root overlap")
    saved = _load_json(retained_record_path, "retained peer context")
    require(saved == dict(record), "retained peer context does not match replay input")
    affinity = record["affinity"]
    require(isinstance(affinity, dict) and set(affinity) == {"peer_cpu", "allowed_affinity"},
            "peer affinity fields differ")
    _valid_affinity(affinity["peer_cpu"], affinity["allowed_affinity"])
    cpu = affinity["peer_cpu"]
    resolver = record["resolver_files"]
    require(isinstance(resolver, dict) and set(resolver) == {"required", "contents", "staged"}
            and resolver["required"] is row.requires_resolver_files,
            "peer resolver file record differs")
    profile, _ = _load_profile(root)
    contents = _resolver_contents(_resolver_setup(profile)) if row.requires_resolver_files else {}
    require(resolver["contents"] == _resolver_content_record(contents), "peer resolver bytes differ")
    _validate_staged_resolver_files(
        root, client_root, contents, resolver["staged"], require_complete=require_complete,
    )
    peers = record["peers"]
    require(isinstance(peers, dict) and set(peers) == ({"echo"} if row.peer_kind == "echo" else {"dns"}),
            "peer roster differs")
    if row.peer_kind == "echo":
        _validate_peer_artifact_paths(root, peers["echo"], invocation_work, client_root, "echo")
        summary = _validate_echo_peer(root, peers["echo"], row, iterations, cpu, require_complete=require_complete)
        expected_summaries = {} if summary is None else {"echo": summary}
    else:
        _validate_peer_artifact_paths(root, peers["dns"], invocation_work, client_root, "dns")
        summary = _validate_dns_peer(root, peers["dns"], row, iterations, cpu)
        expected_summaries = {"dns": summary}
    require(record["event_summaries"] == expected_summaries, "peer event summary differs from raw events")
    cleanup = record["cleanup"]
    require(isinstance(cleanup, dict) and set(cleanup) == {"deadline_seconds", "errors"}
            and cleanup["deadline_seconds"] > 0 and isinstance(cleanup["errors"], list)
            and all(isinstance(error, str) and error for error in cleanup["errors"]),
            "peer cleanup differs")
    if record["status"] == "complete":
        require(cleanup["errors"] == [], "complete peer context retained cleanup errors")
    else:
        require(record["status"] == "incomplete", "peer context status differs")
    if require_complete:
        require(record["status"] == "complete", "peer context cannot support a client result")
    return dict(record)


def _recv_exact(connection: socket.socket, length: int, stopping: callable) -> bytes | None:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        try:
            chunk = connection.recv(remaining)
        except socket.timeout:
            if stopping():
                return None
            continue
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _echo_child(arguments: argparse.Namespace) -> int:
    endpoint = {
        "family": arguments.family,
        "transport": arguments.transport,
        "address": arguments.address,
        "port": arguments.port,
    }
    expected = arguments.expected_echoes
    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    family = socket.AF_INET if arguments.family == "ipv4" else socket.AF_INET6
    transport = socket.SOCK_STREAM if arguments.transport == "tcp" else socket.SOCK_DGRAM
    received = 0
    verified = 0
    echoed = 0
    connections = 0
    error: str | None = None
    sock: socket.socket | None = None
    try:
        sock = socket.socket(family, transport)
        if transport == socket.SOCK_STREAM:
            # Fixed profile ports recur across independent invocations.  This
            # lets a freshly owned listener reclaim a completed peer's local
            # TIME_WAIT state; it never broadens the loopback endpoint.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((arguments.address, arguments.port))
        if transport == socket.SOCK_STREAM:
            sock.listen(1)
        ready = {
            "schema": ECHO_PROTOCOL, "status": "ready", "pid": os.getpid(), "endpoint": endpoint,
            "expected_echoes": expected, "affinity": sorted(os.sched_getaffinity(0)),
        }
        print(json.dumps(ready, sort_keys=True), flush=True)
        if transport == socket.SOCK_STREAM:
            connection: socket.socket | None = None
            while not stopping and connection is None:
                try:
                    connection, _address = sock.accept()
                except socket.timeout:
                    continue
            if connection is not None:
                connections = 1
                with connection:
                    connection.settimeout(0.2)
                    for sequence in range(expected):
                        data = _recv_exact(connection, PAYLOAD_BYTES, lambda: stopping)
                        if data is None:
                            if not stopping:
                                error = "TCP client closed before its exact echo count"
                            break
                        received += 1
                        if data != _make_payload(sequence):
                            error = f"TCP payload sequence differs at {sequence}"
                            break
                        verified += 1
                        connection.sendall(data)
                        echoed += 1
        else:
            for sequence in range(expected):
                while not stopping:
                    try:
                        data, peer = sock.recvfrom(PAYLOAD_BYTES)
                        break
                    except socket.timeout:
                        continue
                else:
                    break
                received += 1
                if data != _make_payload(sequence):
                    error = f"UDP payload sequence differs at {sequence}"
                    break
                verified += 1
                sock.sendto(data, peer)
                echoed += 1
    except BaseException as caught:
        error = str(caught)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    completed = not stopping and error is None and received == verified == echoed == expected
    status = "complete" if completed else "stopped" if stopping and error is None else "failed"
    event = {
        "schema": ECHO_PROTOCOL, "status": status, "pid": os.getpid(), "endpoint": endpoint,
        "expected_echoes": expected, "received_messages": received,
        "sequence_verified_echoes": verified, "echoed_messages": echoed,
        "connections": connections, "affinity": sorted(os.sched_getaffinity(0)), "error": error,
    }
    _write_json(arguments.events, event)
    return 0 if status in {"complete", "stopped"} else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--echo-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--family", choices=("ipv4", "ipv6"))
    parser.add_argument("--transport", choices=("tcp", "udp"))
    parser.add_argument("--address")
    parser.add_argument("--port", type=int)
    parser.add_argument("--expected-echoes", type=int)
    parser.add_argument("--events", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if not arguments.echo_child:
        raise PeerError("x86_64_peers.py is an imported lifecycle helper, not a client runner")
    require(arguments.family is not None and arguments.transport is not None and arguments.address is not None
            and type(arguments.port) is int and 0 < arguments.port <= 65535
            and type(arguments.expected_echoes) is int and arguments.expected_echoes > 0
            and arguments.events is not None,
            "echo child arguments differ")
    return _echo_child(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PeerError as error:
        print(f"x86 performance peers: {error}", file=sys.stderr)
        raise SystemExit(2)
