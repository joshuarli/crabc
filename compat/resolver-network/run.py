#!/usr/bin/env python3
"""Run the resolver/network workload against musl and crabc.

The workload object is compiled exactly once from the pinned musl headers,
then linked once against the pinned musl runtime and once against crabc's
loader/libc. A local DNS server supplies every resolver answer. In an
explicitly marked isolated environment, the runner temporarily installs its
private ``/etc/resolv.conf`` and restores it before publishing the report; it
never contacts public DNS. Like the repository differential runner, it
requires native AArch64 and musl 1.2.6.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import difflib
import hashlib
import json
import os
import platform
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


MUSL_VERSION = "1.2.6"
DEFAULT_MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
RESOLV_CONF = Path("/etc/resolv.conf")
ISOLATED_MARKER = "CRABC_RESOLVER_NETWORK_ISOLATED"
DNS_PORT = 53
ROLE_ADDRESSES = {
    "valid": "127.0.0.1",
    "drop": "127.0.0.2",
    "fallback": "127.0.0.3",
}
RESOLVER_CONFIG = """# crabc resolver-network isolated fixture
nameserver 127.0.0.1
nameserver 127.0.0.2
nameserver 127.0.0.3
search search.test
options ndots:1 timeout:1 attempts:1
"""
EXPECTED_STDOUT = (
    "resolver.a=198.51.100.42\n"
    "resolver.aaaa=2001:db8::42\n"
    "resolver.nxdomain=HOST_NOT_FOUND\n"
    "resolver.nodata=NO_DATA\n"
    "resolver.malformed-wrong-id=accepted-valid\n"
    "resolver.cname=target.example.test\n"
    "resolver.tc-tcp=accepted-over-tcp\n"
    "resolver.search=searchhost.search.test\n"
    "resolver.fallback=second-server\n"
    "network.tcp4=loopback\n"
    "network.tcp6=loopback\n"
    "network.udp4=loopback\n"
    "network.udp6=loopback\n"
    "network.socketpair-sendmsg-recvmsg=ok\n"
    "network.ancillary-scm-rights=ok\n"
    "network.epoll=readiness\n"
    "network.shutdown-half-close=eof\n"
    "network.partial-send=short-write\n"
    "network.socket-timeout=EAGAIN\n"
    "network.eintr=EINTR\n"
    "network.nonblocking-recv=EAGAIN\n"
    "network.poll-select=readiness\n"
)
EXPECTED_SUBCASES = [line.split("=", 1)[0] for line in EXPECTED_STDOUT.splitlines()]
REQUIRED_SERVER_NAMES = {
    "a.example.test.",
    "aaaa.example.test.",
    "nxdomain.example.test.",
    "nodata.example.test.",
    "malformed.example.test.",
    "alias.example.test.",
    "tc.example.test.",
    "searchhost.search.test.",
    "fallback.example.test.",
}


class RunnerError(Exception):
    """A setup or orchestration failure, distinct from a workload mismatch."""


def require_isolated_environment() -> None:
    """Refuse resolver-file access unless the caller labels its environment."""
    if os.environ.get(ISOLATED_MARKER) != "1":
        raise RunnerError(
            f"refusing to modify {RESOLV_CONF} without "
            f"{ISOLATED_MARKER}=1 in an explicitly isolated environment"
        )


def _write_resolver_file(path: Path, contents: bytes, mode: int) -> None:
    with path.open("wb") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(path, mode)


@contextmanager
def isolated_resolver_config():
    """Install and restore the private fixture resolver configuration.

    The runner deliberately accepts only a regular, non-symlink file.  This
    prevents an isolation marker from turning an invocation into permission to
    overwrite a host file mounted at ``/etc/resolv.conf``.
    """
    require_isolated_environment()
    try:
        metadata = RESOLV_CONF.lstat()
    except OSError as error:
        raise RunnerError(f"private resolver configuration is unavailable: {RESOLV_CONF}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RunnerError(f"refusing non-regular private resolver configuration: {RESOLV_CONF}")
    try:
        original = RESOLV_CONF.read_bytes()
    except OSError as error:
        raise RunnerError(f"could not read private resolver configuration: {error}") from error
    mode = stat.S_IMODE(metadata.st_mode)
    try:
        try:
            _write_resolver_file(RESOLV_CONF, RESOLVER_CONFIG.encode("ascii"), mode)
        except OSError as error:
            raise RunnerError(f"could not install private resolver configuration: {error}") from error
        yield
    finally:
        try:
            _write_resolver_file(RESOLV_CONF, original, mode)
        except OSError as error:
            raise RunnerError(f"could not restore private resolver configuration: {error}") from error


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(path: Path) -> Path:
    return path.expanduser().resolve()


def parse_args() -> argparse.Namespace:
    root = repository_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", DEFAULT_MUSL_ROOT)),
        help="pinned musl 1.2.6 tree (default: MUSL_ROOT or /opt/musl-1.2.6)",
    )
    parser.add_argument(
        "--musl-cc",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", root / "target/debug")),
        help="directory containing crabc libc.so and libldso.so",
    )
    parser.add_argument("--ldso", type=Path, default=None, help="crabc dynamic linker override")
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("CRABC_RESOLVER_NETWORK_TIMEOUT", "8")),
        help="per-binary timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="atomic JSON report path (default: compat/reports/resolver-network.json)",
    )
    return parser.parse_args()


def command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def check_inputs(args: argparse.Namespace, root: Path, ldso: Path) -> tuple[list[str], Path, Path]:
    require_isolated_environment()
    if platform.machine() != "aarch64":
        raise RunnerError(f"requires native AArch64 (platform.machine() was {platform.machine()})")
    musl_root = resolve_path(args.musl_root)
    if musl_root.name != f"musl-{MUSL_VERSION}":
        raise RunnerError(
            f"--musl-root must name the pinned musl-{MUSL_VERSION} tree: {musl_root}"
        )
    if not (musl_root / "include").is_dir():
        raise RunnerError(f"pinned musl headers not found: {musl_root / 'include'}")
    if not (musl_root / "lib/ld-musl-aarch64.so.1").is_file():
        raise RunnerError(
            f"pinned AArch64 musl loader not found: {musl_root / 'lib/ld-musl-aarch64.so.1'}"
        )
    if not (musl_root / "lib/libc.so").is_file():
        raise RunnerError(f"pinned AArch64 musl libc not found: {musl_root / 'lib/libc.so'}")
    compiler = shlex.split(args.musl_cc)
    if not compiler:
        raise RunnerError("--musl-cc/MUSL_CC is empty")
    if shutil.which(compiler[0]) is None:
        raise RunnerError(f"compiler not found: {compiler[0]}")
    target_dir = resolve_path(args.target_dir)
    if not (target_dir / "libc.so").is_file():
        raise RunnerError(f"crabc libc not found: {target_dir / 'libc.so'}")
    if not ldso.is_file() or not os.access(ldso, os.X_OK):
        raise RunnerError(f"crabc dynamic linker not found or not executable: {ldso}")
    source = root / "compat/resolver-network/workload.c"
    if not source.is_file():
        raise RunnerError(f"workload source not found: {source}")
    if args.timeout <= 0:
        raise RunnerError(f"--timeout must be positive: {args.timeout}")
    return compiler, source, musl_root


def compile_checked(command: list[str], cwd: Path) -> None:
    try:
        subprocess.run(command, cwd=cwd, check=True)
    except FileNotFoundError as error:
        raise RunnerError(f"unable to execute {command[0]}: {error}") from error
    except subprocess.CalledProcessError as error:
        raise RunnerError(f"command failed ({error.returncode}): {command_text(command)}") from error


def stream_snapshot(stream: bytes) -> dict[str, object]:
    snapshot: dict[str, object] = {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
    }
    try:
        snapshot["text"] = stream.decode("utf-8")
        snapshot["encoding"] = "utf-8"
    except UnicodeDecodeError:
        snapshot["text"] = stream.decode("utf-8", errors="replace")
        snapshot["encoding"] = "utf-8-replaced"
    return snapshot


def atomic_write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    except OSError as error:
        raise RunnerError(f"could not atomically write report {path}: {error}") from error
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def start_server(server_script: Path, events_path: Path) -> tuple[subprocess.Popen[bytes], dict[str, Any]]:
    try:
        process = subprocess.Popen(
            [sys.executable, str(server_script), "--events", str(events_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=repository_root(),
        )
    except OSError as error:
        raise RunnerError(f"could not start DNS server: {error}") from error
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        ready_events = selector.select(timeout=5.0)
        if not ready_events:
            raise RunnerError("DNS server did not publish readiness within 5 seconds")
        line = process.stdout.readline()
        if not line:
            stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
            raise RunnerError(f"DNS server exited before readiness: {stderr.strip()}")
        try:
            ready = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RunnerError(f"DNS server readiness was not JSON: {line!r}") from error
        if ready.get("protocol") != "resolver-network-dns-v1":
            raise RunnerError(f"unexpected DNS server protocol: {ready.get('protocol')!r}")
        for role in ("valid", "drop", "fallback"):
            endpoint = ready.get("endpoints", {}).get(role, {})
            if (
                endpoint.get("ipv4") != ROLE_ADDRESSES[role]
                or endpoint.get("port") != DNS_PORT
                or endpoint.get("udp4_port") != DNS_PORT
                or endpoint.get("tcp4_port") != DNS_PORT
            ):
                raise RunnerError(f"invalid {role} DNS endpoint: {endpoint!r}")
        return process, ready
    except Exception:
        stop_process(process)
        raise
    finally:
        selector.close()


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=3.0)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=3.0)


def run_binary(
    binary: Path,
    arguments: list[str],
    environment: dict[str, str],
    cwd: Path,
    timeout: float,
) -> tuple[int | str, bytes, bytes]:
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        return "TIMEOUT", stdout, stderr
    except OSError as error:
        return f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode("utf-8")


def print_stream_diff(name: str, reference: bytes, candidate: bytes) -> None:
    reference_lines = reference.decode("utf-8", errors="replace").splitlines(keepends=True)
    candidate_lines = candidate.decode("utf-8", errors="replace").splitlines(keepends=True)
    rendered = "".join(
        difflib.unified_diff(reference_lines, candidate_lines, fromfile=f"musl/{name}", tofile=f"crabc/{name}")
    )
    print(f"resolver-network: FAIL: {name} differs", file=sys.stderr)
    if rendered:
        print(rendered, end="", file=sys.stderr)
    else:
        print(f"  musl bytes={reference.hex()}\n  crabc bytes={candidate.hex()}", file=sys.stderr)


def load_events(events_path: Path) -> tuple[list[dict[str, object]], str | None]:
    try:
        data = json.loads(events_path.read_text(encoding="utf-8"))
        events = data.get("events")
        if not isinstance(events, list):
            return [], "event log has no events list"
        return [event for event in events if isinstance(event, dict)], None
    except (OSError, json.JSONDecodeError) as error:
        return [], str(error)


def event_contract(events: list[dict[str, object]]) -> dict[str, object]:
    names = {str(event["name"]) for event in events if "name" in event}
    malformed = any(
        event.get("name") == "malformed.example.test." and event.get("action") == "malformed-sequence"
        for event in events
    )
    drop_count = sum(
        event.get("role") == "drop" and event.get("action") == "drop" for event in events
    )
    fallback_count = sum(
        event.get("name") == "fallback.example.test." and event.get("role") == "fallback"
        for event in events
    )
    valid_fallback_drop_count = sum(
        event.get("name") == "fallback.example.test."
        and event.get("role") == "valid"
        and event.get("action") == "drop"
        for event in events
    )
    cname = any(
        event.get("name") == "alias.example.test." and event.get("action") == "cname"
        for event in events
    )
    tc_udp = any(
        event.get("name") == "tc.example.test."
        and event.get("transport") == "udp"
        and event.get("action") == "tc-sequence"
        for event in events
    )
    tc_tcp = any(
        event.get("name") == "tc.example.test."
        and event.get("transport") == "tcp"
        and event.get("action") == "answer"
        for event in events
    )
    return {
        "required_names_seen": sorted(REQUIRED_SERVER_NAMES & names),
        "required_names_missing": sorted(REQUIRED_SERVER_NAMES - names),
        "malformed_sequence_seen": malformed,
        "drop_endpoint_seen": drop_count >= 2,
        "drop_endpoint_observations": drop_count,
        "fallback_query_seen": fallback_count >= 2,
        "fallback_query_observations": fallback_count,
        "valid_fallback_drop_seen": valid_fallback_drop_count >= 2,
        "valid_fallback_drop_observations": valid_fallback_drop_count,
        "cname_query_seen": cname,
        "tc_udp_truncated_seen": tc_udp,
        "tc_tcp_retry_seen": tc_tcp,
        "passed": (
            REQUIRED_SERVER_NAMES <= names
            and malformed
            and drop_count >= 2
            and fallback_count >= 2
            and valid_fallback_drop_count >= 2
            and cname
            and tc_udp
            and tc_tcp
        ),
    }


def build_report(
    reference_status: int | str,
    candidate_status: int | str,
    reference_stdout: bytes,
    candidate_stdout: bytes,
    reference_stderr: bytes,
    candidate_stderr: bytes,
    events: list[dict[str, object]],
    event_error: str | None,
    ready: dict[str, Any],
    compiler: list[str],
    musl_root: Path,
    target_dir: Path,
    timeout: float,
) -> dict[str, object]:
    status_match = reference_status == candidate_status
    stdout_match = reference_stdout == candidate_stdout
    stderr_match = reference_stderr == candidate_stderr
    reference_success = reference_status == 0 and reference_stdout.decode("utf-8", errors="replace") == EXPECTED_STDOUT
    candidate_success = candidate_status == 0 and candidate_stdout.decode("utf-8", errors="replace") == EXPECTED_STDOUT
    contract = event_contract(events)
    if event_error is not None:
        contract["passed"] = False
        contract["error"] = event_error
    passed = status_match and stdout_match and stderr_match and reference_success and candidate_success and bool(contract["passed"])
    if not status_match:
        print(f"resolver-network: FAIL: status musl={reference_status} crabc={candidate_status}", file=sys.stderr)
    if not stdout_match:
        print_stream_diff("stdout", reference_stdout, candidate_stdout)
    if not stderr_match:
        print_stream_diff("stderr", reference_stderr, candidate_stderr)
    print(f"resolver-network: {'PASS' if passed else 'FAIL'}")
    return {
        "schema_version": 1,
        "harness": "compat/resolver-network",
        "musl_version": MUSL_VERSION,
        "platform": platform.machine(),
        "passed": passed,
        "result": "pass" if passed else "fail",
        "contract": {
            "raw_comparison": "exit status, complete stdout, complete stderr; no normalization",
            "expected_subcases": EXPECTED_SUBCASES,
            "expected_stdout_sha256": hashlib.sha256(EXPECTED_STDOUT.encode("utf-8")).hexdigest(),
            "resolver_configuration": (
                "private /etc/resolv.conf is written and restored only when "
                f"{ISOLATED_MARKER}=1; nameservers 127.0.0.1/.2/.3, search.test, "
                "timeout:1 attempts:1; workload also installs public _res/__res_state"
            ),
            "dns_protocol": "loopback UDP/TCP IPv4, deterministic A/AAAA/CNAME/NXDOMAIN/NODATA, malformed/wrong-ID sequence, UDP TC with TCP retry, search, valid-endpoint drop then nameserver fallback",
            "network_protocol": "loopback TCP/UDP IPv4/IPv6, socketpair, SCM_RIGHTS ancillary data, epoll, shutdown EOF, bounded partial I/O, SO_RCVTIMEO, EINTR, nonblocking EAGAIN, poll/select, sendmsg/recvmsg",
        },
        "reference": {
            "runtime": "musl",
            "exit_status": reference_status,
            "stdout": stream_snapshot(reference_stdout),
            "stderr": stream_snapshot(reference_stderr),
        },
        "candidate": {
            "runtime": "crabc",
            "exit_status": candidate_status,
            "stdout": stream_snapshot(candidate_stdout),
            "stderr": stream_snapshot(candidate_stderr),
        },
        "comparisons": {
            "exit_status_match": status_match,
            "stdout_match": stdout_match,
            "stderr_match": stderr_match,
            "reference_contract_match": reference_success,
            "candidate_contract_match": candidate_success,
        },
        "dns_server": {
            "ready": ready,
            "event_contract": contract,
            "events": events,
        },
        "inputs": {
            "musl_root": str(musl_root),
            "musl_cc": command_text(compiler),
            "target_dir": str(target_dir),
            "timeout_seconds": timeout,
            "resolver_config_path": str(RESOLV_CONF),
            "resolver_config_nameservers": [ROLE_ADDRESSES[role] for role in ("valid", "drop", "fallback")],
            "isolated_environment_marker": ISOLATED_MARKER,
        },
    }


def run(args: argparse.Namespace) -> bool:
    root = repository_root()
    target_dir = resolve_path(args.target_dir)
    ldso = resolve_path(args.ldso) if args.ldso else resolve_path(
        Path(os.environ.get("CRABC_LDSO", target_dir / "libldso.so"))
    )
    compiler, source, musl_root = check_inputs(args, root, ldso)
    report_path = resolve_path(args.report) if args.report else resolve_path(
        Path(os.environ.get("CRABC_RESOLVER_NETWORK_REPORT", root / "compat/reports/resolver-network.json"))
    )
    server_script = root / "compat/resolver-network/dns_server.py"

    with tempfile.TemporaryDirectory(prefix="crabc-resolver-network-") as work_name:
        work = Path(work_name)
        object_file = work / "workload.o"
        reference_binary = work / "workload.musl"
        candidate_binary = work / "workload.crabc"
        events_path = work / "dns-events.json"
        compile_checked(
            compiler
            + [
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-fno-builtin",
                "-fPIE",
                "-I",
                str(musl_root / "include"),
                "-c",
                str(source),
                "-o",
                str(object_file),
            ],
            root,
        )
        compile_checked(compiler + ["-fPIE", "-pie", str(object_file), "-o", str(reference_binary)], root)
        compile_checked(
            compiler
            + [
                "-fPIE",
                "-pie",
                str(object_file),
                f"-Wl,--dynamic-linker={ldso}",
                f"-L{target_dir}",
                "-Wl,--allow-shlib-undefined",
                "-lc",
                "-o",
                str(candidate_binary),
            ],
            root,
        )

        server: subprocess.Popen[bytes] | None = None
        ready: dict[str, Any] = {}
        with isolated_resolver_config():
            try:
                server, ready = start_server(server_script, events_path)
                reference_environment = os.environ.copy()
                reference_environment.pop("LD_LIBRARY_PATH", None)
                candidate_environment = os.environ.copy()
                candidate_environment["LD_LIBRARY_PATH"] = str(target_dir)
                print(f"resolver-network: running musl {MUSL_VERSION}")
                reference_status, reference_stdout, reference_stderr = run_binary(
                    reference_binary, [], reference_environment, root, args.timeout
                )
                print("resolver-network: running crabc")
                candidate_status, candidate_stdout, candidate_stderr = run_binary(
                    candidate_binary, [], candidate_environment, root, args.timeout
                )
            finally:
                if server is not None:
                    stop_process(server)
        events, event_error = load_events(events_path)
        report = build_report(
            reference_status,
            candidate_status,
            reference_stdout,
            candidate_stdout,
            reference_stderr,
            candidate_stderr,
            events,
            event_error,
            ready,
            compiler,
            musl_root,
            target_dir,
            args.timeout,
        )
        atomic_write_json(report_path, report)
        print(f"resolver-network: report: {report_path}")
        return bool(report["passed"])


def main() -> int:
    args = parse_args()
    try:
        return 0 if run(args) else 1
    except RunnerError as error:
        print(f"resolver-network: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
