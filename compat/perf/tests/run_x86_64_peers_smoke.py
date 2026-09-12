#!/usr/bin/env python3
"""Reduced pinned-native lifecycle smoke for x86 performance network peers.

This compiles only the existing static network fixture, starts one helper
context per fixed network row, and executes the client outside the helper in a
private chroot.  It is correctness evidence for peer lifecycle and retained
raw events; it collects no timing, cgroup, or benchmark result.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[3]
WORK_BOUNDARY = ROOT / ".work/x86_64"
MODULE = ROOT / "compat/perf/x86_64_peers.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_x86_peers_smoke", MODULE)
assert SPEC is not None and SPEC.loader is not None
peers = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = peers
SPEC.loader.exec_module(peers)


class SmokeError(RuntimeError):
    """The pinned-native peer lifecycle did not meet its observable contract."""


NETWORK_ROWS = (
    ("loopback_tcp_ipv4_4k", "loopback_tcp_ipv4"),
    ("loopback_tcp_ipv6_4k", "loopback_tcp_ipv6"),
    ("loopback_udp_ipv4_4k", "loopback_udp_ipv4"),
    ("loopback_udp_ipv6_4k", "loopback_udp_ipv6"),
    ("resolver_hosts", "resolver_hosts"),
    ("resolver_dns_dual", "resolver_dns_dual"),
    ("resolver_dns_tcp", "resolver_dns_tcp"),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def bounded_fresh_work(value: Path | None) -> Path:
    boundary = WORK_BOUNDARY.resolve(strict=True)
    require(boundary.is_dir() and not boundary.is_symlink(), "native work boundary is not physical")
    if value is None:
        return Path(tempfile.mkdtemp(prefix="native-performance-peers-smoke-", dir=boundary))
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    require(".." not in candidate.parts, "smoke work path has parent traversal")
    absolute = Path(os.path.abspath(candidate))
    try:
        absolute.relative_to(boundary)
    except ValueError as error:
        raise SmokeError(f"smoke work path escapes {boundary}: {absolute}") from error
    require(not absolute.exists() and not absolute.is_symlink(), f"smoke work path must be fresh: {absolute}")
    absolute.mkdir(mode=0o700)
    require(absolute.resolve(strict=True) == absolute, "smoke work path is not physical")
    return absolute


def compile_network_fixture(compiler: str, output: Path) -> None:
    command = [
        compiler,
        "-static",
        # The pinned compiler otherwise chooses an ET_DYN static PIE that
        # faults before this fixture reaches main on the evidence image.
        "-no-pie",
        "-std=c11",
        "-D_GNU_SOURCE",
        "-O2",
        "-fno-builtin",
        "-fno-stack-protector",
        str(ROOT / "compat/perf/x86_64_network_workload.c"),
        "-o",
        str(output),
    ]
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    require(result.returncode == 0, f"network fixture compile failed: {result.stderr.decode('utf-8', errors='replace')}")
    require(output.is_file() and output.stat().st_mode & 0o111, "network fixture output is not executable")


def prepare_client_root(work: Path, row_id: str, binary: Path) -> Path:
    root = work / f"client-{row_id}"
    application = root / "app"
    application.mkdir(parents=True, mode=0o700)
    destination = application / "network"
    shutil.copy2(binary, destination)
    destination.chmod(0o755)
    return root


def run_client(chroot: str, client_root: Path, row: peers.NetworkRow, iterations: int) -> None:
    command = [chroot, str(client_root), "/app/network", row.mode, str(iterations), *row.argv]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    require(
        result.returncode == 0 and result.stdout == b"ok\n" and not result.stderr,
        "network fixture failed: "
        f"argv={command!r} status={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}",
    )


def run_row(
    work: Path,
    binary: Path,
    chroot: str,
    row_id: str,
    iterations: int,
    cpu: int,
    allowed: tuple[int, ...],
) -> dict[str, Any]:
    mode = dict(NETWORK_ROWS)[row_id]
    row = peers.load_network_row(ROOT, row_id, mode)
    client_root = prepare_client_root(work, row_id, binary)
    context = peers.start_context(
        ROOT,
        row_id=row.row_id,
        mode=row.mode,
        invocation_work=work / f"peer-{row_id}",
        client_root=client_root,
        cpu=cpu,
        allowed_affinity=allowed,
        iterations=iterations,
    )
    try:
        staged = context.stage_resolver_files()
        if row.requires_resolver_files:
            require(set(staged) == {"etc_resolv_conf_bytes", "etc_hosts_bytes"}, "resolver row did not stage both private files")
        else:
            require(staged == {}, "non-resolver row staged resolver files")
        run_client(chroot, client_root, row, iterations)
        evidence = context.stop()
        peers.validate_context(ROOT, evidence)
        return evidence
    except BaseException:
        context.stop()
        raise


def run_cleanup_smoke(work: Path, cpu: int, allowed: tuple[int, ...]) -> dict[str, Any]:
    client_root = work / "cleanup-client"
    client_root.mkdir(mode=0o700)
    context = peers.start_context(
        ROOT,
        row_id="loopback_udp_ipv4_4k",
        mode="loopback_udp_ipv4",
        invocation_work=work / "peer-cleanup",
        client_root=client_root,
        cpu=cpu,
        allowed_affinity=allowed,
        iterations=2,
    )
    try:
        raise SmokeError("deliberate primary client failure")
    except SmokeError:
        evidence = context.stop()
    require(evidence["status"] == "incomplete", "cleanup smoke unexpectedly completed its client route")
    peers.validate_context(ROOT, evidence, require_complete=False)
    return evidence


def run_smoke(compiler: str, work: Path) -> dict[str, Any]:
    chroot = shutil.which("chroot")
    require(chroot is not None and os.path.isabs(chroot), "pinned native smoke needs an absolute chroot command")
    allowed = tuple(sorted(os.sched_getaffinity(0)))
    require(allowed, "native smoke has no permitted CPU")
    binary = work / "network-static"
    compile_network_fixture(compiler, binary)
    records: dict[str, Any] = {}
    for row_id, _mode in NETWORK_ROWS:
        records[row_id] = run_row(work, binary, chroot, row_id, 2, allowed[0], allowed)
    records["exception_cleanup"] = run_cleanup_smoke(work, allowed[0], allowed)
    report = {
        "schema": "crabc.perf.x86_64-peer-smoke/v1",
        "work": str(work.relative_to(ROOT)),
        "rows": {
            row_id: {
                "status": record["status"],
                "record_file": record["record_file"],
                "event_summaries": record["event_summaries"],
            }
            for row_id, record in records.items()
        },
    }
    report_path = work / "peer-smoke-report.json"
    peers._write_json(report_path, report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument("--work", type=Path, default=None)
    arguments = parser.parse_args(argv)
    try:
        work = bounded_fresh_work(arguments.work)
        report = run_smoke(arguments.compiler, work)
    except (OSError, SmokeError, peers.PeerError, subprocess.TimeoutExpired) as error:
        print(f"x86_64 peer lifecycle smoke: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
