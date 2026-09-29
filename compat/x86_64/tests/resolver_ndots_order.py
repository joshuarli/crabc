#!/usr/bin/env python3
"""Compare search-first ndots resolution against pinned musl."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import threading
import time


ROOT = Path(__file__).resolve().parents[3]
ABSOLUTE_NAME = "alpha.beta"
SEARCH_NAME = "alpha.beta.search.test"
RESOLV_CONF = b"nameserver 127.0.0.1\nsearch search.test\noptions ndots:2 timeout:1 attempts:1\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def question(packet: bytes) -> tuple[str, int, int]:
    if len(packet) < 17 or packet[4:6] != b"\0\1":
        raise ValueError("DNS query has no single complete question")
    parts: list[str] = []
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("DNS query name is incomplete")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            raise ValueError("DNS query label is invalid")
        parts.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    if offset + 4 != len(packet) or packet[offset + 2:offset + 4] != b"\0\1":
        raise ValueError("DNS query type or class is invalid")
    return ".".join(parts), int.from_bytes(packet[offset:offset + 2], "big"), offset + 4


def dns_reply(query: bytes) -> tuple[bytes, str]:
    name, record_type, end = question(query)
    if record_type not in (1, 28):
        raise ValueError("unexpected DNS type")
    if name == SEARCH_NAME:
        return query[:2] + b"\x81\x83\0\x01\0\0\0\0\0\0" + query[12:end], "nxdomain"
    if name != ABSOLUTE_NAME:
        raise ValueError("unexpected DNS name")
    address = "198.51.100.23" if record_type == 1 else "2001:db8::23"
    family = socket.AF_INET if record_type == 1 else socket.AF_INET6
    data = socket.inet_pton(family, address)
    record = (b"\xc0\x0c" + record_type.to_bytes(2, "big") + b"\0\x01\0\0\0\x1e" +
              len(data).to_bytes(2, "big") + data)
    return query[:2] + b"\x81\x80\0\x01\0\x01\0\0\0\0" + query[12:end] + record, "answer"


class DnsFixture:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.errors: list[str] = []
        self.stop = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 53))
        self.worker = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self) -> DnsFixture:
        self.worker.start()
        return self

    def __exit__(self, *_unused: object) -> None:
        self.stop.set()
        self.worker.join(timeout=3)
        self.udp.close()

    def serve(self) -> None:
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.udp], [], [], 0.1)
                if ready:
                    query, peer = self.udp.recvfrom(2048)
                    name, record_type, _ = question(query)
                    reply, action = dns_reply(query)
                    self.udp.sendto(reply, peer)
                    self.events.append({"name": name, "type": record_type,
                                        "action": action,
                                        "query_id": int.from_bytes(query[:2], "big"),
                                        "reply_id": int.from_bytes(reply[:2], "big"),
                                        "reply_sha256": hashlib.sha256(reply).hexdigest()})
        except (OSError, ValueError) as error:
            self.errors.append(str(error))


def isolated_network() -> None:
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:] if ":" in line}
    if interfaces != {"lo"} or os.geteuid() != 0:
        raise ValueError("fixture requires root and a loopback-only network namespace")
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if any(row.split()[1:3] == ["00000000", "00000000"] for row in routes):
        raise ValueError("fixture refuses a default network route")


def run_arm(binary: Path, root: Path) -> dict[str, object]:
    root.mkdir()
    (root / "etc").mkdir()
    shutil.copy2(binary, root / "workload")
    (root / "etc/hosts").write_bytes(b"127.0.0.1 localhost\n::1 localhost\n")
    (root / "etc/resolv.conf").write_bytes(RESOLV_CONF)
    with DnsFixture() as fixture:
        started = time.monotonic()
        try:
            result = subprocess.run(["/usr/sbin/chroot", str(root), "/workload"],
                                    capture_output=True, timeout=5, check=False)
            status: int | str = result.returncode
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            status = "timeout"
            stdout, stderr = error.stdout or b"", error.stderr or b""
        elapsed_ms = round((time.monotonic() - started) * 1000)
        time.sleep(0.1)
    return {"status": status, "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"), "elapsed_ms": elapsed_ms,
            "events": fixture.events, "fixture_errors": fixture.errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--static-sysroot", type=Path)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    isolated_network()
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / ".work") or work.exists():
        parser.error("work must be a fresh checkout-local .work path")
    if args.candidate is not None and args.static_sysroot is None:
        parser.error("candidate requires static-sysroot")
    work.mkdir(parents=True)
    binaries = [("oracle", args.oracle)]
    if args.candidate is not None:
        binaries.append(("candidate", args.candidate))
    arms = {label: run_arm(binary.resolve(strict=True), work / label)
            for label, binary in binaries}
    expected_events = [
        {"name": name, "type": record_type, "action": action}
        for name, action in ((SEARCH_NAME, "nxdomain"), (ABSOLUTE_NAME, "answer"))
        for record_type in (1, 28)
    ]
    expected_stdout = ("gai=0 errno=101 h_errno=3 a=198.51.100.23 n4=2 "
                       "aaaa=2001:db8::23 n6=2 canon=alpha.beta\n")
    def route(arm: dict[str, object]) -> list[dict[str, object]]:
        return [{key: event[key] for key in ("name", "type", "action")}
                for event in arm["events"]]
    behavior = all(arm["status"] == 0 and arm["stdout"] == expected_stdout and
                   arm["stderr"] == "" and not arm["fixture_errors"] and
                   arm["elapsed_ms"] <= 1500 and route(arm) == expected_events and
                   all(event["query_id"] == event["reply_id"] for event in arm["events"])
                   for arm in arms.values())
    same = (args.candidate is not None and
            all(arms["oracle"][field] == arms["candidate"][field]
                for field in ("status", "stdout", "stderr")))
    passed = behavior and (same if args.candidate else True)
    source_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = json.loads((args.static_sysroot / "share/crabc/manifest.json").read_bytes()) if args.static_sysroot else None
    report = {"source_revision": source_revision,
              "source_sha256": manifest["source_sha256"] if manifest else None,
              "core_resolver_sha256": digest(ROOT / "crabc-core/src/resolver.rs"),
              "workload_sha256": digest(ROOT / "compat/x86_64/tests/resolver_ndots_order.c"),
              "fixture_sha256": digest(ROOT / "compat/x86_64/tests/resolver_ndots_order.py"),
              "oracle_sha256": digest(args.oracle),
              "candidate_sha256": digest(args.candidate) if args.candidate else None,
              "expected_events": expected_events, "expected_stdout": expected_stdout,
              "behavior_observed": behavior, "raw_equal": same, "passed": passed,
              "arms": arms}
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": passed, "behavior_observed": behavior,
                      "raw_equal": same, "report": str(work / "report.json")}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
