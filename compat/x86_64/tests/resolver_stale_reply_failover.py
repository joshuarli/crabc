#!/usr/bin/env python3
"""Compare late, wrong-ID, and wrong-source DNS replies across static resolvers."""

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
QUERY_NAME = "late.test"
RESOLV_CONF = b"nameserver 127.0.0.1\nnameserver 127.0.0.2\noptions ndots:1 timeout:1 attempts:1\n"


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


def answer(query: bytes, address: str, wrong_id: bool = False) -> bytes:
    name, record_type, end = question(query)
    if name != QUERY_NAME or record_type not in (1, 28):
        raise ValueError("unexpected DNS question")
    family = socket.AF_INET if record_type == 1 else socket.AF_INET6
    data = socket.inet_pton(family, address)
    transaction = query[:2]
    if wrong_id:
        transaction = ((int.from_bytes(transaction, "big") + 1) & 0xFFFF).to_bytes(2, "big")
    record = (b"\xc0\x0c" + record_type.to_bytes(2, "big") + b"\0\x01\0\0\0\x1e" +
              len(data).to_bytes(2, "big") + data)
    return transaction + b"\x81\x80\0\x01\0\x01\0\0\0\0" + query[12:end] + record


class DnsFixture:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.errors: list[str] = []
        self.stop = threading.Event()
        self.udp: dict[socket.socket, str] = {}
        for address, role in (("127.0.0.1", "first"), ("127.0.0.2", "second")):
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.bind((address, 53))
            self.udp[server] = role
        self.spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.spoof.bind(("127.0.0.3", 53))
        self.pending: dict[tuple[str, int], tuple[bytes, tuple[str, int]]] = {}
        self.sent: set[int] = set()
        self.worker = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self) -> DnsFixture:
        self.worker.start()
        return self

    def __exit__(self, *_unused: object) -> None:
        self.stop.set()
        self.worker.join(timeout=3)
        for server in (*self.udp, self.spoof):
            server.close()

    def event(self, role: str, action: str, record_type: int, query: bytes,
              reply: bytes | None = None) -> None:
        self.events.append({"role": role, "action": action, "name": QUERY_NAME,
                            "type": record_type, "query_id": int.from_bytes(query[:2], "big"),
                            "reply_id": int.from_bytes(reply[:2], "big") if reply else None})

    def release(self, record_type: int) -> None:
        if record_type in self.sent or any((role, record_type) not in self.pending
                                           for role in ("first", "second")):
            return
        first_query, first_peer = self.pending[("first", record_type)]
        second_query, second_peer = self.pending[("second", record_type)]
        self.sent.add(record_type)
        if record_type == 1:
            # The second query is the barrier: neither packet from the first
            # nameserver reaches the client before it has tried the second.
            wrong_source = answer(first_query, "203.0.113.99")
            self.spoof.sendto(wrong_source, first_peer)
            self.event("spoof", "same-id-wrong-source", record_type, first_query, wrong_source)
            valid = answer(first_query, "198.51.100.41")
            self.udp_by_role("first").sendto(valid, first_peer)
            self.event("first", "late-valid", record_type, first_query, valid)
        else:
            wrong_id = answer(first_query, "2001:db8::99", wrong_id=True)
            self.udp_by_role("first").sendto(wrong_id, first_peer)
            self.event("first", "late-wrong-id", record_type, first_query, wrong_id)
            valid = answer(second_query, "2001:db8::42")
            self.udp_by_role("second").sendto(valid, second_peer)
            self.event("second", "valid", record_type, second_query, valid)

    def udp_by_role(self, role: str) -> socket.socket:
        return next(server for server, label in self.udp.items() if label == role)

    def serve(self) -> None:
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select(list(self.udp), [], [], 0.1)
                for server in ready:
                    query, peer = server.recvfrom(2048)
                    name, record_type, _ = question(query)
                    if name != QUERY_NAME or record_type not in (1, 28):
                        raise ValueError("unexpected DNS question")
                    role = self.udp[server]
                    self.event(role, "query", record_type, query)
                    self.pending[(role, record_type)] = query, peer
                    self.release(record_type)
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


def route_complete(events: list[dict[str, object]]) -> bool:
    roster = {
        ("first", 1, "query"), ("second", 1, "query"),
        ("spoof", 1, "same-id-wrong-source"), ("first", 1, "late-valid"),
        ("first", 28, "query"), ("second", 28, "query"),
        ("first", 28, "late-wrong-id"), ("second", 28, "valid"),
    }
    if len(events) != len(roster):
        return False
    positions = {(event["role"], event["type"], event["action"]): index
                 for index, event in enumerate(events)}
    if set(positions) != roster or any(event["name"] != QUERY_NAME for event in events):
        return False
    for record_type, actions in (
        (1, (("first", "query"), ("second", "query"),
             ("spoof", "same-id-wrong-source"), ("first", "late-valid"))),
        (28, (("first", "query"), ("second", "query"),
              ("first", "late-wrong-id"), ("second", "valid"))),
    ):
        indices = [positions[(role, record_type, action)] for role, action in actions]
        if indices != sorted(indices):
            return False
    first_a = events[positions[("first", 1, "query")]]["query_id"]
    first_aaaa = events[positions[("first", 28, "query")]]["query_id"]
    second_aaaa = events[positions[("second", 28, "query")]]["query_id"]
    return (events[positions[("spoof", 1, "same-id-wrong-source")]]["reply_id"] == first_a and
            events[positions[("first", 1, "late-valid")]]["reply_id"] == first_a and
            events[positions[("first", 28, "late-wrong-id")]]["reply_id"] != first_aaaa and
            events[positions[("second", 28, "valid")]]["reply_id"] == second_aaaa)


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
    expected_stdout = ("gai=0 errno=101 h_errno=3 a=198.51.100.41 n4=2 "
                       "aaaa=2001:db8::42 n6=2 canon=late.test\n")
    route = all(arm["status"] == 0 and arm["stdout"] == expected_stdout and
                arm["stderr"] == "" and not arm["fixture_errors"] and
                arm["elapsed_ms"] <= 1500 and route_complete(arm["events"])
                for arm in arms.values())
    same = (args.candidate is not None and
            all(arms["oracle"][field] == arms["candidate"][field]
                for field in ("status", "stdout", "stderr")))
    passed = route and (same if args.candidate else True)
    source_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = json.loads((args.static_sysroot / "share/crabc/manifest.json").read_bytes()) if args.static_sysroot else None
    report = {"source_revision": source_revision,
              "source_sha256": manifest["source_sha256"] if manifest else None,
              "core_resolver_sha256": digest(ROOT / "crabc-core/src/resolver.rs"),
              "workload_sha256": digest(ROOT / "compat/x86_64/tests/resolver_stale_reply_failover.c"),
              "fixture_sha256": digest(ROOT / "compat/x86_64/tests/resolver_stale_reply_failover.py"),
              "oracle_sha256": digest(args.oracle),
              "candidate_sha256": digest(args.candidate) if args.candidate else None,
              "expected_stdout": expected_stdout, "route_complete": route,
              "raw_equal": same, "passed": passed, "arms": arms}
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": passed, "route_complete": route,
                      "raw_equal": same, "report": str(work / "report.json")}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
