#!/usr/bin/env python3
"""Compare one pinned-musl C object across local resolver products."""

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
QUERY_NAME = "chain.search.test"
MIDDLE_NAME = "middle.search.test"
FINAL_NAME = "target.search.test"
SEARCH_REPLY = b"nameserver 127.0.0.1\nnameserver 127.0.0.2\nsearch search.test\noptions ndots:1 timeout:1 attempts:1\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wire_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"


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


def dns_reply(query: bytes, kind: str) -> bytes:
    name, record_type, end = question(query)
    if kind == "tc":
        return query[:2] + b"\x83\x80\0\1\0\0\0\0\0\0" + query[12:end]
    if kind == "nxdomain" or name != QUERY_NAME or record_type not in (1, 28):
        return query[:2] + b"\x81\x83\0\1\0\0\0\0\0\0" + query[12:end]

    def record(owner: bytes, rr_type: int, data: bytes) -> bytes:
        return owner + rr_type.to_bytes(2, "big") + b"\0\1\0\0\0\x1e" + len(data).to_bytes(2, "big") + data

    terminal = socket.inet_pton(socket.AF_INET if record_type == 1 else socket.AF_INET6,
                                "198.51.100.77" if record_type == 1 else "2001:db8::77")
    answers = b"".join((
        record(b"\xc0\x0c", 5, wire_name(MIDDLE_NAME)),
        record(wire_name(MIDDLE_NAME), 5, wire_name(FINAL_NAME)),
        record(wire_name(FINAL_NAME), record_type, terminal),
    ))
    return query[:2] + b"\x81\x80\0\1\0\3\0\0\0\0" + query[12:end] + answers


def read_exact(stream: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        block = stream.recv(count - len(data))
        if not block:
            raise ValueError("TCP DNS frame ended early")
        data.extend(block)
    return bytes(data)


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
        self.tcp: dict[socket.socket, str] = {}
        for address, role in (("127.0.0.1", "first"), ("127.0.0.2", "second")):
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, 53))
            server.listen(8)
            self.tcp[server] = role
        self.worker = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self) -> DnsFixture:
        self.worker.start()
        return self

    def __exit__(self, *_unused: object) -> None:
        self.stop.set()
        self.worker.join(timeout=3)
        for server in (*self.udp, *self.tcp):
            server.close()

    def serve(self) -> None:
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([*self.udp, *self.tcp], [], [], 0.1)
                for server in ready:
                    if server in self.tcp:
                        stream, _ = server.accept()
                        with stream:
                            stream.settimeout(2)
                            length = int.from_bytes(read_exact(stream, 2), "big")
                            query = read_exact(stream, length)
                            name, record_type, _ = question(query)
                            role = self.tcp[server]
                            if role == "first":
                                # The announced DNS frame is longer than the bytes sent.
                                stream.sendall(b"\0\x20\x12\x34\x81\x80")
                                action = "short-frame"
                            else:
                                response = dns_reply(query, "answer")
                                stream.sendall(len(response).to_bytes(2, "big") + response)
                                action = "cname-chain" if name == QUERY_NAME else "nxdomain"
                            self.events.append({"role": role, "transport": "tcp", "action": action, "name": name, "type": record_type})
                    else:
                        query, peer = server.recvfrom(2048)
                        name, record_type, _ = question(query)
                        role = self.udp[server]
                        action = "tc" if name == QUERY_NAME else "nxdomain"
                        server.sendto(dns_reply(query, action), peer)
                        self.events.append({"role": role, "transport": "udp", "action": action, "name": name, "type": record_type})
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
    (root / "etc/resolv.conf").write_bytes(SEARCH_REPLY)
    with DnsFixture() as fixture:
        try:
            result = subprocess.run(["/usr/sbin/chroot", str(root), "/workload"],
                                    capture_output=True, timeout=20, check=False)
            status: int | str = result.returncode
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            status = "timeout"
            stdout, stderr = error.stdout or b"", error.stderr or b""
        time.sleep(0.1)
    return {"status": status, "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"), "events": fixture.events,
            "fixture_errors": fixture.errors}


def oracle_route(events: list[dict[str, object]]) -> bool:
    expected = [
        {"role": role, "transport": transport, "action": action,
         "name": QUERY_NAME, "type": record_type}
        for role, transport, action, record_type in (
            ("first", "udp", "tc", 1),
            ("second", "udp", "tc", 1),
            ("first", "udp", "tc", 28),
            ("second", "udp", "tc", 28),
            ("first", "tcp", "short-frame", 1),
            ("first", "tcp", "short-frame", 28),
        )
    ]
    return events == expected


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
    work.mkdir(parents=True)
    if args.candidate is not None and args.static_sysroot is None:
        parser.error("candidate requires static-sysroot")
    binaries = [("oracle", args.oracle)]
    if args.candidate is not None:
        binaries.append(("candidate", args.candidate))
    results = {label: run_arm(binary.resolve(strict=True), work / label)
               for label, binary in binaries}
    oracle = results["oracle"]
    expected_result = oracle["stdout"] == "gai=-3 errno=115 h_errno=3 a=- n4=0 aaaa=- n6=0 canon=-\n"
    behavior = (expected_result and oracle["status"] == 0 and
                not oracle["fixture_errors"] and oracle_route(oracle["events"]))
    same = args.candidate is not None and all(oracle[field] == results["candidate"][field]
                                               for field in ("status", "stdout", "stderr", "events"))
    source_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = json.loads((args.static_sysroot / "share/crabc/manifest.json").read_bytes()) if args.static_sysroot else None
    report = {"source_revision": source_revision,
              "source_sha256": manifest["source_sha256"] if manifest else None,
              "core_resolver_sha256": digest(ROOT / "crabc-core/src/resolver.rs"),
              "workload_sha256": digest(ROOT / "compat/x86_64/tests/resolver_tcp_failover.c"),
              "fixture_sha256": digest(ROOT / "compat/x86_64/tests/resolver_tcp_failover.py"),
              "oracle_sha256": digest(args.oracle),
              "candidate_sha256": digest(args.candidate) if args.candidate else None,
              "expected_result": expected_result, "behavior_observed": behavior,
              "raw_equal": same, "arms": results}
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    passed = behavior and (same if args.candidate else True)
    print(json.dumps({"passed": passed, "behavior_observed": behavior,
                      "raw_equal": same, "report": str(work / "report.json")}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
