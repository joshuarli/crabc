#!/usr/bin/env python3
"""Compare pinned-musl and owned-static handling of a cyclic CNAME target."""

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
QUERY_NAME = "cycle.test"
RESOLV_CONF = b"nameserver 127.0.0.1\noptions ndots:1 timeout:1 attempts:1\n"


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


def cyclic_reply(query: bytes) -> bytes:
    name, record_type, end = question(query)
    if name != QUERY_NAME or record_type not in (1, 28):
        raise ValueError("unexpected DNS question")
    # The two-byte CNAME RDATA points to its own first byte, so expanding
    # the target must never complete or be interpreted as a valid hostname.
    target_offset = end + 12
    if target_offset >= 0x4000:
        raise ValueError("cycle pointer does not fit DNS compression format")
    pointer = bytes((0xC0 | (target_offset >> 8), target_offset & 0xFF))
    record = b"\xc0\x0c\0\x05\0\x01\0\0\0\x1e\0\x02" + pointer
    return query[:2] + b"\x81\x80\0\x01\0\x01\0\0\0\0" + query[12:end] + record


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
                    reply = cyclic_reply(query)
                    self.udp.sendto(reply, peer)
                    self.events.append({"transport": "udp", "action": "cname-self-pointer",
                                        "name": name, "type": record_type,
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
    oracle = arms["oracle"]
    expected_events = [{"transport": "udp", "action": "cname-self-pointer",
                        "name": QUERY_NAME, "type": record_type}
                       for record_type in (1, 28)]
    def route(arm: dict[str, object]) -> list[dict[str, object]]:
        return [{key: event[key] for key in ("transport", "action", "name", "type")}
                for event in arm["events"]]
    # Pinned musl leaves one of two internal parser errors in errno after
    # EAI_NODATA; repeated identical lookups expose both values.
    expected_outputs = [
        f"gai=-5 errno={errno} h_errno=3 a=- n4=0 aaaa=- n6=0 canon=-\n"
        for errno in (11, 22)
    ]
    bounded = all(arm["status"] == 0 and arm["elapsed_ms"] <= 1500 and
                  not arm["fixture_errors"] and route(arm) == expected_events and
                  arm["stdout"] in expected_outputs and arm["stderr"] == ""
                  for arm in arms.values())
    raw_equal = (args.candidate is not None and
                 all(oracle[field] == arms["candidate"][field]
                     for field in ("status", "stdout", "stderr")))
    passed = bounded
    source_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = json.loads((args.static_sysroot / "share/crabc/manifest.json").read_bytes()) if args.static_sysroot else None
    report = {"source_revision": source_revision,
              "source_sha256": manifest["source_sha256"] if manifest else None,
              "core_resolver_sha256": digest(ROOT / "crabc-core/src/resolver.rs"),
              "workload_sha256": digest(ROOT / "compat/x86_64/tests/resolver_cname_cycle.c"),
              "fixture_sha256": digest(ROOT / "compat/x86_64/tests/resolver_cname_cycle.py"),
              "oracle_sha256": digest(args.oracle),
              "candidate_sha256": digest(args.candidate) if args.candidate else None,
              "expected_outputs": expected_outputs, "expected_events": expected_events,
              "bounded": bounded, "raw_equal": raw_equal, "passed": passed,
              "arms": arms}
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": passed, "bounded": bounded, "raw_equal": raw_equal,
                      "report": str(work / "report.json")}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
