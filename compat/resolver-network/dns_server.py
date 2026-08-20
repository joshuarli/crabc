#!/usr/bin/env python3
"""A deterministic DNS server for the resolver/network differential harness.

The server binds only loopback addresses.  It has three logical endpoints:

* ``valid`` answers the fixture's A/AAAA/CNAME/NXDOMAIN/NODATA/search questions
  and emits a deterministic UDP-truncated/TCP-complete response, but drops
  ``fallback.example.test.`` to make nameserver fallback observable;
* ``drop`` receives and records queries but never replies; and
* ``fallback`` is a second valid endpoint used by the fallback contract.

Each endpoint has UDP and TCP listeners on a fixed loopback role address at
port 53: ``valid`` is ``127.0.0.1``, ``drop`` is ``127.0.0.2``, and
``fallback`` is ``127.0.0.3``.  The workload's direct IPv6 cases remain
independent socket coverage; resolver configuration intentionally uses only
these private IPv4 nameservers.  The protocol deliberately uses no third-party
DNS package or network service.
"""

from __future__ import annotations

import argparse
import json
import os
import selectors
import signal
import socket
import struct
import sys
import tempfile
import threading
from pathlib import Path


PROTOCOL_VERSION = "resolver-network-dns-v1"
DNS_PORT = 53
ROLE_ADDRESSES = {
    "valid": "127.0.0.1",
    "drop": "127.0.0.2",
    "fallback": "127.0.0.3",
}
RECORDS: dict[tuple[str, int], tuple[str, bytes | None]] = {
    ("a.example.test.", 1): ("answer", socket.inet_aton("198.51.100.42")),
    ("aaaa.example.test.", 28): (
        "answer",
        socket.inet_pton(socket.AF_INET6, "2001:db8::42"),
    ),
    ("malformed.example.test.", 1): ("malformed-sequence", socket.inet_aton("198.51.100.43")),
    ("alias.example.test.", 1): ("cname", socket.inet_aton("198.51.100.44")),
    ("tc.example.test.", 1): ("tc-sequence", socket.inet_aton("198.51.100.45")),
    ("fallback.example.test.", 1): ("answer", socket.inet_aton("198.51.100.18")),
    ("searchhost.search.test.", 1): ("answer", socket.inet_aton("198.51.100.17")),
    ("nxdomain.example.test.", 1): ("nxdomain", None),
    ("nodata.example.test.", 1): ("nodata", None),
}


def atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def canonical_name(name: str) -> str:
    return name.rstrip(".").lower() + "."


def drops_query(role: str, name: str) -> bool:
    """Keep fallback observable even when a resolver chooses valid first."""
    return role == "drop" or (
        role == "valid" and name == "fallback.example.test."
    )


def decode_name(packet: bytes, offset: int) -> tuple[str, int] | None:
    """Decode the question name, accepting compression only defensively."""
    labels: list[str] = []
    cursor = offset
    jumped = False
    end = offset
    seen: set[int] = set()
    for _ in range(128):
        if cursor >= len(packet):
            return None
        size = packet[cursor]
        cursor += 1
        if size == 0:
            if not jumped:
                end = cursor
            return ".".join(labels) + ".", end
        if size & 0xC0 == 0xC0:
            if cursor >= len(packet):
                return None
            pointer = ((size & 0x3F) << 8) | packet[cursor]
            cursor += 1
            if pointer in seen:
                return None
            seen.add(pointer)
            if not jumped:
                end = cursor
                jumped = True
            cursor = pointer
            continue
        if size > 63 or cursor + size > len(packet):
            return None
        try:
            labels.append(packet[cursor : cursor + size].decode("ascii").lower())
        except UnicodeDecodeError:
            return None
        cursor += size
        if not jumped:
            end = cursor
    return None


def parse_question(packet: bytes) -> tuple[int, str, int, int] | None:
    if len(packet) < 12:
        return None
    identifier, flags, questions = struct.unpack("!HHH", packet[:6])
    if questions < 1:
        return None
    decoded = decode_name(packet, 12)
    if decoded is None:
        return None
    name, offset = decoded
    if offset + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return identifier, canonical_name(name), qtype, qclass


def question_section(packet: bytes) -> bytes:
    """Return exactly the first DNS question, excluding EDNS/additional data."""
    decoded = decode_name(packet, 12)
    if decoded is None:
        raise ValueError("malformed DNS question")
    _, offset = decoded
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    return packet[12 : offset + 4]


def encode_answer(
    question: bytes, identifier: int, name: str, qtype: int, complete: bool = False
) -> bytes:
    """Build a minimal DNS response using the original question verbatim."""
    question_bytes = question_section(question)
    behavior, value = RECORDS.get((name, qtype), ("nxdomain", None))
    if behavior == "nxdomain":
        flags = 0x8183  # response, recursion available, NXDOMAIN
        return struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 0) + question_bytes
    if behavior == "nodata":
        flags = 0x8180  # response, recursion available, NOERROR/NODATA
        return struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 0) + question_bytes
    if behavior == "tc-sequence" and not complete:
        # UDP callers receive this packet and must retry the same query over
        # TCP.  TCP callers use the complete answer below.
        flags = 0x8380  # response, recursion available, truncation, NOERROR
        return struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 0) + question_bytes
    if value is None:
        raise ValueError("answer record has no value")
    flags = 0x8180
    if behavior == "cname":
        target = b"\x06target\x07example\x04test\x00"
        answer_start = 12 + len(question_bytes)
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        target_offset = answer_start + 12
        address_owner = struct.pack("!H", 0xC000 | target_offset)
        address = address_owner + struct.pack("!HHIH", qtype, 1, 60, len(value)) + value
        return struct.pack("!HHHHHH", identifier, flags, 1, 2, 0, 0) + question_bytes + cname + address
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(value)) + value
    return struct.pack("!HHHHHH", identifier, flags, 1, 1, 0, 0) + question_bytes + answer


class LoopbackDnsServer:
    def __init__(self, events_path: Path | None) -> None:
        self.events_path = events_path
        self.selector = selectors.DefaultSelector()
        self.stop_event = threading.Event()
        self.events: list[dict[str, object]] = []
        self.events_lock = threading.Lock()
        self.sockets: list[socket.socket] = []
        self.endpoints: dict[str, dict[str, object]] = {}

    def _record(self, event: dict[str, object]) -> None:
        with self.events_lock:
            self.events.append(event)

    def _bind_endpoint(self, role: str) -> None:
        address = ROLE_ADDRESSES[role]
        udp4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp4.bind((address, DNS_PORT))
        tcp4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp4.bind((address, DNS_PORT))
        tcp4.listen(16)
        for sock in (udp4, tcp4):
            sock.setblocking(False)
            self.sockets.append(sock)
        endpoint = {
            "port": DNS_PORT,
            "ipv4": address,
            "udp4_port": DNS_PORT,
            "tcp4_port": DNS_PORT,
        }
        self.endpoints[role] = endpoint
        self.selector.register(udp4, selectors.EVENT_READ, (role, "ipv4", "udp"))
        self.selector.register(tcp4, selectors.EVENT_READ, (role, "ipv4", "tcp"))

    def start(self) -> None:
        for role in ("valid", "drop", "fallback"):
            self._bind_endpoint(role)
        ready = {
            "schema_version": 1,
            "protocol": PROTOCOL_VERSION,
            "endpoints": self.endpoints,
        }
        print(json.dumps(ready, sort_keys=True), flush=True)

    def _response_packets(
        self, packet: bytes, name: str, qtype: int, identifier: int, transport: str
    ) -> list[bytes]:
        behavior, _ = RECORDS.get((name, qtype), ("nxdomain", None))
        valid = encode_answer(
            packet, identifier, name, qtype, complete=behavior == "tc-sequence" and transport == "tcp"
        )
        if behavior == "malformed-sequence":
            # Three datagrams in one receive order: a short malformed packet,
            # a syntactically valid answer with the wrong ID, then the answer
            # matching the request ID.  No sleeps or randomness are involved.
            wrong = encode_answer(packet, (identifier + 1) & 0xFFFF, name, qtype)
            return [b"\x00\x01\x80", wrong, valid]
        return [valid]

    def _handle_datagram(self, sock: socket.socket, role: str, family: str) -> None:
        try:
            packet, peer = sock.recvfrom(65535)
        except OSError:
            return
        question = parse_question(packet)
        if question is None:
            self._record({"role": role, "family": family, "transport": "udp", "action": "malformed-query"})
            return
        identifier, name, qtype, qclass = question
        event: dict[str, object] = {
            "role": role,
            "family": family,
            "transport": "udp",
            "name": name,
            "qtype": qtype,
            "qclass": qclass,
        }
        if drops_query(role, name):
            event["action"] = "drop"
            if role == "valid":
                event["drop_reason"] = "fallback"
            self._record(event)
            return
        behavior, _ = RECORDS.get((name, qtype), ("nxdomain", None))
        event["action"] = behavior
        self._record(event)
        for response in self._response_packets(packet, name, qtype, identifier, "udp"):
            try:
                sock.sendto(response, peer)
            except OSError:
                return

    def _serve_tcp_connection(self, connection: socket.socket, role: str, family: str) -> None:
        try:
            header = self._recv_exact(connection, 2)
            if header is None:
                return
            length = struct.unpack("!H", header)[0]
            packet = self._recv_exact(connection, length)
            if packet is None:
                return
            question = parse_question(packet)
            if question is None:
                self._record({"role": role, "family": family, "transport": "tcp", "action": "malformed-query"})
                return
            identifier, name, qtype, qclass = question
            event: dict[str, object] = {
                "role": role,
                "family": family,
                "transport": "tcp",
                "name": name,
                "qtype": qtype,
                "qclass": qclass,
            }
            if drops_query(role, name):
                event["action"] = "drop"
                if role == "valid":
                    event["drop_reason"] = "fallback"
                self._record(event)
                return
            behavior, _ = RECORDS.get((name, qtype), ("nxdomain", None))
            event["action"] = "answer" if behavior == "tc-sequence" else behavior
            self._record(event)
            for response in self._response_packets(packet, name, qtype, identifier, "tcp"):
                connection.sendall(struct.pack("!H", len(response)) + response)
        except OSError:
            return
        finally:
            connection.close()

    @staticmethod
    def _recv_exact(connection: socket.socket, length: int) -> bytes | None:
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            if not chunk:
                return None
            result.extend(chunk)
        return bytes(result)

    def run(self) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                for key, _ in self.selector.select(timeout=0.1):
                    sock = key.fileobj
                    role, family, transport = key.data
                    if transport == "udp":
                        self._handle_datagram(sock, role, family)
                    else:
                        try:
                            connection, _ = sock.accept()
                            connection.settimeout(2.0)
                        except OSError:
                            continue
                        thread = threading.Thread(
                            target=self._serve_tcp_connection,
                            args=(connection, role, family),
                            daemon=True,
                        )
                        thread.start()
        finally:
            for sock in self.sockets:
                try:
                    self.selector.unregister(sock)
                except (KeyError, ValueError):
                    pass
                sock.close()
            self.selector.close()
            if self.events_path is not None:
                with self.events_lock:
                    events = list(self.events)
                atomic_write_json(self.events_path, {"schema_version": 1, "events": events})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True, help="atomic event-log destination")
    args = parser.parse_args()
    server = LoopbackDnsServer(args.events)

    def stop(_signum: int, _frame: object) -> None:
        server.stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.run()
    except OSError as error:
        print(f"dns-server: setup failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
