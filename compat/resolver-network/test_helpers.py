#!/usr/bin/env python3
"""Small stdlib-only contract tests for the resolver/network helpers."""

from __future__ import annotations

import importlib.util
import json
import itertools
import socket
import struct
import tempfile
import unittest
from unittest import mock
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dns_server = load_module("resolver_network_dns_server", "dns_server.py")
runner = load_module("resolver_network_runner", "run.py")
native_runner = load_module("resolver_network_native_runner", "run_x86_64.py")


def question(name: str, identifier: int = 7) -> bytes:
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", identifier, 0x100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", 1, 1)


class DnsHelperTests(unittest.TestCase):
    def test_tc_failover_waits_for_both_drop_routes_in_every_receive_order(self) -> None:
        for order in itertools.permutations(("valid", "drop", "fallback")):
            with self.subTest(order=order):
                server = dns_server.LoopbackDnsServer(None)
                self.addCleanup(server.selector.close)
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.addCleanup(client.close)
                client.bind(("127.0.0.1", 0))
                endpoints = {}
                for role in order:
                    endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.addCleanup(endpoint.close)
                    endpoint.bind(("127.0.0.1", 0))
                    endpoints[role] = endpoint
                request = question("tc-failover.example.test")
                observed = set()
                for role in order:
                    client.sendto(request, endpoints[role].getsockname())
                    server._handle_datagram(endpoints[role], role, "ipv4")
                    observed.add(role)
                    if len(observed) < 3:
                        with self.assertRaises(BlockingIOError):
                            client.recv(65535, socket.MSG_DONTWAIT)
                truncated = client.recv(65535, socket.MSG_DONTWAIT)
                self.assertEqual(truncated, dns_server.encode_answer(
                    request, 7, "tc-failover.example.test.", 1))
                connection, tcp_client = socket.socketpair()
                self.addCleanup(connection.close)
                self.addCleanup(tcp_client.close)
                tcp_client.sendall(struct.pack("!H", len(request)) + request)
                server._serve_tcp_connection(connection, "fallback", "ipv4")
                complete = dns_server.encode_answer(
                    request, 7, "tc-failover.example.test.", 1, complete=True)
                self.assertEqual(tcp_client.recv(65535), struct.pack("!H", len(complete)) + complete)
                self.assertTrue(native_runner.tc_failover_provenance(server.events))

    def test_tc_failover_drops_cannot_release_another_client_or_request(self) -> None:
        server = dns_server.LoopbackDnsServer(None)
        self.addCleanup(server.selector.close)
        clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        endpoints = {role: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                     for role in ("valid", "drop", "fallback")}
        for sock in (*clients, *endpoints.values()):
            self.addCleanup(sock.close)
            sock.bind(("127.0.0.1", 0))
        request = question("tc-failover.example.test")
        clients[0].sendto(request, endpoints["fallback"].getsockname())
        server._handle_datagram(endpoints["fallback"], "fallback", "ipv4")
        for client, packet in ((clients[1], request),
                               (clients[0], question("tc-failover.example.test", 8))):
            for role in ("valid", "drop"):
                client.sendto(packet, endpoints[role].getsockname())
                server._handle_datagram(endpoints[role], role, "ipv4")
            with self.assertRaises(BlockingIOError):
                clients[0].recv(65535, socket.MSG_DONTWAIT)
        for role in ("valid", "drop"):
            clients[0].sendto(request, endpoints[role].getsockname())
            server._handle_datagram(endpoints[role], role, "ipv4")
        self.assertEqual(clients[0].recv(65535, socket.MSG_DONTWAIT),
                         dns_server.encode_answer(request, 7, "tc-failover.example.test.", 1))

    def test_question_parser_canonicalizes_name(self) -> None:
        parsed = dns_server.parse_question(question("A.Example.Test"))
        self.assertEqual(parsed, (7, "a.example.test.", 1, 1))

    def test_cname_response_has_cname_and_target_address(self) -> None:
        packet = dns_server.encode_answer(
            question("alias.example.test"), 7, "alias.example.test.", 1
        )
        self.assertEqual(struct.unpack("!H", packet[6:8])[0], 2)
        self.assertIn(b"\x00\x05", packet)  # CNAME RR type
        self.assertTrue(packet.endswith(b"\xc6\x33\x64\x2c"))

    def test_answer_excludes_query_additional_records(self) -> None:
        query = bytearray(question("a.example.test"))
        query[10:12] = b"\x00\x01"  # one EDNS/additional record in the query
        query.extend(b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00")
        packet = dns_server.encode_answer(bytes(query), 7, "a.example.test.", 1)
        self.assertEqual(struct.unpack("!H", packet[10:12])[0], 0)
        self.assertEqual(struct.unpack("!H", packet[6:8])[0], 1)

    def test_tc_response_is_udp_truncated_but_tcp_complete(self) -> None:
        udp = dns_server.encode_answer(question("tc.example.test"), 7, "tc.example.test.", 1)
        tcp = dns_server.encode_answer(
            question("tc.example.test"), 7, "tc.example.test.", 1, complete=True
        )
        self.assertTrue(struct.unpack("!H", udp[2:4])[0] & 0x0200)
        self.assertEqual(struct.unpack("!H", udp[6:8])[0], 0)
        self.assertFalse(struct.unpack("!H", tcp[2:4])[0] & 0x0200)
        self.assertEqual(struct.unpack("!H", tcp[6:8])[0], 1)

    def test_valid_endpoint_drops_only_fallback_name(self) -> None:
        self.assertTrue(dns_server.drops_query("valid", "fallback.example.test."))
        self.assertFalse(dns_server.drops_query("valid", "a.example.test."))
        self.assertTrue(dns_server.drops_query("drop", "a.example.test."))


class RunnerHelperTests(unittest.TestCase):
    def test_runner_requires_isolation_marker(self) -> None:
        with mock.patch.dict(runner.os.environ, {}, clear=True):
            with self.assertRaises(runner.RunnerError):
                runner.require_isolated_environment()

    def test_private_resolver_file_is_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resolv.conf"
            original = b"nameserver 192.0.2.1\n"
            path.write_bytes(original)
            with mock.patch.object(runner, "RESOLV_CONF", path), mock.patch.dict(
                runner.os.environ, {runner.ISOLATED_MARKER: "1"}, clear=True
            ):
                with runner.isolated_resolver_config():
                    self.assertEqual(path.read_text(encoding="ascii"), runner.RESOLVER_CONFIG)
                self.assertEqual(path.read_bytes(), original)

    def test_expected_contract_names_include_new_dns_cases(self) -> None:
        self.assertIn("resolver.cname", runner.EXPECTED_SUBCASES)
        self.assertIn("resolver.tc-tcp", runner.EXPECTED_SUBCASES)
        self.assertIn("network.ancillary-scm-rights", runner.EXPECTED_SUBCASES)
        self.assertIn("network.epoll", runner.EXPECTED_SUBCASES)
        self.assertIn("network.shutdown-half-close", runner.EXPECTED_SUBCASES)
        self.assertIn("network.partial-send", runner.EXPECTED_SUBCASES)
        self.assertIn("network.socket-timeout", runner.EXPECTED_SUBCASES)
        self.assertIn("network.eintr", runner.EXPECTED_SUBCASES)
        self.assertIn("alias.example.test.", runner.REQUIRED_SERVER_NAMES)
        self.assertIn("tc.example.test.", runner.REQUIRED_SERVER_NAMES)

    def test_atomic_report_is_complete_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            runner.atomic_write_json(path, {"schema_version": 1, "passed": True})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["passed"], True)

    def test_event_contract_requires_tc_tcp_pair(self) -> None:
        events = [
            {"name": name, "action": "answer", "role": "valid"}
            for name in runner.REQUIRED_SERVER_NAMES
        ]
        events.extend(
            [
                {"name": "malformed.example.test.", "action": "malformed-sequence"},
                {"role": "drop", "action": "drop"},
                {"role": "drop", "action": "drop"},
                {"name": "fallback.example.test.", "role": "fallback", "action": "answer"},
                {"name": "fallback.example.test.", "role": "fallback", "action": "answer"},
                {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
                {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
                {"name": "alias.example.test.", "action": "cname"},
                {"name": "tc.example.test.", "transport": "udp", "action": "tc-sequence"},
            ]
        )
        self.assertFalse(runner.event_contract(events)["passed"])
        events.append({"name": "tc.example.test.", "transport": "tcp", "action": "answer"})
        events.append({"name": "tc.example.test.", "transport": "tcp", "action": "answer"})
        self.assertTrue(runner.event_contract(events)["passed"])


if __name__ == "__main__":
    unittest.main()
