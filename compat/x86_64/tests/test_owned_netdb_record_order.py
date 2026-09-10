#!/usr/bin/env python3
"""Packet-shape guard for the owned classic-netdb callback-order differential."""
from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SERVER_PATH = ROOT / "compat/resolver-network/dns_server.py"


def server_module():
    spec = importlib.util.spec_from_file_location("owned_record_order_dns", SERVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def query(name: str, qtype: int) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x5411, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def answers(packet: bytes) -> list[tuple[int, bytes]]:
    cursor = 12
    while packet[cursor]:
        cursor += packet[cursor] + 1
    cursor += 5
    count = struct.unpack_from("!H", packet, 6)[0]
    records = []
    for _ in range(count):
        assert packet[cursor:cursor + 2] == b"\xc0\x0c"
        rrtype, _class, _ttl, length = struct.unpack_from("!HHIH", packet, cursor + 2)
        cursor += 12
        records.append((rrtype, packet[cursor:cursor + length]))
        cursor += length
    assert cursor == len(packet), "the callback regression must be complete DNS framing"
    return records


class OwnedNetdbRecordOrderTests(unittest.TestCase):
    def test_selected_address_length_is_complete_but_stops_before_late_cname(self):
        server = server_module()
        for name, qtype, expected in (
            ("order-after.example.test.", 1, 4),
            ("order-aaaa.example.test.", 28, 16),
        ):
            with self.subTest(name=name):
                records = answers(server.encode_answer(query(name, qtype), 0x5411, name, qtype))
                self.assertEqual([(kind, len(value)) for kind, value in records],
                                 [(qtype, expected), (qtype, expected + 1), (5, 19)])

    def test_cname_and_address_cap_records_preserve_the_source_callback_order(self):
        server = server_module()
        before = answers(server.encode_answer(query("order-before.example.test.", 1), 0x5411,
                                              "order-before.example.test.", 1))
        self.assertEqual([(kind, len(value)) for kind, value in before],
                         [(5, 20), (1, 4), (1, 5), (5, 19)])
        capped = answers(server.encode_answer(query("order-cap.example.test.", 1), 0x5411,
                                              "order-cap.example.test.", 1))
        self.assertEqual(len(capped), 50)
        self.assertEqual([(kind, len(value)) for kind, value in capped[-2:]], [(1, 5), (5, 18)])


if __name__ == "__main__":
    unittest.main()
