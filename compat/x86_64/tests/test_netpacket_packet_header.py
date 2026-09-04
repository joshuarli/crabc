#!/usr/bin/env python3
"""Focused x86 regression for the Linux packet header declaration/layout slice."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "netpacket" / "packet.h"


class NetpacketPacketHeaderTests(unittest.TestCase):
    def test_packet_header_exposes_the_musl_packet_vocabulary(self) -> None:
        header = HEADER.read_text(encoding="utf-8")

        self.assertIn("struct packet_mreq {", header)
        self.assertIn("int mr_ifindex;", header)
        self.assertIn("unsigned short int mr_type;", header)
        self.assertIn("unsigned short int mr_alen;", header)
        self.assertIn("unsigned char mr_address[8];", header)

        expected_macros = {
            "PACKET_ADD_MEMBERSHIP": 1,
            "PACKET_DROP_MEMBERSHIP": 2,
            "PACKET_RECV_OUTPUT": 3,
            "PACKET_RX_RING": 5,
            "PACKET_STATISTICS": 6,
            "PACKET_COPY_THRESH": 7,
            "PACKET_AUXDATA": 8,
            "PACKET_ORIGDEV": 9,
            "PACKET_VERSION": 10,
            "PACKET_HDRLEN": 11,
            "PACKET_RESERVE": 12,
            "PACKET_TX_RING": 13,
            "PACKET_LOSS": 14,
            "PACKET_VNET_HDR": 15,
            "PACKET_TX_TIMESTAMP": 16,
            "PACKET_TIMESTAMP": 17,
            "PACKET_FANOUT": 18,
            "PACKET_TX_HAS_OFF": 19,
            "PACKET_QDISC_BYPASS": 20,
            "PACKET_ROLLOVER_STATS": 21,
            "PACKET_FANOUT_DATA": 22,
            "PACKET_IGNORE_OUTGOING": 23,
            "PACKET_MR_MULTICAST": 0,
            "PACKET_MR_PROMISC": 1,
            "PACKET_MR_ALLMULTI": 2,
            "PACKET_MR_UNICAST": 3,
        }
        for name, value in expected_macros.items():
            self.assertIn(f"#define {name} {value}", header)

    def test_packet_header_compiles_constants_and_mreq_layout_in_c_and_cpp(self) -> None:
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler, "focused packet-header regression requires clang")
        assert compiler is not None

        c_source = r"""
#include <netpacket/packet.h>

_Static_assert(PACKET_ADD_MEMBERSHIP == 1 && PACKET_DROP_MEMBERSHIP == 2 &&
    PACKET_RECV_OUTPUT == 3 && PACKET_RX_RING == 5 && PACKET_STATISTICS == 6 &&
    PACKET_COPY_THRESH == 7 && PACKET_AUXDATA == 8 && PACKET_ORIGDEV == 9 &&
    PACKET_VERSION == 10 && PACKET_HDRLEN == 11 && PACKET_RESERVE == 12 &&
    PACKET_TX_RING == 13 && PACKET_LOSS == 14 && PACKET_VNET_HDR == 15 &&
    PACKET_TX_TIMESTAMP == 16 && PACKET_TIMESTAMP == 17 && PACKET_FANOUT == 18 &&
    PACKET_TX_HAS_OFF == 19 && PACKET_QDISC_BYPASS == 20 &&
    PACKET_ROLLOVER_STATS == 21 && PACKET_FANOUT_DATA == 22 &&
    PACKET_IGNORE_OUTGOING == 23, "packet option values");
_Static_assert(PACKET_MR_MULTICAST == 0 && PACKET_MR_PROMISC == 1 &&
    PACKET_MR_ALLMULTI == 2 && PACKET_MR_UNICAST == 3, "packet membership values");
_Static_assert(sizeof(struct packet_mreq) == 16 && _Alignof(struct packet_mreq) == 4 &&
    __builtin_offsetof(struct packet_mreq, mr_ifindex) == 0 &&
    __builtin_offsetof(struct packet_mreq, mr_type) == 4 &&
    __builtin_offsetof(struct packet_mreq, mr_alen) == 6 &&
    __builtin_offsetof(struct packet_mreq, mr_address) == 8,
    "packet_mreq x86 layout");
"""
        cpp_source = c_source.replace("_Static_assert", "static_assert").replace(
            "_Alignof(struct packet_mreq)", "alignof(struct packet_mreq)"
        )

        for language, source in (("C", c_source), ("C++", cpp_source)):
            result = subprocess.run(
                [
                    compiler,
                    "-x",
                    "c" if language == "C" else "c++",
                    "-std=c11" if language == "C" else "-std=c++17",
                    "-fsyntax-only",
                    "-nostdinc",
                    "-nostdinc++",
                    "-I",
                    str(ROOT / "include"),
                    "-",
                ],
                cwd=ROOT,
                input=source,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"{language} compile failed: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
