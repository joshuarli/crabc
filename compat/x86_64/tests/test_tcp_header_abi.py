#!/usr/bin/env python3
"""Focused structural contract for the x86 pinned-musl <netinet/tcp.h> matrix."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
C_PROBE = ROOT / "compat" / "x86_64" / "tcp_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "tcp_header_abi_probe.cpp"
RUNNER = ROOT / "compat" / "x86_64" / "run_tcp_header_abi.sh"
TCP_HEADER = ROOT / "include" / "netinet" / "tcp.h"


class TcpHeaderAbiTests(unittest.TestCase):
    def test_x86_header_preserves_musl_body_and_historical_fallback(self) -> None:
        header = TCP_HEADER.read_text(encoding="utf-8")

        self.assertTrue(header.startswith("#ifndef _NETINET_TCP_H\n"))
        self.assertIn("#if defined(__x86_64__)\n", header)
        self.assertIn("#include <features.h>\n", header)
        self.assertIn("#define TCP_NODELAY 1\n", header)
        self.assertIn("#define TCP_TX_DELAY     37\n", header)
        self.assertIn("TCP_NLA_TTL,\n", header)
        self.assertIn("struct tcphdr {\n", header)
        self.assertIn("struct tcp_info {\n", header)
        self.assertIn("struct tcp_md5sig {\n", header)
        self.assertIn("struct tcp_diag_md5sig {\n", header)
        self.assertIn("struct tcp_repair_window {\n", header)
        self.assertIn("struct tcp_zerocopy_receive {\n", header)

        self.assertEqual(header.count("#define TCP_NODELAY 1\n"), 2)
        self.assertIn(
            "#else\n#define TCP_NODELAY 1\n#endif\n\n#endif\n",
            header,
        )

    def test_probes_cover_unconditional_and_gated_tcp_abi(self) -> None:
        c_probe = C_PROBE.read_text(encoding="utf-8")
        cxx_probe = CXX_PROBE.read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            self.assertIn("#include <netinet/tcp.h>", probe)
            for phrase in (
                "TCP_TX_DELAY == 37",
                "TCP_NLA_TTL == 26",
                "TCPOPT_EOL == 0",
                "SOL_TCP == 6",
                "tcphdr_gnu_aliases",
            ):
                self.assertIn(phrase, probe)
            self.assertNotIn("main(", probe)

        for phrase in (
            "sizeof(struct tcphdr) == 20",
            "_Alignof(struct tcphdr) == 4",
            "sizeof(struct tcp_info) == 232",
            "sizeof(struct tcp_md5sig) == 216",
            "sizeof(struct tcp_diag_md5sig) == 100",
            "sizeof(struct tcp_repair_window) == 20",
            "sizeof(struct tcp_zerocopy_receive) == 64",
        ):
            self.assertIn(phrase, c_probe)
        for phrase in (
            "sizeof(tcphdr) == 20",
            "alignof(tcphdr) == 4",
            "sizeof(tcp_info) == 232",
            "sizeof(tcp_md5sig) == 216",
            "sizeof(tcp_diag_md5sig) == 100",
            "sizeof(tcp_repair_window) == 20",
            "sizeof(tcp_zerocopy_receive) == 64",
        ):
            self.assertIn(phrase, cxx_probe)

        self.assertIn("__builtin_offsetof", c_probe)
        self.assertIn("static_assert", cxx_probe)
        self.assertIn("#error \"BSD TCP profile unexpectedly exposes GNU diagnostics\"", c_probe)

    def test_runner_is_a_closed_seven_profile_compile_only_gate(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "readonly MUSL_ROOT=/opt/musl-1.2.6",
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "readonly CANDIDATE_CC=/usr/bin/gcc",
            "readonly -a PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 c11-gnu c11-bsd cxx17-strict cxx17-gnu)",
            "-nostdinc",
            "-nostdinc++",
            "-H",
            "netinet/tcp.h features.h",
            "sys/types.h sys/socket.h stdint.h",
            "unexpectedly included gated",
            "makes no claim about TCP socket-option behavior",
            "compile-only evidence",
            "pinned-musl/project C/C++ <netinet/tcp.h> ABI",
        ):
            self.assertIn(phrase, runner)


if __name__ == "__main__":
    unittest.main()
