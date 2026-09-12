#!/usr/bin/env python3
"""Focused contract tests for native x86 performance network peers."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/perf/x86_64_peers.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_x86_peers", MODULE)
assert SPEC is not None and SPEC.loader is not None
peers = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = peers
SPEC.loader.exec_module(peers)

WORK_ROOT = ROOT / ".work/x86_64"
WORK_ROOT.mkdir(parents=True, exist_ok=True)


def _udp_event(role: str, name: str, qtype: int, identifier: int, action: str) -> dict[str, object]:
    return {
        "role": role, "family": "ipv4", "transport": "udp", "name": name,
        "qtype": qtype, "qclass": 1, "identifier": identifier, "action": action,
    }


def _tcp_event(role: str, name: str, qtype: int, action: str) -> dict[str, object]:
    return {
        "role": role, "family": "ipv4", "transport": "tcp", "name": name,
        "qtype": qtype, "qclass": 1, "action": action,
    }


def dual_events(iterations: int) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for index in range(iterations):
        a_identifier = 2 * index
        aaaa_identifier = 2 * index + 1
        events.extend((
            _udp_event("valid", "batch.example.test.", 1, a_identifier, "batch-held-a"),
            _udp_event("drop", "batch.example.test.", 1, a_identifier, "batch-held-a"),
            _udp_event("valid", "batch.example.test.", 28, aaaa_identifier, "batch-release"),
            _udp_event("drop", "batch.example.test.", 28, aaaa_identifier, "batch-release"),
            _udp_event("fallback", "batch.example.test.", 1, a_identifier, "batch-held-a"),
            _udp_event("fallback", "batch.example.test.", 28, aaaa_identifier, "batch-release"),
        ))
    return events


def tcp_events(iterations: int) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for index in range(iterations):
        events.extend((
            _udp_event("valid", "tc.example.test.", 1, index, "tc-sequence"),
            _udp_event("drop", "tc.example.test.", 1, index, "drop"),
            _udp_event("fallback", "tc.example.test.", 1, index, "tc-sequence"),
            _tcp_event("valid", "tc.example.test.", 1, "answer"),
        ))
    return events


class NetworkProfileTests(unittest.TestCase):
    def test_seven_fixed_rows_reject_a_mode_substitution(self) -> None:
        row = peers.load_network_row(ROOT, "loopback_tcp_ipv4_4k", "loopback_tcp_ipv4")
        self.assertEqual(row.argv, ("127.0.0.1", "39041"))
        self.assertEqual(row.full_iterations, 10_000)
        with self.assertRaisesRegex(peers.PeerError, "mode"):
            peers.load_network_row(ROOT, "loopback_tcp_ipv4_4k", "loopback_udp_ipv4")


class RetainedEventTests(unittest.TestCase):
    def test_dns_route_reader_replays_full_causal_invocation_geometry(self) -> None:
        dual = dual_events(2)
        summary = peers.summarize_dns_events("resolver_dns_dual", dual, iterations=2)
        self.assertEqual(summary, {"event_count": 12, "batch_a_udp": 6, "batch_aaaa_udp": 6})
        interleaved_dual = [
            dual[0], dual[1], dual[4], dual[2], dual[3], dual[5],
            dual[6], dual[7], dual[10], dual[8], dual[9], dual[11],
        ]
        self.assertEqual(
            peers.summarize_dns_events("resolver_dns_dual", interleaved_dual, iterations=2),
            summary,
        )
        with self.assertRaisesRegex(peers.PeerError, "event count"):
            peers.summarize_dns_events("resolver_dns_dual", dual[:6], iterations=1_000)
        with self.assertRaisesRegex(peers.PeerError, "event count"):
            peers.summarize_dns_events("resolver_dns_dual", [*dual, dual[0]], iterations=2)
        reversed_route = copy.deepcopy(dual)
        reversed_route[0], reversed_route[2] = reversed_route[2], reversed_route[0]
        with self.assertRaisesRegex(peers.PeerError, "reverses A before AAAA"):
            peers.summarize_dns_events("resolver_dns_dual", reversed_route, iterations=2)
        wrong_identifier = copy.deepcopy(dual)
        wrong_identifier[4]["identifier"] = 99
        with self.assertRaisesRegex(peers.PeerError, "identifiers"):
            peers.summarize_dns_events("resolver_dns_dual", wrong_identifier, iterations=2)
        unexpected = copy.deepcopy(dual)
        unexpected[0]["unexpected"] = True
        with self.assertRaisesRegex(peers.PeerError, "fields differ"):
            peers.summarize_dns_events("resolver_dns_dual", unexpected, iterations=2)

        tcp = tcp_events(2)
        summary = peers.summarize_dns_events("resolver_dns_tcp", tcp, iterations=2)
        self.assertEqual(summary, {"event_count": 8, "udp_truncated": 4, "udp_drop": 2, "tcp_answer": 2})
        interleaved_tcp = [
            tcp[0], tcp[2], tcp[1], tcp[3],
            tcp[4], tcp[6], tcp[5], tcp[7],
        ]
        self.assertEqual(
            peers.summarize_dns_events("resolver_dns_tcp", interleaved_tcp, iterations=2),
            summary,
        )
        fallback_answer = copy.deepcopy(tcp)
        fallback_answer[3] = _tcp_event("fallback", "tc.example.test.", 1, "answer")
        self.assertEqual(
            peers.summarize_dns_events("resolver_dns_tcp", fallback_answer, iterations=2),
            summary,
        )
        reversed_tcp = [tcp[3], tcp[0], tcp[1], tcp[2], *tcp[4:]]
        with self.assertRaisesRegex(peers.PeerError, "precedes its answering UDP truncation"):
            peers.summarize_dns_events("resolver_dns_tcp", reversed_tcp, iterations=2)

    def test_hosts_reader_rejects_even_one_dns_query(self) -> None:
        self.assertEqual(
            peers.summarize_dns_events("resolver_hosts", [], iterations=20_000),
            {"event_count": 0, "zero_dns_queries": True},
        )
        with self.assertRaisesRegex(peers.PeerError, "zero DNS"):
            peers.summarize_dns_events(
                "resolver_hosts",
                [{
                    "role": "valid", "family": "ipv4", "transport": "udp",
                    "name": "perf-host.example.test.", "qtype": 1, "qclass": 1,
                    "identifier": 4, "action": "answer",
                }],
                iterations=20_000,
            )


class ReadinessDeadlineTests(unittest.TestCase):
    def test_partial_readiness_line_cannot_block_past_its_deadline(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable, "-B", "-c",
                "import sys, time; sys.stdout.write('{'); sys.stdout.flush(); time.sleep(5)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            started = time.monotonic()
            with self.assertRaisesRegex(peers.PeerError, "did not publish readiness"):
                peers._wait_ready(process, 0.15, "partial readiness test peer")
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=3)


class ResolverStagingTests(unittest.TestCase):
    def test_retained_resolver_paths_must_be_the_client_etc_paths(self) -> None:
        contents = {
            "etc_resolv_conf_bytes": b"nameserver 127.0.0.1\n",
            "etc_hosts_bytes": b"127.0.0.1 localhost\n",
        }
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary_text:
            client_root = Path(temporary_text) / "client-root"
            client_root.mkdir()
            staged = {
                "etc_resolv_conf_bytes": peers.file_identity(
                    ROOT, peers._write_client_file(client_root, Path("etc/resolv.conf"), contents["etc_resolv_conf_bytes"]),
                ),
                "etc_hosts_bytes": peers.file_identity(
                    ROOT, peers._write_client_file(client_root, Path("etc/hosts"), contents["etc_hosts_bytes"]),
                ),
            }
            peers._validate_staged_resolver_files(
                ROOT, client_root, contents, staged, require_complete=True,
            )
            alternate = client_root / "retained-but-not-etc-resolv.conf"
            peers._write_bytes(alternate, contents["etc_resolv_conf_bytes"])
            forged = dict(staged)
            forged["etc_resolv_conf_bytes"] = peers.file_identity(ROOT, alternate)
            with self.assertRaisesRegex(peers.PeerError, "exact private client resolver path"):
                peers._validate_staged_resolver_files(
                    ROOT, client_root, contents, forged, require_complete=True,
                )


def echo_client(address: str, port: int, *, transport: int, count: int) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, transport) as connection:
        connection.settimeout(3)
        connection.connect((address, port))
        for sequence in range(count):
            payload = peers._make_payload(sequence)
            if transport == socket.SOCK_STREAM:
                connection.sendall(payload)
                chunks: list[bytes] = []
                remaining = len(payload)
                while remaining:
                    chunk = connection.recv(remaining)
                    if not chunk:
                        raise AssertionError("peer closed TCP echo early")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                reply = b"".join(chunks)
            else:
                connection.send(payload)
                reply = connection.recv(len(payload))
            if reply != payload:
                raise AssertionError("peer echo did not preserve the checked sequence payload")


class PeerLifecycleTests(unittest.TestCase):
    def _inputs(self, temporary: Path) -> tuple[int, tuple[int, ...], Path, Path]:
        allowed = tuple(sorted(os.sched_getaffinity(0)))
        client_root = temporary / "client-root"
        client_root.mkdir()
        return allowed[0], allowed, temporary / "peer", client_root

    def test_echo_context_retains_exact_peer_evidence_and_rejects_semantic_mutation(self) -> None:
        before_affinity = os.sched_getaffinity(0)
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary_text:
            temporary = Path(temporary_text)
            cpu, allowed, invocation, client_root = self._inputs(temporary)
            context = peers.start_context(
                ROOT, row_id="loopback_tcp_ipv4_4k", mode="loopback_tcp_ipv4",
                invocation_work=invocation, client_root=client_root, cpu=cpu,
                allowed_affinity=allowed, iterations=2,
            )
            self.assertEqual(context.events, {"echo": invocation / "echo-events.json"})
            echo_client("127.0.0.1", 39041, transport=socket.SOCK_STREAM, count=2)
            evidence = context.stop()
            peers.validate_context(ROOT, evidence)
            self.assertEqual(os.sched_getaffinity(0), before_affinity)

            event_path = ROOT / evidence["peers"]["echo"]["events"]["path"]
            misplaced = client_root / "replayed-echo-events.json"
            peers._write_bytes(misplaced, event_path.read_bytes())
            escaped = copy.deepcopy(evidence)
            escaped["peers"]["echo"]["events"] = peers.file_identity(ROOT, misplaced)
            peers._write_json(ROOT / escaped["record_file"], escaped)
            with self.assertRaisesRegex(peers.PeerError, "must remain in invocation work outside client root"):
                peers.validate_context(ROOT, escaped)

            forged = copy.deepcopy(evidence)
            event = json.loads(event_path.read_text(encoding="utf-8"))
            event["received_messages"] = 1
            event["sequence_verified_echoes"] = 1
            event["echoed_messages"] = 1
            peers._write_json(event_path, event)
            forged["peers"]["echo"]["events"] = peers.file_identity(ROOT, event_path)
            forged["event_summaries"]["echo"] = {
                "expected_echoes": 2, "received_messages": 1,
                "sequence_verified_echoes": 1, "echoed_messages": 1, "connections": 1,
            }
            peers._write_json(ROOT / forged["record_file"], forged)
            with self.assertRaisesRegex(peers.PeerError, "sequence-checked"):
                peers.validate_context(ROOT, forged)

    def test_affinity_raw_pid_must_bind_the_started_peer(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary_text:
            temporary = Path(temporary_text)
            cpu, allowed, invocation, client_root = self._inputs(temporary)
            context = peers.start_context(
                ROOT, row_id="loopback_udp_ipv4_4k", mode="loopback_udp_ipv4",
                invocation_work=invocation, client_root=client_root, cpu=cpu,
                allowed_affinity=allowed, iterations=1,
            )
            echo_client("127.0.0.1", 39043, transport=socket.SOCK_DGRAM, count=1)
            evidence = context.stop()
            peers.validate_context(ROOT, evidence)

            forged = copy.deepcopy(evidence)
            raw_path = ROOT / forged["peers"]["echo"]["affinity"]["raw"]["path"]
            lines = raw_path.read_text(encoding="utf-8").splitlines()
            rewritten = ["Pid:\t999999" if line.startswith("Pid:") else line for line in lines]
            peers._write_bytes(raw_path, ("\n".join(rewritten) + "\n").encode("utf-8"))
            forged["peers"]["echo"]["affinity"]["raw"] = peers.file_identity(ROOT, raw_path)
            peers._write_json(ROOT / forged["record_file"], forged)
            with self.assertRaisesRegex(peers.PeerError, "raw affinity Pid"):
                peers.validate_context(ROOT, forged)

    def test_primary_client_error_is_preserved_while_cleanup_retains_a_partial_context(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary_text:
            temporary = Path(temporary_text)
            cpu, allowed, invocation, client_root = self._inputs(temporary)
            with self.assertRaisesRegex(RuntimeError, "client-primary"):
                with peers.start_context(
                    ROOT, row_id="loopback_udp_ipv4_4k", mode="loopback_udp_ipv4",
                    invocation_work=invocation, client_root=client_root, cpu=cpu,
                    allowed_affinity=allowed, iterations=2,
                ) as context:
                    raise RuntimeError("client-primary")
            evidence = context.evidence
            self.assertEqual(evidence["status"], "incomplete")
            peers.validate_context(ROOT, evidence, require_complete=False)
            self.assertEqual(context.peer_pids.keys(), {"echo"})


if __name__ == "__main__":
    unittest.main()
