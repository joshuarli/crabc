#!/usr/bin/env python3
"""Contract checks for the installed ordinary local IPC/readiness consumer."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class OwnedStaticIpcReadinessConsumerTests(unittest.TestCase):
    def test_consumer_uses_only_private_local_endpoints_and_bounded_waits(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "owned_static_ipc_readiness_consumer.c"
        ).read_text(encoding="utf-8")

        for required in (
            "socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)",
            "epoll_create1(EPOLL_CLOEXEC)",
            "EPOLLIN | EPOLLRDHUP",
            "socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)",
            "htonl(INADDR_LOOPBACK)",
            ".sin_port = 0",
            "READINESS_TIMEOUT_MS = 1000",
            "QUIESCENT_TIMEOUT_MS = 25",
            "pthread_create(&peer, 0, unix_peer, &round)",
            "pthread_create(&client, 0, loopback_client, &round)",
            "pthread_join(peer, 0)",
            "pthread_join(client, 0)",
            "readv(pair[0], response, 2)",
            "writev(pair[0], request, 2)",
            "sendmsg(endpoint, &request, 0)",
            "recvmsg(accepted, &request, 0)",
            "MSG_NOSIGNAL",
            "errno != EPIPE",
            "close_owned(&round->endpoint)",
            "close_owned(&endpoint)",
        ):
            self.assertIn(required, probe)
        for forbidden in ("getaddrinfo", "gethostbyname", "pthread_cancel", "/etc/"):
            self.assertNotIn(forbidden, probe)

    def test_existing_selected_leaves_need_no_new_feature_or_cancellation_overlay(self) -> None:
        module_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        socket_transport = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "socket_transport.rs"
        ).read_text(encoding="utf-8")
        readiness = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "readiness_waits.rs"
        ).read_text(encoding="utf-8")

        for module in (
            "descriptor_io.rs",
            "vector_io.rs",
            "readiness_waits.rs",
            "event_descriptors.rs",
            "socket_transport.rs",
            "socket_messages.rs",
        ):
            self.assertIn(f'#[path = "{module}"]', module_root)
        self.assertIn("omit cancellation integration", socket_transport)
        self.assertIn("does not provide musl's pthread cancellation-point behavior", readiness)

    def test_runner_checks_oracle_both_static_modes_and_exact_link_provenance(self) -> None:
        runner_path = (
            ROOT / "compat" / "x86_64" / "run_owned_static_ipc_readiness_consumer.sh"
        )
        runner = runner_path.read_text(encoding="utf-8")

        for required in (
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            "usage: %s <installed-owned-static-sysroot>",
            '"$sysroot/bin/crabc-cc" "$mode"',
            "runtime allowlist or exact application-object receipt drifted",
            "audit_linker_trace(",
            "application_paths=(application,)",
            "run_installed_mode -static et-exec",
            "run_installed_mode -static-pie static-pie",
            "timeout 30 env -i",
        ):
            self.assertIn(required, runner)
        for symbol in (
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "pthread_create",
            "pthread_join",
        ):
            self.assertIn(symbol, runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("run_owned_static_sysroot.sh", runner)
        self.assertTrue(runner_path.stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
