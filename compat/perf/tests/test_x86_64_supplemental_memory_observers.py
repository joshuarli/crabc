#!/usr/bin/env python3
"""Validate the finite supplemental memory-observer artifact mapping."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PROFILE = ROOT / "compat/perf/x86_64-profile.toml"

ARTIFACTS = {
    "x86_64_clock_allocator_workload": {
        "source": ROOT / "compat/perf/x86_64_memory_observer_clock_allocator.c",
        "rows": {
            "clock_gettime_realtime",
            "clock_gettime_process_cpu",
            "clock_gettime_thread_cpu",
            "clock_gettime_monotonic_raw",
            "clock_gettime_realtime_coarse",
            "clock_gettime_monotonic_coarse",
            "clock_gettime_boottime",
            "clock_gettime_realtime_alarm",
            "clock_gettime_boottime_alarm",
            "clock_gettime_tai",
            "allocator_live_4m",
            "allocator_live_32m",
            "allocator_refill_4m",
            "allocator_worker_local_64",
            "allocator_worker_local_4k",
        },
        "phases": {
            **{
                row: "clock-final-call"
                for row in (
                    "clock_gettime_realtime",
                    "clock_gettime_process_cpu",
                    "clock_gettime_thread_cpu",
                    "clock_gettime_monotonic_raw",
                    "clock_gettime_realtime_coarse",
                    "clock_gettime_monotonic_coarse",
                    "clock_gettime_boottime",
                    "clock_gettime_realtime_alarm",
                    "clock_gettime_boottime_alarm",
                    "clock_gettime_tai",
                )
            },
            "allocator_live_4m": "allocator-live",
            "allocator_live_32m": "allocator-live",
            "allocator_refill_4m": "allocator-refill-live",
            "allocator_worker_local_64": "allocator-workers-complete",
            "allocator_worker_local_4k": "allocator-workers-complete",
        },
    },
    "x86_64_network_workload": {
        "source": ROOT / "compat/perf/x86_64_memory_observer_network.c",
        "rows": {
            "loopback_tcp_ipv4_4k",
            "loopback_tcp_ipv6_4k",
            "loopback_udp_ipv4_4k",
            "loopback_udp_ipv6_4k",
            "resolver_hosts",
            "resolver_dns_dual",
            "resolver_dns_tcp",
        },
        "phases": {
            "loopback_tcp_ipv4_4k": "network-final-echo-open",
            "loopback_tcp_ipv6_4k": "network-final-echo-open",
            "loopback_udp_ipv4_4k": "network-final-echo-open",
            "loopback_udp_ipv6_4k": "network-final-echo-open",
            "resolver_hosts": "resolver-final-result-live",
            "resolver_dns_dual": "resolver-final-result-live",
            "resolver_dns_tcp": "resolver-final-result-live",
        },
    },
    "x86_64_primitive_boundary_workload": {
        "source": ROOT / "compat/perf/x86_64_memory_observer_primitive.c",
        "rows": {
            f"{primitive}_{variant}"
            for primitive in ("memcpy", "memset", "strlen", "memchr", "strstr", "memmem")
            for variant in ("empty", "short31_unaligned", "guard63")
        },
        "phases": {
            f"{primitive}_{variant}": "primitive-guard-window-live"
            for primitive in ("memcpy", "memset", "strlen", "memchr", "strstr", "memmem")
            for variant in ("empty", "short31_unaligned", "guard63")
        },
    },
}


class SupplementalMemoryObserverContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with PROFILE.open("rb") as stream:
            cls.profile = tomllib.load(stream)
        cls.rows = cls.profile["supplemental_row"]

    def test_profile_rows_have_one_observer_artifact_family(self) -> None:
        self.assertEqual(len(self.rows), 40)
        rows_by_binary: dict[str, list[dict[str, object]]] = {}
        for row in self.rows:
            rows_by_binary.setdefault(str(row["binary"]), []).append(row)

        self.assertEqual(set(rows_by_binary), set(ARTIFACTS))
        observed_rows: set[str] = set()
        for binary, contract in ARTIFACTS.items():
            rows = rows_by_binary[binary]
            row_ids = {str(row["id"]) for row in rows}
            self.assertEqual(row_ids, contract["rows"])
            self.assertTrue(contract["source"].is_file())
            self.assertEqual(
                {str(row["id"]): str(row["observer_phase"]) for row in rows},
                contract["phases"],
            )
            observed_rows.update(row_ids)

        self.assertEqual(len(observed_rows), 40)


if __name__ == "__main__":
    unittest.main()
