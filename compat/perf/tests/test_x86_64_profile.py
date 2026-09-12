#!/usr/bin/env python3
"""Validate the closed native x86 supplemental performance profile."""

from __future__ import annotations

import ast
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = ROOT / "compat/perf/x86_64-profile.toml"
LEGACY_RUNNER_PATH = ROOT / "compat/perf/run.py"

CLOCK_ROWS = {
    "clock_gettime_realtime": "0",
    "clock_gettime_process_cpu": "2",
    "clock_gettime_thread_cpu": "3",
    "clock_gettime_monotonic_raw": "4",
    "clock_gettime_realtime_coarse": "5",
    "clock_gettime_monotonic_coarse": "6",
    "clock_gettime_boottime": "7",
    "clock_gettime_realtime_alarm": "8",
    "clock_gettime_boottime_alarm": "9",
    "clock_gettime_tai": "11",
}

ALLOCATOR_ROWS = {
    "allocator_live_4m": ("live", 8, ["1024", "4096"]),
    "allocator_live_32m": ("live", 1, ["128", "262144"]),
    "allocator_refill_4m": ("refill", 16, ["1024", "4096", "512"]),
    "allocator_worker_local_64": ("worker", 16, ["4", "256", "64"]),
    "allocator_worker_local_4k": ("worker", 16, ["4", "256", "4096"]),
}

NETWORK_ROWS = {
    "loopback_tcp_ipv4_4k": ("loopback_tcp_ipv4", ["127.0.0.1", "39041"]),
    "loopback_tcp_ipv6_4k": ("loopback_tcp_ipv6", ["::1", "39042"]),
    "loopback_udp_ipv4_4k": ("loopback_udp_ipv4", ["127.0.0.1", "39043"]),
    "loopback_udp_ipv6_4k": ("loopback_udp_ipv6", ["::1", "39044"]),
    "resolver_hosts": (
        "resolver_hosts",
        ["perf-host.example.test", "80", "127.0.0.77", "2001:db8::77"],
    ),
    "resolver_dns_dual": (
        "resolver_dns_dual",
        ["batch.example.test.", "80", "198.51.100.48", "2001:db8::48"],
    ),
    "resolver_dns_tcp": (
        "resolver_dns_tcp",
        ["tc.example.test.", "80", "198.51.100.45"],
    ),
}

PRIMITIVES = ("memcpy", "memset", "strlen", "memchr", "strstr", "memmem")
VARIANTS = {
    "empty": 2_000_000,
    "short31_unaligned": 2_000_000,
    "guard63": 500_000,
}

LEGACY_ROWS = {
    "startup",
    "startup_constructor_destructor",
    "startup_dependency_graph",
    "clock_gettime",
    "gettimeofday",
    "getpid",
    "open_close",
    "fd_file_4k",
    "stdio_file_4k",
    "stdio_format_parse",
    "pthread_create_join_tls",
    "pthread_mutex_uncontended",
    "pthread_mutex_cond_ping_pong",
    "loader_dynamic_tls_growth",
    "memcpy_16k",
    "memset_16k",
    "strlen_16k",
    "memchr_16k",
    "strstr_4k",
    "memmem_4k",
    "memcpy_64_aligned",
    "memcpy_64_unaligned",
    "memcpy_16k_aligned",
    "memcpy_16k_unaligned",
    "memcpy_256k_aligned",
    "memcpy_256k_unaligned",
    "memset_64_aligned",
    "memset_64_unaligned",
    "memset_16k_aligned",
    "memset_16k_unaligned",
    "memset_256k_aligned",
    "memset_256k_unaligned",
    "strlen_64_aligned",
    "strlen_64_unaligned",
    "strlen_16k_aligned",
    "strlen_16k_unaligned",
    "strlen_256k_aligned",
    "strlen_256k_unaligned",
    "memchr_64_aligned",
    "memchr_64_unaligned",
    "memchr_16k_aligned",
    "memchr_16k_unaligned",
    "memchr_256k_aligned",
    "memchr_256k_unaligned",
    "strstr_64_aligned",
    "strstr_64_unaligned",
    "strstr_16k_aligned",
    "strstr_16k_unaligned",
    "strstr_256k_aligned",
    "strstr_256k_unaligned",
    "memmem_64_aligned",
    "memmem_64_unaligned",
    "memmem_16k_aligned",
    "memmem_16k_unaligned",
    "memmem_256k_aligned",
    "memmem_256k_unaligned",
    "memcpy_128m_aligned",
    "memcpy_128m_unaligned",
    "memset_128m_aligned",
    "memset_128m_unaligned",
    "strlen_128m_aligned",
    "strlen_128m_unaligned",
    "memchr_128m_aligned",
    "memchr_128m_unaligned",
    "strstr_128m_aligned",
    "strstr_128m_unaligned",
    "memmem_128m_aligned",
    "memmem_128m_unaligned",
    "allocator_64",
    "allocator_4k",
    "dlsym_1",
    "dlsym_128",
    "dlsym_1024",
    "dlopen_graph",
}

LEGACY_GROUP_ROWS = (
    ("startup", "startup_constructor_destructor", "startup_dependency_graph"),
    ("clock_gettime", "gettimeofday", "getpid"),
    ("open_close",),
    ("fd_file_4k",),
    ("stdio_file_4k", "stdio_format_parse"),
    ("pthread_create_join_tls",),
    ("pthread_mutex_uncontended",),
    ("pthread_mutex_cond_ping_pong",),
    ("loader_dynamic_tls_growth",),
    (
        "memcpy_16k", "memset_16k", "strlen_16k", "memchr_16k", "strstr_4k", "memmem_4k",
        "memcpy_64_aligned", "memcpy_64_unaligned", "memcpy_16k_aligned", "memcpy_16k_unaligned",
        "memcpy_256k_aligned", "memcpy_256k_unaligned", "memset_64_aligned", "memset_64_unaligned",
        "memset_16k_aligned", "memset_16k_unaligned", "memset_256k_aligned", "memset_256k_unaligned",
        "strlen_64_aligned", "strlen_64_unaligned", "strlen_16k_aligned", "strlen_16k_unaligned",
        "strlen_256k_aligned", "strlen_256k_unaligned", "memchr_64_aligned", "memchr_64_unaligned",
        "memchr_16k_aligned", "memchr_16k_unaligned", "memchr_256k_aligned", "memchr_256k_unaligned",
        "strstr_64_aligned", "strstr_64_unaligned", "strstr_16k_aligned", "strstr_16k_unaligned",
        "strstr_256k_aligned", "strstr_256k_unaligned", "memmem_64_aligned", "memmem_64_unaligned",
        "memmem_16k_aligned", "memmem_16k_unaligned", "memmem_256k_aligned", "memmem_256k_unaligned",
    ),
    (
        "memcpy_128m_aligned", "memcpy_128m_unaligned", "memset_128m_aligned", "memset_128m_unaligned",
        "strlen_128m_aligned", "strlen_128m_unaligned", "memchr_128m_aligned", "memchr_128m_unaligned",
        "strstr_128m_aligned", "strstr_128m_unaligned", "memmem_128m_aligned", "memmem_128m_unaligned",
    ),
    ("allocator_64", "allocator_4k"),
    ("dlsym_1", "dlsym_128", "dlsym_1024"),
    ("dlopen_graph",),
)


class NativeProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with PROFILE_PATH.open("rb") as stream:
            cls.profile = tomllib.load(stream)
        cls.rows = cls.profile["supplemental_row"]
        cls.by_id = {row["id"]: row for row in cls.rows}

    def test_profile_declares_separate_timed_and_observer_artifacts(self) -> None:
        profile = self.profile["profile"]
        self.assertEqual(profile["schema"], "crabc.perf.x86_64-profile/v1")
        self.assertEqual(profile["target"], "x86_64-unknown-linux-musl")
        self.assertEqual(profile["observer_protocol"], "crabc.perf.observer-r-c/v1")
        self.assertFalse(profile["release_qualification"])
        self.assertTrue(profile["timed_artifact_unchanged"])
        self.assertTrue(profile["observer_artifact_separate"])
        self.assertFalse(profile["observer_artifact_byte_identical"])
        self.assertEqual(profile["observer_ready_env"], "CRABC_PERF_OBSERVER_READY_FD")
        self.assertEqual(profile["observer_continue_env"], "CRABC_PERF_OBSERVER_CONTINUE_FD")
        self.assertEqual(profile["observer_ready_fd"], 97)
        self.assertEqual(profile["observer_continue_fd"], 98)
        self.assertEqual(
            self.profile["execution_model"],
            {
                "measured_client_processes_per_row": 1,
                "full_client_process_setup_included": True,
                "staged_peer_endpoints_excluded_from_client_measurement": True,
            },
        )
        self.assertEqual(
            self.profile["operation_counting"]["operations_field"],
            "selected-repeated-route-units",
        )

    def test_fixture_build_inputs_are_closed(self) -> None:
        fixtures = {fixture["binary"]: fixture for fixture in self.profile["fixture"]}
        self.assertEqual(
            fixtures,
            {
                "x86_64_clock_allocator_workload": {
                    "binary": "x86_64_clock_allocator_workload",
                    "source": "compat/perf/x86_64_clock_allocator_workload.c",
                    "c_standard": "c11",
                    "compile_defines": ["_GNU_SOURCE"],
                    "link_flags": ["-pthread"],
                },
                "x86_64_network_workload": {
                    "binary": "x86_64_network_workload",
                    "source": "compat/perf/x86_64_network_workload.c",
                    "c_standard": "c11",
                    "compile_defines": ["_GNU_SOURCE"],
                    "link_flags": [],
                },
                "x86_64_primitive_boundary_workload": {
                    "binary": "x86_64_primitive_boundary_workload",
                    "source": "compat/perf/x86_64_primitive_boundary_workload.c",
                    "c_standard": "c11",
                    "compile_defines": ["_GNU_SOURCE"],
                    "link_flags": [],
                },
            },
        )

    def test_resolver_setup_is_private_and_reuses_the_existing_helper(self) -> None:
        self.assertEqual(
            self.profile["resolver_setup"],
            {
                "dns_server": "compat/resolver-network/dns_server.py",
                "dns_protocol": "resolver-network-dns-v1",
                "dns_port": 53,
                "loopback_nameservers": ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
                "resolv_conf": (
                    "# crabc native performance resolver fixture\n"
                    "nameserver 127.0.0.1\n"
                    "nameserver 127.0.0.2\n"
                    "nameserver 127.0.0.3\n"
                    "search search.test\n"
                    "options ndots:1 timeout:1 attempts:1\n"
                ),
                "hosts_conf": (
                    "127.0.0.1 localhost\n"
                    "::1 localhost\n"
                    "127.0.0.77 perf-host.example.test\n"
                    "2001:db8::77 perf-host.example.test\n"
                ),
            },
        )

    def test_closed_40_row_roster_has_required_invocation_fields(self) -> None:
        expected = set(CLOCK_ROWS) | set(ALLOCATOR_ROWS) | set(NETWORK_ROWS)
        expected |= {f"{primitive}_{variant}" for primitive in PRIMITIVES for variant in VARIANTS}
        self.assertEqual(len(expected), 40)
        self.assertEqual(len(self.rows), 40)
        self.assertEqual(set(self.by_id), expected)
        for row in self.rows:
            self.assertEqual(
                {"id", "binary", "mode", "iterations", "argv", "observer_phase",
                 "requires_loopback_peer", "requires_hermetic_resolver_files",
                 "operations", "result_contract", "geometry"},
                set(row),
            )
            self.assertIsInstance(row["iterations"], int)
            self.assertGreater(row["iterations"], 0)
            self.assertIsInstance(row["argv"], list)
            self.assertIsInstance(row["geometry"], dict)

    def test_clock_rows_are_the_ten_non_legacy_clock_ids(self) -> None:
        for row_id, clock_id in CLOCK_ROWS.items():
            row = self.by_id[row_id]
            self.assertEqual(
                (row["binary"], row["mode"], row["iterations"], row["argv"],
                 row["observer_phase"], row["operations"]),
                ("x86_64_clock_allocator_workload", "clock_gettime", 200_000,
                 [clock_id], "clock-final-call", 200_000),
            )
            self.assertFalse(row["requires_loopback_peer"])
            self.assertFalse(row["requires_hermetic_resolver_files"])
            self.assertEqual(row["geometry"]["clock_id"], int(clock_id))
            self.assertEqual(row["geometry"]["calls"], 200_000)

    def test_allocator_rows_pin_live_sets_refill_and_worker_ownership(self) -> None:
        for row_id, (mode, epochs, argv) in ALLOCATOR_ROWS.items():
            row = self.by_id[row_id]
            self.assertEqual(
                (row["binary"], row["mode"], row["iterations"], row["argv"]),
                ("x86_64_clock_allocator_workload", mode, epochs, argv),
            )
            self.assertFalse(row["requires_loopback_peer"])
            self.assertFalse(row["requires_hermetic_resolver_files"])
        self.assertEqual(
            self.by_id["allocator_live_4m"]["geometry"],
            {"epochs": 8, "allocations_per_epoch": 1024, "bytes_per_allocation": 4096,
             "live_bytes": 4 * 1024 * 1024},
        )
        self.assertEqual(
            self.by_id["allocator_live_32m"]["geometry"],
            {"epochs": 1, "allocations_per_epoch": 128, "bytes_per_allocation": 262144,
             "live_bytes": 32 * 1024 * 1024},
        )
        self.assertEqual(
            self.by_id["allocator_refill_4m"]["geometry"],
            {"rounds": 16, "slots": 1024, "refilled_even_slots": 512,
             "bytes_per_allocation": 4096, "odd_slots_preserved": 512,
             "address_reuse_required": False},
        )
        for row_id, size in (("allocator_worker_local_64", 64), ("allocator_worker_local_4k", 4096)):
            self.assertEqual(
                self.by_id[row_id]["geometry"],
                {"workers": 4, "epochs_per_worker": 16, "lifetimes_per_epoch": 256,
                 "bytes_per_allocation": size, "allocation_owner": "worker"},
            )

    def test_network_rows_bind_fixed_private_inputs(self) -> None:
        for row_id, (mode, argv) in NETWORK_ROWS.items():
            row = self.by_id[row_id]
            self.assertEqual(row["binary"], "x86_64_network_workload")
            self.assertEqual(row["mode"], mode)
            self.assertEqual(row["argv"], argv)
        for row_id in (
            "loopback_tcp_ipv4_4k", "loopback_tcp_ipv6_4k",
            "loopback_udp_ipv4_4k", "loopback_udp_ipv6_4k",
        ):
            row = self.by_id[row_id]
            self.assertEqual(row["iterations"], 10_000)
            self.assertTrue(row["requires_loopback_peer"])
            self.assertFalse(row["requires_hermetic_resolver_files"])
            self.assertEqual(row["geometry"], {"request_echo_pairs": 10_000, "payload_bytes": 4096,
                                               "client_sockets": 1, "client_connections": 1})
        self.assertEqual(self.by_id["resolver_hosts"]["iterations"], 20_000)
        self.assertFalse(self.by_id["resolver_hosts"]["requires_loopback_peer"])
        self.assertTrue(self.by_id["resolver_hosts"]["requires_hermetic_resolver_files"])
        for row_id in ("resolver_dns_dual", "resolver_dns_tcp"):
            self.assertEqual(self.by_id[row_id]["iterations"], 1_000)
            self.assertTrue(self.by_id[row_id]["requires_loopback_peer"])
            self.assertTrue(self.by_id[row_id]["requires_hermetic_resolver_files"])

    def test_primitive_rows_pin_boundary_shapes(self) -> None:
        for primitive in PRIMITIVES:
            for variant, iterations in VARIANTS.items():
                row = self.by_id[f"{primitive}_{variant}"]
                self.assertEqual(
                    (row["binary"], row["mode"], row["iterations"], row["argv"],
                     row["observer_phase"]),
                    ("x86_64_primitive_boundary_workload", "primitive", iterations,
                     [primitive, variant], "primitive-guard-window-live"),
                )
                self.assertFalse(row["requires_loopback_peer"])
                self.assertFalse(row["requires_hermetic_resolver_files"])
                if variant == "empty":
                    self.assertEqual(row["geometry"], {"valid_bytes": 0, "unaligned_offset": 0})
                elif variant == "short31_unaligned":
                    self.assertEqual(
                        row["geometry"],
                        {
                            "valid_bytes": 31,
                            "unaligned_offset": 1,
                            "tail_needle_bytes": 6 if primitive in ("strstr", "memmem") else 0,
                        },
                    )
                else:
                    self.assertEqual(
                        row["geometry"],
                        {
                            "valid_bytes": 63,
                            "guard_page": True,
                            "guarded_mappings": 2 if primitive == "memcpy" else 1,
                            "string_nul_before_guard": primitive in ("strlen", "strstr"),
                            "tail_needle_bytes": 6 if primitive in ("strstr", "memmem") else 0,
                        },
                    )

    def test_all_74_legacy_rows_have_one_declared_memory_mapping(self) -> None:
        groups = self.profile["legacy_memory_phase"]
        flattened = [row for group in groups for row in group["rows"]]
        self.assertEqual(self.profile["legacy_memory_phase_count"], 74)
        self.assertEqual(len(flattened), 74)
        self.assertEqual(len(set(flattened)), 74)
        self.assertEqual(set(flattened), LEGACY_ROWS)
        self.assertEqual(len(LEGACY_ROWS), 74)
        self.assertEqual(
            tuple(tuple(group["rows"]) for group in groups),
            LEGACY_GROUP_ROWS,
        )
        for group in groups:
            self.assertIn("checkpoint", group)
            self.assertIn("peak_rule", group)
            self.assertEqual(group["peak_rule"], "maximum-declared-checkpoints")
        self.assertEqual(
            self.profile["memory_observation"]["cgroup_peak"],
            "fresh-client-leaf-after-exit",
        )
        self.assertEqual(
            self.profile["memory_observation"]["timing_and_memory_artifacts"],
            "separate",
        )

    def test_legacy_memory_mapping_covers_the_current_runner_roster(self) -> None:
        tree = ast.parse(LEGACY_RUNNER_PATH.read_text(encoding="utf-8"))
        assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "WORKLOADS" for target in node.targets)
        )
        self.assertIsInstance(assignment.value, ast.Tuple)
        runner_rows = {
            element.args[0].value
            for element in assignment.value.elts
            if isinstance(element, ast.Call)
            and element.args
            and isinstance(element.args[0], ast.Constant)
            and isinstance(element.args[0].value, str)
        }
        self.assertEqual(len(runner_rows), 74)
        self.assertEqual(runner_rows, LEGACY_ROWS)
        self.assertEqual(
            {row for group in self.profile["legacy_memory_phase"] for row in group["rows"]},
            runner_rows,
        )


if __name__ == "__main__":
    unittest.main()
