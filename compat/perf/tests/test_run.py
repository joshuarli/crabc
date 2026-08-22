"""Host-only contract tests for the performance-report helpers."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


MODULE = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf", MODULE)
assert SPEC is not None and SPEC.loader is not None
perf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = perf
SPEC.loader.exec_module(perf)


class SyscallSummaryTests(unittest.TestCase):
    def test_counts_multiple_strace_layouts_and_errors(self) -> None:
        trace = """[pid 12] clock_gettime(CLOCK_MONOTONIC, {tv_sec=1, tv_nsec=2}) = 0
13 openat(AT_FDCWD, \"/missing\", O_RDONLY) = -1 ENOENT (No such file or directory)
getpid() = 13
"""
        self.assertEqual(
            perf.syscall_summary(trace),
            {
                "calls": {
                    "clock_gettime": {"calls": 1, "errors": 0},
                    "getpid": {"calls": 1, "errors": 0},
                    "openat": {"calls": 1, "errors": 1},
                },
                "total_calls": 3,
                "total_errors": 1,
            },
        )

    def test_isolates_calls_between_the_fixture_diagnostic_markers(self) -> None:
        trace = """[pid 42] openat(AT_FDCWD, "/lib/libc.so", O_RDONLY) = 3
42    write(9, "CRABC_PERF_BEGIN", 16)  = 16
[pid 42] getpid() = 42
[pid 42] close(5) = -1 EBADF (Bad file descriptor)
42    write(9, "CRABC_PERF_END", 14)    = 14
[pid 42] exit_group(0) = ?
"""
        summary = perf.marked_syscall_summary(trace, 9)
        self.assertEqual(
            summary,
            {
                "status": "ok",
                "marker_fd": 9,
                "begin_trace_line": 2,
                "end_trace_line": 5,
                "calls": {
                    "close": {"calls": 1, "errors": 1},
                    "getpid": {"calls": 1, "errors": 0},
                },
                "total_calls": 2,
                "total_errors": 1,
            },
        )
        self.assertEqual(
            perf.non_marker_syscall_summary(trace, 9),
            {
                "calls": {
                    "close": {"calls": 1, "errors": 1},
                    "exit_group": {"calls": 1, "errors": 0},
                    "getpid": {"calls": 1, "errors": 0},
                    "openat": {"calls": 1, "errors": 0},
                },
                "total_calls": 4,
                "total_errors": 1,
            },
        )

    def test_rejects_missing_or_duplicated_markers(self) -> None:
        missing_end = '[pid 42] write(9, "CRABC_PERF_BEGIN", 16) = 16\n'
        self.assertEqual(
            perf.marked_syscall_summary(missing_end, 9),
            {
                "status": "failed",
                "reason": "expected one begin and one end marker, found 1 begin and 0 end",
                "marker_fd": 9,
            },
        )
        duplicated_begin = """[pid 42] write(9, "CRABC_PERF_BEGIN", 16) = 16
[pid 42] write(9, "CRABC_PERF_BEGIN", 16) = 16
[pid 42] write(9, "CRABC_PERF_END", 14) = 14
"""
        self.assertEqual(
            perf.marked_syscall_summary(duplicated_begin, 9),
            {
                "status": "failed",
                "reason": "expected one begin and one end marker, found 2 begin and 1 end",
                "marker_fd": 9,
            },
        )

    def test_reports_rates_per_completed_operation_without_rounding(self) -> None:
        summary = {
            "calls": {
                "close": {"calls": 1, "errors": 1},
                "getpid": {"calls": 2, "errors": 0},
            },
            "total_calls": 3,
            "total_errors": 1,
        }
        self.assertEqual(
            perf.syscall_rate_per_operation(summary, 4),
            {
                "completed_operations": 4,
                "calls": {
                    "close": {"calls": 0.25, "errors": 0.25},
                    "getpid": {"calls": 0.5, "errors": 0.0},
                },
                "total_calls": 0.75,
                "total_errors": 0.25,
            },
        )


class SummaryTests(unittest.TestCase):
    def test_summary_keeps_resource_units_and_median(self) -> None:
        samples = []
        for value in (10, 20, 30):
            samples.append(
                {
                    "elapsed_wall_ns": value,
                    "resources": {
                        "user_cpu_ns": value,
                        "system_cpu_ns": value,
                        "max_rss_kib": value,
                        "minor_faults": value,
                        "major_faults": value,
                        "voluntary_context_switches": value,
                        "involuntary_context_switches": value,
                    },
                }
            )
        summary = perf.summarize_samples(samples)
        self.assertEqual(summary["elapsed_wall_ns"], {"min": 10, "median": 20, "p95": 30, "max": 30})
        self.assertEqual(summary["resources.max_rss_kib"]["median"], 20)


class SmapsMappingSummaryTests(unittest.TestCase):
    def test_aggregates_required_resident_metrics_by_stable_mapping_name(self) -> None:
        smaps = """00400000-00401000 r--p 00000000 00:00 0 /tmp/crabc-perf/workload
Rss:                   4 kB
Pss:                   3 kB
Private_Clean:         1 kB
Private_Dirty:         2 kB
00401000-00402000 r-xp 00001000 00:00 0 /tmp/crabc-perf/workload
Rss:                   8 kB
Pss:                   6 kB
Private_Clean:         0 kB
Private_Dirty:         6 kB
7fff0000-7fff1000 rw-p 00000000 00:00 0
Rss:                   12 kB
Pss:                   12 kB
Private_Clean:         0 kB
Private_Dirty:         12 kB
"""
        self.assertEqual(
            perf.smaps_mapping_summary(smaps),
            {
                "[anonymous]": {
                    "private_clean_kib": 0,
                    "private_dirty_kib": 12,
                    "pss_kib": 12,
                    "rss_kib": 12,
                },
                "file:workload": {
                    "private_clean_kib": 1,
                    "private_dirty_kib": 8,
                    "pss_kib": 9,
                    "rss_kib": 12,
                },
            },
        )


class CgroupV2Tests(unittest.TestCase):
    def test_resolves_current_cgroup_below_a_non_root_mount(self) -> None:
        mountinfo = (
            "31 24 0:28 /delegated /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime "
            "- cgroup2 cgroup rw\n"
        )
        self.assertEqual(
            perf.cgroup_v2_parent_path(mountinfo, "0::/delegated/runner"),
            Path("/sys/fs/cgroup/runner"),
        )

    def test_rejects_a_cgroup_outside_the_mount_root(self) -> None:
        mountinfo = "31 24 0:28 /delegated /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        with self.assertRaises(ValueError):
            perf.cgroup_v2_parent_path(mountinfo, "0::/other/runner")


class WorkloadArgumentTests(unittest.TestCase):
    def test_dlsym_lanes_select_their_symbol_table_and_late_symbol(self) -> None:
        dso_1 = Path("/tmp/libsymbols_1.so")
        dso_128 = Path("/tmp/libsymbols_128.so")
        dso_1024 = Path("/tmp/libsymbols_1024.so")
        graph_root = Path("/tmp/libbench_graph_root.so")
        workloads = {workload.name: workload for workload in perf.WORKLOADS}
        self.assertEqual(
            perf.workload_arguments(workloads["dlsym_1"], dso_1, dso_128, dso_1024, graph_root),
            ["dlsym_1", "100000", str(dso_1), "bench_symbol_0"],
        )
        self.assertEqual(
            perf.workload_arguments(workloads["dlsym_128"], dso_1, dso_128, dso_1024, graph_root),
            ["dlsym_128", "100000", str(dso_128), "bench_symbol_7f"],
        )
        self.assertEqual(
            perf.workload_arguments(workloads["dlsym_1024"], dso_1, dso_128, dso_1024, graph_root),
            ["dlsym_1024", "100000", str(dso_1024), "bench_symbol_1024"],
        )
        self.assertEqual(
            perf.workload_arguments(workloads["dlopen_graph"], dso_1, dso_128, dso_1024, graph_root),
            ["dlopen_graph", "1", str(graph_root)],
        )

    def test_file_workloads_receive_their_lane_specific_fixed_input(self) -> None:
        dso = Path("/tmp/libsymbols.so")
        graph_root = Path("/tmp/libbench_graph_root.so")
        io_file = Path("/tmp/io-fixture.bin")
        workloads = {workload.name: workload for workload in perf.WORKLOADS}
        self.assertEqual(
            perf.workload_arguments(
                workloads["fd_file_4k"], dso, dso, dso, graph_root, io_file,
            ),
            ["fd_file_4k", "5000", str(io_file)],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["stdio_file_4k"], dso, dso, dso, graph_root, io_file,
            ),
            ["stdio_file_4k", "100", str(io_file)],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["stdio_format_parse"], dso, dso, dso, graph_root, io_file,
            ),
            ["stdio_format_parse", "1000", str(io_file)],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["pthread_create_join_tls"], dso, dso, dso, graph_root,
            ),
            ["pthread_create_join_tls", "1000"],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["pthread_mutex_uncontended"], dso, dso, dso, graph_root,
            ),
            ["pthread_mutex_uncontended", "2000000"],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["pthread_mutex_cond_ping_pong"], dso, dso, dso, graph_root,
            ),
            ["pthread_mutex_cond_ping_pong", "10000"],
        )
        tls_directory = Path("/tmp/tls-growth")
        self.assertEqual(
            perf.workload_arguments(
                workloads["loader_dynamic_tls_growth"], dso, dso, dso, graph_root,
                tls_growth_directory=tls_directory,
            ),
            ["loader_dynamic_tls_growth", "8", str(tls_directory)],
        )
        with self.assertRaisesRegex(ValueError, "requires staged TLS DSOs"):
            perf.workload_arguments(
                workloads["loader_dynamic_tls_growth"], dso, dso, dso, graph_root,
            )

    def test_scalar_matrix_rows_record_their_size_and_alignment_inputs(self) -> None:
        dso = Path("/tmp/libsymbols.so")
        graph_root = Path("/tmp/libbench_graph_root.so")
        workloads = {workload.name: workload for workload in perf.WORKLOADS}
        self.assertEqual(
            perf.workload_arguments(
                workloads["memcpy_256k_unaligned"], dso, dso, dso, graph_root,
            ),
            ["memcpy_matrix", "500", "262144", "1", "3"],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["memset_64_unaligned"], dso, dso, dso, graph_root,
            ),
            ["memset_matrix", "2000000", "64", "3"],
        )
        self.assertEqual(
            perf.workload_arguments(
                workloads["strstr_16k_aligned"], dso, dso, dso, graph_root,
            ),
            ["strstr_matrix", "2000", "16384", "0"],
        )

    def test_cache_spanning_rows_receive_lane_private_mapped_inputs(self) -> None:
        dso = Path("/tmp/libsymbols.so")
        graph_root = Path("/tmp/libbench_graph_root.so")
        aligned = Path("/tmp/span-aligned.bin")
        unaligned = Path("/tmp/span-unaligned.bin")
        destination = Path("/tmp/span-destination.bin")
        workloads = {workload.name: workload for workload in perf.WORKLOADS}
        self.assertEqual(
            perf.workload_arguments(
                workloads["memmem_128m_unaligned"], dso, dso, dso, graph_root,
                span_source_aligned=aligned,
                span_source_unaligned=unaligned,
                span_destination=destination,
            ),
            [
                "span_matrix", "4", "memmem", str(perf.CACHE_SPAN_BYTES), "3",
                str(unaligned), str(destination),
            ],
        )
        with self.assertRaisesRegex(ValueError, "requires staged cache-spanning inputs"):
            perf.workload_arguments(workloads["memmem_128m_unaligned"], dso, dso, dso, graph_root)


class WorkloadSelectionTests(unittest.TestCase):
    def test_selects_declared_rows_in_stable_matrix_order(self) -> None:
        selected = perf.select_workloads(["memchr_64_unaligned", "memcpy_64_aligned"])
        self.assertEqual(
            [workload.name for workload in selected],
            ["memcpy_64_aligned", "memchr_64_unaligned"],
        )

    def test_rejects_unknown_and_duplicate_workload_selection(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown workload selection: unknown"):
            perf.select_workloads(["unknown"])
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            perf.select_workloads(["memcpy_64_aligned", "memcpy_64_aligned"])

    def test_selects_the_declared_fixture_binary_for_startup_contracts(self) -> None:
        workloads = {workload.name: workload for workload in perf.WORKLOADS}
        lane = {
            "binary": Path("/tmp/workload"),
            "constructor_binary": Path("/tmp/constructor"),
            "graph_binary": Path("/tmp/graph"),
        }
        self.assertEqual(perf.workload_binary_for_lane(workloads["startup"], lane), Path("/tmp/workload"))
        self.assertEqual(
            perf.workload_binary_for_lane(workloads["startup_constructor_destructor"], lane),
            Path("/tmp/constructor"),
        )
        self.assertEqual(
            perf.workload_binary_for_lane(workloads["startup_dependency_graph"], lane),
            Path("/tmp/graph"),
        )


class CacheTopologyTests(unittest.TestCase):
    def test_parses_linux_cache_sizes_without_accepting_malformed_values(self) -> None:
        self.assertEqual(perf.parse_cache_size_bytes("128K\n"), 128 * 1024)
        self.assertEqual(perf.parse_cache_size_bytes("12M"), 12 * 1024 * 1024)
        self.assertEqual(perf.parse_cache_size_bytes("1G"), 1024 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "unexpected cache size"):
            perf.parse_cache_size_bytes("128KB")

    def test_records_cache_entries_and_classifies_fixed_scalar_sizes(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cpu7" / "cache"
            entries = (
                ("index0", "1", "Data", "128K", "64", "7"),
                ("index1", "2", "Unified", "2M", "64", "4-7"),
            )
            for index, level, cache_type, size, line, shared in entries:
                entry = cache / index
                entry.mkdir(parents=True)
                (entry / "level").write_text(level + "\n", encoding="ascii")
                (entry / "type").write_text(cache_type + "\n", encoding="ascii")
                (entry / "size").write_text(size + "\n", encoding="ascii")
                (entry / "coherency_line_size").write_text(line + "\n", encoding="ascii")
                (entry / "shared_cpu_list").write_text(shared + "\n", encoding="ascii")

            topology = perf.benchmark_cpu_cache_topology(7, root)

        self.assertEqual(topology["status"], "ok")
        self.assertEqual(topology["caches"][0]["size_bytes"], 128 * 1024)
        classes = topology["scalar_matrix_size_classes"]
        self.assertEqual(classes["64"]["cache_level"], 1)
        self.assertEqual(classes[str(16 * 1024)]["cache_level"], 1)
        self.assertEqual(classes[str(256 * 1024)]["cache_level"], 2)
        self.assertEqual(
            topology["cache_span_size_class"],
            {
                "bytes": perf.CACHE_SPAN_BYTES,
                "classification": "exceeds-largest-reported-data-cache",
            },
        )

    def test_marks_missing_sysfs_as_unsupported(self) -> None:
        with TemporaryDirectory() as temporary:
            topology = perf.benchmark_cpu_cache_topology(0, Path(temporary))
        self.assertEqual(topology["status"], "unsupported")
        self.assertIn("cache sysfs is unavailable", topology["reason"])


class CacheSpanFixtureTests(unittest.TestCase):
    def test_stages_tail_needle_and_c_string_terminator_at_the_requested_offset(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "span.bin"
            perf.stage_cache_span_source(path, span_bytes=1024, offset=3)
            contents = path.read_bytes()

        self.assertEqual(len(contents), 3 + 1024 + perf.CACHE_SPAN_PADDING_BYTES)
        self.assertEqual(contents[:3], b"aaa")
        self.assertEqual(contents[3 + 1024 - len(perf.CACHE_SPAN_NEEDLE):3 + 1024], perf.CACHE_SPAN_NEEDLE)
        self.assertEqual(contents[3 + 1024], 0)


class PairedSamplingTests(unittest.TestCase):
    def test_plan_is_seeded_and_keeps_each_lane_pair_adjacent(self) -> None:
        plan = perf.paired_sample_plan(samples=3, seed=7)
        self.assertEqual(plan, perf.paired_sample_plan(samples=3, seed=7))
        self.assertEqual(len(plan), 6)
        self.assertEqual({sample_index for _lane, sample_index in plan}, {0, 1, 2})
        for offset in range(0, len(plan), 2):
            first, second = plan[offset:offset + 2]
            self.assertEqual(first[1], second[1])
            self.assertNotEqual(first[0], second[0])

    def test_bootstrap_cpu_ratio_is_deterministic(self) -> None:
        reference = [10, 20, 30]
        candidate = [8, 16, 24]
        score = perf.bootstrap_cpu_ratio(reference, candidate, seed=11, resamples=100)
        self.assertEqual(score["median_ratio"], 0.8)
        self.assertEqual(score, perf.bootstrap_cpu_ratio(reference, candidate, seed=11, resamples=100))


if __name__ == "__main__":
    unittest.main()
