"""Focused raw-to-derived regressions for native x86 C-performance evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
WORK_ROOT = ROOT / ".work/x86_64"
WORK_ROOT.mkdir(parents=True, exist_ok=True)
MODULE = ROOT / "compat/perf/x86_64_evidence.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_x86_evidence", MODULE)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


RESOURCE_FIELDS = (
    "user_cpu_ns", "system_cpu_ns", "max_rss_kib", "minor_faults", "major_faults",
    "voluntary_context_switches", "involuntary_context_switches",
)


def identity(path: Path) -> dict[str, object]:
    return evidence.container_file_identity(ROOT, evidence.SOURCE_MOUNT, path)


def resources(value: int) -> dict[str, int]:
    return {name: value for name in RESOURCE_FIELDS}


class CanonicalProfileInvocationTests(unittest.TestCase):
    def test_host_reader_reconstructs_all_114_timed_invocations(self) -> None:
        invocations = evidence.canonical_workload_invocations(ROOT)
        self.assertEqual(len(invocations), 114)
        self.assertEqual(
            invocations["allocator_live_32m"],
            {
                "binary": "/app/bin/x86_64_clock_allocator_workload",
                "arguments": ["live", "1", "128", "262144"],
                "fixture_mode": "live",
                "iterations_per_process": 1,
                "operations_per_process": 128,
            },
        )
        self.assertEqual(
            invocations["resolver_dns_tcp"]["arguments"],
            ["resolver_dns_tcp", "1000", "tc.example.test.", "80", "198.51.100.45"],
        )
        self.assertEqual(
            invocations["memmem_guard63"]["binary"],
            "/app/bin/x86_64_primitive_boundary_workload",
        )

    def test_rewriting_file_row_does_not_share_the_read_fixture(self) -> None:
        """No row's input may depend on whether a rewriting row ran first.

        ``stdio_format_parse`` recreates its file with ``w+``; the 4-KiB
        descriptor/stdio rows require the intact ``0..255`` pattern.  Observers
        run every row before the timed samples, so a shared path made those
        rows fail by order alone.
        """

        invocations = evidence.canonical_workload_invocations(ROOT)
        read_rows = ("fd_file_4k", "stdio_file_4k")
        read_paths = {invocations[name]["arguments"][-1] for name in read_rows}
        self.assertEqual(read_paths, {evidence.IO_FIXTURE_FILE})
        self.assertEqual(invocations["stdio_format_parse"]["arguments"][-1], evidence.FORMAT_PARSE_FILE)
        self.assertNotEqual(evidence.FORMAT_PARSE_FILE, evidence.IO_FIXTURE_FILE)

    def test_full_build_roster_keeps_timed_and_memory_artifacts_distinct(self) -> None:
        """All 114 rows use 28 fixed provider outputs, never 114 rebuilds."""

        self.assertEqual(len(evidence.FULL_LINK_NAMES), 28)
        self.assertEqual(len(evidence.FULL_OBJECT_NAMES), 28)
        self.assertIn("x86_64_clock_allocator_workload", evidence.FULL_LINK_NAMES)
        self.assertIn("x86_64_memory_observer_clock_allocator", evidence.FULL_LINK_NAMES)
        self.assertIn("x86_64_memory_observer_graph", evidence.GRAPH_LINK_NAMES)
        self.assertEqual(
            evidence._expected_link_object("x86_64_memory_observer_network"),
            "memory_observer:x86_64_memory_observer_network",
        )
        self.assertEqual(
            evidence._expected_link_flags(ROOT, "x86_64_memory_observer_clock_allocator"),
            ["-pthread"],
        )
        self.assertIn("x86_64-profile.toml", evidence.FULL_HEADER_PATHS)
        self.assertIn("diagnostic_marker.h", evidence.FULL_HEADER_PATHS)


class RawTraceReplayTests(unittest.TestCase):
    def test_scorecard_gate_requires_whole_process_and_classifies_every_difference(self) -> None:
        """A zero marked main cannot conceal startup/loader syscall drift."""

        reference = {
            "marked_region": {"calls": {}},
            "whole_process": {"calls": {"openat": {"calls": 10, "errors": 0}}},
        }
        candidate = {
            "marked_region": {"calls": {}},
            "whole_process": {"calls": {"openat": {"calls": 41, "errors": 0}}},
        }
        gate = evidence.scorecard_syscall_gate(reference, candidate, operations=1)
        self.assertEqual(gate["marked_region"]["status"], "pass")
        self.assertEqual(gate["whole_process"]["status"], "fail")
        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["whole_process"]["total_calls"]["release_gate"], "fail")
        self.assertTrue(any("whole_process: total calls: candidate 41 exceeds 2R=20" == item for item in gate["violations"]))

        # A candidate can remain below 2R and still cannot pass until a
        # workload-contract owner classifies the nonzero lifecycle difference.
        candidate["whole_process"]["calls"]["openat"]["calls"] = 11
        unresolved = evidence.scorecard_syscall_gate(reference, candidate, operations=1)
        self.assertEqual(unresolved["whole_process"]["status"], "fail")
        self.assertEqual(unresolved["whole_process"]["total_calls"]["release_gate"], "pass")
        self.assertTrue(any("unclassified" in item for item in unresolved["violations"]))

        # Per-name redistribution is visible for review but does not replace
        # the scorecard's total-call 2R rule with a stricter per-name rule.
        reference["whole_process"]["calls"] = {
            "openat": {"calls": 8, "errors": 0}, "close": {"calls": 2, "errors": 0},
        }
        candidate["whole_process"]["calls"] = {
            "openat": {"calls": 3, "errors": 0}, "close": {"calls": 17, "errors": 0},
        }
        redistributed = evidence.scorecard_syscall_gate(reference, candidate, operations=1)
        self.assertEqual(redistributed["whole_process"]["total_calls"], {
            "reference": 10, "candidate": 20, "threshold_numerator": 2,
            "threshold_denominator": 1, "rule": "at-most-2R", "release_gate": "pass",
        })
        self.assertEqual(redistributed["status"], "fail")
        self.assertTrue(any("unclassified" in item for item in redistributed["violations"]))

    def test_whole_process_begins_at_selected_execve_not_python_prelude(self) -> None:
        begin = "CRABC_PERF_BEGIN"
        end = "CRABC_PERF_END"
        trace = "\n".join((
            'openat(AT_FDCWD, "/workspace/python-prelude", O_RDONLY) = 3',
            'execve("/app/bin/workload", ["/app/bin/workload", "clock_gettime", "7"], 0x1 /* 5 vars */) = 0',
            f'write(97, "{begin}", {len(begin)}) = {len(begin)}',
            'getpid() = 42',
            f'write(97, "{end}", {len(end)}) = {len(end)}',
            'close(3) = 0',
            '',
        ))
        summary = evidence.replay_whole_process_after_execve(
            trace, "/app/bin/workload", ["clock_gettime", "7"], 97, begin, end
        )
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["boundary_trace_line"], 2)
        self.assertNotIn("openat", summary["calls"])
        self.assertEqual(summary["calls"]["execve"], {"calls": 1, "errors": 0})
        self.assertEqual(summary["calls"]["getpid"], {"calls": 1, "errors": 0})
        self.assertEqual(summary["calls"]["close"], {"calls": 1, "errors": 0})

    def test_raw_trace_rejects_forged_marked_region(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            begin = "CRABC_PERF_BEGIN"
            end = "CRABC_PERF_END"
            trace = directory / "trace.raw"
            trace.write_text("\n".join((
                'execve("/app/bin/workload", ["/app/bin/workload", "mode"], 0x1 /* 5 vars */) = 0',
                f'write(97, "{begin}", {len(begin)}) = {len(begin)}',
                'getpid() = 1',
                f'write(97, "{end}", {len(end)}) = {len(end)}',
                '',
            )), encoding="utf-8")
            stdout = directory / "stdout"; stdout.write_bytes(b"ok\n")
            stderr = directory / "stderr"; stderr.write_bytes(b"")
            markers = directory / "markers"; markers.write_bytes(b"")
            strace_stdout = directory / "strace.stdout"; strace_stdout.write_bytes(b"")
            strace_stderr = directory / "strace.stderr"; strace_stderr.write_bytes(b"")
            invocation = {
                "binary": "/app/bin/workload", "arguments": ["mode"],
                "fixture_mode": "test", "iterations_per_process": 1,
            }
            marked = evidence.replay_marker_region(trace.read_text(), 97, begin, end)
            whole = evidence.replay_whole_process_after_execve(trace.read_text(), "/app/bin/workload", ["mode"], 97, begin, end)
            diagnostic = {
                "status": "ok", "diagnostic": True, "timing": False,
                "child": {"kind": "exit", "code": 0}, "resources": resources(1),
                "trace": identity(trace), "stdout": identity(stdout), "stderr": identity(stderr),
                "markers": identity(markers), "strace_stdout": identity(strace_stdout), "strace_stderr": identity(strace_stderr),
                "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
                "whole_process": whole, "marked_region": marked,
                "workload_execve": {"path": "/app/bin/workload", "argv": ["/app/bin/workload", "mode"]},
                "successful_workload_execve_trace_lines": [whole["boundary_trace_line"]],
                "marker_writes_excluded_from_whole_process": True,
            }
            evidence._verify_diagnostic(ROOT, diagnostic, invocation, "trace")
            forged = copy.deepcopy(diagnostic)
            forged["marked_region"]["calls"]["getpid"]["calls"] = 99
            with self.assertRaisesRegex(evidence.EvidenceError, "marked syscall region"):
                evidence._verify_diagnostic(ROOT, forged, invocation, "trace")

    def test_raw_trace_rejects_lane_swapped_preexec_chroot(self) -> None:
        """The selected client trace must enter the matching sealed lane root."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            begin = "CRABC_PERF_BEGIN"
            end = "CRABC_PERF_END"
            musl_root = "/workspace/.work/x86_64/roots/musl"
            crabc_root = "/workspace/.work/x86_64/roots/crabc"
            trace = directory / "trace.raw"
            trace.write_text("\n".join((
                f'chroot("{crabc_root}") = 0',
                'execve("/app/bin/workload", ["/app/bin/workload", "mode"], 0x1 /* 5 vars */) = 0',
                f'write(97, "{begin}", {len(begin)}) = {len(begin)}',
                'getpid() = 1',
                f'write(97, "{end}", {len(end)}) = {len(end)}',
                '',
            )), encoding="utf-8")
            stdout = directory / "stdout"; stdout.write_bytes(b"ok\n")
            stderr = directory / "stderr"; stderr.write_bytes(b"")
            markers = directory / "markers"; markers.write_bytes(b"")
            strace_stdout = directory / "strace.stdout"; strace_stdout.write_bytes(b"")
            strace_stderr = directory / "strace.stderr"; strace_stderr.write_bytes(b"")
            invocation = {
                "binary": "/app/bin/workload", "arguments": ["mode"],
                "fixture_mode": "test", "iterations_per_process": 1,
            }
            marked = evidence.replay_marker_region(trace.read_text(), 97, begin, end)
            whole = evidence.replay_whole_process_after_execve(
                trace.read_text(), "/app/bin/workload", ["mode"], 97, begin, end,
            )
            diagnostic = {
                "status": "ok", "diagnostic": True, "timing": False,
                "child": {"kind": "exit", "code": 0}, "resources": resources(1),
                "trace": identity(trace), "stdout": identity(stdout), "stderr": identity(stderr),
                "markers": identity(markers), "strace_stdout": identity(strace_stdout), "strace_stderr": identity(strace_stderr),
                "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
                "whole_process": whole, "marked_region": marked,
                "workload_execve": {"path": "/app/bin/workload", "argv": ["/app/bin/workload", "mode"]},
                "successful_workload_execve_trace_lines": [whole["boundary_trace_line"]],
                "marker_writes_excluded_from_whole_process": True,
                "peer": None,
            }
            rows = evidence.performance_profile.performance_rows(
                ROOT, evidence._performance_contract(str(ROOT.resolve())).WORKLOADS,
            )
            row = next(item for item in rows if item.name == "startup")
            with self.assertRaisesRegex(evidence.EvidenceError, "chroot"):
                evidence._verify_diagnostic(
                    ROOT, diagnostic, invocation, "lane-trace", row=row,
                    root_record=musl_root, host={}, seen_peers=set(),
                )


class RawMemoryReplayTests(unittest.TestCase):
    def test_raw_smaps_rejects_forged_pss(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            status = directory / "status"
            rollup = directory / "smaps_rollup"
            smaps = directory / "smaps"
            status.write_text("Pid:\t123\nVmRSS:\t      12 kB\nVmHWM:\t      12 kB\nVmSize:\t      24 kB\n", encoding="utf-8")
            rollup.write_text("Rss:                12 kB\nPss:                 9 kB\nPrivate_Clean:       1 kB\nPrivate_Dirty:       8 kB\n", encoding="utf-8")
            smaps.write_text(
                "00400000-00401000 r--p 00000000 00:00 0 /workspace/.work/x86_64/mapped\n"
                "Rss:                   12 kB\nPss:                    9 kB\n"
                "Private_Clean:          1 kB\nPrivate_Dirty:          8 kB\n",
                encoding="utf-8",
            )
            snapshot = {
                "vmrss_kib": 12, "vmhwm_kib": 12, "vmsize_kib": 24,
                "rss_kib": 12, "pss_kib": 9, "private_clean_kib": 1, "private_dirty_kib": 8,
                "mapping_attribution": evidence._performance_contract(str(ROOT.resolve())).smaps_mapping_summary(smaps.read_text()),
                "raw": {"status": identity(status), "smaps_rollup": identity(rollup), "smaps": identity(smaps)},
            }
            evidence._verify_memory_snapshot(ROOT, snapshot, "memory", expected_pid=123)
            forged = copy.deepcopy(snapshot)
            forged["pss_kib"] = 10
            with self.assertRaisesRegex(evidence.EvidenceError, "disagrees"):
                evidence._verify_memory_snapshot(ROOT, forged, "memory")
            with self.assertRaisesRegex(evidence.EvidenceError, "status PID"):
                evidence._verify_memory_snapshot(ROOT, snapshot, "memory", expected_pid=124)

    def test_raw_cgroup_peak_rejects_a_forged_after_exit_value(self) -> None:
        """The post-ready increase must come from retained cgroup bytes."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            stdout = directory / "stdout"; stdout.write_bytes(b"ok\n")
            stderr = directory / "stderr"; stderr.write_bytes(b"")
            before_peak = directory / "memory-peak-before"; before_peak.write_text("4096\n", encoding="ascii")
            after_peak = directory / "memory-peak-after"; after_peak.write_text("8192\n", encoding="ascii")
            before_stat = directory / "memory-stat-before"; before_stat.write_text("anon 4096\n", encoding="ascii")
            after_stat = directory / "memory-stat-after"; after_stat.write_text("anon 8192\n", encoding="ascii")
            raw = {
                "memory_peak_before_ready": identity(before_peak),
                "memory_peak_after_exit": identity(after_peak),
                "memory_stat_before_continue": identity(before_stat),
                "memory_stat_after_exit": identity(after_stat),
            }
            result = {
                "status": "ok", "mode": "allocator_after_ready", "live_allocation_bytes": 128 * 262144,
                "memory": {"raw": {}},
                "cgroup_memory": {
                    "status": "ok", "memory_peak_before_ready_bytes": 4096,
                    "memory_peak_after_exit_bytes": 8192,
                    "memory_stat": {"before_continue": {"anon": 4096}, "after_exit": {"anon": 8192}},
                    "raw": raw,
                    "attribution_limit": "memory.peak can include warm file-cache charges; it is retained as cgroup high-water and is never reset, subtracted, or read from Docker's parent cgroup",
                },
                "migration": {
                    "pid": 123, "root": "/workspace/.work/x86_64/root", "executable": "/usr/bin/python3",
                    "expected_executable": "/usr/bin/python3", "threads": 1,
                    "probe": "/workspace/.work/x86_64/probe", "event": "syscall-entry-execve",
                    "syscall": {
                        "api": "PTRACE_GET_SYSCALL_INFO", "entry": True, "architecture": "x86_64", "number": 59,
                        "path": "/app/bin/workload",
                        "argv": ["/app/bin/workload", "allocator_after_ready", "128", "262144", "97", "98"],
                    },
                },
                "child": {"kind": "exit", "code": 0}, "resources": resources(0),
                "stdout": identity(stdout), "stderr": identity(stderr),
                "stdout_sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(), "mappings": None,
            }
            owned_probe = "/workspace/.work/x86_64/probe"
            evidence._verify_memory_probe(
                ROOT, result, "post-ready", live=False,
                expected_root=result["migration"]["root"], owned_probe_leaves=[owned_probe],
            )
            forged = copy.deepcopy(result)
            forged["cgroup_memory"]["memory_peak_after_exit_bytes"] = 9000
            with self.assertRaisesRegex(evidence.EvidenceError, "peak values"):
                evidence._verify_memory_probe(
                    ROOT, forged, "post-ready", live=False,
                    expected_root=result["migration"]["root"], owned_probe_leaves=[owned_probe],
                )
            foreign_root = copy.deepcopy(result)
            foreign_root["migration"]["root"] = "/workspace/.work/x86_64/foreign-root"
            with self.assertRaisesRegex(evidence.EvidenceError, "matching sealed execution root"):
                evidence._verify_memory_probe(
                    ROOT, foreign_root, "post-ready", live=False,
                    expected_root=result["migration"]["root"], owned_probe_leaves=[owned_probe],
                )
            foreign_probe = copy.deepcopy(result)
            foreign_probe["migration"]["probe"] = "/workspace/.work/x86_64/foreign-probe"
            with self.assertRaisesRegex(evidence.EvidenceError, "owned cleaned cgroup leaf"):
                evidence._verify_memory_probe(
                    ROOT, foreign_probe, "post-ready", live=False,
                    expected_root=result["migration"]["root"], owned_probe_leaves=[owned_probe],
                )

    def test_probe_assignment_rejects_reused_cgroup_leaf(self) -> None:
        mount = "/workspace/.work/x86_64/cgroup2-private"
        probes = {
            (lane, phase): f"{mount}/probe-{lane}-{phase}"
            for lane in ("musl", "crabc") for phase in ("live", "after-ready")
        }
        memory = {
            lane: {
                "migration": {"probe": probes[(lane, "live")]},
                "cgroup_memory": {"after_ready_self_test": {"migration": {"probe": probes[(lane, "after-ready")]}}},
            }
            for lane in ("musl", "crabc")
        }
        evidence._verify_probe_assignment(memory, {}, (), list(probes.values()), mount)
        reused = copy.deepcopy(memory)
        reused["crabc"]["cgroup_memory"]["after_ready_self_test"]["migration"]["probe"] = probes[("crabc", "live")]
        with self.assertRaisesRegex(evidence.EvidenceError, "lane/phase"):
            evidence._verify_probe_assignment(reused, {}, (), list(probes.values()), mount)
        swapped = copy.deepcopy(memory)
        swapped["musl"]["migration"]["probe"] = probes[("crabc", "live")]
        with self.assertRaisesRegex(evidence.EvidenceError, "lane/phase"):
            evidence._verify_probe_assignment(swapped, {}, (), list(probes.values()), mount)


class ObservedMappingReplayTests(unittest.TestCase):
    def test_observer_maps_replay_in_recorded_mount_before_host_translation(self) -> None:
        """Container `/workspace` maps remain valid when host replay relocates them."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            root = directory / "execution/roots/musl"
            mapped = root / "app/bin/observer"
            mapped.parent.mkdir(parents=True)
            mapped.write_bytes(b"observer")
            root_record = evidence._recorded_path(ROOT, evidence.SOURCE_MOUNT, str(root))
            mapped_record = f"{root_record}/app/bin/observer"
            raw = directory / "maps.raw"
            raw.write_text(
                f"00400000-00401000 r-xp 00000000 00:00 0 {mapped_record}\n",
                encoding="utf-8",
            )
            mappings = {"raw": identity(raw), "paths": [mapped_record]}
            evidence._verify_observer_mapping(ROOT, mappings, root, root_record, "mapping")


class RawElfReplayTests(unittest.TestCase):
    @staticmethod
    def _minimal_dynamic_dso() -> bytes:
        """A bounded ET_DYN image with the same facts as its readelf fixture."""

        dynamic_offset = 0x200
        strings_offset = 0x300
        strings = b"\0libc.so\0/app/lib:/usr/lib\0"
        data = bytearray(0x400)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                         3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        struct.pack_into("<IIQQQQQQ", data, 64,
                         1, 5, 0, 0, 0, len(data), len(data), 0x1000)
        struct.pack_into("<IIQQQQQQ", data, 64 + 56,
                         2, 4, dynamic_offset, dynamic_offset, dynamic_offset, 6 * 16, 6 * 16, 8)
        entries = (
            (5, strings_offset), (10, len(strings)), (1, 1), (29, 9), (4, 0x380), (0, 0),
        )
        for index, entry in enumerate(entries):
            struct.pack_into("<qQ", data, dynamic_offset + index * 16, *entry)
        data[strings_offset:strings_offset + len(strings)] = strings
        return bytes(data)

    def _stream(self, directory: Path, name: str, contents: str) -> dict[str, object]:
        output = directory / f"{name}.out"
        stderr = directory / f"{name}.err"
        output.write_text(contents, encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        arguments = {
            "header": ["-hW"], "program_headers": ["-lW"], "dynamic": ["-dW"], "dynamic_symbols": ["--dyn-syms", "-W"],
        }[name]
        return {
            "command": [evidence.FIXED_READELF, *arguments, self.output_record["path"]],
            "status": {"kind": "exit", "code": 0}, "output": identity(output), "stderr": identity(stderr),
        }

    def test_swapped_dynamic_raw_cannot_validate_another_output(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            binary = directory / "libsymbols_1.so"; binary.write_bytes(self._minimal_dynamic_dso())
            self.output_record = identity(binary)
            header = "Class:                             ELF64\nData:                              2's complement, little endian\nType:                              DYN (Shared object file)\nMachine:                           Advanced Micro Devices X86-64\n"
            dynamic = " 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n 0x000000000000001d (RUNPATH)            Library runpath: [/app/lib:/usr/lib]\n 0x0000000000000004 (HASH)               0x0\n"
            raw = {
                "header": self._stream(directory, "header", header),
                "program_headers": self._stream(directory, "program_headers", "Program Headers:\n"),
                "dynamic": self._stream(directory, "dynamic", dynamic),
                "dynamic_symbols": self._stream(directory, "dynamic_symbols", "Symbol table '.dynsym' contains 1 entry:\n"),
            }
            for name in ("link.stdout", "link.stderr"):
                path = directory / name; path.write_bytes(b"")
                raw["link_" + name.split(".")[1]] = identity(path)
            evidence._verify_readelf_record(ROOT, raw, self.output_record, provider="musl", name="libsymbols_1.so", index=1)
            foreign = directory / "foreign-dynamic.out"
            foreign.write_text(" 0x0000000000000001 (NEEDED)             Shared library: [other.so]\n", encoding="utf-8")
            forged = copy.deepcopy(raw)
            forged["dynamic"]["output"] = identity(foreign)
            with self.assertRaisesRegex(evidence.EvidenceError, "dynamic"):
                evidence._verify_readelf_record(ROOT, forged, self.output_record, provider="musl", name="libsymbols_1.so", index=1)
            binary.write_bytes(b"not an ELF")
            replaced = identity(binary)
            with self.assertRaisesRegex(evidence.EvidenceError, "physical ELF output"):
                evidence._verify_readelf_record(ROOT, raw, replaced, provider="musl", name="libsymbols_1.so", index=1)


class DynamicReceiptReplayTests(unittest.TestCase):
    def test_direct_receipt_rejects_a_changed_dso_identity(self) -> None:
        """Schema-2 links bind their direct input bytes, not just a receipt hash."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            product = directory / "product"
            manifest = product / "share/crabc/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("{}\n", encoding="utf-8")
            output = directory / "workload"; output.write_bytes(b"elf-output")
            dso = directory / "libbench.so"; dso.write_bytes(b"application-dso")
            dynamic = directory / "dynamic.raw"
            dynamic.write_text(
                " 0x0000000000000001 (NEEDED)             Shared library: [libbench.so]\n"
                " 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n"
                " 0x000000000000001d (RUNPATH)            Library runpath: [/app/lib:/usr/lib]\n"
                " 0x0000000000000004 (HASH)               0x0\n", encoding="utf-8",
            )
            dso_hash = hashlib.sha256(dso.read_bytes()).hexdigest()
            receipt = directory / "workload.crabc-link.json"
            record = {
                "schema": 2, "format": "crabc-x86-64-owned-dynamic-sysroot-v1", "mode": "pie", "binding": "now",
                "runtime_imports": [], "application_runpath": "/app/lib:/usr/lib", "application_rpath": None,
                "application_search_kind": "runpath", "application_hash_style": "sysv",
                "output_path": str(output), "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "application_dsos": {"libbench.so": dso_hash}, "owned_runtime_inputs": [],
                "input_receipts": [{"path": str(dso), "sha256": dso_hash}],
                "resolved_linker": {"path": "/usr/bin/ld.lld", "sha256": "a" * 64},
                "link_command": ["/usr/bin/ld.lld", str(dso)], "link_trace": [str(dso)], "campaign_complete": False,
            }
            receipt.write_text(__import__("json").dumps(record), encoding="utf-8")
            search = type("Search", (), {"schema": 2, "kind": "runpath", "path": "/app/lib:/usr/lib", "hash_style": "sysv"})()
            contract = type("Contract", (), {"validate": staticmethod(lambda *args, **kwargs: search)})()
            with patch.object(evidence, "_receipt_contract", return_value=contract):
                evidence.validate_dynamic_direct_receipt(
                    checkout=ROOT, product=product, receipt_path=receipt, output=output, dynamic_raw=dynamic,
                    expected_direct=[dso], expected_mode="pie", expected_search_path="/app/lib:/usr/lib",
                )
                record["application_dsos"] = {"libbench.so": "b" * 64}
                receipt.write_text(__import__("json").dumps(record), encoding="utf-8")
                with self.assertRaisesRegex(evidence.EvidenceError, "DSO roster"):
                    evidence.validate_dynamic_direct_receipt(
                        checkout=ROOT, product=product, receipt_path=receipt, output=output, dynamic_raw=dynamic,
                        expected_direct=[dso], expected_mode="pie", expected_search_path="/app/lib:/usr/lib",
                    )


class ImageToolManifestTests(unittest.TestCase):
    def test_retained_manifest_must_bind_the_selected_external_hashes(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            raw = directory / "image-tools.manifest"
            hashes = {
                evidence.FIXED_MUSL_COMPILER: "a" * 64,
                evidence.FIXED_READELF: "b" * 64,
                evidence.FIXED_STRACE: "c" * 64,
                evidence.FIXED_MUSL_LOADER: "d" * 64,
                evidence.FIXED_MUSL_LIBC: "e" * 64,
            }
            raw.write_text(
                f"format={evidence.IMAGE_TOOL_MANIFEST_FORMAT}\n"
                + "".join(f"{path} {digest}\n" for path, digest in hashes.items()), encoding="ascii",
            )
            record = {
                "raw": identity(raw), "format": evidence.IMAGE_TOOL_MANIFEST_FORMAT, "tools": hashes,
            }
            tools = {
                "musl_compiler": {"sha256": hashes[evidence.FIXED_MUSL_COMPILER]},
                "readelf": {"sha256": hashes[evidence.FIXED_READELF]},
                "strace": {"sha256": hashes[evidence.FIXED_STRACE]},
                "musl_loader": {"sha256": hashes[evidence.FIXED_MUSL_LOADER]},
                "musl_libc": {"sha256": hashes[evidence.FIXED_MUSL_LIBC]},
            }
            evidence._verify_image_tool_manifest(ROOT, record, index=1, tools=tools)
            forged = copy.deepcopy(record)
            forged["tools"][evidence.FIXED_STRACE] = "f" * 64
            with self.assertRaisesRegex(evidence.EvidenceError, "manifest record"):
                evidence._verify_image_tool_manifest(ROOT, forged, index=1, tools=tools)


class CpuDiagnosticReplayTests(unittest.TestCase):
    def test_raw_cpu_model_and_frequency_telemetry_replay_independently(self) -> None:
        """Frequency drift stays diagnostic, while replay still needs raw bytes."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            raw = Path(temporary) / "cpuinfo.raw"
            raw.write_bytes(
                b"processor\t: 0\n"
                b"model name\t: Example x86 CPU\n"
                b"cpu MHz\t\t: 3200.000\n"
                b"bogomips\t: 6400.00\n"
            )
            record = {"raw": identity(raw), **evidence.cpuinfo_diagnostics(raw.read_bytes())}
            self.assertEqual(
                evidence._verify_cpuinfo_diagnostic(ROOT, record, "before"),
                {"model_names": ["Example x86 CPU"], "cpu_mhz": ["3200.000"], "bogomips": ["6400.00"]},
            )
            forged = copy.deepcopy(record)
            forged["cpu_mhz"] = ["800.000"]
            with self.assertRaisesRegex(evidence.EvidenceError, "differs from raw"):
                evidence._verify_cpuinfo_diagnostic(ROOT, forged, "before")

    def test_stable_cpu_identity_replays_both_raw_captures(self) -> None:
        """Volatile frequency drift is allowed; a changed CPU identity is not."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            before = directory / "cpuinfo.before"
            after = directory / "cpuinfo.after"
            before.write_bytes(
                b"model name\t: Example x86 CPU\n"
                b"cpu MHz\t\t: 3200.000\n"
                b"bogomips\t: 6400.00\n"
            )
            after.write_bytes(
                b"model name\t: Example x86 CPU\n"
                b"cpu MHz\t\t: 800.000\n"
                b"bogomips\t: 1600.00\n"
            )
            diagnostics = {
                "before": {"raw": identity(before), **evidence.cpuinfo_diagnostics(before.read_bytes())},
                "after": {"raw": identity(after), **evidence.cpuinfo_diagnostics(after.read_bytes())},
            }
            host = {"cpuinfo_sha256": evidence.cpuinfo_identity_sha256(before.read_bytes())}
            evidence._verify_stable_cpuinfo_identity(ROOT, host, diagnostics, index=1)
            after.write_bytes(after.read_bytes().replace(b"Example x86 CPU", b"Other x86 CPU"))
            diagnostics["after"] = {"raw": identity(after), **evidence.cpuinfo_diagnostics(after.read_bytes())}
            with self.assertRaisesRegex(evidence.EvidenceError, "stable CPU identity"):
                evidence._verify_stable_cpuinfo_identity(ROOT, host, diagnostics, index=1)


def _row_workload(*, cpu_upper: float, marked: tuple[int, int], whole: tuple[int, int]) -> dict[str, object]:
    """Build one already-replayed timed row from raw-shaped call totals."""

    def diagnostic(calls: int) -> dict[str, object]:
        return {"calls": {"getpid": {"calls": calls, "errors": 0}} if calls else {}}

    gate = evidence.scorecard_syscall_gate(
        {"marked_region": diagnostic(marked[0]), "whole_process": diagnostic(whole[0])},
        {"marked_region": diagnostic(marked[1]), "whole_process": diagnostic(whole[1])},
        operations=10,
    )
    summary = {
        key: {"min": 1, "median": 2, "p95": 3, "max": 4}
        for key in (
            "elapsed_wall_ns", "resources.user_cpu_ns", "resources.system_cpu_ns", "resources.max_rss_kib",
            "resources.minor_faults", "resources.major_faults", "resources.voluntary_context_switches",
            "resources.involuntary_context_switches",
        )
    }
    return {
        "musl": {"summary": summary},
        "crabc": {"summary": summary},
        "comparison": {
            "cpu": {
                "median_ratio": cpu_upper - 0.01, "one_sided_95_upper": cpu_upper,
                "resamples": evidence.CPU_RESAMPLES, "seed": 1,
                "release_gate": "pass" if cpu_upper <= 0.90 else "fail",
            },
            "syscall_gate": gate,
        },
    }


def _row_observer(*, pss: tuple[int, int], peak: tuple[int, int]) -> dict[str, object]:
    return {"comparison": {
        "status": "ok",
        "pss_max_kib": evidence._memory_metric(*pss),
        "memory_peak_after_exit_bytes": evidence._memory_metric(*peak),
    }}


PASSING_ROW = {"cpu_upper": 0.85, "marked": (10, 10), "whole": (20, 20)}
PASSING_MEMORY = {"pss": (1000, 800), "peak": (1 << 20, 900_000)}


class ScorecardDerivationTests(unittest.TestCase):
    def test_row_passes_only_when_all_four_metrics_pass(self) -> None:
        row = evidence.row_scorecard(_row_workload(**PASSING_ROW), _row_observer(**PASSING_MEMORY))
        self.assertEqual(row["gate"], "pass")
        self.assertEqual(row["syscalls"]["whole_process"], {"reference": 20, "candidate": 20, "gate": "pass"})

        failing = {
            "cpu": (_row_workload(**{**PASSING_ROW, "cpu_upper": 0.91}), _row_observer(**PASSING_MEMORY)),
            "pss": (_row_workload(**PASSING_ROW), _row_observer(**{**PASSING_MEMORY, "pss": (1000, 901)})),
            "memory_peak": (_row_workload(**PASSING_ROW), _row_observer(**{**PASSING_MEMORY, "peak": (1000, 901)})),
            "reference-zero memory": (_row_workload(**PASSING_ROW), _row_observer(**{**PASSING_MEMORY, "peak": (0, 0)})),
            "marked syscalls": (_row_workload(**{**PASSING_ROW, "marked": (0, 1)}), _row_observer(**PASSING_MEMORY)),
            "whole-process syscalls above 2R": (_row_workload(**{**PASSING_ROW, "whole": (20, 41)}), _row_observer(**PASSING_MEMORY)),
            # No native classification owner exists, so an in-bound difference
            # is still an explicit unresolved failure.
            "unclassified whole-process difference": (
                _row_workload(**{**PASSING_ROW, "whole": (20, 30)}), _row_observer(**PASSING_MEMORY),
            ),
        }
        for label, (workload, observer) in failing.items():
            with self.subTest(label):
                self.assertEqual(evidence.row_scorecard(workload, observer)["gate"], "fail")

    def test_one_failed_attempt_fails_the_row_without_compensation(self) -> None:
        passing = evidence.row_scorecard(_row_workload(**PASSING_ROW), _row_observer(**PASSING_MEMORY))
        failed = evidence.row_scorecard(
            _row_workload(**{**PASSING_ROW, "cpu_upper": 1.2}), _row_observer(**PASSING_MEMORY),
        )
        scorecard = evidence.collector_scorecard([
            {"startup": passing, "getpid": passing},
            {"startup": passing, "getpid": failed},
            {"startup": passing, "getpid": passing},
        ])
        self.assertEqual(scorecard["failing_rows"], ["getpid"])
        self.assertEqual(scorecard["passing_rows"], 1)
        self.assertEqual([item["gate"] for item in scorecard["rows"]["getpid"]["attempts"]], ["pass", "fail", "pass"])
        with self.assertRaisesRegex(evidence.EvidenceError, "ordered workload roster"):
            evidence.collector_scorecard([{"startup": passing}, {"getpid": passing}, {"startup": passing}])

    def test_release_blockers_name_every_unmet_condition(self) -> None:
        canonical = list(evidence.canonical_workload_invocations(ROOT))
        available = {"status": "available", "owner": evidence.CORRECTNESS_OWNER, "unmet": []}
        validated = {"status": "validated-product-prerequisite"}
        policy = [f"acceptance policy {key}: {value}" for key, value in evidence.ACCEPTANCE_POLICY_BLOCKERS.items()]
        self.assertEqual(evidence.release_blockers(
            admission=available, dynamic_product=validated, budget=evidence.FULL_BUDGET, attempts=3,
            workloads=canonical, canonical_workloads=canonical, failing_rows=[],
        ), policy)
        blockers = evidence.release_blockers(
            admission={"status": "unavailable", "owner": evidence.CORRECTNESS_OWNER, "unmet": ["a: planned"]},
            dynamic_product={"status": "unavailable"}, budget=evidence.SMOKE_BUDGET, attempts=1,
            workloads=canonical[1:], canonical_workloads=canonical, failing_rows=["getpid"],
        )
        self.assertEqual(len(blockers), 6 + len(policy))
        self.assertIn("a: planned", blockers[0])
        self.assertIn("owned-dynamic-qualification", blockers[1])
        self.assertIn("implementation-smoke", blockers[2])
        self.assertIn("1 attempt(s)", blockers[3])
        self.assertIn(canonical[0], blockers[4])
        self.assertIn("getpid", blockers[5])


class CorrectnessAdmissionTests(unittest.TestCase):
    def test_every_incomplete_predecessor_gate_is_named(self) -> None:
        admission = evidence.correctness_admission(ROOT)
        chain = evidence._x86_module(ROOT, "generate_qualification_manifest").CHAIN
        predecessors = chain[:chain.index(evidence.PERFORMANCE_GATE)]
        self.assertEqual(admission["status"], "unavailable")
        self.assertEqual(admission["owner"], evidence.CORRECTNESS_OWNER)
        self.assertEqual([item.split(":")[0] for item in admission["unmet"]], list(predecessors))

    def test_only_completed_predecessors_admit(self) -> None:
        owner = evidence._x86_module(ROOT, "generate_qualification_manifest")
        contract = owner.load_contract()
        completed = copy.deepcopy(contract)
        completed["incomplete_gates"] = [evidence.PERFORMANCE_GATE]
        with patch.object(owner, "load_contract", return_value=completed):
            self.assertEqual(evidence.correctness_admission(ROOT),
                             {"status": "available", "owner": evidence.CORRECTNESS_OWNER, "unmet": []})
        one_open = copy.deepcopy(contract)
        one_open["incomplete_gates"] = ["capability.accounting", evidence.PERFORMANCE_GATE]
        with patch.object(owner, "load_contract", return_value=one_open):
            admission = evidence.correctness_admission(ROOT)
        self.assertEqual(admission["status"], "unavailable")
        self.assertEqual(len(admission["unmet"]), 1)
        self.assertTrue(admission["unmet"][0].startswith("capability.accounting: "))


class CollectorCompositionTests(unittest.TestCase):
    def test_collector_replays_each_attempt_and_derives_its_release_decision(self) -> None:
        """The live three-attempt loop derives, never accepts, scorecard and release."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            source_revision = "a" * 40
            source_digest = "b" * 64
            product = {"manifest": {"sha256": "c" * 64}, "driver": {"path": "/workspace/product/driver"}}
            dynamic = {"status": "unavailable", "reason": "no validated owned-dynamic-qualification receipt was supplied"}
            admission = evidence.correctness_admission(ROOT)

            def recorded(path: Path) -> str:
                return "/workspace/" + path.relative_to(ROOT).as_posix()

            requests: list[dict[str, object]] = []
            for index in range(1, evidence.COLLECTOR_ATTEMPTS + 1):
                work = directory / f"attempt-{index}"
                work.mkdir()
                report = work / "report.json"
                requests.append({
                    "index": index, "work_dir": recorded(work), "report": recorded(report),
                    "predecessor_report": None if index == 1 else requests[index - 2]["report"],
                })
            roster = {
                "schema": evidence.ROSTER_SCHEMA, "kind": evidence.ROSTER_KIND, "status": "planned",
                "source_mount": evidence.SOURCE_MOUNT, "source_revision": source_revision,
                "source_sha256": source_digest, "product": product,
                "dynamic_product_qualification": dynamic, "correctness_admission": admission,
                "budget": evidence.SMOKE_BUDGET, "attempts": requests,
            }
            roster_path = directory / "attempt-roster.json"
            roster_path.write_text(json.dumps(roster), encoding="utf-8")
            attempt_paths: list[Path] = []
            image_id = "sha256:" + "d" * 64
            for index, request in enumerate(requests, start=1):
                attempt_path = directory / f"attempt-{index}" / "report.json"
                prior = None if index == 1 else identity(attempt_paths[index - 2])
                attempt = {
                    "schema": evidence.SCHEMA, "kind": evidence.KIND, "status": evidence.SMOKE_BUDGET,
                    "source_mount": evidence.SOURCE_MOUNT,
                    "attempt": {
                        "index": index, "docker_image_id": image_id, "invocation_nonce": f"nonce-{index:012d}",
                        "clean_revision": True, "source_revision": source_revision,
                        "roster": {"status": "bound", "plan": identity(roster_path), "request": request, "predecessor": prior},
                    },
                    "source": {}, "product": {"before": product, "after": copy.deepcopy(product)},
                    "tools": {}, "build": {}, "execution": {},
                    "measurement": {"attempt-marker": index},
                    "release": {"qualified": False, "reason": evidence.RELEASE_QUALIFICATION_REASON},
                }
                attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
                attempt_paths.append(attempt_path)
            collector = {
                "attempt_roster": identity(roster_path), "dynamic_product_qualification": dynamic,
                "correctness_admission": admission, "budget": evidence.SMOKE_BUDGET,
                "attempt_count": evidence.COLLECTOR_ATTEMPTS,
                "source": {"anything": {}}, "source_revision": source_revision,
                "source_sha256": source_digest, "product": product,
            }
            report = {
                "schema": evidence.SCHEMA, "kind": evidence.KIND, "status": evidence.SMOKE_BUDGET,
                "source_mount": evidence.SOURCE_MOUNT, "collector": collector,
                "attempts": [{"index": index, "report": identity(path)} for index, path in enumerate(attempt_paths, start=1)],
                "scorecard": {}, "release": {},
            }
            broken_roster = copy.deepcopy(roster)
            broken_roster["attempts"][1]["predecessor_report"] = None
            roster_path.write_text(json.dumps(broken_roster), encoding="utf-8")
            with self.assertRaisesRegex(evidence.EvidenceError, "predecessor"):
                evidence._verify_collector_roster(ROOT, roster_path, collector)
            roster_path.write_text(json.dumps(roster), encoding="utf-8")
            passing = evidence.row_scorecard(_row_workload(**PASSING_ROW), _row_observer(**PASSING_MEMORY))
            failing = evidence.row_scorecard(
                _row_workload(**{**PASSING_ROW, "whole": (11, 81)}), _row_observer(**PASSING_MEMORY),
            )
            seen: list[dict[str, object]] = []
            replayed: list[tuple[int, str, str]] = []

            def tools_replay(_checkout: Path, attempt: dict[str, object], product_record: object, _index: int) -> None:
                self.assertIsInstance(product_record, dict)
                self.assertEqual(product_record, attempt["product"]["before"])
                self.assertIn("driver", product_record)
                seen.append(product_record)

            def measurement_replay(_checkout: Path, attempt: dict[str, object], _workloads: object, *, full: bool, budget: str) -> list[str]:
                self.assertTrue(full)
                replayed.append((attempt["measurement"]["attempt-marker"], budget, attempt["attempt"]["roster"]["request"]["work_dir"]))
                return []

            def scorecards(measurement: dict[str, object]) -> dict[str, object]:
                return {"startup": passing, "getpid": failing if measurement["attempt-marker"] == 2 else passing}

            with patch.object(evidence, "verify_dynamic_product_identity", return_value=directory / "product"), \
                 patch.object(evidence, "verify_file_seal"), \
                 patch.object(evidence, "_verify_attempt_source"), \
                 patch.object(evidence, "_verify_attempt_tools", side_effect=tools_replay), \
                 patch.object(evidence, "_verify_attempt_build"), \
                 patch.object(evidence, "_verify_attempt_execution"), \
                 patch.object(evidence, "validate_measurement_attempt", side_effect=measurement_replay), \
                 patch.object(evidence, "attempt_scorecard", side_effect=scorecards):
                scorecard, release = evidence.replay_collection(ROOT, report)
                self.assertEqual(len(seen), evidence.COLLECTOR_ATTEMPTS)
                self.assertEqual([entry[:2] for entry in replayed],
                                 [(1, evidence.SMOKE_BUDGET), (2, evidence.SMOKE_BUDGET), (3, evidence.SMOKE_BUDGET)])
                self.assertEqual([entry[2] for entry in replayed], [request["work_dir"] for request in requests])
                self.assertEqual(scorecard["budget"], evidence.SMOKE_BUDGET)
                self.assertEqual(scorecard["failing_rows"], ["getpid"])
                self.assertFalse(release["qualified"])
                self.assertTrue(any("implementation-smoke" in item for item in release["blockers"]))
                self.assertTrue(any(item.startswith("correctness admission") for item in release["blockers"]))

                report_path = directory / "collector.json"
                report_path.write_text(json.dumps({**report, "scorecard": scorecard, "release": release}), encoding="utf-8")
                checked = evidence.validate_collector_report(ROOT, report_path)
                self.assertTrue(checked.evidence_valid)
                self.assertFalse(checked.release_qualified)
                self.assertEqual(list(checked.blockers), release["blockers"])

                forged_release = {**report, "scorecard": scorecard, "release": {"qualified": True, "blockers": []}}
                report_path.write_text(json.dumps(forged_release), encoding="utf-8")
                with self.assertRaisesRegex(evidence.EvidenceError, "release decision"):
                    evidence.validate_collector_report(ROOT, report_path)
                forged_scorecard = copy.deepcopy(scorecard)
                forged_scorecard["failing_rows"] = []
                report_path.write_text(json.dumps({**report, "scorecard": forged_scorecard, "release": release}), encoding="utf-8")
                with self.assertRaisesRegex(evidence.EvidenceError, "scorecard does not derive"):
                    evidence.validate_collector_report(ROOT, report_path)
                full_label = copy.deepcopy(report)
                full_label["status"] = "complete-evidence"
                with self.assertRaisesRegex(evidence.EvidenceError, "budget"):
                    evidence.replay_collection(ROOT, full_label)
                self_admitted = copy.deepcopy(report)
                self_admitted["collector"]["correctness_admission"] = {
                    "status": "available", "owner": evidence.CORRECTNESS_OWNER, "unmet": [],
                }
                with self.assertRaisesRegex(evidence.EvidenceError, "ordered qualification chain"):
                    evidence.replay_collection(ROOT, self_admitted)


class DynamicQualificationReplayTests(unittest.TestCase):
    def test_partial_qualification_receipt_cannot_be_a_product_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            receipt_path = directory / "qualification.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            digest = "a" * 64
            products = {name: "b" * 64 for name in ("installed", "second", "extracted")}
            record = {
                "status": "validated-product-prerequisite", "receipt": identity(receipt_path),
                "source_sha256": digest, "products": products,
            }
            product = {"manifest": {"sha256": "b" * 64}}
            owner = type("Owner", (), {
                "validate_receipt": staticmethod(lambda _path: {
                    "schema": "crabc.x86_64-owned-dynamic-qualification/v1",
                    "status": "qualified-pending-review", "source_sha256": digest, "products": products,
                }),
                "source_digest": staticmethod(lambda: digest),
            })()
            with patch.object(evidence, "_x86_module", return_value=owner):
                evidence.verify_dynamic_product_prerequisite(ROOT, record, product, digest)
            partial = type("PartialOwner", (), {
                "validate_receipt": staticmethod(lambda _path: {"status": "partial"}),
                "source_digest": staticmethod(lambda: digest),
            })()
            with patch.object(evidence, "_x86_module", return_value=partial):
                with self.assertRaisesRegex(evidence.EvidenceError, "not a validated three-product"):
                    evidence.verify_dynamic_product_prerequisite(ROOT, record, product, digest)


class StagedRuntimeReplayTests(unittest.TestCase):
    @staticmethod
    def _origin(path: str, digest: str, *, mode: int = 0o755, size: int = 7) -> dict[str, object]:
        return {"path": path, "sha256": digest, "mode": mode, "bytes": size}

    def test_staged_application_bytes_must_match_provider_link_output(self) -> None:
        output = self._origin("/workspace/build/workload", "a" * 64)
        links = {"workload": {"musl": {"output": output}}}
        inventory = [{"path": "app/bin/workload", "kind": "file", "mode": 0o755, "sha256": "a" * 64, "bytes": 7}]
        evidence._verify_staged_link_inventory(inventory, links, "musl", index=1, lane="musl")
        swapped = copy.deepcopy(inventory)
        swapped[0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(evidence.EvidenceError, "bytes differ"):
            evidence._verify_staged_link_inventory(swapped, links, "musl", index=1, lane="musl")

    def test_staged_candidate_and_musl_runtime_bytes_have_oracles(self) -> None:
        product_libc = self._origin("/workspace/product/lib/libc.so", "a" * 64)
        candidate_inventory = [
            {"path": "lib/libc.so", "kind": "file", "mode": 0o755, "sha256": "a" * 64, "bytes": 7},
            {"path": "lib/ld-musl-x86_64.so.1", "kind": "symlink", "target": "ld-crabc-x86_64.so.1"},
        ]
        evidence._verify_staged_runtime_inventory(
            candidate_inventory, "crabc", {"payload": {"lib/libc.so": product_libc}}, {}, index=1,
        )
        candidate_swapped = copy.deepcopy(candidate_inventory)
        candidate_swapped[0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(evidence.EvidenceError, "runtime oracle"):
            evidence._verify_staged_runtime_inventory(
                candidate_swapped, "crabc", {"payload": {"lib/libc.so": product_libc}}, {}, index=1,
            )

        loader = self._origin(evidence.FIXED_MUSL_LOADER, "c" * 64)
        libc = self._origin(evidence.FIXED_MUSL_LIBC, "d" * 64)
        musl_inventory = [
            {"path": "lib/ld-musl-x86_64.so.1", "kind": "file", "mode": 0o755, "sha256": "c" * 64, "bytes": 7},
            {"path": "lib/libc.so", "kind": "file", "mode": 0o755, "sha256": "d" * 64, "bytes": 7},
            {"path": "usr/lib/libc.so", "kind": "file", "mode": 0o755, "sha256": "d" * 64, "bytes": 7},
            {"path": "opt/musl-1.2.6/lib/ld-musl-x86_64.so.1", "kind": "symlink", "target": "../../../lib/ld-musl-x86_64.so.1"},
            {"path": "opt/musl-1.2.6/lib/libc.so", "kind": "symlink", "target": "../../../lib/libc.so"},
        ]
        evidence._verify_staged_runtime_inventory(
            musl_inventory, "musl", {}, {"musl_loader": loader, "musl_libc": libc}, index=1,
        )
        missing_interpreter = musl_inventory[:-2]
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical runtime alias"):
            evidence._verify_staged_runtime_inventory(
                missing_interpreter, "musl", {}, {"musl_loader": loader, "musl_libc": libc}, index=1,
            )


class SourceRosterReplayTests(unittest.TestCase):
    def test_full_source_roster_rejects_a_foreign_sealed_c_source(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            work = directory / "attempt"
            generated = work / "build/generated"
            generated.mkdir(parents=True)
            before: dict[str, dict[str, object]] = {}
            for name, relative in evidence.FULL_SOURCE_PATHS.items():
                before[f"source:{name}"] = identity(ROOT / relative)
            for header, relative in evidence.FULL_HEADER_PATHS.items():
                before[f"header:{header}"] = identity(ROOT / relative)
            for name in ("symbols_1", "symbols_1024", *(f"graph:{entry}" for entry in evidence.GRAPH_SOURCES)):
                path = generated / f"{name.removeprefix('graph:')}.c"
                path.write_text(evidence.generated_source_contents(name), encoding="utf-8")
                before[f"source:{name}"] = identity(path)
            revision = "a" * 40
            digest = "b" * 64
            work_dir = "/workspace/" + work.relative_to(ROOT).as_posix()
            attempt = {
                "source": {
                    "before": before, "after": copy.deepcopy(before),
                    "source_sha256_before": digest, "source_sha256_after": digest,
                },
                "attempt": {"source_revision": revision},
            }
            evidence._verify_attempt_source(
                ROOT, attempt, index=1, collector_revision=revision, collector_digest=digest, work_dir=work_dir,
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "generated source path"):
                evidence._verify_attempt_source(
                    ROOT, attempt, index=1, collector_revision=revision, collector_digest=digest,
                    work_dir=work_dir + "-elsewhere",
                )
            foreign = directory / "foreign.c"
            foreign.write_text("int foreign(void) { return 0; }\n", encoding="utf-8")
            forged = copy.deepcopy(attempt)
            forged["source"]["before"]["source:workload"] = identity(foreign)
            forged["source"]["after"] = copy.deepcopy(forged["source"]["before"])
            with self.assertRaisesRegex(evidence.EvidenceError, "fixed source path"):
                evidence._verify_attempt_source(
                    ROOT, forged, index=1, collector_revision=revision, collector_digest=digest, work_dir=work_dir,
                )


class SamplePlanReplayTests(unittest.TestCase):
    def _sample(self, stdout: dict[str, object], stderr: dict[str, object], *, index: int | None = None, order: int | None = None, warmup: int | None = None, cpu: int = 100) -> dict[str, object]:
        sample: dict[str, object] = {
            "elapsed_wall_ns": cpu, "status": {"kind": "exit", "code": 0}, "resources": resources(cpu),
            "stdout": stdout, "stderr": stderr, "stdout_matches": True, "stderr_bytes": 0,
            "stdout_sha256": stdout["sha256"], "stderr_sha256": stderr["sha256"],
        }
        if index is not None:
            sample["sample_index"] = index
        if order is not None:
            sample["execution_order"] = order
        if warmup is not None:
            sample["warmup_index"] = warmup
        return sample

    def test_wrong_sample_order_and_bootstrap_claim_reject(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            ok = directory / "ok"; ok.write_bytes(b"ok\n")
            empty = directory / "empty"; empty.write_bytes(b"")
            stdout, stderr = identity(ok), identity(empty)
            name = "startup"
            invocation = evidence.canonical_workload_invocations(ROOT)[name]
            contract = evidence._performance_contract(str(ROOT.resolve()))
            seed = 917
            plan = contract.paired_sample_plan(evidence.FULL_SAMPLE_COUNT, seed)
            orders = {(lane, index): order for order, (lane, index) in enumerate(plan)}
            lanes: dict[str, dict[str, object]] = {}
            for lane, cpu in (("musl", 100), ("crabc", 90)):
                samples = [self._sample(stdout, stderr, index=index, order=orders[(lane, index)], cpu=cpu)
                           for index in range(evidence.FULL_SAMPLE_COUNT)]
                warmups = [self._sample(stdout, stderr, warmup=index, cpu=cpu)
                           for index in range(evidence.FULL_WARMUP_COUNT)]
                lanes[lane] = {
                    "status": "ok", "iterations_per_process": invocation["iterations_per_process"],
                    "operations_per_process": invocation["operations_per_process"],
                    "warmup_processes": evidence.FULL_WARMUP_COUNT, "warmups": warmups,
                    "sample_count": evidence.FULL_SAMPLE_COUNT, "samples": samples,
                    "summary": contract.summarize_samples(samples),
                    "syscalls": {"marked_region": {"calls": {}}, "whole_process": {"calls": {}}},
                }
            reference = [200 for _ in range(evidence.FULL_SAMPLE_COUNT)]
            candidate = [180 for _ in range(evidence.FULL_SAMPLE_COUNT)]
            cpu = contract.bootstrap_cpu_ratio(reference, candidate, seed=seed, resamples=evidence.CPU_RESAMPLES)
            comparison = {
                "status": "ok", "seed": seed,
                "sample_plan": [{"lane": lane, "sample_index": index} for lane, index in plan],
                "cpu": {**cpu, "release_gate": "pass" if cpu["one_sided_95_upper"] <= 0.90 else "fail"},
                "syscall_gate": evidence.scorecard_syscall_gate(
                    {"marked_region": {"calls": {}}, "whole_process": {"calls": {}}},
                    {"marked_region": {"calls": {}}, "whole_process": {"calls": {}}},
                    operations=invocation["operations_per_process"],
                ),
            }
            mapping = {"raw": identity(empty), "paths": []}
            report = {
                "measurement": {
                    "selected_workloads": [name], "samples": evidence.FULL_SAMPLE_COUNT,
                    "warmup": evidence.FULL_WARMUP_COUNT, "seed": seed,
                    "cgroup_setup": {"private_mount_command": ["mount", "-t", "cgroup2", "none", "/workspace/.work/x86_64/cgroup"]},
                    "cgroup_cleanup": {"owned_leaves": []},
                    "memory": {
                        "musl": {"mappings": mapping, "cgroup_memory": {"after_ready_self_test": {}}},
                        "crabc": {"mappings": mapping, "cgroup_memory": {"after_ready_self_test": {}}},
                    },
                    "memory_observers": {},
                    "workloads": {name: {"invocation": invocation, **lanes, "comparison": comparison}},
                },
                "execution": {"roots": {
                    "musl": {"root": "/workspace/.work/x86_64/musl-root", "observed_mappings": mapping},
                    "crabc": {"root": "/workspace/.work/x86_64/crabc-root", "observed_mappings": mapping},
                }},
            }
            with patch.object(evidence, "_verify_cgroup_lifecycle"), \
                 patch.object(evidence, "_verify_diagnostic"), \
                 patch.object(evidence, "_verify_memory_probe"), \
                 patch.object(evidence, "_verify_probe_assignment"):
                self.assertEqual(evidence.validate_measurement_attempt(ROOT, report, [name], full=False), [])
                bad_order = copy.deepcopy(report)
                bad_order["measurement"]["workloads"][name]["crabc"]["samples"][1]["execution_order"] = 0
                self.assertTrue(evidence.validate_measurement_attempt(ROOT, bad_order, [name], full=False))
                bad_bootstrap = copy.deepcopy(report)
                bad_bootstrap["measurement"]["workloads"][name]["comparison"]["cpu"]["one_sided_95_upper"] = 0.01
                self.assertTrue(evidence.validate_measurement_attempt(ROOT, bad_bootstrap, [name], full=False))
                bad_operations = copy.deepcopy(report)
                bad_operations["measurement"]["workloads"][name]["crabc"]["operations_per_process"] = 2
                self.assertTrue(evidence.validate_measurement_attempt(ROOT, bad_operations, [name], full=False))
                extra = copy.deepcopy(report)
                extra["measurement"]["workloads"]["cheap-substitute"] = copy.deepcopy(extra["measurement"]["workloads"][name])
                self.assertTrue(evidence.validate_measurement_attempt(ROOT, extra, [name], full=False))


class TimingLauncherArtifactReplayTests(unittest.TestCase):
    def test_timing_launcher_raw_artifacts_cannot_be_reused(self) -> None:
        """One raw launcher result and streams prove only one fresh client."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            invocation_directory = directory / "raw/execution/sample-musl-startup-0"
            invocation_directory.mkdir(parents=True)
            launcher_binary = directory / "launcher"; launcher_binary.write_bytes(b"launcher")
            stdout = invocation_directory / "stdout"; stdout.write_bytes(b"ok\n")
            stderr = invocation_directory / "stderr"; stderr.write_bytes(b"")
            launcher_stdout = invocation_directory / "timing-launcher.stdout"; launcher_stdout.write_bytes(b"")
            launcher_stderr = invocation_directory / "timing-launcher.stderr"; launcher_stderr.write_bytes(b"")
            raw_result = invocation_directory / "timing-launcher-result.json"
            raw_result.write_text(json.dumps({
                "schema": evidence.TIMING_LAUNCHER_SCHEMA, "child_pid": 77, "wait_status": 0,
                "timed_out": False, "elapsed_wall_ns": 11, "resources": resources(1),
            }), encoding="utf-8")
            root_record = "/workspace/.work/x86_64/staged-root"
            invocation = {"binary": "/app/bin/workload", "arguments": ["mode"]}
            sample = {
                "elapsed_wall_ns": 11, "status": {"kind": "exit", "code": 0}, "resources": resources(1),
                "stdout": identity(stdout), "stderr": identity(stderr),
            }
            launcher = {
                "command": [
                    identity(launcher_binary)["path"], root_record, sample["stdout"]["path"],
                    sample["stderr"]["path"], identity(raw_result)["path"], "1000",
                    invocation["binary"], *invocation["arguments"],
                ],
                "status": {"kind": "exit", "code": 0},
                "stdout": identity(launcher_stdout), "stderr": identity(launcher_stderr),
                "result": identity(raw_result),
            }
            seen: set[str] = set()
            evidence._verify_timing_launcher_sample(
                ROOT, sample, launcher, launcher_output=identity(launcher_binary),
                root_record=root_record, invocation=invocation, label="first",
                invocation_directory=invocation_directory, seen_artifacts=seen,
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "reused"):
                evidence._verify_timing_launcher_sample(
                    ROOT, sample, launcher, launcher_output=identity(launcher_binary),
                    root_record=root_record, invocation=invocation, label="second",
                    invocation_directory=invocation_directory, seen_artifacts=seen,
                )


if __name__ == "__main__":
    unittest.main()
