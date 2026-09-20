#!/usr/bin/env python3
"""Focused contracts for the native huge-page/multi-NUMA qualification job."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/allocator/x86_64_huge_numa_qualification.py"
SPEC = importlib.util.spec_from_file_location("huge_numa_qualification", MODULE)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qualification
SPEC.loader.exec_module(qualification)


class HugeNumaQualificationTests(unittest.TestCase):
    def test_linux_range_lists_are_parsed_without_topology_assumptions(self) -> None:
        self.assertEqual(qualification.parse_integer_set("0-1,4,8-9", subject="fixture"), {0, 1, 4, 8, 9})
        for value in ("", "1-0", "0,,1", "0-", "node0"):
            with self.subTest(value=value):
                with self.assertRaises(qualification.run.HarnessError):
                    qualification.parse_integer_set(value, subject="fixture")

    def test_c_trace_accepts_address_sorted_identity_but_requires_the_requested_node_set(self) -> None:
        output = "\n".join((
            "CRABC_MI_HUGE_NUMA_C_TRACE_BEGIN",
            "CRABC_MI_HUGE_NUMA_C_MAP.0.observed_node=7",
            "CRABC_MI_HUGE_NUMA_C_MAP.0.kernel_page_kib=1048576",
            "CRABC_MI_HUGE_NUMA_C_MAP.0.mapping_address=140737488355328",
            "CRABC_MI_HUGE_NUMA_C_MAP.1.observed_node=3",
            "CRABC_MI_HUGE_NUMA_C_MAP.1.kernel_page_kib=1048576",
            "CRABC_MI_HUGE_NUMA_C_MAP.1.mapping_address=141836999983104",
            "CRABC_MI_HUGE_NUMA_C_TRACE_END",
        ))
        rows = qualification.parse_trace(output, "C")
        qualification.validate_trace(rows, [3, 7], "C")
        with self.assertRaisesRegex(qualification.run.HarnessError, "exact requested NUMA-node set"):
            qualification.validate_trace(rows, [3, 6], "C")

    def test_rust_trace_binds_each_live_mapping_to_its_requested_node(self) -> None:
        output = "\n".join((
            "CRABC_MI_HUGE_NUMA_RUST_TRACE_BEGIN",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.0.requested_node=3",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.0.observed_node=3",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.0.kernel_page_kib=1048576",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.0.mapping_address=140737488355328",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.1.requested_node=7",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.1.observed_node=7",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.1.kernel_page_kib=1048576",
            "CRABC_MI_HUGE_NUMA_RUST_MAP.1.mapping_address=141836999983104",
            "CRABC_MI_HUGE_NUMA_RUST_TRACE_END",
        ))
        rows = qualification.parse_trace(output, "RUST")
        qualification.validate_trace(rows, [3, 7], "RUST")
        rows[1]["observed_node"] = 3
        with self.assertRaisesRegex(qualification.run.HarnessError, "did not land"):
            qualification.validate_trace(rows, [3, 7], "RUST")

    def test_trace_rejects_duplicate_or_incomplete_mapping_evidence(self) -> None:
        malformed = "\n".join((
            "CRABC_MI_HUGE_NUMA_C_TRACE_BEGIN",
            "CRABC_MI_HUGE_NUMA_C_MAP.0.observed_node=0",
            "CRABC_MI_HUGE_NUMA_C_MAP.0.observed_node=0",
            "CRABC_MI_HUGE_NUMA_C_TRACE_END",
        ))
        with self.assertRaises(qualification.run.HarnessError):
            qualification.parse_trace(malformed, "C")

    def test_mbind_probe_requires_one_raw_result_and_a_successful_unmap(self) -> None:
        output = "\n".join((
            "CRABC_MI_HUGE_NUMA_MBIND_PROBE.node=4",
            "CRABC_MI_HUGE_NUMA_MBIND_PROBE.page_bytes=4096",
            "CRABC_MI_HUGE_NUMA_MBIND_PROBE.result=-1",
            "CRABC_MI_HUGE_NUMA_MBIND_PROBE.errno=1",
            "CRABC_MI_HUGE_NUMA_MBIND_PROBE.unmap_result=0",
            "CRABC_MI_HUGE_NUMA_MBIND_PROBE.unmap_errno=0",
        ))
        self.assertEqual(qualification.parse_mbind_permission_probe(output)["errno"], 1)
        with self.assertRaises(qualification.run.HarnessError):
            qualification.parse_mbind_permission_probe(output.replace("unmap_result=0", "unmap_result=-1"))

    def test_requirement_contract_keeps_huge_pool_separate_from_ordinary_overhead(self) -> None:
        contract = qualification.qualification_requirements()
        footprint = contract["hardware_footprint"]
        self.assertEqual(footprint["mapping_size_bytes"], 1024 ** 3)
        self.assertEqual(footprint["concurrent_mappings"], 2)
        self.assertEqual(footprint["reserved_hugetlb_bytes"], 2 * 1024 ** 3)
        self.assertIn("outside", footprint["ordinary_overhead"])
        self.assertIn("unmeasured", footprint["ordinary_overhead"])
        self.assertIn("any two", contract["topology"]["selection"])
        self.assertIn("not required", contract["topology"]["cpu_affinity"])

    def test_source_prerequisite_virtual_address_envelope_is_not_hidden_in_ordinary_ram(self) -> None:
        envelope = qualification.source_prerequisite_virtual_address()
        self.assertEqual(envelope["required_rlimit_as"], "unlimited")
        self.assertEqual(envelope["source_mapping_peak_bytes"], 36 * 1024 ** 3 + 96 * 1024 ** 2)
        self.assertEqual(envelope["source_mapping_peak_gib"], 36)
        self.assertEqual(envelope["source_mapping_peak_mib_remainder"], 96)
        self.assertEqual(envelope["c_registry_peak_bytes"], 18 * 1024 ** 3 + 32 * 1024 ** 2)
        others = envelope["other_selected_prerequisites"]
        self.assertEqual(others["huge_reservation_c_anonymous_span_bytes"], 3 * 1024 ** 3)
        self.assertEqual(others["huge_reservation_rust_aligned_retry_peak_bytes"], 4 * 1024 ** 3)
        self.assertEqual(
            qualification.qualification_requirements()["source_prerequisite_virtual_address"], envelope,
        )

    def test_cargo_json_selects_only_the_actual_mimalloc_lib_test_product(self) -> None:
        messages = "\n".join((
            '{"reason":"compiler-artifact","target":{"name":"other","kind":["lib"]},"executable":"/work/other"}',
            '{"reason":"compiler-artifact","target":{"name":"crabc_mimalloc","kind":["lib"]},"executable":"/work/mimalloc-test"}',
            '{"reason":"build-finished","success":true}',
        ))
        self.assertEqual(qualification.cargo_test_executable(messages), Path("/work/mimalloc-test"))
        with self.assertRaises(qualification.run.HarnessError):
            qualification.cargo_test_executable('{"reason":"build-finished","success":true}')

    def test_retained_run_directory_rejects_nonempty_reuse_and_keeps_a_stable_pointer(self) -> None:
        scratch = ROOT / ".work/allocator-x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary_name:
            temporary = Path(temporary_name)
            runs = temporary / "runs"
            first = qualification.reserve_run_directory(runs, "run-first")
            (first / "receipt.json").write_text('{"preserved":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(qualification.run.HarnessError, "refuses to reuse"):
                qualification.reserve_run_directory(runs, "run-first")
            second = qualification.reserve_run_directory(runs, "run-second")
            output = {
                "directory": second,
                "report": second / "receipt.json",
                "products": second / "products",
            }
            original_latest = qualification.LATEST_REPORT
            try:
                qualification.LATEST_REPORT = temporary / "latest.json"
                qualification.publish_report(output, {"schema": qualification.SCHEMA,
                                                      "format": qualification.FORMAT,
                                                      "status": "pending_external_resources"})
            finally:
                qualification.LATEST_REPORT = original_latest
            self.assertTrue((first / "receipt.json").is_file())
            latest = json.loads((temporary / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(latest["status"], "pending_external_resources")
            self.assertEqual(latest["latest_receipt"]["path"], qualification.run.relative(output["report"]))

    def test_checked_in_c_workloads_preserve_the_source_and_permission_boundaries(self) -> None:
        huge = (ROOT / "compat/allocator/m2_huge_numa_qualification_x86_64.c").read_text(encoding="utf-8")
        permission = (ROOT / "compat/allocator/m2_huge_numa_permission_x86_64.c").read_text(encoding="utf-8")
        registry = (ROOT / "compat/allocator/m2_huge_registry_x86_64.c").read_text(encoding="utf-8")
        reservation = (ROOT / "compat/allocator/m2_huge_reservation_x86_64.c").read_text(encoding="utf-8")
        registry_rust = (ROOT / "crabc-mimalloc/src/arena_owned.rs").read_text(encoding="utf-8")
        registry_runner = (ROOT / "compat/allocator/x86_64_huge_registry_evidence.py").read_text(encoding="utf-8")
        config = (ROOT / "crabc-mimalloc/src/config.rs").read_text(encoding="utf-8")
        mapping = (ROOT / "crabc-mimalloc/src/os.rs").read_text(encoding="utf-8")
        self.assertIn('#include "static.c"', huge)
        self.assertIn("mi_reserve_huge_os_pages_at(1", huge)
        self.assertIn("numa_maps itself is address-sorted", huge)
        self.assertNotIn("MAP_HUGETLB", permission[permission.index("int main"):])
        self.assertNotIn("#include <linux/mempolicy.h>", permission)
        self.assertIn("enum { MPOL_PREFERRED = 1 };", permission)
        self.assertIn("MPOL_PREFERRED", permission)
        self.assertIn("SYS_mbind", permission)
        self.assertIn("munmap", permission)
        self.assertIn("17 * MI_GiB", registry)
        self.assertIn("MI_ARENA_MIN_SIZE", registry)
        self.assertIn("3 * MI_HUGE_OS_PAGE_SIZE", reservation)
        self.assertGreaterEqual(registry_rust.count("test_registry_allocation(process, config(), 17)"), 2)
        self.assertIn('"arena::owned::tests::huge_"', registry_runner)
        self.assertIn("--test-threads=1", registry_runner)
        self.assertIn("pub(crate) const ARENA_MIN_SIZE: usize = BCHUNK_BITS * ARENA_SLICE_SIZE", config)
        self.assertIn("let over_length = match length.checked_add(alignment_headroom)", mapping)
        self.assertIn("mapping.is_mapped = false", mapping)

    def test_private_launcher_adds_only_ipc_lock_for_the_hardware_job(self) -> None:
        launcher = (ROOT / "compat/allocator/run-x86_64.sh").read_text(encoding="utf-8")
        self.assertIn("allocator-huge-numa-qualification)", launcher)
        self.assertIn("run_in_container --with-ipc-lock", launcher)
        self.assertIn("--cap-add=IPC_LOCK", launcher)
        self.assertNotIn("security-opt seccomp=unconfined", launcher)


if __name__ == "__main__":
    unittest.main()
