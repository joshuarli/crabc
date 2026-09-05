"""Fail-closed assembly regressions for native x86 M2 VM evidence."""

from __future__ import annotations

import copy
import unittest
from unittest import mock

from test_runner import RUNNER


class NativeVmAssemblyTests(unittest.TestCase):
    @staticmethod
    def vm_evidence(summary):
        vm = next(component for component in summary["components"] if component["id"] == "vm-primitives")
        producer = RUNNER._m2_x86_64_vm_producer()
        fragment = RUNNER.read_json(RUNNER.M2_X86_64_VM_FRAGMENT)
        anchors = []
        seen = set()
        for definition in fragment["component"]["bounded_source_definitions"]:
            anchor = definition["source_anchor"]
            key = (anchor["member"], anchor["start_line"], anchor["end_line"])
            if key not in seen:
                seen.add(key)
                anchors.append({"bytes": 1, **anchor})
        for branch in fragment["component"]["branch_matrix"]:
            for anchor in branch["source_anchors"]:
                key = (anchor["member"], anchor["start_line"], anchor["end_line"])
                if key not in seen:
                    seen.add(key)
                    anchors.append({"bytes": 1, **anchor})
        pin = RUNNER.load_pin()
        c_command = [
            "musl-gcc",
            "-std=c11",
            "-fPIC",
            "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            *RUNNER.CONFIGURATION_PROFILES["release"],
            "-I",
            "/pinned/include",
            "-I",
            "/pinned/src",
            str(RUNNER.ALLOCATOR_ROOT / "m2_vm_x86_64.c"),
            *(f"/pinned/{path}" for path in RUNNER.M1_RAW_PRIMITIVE_ORACLE_SOURCES),
            "-Wl,--wrap=munmap",
            "-pthread",
            "-o",
            "/work/m2-vm-primitives-oracle",
        ]
        return {
            "architecture": "x86_64",
            "c_command": c_command,
            "c_source_files": [
                {"path": path, "sha256": "a" * 64, "bytes": 1}
                for path in sorted(("include/mimalloc/prim.h", "src/os.c", "src/prim/prim.c", "src/prim/unix/prim.c"))
            ],
            "compared_value_count": len(producer.TRACE_KEYS),
            "comparison": {"compared_value_count": len(producer.TRACE_KEYS), "status": "matched"},
            "fixture": {"path": "compat/allocator/m2_vm_x86_64.c", "sha256": "b" * 64, "bytes": 1},
            "format": 1,
            "profile": "release-no-default-features-fixed-regular-vm-thp-disabled-offset-release-fault",
            "rust_build_command": ["cargo", "test", "--no-run"],
            "rust_command": [
                ".work/prepared-test",
                "os::tests::emit_m2_vm_primitives_c_rust_trace",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
            "rust_passed_test_count": 1,
            "schema": "crabc-mimalloc-x86_64-m2-vm-primitives-evidence",
            "source_anchors": anchors,
            "status": "passed",
            "trace_sha256": "c" * 64,
            "upstream": {"revision": pin["revision"], "archive_sha256": pin["sha256"]},
            "nonclaims": list(vm["remaining_conditions"]),
        }

    def test_release_fault_trace_schema_requires_the_retained_owner_and_retry(self):
        producer = RUNNER._m2_x86_64_vm_producer()
        self.assertIn(
            "m2.vm.release.failure.full_memid_base_and_size",
            producer.TRACE_KEYS,
        )
        self.assertIn(
            "m2.vm.release.retry.full_memid_base_and_size",
            producer.TRACE_KEYS,
        )
        values = {key: 1 for key in producer.TRACE_KEYS}
        values.update(
            {
                "m2.vm.config.page_size": 4096,
                "m2.vm.config.large_page_size": 2 * 1024 * 1024,
                "m2.vm.config.alloc_granularity": 4096,
                "m2.vm.config.has_transparent_huge_pages": 0,
                "m2.vm.reserved.initially_committed": 0,
                "m2.vm.normal.good_size": 4096,
                "m2.vm.aligned.alignment": 64 * 1024,
                "m2.vm.aligned.good_size": 4096,
                "m2.vm.offset.good_size": 17 * 4096,
            }
        )
        trace = "\n".join(
            [producer.TRACE_BEGIN, *(f"{key}={value}" for key, value in values.items()), producer.TRACE_END]
        )
        self.assertEqual(producer.parse_trace(trace, source="test"), values)

        missing_retry = trace.replace(
            "m2.vm.release.retry.real_munmap_success=1\n", "", 1
        )
        with self.assertRaises(ValueError):
            producer.parse_trace(missing_retry, source="test")

    def summary(self):
        return RUNNER.validate_x86_64_m2_memory_substrate_contract(
            RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT), RUNNER.load_pin()
        )

    def test_partial_vm_fragment_materializes_all_receipts_without_promotion(self):
        summary = self.summary()
        vm = summary["components"][0]
        self.assertEqual(vm["id"], "vm-primitives")
        self.assertEqual(vm["native_status"], "partial")
        self.assertEqual(len(vm["checks"]), 17)
        self.assertEqual(len(vm["bounded_source_definitions"]), 7)
        self.assertEqual(len(vm["branch_matrix"]), 13)
        self.assertEqual(len(vm["unqualified_failure_matrix"]), 3)
        self.assertEqual(len(vm["remaining_conditions"]), 5)
        self.assertEqual(summary["milestone"]["status"], "partial")

    def test_vm_fragment_reference_and_partial_status_fail_closed(self):
        contract = RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT)
        contract["components"][0]["evidence_fragment"]["inventory_sha256"] = "0" * 64
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER.validate_x86_64_m2_memory_substrate_contract(contract, RUNNER.load_pin())

        contract = RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT)
        with mock.patch.object(
            RUNNER,
            "_m2_x86_64_vm_component",
            return_value={
                **self.summary()["components"][0],
                "native_status": "complete",
                "remaining_conditions": [],
            },
        ), self.assertRaises(RUNNER.HarnessError):
            RUNNER.validate_x86_64_m2_memory_substrate_contract(contract, RUNNER.load_pin())

    def test_vm_producer_receipt_rejects_missing_comparison_anchors_and_nonclaims(self):
        summary = self.summary()
        for field, replacement in (
            ("status", "partial"),
            ("compared_value_count", 34),
            ("source_anchors", []),
            ("nonclaims", []),
        ):
            with self.subTest(field=field):
                evidence = self.vm_evidence(summary)
                evidence[field] = replacement
                with self.assertRaises(RUNNER.HarnessError):
                    RUNNER._m2_x86_64_vm_check_records(summary, evidence)

    def test_vm_producer_receipt_requires_the_wrapped_direct_source_closure(self):
        summary = self.summary()

        omitted_wrapper = self.vm_evidence(summary)
        omitted_wrapper["c_command"].remove("-Wl,--wrap=munmap")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, omitted_wrapper)

        wrong_source = self.vm_evidence(summary)
        wrong_source["c_command"].append("/pinned/src/os.c")
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_vm_check_records(summary, wrong_source)


if __name__ == "__main__":
    unittest.main()
