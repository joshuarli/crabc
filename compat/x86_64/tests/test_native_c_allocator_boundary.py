#!/usr/bin/env python3
"""Focused installed-product C allocator boundary reader contracts."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/native_c_allocator_boundary.py"
SPEC = importlib.util.spec_from_file_location("native_c_allocator_boundary_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
BOUNDARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOUNDARY
SPEC.loader.exec_module(BOUNDARY)


class NativeCAllocatorBoundaryHarnessTests(unittest.TestCase):
    def test_interposition_runner_retains_owned_dynamic_link_receipts(self) -> None:
        runner = (ROOT / "compat/x86_64/run_owned_c_allocation_interposition.sh").read_text(
            encoding="utf-8"
        )

        for mode in ("pie", "non-pie"):
            self.assertIn(f'"$work/candidate-$mode.crabc-link.json"', runner)
        self.assertIn('"$installed/bin/crabc-cc-dynamic" "$candidate_mode" --link-receipt', runner)

    def test_link_receipt_reader_keeps_the_real_workload_separate_from_its_output(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            work = output / "work"
            work.mkdir()
            workload = work / "workload.o"
            executable = work / "candidate-pie"
            receipt = work / "candidate-pie.crabc-link.json"
            for path in (workload, executable, receipt):
                path.write_bytes(b"fixture")
            with (
                mock.patch.object(BOUNDARY.product_evidence, "validate_link", return_value={"linkage": "pie"}) as validate,
                mock.patch.object(BOUNDARY, "json_object", return_value={"resolved_linker": {"path": "/fixture/ld.lld", "sha256": "a" * 64}}),
                mock.patch.object(BOUNDARY, "physical_file", return_value=Path("/fixture/ld.lld")),
                mock.patch.object(BOUNDARY.inventory, "sha256", return_value="a" * 64),
            ):
                BOUNDARY._link(work, output, Path("/fixture/product"), workload, "candidate-pie", "candidate-pie.crabc-link.json", "pie")
            self.assertEqual(validate.call_args.args[:4], (Path("/fixture/product"), workload, executable, receipt))

    def test_static_preparation_uses_its_actual_two_field_product_source_shape(self) -> None:
        source = {"revision": "a" * 40, "content_sha256": "b" * 64}
        self.assertEqual(BOUNDARY._product_source({"source": source}), source)

    def test_current_wrapper_and_lifecycle_sources_match_the_supplied_b525_epoch(self) -> None:
        resolution = BOUNDARY.source_resolution(ROOT, "b52538c57e07958a1d31ef5321dd5c6e2dedc258")
        self.assertEqual(resolution["product_revision"], "b52538c57e07958a1d31ef5321dd5c6e2dedc258")
        self.assertEqual(set(resolution["runtime_source_sha256"]), set(BOUNDARY.RUNTIME_SOURCES))

    def test_host_replay_uses_the_retained_workspace_link_reader_and_sealed_linker(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            work = output / "work"
            work.mkdir()
            for name in ("workload.o", "candidate-pie", "candidate-pie.crabc-link.json"):
                (work / name).write_bytes(b"fixture")
            link = {
                "validated": {"linkage": "pie"},
                "linker": {"path": "/opt/ld.lld", "sha256": "a" * 64},
                "executable": BOUNDARY.identity(work / "candidate-pie", logical_path="work/candidate-pie"),
                "receipt": BOUNDARY.identity(work / "candidate-pie.crabc-link.json", logical_path="work/candidate-pie.crabc-link.json"),
            }
            with mock.patch.object(BOUNDARY.product_evidence, "validate_retained_link", return_value={"linkage": "pie"}) as validate:
                BOUNDARY._replay_link(work, output, Path("/fixture/product"), work / "workload.o", "candidate-pie", "candidate-pie.crabc-link.json", "pie", link)
            self.assertEqual(validate.call_args.args[:3], (ROOT, "/workspace", Path("/fixture/product")))
            self.assertEqual(validate.call_args.args[-1], link["linker"])


if __name__ == "__main__":
    unittest.main()
