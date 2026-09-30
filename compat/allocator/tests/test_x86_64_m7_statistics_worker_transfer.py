"""Validate the observable aligned-transfer statistics boundary."""

import sys
import json
from unittest import mock
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run as harness
import x86_64_m7_statistics_worker_transfer as worker


class AlignedTransferStatisticsTests(unittest.TestCase):
    def trace(self, level=2, fresh=False):
        trace = {"profile.level": str(level), "profile.fresh_free": str(int(fresh)),
                 "allocation.small_usable": "320", "allocation.huge_usable": "589824",
                 "allocation.refused": "1"}
        for stage in worker.ALIGNED_STAGES:
            trace.update({f"{stage}.{field}": "0,0,0" for field in worker.ALIGNED_COUNTS})
            trace.update({f"{stage}.{field}": "" for field in ("malloc_bins", "page_bins")})
            trace.update({f"{stage}.{field}": "0" for field in ("normal_count", "huge_count")})
        for stage in ("owner_output", "freeing_output", "final_output"):
            for field in ("binned", "huge", "requested"):
                label = "malloc req" if field == "requested" else field
                row = f"  {label}: 288 B" if level == 2 or (level == 1 and field != "requested") else ""
                trace[f"{stage}.{field}.hex"] = row.encode("ascii").hex()
        if level == 0:
            for stage in worker.ALIGNED_STAGES[1:]:
                trace[f"{stage}.huge"] = "589824,589824,589824"
                trace[f"{stage}.huge_count"] = "1"
        return trace

    def test_level_two_reads_source_requested_label(self):
        worker.validate_aligned(self.trace(), 2, False, "C")

    def test_level_two_requires_allocated_and_final_requested_rows(self):
        for stage in ("owner_output", "final_output"):
            with self.subTest(stage=stage):
                trace = self.trace()
                trace[f"{stage}.requested.hex"] = ""
                with self.assertRaises(harness.HarnessError):
                    worker.validate_aligned(trace, 2, False, "C")

    def test_refused_allocation_cannot_change_existing_accounting(self):
        for field in worker.ALIGNED_COUNTS:
            with self.subTest(field=field):
                trace = self.trace()
                trace[f"refused.{field}"] = "1,1,1"
                with self.assertRaisesRegex(harness.HarnessError, "charged failed aligned allocation"):
                    worker.validate_aligned(trace, 2, False, "C")

    def test_level_zero_retains_huge_statistics_and_disables_normal_requested(self):
        worker.validate_aligned(self.trace(level=0), 0, False, "C")
        for field in ("normal", "requested"):
            with self.subTest(field=field):
                trace = self.trace(level=0)
                trace[f"allocated.{field}"] = "1,1,1"
                with self.assertRaisesRegex(harness.HarnessError, "enabled disabled allocation statistics"):
                    worker.validate_aligned(trace, 0, False, "C")

    def test_level_zero_free_does_not_debit_unconditional_huge_allocation(self):
        trace = self.trace(level=0)
        trace["remote_free.huge"] = "589824,589824,0"
        with self.assertRaisesRegex(harness.HarnessError, "charged a level-zero free"):
            worker.validate_aligned(trace, 0, False, "C")


class InitialAttachmentStatisticsTests(unittest.TestCase):
    def trace(self, level=2, request="small"):
        size, alignment = worker.INITIAL_REQUESTS[request]
        trace = {"profile.level": str(level), "allocation.request": str(size),
                 "allocation.alignment": str(alignment), "allocation.usable": str(size)}
        for stage in worker.INITIAL_STAGES:
            trace.update({f"{stage}.{field}": "0,0,0" for field in worker.ALIGNED_COUNTS})
            trace.update({f"{stage}.{field}": "" for field in ("malloc_bins", "page_bins")})
            trace.update({f"{stage}.{field}": "0" for field in ("normal_count", "huge_count")})
        trace["allocated.theaps"] = "1,1,1"
        for stage in ("owner_exit", "freed", "collected"):
            trace[f"{stage}.theaps"] = "1,1,0"
        for stage in ("owner_output", "final_output"):
            for field in ("binned", "huge", "requested"):
                label = "malloc req" if field == "requested" else field
                trace[f"{stage}.{field}.hex"] = (f"  {label}: 64 B" if level == 2 else "").encode().hex()
        if level == 0 and request in ("huge", "os-aligned-small"):
            for stage in ("allocated", "owner_exit", "freed", "collected"):
                trace[f"{stage}.huge"] = "589824,589824,589824"
                trace[f"{stage}.huge_count"] = "1"
        return trace

    def os_trace(self, new_submap):
        trace = self.trace(request="os-aligned-small")
        witness = {"warm_index": 7, "client_index": 8 if new_submap else 7,
                   "client_lower_bound_index": 8 if new_submap else 7,
                   "client_bound_index": 8 if new_submap else 7}
        for stage in worker.INITIAL_STAGES:
            active = stage not in ("before", "untouched")
            witness[f"{stage}.mmap_calls"] = 1 + new_submap if active else 0
            for field in ("reserved", "committed"):
                if not active:
                    values = (0, 0, 0)
                elif field == "reserved":
                    values = (1114112, 1114112, 0 if stage in ("freed", "collected") else 1114112)
                else:
                    values = (131072, 131072, 65536 if stage in ("freed", "collected") else 131072)
                charge = 65536 * new_submap if active else 0
                trace[f"{stage}.{field}"] = ",".join(str(value + charge) for value in values)
        return trace, witness

    def placement(self, witness):
        return "\n".join(f"placement.{key}={value}" for key, value in witness.items())

    def test_os_page_map_charge_is_proved_without_rewriting_raw_trace(self):
        previous = None
        for new_submap in (0, 1):
            trace, witness = self.os_trace(new_submap)
            raw = dict(trace)
            accounted = worker.validate_initial(trace, 2, "os-aligned-small", "C", self.placement(witness))
            self.assertEqual(trace, raw)
            if previous is not None:
                self.assertEqual(accounted, previous)
            previous = accounted

    def test_os_page_map_charge_rejects_missing_multiindex_or_wrong_counter(self):
        trace, witness = self.os_trace(1)
        for key, value in (("client_bound_index", 9), ("client_lower_bound_index", 7), ("allocated.mmap_calls", 1)):
            with self.subTest(key=key):
                changed = dict(witness, **{key: value})
                with self.assertRaises(harness.HarnessError):
                    worker.validate_initial(trace, 2, "os-aligned-small", "C", self.placement(changed))
        with self.assertRaises(harness.HarnessError):
            worker.validate_initial(trace, 2, "os-aligned-small", "C")
        trace["collected.reserved"] = "1179648,1179648,0"
        with self.assertRaisesRegex(harness.HarnessError, "PageMap charge"):
            worker.validate_initial(trace, 2, "os-aligned-small", "C", self.placement(witness))

    def test_canonical_reader_rejects_old_matrix_without_os_aligned_small(self):
        root = mock.MagicMock(spec=Path)
        root.__truediv__.return_value.read_text.return_value = json.dumps({
            "status": "passed", "profiles": {
                f"{profile}/{request}": "passed" for profile in worker.ALIGNED_PROFILES
                for request in ("small", "medium", "huge")
            },
        })
        with mock.patch.object(harness, "require_native_x86_64"), \
             self.assertRaisesRegex(harness.HarnessError, "matrix is incomplete"):
            worker.replay_worker_transfer_matrix(root, initial=True)

    def test_untouched_statistics_query_does_not_attach_or_charge_vm(self):
        worker.validate_initial(self.trace(), 2, "small", "C")
        for field in ("theaps", "threads", "reserved", "committed"):
            with self.subTest(field=field):
                trace = self.trace()
                trace[f"untouched.{field}"] = "1,1,1"
                with self.assertRaisesRegex(harness.HarnessError, "untouched worker"):
                    worker.validate_initial(trace, 2, "small", "C")

    def test_owner_exit_must_release_first_attachment(self):
        trace = self.trace()
        trace["owner_exit.theaps"] = "1,1,1"
        with self.assertRaisesRegex(harness.HarnessError, "owner exit"):
            worker.validate_initial(trace, 2, "small", "Rust")

    def test_initial_huge_stat_zero_keeps_allocation_after_remote_free(self):
        trace = self.trace(0, "huge")
        worker.validate_initial(trace, 0, "huge", "C")
        trace["freed.huge"] = "589824,589824,0"
        with self.assertRaisesRegex(harness.HarnessError, "level-zero huge free"):
            worker.validate_initial(trace, 0, "huge", "Rust")

    def test_complete_first_attachment_trace_keeps_vm_and_printed_labels(self):
        for key in ("allocated.reserved", "allocated.committed", "owner_output.requested.hex"):
            with self.subTest(key=key):
                trace = self.trace()
                del trace[key]
                with self.assertRaises(harness.HarnessError):
                    worker.validate_initial(trace, 2, "small", "Rust")


class InitialPlacementDiagnosticTests(unittest.TestCase):
    def test_placement_diagnostic_cannot_change_another_statistics_workload(self):
        for arguments in ([], ['--aligned-transfer']):
            with self.subTest(arguments=arguments), \
                 mock.patch.object(sys, 'argv', ['worker', '--initial-placement-diagnostic', *arguments]), \
                 mock.patch.object(worker, 'run_worker_transfer_matrix') as execute, \
                 mock.patch('sys.stderr'):
                with self.assertRaises(SystemExit) as stopped:
                    worker.main()
                self.assertEqual(stopped.exception.code, 2)
                execute.assert_not_called()

    def test_explicit_initial_diagnostic_preserves_the_selected_request_and_profile(self):
        arguments = ['worker', '--initial-attachment', '--initial-request', 'os-aligned-small',
                     '--profile', 'stat-0', '--initial-placement-diagnostic', '--offline']
        with mock.patch.object(sys, 'argv', arguments), \
             mock.patch.object(worker, 'run_worker_transfer_matrix', return_value=0) as execute:
            self.assertEqual(worker.main(), 0)
        execute.assert_called_once_with(True, 'stat-0', initial=True,
            request='os-aligned-small', placement_diagnostic=True)


if __name__ == "__main__":
    unittest.main()
