#!/usr/bin/env python3
"""Exercise PageMap placement accounting across the remote large-page stages."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run as harness
import x86_64_m7_gate as gate
import x86_64_m7_os_large_remote_stats_placement as placement


class OsLargeRemotePlacementTests(unittest.TestCase):
    def trace(self, *, worker: int, warm: int, target: int) -> dict[str, str]:
        warm_new = int(warm != worker)
        target_new = int(target not in {worker, warm})
        warm_charge = 65536 * warm_new
        target_charge = 65536 * target_new
        trace = {
            "placement.worker_index": str(worker),
            "placement.warm_index": str(warm),
            "placement.target_index": str(target),
            "warm.reserved": ",".join([str(4456448 + warm_charge)] * 3),
            "warm.committed": ",".join([str(4194304 + warm_charge)] * 3),
            "warm.mmap_calls": str(1 + warm_new),
        }
        stage_values = {
            "allocated": ((4456448, 4456448, 4456448),
                          (4194304, 4194304, 4194304)),
            "owner_merged": ((4456448, 4456448, 4456448),
                             (4194304, 4194304, 4194304)),
            "worker_merged": ((4456448, 4456448, 0),
                              (4194304, 4194304, -196608)),
            "released": ((4456448, 4456448, -4456448),
                         (4194304, 4194304, -4587520)),
        }
        for stage, (reserved, committed) in stage_values.items():
            trace[f"{stage}.reserved"] = ",".join(str(value + target_charge) for value in reserved)
            trace[f"{stage}.committed"] = ",".join(str(value + target_charge) for value in committed)
            trace[f"{stage}.mmap_calls"] = str(1 + target_new)
        return trace

    def test_stage_accounting_compares_every_vm_key_across_different_placement_stages(self):
        c = self.trace(worker=10, warm=10, target=11)
        rust = self.trace(worker=10, warm=11, target=11)
        self.assertNotEqual(c["warm.reserved"], rust["warm.reserved"])
        self.assertNotEqual(c["allocated.committed"], rust["allocated.committed"])
        c_accounting = placement.source_placement(c, warmed=True)
        rust_accounting = placement.source_placement(rust, warmed=True)
        self.assertEqual(len(c_accounting["accounted_vm"]), 15)
        gate.compare_options_traces(c_accounting["accounted_vm"], rust_accounting["accounted_vm"])

    def test_later_vm_change_survives_exact_submap_accounting(self):
        c = self.trace(worker=10, warm=10, target=11)
        rust = self.trace(worker=10, warm=11, target=11)
        values = rust["released.committed"].split(",")
        values[-1] = str(int(values[-1]) + 1)
        rust["released.committed"] = ",".join(values)
        c_accounting = placement.source_placement(c, warmed=True)
        rust_accounting = placement.source_placement(rust, warmed=True)
        with self.assertRaisesRegex(harness.HarnessError, "released.committed"):
            gate.compare_options_traces(c_accounting["accounted_vm"], rust_accounting["accounted_vm"])

    def test_extra_submap_mapping_requires_a_new_address_index(self):
        trace = self.trace(worker=10, warm=11, target=11)
        trace["allocated.mmap_calls"] = "2"
        with self.assertRaisesRegex(harness.HarnessError, "target VM event"):
            placement.source_placement(trace, warmed=True)


if __name__ == "__main__":
    unittest.main()
