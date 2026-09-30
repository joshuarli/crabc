#!/usr/bin/env python3
"""Ownership admission requires both full callers before their observations."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_deleted_heap_remote_exit as ownership


class OwnershipProfileReceiptTests(unittest.TestCase):
    def receipt(self, cases, profiles=("release",)):
        parameters = {"profiles": ",".join(profiles), "modes": "before,after",
            "watchdog-seconds": "60", "workload": "original-full",
            "boundary": "explicit-native-mi-adapter", "source-assertions": "active"}
        return ownership.receipts.Receipt(Path("receipt.json"), ownership.RUNNER, {}, {},
            [{"id": case, "status": 0, "logs": {}} for case in cases], parameters)

    def admit(self, cases, profiles=("release",)):
        with patch.object(ownership.receipts, "read_receipt", return_value=self.receipt(cases, profiles)):
            ownership.ownership_matrix(ownership.DRIVER, ownership.ARTIFACTS,
                ownership.RUNNER, profiles, ("before", "after"), ownership.BEGIN,
                ownership.END, ownership.EXPECTED, read=True)

    def release_cases(self):
        return ["release-oracle-build", "release-native-build",
            "release-c-compile", "release-c-link", "release-c-before", "release-c-after",
            "release-native-compile", "release-native-link",
            "release-native-before", "release-native-after",
            "release-before-observations", "release-after-observations"]

    def test_complete_original_release_callers_are_admitted(self):
        self.admit(self.release_cases())

    def test_missing_native_final_free_is_rejected(self):
        cases = self.release_cases()
        cases.remove("release-native-after")
        with self.assertRaises(ownership.harness.HarnessError):
            self.admit(cases)

    def test_observations_before_native_final_free_are_rejected(self):
        cases = self.release_cases()
        first = cases.index("release-native-after")
        second = cases.index("release-before-observations")
        cases[first], cases[second] = cases[second], cases[first]
        with self.assertRaises(ownership.harness.HarnessError):
            self.admit(cases)

    def test_release_callers_cannot_satisfy_all_selected_profiles(self):
        with self.assertRaises(ownership.harness.HarnessError):
            self.admit(self.release_cases(), ownership.PROFILES)


if __name__ == "__main__":
    unittest.main()
