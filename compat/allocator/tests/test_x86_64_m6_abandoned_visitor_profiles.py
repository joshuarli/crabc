"""Behavioral contracts for complete abandoned-page visitor observations."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_abandoned_visitor as regular
import x86_64_m6_abandoned_os_visitor as os_visitor
import x86_64_m6_abandoned_combined_visitor as combined


def stdout(module, trace):
    return module.BEGIN + "\n" + "".join(f"{key}={value}\n" for key, value in trace.items()) + module.END + "\n"


def changed(trace, key, field, value):
    result = dict(trace)
    row = result[key].split(",")
    row[field] = str(value)
    result[key] = ",".join(row)
    return result


class AbandonedVisitorProfilesTests(unittest.TestCase):
    def test_regular_profile_geometry_preserves_payload_order_and_used_counts(self):
        trace = dict(regular.SOURCE_REGULAR_PAGE)
        for key in trace:
            if not key.endswith("before"):
                trace = changed(trace, key, 4, 152)
        output = stdout(regular, trace)
        regular.compare_runs(output, "", output, "", "debug-1")
        with self.assertRaises(regular.harness.HarnessError):
            regular.compare_runs(output, "", output, "", "release")

    def test_regular_geometry_must_be_consistent_across_early_stops(self):
        trace = changed(regular.SOURCE_REGULAR_PAGE, "abandoned.stop_block", 4, 152)
        with self.assertRaises(regular.harness.HarnessError):
            regular.require_trace(trace, "c", "debug-1")

    def test_regular_live_payload_tags_exclude_the_freed_middle_block(self):
        trace = changed(regular.SOURCE_REGULAR_PAGE, "abandoned.blocks", 5, 123)
        with self.assertRaises(regular.harness.HarnessError):
            regular.require_trace(trace, "native", "stat-2")

    def test_regular_early_block_stop_does_not_visit_second_client(self):
        trace = changed(regular.SOURCE_REGULAR_PAGE, "abandoned.stop_block", 2, 2)
        with self.assertRaises(regular.harness.HarnessError):
            regular.require_trace(trace, "c", "stat-1")

    def test_regular_ordinary_visitation_must_match_abandoned_live_clients(self):
        trace = changed(regular.SOURCE_REGULAR_PAGE, "abandoned.ordinary", 3, 3)
        with self.assertRaises(regular.harness.HarnessError):
            regular.require_trace(trace, "native")

    def test_os_source_assertions_require_both_singletons_and_owner_transfer(self):
        output = stdout(os_visitor, os_visitor.SOURCE_OS_SINGLETON)
        os_visitor.compare_runs(output, "source.os=1,1\nsource.transfer=1,1,1\n", output, "", "debug-1")
        for diagnostic in ("source.os=1,0\nsource.transfer=1,1,1\n", "source.os=1,1\nsource.transfer=1,1,0\n"):
            with self.assertRaises(regular.harness.HarnessError):
                os_visitor.compare_runs(output, diagnostic, output, "", "debug-1")

    def test_os_freed_client_membership_is_rejected(self):
        trace = changed(os_visitor.SOURCE_OS_SINGLETON, "os.blocks", 7, 1)
        with self.assertRaises(regular.harness.HarnessError):
            os_visitor.require_trace(trace, "native")

    def test_os_early_area_stop_excludes_block_callback(self):
        trace = changed(os_visitor.SOURCE_OS_SINGLETON, "os.stop_area", 2, 1)
        with self.assertRaises(regular.harness.HarnessError):
            os_visitor.require_trace(trace, "c")

    def test_combined_regular_bin_precedes_os_page(self):
        trace = changed(combined.SOURCE_COMBINED_PAGES, "combined.blocks", 8, "OSR13")
        with self.assertRaises(regular.harness.HarnessError):
            combined.require_trace(trace, "native")

    def test_combined_early_stop_does_not_reach_os_page(self):
        trace = changed(combined.SOURCE_COMBINED_PAGES, "combined.stop_regular_area", 2, 1)
        with self.assertRaises(regular.harness.HarnessError):
            combined.require_trace(trace, "c")

    def test_combined_source_assertions_preserve_arena_bin_and_os_ownership(self):
        output = stdout(combined, combined.SOURCE_COMBINED_PAGES)
        combined.compare_runs(output, "source.transfer=1,1,1,1,1\n", output, "", "stat-2")
        with self.assertRaises(regular.harness.HarnessError):
            combined.compare_runs(output, "source.transfer=1,1,1,0,1\n", output, "", "stat-2")

    def test_complete_stdout_and_diagnostics_cannot_be_filtered(self):
        output = stdout(regular, regular.SOURCE_REGULAR_PAGE)
        with self.assertRaises(regular.harness.HarnessError):
            regular.compare_runs(output, "", output + "extra observation\n", "", "release")
        with self.assertRaises(regular.harness.HarnessError):
            regular.compare_runs(output, "", output, "unexpected diagnostic\n", "release")


if __name__ == "__main__":
    unittest.main()
