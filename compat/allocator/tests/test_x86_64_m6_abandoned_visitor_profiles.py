"""Behavioral contracts for complete abandoned-page visitor observations."""

from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
from unittest import mock

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


class AbandonedVisitorReceiptRosterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for argv in (("init", "-q"), ("config", "user.email", "test@example.invalid"),
                     ("config", "user.name", "test")):
            subprocess.run(["git", *argv], cwd=self.root, check=True)
        (self.root / ".gitignore").write_text(".work/\n")
        (self.root / "fixture.c").write_text("int main(void) { return 0; }\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.root, check=True)
        self.work = self.root / ".work/run"
        self.work.mkdir(parents=True)
        log = self.work / "success.stdout"
        log.write_text("success\n")
        self.cases = []
        self.products = {}
        for name in (regular.DRIVER.name, "mimalloc.h", "LICENSE", "mimalloc-3.5.0.tar.gz", "inputs.json"):
            product = self.work / name
            product.write_bytes(b"retained fixture input\n")
            self.products[name] = product
        for profile in regular.PROFILES:
            for phase in ("oracle-build", "native-build"):
                self.cases.append((f"{profile}-{phase}", 0, [log]))
            for backend in ("c", "native"):
                for phase in ("compile", "imports", "link", "run"):
                    self.cases.append((f"{profile}-{backend}-{phase}", 0, [log]))
            self.cases.append((f"{profile}-comparison", 0, [log]))
            for suffix in ("oracle.o", "native-mi-adapter.a", "c", "native", "c.o", "native.o"):
                name = f"{profile}-{suffix}"
                product = self.work / name
                product.write_bytes(b"retained profile product\n")
                self.products[name] = product
        patcher = mock.patch.object(regular.harness, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def publish(self, cases=None, products=None, profiles=None):
        return regular.receipts.write_receipt(self.root, regular.RUNNER, self.work,
            self.products if products is None else products,
            self.cases if cases is None else cases,
            {"profiles": ",".join(regular.PROFILES if profiles is None else profiles)}, True)

    def read(self):
        regular.read_and_replay(regular.PROFILES, regular.RUNNER, regular.compare_runs)

    def test_complete_physical_profile_receipt_is_accepted(self):
        self.publish()
        self.read()

    def test_missing_native_build_is_not_four_profile_evidence(self):
        self.publish(cases=[case for case in self.cases if case[0] != "debug-1-native-build"])
        with self.assertRaises(regular.harness.HarnessError):
            self.read()

    def test_extra_runtime_case_is_not_the_original_workload(self):
        cases = [*self.cases, ("stat-2-native-extra-run", 0, self.cases[-1][2])]
        self.publish(cases=cases)
        with self.assertRaises(regular.harness.HarnessError):
            self.read()

    def test_reordered_runtime_and_comparison_phases_are_rejected(self):
        cases = list(self.cases)
        native_run = next(i for i, case in enumerate(cases) if case[0] == "release-native-run")
        comparison = next(i for i, case in enumerate(cases) if case[0] == "release-comparison")
        cases[native_run], cases[comparison] = cases[comparison], cases[native_run]
        self.publish(cases=cases)
        with self.assertRaises(regular.harness.HarnessError):
            self.read()

    def test_reordered_or_repeated_profiles_are_rejected(self):
        for profiles in (tuple(reversed(regular.PROFILES)), (*regular.PROFILES, "release")):
            with self.subTest(profiles=profiles):
                self.publish(profiles=profiles)
                with self.assertRaises(regular.harness.HarnessError):
                    self.read()

    def test_missing_retained_profile_elf_is_rejected(self):
        products = {name: path for name, path in self.products.items() if name != "stat-1-native"}
        self.publish(products=products)
        with self.assertRaises(regular.harness.HarnessError):
            self.read()

    def test_extra_retained_profile_product_is_rejected(self):
        self.publish(products={**self.products, "stat-2-other-caller": self.products["stat-2-native"]})
        with self.assertRaises(regular.harness.HarnessError):
            self.read()

    def test_product_mapping_order_does_not_change_the_roster(self):
        path = self.publish()
        data = json.loads(path.read_text())
        data["products"] = dict(reversed(list(data["products"].items())))
        path.write_text(json.dumps(data))
        self.read()


if __name__ == "__main__":
    unittest.main()
