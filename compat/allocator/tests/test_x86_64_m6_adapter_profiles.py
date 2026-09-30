"""Public allocator producer checks complete observations and physical profile receipts."""
from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_adapter as adapter


def trace_stdout(values=None):
    trace = {key: "1" for key in sorted(adapter.EXPECTED_KEYS)}
    trace.update(values or {})
    return adapter.TRACE_BEGIN + "\n" + "".join(f"{key}={value}\n" for key,value in trace.items()) + adapter.TRACE_END + "\n"


class PublicAdapterObservationTests(unittest.TestCase):
    def run_result(self, stdout=None, stderr=""):
        return {"stdout": trace_stdout() if stdout is None else stdout, "stderr": stderr}

    def test_all_original_observations_match_without_profile_geometry_pins(self):
        output=trace_stdout({"heap.malloc.usable":"56","reserve.commit.committed":"67108864"})
        for profile in adapter.PROFILES:
            adapter.compare_runs(self.run_result(output), self.run_result(output), profile)

    def test_missing_obligation_is_rejected_even_when_both_sides_omit_it(self):
        output=trace_stdout().replace("subproc.child.cross_heap_realloc=1\n", "")
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_runs(self.run_result(output), self.run_result(output), "release")

    def test_source_refusal_errno_is_compared(self):
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_runs(self.run_result(),self.run_result(trace_stdout({"reserve.too_large.errno":"12"})), "stat-2")

    def test_callback_warning_payload_is_compared(self):
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_runs(self.run_result(),self.run_result(trace_stdout({"subproc.messages":"different"})), "debug-1")

    def test_entire_stdout_and_stderr_are_compared(self):
        for native in (self.run_result(trace_stdout()+"extra\n"),self.run_result(stderr="unexpected\n")):
            with self.assertRaises(adapter.harness.HarnessError):
                adapter.compare_runs(self.run_result(),native,"stat-1")


class PublicAdapterReceiptRosterTests(unittest.TestCase):
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
        log.write_text(trace_stdout())
        self.cases = []
        self.products = {}
        for name in (adapter.DRIVER.name, "native_heap_visit_contract.rs", "mimalloc.h", "LICENSE", "mimalloc-3.5.0.tar.gz", "inputs.json"):
            product = self.work / name
            product.write_bytes(b"retained fixture input\n")
            self.products[name] = product
        for profile in adapter.PROFILES:
            for phase in ("oracle-build", "native-build"):
                self.cases.append((f"{profile}-{phase}", 0, [log]))
            for backend in ("c", "native"):
                for phase in ("compile", "imports", "link", "run"):
                    self.cases.append((f"{profile}-{backend}-{phase}", 0, [log]))
            self.cases.append((f"{profile}-comparison", 0, [log]))
            self.cases.append((f"{profile}-native-contract-build", 0, [log]))
            self.cases.append((f"{profile}-native-contract-run", 0, [log]))
            for suffix in ("oracle.o", "native-adapter.a", "c", "native", "c.o", "native.o", "native-contract"):
                name = f"{profile}-{suffix}"
                product = self.work / name
                product.write_bytes(b"retained profile product\n")
                self.products[name] = product
        patcher = mock.patch.object(adapter.harness, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def publish(self, cases=None, products=None, profiles=None):
        return adapter.receipts.write_receipt(self.root, adapter.RUNNER, self.work,
            self.products if products is None else products,
            self.cases if cases is None else cases,
            {"profiles": ",".join(adapter.PROFILES if profiles is None else profiles)}, True)

    def read(self):
        adapter.read_and_replay(adapter.PROFILES)

    def test_complete_physical_profile_receipt_is_accepted(self):
        self.publish()
        self.read()

    def test_missing_native_build_is_not_four_profile_evidence(self):
        self.publish(cases=[case for case in self.cases if case[0] != "debug-1-native-build"])
        with self.assertRaises(adapter.harness.HarnessError):
            self.read()

    def test_extra_runtime_case_is_not_the_original_workload(self):
        cases = [*self.cases, ("stat-2-native-extra-run", 0, self.cases[-1][2])]
        self.publish(cases=cases)
        with self.assertRaises(adapter.harness.HarnessError):
            self.read()

    def test_reordered_runtime_and_comparison_phases_are_rejected(self):
        cases = list(self.cases)
        native_run = next(i for i, case in enumerate(cases) if case[0] == "release-native-run")
        comparison = next(i for i, case in enumerate(cases) if case[0] == "release-comparison")
        cases[native_run], cases[comparison] = cases[comparison], cases[native_run]
        self.publish(cases=cases)
        with self.assertRaises(adapter.harness.HarnessError):
            self.read()

    def test_reordered_or_repeated_profiles_are_rejected(self):
        for profiles in (tuple(reversed(adapter.PROFILES)), (*adapter.PROFILES, "release")):
            with self.subTest(profiles=profiles):
                self.publish(profiles=profiles)
                with self.assertRaises(adapter.harness.HarnessError):
                    self.read()

    def test_missing_retained_profile_elf_is_rejected(self):
        products = {name: path for name, path in self.products.items() if name != "stat-1-native"}
        self.publish(products=products)
        with self.assertRaises(adapter.harness.HarnessError):
            self.read()

    def test_extra_retained_profile_product_is_rejected(self):
        self.publish(products={**self.products, "stat-2-other-caller": self.products["stat-2-native"]})
        with self.assertRaises(adapter.harness.HarnessError):
            self.read()

    def test_product_mapping_order_does_not_change_the_roster(self):
        path = self.publish()
        data = json.loads(path.read_text())
        data["products"] = dict(reversed(list(data["products"].items())))
        path.write_text(json.dumps(data))
        self.read()


if __name__ == "__main__":
    unittest.main()
