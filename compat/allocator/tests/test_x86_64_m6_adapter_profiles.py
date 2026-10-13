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
    trace["unabandon.pages_abandoned"] = "1,0"
    trace["unabandon.os.pages_abandoned"] = "1,0"
    trace.update(values or {})
    return adapter.TRACE_BEGIN + "\n" + "".join(f"{key}={value}\n" for key,value in trace.items()) + adapter.TRACE_END + "\n"


def debug_subproc_messages(side):
    address = 0x7F001000 if side == "c" else 0x7E001000
    values = {}
    for key, diagnostics in adapter._DEBUG_SUBPROC_DIAGNOSTICS.items():
        chunks = []
        for severity, body in diagnostics:
            chunks.append(f"mimalloc: {severity}: thread 0xTID: ")
            if isinstance(body, tuple):
                size, alignment, commit = body
                chunks.append(adapter._FALLBACK_WARNING.format(
                    size=hex(size), address=hex(address), alignment=hex(alignment), commit=commit))
                address += 0x1000
            else:
                chunks.append(body)
        values[key] = ":".join(chunk.encode().hex() for chunk in chunks)
    return values


def mutate_debug_message(result, key, mutate):
    stdout = result["stdout"]
    trace = stdout.split(adapter.TRACE_BEGIN + "\n", 1)[1].split(adapter.TRACE_END, 1)[0]
    rows = dict(line.split("=", 1) for line in trace.splitlines())
    chunks = [bytes.fromhex(part).decode() for part in rows[key].split(":") if part]
    rows[key] = ":".join(chunk.encode().hex() for chunk in mutate(chunks))
    changed = adapter.TRACE_BEGIN + "\n" + "".join(f"{name}={value}\n" for name, value in rows.items())
    changed += adapter.TRACE_END + "\n"
    return {**result, "stdout": changed}


def mutate_first_warning_field(chunks, field, replacement):
    for index, chunk in enumerate(chunks):
        if chunk.startswith("unable to allocate aligned OS memory directly"):
            marker = f"{field}: "
            start = chunk.index(marker) + len(marker)
            end = chunk.index(")" if field == "commit" else ",", start)
            return [*chunks[:index], chunk[:start] + replacement + chunk[end:], *chunks[index + 1:]]
    raise AssertionError("debug fixture has no aligned-OS fallback warning")


class PublicAdapterObservationTests(unittest.TestCase):
    def run_result(self, stdout=None, stderr=""):
        return {"stdout": trace_stdout() if stdout is None else stdout, "stderr": stderr}

    def valid_domain_result(self, side, stdout=None, extra_stderr=""):
        if stdout is None:
            stdout = trace_stdout(debug_subproc_messages(side))
        marker = (f"m6-valid-domain profile=debug-1 backend={side} guarded_precise="
                 f"{1 if side == 'c' else 0}\n")
        return self.run_result(stdout, marker + extra_stderr)

    def test_all_original_observations_match_without_profile_geometry_pins(self):
        values = {"heap.malloc.usable":"56","reserve.commit.committed":"67108864"}
        for profile in adapter.PROFILES:
            if profile == "debug-1":
                adapter.compare_runs(self.valid_domain_result("c", trace_stdout({**values, **debug_subproc_messages("c")})),
                                     self.valid_domain_result("native", trace_stdout({**values, **debug_subproc_messages("native")})), profile)
            else:
                output = trace_stdout(values)
                adapter.compare_runs(self.run_result(output), self.run_result(output), profile)

    def test_missing_obligation_is_rejected_even_when_both_sides_omit_it(self):
        output=trace_stdout().replace("subproc.child.cross_heap_realloc=1\n", "")
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_runs(self.run_result(output), self.run_result(output), "release")

    def test_source_refusal_errno_is_compared(self):
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_runs(self.run_result(),self.run_result(trace_stdout({"reserve.too_large.errno":"12"})), "stat-2")

    def test_abandoned_singleton_release_returns_heap_count_to_baseline(self):
        for key in ("unabandon.pages_abandoned", "unabandon.os.pages_abandoned"):
            output = trace_stdout({key: "1,1"})
            with self.subTest(key=key), self.assertRaises(adapter.harness.HarnessError):
                adapter.compare_runs(self.run_result(output), self.run_result(output), "release")

    def test_debug_source_assertion_is_a_controlled_success(self):
        c_stdout = (adapter.TRACE_BEGIN + "\ncontrol.input=100,64;200,24\n"
                    "control.source_abort=1,6\n" + adapter.TRACE_END + "\n")
        native_stdout = (adapter.TRACE_BEGIN + "\ncontrol.input=100,64;200,24\n"
                         "control.outcome=1,0,1\ncontrol.codes=22\ncontrol.messages=74657374\n"
                         + adapter.TRACE_END + "\n")
        c = {"status": 0, "stdout": c_stdout,
             "stderr": 'assertion: "mi_alignment_is_valid(alignment)" mi_theap_realloc_zero_aligned_at'}
        native = {"status": 0, "stdout": native_stdout, "stderr": ""}
        adapter.compare_precondition_control("debug-1", c, native)

    def test_callback_warning_payload_is_compared(self):
        native = self.valid_domain_result("native")
        native = mutate_debug_message(native, "subproc.messages",
            lambda chunks: [*chunks[:-1], "different\n"])
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_runs(self.valid_domain_result("c"), native, "debug-1")

    def test_debug_warning_addresses_are_the_only_callback_bytes_canonicalized(self):
        adapter.compare_runs(self.valid_domain_result("c"), self.valid_domain_result("native"), "debug-1")

    def test_debug_warning_mutations_are_rejected(self):
        c = self.valid_domain_result("c")
        native = self.valid_domain_result("native")
        warning_chunk = 2
        mutations = (
            ("missing", lambda chunks: chunks[:warning_chunk * 2] + chunks[warning_chunk * 2 + 2:]),
            ("extra", lambda chunks: chunks[:warning_chunk * 2] + chunks[warning_chunk * 2:warning_chunk * 2 + 2] + chunks[warning_chunk * 2:]),
            ("reordered", lambda chunks: chunks[2:4] + chunks[:2] + chunks[4:]),
            ("size", lambda chunks: mutate_first_warning_field(chunks, "size", "0x40001000")),
            ("alignment", lambda chunks: mutate_first_warning_field(chunks, "alignment", "0x20000000")),
            ("commit", lambda chunks: mutate_first_warning_field(chunks, "commit", "0")),
            ("null candidate", lambda chunks: mutate_first_warning_field(chunks, "address", "0x0")),
            ("unaligned candidate", lambda chunks: mutate_first_warning_field(chunks, "address", "0x7e001001")),
            ("requested-alignment candidate", lambda chunks: mutate_first_warning_field(chunks, "address", "0x10000000")),
            ("unknown diagnostic", lambda chunks: [*chunks[:-1], "unexpected warning\n"]),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), self.assertRaises(adapter.harness.HarnessError):
                changed = mutate_debug_message(native, "subproc.messages", mutate)
                adapter.compare_runs(c, changed, "debug-1")

    def test_reader_replay_masks_only_validated_aslr_candidates(self):
        retained = self.valid_domain_result("c")
        replayed = self.valid_domain_result("c", trace_stdout(debug_subproc_messages("native")))
        retained_stdout = retained["stdout"].encode()
        retained_stderr = retained["stderr"].encode()
        adapter.compare_recorded_replay(retained_stdout, retained_stderr,
            replayed["stdout"].encode(), replayed["stderr"].encode(), "debug-1", "c")
        self.assertEqual(retained["stdout"].encode(), retained_stdout)

        mutations = (
            ("missing", lambda chunks: chunks[:4] + chunks[6:]),
            ("extra", lambda chunks: chunks[:4] + chunks[2:4] + chunks[4:]),
            ("reordered", lambda chunks: chunks[2:4] + chunks[:2] + chunks[4:]),
            ("size", lambda chunks: mutate_first_warning_field(chunks, "size", "0x40001000")),
            ("alignment", lambda chunks: mutate_first_warning_field(chunks, "alignment", "0x20000000")),
            ("commit", lambda chunks: mutate_first_warning_field(chunks, "commit", "0")),
            ("unknown diagnostic", lambda chunks: [*chunks[:-1], "unexpected warning\n"]),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), self.assertRaises(adapter.harness.HarnessError):
                changed = mutate_debug_message(replayed, "subproc.messages", mutate)
                adapter.compare_recorded_replay(retained_stdout, retained_stderr,
                    changed["stdout"].encode(), changed["stderr"].encode(), "debug-1", "c")

        changed_row = replayed["stdout"].replace("collect.pages=1\n", "collect.pages=2\n", 1)
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_recorded_replay(retained_stdout, retained_stderr,
                changed_row.encode(), replayed["stderr"].encode(), "debug-1", "c")
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_recorded_replay(retained_stdout, retained_stderr,
                replayed["stdout"].encode(), (replayed["stderr"] + "unexpected\n").encode(), "debug-1", "c")

    def test_aligned_offset_control_retains_source_diagnostic_and_page(self):
        marker_c = "m6-alignment-control profile=debug-1 backend=c guarded_precise=0\n"
        marker_native = "m6-alignment-control profile=debug-1 backend=native guarded_precise=0\n"
        message = ":".join((
            "mimalloc: error: thread 0xTID: ".encode().hex(),
            "mi_free: invalid (unaligned) pointer: 0xCLIENT\n".encode().hex(),
        ))
        c = {"status": 0, "stderr": marker_c,
             "stdout": (f"{adapter.TRACE_BEGIN}\ncontrol.pointer=1,28\n"
                        "control.pages=2,2\ncontrol.codes=22\n"
                        f"control.messages={message}\n{adapter.TRACE_END}\n")}
        native = {"status": 0, "stderr": marker_native,
                  "stdout": (f"{adapter.TRACE_BEGIN}\ncontrol.pointer=1,28\n"
                             "control.pages=2,1\ncontrol.codes=\ncontrol.messages=\n"
                             f"{adapter.TRACE_END}\n")}
        adapter.compare_aligned_offset_control(c, native)
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_aligned_offset_control({**c, "stdout": c["stdout"].replace("control.codes=22", "control.codes=")}, native)
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_aligned_offset_control(
                {**c, "stdout": c["stdout"].replace("3078434c49454e54", "30784f54484552")}, native)
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_aligned_offset_control(
                {**c, "stdout": c["stdout"].replace("control.pages=2,2", "control.pages=2,3")}, native)
        with self.assertRaises(adapter.harness.HarnessError):
            adapter.compare_aligned_offset_control(
                c, {**native, "stdout": native["stdout"].replace("control.pages=2,1", "control.pages=2,0")})

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
            self.cases.append((f"{profile}-oracle-build", 0, [log]))
            if profile == "debug-1":
                source = self.work / "source"
                command = ["musl-gcc", "-std=c11", *adapter.m4.api_profile_flags("debug-1"),
                           "-DMI_LIBC_MUSL=1", "-I", str(source / "include"), "-E",
                           str(source / "src/static.c")]
                proof = {"kind": "process", "status": 0, "command": command,
                         "stdout": "mi_option_guarded_precise mi_option_guarded_precise "
                                   "mi_option_is_enabled(mi_option_guarded_precise)\n", "stderr": ""}
                proof_path = self.work / "debug-1-source-debug-preprocess.json"
                proof_path.write_text(json.dumps(proof))
                self.products[proof_path.name] = proof_path
                self.cases.append(("debug-1-source-debug-preprocess", 0, [log]))
            self.cases.append((f"{profile}-native-build", 0, [log]))
            for backend in ("c", "native"):
                for phase in ("compile", "imports", "link", "run"):
                    self.cases.append((f"{profile}-{backend}-{phase}", 0, [log]))
            self.cases.append((f"{profile}-comparison", 0, [log]))
            if profile == "debug-1":
                self.cases.extend([
                    (f"{profile}-c-aligned-offset-control-run", 0, [log]),
                    (f"{profile}-native-aligned-offset-control-run", 0, [log]),
                    (f"{profile}-aligned-offset-control-comparison", 0, [log]),
                ])
            self.cases.append((f"{profile}-c-precondition-aligned-invalid-run", 0, [log]))
            self.cases.append((f"{profile}-native-precondition-aligned-invalid-run", 0, [log]))
            self.cases.append((f"{profile}-precondition-aligned-invalid-comparison", 0, [log]))
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
