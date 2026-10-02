#!/usr/bin/env python3
"""Host behavior of the native x86 ``consumer.rust-std-lto`` gate runner."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("consumer_rust_std_lto", ROOT / "compat/x86_64/consumer_rust_std_lto.py")
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)
import owned_dynamic_qualification as DYNAMIC_QUALIFICATION
WORK = ROOT / ".work/x86_64/consumer-rust-std-lto-tests"


def execution(status: object, stdout: bytes, stderr: bytes = b"") -> dict[str, object]:
    return {"status": status, "stdout": {"sha256": GATE.hashlib.sha256(stdout).hexdigest()},
            "stderr": {"sha256": GATE.hashlib.sha256(stderr).hexdigest()}}


class DebugRouteTests(unittest.TestCase):
    def test_debug_cargo_invocation_is_opt0_and_declares_debug_link_roots(self):
        WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            output = Path(temporary)
            context = GATE.Context(output=output, retained=GATE.Retained(output),
                                   toolchain={"target_libdir": "stock"},
                                   provider={"archive": {"path": "provider"}}, cargo_home=output / "cargo",
                                   products={"development": {"static": {"root": "static"}}},
                                   consumer="development", debug=True)
            failed = SimpleNamespace(returncode=1, stdout=b"", stderr=b"compile failed")
            with mock.patch.object(GATE, "run", return_value=failed) as run:
                GATE.cargo_consumer(context, output / "consumer", fixture="rust-std", build_std=False,
                                    flags=("-C", "target-feature=+crt-static"),
                                    link="owned-static", product="development")
            command = run.call_args.args[0]
            environment = run.call_args.kwargs["env"]
            self.assertNotIn("--release", command)
            self.assertIn("--offline", command)
            self.assertEqual(environment[GATE.owned_rust_link.CARGO_PROFILE_ENV], "debug")
            self.assertEqual(environment["CARGO_PROFILE_DEV_OPT_LEVEL"], "0")
            self.assertIn("opt-level=0", environment["RUSTFLAGS"])
            self.assertIn("lto=off", environment["RUSTFLAGS"])

    def test_debug_route_requires_development_products_and_excludes_full_rosters(self):
        base = ["run", "--debug", "--provider-vendor", "vendor", "--dependency-vendor", "deps",
                "--output", "output"]
        development = ["--development-static-sysroot", "static", "--development-dynamic-sysroot", "dynamic"]
        args = GATE.parse_arguments(base + development)
        self.assertTrue(args.debug)
        self.assertEqual(args.select, ["rust-std", "rust-std-dependent", "unwind"])
        with self.assertRaises(SystemExit):
            GATE.parse_arguments(base + development + ["--select", "lto"])
        with self.assertRaises(SystemExit):
            GATE.parse_arguments(base + ["--static-preparation", "static", "--dynamic-qualification", "dynamic"])


class ComparisonTests(unittest.TestCase):
    def test_raw_comparison_requires_a_successful_identical_oracle(self) -> None:
        self.assertTrue(GATE.raw_comparison(execution(0, b"a\n"), execution(0, b"a\n"))["passed"])
        failed_oracle = GATE.raw_comparison(execution(1, b"a\n"), execution(1, b"a\n"))
        self.assertFalse(failed_oracle["passed"])
        differs = GATE.raw_comparison(execution(0, b"dns:2\n"), execution(0, b"dns:1\n"))
        self.assertEqual(differs["same"], {"status": True, "stdout": False, "stderr": True})
        self.assertFalse(differs["passed"])


class OwnedLinkConditionTests(unittest.TestCase):
    def build(self, **facts: object) -> dict[str, object]:
        link = {"unwind_requests": ["-lgcc_s"], "provider_members_extracted": ["crabc-unwind.o"]}
        link.update(facts)
        return {"status": "built", "link_facts": link}

    def test_provider_member_must_be_extracted_for_the_unwind_request(self) -> None:
        self.assertEqual(GATE.owned_link_conditions("lane", self.build(), provider={}), [])
        missing = GATE.owned_link_conditions("lane", self.build(provider_members_extracted=[]), provider={})
        self.assertIn("ordinary archive extraction", missing[0])

    def test_std_graph_without_an_unwinder_request_is_not_evidence(self) -> None:
        unmet = GATE.owned_link_conditions("lane", self.build(unwind_requests=[], provider_members_extracted=[]),
                                           provider={})
        self.assertIn("no native unwinder request", unmet[0])

    def test_failed_build_is_named_with_its_compiler_output(self) -> None:
        unmet = GATE.owned_link_conditions("lane", {"status": "build-failed", "stderr_tail": "E0425"}, provider={})
        self.assertIn("E0425", unmet[0])


class NativeRouteTests(unittest.TestCase):
    DISASSEMBLY = """
0000000000001000 <crabc_rs_native_facade_getpid_witness>:
    1000:\tmov    $0x27,%eax
    1005:\tsyscall
    1007:\tmov    $0x27,%eax
    100c:\tsyscall
    100e:\tret

0000000000001010 <native_facade_direct_route>:
    1010:\tmov    $0x1,%eax
    1015:\tsyscall
    1017:\tret
"""

    def test_direct_syscalls_without_public_edges_prove_the_route(self) -> None:
        route = GATE.inspect_native_route(self.DISASSEMBLY)
        self.assertTrue(route["direct_route_proven"])
        self.assertEqual(route["witness_direct_getpid_syscalls"], 2)

    def test_public_c_or_errno_edges_in_the_witness_fail(self) -> None:
        for callee in ("getpid@plt", "__errno_location"):
            with self.subTest(callee=callee):
                text = self.DISASSEMBLY.replace("    100e:\tret", f"    100e:\tcall   2000 <{callee}>")
                self.assertFalse(GATE.inspect_native_route(text)["direct_route_proven"])

    def test_llvm_objdump_spelling_is_the_same_route(self) -> None:
        llvm = (self.DISASSEMBLY.replace("mov    $0x27,%eax", "movl\t$0x27, %eax")
                .replace("mov    $0x1,%eax", "movl\t$0x1, %eax"))
        self.assertTrue(GATE.inspect_native_route(llvm)["direct_route_proven"])

    def test_absent_anchor_is_not_a_route(self) -> None:
        self.assertFalse(GATE.inspect_native_route("")["direct_route_proven"])


class FixtureVendorTests(unittest.TestCase):
    def test_checked_in_fixture_locks_form_one_consistent_closure(self) -> None:
        closure = GATE.fixture_lock_closure()
        self.assertIn("smol-2.0.2", closure)
        self.assertIn("bitflags-2.13.1", closure)
        self.assertFalse(any(name.startswith("crabc-") for name in closure))


class ProviderRegressionCollectionTests(unittest.TestCase):
    def test_all_reported_controls_retain_their_compiled_and_raw_evidence(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=WORK) as temporary:
            root = Path(temporary)
            output = root / "gate"
            output.mkdir()
            controls = [root / f"control-{index}" for index in range(4)]
            expected = set()
            for control in controls:
                control.mkdir()
                for name, contents in (("receipt.json", b"{}\n"), ("fixture", b"compiled fixture"),
                                       ("execution.log", b"guarded metadata rejected\n")):
                    artifact = control / name
                    artifact.write_bytes(contents)
                    expected.add(str(artifact))
            retained = GATE.Retained(output)
            context = SimpleNamespace(output=output, retained=retained)
            result = GATE.subprocess.CompletedProcess([], 0,
                ("\n".join(map(str, controls)) + "\n").encode(), b"")
            with mock.patch.object(GATE, "PROVIDER_REGRESSIONS", ("frame_bounds.py",)), \
                    mock.patch.object(GATE, "run", return_value=result):
                report = GATE.provider_regressions(context, {"cargo_home": "cargo", "registry_source": "source"})
            self.assertEqual(report["lanes"]["frame_bounds.py"]["unmet"], [])
            self.assertTrue(expected.issubset(retained.files), expected - retained.files.keys())


class ArgumentTests(unittest.TestCase):
    def test_cohort_and_development_products_are_exclusive(self) -> None:
        base = ["run", "--provider-vendor", "p", "--dependency-vendor", "d", "--output", "o"]
        GATE.parse_arguments([*base, "--static-preparation", "s", "--dynamic-qualification", "q"])
        GATE.parse_arguments([*base, "--development-static-sysroot", "s", "--development-dynamic-sysroot", "q"])
        GATE.parse_arguments([*base, "--allocator-evidence", "native-shadow",
                              "--development-static-sysroot", "s", "--development-dynamic-sysroot", "q"])
        for extra in (["--static-preparation", "s"],
                      ["--allocator-evidence", "native-shadow", "--static-preparation", "s",
                       "--dynamic-qualification", "q"],
                      ["--static-preparation", "s", "--dynamic-qualification", "q", "--development-static-sysroot", "x"],
                      []):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), \
                    mock.patch("sys.stderr"):
                GATE.parse_arguments([*base, *extra])


class ReceiptReaderTests(unittest.TestCase):
    """The gate reader rejects every receipt that no longer proves the gate."""

    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        root = Path(self.temporary.name)
        self.evidence = root / "candidate.stdout"
        self.evidence.write_bytes(b"ok\n")
        provider = root / "provider"
        provider.mkdir()
        archive = provider / "libcrabc-unwind.a"
        archive.write_bytes(b"provider archive\n")
        provenance = provider / "provenance.json"
        provider_record = {"archive": {"name": archive.name, "sha256": GATE.sha256_file(archive)}}
        provenance.write_text(json.dumps(provider_record))
        self.provider = {
            "archive": {"path": str(archive), "sha256": GATE.sha256_file(archive)},
            "provenance": {"path": str(provenance), "sha256": GATE.sha256_file(provenance)},
            "record": provider_record, "defined_unwind_abi": [],
        }
        link_receipt = root / "candidate.crabc-owned-rust-link.json"
        link_receipt.write_text(json.dumps({"provider_archive": self.provider["archive"]}))
        self.product_paths = {}
        self.products = {}
        for label in GATE.UNWIND_PRODUCTS:
            paths = {}
            for mode in ("static", "dynamic"):
                product = root / label / mode
                product.mkdir(parents=True)
                manifest = product / "manifest.json"
                manifest.write_bytes(f"{label} {mode}\n".encode())
                paths[mode] = product
            self.product_paths[label] = paths
            self.products[label] = self.snapshot_product_pair(label, paths["static"], paths["dynamic"])
        self.cohort = {"request": {"static_preparation": "s.json", "dynamic_qualification": "q.json"},
                       "evidence": {"source": "x"}}
        self.record = {
            "schema": GATE.SCHEMA, "gate": GATE.GATE, "source_sha256": "a" * 64, "qualifying": True,
            "cohort": self.cohort, "passed": True, "unmet_conditions": [],
            "toolchain": {"rustc_vv": "test-compiler"}, "provider": self.provider, "products": self.products,
            "gates": {
                gate: {"lanes": {lane: {"unmet": []} for lane in lanes}}
                for gate, lanes in {
                    "rust-std": ("stock-std",),
                    "rust-std-dependent": ("stock-std",),
                    "lto": ("A", "B", "C", "D"),
                    "lto-native-facade": ("control-o3", "fat-lto", "stock-std-fat"),
                }.items()
            },
            "unwind": {label: {"unmet": [], "cross_dso": {
                origin: {"unmet": []} for origin in ("stock-std", "build-std")}}
                for label in GATE.UNWIND_PRODUCTS},
            "provider_regressions": {"lanes": {script: {"unmet": []} for script in GATE.PROVIDER_REGRESSIONS}},
            "retained_files": {str(self.evidence): GATE.sha256_file(self.evidence),
                               str(archive): GATE.sha256_file(archive),
                               str(link_receipt): GATE.sha256_file(link_receipt)},
        }
        self.record["gates"]["rust-std"]["lanes"]["stock-std"]["candidate_build"] = {
            "link_receipt": {"path": str(link_receipt), "sha256": GATE.sha256_file(link_receipt)}}
        for label in GATE.UNWIND_PRODUCTS:
            cleanup_receipt = root / label / "receipt.json"
            cleanup_receipt.write_text("{}\n")
            digest = GATE.sha256_file(cleanup_receipt)
            self.record["unwind"][label]["receipt"] = {"path": str(cleanup_receipt), "sha256": digest}
            self.record["retained_files"][str(cleanup_receipt)] = digest
        self.receipt = root / "receipt.json"
        qualification = mock.MagicMock()
        qualification.source_digest.return_value = "a" * 64
        qualification.QualificationError = DYNAMIC_QUALIFICATION.QualificationError
        self.patches = [
            mock.patch.dict(sys.modules, {"owned_dynamic_qualification": qualification}),
            mock.patch.object(GATE, "cohort_products",
                              side_effect=lambda *_: (copy.deepcopy(self.cohort), self.product_paths)),
            mock.patch.object(GATE, "product_pair", side_effect=self.snapshot_product_pair),
            mock.patch.object(GATE.owned_cleanup, "provider_snapshot", return_value=copy.deepcopy(self.provider)),
            mock.patch.object(GATE.installed_backtrace, "owned_receipt", return_value={}),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def validate(self, record: dict[str, object]) -> dict[str, object]:
        self.receipt.unlink(missing_ok=True)
        # The runner writes sorted keys; the reader must not depend on order.
        self.receipt.write_text(json.dumps(record, sort_keys=True))
        return GATE.validate_receipt(GATE.ROOT, self.receipt)

    @staticmethod
    def snapshot_product_pair(label: str, static: Path, dynamic: Path) -> dict[str, object]:
        return {
            "label": label,
            "static": {"root": str(static), "manifest": {"path": str(static / "manifest.json"),
                                                      "sha256": GATE.sha256_file(static / "manifest.json")}},
            "dynamic": {"root": str(dynamic), "manifest": {"path": str(dynamic / "manifest.json"),
                                                         "sha256": GATE.sha256_file(dynamic / "manifest.json")}},
        }

    def test_complete_current_receipt_is_read(self) -> None:
        self.assertTrue(self.validate(self.record)["passed"])

    def test_missing_frozen_consumer_lane_fails_closed(self) -> None:
        record = copy.deepcopy(self.record)
        del record["gates"]["lto"]["lanes"]["D"]
        with self.assertRaisesRegex(GATE.GateError, "lto.*lanes"):
            self.validate(record)

    def test_missing_cross_dso_consumer_fails_closed(self) -> None:
        record = copy.deepcopy(self.record)
        del record["unwind"]["extracted"]["cross_dso"]["build-std"]
        with self.assertRaisesRegex(GATE.GateError, "cross-DSO"):
            self.validate(record)

    def test_cross_dso_failure_fails_even_if_parent_summary_is_empty(self) -> None:
        record = copy.deepcopy(self.record)
        record["unwind"]["primary"]["cross_dso"]["stock-std"]["unmet"] = ["execution failed"]
        with self.assertRaisesRegex(GATE.GateError, "cross-DSO"):
            self.validate(record)

    def test_changed_nested_cleanup_evidence_fails_even_when_summary_passes(self) -> None:
        with mock.patch.object(GATE.installed_backtrace, "owned_receipt",
                               side_effect=GATE.owned_cleanup.OwnedCleanupError("stock static stdout changed")):
            with self.assertRaisesRegex(GATE.GateError, "cleanup evidence.*stdout changed"):
                self.validate(self.record)

    def test_cleanup_reader_receives_each_physical_product_pair(self) -> None:
        self.validate(self.record)
        expected = [mock.call(Path(self.record["unwind"][label]["receipt"]["path"]), self.products[label])
                    for label in GATE.UNWIND_PRODUCTS]
        self.assertEqual(GATE.installed_backtrace.owned_receipt.call_args_list, expected)

    def test_current_receipt_accepts_reproduction_cohort_product(self) -> None:
        reproduction = self.receipt.parent / "reproduction"
        self.product_paths["reproduction"] = {}
        for mode in ("static", "dynamic"):
            product = reproduction / mode
            product.mkdir(parents=True)
            (product / "manifest.json").write_bytes(f"reproduction {mode}\n".encode())
            self.product_paths["reproduction"][mode] = product
        self.assertTrue(self.validate(self.record)["passed"])

    def test_rehashed_provider_archive_cannot_replace_selected_archive(self) -> None:
        alternate = self.receipt.parent / "alternate-provider"
        alternate.mkdir()
        substitute = alternate / "libcrabc-unwind.a"
        substitute.write_bytes(b"different provider archive\n")
        provider = copy.deepcopy(self.provider)
        provider["archive"] = {"path": str(substitute), "sha256": GATE.sha256_file(substitute)}
        provider["record"]["archive"]["sha256"] = GATE.sha256_file(substitute)
        provenance = alternate / "provenance.json"
        provenance.write_text(json.dumps(provider["record"]))
        provider["provenance"] = {"path": str(provenance), "sha256": GATE.sha256_file(provenance)}
        record = {**self.record, "provider": provider,
                  "retained_files": {**self.record["retained_files"], str(substitute): GATE.sha256_file(substitute),
                                     str(provenance): GATE.sha256_file(provenance)}}
        with self.assertRaisesRegex(GATE.GateError, "provider"):
            self.validate(record)

    def test_rehashed_canonical_provider_conflicts_with_retained_link_receipt(self) -> None:
        archive = Path(self.provider["archive"]["path"])
        archive.write_bytes(b"different provider archive\n")
        provider = copy.deepcopy(self.provider)
        provider["archive"]["sha256"] = GATE.sha256_file(archive)
        provider["record"]["archive"]["sha256"] = GATE.sha256_file(archive)
        provenance = Path(provider["provenance"]["path"])
        provenance.write_text(json.dumps(provider["record"]))
        provider["provenance"]["sha256"] = GATE.sha256_file(provenance)
        record = {**self.record, "provider": provider,
                  "retained_files": {**self.record["retained_files"], str(archive): GATE.sha256_file(archive)}}
        with mock.patch.object(GATE.owned_cleanup, "provider_snapshot", return_value=copy.deepcopy(provider)):
            with self.assertRaisesRegex(GATE.GateError, "link receipt"):
                self.validate(record)

    def test_rehashed_product_manifest_cannot_replace_cohort_product(self) -> None:
        alternate = self.receipt.parent / "alternate-product"
        alternate.mkdir()
        substitute = alternate / "manifest.json"
        substitute.write_bytes(b"different product\n")
        products = copy.deepcopy(self.products)
        products["primary"]["static"]["root"] = str(alternate)
        products["primary"]["static"]["manifest"] = {"path": str(substitute),
                                                       "sha256": GATE.sha256_file(substitute)}
        record = {**self.record, "products": products,
                  "retained_files": {**self.record["retained_files"], str(substitute): GATE.sha256_file(substitute)}}
        with self.assertRaisesRegex(GATE.GateError, "product"):
            self.validate(record)

    def test_failure_modes_fail_closed(self) -> None:
        cases = {
            "development products": {"qualifying": False},
            "stale source": {"source_sha256": "b" * 64},
            "failed lane": {"gates": {**self.record["gates"],
                                      "lto": {"lanes": {"D": {"unmet": ["lto/D: build-failed"]}}}}},
            "missing frozen gate": {"gates": {gate: self.record["gates"][gate] for gate in GATE.FROZEN_GATES[:-1]}},
            "extracted unwind omitted": {"unwind": {"primary": {"unmet": []}}},
            "failed unwind": {"unwind": {"primary": {"unmet": []}, "extracted": {"unmet": ["cleanup"]}}},
            "no retained evidence": {"retained_files": {}},
            "failed provider regression": {"provider_regressions": {"lanes": {
                script: {"unmet": ["exit 1"] if script == "frame_bounds.py" else []}
                for script in GATE.PROVIDER_REGRESSIONS}}},
        }
        for description, change in cases.items():
            with self.subTest(description), self.assertRaises(GATE.GateError):
                self.validate({**self.record, **change})

    def test_failed_receipt_names_its_unmet_conditions(self) -> None:
        failed = {**self.record, "passed": False, "unmet_conditions": ["lto/D: build-failed"]}
        with self.assertRaisesRegex(GATE.GateError, "did not pass: lto/D: build-failed"):
            self.validate(failed)

    def test_changed_retained_bytes_or_cohort_fail_closed(self) -> None:
        self.evidence.write_bytes(b"changed\n")
        with self.assertRaisesRegex(GATE.GateError, "evidence changed"):
            self.validate(self.record)
        self.evidence.write_bytes(b"ok\n")
        with mock.patch.object(GATE, "cohort_products", return_value=({"request": {}, "evidence": {}}, {})):
            with self.assertRaisesRegex(GATE.GateError, "cohort changed"):
                self.validate(self.record)

    def test_removed_physical_cohort_fails_as_a_gate_error(self) -> None:
        qualification = self.receipt.parent / "qualification.json"
        qualification.write_text("{}\n")
        cohort = copy.deepcopy(self.cohort)
        cohort["request"]["dynamic_qualification"] = qualification.relative_to(ROOT).as_posix()
        record = {**self.record, "cohort": cohort}

        def read_cohort(*_paths: Path) -> tuple[dict[str, object], dict[str, object]]:
            DYNAMIC_QUALIFICATION.digest(qualification)
            return copy.deepcopy(cohort), self.product_paths

        with mock.patch.object(GATE, "cohort_products", side_effect=read_cohort):
            self.validate(record)
            qualification.unlink()
            with self.assertRaisesRegex(GATE.GateError, "cohort evidence.*missing or unsafe"):
                self.validate(record)

    def test_removed_retained_artifact_fails_closed(self) -> None:
        self.validate(self.record)
        self.evidence.unlink()
        with self.assertRaisesRegex(GATE.GateError, "evidence changed"):
            self.validate(self.record)


if __name__ == "__main__":
    unittest.main()
