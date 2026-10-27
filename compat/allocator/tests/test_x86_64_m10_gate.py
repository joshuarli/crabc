#!/usr/bin/env python3
"""Artifact purity, prior-evidence, and default-switch gate regressions."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
import x86_64_m10_gate as gate  # noqa: E402


TOOLS = {name: shutil.which(name) for name in ("cc", "ar", "nm")}


def temporary_directory() -> tempfile.TemporaryDirectory:
    scratch = ROOT / ".work/tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=scratch)


class ReportReadabilityTests(unittest.TestCase):
    def test_atomic_reports_preserve_cross_owner_readability_without_write_access(self):
        with temporary_directory() as directory:
            path = Path(directory) / 'report.json'
            gate.harness.write_json(path, {'status': 'passed'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    @unittest.skipUnless(os.geteuid() == 0, 'cross-UID replay runs in the root allocator producer image')
    def test_root_produced_reports_are_readable_after_uid_and_gid_change(self):
        with temporary_directory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            path = root / 'report.json'
            gate.harness.write_json(path, {'status': 'passed'})
            self.assertEqual(path.stat().st_uid, 0)
            result = subprocess.run([sys.executable, '-c',
                'import json,os,sys; assert os.geteuid()==65534 and os.getegid()==65534; '
                'assert json.load(open(sys.argv[1]))=={"status":"passed"}; '
                'assert not os.access(sys.argv[1], os.W_OK)', str(path)],
                user=65534, group=65534, extra_groups=[], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(all(TOOLS.values()), "needs cc, ar and nm")
class ArtifactAuditTests(unittest.TestCase):
    def product(self, root: Path, *, c_symbol: bool = False, member: str = "c.rust.rcgu.o", backend: str = "native",
                provenance: dict | None = None, header: bool = False) -> Path:
        product = root / "product"
        (product / "usr/lib").mkdir(parents=True)
        (product / "usr/include").mkdir(parents=True)
        (product / "share/crabc").mkdir(parents=True)
        source = root / "member.c"
        source.write_text(("void *mi_malloc(unsigned long n) { return 0; }\n" if c_symbol else "")
                          + "int crabc_marker(void) { return 1; }\n", encoding="utf-8")
        subprocess.run([TOOLS["cc"], "-c", str(source), "-o", str(root / member)], check=True)
        subprocess.run([TOOLS["ar"], "rcs", str(product / "usr/lib/libc.a"), str(root / member)], check=True)
        (product / "share/crabc/manifest.json").write_text(json.dumps({"allocator_backend": backend}), encoding="utf-8")
        record = provenance if provenance is not None else {"dependency_graph": {"packages": ["crabc-mimalloc v0.1.0"]}}
        (product / "share/crabc/libc-static.provenance.json").write_text(json.dumps(record), encoding="utf-8")
        if header:
            (product / "usr/include/mimalloc.h").write_text("", encoding="utf-8")
        return product

    def audit(self, **kwargs) -> list[str]:
        packages = kwargs.pop("packages", ["crabc-mimalloc v0.1.0"])
        with temporary_directory() as directory:
            return gate.audit_product(self.product(Path(directory), **kwargs), ar=TOOLS["ar"], nm=TOOLS["nm"],
                                      cargo_packages=packages)

    def test_a_clean_native_product_passes(self) -> None:
        self.assertEqual(self.audit(), [])
        # The Rust allocator's own codegen units are not C mimalloc objects.
        self.assertEqual(self.audit(member="c.crabc_mimalloc-84c66b7b.crabc_mimalloc.377de8bf-cgu.114.rcgu.o"), [])

    def test_names_every_kind_of_c_mimalloc_trace(self) -> None:
        cases = {
            "C mimalloc symbol mi_malloc": {"c_symbol": True},
            "member b85de32113adef8e-static.o is a C mimalloc object": {"member": "b85de32113adef8e-static.o"},
            "backend is 'accepted-c'": {"backend": "accepted-c"},
            "C mimalloc header usr/include/mimalloc.h": {"header": True},
            "names C mimalloc (libmimalloc)": {"provenance": {"dependency_graph": {"packages": ["crabc-mimalloc v0.1.0"]},
                                                              "crate": {"name": "libmimalloc-sys"}}},
            "recorded dependency graph selects libmimalloc-sys": {
                "provenance": {"dependency_graph": {"packages": ["libmimalloc-sys v0.1.49"]}}},
            "records no resolved dependency graph": {"provenance": {}},
            "resolved Cargo graph of the native features selects libmimalloc-sys": {"packages": ["libmimalloc-sys v0.1.49"]},
        }
        for expected, change in cases.items():
            with self.subTest(expected=expected):
                unmet = self.audit(**change)
                self.assertTrue(any(expected in item for item in unmet), unmet)


class NativeArtifactCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture_index = 0

    def static_product(self, product: Path) -> None:
        import owned_static_sysroot_package as package
        import static_product_contract

        (product / "bin").mkdir(parents=True)
        (product / "usr/include").mkdir(parents=True)
        (product / "usr/lib").mkdir(parents=True)
        (product / "share/crabc").mkdir(parents=True)
        driver = product / "bin/crabc-cc"
        driver.write_text("#!/bin/sh\n", encoding="utf-8")
        driver.chmod(0o755)
        (product / "usr/include/stdint.h").write_text("\n", encoding="utf-8")
        for name in package.REQUIRED_CRT_OBJECTS:
            path = product / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        (product / "usr/lib/libc.a").write_bytes(b"native libc archive\n")
        (product / "usr/lib/libcrabc-builtins.a").write_bytes(b"owned builtins\n")
        files = {path.relative_to(product).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(product.rglob("*")) if path.is_file()}
        manifest = {
            "format": package.SYSROOT_FORMAT,
            "target": package.TARGET,
            "source_sha256": static_product_contract.source_digest(),
            "allocator_backend": "native",
            "package": {"format": package.PACKAGE_FORMAT, "archive_root": package.ARCHIVE_ROOT},
            "installed": {"headers": "usr/include", "crt_objects": list(package.REQUIRED_CRT_OBJECTS),
                          "static_libc": "usr/lib/libc.a", "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
                          "sealed_static_driver": "bin/crabc-cc", "files": files},
            "sealed_static_driver": {"format": package.DRIVER_FORMAT, "path": "bin/crabc-cc"},
        }
        (product / "share/crabc/manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")

    def dynamic_product(self, product: Path) -> None:
        import crabc_cc_owned_dynamic as driver
        import owned_dynamic_qualification as qualification

        for relative in sorted(driver.REQUIRED):
            path = product / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode())
        metadata = product / "share/crabc"
        (metadata / "crt.provenance.json").write_text(json.dumps({
            "hardening_profile": "compatibility",
            "objects": {"Scrt1.o": {"sha256": hashlib.sha256(
                (product / "usr/lib/Scrt1.o").read_bytes()).hexdigest()}},
        }) + "\n", encoding="utf-8")
        (metadata / "loader.provenance.json").write_text(json.dumps({
            "build_profile": "debug",
            "compiler_command": [],
            "artifact": {"path": "lib/ld-crabc-x86_64.so.1", "sha256": hashlib.sha256(
                (product / "lib/ld-crabc-x86_64.so.1").read_bytes()).hexdigest()},
        }) + "\n", encoding="utf-8")
        (metadata / "libc-shared.provenance.json").write_text(
            json.dumps({"allocator_backend": "native-shadow"}) + "\n", encoding="utf-8")
        payload_files = {path.relative_to(product).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in sorted(product.rglob("*")) if path.is_file()}
        state = {
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "status": "materialized-unqualified",
            "source_sha256": qualification.source_digest(),
            "contracts": qualification.contract_digests(),
            "payload_files": payload_files,
            "allocator_backend": "native-shadow",
            "allocator_lifecycle_test_audit": False,
            "allocator_promoted": False,
            "runtime_v1_published": False,
            "campaign_complete": False,
            "public_support": False,
            "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
            "runtime_profile": qualification.MATERIALIZATION_PROFILE,
            "qualification": qualification.MATERIALIZATION_QUALIFICATION,
        }
        (metadata / "dynamic-product-state.json").write_text(json.dumps(state, sort_keys=True) + "\n")
        payload_files["share/crabc/dynamic-product-state.json"] = hashlib.sha256(
            (metadata / "dynamic-product-state.json").read_bytes()).hexdigest()
        manifest = {"schema": 1, "format": driver.FORMAT, "target": driver.shared.TARGET,
                    "toolchain": "pinned-test-toolchain", "build_profile": "debug",
                    "hardening_profile": "compatibility",
                    "source_sha256": qualification.source_digest(), "files": payload_files,
                    "symlinks": driver.ALIASES}
        (metadata / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        (product / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")

    def audit_fixture(self, mutation=None) -> tuple[Path, Path]:
        self.fixture_index += 1
        products = self.root / f"m10-native-{self.fixture_index}"
        products.mkdir()
        with mock.patch.object(gate, "PRODUCTS", products):
            for kind, build in (("static", self.static_product), ("dynamic", self.dynamic_product)):
                build(products / kind)
            rows = {}
            for kind in ("static", "dynamic"):
                identity = gate.installed_product_identity(kind, products / kind)
                rows[kind] = {"built": True, "path": (products / kind).relative_to(ROOT).as_posix(),
                              "unmet": [], "cargo_packages": [], **identity}
            if mutation is not None:
                mutation(products, rows)
            audit = self.root / "native-artifact-audit.json"
            audit.write_text(json.dumps({"git": {"head": "a", "clean": True}, "passed": True,
                                         "products": rows, "unmet": []}, sort_keys=True))
        return products, audit

    def test_native_artifact_replay_revalidates_both_installed_trees(self) -> None:
        products, audit = self.audit_fixture()
        with mock.patch.object(gate, "PRODUCTS", products):
            self.assertTrue(gate.native_artifacts({"head": "a"}, audit)["met"])

    def test_native_artifact_replay_rejects_stale_source_seals_and_payload_changes(self) -> None:
        for kind, location, expected in (
            ("static", "source", "source seal differs"),
            ("dynamic", "source", "source is stale"),
            ("static", "payload", "payload hash mismatch"),
            ("dynamic", "payload", "payload hash mismatch"),
            ("static", "manifest-map", "payload hash mismatch"),
            ("dynamic", "manifest-map", "payload hash mismatch"),
        ):
            with self.subTest(kind=kind, location=location):
                products, audit = self.audit_fixture()
                product = products / kind
                if location == "source" and kind == "static":
                    manifest_path = product / "share/crabc/manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["source_sha256"] = "0" * 64
                    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
                elif location == "source":
                    state_path = product / "share/crabc/dynamic-product-state.json"
                    state = json.loads(state_path.read_text())
                    state["source_sha256"] = "0" * 64
                    state_path.write_text(json.dumps(state, sort_keys=True) + "\n")
                    manifest_path = product / "share/crabc/manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["files"]["share/crabc/dynamic-product-state.json"] = hashlib.sha256(
                        state_path.read_bytes()).hexdigest()
                    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
                elif location == "manifest-map":
                    manifest_path = product / "share/crabc/manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    payloads = (manifest["installed"]["files"] if kind == "static" else manifest["files"])
                    relative = "usr/lib/libc.a" if kind == "static" else "usr/lib/libc.so"
                    payloads[relative] = "0" * 64
                    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
                else:
                    payload = product / ("usr/lib/libc.a" if kind == "static" else "usr/lib/libc.so")
                    payload.write_bytes(b"mutated installed payload\n")
                with mock.patch.object(gate, "PRODUCTS", products):
                    result = gate.native_artifacts({"head": "a"}, audit)
                self.assertFalse(result["met"])
                self.assertTrue(any(expected in detail for detail in result["detail"]), result["detail"])

    def test_native_artifact_report_binds_the_replayed_manifest_and_payload_map(self) -> None:
        def alter_report(products, rows):
            rows["static"]["source_sha256"] = "0" * 64
            rows["dynamic"]["payload_files"]["usr/lib/libc.so"] = "0" * 64

        products, audit = self.audit_fixture(alter_report)
        with mock.patch.object(gate, "PRODUCTS", products):
            details = gate.native_artifacts({"head": "a"}, audit)["detail"]
        self.assertIn("native artifact audit static installed source_sha256 changed", details)
        self.assertIn("native artifact audit dynamic installed payload_files changed", details)


class BackendSelectionTests(unittest.TestCase):
    def test_native_is_the_shadow_rust_selection_without_test_audit_and_not_the_default(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import build_x86_64_owned_sysroot as common

        self.assertEqual(common.DEFAULT_ALLOCATOR_BACKEND, "accepted-c")
        self.assertIn("native", common.ALLOCATOR_BACKENDS)
        self.assertEqual(common.backend_selection("native", False), "native-shadow")
        self.assertEqual(common.backend_selection("accepted-c", True), "accepted-c")
        with self.assertRaisesRegex(common.BuildError, "no allocator test-audit"):
            common.backend_selection("native", True)
        self.assertEqual(common.parse_args([]).allocator_backend, "accepted-c")

    def test_native_elf_audit_covers_production_and_shadow_selections(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import build_x86_64_owned_dynamic_sysroot as dynamic

        self.assertTrue(dynamic.native_allocator_elf_audit_required("native"))
        self.assertTrue(dynamic.native_allocator_elf_audit_required("native-shadow"))
        self.assertFalse(dynamic.native_allocator_elf_audit_required("accepted-c"))


class ConditionTests(unittest.TestCase):
    def test_the_switch_is_recorded_while_the_default_is_unchanged(self) -> None:
        record = gate.switch_record()
        self.assertEqual(record["default"], "accepted-c")
        self.assertEqual(record["would_change"], ['DEFAULT_ALLOCATOR_BACKEND = "accepted-c" -> "native"'])
        self.assertTrue(any("owned_dynamic_qualification.py" in line for line in record["accepted_c_selections"]))
        self.assertFalse(gate.switch_condition(record, True)["met"])

    def test_an_early_switch_is_an_error(self) -> None:
        record = dict(gate.switch_record(), default="native")
        with self.assertRaisesRegex(gate.harness.HarnessError, "before every M10 condition"):
            gate.switch_condition(record, False)
        self.assertTrue(gate.switch_condition(record, True)["met"])

    def test_the_audit_must_be_passing_clean_and_for_this_head(self) -> None:
        with temporary_directory() as directory:
            path = Path(directory) / "audit.json"
            path.write_text(json.dumps({"git": {"head": "a", "clean": True}, "unmet": [], "passed": True,
                                       "products": {kind: {"built": True, "unmet": []} for kind in ("static", "dynamic")}}), encoding="utf-8")
            self.assertFalse(gate.native_artifacts({"head": "a"}, path)["met"])
            detail = gate.native_artifacts({"head": "b"}, path)["detail"]
            self.assertTrue(any("not HEAD b" in item for item in detail), detail)
            path.write_text(json.dumps({"git": {"head": "a", "clean": False}, "unmet": ["x"], "passed": True,
                                       "products": {kind: {"built": True, "unmet": []} for kind in ("static", "dynamic")}}), encoding="utf-8")
            self.assertGreaterEqual(len(gate.native_artifacts({"head": "a"}, path)["detail"]), 2)
            self.assertIn("--build-audit", gate.native_artifacts({"head": "a"}, Path(directory) / "absent")["detail"][0])

    def test_artifact_audit_requires_both_actual_built_products_and_a_pass(self) -> None:
        with temporary_directory() as directory:
            path = Path(directory) / "audit.json"
            complete = {"git": {"head": "a", "clean": True}, "passed": True,
                        "products": {kind: {"built": True, "unmet": []} for kind in ("static", "dynamic")},
                        "unmet": []}
            for change in ({"passed": False}, {"products": {}},
                           {"products": {"static": {"built": True, "unmet": []}}},
                           {"products": {kind: {"built": False, "unmet": []} for kind in ("static", "dynamic")}}):
                with self.subTest(change=change):
                    path.write_text(json.dumps(dict(complete, **change)), encoding="utf-8")
                    self.assertFalse(gate.native_artifacts({"head": "a"}, path)["met"])

    def test_milestone_reports_must_have_passed(self) -> None:
        with temporary_directory() as directory:
            path = Path(directory) / "r.json"
            self.assertIn("no retained report", gate.report_passed(path))
            path.write_text(json.dumps({"overall_status": "unmet"}), encoding="utf-8")
            self.assertIn("'unmet'", gate.report_passed(path))
            path.write_text(json.dumps({"status": "passed"}), encoding="utf-8")
            self.assertIsNone(gate.report_passed(path))
            path.write_text(json.dumps({"milestone": {"status": "ready-for-native-evidence"}}), encoding="utf-8")
            self.assertIn("ready-for-native-evidence", gate.report_passed(path))
            path.write_text(json.dumps({"milestone": {"status": "complete"}}), encoding="utf-8")
            self.assertIsNone(gate.report_passed(path))

    def test_prior_milestones_accept_a_passing_m8_gate_report(self) -> None:
        self.assertIn("M8", gate.PRIOR_REPORTS)
        with temporary_directory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"overall_status": "passed"}), encoding="utf-8")
            with mock.patch.object(gate, "PRIOR_REPORTS", {"M8": report}):
                self.assertTrue(gate.prior_milestones({"status": 0})["met"])
                report.write_text(json.dumps({"overall_status": "unmet"}), encoding="utf-8")
                self.assertIn("M8: report status is 'unmet'", gate.prior_milestones({"status": 0})["detail"])

    def test_baseline_retains_release_performance_purity_and_unqualified_hardware(self) -> None:
        met = lambda name: gate._condition(name, [], "validated fixture")
        with (mock.patch.object(gate, "prior_milestones", return_value=met("m10.prior-milestones")) as prior,
              mock.patch.object(gate, "promotion_gates", return_value=gate._condition(
                  "m10.promotion-gates", ["actual release performance missing"], "")) as timing,
              mock.patch.object(gate, "native_artifacts", return_value=met("m10.native-artifacts")),
              mock.patch.object(gate, "oracle_retained", return_value=met("m10.oracle-retained"))):
            result = gate.evaluate(m0={"status": 0}, receipt=Path("real.json"), head={}, profile="baseline")
        prior.assert_called_once_with({"status": 0}, profile="baseline")
        timing.assert_called_once_with(Path("real.json"))
        self.assertFalse(result["pre_switch_ready"])
        self.assertIn("m10.promotion-gates", result["unmet"])
        self.assertIn("m10.promotion-rerun", result["unmet"])
        self.assertEqual(result["unqualified_modes"], ["physical-numa", "2mib-pages", "1gib-pages"])

    def test_full_promotion_rejects_baseline_report_and_baseline_requires_explicit_nonclaims(self) -> None:
        with temporary_directory() as directory:
            path = Path(directory) / "report.json"
            report = {"overall_status": "passed", "qualification_profile": "baseline",
                      "unqualified_modes": ["physical-numa", "2mib-pages", "1gib-pages"]}
            path.write_text(json.dumps(report))
            self.assertIsNotNone(gate.report_passed(path))
            self.assertIsNone(gate.report_passed(path, profile="baseline"))
            report["unqualified_modes"] = []
            path.write_text(json.dumps(report))
            self.assertIsNotNone(gate.report_passed(path, profile="baseline"))

    def test_correctness_profile_defers_timing_and_retains_switch_and_purity(self) -> None:
        met = lambda name: gate._condition(name, [], "validated fixture")
        with (mock.patch.object(gate, "prior_milestones", return_value=met("m10.prior-milestones")) as prior,
              mock.patch.object(gate, "functional_convergence", return_value=met("m10.source-convergence")),
              mock.patch.object(gate, "promotion_gates") as timing,
              mock.patch.object(gate, "native_artifacts", return_value=gate._condition(
                  "m10.native-artifacts", ["wrong source"], ""))):
            result = gate.evaluate(m0={"status": 0}, receipt=None, head={"head": "fixture", "clean": True},
                                   profile="correctness")
            prior.assert_called_once_with({"status": 0}, profile="correctness")
            timing.assert_not_called()
            self.assertFalse(result["performance_qualified"])
            self.assertIn("m10.native-artifacts", result["unmet"])
            self.assertIn("m10.promotion-rerun", result["unmet"])
            self.assertIn("m10.switch", result["unmet"])
            self.assertEqual(result["qualification_profile"], "correctness")
        with self.assertRaisesRegex(gate.harness.HarnessError, "does not consume performance"):
            gate.evaluate(m0={"status": 0}, receipt=Path("timed.json"), head={}, profile="correctness")
        with self.assertRaisesRegex(gate.harness.HarnessError, "unknown M10 profile"):
            gate.evaluate(m0={}, receipt=None, head={}, profile="other")

    def test_post_switch_reruns_do_not_make_pre_switch_readiness_circular(self) -> None:
        met = lambda name: gate._condition(name, [], "validated actual producer")
        with (mock.patch.object(gate, "prior_milestones", return_value=met("m10.prior-milestones")),
              mock.patch.object(gate, "functional_convergence", return_value=met("m10.source-convergence")),
              mock.patch.object(gate, "native_artifacts", return_value=met("m10.native-artifacts")),
              mock.patch.object(gate, "oracle_retained", return_value=met("m10.oracle-retained")),
              mock.patch.object(gate, "switch_record", return_value=dict(gate.switch_record(), default="native"))):
            result = gate.evaluate(m0={"status": 0}, receipt=None, head={"head": "fixture", "clean": True},
                                   profile="correctness")
        self.assertTrue(result["pre_switch_ready"])
        self.assertEqual(result["phase"], "post-switch-qualification")
        self.assertEqual(result["overall_status"], "unmet")
        self.assertIn("m10.promotion-rerun", result["unmet"])
        self.assertNotIn("m10.switch", result["unmet"])

    def test_full_profile_only_needs_switch_and_post_switch_rerun_before_switch(self) -> None:
        met = lambda name: gate._condition(name, [], "validated fixture")
        with (mock.patch.object(gate, "prior_milestones", return_value=met("m10.prior-milestones")),
              mock.patch.object(gate, "promotion_gates", return_value=met("m10.promotion-gates")),
              mock.patch.object(gate, "native_artifacts", return_value=met("m10.native-artifacts")),
              mock.patch.object(gate, "oracle_retained", return_value=met("m10.oracle-retained"))):
            result = gate.evaluate(m0={"status": 0}, receipt=Path("performance.json"),
                                   qualification_receipt=None,
                                   head={"head": "fixture", "clean": True}, profile="full")

        self.assertEqual(set(result["unmet"]), {"m10.switch", "m10.promotion-rerun"})

    def test_a_full_chain_receipt_for_the_switched_revision_completes_m10(self) -> None:
        met = lambda name: gate._condition(name, [], "validated fixture")
        receipt = Path("qualification-receipt.json")
        chain = {"qualification_profile": "full", "complete_profile": True, "complete_chain": True,
                 "outcome": "passed", "source_before": {"revision": "fixture"},
                 "source_after": {"revision": "fixture"}}
        with (mock.patch.object(gate, "prior_milestones", return_value=met("m10.prior-milestones")),
              mock.patch.object(gate, "promotion_gates", return_value=met("m10.promotion-gates")),
              mock.patch.object(gate, "native_artifacts", return_value=met("m10.native-artifacts")),
              mock.patch.object(gate, "oracle_retained", return_value=met("m10.oracle-retained")),
              mock.patch.object(gate, "switch_record", return_value=dict(gate.switch_record(), default="native")),
              mock.patch.object(gate, "validate_chain_receipt", return_value=chain)):
            result = gate.evaluate(m0={"status": 0}, receipt=Path("performance.json"),
                                   qualification_receipt=receipt,
                                   head={"head": "fixture", "clean": True}, profile="full")

        self.assertEqual(result["unmet"], [])
        self.assertEqual(result["overall_status"], "passed")

    def test_promotion_rerun_rejects_nonfull_or_stale_chain_receipts(self) -> None:
        current = {"head": "current", "clean": True}
        full = {"qualification_profile": "full", "complete_profile": True, "complete_chain": True,
                "outcome": "passed", "source_before": {"revision": "current"},
                "source_after": {"revision": "current"}}
        with mock.patch.object(gate, "validate_chain_receipt", return_value=full):
            self.assertTrue(gate.promotion_rerun(current, Path("receipt.json"))["met"])
        for mutation, expected in (({"qualification_profile": "correctness"}, "profile is"),
                                   ({"complete_profile": False}, "incomplete"),
                                   ({"outcome": "failed"}, "outcome is"),
                                   ({"source_after": {"revision": "other"}}, "not HEAD current")):
            with self.subTest(mutation=mutation), mock.patch.object(
                    gate, "validate_chain_receipt", return_value={**full, **mutation}):
                result = gate.promotion_rerun(current, Path("receipt.json"))
                self.assertFalse(result["met"])
                self.assertTrue(any(expected in item for item in result["detail"]), result)

    def test_the_gate_fails_closed_today(self) -> None:
        result = gate.evaluate(m0={"status": 0}, receipt=None, head={"head": "none", "clean": True})
        self.assertEqual(result["overall_status"], "unmet")
        self.assertEqual([row["id"] for row in result["conditions"]], [
            "m10.prior-milestones", "m10.promotion-gates", "m10.native-artifacts", "m10.oracle-retained",
            "m10.promotion-rerun", "m10.switch"])
        self.assertTrue(next(row for row in result["conditions"] if row["id"] == "m10.oracle-retained")["met"])


if __name__ == "__main__":
    unittest.main()
