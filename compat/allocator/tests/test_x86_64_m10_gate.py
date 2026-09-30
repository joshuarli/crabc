#!/usr/bin/env python3
"""Artifact purity, prior-evidence, and default-switch gate regressions."""

from __future__ import annotations

import json
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
        with tempfile.TemporaryDirectory() as directory:
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
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            path.write_text(json.dumps({"git": {"head": "a", "clean": True}, "unmet": [], "passed": True,
                                       "products": {kind: {"built": True, "unmet": []} for kind in ("static", "dynamic")}}), encoding="utf-8")
            self.assertTrue(gate.native_artifacts({"head": "a"}, path)["met"])
            detail = gate.native_artifacts({"head": "b"}, path)["detail"]
            self.assertIn("not HEAD b", detail[0])
            path.write_text(json.dumps({"git": {"head": "a", "clean": False}, "unmet": ["x"], "passed": True,
                                       "products": {kind: {"built": True, "unmet": []} for kind in ("static", "dynamic")}}), encoding="utf-8")
            self.assertEqual(len(gate.native_artifacts({"head": "a"}, path)["detail"]), 2)
            self.assertIn("--build-audit", gate.native_artifacts({"head": "a"}, Path(directory) / "absent")["detail"][0])

    def test_artifact_audit_requires_both_actual_built_products_and_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
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
        with tempfile.TemporaryDirectory() as directory:
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
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"overall_status": "passed"}), encoding="utf-8")
            with mock.patch.object(gate, "PRIOR_REPORTS", {"M8": report}):
                self.assertTrue(gate.prior_milestones({"status": 0})["met"])
                report.write_text(json.dumps({"overall_status": "unmet"}), encoding="utf-8")
                self.assertIn("M8: report status is 'unmet'", gate.prior_milestones({"status": 0})["detail"])

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

    def test_the_gate_fails_closed_today(self) -> None:
        result = gate.evaluate(m0={"status": 0}, receipt=None, head={"head": "none", "clean": True})
        self.assertEqual(result["overall_status"], "unmet")
        self.assertEqual([row["id"] for row in result["conditions"]], [
            "m10.prior-milestones", "m10.promotion-gates", "m10.native-artifacts", "m10.oracle-retained",
            "m10.promotion-rerun", "m10.switch"])
        self.assertTrue(next(row for row in result["conditions"] if row["id"] == "m10.oracle-retained")["met"])


if __name__ == "__main__":
    unittest.main()
