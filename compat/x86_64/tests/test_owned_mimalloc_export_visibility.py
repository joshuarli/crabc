#!/usr/bin/env python3
"""Structural contracts for exact shared-only bundled-mimalloc visibility."""
from __future__ import annotations

import argparse
import contextlib
import io
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
LIST = ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list"
BUILDER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"
RUNNER = ROOT / "compat/x86_64/run_libc_mimalloc_export_visibility.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_mimalloc_export_visibility.py"
EVIDENCE_SPEC = importlib.util.spec_from_file_location("owned_mimalloc_export_visibility_test", EVIDENCE)
assert EVIDENCE_SPEC is not None and EVIDENCE_SPEC.loader is not None
evidence = importlib.util.module_from_spec(EVIDENCE_SPEC)
sys.modules[EVIDENCE_SPEC.name] = evidence
EVIDENCE_SPEC.loader.exec_module(evidence)


class OwnedMimallocExportVisibilityTests(unittest.TestCase):
    def test_native_image_input_rejects_changed_tool_bytes(self) -> None:
        scratch_root = ROOT / ".work/x86_64/visibility-host-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as scratch:
            tool = Path(scratch) / "readelf"
            tool.write_bytes(b"pinned inspection tool")
            tool.chmod(0o755)
            expected = {"schema": "crabc.x86_64-owned-mimalloc-export-visibility-image-inputs/v1",
                        "image": "image-id", "tools": {"readelf": {
                "path": str(tool), "sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
                "size": tool.stat().st_size, "mode": 0o755,
            }}}
            with mock.patch.object(evidence, "NATIVE_IMAGE_INPUTS", Path(scratch) / "inputs.json"), \
                 mock.patch.object(evidence, "CORE_IMAGE_ID", "image-id"), \
                 mock.patch.object(evidence, "NATIVE_IMAGE_TOOL_NAMES", ("readelf",)):
                evidence.NATIVE_IMAGE_INPUTS.write_text(json.dumps(expected), encoding="utf-8")
                self.assertEqual(evidence.native_image_inputs({"readelf": str(tool)})["tools"], expected["tools"])
                retired = {**expected, "image": "retired-image-id"}
                evidence.NATIVE_IMAGE_INPUTS.write_text(json.dumps(retired), encoding="utf-8")
                with self.assertRaisesRegex(evidence.EvidenceError, "manifest or image differs"):
                    evidence.native_image_inputs({"readelf": str(tool)})
                evidence.NATIVE_IMAGE_INPUTS.write_text(json.dumps(expected), encoding="utf-8")
                tool.write_bytes(b"tampered inspection tool")
                with self.assertRaisesRegex(evidence.EvidenceError, "image input differs: readelf"):
                    evidence.native_image_inputs({"readelf": str(tool)})

    def test_image_check_needs_no_products_and_never_starts_symbol_inspection(self) -> None:
        with (mock.patch.object(evidence, "native_image_inputs", return_value={"image": "authenticated"}) as tools,
              mock.patch.object(evidence, "native_shadow", side_effect=AssertionError("product inspection")),
              mock.patch.object(evidence, "validate", side_effect=AssertionError("product inspection")),
              contextlib.redirect_stdout(io.StringIO()) as stdout):
            self.assertEqual(evidence.main(["--check-image-inputs"]), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"image": "authenticated"})
        tools.assert_called_once_with({name: "/usr/bin/" + name for name in evidence.NATIVE_IMAGE_TOOL_NAMES})

    def test_current_products_reject_other_backend_or_source_before_symbols(self) -> None:
        scratch = ROOT / ".work/x86_64/visibility-host-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            roots = {label: work / label for label in ("static", "dynamic")}
            metadata = {"allocator_backend": "native-shadow", "source_sha256": "a" * 64}
            for root in roots.values():
                (root / "share/crabc").mkdir(parents=True)
                (root / "usr/lib").mkdir(parents=True)
                for name in ("manifest.json", "dynamic-product-state.json"):
                    (root / "share/crabc" / name).write_text(json.dumps(metadata))
            args = argparse.Namespace(allocator_backend="native-shadow",
                static_archive=roots["static"] / "usr/lib/libc.a", dynamic_shared=roots["dynamic"] / "usr/lib/libc.so")
            collector = {"source_sha256": "a" * 64}
            with (mock.patch.object(evidence.static_driver, "validate_installed_runtime"),
                  mock.patch.object(evidence.qualification, "product_identity")):
                evidence.selected_products(args, collector)
                for label in ("static", "dynamic"):
                    file = roots[label] / "share/crabc" / ("manifest.json" if label == "static" else "dynamic-product-state.json")
                    for changed, message in (({"allocator_backend": "accepted-c"}, "backend differs"),
                                             ({"source_sha256": "b" * 64}, "source differs")):
                        with self.subTest(product=label, changed=changed):
                            file.write_text(json.dumps({**metadata, **changed}))
                            with self.assertRaisesRegex(evidence.EvidenceError, message):
                                evidence.selected_products(args, collector)
                    file.write_text(json.dumps(metadata))

    def test_native_provenance_rejects_c_backend_visibility_claim(self) -> None:
        native = {"allocator_backend": "native-shadow", "accepted_allocator": None,
                  "shared_mimalloc_hidden_exports": {"status": "not-selected-native-shadow"},
                  "native_allocator": {"path": "crabc-mimalloc/UPSTREAM.md", "sha256": "a" * 64, "mode": 0o644},
                  "selected_members": {"rust-libc.o": "b" * 64},
                  "libc_shared_link_command": ["ld.lld", "--version-script=$BUILD/libc-errno-private.exports",
                                               "--exclude-libs=libcrabc-builtins.a"]}
        evidence.validate_native_provenance(native, native["native_allocator"])
        altered = dict(native, shared_mimalloc_hidden_exports={"member_count": 424})
        with self.assertRaisesRegex(evidence.EvidenceError, "C allocator visibility policy"):
            evidence.validate_native_provenance(altered, native["native_allocator"])
        broad = dict(native, libc_shared_link_command=["ld.lld", "--exclude-libs=ALL"])
        with self.assertRaisesRegex(evidence.EvidenceError, "broad visibility policy"):
            evidence.validate_native_provenance(broad, native["native_allocator"])

    def test_exact_contract_is_sealed_and_not_a_prefix_rule(self) -> None:
        members = LIST.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(members), 424)
        self.assertEqual(members, sorted(set(members)))
        self.assertEqual(
            hashlib.sha256(LIST.read_bytes()).hexdigest(),
            "cd537f6579018bbba79d831ee148a7b07f51a0f3bda538a27970724751d78873",
        )
        for required in (
            "mi_malloc_aligned",
            "mi_usable_size",
            "_mi_os_alloc",
            "_ZSt15get_new_handlerv",
        ):
            self.assertIn(required, members)
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("MIMALLOC_V3_HIDDEN_LIST_COUNT = 424", source)
        self.assertIn("MIMALLOC_V3_HIDDEN_LIST_SHA256", source)
        self.assertIn("members != tuple(sorted(set(members)))", source)
        self.assertNotIn("mi_*", source)

    def test_only_the_shared_link_receives_the_exact_version_script(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("shared_libc_mimalloc_hidden_exports", source)
        self.assertIn('f"--version-script={mimalloc_hidden_exports}"', source)
        self.assertIn('f"--version-script={errno_private_aliases}"', source)
        self.assertIn('"linker_policy": "exact-local-symbols"', source)
        self.assertIn('"shared_mimalloc_hidden_exports": shared_mimalloc_hidden_exports', source)
        native = {"allocator_backend": "native-shadow", "accepted_allocator": None,
                  "native_allocator": {}, "selected_members": {"libc.o": "a" * 64},
                  "shared_mimalloc_hidden_exports": {"status": "not-selected-native-shadow"},
                  "libc_shared_link_command": ["ld.lld", "--version-script=$BUILD/libc-mimalloc-hidden.exports"]}
        with self.assertRaisesRegex(evidence.EvidenceError, "C allocator or broad visibility policy"):
            evidence.validate_native_provenance(native, {})

    def test_local_contract_rejects_a_public_dynsym_row_or_nonlocal_symtab_row(self) -> None:
        members = ["hidden_function", "hidden_object"]
        provider = [
            {"raw_name": "hidden_function", "name": "hidden_function", "version": None,
             "version_default": False, "type": "FUNC", "size": "13", "size_bytes": 13,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "1"},
            {"raw_name": "hidden_object", "name": "hidden_object", "version": None,
             "version_default": False, "type": "OBJECT", "size": "8", "size_bytes": 8,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "2"},
        ]
        shared = [
            {**provider[0], "binding": "LOCAL"},
            {**provider[1], "binding": "LOCAL"},
        ]
        self.assertEqual(
            evidence.validate_local_contract_rows(members, [], shared, provider),
            ["hidden_function", "hidden_object"],
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "still has a dynsym row"):
            evidence.validate_local_contract_rows(members, [shared[0]], shared, provider)
        nonlocal_rows = [dict(row) for row in shared]
        nonlocal_rows[0]["binding"] = "GLOBAL"
        with self.assertRaisesRegex(evidence.EvidenceError, "is not LOCAL"):
            evidence.validate_local_contract_rows(members, [], nonlocal_rows, provider)
        version_drift = [dict(row) for row in shared]
        version_drift[0].update(raw_name="hidden_function@@CRABC_1", version="CRABC_1", version_default=True)
        with self.assertRaisesRegex(evidence.EvidenceError, "spelling/version/kind differs"):
            evidence.validate_local_contract_rows(members, [], version_drift, provider)

    def test_local_contract_rejects_object_size_drift_and_extra_hidden_public_row(self) -> None:
        members = ["hidden_object"]
        provider = [{"raw_name": "hidden_object", "name": "hidden_object", "version": None,
                     "version_default": False, "type": "OBJECT", "size": "8", "size_bytes": 8,
                     "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "2"}]
        shared = [{**provider[0], "binding": "LOCAL"}]
        size_drift = [dict(shared[0], size="9", size_bytes=9)]
        with self.assertRaisesRegex(evidence.EvidenceError, "object size differs"):
            evidence.validate_local_contract_rows(members, [], size_drift, provider)
        baseline = [
            {"raw_name": "hidden_object", "name": "hidden_object", "type": "OBJECT", "size": "8", "size_bytes": 8,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "2",
             "version": None, "version_default": False},
            {"raw_name": "surviving_object", "name": "surviving_object", "type": "OBJECT", "size": "8", "size_bytes": 8,
             "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "3",
             "version": None, "version_default": False},
        ]
        current = [dict(baseline[1], size="9", size_bytes=9)]
        with self.assertRaisesRegex(evidence.EvidenceError, "data size changed"):
            evidence.validate_visible_symtab_delta(baseline, current, set(members))

    def test_exact_dynsym_delta_retains_a_matched_independent_extra(self) -> None:
        def row(name: str) -> dict[str, object]:
            return {
                "name": name, "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
                "version": None, "version_default": False, "size": "1",
            }

        reference = [row("portable_api")]
        candidate = [row("portable_api"), row("mimalloc_hidden"), row("tgkill")]
        triage = [row("mimalloc_hidden"), row("tgkill")]
        extras = evidence.derived_baseline_extra_names(reference, candidate, triage)
        self.assertEqual(extras, {"mimalloc_hidden", "tgkill"})
        with self.assertRaisesRegex(evidence.EvidenceError, "raw triage extra roster disagrees"):
            evidence.derived_baseline_extra_names(reference, candidate, [row("mimalloc_hidden")])
        drifted_triage = [row("mimalloc_hidden"), {
            **row("tgkill"), "binding": "WEAK", "visibility": "HIDDEN", "size": "17",
        }]
        with self.assertRaisesRegex(evidence.EvidenceError, "raw triage extra row differs"):
            evidence.derived_baseline_extra_names(reference, candidate, drifted_triage)

        baseline = {item["name"]: item for item in candidate}
        current = {item["name"]: item for item in (row("portable_api"), row("tgkill"))}
        self.assertEqual(
            evidence.validate_dynsym_delta(baseline, current, {"mimalloc_hidden"}),
            ["mimalloc_hidden"],
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "changed by names beyond"):
            evidence.validate_dynsym_delta(
                baseline,
                {**current, "only_after_visibility": row("only_after_visibility")},
                {"mimalloc_hidden"},
            )

    def test_runner_compares_the_prechange_product_and_reuses_behavioral_components(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        evidence = EVIDENCE.read_text(encoding="utf-8")
        for required in (
            "build_x86_64_owned_sysroot.py",
            "build_x86_64_owned_dynamic_sysroot.py",
            "owned_mimalloc_export_visibility.py",
            "run_owned_c_allocation_interposition.sh",
            "run_owned_mimalloc_startup_errno.sh",
            "PRECHANGE_ABI_REPORT PRECHANGE_LIBC_SO",
        ):
            self.assertIn(required, runner)
        for required in (
            "derived_baseline_extra_names",
            "candidate-minus-reference-dynamic-symbol-identities",
            "validate_dynsym_delta",
            "shared dynsym changed by names beyond the exact 424-name mimalloc local contract",
            "static allocator provider lost hidden shared-only names",
            "fresh shared link selected allocator member differs from the static provider",
            "shared symtab {member} spelling/version/kind differs from the static allocator provider",
            "surviving shared symtab data size changed",
            "--version-script=$BUILD/libc-mimalloc-hidden.exports",
            "public allocator entry {name} binding/visibility drifted",
        ):
            self.assertIn(required, evidence)


if __name__ == "__main__":
    unittest.main()
