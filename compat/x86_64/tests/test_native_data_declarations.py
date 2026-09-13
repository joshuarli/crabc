#!/usr/bin/env python3
"""Focused contract tests for selected native public-data declarations."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_data_declarations.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ADAPTER = load_module("native_data_declarations_test", MODULE_PATH)


class NativeDataDeclarationsTests(unittest.TestCase):
    """Use a small physical-occurrence fixture, never a C text parser."""

    def contract(self):
        return ADAPTER.load_contract()

    def selected_objects(self):
        return [copy.deepcopy(item) for item in self.contract()["objects"]]

    def report_envelope(self):
        contract = self.contract()
        languages = contract["profile_languages"]
        occurrences = []
        macro_events = []
        active = []
        for item in contract["objects"]:
            kind = item["declaration_kind"]
            if kind == "installed-variable":
                for tree, root, line_key in (
                    ("candidate", "candidate-header-root", "candidate_line"),
                    ("reference", "pinned-musl-header-root", "reference_line"),
                ):
                    for site in item["sites"]:
                        for profile in site["profiles"]:
                            language = languages[profile]
                            occurrences.append(
                                {
                                    "kind": "variable",
                                    "name": item["name"],
                                    "tree": tree,
                                    "input_header": site["header"],
                                    "profile": profile,
                                    "source_language": language,
                                    "source": {
                                        "declaring_header": site["header"],
                                        "include_root": root,
                                        "line": site[line_key],
                                        "origin_resolution": "physical",
                                    },
                                    "type": {
                                        "qual_type": item["qual_type"],
                                        "desugared_qual_type": None,
                                    },
                                    "storage_class_observation": "extern",
                                    "linkage_status": "source-external-declaration",
                                    "linkage_specifier_languages": [] if language == "c" else ["C"],
                                    "mangled_name_observation": item["name"],
                                    "definition_observation": "extern-declaration-without-initializer",
                                    "tls_observation": None,
                                }
                            )
            elif kind == "accessor-macro":
                for tree, root, line_key in (
                    ("candidate", "candidate-header-root", "candidate_line"),
                    ("reference", "pinned-musl-header-root", "reference_line"),
                ):
                    for profile in item["macro_profiles"]:
                        language = languages[profile]
                        source = {
                            "declaring_header": item["macro_header"],
                            "include_root": root,
                            "line": item[f"macro_{line_key}"],
                            "origin_resolution": "physical",
                        }
                        macro_events.append(
                            {
                                "event": "define",
                                "form": item["macro_form"],
                                "name": item["name"],
                                "tree": tree,
                                "input_header": item["macro_header"],
                                "profile": profile,
                                "source": source,
                                "replacement": item["macro_replacement"],
                            }
                        )
                        active.append(
                            {
                                "form": item["macro_form"],
                                "name": item["name"],
                                "tree": tree,
                                "input_header": item["macro_header"],
                                "profile": profile,
                                "source": source,
                                "replacement": item["macro_replacement"],
                            }
                        )
                        accessor_source = {
                            "declaring_header": item["accessor_header"],
                            "include_root": root,
                            "line": item[f"accessor_{line_key}"],
                            "origin_resolution": "physical",
                        }
                        occurrences.append(
                            {
                                "kind": "function",
                                "name": item["accessor_name"],
                                "tree": tree,
                                "input_header": item["accessor_header"],
                                "profile": profile,
                                "source_language": language,
                                "source": accessor_source,
                                "type": {
                                    "qual_type": item["accessor_qual_types"][language],
                                    "desugared_qual_type": None,
                                },
                                "storage_class_observation": None,
                                "linkage_status": "unresolved-from-json",
                                "linkage_specifier_languages": [] if language == "c" else ["C"],
                                "mangled_name_observation": item["accessor_name"],
                                "definition_observation": "unresolved-from-json",
                                "tls_observation": None,
                            }
                        )
        return {
            "current_selecting_source": {"matches_retained": True, "differences": []},
            "report": {
                "schema": ADAPTER.HEADER_REPORT_SCHEMA,
                "target": ADAPTER.TARGET,
                "scope": {
                    "compiler_ast_json": True,
                    "compiler_preprocessor_records": True,
                    "header_text_parsing": False,
                    "layout_evaluation": False,
                    "macro_events_before_collapse": True,
                    "provider_selection": False,
                    "runtime": False,
                    "variable_occurrences_before_collapse": True,
                },
                "occurrences": occurrences,
                "macro_events": macro_events,
                "final_active_macros": active,
            },
        }

    def account(self, envelope=None, selected_objects=None):
        return ADAPTER.account_declarations(
            self.report_envelope() if envelope is None else envelope,
            self.selected_objects() if selected_objects is None else selected_objects,
        )

    def test_accounts_selected_declarations_without_claiming_provider_or_layout_closure(self) -> None:
        account = self.account()
        self.assertEqual(account["selected_data_declaration_status"], "proved-with-explicit-boundaries")
        self.assertEqual(account["scope"]["provider_selection"], "not-evaluated")
        self.assertEqual(account["scope"]["runtime"], "not-evaluated")
        self.assertEqual(account["scope"]["object_layout"], "not-evaluated")
        records = {item["name"]: item for item in account["objects"]}
        self.assertEqual(records["stdin"]["qual_type"], "FILE *const")
        self.assertTrue(records["stdin"]["source_mutable"])
        self.assertEqual(records["stdin"]["pointer_target_mutability"], "mutable")
        self.assertEqual(records["stdin"]["object_qualifier"], "const-pointer-object")
        self.assertEqual(records["_ns_flagdata"]["array_extent"], "incomplete")
        self.assertEqual(records["_ns_flagdata"]["layout_evidence"], "not-proved-by-declaration-inventory")
        self.assertEqual(records["h_errno"]["header_storage_kind"], "accessor-macro-not-object")
        self.assertEqual(records["h_errno"]["accessor_name"], "__h_errno_location")
        self.assertEqual(records["__timezone"]["header_storage_kind"], "abi-only-absence")

    def test_historical_header_receipt_keeps_source_drift_explicit(self) -> None:
        envelope = self.report_envelope()
        envelope["current_selecting_source"] = {
            "matches_retained": False,
            "differences": [{"path": "include/stdio.h", "kind": "sha256-differs"}],
        }
        account = self.account(envelope=envelope)
        self.assertEqual(account["selected_data_declaration_status"], "historical-source-drift-with-explicit-boundaries")
        self.assertFalse(account["source_receipt"]["current_selecting_source_matches_retained"])
        self.assertEqual(account["source_receipt"]["current_selecting_source_differences"], envelope["current_selecting_source"]["differences"])

    def test_omitted_selected_direct_declaration_rejects(self) -> None:
        envelope = self.report_envelope()
        envelope["report"]["occurrences"] = [
            item
            for item in envelope["report"]["occurrences"]
            if not (
                item["kind"] == "variable"
                and item["name"] == "stdin"
                and item["tree"] == "candidate"
                and item["profile"] == "c11-gnu"
            )
        ]
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, "stdin direct declaration profile roster differs"):
            self.account(envelope=envelope)

    def test_qualified_pointer_change_rejects(self) -> None:
        envelope = self.report_envelope()
        for item in envelope["report"]["occurrences"]:
            if item["kind"] == "variable" and item["name"] == "stdin" and item["tree"] == "candidate":
                item["type"]["qual_type"] = "FILE *"
                break
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, "stdin declaration type differs"):
            self.account(envelope=envelope)

    def test_wrong_cxx_linker_name_rejects(self) -> None:
        envelope = self.report_envelope()
        for item in envelope["report"]["occurrences"]:
            if item["kind"] == "variable" and item["name"] == "stdin" and item["tree"] == "candidate" and item["source_language"] == "cxx":
                item["mangled_name_observation"] = "_Z5stdin"
                break
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, r"stdin direct declaration C\+\+ linker name differs"):
            self.account(envelope=envelope)

    def test_h_errno_macro_profile_and_expansion_changes_reject(self) -> None:
        profile_changed = self.report_envelope()
        for item in profile_changed["report"]["final_active_macros"]:
            if item["name"] == "h_errno" and item["tree"] == "candidate" and item["profile"] == "c11-bsd":
                item["profile"] = "c11-strict"
                break
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, "h_errno final macro profile roster differs"):
            self.account(envelope=profile_changed)

        expansion_changed = self.report_envelope()
        for item in expansion_changed["report"]["macro_events"]:
            if item["name"] == "h_errno" and item["tree"] == "candidate":
                item["replacement"] = " (h_errno)"
                break
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, "h_errno macro event replacement differs"):
            self.account(envelope=expansion_changed)

    def test_selected_abi_only_kind_reclassification_rejects(self) -> None:
        selected = self.selected_objects()
        record = next(item for item in selected if item["name"] == "__timezone")
        record["declaration_kind"] = "installed-variable"
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, "selected object contract object:__timezone declaration_kind differs"):
            self.account(selected_objects=selected)

    def test_abi_only_reclassification_rejects(self) -> None:
        envelope = self.report_envelope()
        envelope["report"]["occurrences"].append(
            {
                "kind": "variable",
                "name": "__timezone",
                "tree": "candidate",
                "input_header": "time.h",
                "profile": "c11-gnu",
                "source_language": "c",
                "source": {
                    "declaring_header": "time.h",
                    "include_root": "candidate-header-root",
                    "line": 226,
                    "origin_resolution": "physical",
                },
                "type": {"qual_type": "long", "desugared_qual_type": None},
                "storage_class_observation": "extern",
                "linkage_status": "source-external-declaration",
                "linkage_specifier_languages": [],
                "mangled_name_observation": "__timezone",
                "definition_observation": "extern-declaration-without-initializer",
                "tls_observation": None,
            }
        )
        with self.assertRaisesRegex(ADAPTER.NativeDataDeclarationsError, "__timezone ABI-only name appears as a header declaration"):
            self.account(envelope=envelope)


if __name__ == "__main__":
    unittest.main()
