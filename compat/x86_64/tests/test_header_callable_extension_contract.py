#!/usr/bin/env python3
"""Focused strict policy checks for reviewed native callable extensions."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "header_callable_extension_contract.py"
README = ROOT / "compat" / "x86_64" / "README.md"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EXTENSION = load_module("header_callable_extension_contract_test", MODULE_PATH)


class HeaderCallableExtensionContractTests(unittest.TestCase):
    def mutated_contract(self, text: str):
        work_root = ROOT / ".work" / "x86_64" / "header-callable-extension" / "contract-tests"
        work_root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work_root)
        path = Path(temporary.name) / "contract.toml"
        path.write_text(text, encoding="utf-8")
        return temporary, path

    def records_for_contract(self, contract):
        records = []
        for extension in contract.extensions:
            for profile in extension.visible_profiles:
                records.append(
                    {
                        "classification": extension.classification,
                        "declaration_kind": extension.declaration_kind,
                        "declaring_header": extension.header,
                        "line": 275,
                        "name": extension.name,
                        "origin_resolution": "physical",
                        "profile": profile,
                        "storage_class": "extern",
                        "tree": "candidate",
                        "type": extension.signature,
                        "visible_from_headers": list(extension.visible_from_headers),
                    }
                )
        return records

    def test_checked_contract_is_one_exact_tgkill_record(self) -> None:
        contract = EXTENSION.load_contract()

        self.assertEqual(contract.profiles, EXTENSION.PROFILES)
        self.assertEqual(len(contract.extensions), 1)
        extension = contract.extensions[0]
        self.assertEqual((extension.header, extension.name), ("signal.h", "tgkill"))
        self.assertEqual(extension.declaration_kind, "function")
        self.assertEqual(extension.classification, "external")
        self.assertEqual(extension.signature, "int (int, int, int)")
        self.assertEqual(extension.c_linkage_symbol, "tgkill")
        self.assertEqual(
            extension.visible_profiles,
            ("c11-gnu", "cxx17-gnu", "c11-bsd", "cxx17-strict"),
        )
        self.assertEqual(
            extension.hidden_profiles,
            ("c11-strict", "c11-posix-2008", "c11-xopen-700"),
        )
        self.assertEqual(
            extension.visible_from_headers,
            ("aio.h", "signal.h", "sys/signal.h", "sys/ucontext.h", "sys/wait.h", "ucontext.h", "wait.h"),
        )
        self.assertEqual(extension.provider_route, "default-static")
        self.assertEqual(
            extension.evidence,
            (
                "include/signal.h",
                "libc/src/c_abi/x86_64/thread_signal.rs",
                "compat/x86_64/native-thread-signal-abi.md",
            ),
        )
        self.assertEqual(
            extension.abi_signature_for("cxx17-gnu"),
            "int (int, int, int)|mangled=tgkill",
        )
        self.assertIn("_GNU_SOURCE", README.read_text(encoding="utf-8"))

    def test_contract_rejects_numeric_policy_values(self) -> None:
        """A TOML integer must not impersonate an exact policy Boolean."""

        source = EXTENSION.CONTRACT_PATH.read_text(encoding="utf-8")
        temporary, path = self.mutated_contract(
            source.replace("public_support = false", "public_support = 0", 1)
        )
        with temporary:
            with self.assertRaisesRegex(
                EXTENSION.CallableExtensionContractError, "policy.public_support"
            ):
                EXTENSION.load_contract(path)

    def test_contract_rejects_noncanonical_evidence_spelling(self) -> None:
        source = EXTENSION.CONTRACT_PATH.read_text(encoding="utf-8")
        temporary, path = self.mutated_contract(
            source.replace('"include/signal.h"', '"./include/signal.h"', 1)
        )
        with temporary:
            with self.assertRaisesRegex(
                EXTENSION.CallableExtensionContractError,
                "evidence\\[0\\] must use a canonical repository path",
            ):
                EXTENSION.load_contract(path)

    def test_contract_rejects_canonical_but_wrong_evidence_mapping(self) -> None:
        source = EXTENSION.CONTRACT_PATH.read_text(encoding="utf-8")
        temporary, path = self.mutated_contract(
            source.replace('"include/signal.h"', '"compat/x86_64/README.md"', 1)
        )
        with temporary:
            with self.assertRaisesRegex(
                EXTENSION.CallableExtensionContractError, "evidence source mapping"
            ):
                EXTENSION.load_contract(path)

    def test_inventory_requires_exact_physical_declaration_profiles_and_roots(self) -> None:
        contract = EXTENSION.load_contract()
        records = self.records_for_contract(contract)
        expected_rows = EXTENSION.validate_callable_inventory_records(
            contract,
            records,
            known_headers=frozenset(contract.extensions[0].visible_from_headers),
        )
        self.assertEqual(len(expected_rows), 28)

        missing = records[:-1]
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "missing candidate"):
            EXTENSION.validate_callable_inventory_records(
                contract,
                missing,
                known_headers=frozenset(contract.extensions[0].visible_from_headers),
            )

        wrong_origin = deepcopy(records)
        wrong_origin[0]["declaring_header"] = "sys/signal.h"
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "declaring header"):
            EXTENSION.validate_callable_inventory_records(
                contract,
                wrong_origin,
                known_headers=frozenset(contract.extensions[0].visible_from_headers),
            )

        reference = deepcopy(records)
        reference[0]["tree"] = "reference"
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "reference declares"):
            EXTENSION.validate_callable_inventory_records(
                contract,
                reference,
                known_headers=frozenset(contract.extensions[0].visible_from_headers),
            )

        hidden = deepcopy(records)
        hidden.append({**hidden[0], "profile": "c11-strict"})
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "hidden profile"):
            EXTENSION.validate_callable_inventory_records(
                contract,
                hidden,
                known_headers=frozenset(contract.extensions[0].visible_from_headers),
            )

    def test_visibility_review_retains_target_and_rejects_extra_or_hidden_surface(self) -> None:
        contract = EXTENSION.load_contract()
        target = [{"classification": "external", "name": "tgkill"}]

        extension = EXTENSION.review_callable_difference(
            contract,
            header="signal.h",
            profile="c11-gnu",
            candidate_only=target,
            reference_only=[],
        )
        self.assertIsNotNone(extension)
        self.assertEqual(extension.name, "tgkill")
        self.assertIsNone(
            EXTENSION.review_callable_difference(
                contract,
                header="signal.h",
                profile="c11-strict",
                candidate_only=[],
                reference_only=[],
            )
        )
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "hidden profile"):
            EXTENSION.review_callable_difference(
                contract,
                header="signal.h",
                profile="c11-strict",
                candidate_only=target,
                reference_only=[],
            )
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "additional raw"):
            EXTENSION.review_callable_difference(
                contract,
                header="signal.h",
                profile="c11-gnu",
                candidate_only=[*target, {"classification": "external", "name": "unreviewed"}],
                reference_only=[],
            )

    def test_declaration_review_requires_exact_signature_and_c_linkage(self) -> None:
        contract = EXTENSION.load_contract()
        difference = {
            "candidate_only": [
                {
                    "kind": "function",
                    "name": "tgkill",
                    "signature": "int (int, int, int)|mangled=tgkill",
                }
            ],
            "incompatible": [],
            "reference_only": [],
        }
        extension = EXTENSION.review_declaration_difference(
            contract,
            header="signal.h",
            profile="cxx17-gnu",
            difference=difference,
        )
        self.assertIsNotNone(extension)
        self.assertEqual(extension.c_linkage_symbol, "tgkill")

        bad_linkage = deepcopy(difference)
        bad_linkage["candidate_only"][0]["signature"] = "int (int, int, int)|mangled=_Z6tgkilliii"
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "signature"):
            EXTENSION.review_declaration_difference(
                contract,
                header="signal.h",
                profile="cxx17-gnu",
                difference=bad_linkage,
            )
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "reference declaration"):
            EXTENSION.review_declaration_difference(
                contract,
                header="signal.h",
                profile="c11-gnu",
                difference={
                    "candidate_only": difference["candidate_only"],
                    "incompatible": [],
                    "reference_only": [{"kind": "function", "name": "tgkill", "signature": "int (int, int, int)|mangled=tgkill"}],
                },
            )

    def test_provider_route_is_checked_separately_from_header_semantics(self) -> None:
        contract = EXTENSION.load_contract()
        routes = EXTENSION.validate_provider_routes(
            contract,
            candidate_external=("kill", "tgkill"),
            static_exports=("kill", "tgkill"),
            default_static=("kill", "tgkill"),
        )
        self.assertEqual(
            routes,
            [
                {
                    "candidate_external_present": True,
                    "header": "signal.h",
                    "name": "tgkill",
                    "provider_route": "default-static",
                }
            ],
        )
        with self.assertRaisesRegex(EXTENSION.CallableExtensionContractError, "default static"):
            EXTENSION.validate_provider_routes(
                contract,
                candidate_external=("kill", "tgkill"),
                static_exports=("kill",),
                default_static=("kill",),
            )


if __name__ == "__main__":
    unittest.main()
