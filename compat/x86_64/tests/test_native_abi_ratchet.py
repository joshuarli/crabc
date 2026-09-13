#!/usr/bin/env python3
"""Focused fieldwise checks for the native x86 dynamic ABI ratchet."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_abi_ratchet.py"
SPEC = importlib.util.spec_from_file_location("native_abi_ratchet_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ratchet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ratchet
SPEC.loader.exec_module(ratchet)


def symbol(
    name: str,
    *,
    symbol_type: str = "FUNC",
    binding: str = "GLOBAL",
    visibility: str = "DEFAULT",
    version: str | None = None,
    version_default: bool = False,
    size: str = "1",
) -> dict[str, object]:
    return {
        "name": name,
        "type": symbol_type,
        "binding": binding,
        "visibility": visibility,
        "version": version,
        "version_default": version_default,
        "size": size,
        "value": "0000000000000010",
        "section_index": "12",
    }


def source(symbols: list[dict[str, object]]) -> dict[str, object]:
    return ratchet.symbol_state(symbols)


def identity(name: str, version: str | None = None, version_default: bool = False) -> dict[str, object]:
    return {"name": name, "version": version, "version_default": version_default}


def baseline(
    reference: list[dict[str, object]],
    candidate: list[dict[str, object]],
) -> dict[str, object]:
    return ratchet.baseline_from_symbol_sets(
        reference,
        candidate,
        origin={
            "inventory_report": {
                "path": "/historical/native-abi-inventory/report.json",
                "sha256": "a" * 64,
                "size": 1,
                "schema": ratchet.INVENTORY_SCHEMA,
                "target": ratchet.TARGET,
                "image": "crabc-core-evidence@sha256:" + "0" * 64,
                "collector_execution_source": {
                    "revision": "b" * 40,
                    "content_sha256": "c" * 64,
                    "clean": True,
                },
            },
            "review": {
                "path": "/historical/native-abi-inventory/verification.json",
                "sha256": "9" * 64,
                "size": 1,
            },
            "oracle": {
                "repository_pin": {
                    "version": "1.2.6",
                    "source": "https://example.invalid/musl",
                    "sha256": "d" * 64,
                    "fallback_repository": "https://example.invalid/mirror",
                    "fallback_revision": "e" * 40,
                },
                "shared_identity": {
                    "path": "/opt/musl-1.2.6/lib/libc.so",
                    "sha256": "f" * 64,
                    "size": 1,
                    "mode": 0o755,
                },
            },
            "candidate": {
                "build": {
                    "classification": "materialized-unqualified-product-measurement-only",
                    "revision": "1" * 40,
                    "source_content_sha256": "2" * 64,
                    "revision_provenance": "test provenance",
                },
                "shared_identity": {
                    "path": "/inputs/dynamic-product/usr/lib/libc.so",
                    "sha256": "3" * 64,
                    "size": 1,
                    "mode": 0o755,
                },
                "dynamic_manifest_sha256": "4" * 64,
            },
        },
    )


def reviewed_additions(
    entries: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if entries is None:
        entries = [{
            "identity": identity("tgkill"),
            "abi": {
                "type": "FUNC",
                "binding": "GLOBAL",
                "visibility": "DEFAULT",
                "data_size": None,
            },
            "selection": {
                "frozen_c_contracts": [
                    "3e100d45c5a0798c2d3862d5e2eef584c610ccf9:libc/src/c_abi.rs::tgkill",
                    "3e100d45c5a0798c2d3862d5e2eef584c610ccf9:include/signal.h",
                ],
                "component_contract": "compat/x86_64/native-thread-signal-abi.md",
            },
        }]
    return {
        "schema": "crabc.x86_64-native-abi-dynamic-ratchet-additions/v1",
        "target": ratchet.TARGET,
        "additions": entries,
    }


class NativeAbiRatchetTests(unittest.TestCase):
    def test_newly_present_missing_symbol_requires_all_expected_abi_fields(self) -> None:
        reference = [symbol("missing")]
        policy = baseline(reference, [])

        incorrect = source([symbol("missing", binding="WEAK")])
        result = ratchet.evaluate(policy, incorrect)
        self.assertEqual(result["violations"]["newly_present_not_correct"], [identity("missing")])

        correct = source([symbol("missing")])
        result = ratchet.evaluate(policy, correct)
        self.assertEqual(result["violations"]["newly_present_not_correct"], [])
        self.assertEqual(result["improvements"]["resolved_missing"], [identity("missing")])

    def test_exact_match_cannot_regress(self) -> None:
        reference = [symbol("stable")]
        policy = baseline(reference, [symbol("stable")])
        result = ratchet.evaluate(policy, source([symbol("stable", binding="WEAK")]))
        self.assertEqual(result["violations"]["regressed_matches"], [identity("stable")])

    def test_mismatched_field_can_stay_or_become_correct_but_not_change_again(self) -> None:
        reference = [symbol("partial")]
        policy = baseline(reference, [symbol("partial", binding="WEAK")])

        retained = ratchet.evaluate(policy, source([symbol("partial", binding="WEAK")]))
        self.assertEqual(retained["violations"]["field_transitions"], [])

        fixed = ratchet.evaluate(policy, source([symbol("partial")]))
        self.assertEqual(fixed["violations"]["field_transitions"], [])
        self.assertEqual(fixed["improvements"]["corrected_fields"], [{
            "symbol": identity("partial"),
            "fields": ["binding"],
        }])

        third_value = ratchet.evaluate(policy, source([symbol("partial", binding="UNIQUE")]))
        self.assertEqual(third_value["violations"]["field_transitions"], [{
            "symbol": identity("partial"),
            "field": "binding",
            "baseline": "WEAK",
            "expected": "GLOBAL",
            "current": "UNIQUE",
        }])

    def test_previously_correct_field_on_a_mismatch_cannot_regress(self) -> None:
        reference = [symbol("partial")]
        policy = baseline(reference, [symbol("partial", binding="WEAK")])
        result = ratchet.evaluate(
            policy,
            source([symbol("partial", binding="WEAK", visibility="PROTECTED")]),
        )
        self.assertEqual(result["violations"]["field_transitions"], [{
            "symbol": identity("partial"),
            "field": "visibility",
            "baseline": "DEFAULT",
            "expected": "DEFAULT",
            "current": "PROTECTED",
        }])

    def test_version_and_defaultness_are_symbol_identity(self) -> None:
        reference = [symbol("versioned", version="V1", version_default=False)]
        policy = baseline(reference, [symbol("versioned", version="V1", version_default=False)])
        result = ratchet.evaluate(
            policy,
            source([symbol("versioned", version="V1", version_default=True)]),
        )
        self.assertEqual(result["violations"]["new_missing"], [{
            "name": "versioned",
            "version": "V1",
            "version_default": False,
        }])
        self.assertEqual(result["violations"]["new_unexpected"], [{
            "name": "versioned",
            "version": "V1",
            "version_default": True,
        }])

    def test_object_size_is_ratchet_metadata_but_function_size_is_not(self) -> None:
        reference = [
            symbol("data", symbol_type="OBJECT", size="4"),
            symbol("code", symbol_type="FUNC", size="4"),
        ]
        policy = baseline(reference, [
            symbol("data", symbol_type="OBJECT", size="8"),
            symbol("code", symbol_type="FUNC", size="8"),
        ])
        retained = ratchet.evaluate(policy, source([
            symbol("data", symbol_type="OBJECT", size="8"),
            symbol("code", symbol_type="FUNC", size="999"),
        ]))
        self.assertEqual(retained["violations"]["field_transitions"], [])

        regressed = ratchet.evaluate(policy, source([
            symbol("data", symbol_type="OBJECT", size="16"),
            symbol("code", symbol_type="FUNC", size="999"),
        ]))
        self.assertEqual(regressed["violations"]["field_transitions"], [{
            "symbol": identity("data"),
            "field": "data_size",
            "baseline": "8",
            "expected": "4",
            "current": "16",
        }])

    def test_wrong_candidate_type_does_not_turn_object_size_into_function_abi(self) -> None:
        policy = baseline(
            [symbol("function", symbol_type="FUNC", size="4")],
            [symbol("function", symbol_type="OBJECT", size="64")],
        )
        retained = ratchet.evaluate(policy, source([
            symbol("function", symbol_type="OBJECT", size="512"),
        ]))
        self.assertEqual(retained["violations"]["field_transitions"], [])

        third_type = ratchet.evaluate(policy, source([
            symbol("function", symbol_type="TLS", size="512"),
        ]))
        self.assertEqual(third_type["violations"]["field_transitions"], [{
            "symbol": identity("function"),
            "field": "type",
            "baseline": "OBJECT",
            "expected": "FUNC",
            "current": "TLS",
        }])

    def test_existing_extra_may_disappear_but_a_new_one_cannot_appear(self) -> None:
        reference = [symbol("expected")]
        policy = baseline(reference, [symbol("expected"), symbol("old_extra")])
        result = ratchet.evaluate(policy, source([symbol("expected")]))
        self.assertEqual(result["violations"]["new_unexpected"], [])
        self.assertEqual(result["improvements"]["removed_unexpected"], [identity("old_extra")])

        result = ratchet.evaluate(policy, source([symbol("expected"), symbol("new_extra")]))
        self.assertEqual(result["violations"]["new_unexpected"], [identity("new_extra")])

    def test_reviewed_tgkill_extension_still_has_a_raw_musl_extra_but_no_new_extra_violation(self) -> None:
        policy = baseline([symbol("expected")], [symbol("expected")])
        current = source([symbol("expected"), symbol("tgkill")])

        # This is the historical ratchet behavior: a selected tgkill provider
        # is still absent from musl and therefore first appears as a new extra.
        historical = ratchet.evaluate(policy, current)
        self.assertEqual(historical["current"]["unexpected"], [identity("tgkill")])
        self.assertEqual(historical["violations"]["new_unexpected"], [identity("tgkill")])
        self.assertEqual(set(historical["violations"]), {
            "new_missing",
            "new_unexpected",
            "newly_present_not_correct",
            "regressed_matches",
            "field_transitions",
        })

        reviewed = ratchet.evaluate(policy, current, additions=reviewed_additions())
        self.assertEqual(reviewed["current"]["unexpected"], [identity("tgkill")])
        self.assertEqual(reviewed["violations"]["new_unexpected"], [])
        self.assertEqual(reviewed["violations"]["missing_additions"], [])
        self.assertEqual(reviewed["violations"]["mismatched_additions"], [])

    def test_reviewed_addition_is_required_and_its_metadata_is_exact(self) -> None:
        policy = baseline([symbol("expected")], [symbol("expected")])

        missing = ratchet.evaluate(policy, source([symbol("expected")]), additions=reviewed_additions())
        self.assertEqual(missing["violations"]["new_unexpected"], [])
        self.assertEqual(missing["violations"]["missing_additions"], [identity("tgkill")])
        self.assertEqual(missing["violations"]["mismatched_additions"], [])

        wrong_metadata = ratchet.evaluate(
            policy,
            source([symbol("expected"), symbol("tgkill", binding="WEAK")]),
            additions=reviewed_additions(),
        )
        self.assertEqual(wrong_metadata["current"]["unexpected"], [identity("tgkill")])
        self.assertEqual(wrong_metadata["violations"]["new_unexpected"], [])
        self.assertEqual(wrong_metadata["violations"]["missing_additions"], [])
        self.assertEqual(wrong_metadata["violations"]["mismatched_additions"], [{
            "identity": identity("tgkill"),
            "expected": {
                "type": "FUNC",
                "binding": "GLOBAL",
                "visibility": "DEFAULT",
                "data_size": None,
            },
            "candidate": {
                "type": "FUNC",
                "binding": "WEAK",
                "visibility": "DEFAULT",
                "data_size": None,
            },
            "incorrect_fields": ["binding"],
        }])

    def test_reviewed_addition_does_not_allow_an_unlisted_new_export(self) -> None:
        policy = baseline([symbol("expected")], [symbol("expected")])
        result = ratchet.evaluate(
            policy,
            source([symbol("expected"), symbol("tgkill"), symbol("unlisted")]),
            additions=reviewed_additions(),
        )
        self.assertEqual(result["violations"]["new_unexpected"], [identity("unlisted")])

    def test_additions_policy_requires_exact_nonoverlapping_identities_and_attribution(self) -> None:
        policy = baseline([symbol("historical")], [symbol("historical")])

        with self.assertRaisesRegex(ratchet.RatchetError, "is empty"):
            ratchet.validate_additions_policy(reviewed_additions([]), policy)

        unknown_field = reviewed_additions()
        unknown_field["unexpected"] = True
        with self.assertRaisesRegex(ratchet.RatchetError, "fields drifted"):
            ratchet.validate_additions_policy(unknown_field, policy)

        unknown_selection_field = reviewed_additions()
        unknown_selection_field["additions"][0]["selection"]["wildcard"] = "*"
        with self.assertRaisesRegex(ratchet.RatchetError, "fields drifted"):
            ratchet.validate_additions_policy(unknown_selection_field, policy)

        wildcard_identity = reviewed_additions()
        wildcard_identity["additions"][0]["identity"] = identity("tg*")
        with self.assertRaisesRegex(ratchet.RatchetError, "not exact"):
            ratchet.validate_additions_policy(wildcard_identity, policy)

        wildcard_attribution = reviewed_additions()
        wildcard_attribution["additions"][0]["selection"]["frozen_c_contracts"][0] = "3e100d45c5a0798c2d3862d5e2eef584c610ccf9:libc/*"
        with self.assertRaisesRegex(ratchet.RatchetError, "not exact"):
            ratchet.validate_additions_policy(wildcard_attribution, policy)

        overlap = reviewed_additions()
        overlap["additions"][0]["identity"] = identity("historical")
        with self.assertRaisesRegex(ratchet.RatchetError, "redefines a baseline or musl oracle"):
            ratchet.validate_additions_policy(overlap, policy)

        version_shift = reviewed_additions()
        shifted = json.loads(json.dumps(version_shift["additions"][0]))
        shifted["identity"] = identity("tgkill", "TGKILL_1", True)
        version_shift["additions"].append(shifted)
        with self.assertRaisesRegex(ratchet.RatchetError, "repeats or version-shifts"):
            ratchet.validate_additions_policy(version_shift, policy)

    def test_unknown_public_binding_is_rejected_not_dropped(self) -> None:
        with self.assertRaisesRegex(ratchet.RatchetError, "binding"):
            source([symbol("opaque", binding="LOCAL")])

    def test_unique_public_binding_is_preserved(self) -> None:
        self.assertEqual(
            source([symbol("singleton", binding="UNIQUE")]),
            {
                "symbols": [{
                    "identity": identity("singleton"),
                    "abi": {
                        "type": "FUNC",
                        "binding": "UNIQUE",
                        "visibility": "DEFAULT",
                        "data_size": None,
                    },
                }],
            },
        )

    def test_baseline_origin_and_status_are_exact(self) -> None:
        policy = baseline([symbol("expected")], [symbol("expected")])
        policy["origin"]["inventory_report"]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ratchet.RatchetError, "origin"):
            ratchet.validate_baseline(policy)

        policy = baseline([symbol("expected")], [symbol("expected")])
        policy["status"]["promotion_ready"] = True
        with self.assertRaisesRegex(ratchet.RatchetError, "status"):
            ratchet.validate_baseline(policy)

        policy = baseline([symbol("expected")], [symbol("expected")])
        policy["status"]["promotion_ready"] = 0
        with self.assertRaisesRegex(ratchet.RatchetError, "boolean"):
            ratchet.validate_baseline(policy)

    def test_checked_baseline_retains_the_reviewed_inventory_origin(self) -> None:
        policy, identity_record = ratchet._baseline()
        self.assertEqual(identity_record["sha256"], "5dd9f4de0ef543072fa8cca7bb4026e3881c5a61eb5482aaaace47885d3e74c1")
        self.assertEqual(
            policy["origin"]["inventory_report"]["sha256"],
            "aece2d1129f97e99ae2c3822f5f4adb7a00df168ecb372790286b2dfbf2a33ab",
        )
        self.assertEqual(
            policy["origin"]["review"]["sha256"],
            "8f163679d27c3e715e58a9f0fe92c6feb66165f533087a98bd1ea63cae3924df",
        )
        self.assertEqual(
            {key: len(value) for key, value in policy["baseline_state"].items()},
            {"missing": 72, "unexpected": 475, "matched": 1477, "mismatched": 101},
        )

    def test_checked_additions_policy_retains_the_exact_tgkill_extension(self) -> None:
        policy, _ = ratchet._baseline()
        additions, identity_record = ratchet._additions(policy)
        self.assertEqual(identity_record["sha256"], "bd80f655151fff341eabd83f2f90b102dd82c8ee2fee9e4b5dee94124ee68174")
        self.assertEqual(identity_record["size"], 691)
        self.assertEqual(additions, reviewed_additions())
        self.assertEqual(additions["additions"][0]["selection"], {
            "frozen_c_contracts": [
                "3e100d45c5a0798c2d3862d5e2eef584c610ccf9:libc/src/c_abi.rs::tgkill",
                "3e100d45c5a0798c2d3862d5e2eef584c610ccf9:include/signal.h",
            ],
            "component_contract": "compat/x86_64/native-thread-signal-abi.md",
        })

    def test_pinned_oracle_identity_cannot_drift(self) -> None:
        reference = [symbol("expected")]
        policy = baseline(reference, [symbol("expected")])
        current_origin = {"oracle": json.loads(json.dumps(policy["origin"]["oracle"]))}
        current_origin["oracle"]["shared_identity"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ratchet.RatchetError, "oracle identity"):
            ratchet._verify_oracle_floor(policy, current_origin, source(reference)["symbols"])

    def test_fresh_inventory_must_match_the_current_clean_source(self) -> None:
        recorded_source = {
            "revision": "1" * 40,
            "content_sha256": "2" * 64,
            "clean": True,
        }
        current_source = {**recorded_source, "revision": "3" * 40}
        with (
            mock.patch.object(ratchet.inventory, "validate_report", return_value={"collector_execution_source": recorded_source}) as validate,
            mock.patch.object(ratchet.inventory, "collector_source_seal", return_value=current_source),
        ):
            with self.assertRaisesRegex(ratchet.RatchetError, "collector source"):
                ratchet._validate_fresh_inventory(
                    Path("/unused/inventory/report.json"),
                    static_product=Path("/unused/static"),
                    dynamic_product=Path("/unused/dynamic"),
                    static_preparation=Path("/unused/preparation.json"),
                )
        validate.assert_called_once()

    def test_fresh_report_identity_omits_the_nonsemantic_report_mode(self) -> None:
        policy = baseline([symbol("expected")], [symbol("expected")])
        origin = policy["origin"]
        report = {
            "schema": ratchet.INVENTORY_SCHEMA,
            "target": ratchet.TARGET,
            "image": origin["inventory_report"]["image"],
            "collector_execution_source": origin["inventory_report"]["collector_execution_source"],
            "inputs": {
                "pinned_musl": {"repository_pin": origin["oracle"]["repository_pin"]},
            },
            "inventories": {
                "reference": {"shared": {"identity": origin["oracle"]["shared_identity"]}},
                "candidate": {"shared": {"identity": origin["candidate"]["shared_identity"]}},
            },
            "product_provenance": {
                "candidate_build": origin["candidate"]["build"],
                "dynamic_materialization": {"manifest_sha256": origin["candidate"]["dynamic_manifest_sha256"]},
            },
        }
        work = ROOT / ".work/x86_64/native-abi-ratchet-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            report_path = Path(temporary) / "report.json"
            report_path.write_text("{}\n", encoding="utf-8")
            observed = ratchet._inventory_origin(report, report_path)
        self.assertEqual(
            set(observed["inventory_report"]),
            {"path", "sha256", "size", "schema", "target", "image", "collector_execution_source"},
        )

    def test_cli_retains_a_failing_check_report_and_returns_nonzero(self) -> None:
        work = ROOT / ".work/x86_64/native-abi-ratchet-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            output = Path(temporary) / "result"
            with (
                mock.patch.object(ratchet, "_check_payload", return_value={"passed": False}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = ratchet.main([
                    "check",
                    "--inventory-report", "/unused/inventory/report.json",
                    "--static-product", "/unused/static",
                    "--dynamic-product", "/unused/dynamic",
                    "--static-preparation", "/unused/preparation.json",
                    "--output", str(output),
                ])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads((output / "ratchet.json").read_text(encoding="utf-8")), {"passed": False})

    def test_check_payload_binds_the_fixed_additions_policy_in_the_v2_receipt(self) -> None:
        policy = baseline([symbol("expected")], [symbol("expected")])
        baseline_identity = {
            "path": "/reviewed/x86_64-dynamic.json",
            "sha256": "5" * 64,
            "size": 1,
            "mode": 0o644,
        }
        current_origin = {
            "inventory_report": {"kind": "synthetic"},
            "oracle": {"kind": "synthetic"},
            "candidate": {"kind": "synthetic"},
        }
        source_seal = {
            "revision": "6" * 40,
            "content_sha256": "7" * 64,
            "clean": True,
        }
        candidate = source([symbol("expected"), symbol("tgkill")])["symbols"]
        with (
            mock.patch.object(ratchet, "_baseline", return_value=(policy, baseline_identity)),
            mock.patch.object(
                ratchet,
                "_validate_fresh_inventory",
                return_value=({}, current_origin, source([symbol("expected")])["symbols"], candidate),
            ),
            mock.patch.object(ratchet, "_verify_oracle_floor"),
            mock.patch.object(ratchet.inventory, "collector_source_seal", return_value=source_seal),
        ):
            payload = ratchet._check_payload(
                Path("/unused/inventory/report.json"),
                static_product=Path("/unused/static"),
                dynamic_product=Path("/unused/dynamic"),
                static_preparation=Path("/unused/preparation.json"),
            )
        additions, additions_identity = ratchet._additions(policy)
        self.assertEqual(payload["schema"], ratchet.CHECK_SCHEMA)
        self.assertEqual(payload["additions_policy"], {
            "path": "compat/x86_64/native-abi-ratchet-additions.json",
            "identity": additions_identity,
            "content": additions,
        })
        self.assertTrue(payload["passed"])

    def test_retained_check_rejects_additions_policy_hash_and_content_mutations(self) -> None:
        policy, _ = ratchet._baseline()
        additions, additions_identity = ratchet._additions(policy)
        expected = {
            "schema": ratchet.CHECK_SCHEMA,
            "additions_policy": {
                "path": "compat/x86_64/native-abi-ratchet-additions.json",
                "identity": additions_identity,
                "content": additions,
            },
            "passed": True,
        }
        work = ROOT / ".work/x86_64/native-abi-ratchet-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            report = Path(temporary) / "ratchet.json"
            report.write_text(json.dumps(expected), encoding="utf-8")
            with mock.patch.object(ratchet, "_check_payload", return_value=expected):
                self.assertEqual(
                    ratchet.validate_check_report(
                        report,
                        inventory_report=Path("/unused/inventory/report.json"),
                        static_product=Path("/unused/static"),
                        dynamic_product=Path("/unused/dynamic"),
                        static_preparation=Path("/unused/preparation.json"),
                    ),
                    expected,
                )

                hash_mutation = json.loads(json.dumps(expected))
                hash_mutation["additions_policy"]["identity"]["sha256"] = "0" * 64
                report.write_text(json.dumps(hash_mutation), encoding="utf-8")
                with self.assertRaisesRegex(ratchet.RatchetError, "does not reconstruct"):
                    ratchet.validate_check_report(
                        report,
                        inventory_report=Path("/unused/inventory/report.json"),
                        static_product=Path("/unused/static"),
                        dynamic_product=Path("/unused/dynamic"),
                        static_preparation=Path("/unused/preparation.json"),
                    )

                content_mutation = json.loads(json.dumps(expected))
                content_mutation["additions_policy"]["content"]["additions"][0]["abi"]["binding"] = "WEAK"
                report.write_text(json.dumps(content_mutation), encoding="utf-8")
                with self.assertRaisesRegex(ratchet.RatchetError, "does not reconstruct"):
                    ratchet.validate_check_report(
                        report,
                        inventory_report=Path("/unused/inventory/report.json"),
                        static_product=Path("/unused/static"),
                        dynamic_product=Path("/unused/dynamic"),
                        static_preparation=Path("/unused/preparation.json"),
                    )

    def test_retained_result_rejects_numeric_boolean_substitution(self) -> None:
        work = ROOT / ".work/x86_64/native-abi-ratchet-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            report = Path(temporary) / "ratchet.json"
            expected = {"status": dict(ratchet.POLICY_STATUS), "passed": True}
            report.write_text(json.dumps(expected), encoding="utf-8")
            with mock.patch.object(ratchet, "_check_payload", return_value=expected):
                self.assertEqual(
                    ratchet.validate_check_report(
                        report,
                        inventory_report=Path("/unused/inventory/report.json"),
                        static_product=Path("/unused/static"),
                        dynamic_product=Path("/unused/dynamic"),
                        static_preparation=Path("/unused/preparation.json"),
                    ),
                    expected,
                )
                retained = dict(expected)
                retained["status"] = dict(expected["status"])
                retained["status"]["promotion_ready"] = 0
                report.write_text(json.dumps(retained), encoding="utf-8")
                with self.assertRaisesRegex(ratchet.RatchetError, "does not reconstruct"):
                    ratchet.validate_check_report(
                        report,
                        inventory_report=Path("/unused/inventory/report.json"),
                        static_product=Path("/unused/static"),
                        dynamic_product=Path("/unused/dynamic"),
                        static_preparation=Path("/unused/preparation.json"),
                    )


if __name__ == "__main__":
    unittest.main()
