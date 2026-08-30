"""Focused contract tests for the standalone native churn/RSS smoke harness."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HARNESS_PATH = ROOT / "compat/allocator/native_churn_rss_smoke.py"
SPEC = importlib.util.spec_from_file_location("native_churn_rss_smoke", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def fixture_result(seed: int = 91, cycles: int = 3) -> dict[str, object]:
    """Return the smallest valid result with observable high-water state."""

    return {
        "schema": HARNESS.FIXTURE_SCHEMA,
        "seed": seed,
        "cycles": cycles,
        "owner_exits_with_live_blocks": cycles,
        "successful_cross_thread_handoffs": cycles,
        "post_exit_initial_thread_frees": cycles * 6,
        "requested_bytes_total": 123,
        "requested_bytes_live_final": 0,
        "requested_bytes_live_high_water": 97,
        "usable_bytes_live_final": 0,
        "usable_bytes_live_high_water": 128,
        "live_blocks_final": 0,
        "live_blocks_high_water": 7,
        "rss_initial_bytes": 4096,
        "rss_final_bytes": 8192,
        "rss_high_water_bytes": 12288,
        "rss_samples": 10,
        "allocator_metadata_high_water_bytes": None,
        "allocator_metadata_observation": "not-exposed-by-production-shadow-c-api",
    }


class NativeChurnRssSmokeContractTests(unittest.TestCase):
    """Keep the no-private-hook lifecycle and report boundary durable."""

    def test_contract_hashes_fixture_and_requires_production_api_only(self) -> None:
        contract = HARNESS.read_json(HARNESS.CONTRACT_PATH)
        validated = HARNESS.validate_contract(contract)

        self.assertEqual(validated["cycles"], 8)
        self.assertEqual(validated["process_epochs"], 4)
        self.assertEqual(
            contract["production_shadow_boundary"]["allowed_allocation_apis"],
            ["malloc", "free", "posix_memalign", "malloc_usable_size"],
        )
        self.assertFalse(contract["production_shadow_boundary"]["allocator_private_hooks"])
        self.assertFalse(contract["production_shadow_boundary"]["c_backend_fallback"])

    def test_contract_requires_selected_shadow_build_and_free_route_attestation(self) -> None:
        contract = HARNESS.read_json(HARNESS.CONTRACT_PATH)
        validated = HARNESS.validate_contract(contract)

        attestation = validated["selected_shadow_artifact_attestation"]
        self.assertEqual(
            attestation["cargo_fingerprint"]["exact_features"],
            ["default", "native-mimalloc-shadow"],
        )
        self.assertEqual(
            attestation["exported_free_route"]["required_callee_suffix"], "native_free>"
        )
        self.assertEqual(
            attestation["rust_cleanup_free_route"]["required_branch_target"], "free@plt>"
        )
        self.assertEqual(validated["rss_threshold_bytes"], 16777216)

    def test_selected_shadow_fingerprint_requires_exact_feature_identity(self) -> None:
        expectation = HARNESS.read_json(HARNESS.CONTRACT_PATH)[
            "selected_shadow_artifact_attestation"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "target/debug"
            fingerprint = runtime / ".fingerprint/crabc-libc-selected/lib-c.json"
            fingerprint.parent.mkdir(parents=True)
            fingerprint.write_text(
                json.dumps(
                    {
                        "features": json.dumps(["default", "native-mimalloc-shadow"]),
                        "declared_features": json.dumps(["default", "native-mimalloc-shadow"]),
                    }
                ),
                encoding="utf-8",
            )

            result = HARNESS.selected_shadow_fingerprint(runtime, expectation)

        self.assertEqual(result["features"], ["default", "native-mimalloc-shadow"])
        self.assertEqual(result["path"].endswith("lib-c.json"), True)

    def test_free_route_attestation_rejects_the_c_backend_path(self) -> None:
        dynamic_symbols = "  42: 0000000000001000    16 FUNC    WEAK   DEFAULT   12 free\n"
        native_route = "    1000: 94000000 bl 2000 <_RNvNtCnative_free>\n"
        fallback_route = "    1000: 94000000 bl 2000 <mi_free>\n"

        self.assertEqual(
            HARNESS.attested_free_symbol(dynamic_symbols, "free"),
            {"binding": "WEAK", "visibility": "DEFAULT", "section": "12"},
        )
        HARNESS.require_branch_target(native_route, "native_free>", "exported free")
        with self.assertRaisesRegex(HARNESS.ArtifactAttestationError, "forbidden"):
            HARNESS.require_no_branch_target(fallback_route, "mi_free>", "exported free")

    def test_fixture_result_requires_initial_thread_post_exit_frees(self) -> None:
        result = fixture_result()

        parsed = HARNESS.parse_fixture_output(json.dumps(result), seed=91, cycles=3)

        self.assertEqual(parsed["post_exit_initial_thread_frees"], 18)
        self.assertEqual(parsed["owner_exits_with_live_blocks"], 3)
        self.assertEqual(parsed["allocator_metadata_high_water_bytes"], None)

    def test_fixture_result_rejects_hidden_post_exit_release(self) -> None:
        result = fixture_result()
        result["post_exit_initial_thread_frees"] = 0

        with self.assertRaisesRegex(
            HARNESS.AllocatorLivenessError, "post_exit_initial_thread_frees"
        ):
            HARNESS.parse_fixture_output(json.dumps(result), seed=91, cycles=3)

    def test_high_water_preserves_unknown_allocator_metadata(self) -> None:
        first = fixture_result(seed=91, cycles=3)
        second = fixture_result(seed=92, cycles=3)
        second["rss_high_water_bytes"] = 16384
        second["live_blocks_high_water"] = 11

        high_water = HARNESS.high_water(
            [
                {"epoch": 1, "fixture": first},
                {"epoch": 2, "fixture": second},
            ]
        )

        self.assertEqual(high_water["rss_bytes"], 16384)
        self.assertEqual(high_water["live_blocks"], 11)
        self.assertEqual(high_water["allocator_metadata"]["high_water_bytes"], None)
        self.assertFalse(high_water["allocator_metadata"]["available"])

    def test_failed_preflight_writes_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "failure.json"

            with redirect_stderr(io.StringIO()):
                status = HARNESS.main(["--report", str(report), "--seed", "0"])

            self.assertEqual(status, 1)
            value = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(value["schema"], HARNESS.REPORT_SCHEMA)
            self.assertEqual(value["status"], "failed")
            self.assertEqual(value["failure"]["kind"], "harness")
            self.assertIn("positive", value["error"])

    def test_failure_report_distinguishes_liveness_from_rss_threshold(self) -> None:
        liveness = HARNESS.failure_report(HARNESS.AllocatorLivenessError("owner handoff failed"))
        threshold_error = HARNESS.RssThresholdError(observed_bytes=32768, threshold_bytes=16384)
        threshold_error.selected_shadow_artifact_attestation = {"status": "passed"}
        threshold_error.artifact = {"sha256": "a" * 64, "size_bytes": 1}
        threshold_error.dynamic_dependencies = ["libc.so"]
        threshold = HARNESS.failure_report(threshold_error)

        self.assertEqual(liveness["failure"]["kind"], "allocator_liveness")
        self.assertEqual(threshold["failure"]["kind"], "rss_threshold")
        self.assertEqual(
            threshold["failure"]["rss"],
            {"observed_high_water_bytes": 32768, "threshold_bytes": 16384},
        )
        self.assertEqual(
            threshold["production_shadow_boundary"]["selected_shadow_artifact_attestation"],
            {"status": "passed"},
        )
        self.assertEqual(threshold["artifact"], {"sha256": "a" * 64, "size_bytes": 1})


if __name__ == "__main__":
    unittest.main()
