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

    def test_fixture_result_requires_initial_thread_post_exit_frees(self) -> None:
        result = fixture_result()

        parsed = HARNESS.parse_fixture_output(json.dumps(result), seed=91, cycles=3)

        self.assertEqual(parsed["post_exit_initial_thread_frees"], 18)
        self.assertEqual(parsed["owner_exits_with_live_blocks"], 3)
        self.assertEqual(parsed["allocator_metadata_high_water_bytes"], None)

    def test_fixture_result_rejects_hidden_post_exit_release(self) -> None:
        result = fixture_result()
        result["post_exit_initial_thread_frees"] = 0

        with self.assertRaisesRegex(HARNESS.SmokeError, "post_exit_initial_thread_frees"):
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
            self.assertIn("positive", value["error"])


if __name__ == "__main__":
    unittest.main()
