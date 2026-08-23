"""Host-only tests for the Rustybench facade-report aggregation contract."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "run.py"
MANIFEST = MODULE.with_name("Cargo.toml")
ROOT = MODULE.parents[3]
SPEC = importlib.util.spec_from_file_location("crabc_perf_native", MODULE)
assert SPEC is not None and SPEC.loader is not None
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)


def resource(value: int) -> dict[str, object]:
    return {
        "status": "supported",
        "memory_status": "supported",
        "user_cpu_ns": value,
        "system_cpu_ns": value,
        "voluntary_context_switches": value,
        "involuntary_context_switches": value,
        "minor_page_faults": value,
        "major_page_faults": value,
        "rss_bytes": value,
        "pss_bytes": value,
    }


class AggregateRunsTests(unittest.TestCase):
    def test_medians_preserve_resource_contract(self) -> None:
        runs = [
            {"benchmarks": [{"name": "native::getpid", "median_ns": value, "alloc_count": 0,
                "alloc_bytes": 0, "max_alloc_count": 0, "max_alloc_bytes": 0,
                "process_resources": resource(value)}]}
            for value in (10, 20, 30)
        ]
        summary = native.aggregate_runs(runs)
        getpid = summary["native::getpid"]
        self.assertEqual(getpid["median_ns"], 20)
        self.assertEqual(getpid["process_resources"]["rss_bytes"], 20)
        self.assertEqual(getpid["invocation_count"], 3)


class BuildStdContractTests(unittest.TestCase):
    def test_bench_profile_does_not_split_build_std_core_by_panic_strategy(self) -> None:
        bench_profile = MANIFEST.read_text(encoding="utf-8").split("[profile.bench]", 1)[1]
        self.assertNotIn("panic =", bench_profile)

    def test_build_std_runner_keeps_the_empty_feature_contract(self) -> None:
        args = SimpleNamespace(build_std=True, sample_count=1, sample_size=1, runs=1)
        completed = SimpleNamespace(
            returncode=0,
            stdout=b'{"schema": 1, "benchmarks": []}',
            stderr=b"",
        )
        with patch.object(native.subprocess, "run", return_value=completed) as run:
            report = native.run_backend(ROOT, args, "crabc")

        command = run.call_args.args[0]
        self.assertEqual(
            command[:5],
            ["cargo", "-Z", "build-std=std", "-Z", "build-std-features="],
        )
        self.assertEqual(report["status"], "ok")


class ManifestRenderingTests(unittest.TestCase):
    def test_effective_manifest_uses_validated_comparison_sources(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "CRABC_RUSTYBENCH_SOURCE": "/oracle/rustybench",
                "CRABC_NATIVE_RUSTIX_SOURCE": "/oracle/rustix",
            },
            clear=True,
        ):
            manifest = native.render_manifest(ROOT)

        self.assertIn('rustybench = { path = "/oracle/rustybench" }', manifest)
        self.assertIn('rustix = { path = "/oracle/rustix"', manifest)
        self.assertIn(f'crabc-rs = {{ path = "{ROOT}/crabc-rs"', manifest)
        self.assertIn(f'path = "{ROOT}/compat/perf/native/src/main.rs"', manifest)


if __name__ == "__main__":
    unittest.main()
