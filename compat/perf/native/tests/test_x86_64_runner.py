"""Focused contract tests for the native x86 Rust-facade companion runner."""

from __future__ import annotations

import copy
import contextlib
import io
import importlib.util
import os
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
MODULE = ROOT / "compat/perf/native/x86_64_runner.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_native_x86", MODULE)
assert SPEC is not None and SPEC.loader is not None
native_x86 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native_x86
SPEC.loader.exec_module(native_x86)


ROW_NAMES = (
    "native_x86::caller_buffer",
    "native_x86::missing_error",
    "native_x86::frozen::clock_gettime",
    "native_x86::frozen::getpid",
    "native_x86::frozen::open_close",
)
RESOURCE_KEYS = (
    "user_cpu_ns",
    "system_cpu_ns",
    "voluntary_context_switches",
    "involuntary_context_switches",
    "minor_page_faults",
    "major_page_faults",
    "rss_bytes",
    "pss_bytes",
)

CORRECTNESS_OUTPUT = """native_x86
├─ caller_buffer
├─ missing_error
╰─ frozen
   ├─ clock_gettime
   ├─ getpid
   ╰─ open_close

"""


def raw_report(*, sample_count: int = 2, sample_size: int = 3) -> dict[str, object]:
    benchmarks: list[dict[str, object]] = []
    for index, name in enumerate(ROW_NAMES):
        resources: dict[str, object] = {
            "status": "supported",
            "memory_status": "supported",
        }
        resources.update({key: index + 1 for key in RESOURCE_KEYS})
        benchmarks.append(
            {
                "name": name,
                "median_ns": index + 10,
                "alloc_count": index,
                "alloc_bytes": index * 8,
                "max_alloc_count": index,
                "max_alloc_bytes": index * 8,
                "sample_count": sample_count,
                "iter_count": sample_count * sample_size,
                "process_resources": resources,
            }
        )
    return {"schema": 1, "benchmarks": benchmarks}


class RawReportTests(unittest.TestCase):
    def test_exact_five_row_raw_report_recomputes_derived_metrics(self) -> None:
        result = native_x86.validate_benchmark_report(
            raw_report(), ROW_NAMES, sample_count=2, sample_size=3,
        )
        self.assertEqual(result["row_count"], 5)
        self.assertEqual(result["total_median_ns"], sum(range(10, 15)))
        self.assertEqual(result["total_user_cpu_ns"], sum(range(1, 6)))
        self.assertEqual(result["total_minor_page_faults"], sum(range(1, 6)))
        self.assertEqual(result["total_max_alloc_bytes"], sum(index * 8 for index in range(5)))

    def test_raw_report_rejects_duplicate_missing_and_absent_resource_values(self) -> None:
        duplicate = raw_report()
        duplicate["benchmarks"][1]["name"] = ROW_NAMES[0]  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "duplicate|missing"):
            native_x86.validate_benchmark_report(duplicate, ROW_NAMES, sample_count=2, sample_size=3)

        missing_resource = raw_report()
        del missing_resource["benchmarks"][0]["process_resources"]["pss_bytes"]  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "pss_bytes"):
            native_x86.validate_benchmark_report(
                missing_resource, ROW_NAMES, sample_count=2, sample_size=3,
            )

        null_resource = raw_report()
        null_resource["benchmarks"][0]["process_resources"]["user_cpu_ns"] = None  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "user_cpu_ns"):
            native_x86.validate_benchmark_report(
                null_resource, ROW_NAMES, sample_count=2, sample_size=3,
            )

    def test_raw_report_rejects_sample_and_iteration_drift(self) -> None:
        drifted = raw_report()
        drifted["benchmarks"][0]["iter_count"] = 5  # type: ignore[index]
        with self.assertRaisesRegex(native_x86.RunnerError, "iter_count"):
            native_x86.validate_benchmark_report(drifted, ROW_NAMES, sample_count=2, sample_size=3)


class AdmissionAndPathTests(unittest.TestCase):
    def test_full_mode_is_unconditionally_unavailable(self) -> None:
        with self.assertRaisesRegex(native_x86.RunnerError, "correctness predecessor"):
            native_x86.require_admitted_mode("full")

    def test_cli_refuses_full_mode_before_it_requires_any_source_argument(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(native_x86.main(["--mode", "full"]), 2)
        self.assertIn("correctness predecessor", stderr.getvalue())

    def test_smoke_mode_is_the_fixed_reduced_geometry(self) -> None:
        self.assertEqual(native_x86.require_admitted_mode("smoke"), (1, 2, 3))

    def test_direct_rustybench_invocations_explicitly_select_the_bench_action(self) -> None:
        artifact = Path("/private/target/native_x86")
        self.assertEqual(
            native_x86.rustybench_invocation_argv(artifact, kind="correctness"),
            [str(artifact), "--test"],
        )
        self.assertEqual(
            native_x86.rustybench_invocation_argv(
                artifact, kind="reduced", sample_count=2, sample_size=3,
            ),
            [
                str(artifact), "--bench", "--format", "json", "--sample-count", "2",
                "--sample-size", "3",
            ],
        )
        with self.assertRaisesRegex(native_x86.RunnerError, "geometry"):
            native_x86.rustybench_invocation_argv(
                artifact, kind="reduced", sample_count=0, sample_size=3,
            )
        with self.assertRaisesRegex(native_x86.RunnerError, "unknown"):
            native_x86.rustybench_invocation_argv(artifact, kind="foreign")

    def test_correctness_discovery_is_an_exact_five_row_roster(self) -> None:
        native_x86.validate_correctness_stdout(CORRECTNESS_OUTPUT)
        with self.assertRaisesRegex(native_x86.RunnerError, "roster"):
            native_x86.validate_correctness_stdout(CORRECTNESS_OUTPUT + "├─ foreign\n")

    def test_profile_contract_rejects_a_changed_row_source_or_image(self) -> None:
        with (ROOT / "compat/perf/native/x86_64_profile.toml").open("rb") as stream:
            profile = tomllib.load(stream)
        native_x86.validate_profile_contract(profile)

        changed_row = copy.deepcopy(profile)
        changed_row["rows"][0]["source"] = "frozen"
        with self.assertRaisesRegex(native_x86.RunnerError, "row contract"):
            native_x86.validate_profile_contract(changed_row)

        changed_image = copy.deepcopy(profile)
        changed_image["execution"]["image"] = "untrusted"
        with self.assertRaisesRegex(native_x86.RunnerError, "image"):
            native_x86.validate_profile_contract(changed_image)

    def test_active_dependency_roster_rejects_a_subset_or_extra_package(self) -> None:
        with (ROOT / "compat/perf/native/x86_64_profile.toml").open("rb") as stream:
            profile = tomllib.load(stream)
        expected = profile["dependency_policy"]["active_crabc"]
        records = [
            {"name": item.rsplit("@", 1)[0], "version": item.rsplit("@", 1)[1]}
            for item in expected
        ]
        native_x86.validate_active_dependency_roster(profile, "crabc", records)
        with self.assertRaisesRegex(native_x86.RunnerError, "roster"):
            native_x86.validate_active_dependency_roster(profile, "crabc", records[:-1])
        with self.assertRaisesRegex(native_x86.RunnerError, "roster"):
            native_x86.validate_active_dependency_roster(
                profile, "crabc", [*records, {"name": "foreign", "version": "9"}],
            )

    def test_dependency_source_kind_cannot_substitute_a_registry_copy_for_a_pinned_path_input(self) -> None:
        native_x86.validate_dependency_source_kinds(
            "crabc",
            [
                {
                    "name": "rustybench",
                    "version": "0.1.0",
                    "source_kind": "rustybench",
                    "source": None,
                },
                {
                    "name": "itoa",
                    "version": "1.0.18",
                    "source_kind": "cargo-registry",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
            ],
        )
        with self.assertRaisesRegex(native_x86.RunnerError, "source root"):
            native_x86.validate_dependency_source_kinds(
                "crabc",
                [
                    {
                        "name": "rustybench",
                        "version": "0.1.0",
                        "source_kind": "cargo-registry",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                    },
                ],
            )

    def test_report_and_work_paths_must_stay_in_this_checkout_work_boundary(self) -> None:
        work_root = ROOT / ".work/x86_64"
        self.assertEqual(native_x86.require_private_work_path(ROOT, work_root), work_root.resolve())
        with self.assertRaisesRegex(native_x86.RunnerError, "below"):
            native_x86.require_private_work_path(ROOT, ROOT / "compat")
        with tempfile.TemporaryDirectory(dir=work_root) as temporary_text:
            temporary = Path(temporary_text)
            foreign = temporary / "escape"
            foreign.symlink_to(ROOT / "compat", target_is_directory=True)
            with self.assertRaisesRegex(native_x86.RunnerError, "physical"):
                native_x86.require_private_work_path(ROOT, foreign)


class ProvenanceTests(unittest.TestCase):
    def test_static_pie_elf_contract_rejects_a_dynamic_interpreter(self) -> None:
        header = "\n".join(
            (
                "Class:                             ELF64",
                "Data:                              2's complement, little endian",
                "Type:                              DYN (Position-Independent Executable file)",
                "Machine:                           Advanced Micro Devices X86-64",
            )
        )
        native_x86._validate_elf_text(header, "test")
        with self.assertRaisesRegex(native_x86.RunnerError, "dynamic runtime"):
            native_x86._validate_elf_text(header + "\n  INTERP", "test")

    def test_tree_identity_rejects_a_changed_source_byte(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            source = Path(temporary_text) / "source"
            source.mkdir()
            tracked = source / "fixture.rs"
            tracked.write_text("original\n", encoding="utf-8")
            identity = native_x86.tree_identity(source)
            native_x86.verify_tree_identity(source, identity, "test source")
            tracked.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(native_x86.RunnerError, "tree identity"):
                native_x86.verify_tree_identity(source, identity, "test source")

    def test_file_identity_rejects_a_changed_frozen_source_byte(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary_text:
            source = Path(temporary_text) / "main.rs"
            source.write_text("frozen\n", encoding="utf-8")
            identity = native_x86.file_identity(source)
            source.write_text("mutated\n", encoding="utf-8")
            with self.assertRaisesRegex(native_x86.RunnerError, "sha256"):
                native_x86.verify_file_identity(source, identity, "frozen route source")


if __name__ == "__main__":
    unittest.main()
