#!/usr/bin/env python3
"""Focused contracts for retained owned dynamic-fork product evidence."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_general_dynamic_fork.sh"
WRAPPER = ROOT / "compat/x86_64/run_owned_dynamic_fork.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_dynamic_fork_evidence.py"
LIBRARY = ROOT / "compat/x86_64/general_dynamic_fork_library.c"
CONSUMER = ROOT / "compat/x86_64/general_dynamic_fork_consumer.c"


def load_evidence():
    spec = importlib.util.spec_from_file_location("owned_dynamic_fork_evidence_test", EVIDENCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OwnedDynamicForkRunnerTests(unittest.TestCase):
    def test_supplied_dynamic_escape_is_rejected_before_evidence_creation(self) -> None:
        scratch_root = ROOT / ".work/x86_64/owned-dynamic-fork-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            scratch = Path(temporary)
            escaped = scratch / "escaped-product"
            escaped.symlink_to(ROOT, target_is_directory=True)
            result = subprocess.run(
                ["bash", str(RUNNER), str(escaped)],
                cwd=ROOT,
                env={**os.environ, "TMPDIR": str(scratch)},
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "dynamic-fork product must be a physical checkout .work directory",
                result.stderr,
            )
            self.assertNotIn("dynamic fork evidence:", result.stdout)

    def test_one_dynamic_driver_compilation_per_tag_and_consumer(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        expected = (
            '"$driver" --dynamic-shared-object -std=c11 -fno-builtin '
            '"-DFORK_LIBRARY_TAG=$tag" -c "$library" -o "$work/objects/libfork-$name.o"',
            '"$driver" --dynamic-pie -std=c11 -fno-builtin -c "$consumer" '
            '-o "$work/objects/semantic-consumer.o"',
            '"$driver" --dynamic-pie -std=c11 -fno-builtin -DCRABC_OWNED_WITNESS '
            '-c "$consumer" -o "$work/objects/owned-layout-consumer.o"',
        )
        for command in expected:
            with self.subTest(command=command):
                self.assertEqual(source.count(command), 1)
        self.assertIn('python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" record-compile', source)
        self.assertIn('python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" validate', source)
        self.assertIn('seal-observations', source)

    def test_same_four_objects_feed_musl_dso_links_and_both_consumer_entries(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"$oracle_cc" -shared "$work/objects/libfork-$name.o"', source)
        self.assertIn('"$oracle_cc" -std=c11 "${oracle_entry[@]}" "$work/objects/semantic-consumer.o"', source)
        self.assertNotIn('"$library" "${dependencies[@]}" -o', source)
        self.assertNotIn('"$consumer" -L"$work/oracle"', source)
        self.assertIn('"$driver" --dynamic-shared-object "$work/objects/libfork-$name.o"', source)
        self.assertIn('"$driver" "--dynamic-$mode" "$work/objects/semantic-consumer.o"', source)
        self.assertIn('"$driver" "--dynamic-$mode" "$work/objects/owned-layout-consumer.o"', source)
        self.assertIn('for entry in kernel direct; do', source)
        self.assertIn('command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode" "$scenario")', source)

    def test_compile_record_seals_preprocessor_tag_and_header_identities(self) -> None:
        source = EVIDENCE.read_text(encoding="utf-8")
        self.assertIn('crabc.dynamic-fork-compile/v1', source)
        self.assertIn('FORK_LIBRARY_TAG', source)
        self.assertIn('preprocessed_sha256', source)
        self.assertIn('dependencies', source)
        self.assertIn('source_sha256', source)
        self.assertIn('object_sha256', source)

    def test_dso_receipts_and_actual_dependency_topology_are_audited(self) -> None:
        source = EVIDENCE.read_text(encoding="utf-8")
        self.assertIn('DSO_TOPOLOGY', source)
        self.assertIn('link_trace', source)
        self.assertIn('application_dsos', source)
        self.assertIn('DT_NEEDED', source)
        self.assertIn('libfork-initial.so', source)
        self.assertIn('mode") != "shared"', source)
        self.assertIn('seal_observations', source)
        self.assertIn('owned-layout', source)

    def test_raw_status_stdout_and_stderr_are_retained_for_all_runs(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"$output" 2>"${output%.stdout}.stderr" || status=$?', source)
        self.assertIn('"${output%.stdout}.status"', source)
        self.assertIn('run_interactive', source)
        self.assertIn('owned-layout', source)
        self.assertIn('for suffix in stdout stderr status; do', source)

    def test_observation_receipt_requires_all_semantic_and_private_layout_results(self) -> None:
        evidence = load_evidence()
        scratch_root = ROOT / ".work/x86_64/owned-dynamic-fork-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            work = Path(temporary)
            scenarios = (
                "main", "worker", "kernel-main", "kernel-worker", "recursive", "abandoned",
                "failure", "finalizer-single", "finalizer-held", "worker-survivor",
            )

            def retain(label: str, payload: bytes) -> None:
                (work / f"{label}.stdout").write_bytes(payload)
                (work / f"{label}.stderr").write_bytes(b"")
                (work / f"{label}.status").write_text("0\n", encoding="utf-8")

            for mode in ("pie", "non-pie"):
                for scenario in scenarios:
                    payload = f"{mode}:{scenario}\n".encode()
                    retain(f"oracle-{mode}-{scenario}", payload)
                    for entry in ("kernel", "direct"):
                        retain(f"semantic-{mode}-{entry}-{scenario}", payload)
                        retain(f"owned-layout-{mode}-{entry}-{scenario}", b"private " + payload)
            evidence.seal_observations(work)
            receipt = json.loads((work / "observations.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], "crabc.dynamic-fork-observations/v1")
            self.assertEqual(len(receipt["semantic_consumer"]["oracle"]), 20)
            self.assertEqual(len(receipt["semantic_consumer"]["candidate"]), 40)
            self.assertEqual(len(receipt["owned_layout_consumer"]["candidate"]), 40)

            (work / "observations.json").unlink()
            (work / "owned-layout-pie-kernel-main.status").write_text("124\n", encoding="utf-8")
            with self.assertRaisesRegex(evidence.EvidenceError, "failed or timed out"):
                evidence.seal_observations(work)

    def test_dispatcher_wrapper_still_builds_then_calls_the_qualification_runner(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('build_x86_64_owned_dynamic_sysroot.py', source)
        self.assertIn('run_general_dynamic_fork.sh', source)
        self.assertIn('#if FORK_LIBRARY_TAG == 0', LIBRARY.read_text(encoding="utf-8"))
        self.assertIn('CRABC_OWNED_WITNESS', CONSUMER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
