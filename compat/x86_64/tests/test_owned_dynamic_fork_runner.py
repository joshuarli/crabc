#!/usr/bin/env python3
"""Focused contracts for retained owned dynamic-fork product evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


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
    @staticmethod
    def _write_product(product: Path) -> None:
        required = (
            "bin/crabc-cc-dynamic", "share/crabc/crabc_cc_static.py", "usr/include/stdint.h",
            "lib/ld-crabc-x86_64.so.1", "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/crti.o",
            "usr/lib/crtn.o", "usr/lib/crabc-dynamic-attach.o", "usr/lib/libc.so",
            "usr/lib/libcrabc-builtins.a",
        )
        files: dict[str, str] = {}
        for index, relative in enumerate(required):
            payload = f"owned dynamic payload {index}\n".encode()
            target = product / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            files[relative] = hashlib.sha256(payload).hexdigest()
        (product / "bin/crabc-cc-dynamic").chmod(0o755)
        (product / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        manifest = {
            "schema": 1,
            "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "target": "x86_64-unknown-linux-musl",
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
            "files": files,
        }
        metadata = product / "share/crabc"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    @staticmethod
    def _retain_observations(work: Path) -> None:
        scenarios = (
            "main", "worker", "kernel-main", "kernel-worker", "recursive", "abandoned",
            "failure", "finalizer-single", "finalizer-held", "worker-survivor",
        )

        def retain(label: str, payload: bytes) -> None:
            (work / f"{label}.stdout").write_bytes(payload)
            if label.endswith("worker-survivor"):
                (work / f"{label}.raw.stdout").write_bytes(b"123\n" + payload)
            (work / f"{label}.stderr").write_bytes(b"")
            (work / f"{label}.status").write_text("0\n", encoding="utf-8")

        for mode in ("pie", "non-pie"):
            for scenario in scenarios:
                payload = (b"dynamic fork survives adopted main exit: ok\n"
                           if scenario == "worker-survivor"
                           else f"{mode}:{scenario}\n".encode())
                retain(f"oracle-{mode}-{scenario}", payload)
                for entry in ("kernel", "direct"):
                    retain(f"semantic-{mode}-{entry}-{scenario}", payload)
                    retain(f"owned-layout-{mode}-{entry}-{scenario}",
                           payload if scenario == "worker-survivor" else b"private " + payload)

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
        self.assertIn('python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" record-oracle', source)
        self.assertIn('python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" record-execution', source)
        self.assertIn('python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" validate', source)
        self.assertIn('seal-observations', source)
        self.assertIn('--product "$installed" --work "$work"', source)
        self.assertLess(source.index('record-oracle'), source.index('run_host "$work/oracle-'))
        self.assertLess(source.index('record-execution'), source.index('run_host "$work/oracle-'))

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
        self.assertIn('driver_compile_command', source)
        self.assertIn('selected_compiler', source)
        self.assertIn('compiler_helper', source)
        self.assertIn('installed driver compile command or prescribed flags drifted', source)

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
        self.assertIn('current preprocessor identity', source)
        self.assertIn('compile dependency roster or installed-header hashes drifted', source)
        self.assertIn('validation', source)

    def test_raw_status_stdout_and_stderr_are_retained_for_all_runs(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"$output" 2>"${output%.stdout}.stderr" || status=$?', source)
        self.assertIn('"${output%.stdout}.status"', source)
        self.assertIn('run_interactive', source)
        self.assertIn('owned-layout', source)
        self.assertIn('for suffix in stdout stderr status; do', source)
        self.assertIn("raw_output = work / f'{label}.raw.stdout'", source)
        self.assertIn('raw_output.write_bytes(captured)', source)

    def test_observation_receipt_requires_all_semantic_and_private_layout_results(self) -> None:
        evidence = load_evidence()
        scratch_root = ROOT / ".work/x86_64/owned-dynamic-fork-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            work = Path(temporary)
            self._retain_observations(work)
            validation = {
                "product_manifest_sha256": "a" * 64,
                "compile_sha256": "b" * 64,
                "link_receipts": {"consumer-pie": "c" * 64},
            }
            consumed = {
                **validation,
                "oracle_products_sha256": "d" * 64,
                "execution_payload_sha256": "e" * 64,
            }
            with patch.object(evidence, "validate", return_value=validation) as validate, \
                 patch.object(evidence, "audit_oracle", return_value="d" * 64), \
                 patch.object(evidence, "audit_execution", return_value="e" * 64):
                evidence.seal_observations(work, Path("/validated-product"))
            validate.assert_called_once_with(Path("/validated-product"), work)
            receipt = json.loads((work / "observations.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], "crabc.dynamic-fork-observations/v2")
            self.assertEqual(receipt["validation"], consumed)
            self.assertEqual(len(receipt["semantic_consumer"]["oracle"]), 20)
            self.assertEqual(len(receipt["semantic_consumer"]["candidate"]), 40)
            self.assertEqual(len(receipt["owned_layout_consumer"]["candidate"]), 40)
            survivor = receipt["semantic_consumer"]["oracle"]["oracle-pie-worker-survivor"]
            self.assertEqual(survivor["survivor_pid"], 123)
            self.assertIn("raw_stdout_sha256", survivor)
            self.assertIn("semantic_stdout_sha256", survivor)

            (work / "observations.json").unlink()
            (work / "owned-layout-pie-kernel-main.status").write_text("124\n", encoding="utf-8")
            with self.assertRaisesRegex(evidence.EvidenceError, "failed or timed out"):
                with patch.object(evidence, "validate", return_value=validation), \
                     patch.object(evidence, "audit_oracle", return_value="d" * 64), \
                     patch.object(evidence, "audit_execution", return_value="e" * 64):
                    evidence.seal_observations(work, Path("/validated-product"))

    def test_final_seal_rejects_mutated_oracle_and_execution_products(self) -> None:
        evidence = load_evidence()
        scratch_root = ROOT / ".work/x86_64/owned-dynamic-fork-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            work = Path(temporary)
            product = work / "installed"
            self._write_product(product)
            (work / "objects").mkdir()
            (work / "oracle").mkdir()
            compiler = work / "pinned-musl-compiler"
            compiler.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            compiler.chmod(0o755)
            for name in ("initial", "one", "two"):
                (work / "objects" / f"libfork-{name}.o").write_bytes(f"{name} object\n".encode())
                (work / "oracle" / f"libfork-{name}.so").write_bytes(f"{name} oracle\n".encode())
            (work / "objects" / "semantic-consumer.o").write_bytes(b"semantic object\n")
            for mode in ("pie", "non-pie"):
                (work / "oracle" / f"consumer-{mode}").write_bytes(f"oracle {mode}\n".encode())

            for name in ("initial", "one", "two"):
                (work / f"libfork-{name}.so").write_bytes(f"{name} candidate\n".encode())
            for name in ("consumer-pie", "consumer-non-pie", "consumer-owned-layout-pie", "consumer-owned-layout-non-pie"):
                (work / name).write_bytes(f"{name} candidate\n".encode())
            shutil.copytree(product, work / "execution-root", symlinks=True)
            for name in ("initial", "one", "two"):
                shutil.copyfile(work / f"libfork-{name}.so", work / "execution-root" / f"libfork-{name}.so")
            shutil.copyfile(work / "libfork-initial.so", work / "execution-root/usr/lib/libfork-initial.so")
            for name in ("consumer-pie", "consumer-non-pie", "consumer-owned-layout-pie", "consumer-owned-layout-non-pie"):
                shutil.copyfile(work / name, work / "execution-root" / name)

            with patch.object(evidence, "ORACLE_COMPILER", compiler):
                evidence.record_oracle(work)
                evidence.record_execution(product, work)
                self._retain_observations(work)
                validation = {"product_manifest_sha256": "a" * 64, "compile_sha256": "b" * 64, "link_receipts": {}}
                with patch.object(evidence, "validate", return_value=validation):
                    evidence.seal_observations(work, product)
                receipt = json.loads((work / "observations.json").read_text(encoding="utf-8"))
                self.assertEqual(receipt["validation"]["oracle_products_sha256"], evidence.digest(work / "oracle-products.json"))
                self.assertEqual(receipt["validation"]["execution_payload_sha256"], evidence.digest(work / "execution-payload.json"))

                (work / "observations.json").unlink()
                (work / "execution-root/consumer-pie").write_bytes(b"mutated candidate consumer\n")
                with self.assertRaisesRegex(evidence.EvidenceError, "application payload semantic-consumer-pie execution copy"):
                    with patch.object(evidence, "validate", return_value=validation):
                        evidence.seal_observations(work, product)
                shutil.copyfile(work / "consumer-pie", work / "execution-root/consumer-pie")

                (work / "oracle/consumer-pie").write_bytes(b"mutated oracle consumer\n")
                with self.assertRaisesRegex(evidence.EvidenceError, "oracle product binary"):
                    with patch.object(evidence, "validate", return_value=validation):
                        evidence.seal_observations(work, product)

    def test_worker_survivor_raw_protocol_requires_a_positive_pid_and_exact_projection(self) -> None:
        evidence = load_evidence()
        scratch_root = ROOT / ".work/x86_64/owned-dynamic-fork-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            work = Path(temporary)
            label = work / "semantic-pie-kernel-worker-survivor"
            body = b"dynamic fork survives adopted main exit: ok\n"
            Path(str(label) + ".stdout").write_bytes(body)
            Path(str(label) + ".raw.stdout").write_bytes(b"417\n" + body)
            Path(str(label) + ".stderr").write_bytes(b"")
            Path(str(label) + ".status").write_text("0\n", encoding="utf-8")
            record = evidence.worker_survivor_observation(label)
            self.assertEqual(record["survivor_pid"], 417)
            self.assertIn("raw_stdout_sha256", record)
            self.assertIn("semantic_stdout_sha256", record)

            Path(str(label) + ".raw.stdout").write_bytes(b"0\n" + body)
            with self.assertRaisesRegex(evidence.EvidenceError, "raw protocol differs"):
                evidence.worker_survivor_observation(label)

            Path(str(label) + ".raw.stdout").write_bytes(b"417\n" + body)
            Path(str(label) + ".stdout").write_bytes(b"wrong projection\n")
            with self.assertRaisesRegex(evidence.EvidenceError, "semantic projection differs"):
                evidence.worker_survivor_observation(label)

    def test_dispatcher_wrapper_still_builds_then_calls_the_qualification_runner(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('build_x86_64_owned_dynamic_sysroot.py', source)
        self.assertIn('run_general_dynamic_fork.sh', source)
        self.assertIn('#if FORK_LIBRARY_TAG == 0', LIBRARY.read_text(encoding="utf-8"))
        self.assertIn('CRABC_OWNED_WITNESS', CONSUMER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
