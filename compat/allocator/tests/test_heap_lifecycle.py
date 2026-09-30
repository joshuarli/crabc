"""Physical Heap fault replay preserves retained evidence and refusal traces."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
spec = importlib.util.spec_from_file_location("heap_lifecycle", ROOT / "compat/allocator/heap_lifecycle.py")
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class HeapFaultReplayTests(unittest.TestCase):
    def test_replay_executes_controls_without_writing_retained_evidence(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            root = Path(directory)
            artifacts = root / "retained/x86_64/heap-lifecycle/faults"
            artifacts.mkdir(parents=True)
            sections = {"fault": 16, "image_fault": 12, "key_fault": 32, "lock": 64, "birth": 40}
            output = "\n".join(f"m6.heap.{section}.{index}=1" for section, count in sections.items()
                               for index in range(count))
            recorded = {"provenance": {"image_id": "sha256:" + "1" * 64,
                "git": {}, "seal": {}, "inputs": [], "products": []}}
            for section, count in sections.items():
                name = {"fault": "", "image_fault": "image_", "key_fault": "key_",
                        "lock": "lock_", "birth": "birth_"}[section]
                for language in ("c", "rust"):
                    recorded[f"{language}_{name}trace"] = [1] * count
            recorded["branches"] = [{"id": branch, "c_trace": {}, "rust_trace": {}, "comparison": "pass"}
                                    for branch in producer.FAULT_BRANCHES]
            writes = []
            original_write = Path.write_text
            def write(path, content, *args, **kwargs):
                if path.is_relative_to(artifacts):
                    raise PermissionError("retained evidence is read-only")
                writes.append(path)
                return original_write(path, content, *args, **kwargs)
            with mock.patch.dict(producer.os.environ, {"CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID": recorded["provenance"]["image_id"]}), \
                 mock.patch.object(producer.harness, "ARTIFACT_ROOT", root / "retained"), \
                 mock.patch.object(producer.harness, "TEMP_ROOT", root / "scratch"), \
                 mock.patch.object(producer.harness, "require_native_x86_64"), \
                 mock.patch.object(producer.harness, "read_json", return_value=recorded), \
                 mock.patch.object(producer.engine, "git_provenance", return_value={}), \
                 mock.patch.object(producer.integrated, "source_seal_unmet", return_value=[]), \
                 mock.patch.object(producer.harness, "command_record", return_value={"exit_code": 0, "stdout": output, "stderr": ""}) as execute, \
                 mock.patch.object(producer.harness, "require_success"), \
                 mock.patch.object(producer.harness, "parse_rust_test_count", return_value=1), \
                 mock.patch.object(producer.harness, "temporary_directory", side_effect=lambda prefix: tempfile.TemporaryDirectory(prefix=prefix, dir=root)), \
                 mock.patch.object(producer.initialization, "parse_branch_trace", return_value={}), \
                 mock.patch.object(producer.initialization, "validate_branch_trace"), \
                 mock.patch.object(producer.initialization, "compare_branch_trace", return_value="pass"), \
                 mock.patch.object(Path, "write_text", write):
                producer.run_faults(replay=True)
            self.assertEqual(execute.call_count, 17)
            self.assertEqual(len(writes), 17)
            self.assertFalse(any(path.is_relative_to(artifacts) for path in writes))


    def test_changed_retained_input_or_product_prevents_execution(self):
        for kind in ("inputs", "products"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
                root = Path(directory)
                image = "sha256:" + "1" * 64
                original = {"path": "retained-client", "sha256": "original"}
                recorded = {"provenance": {"image_id": image, "git": {}, "seal": {},
                            "inputs": [], "products": []}}
                recorded["provenance"][kind] = [original]
                with mock.patch.dict(producer.os.environ, {"CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID": image}), \
                     mock.patch.object(producer.harness, "require_native_x86_64"), \
                     mock.patch.object(producer.harness, "ARTIFACT_ROOT", root / "retained"), \
                     mock.patch.object(producer.harness, "TEMP_ROOT", root / "scratch"), \
                     mock.patch.object(producer.harness, "read_json", return_value=recorded), \
                     mock.patch.object(producer.engine, "git_provenance", return_value={}), \
                     mock.patch.object(producer.integrated, "source_seal_unmet", return_value=[]), \
                     mock.patch.object(producer.engine, "file_record", return_value={**original, "sha256": "changed"}), \
                     mock.patch.object(producer.harness, "command_record") as execute:
                    with self.assertRaisesRegex(producer.harness.HarnessError, "changed: retained-client"):
                        producer.run_faults(replay=True)
                    execute.assert_not_called()

    def test_key_refusal_requires_every_ordered_observation(self):
        for indexes in (range(31), [*range(32), 31], [1, 0, *range(2, 32)]):
            with self.subTest(indexes=list(indexes)):
                output = "\n".join(f"m6.heap.key_fault.{index}=1" for index in indexes)
                with self.assertRaises(producer.harness.HarnessError):
                    producer.trace(output, "key_fault", 32)

    def test_refusal_retry_must_match_source_ownership_observation(self):
        expected = [1] * 32
        observed = [1] * 32
        observed[25] = 0
        with self.assertRaisesRegex(producer.harness.HarnessError, "key_fault differs: 25"):
            producer.compare("key_fault", expected, observed)


if __name__ == "__main__":
    unittest.main()
