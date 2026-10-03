"""The dynamic sysroot producer must start under a qualification case's Python policy."""
import os
import importlib.util
import json
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"


class DynamicSysrootEntryTests(unittest.TestCase):
    def test_debug_manifest_seals_source_without_release_materialization_fields(self):
        spec = importlib.util.spec_from_file_location("dynamic_debug_source_producer", PRODUCER)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            output = Path(temporary)
            metadata = output / "share/crabc"
            metadata.mkdir(parents=True)
            state = {"build_profile": "debug", "allocator_backend": "native-shadow",
                     "allocator_lifecycle_test_audit": False, "status": "materialized-unqualified"}
            builder.common.write_json(metadata / "dynamic-product-state.json", state)
            with mock.patch.object(builder.qualification, "source_digest", return_value="a" * 64):
                builder.write_product_manifest(output, metadata, profile="debug")
            manifest = json.loads((metadata / "manifest.json").read_text())
            self.assertEqual(manifest["source_sha256"], "a" * 64)
            self.assertEqual(manifest["build_profile"], "debug")
            self.assertEqual(json.loads((metadata / "dynamic-product-state.json").read_text()), state)
            self.assertEqual(manifest["files"]["share/crabc/dynamic-product-state.json"], builder.common.sha256_file(metadata / "dynamic-product-state.json"))
            builder.write_product_manifest(output, metadata, profile="release")
            self.assertNotIn("source_sha256", json.loads((metadata / "manifest.json").read_text()))

    def test_debug_source_change_during_build_refuses_publication(self):
        spec = importlib.util.spec_from_file_location("dynamic_debug_source_change", PRODUCER)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            output = Path(temporary) / "candidate"
            with (mock.patch.object(builder.common, "assert_native_target"),
                  mock.patch.object(builder, "build_staged_payload"),
                  mock.patch.object(builder.qualification, "source_digest", side_effect=["a" * 64, "b" * 64]),
                  mock.patch.object(builder.installed_driver, "validate") as installed,
                  mock.patch.object(builder.shared_package, "publish_noreplace") as publish):
                with self.assertRaisesRegex(builder.common.BuildError, "source changed"):
                    builder.build(output, profile="debug", allocator_backend="native-shadow")
                installed.assert_not_called()
                publish.assert_not_called()
                self.assertFalse(output.exists())

    def test_producer_imports_its_shared_static_module_with_pythonsafepath(self):
        # A qualification case may run this producer directly with
        # PYTHONSAFEPATH=1, which omits the script directory from sys.path.
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
        }
        completed = subprocess.run(
            [sys.executable, "-B", str(PRODUCER), "--help"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertIn(b"usage:", completed.stdout)


if __name__ == "__main__":
    unittest.main()
