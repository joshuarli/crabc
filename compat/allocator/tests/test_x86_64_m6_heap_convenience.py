"""Heap convenience Cargo commands select the source checkout explicitly."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_heap_convenience as convenience


class HeapConvenienceCompilerAuthorityTests(unittest.TestCase):
    def test_profile_build_selects_absolute_owning_adapter_manifest(self):
        root = Path("/candidate")
        for profile in convenience.PROFILES:
            command = convenience.native_build_command(root, root / ".work/build", profile, "/bin/cargo")
            self.assertIn("--manifest-path", command)
            self.assertEqual(command[command.index("--manifest-path") + 1],
                str(root / "compat/allocator/native-mi-adapter/Cargo.toml"))

    def test_actual_compiler_ignores_another_checkout_with_same_package_name(self):
        cargo = shutil.which("cargo")
        if cargo is None:
            self.skipTest("run inside the pinned native compiler image")
        with tempfile.TemporaryDirectory() as scratch:
            base = Path(scratch)
            owner, other = base / "owner", base / "other"
            for root, answer in ((owner, 42), (other, 99)):
                package = root / "compat/allocator/native-mi-adapter"
                (package / "src").mkdir(parents=True)
                (root / "Cargo.toml").write_text('[workspace]\nmembers=["compat/allocator/native-mi-adapter"]\nresolver="2"\n')
                (package / "Cargo.toml").write_text('[package]\nname="crabc-mimalloc-native-mi-adapter"\nversion="0.1.0"\nedition="2021"\n')
                (package / "src/lib.rs").write_text(f'#![no_std]\npub fn answer() -> u32 {{ {answer} }}\n')
                subprocess.run([cargo, "generate-lockfile", "--offline"], cwd=root, check=True, capture_output=True)
            command = convenience.native_build_command(owner, base / "target", "release", cargo)
            result = subprocess.run([*command, "--message-format=json"], cwd=other, check=True, capture_output=True, text=True)
            artifacts = [json.loads(line) for line in result.stdout.splitlines()
                if json.loads(line).get("reason") == "compiler-artifact"]
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["manifest_path"], str(owner / "compat/allocator/native-mi-adapter/Cargo.toml"))
            self.assertEqual(artifacts[0]["target"]["src_path"], str(owner / "compat/allocator/native-mi-adapter/src/lib.rs"))


class HeapConvenienceReceiptAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / ".work/control/run-one"
        self.work.mkdir(parents=True)
        self.products, self.cases = {}, []
        for profile in convenience.PROFILES:
            directory = self.work / profile
            directory.mkdir()
            for name in ("native-mi-adapter.a", "c-native"):
                path = directory / name
                path.write_bytes((profile + name).encode())
                self.products[f"{profile}-{name}"] = path
            command = convenience.native_build_command(self.root, directory / "cargo-target", profile, "/tools/cargo")
            path = self.work / f"{profile}-native-build.json"
            path.write_text(json.dumps({"command": command, "kind": "process", "status": 0}))
            self.cases.append((f"{profile}-native-build", 0, [path]))
        path = self.work / "release-c-native-normal.json"
        path.write_text(json.dumps({"command": [str(self.work / "release/c-native")], "kind": "process", "status": 0}))
        self.cases.append(("release-c-native-normal", 0, [path]))
        for patcher in (
            mock.patch.object(convenience.harness, "ROOT", self.root),
            mock.patch.object(convenience.harness, "require_tool", return_value="/tools/cargo"),
            mock.patch.object(convenience.receipts, "source_seal", return_value={"revision": "a" * 40, "worktree_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def publish(self):
        convenience.receipts.write_receipt(self.root, convenience.RUNNER, self.work,
            self.products, self.cases, {}, True)
        return convenience.receipts.read_receipt(self.root, convenience.RUNNER)

    def test_valid_physically_retained_builds_are_readable(self):
        convenience.read_native_build_authority(self.publish())

    def test_newly_sealed_wrong_checkout_and_omitted_manifest_are_rejected(self):
        for wrong in ("/another/Cargo.toml", None):
            path = self.work / "debug-1-native-build.json"
            command = convenience.native_build_command(self.root, self.work / "debug-1/cargo-target", "debug-1", "/tools/cargo")
            index = command.index("--manifest-path")
            if wrong is None:
                del command[index:index + 2]
            else:
                command[index + 1] = wrong
            path.write_text(json.dumps({"command": command, "kind": "process", "status": 0}))
            receipt = self.publish()
            with self.assertRaisesRegex(convenience.harness.HarnessError, "native build authority"):
                convenience.read_native_build_authority(receipt)

    def test_original_library_drift_is_rejected_beyond_retained_hashes(self):
        receipt = self.publish()
        self.products["stat-1-native-mi-adapter.a"].write_bytes(b"other checkout library")
        with self.assertRaisesRegex(convenience.harness.HarnessError, "original stat-1"):
            convenience.read_native_build_authority(receipt)


if __name__ == "__main__":
    unittest.main()
