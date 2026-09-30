"""Heap convenience Cargo commands select the source checkout explicitly."""
from pathlib import Path
import json
import hashlib
import io
import signal
import tarfile
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
        archive = self.work / "mimalloc-3.5.0.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name in ("include/mimalloc.h", "src/static.c", "src/alloc.c", "LICENSE"):
                data = ("pinned fixture " + name).encode()
                member = tarfile.TarInfo("mimalloc-3.5.0/" + name)
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        self.pin = {"archive_root": "mimalloc-3.5.0", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        source = convenience.harness.safe_extract(archive, self.work / "source", self.pin["archive_root"])
        self.products, self.cases = {archive.name: archive}, []
        drivers = []
        for original in (convenience.C_SOURCE, convenience.CXX_SOURCE):
            driver = self.root / "compat/allocator" / original.name
            driver.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, driver)
            drivers.append(driver)
        for original in (*drivers, source / "include/mimalloc.h", source / "src/static.c", source / "LICENSE"):
            retained = self.work / original.name
            shutil.copy2(original, retained)
            self.products[retained.name] = retained
        seal = {"revision": "a" * 40, "worktree_sha256": hashlib.sha256(b"").hexdigest()}
        execution = {"execution_mode": "native", "host_architecture": "x86_64", "image_id": "sha256:" + "1" * 64}
        inputs = self.work / "inputs.json"
        inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": self.pin,
            "profiles": convenience.PROFILES,
            "boundary": "explicit native mi_*; host musl and C++ standard library substrate",
            "header_sha256": hashlib.sha256((source / "include/mimalloc.h").read_bytes()).hexdigest(),
            "expected_abort": -signal.SIGABRT, "runtime_watchdog_seconds": 60}))
        self.products[inputs.name] = inputs
        tools = {name: "/tools/" + name for name in ("musl-gcc", "g++", "cargo", "nm")}
        for profile in convenience.PROFILES:
            directory = self.work / profile
            directory.mkdir()
            for name in ("native-mi-adapter.a", "oracle.o", "c-c", "c-native", "cxx-c", "cxx-native",
                         "c-c.o", "c-native.o", "cxx-c.o", "cxx-native.o"):
                path = directory / name
                path.write_bytes((profile + name).encode())
                self.products[f"{profile}-{name}"] = path
            for step, command in convenience.profile_commands(self.root, self.work, source, profile, tools).items():
                case_id = profile + "-" + step
                raw_status = -signal.SIGABRT if step.endswith("-overflow-abort") else 0
                stdout = b"observable caller result\n" if step.endswith("-normal") else b""
                raw = {"command": command, "kind": "process", "status": raw_status,
                    "stdout": convenience.stress.bytes_record(stdout), "stderr": convenience.stress.bytes_record(b"")}
                paths = [self.work / (case_id + suffix) for suffix in (".json", ".stdout", ".stderr")]
                paths[0].write_text(json.dumps(raw)); paths[1].write_bytes(stdout); paths[2].write_bytes(b"")
                self.cases.append((case_id, 0, paths))
        for patcher in (
            mock.patch.object(convenience.harness, "ROOT", self.root),
            mock.patch.object(convenience, "C_SOURCE", drivers[0]),
            mock.patch.object(convenience, "CXX_SOURCE", drivers[1]),
            mock.patch.object(convenience.harness, "TEMP_ROOT", self.root / ".work/reader"),
            mock.patch.object(convenience.harness, "load_pin", return_value=self.pin),
            mock.patch.object(convenience.harness, "require_tool", side_effect=lambda name: tools[name]),
            mock.patch.object(convenience.harness, "require_native_x86_64", return_value=execution),
            mock.patch.object(convenience.receipts, "source_seal", return_value=seal),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def publish(self):
        convenience.receipts.write_receipt(self.root, convenience.RUNNER, self.work,
            self.products, self.cases, {"profiles": ",".join(convenience.PROFILES),
                "boundary": "explicit native-mi-adapter", "c-substrate": "pinned-musl-1.2.6",
                "cxx-substrate": "native-image-musl-libstdc++", "expected-overflow-abort": "SIGABRT",
                "watchdog-seconds": "60"}, True)
        return convenience.receipts.read_receipt(self.root, convenience.RUNNER)

    def test_valid_physically_retained_builds_are_readable(self):
        convenience.read_convenience_authority(self.publish())

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
            with self.assertRaisesRegex(convenience.harness.HarnessError, "native-build.*authority"):
                convenience.read_convenience_authority(receipt)

    def test_newly_sealed_wrong_oracle_profile_is_rejected(self):
        path = self.work / "debug-1-oracle-build.json"
        raw = json.loads(path.read_text())
        raw["command"][raw["command"].index("-DMI_DEBUG=1")] = "-DMI_DEBUG=0"
        path.write_text(json.dumps(raw))
        receipt = self.publish()
        with self.assertRaisesRegex(convenience.harness.HarnessError, "oracle-build.*authority"):
            convenience.read_convenience_authority(receipt)

    def test_newly_sealed_wrong_cxx_compiler_link_and_execute_are_rejected(self):
        for case_id, mutate in (
            ("stat-1-cxx-native-compile", lambda c: c.__setitem__(0, "/unrelated/g++")),
            ("stat-1-cxx-native-link", lambda c: c.__setitem__(-4, "/unrelated/allocator.a")),
            ("stat-1-cxx-native-overflow-throw", lambda c: c.__setitem__(0, "/unrelated/cxx-native")),
        ):
            path = self.work / (case_id + ".json")
            original = path.read_text()
            raw = json.loads(original)
            mutate(raw["command"])
            path.write_text(json.dumps(raw))
            with self.subTest(case_id=case_id):
                receipt = self.publish()
                with self.assertRaisesRegex(convenience.harness.HarnessError, "command authority"):
                    convenience.read_convenience_authority(receipt)
            path.write_text(original)

    def test_resealed_driver_header_and_license_drift_are_rejected(self):
        for name in (convenience.CXX_SOURCE.name, "mimalloc.h", "LICENSE", "static.c", "mimalloc-3.5.0.tar.gz"):
            path = self.products[name]
            original = path.read_bytes()
            path.write_bytes(b"changed authentic-looking source input")
            with self.subTest(product=name):
                receipt = self.publish()
                with self.assertRaises(convenience.harness.HarnessError):
                    convenience.read_convenience_authority(receipt)
            path.write_bytes(original)

    def test_matched_nonzero_exit_cannot_be_relabelled_a_passing_case(self):
        path = self.work / "release-cxx-native-normal.json"
        raw = json.loads(path.read_text()); raw["status"] = 1
        path.write_text(json.dumps(raw))
        receipt = self.publish()
        with self.assertRaisesRegex(convenience.harness.HarnessError, "actual status"):
            convenience.read_convenience_authority(receipt)

    def test_missing_runtime_mode_is_not_complete_four_profile_evidence(self):
        self.cases = [case for case in self.cases if case[0] != "stat-2-cxx-native-refusal-handler"]
        receipt = self.publish()
        with self.assertRaisesRegex(convenience.harness.HarnessError, "ordered caller roster"):
            convenience.read_convenience_authority(receipt)

    def test_original_library_drift_is_rejected_beyond_retained_hashes(self):
        receipt = self.publish()
        self.products["stat-1-native-mi-adapter.a"].write_bytes(b"other checkout library")
        with self.assertRaisesRegex(convenience.harness.HarnessError, "original input or product"):
            convenience.read_convenience_authority(receipt)


if __name__ == "__main__":
    unittest.main()
