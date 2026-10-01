"""Physical receipt controls for the full debug-padding page workload."""
from pathlib import Path
import json
import hashlib
import tarfile
import tomllib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m7_debug_padding_page as page


class DebugPaddingPageReceiptTests(unittest.TestCase):
    def setUp(self):
        scratch = page.harness.ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        manifest = page.harness.ROOT / "crabc-mimalloc/Cargo.toml"
        retained_manifest = self.root / "crabc-mimalloc/Cargo.toml"
        retained_manifest.parent.mkdir(parents=True)
        retained_manifest.write_bytes(manifest.read_bytes())
        selected = set()
        pending = [page.RUST_FEATURE.split("/", 1)[1]]
        features = tomllib.loads(manifest.read_text())["features"]
        while pending:
            feature = pending.pop()
            if feature not in selected:
                selected.add(feature)
                pending.extend(name for name in features[feature] if name in features)
        self.work = self.root / ".work/allocator-x86_64/target/compat/allocator/x86_64/m7-debug-padding/page-test"
        self.work.mkdir(parents=True)
        mock.patch.object(page, "REPORT", self.work.parent / "page.json").start()
        mock.patch.object(page.harness, "WORK_ROOT", self.root / ".work/allocator-x86_64").start()
        mock.patch.object(page.harness, "TEMP_ROOT", self.root / ".work/tmp/allocator").start()
        self.seal = {"revision": "a" * 40, "worktree_sha256": "b" * 64}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(page.harness, "ROOT", self.root).start()
        mock.patch.object(page.receipts, "source_seal", return_value=self.seal).start()
        names = ["c-build", "rust-build", "rust-link", "c-clean", "c-corrupt", "rust-clean", "rust-corrupt", "comparison"]
        self.cases = []
        for name in names:
            log = self.work / (name + ".json")
            log.write_text('{}\n')
            self.cases.append((name, 0, [log]))
        report = {"status": "passed", "mismatch_keys": {"clean": [], "corrupt": []},
                  "traces": {}, "executions": {}}
        for side in ("c", "rust"):
            for case in ("clean", "corrupt"):
                report["traces"][f"{side}.{case}"] = {"case": case, "owned.live": "1"}
                report["executions"][f"{side}.{case}"] = {"status": 0, "stdout": "", "stderr": ""}
        self.products = {}
        for name in ("c", "rust", page.FIXTURE.name, "mimalloc-3.5.0.tar.gz", "inputs.json", "page.json", "native-library"):
            path = self.work / name
            path.write_text(json.dumps(report) if name == "page.json" else '{}\n')
            self.products[name] = path
        self.execution = {"execution_mode": "native", "host_architecture": "x86_64", "image_id": "sha256:" + "1" * 64}
        self.products["inputs.json"].write_text(json.dumps({"execution": self.execution}))
        mock.patch.object(page.harness, "require_native_x86_64", return_value=self.execution).start()
        self.parameters = {"debug": "1", "padding": "1", "stat": "2"}

        fixture = self.root / "compat/allocator" / page.FIXTURE.name
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(page.FIXTURE.read_bytes())
        mock.patch.object(page, "FIXTURE", fixture).start()
        self.products[fixture.name].write_bytes(fixture.read_bytes())
        source = self.work / "source/mimalloc-3.5.0"
        for directory, name in (("src", "static.c"), ("src", "alloc.c"), ("include", "mimalloc.h")):
            path = source / directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("selected source fixture\n")
        archive = self.products["mimalloc-3.5.0.tar.gz"]
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(source, arcname=source.name)
        self.pin = {"archive_root": source.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        mock.patch.object(page.harness, "load_pin", return_value=self.pin).start()
        tools = self.root / "tools"
        tools.mkdir()
        for tool in ("musl-gcc", "cargo"):
            (tools / tool).write_bytes(tool.encode())
        mock.patch.object(page.harness, "require_tool", side_effect=lambda tool: str(tools / tool)).start()
        compiler = str(tools / "musl-gcc")
        cargo = str(tools / "cargo")
        target = page.harness.WORK_ROOT / "cargo-target/m7-debug-padding-page"
        library = target / page.TARGET / "release" / page.STATICLIB
        common = [compiler, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *page.C_FLAGS, "-I", str(source / "include"), str(fixture)]
        self.commands = {
            "c-build": [*common, str(source / "src/static.c"), "-pthread", "-o", str(self.work / "debug-padding-page-c")],
            "rust-build": [cargo, "build", "--locked", "--offline", "--release", "--message-format=json", "--target", page.TARGET,
                "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features", "--features", page.RUST_FEATURE, "--target-dir", str(target)],
            "rust-link": [*common, str(self.work / "native-mi-adapter.a"), "-pthread", "-o", str(self.work / "debug-padding-page-rust")],
        }
        release = {"opt_level": "3", "debuginfo": 0, "debug_assertions": False, "overflow_checks": False, "test": False}
        messages = [{"reason": "compiler-artifact", "manifest_path": str(self.root / "compat/allocator/native-mi-adapter/Cargo.toml"),
                     "target": {"name": "crabc_mimalloc_native_mi_adapter", "kind": ["staticlib"], "src_path": str(self.root / "compat/allocator/native-mi-adapter/src/lib.rs")},
                     "filenames": [str(library)], "profile": release, "features": []},
                    {"reason": "compiler-artifact", "manifest_path": str(retained_manifest),
                     "target": {"name": "crabc_mimalloc", "src_path": str(self.root / "crabc-mimalloc/src/lib.rs")}, "features": sorted(selected), "profile": release}]
        for name, command in self.commands.items():
            product = {"c-build": "c", "rust-build": "native-library", "rust-link": "rust"}[name]
            output = library if name == "rust-build" else Path(command[-1])
            payload = self.products[product].read_bytes()
            record = {"command": command, "status": 0, "stdout": "\n".join(json.dumps(row) for row in messages) if name == "rust-build" else "",
                      "stderr": "", "artifact": {"path": page.harness.relative(output), "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}}
            (self.work / (name + ".json")).write_text(json.dumps(record))
            report[{"c-build": "c_build_command", "rust-build": "rust_build_command", "rust-link": "rust_link_command"}[name]] = command
        self.products["page.json"].write_text(json.dumps(report))
        self.products["inputs.json"].write_text(json.dumps({"execution": self.execution, "source": self.seal, "upstream": self.pin,
            "compiler": page.engine.file_record(tools / "musl-gcc"), "cargo": page.engine.file_record(tools / "cargo"),
            "fixture": page.engine.file_record(fixture), "c-flags": list(page.C_FLAGS), "rust-feature": page.RUST_FEATURE}))
        link_bytes = {side: self.products[side].read_bytes() for side in ("c", "rust")}
        def link(command, **kwargs):
            side = "c" if str(source / "src/static.c") in command else "rust"
            Path(command[-1]).write_bytes(link_bytes[side])
            return {"command": command, "status": 0, "stdout": "", "stderr": ""}
        mock.patch.object(page.harness, "command_record", side_effect=link).start()

    def publish(self):
        return page.receipts.write_receipt(self.root, page.RUNNER, self.work,
                                          self.products, self.cases, self.parameters, True)

    def test_resealed_original_link_to_different_provider_is_rejected(self):
        log = self.work / "rust-link.json"
        record = json.loads(log.read_text())
        record["command"][-4] = str(self.work / "pinned-c-provider.a")
        log.write_text(json.dumps(record))
        self.publish()
        with self.assertRaises(page.harness.HarnessError):
            page.read_and_replay()

    def test_resealed_native_archive_cannot_replace_the_emitted_artifact(self):
        self.products["native-library"].write_bytes(b"different allocator provider archive")
        self.publish()
        with self.assertRaisesRegex(page.harness.HarnessError, "provider link binding"):
            page.read_and_replay()

    def test_resealed_caller_must_relink_from_its_authenticated_provider(self):
        self.products["rust"].write_bytes(b"different caller ELF")
        log = self.work / "rust-link.json"
        record = json.loads(log.read_text())
        record["artifact"].update(sha256=hashlib.sha256(self.products["rust"].read_bytes()).hexdigest(), bytes=self.products["rust"].stat().st_size)
        log.write_text(json.dumps(record))
        self.publish()
        with self.assertRaisesRegex(page.harness.HarnessError, "caller differs from its selected provider link"):
            page.read_and_replay()

    def test_resealed_archive_must_match_the_source_pin(self):
        self.products["mimalloc-3.5.0.tar.gz"].write_bytes(b"different pinned oracle archive")
        self.publish()
        with self.assertRaisesRegex(page.harness.HarnessError, "oracle archive differs"):
            page.read_and_replay()

    def test_compiler_emitted_allocator_must_select_debug_and_stat_levels(self):
        log = self.work / "rust-build.json"
        record = json.loads(log.read_text())
        messages = [json.loads(line) for line in record["stdout"].splitlines()]
        messages[1]["features"] = ["mi-stat-2"]
        record["stdout"] = "\n".join(json.dumps(row) for row in messages)
        log.write_text(json.dumps(record))
        self.publish()
        with self.assertRaisesRegex(page.harness.HarnessError, "native provider configuration"):
            page.read_and_replay()

    def test_original_compilation_headers_must_come_from_the_pinned_archive(self):
        (self.work / "source/mimalloc-3.5.0/include/mimalloc.h").write_text("different header source")
        self.publish()
        with self.assertRaisesRegex(page.harness.HarnessError, "compiler source differs"):
            page.read_and_replay()

    def test_resealed_retained_driver_must_match_the_selected_tracked_driver(self):
        self.products[page.FIXTURE.name].write_bytes(b"different client workload")
        self.publish()
        with self.assertRaisesRegex(page.harness.HarnessError, "caller differs from the selected source"):
            page.read_and_replay()

    def test_complete_retained_builds_callers_and_comparison_are_readable(self):
        self.publish()
        page.read_and_replay()

    def test_missing_or_extra_or_reordered_caller_phase_is_rejected(self):
        original = self.cases[:]
        for cases in (original[:-1], original + [("extra", 0, original[0][2])],
                      [original[1], original[0], *original[2:]]):
            with self.subTest(cases=[case[0] for case in cases]):
                self.cases = cases
                self.publish()
                with self.assertRaises(page.harness.HarnessError):
                    page.read_and_replay()

    def test_missing_or_extra_product_is_rejected(self):
        original = self.products.copy()
        for products in ({key: value for key, value in original.items() if key != "c"},
                         {**original, "extra": original["c"]}):
            self.products = products
            self.publish()
            with self.assertRaises(page.harness.HarnessError):
                page.read_and_replay()

    def test_changed_physical_product_is_rejected_by_generic_reader(self):
        receipt = self.publish()
        (receipt.parent / "products/c").write_bytes(b"changed ELF bytes")
        with self.assertRaises(page.receipts.ReceiptError):
            page.read_and_replay()

    def test_wrong_selected_numeric_configuration_is_rejected(self):
        self.parameters["stat"] = "1"
        self.publish()
        with self.assertRaises(page.harness.HarnessError):
            page.read_and_replay()

    def test_nonzero_actual_caller_status_cannot_be_admitted(self):
        name, _, logs = self.cases[3]
        self.cases[3] = (name, -6, logs)
        self.publish()
        with self.assertRaises(page.receipts.ReceiptError):
            page.read_and_replay()

    def test_receipt_from_different_compiler_runtime_image_is_rejected(self):
        inputs = json.loads(self.products["inputs.json"].read_text())
        inputs["execution"]["image_id"] = "sha256:" + "2" * 64
        self.products["inputs.json"].write_text(json.dumps(inputs))
        self.publish()
        with self.assertRaises(page.harness.HarnessError):
            page.read_and_replay()

    def test_disagreeing_native_page_observation_is_rejected(self):
        report = json.loads(self.products["page.json"].read_text())
        report["traces"]["rust.clean"]["owned.live"] = "0"
        self.products["page.json"].write_text(json.dumps(report))
        self.publish()
        with self.assertRaises(page.harness.HarnessError):
            page.read_and_replay()


if __name__ == "__main__":
    unittest.main()
