"""Regression contracts for the supplied-product cleanup consumer receipt."""
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))
import build  # noqa: E402
import owned_cleanup  # noqa: E402


WORK = Path(__file__).parents[2] / ".work/x86_64/unwinder-output-tests"


class OwnedCleanupContract(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.provider = Path(self.temporary.name) / "provider"
        self.provider.mkdir()
        self.archive = self.provider / "libcrabc-unwind.a"
        self.archive.write_bytes(b"selected provider")
        defined = "\n".join(f"00000000 T {name}" for name in sorted(build.UNWIND_ABI)) + "\n"
        (self.provider / "defined-symbols.txt").write_text(defined)

    def tearDown(self):
        self.temporary.cleanup()

    def write_provenance(self, **changes):
        record = {
            "schema": 1,
            "target": owned_cleanup.TARGET,
            "qualified": False,
            "native_build_products": False,
            "personality_owner": "consumer Rust std",
            "archive": {"name": self.archive.name, "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()},
            "unwind_abi": sorted(build.UNWIND_ABI),
            "toolchain": "pinned compiler\n",
        }
        record.update(changes)
        (self.provider / "provenance.json").write_text(json.dumps(record))

    def test_provider_snapshot_binds_archive_abi_and_nonpromoting_state(self):
        self.write_provenance()
        snapshot = owned_cleanup.provider_snapshot(self.provider, "pinned compiler\n")
        self.assertEqual(snapshot["archive"]["path"], str(self.archive))
        self.assertEqual(snapshot["defined_unwind_abi"], sorted(build.UNWIND_ABI))

    def test_provider_snapshot_rejects_a_promoted_or_product_provider(self):
        for changes in ({"qualified": True}, {"native_build_products": True}):
            with self.subTest(changes=changes):
                self.write_provenance(**changes)
                with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "qualification or product"):
                    owned_cleanup.provider_snapshot(self.provider, "pinned compiler\n")

    def test_link_receipt_flags_must_remain_false(self):
        owned_cleanup.assert_nonpromoting(
            {"qualified": False, "family_completion": False, "promotion_ready": False, "public_support": False},
            "test receipt",
        )
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "promotion_ready"):
            owned_cleanup.assert_nonpromoting(
                {"qualified": False, "family_completion": False, "promotion_ready": True, "public_support": False},
                "test receipt",
            )

    def test_source_built_receipt_requires_source_runtime_omissions(self):
        source = Path(self.temporary.name) / "source-built"
        source.mkdir()
        binary = Path(self.temporary.name) / "cleanup"
        binary.write_bytes(b"cleanup")
        receipt = Path(str(binary) + ".crabc-owned-rust-link.json")
        record = {
            "schema": 2,
            "format": "crabc-owned-rust-source-build-link/v1",
            "rust_library_origin": "source-built",
            "source_built_target_library_root": str(source),
            "omitted_source_built_rust_unwind": {"path": str(source / "libunwind-hash.rlib")},
            "omitted_source_built_compiler_builtins": {"path": str(source / "libcompiler_builtins-hash.rlib")},
            "application_inputs": [
                {"path": str(source / "libstd-hash.rlib")},
                {"path": str(source / "libcore-hash.rlib")},
                {"path": str(source / "liballoc-hash.rlib")},
                {"path": str(source / "libpanic_unwind-hash.rlib")},
            ],
            "output": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
            "command": ["/pinned/ld.lld", str(self.archive)],
            "resolved_input_trace": str(self.archive),
            "qualified": False,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        receipt.write_text(json.dumps(record))
        selected = owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        self.assertEqual(selected["rust_library_origin"], "source-built")
        record["omitted_stock_rust_unwind"] = {"path": "/stock/libunwind-hash.rlib"}
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "stock Rust runtime"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")

    def host_build_fixture(self):
        """Make the Cargo hard-link and its wrapper receipt without Cargo."""

        rust_source = Path(self.temporary.name) / "rust-src/library"
        package_source = rust_source / "compiler-builtins/compiler-builtins"
        package_source.mkdir(parents=True)
        (rust_source / "Cargo.lock").write_text("source lock\n")
        manifest = package_source / "Cargo.toml"
        source = package_source / "build.rs"
        manifest.write_text("[package]\nname = \"compiler_builtins\"\n")
        source.write_text("fn main() {}\n")
        host_root = Path(self.temporary.name) / "cargo-target/release/build"
        package = host_root / "compiler_builtins-0123456789abcdef"
        package.mkdir(parents=True)
        linked = package / "build_script_build-0123456789abcdef"
        linked.write_bytes(b"host build script")
        linked.chmod(0o755)
        artifact = package / "build-script-build"
        os.link(linked, artifact)
        receipts = Path(self.temporary.name) / "host-build-receipts"
        receipts.mkdir()
        receipt_record = {
            "schema": 1,
            "kind": "cargo-host-build-script",
            "linker": owned_cleanup.record_file(
                owned_cleanup.HOST_BUILD_LINKER, "pinned Cargo host build-script linker",
            ),
            "command": [str(owned_cleanup.HOST_BUILD_LINKER), "-o", str(linked)],
            "output": owned_cleanup.record_file(linked, "Cargo host build-script linker output"),
        }
        receipt = receipts / (hashlib.sha256(str(linked).encode()).hexdigest() + ".json")
        receipt.write_text(json.dumps(receipt_record) + "\n")
        cargo_record = {
            "reason": "compiler-artifact",
            "package_id": f"path+file://{package_source}#compiler_builtins@0.1.0",
            "manifest_path": str(manifest),
            "target": {
                "kind": ["custom-build"],
                "crate_types": ["bin"],
                "name": "build-script-build",
                "src_path": str(source),
            },
            "filenames": [str(artifact)],
            "executable": None,
        }
        cargo_stdout = Path(self.temporary.name) / "cargo.stdout.jsonl"
        cargo_stdout.write_text(json.dumps(cargo_record) + "\n")
        return {
            "rust_source": rust_source,
            "host_root": host_root,
            "linked": linked,
            "artifact": artifact,
            "receipts": receipts,
            "receipt": receipt,
            "receipt_record": receipt_record,
            "cargo_record": cargo_record,
            "cargo_stdout": cargo_stdout,
        }

    def write_host_receipt(self, directory, output):
        record = {
            "schema": 1,
            "kind": "cargo-host-build-script",
            "linker": owned_cleanup.record_file(
                owned_cleanup.HOST_BUILD_LINKER, "pinned Cargo host build-script linker",
            ),
            "command": [str(owned_cleanup.HOST_BUILD_LINKER), "-o", str(output)],
            "output": owned_cleanup.record_file(output, "Cargo host build-script linker output"),
        }
        receipt = directory / (hashlib.sha256(str(output).encode()).hexdigest() + ".json")
        receipt.write_text(json.dumps(record) + "\n")
        return receipt

    def host_build_manifest(self, fixture, stream=None):
        manifest = Path(self.temporary.name) / "host-build-manifest.json"
        return owned_cleanup.host_build_script_manifest(
            cargo_stream=stream if stream is not None else fixture["cargo_stdout"].read_text(),
            cargo_stdout=fixture["cargo_stdout"],
            rust_source=fixture["rust_source"],
            rust_source_lock=fixture["rust_source"] / "Cargo.lock",
            host_build_root=fixture["host_root"],
            receipts_root=fixture["receipts"],
            output=manifest,
        )

    def test_host_build_manifest_closes_cargo_custom_build_artifact_to_one_receipt(self):
        fixture = self.host_build_fixture()
        manifest = self.host_build_manifest(fixture)
        self.assertEqual(manifest["format"], "crabc-owned-rust-host-build-manifest/v1")
        self.assertEqual(manifest["rust_source_lock"], owned_cleanup.record_file(
            fixture["rust_source"] / "Cargo.lock", "pinned rust-src lock",
        ))
        self.assertEqual(len(manifest["artifacts"]), 1)
        artifact = manifest["artifacts"][0]
        self.assertEqual(artifact["artifact_output"], owned_cleanup.record_file(
            fixture["artifact"], "Cargo custom-build artifact output",
        ))
        self.assertEqual(artifact["host_link_output"], owned_cleanup.record_file(
            fixture["linked"], "Cargo host build-script linker output",
        ))

    def test_host_build_manifest_rejects_target_lookalike(self):
        fixture = self.host_build_fixture()
        record = fixture["cargo_record"]
        record["target"]["kind"] = ["bin"]
        fixture["cargo_stdout"].write_text(json.dumps(record) + "\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "did not declare"):
            self.host_build_manifest(fixture)

    def test_host_build_manifest_rejects_an_unmatched_host_receipt(self):
        fixture = self.host_build_fixture()
        forged = fixture["host_root"] / "forged-0123456789abcdef"
        forged.mkdir()
        output = forged / "build_script_build-fedcba9876543210"
        output.write_bytes(b"forged host build script")
        output.chmod(0o755)
        self.write_host_receipt(fixture["receipts"], output)
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "closure differs"):
            self.host_build_manifest(fixture)

    def test_host_build_manifest_rejects_duplicate_cargo_artifact_records(self):
        fixture = self.host_build_fixture()
        stream = (json.dumps(fixture["cargo_record"]) + "\n") * 2
        fixture["cargo_stdout"].write_text(stream)
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "duplicate custom-build artifact"):
            self.host_build_manifest(fixture)

    def test_host_build_manifest_uses_the_retained_cargo_stream(self):
        fixture = self.host_build_fixture()
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "stream changed"):
            self.host_build_manifest(fixture, "{}\n")

    def test_host_build_manifest_rejects_a_forged_source_path(self):
        fixture = self.host_build_fixture()
        forged_source = Path(self.temporary.name) / "forged-build.rs"
        forged_source.write_text("fn main() {}\n")
        record = fixture["cargo_record"]
        record["target"]["src_path"] = str(forged_source)
        fixture["cargo_stdout"].write_text(json.dumps(record) + "\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "outside pinned rust-src"):
            self.host_build_manifest(fixture)

    def test_host_build_script_link_cannot_be_reclassified_as_a_final_target_link(self):
        fixture = self.host_build_fixture()
        final = Path(self.temporary.name) / "final-cleanup"
        final.write_bytes(b"not a host build script")
        final.chmod(0o755)
        fixture["receipt_record"]["output"] = owned_cleanup.record_file(
            final, "Cargo host build-script linker output",
        )
        fixture["receipt_record"]["command"][-1] = str(final)
        fixture["receipt"].write_text(json.dumps(fixture["receipt_record"]) + "\n")
        replacement = fixture["receipts"] / (hashlib.sha256(str(final).encode()).hexdigest() + ".json")
        fixture["receipt"].rename(replacement)
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "outside the declared host root"):
            self.host_build_manifest(fixture)

    def test_cargo_artifact_accepts_only_the_declared_fixture_target(self):
        package = Path(self.temporary.name) / "package"
        source = package / "src"
        target = Path(self.temporary.name) / "target"
        source.mkdir(parents=True)
        target.mkdir()
        (source / "main.rs").write_text("fn main() {}\n")
        binary = target / "cleanup"
        binary.write_bytes(b"cleanup")
        stream = json.dumps({
            "reason": "compiler-artifact",
            "target": {"name": "cleanup", "crate_types": ["bin"], "src_path": str(source / "main.rs")},
            "executable": str(binary),
        })
        self.assertEqual(
            owned_cleanup.cargo_artifact(stream, package=package, target=target, name="cleanup", crate_type="bin"),
            binary,
        )


if __name__ == "__main__":
    unittest.main()
