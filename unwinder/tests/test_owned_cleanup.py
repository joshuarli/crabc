"""Regression contracts for the supplied-product cleanup consumer receipt."""
from pathlib import Path
import hashlib
import json
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

    def test_host_build_script_link_cannot_be_reclassified_as_a_final_target_link(self):
        host_root = Path(self.temporary.name) / "cargo-target/release/build"
        package = host_root / "compiler_builtins-0123456789abcdef"
        package.mkdir(parents=True)
        build_script = package / "build_script_build-0123456789abcdef"
        build_script.write_bytes(b"host build script")
        build_script.chmod(0o755)
        log = Path(self.temporary.name) / "host-build-links.jsonl"
        record = {
            "schema": 1,
            "kind": "cargo-host-build-script",
            "linker": owned_cleanup.record_file(
                owned_cleanup.HOST_BUILD_LINKER, "pinned Cargo host build-script linker"
            ),
            "command": [str(owned_cleanup.HOST_BUILD_LINKER), "-o", str(build_script)],
            "output": owned_cleanup.record_file(build_script, "Cargo host build-script output"),
        }
        log.write_text(json.dumps(record) + "\n")
        self.assertEqual(
            owned_cleanup.host_build_script_links(log, host_root), [record]
        )

        final = Path(self.temporary.name) / "final-cleanup"
        final.write_bytes(b"not a host build script")
        final.chmod(0o755)
        record["output"] = owned_cleanup.record_file(final, "Cargo host build-script output")
        log.write_text(json.dumps(record) + "\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "outside the declared host root"):
            owned_cleanup.host_build_script_links(log, host_root)

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
