"""Regression contracts for the supplied-product cleanup consumer receipt."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import tempfile
import tomllib
import unittest
from unittest import mock


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

    def test_source_build_lto_is_owned_by_the_cargo_profile(self):
        self.assertEqual(owned_cleanup.SOURCE_BUILD_PROFILE, {
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
            "CARGO_PROFILE_RELEASE_LTO": "fat",
        })
        self.assertNotIn("lto=fat", owned_cleanup.SOURCE_BUILD_RUSTFLAGS)
        self.assertNotIn("codegen-units=1", owned_cleanup.SOURCE_BUILD_RUSTFLAGS)

    def test_source_build_log_accepts_cargo_linker_plugin_lto(self):
        source = Path(self.temporary.name) / "rust-src"
        source.mkdir()
        invocation = "\n".join(
            f"--crate-name {crate}" for crate in owned_cleanup.BUILD_STD_CRATES
        )
        owned_cleanup.source_build_log_contract(
            f"{invocation}\n{source}\n-C linker-plugin-lto -C codegen-units=1\n", source,
        )

    def test_source_graph_provider_inherits_unwind_profile_and_lto(self):
        log = "rustc --crate-name crabc_unwinder -C panic=unwind -C linker-plugin-lto -C codegen-units=1\n"
        owned_cleanup.source_graph_profile_contract(log)
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "unwind profile"):
            owned_cleanup.source_graph_profile_contract(log.replace("panic=unwind", "panic=abort"))

    def write_vendor_package(
        self, root, name, version, package_checksum, source="pub fn source() {}\n", directory_name=None,
    ):
        directory = root / (directory_name if directory_name is not None else f"{name}-{version}")
        source_path = directory / "src/lib.rs"
        source_path.parent.mkdir(parents=True)
        manifest = directory / "Cargo.toml"
        manifest.write_text(f'[package]\nname = "{name}"\nversion = "{version}"\n')
        source_path.write_text(source)
        files = {
            "Cargo.toml": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "src/lib.rs": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        }
        (directory / ".cargo-checksum.json").write_text(json.dumps({
            "$comment": "test Cargo vendor source",
            "package": package_checksum,
            "files": files,
        }))
        return directory

    def test_cargo_vendor_rehashes_the_locked_package_sources(self):
        vendor = Path(self.temporary.name) / "vendor"
        vendor.mkdir()
        package_checksum = "a" * 64
        directory = self.write_vendor_package(
            vendor, "fixture", "1.2.3", package_checksum, directory_name="fixture",
        )
        expected = {"fixture-1.2.3": ("fixture", "1.2.3", package_checksum)}
        record = owned_cleanup.cargo_vendor_tree(vendor, expected, "test Cargo vendor")
        self.assertEqual(record["packages"][0]["package_checksum"], package_checksum)
        self.assertEqual(len(record["packages"][0]["files"]), 2)
        (directory / "src/lib.rs").write_text("tampered\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "files differ"):
            owned_cleanup.cargo_vendor_tree(vendor, expected, "test Cargo vendor")

    def test_composite_vendor_keeps_the_full_rust_source_closure_and_provider_libc(self):
        rust_source = Path(self.temporary.name) / "rust-src/library"
        rust_source.mkdir(parents=True)
        (rust_source / ".cargo").mkdir()
        (rust_source / ".cargo/config.toml").write_text(
            '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
            '[source.vendored-sources]\ndirectory = "vendor"\n',
        )
        gimli_version, gimli_checksum = build.PINS["gimli"]
        unwinding_version, unwinding_checksum = build.PINS["unwinding"]
        rust_libc_checksum = "c" * 64
        (rust_source / "Cargo.lock").write_text(
            "version = 4\n\n[[package]]\nname = \"gimli\"\n"
            f"version = \"{gimli_version}\"\nsource = \"{build.CRATES_IO_REGISTRY}\"\nchecksum = \"{gimli_checksum}\"\n\n"
            "[[package]]\nname = \"unwinding\"\n"
            f"version = \"{unwinding_version}\"\nsource = \"{build.CRATES_IO_REGISTRY}\"\nchecksum = \"{unwinding_checksum}\"\n\n"
            "[[package]]\nname = \"libc\"\nversion = \"0.2.189\"\n"
            f"source = \"{build.CRATES_IO_REGISTRY}\"\nchecksum = \"{rust_libc_checksum}\"\n",
        )
        standard_vendor = rust_source / "vendor"
        standard_vendor.mkdir()
        self.write_vendor_package(standard_vendor, "gimli", gimli_version, gimli_checksum)
        self.write_vendor_package(standard_vendor, "unwinding", unwinding_version, unwinding_checksum)
        self.write_vendor_package(standard_vendor, "libc", "0.2.189", rust_libc_checksum)

        provider_vendor = WORK / f"provider-vendor-{Path(self.temporary.name).name}"
        provider_vendor.mkdir()
        for name, (version, checksum) in build.PINS.items():
            self.write_vendor_package(provider_vendor, name, version, checksum)
        application = Path(self.temporary.name) / "application"
        cargo_home = application / "cargo-home"
        application.mkdir()
        cargo_home.mkdir()
        try:
            sources = owned_cleanup.prepare_offline_cargo_sources(
                application, rust_source, provider_vendor, cargo_home,
            )
        finally:
            shutil.rmtree(provider_vendor)
        names = {package["name"] + "-" + package["version"]
                 for package in sources["composite_vendor"]["packages"]}
        self.assertEqual(names, {"gimli-0.34.0", "libc-0.2.189", "libc-0.2.186", "unwinding-0.2.10"})
        config = Path(sources["cargo_config"]["path"]).read_text()
        self.assertIn("crabc-owned-composite-vendor", config)
        self.assertIn("offline = true", config)

    def test_composite_vendor_binds_declared_custom_build_sources(self):
        vendor = Path(self.temporary.name) / "vendor"
        package = vendor / "fixture-1.2.3"
        package.mkdir(parents=True)
        manifest = package / "Cargo.toml"
        build_source = package / "build.rs"
        manifest.write_text('[package]\nname = "fixture"\nversion = "1.2.3"\nbuild = "build.rs"\n')
        build_source.write_text("fn main() {}\n")
        files = {
            "Cargo.toml": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "build.rs": hashlib.sha256(build_source.read_bytes()).hexdigest(),
        }
        checksum = "d" * 64
        (package / ".cargo-checksum.json").write_text(json.dumps({
            "$comment": "test Cargo vendor source", "package": checksum, "files": files,
        }))
        record = owned_cleanup.cargo_vendor_tree(
            vendor, {"fixture-1.2.3": ("fixture", "1.2.3", checksum)}, "test Cargo vendor",
        )
        self.assertEqual(owned_cleanup.cargo_vendor_custom_build_inputs(record), [{
            "manifest": owned_cleanup.record_file(manifest, "test vendor manifest"),
            "source": owned_cleanup.record_file(build_source, "test vendor build source"),
        }])

    def test_provider_vendor_reconstructs_the_pinned_registry_transport_shape(self):
        vendor = Path(self.temporary.name) / "provider-vendor"
        vendor.mkdir()
        version, checksum = build.PINS[build.PATCHED_UNWINDING]
        source = self.write_vendor_package(vendor, build.PATCHED_UNWINDING, version, checksum,
                                           directory_name=build.PATCHED_UNWINDING)
        expected = Path(self.temporary.name) / "registry-shape"
        shutil.copytree(source, expected)
        (expected / ".cargo-checksum.json").unlink()
        for relative, contents in owned_cleanup.CARGO_REGISTRY_UNWINDING_MARKERS.items():
            (expected / relative).write_bytes(contents)
        expected_tree = build.tree_digest(expected)
        application = Path(self.temporary.name) / "application"
        application.mkdir()
        offline_sources = {
            "provider_vendor": {
                "packages": [{
                    "name": build.PATCHED_UNWINDING,
                    "version": version,
                    "directory": str(source),
                    "checksum": owned_cleanup.record_file(source / ".cargo-checksum.json", "test vendor checksum"),
                }],
            },
        }
        with mock.patch.object(build, "PATCHED_UNWINDING_UPSTREAM_TREE_SHA256", expected_tree):
            record = owned_cleanup.provider_registry_unwinding_source(application, offline_sources)
        registry = Path(record["registry_source"])
        self.assertEqual(record["upstream_tree_sha256"], expected_tree)
        self.assertTrue((source / ".cargo-checksum.json").exists())
        self.assertFalse((registry / ".cargo-checksum.json").exists())
        self.assertEqual((registry / ".cargo-ok").read_bytes(), b'{"v":1}')

    def test_generated_source_graph_manifest_accepts_the_staged_unwinding_directory(self):
        application = Path(self.temporary.name) / "application"
        staged_root = Path(self.temporary.name) / "staged-root"
        staged_unwinding = Path(self.temporary.name) / "staged-unwinding"
        application.mkdir()
        staged_root.mkdir()
        staged_unwinding.mkdir()
        (staged_root / "Cargo.toml").write_text("[package]\nname = \"crabc-unwinder\"\nversion = \"0.1.0\"\n")
        (staged_unwinding / "Cargo.toml").write_text("[package]\nname = \"unwinding\"\nversion = \"0.2.10\"\n")
        prepared = owned_cleanup.prepare_source_graph_package(
            application, owned_cleanup.BUILD_STD_FIXTURE,
            {"manifest": str(staged_root / "Cargo.toml"), "staged": str(staged_unwinding)}, False,
        )
        manifest = tomllib.loads(Path(prepared["generated_manifest"]["path"]).read_text())
        self.assertEqual(manifest["dependencies"]["crabc-unwinder"]["path"], str(staged_root))
        self.assertEqual(manifest["patch"]["crates-io"]["unwinding"]["path"], str(staged_unwinding))

    def test_source_graph_preflight_uses_the_generated_static_workspace_without_a_sysroot_product(self):
        output = WORK / f"source-graph-preflight-{Path(self.temporary.name).name}"
        rust_sysroot = Path(self.temporary.name) / "rust-sysroot"
        rust_source = rust_sysroot / "lib/rustlib/src/rust/library"
        rust_source.mkdir(parents=True)
        (rust_source / "Cargo.lock").write_text("version = 4\n")

        def sysroot(command, _environment, log, _description):
            self.assertEqual(command[-2:], ["--print", "sysroot"])
            log.write_text(f"{rust_sysroot}\n")
            return f"{rust_sysroot}\n"

        offline_sources = {"composite_vendor": {"identity": "test-vendor"}}
        provider_graph = {"receipt": {"fixture": {"root": "generated-workspace"}}}
        with mock.patch.object(owned_cleanup, "run_logged", side_effect=sysroot), \
             mock.patch.object(owned_cleanup, "prepare_offline_cargo_sources", return_value=offline_sources), \
             mock.patch.object(owned_cleanup, "source_graph_provider", return_value=provider_graph) as graph:
            result = owned_cleanup.run_source_graph_preflight(Path(self.temporary.name) / "unused-vendor", output)
        self.assertEqual(result, output)
        arguments = graph.call_args.kwargs
        self.assertEqual(arguments["package"], owned_cleanup.BUILD_STD_FIXTURE)
        self.assertFalse(arguments["with_plugin"])
        self.assertEqual(arguments["offline_sources"], offline_sources)
        self.assertEqual(Path(arguments["environment"]["CARGO_HOME"]), output / "source-graph-preflight/cargo-home")
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertEqual(receipt["provider_graph"], provider_graph["receipt"])
        self.assertFalse(receipt["qualified"])

    def test_source_built_receipt_requires_the_compiler_builtins_omission_and_no_direct_libunwind(self):
        source = Path(self.temporary.name) / "source-built"
        source.mkdir()
        toolchain_search = Path(self.temporary.name) / "toolchain-target-lib"
        toolchain_search.mkdir()
        binary = Path(self.temporary.name) / "cleanup"
        binary.write_bytes(b"cleanup")
        receipt = Path(str(binary) + ".crabc-owned-rust-link.json")
        built_unwind = source / "libunwind-hash.rlib"
        built_unwind.write_bytes(b"source-built unwind")
        built_unwind_record = owned_cleanup.record_file(built_unwind, "test source-built unwind")
        record = {
            "schema": 2,
            "format": "crabc-owned-rust-source-build-link/v1",
            "rust_library_origin": "source-built",
            "source_built_target_library_root": str(source),
            "declared_toolchain_search_root": str(toolchain_search),
            "unused_search_paths": [str(toolchain_search)],
            "omitted_source_built_compiler_builtins": {"path": str(source / "libcompiler_builtins-hash.rlib")},
            "application_inputs": [
                {"path": str(source / "libstd-hash.rlib")},
                {"path": str(source / "libcore-hash.rlib")},
                {"path": str(source / "liballoc-hash.rlib")},
                {"path": str(source / "libpanic_unwind-hash.rlib")},
                {"path": str(source / "libcrabc_unwinder-hash.rlib")},
            ],
            "cargo_graph_provider": {"path": str(source / "libcrabc_unwinder-hash.rlib")},
            "output": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
            "command": ["/pinned/ld.lld", str(source / "libcrabc_unwinder-hash.rlib")],
            "resolved_input_trace": str(source / "libcrabc_unwinder-hash.rlib"),
            "qualified": False,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        receipt.write_text(json.dumps(record))
        selected = owned_cleanup.source_built_link_receipt(
            receipt, binary, source, "test source-built link", built_unwind=built_unwind_record,
        )
        self.assertEqual(selected["rust_library_origin"], "source-built")
        record["provider_archive"] = {"path": str(self.archive)}
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "standalone provider"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record.pop("provider_archive")
        record["omitted_stock_rust_unwind"] = {"path": "/stock/libunwind-hash.rlib"}
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "stock Rust runtime"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record.pop("omitted_stock_rust_unwind")
        record["omitted_source_built_rust_unwind"] = {"path": str(source / "libunwind-hash.rlib")}
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "direct source-built Rust libunwind"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record.pop("omitted_source_built_rust_unwind")
        record["unused_search_paths"].append("/unapproved/search")
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "search path"):
            owned_cleanup.source_built_link_receipt(
                receipt, binary, source, "test source-built link", toolchain_search_root=toolchain_search,
            )

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
        self.assertEqual(manifest["format"], "crabc-owned-rust-host-build-manifest/v3")
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
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "outside approved pinned source"):
            self.host_build_manifest(fixture)

    def test_host_build_manifest_admits_only_the_audited_provider_build_source(self):
        fixture = self.host_build_fixture()
        provider = Path(self.temporary.name) / "provider-libc"
        provider.mkdir()
        manifest = provider / "Cargo.toml"
        source = provider / "build.rs"
        manifest.write_text("[package]\nname = \"libc\"\n")
        source.write_text("fn main() {}\n")
        record = fixture["cargo_record"]
        record["manifest_path"] = str(manifest)
        record["target"]["src_path"] = str(source)
        fixture["cargo_stdout"].write_text(json.dumps(record) + "\n")
        output = Path(self.temporary.name) / "host-build-manifest.json"
        composite_inputs = [{
            "manifest": owned_cleanup.record_file(manifest, "vendor manifest"),
            "source": owned_cleanup.record_file(source, "vendor source"),
        }]
        result = owned_cleanup.host_build_script_manifest(
            cargo_stream=fixture["cargo_stdout"].read_text(), cargo_stdout=fixture["cargo_stdout"],
            rust_source=fixture["rust_source"], rust_source_lock=fixture["rust_source"] / "Cargo.lock",
            host_build_root=fixture["host_root"], receipts_root=fixture["receipts"], output=output,
            composite_vendor_custom_build_inputs=composite_inputs,
        )
        self.assertEqual(result["composite_vendor_custom_build_inputs"], composite_inputs)

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

    def test_cargo_build_std_unwind_artifact_is_fresh_and_source_identified(self):
        target = Path(self.temporary.name) / "target"
        target.mkdir()
        rust_source = Path(self.temporary.name) / "rust-src/library"
        unwind_source = rust_source / "unwind/src/lib.rs"
        unwind_source.parent.mkdir(parents=True)
        unwind_source.write_text("#![no_std]\n")
        archive = target / "libunwind-0123456789abcdef.rlib"
        archive.write_bytes(b"unwind")
        stream = json.dumps({
            "reason": "compiler-artifact",
            "target": {"name": "unwind", "kind": ["lib"], "crate_types": ["lib"], "src_path": str(unwind_source)},
            "filenames": [str(archive)],
            "executable": None,
        })
        self.assertEqual(owned_cleanup.cargo_build_std_unwind_artifact(stream, target, rust_source), archive)

    def test_cargo_json_records_ignore_build_script_text_but_reject_malformed_json(self):
        record = {"reason": "compiler-artifact", "target": {"name": "fixture"}}
        records = owned_cleanup.cargo_json_records(
            "[fixture 1.0.0] cargo:rerun-if-changed=build.rs\n" + json.dumps(record),
            "test Cargo stream",
        )
        self.assertEqual(records, [record])
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "malformed Cargo JSON"):
            owned_cleanup.cargo_json_records('{"reason":\n', "test Cargo stream")

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
