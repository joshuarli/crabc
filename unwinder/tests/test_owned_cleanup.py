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

    def test_source_provider_link_anchor_names_the_real_raise_exception_implementation(self):
        source = owned_cleanup.ROOT / "src/lib.rs"
        self.assertEqual(
            owned_cleanup.source_provider_link_anchor(source),
            owned_cleanup.record_file(source, "staged crabc-unwinder source link anchor"),
        )
        missing = Path(self.temporary.name) / "missing-anchor.rs"
        missing.write_text("#![no_std]\nextern crate unwinding;\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "real _Unwind_RaiseException link anchor"):
            owned_cleanup.source_provider_link_anchor(missing)

    def test_source_built_std_cleanup_unwinds_through_the_declared_application_crate(self):
        for package in (owned_cleanup.BUILD_STD_FIXTURE, owned_cleanup.BUILD_STD_DSO_FIXTURE):
            manifest = tomllib.loads((package / "Cargo.toml").read_text())
            self.assertEqual(
                manifest["dependencies"],
                {"crabc-cleanup-dependency": {"path": "../cleanup-dependency"}},
            )
            lock = tomllib.loads((package / "Cargo.lock").read_text())
            root = next(item for item in lock["package"] if item["name"] == manifest["package"]["name"])
            self.assertEqual(root["dependencies"], ["crabc-cleanup-dependency"])
        dependency = (owned_cleanup.DEPENDENCY_FIXTURE / "src/lib.rs").read_text()
        self.assertIn("#[inline(never)]", dependency)
        self.assertIn("std::panic::panic_any(73usize)", dependency)
        self.assertIn("std::panic::catch_unwind", dependency)
        self.assertIn("std::panic::resume_unwind", dependency)
        cleanup = dependency.index("let _cleanup = DependencyCleanup(count)")
        caught_panic = dependency.index("std::panic::catch_unwind")
        resumed_panic = dependency.index("std::panic::resume_unwind")
        self.assertLess(cleanup, caught_panic)
        self.assertLess(caught_panic, resumed_panic)
        for source in (
            owned_cleanup.BUILD_STD_FIXTURE / "src/main.rs",
            owned_cleanup.BUILD_STD_DSO_FIXTURE / "src/plugin.rs",
        ):
            self.assertIn("crabc_cleanup_dependency::panic_with_cleanup", source.read_text())

    def test_dso_thread_join_contract_matches_thread_completion_without_result_equality(self):
        host = owned_cleanup.BUILD_STD_DSO_FIXTURE / "src/main.rs"
        plugin = owned_cleanup.BUILD_STD_DSO_FIXTURE / "src/plugin.rs"
        self.assertEqual(
            owned_cleanup.dso_thread_join_contract(host, plugin),
            {
                "host_post_close": owned_cleanup.record_file(host, "cleanup DSO host post-close result contract"),
                "plugin_worker": owned_cleanup.record_file(plugin, "cleanup DSO plugin worker result contract"),
            },
        )
        invalid = Path(self.temporary.name) / "invalid-dso-host.rs"
        invalid.write_text("if release() != 0 || running.join() != Ok(0) || run() != 0 {\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "does not match its first post-close plugin result"):
            owned_cleanup.dso_thread_join_contract(invalid, plugin)
        invalid.write_text("if worker.join() != Ok(true) {\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "does not match its worker cleanup result"):
            owned_cleanup.dso_thread_join_contract(host, invalid)

    def test_mixed_source_generated_compile_diagnostics_compile_both_fixture_shapes_without_execution(self):
        output = WORK / f"mixed-source-diagnostics-{Path(self.temporary.name).name}"
        static = {"root": str(Path(self.temporary.name) / "static"), "manifest": {"path": "static"}, "files": {}}
        dynamic = {"root": str(Path(self.temporary.name) / "dynamic"), "manifest": {"path": "dynamic"}, "files": {}}
        consumers = [{"fixture": "static"}, {"fixture": "dynamic-dso"}]
        with mock.patch.object(owned_cleanup, "product_snapshot", side_effect=[static, dynamic]), \
             mock.patch.object(owned_cleanup, "compile_source_built_mode", side_effect=consumers) as compile_source, \
             mock.patch.object(owned_cleanup, "assert_same_product"):
            result = owned_cleanup.run_mixed_source_generated_compile_diagnostics(
                Path("unused-static"), Path("unused-dynamic"), Path("unused-vendor"), output,
            )
        self.assertEqual(result, output)
        self.assertEqual([call.kwargs["package"] for call in compile_source.call_args_list], [
            owned_cleanup.BUILD_STD_FIXTURE, owned_cleanup.BUILD_STD_DSO_FIXTURE,
        ])
        self.assertEqual([call.kwargs["with_plugin"] for call in compile_source.call_args_list], [False, True])
        receipt = json.loads((output / "generated-source-compile-diagnostics.json").read_text())
        self.assertEqual(receipt["source_product_relation"], "mixed-source development diagnostics only")
        self.assertEqual(receipt["source_built_generated_consumers"], {
            "static": consumers[0], "dynamic_dso": consumers[1],
        })
        self.assertFalse(receipt["qualified"])

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
        provider_unwinding = provider_vendor / f"unwinding-{unwinding_version}"
        provider_gitignore = provider_unwinding / ".gitignore"
        provider_gitignore.write_bytes(owned_cleanup.CARGO_REGISTRY_UNWINDING_MARKERS[".gitignore"])
        provider_checksum_path = provider_unwinding / ".cargo-checksum.json"
        provider_checksum = json.loads(provider_checksum_path.read_text())
        provider_checksum["files"][".gitignore"] = hashlib.sha256(provider_gitignore.read_bytes()).hexdigest()
        provider_checksum_path.write_text(json.dumps(provider_checksum))
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
        composite_unwinding = Path(sources["composite_vendor"]["root"]) / f"unwinding-{unwinding_version}"
        self.assertFalse((composite_unwinding / ".gitignore").exists())
        config = Path(sources["cargo_config"]["path"]).read_text()
        self.assertIn("crabc-owned-composite-vendor", config)
        self.assertIn("offline = true", config)

    def test_standalone_provider_cargo_home_uses_the_verified_read_only_vendor(self):
        vendor = WORK / f"standalone-provider-vendor-{Path(self.temporary.name).name}"
        vendor.mkdir()
        for name, (version, checksum) in build.PINS.items():
            self.write_vendor_package(vendor, name, version, checksum)
        files = tuple(path for path in vendor.rglob("*") if path.is_file())
        directories = tuple(path for path in vendor.rglob("*") if path.is_dir()) + (vendor,)
        input_bytes = {path: path.read_bytes() for path in files}
        original_modes = {path: path.stat().st_mode & 0o777 for path in (*files, *directories)}
        for path in files:
            path.chmod(0o444)
        for path in directories:
            path.chmod(0o555)
        output = Path(self.temporary.name) / "consumer-output"
        output.mkdir()
        try:
            prepared = owned_cleanup.prepare_standalone_provider_cargo_home(output, vendor)
            config = Path(prepared["cargo_config"]["path"])
            self.assertEqual(Path(prepared["cargo_home"]), output / "provider-cargo-home")
            self.assertEqual(prepared["provider_vendor"]["root"], str(vendor))
            self.assertIn("crabc-owned-provider-vendor", config.read_text())
            self.assertIn(f'directory = "{vendor}"', config.read_text())
            self.assertIn("offline = true", config.read_text())
            self.assertEqual({path: path.read_bytes() for path in files}, input_bytes)
            self.assertEqual({path: path.stat().st_mode & 0o777 for path in files},
                             {path: 0o444 for path in files})
            self.assertEqual({path: path.stat().st_mode & 0o777 for path in directories},
                             {path: 0o555 for path in directories})
        finally:
            for path, mode in original_modes.items():
                path.chmod(mode)
            shutil.rmtree(vendor)

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
        source_checksum = source / ".cargo-checksum.json"
        registry_gitignore = owned_cleanup.CARGO_REGISTRY_UNWINDING_MARKERS[".gitignore"]
        (source / ".gitignore").write_bytes(registry_gitignore)
        checksum_data = json.loads(source_checksum.read_text())
        checksum_data["files"][".gitignore"] = hashlib.sha256(registry_gitignore).hexdigest()
        source_checksum.write_text(json.dumps(checksum_data))
        expected = Path(self.temporary.name) / "registry-shape"
        shutil.copytree(source, expected)
        (expected / ".cargo-checksum.json").unlink()
        for relative, contents in owned_cleanup.CARGO_REGISTRY_UNWINDING_MARKERS.items():
            (expected / relative).write_bytes(contents)
        expected_tree = build.tree_digest(expected)
        source_bytes = {
            path.relative_to(source).as_posix(): path.read_bytes()
            for path in source.rglob("*") if path.is_file()
        }
        original_source_mode = source.stat().st_mode & 0o777
        original_checksum_mode = source_checksum.stat().st_mode & 0o777
        source.chmod(0o555)
        source_checksum.chmod(0o444)
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
        try:
            with mock.patch.object(build, "PATCHED_UNWINDING_UPSTREAM_TREE_SHA256", expected_tree):
                record = owned_cleanup.provider_registry_unwinding_source(application, offline_sources)
            registry = Path(record["registry_source"])
            self.assertEqual(record["upstream_tree_sha256"], expected_tree)
            self.assertEqual(source.stat().st_mode & 0o777, 0o555)
            self.assertEqual(source_checksum.stat().st_mode & 0o777, 0o444)
            self.assertEqual({
                path.relative_to(source).as_posix(): path.read_bytes()
                for path in source.rglob("*") if path.is_file()
            }, source_bytes)
            self.assertEqual(registry.stat().st_mode & 0o777, 0o555)
            self.assertTrue(source_checksum.exists())
            self.assertFalse((registry / ".cargo-checksum.json").exists())
            self.assertEqual((registry / ".cargo-ok").read_bytes(), b'{"v":1}')
            invalid_vendor = Path(self.temporary.name) / "invalid-provider-vendor"
            invalid_vendor.mkdir()
            invalid_source = self.write_vendor_package(
                invalid_vendor, build.PATCHED_UNWINDING, version, checksum,
                directory_name=build.PATCHED_UNWINDING,
            )
            invalid_gitignore = invalid_source / ".gitignore"
            invalid_gitignore.write_text("not the registry transport marker\n")
            invalid_checksum_path = invalid_source / ".cargo-checksum.json"
            invalid_checksum = json.loads(invalid_checksum_path.read_text())
            invalid_checksum["files"][".gitignore"] = hashlib.sha256(invalid_gitignore.read_bytes()).hexdigest()
            invalid_checksum_path.write_text(json.dumps(invalid_checksum))
            invalid_application = Path(self.temporary.name) / "invalid-application"
            invalid_application.mkdir()
            invalid_offline_sources = {
                "provider_vendor": {
                    "packages": [{
                        "name": build.PATCHED_UNWINDING,
                        "version": version,
                        "directory": str(invalid_source),
                        "checksum": owned_cleanup.record_file(
                            invalid_checksum_path, "invalid test vendor checksum",
                        ),
                    }],
                },
            }
            with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "differs from the pinned transport shape"):
                owned_cleanup.provider_registry_unwinding_source(invalid_application, invalid_offline_sources)
            failed_application = Path(self.temporary.name) / "failed-application"
            failed_application.mkdir()
            with mock.patch.object(build, "PATCHED_UNWINDING_UPSTREAM_TREE_SHA256", "0" * 64), \
                 self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "does not reconstruct"):
                owned_cleanup.provider_registry_unwinding_source(failed_application, offline_sources)
            failed_registry = failed_application / "provider-registry-source" / f"{source.name}-{version}"
            self.assertEqual(failed_registry.stat().st_mode & 0o777, 0o555)
        finally:
            source.chmod(original_source_mode)
            source_checksum.chmod(original_checksum_mode)

    def test_source_graph_stages_the_overlay_below_its_writable_application(self):
        """A read-only checkout cannot redirect private provider preparation."""

        checkout = Path(self.temporary.name) / "checkout"
        provider_root = checkout / "unwinder"
        provider_source = provider_root / "src/lib.rs"
        provider_source.parent.mkdir(parents=True)
        (provider_root / "Cargo.toml").write_text('[package]\nname = "crabc-unwinder"\nversion = "0.1.0"\n')
        (provider_root / "Cargo.lock").write_text("version = 4\n")
        provider_source.write_text("#![no_std]\n")
        patches_root = provider_root / "patches"
        patches_root.mkdir()
        overlay = patches_root / "phdr.rs"
        overlay.write_text("patched\n")

        work = checkout / ".work/x86_64"
        application = work / "owned-rust-std-cleanup/run/source-built-static"
        application.mkdir(parents=True)
        source = work / "inputs/provider-vendor/unwinding-0.2.10"
        target = source / "src/unwinder/find_fde/phdr.rs"
        target.parent.mkdir(parents=True)
        target.write_text("upstream\n")
        (source / "Cargo.toml").write_text('[package]\nname = "unwinding"\nversion = "0.2.10"\n')
        source_checksum = source / ".cargo-checksum.json"
        source_checksum.write_text("directory-source checksum\n")

        registry = Path(self.temporary.name) / "registry-tree"
        shutil.copytree(source, registry)
        (registry / ".cargo-checksum.json").unlink()
        for relative, contents in owned_cleanup.CARGO_REGISTRY_UNWINDING_MARKERS.items():
            (registry / relative).write_bytes(contents)
        expected_tree = build.tree_digest(registry)
        shutil.rmtree(registry)
        patches = {
            "src/unwinder/find_fde/phdr.rs": {
                "overlay": overlay,
                "upstream_sha256": build.digest(target),
            },
        }
        source_files = tuple(path for path in source.rglob("*") if path.is_file())
        source_bytes = {path: path.read_bytes() for path in source_files}
        source_modes = {path: path.stat().st_mode & 0o777 for path in source_files}
        directories = (checkout / ".work", work, source, source / "src", source / "src/unwinder",
                       source / "src/unwinder/find_fde")
        directory_modes = {path: path.stat().st_mode & 0o777 for path in directories}
        for path in source_files:
            path.chmod(0o444)
        for path in directories:
            path.chmod(0o555)

        offline_sources = {
            "provider_vendor": {
                "packages": [{
                    "name": build.PATCHED_UNWINDING,
                    "version": build.PINS[build.PATCHED_UNWINDING][0],
                    "directory": str(source),
                    "checksum": owned_cleanup.record_file(source_checksum, "test provider vendor checksum"),
                }],
            },
        }

        def streams(_command, _environment, stdout, stderr, _description):
            stdout.write_text("{}\n")
            stderr.write_text("")
            return "{}\n", ""

        def command(_command, _environment, log, _description):
            log.write_text("")
            return ""

        observed = {}

        def prepare(application_root, _package, staged, _with_plugin):
            root = application_root / "cargo-package"
            root.mkdir()
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n')
            lock.write_text("version = 4\n")
            self.assertTrue(Path(staged["source_input"]).is_relative_to(application_root / "unwinder-source-inputs"))
            observed["staged"] = staged
            return {
                "root": root,
                "fixture_manifest": owned_cleanup.record_file(provider_root / "Cargo.toml", "test fixture manifest"),
                "fixture_lock": owned_cleanup.record_file(provider_root / "Cargo.lock", "test fixture lock"),
                "generated_manifest": owned_cleanup.record_file(manifest, "test generated manifest"),
                "sources": [],
            }

        packages = {
            build.PATCHED_UNWINDING: {
                "source": build.CRATES_IO_REGISTRY,
                "manifest_path": str(source / "Cargo.toml"),
            },
        }
        try:
            with mock.patch.object(owned_cleanup, "ROOT", provider_root), \
                 mock.patch.object(owned_cleanup, "CHECKOUT", checkout), \
                 mock.patch.object(build, "ROOT", provider_root), \
                 mock.patch.object(build, "PATCHES", patches), \
                 mock.patch.object(build, "PATCHED_UNWINDING_UPSTREAM_TREE_SHA256", expected_tree), \
                 mock.patch.object(build, "audit_graph", return_value=packages), \
                 mock.patch.object(owned_cleanup, "run_logged_streams", side_effect=streams), \
                 mock.patch.object(owned_cleanup, "run_logged", side_effect=command), \
                 mock.patch.object(owned_cleanup, "prepare_source_graph_package", side_effect=prepare), \
                 mock.patch.object(
                     owned_cleanup, "audit_source_graph",
                     return_value={"provider_custom_builds": [], "provider_package_id": "test-provider"},
                 ):
                result = owned_cleanup.source_graph_provider(
                    application=application, package=provider_root, channel="test", environment={}, with_plugin=False,
                    offline_sources=offline_sources,
                )
            stage_root = application / "unwinder-source-inputs"
            staged_unwinding = Path(observed["staged"]["staged"])
            self.assertTrue(staged_unwinding.is_relative_to(stage_root))
            self.assertEqual((staged_unwinding / "src/unwinder/find_fde/phdr.rs").read_bytes(), overlay.read_bytes())
            self.assertFalse((work / "unwinder-source-inputs").exists())
            self.assertEqual({path: path.read_bytes() for path in source_files}, source_bytes)
            self.assertEqual({path: path.stat().st_mode & 0o777 for path in source_files},
                             {path: 0o444 for path in source_files})
        finally:
            for path, mode in directory_modes.items():
                path.chmod(mode)
            for path, mode in source_modes.items():
                path.chmod(mode)

    def test_generated_source_graph_manifest_accepts_the_staged_unwinding_directory(self):
        staged_root = Path(self.temporary.name) / "staged-root"
        staged_unwinding = Path(self.temporary.name) / "staged-unwinding"
        staged_root.mkdir(parents=True)
        staged_unwinding.mkdir()
        (staged_root / "Cargo.toml").write_text("[package]\nname = \"crabc-unwinder\"\nversion = \"0.1.0\"\n")
        (staged_unwinding / "Cargo.toml").write_text("[package]\nname = \"unwinding\"\nversion = \"0.2.10\"\n")
        staged = {"manifest": str(staged_root / "Cargo.toml"), "staged": str(staged_unwinding)}
        for index, package in enumerate((owned_cleanup.BUILD_STD_FIXTURE, owned_cleanup.BUILD_STD_DSO_FIXTURE)):
            application = Path(self.temporary.name) / f"application-{index}"
            application.mkdir()
            prepared = owned_cleanup.prepare_source_graph_package(application, package, staged, index == 1)
            manifest = tomllib.loads(Path(prepared["generated_manifest"]["path"]).read_text())
            self.assertEqual(manifest["dependencies"]["crabc-unwinder"]["path"], str(staged_root))
            self.assertEqual(
                manifest["dependencies"]["crabc-cleanup-dependency"]["path"], "../cleanup-dependency",
            )
            self.assertEqual(manifest["patch"]["crates-io"]["unwinding"]["path"], str(staged_unwinding))
            self.assertTrue((application / "cleanup-dependency/src/lib.rs").is_file())
            self.assertEqual(len(prepared["sources"]), 4 if index == 1 else 3)

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

    def test_source_built_receipt_retains_fused_lto_abi_after_cargo_removes_the_object(self):
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
        fused = Path(self.temporary.name) / "cleanup.cgu.0.rcgu.o"
        fused_bytes = b"fused Cargo LTO object"
        fused.write_bytes(fused_bytes)
        fused_record = owned_cleanup.record_file(fused, "test fused Cargo LTO object")
        retained = Path(str(binary) + ".crabc-owned-source-lto.o")
        shutil.copyfile(fused, retained)
        retained_record = owned_cleanup.record_file(retained, "test retained fused Cargo LTO object")
        record = {
            "schema": 6,
            "format": "crabc-owned-rust-source-build-link/v5",
            "rust_library_origin": "source-built",
            "source_built_target_library_root": str(source),
            "declared_toolchain_search_root": str(toolchain_search),
            "unused_search_paths": [str(toolchain_search)],
            "omitted_source_built_compiler_builtins": {"path": str(source / "libcompiler_builtins-hash.rlib")},
            "application_inputs": [retained_record],
            "source_lto_object": {
                "cargo_object": fused_record,
                "retained_object": retained_record,
                "defined_unwind_abi": sorted(build.UNWIND_ABI),
                "rust_eh_personality": True,
            },
            "output": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
            "command": ["/pinned/ld.lld", str(retained)],
            "resolved_input_trace": str(retained),
            "qualified": False,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        receipt.write_text(json.dumps(record))
        # Cargo removes its intermediate after the wrapper retained and linked
        # the confined evidence copy.
        fused.unlink()
        selected = owned_cleanup.source_built_link_receipt(
            receipt, binary, source, "test source-built link", built_unwind=built_unwind_record,
        )
        self.assertEqual(selected["rust_library_origin"], "source-built")
        record["rust_requested_mode"] = "shared"
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "cdylib version-script safety flag"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record["command"].append("--no-undefined-version")
        cargo_script = Path(self.temporary.name) / "cargo-rust-list"
        expected_dynamic_exports = sorted({*owned_cleanup.owned_rust_link.RUST_CDYLIB_EXPORTS, *build.UNWIND_ABI})
        cargo_script_contents = (
            "{\n  global:\n"
            + "".join(f"    {symbol};\n" for symbol in owned_cleanup.owned_rust_link.RUST_CDYLIB_EXPORTS)
            + "".join(f"    {symbol};\n" for symbol in sorted(build.UNWIND_ABI))
            + "\n  local:\n    *;\n};\n"
        )
        cargo_script.write_text(cargo_script_contents)
        retained_script = binary.with_name(binary.name + ".crabc-owned-rust-export-script.map")
        shutil.copyfile(cargo_script, retained_script)
        record["rust_cdylib_export_script"] = {
            "cargo_script": owned_cleanup.record_file(cargo_script, "test Cargo cdylib export script"),
            "retained_script": owned_cleanup.record_file(retained_script, "test retained cdylib export script"),
            "dynamic_exports": expected_dynamic_exports,
        }
        record["command"].extend(("--version-script", str(retained_script)))
        receipt.write_text(json.dumps(record))
        # Cargo may delete its generated list as it tears down the target
        # directory. The receipt keeps that original as a source fact while
        # independently rehashing the confined copy LLD received.
        cargo_script.unlink()
        owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record["rust_cdylib_export_script"]["dynamic_exports"] = expected_dynamic_exports[:-1]
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "retained cdylib export script"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record["rust_cdylib_export_script"]["dynamic_exports"] = expected_dynamic_exports
        receipt.write_text(json.dumps(record))
        retained_script.write_text("tampered cdylib export script\n")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "retained cdylib export script"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        retained_script.write_text(cargo_script_contents)
        record.pop("rust_requested_mode")
        record["command"].pop()
        record["command"].pop()
        record.pop("rust_cdylib_export_script")
        retained.write_bytes(b"tampered retained Cargo LTO object")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "fused Cargo LTO unwind ABI"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        retained.write_bytes(fused_bytes)
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
        record["source_lto_object"]["defined_unwind_abi"] = []
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "fused Cargo LTO unwind ABI"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record["source_lto_object"]["defined_unwind_abi"] = sorted(build.UNWIND_ABI)
        record["source_lto_object"]["cargo_object"] = {**fused_record, "sha256": "0" * 64}
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "fused Cargo LTO unwind ABI"):
            owned_cleanup.source_built_link_receipt(receipt, binary, source, "test source-built link")
        record["source_lto_object"]["cargo_object"] = fused_record
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

    def test_cargo_primary_rustc_binds_source_runtime_and_provider_externs_to_fused_output(self):
        target = Path(self.temporary.name) / "target"
        target.mkdir()
        rust_source = Path(self.temporary.name) / "rust-src/library"
        artifacts = {}
        records = []
        for name, (relative, kinds, crate_types) in owned_cleanup.SOURCE_LTO_RUNTIME_TARGETS.items():
            source = rust_source / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("#![no_std]\n")
            artifact = target / f"lib{name}-0123456789abcdef.rlib"
            artifact.write_bytes(name.encode())
            artifacts[name] = artifact
            records.append({
                "reason": "compiler-artifact",
                "target": {"name": name, "kind": kinds, "crate_types": crate_types, "src_path": str(source)},
                "filenames": [str(artifact)],
                "executable": None,
            })
        runtime = owned_cleanup.cargo_build_std_runtime_artifacts(
            "\n".join(json.dumps(record) for record in records), target, rust_source,
        )
        runtime_records = {
            name: owned_cleanup.record_file(path, f"test source-built {name} archive")
            for name, path in runtime.items()
        }
        provider = target / "libcrabc_unwinder-fedcba9876543210.rlib"
        provider.write_bytes(b"provider")
        provider_record = owned_cleanup.record_file(provider, "test Cargo provider archive")
        dependency = target / "libcrabc_cleanup_dependency-0123456789abcdef.rlib"
        dependency.write_bytes(b"application dependency")
        dependency_record = owned_cleanup.record_file(dependency, "test Cargo cleanup dependency archive")
        built_unwind = target / "libunwind-0011223344556677.rlib"
        built_unwind.write_bytes(b"unselected unwind")
        built_unwind_record = owned_cleanup.record_file(built_unwind, "test source-built unwind archive")
        output = target / "crabc_owned_cleanup_build_std-deadbeef"
        output.write_bytes(b"fused output")
        externs = [
            f"--extern {name}={path}"
            for name, path in {
                **runtime, "crabc_unwinder": provider, "crabc_cleanup_dependency": dependency,
            }.items()
        ]
        log = (
            "     Running `CARGO_PRIMARY_PACKAGE=1 CARGO_BIN_NAME=crabc-owned-cleanup-build-std "
            "CARGO_CRATE_NAME=crabc_owned_cleanup_build_std "
            "rustc --crate-name crabc_owned_cleanup_build_std --out-dir "
            f"{target} -C extra-filename=-deadbeef {' '.join(externs)}`\n"
        )
        closure = owned_cleanup.cargo_source_lto_extern_closure(
            log, target_name="crabc-owned-cleanup-build-std", binary_name="crabc-owned-cleanup-build-std",
            link_output=output,
            source_library_root=target, runtime_artifacts=runtime_records, cargo_provider=provider_record,
            application_dependency=dependency_record, built_unwind=built_unwind_record,
        )
        self.assertEqual(closure["linker_output"], owned_cleanup.record_file(output, "test fused output"))
        self.assertEqual(closure["externs"], {
            **runtime_records, "crabc_unwinder": provider_record,
            "crabc_cleanup_dependency": dependency_record,
        })
        plugin_output = target / "libcrabc_owned_cleanup_plugin.so"
        plugin_output.write_bytes(b"fused plugin output")
        plugin_log = (
            "     Running `CARGO_PRIMARY_PACKAGE=1 CARGO_CRATE_NAME=crabc_owned_cleanup_plugin "
            "rustc --crate-name crabc_owned_cleanup_plugin --out-dir "
            f"{target} {' '.join(externs)}`\n"
        )
        plugin_closure = owned_cleanup.cargo_source_lto_extern_closure(
            plugin_log, target_name="crabc_owned_cleanup_plugin", binary_name=None,
            link_output=plugin_output, source_library_root=target, runtime_artifacts=runtime_records,
            cargo_provider=provider_record, application_dependency=dependency_record,
            built_unwind=built_unwind_record,
        )
        self.assertEqual(plugin_closure["linker_output"], owned_cleanup.record_file(plugin_output, "test fused plugin output"))
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "cdylib rustc has an unapproved extra filename"):
            owned_cleanup.cargo_source_lto_extern_closure(
                plugin_log.replace(f"--out-dir {target}", f"--out-dir {target} -C extra-filename=-deadbeef"),
                target_name="crabc_owned_cleanup_plugin", binary_name=None,
                link_output=plugin_output, source_library_root=target, runtime_artifacts=runtime_records,
                cargo_provider=provider_record, application_dependency=dependency_record,
                built_unwind=built_unwind_record,
            )
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "unselected source-built libunwind"):
            owned_cleanup.cargo_source_lto_extern_closure(
                log.replace(f"--extern crabc_unwinder={provider}",
                            f"--extern crabc_unwinder={provider} --extern unwind={built_unwind}"),
                target_name="crabc-owned-cleanup-build-std", binary_name="crabc-owned-cleanup-build-std",
                link_output=output,
                source_library_root=target, runtime_artifacts=runtime_records, cargo_provider=provider_record,
                application_dependency=dependency_record, built_unwind=built_unwind_record,
            )
        extra = target / "libextra-0011223344556677.rlib"
        extra.write_bytes(b"unapproved source target input")
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "extern closure differs"):
            owned_cleanup.cargo_source_lto_extern_closure(
                log.replace(f"--extern crabc_unwinder={provider}",
                            f"--extern crabc_unwinder={provider} --extern extra={extra}"),
                target_name="crabc-owned-cleanup-build-std", binary_name="crabc-owned-cleanup-build-std",
                link_output=output,
                source_library_root=target, runtime_artifacts=runtime_records, cargo_provider=provider_record,
                application_dependency=dependency_record, built_unwind=built_unwind_record,
            )

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

    def test_cargo_application_dependency_artifact_is_source_and_target_bound(self):
        application = Path(self.temporary.name) / "application"
        package = application / "cargo-package"
        dependency_source = application / "cleanup-dependency/src/lib.rs"
        dependency_source.parent.mkdir(parents=True)
        dependency_source.write_text("pub fn source() {}\n")
        target = Path(self.temporary.name) / "target"
        deps = target / "release/deps"
        deps.mkdir(parents=True)
        archive = deps / "libcrabc_cleanup_dependency-0123456789abcdef.rlib"
        archive.write_bytes(b"local cleanup dependency")
        record = {
            "reason": "compiler-artifact",
            "target": {
                "name": "crabc_cleanup_dependency", "kind": ["lib"], "crate_types": ["lib"],
                "src_path": str(dependency_source),
            },
            "filenames": [str(archive)],
            "executable": None,
        }
        self.assertEqual(
            owned_cleanup.cargo_application_dependency_artifact(
                json.dumps(record), package_root=package, target=target,
            ),
            archive,
        )
        changed = dict(record)
        changed["target"] = {**record["target"], "src_path": str(Path(self.temporary.name) / "other.rs")}
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "expected one local cleanup dependency archive"):
            owned_cleanup.cargo_application_dependency_artifact(
                json.dumps(changed), package_root=package, target=target,
            )

    def test_cargo_graph_provider_uses_the_declared_rlib_target_kind(self):
        target = Path(self.temporary.name) / "target"
        target.mkdir()
        provider = Path(self.temporary.name) / "provider"
        source = provider / "src/lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("#![no_std]\n")
        archive = target / "libcrabc_unwinder-0123456789abcdef.rlib"
        archive.write_bytes(b"provider")
        record = {
            "reason": "compiler-artifact",
            "package_id": "path+file:///provider#0.1.0",
            "target": {
                "name": "crabc_unwinder", "kind": ["rlib"], "crate_types": ["rlib"],
                "src_path": str(source),
            },
            "filenames": [str(archive)],
            "executable": None,
        }
        self.assertEqual(
            owned_cleanup.cargo_graph_provider_artifact(
                json.dumps(record), target=target, provider_package_id=record["package_id"], provider_source=source,
            ), archive,
        )
        record["target"]["kind"] = ["lib"]
        with self.assertRaisesRegex(owned_cleanup.OwnedCleanupError, "provider artifact identity drifted"):
            owned_cleanup.cargo_graph_provider_artifact(
                json.dumps(record), target=target, provider_package_id=record["package_id"], provider_source=source,
            )


if __name__ == "__main__":
    unittest.main()
