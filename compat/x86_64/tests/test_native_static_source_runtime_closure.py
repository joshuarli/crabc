#!/usr/bin/env python3
"""Focused contracts for the native source-runtime Cargo evidence parser."""

from __future__ import annotations

import importlib.util
import argparse
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_static_source_runtime_closure.py"
SPEC = importlib.util.spec_from_file_location("native_static_source_runtime_closure", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load native static source-runtime closure helper")
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)


class NativeStaticSourceRuntimeClosureTests(unittest.TestCase):
    def test_wrapped_compiler_commands_bind_exact_tools_and_fixed_environment(self):
        scratch = Path(__file__).resolve().parents[3] / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            wrapper, compiler = root / "kache", root / "rustc"
            wrapper.write_bytes(b"pinned wrapper")
            compiler.write_bytes(b"pinned compiler")
            with patch.object(CLOSURE.native_build_tools, "KACHE", wrapper):
                command = ["CARGO_PKG_NAME=probe", str(wrapper), str(compiler), "--crate-name", "probe"]
                CLOSURE.validate_wrapped_commands([command], compiler)
                CLOSURE.validate_wrapped_commands([["CARGO_PKG_DESCRIPTION=first line\nsecond line", *command]], compiler)
                fixed = CLOSURE.native_build_tools.environment()
                CLOSURE.validate_wrapped_commands([[f"{key}={value}" for key, value in fixed.items()] + command], compiler)
                for changed in (
                    [str(root / "other-wrapper"), *command[2:]],
                    [str(wrapper), str(root / "other-rustc"), *command[3:]],
                    [str(compiler), *command[3:]],
                    ["KACHE_LOCAL_ONLY=0", *command],
                    ["KACHE_CONFIG=/ambient/config", *command],
                    ["KACHE_CACHE_DIR=/ambient/cache", *command],
                    ["KACHE_AUTO_CLEAN_UNUSED_UNITS_DAYS=1", *command],
                    ["KACHE_AUTO_SHARE_TARGET_FILES=1", *command],
                    ["KACHE_REMOTE_URL=https://example.invalid", *command],
                    ["RUSTC_WORKSPACE_WRAPPER=/ambient/wrapper", *command],
                    [str(wrapper), str(wrapper), str(compiler), *command[3:]],
                ):
                    with self.subTest(command=changed), self.assertRaises(CLOSURE.ClosureError):
                        CLOSURE.validate_wrapped_commands([changed], compiler)

    def test_cargo_parser_retains_wrapped_commands_before_uncached_diagnostics(self):
        scratch = Path(__file__).resolve().parents[3] / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            log = Path(temporary) / "cargo.stderr.log"
            raw = ("     Running `/usr/local/bin/kache /opt/rustup/pinned/bin/rustc --crate-name c`\n"
                   "[kache] Caching is disabled for this build — compilation still succeeds,\n"
                   "[kache] just without cache hits or stores (everything builds uncached).\n"
                   "    Finished `dev` profile target(s) in 1s\n")
            log.write_text(raw, encoding="utf-8")
            self.assertEqual(CLOSURE.cargo_commands(log), [["/usr/local/bin/kache", "/opt/rustup/pinned/bin/rustc", "--crate-name", "c"]])
            self.assertEqual(log.read_text(encoding="utf-8"), raw)

    def test_pinned_environment_ignores_ambient_wrapper_cache_and_target_controls(self):
        injected = {name: "/ambient/control" for name in CLOSURE.native_build_tools.environment()}
        injected["RUSTC_WORKSPACE_WRAPPER"] = "/ambient/workspace-wrapper"
        with patch.dict(CLOSURE.os.environ, injected), \
                patch.object(CLOSURE, "pinned_rustup_frontend", return_value={"argv0": "/opt/cargo/bin/rustup"}), \
                patch.object(CLOSURE, "physical", side_effect=lambda path, _description, **_kwargs: path):
            _, environment = CLOSURE.pinned_environment()
        for name, value in CLOSURE.native_build_tools.environment().items():
            self.assertEqual(environment[name], value)
        self.assertNotIn("RUSTC_WORKSPACE_WRAPPER", environment)
        self.assertEqual(environment["CARGO_HOME"], "/opt/cargo")
        self.assertEqual(environment["RUSTUP_HOME"], "/opt/rustup")

    def _private_vendor_fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        repository = root / "repository"
        rust_source = root / "toolchain" / "library"
        project_vendor = repository / ".work" / "x86_64" / "cargo" / "native-static-source-runtime-vendor"
        work = root / "graph"
        repository.mkdir()
        (rust_source / ".cargo").mkdir(parents=True)
        source_vendor = rust_source / "vendor" / "cache-probe-1.0.0"
        (source_vendor / "src").mkdir(parents=True)
        project_vendor.mkdir(parents=True)
        work.mkdir()

        crate_source = b"pub fn cache_probe() {}\n"
        crate_file = source_vendor / "src" / "lib.rs"
        crate_file.write_bytes(crate_source)
        package_checksum = "0" * 64
        (source_vendor / ".cargo-checksum.json").write_text(
            json.dumps({
                "package": package_checksum,
                "files": {"src/lib.rs": hashlib.sha256(crate_source).hexdigest()},
            }),
            encoding="utf-8",
        )
        for lock in (repository / "Cargo.lock", rust_source / "Cargo.lock"):
            lock.write_text(
                "version = 4\n\n[[package]]\n"
                'name = "cache-probe"\nversion = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{package_checksum}"\n',
                encoding="utf-8",
            )
        (rust_source / ".cargo" / "config.toml").write_text(
            '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
            '[source.vendored-sources]\ndirectory = "vendor"\n',
            encoding="utf-8",
        )
        return repository, work, rust_source, project_vendor

    def _populate_post_cargo_cache(self, cargo_home: Path) -> None:
        with sqlite3.connect(cargo_home / ".global-cache") as database:
            database.execute("CREATE TABLE global_data (last_auto_gc INTEGER NOT NULL)")
            database.execute("INSERT INTO global_data VALUES (0)")
        (cargo_home / ".package-cache").touch()
        (cargo_home / ".package-cache-mutate").touch()
        registry = cargo_home / "registry"
        registry.mkdir()
        (registry / "CACHEDIR.TAG").write_bytes(
            b"Signature: 8a477f597d28d172789f06886806bc55\n"
            b"# This file is a cache directory tag created by cargo.\n"
            b"# For information about cache directory tags see https://bford.info/cachedir/\n"
        )

    def test_private_vendor_replay_accepts_pinned_cargo_cache_metadata(self) -> None:
        work_root = ROOT / ".work" / "tmp"
        work_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="source-runtime-cache-replay.", dir=work_root) as temporary:
            repository, work, rust_source, project_vendor = self._private_vendor_fixture(Path(temporary))
            with patch.object(CLOSURE, "ROOT", repository):
                produced = CLOSURE.private_vendor(work, rust_source, project_vendor)
                self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)

                self._populate_post_cargo_cache(work / "cargo-home")
                self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)

                cargo_home = work / "cargo-home"
                (cargo_home / ".package-cache-mutate").unlink()
                self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)
                (cargo_home / ".package-cache").unlink()
                self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)
                (cargo_home / ".global-cache").unlink()
                self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)
                cache_tag = cargo_home / "registry" / "CACHEDIR.TAG"
                cache_tag.unlink()
                cache_tag.parent.rmdir()
                self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)

    def test_private_vendor_replay_rejects_cargo_home_inputs_and_substitutions(self) -> None:
        work_root = ROOT / ".work" / "tmp"
        work_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="source-runtime-cache-controls.", dir=work_root) as temporary:
            repository, work, rust_source, project_vendor = self._private_vendor_fixture(Path(temporary))
            with patch.object(CLOSURE, "ROOT", repository):
                CLOSURE.private_vendor(work, rust_source, project_vendor)
                cargo_home = work / "cargo-home"
                self._populate_post_cargo_cache(cargo_home)
                config_path = cargo_home / "config.toml"
                original_config = config_path.read_bytes()

                unknown_input = cargo_home / "credentials.toml"
                unknown_input.write_text("[registry]\ntoken = 'injected'\n", encoding="utf-8")
                with self.assertRaisesRegex(CLOSURE.ClosureError, "unrecorded input"):
                    CLOSURE.replay_private_vendor(work, rust_source)
                unknown_input.unlink()

                config_path.write_bytes(original_config + b"\n[build]\nrustc-wrapper = 'injected'\n")
                with self.assertRaisesRegex(CLOSURE.ClosureError, "config differs"):
                    CLOSURE.replay_private_vendor(work, rust_source)
                config_path.write_bytes(original_config)

                global_cache = cargo_home / ".global-cache"
                original_cache = global_cache.read_bytes()
                global_cache.write_bytes(b"not a SQLite database")
                with self.assertRaisesRegex(CLOSURE.ClosureError, "not a SQLite database"):
                    CLOSURE.replay_private_vendor(work, rust_source)
                global_cache.write_bytes(original_cache)

                lock = cargo_home / ".package-cache-mutate"
                lock.write_bytes(b"not empty")
                with self.assertRaisesRegex(CLOSURE.ClosureError, "lock is not empty"):
                    CLOSURE.replay_private_vendor(work, rust_source)
                lock.write_bytes(b"")

                registry_input = cargo_home / "registry" / "index"
                registry_input.mkdir()
                with self.assertRaisesRegex(CLOSURE.ClosureError, "registry cache contains an unrecorded input"):
                    CLOSURE.replay_private_vendor(work, rust_source)
                registry_input.rmdir()

                cache_tag = cargo_home / "registry" / "CACHEDIR.TAG"
                original_tag = cache_tag.read_bytes()
                cache_tag.write_bytes(original_tag + b"substitution")
                with self.assertRaisesRegex(CLOSURE.ClosureError, "cache tag differs"):
                    CLOSURE.replay_private_vendor(work, rust_source)
                cache_tag.write_bytes(original_tag)

                global_cache.unlink()
                global_cache.symlink_to(config_path)
                with self.assertRaisesRegex(CLOSURE.ClosureError, "not a physical child"):
                    CLOSURE.replay_private_vendor(work, rust_source)

    def test_target_c_environment_rejects_unapproved_overrides_before_building(self) -> None:
        approved = {
            "CC_x86_64_unknown_linux_musl": "/usr/bin/gcc",
            "CFLAGS_x86_64_unknown_linux_musl": "-nostdinc",
            "CC_SHELL_ESCAPED_FLAGS": "1",
        }
        for override in (
            dict(approved, PATH="/ambient"),
            dict(approved, CC_x86_64_unknown_linux_musl="gcc"),
            dict(approved, CC_SHELL_ESCAPED_FLAGS="0"),
            {key: value for key, value in approved.items() if key != "CFLAGS_x86_64_unknown_linux_musl"},
        ):
            with self.subTest(override=override):
                with self.assertRaisesRegex(CLOSURE.ClosureError, "pinned target compiler"):
                    CLOSURE.build(argparse.Namespace(), c_environment=override)

    def test_selected_static_c_profiles_exclude_optional_runtime_dependencies(self) -> None:
        for features in ("", "x86-legacy-misc"):
            with self.subTest(features=features):
                profile = CLOSURE.source_runtime_profile(features)
                self.assertEqual(profile["staticlib_runtime_names"], ("core", "compiler_builtins"))
                self.assertFalse(profile["builds_crabc_mimalloc"])
                self.assertEqual(
                    profile["libc_externs"],
                    {
                        "alloc": ("noprelude", "nounused"),
                        "compiler_builtins": ("noprelude", "nounused"),
                        "core": ("noprelude", "nounused"),
                    },
                )

    def test_owned_static_core_profile_has_no_crypt_or_native_shadow_externs(self) -> None:
        profile = CLOSURE.source_runtime_profile("x86-owned-static-runtime-core")

        self.assertEqual(profile["name"], "owned-static-c-allocator-core")
        self.assertFalse(profile["builds_crabc_mimalloc"])
        self.assertEqual(
            profile["libc_externs"],
            {
                "alloc": ("noprelude", "nounused"),
                "compiler_builtins": ("noprelude", "nounused"),
                "core": ("noprelude", "nounused"),
                "crabc_core": (),
                "libmimalloc_sys": (),
                "rand_pcg": (),
            },
        )
        command, target, runtime, artifacts, source = self._command(
            immediate_abort=True,
            extern_matrix=profile["libc_externs"],
        )
        record = CLOSURE.command_record(
            command,
            target,
            runtime,
            self._emitted(artifacts),
            "crabc-libc",
            source,
            extern_matrix=profile["libc_externs"],
        )
        self.assertEqual(set(record["all_externs"]), set(profile["libc_externs"]))
        self.assertNotIn("base64ct", record["all_externs"])
        self.assertNotIn("sha_crypt", record["all_externs"])
        self.assertNotIn("crabc_mimalloc", record["all_externs"])

    def test_unnamed_feature_sets_derive_their_closure_from_cargo(self) -> None:
        profile = CLOSURE.source_runtime_profile("x86-owned-static-runtime-core,x86-crypt")

        self.assertEqual(profile["name"], "derived-static-c-abi")
        self.assertIsNone(profile["builds_crabc_mimalloc"])
        self.assertIsNone(profile["staticlib_runtime_names"])
        self.assertIsNone(profile["libc_externs"])
        self.assertEqual(CLOSURE.normalized_features(" x86-a64l  x86-crypt,x86-scandir "),
                         "x86-a64l,x86-crypt,x86-scandir")
        self.assertEqual(CLOSURE.source_runtime_profile("x86-legacy-misc ")["name"], "selected-static-legacy-misc")
        for malformed in ("--all-features", "crabc-libc/x86-crypt", "dep:rand_pcg", "X86-crypt"):
            with self.subTest(features=malformed):
                with self.assertRaisesRegex(CLOSURE.ClosureError, "malformed source-runtime feature list"):
                    CLOSURE.source_runtime_profile(malformed)

    def test_derived_libc_externs_require_source_runtime_and_plain_dependencies(self) -> None:
        matrix = {
            "alloc": ("noprelude", "nounused"),
            "compiler_builtins": ("noprelude", "nounused"),
            "core": ("noprelude", "nounused"),
            "crabc_core": (),
            "libmimalloc_sys": (),
        }
        command, target, runtime, artifacts, source = self._command(immediate_abort=True, extern_matrix=matrix)

        self.assertEqual(CLOSURE.derived_libc_externs(command, "Cargo crabc-libc rustc"), matrix)
        record = CLOSURE.command_record(
            command, target, runtime, self._emitted(artifacts), "crabc-libc", source,
            extern_matrix=CLOSURE.derived_libc_externs(command, "Cargo crabc-libc rustc"),
        )
        self.assertEqual(set(record["all_externs"]), set(matrix))

        marker = f"crabc_core={artifacts['crabc_core']}"
        privileged = [*command]
        privileged[privileged.index(marker)] = f"priv:crabc_core={artifacts['crabc_core']}"
        with self.assertRaisesRegex(CLOSURE.ClosureError, "modifier sequence differs"):
            CLOSURE.command_record(
                privileged, target, runtime, self._emitted(artifacts), "crabc-libc", source,
                extern_matrix=CLOSURE.derived_libc_externs(privileged, "Cargo crabc-libc rustc"),
            )

        index = command.index(f"noprelude,nounused:alloc={artifacts['alloc']}")
        without_alloc = [*command[:index - 1], *command[index + 1:]]
        with self.assertRaisesRegex(CLOSURE.ClosureError, "missing=\\['alloc'\\]"):
            CLOSURE.command_record(
                without_alloc, target, runtime, self._emitted(artifacts), "crabc-libc", source,
                extern_matrix=CLOSURE.derived_libc_externs(without_alloc, "Cargo crabc-libc rustc"),
            )

    def test_runtime_flags_follow_the_selected_relocation_model(self) -> None:
        self.assertEqual(CLOSURE.runtime_flags("static"), CLOSURE.RUNTIME_FLAGS)
        pic = CLOSURE.runtime_flags("pic")
        self.assertIn("-Crelocation-model=pic", pic)
        self.assertNotIn("-Crelocation-model=static", pic)
        self.assertIn("-Cpanic=immediate-abort", pic)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "unsupported relocation model"):
            CLOSURE.runtime_flags("dynamic-no-pic")

        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        with self.assertRaisesRegex(CLOSURE.ClosureError, "relocation-model=pic"):
            CLOSURE.command_record(
                command, target, runtime, self._emitted(artifacts), "crabc-libc", source, flags=pic,
            )

    def test_libc_rustc_arguments_cannot_override_the_shared_runtime_profile(self) -> None:
        accepted = ["-C", "codegen-units=1", "-Clto=off", "--cfg", "crabc_owned_static_sysroot"]
        self.assertEqual(CLOSURE.libc_rustc_arguments(accepted), accepted)
        for rejected in (
            ["-C", "panic=abort"],
            ["-Cpanic=unwind"],
            ["-C", "relocation-model=pic"],
            ["-Ccode-model=large"],
            ["-Ztls-model=global-dynamic"],
            ["-Z", "tls-model=local-exec"],
            ["-C", "force-unwind-tables=yes"],
            ["-C"],
        ):
            with self.subTest(arguments=rejected):
                with self.assertRaisesRegex(CLOSURE.ClosureError, "libc rustc argument"):
                    CLOSURE.libc_rustc_arguments(rejected)

    def test_process_exec_release_arguments_remain_valid_for_shared_command_records(self) -> None:
        arguments = [
            "-C", "debuginfo=0", "-C", "opt-level=2", "-C", "overflow-checks=off",
            "-C", "debug-assertions=off", "-C", "link-dead-code=no", "-C", "lto=off",
            "-C", "codegen-units=256",
        ]
        self.assertEqual(CLOSURE.libc_rustc_arguments(arguments), arguments)
        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        command.extend(arguments)

        record = CLOSURE.command_record(
            command, target, runtime, self._emitted(artifacts), "crabc-libc", source,
        )

        self.assertEqual(record["arguments"][-len(arguments):], arguments)

    def test_rustc_cannot_override_runtime_flags_after_the_required_values(self) -> None:
        for trailing in (("-C", "panic=unwind"), ("-C", "panic")):
            with self.subTest(trailing=trailing):
                command, target, runtime, artifacts, source = self._command(immediate_abort=True)
                command.extend(trailing)

                with self.assertRaisesRegex(CLOSURE.ClosureError, "overrides the source-runtime flag"):
                    CLOSURE.command_record(
                        command, target, runtime, self._emitted(artifacts), "crabc-libc", source,
                    )

    def test_derived_staticlib_closure_takes_alloc_all_or_nothing(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            work = Path(temporary)
            archive = work / "libc.a"
            archive.write_bytes(b"synthetic archive identity")
            runtime_paths = {
                "core": work / "core.o",
                "alloc": work / "alloc.o",
                "alloc-second": work / "alloc-second.o",
                "compiler_builtins": work / "compiler_builtins.o",
            }
            for name, path in runtime_paths.items():
                path.write_bytes(name.encode("ascii"))
            expected = {
                path.name: {"runtime": name.removesuffix("-second"), "sha256": CLOSURE.digest(path)}
                for name, path in runtime_paths.items()
            }

            def no_undefined_symbols(_nm: Path, _archive: Path, output: Path) -> list[str]:
                output.write_text("", encoding="utf-8")
                return []

            def closure(selected: dict[str, Path]) -> dict[str, object]:
                with (
                    patch.object(CLOSURE, "runtime_members", return_value=expected),
                    patch.object(CLOSURE, "archive_members", return_value=selected),
                    patch.object(CLOSURE, "undefined_symbols", side_effect=no_undefined_symbols),
                ):
                    return CLOSURE.staticlib_closure(
                        Path("llvm-ar"), Path("llvm-nm"), archive, {}, work, required_runtime_names=None,
                    )

            base = {runtime_paths[name].name: runtime_paths[name] for name in ("core", "compiler_builtins")}
            self.assertEqual(
                {member["runtime"] for member in closure(base)["source_runtime_members"]},
                {"core", "compiler_builtins"},
            )
            every = {path.name: path for path in runtime_paths.values()}
            self.assertEqual(
                {member["runtime"] for member in closure(every)["source_runtime_members"]},
                {"core", "alloc", "compiler_builtins"},
            )
            with self.assertRaisesRegex(CLOSURE.ClosureError, "omits source-built runtime members"):
                closure({**base, runtime_paths["alloc"].name: runtime_paths["alloc"]})
            with self.assertRaisesRegex(CLOSURE.ClosureError, "omits source-built runtime members"):
                closure({runtime_paths["core"].name: runtime_paths["core"]})

    def test_c_allocator_staticlib_selects_core_without_alloc_members(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            work = Path(temporary)
            archive = work / "libc.a"
            archive.write_bytes(b"synthetic archive identity")
            runtime_paths = {
                "core": work / "core.o",
                "alloc": work / "alloc.o",
                "compiler_builtins": work / "compiler_builtins.o",
            }
            for name, path in runtime_paths.items():
                path.write_bytes(name.encode("ascii"))
            expected = {
                path.name: {"runtime": name, "sha256": CLOSURE.digest(path)}
                for name, path in runtime_paths.items()
            }
            selected = {
                runtime_paths["core"].name: runtime_paths["core"],
                runtime_paths["compiler_builtins"].name: runtime_paths["compiler_builtins"],
            }
            def no_undefined_symbols(_nm: Path, _archive: Path, output: Path) -> list[str]:
                output.write_text("", encoding="utf-8")
                return []

            with (
                patch.object(CLOSURE, "runtime_members", return_value=expected),
                patch.object(CLOSURE, "archive_members", return_value=selected),
                patch.object(CLOSURE, "undefined_symbols", side_effect=no_undefined_symbols),
            ):
                closure = CLOSURE.staticlib_closure(
                    Path("llvm-ar"), Path("llvm-nm"), archive, {}, work,
                    required_runtime_names=("core", "compiler_builtins"),
                )
                self.assertEqual(
                    {member["runtime"] for member in closure["source_runtime_members"]},
                    {"core", "compiler_builtins"},
                )

            with (
                patch.object(CLOSURE, "runtime_members", return_value=expected),
                patch.object(CLOSURE, "archive_members", return_value={**selected, runtime_paths["alloc"].name: runtime_paths["alloc"]}),
                patch.object(CLOSURE, "undefined_symbols", side_effect=no_undefined_symbols),
            ):
                with self.assertRaisesRegex(CLOSURE.ClosureError, "excluded source runtime alloc"):
                    CLOSURE.staticlib_closure(
                        Path("llvm-ar"), Path("llvm-nm"), archive, {}, work,
                        required_runtime_names=("core", "compiler_builtins"),
                    )

    def _command(
        self,
        *,
        immediate_abort: bool,
        record_crate: str = "crabc-libc",
        extern_matrix: dict[str, tuple[str, ...]] | None = None,
    ) -> tuple[list[str], Path, dict[str, Path], dict[str, Path], Path]:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        target = temporary / "target"
        target.mkdir()
        source = temporary / "lib.rs"
        source.write_text("#![no_std]\n", encoding="utf-8")
        matrix = extern_matrix or CLOSURE.EXTERN_MODIFIER_MATRIX[record_crate]
        all_artifacts: dict[str, Path] = {}
        for name in matrix:
            artifact = target / f"lib{name}.rlib"
            artifact.write_bytes(name.encode("ascii"))
            all_artifacts[name] = artifact
        runtime = {name: all_artifacts[name] for name in ("core", "alloc", "compiler_builtins")
                   if name in all_artifacts}
        flags = ["-Ztls-model=initial-exec", "-Zunstable-options"]
        flags.append("-Cpanic=immediate-abort" if immediate_abort else "-Cpanic=abort")
        flags.extend(["-Cforce-unwind-tables=no", "-Crelocation-model=static", "-Ccode-model=small"])
        command = [
            "rustc", "--crate-name", "c", "--target", CLOSURE.TARGET, *flags, str(source),
        ]
        for name, modifiers in matrix.items():
            prefix = "" if not modifiers else ",".join(modifiers) + ":"
            command.extend(["--extern", f"{prefix}{name}={all_artifacts[name]}"])
        return command, target, runtime, all_artifacts, source

    @staticmethod
    def _emitted(runtime: dict[str, Path]) -> dict[Path, dict[str, object]]:
        return {
            path: {"target_name": name, "package_id": f"path+file:///source/{name}", "source": str(path)}
            for name, path in runtime.items()
        }

    def test_pinned_rustup_keeps_lexical_frontend_for_bootstrap_target(self) -> None:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        target = temporary / "usr" / "bin" / "rustup-init"
        target.parent.mkdir(parents=True)
        target.write_text("bootstrap", encoding="utf-8")
        target.chmod(0o755)
        frontend = temporary / "opt" / "cargo" / "bin" / "rustup"
        frontend.parent.mkdir(parents=True)
        frontend.symlink_to(target)

        identity = CLOSURE.pinned_rustup_frontend(frontend, target)

        self.assertEqual(identity["argv0"], str(frontend))
        self.assertEqual(identity["frontend"], str(frontend))
        self.assertEqual(identity["resolved_target"], str(target))

        with self.assertRaisesRegex(CLOSURE.ClosureError, "lexical rustup frontend"):
            CLOSURE.pinned_rustup_frontend(target, target)

    def test_retained_leaf_profiles_keep_exact_empty_dependency_closures(self) -> None:
        for feature in ('x86-signal-legacy-aliases', 'x86-process-exec', 'x86-netdb-setent'):
            with self.subTest(feature=feature):
                self.assertEqual(CLOSURE.retained_package_features(feature), frozenset(('default', feature)))
        for feature in ('x86-crypt', 'x86-owned-static-runtime', 'x86-process-exec,x86-netdb-setent'):
            with self.subTest(feature=feature), self.assertRaisesRegex(CLOSURE.ClosureError, 'requested feature profile'):
                CLOSURE.retained_package_features(feature)

    def test_retained_cargo_command_accepts_only_the_fixed_feature_invocation(self) -> None:
        feature = CLOSURE.RETAINED_MATH_FEATURE
        baseline = [
            str(CLOSURE.PINNED_RUSTUP_FRONTEND), "run", CLOSURE.TOOLCHAIN, "cargo",
            "-Zbuild-std=core,alloc,compiler_builtins", "rustc", "--locked", "--offline", "-vv",
            "--message-format=json-render-diagnostics", "-p", "crabc-libc", "--lib", "--target",
            CLOSURE.TARGET,
        ]
        accepted = [*baseline, "--features", feature]

        class ReachedCargoFiles(Exception):
            pass

        with tempfile.TemporaryDirectory(dir=ROOT / ".work" / "tmp") as temporary:
            graph = Path(temporary) / "graph"
            graph.mkdir()
            receipt_path = graph / "receipt.json"
            with patch.object(CLOSURE, "physical_child", side_effect=ReachedCargoFiles):
                for features, command in (("", baseline), (feature, accepted)):
                    profile = CLOSURE.source_runtime_profile(features)
                    receipt = {
                        "cargo_command": command,
                        "profile": profile["name"],
                        "features": features,
                        "cargo_profile": "dev",
                        "cargo_profile_dev_debug": 0,
                        "cargo_profile_dev_codegen_units": CLOSURE.DEV_CODEGEN_UNITS,
                        "libc_rustc_arguments": [],
                        "c_environment": {},
                        "runtime_flags": list(CLOSURE.RUNTIME_FLAGS),
                    }
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

                    with self.subTest(features=features):
                        with self.assertRaises(ReachedCargoFiles):
                            CLOSURE.replay_cargo_graph(graph, features)

                changed_commands = (
                    ["rustup", *accepted[1:]],
                    [*accepted, "--release"],
                    [*accepted[:-1], "x86-crypt"],
                    [*accepted, "--", "--cfg", "receipt_probe"],
                )
                for changed in changed_commands:
                    receipt["cargo_command"] = changed
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                    with self.subTest(changed=changed):
                        with self.assertRaisesRegex(CLOSURE.ClosureError, "Cargo argv differs"):
                            CLOSURE.replay_cargo_graph(graph, feature)

                del receipt["cargo_command"]
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                with self.assertRaisesRegex(CLOSURE.ClosureError, "Cargo argv differs"):
                    CLOSURE.replay_cargo_graph(graph, feature)

    def test_build_records_the_original_cargo_argv_after_runtime_invocations(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work" / "tmp") as temporary:
            fixture = Path(temporary)
            repository = fixture / "repository"
            work_root = repository / ".work" / "x86_64"
            project_vendor = work_root / "cargo" / "native-static-source-runtime-vendor"
            project_vendor.mkdir(parents=True)
            libc_source = repository / "libc" / "src" / "lib.rs"
            libc_source.parent.mkdir(parents=True)
            libc_source.write_text("#![no_std]\n", encoding="utf-8")

            rustup_home = fixture / "opt" / "rustup"
            sysroot = rustup_home / "toolchains" / f"{CLOSURE.TOOLCHAIN}-x86_64-unknown-linux-musl"
            rust_source = sysroot / "lib" / "rustlib" / "src" / "rust" / "library"
            for relative in CLOSURE.RUNTIME_SOURCES.values():
                source = rust_source / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("#![no_std]\n", encoding="utf-8")

            artifacts = {}
            artifact_root = fixture / "artifacts"
            artifact_root.mkdir()
            for name in (*CLOSURE.RUNTIME_SOURCES, "c"):
                artifact = artifact_root / (f"lib{name}.a" if name == "c" else f"lib{name}.rlib")
                artifact.write_bytes(name.encode("ascii"))
                artifacts[name] = artifact

            expected = [
                str(CLOSURE.PINNED_RUSTUP_FRONTEND), "run", CLOSURE.TOOLCHAIN, "cargo",
                "-Zbuild-std=core,alloc,compiler_builtins", "rustc", "--locked", "--offline", "-vv",
                "--message-format=json-render-diagnostics", "-p", "crabc-libc", "--lib", "--target",
                CLOSURE.TARGET, "--release", "--features", CLOSURE.RETAINED_MATH_FEATURE,
                "--", "--cfg", "receipt_probe",
            ]
            captured = {}

            def retain_streams(command, _environment, stdout_path, stderr_path, _description):
                captured["run_command"] = list(command)
                stdout_path.write_text("{}\n", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")

            def rustc_invocation(_commands, name):
                return ["/opt/rustup/bin/rustc", "--crate-name", name]

            arguments = SimpleNamespace(
                features=CLOSURE.RETAINED_MATH_FEATURE,
                relocation_model="static",
                rustc_arguments=["--cfg", "receipt_probe"],
                release=True,
                work=Path("build"),
            )
            with (
                patch.object(CLOSURE, "ROOT", repository),
                patch.object(CLOSURE, "PINNED_RUSTUP_HOME", rustup_home),
                patch.object(CLOSURE, "pinned_environment", return_value=(
                    {"argv0": str(CLOSURE.PINNED_RUSTUP_FRONTEND)}, {},
                )),
                patch.object(CLOSURE.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=f"{sysroot}\n", stderr="",
                )),
                patch.object(CLOSURE, "private_vendor", return_value={"private_vendor": True}),
                patch.object(CLOSURE, "run", side_effect=retain_streams),
                patch.object(CLOSURE, "cargo_records", return_value=[]),
                patch.object(CLOSURE, "emitted_artifacts", return_value={}),
                patch.object(CLOSURE, "artifact_for_source", side_effect=lambda _records, _source, name, _target, _suffix: artifacts[name]),
                patch.object(CLOSURE, "cargo_commands", return_value=[]),
                patch.object(CLOSURE, "validate_wrapped_commands"),
                patch.object(CLOSURE, "compiler_tools", return_value={}),
                patch.object(CLOSURE, "invocation_for", side_effect=rustc_invocation),
                patch.object(CLOSURE, "command_record", return_value={}),
                patch.object(CLOSURE, "required_tool", return_value=Path("/tool")),
                patch.object(CLOSURE, "staticlib_closure", return_value={}),
            ):
                CLOSURE.build(arguments)

            receipt = json.loads((work_root / "build" / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(captured["run_command"], expected)
            self.assertEqual(receipt["cargo_command"], expected)
            self.assertEqual(receipt["cargo_profile"], "release")
            self.assertEqual(receipt["features"], CLOSURE.RETAINED_MATH_FEATURE)
            self.assertEqual(receipt["libc_rustc_arguments"], ["--cfg", "receipt_probe"])

    def test_project_vendor_requires_exact_versioned_package_directory(self) -> None:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        vendor = temporary / "authenticated-project-vendor"
        package = vendor / "example-runtime-1.2.3"
        package.mkdir(parents=True)

        found = CLOSURE.find_project_vendor_package(
            vendor, "example-runtime", "1.2.3", "test project vendor package"
        )

        self.assertEqual(found, package.resolve())

    def test_private_vendor_replay_matches_locked_sources_and_rejects_changed_bytes(self) -> None:
        work_root = ROOT / ".work" / "tmp"
        work_root.mkdir(parents=True, exist_ok=True)
        toolchain_root = CLOSURE.PINNED_RUSTUP_HOME / "toolchains" / f"{CLOSURE.TOOLCHAIN}-x86_64-unknown-linux-musl"
        rust_source = toolchain_root / "lib" / "rustlib" / "src" / "rust" / "library"
        project_vendor = ROOT / ".work" / "x86_64" / "cargo" / "native-static-source-runtime-vendor"
        if not project_vendor.is_dir():
            self.skipTest("requires the prepared workspace Cargo vendor")
        with tempfile.TemporaryDirectory(prefix="source-runtime-vendor-replay.", dir=work_root) as temporary:
            work = Path(temporary)
            produced = CLOSURE.private_vendor(work, rust_source, project_vendor)

            self.assertEqual(CLOSURE.replay_private_vendor(work, rust_source), produced)

            package = Path(produced["packages"][0]["directory"])
            vendored_file = next(
                path for path in package.rglob("*")
                if path.is_file() and path.name != ".cargo-checksum.json"
            )
            vendored_file.write_bytes(vendored_file.read_bytes() + b"changed")
            with self.assertRaisesRegex(CLOSURE.ClosureError, "file digest differs"):
                CLOSURE.replay_private_vendor(work, rust_source)

    def test_cargo_commands_accepts_literal_backticks_in_multiline_description(self) -> None:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        stderr = temporary / "cargo.stderr.log"
        # This is Cargo's retained `-vv` form from the failing source-runtime
        # graph: the description is shell quoted but Cargo leaves its Markdown
        # backticks and physical newlines intact inside the outer `Running` pair.
        stderr.write_text(
            "     Running `CARGO_PKG_DESCRIPTION='Constant-time utility library\n"
            "applications. Supports `const fn` where appropriate. Built on `cmov`.\n"
            "' /opt/rustup/bin/rustc --crate-name ctutils --target x86_64-unknown-linux-musl`\n"
            "   Compiling crabc-libc v0.3.0 (/workspace/libc)\n"
            "     Running `RUSTC=/opt/rustup/bin/rustc /opt/rustup/bin/rustc --crate-name c "
            "--target x86_64-unknown-linux-musl`\n"
            "    Finished `dev` profile [optimized + debuginfo] target(s) in 1.00s\n",
            encoding="utf-8",
        )

        commands = CLOSURE.cargo_commands(stderr)

        self.assertEqual([CLOSURE.option_values(command, "--crate-name") for command in commands], [["ctutils"], ["c"]])
        self.assertIn("CARGO_PKG_DESCRIPTION=Constant-time utility library\napplications. Supports `const fn` where appropriate. Built on `cmov`.\n", commands[0])

    def test_cargo_commands_rejects_ambiguous_or_malformed_rendering(self) -> None:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        stderr = temporary / "cargo.stderr.log"
        stderr.write_text(
            "     Running `rustc --crate-name c --target x86_64-unknown-linux-musl`\n"
            "warning: synthetic diagnostic\n"
            "`\n"
            "    Finished `dev` profile [optimized + debuginfo] target(s) in 1.00s\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(CLOSURE.ClosureError, "unambiguous rendered command"):
            CLOSURE.cargo_commands(stderr)

        stderr.write_text(
            "     Running `rustc --crate-name c --target x86_64-unknown-linux-musl\n"
            "warning: synthetic diagnostic\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CLOSURE.ClosureError, "unambiguous rendered command"):
            CLOSURE.cargo_commands(stderr)

    def test_command_source_identity_accepts_only_exact_frozen_root_spelling(self) -> None:
        source = (ROOT / "libc" / "src" / "lib.rs").resolve()

        identity = CLOSURE.command_source_identity(["libc/src/lib.rs"], source, "test Cargo c rustc")

        self.assertEqual(identity, {"lexical_path": "libc/src/lib.rs", "physical_path": str(source)})
        self.assertEqual(
            CLOSURE.command_source_identity([str(source)], source, "test Cargo c rustc"),
            {"lexical_path": str(source), "physical_path": str(source)},
        )
        with self.assertRaisesRegex(CLOSURE.ClosureError, "exact checked-in source"):
            CLOSURE.command_source_identity(["libc/../libc/src/lib.rs"], source, "test Cargo c rustc")

    def test_primary_record_binds_all_source_runtime_externs(self) -> None:
        command, target, runtime, artifacts, source = self._command(immediate_abort=True)

        record = CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-libc", source)

        self.assertEqual(set(record["runtime_externs"]), set(runtime))
        self.assertEqual(
            [record["runtime_externs"][name]["path"] for name in sorted(runtime)],
            [str(runtime[name]) for name in sorted(runtime)],
        )
        self.assertEqual(
            [record["runtime_externs"][name]["modifiers"] for name in sorted(runtime)],
            [["noprelude", "nounused"], ["noprelude", "nounused"], ["noprelude", "nounused"]],
        )
        self.assertEqual(
            [record["runtime_externs"][name]["logical_name"] for name in sorted(runtime)],
            sorted(runtime),
        )
        self.assertEqual(record["runtime_externs"]["core"]["artifact"]["source"], str(runtime["core"]))
        self.assertEqual(record["all_externs"]["base64ct"]["logical_name"], "base64ct")
        self.assertEqual(record["all_externs"]["base64ct"]["modifiers"], [])

    def test_primary_record_accepts_only_matching_rlib_rmeta_pairs(self) -> None:
        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        emitted = self._emitted(artifacts)
        metadata = artifacts["core"].with_suffix(".rmeta")
        metadata.write_bytes(b"core metadata")
        emitted[metadata] = dict(emitted[artifacts["core"]])
        command.extend(["--extern", f"noprelude,nounused:core={metadata}"])

        record = CLOSURE.command_record(command, target, runtime, emitted, "crabc-libc", source)
        self.assertEqual(record["all_externs"]["core"]["path"], str(artifacts["core"]))
        self.assertEqual(record["all_externs"]["core"]["metadata"]["path"], str(metadata))

        bad_identity = dict(emitted)
        bad_identity[metadata] = {**bad_identity[metadata], "target_name": "std"}
        with self.assertRaisesRegex(CLOSURE.ClosureError, "metadata does not bind"):
            CLOSURE.command_record(command, target, runtime, bad_identity, "crabc-libc", source)

        repeated = [*command, "--extern", f"noprelude,nounused:core={metadata}"]
        with self.assertRaisesRegex(CLOSURE.ClosureError, "repeats --extern core"):
            CLOSURE.command_record(repeated, target, runtime, emitted, "crabc-libc", source)

        mismatched = artifacts["core"].with_name("libother.rmeta")
        mismatched.write_bytes(b"other metadata")
        malformed = [*command[:-2], "--extern", f"noprelude,nounused:core={mismatched}"]
        with self.assertRaisesRegex(CLOSURE.ClosureError, "repeats --extern core"):
            CLOSURE.command_record(malformed, target, runtime, emitted, "crabc-libc", source)

    def test_alloc_record_retains_private_compiler_builtins_edge(self) -> None:
        command, target, _, artifacts, source = self._command(immediate_abort=True, record_crate="alloc")

        record = CLOSURE.command_record(command, target, {}, self._emitted(artifacts), "alloc", source)

        self.assertEqual(record["all_externs"]["compiler_builtins"]["logical_name"], "compiler_builtins")
        self.assertEqual(record["all_externs"]["compiler_builtins"]["modifiers"], ["priv"])
        self.assertEqual(record["all_externs"]["core"]["modifiers"], [])

        stripped = [*command]
        marker = f"priv:compiler_builtins={artifacts['compiler_builtins']}"
        stripped[stripped.index(marker)] = f"compiler_builtins={artifacts['compiler_builtins']}"
        with self.assertRaisesRegex(CLOSURE.ClosureError, "modifier sequence differs"):
            CLOSURE.command_record(stripped, target, {}, self._emitted(artifacts), "alloc", source)

    def test_mimalloc_record_binds_source_runtime_metadata_artifacts(self) -> None:
        command, target, runtime, artifacts, source = self._command(immediate_abort=True, record_crate="crabc-mimalloc")
        emitted = self._emitted(artifacts)
        metadata: dict[str, Path] = {}
        for name, artifact in runtime.items():
            rmeta = artifact.with_suffix(".rmeta")
            rmeta.write_bytes((name + " metadata").encode("ascii"))
            emitted[rmeta] = dict(emitted[artifact])
            marker = f"noprelude,nounused:{name}={artifact}"
            command[command.index(marker)] = f"noprelude,nounused:{name}={rmeta}"
            metadata[name] = rmeta

        record = CLOSURE.command_record(command, target, runtime, emitted, "crabc-mimalloc", source)

        self.assertEqual(
            [record["runtime_externs"][name]["path"] for name in sorted(runtime)],
            [str(metadata[name]) for name in sorted(runtime)],
        )
        self.assertEqual(
            [record["runtime_externs"][name]["modifiers"] for name in sorted(runtime)],
            [["noprelude", "nounused"], ["noprelude", "nounused"], ["noprelude", "nounused"]],
        )

    def test_mimalloc_record_accepts_its_pinned_xoshiro_dependency_without_privileged_modifiers(self) -> None:
        matrix = dict(CLOSURE.EXTERN_MODIFIER_MATRIX["crabc-mimalloc"], rand_xoshiro=())
        command, target, runtime, artifacts, source = self._command(
            immediate_abort=True, record_crate="crabc-mimalloc", extern_matrix=matrix,
        )
        record = CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-mimalloc", source)
        self.assertEqual(record["all_externs"]["rand_xoshiro"]["modifiers"], [])
        marker = f"rand_xoshiro={artifacts['rand_xoshiro']}"
        command[command.index(marker)] = f"priv:{marker}"
        with self.assertRaisesRegex(CLOSURE.ClosureError, "modifier sequence differs"):
            CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-mimalloc", source)

    def test_primary_record_rejects_abort_profile_without_immediate_abort(self) -> None:
        command, target, runtime, artifacts, source = self._command(immediate_abort=False)

        with self.assertRaisesRegex(CLOSURE.ClosureError, "panic=immediate-abort"):
            CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-libc", source)

    def test_primary_record_rejects_unrecorded_target_extern(self) -> None:
        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        extra = target / "libextra.rlib"
        extra.write_bytes(b"not-a-recorded-cargo-artifact")
        marker = f"base64ct={artifacts['base64ct']}"
        command[command.index(marker)] = f"base64ct={extra}"

        with self.assertRaisesRegex(CLOSURE.ClosureError, "does not bind an emitted Cargo artifact"):
            CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-libc", source)

    def test_primary_record_rejects_external_or_forbidden_extern_identity(self) -> None:
        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        external = target.parent / "external.rlib"
        external.write_bytes(b"external")
        marker = f"base64ct={artifacts['base64ct']}"
        command[command.index(marker)] = f"base64ct={external}"

        with self.assertRaisesRegex(CLOSURE.ClosureError, "admits external Rust artifact"):
            CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-libc", source)

        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        emitted = self._emitted(artifacts)
        emitted[artifacts["base64ct"]]["target_name"] = "std"
        with self.assertRaisesRegex(CLOSURE.ClosureError, "admits forbidden runtime extern"):
            CLOSURE.command_record(command, target, runtime, emitted, "crabc-libc", source)

    def test_primary_record_rejects_modified_runtime_modifier_contract(self) -> None:
        cases = (
            ("core", "core", "modifier sequence differs"),
            ("core", "priv:core", "modifier sequence differs"),
            ("core", "nounused,noprelude:core", "unsupported --extern modifier sequence"),
            ("core", "noprelude,noprelude:core", "unsupported --extern modifier sequence"),
            ("core", "hidden:core", "unsupported --extern modifier sequence"),
        )
        for logical_name, replacement, message in cases:
            with self.subTest(replacement=replacement):
                command, target, runtime, artifacts, source = self._command(immediate_abort=True)
                marker = f"noprelude,nounused:{logical_name}={artifacts[logical_name]}"
                command[command.index(marker)] = f"{replacement}={artifacts[logical_name]}"
                with self.assertRaisesRegex(CLOSURE.ClosureError, message):
                    CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-libc", source)

        command, target, runtime, artifacts, source = self._command(immediate_abort=True)
        command.extend(["--extern", f"core={artifacts['core']}"])
        with self.assertRaisesRegex(CLOSURE.ClosureError, "repeats --extern core"):
            CLOSURE.command_record(command, target, runtime, self._emitted(artifacts), "crabc-libc", source)


if __name__ == "__main__":
    unittest.main()
