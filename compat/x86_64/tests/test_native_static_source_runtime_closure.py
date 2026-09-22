#!/usr/bin/env python3
"""Focused contracts for the native source-runtime Cargo evidence parser."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_static_source_runtime_closure.py"
SPEC = importlib.util.spec_from_file_location("native_static_source_runtime_closure", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load native static source-runtime closure helper")
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)


class NativeStaticSourceRuntimeClosureTests(unittest.TestCase):
    def _command(self, *, immediate_abort: bool, record_crate: str = "crabc-libc") -> tuple[list[str], Path, dict[str, Path], dict[str, Path], Path]:
        work = ROOT / ".work"
        work.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(dir=work))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary, ignore_errors=True))
        target = temporary / "target"
        target.mkdir()
        source = temporary / "lib.rs"
        source.write_text("#![no_std]\n", encoding="utf-8")
        all_artifacts: dict[str, Path] = {}
        for name in CLOSURE.EXTERN_MODIFIER_MATRIX[record_crate]:
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
        for name, modifiers in CLOSURE.EXTERN_MODIFIER_MATRIX[record_crate].items():
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

        self.assertEqual(identity["argv0"], "rustup")
        self.assertEqual(identity["frontend"], str(frontend))
        self.assertEqual(identity["resolved_target"], str(target))

        with self.assertRaisesRegex(CLOSURE.ClosureError, "lexical rustup frontend"):
            CLOSURE.pinned_rustup_frontend(target, target)

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
