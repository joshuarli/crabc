"""Focused contract tests for the source-purity checks in build.py."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("crabc_builtins_build", ROOT / "build.py")
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class BuildContractTests(unittest.TestCase):
    def test_symbol_contract_has_no_memory_or_atomic_exports(self) -> None:
        symbols = set(BUILD.EXPECTED_SYMBOLS)
        self.assertTrue(symbols)
        self.assertFalse(any("mem" in symbol or "atomic" in symbol for symbol in symbols))

    def test_source_audit_records_the_production_inputs(self) -> None:
        sources = BUILD.audit_source()
        self.assertEqual(
            [entry["path"] for entry in sources],
            ["Cargo.toml", "Cargo.lock", "build.py", "provenance.toml", "src/lib.rs"],
        )

    def test_compiler_command_disables_outline_atomics_and_unwinding(self) -> None:
        command = BUILD.compiler_command(("rustc",), pathlib.Path("/tmp/crabc-builtins.o"))
        self.assertIn("panic=abort", command)
        self.assertIn("force-unwind-tables=no", command)
        self.assertIn("target-feature=-outline-atomics", command)
        self.assertNotIn("-C link-arg=-lgcc", command)

    def test_source_build_contract_is_exact_and_locked(self) -> None:
        contract = BUILD.tomllib.loads((ROOT / "provenance.toml").read_text(encoding="utf-8"))
        upstream = contract["upstream_compiler_builtins"]
        self.assertEqual(tuple(upstream["source_build"]), BUILD.UPSTREAM_SOURCE_BUILD_COMPONENTS)
        self.assertEqual(set(upstream["required_features"]), BUILD.UPSTREAM_REQUIRED_FEATURES)
        self.assertEqual(set(upstream["forbidden_features"]), BUILD.UPSTREAM_FORBIDDEN_FEATURES)
        self.assertTrue(upstream["locked_resolution"])

    def test_source_build_feature_parser_rejects_feature_drift(self) -> None:
        target = pathlib.Path("/tmp/crabc-source-build-target")
        good = (
            f"rustc --crate-name core --out-dir {target}\n"
            f"rustc --crate-name compiler_builtins --extern core={target}/core.rmeta "
            '--cfg feature="arch" --cfg feature="compiler-builtins" '
            '--cfg feature="default" --cfg feature="unmangled-names"\n'
        )
        self.assertEqual(
            BUILD.compiler_builtins_features(good, target),
            sorted(BUILD.UPSTREAM_REQUIRED_FEATURES),
        )
        with self.assertRaises(BUILD.BuildError):
            BUILD.compiler_builtins_features(good.replace('feature="default"', 'feature="default" --cfg feature="c"'), target)

    def test_source_build_environment_seals_native_and_codegen_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = BUILD.source_build_environment(pathlib.Path(temporary), ("-C", "panic=abort"))
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        self.assertEqual(environment["CARGO_ENCODED_RUSTFLAGS"], "-C\x1fpanic=abort")
        for key in BUILD.SEALED_SOURCE_BUILD_ENVIRONMENT_KEYS - {"CARGO_ENCODED_RUSTFLAGS"}:
            self.assertNotIn(key, environment)

    def test_native_build_log_and_selected_native_source_are_rejected(self) -> None:
        with self.assertRaises(BUILD.BuildError):
            BUILD.native_build_commands_from_log("Running `clang -c fallback.c -o fallback.o`")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workspace = root / "compiler-builtins"
            upstream = workspace / "compiler-builtins"
            upstream.mkdir(parents=True)
            native = upstream / "fallback.S"
            native.write_text(".text\n", encoding="utf-8")
            rlib = root / "libcompiler_builtins-fixture.rlib"
            rlib.write_bytes(b"placeholder")
            rlib.with_suffix(".d").write_text(f"{rlib}: {native}\n", encoding="utf-8")
            with self.assertRaises(BUILD.BuildError):
                BUILD.selected_upstream_sources(rlib, upstream)


if __name__ == "__main__":
    unittest.main()
