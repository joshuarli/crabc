from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/crabc-rs/build_examples.py"
SPEC = importlib.util.spec_from_file_location("build_examples", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


class ManifestExamplesTests(unittest.TestCase):
    def manifest(self, body: str, *example_paths: str) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        manifest = root / "Cargo.toml"
        manifest.write_text(body, encoding="utf-8")
        for example_path in example_paths:
            source = root / example_path
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("#![no_std]\n", encoding="utf-8")
        return directory, manifest

    def test_manifest_entries_drive_individual_feature_aware_commands(self) -> None:
        directory, manifest = self.manifest(
            """
[features]
alloc = []
runtime-loader = []

[[example]]
name = "direct_io_probe"
path = "examples/direct_io_probe.rs"
crate-type = ["staticlib"]

[[example]]
name = "loader_probe"
path = "examples/loader_probe.rs"
crate-type = ["staticlib"]
required-features = ["alloc", "runtime-loader"]
""",
            "examples/direct_io_probe.rs",
            "examples/loader_probe.rs",
        )
        self.addCleanup(directory.cleanup)

        targets = builder.load_examples(manifest)

        self.assertEqual([target.name for target in targets], ["direct_io_probe", "loader_probe"])
        self.assertEqual(targets[1].required_features, ("alloc", "runtime-loader"))
        self.assertEqual(
            builder.build_command("cargo", targets[0]),
            ("cargo", "build", "-p", "crabc-rs", "--example", "direct_io_probe", "--release", "--no-default-features"),
        )
        self.assertEqual(
            builder.build_command("cargo", targets[1]),
            (
                "cargo",
                "build",
                "-p",
                "crabc-rs",
                "--example",
                "loader_probe",
                "--release",
                "--no-default-features",
                "--features",
                "alloc,runtime-loader",
            ),
        )

    def test_run_builds_invokes_every_declared_target_separately(self) -> None:
        directory, manifest = self.manifest(
            """
[features]
alloc = []

[[example]]
name = "first_probe"
path = "examples/first_probe.rs"
crate-type = ["staticlib"]

[[example]]
name = "second_probe"
path = "examples/second_probe.rs"
crate-type = ["staticlib"]
required-features = ["alloc"]
""",
            "examples/first_probe.rs",
            "examples/second_probe.rs",
        )
        self.addCleanup(directory.cleanup)
        commands: list[tuple[str, ...]] = []

        def runner(command: tuple[str, ...]) -> SimpleNamespace:
            commands.append(command)
            return SimpleNamespace(returncode=0)

        builder.run_builds(builder.load_examples(manifest), "cargo", runner)

        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][4:6], ("--example", "first_probe"))
        self.assertEqual(commands[1][4:6], ("--example", "second_probe"))
        self.assertIn("alloc", commands[1])

    def test_rejects_missing_example_source_and_unknown_required_feature(self) -> None:
        directory, manifest = self.manifest(
            """
[features]
alloc = []

[[example]]
name = "missing_probe"
path = "examples/missing_probe.rs"
crate-type = ["staticlib"]
required-features = ["not-declared"]
"""
        )
        self.addCleanup(directory.cleanup)

        with self.assertRaises(builder.ManifestError):
            builder.load_examples(manifest)

    def test_rejects_an_example_source_without_a_manifest_entry(self) -> None:
        directory, manifest = self.manifest(
            """
[features]

[[example]]
name = "declared_probe"
path = "examples/declared_probe.rs"
crate-type = ["staticlib"]
""",
            "examples/declared_probe.rs",
            "examples/undeclared_probe.rs",
        )
        self.addCleanup(directory.cleanup)

        with self.assertRaisesRegex(builder.ManifestError, "lack \\[\\[example\\]\\] entries"):
            builder.load_examples(manifest)


if __name__ == "__main__":
    unittest.main()
