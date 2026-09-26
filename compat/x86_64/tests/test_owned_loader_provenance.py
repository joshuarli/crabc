#!/usr/bin/env python3
"""Compiler dependency provenance for the installed native loader."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import build_x86_64_owned_dynamic_sysroot as producer
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_loader_inventory as inventory


class OwnedLoaderProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        self.stage = self.root / ".work" / "loader-product.build"
        self.compiler_artifact = (
            self.stage / "loader" / producer.common.TARGET / "release" / "libldso.so"
        )
        self.installed_artifact = self.root / "installed" / "lib/ld-crabc-x86_64.so.1"
        self.sources = (
            "scripts/build_x86_64_owned_dynamic_sysroot.py",
            "scripts/build_x86_64_owned_sysroot.py",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            "ldso/Cargo.toml",
            "ldso/build.rs",
            "ldso/src/lib.rs",
            "ldso/src/x86_64_initial_graph.rs",
            "libc/src/c_abi/x86_64/owned_discard_unwind.ld",
            "ldso/x86_64-owned-bss-layout.ld",
        )
        for relative in self.sources:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative + "\n", encoding="utf-8")
            path.chmod(0o640 if relative.endswith("build.rs") else 0o644)
        self.compiler_artifact.parent.mkdir(parents=True)
        self.compiler_artifact.write_bytes(b"compiler-owned loader\n")
        self.compiler_artifact.chmod(0o755)
        self.installed_artifact.parent.mkdir(parents=True)
        self.installed_artifact.write_bytes(self.compiler_artifact.read_bytes())
        self.installed_artifact.chmod(0o755)
        self.dependencies = self.compiler_artifact.with_name("libldso.d")
        self.write_dependencies()
        self.root_patch = mock.patch.object(producer, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def write_dependencies(self, sources: tuple[str, ...] | None = None, *, target: Path | None = None) -> None:
        selected = sources or ("ldso/build.rs", "ldso/src/lib.rs", "ldso/src/x86_64_initial_graph.rs")
        destination = target or self.compiler_artifact
        self.dependencies.write_text(
            str(destination) + ": " + " ".join(str(self.root / source) for source in selected) + "\n",
            encoding="utf-8",
        )

    def collect(self) -> dict[str, object]:
        return self.collect_at(self.stage, self.compiler_artifact, self.installed_artifact)

    def collect_at(self, stage: Path, compiler_artifact: Path, installed_artifact: Path) -> dict[str, object]:
        command = [
            "/opt/pinned/rustup",
            "run",
            producer.common.PINNED_TOOLCHAIN,
            "cargo",
            "build",
            "--locked",
            "-p",
            "crabc-ldso",
            "--release",
            "--config",
            'profile.release.opt-level="s"',
            "--target",
            producer.common.TARGET,
            "--target-dir",
            str(stage / "loader"),
            "--no-default-features",
            "--features",
            producer.LOADER_FEATURE,
        ]
        return producer.loader_provenance(
            stage,
            command,
            "-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic"
            f" -C link-arg=-Wl,-T,{self.root / 'libc/src/c_abi/x86_64/owned_discard_unwind.ld'}"
            f" -C link-arg=-Wl,-T,{self.root / 'ldso/x86_64-owned-bss-layout.ld'}",
            compiler_artifact,
            installed_artifact,
        )

    def test_compiler_dependencies_bind_selected_sources_and_normalize_build_paths(self) -> None:
        record = self.collect()
        self.assertEqual(record["schema"], producer.LOADER_PROVENANCE_SCHEMA)
        self.assertEqual(record["target"], producer.common.TARGET)
        self.assertEqual(
            record["artifact"],
            {
                "path": producer.LOADER_ARTIFACT,
                "sha256": producer.common.sha256_file(self.installed_artifact),
                "mode": 0o755,
            },
        )
        cargo = record["cargo"]
        self.assertEqual(cargo["argv"][cargo["argv"].index("--target-dir") + 1], "$BUILD/loader")
        self.assertEqual(
            cargo["rustflags"],
            "-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic"
            f" -C link-arg=-Wl,-T,{self.root / 'libc/src/c_abi/x86_64/owned_discard_unwind.ld'}"
            f" -C link-arg=-Wl,-T,{self.root / 'ldso/x86_64-owned-bss-layout.ld'}",
        )
        dependencies = record["compiler_dependencies"]
        self.assertEqual([entry["path"] for entry in dependencies], [
            "ldso/build.rs",
            "ldso/src/lib.rs",
            "ldso/src/x86_64_initial_graph.rs",
        ])
        self.assertEqual(dependencies[0]["mode"], 0o640)
        self.assertEqual(
            [entry["path"] for entry in record["configuration"]],
            [
                "scripts/build_x86_64_owned_dynamic_sysroot.py",
                "scripts/build_x86_64_owned_sysroot.py",
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                ".cargo/config.toml",
                "ldso/Cargo.toml",
                "libc/src/c_abi/x86_64/owned_discard_unwind.ld",
                "ldso/x86_64-owned-bss-layout.ld",
            ],
        )

    def test_different_private_stage_paths_produce_identical_provenance(self) -> None:
        other_stage = self.root / ".work" / "other-loader-product.build"
        other_compiler = (
            other_stage / "loader" / producer.common.TARGET / "release" / "libldso.so"
        )
        other_installed = self.root / "other-installed" / "lib/ld-crabc-x86_64.so.1"
        other_compiler.parent.mkdir(parents=True)
        other_installed.parent.mkdir(parents=True)
        other_compiler.write_bytes(self.compiler_artifact.read_bytes())
        other_installed.write_bytes(self.compiler_artifact.read_bytes())
        other_compiler.chmod(0o755)
        other_installed.chmod(0o755)
        other_compiler.with_name("libldso.d").write_text(
            str(other_compiler)
            + ": "
            + " ".join(
                str(self.root / source)
                for source in ("ldso/build.rs", "ldso/src/lib.rs", "ldso/src/x86_64_initial_graph.rs")
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.collect(),
            self.collect_at(other_stage, other_compiler, other_installed),
        )

    def test_dependency_trace_rejects_missing_required_source_duplicate_foreign_and_swapped_target(self) -> None:
        outside = self.root.parent / "outside.rs"
        outside.write_text("outside\n", encoding="utf-8")
        swapped = self.compiler_artifact.with_name("other.so")
        swapped.write_bytes(self.compiler_artifact.read_bytes())
        cases = (
            (("ldso/build.rs", "ldso/src/x86_64_initial_graph.rs"), None, "build.rs or lib.rs"),
            (("ldso/build.rs", "ldso/src/lib.rs", "ldso/src/lib.rs"), None, "duplicate"),
            (("ldso/build.rs", "ldso/src/lib.rs", "../outside.rs"), None, "physical checkout"),
            (None, swapped, "does not bind"),
        )
        for sources, target, message in cases:
            with self.subTest(message=message):
                if sources is not None:
                    if "../outside.rs" in sources:
                        self.dependencies.write_text(
                            str(self.compiler_artifact) + ": "
                            + " ".join(
                                str(outside) if source == "../outside.rs" else str(self.root / source)
                                for source in sources
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                    else:
                        self.write_dependencies(sources)
                else:
                    self.write_dependencies(target=target)
                with self.assertRaisesRegex(producer.common.BuildError, message):
                    self.collect()

    def test_dependency_trace_rejects_symlinked_source_and_changed_installed_artifact(self) -> None:
        source = self.root / "ldso/src/x86_64_initial_graph.rs"
        replacement = self.root / "ldso/src/linked.rs"
        source.rename(replacement)
        source.symlink_to(replacement.name)
        with self.assertRaisesRegex(producer.common.BuildError, "physical checkout file"):
            self.collect()
        source.unlink()
        replacement.rename(source)
        self.installed_artifact.write_bytes(b"substituted loader\n")
        with self.assertRaisesRegex(producer.common.BuildError, "differs from its compiler artifact"):
            self.collect()

    def test_inventory_accepts_selected_loader_cargo_and_rejects_tampering(self) -> None:
        record = self.collect()
        metadata = self.installed_artifact.parents[1] / "share/crabc"
        metadata.mkdir(parents=True)
        provenance = metadata / "loader.provenance.json"
        (metadata / "producer-tools.json").write_text(
            json.dumps({"rustup": {"path": "/opt/pinned/rustup"}}), encoding="utf-8"
        )
        product = self.installed_artifact.parents[1]

        def read(selected: dict[str, object]) -> None:
            provenance.write_text(json.dumps(selected), encoding="utf-8")
            manifest = {"files": {inventory.LOADER_PROVENANCE_PATH: inventory.digest(provenance)}}
            with mock.patch.object(inventory, "ROOT", self.root), \
                 mock.patch.object(inventory.installed_driver, "validate", return_value=manifest), \
                 mock.patch.object(inventory.qualification, "product_identity", return_value="sealed"):
                inventory.load_loader_provenance(product)

        read(record)
        cargo = record["cargo"]
        argv = cargo["argv"]
        rustflags = cargo["rustflags"]
        tampered = (
            ("missing size profile", argv[:argv.index("--config")] + argv[argv.index("--target"):], rustflags),
            ("changed size profile", [
                'profile.release.opt-level="z"' if arg == 'profile.release.opt-level="s"' else arg
                for arg in argv
            ], rustflags),
            ("extra Cargo option", argv + ["--offline"], rustflags),
            ("missing linker script", argv, rustflags.split(" -C link-arg=")[0]),
            ("changed linker script", argv, rustflags.replace("x86_64-owned-bss-layout.ld", "other.ld")),
        )
        for name, command, flags in tampered:
            changed = json.loads(json.dumps(record))
            changed["cargo"] = {"argv": command, "rustflags": flags}
            with self.subTest(name=name):
                with self.assertRaisesRegex(inventory.InventoryError, "Cargo command or RUSTFLAGS differ"):
                    read(changed)


if __name__ == "__main__":
    unittest.main()
