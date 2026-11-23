from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "source_image_toolchain_check", ROOT / "compat/x86_64/source_image_toolchain_check.py"
)
assert SPEC is not None and SPEC.loader is not None
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class SourceImageToolchainCheckTests(unittest.TestCase):
    def test_current_paths_pass_and_stale_paths_fail_for_each_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifests = root / "compat/x86_64"
            manifests.mkdir(parents=True)
            (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-11-09"\n')
            for arch, names in check.MANIFESTS.items():
                current = f"/opt/rustup/toolchains/nightly-2026-11-09-{arch}-unknown-linux-musl/bin/rustc"
                for name in names:
                    (manifests / name).write_text(json.dumps({"files": {current: {}}}))
            self.assertEqual(check.stale_manifests(root), [])
            for arch, names in check.MANIFESTS.items():
                with self.subTest(arch=arch):
                    path = manifests / names[0]
                    current_data = path.read_text()
                    stale = f"/opt/rustup/toolchains/nightly-2026-09-15-{arch}-unknown-linux-musl/bin/rustc"
                    path.write_text(json.dumps({"files": {stale: {}}}))
                    self.assertEqual(check.stale_manifests(root), [names[0]])
                    path.write_text(current_data)
                    self.assertEqual(check.stale_manifests(root), [])


if __name__ == "__main__":
    unittest.main()
