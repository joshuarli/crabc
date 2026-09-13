"""Contract boundary for the finite pthread timed-feature evidence reader."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))


class TimedFeatureReceiptBoundaryTests(unittest.TestCase):
    def test_four_feature_owned_aliases_have_one_fixed_roster(self) -> None:
        reader = importlib.import_module("owned_pthread_timed_feature_contract_reader")
        self.assertEqual(
            reader.FEATURE_ALIASES,
            (
                ("pthread_cond_timedwait", "__pthread_cond_timedwait"),
                ("pthread_mutex_timedlock", "__pthread_mutex_timedlock"),
                ("pthread_timedjoin_np", "__pthread_timedjoin_np"),
                ("pthread_tryjoin_np", "__pthread_tryjoin_np"),
            ),
        )
        self.assertEqual(reader.ARCHIVE_HIDDEN, tuple(provider for _, provider in reader.FEATURE_ALIASES))
        self.assertEqual(
            reader.MUSL_STATIC_PROVIDER_SHAPES["__pthread_timedjoin_np"],
            ("FUNC", "LOCAL", "DEFAULT"),
        )

    def test_feature_source_route_is_present_and_does_not_claim_a_build_invocation(self) -> None:
        reader = importlib.import_module("owned_pthread_timed_feature_contract_reader")
        record = reader.evaluate_feature_source(ROOT)
        self.assertEqual(record["builder_argv_source"], ["--features", "x86-owned-static-runtime"])
        self.assertFalse(record["product_build_invocation_proven"])
        self.assertEqual(record["aliases"], [
            {"public": public, "provider": provider}
            for public, provider in reader.FEATURE_ALIASES
        ])

    def test_source_alias_mutation_is_rejected(self) -> None:
        reader = importlib.import_module("owned_pthread_timed_feature_contract_reader")
        scratch_root = ROOT / ".work" / "x86_64"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            copied = Path(temporary)
            for relative in reader.SOURCE_CONTRACT_PATHS:
                source = ROOT / relative
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            join_source = copied / "libc/src/c_abi/x86_64/pthread_create_join.rs"
            text = join_source.read_text(encoding="utf-8")
            self.assertIn(".set pthread_tryjoin_np, __pthread_tryjoin_np", text)
            join_source.write_text(
                text.replace(
                    ".set pthread_tryjoin_np, __pthread_tryjoin_np",
                    ".set pthread_tryjoin_np, __pthread_timedjoin_np",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(reader.ReceiptError):
                reader.evaluate_feature_source(copied)

    def test_feature_selection_sources_are_distinct_from_v1_alias_authority(self) -> None:
        reader = importlib.import_module("owned_pthread_timed_feature_contract_reader")
        self.assertTrue({
            "libc/Cargo.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "scripts/build_x86_64_owned_sysroot.py",
            "compat/x86_64/parity.toml",
        } <= set(reader.SOURCE_CONTRACT_PATHS))
        v1 = (ROOT / "compat/x86_64/owned_pthread_alias_contract_reader.py").read_text(encoding="utf-8")
        self.assertNotIn('("pthread_timedjoin_np", "__pthread_timedjoin_np")', v1)
        self.assertNotIn('("pthread_tryjoin_np", "__pthread_tryjoin_np")', v1)

    def test_image_tool_binding_rejects_invented_linker_path_digest_and_mode(self) -> None:
        reader = importlib.import_module("owned_pthread_timed_feature_contract_reader")
        scratch_root = ROOT / ".work" / "x86_64"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            work = Path(temporary)
            manifest_path = work / "trusted-image.json"
            invocation = "/opt/toolchain/ld.lld"
            payload = b"trusted-lld-bytes"
            manifest = {
                "schema": "crabc.x86_64-owned-pthread-timed-feature-image-inputs/v1",
                "image": reader.PINNED_IMAGE,
                "path": reader.IMAGE_PATH,
                "files": {
                    invocation: {
                        "path": invocation,
                        "sha256": __import__("hashlib").sha256(payload).hexdigest(),
                        "size": len(payload),
                        "mode": 0o755,
                    },
                },
            }
            manifest_bytes = (json.dumps(manifest, sort_keys=True) + "\n").encode()
            manifest_path.write_bytes(manifest_bytes)
            retained_name = reader._image_copy_path(invocation)
            retained = work / retained_name
            retained.parent.mkdir(parents=True)
            retained.write_bytes(payload)
            retained.chmod(0o755)
            artifacts = {retained_name: reader.artifact_record(work, retained)}
            record = {**manifest["files"][invocation], "retained": retained_name}
            old_path = reader.IMAGE_MANIFEST_PATH
            try:
                reader.IMAGE_MANIFEST_PATH = manifest_path
                git_files = {reader.IMAGE_MANIFEST_SOURCE: (0o644, manifest_bytes, False)}
                reader._validate_image_inputs(work, {invocation: record}, artifacts, git_files)
                for field, replacement in (("path", "/invented/ld.lld"), ("sha256", "0" * 64), ("mode", 0o644)):
                    forged = dict(record)
                    forged[field] = replacement
                    with self.assertRaises(reader.ReceiptError, msg=field):
                        reader._validate_image_inputs(work, {invocation: forged}, artifacts, git_files)
            finally:
                reader.IMAGE_MANIFEST_PATH = old_path


if __name__ == "__main__":
    unittest.main()
