#!/usr/bin/env python3
"""Semantic replay of retained native-shadow DSO evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as shared  # noqa: E402
import owned_native_allocator_dso_receipt as reader  # noqa: E402

SEAL = {"revision": "a" * 40, "worktree_sha256": "b" * 64}


def record(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


class OwnedNativeAllocatorDsoReceiptReaderTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_DSO_TEST_NATIVE") == "1", "requires source-built DSO receipt")
    def test_resealed_prior_checkout_product_is_rejected(self) -> None:
        latest = shared.receipt_directory(ROOT, reader.RUNNER)
        self.assertTrue((latest / "receipt.json").is_file(), "run the source-built DSO producer first")

        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            other = Path(temporary)
            (other / ".gitignore").write_text(".work/\n")
            (other / "source.c").write_text("int different_source(void) { return 1; }\n")
            subprocess.run(["git", "init", "-q", str(other)], check=True)
            subprocess.run(["git", "-C", str(other), "add", ".gitignore", "source.c"], check=True)
            subprocess.run(["git", "-C", str(other), "-c", "user.name=Receipt Test",
                            "-c", "user.email=receipt@example.invalid", "commit", "-qm", "source"], check=True)
            transplanted = shared.receipt_directory(other, reader.RUNNER)
            transplanted.parent.mkdir(parents=True)
            shutil.copytree(latest, transplanted)
            receipt_path = transplanted / "receipt.json"
            record = json.loads(receipt_path.read_text())
            record["source"] = shared.source_seal(other)
            receipt_path.write_text(json.dumps(record))

            shared.read_receipt(other, reader.RUNNER)
            with self.assertRaisesRegex(shared.ReceiptError, "dynamic product source"):
                reader.read_native_allocator_dso_receipt(other)

    def test_rehashed_omitted_mode_passes_shared_reader_but_fails_semantic_reader(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            root = Path(temporary)
            latest = shared.receipt_directory(root, reader.RUNNER)
            (latest / "logs").mkdir(parents=True)
            (latest / "products").mkdir()
            output = latest / "logs/oracle-pie.stdout"
            output.write_bytes(b"oracle\n")
            product = latest / "products/dynamic-loader"
            product.write_bytes(b"loader")
            data = {
                "canonical": True,
                "cases": [
                    {"id": "oracle-pie", "status": 0, "logs": {"oracle-pie.stdout": record(output)}},
                    {"id": "direct-non-pie", "status": 0, "logs": {"oracle-pie.stdout": record(output)}},
                ],
                "parameters": {"CASE_TIMEOUT": "30", "MODES": "pie,non-pie", "ENTRIES": "kernel,direct",
                               "DSOS": "initial,dlopen-plugin", "ENVIRONMENT": "empty-with-pinned-PATH"},
                "products": {"dynamic-loader": record(product)},
                "runner": reader.RUNNER,
                "schema": shared.SCHEMA,
                "source": SEAL,
                "work": ".work/x86_64/tmp/owned-native-allocator-dso.fake",
            }
            # A rewritten transcript can carry valid hashes while an executed
            # mode is omitted from the semantic roster.
            output.write_bytes(b"wrong transcript\n")
            data["cases"] = [case for case in data["cases"] if case["id"] != "direct-non-pie"]
            data["cases"][0]["logs"]["oracle-pie.stdout"] = record(output)
            (latest / "receipt.json").write_text(json.dumps(data))

            shared.read_receipt(root, reader.RUNNER, seal=SEAL)
            with self.assertRaisesRegex(shared.ReceiptError, "case roster"):
                reader.read_native_allocator_dso_receipt(root, seal=SEAL)


if __name__ == "__main__":
    unittest.main()
