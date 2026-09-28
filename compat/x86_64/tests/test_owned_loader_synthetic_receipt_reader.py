#!/usr/bin/env python3
"""Semantic replay of retained synthetic-loader evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as shared  # noqa: E402
import owned_loader_synthetic_receipt as reader  # noqa: E402

SEAL = {"revision": "a" * 40, "worktree_sha256": "b" * 64}


def file_record(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


class OwnedLoaderSyntheticReceiptReaderTests(unittest.TestCase):
    def test_rehashed_omitted_workload_passes_shared_reader_but_fails_semantic_reader(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            root = Path(temporary)
            latest = shared.receipt_directory(root, reader.RUNNER)
            (latest / "logs").mkdir(parents=True)
            (latest / "products").mkdir()
            product = latest / "products/dynamic-loader"
            product.write_bytes(b"loader")
            report = latest / "logs/report.json"
            report.write_text(json.dumps({"selected": ["nested-needed", "weak-strong"],
                                          "cases": {"nested-needed": {"status": "pass"},
                                                    "weak-strong": {"status": "pass"}}}))
            nested = latest / "logs/nested.stdout"
            nested.write_bytes(b"nested=42\n")
            receipt = {
                "canonical": True,
                "cases": [
                    {"id": "nested-needed", "status": 0, "logs": {"nested.stdout": file_record(nested)}},
                    {"id": "weak-strong", "status": 0, "logs": {"nested.stdout": file_record(nested)}},
                    {"id": "runner", "status": 0, "logs": {"report.json": file_record(report)}},
                ],
                "parameters": {"BACKEND": "native-shadow", "CASES": "21-frozen",
                               "CASE_TIMEOUT": "20", "ORACLE": "pinned-musl",
                               "PRODUCT": "supplied-dynamic-sysroot"},
                "products": {"dynamic-loader": file_record(product)},
                "runner": reader.RUNNER,
                "schema": shared.SCHEMA,
                "source": SEAL,
                "work": ".work/x86_64/owned-loader-synthetic.fake",
            }
            # A report and receipt can be rewritten with matching digests while
            # still omitting a required workload.
            report.write_text(json.dumps({"selected": ["nested-needed"],
                                          "cases": {"nested-needed": {"status": "pass"}}}))
            receipt["cases"] = [case for case in receipt["cases"] if case["id"] != "weak-strong"]
            receipt["cases"][-1]["logs"]["report.json"] = file_record(report)
            (latest / "receipt.json").write_text(json.dumps(receipt))

            shared.read_receipt(root, reader.RUNNER, seal=SEAL)
            with self.assertRaisesRegex(shared.ReceiptError, "workload roster"):
                reader.read_loader_synthetic_receipt(root, seal=SEAL)


if __name__ == "__main__":
    unittest.main()
