"""Installed products must identify one production-capable allocator backend."""

import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import installed_allocator_backend as allocator
from installed_allocator_backend import selected_backend
from native_shadow_receipt import ReceiptError


class InstalledAllocatorBackendTests(unittest.TestCase):
    def test_existing_production_backends_agree(self) -> None:
        for backend in ("accepted-c", "native-shadow", "native"):
            self.assertEqual(selected_backend(backend, backend, backend), backend)

    def test_mixed_products_are_rejected(self) -> None:
        with self.assertRaisesRegex(ReceiptError, "disagree"):
            selected_backend("accepted-c", "native-shadow")

    def test_unknown_missing_and_evidence_only_backends_are_rejected(self) -> None:
        for backend in (None, "", "pinned-c-evidence", "unknown", {}, []):
            with self.subTest(backend=backend), self.assertRaisesRegex(ReceiptError, "unsupported"):
                selected_backend(backend)
        with self.assertRaisesRegex(ReceiptError, "unsupported"):
            selected_backend()


class InstalledAllocatorProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        upstream = self.root / "crabc-mimalloc/UPSTREAM.md"
        upstream.parent.mkdir()
        upstream.write_bytes(b"reviewed upstream source")
        self.marker = {"path": "crabc-mimalloc/UPSTREAM.md",
                       "sha256": hashlib.sha256(upstream.read_bytes()).hexdigest()}

    def test_accepted_c_requires_the_reviewed_pin_despite_matching_labels(self) -> None:
        state = {"allocator_backend": "accepted-c"}
        for pin in (None, {}, allocator.products.C_ALLOCATOR_PIN | {"checksum": "0" * 64}):
            provenance = state | {"accepted_allocator": pin, "native_allocator": None}
            with self.subTest(pin=pin), self.assertRaisesRegex(ReceiptError, "accepted allocator source"):
                allocator.dynamic_backend(self.root, state, provenance)
        provenance = state | {"accepted_allocator": dict(allocator.products.C_ALLOCATOR_PIN),
                              "native_allocator": None}
        self.assertEqual(allocator.dynamic_backend(self.root, state, provenance), "accepted-c")
        provenance["native_allocator"] = self.marker
        with self.assertRaisesRegex(ReceiptError, "native allocator source"):
            allocator.dynamic_backend(self.root, state, provenance)

    def test_runner_preflight_validates_provenance_before_printing_the_backend(self) -> None:
        state = self.root / "state.json"
        dynamic = self.root / "dynamic.json"
        manifest = self.root / "manifest.json"
        static = self.root / "static.json"
        state.write_text(json.dumps({"allocator_backend": "accepted-c"}))
        manifest.write_text(state.read_text())
        dynamic.write_text(json.dumps({"allocator_backend": "accepted-c",
                                       "accepted_allocator": allocator.products.C_ALLOCATOR_PIN,
                                       "native_allocator": None}))
        static.write_text(json.dumps({"allocator_backend": {"crate": allocator.products.C_ALLOCATOR_PIN}}))
        for paths in ((state, dynamic), (manifest, static, state, dynamic)):
            command = [sys.executable, "-B", allocator.__file__, *map(str, paths)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "accepted-c\n", ""))
        dynamic.write_text(json.dumps({"allocator_backend": "accepted-c", "accepted_allocator": None}))
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        self.assertIn("accepted allocator source", result.stderr)

    def test_both_rust_backends_require_the_actual_source_marker(self) -> None:
        for backend in allocator.products.NATIVE_ALLOCATOR_BACKENDS:
            state = {"allocator_backend": backend}
            for marker in (None, {}, self.marker | {"sha256": "0" * 64},
                           self.marker | {"path": "other/UPSTREAM.md"}):
                provenance = state | {"native_allocator": marker, "accepted_allocator": None}
                with self.subTest(backend=backend, marker=marker):
                    with self.assertRaisesRegex(ReceiptError, "native allocator source"):
                        allocator.dynamic_backend(self.root, state, provenance)
            provenance = state | {"native_allocator": dict(self.marker), "accepted_allocator": None}
            self.assertEqual(allocator.dynamic_backend(self.root, state, provenance), backend)
            (self.root / self.marker["path"]).write_bytes(b"substituted source")
            with self.assertRaisesRegex(ReceiptError, "native allocator source"):
                allocator.dynamic_backend(self.root, state, provenance)
            (self.root / self.marker["path"]).write_bytes(b"reviewed upstream source")
