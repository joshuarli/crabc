#!/usr/bin/env python3
"""Behavior checks for the reviewed native x86 export delta."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import native_abi_exports as exports  # noqa: E402
import native_abi_inventory as inventory  # noqa: E402


def dynamic(
    name: str,
    *,
    symbol_type: str = "FUNC",
    binding: str = "GLOBAL",
    visibility: str = "DEFAULT",
    version: str | None = None,
    version_default: bool = False,
    size: str = "8",
) -> dict[str, object]:
    return {
        "name": name,
        "type": symbol_type,
        "binding": binding,
        "visibility": visibility,
        "version": version,
        "version_default": version_default,
        "size": size,
        "value": "0000000000000010",
        "section_index": "12",
    }


def static(name: str, nm_type: str = "T") -> dict[str, object]:
    return {"name": name, "nm_type": nm_type, "count": 1}


def report(
    *,
    shared_extra: list[dict[str, object]] | None = None,
    shared_missing: list[dict[str, object]] | None = None,
    static_extra: list[dict[str, object]] | None = None,
    static_missing: list[dict[str, object]] | None = None,
    measurement: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema": inventory.SCHEMA,
        "target": inventory.TARGET,
        "triage": {
            "shared_dynamic": {
                "extra": shared_extra or [],
                "missing": shared_missing or [],
                "compatibility_differences": [],
                "data_size_differences": [],
                "version_differences": [],
                "measurement_differences": measurement or [],
            },
            "static_archive": {
                "extra": static_extra or [],
                "missing": static_missing or [],
                "class_differences": [],
            },
            "disposition": "test",
        },
    }


class NativeAbiExportsTests(unittest.TestCase):
    def setUp(self) -> None:
        work = ROOT / ".work/x86_64/native-abi-exports-tests"
        work.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.report_path = self.root / "report.json"
        self.tracked_path = self.root / "tracked.json"

    def write(self, value: dict[str, object]) -> None:
        self.report_path.write_text(json.dumps(value), encoding="utf-8")

    def seed(self, value: dict[str, object]) -> None:
        self.write(value)
        exports.update(self.report_path, tracked_path=self.tracked_path)

    def check(self, value: dict[str, object]) -> tuple[bool, str]:
        self.write(value)
        stream = io.StringIO()
        passed = exports.check(self.report_path, tracked_path=self.tracked_path, stream=stream)
        return passed, stream.getvalue()

    def test_equal_projection_passes(self) -> None:
        value = report(shared_extra=[dynamic("tgkill")], static_extra=[static("owned")])
        self.seed(value)
        passed, output = self.check(value)
        self.assertTrue(passed, output)
        self.assertIn("match", output)

    def test_new_static_extra_fails(self) -> None:
        self.seed(report(static_extra=[static("owned")]))
        passed, output = self.check(report(static_extra=[static("owned"), static("mi_malloc")]))
        self.assertFalse(passed)
        self.assertIn("static_archive.extra", output)
        self.assertIn("mi_malloc", output)

    def test_removed_dynamic_export_fails(self) -> None:
        self.seed(report(shared_extra=[dynamic("tgkill")]))
        passed, output = self.check(report())
        self.assertFalse(passed)
        self.assertIn("shared_dynamic.extra", output)
        self.assertIn("tgkill", output)

    def test_changed_binding_fails(self) -> None:
        self.seed(report(shared_extra=[dynamic("tgkill")]))
        passed, output = self.check(report(shared_extra=[dynamic("tgkill", binding="WEAK")]))
        self.assertFalse(passed)
        self.assertIn("shared_dynamic.extra", output)
        self.assertIn("WEAK", output)

    def test_rust_v0_mangled_static_extra_is_ignored(self) -> None:
        self.seed(report(static_extra=[static("owned")]))
        passed, output = self.check(
            report(static_extra=[static("owned"), static("_Rchurn636"), static("_Rchurn123")])
        )
        self.assertTrue(passed, output)
        self.assertNotIn("_Rchurn", self.tracked_path.read_text(encoding="utf-8"))

    def test_measurement_differences_are_not_gated(self) -> None:
        self.seed(report(shared_extra=[dynamic("tgkill")]))
        passed, output = self.check(
            report(
                shared_extra=[dynamic("tgkill", size="999")],
                measurement=[{"key": {"name": "tgkill", "version": None, "version_default": False}}],
            )
        )
        self.assertTrue(passed, output)


if __name__ == "__main__":
    unittest.main()
