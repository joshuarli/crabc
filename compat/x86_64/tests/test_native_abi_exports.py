#!/usr/bin/env python3
"""Behavior checks for the reviewed native x86 export delta."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
        "target": "x86_64-unknown-linux-musl",
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
        target = patch.object(exports, "TARGET", "x86_64-unknown-linux-musl")
        target.start()
        self.addCleanup(target.stop)

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

    def test_arm_inventory_uses_reviewed_x86_delta(self) -> None:
        delta = json.loads(exports.ARM_STATIC_DELTA.read_text())
        original = report(shared_extra=[dynamic("tgkill")],
                          static_extra=[static(name) for name in delta["extra_remove"]],
                          static_missing=[static(name) for name in delta["missing_remove"]])
        self.seed(original)
        value = report(shared_extra=[dynamic("tgkill")],
                       static_extra=[static(name) for name in delta["extra_add"] + delta["anonymous_extra"]],
                       static_missing=[static(name) for name in delta["missing_add"] + delta["anonymous_missing"]])
        value["target"] = "aarch64-unknown-linux-musl"
        with patch.object(exports, "TARGET", "aarch64-unknown-linux-musl"):
            passed, output = self.check(value)
            self.assertTrue(passed, output)
            value["triage"]["static_archive"]["extra"].append(static("anon.unreviewed"))
            passed, output = self.check(value)
            self.assertFalse(passed, output)
            self.assertIn("anon.unreviewed", output)
            value["triage"]["static_archive"]["extra"].pop()
            value["triage"]["static_archive"]["extra"].pop()
            passed, output = self.check(value)
            self.assertFalse(passed, output)
            self.assertIn("static_archive.extra", output)
            value["triage"]["shared_dynamic"]["extra"] = []
            passed, output = self.check(value)
            self.assertFalse(passed, output)
            self.assertIn("shared_dynamic.extra", output)

    def test_arm_update_recollects_only_anonymous_rosters(self) -> None:
        delta = json.loads(exports.ARM_STATIC_DELTA.read_text())
        original = report(shared_extra=[dynamic("tgkill")],
                          static_extra=[static(name) for name in delta["extra_remove"]],
                          static_missing=[static(name) for name in delta["missing_remove"]])
        self.seed(original)
        value = report(shared_extra=[dynamic("tgkill")],
                       static_extra=[static(name) for name in delta["extra_add"]] + [static("anon.renamed.0.llvm.7")],
                       static_missing=[static(name) for name in delta["missing_add"]])
        value["target"] = "aarch64-unknown-linux-musl"
        path = self.root / "arm-report.json"
        path.write_text(json.dumps(value))
        arm_delta = self.root / "arm-delta.json"
        arm_delta.write_text(json.dumps(delta))
        with patch.object(exports, "TARGET", "aarch64-unknown-linux-musl"), \
                patch.object(exports, "ARM_STATIC_DELTA", arm_delta):
            self.assertFalse(self.check(value)[0])
            exports.update(path, tracked_path=self.tracked_path)
            updated = json.loads(arm_delta.read_text())
            self.assertEqual(updated["anonymous_extra"], ["anon.renamed.0.llvm.7"])
            self.assertEqual(updated["anonymous_missing"], [])
            self.assertEqual({key: updated[key] for key in updated if not key.startswith("anonymous_")},
                             {key: delta[key] for key in delta if not key.startswith("anonymous_")})
            self.assertTrue(self.check(value)[0])
            value["triage"]["static_archive"]["extra"].append(static("unreviewed_named"))
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(exports.ExportsError, "named export delta differs"):
                exports.update(path, tracked_path=self.tracked_path)

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

    def test_llvm_promotion_suffix_of_anonymous_static_extra_is_ignored(self) -> None:
        self.seed(report(static_extra=[static("owned"), static("anon.0b65.0.llvm.18065665657365612692")]))
        passed, output = self.check(report(static_extra=[static("owned"), static("anon.0b65.0.llvm.17626645863537651630")]))
        self.assertTrue(passed, output)
        passed, output = self.check(report(static_extra=[static("owned"), static("anon.0b65.1.llvm.17626645863537651630")]))
        self.assertFalse(passed, output)
        self.assertIn("anon.0b65.1", output)
        passed, output = self.check(report(static_extra=[static("owned")]))
        self.assertFalse(passed, output)
        self.assertIn("anon.0b65.0", output)

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
