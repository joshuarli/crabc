#!/usr/bin/env python3
"""The locale receipt reader replays retained component semantics."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_locale_component_receipt.py"


def load_module():
    spec = importlib.util.spec_from_file_location("owned_locale_component_receipt_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class OwnedLocaleComponentReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def setUp(self) -> None:
        (ROOT / ".work/x86_64/tmp").mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-locale-reader.", dir=ROOT / ".work/x86_64/tmp")
        self.root = Path(self.temporary.name)
        self.work = self.root / ".work/x86_64/owned-locale-products.fixture"
        self.work.mkdir(parents=True)
        self.probe = self.write("compat/x86_64/owned_locale_probe.c", b"probe\n")
        self.runner = self.write("compat/x86_64/run_owned_locale.sh", b"runner\n")
        self.reader = self.write("compat/x86_64/owned_locale_component_receipt.py", b"reader\n")
        self.dynamic = self.mkdir(".work/x86_64/dynamic")
        self.static = self.mkdir(".work/x86_64/static")
        self.workload = self.write_elf(".work/x86_64/owned-locale-products.fixture/workload.o", etype=1)
        self.oracle = self.write(".work/x86_64/owned-locale-products.fixture/oracle", b"oracle\n")
        self.static_executable = self.write_elf(".work/x86_64/owned-locale-products.fixture/static", etype=2)
        self.static_pie_executable = self.write_elf(".work/x86_64/owned-locale-products.fixture/static-pie", etype=3)
        self.dynamic_pie = self.write_elf(".work/x86_64/owned-locale-products.fixture/dynamic-pie", etype=3)
        self.dynamic_non_pie = self.write_elf(".work/x86_64/owned-locale-products.fixture/dynamic-non-pie", etype=2)
        self.tools = {name: self.identity(self.write(f".work/x86_64/{name}", name.encode()))
                      for name in ("oracle-tool", "dynamic-driver", "compiler", "linker", "static-driver")}
        self.tool_roster = {
            "oracle": self.tools["oracle-tool"], "dynamic_driver": self.tools["dynamic-driver"],
            "compiler": self.tools["compiler"], "linker": self.tools["linker"],
            "static_driver": self.tools["static-driver"],
        }
        source_records = {name: {**self.identity(path), "mode": stat.S_IMODE(path.stat().st_mode)}
                          for name, path in (("probe", self.probe), ("runner", self.runner), ("reader", self.reader))}
        self.seal = {
            "sources": source_records,
            "dynamic": {"path": self.relative(self.dynamic), "manifest": self.identity(self.write(".work/x86_64/dynamic/manifest", b"dynamic\n")), "tree": {}},
            "static": {"path": self.relative(self.static), "manifest": self.identity(self.write(".work/x86_64/static/manifest", b"static\n")), "tree": {}},
        }
        self.report = self.make_report("full-six-mode")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mkdir(self, relative: str) -> Path:
        path = self.root / relative
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write(self, relative: str, contents: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def write_elf(self, relative: str, *, etype: int) -> Path:
        header = bytearray(64)
        header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        header[16:18] = etype.to_bytes(2, "little")
        header[18:20] = (62).to_bytes(2, "little")
        return self.write(relative, bytes(header))

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def identity(self, path: Path) -> dict[str, object]:
        data = path.read_bytes()
        return {"path": self.relative(path), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    def raw(self, label: str, argv: list[str], *, stdout: bytes = b"", stderr: bytes = b"") -> dict[str, dict[str, object]]:
        values = {"argv": json.dumps(argv, separators=(",", ":")).encode() + b"\n", "stdout": stdout,
                  "stderr": stderr, "status": b"0\n"}
        return {name: self.identity(self.write(f".work/x86_64/owned-locale-products.fixture/{label}.{name}{'.json' if name == 'argv' else ''}", value))
                for name, value in values.items()}

    def make_report(self, mode: str) -> Path:
        module = self.module
        paths = {"root": self.root, "work": self.work, "probe": self.probe, "runner": self.runner,
                 "reader": self.reader, "static": self.static if mode == "full-six-mode" else None,
                 "dynamic": self.dynamic, "workload": self.workload, "oracle": self.oracle,
                 "executables": {"static": self.static_executable, "static-pie": self.static_pie_executable,
                                 "dynamic-pie": self.dynamic_pie, "dynamic-non-pie": self.dynamic_non_pie}}
        plan = module.command_plan(paths, self.tool_roster, mode)
        commands = {}
        for label, argv in plan.items():
            stderr = b""
            stdout = b""
            if label == "header-trace":
                stdout = b"# installed locale preprocessed source\n"
                stderr = b"\n".join((module.mounted(self.root, self.dynamic / "usr/include" / header).encode()
                                       for header in module.HEADERS)) + b"\n"
            if "copy-audit" in label:
                stdout = b"{}\n"
            if label == "oracle-run" or label.endswith("-run") or label.endswith("-kernel") or label.endswith("-direct"):
                stdout = module.ORACLE_STDOUT
            if label.endswith("-validate"):
                stdout = module.canonical(self.link_result(label.removesuffix("-validate")))
            commands[label] = self.raw(label, argv, stdout=stdout, stderr=stderr)
        for name, value in (("source-product-before", self.seal), ("source-product-after", self.seal),
                            ("tools-before", self.tool_roster), ("tools-after", self.tool_roster)):
            self.write(f".work/x86_64/owned-locale-products.fixture/{name}.json",
                       json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        source_paths = (self.probe, self.runner, self.reader, self.workload)
        before = self.write(
            ".work/x86_64/owned-locale-products.fixture/source-object-before.sha256",
            b"".join(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {module.mounted(self.root, item)}\n".encode()
                     for item in source_paths),
        )
        after = self.write(
            ".work/x86_64/owned-locale-products.fixture/source-object-after.txt",
            b"".join(f"{module.mounted(self.root, item)}: OK\n".encode() for item in source_paths),
        )
        for name in ("static", "static-pie", "dynamic-pie", "dynamic-non-pie"):
            if mode == "dynamic-only-four-cell-development" and name.startswith("static"):
                continue
            self.write(f".work/x86_64/owned-locale-products.fixture/{name}.product-link.json",
                       module.canonical(self.link_result(name)))
        payloads = {}
        for name in ("pie", "non-pie"):
            root = self.mkdir(f".work/x86_64/owned-locale-products.fixture/dynamic-{name}-root")
            self.write(f".work/x86_64/owned-locale-products.fixture/dynamic-{name}-root/consumer", b"consumer\n")
            record = self.write(f".work/x86_64/owned-locale-products.fixture/dynamic-{name}-execution-payload.json", b"{}\n")
            payloads[name] = {"record": self.identity(record),
                              "before": commands[f"dynamic-{name}-copy-audit-before"]["stdout"],
                              "after": commands[f"dynamic-{name}-copy-audit-after"]["stdout"]}
        links = {name: self.identity(self.root / f".work/x86_64/owned-locale-products.fixture/{name}.product-link.json")
                 for name in ("static", "static-pie", "dynamic-pie", "dynamic-non-pie")
                 if not (mode == "dynamic-only-four-cell-development" and name.startswith("static"))}
        record = {
            "schema": module.SCHEMA, "source_mount": module.SOURCE_MOUNT, "execution_mode": mode,
            "scope": list(module.SCOPE), "sources": self.seal["sources"], "workload": self.identity(self.workload),
            "products": {"dynamic": self.relative(self.dynamic), **({"static": self.relative(self.static)} if mode == "full-six-mode" else {})},
            "seals": {name: self.identity(self.work / f"{name}.json") for name in
                      ("source-product-before", "source-product-after", "tools-before", "tools-after")},
            "commands": commands, "links": links, "execution_payloads": payloads,
            "source_object_checks": {"before": self.identity(before), "after": self.identity(after)},
            "family_completion": False, "promotion_ready": False, "public_support": False,
        }
        path = self.work / "owned-locale-products.json"
        path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        return path

    def link_result(self, name: str) -> dict[str, object]:
        linkage = {"static": "static", "static-pie": "static-pie", "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}[name]
        product = self.static if linkage.startswith("static") else self.dynamic
        return {
            "linkage": linkage, "product": self.module.mounted(self.root, product), "product_format": "fixture",
            "product_manifest_sha256": "0" * 64, "workload_sha256": "0" * 64,
            "executable_sha256": "0" * 64, "receipt_sha256": "0" * 64,
        }

    def reconstructed_link(self, _root: Path, _mount: str, product: Path, _workload: Path, _executable: Path,
                           _receipt: Path, linkage: str, _linker: object) -> dict[str, object]:
        name = {"static": "static", "static-pie": "static-pie", "pie": "dynamic-pie", "non-pie": "dynamic-non-pie"}[linkage]
        value = self.link_result(name)
        value["product"] = str(product)
        return value

    def validate(self, *, require_static: bool = False) -> dict[str, object]:
        with mock.patch.object(self.module, "source_product_seal", return_value=self.seal), \
             mock.patch.object(self.module, "tool_roster", return_value=self.tool_roster), \
             mock.patch.object(self.module.products, "validate_retained_link", side_effect=self.reconstructed_link), \
             mock.patch.object(self.module.copies, "audit_execution_payload", return_value={}):
            return self.module.validate_report(self.root, self.report, require_static=require_static)

    def rewrite_identity(self, identity: dict[str, object]) -> None:
        path = self.root / str(identity["path"])
        identity.update(self.identity(path))

    def rewrite_report(self, record: dict[str, object]) -> None:
        self.report.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def report_value(self) -> dict[str, object]:
        return json.loads(self.report.read_text(encoding="utf-8"))

    def test_recomputed_identity_does_not_admit_changed_dynamic_link_argv(self) -> None:
        record = self.report_value()
        identity = record["commands"]["dynamic-pie-link"]["argv"]
        path = self.root / identity["path"]
        path.write_text(json.dumps(["garbage"], separators=(",", ":")) + "\n", encoding="utf-8")
        self.rewrite_identity(identity)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.LocaleReceiptError, "argv differs"):
            self.validate()

    def test_full_six_mode_control_reconstructs_before_negative_mutations(self) -> None:
        self.assertEqual(self.validate()["execution_mode"], "full-six-mode")

    def test_recomputed_identity_does_not_admit_garbage_candidate_output(self) -> None:
        record = self.report_value()
        identity = record["commands"]["dynamic-pie-kernel"]["stdout"]
        path = self.root / identity["path"]
        path.write_bytes(b"garbage\n")
        self.rewrite_identity(identity)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.LocaleReceiptError, "stdout differs from pinned musl"):
            self.validate()

    def test_recomputed_identity_does_not_admit_changed_product_link_validation(self) -> None:
        record = self.report_value()
        forged = self.module.canonical({"linkage": "pie", "product": "/workspace/forged"})
        link_identity = record["links"]["dynamic-pie"]
        (self.root / link_identity["path"]).write_bytes(forged)
        self.rewrite_identity(link_identity)
        stdout_identity = record["commands"]["dynamic-pie-validate"]["stdout"]
        (self.root / stdout_identity["path"]).write_bytes(forged)
        self.rewrite_identity(stdout_identity)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.LocaleReceiptError, "product-link differs"):
            self.validate()

    def test_recomputed_identity_does_not_admit_an_ambient_header_trace_origin(self) -> None:
        record = self.report_value()
        identity = record["commands"]["header-trace"]["stderr"]
        path = self.root / identity["path"]
        path.write_bytes(path.read_bytes() + b". /usr/include/ambient.h\n")
        self.rewrite_identity(identity)
        self.rewrite_report(record)
        with self.assertRaisesRegex(self.module.LocaleReceiptError, "ambient header origin"):
            self.validate()

    def test_checkout_contained_tool_identity_uses_the_pinned_workspace_spelling(self) -> None:
        tool = self.write(".work/x86_64/tool", b"tool\n")
        record = self.module.recorded_tool_identity(self.root, tool, "fixture tool")
        self.assertEqual(record["path"], self.module.mounted(self.root, tool))
        self.assertEqual(record["sha256"], hashlib.sha256(b"tool\n").hexdigest())

    def test_dynamic_only_replays_but_cannot_satisfy_static_requirement(self) -> None:
        self.report.unlink()
        self.report = self.make_report("dynamic-only-four-cell-development")
        self.validate()
        with self.assertRaisesRegex(self.module.LocaleReceiptError, "requires static/static-pie"):
            self.validate(require_static=True)


if __name__ == "__main__":
    unittest.main()
