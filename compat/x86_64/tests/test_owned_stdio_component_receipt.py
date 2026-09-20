#!/usr/bin/env python3
"""Regression contract for the retained installed-stdio component receipt."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
READER_PATH = ROOT / "compat/x86_64/owned_stdio_component_receipt.py"
SPEC = importlib.util.spec_from_file_location("owned_stdio_component_receipt_test", READER_PATH)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)


def identity(root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


class ReceiptFixture:
    """Small physical receipt whose product/link boundaries are mocked alone.

    The reader itself still consumes physical argv, transcript, header, object,
    seal, tool and payload bytes.  The established product readers are patched
    only because a synthetic fixture cannot manufacture an owned ELF product.
    """

    def __init__(self, root: Path, *, static: bool = False) -> None:
        self.root = root
        self.checkout = root / "checkout"
        self.work = self.checkout / ".work" / "stdio"
        self.dynamic = root / "dynamic-product"
        self.static = root / "static-product"
        self.checkout.mkdir(parents=True)
        self.work.mkdir(parents=True)
        self.dynamic.mkdir()
        if static:
            self.static.mkdir()
        (self.dynamic / "bin").mkdir()
        (self.dynamic / "share/crabc").mkdir(parents=True)
        self.dynamic_driver = self.dynamic / "bin/crabc-cc-dynamic"
        self.dynamic_driver.write_bytes(b"dynamic driver\n")
        self.dynamic_driver.chmod(0o755)
        (self.dynamic / "share/crabc/manifest.json").write_bytes(b"dynamic manifest\n")
        if static:
            (self.static / "bin").mkdir()
            (self.static / "share/crabc").mkdir(parents=True)
            self.static_driver = self.static / "bin/crabc-cc"
            self.static_driver.write_bytes(b"static driver\n")
            self.static_driver.chmod(0o755)
            (self.static / "share/crabc/manifest.json").write_bytes(b"static manifest\n")
        self.probe = self.checkout / "compat/x86_64/owned_stdio_probe.c"
        self.runner = self.checkout / "compat/x86_64/run_owned_stdio.sh"
        self.probe.parent.mkdir(parents=True)
        self.probe.write_bytes(b"int selected_stdio_probe;\n")
        self.runner.write_bytes(b"#!/bin/sh\n")
        self.runner.chmod(0o755)
        self.reader = self.checkout / "compat/x86_64/owned_stdio_component_receipt.py"
        self.reader.write_bytes(b"# retained stdio receipt reader\n")
        self.object = self.work / "workload.o"
        self.object.write_bytes(b"ELF selected object\n")
        self.oracle = self.work / "oracle"
        self.oracle.write_bytes(b"oracle binary\n")
        self.tool = self.work / "tool"
        self.tool.write_bytes(b"tool\n")
        self.tool.chmod(0o755)
        helper = self.dynamic / "share/crabc/crabc_cc_static.py"
        helper.write_text(
            "def compiler():\n"
            f"    return {str(self.tool)!r}\n\n"
            "def linker():\n"
            f"    return {str(self.tool)!r}\n",
            encoding="utf-8",
        )
        self._write_raw(static)
        self._write_report(static)

    def write(self, name: str, body: bytes) -> Path:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def command(self, stem: str, argv: list[str], stdout: bytes = b"", stderr: bytes = b"", status: bytes = b"0\n") -> None:
        self.write(stem + ".argv.json", json.dumps(argv, separators=(",", ":")).encode() + b"\n")
        self.write(stem + ".stdout", stdout)
        self.write(stem + ".stderr", stderr)
        self.write(stem + ".status", status)

    def _write_raw(self, static: bool) -> None:
        source_seal = {
            "sources": {
                "probe": {"path": "compat/x86_64/owned_stdio_probe.c", "sha256": hashlib.sha256(self.probe.read_bytes()).hexdigest(), "mode": 0o644},
                "runner": {"path": "compat/x86_64/run_owned_stdio.sh", "sha256": hashlib.sha256(self.runner.read_bytes()).hexdigest(), "mode": 0o755},
                "reader": {"path": "compat/x86_64/owned_stdio_component_receipt.py", "sha256": hashlib.sha256(self.reader.read_bytes()).hexdigest(), "mode": 0o644},
            },
            "dynamic": {"path": str(self.dynamic), "manifest": {"path": str(self.dynamic / "share/crabc/manifest.json"), "sha256": hashlib.sha256((self.dynamic / "share/crabc/manifest.json").read_bytes()).hexdigest(), "size": (self.dynamic / "share/crabc/manifest.json").stat().st_size}, "tree": receipt.tree_identity(self.dynamic)},
        }
        if static:
            source_seal["static"] = {"path": str(self.static), "manifest": {"path": str(self.static / "share/crabc/manifest.json"), "sha256": hashlib.sha256((self.static / "share/crabc/manifest.json").read_bytes()).hexdigest(), "size": (self.static / "share/crabc/manifest.json").stat().st_size}, "tree": receipt.tree_identity(self.static)}
        encoded = json.dumps(source_seal, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.write("source-product-before.json", encoded)
        self.write("source-product-after.json", encoded)
        tool_record = lambda path: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size, "mode": stat.S_IMODE(path.stat().st_mode)}
        tools = {"oracle": tool_record(self.tool), "dynamic_driver": tool_record(self.dynamic_driver),
                 "compiler": tool_record(self.tool), "linker": tool_record(self.tool)}
        if static:
            tools["static_driver"] = tool_record(self.static_driver)
        encoded_tools = json.dumps(tools, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.write("tools-before.json", encoded_tools)
        self.write("tools-after.json", encoded_tools)
        header_prefix = str(self.dynamic / "usr/include")
        header_trace = b"".join((f". {header_prefix}/{name}\n".encode() for name in receipt.REQUIRED_HEADERS))
        header_source = (f'# 0 "{self.probe}"\nint main(int argc, char **argv) {{ return 0; }}\n').encode()
        self.command("header-trace", [str(self.tool), "-nostdinc", "-isystem", header_prefix, "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-std=c11", "-fPIE", "-E", "-H", str(self.probe)], stdout=header_source, stderr=header_trace)
        self.command("compile", [str(self.dynamic_driver), "--dynamic-pie", "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-fno-builtin", "-fno-stack-protector", "-c", str(self.probe), "-o", str(self.object)])
        self.command("oracle-link", [str(self.tool), "-std=c11", "-static", "-fno-pie", "-no-pie", str(self.object), "-o", str(self.oracle)])
        runtime_argv = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(self.oracle), str(self.work / "oracle-first"), str(self.work / "oracle-second"), str(self.work / "oracle-wide")]
        self.command("oracle-run", runtime_argv, b"owned-stdio-products-ok\n")
        for linkage in ("pie", "non-pie"):
            executable = self.work / ("dynamic-" + linkage)
            executable.write_bytes((linkage + " executable\n").encode())
            self.command("dynamic-" + linkage + "-link", [str(self.dynamic_driver), "--dynamic-" + linkage, "-std=c11", str(self.object), "-o", str(executable)])
            link = {"linkage": linkage, "product": str(self.dynamic), "product_format": "dynamic", "product_manifest_sha256": "d" * 64,
                    "workload_sha256": hashlib.sha256(self.object.read_bytes()).hexdigest(), "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "receipt_sha256": linkage[0] * 64}
            self.write("dynamic-" + linkage + ".product-link.json", json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            self.command("dynamic-" + linkage + "-validate", ["python3", "-B", "-", str(self.checkout), str(self.dynamic), str(self.object), str(executable), str(executable) + ".crabc-link.json", linkage], json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            payload = {"schema": "payload", "mode": linkage}
            record_path = self.write("dynamic-" + linkage + "-execution-payload.json", json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            root = self.work / ("dynamic-" + linkage + "-root")
            root.mkdir()
            (root / "consumer").write_bytes(executable.read_bytes())
            common = ["--product", str(self.dynamic), "--execution-root", str(root), "--source-consumer", str(executable),
                      "--execution-consumer", str(root / "consumer"), "--record", str(record_path)]
            self.command("dynamic-" + linkage + "-copy-before", ["python3", "-B", str(receipt.COPIES_PATH), "record", *common])
            for phase in ("before", "after"):
                self.command("dynamic-" + linkage + "-copy-audit-" + phase, ["python3", "-B", str(receipt.COPIES_PATH), "audit", *common], json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            for entry in ("kernel", "direct"):
                argv = (["chroot", str(root), "/consumer", "/scratch/first", "/scratch/second", "/scratch/wide"]
                        if entry == "kernel" else
                        ["chroot", str(root), "/lib/ld-crabc-x86_64.so.1", "/consumer", "/scratch/first", "/scratch/second", "/scratch/wide"])
                self.command("dynamic-" + linkage + "-" + entry, argv, b"owned-stdio-products-ok\n")
        if static:
            for linkage in ("static", "static-pie"):
                executable = self.work / linkage
                executable.write_bytes((linkage + " executable\n").encode())
                self.command(linkage + "-link", [str(self.static_driver), "-" + linkage, "--link-receipt", linkage + ".crabc-link.json", str(self.object), "-o", str(executable)])
                link = {"linkage": linkage, "product": str(self.static), "product_format": "static", "product_manifest_sha256": "s" * 64,
                        "workload_sha256": hashlib.sha256(self.object.read_bytes()).hexdigest(), "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "receipt_sha256": linkage[0] * 64}
                self.write(linkage + ".product-link.json", json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.command(linkage + "-validate", ["python3", "-B", "-", str(self.checkout), str(self.static), str(self.object), str(executable), str(self.work / (linkage + ".crabc-link.json")), linkage], json.dumps(link, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self.command(linkage + "-run", ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(executable), str(self.work / (linkage + "-first")), str(self.work / (linkage + "-second")), str(self.work / (linkage + "-wide"))], b"owned-stdio-products-ok\n")

    def _write_report(self, static: bool) -> None:
        commands = {}
        for argv in sorted(self.work.glob("*.argv.json")):
            stem = argv.name.removesuffix(".argv.json")
            commands[stem] = {part: identity(self.work, self.work / (stem + "." + suffix))
                              for part, suffix in (("argv", "argv.json"), ("stdout", "stdout"), ("stderr", "stderr"), ("status", "status"))}
        links = {name: identity(self.work, self.work / (name + ".product-link.json"))
                 for name in ("dynamic-pie", "dynamic-non-pie", "static", "static-pie")
                 if (self.work / (name + ".product-link.json")).exists()}
        payloads = {name: {part: identity(self.work, self.work / ("dynamic-" + name + suffix))
                           for part, suffix in (("record", "-execution-payload.json"), ("before", "-copy-audit-before.stdout"), ("after", "-copy-audit-after.stdout"))}
                    for name in ("pie", "non-pie")}
        self.report = {
            "schema": receipt.SCHEMA,
            "scope": list(receipt.SCOPE),
            "source": identity(self.checkout, self.probe),
            "workload": identity(self.work, self.object),
            "products": {"dynamic": str(self.dynamic), **({"static": str(self.static)} if static else {})},
            "seals": {name: identity(self.work, self.work / (name + ".json"))
                      for name in ("source-product-before", "source-product-after", "tools-before", "tools-after")},
            "object_seals": {},
            "commands": commands,
            "links": links,
            "execution_payloads": payloads,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        self.path = self.work / "owned-stdio-products.json"
        self.refresh_object_seals()
        self.write_report()

    def write_report(self) -> None:
        self.path.write_text(json.dumps(self.report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def refresh_object_seals(self) -> None:
        before = self.work / "source-object-before.sha256"
        after = self.work / "source-object-after.txt"
        before.write_bytes(b"".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n".encode() for path in (self.probe, self.runner, self.object)))
        after.write_bytes(b"".join(f"{path}: OK\n".encode() for path in (self.probe, self.runner, self.object)))
        self.report["object_seals"] = {"before": identity(self.work, before), "after": identity(self.work, after)}

    def refresh(self, *names: str) -> None:
        for name in names:
            if name == "commands":
                for argv in sorted(self.work.glob("*.argv.json")):
                    stem = argv.name.removesuffix(".argv.json")
                    self.report["commands"][stem] = {part: identity(self.work, self.work / (stem + "." + suffix))
                                                     for part, suffix in (("argv", "argv.json"), ("stdout", "stdout"), ("stderr", "stderr"), ("status", "status"))}
            elif name == "links":
                for stem in self.report["links"]:
                    self.report["links"][stem] = identity(self.work, self.work / (stem + ".product-link.json"))
            elif name == "payloads":
                for mode, values in self.report["execution_payloads"].items():
                    for part, suffix in (("record", "-execution-payload.json"), ("before", "-copy-audit-before.stdout"), ("after", "-copy-audit-after.stdout")):
                        values[part] = identity(self.work, self.work / ("dynamic-" + mode + suffix))
            elif name == "object_seals":
                self.refresh_object_seals()
            else:
                self.report["seals"][name] = identity(self.work, self.work / (name + ".json"))
        self.write_report()


class OwnedStdioComponentReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".work")
        self.root = Path(self.temporary.name)
        self.fixture = ReceiptFixture(self.root)
        self.patches = [
            mock.patch.object(receipt, "ORACLE_COMPILER", str(self.fixture.tool)),
            mock.patch.object(receipt.products, "_validate_dynamic_product", return_value=(self.fixture.dynamic / "manifest.json", {"bin/crabc-cc-dynamic": "d" * 64})),
            mock.patch.object(receipt.products, "_validate_static_product", return_value=(self.fixture.static / "manifest.json", {"bin/crabc-cc": "s" * 64})),
            mock.patch.object(receipt.products, "validate_link", side_effect=self._link),
            mock.patch.object(receipt.copies, "audit_execution_payload", side_effect=self._payload),
        ]
        for patch in self.patches:
            patch.start()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(lambda: [patch.stop() for patch in reversed(self.patches)])

    def _link(self, product: Path, workload: Path, executable: Path, _link_receipt: Path, linkage: str) -> dict[str, str]:
        stem = "dynamic-" + linkage if linkage in ("pie", "non-pie") else linkage
        return json.loads((self.fixture.work / (stem + ".product-link.json")).read_text())

    def _payload(self, _product: Path, _root: Path, _source: Path, _consumer: Path, record: Path) -> dict[str, object]:
        return json.loads(record.read_text())

    def validate(self, *, require_static: bool = False) -> dict[str, object]:
        return receipt.validate_report(self.fixture.path, self.fixture.checkout, require_static=require_static)

    def test_dynamic_development_receipt_reconstructs_exactly_four_cells(self) -> None:
        report = self.validate()
        self.assertEqual(report["matrix"], "dynamic-development")
        with self.assertRaisesRegex(receipt.ReceiptError, "supplied-static"):
            self.validate(require_static=True)

    def test_supplied_static_receipt_reconstructs_exactly_six_cells(self) -> None:
        self.fixture = ReceiptFixture(self.root / "static", static=True)
        self.patches[0].stop()
        self.patches[0] = mock.patch.object(receipt, "ORACLE_COMPILER", str(self.fixture.tool))
        self.patches[0].start()
        report = self.validate(require_static=True)
        self.assertEqual(report["matrix"], "supplied-static")

    def test_recomputed_hashes_cannot_substitute_compile_argv(self) -> None:
        path = self.fixture.work / "compile.argv.json"
        path.write_text(json.dumps(["wrong", "-c", str(self.fixture.probe), "-o", str(self.fixture.object)]) + "\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "compile argv"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_runtime_output(self) -> None:
        path = self.fixture.work / "dynamic-pie-kernel.stdout"
        path.write_bytes(b"forged success\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic pie kernel stdout"):
            self.validate()

    def test_recomputed_hashes_cannot_omit_a_required_installed_header(self) -> None:
        path = self.fixture.work / "header-trace.stderr"
        path.write_bytes(b". forged/header.h\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "header trace"):
            self.validate()

    def test_recomputed_hashes_cannot_trace_an_ambient_header(self) -> None:
        path = self.fixture.work / "header-trace.stderr"
        path.write_bytes(path.read_bytes() + b". /usr/include/stdio.h\n")
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "header trace escapes installed include tree"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_helper_selected_tools(self) -> None:
        replacement = self.fixture.work / "replacement-tool"
        replacement.write_bytes(b"replacement tool\n")
        replacement.chmod(0o755)
        replacement_record = {
            "path": str(replacement),
            "sha256": hashlib.sha256(replacement.read_bytes()).hexdigest(),
            "size": replacement.stat().st_size,
            "mode": stat.S_IMODE(replacement.stat().st_mode),
        }
        original_tools = {name: (self.fixture.work / name).read_bytes()
                          for name in ("tools-before.json", "tools-after.json")}
        header_argv = self.fixture.work / "header-trace.argv.json"
        original_header_argv = header_argv.read_bytes()
        for role in ("compiler", "linker"):
            for name, body in original_tools.items():
                (self.fixture.work / name).write_bytes(body)
            header_argv.write_bytes(original_header_argv)
            for name in ("tools-before.json", "tools-after.json"):
                path = self.fixture.work / name
                tools = json.loads(path.read_text())
                tools[role] = replacement_record
                path.write_text(json.dumps(tools, sort_keys=True, separators=(",", ":")) + "\n")
            if role == "compiler":
                argv = json.loads(header_argv.read_text())
                argv[0] = str(replacement)
                header_argv.write_text(json.dumps(argv, separators=(",", ":")) + "\n")
                self.fixture.refresh("commands")
            self.fixture.refresh("tools-before", "tools-after")
            with self.subTest(role=role):
                with self.assertRaisesRegex(receipt.ReceiptError, role + " tool path differs from sealed helper"):
                    self.validate()

    def test_recomputed_hashes_cannot_substitute_preprocessed_source(self) -> None:
        path = self.fixture.work / "header-trace.stdout"
        path.write_bytes(b'# 0 "forged.c"\nint main(void) { return 0; }\n')
        self.fixture.refresh("commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "preprocessed source"):
            self.validate()

    def test_recomputed_hashes_cannot_replace_the_shared_object(self) -> None:
        self.fixture.object.write_bytes(b"other ELF selected object\n")
        self.fixture.report["workload"] = identity(self.fixture.work, self.fixture.object)
        self.fixture.refresh_object_seals()
        self.fixture.write_report()
        with self.assertRaisesRegex(receipt.ReceiptError, "link workload identity"):
            self.validate()

    def test_recomputed_hashes_cannot_substitute_a_link_identity(self) -> None:
        path = self.fixture.work / "dynamic-pie.product-link.json"
        value = json.loads(path.read_text())
        value["product"] = str(self.root / "wrong-product")
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        validate = self.fixture.work / "dynamic-pie-validate.stdout"
        validate.write_bytes(path.read_bytes())
        self.fixture.refresh("links", "commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic pie link identity"):
            self.validate()

    def test_recomputed_hashes_cannot_replace_payload_audit(self) -> None:
        path = self.fixture.work / "dynamic-non-pie-copy-audit-after.stdout"
        path.write_bytes(b'{"mode":"forged","schema":"payload"}\n')
        self.fixture.refresh("payloads", "commands")
        with self.assertRaisesRegex(receipt.ReceiptError, "payload audit"):
            self.validate()

    def test_reader_rejects_a_symlink_hop_before_opening_the_report(self) -> None:
        alias = self.root / "receipt-link"
        alias.symlink_to(self.fixture.path)
        with self.assertRaisesRegex(receipt.ReceiptError, "symlink"):
            receipt.validate_report(alias, self.fixture.checkout)


if __name__ == "__main__":
    unittest.main()
