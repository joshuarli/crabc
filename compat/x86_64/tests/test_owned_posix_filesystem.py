#!/usr/bin/env python3
"""Composition and same-object contracts for installed POSIX filesystem APIs."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CARGO = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
COMPAT = ROOT / "libc" / "src" / "compat_exports.rs"
DIRECTORY = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "directory_streams.rs"
TRAVERSAL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_traversal.rs"
HANDLES = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "file_handles.rs"
TEMPORARY_NAMES = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "temporary_names.rs"
OWNED_FILESYSTEM = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_filesystem_mechanisms.rs"
QUALIFICATION = ROOT / "compat" / "x86_64" / "owned_dynamic_qualification.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_posix_filesystem.sh"
PROBE = ROOT / "compat" / "x86_64" / "owned_posix_filesystem_probe.c"
AUDITOR = ROOT / "compat" / "x86_64" / "owned_posix_filesystem_audit.py"
DOCUMENT = ROOT / "compat" / "x86_64" / "owned-posix-filesystem.md"


def load_auditor():
    spec = importlib.util.spec_from_file_location("owned_posix_filesystem_audit", AUDITOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OwnedPosixFilesystemTests(unittest.TestCase):
    @staticmethod
    def _write_file(root: Path, relative: str, contents: bytes) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def _write_static_product(self, root: Path, auditor) -> None:
        self._write_file(root, "bin/crabc-cc", b"static driver\n")
        self._write_file(root, "usr/include/stdio.h", b"/* owned */\n")
        for name in ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o"):
            self._write_file(root, f"usr/lib/{name}", name.encode("ascii"))
        self._write_file(root, "usr/lib/libc.a", b"owned static libc\n")
        self._write_file(root, "usr/lib/libcrabc-builtins.a", b"owned static builtins\n")
        files = {
            path.relative_to(root).as_posix(): auditor.digest(path)
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }
        manifest = {
            "schema": 1,
            "format": auditor.STATIC_FORMAT,
            "target": auditor.TARGET,
            "installed": {
                "headers": "usr/include",
                "crt_objects": [
                    "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/rcrt1.o",
                    "usr/lib/crti.o", "usr/lib/crtn.o",
                ],
                "static_libc": "usr/lib/libc.a",
                "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
                "sealed_static_driver": "bin/crabc-cc",
                "files": files,
            },
            "sealed_static_driver": {"format": auditor.STATIC_RECEIPT_FORMAT},
        }
        manifest_path = root / auditor.MANIFEST_RELATIVE
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def _write_dynamic_product(self, root: Path, auditor) -> None:
        self._write_file(root, "bin/crabc-cc-dynamic", b"dynamic driver\n")
        self._write_file(root, "usr/include/stdio.h", b"/* owned */\n")
        for name in (
            "libc.so", "crt1.o", "Scrt1.o", "crti.o", "crtn.o",
            "crabc-dynamic-attach.o", "libcrabc-builtins.a",
        ):
            self._write_file(root, f"usr/lib/{name}", name.encode("ascii"))
        self._write_file(root, "lib/ld-crabc-x86_64.so.1", b"owned loader\n")
        (root / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        files = {
            path.relative_to(root).as_posix(): auditor.digest(path)
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }
        manifest = {
            "schema": 1,
            "format": auditor.DYNAMIC_FORMAT,
            "target": auditor.TARGET,
            "files": files,
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        manifest_path = root / auditor.MANIFEST_RELATIVE
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def _write_static_receipt(
        self, auditor, product: Path, application: Path, candidate: Path, receipt: Path, linker: Path
    ) -> None:
        library = product / "usr/lib"
        map_path = receipt.with_suffix(".map")
        trace_path = receipt.with_suffix(".trace")
        map_path.write_text("owned static map\n", encoding="utf-8")
        trace_path.write_text(
            "\n".join(
                (
                    str(library / "crt1.o"), str(library / "crti.o"), str(application),
                    str(library / "libc.a") + "(member.o)",
                    str(library / "libcrabc-builtins.a") + "(member.o)",
                    str(library / "crtn.o"), "",
                )
            ),
            encoding="utf-8",
        )
        runtime = (
            ("crt-entry", library / "crt1.o"), ("crt-prologue", library / "crti.o"),
            ("libc", library / "libc.a"), ("builtins", library / "libcrabc-builtins.a"),
            ("crt-epilogue", library / "crtn.o"),
        )
        record = {
            "schema": 1,
            "format": auditor.STATIC_RECEIPT_FORMAT,
            "target": auditor.TARGET,
            "mode": {
                "id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o",
                "interpreter": "absent",
            },
            "resolved_linker": {"path": str(linker), "sha256": auditor.digest(linker)},
            "owned_link_contract": [
                "ld.lld", "-static", "--no-dynamic-linker", "--no-undefined", "--gc-sections",
                "-z", "relro", "-z", "now", "-e", "_start", str(library / "crt1.o"),
                str(library / "crti.o"), "<application-objects>", str(library / "libc.a"),
                str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", "<output>",
            ],
            "input_receipts": [
                {"role": role, "path": str(path.relative_to(product)), "sha256": auditor.digest(path)}
                for role, path in runtime
            ] + [{"role": "application", "path": str(application), "sha256": auditor.digest(application)}],
            "output": {"path": str(candidate), "sha256": auditor.digest(candidate)},
            "map": {"path": map_path.name, "sha256": auditor.digest(map_path)},
            "trace": {"path": trace_path.name, "sha256": auditor.digest(trace_path)},
        }
        receipt.write_text(json.dumps(record), encoding="utf-8")

    def _write_dynamic_receipt(
        self, auditor, product: Path, application: Path, candidate: Path, receipt: Path, linker: Path
    ) -> None:
        library = product / "usr/lib"
        entry = library / "Scrt1.o"
        attach = library / "crabc-dynamic-attach.o"
        prologue = library / "crti.o"
        libc = library / "libc.so"
        builtins = library / "libcrabc-builtins.a"
        epilogue = library / "crtn.o"
        runtime = [prologue, libc, epilogue, entry, attach]
        record = {
            "schema": 1,
            "format": auditor.DYNAMIC_FORMAT,
            "mode": "pie",
            "binding": "now",
            "runtime_imports": [],
            "application_dsos": {},
            "application_runpath": "/usr/lib",
            "resolved_linker": {"path": str(linker), "sha256": auditor.digest(linker)},
            "input_receipts": [
                {"path": str(path), "sha256": auditor.digest(path)} for path in runtime
            ] + [
                {"path": str(application), "sha256": auditor.digest(application)},
                {"path": str(builtins), "sha256": auditor.digest(builtins)},
            ],
            "owned_runtime_inputs": sorted(
                path.relative_to(product).as_posix() for path in [*runtime, builtins]
            ),
            "manifest_sha256": auditor.digest(product / auditor.MANIFEST_RELATIVE),
            "output_path": str(candidate),
            "output_sha256": auditor.digest(candidate),
            "link_command": [
                str(linker), "-pie", "--hash-style=sysv", "-z", "relro", "-z", "now", "-z",
                "noexecstack", "-z", "text", "--no-undefined", "--allow-shlib-undefined",
                "--enable-new-dtags", "-rpath", "/usr/lib", "--dynamic-linker",
                auditor.DYNAMIC_INTERPRETER, str(entry), str(attach), str(prologue),
                str(application), str(libc), str(builtins), str(epilogue), "-o", str(candidate),
            ],
            "link_trace": [
                str(entry), str(attach), str(prologue), str(application), str(libc) + "(member.o)",
                str(builtins) + "(member.o)", str(epilogue),
            ],
        }
        receipt.write_text(json.dumps(record), encoding="utf-8")

    def test_receipt_auditor_is_a_separate_testable_boundary(self) -> None:
        auditor = load_auditor()
        self.assertTrue(callable(auditor.audit_static_receipt))
        self.assertTrue(callable(auditor.audit_dynamic_receipt))
        self.assertTrue(callable(auditor.validate_static_product))
        self.assertTrue(callable(auditor.validate_dynamic_product))

    def test_product_payload_tampering_is_rejected_before_receipt_audit(self) -> None:
        auditor = load_auditor()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            for name, populate, validate, payload in (
                ("static", self._write_static_product, auditor.validate_static_product, "usr/lib/libc.a"),
                ("dynamic", self._write_dynamic_product, auditor.validate_dynamic_product, "usr/lib/libc.so"),
            ):
                with self.subTest(name=name):
                    product = workspace / name
                    populate(product, auditor)
                    validate(product)
                    (product / payload).write_bytes(b"tampered\n")
                    with self.assertRaisesRegex(auditor.AuditError, "payload hash drifted"):
                        validate(product)

    def test_static_receipt_rejects_forged_workload_hash_and_trace(self) -> None:
        auditor = load_auditor()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            product = workspace / "static"
            self._write_static_product(product, auditor)
            application = self._write_file(workspace, "workload.o", b"object\n")
            candidate = self._write_file(workspace, "consumer", b"consumer\n")
            linker = self._write_file(workspace, "ld.lld", b"linker\n")
            receipt = workspace / "consumer.receipt.json"
            self._write_static_receipt(auditor, product, application, candidate, receipt, linker)
            auditor.audit_static_receipt(product, "static", application, candidate, receipt)

            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["input_receipts"][-1]["sha256"] = "0" * 64
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(auditor.AuditError, "input_receipts drifted"):
                auditor.audit_static_receipt(product, "static", application, candidate, receipt)

            self._write_static_receipt(auditor, product, application, candidate, receipt, linker)
            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["input_receipts"][0]["path"] = "usr/lib/foreign-crt.o"
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(auditor.AuditError, "input_receipts drifted"):
                auditor.audit_static_receipt(product, "static", application, candidate, receipt)

            self._write_static_receipt(auditor, product, application, candidate, receipt, linker)
            trace_path = receipt.with_suffix(".trace")
            trace_path.write_text("/ambient/foreign.o\n", encoding="utf-8")
            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["trace"]["sha256"] = auditor.digest(trace_path)
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(auditor.AuditError, "link trace escaped"):
                auditor.audit_static_receipt(product, "static", application, candidate, receipt)

    def test_dynamic_receipt_rejects_forged_dso_and_trace(self) -> None:
        auditor = load_auditor()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            product = workspace / "dynamic"
            self._write_dynamic_product(product, auditor)
            application = self._write_file(workspace, "workload.o", b"object\n")
            candidate = self._write_file(workspace, "consumer", b"consumer\n")
            linker = self._write_file(workspace, "ld.lld", b"linker\n")
            receipt = workspace / "consumer.crabc-link.json"
            self._write_dynamic_receipt(auditor, product, application, candidate, receipt, linker)
            auditor.audit_dynamic_receipt(product, "pie", application, candidate, receipt)

            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["runtime_imports"] = ["forged_import"]
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(auditor.AuditError, "runtime_imports drifted"):
                auditor.audit_dynamic_receipt(product, "pie", application, candidate, receipt)

            self._write_dynamic_receipt(auditor, product, application, candidate, receipt, linker)
            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["application_dsos"] = {"forged.so": "0" * 64}
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(auditor.AuditError, "application_dsos drifted"):
                auditor.audit_dynamic_receipt(product, "pie", application, candidate, receipt)

            self._write_dynamic_receipt(auditor, product, application, candidate, receipt, linker)
            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["link_trace"][-1] = "/ambient/foreign.o"
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(auditor.AuditError, "link trace escaped"):
                auditor.audit_dynamic_receipt(product, "pie", application, candidate, receipt)

    def test_owned_runtime_selects_existing_file_handle_and_temporary_name_leaves(self) -> None:
        manifest = CARGO.read_text(encoding="utf-8")
        aggregate = manifest.split("x86-owned-static-runtime = [", 1)[1].split("]", 1)[0]
        self.assertIn('"x86-file-handles",', aggregate)
        self.assertIn('"x86-temporary-names",', aggregate)

        root = STATIC_ROOT.read_text(encoding="utf-8")
        self.assertIn('#[cfg(feature = "x86-file-handles")]\n#[path = "file_handles.rs"]', root)
        self.assertIn('#[cfg(feature = "x86-temporary-names")]\n#[path = "temporary_names.rs"]', root)

    def test_source_owners_retain_the_pinned_musl_boundaries(self) -> None:
        compat = COMPAT.read_text(encoding="utf-8")
        for name in ("__xstat", "__lxstat", "__fxstat", "__fxstatat"):
            self.assertIn(f"fn {name}(", compat)

        directory = DIRECTORY.read_text(encoding="utf-8")
        for name in ("readdir_r", "telldir", "alphasort", "versionsort", "scandir"):
            self.assertIn(f"fn {name}(", directory)
        self.assertIn("src/dirent/scandir.c", directory)

        traversal = TRAVERSAL.read_text(encoding="utf-8")
        for source in ("src/legacy/ftw.c", "src/misc/nftw.c", "disable/walk/restore"):
            self.assertIn(source, traversal)
        self.assertIn("pthread_setcancelstate", traversal)

        handles = HANDLES.read_text(encoding="utf-8")
        for source in ("src/linux/name_to_handle_at.c", "src/linux/open_by_handle_at.c"):
            self.assertIn(source, handles)
        self.assertIn("caller-owned", handles)

        temporary = TEMPORARY_NAMES.read_text(encoding="utf-8")
        for source in ("src/stdio/tmpnam.c", "src/stdio/tempnam.c", "src/temp/__randname.c"):
            self.assertIn(source, temporary)
        self.assertIn("inherently racy", temporary)

        owned_filesystem = OWNED_FILESYSTEM.read_text(encoding="utf-8")
        self.assertIn("src/stat/lchmod.c", owned_filesystem)
        self.assertIn("AT_SYMLINK_NOFOLLOW", owned_filesystem)

    def assert_static_replay_usage(self, *arguments: str) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_static_replay_parser_rejects_missing_empty_option_like_and_duplicate_arguments(self) -> None:
        for arguments in (
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "--another-option"),
            ("",),
            ("-dynamic-product",),
            ("--unknown-option",),
            ("dynamic-one", "dynamic-two"),
            ("--static-sysroot", "static-one", "--static-sysroot", "static-two"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_static_replay_usage(*arguments)

    def test_static_replay_parser_rejects_canonical_duplicate_product_paths(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            workspace = Path(temporary)
            product = workspace / "product"
            product.mkdir()
            alias = workspace / "product-alias"
            alias.symlink_to(product, target_is_directory=True)

            self.assert_static_replay_usage(
                "--static-sysroot", str(product), str(alias)
            )

    def test_runner_requires_one_installed_object_and_every_entry_mode(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "crabc-cc-dynamic\" --dynamic-pie",
            '"$work/workload.o"',
            "static static-pie",
            "pie non-pie",
            "kernel direct",
            "assert_posix_filesystem_symbols",
            "audit_consumer",
            "owned_posix_filesystem_audit.py",
            "audit-static",
            "audit-dynamic",
            "validate-dynamic-product",
            "validate-static-product",
            "--link-receipt",
            "name_to_handle_at",
            "open_by_handle_at",
            "PTHREAD_CANCELED",
            "payload hash and the canonical loader alias",
        ):
            self.assertIn(required, source)
        self.assertEqual(source.count('if [ -z "$provided_dynamic" ]; then'), 1)
        for required in (
            "provided_static=''",
            "dynamic_was_supplied=0",
            "--static-sysroot)",
            "-*|'')",
            '[ "$provided_static" = "$provided_dynamic" ]',
            'elif [ "$dynamic_was_supplied" -eq 0 ]; then',
            'static_product="$provided_static"',
            'validate-static-product "$static_product"',
        ):
            self.assertIn(required, source)

        probe = PROBE.read_text(encoding="utf-8")
        for required in (
            "extern int __xstat",
            "readdir_r",
            "scandir",
            "pthread_cancel",
            "pthread_testcancel",
            "mktemp",
            "tempnam",
            "name_to_handle_at",
            "open_by_handle_at",
            "AT_SYMLINK_NOFOLLOW",
            "directory_descriptor, \"relative\"",
            "validate_preorder_transcript",
            "raw `readdir` order",
            "handles raw name=",
            "valid non-null pathname and caller-owned storage",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("acceptable_unsupported", probe)
        self.assertNotIn("name_to_handle_at(AT_FDCWD, NULL", probe)
        self.assertNotIn("open_by_handle_at(-1, NULL", probe)

    def test_dynamic_qualification_replays_the_composed_runner(self) -> None:
        source = QUALIFICATION.read_text(encoding="utf-8")
        self.assertIn(
            '"posix-filesystem": ("run_owned_posix_filesystem.sh", None)',
            source,
        )

    def test_contract_documents_the_closed_receipt_and_allowed_walk_orders(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        for required in (
            "complete manifest payload",
            "single workload object and hash",
            "linker\ntrace",
            "two raw\nroot-sibling orders",
            "caller-owned,\nnon-null variable-sized storage",
            "raw return and `errno`",
            "canonical duplicate static/dynamic paths",
            "does not build or run a static product",
            "invokes neither producer",
        ):
            self.assertIn(required, document)
        self.assertNotIn("null-pointer", document)

    def test_supplied_product_escape_is_rejected_before_building(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            for arguments, expected in (
                ((str(ROOT),), "dynamic"),
                (("--static-sysroot", str(ROOT)), "static"),
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(RUNNER), *arguments],
                        env={**os.environ, "TMPDIR": temporary},
                        text=True,
                        capture_output=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"owned POSIX filesystem {expected} product must be a checkout .work directory",
                        result.stderr,
                    )
                    self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
