#!/usr/bin/env python3
"""Retained policy evidence must reconstruct the executed musl comparison."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipt
import owned_native_allocator_policy_receipt as policy


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf(kind: int, interpreter: str | None = None) -> bytes:
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, kind, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    if interpreter:
        encoded = interpreter.encode() + b"\0"
        struct.pack_into("<I", data, 64, 3)
        struct.pack_into("<Q", data, 72, 128)
        struct.pack_into("<Q", data, 96, len(encoded))
        data[128:128 + len(encoded)] = encoded
    return bytes(data)


class PolicyReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for command in (("init", "-q"), ("config", "user.email", "t@example.invalid"),
                        ("config", "user.name", "t")):
            subprocess.run(("git", *command), cwd=self.root, check=True)
        (self.root / ".gitignore").write_text(".work/\n")
        (self.root / "source.c").write_text("int main(void) { return 0; }\n")
        for program, relative in policy.SOURCE_PATHS.items():
            source = self.root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(f"int {program}(void) {{ return 0; }}\n")
        upstream = self.root / "crabc-mimalloc/UPSTREAM.md"
        upstream.parent.mkdir()
        upstream.write_text("fixed upstream allocator\n")
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-qm", "base"), cwd=self.root, check=True)
        self.work = self.root / ".work/x86_64/tmp/policy"
        self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self, *, missing_case: str = "", missing_product: str = "",
                differing_mode: str = "", stderr_mode: str = "",
                bad_archive: bool = False, bad_source_digest: bool = False,
                wrong_elf_mode: bool = False, bad_link_input: bool = False,
                bad_dynamic_input: bool = False, bad_oracle_compiler: bool = False,
                bad_probe_source: bool = False) -> Path:
        files: dict[str, Path] = {}

        def product(name: str, data: bytes) -> None:
            path = self.work / name
            path.write_bytes(data)
            files[name] = path

        def record(name: str, value: dict) -> None:
            product(name, json.dumps(value, sort_keys=True).encode())

        for program, relative in policy.SOURCE_PATHS.items():
            product(f"source-{program}", (b"substituted source\n" if bad_probe_source and program == "policy"
                                           else (self.root / relative).read_bytes()))
        for name in policy.SYSROOT_PRODUCTS - {
            "static-manifest", "static-libc-provenance", "static-libc-archive",
            "dynamic-manifest", "dynamic-product-state", "dynamic-libc-provenance",
            "dynamic-libc", "dynamic-loader",
        }:
            product(name, name.encode())

        product("static-libc-archive", b"archive")
        product("dynamic-libc", b"shared-libc")
        product("dynamic-loader", b"loader")
        upstream_hash = digest(self.root / "crabc-mimalloc/UPSTREAM.md")
        product("static-libc-provenance", json.dumps({
            "archive": {"sha256": "0" * 64 if bad_archive else digest(files["static-libc-archive"])},
            "allocator_backend": {"upstream_sha256": upstream_hash},
        }).encode())
        product("dynamic-libc-provenance", json.dumps({
            "allocator_backend": "native-shadow",
            "native_allocator": {"path": "crabc-mimalloc/UPSTREAM.md", "sha256": upstream_hash},
        }).encode())
        product("static-manifest", json.dumps({
            "allocator_backend": "native-shadow", "installed": {"files": {
                "usr/lib/libc.a": digest(files["static-libc-archive"]),
                "share/crabc/libc-static.provenance.json": digest(files["static-libc-provenance"]),
                **{path: digest(files[name]) for name, path in {
                    "static-driver": "bin/crabc-cc", "static-crt1": "usr/lib/crt1.o",
                    "static-rcrt1": "usr/lib/rcrt1.o", "static-crti": "usr/lib/crti.o",
                    "static-crtn": "usr/lib/crtn.o", "static-builtins": "usr/lib/libcrabc-builtins.a",
                }.items()},
            }},
        }).encode())
        dynamic_files = {
            "usr/lib/libc.so": digest(files["dynamic-libc"]),
            "lib/ld-crabc-x86_64.so.1": digest(files["dynamic-loader"]),
            "share/crabc/libc-shared.provenance.json": digest(files["dynamic-libc-provenance"]),
            **{path: digest(files[name]) for name, path in {
                "dynamic-driver": "bin/crabc-cc-dynamic", "dynamic-crt1": "usr/lib/crt1.o",
                "dynamic-scrt1": "usr/lib/Scrt1.o", "dynamic-crti": "usr/lib/crti.o",
                "dynamic-crtn": "usr/lib/crtn.o", "dynamic-attach": "usr/lib/crabc-dynamic-attach.o",
                "dynamic-builtins": "usr/lib/libcrabc-builtins.a",
            }.items()},
        }
        product("dynamic-product-state", json.dumps({
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "allocator_backend": "native-shadow",
            "source_sha256": "0" * 64 if bad_source_digest else policy._product_source_digest(self.root),
            "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
            "payload_files": dynamic_files,
        }).encode())
        product("dynamic-manifest", json.dumps({"files": dynamic_files | {
            "share/crabc/dynamic-product-state.json": digest(files["dynamic-product-state"]),
        }}).encode())
        for program in policy.PROGRAMS:
            product(f"oracle-{program}", elf(2))
            product(f"static-{program}", elf(2))
            product(f"static-pie-{program}", elf(2 if wrong_elf_mode else 3))
            for kind in ("pie", "non-pie"):
                product(f"dynamic-{kind}-{program}", elf(3 if kind == "pie" else 2,
                                                        "/lib/ld-crabc-x86_64.so.1"))
            oracle_compiler_inputs = {
                "oracle-gcc": {"path": "/usr/bin/gcc", "sha256": digest(files["oracle-gcc"])},
                "oracle-specs": {"path": "/opt/musl-1.2.6/lib/musl-gcc.specs",
                                 "sha256": digest(files["oracle-specs"])},
            }
            for mode in policy.COMPILE_MODES:
                object_name = f"object-{mode}-{program}"
                product(object_name, object_name.encode())
                compiler = ("oracle-wrapper" if mode == "oracle" else
                            "dynamic-driver" if mode.startswith("dynamic-") else "static-driver")
                selection = (["-static", "-fno-pie", "-no-pie"] if mode == "oracle" else
                             ["--" + mode] if mode.startswith("dynamic-") else ["-" + mode])
                compiled = {
                    "schema": "crabc.x86_64-allocator-policy-compile/v1",
                    "mode": mode, "program": program, "source_path": policy.SOURCE_PATHS[program],
                    "source_sha256": digest(files[f"source-{program}"]),
                    "object_sha256": digest(files[object_name]),
                    "compiler_sha256": digest(files[compiler]),
                    "flags": selection + policy.COMMON_FLAGS + ["-c"],
                }
                if mode == "oracle":
                    compiled["compiler_inputs"] = (oracle_compiler_inputs | {
                        "oracle-specs": {"path": "/opt/musl-1.2.6/lib/musl-gcc.specs", "sha256": "0" * 64}}
                        if bad_oracle_compiler and program == "policy" else oracle_compiler_inputs)
                record(f"compile-{mode}-{program}", compiled)
            oracle_runtime = {
                "oracle-musl-scrt1": "/opt/musl-1.2.6/lib/Scrt1.o",
                "oracle-musl-crti": "/opt/musl-1.2.6/lib/crti.o",
                "oracle-musl-libc": "/opt/musl-1.2.6/lib/libc.a",
                "oracle-musl-libssp": "/opt/musl-1.2.6/lib/libssp_nonshared.a",
                "oracle-musl-libpthread": "/opt/musl-1.2.6/lib/libpthread.a",
                "oracle-musl-crtn": "/opt/musl-1.2.6/lib/crtn.o",
                "oracle-crtbegin": "/usr/lib/gcc/test/crtbeginS.o",
                "oracle-crtend": "/usr/lib/gcc/test/crtendS.o",
                "oracle-libgcc": "/usr/lib/gcc/test/libgcc.a",
                "oracle-libgcc-eh": "/usr/lib/gcc/test/libgcc_eh.a",
            }
            trace_roles = ("oracle-musl-scrt1", "oracle-musl-crti", "oracle-crtbegin")
            trace_after_object = (
                "oracle-musl-libssp", "oracle-libgcc", "oracle-libgcc-eh",
                "oracle-musl-libpthread", "oracle-musl-libc", "oracle-libgcc", "oracle-libgcc-eh",
                "oracle-musl-libpthread", "oracle-musl-libc", "oracle-crtend", "oracle-musl-crtn",
            )
            trace = [oracle_runtime[name] for name in trace_roles] + [f"/work/object-oracle-{program}.o"] + [
                oracle_runtime[name] for name in trace_after_object]
            product(f"trace-oracle-{program}", ("\n".join(trace) + "\n").encode())
            record(f"link-oracle-{program}", {
                "schema": "crabc.x86_64-allocator-policy-oracle-link/v1", "program": program,
                "mode": "static-et-exec", "compiler_sha256": digest(files["oracle-wrapper"]),
                "object_sha256": digest(files[f"object-oracle-{program}"]),
                "object_path": f"/work/object-oracle-{program}.o",
                "output_sha256": digest(files[f"oracle-{program}"]),
                "output_path": f"/work/oracle-{program}.exe",
                "trace_sha256": digest(files[f"trace-oracle-{program}"]),
                "compiler_inputs": oracle_compiler_inputs,
                "runtime_inputs": {name: {"path": path, "sha256": digest(files[name])}
                                   for name, path in oracle_runtime.items()},
                "flags": ["-static", "-fno-pie", "-no-pie", *policy.COMMON_FLAGS],
            })
            for mode in ("static", "static-pie"):
                name = f"{mode}-{program}"
                product(f"map-{name}", b"link map\n")
                product(f"trace-{name}", b"link trace\n")
                runtime = [
                    ("crt-entry", "static-crt1" if mode == "static" else "static-rcrt1",
                     "usr/lib/crt1.o" if mode == "static" else "usr/lib/rcrt1.o"),
                    ("crt-prologue", "static-crti", "usr/lib/crti.o"),
                    ("libc", "static-libc-archive", "usr/lib/libc.a"),
                    ("builtins", "static-builtins", "usr/lib/libcrabc-builtins.a"),
                    ("crt-epilogue", "static-crtn", "usr/lib/crtn.o"),
                ]
                object_hash = ("0" * 64 if bad_link_input and name == "static-pie-policy" else
                               digest(files[f"object-{name}"]))
                record(f"link-{name}", {
                    "schema": 1, "format": "crabc-x86-64-sealed-static-driver-v1",
                    "target": "x86_64-unknown-linux-musl",
                    "mode": {"id": "static-et-exec" if mode == "static" else "static-pie",
                             "elf_type": "ET_EXEC" if mode == "static" else "ET_DYN",
                             "crt_object": "crt1.o" if mode == "static" else "rcrt1.o",
                             "interpreter": "absent"},
                    "output": {"path": f"/work/{name}.exe", "sha256": digest(files[name])},
                    "map": {"path": f"/work/link-{name}.map", "sha256": digest(files[f"map-{name}"])},
                    "trace": {"path": f"/work/link-{name}.trace", "sha256": digest(files[f"trace-{name}"])},
                    "input_receipts": [
                        {"role": role, "path": path, "sha256": digest(files[product])}
                        for role, product, path in runtime
                    ] + [{"role": "application", "path": f"/work/object-{name}.o",
                          "sha256": object_hash}],
                })
            for mode in ("pie", "non-pie"):
                name = f"dynamic-{mode}-{program}"
                product(f"map-{name}", b"dynamic link map\n")
                runtime = {
                    "crti.o": "dynamic-crti", "libc.so": "dynamic-libc", "crtn.o": "dynamic-crtn",
                    "Scrt1.o" if mode == "pie" else "crt1.o":
                        "dynamic-scrt1" if mode == "pie" else "dynamic-crt1",
                    "crabc-dynamic-attach.o": "dynamic-attach",
                    "libcrabc-builtins.a": "dynamic-builtins",
                    f"object-{name}.o": f"object-{name}",
                }
                inputs = [{"path": f"/work/usr/lib/{basename}" if not basename.startswith("object-")
                           else f"/work/{basename}",
                           "sha256": "0" * 64 if bad_dynamic_input and name == "dynamic-non-pie-policy"
                           and basename == "libc.so" else digest(files[product])}
                          for basename, product in runtime.items()]
                record(f"link-{name}", {
                    "schema": 2, "mode": "pie" if mode == "pie" else "exec",
                    "manifest_sha256": digest(files["dynamic-manifest"]),
                    "output_sha256": digest(files[name]), "output_path": f"/work/{name}.exe",
                    "application_dsos": {}, "input_receipts": inputs,
                    "link_command": [item["path"] for item in inputs],
                    "link_trace": [item["path"] for item in inputs],
                })
                record(f"elf-{name}", {
                    "output_sha256": digest(files[name]),
                    "link_map": {"sha256": digest(files[f"map-{name}"])},
                    "declared": {"mode": "pie" if mode == "pie" else "exec"},
                    "facts": {"needed": ["libc.so"], "symbol_versioning": False},
                })
        cases = []
        for program in policy.PROGRAMS:
            for mode in policy.MODES:
                name = f"{mode}-{program}"
                stdout = self.work / f"{name}.stdout"
                stderr = self.work / f"{name}.stderr"
                status = self.work / f"{name}.status"
                stdout.write_bytes((b"" if program == "observability" else b"policy=" + program.encode() + b"\n") +
                                   (b"wrong\n" if name == differing_mode else b""))
                stderr.write_bytes(b"unexpected\n" if name == stderr_mode else b"")
                status.write_bytes(b"0\n")
                if name != missing_case:
                    cases.append((name, 0, (stdout, stderr, status)))
        runner = self.work / "runner.status"
        runner.write_bytes(b"0\n")
        cases.append(("runner", 0, (runner,)))
        if missing_product:
            del files[missing_product]
        return receipt.write_receipt(self.root, policy.RUNNER, self.work, files, cases,
                                     policy.PARAMETERS, True)

    def read(self) -> receipt.Receipt:
        with mock.patch.object(policy.owned_dynamic_elf, "inspect", return_value={
            "needed": ["libc.so"], "symbol_versioning": False,
        }):
            return policy.read_policy_receipt(self.root)

    def test_shared_reader_accepts_an_incomplete_policy_matrix(self) -> None:
        self.publish(missing_case="direct-non-pie-policy")
        self.assertEqual(len(receipt.read_receipt(self.root, policy.RUNNER).cases), 21)
        with self.assertRaisesRegex(receipt.ReceiptError, "22-case matrix"):
            self.read()

    def test_complete_matrix_survives_work_cleanup(self) -> None:
        self.publish()
        shutil.rmtree(self.work)
        self.assertEqual(len(self.read().cases), 22)

    def test_rehashed_wrong_candidate_transcript_is_rejected(self) -> None:
        self.publish(differing_mode="direct-pie-basic")
        receipt.read_receipt(self.root, policy.RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "differs from pinned musl"):
            self.read()

    def test_missing_executed_product_is_rejected(self) -> None:
        self.publish(missing_product="dynamic-non-pie-policy")
        with self.assertRaisesRegex(receipt.ReceiptError, "executed products"):
            self.read()

    def test_omitted_link_evidence_is_rejected(self) -> None:
        self.publish(missing_product="link-static-pie-policy")
        receipt.read_receipt(self.root, policy.RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "products|link|input"):
            self.read()

    def test_rehashed_wrong_static_link_input_is_rejected(self) -> None:
        self.publish(bad_link_input=True)
        receipt.read_receipt(self.root, policy.RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "application object"):
            self.read()

    def test_rehashed_wrong_dynamic_libc_input_is_rejected(self) -> None:
        self.publish(bad_dynamic_input=True)
        receipt.read_receipt(self.root, policy.RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic libc.so input"):
            self.read()

    def test_rehashed_wrong_oracle_compiler_and_source_are_rejected(self) -> None:
        self.publish(bad_oracle_compiler=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "oracle-policy compile input"):
            self.read()
        self.publish(bad_probe_source=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "retained source"):
            self.read()

    def test_rehashed_wrong_provenance_is_rejected(self) -> None:
        self.publish(bad_archive=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "provenance"):
            self.read()

    def test_rehashed_wrong_product_source_digest_is_rejected(self) -> None:
        self.publish(bad_source_digest=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "source digest"):
            self.read()

    def test_stderr_and_elf_mode_are_checked(self) -> None:
        self.publish(stderr_mode="kernel-pie-policy")
        with self.assertRaisesRegex(receipt.ReceiptError, "wrote stderr"):
            self.read()
        self.publish(wrong_elf_mode=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "static ELF link mode"):
            self.read()

    def test_wrong_dynamic_linkage_is_rejected(self) -> None:
        self.publish()
        with mock.patch.object(policy.owned_dynamic_elf, "inspect", return_value={
            "needed": ["libc.so.6"], "symbol_versioning": False,
        }):
            with self.assertRaisesRegex(receipt.ReceiptError, "dynamic libc linkage"):
                policy.read_policy_receipt(self.root)


if __name__ == "__main__":
    unittest.main()
