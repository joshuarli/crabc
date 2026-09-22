#!/usr/bin/env python3
"""Regression coverage for exact ELF pthread/C11 alias identity checks."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_pthread_alias_contract_reader import (
    ALIASES,
    DYNAMIC_STATE_CONTRACTS,
    DYNAMIC_STATE_MODES,
    DYNAMIC_STATE_PROFILE,
    DYNAMIC_STATE_QUALIFICATION,
    INPUT_NAMES,
    INPUT_SCHEMA,
    ReceiptError,
    SymbolRow,
    _load_inputs,
    _shared_symbols,
    _validate_dynamic_link_receipt,
    _validate_dynamic_materialization_state,
    artifact_record,
    load_json_object,
    same_definition,
    validate_command_argv,
    validate_retained_artifact,
)


class OwnedPthreadAliasContractReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch_parent = SOURCE_DIR.parents[1] / ".work" / "x86_64"
        self.scratch_parent.mkdir(parents=True, exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(
            prefix="owned-pthread-alias-reader-test.", dir=self.scratch_parent
        )
        self.root = Path(self.scratch.name)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def test_retained_command_output_mutation_is_rejected(self) -> None:
        """The old input-only ledger could not bind a passing runtime stream."""

        output = self.root / "dynamic-pie-kernel.stdout"
        output.write_text("owned-pthread-alias-contract-ok\n", encoding="utf-8")
        sealed = artifact_record(self.root, output)
        validate_retained_artifact(self.root, sealed, "dynamic PIE kernel stdout")

        output.write_text("forged passing transcript\n", encoding="utf-8")
        with self.assertRaisesRegex(ReceiptError, "identity changed"):
            validate_retained_artifact(self.root, sealed, "dynamic PIE kernel stdout")

    def test_canonical_sorted_input_identity_roster_is_accepted(self) -> None:
        """The receipt writer uses sorted JSON keys but retains the full named roster."""

        identities = self.root / "input-identities.json"
        identities.write_text(
            __import__("json").dumps({
                "format": INPUT_SCHEMA,
                "inputs": {
                    name: {"path": f"/inputs/{name}", "sha256": "a" * 64, "size": 0}
                    for name in INPUT_NAMES
                },
            }, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(tuple(_load_inputs(identities)), INPUT_NAMES)

    def test_dynamic_materialization_state_binds_full_manifest_payload_roster(self) -> None:
        """A source digest alone cannot authenticate the selected dynamic product."""

        source = "b" * 64
        files = {
            "usr/lib/libc.so": "c" * 64,
            "share/crabc/dynamic-product-state.json": "d" * 64,
        }
        state = {
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "status": "materialized-unqualified",
            "source_sha256": source,
            "contracts": {name: "e" * 64 for name in DYNAMIC_STATE_CONTRACTS},
            "payload_files": {"usr/lib/libc.so": "c" * 64},
            "allocator_backend": "accepted-c",
            "allocator_lifecycle_test_audit": False,
            "allocator_promoted": False,
            "runtime_v1_published": False,
            "campaign_complete": False,
            "public_support": False,
            "modes": DYNAMIC_STATE_MODES,
            "runtime_profile": DYNAMIC_STATE_PROFILE,
            "qualification": DYNAMIC_STATE_QUALIFICATION,
        }
        _validate_dynamic_materialization_state(state, source, files, "test dynamic state")
        for field, replacement in (
            ("allocator_backend", "native-shadow"),
            ("allocator_lifecycle_test_audit", True),
            ("allocator_promoted", True),
        ):
            with self.subTest(field=field):
                forged = dict(state)
                forged[field] = replacement
                with self.assertRaisesRegex(ReceiptError, "allocator provenance"):
                    _validate_dynamic_materialization_state(forged, source, files, "test dynamic state")
        state["payload_files"] = {}
        with self.assertRaisesRegex(ReceiptError, "payload binding"):
            _validate_dynamic_materialization_state(state, source, files, "test dynamic state")

    def test_duplicate_raw_command_json_is_rejected(self) -> None:
        """A duplicate command key must not disappear before argv reconstruction."""

        command = self.root / "dynamic-pie-link.argv.json"
        command.write_text('{"argv":["first"],"argv":["forged"]}\n', encoding="utf-8")
        with self.assertRaisesRegex(ReceiptError, "duplicate JSON key"):
            load_json_object(command, "link command")

    def test_link_argv_requires_the_one_compiled_object_and_retained_map(self) -> None:
        """A self-consistent link transcript cannot switch source or omit its map."""

        work = "/workspace/.work/x86_64/receipt"
        inputs = {
            "static_driver": "/workspace/.work/x86_64/products/static/bin/crabc-cc",
            "dynamic_driver": "/workspace/.work/x86_64/products/dynamic/bin/crabc-cc-dynamic",
            "oracle_compiler": "/usr/local/bin/crabc-x86_64-musl-gcc",
            "probe": "/workspace/compat/x86_64/owned_pthread_alias_contract_probe.c",
        }
        valid = [
            inputs["static_driver"], "-static", "-pthread", f"{work}/contract.o",
            "--link-receipt", ".work/x86_64/receipt/static-contract.link.json",
            "-o", f"{work}/static-contract",
        ]
        validate_command_argv("static-link", valid, work, inputs)

        with self.subTest("source-recompile"):
            changed = list(valid)
            changed[3] = inputs["probe"]
            with self.assertRaisesRegex(ReceiptError, "compiled contract object"):
                validate_command_argv("static-link", changed, work, inputs)
        with self.subTest("missing-map"):
            changed = [
                value for value in valid
                if value not in {"--link-receipt", ".work/x86_64/receipt/static-contract.link.json"}
            ]
            with self.assertRaisesRegex(ReceiptError, "exact retained link map"):
                validate_command_argv("static-link", changed, work, inputs)

    def test_dynamic_link_argv_has_no_unsealed_map_flag(self) -> None:
        """The sealed dynamic driver receipt, rather than a linker map, binds this link."""

        work = "/workspace/.work/x86_64/receipt"
        inputs = {
            "static_driver": "/workspace/.work/x86_64/products/static/bin/crabc-cc",
            "dynamic_driver": "/workspace/.work/x86_64/products/dynamic/bin/crabc-cc-dynamic",
            "oracle_compiler": "/usr/local/bin/crabc-x86_64-musl-gcc",
            "probe": "/workspace/compat/x86_64/owned_pthread_alias_contract_probe.c",
        }
        valid = [
            inputs["dynamic_driver"], "--dynamic-pie", "-pthread", "-rdynamic",
            f"{work}/contract.o", "-o", f"{work}/dynamic-pie-contract",
        ]
        validate_command_argv("dynamic-pie-link", valid, work, inputs)
        forged = list(valid)
        forged.insert(-2, f"-Wl,-Map,{work}/dynamic-pie-contract.map")
        with self.assertRaisesRegex(ReceiptError, "argv differs"):
            validate_command_argv("dynamic-pie-link", forged, work, inputs)

        non_pie = [
            inputs["dynamic_driver"], "--dynamic-non-pie", "-pthread", "-rdynamic",
            f"{work}/contract.o", "-o", f"{work}/dynamic-non-pie-contract",
        ]
        validate_command_argv("dynamic-non-pie-link", non_pie, work, inputs)

    def test_dynamic_sidecar_reconstructs_its_linker_command(self) -> None:
        """A changed dynamic-driver linker argv cannot be made self-consistent."""

        work_path = "/workspace/.work/x86_64/receipt"
        product_root = "/products/dynamic"
        runtime_files = {
            "usr/lib/Scrt1.o": "a" * 64,
            "usr/lib/crabc-dynamic-attach.o": "b" * 64,
            "usr/lib/crti.o": "c" * 64,
            "usr/lib/crtn.o": "d" * 64,
            "usr/lib/libc.so": "e" * 64,
            "usr/lib/libcrabc-builtins.a": "f" * 64,
        }
        manifest = self.root / "retained/products/dynamic-manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(__import__("json").dumps({"files": runtime_files}) + "\n", encoding="utf-8")
        binary = "dynamic-pie-contract"
        receipt_path = self.root / f"{binary}.crabc-link.json"
        trace = [
            f"{product_root}/usr/lib/Scrt1.o", f"{product_root}/usr/lib/crabc-dynamic-attach.o",
            f"{product_root}/usr/lib/crti.o", f"{work_path}/contract.o",
            f"{product_root}/usr/lib/libc.so", f"{product_root}/usr/lib/crtn.o",
        ]
        command = [
            "/tools/ld.lld", "-pie", "--hash-style=sysv", "-z", "relro", "-z", "now",
            "-z", "noexecstack", "-z", "text", "--no-undefined", "--allow-shlib-undefined",
            "--enable-new-dtags", "-rpath", "/usr/lib", "--export-dynamic", "--dynamic-linker",
            "/lib/ld-crabc-x86_64.so.1", *trace[:3], f"{work_path}/contract.o",
            f"{product_root}/usr/lib/libc.so", f"{product_root}/usr/lib/libcrabc-builtins.a",
            f"{product_root}/usr/lib/crtn.o", "-o", f"{work_path}/{binary}",
        ]
        receipt = {
            "schema": 2, "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "campaign_complete": False, "mode": "pie", "output_path": f"{work_path}/{binary}",
            "output_sha256": "0" * 64, "runtime_imports": [], "application_dsos": {},
            "application_hash_style": "sysv", "application_rpath": None, "application_runpath": "/usr/lib",
            "application_search_kind": "runpath", "binding": "now", "manifest_sha256": "1" * 64,
            "owned_runtime_inputs": sorted(runtime_files),
            "input_receipts": [
                {"path": f"{product_root}/{name}", "sha256": digest}
                for name, digest in runtime_files.items()
            ] + [{"path": f"{work_path}/contract.o", "sha256": "2" * 64}],
            "link_trace": trace, "link_command": command,
            "resolved_linker": {"path": "/tools/ld.lld", "sha256": "3" * 64},
        }
        receipt_path.write_text(__import__("json").dumps(receipt) + "\n", encoding="utf-8")
        artifacts = {
            binary: {"sha256": "0" * 64}, "contract.o": {"sha256": "2" * 64},
            "retained/products/dynamic-manifest.json": {"sha256": "1" * 64},
        }
        products = {"dynamic": {
            "manifest": "retained/products/dynamic-manifest.json",
            "original_paths": {"driver": f"{product_root}/bin/crabc-cc-dynamic"},
        }}
        _validate_dynamic_link_receipt(receipt_path, work_path, binary, artifacts, products)
        receipt["link_command"][1] = "--forged-pie"
        receipt_path.write_text(__import__("json").dumps(receipt) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReceiptError, "dynamic linker command changed"):
            _validate_dynamic_link_receipt(receipt_path, work_path, binary, artifacts, products)

    def test_same_member_zero_value_different_sections_is_not_an_alias(self) -> None:
        alias = SymbolRow(
            member="pthread_mutex_lock.o",
            value="0000000000000000",
            symbol_type="FUNC",
            binding="WEAK",
            visibility="DEFAULT",
            section="17",
            name="pthread_mutex_lock",
        )
        forwarding_body = alias._replace(
            binding="GLOBAL",
            section="18",
            name="__pthread_mutex_lock",
        )

        self.assertFalse(same_definition(alias, forwarding_body))

    def _shared_symbol_stream(self, section: str) -> Path:
        """Build the complete finite shared alias roster with one Ndx spelling."""

        providers = tuple(dict.fromkeys(provider for _, provider in ALIASES))
        values = {
            provider: f"{index:016x}"
            for index, provider in enumerate(providers, start=1)
        }
        lines = [
            f"Symbol table '.symtab' contains {len(ALIASES) + len(providers)} entries:",
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name",
        ]
        index = 1
        for name, provider in ALIASES:
            lines.append(
                f"{index:6}: {values[provider]}     1 FUNC    WEAK   DEFAULT {section:>4} {name}"
            )
            index += 1
        for provider in providers:
            lines.append(
                f"{index:6}: {values[provider]}     1 FUNC    LOCAL  DEFAULT {section:>4} {provider}"
            )
            index += 1
        path = self.root / f"shared-{section}.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_shared_aliases_require_positive_defining_section_indices(self) -> None:
        """Reserved Ndx spellings cannot turn 17 aliases into fabricated bodies."""

        _, definitions = _shared_symbols(self._shared_symbol_stream("9"))
        self.assertEqual(tuple(definitions), tuple(name for name, _ in ALIASES))

        for section in ("UND", "ABS", "COM", "0"):
            with self.subTest(section=section):
                with self.assertRaisesRegex(ReceiptError, "expected one defined"):
                    _shared_symbols(self._shared_symbol_stream(section))

    @unittest.skipUnless(
        Path("/usr/local/bin/crabc-x86_64-musl-gcc").is_file(),
        "requires the pinned native x86-64 image",
    )
    def test_runner_rejects_product_overlapping_output_before_writing(self) -> None:
        """Invalid fixtures cannot make runner evidence directories inside products."""

        runner = SOURCE_DIR / "run_owned_pthread_alias_contract.sh"
        static = self.root / "static-product"
        dynamic = self.root / "dynamic-product"
        for product, names in (
            (static, ("bin/crabc-cc", "usr/lib/libc.a")),
            (dynamic, (
                "bin/crabc-cc-dynamic", "usr/lib/libc.so",
                "lib/ld-crabc-x86_64.so.1",
            )),
        ):
            for name in names:
                path = product / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"invalid isolated product fixture\n")
        anchor = self.root / "product-anchor.json"
        historical = self.root / "historical-inputs.json"
        anchor.write_text("{}\n", encoding="utf-8")
        historical.write_text("{}\n", encoding="utf-8")
        ordinary_tmp = self.root / "ordinary-tmp"
        ordinary_tmp.mkdir()
        environment = dict(os.environ)
        environment.pop("CRABC_RETAINED_640C0939_ROOT", None)

        def run(*arguments: str, temporary: Path) -> subprocess.CompletedProcess[str]:
            environment["TMPDIR"] = str(temporary)
            return subprocess.run(
                ["bash", str(runner), *arguments],
                cwd=SOURCE_DIR.parents[1],
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        for label, product in (("static", static), ("dynamic", dynamic)):
            with self.subTest(receipt_product=label):
                receipt = product / "new-receipt"
                before = sorted(path.relative_to(product).as_posix() for path in product.rglob("*"))
                result = run(
                    "--receipt-dir", str(receipt),
                    "--product-report", str(anchor),
                    "--historical-inputs", str(historical),
                    "--historical-source-commit", "0" * 40,
                    str(static), str(dynamic),
                    temporary=ordinary_tmp,
                )
                after = sorted(path.relative_to(product).as_posix() for path in product.rglob("*"))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"receipt directory overlaps {label} product", result.stderr)
                self.assertEqual(before, after)

        for label, product in (("static", static), ("dynamic", dynamic)):
            with self.subTest(temporary_product=label):
                temporary = product / "ordinary-tmp"
                temporary.mkdir()
                before = sorted(path.relative_to(product).as_posix() for path in product.rglob("*"))
                result = run(str(static), str(dynamic), temporary=temporary)
                after = sorted(path.relative_to(product).as_posix() for path in product.rglob("*"))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"TMPDIR overlaps {label} product", result.stderr)
                self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
